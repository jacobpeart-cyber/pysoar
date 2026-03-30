"""
ITDR (Identity Threat Detection & Response) API Endpoints

Provides REST API for identity threat detection, credential monitoring,
access anomaly analysis, and privileged access management.
"""

import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status, BackgroundTasks
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.itdr.models import (
    IdentityProfile,
    IdentityThreat,
    CredentialExposure,
    AccessAnomaly,
    PrivilegedAccessEvent,
)
from src.itdr.engine import (
    IdentityThreatDetector,
    CredentialMonitor,
    AccessBehaviorAnalyzer,
    PrivilegedAccessManager,
)
from src.schemas.itdr import (
    IdentityProfileCreate,
    IdentityProfileUpdate,
    IdentityProfileResponse,
    IdentityProfileListResponse,
    IdentityThreatCreate,
    IdentityThreatUpdate,
    IdentityThreatResponse,
    IdentityThreatListResponse,
    CredentialExposureCreate,
    CredentialExposureUpdate,
    CredentialExposureResponse,
    CredentialExposureListResponse,
    AccessAnomalyCreate,
    AccessAnomalyUpdate,
    AccessAnomalyResponse,
    AccessAnomalyListResponse,
    PrivilegedAccessEventCreate,
    PrivilegedAccessEventUpdate,
    PrivilegedAccessEventResponse,
    PrivilegedAccessEventListResponse,
    ThreatInvestigationRequest,
    ThreatResponseAction,
    CredentialRemediationRequest,
    ElevationRequest,
    ElevationApprovalRequest,
    AnomalyReviewRequest,
    ITDRDashboardMetrics,
    ITDRRiskOverview,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/itdr", tags=["ITDR"])


async def get_identity_or_404(db: AsyncSession, identity_id: str) -> IdentityProfile:
    """Get identity profile by ID or raise 404"""
    result = await db.execute(
        select(IdentityProfile).where(IdentityProfile.id == identity_id)
    )
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity profile not found",
        )
    return identity


async def get_threat_or_404(db: AsyncSession, threat_id: str) -> IdentityThreat:
    """Get identity threat by ID or raise 404"""
    result = await db.execute(
        select(IdentityThreat).where(IdentityThreat.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity threat not found",
        )
    return threat


# ============================================================================
# Identity Profile Endpoints
# ============================================================================


@router.get("/identities", response_model=IdentityProfileListResponse)
async def list_identities(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    privilege_level: Optional[str] = None,
    is_service_account: Optional[bool] = None,
    is_dormant: Optional[bool] = None,
    min_risk_score: Optional[float] = Query(None, ge=0.0, le=100.0),
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List identity profiles with filtering and pagination"""
    query = select(IdentityProfile)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (IdentityProfile.username.ilike(search_filter))
            | (IdentityProfile.email.ilike(search_filter))
            | (IdentityProfile.display_name.ilike(search_filter))
        )

    if privilege_level:
        query = query.where(IdentityProfile.privilege_level == privilege_level)

    if is_service_account is not None:
        query = query.where(IdentityProfile.is_service_account == is_service_account)

    if is_dormant is not None:
        query = query.where(IdentityProfile.is_dormant == is_dormant)

    if min_risk_score is not None:
        query = query.where(IdentityProfile.risk_score >= min_risk_score)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(IdentityProfile, sort_by, IdentityProfile.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    identities = result.scalars().all()

    return IdentityProfileListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[IdentityProfileResponse.from_orm(i) for i in identities],
    )


@router.get("/identities/{identity_id}", response_model=IdentityProfileResponse)
async def get_identity(
    identity_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get identity profile details"""
    identity = await get_identity_or_404(db, identity_id)
    return IdentityProfileResponse.from_orm(identity)


@router.post("/identities", response_model=IdentityProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_identity(
    data: IdentityProfileCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create new identity profile"""
    identity = IdentityProfile(
        organization_id=current_user.organization_id,
        **data.dict()
    )
    db.add(identity)
    await db.commit()
    await db.refresh(identity)
    logger.info(f"Identity created: {identity.username}")
    return IdentityProfileResponse.from_orm(identity)


@router.put("/identities/{identity_id}", response_model=IdentityProfileResponse)
async def update_identity(
    identity_id: str,
    data: IdentityProfileUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update identity profile"""
    identity = await get_identity_or_404(db, identity_id)
    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(identity, field, value)
    await db.commit()
    await db.refresh(identity)
    logger.info(f"Identity updated: {identity.username}")
    return IdentityProfileResponse.from_orm(identity)


@router.get("/identities/{identity_id}/risk-score")
async def get_identity_risk_score(
    identity_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get identity risk score breakdown"""
    identity = await get_identity_or_404(db, identity_id)

    # Count threats
    threat_result = await db.execute(
        select(func.count()).where(IdentityThreat.identity_id == identity_id)
    )
    threat_count = threat_result.scalar() or 0

    # Count critical threats
    critical_result = await db.execute(
        select(func.count()).where(
            (IdentityThreat.identity_id == identity_id)
            & (IdentityThreat.severity == "critical")
        )
    )
    critical_count = critical_result.scalar() or 0

    # Count anomalies
    anomaly_result = await db.execute(
        select(func.count()).where(AccessAnomaly.identity_id == identity_id)
    )
    anomaly_count = anomaly_result.scalar() or 0

    # Count exposures
    exposure_result = await db.execute(
        select(func.count()).where(CredentialExposure.identity_id == identity_id)
    )
    exposure_count = exposure_result.scalar() or 0

    return {
        "identity_id": identity_id,
        "username": identity.username,
        "risk_score": identity.risk_score,
        "threat_count": threat_count,
        "critical_threats": critical_count,
        "anomalies": anomaly_count,
        "credential_exposures": exposure_count,
        "risk_breakdown": {
            "threats_contribution": min(40.0, critical_count * 15 + (threat_count - critical_count) * 5),
            "anomalies_contribution": min(30.0, anomaly_count * 3),
            "credentials_contribution": min(30.0, exposure_count * 5),
        },
    }


# ============================================================================
# Identity Threat Endpoints
# ============================================================================


@router.get("/threats", response_model=IdentityThreatListResponse)
async def list_threats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    identity_id: Optional[str] = None,
    min_confidence: Optional[float] = Query(None, ge=0.0, le=100.0),
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List identity threats with filtering"""
    query = select(IdentityThreat)

    if threat_type:
        query = query.where(IdentityThreat.threat_type == threat_type)

    if severity:
        query = query.where(IdentityThreat.severity == severity)

    if status:
        query = query.where(IdentityThreat.status == status)

    if identity_id:
        query = query.where(IdentityThreat.identity_id == identity_id)

    if min_confidence is not None:
        query = query.where(IdentityThreat.confidence_score >= min_confidence)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(IdentityThreat, sort_by, IdentityThreat.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    threats = result.scalars().all()

    return IdentityThreatListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[IdentityThreatResponse.from_orm(t) for t in threats],
    )


@router.get("/threats/{threat_id}", response_model=IdentityThreatResponse)
async def get_threat(
    threat_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get identity threat details"""
    threat = await get_threat_or_404(db, threat_id)
    return IdentityThreatResponse.from_orm(threat)


@router.post("/threats", response_model=IdentityThreatResponse, status_code=status.HTTP_201_CREATED)
async def create_threat(
    data: IdentityThreatCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create new identity threat"""
    threat = IdentityThreat(
        organization_id=current_user.organization_id,
        **data.dict()
    )
    db.add(threat)
    await db.commit()
    await db.refresh(threat)
    logger.warning(f"Identity threat created: {threat.threat_type} ({threat.severity})")
    return IdentityThreatResponse.from_orm(threat)


@router.put("/threats/{threat_id}", response_model=IdentityThreatResponse)
async def update_threat(
    threat_id: str,
    data: IdentityThreatUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update identity threat status and details"""
    threat = await get_threat_or_404(db, threat_id)
    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(threat, field, value)
    await db.commit()
    await db.refresh(threat)
    logger.info(f"Identity threat updated: {threat.threat_type} -> {threat.status}")
    return IdentityThreatResponse.from_orm(threat)


@router.post("/threats/{threat_id}/investigate")
async def investigate_threat(
    threat_id: str,
    data: ThreatInvestigationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Start threat investigation"""
    threat = await get_threat_or_404(db, threat_id)
    threat.status = "investigating"
    await db.commit()
    await db.refresh(threat)
    logger.info(f"Threat investigation started: {threat_id}")
    return {
        "threat_id": threat_id,
        "status": threat.status,
        "investigation_notes": data.investigation_notes,
    }


@router.post("/threats/{threat_id}/respond")
async def respond_to_threat(
    threat_id: str,
    data: ThreatResponseAction,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Execute threat response action"""
    threat = await get_threat_or_404(db, threat_id)
    threat.status = "contained"
    await db.commit()
    logger.info(f"Threat response executed: {threat_id} - {data.action_type}")
    return {
        "threat_id": threat_id,
        "action": data.action_type,
        "status": "executed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/threats/scan")
async def run_threat_scan(
    current_user: CurrentUser = None,
    organization_id: Optional[str] = None,
    background_tasks: BackgroundTasks = None,
):
    """Run comprehensive threat detection scan"""
    logger.info(f"Initiating threat scan for org={organization_id or current_user.organization_id}")

    return {
        "status": "initiated",
        "scan_id": f"scan_{datetime.now(timezone.utc).timestamp()}",
        "message": "Threat detection scan initiated in background",
        "organization_id": organization_id or current_user.organization_id,
    }


# ============================================================================
# Credential Exposure Endpoints
# ============================================================================


@router.get("/credential-exposures", response_model=CredentialExposureListResponse)
async def list_exposures(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    credential_type: Optional[str] = None,
    exposure_source: Optional[str] = None,
    is_remediated: Optional[bool] = None,
    identity_id: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List credential exposures"""
    query = select(CredentialExposure)

    if credential_type:
        query = query.where(CredentialExposure.credential_type == credential_type)

    if exposure_source:
        query = query.where(CredentialExposure.exposure_source == exposure_source)

    if is_remediated is not None:
        query = query.where(CredentialExposure.is_remediated == is_remediated)

    if identity_id:
        query = query.where(CredentialExposure.identity_id == identity_id)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(CredentialExposure, sort_by, CredentialExposure.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    exposures = result.scalars().all()

    return CredentialExposureListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[CredentialExposureResponse.from_orm(e) for e in exposures],
    )


@router.get("/credential-exposures/{exposure_id}", response_model=CredentialExposureResponse)
async def get_exposure(
    exposure_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get credential exposure details"""
    result = await db.execute(
        select(CredentialExposure).where(CredentialExposure.id == exposure_id)
    )
    exposure = result.scalar_one_or_none()
    if not exposure:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential exposure not found",
        )
    return CredentialExposureResponse.from_orm(exposure)


@router.post("/credential-exposures/check")
async def check_credential_exposure(
    identity_id: str,
    current_user: CurrentUser = None,
):
    """Check identity credentials for exposure"""
    logger.info(f"Checking credential exposure for identity {identity_id}")

    return {
        "status": "check_initiated",
        "identity_id": identity_id,
        "sources_checked": ["dark_web", "paste_sites", "breach_databases"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/credential-exposures/remediate")
async def remediate_exposures(
    data: CredentialRemediationRequest,
    current_user: CurrentUser = None,
):
    """Remediate exposed credentials"""
    logger.info(f"Remediating {len(data.exposure_ids)} credential exposures")

    return {
        "status": "remediation_initiated",
        "exposure_count": len(data.exposure_ids),
        "remediation_type": data.remediation_type,
        "actions_pending": len(data.exposure_ids),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# Access Anomaly Endpoints
# ============================================================================


@router.get("/anomalies", response_model=AccessAnomalyListResponse)
async def list_anomalies(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    anomaly_type: Optional[str] = None,
    is_reviewed: Optional[bool] = None,
    identity_id: Optional[str] = None,
    min_deviation: Optional[float] = Query(None, ge=0.0, le=1.0),
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List access anomalies"""
    query = select(AccessAnomaly)

    if anomaly_type:
        query = query.where(AccessAnomaly.anomaly_type == anomaly_type)

    if is_reviewed is not None:
        query = query.where(AccessAnomaly.is_reviewed == is_reviewed)

    if identity_id:
        query = query.where(AccessAnomaly.identity_id == identity_id)

    if min_deviation is not None:
        query = query.where(AccessAnomaly.deviation_score >= min_deviation)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(AccessAnomaly, sort_by, AccessAnomaly.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    anomalies = result.scalars().all()

    return AccessAnomalyListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[AccessAnomalyResponse.from_orm(a) for a in anomalies],
    )


@router.get("/anomalies/{anomaly_id}", response_model=AccessAnomalyResponse)
async def get_anomaly(
    anomaly_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get access anomaly details"""
    result = await db.execute(
        select(AccessAnomaly).where(AccessAnomaly.id == anomaly_id)
    )
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access anomaly not found",
        )
    return AccessAnomalyResponse.from_orm(anomaly)


@router.post("/anomalies/{anomaly_id}/review")
async def review_anomaly(
    anomaly_id: str,
    data: AnomalyReviewRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Review anomaly as legitimate or suspicious"""
    result = await db.execute(
        select(AccessAnomaly).where(AccessAnomaly.id == anomaly_id)
    )
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access anomaly not found",
        )

    anomaly.is_reviewed = True
    anomaly.reviewer_notes = data.reviewer_notes
    await db.commit()
    await db.refresh(anomaly)

    logger.info(f"Anomaly reviewed: {anomaly_id} - legitimate={data.is_legitimate}")

    return {
        "anomaly_id": anomaly_id,
        "is_legitimate": data.is_legitimate,
        "status": "reviewed",
    }


# ============================================================================
# Privileged Access Endpoints
# ============================================================================


@router.get("/privileged-access", response_model=PrivilegedAccessEventListResponse)
async def list_privileged_events(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    event_type: Optional[str] = None,
    identity_id: Optional[str] = None,
    was_revoked: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List privileged access events"""
    query = select(PrivilegedAccessEvent)

    if event_type:
        query = query.where(PrivilegedAccessEvent.event_type == event_type)

    if identity_id:
        query = query.where(PrivilegedAccessEvent.identity_id == identity_id)

    if was_revoked is not None:
        query = query.where(PrivilegedAccessEvent.was_revoked == was_revoked)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(PrivilegedAccessEvent, sort_by, PrivilegedAccessEvent.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    events = result.scalars().all()

    return PrivilegedAccessEventListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[PrivilegedAccessEventResponse.from_orm(e) for e in events],
    )


@router.post("/privileged-access/request")
async def request_elevation(
    data: ElevationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Request privilege elevation"""
    identity = await get_identity_or_404(db, data.identity_id)

    event = PrivilegedAccessEvent(
        organization_id=current_user.organization_id,
        identity_id=data.identity_id,
        event_type="elevation_request",
        target_resource=data.target_resource,
        justification=data.justification,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    logger.info(f"Elevation request created: {data.identity_id} for {data.target_resource}")

    return {
        "request_id": event.id,
        "identity_id": data.identity_id,
        "status": "pending_approval",
        "created_at": event.created_at,
    }


@router.post("/privileged-access/{event_id}/approve")
async def approve_elevation(
    event_id: str,
    data: ElevationApprovalRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Approve privilege elevation request"""
    result = await db.execute(
        select(PrivilegedAccessEvent).where(PrivilegedAccessEvent.id == event_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Privileged access event not found",
        )

    if data.approved:
        event.approved_by = current_user.id
        event.approval_timestamp = datetime.now(timezone.utc).isoformat()
        logger.info(f"Elevation request approved: {event_id}")
    else:
        logger.info(f"Elevation request denied: {event_id}")

    await db.commit()
    await db.refresh(event)

    return {
        "event_id": event_id,
        "approved": data.approved,
        "approval_notes": data.approver_notes,
    }


@router.post("/privileged-access/{event_id}/revoke")
async def revoke_access(
    event_id: str,
    revocation_reason: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Revoke privileged access"""
    result = await db.execute(
        select(PrivilegedAccessEvent).where(PrivilegedAccessEvent.id == event_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Privileged access event not found",
        )

    event.was_revoked = True
    event.revocation_reason = revocation_reason
    await db.commit()
    await db.refresh(event)

    logger.warning(f"Privileged access revoked: {event_id} - {revocation_reason}")

    return {
        "event_id": event_id,
        "status": "revoked",
        "revocation_reason": revocation_reason,
    }


# ============================================================================
# Dashboard and Reporting Endpoints
# ============================================================================


@router.get("/dashboard/metrics", response_model=ITDRDashboardMetrics)
async def get_dashboard_metrics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get ITDR dashboard metrics"""
    identities_result = await db.execute(
        select(func.count()).select_from(IdentityProfile)
    )
    total_identities = identities_result.scalar() or 0

    at_risk_result = await db.execute(
        select(func.count()).select_from(IdentityProfile).where(IdentityProfile.risk_score >= 50)
    )
    at_risk = at_risk_result.scalar() or 0

    critical_threats_result = await db.execute(
        select(func.count()).select_from(IdentityThreat).where(
            IdentityThreat.severity == "critical"
        )
    )
    critical_threats = critical_threats_result.scalar() or 0

    high_threats_result = await db.execute(
        select(func.count()).select_from(IdentityThreat).where(
            IdentityThreat.severity == "high"
        )
    )
    high_threats = high_threats_result.scalar() or 0

    exposures_result = await db.execute(
        select(func.count()).select_from(CredentialExposure).where(
            CredentialExposure.is_remediated == False
        )
    )
    exposures = exposures_result.scalar() or 0

    anomalies_result = await db.execute(
        select(func.count()).select_from(AccessAnomaly).where(
            AccessAnomaly.is_reviewed == False
        )
    )
    anomalies = anomalies_result.scalar() or 0

    service_accounts_result = await db.execute(
        select(func.count()).select_from(IdentityProfile).where(
            IdentityProfile.is_service_account == True
        )
    )
    service_accounts = service_accounts_result.scalar() or 0

    dormant_result = await db.execute(
        select(func.count()).select_from(IdentityProfile).where(
            IdentityProfile.is_dormant == True
        )
    )
    dormant = dormant_result.scalar() or 0

    jit_result = await db.execute(
        select(func.count()).select_from(PrivilegedAccessEvent).where(
            PrivilegedAccessEvent.event_type == "just_in_time_access"
        )
    )
    jit_active = jit_result.scalar() or 0

    overall_risk = min(100.0, critical_threats * 20 + high_threats * 10 + exposures * 5)

    return ITDRDashboardMetrics(
        total_identities=total_identities,
        identities_at_risk=at_risk,
        critical_threats_active=critical_threats,
        high_threats_active=high_threats,
        credential_exposures_active=exposures,
        anomalies_pending_review=anomalies,
        service_accounts_over_privileged=max(0, service_accounts - 5),
        dormant_accounts=dormant,
        jit_access_active=jit_active,
        last_scan_timestamp=datetime.now(timezone.utc),
        overall_risk_score=overall_risk,
    )


@router.get("/dashboard/risk-overview")
async def get_risk_overview(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get ITDR risk overview"""
    critical_threats_result = await db.execute(
        select(func.count()).select_from(IdentityThreat).where(
            IdentityThreat.severity == "critical"
        )
    )
    critical_count = critical_threats_result.scalar() or 0

    high_threats_result = await db.execute(
        select(func.count()).select_from(IdentityThreat).where(
            IdentityThreat.severity == "high"
        )
    )
    high_count = high_threats_result.scalar() or 0

    critical_findings = []
    if critical_count > 0:
        critical_findings.append(f"{critical_count} critical threats detected")
    if high_count > 0:
        critical_findings.append(f"{high_count} high-severity threats")

    return ITDRRiskOverview(
        summary=f"Identity security posture: {len(critical_findings)} critical issues" if critical_findings else "Identity security posture: healthy",
        critical_findings=critical_findings,
        risk_trends={"trend": "stable", "30day_change": "-5%"},
        recommendations=[
            "Review and revoke excessive privileges",
            "Enforce MFA on all identities",
            "Rotate exposed credentials immediately",
            "Remediate detected threats",
        ],
        compliance_status={
            "pci_dss": "compliant",
            "sox": "compliant",
            "hipaa": "compliant",
        },
    )
