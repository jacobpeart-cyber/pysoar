"""
ITDR (Identity Threat Detection & Response) API Endpoints

Provides REST API for identity threat detection, credential monitoring,
access anomaly analysis, and privileged access management.
"""

import math
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status, BackgroundTasks
import json

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.services.automation import AutomationService
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

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(IdentityProfile.organization_id == org_id)

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
        items=[IdentityProfileResponse.model_validate(i) for i in identities],
    )


@router.get("/identities/{identity_id}", response_model=IdentityProfileResponse)
async def get_identity(
    identity_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get identity profile details"""
    identity = await get_identity_or_404(db, identity_id)
    return IdentityProfileResponse.model_validate(identity)


@router.post("/identities", response_model=IdentityProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_identity(
    data: IdentityProfileCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create new identity profile"""
    identity = IdentityProfile(
        organization_id=getattr(current_user, "organization_id", None),
        **data.dict()
    )
    db.add(identity)
    await db.commit()
    await db.refresh(identity)
    logger.info(f"Identity created: {identity.username}")
    return IdentityProfileResponse.model_validate(identity)


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
    return IdentityProfileResponse.model_validate(identity)


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

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(IdentityThreat.organization_id == org_id)

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
        items=[IdentityThreatResponse.model_validate(t) for t in threats],
    )


@router.get("/threats/{threat_id}", response_model=IdentityThreatResponse)
async def get_threat(
    threat_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get identity threat details"""
    threat = await get_threat_or_404(db, threat_id)
    return IdentityThreatResponse.model_validate(threat)


@router.post("/threats", response_model=IdentityThreatResponse, status_code=status.HTTP_201_CREATED)
async def create_threat(
    data: IdentityThreatCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create new identity threat"""
    threat_data = data.dict()
    # Convert empty identity_id to None to avoid FK violation
    if not threat_data.get("identity_id"):
        threat_data["identity_id"] = None
    threat = IdentityThreat(
        organization_id=getattr(current_user, "organization_id", None),
        **threat_data
    )
    db.add(threat)
    await db.commit()
    await db.refresh(threat)

    # Trigger automation rules
    try:
        org_id = getattr(current_user, "organization_id", None)
        automation = AutomationService(db)
        await automation.on_itdr_threat(
            threat_type=threat.threat_type,
            identity=threat.identity_id or "unknown",
            risk_level=threat.severity or "high",
            organization_id=org_id,
        )
    except Exception as e:
        logger.error(f"Automation failed for ITDR threat {threat.id}: {e}")

    logger.warning(f"Identity threat created: {threat.threat_type} ({threat.severity})")
    return IdentityThreatResponse.model_validate(threat)


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
    return IdentityThreatResponse.model_validate(threat)


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
    db: DatabaseSession = None,
):
    """Run identity threat detection scan synchronously.

    Previously returned a fake scan_id and claimed work was happening
    in the background — nothing actually ran. Now scans every
    IdentityProfile in the caller's organization for three real
    risk signals and creates IdentityThreat rows for each hit:

      - **dormant_admin**: is_dormant == True AND role contains "admin"
      - **mfa_missing_privileged**: mfa_enabled == False AND
        role contains "admin" or "root" or is_privileged == True
      - **stale_credential**: last_password_change older than 180 days

    Already-open threats of the same type on the same identity are
    skipped so re-running the scan is idempotent within its cooldown
    window. The dropped ``organization_id`` query parameter was a
    cross-tenant vector — we now always use current_user.organization_id.
    """
    from src.itdr.models import ThreatStatus, PrivilegeLevel

    org_id = getattr(current_user, "organization_id", None)
    logger.info(f"Running identity threat scan for org={org_id}")

    now = datetime.now(timezone.utc)
    cutoff_180d = now - timedelta(days=180)

    id_query = select(IdentityProfile)
    if org_id:
        id_query = id_query.where(IdentityProfile.organization_id == org_id)
    identities = list((await db.execute(id_query)).scalars().all())

    # Preload open threats so we can dedupe
    existing_q = select(IdentityThreat).where(
        IdentityThreat.status.in_([
            ThreatStatus.DETECTED.value,
            ThreatStatus.INVESTIGATING.value,
        ])
    )
    if org_id:
        existing_q = existing_q.where(IdentityThreat.organization_id == org_id)
    existing_rows = list((await db.execute(existing_q)).scalars().all())
    existing_by_identity: dict[str, set[str]] = {}
    for t in existing_rows:
        existing_by_identity.setdefault(t.identity_id, set()).add(t.threat_type)

    def _create_threat(
        identity_id: str,
        threat_type: str,
        severity: str,
        evidence: dict,
    ) -> bool:
        if threat_type in existing_by_identity.get(identity_id, set()):
            return False
        threat = IdentityThreat(
            organization_id=org_id,
            identity_id=identity_id,
            threat_type=threat_type,
            severity=severity,
            confidence_score=0.9,
            evidence=evidence,
            status=ThreatStatus.DETECTED.value,
        )
        db.add(threat)
        return True

    def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
        """IdentityProfile stores last_password_change as an ISO
        string rather than a DateTime column, so normalize it here."""
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    scanned = len(identities)
    created = 0
    for identity in identities:
        # role_assignments is a JSON list on the model, not a scalar role.
        role_list = getattr(identity, "role_assignments", None) or []
        if isinstance(role_list, str):
            try:
                role_list = json.loads(role_list)
            except Exception:  # noqa: BLE001
                role_list = []
        roles_lower = [str(r).lower() for r in role_list] if isinstance(role_list, list) else []
        has_admin_role = any(("admin" in r or "root" in r) for r in roles_lower)

        privilege_level = (getattr(identity, "privilege_level", "") or "").lower()
        is_privileged = has_admin_role or privilege_level in (
            PrivilegeLevel.ADMIN.value if hasattr(PrivilegeLevel, "ADMIN") else "admin",
            "privileged",
            "root",
            "super",
        )

        # 1) dormant_admin
        if getattr(identity, "is_dormant", False) and has_admin_role:
            if _create_threat(
                identity.id,
                "dormant_admin",
                "high",
                {
                    "username": identity.username,
                    "roles": role_list,
                    "reason": "dormant account retains admin privileges",
                },
            ):
                created += 1

        # 2) mfa_missing_privileged
        if is_privileged and not getattr(identity, "mfa_enabled", False):
            if _create_threat(
                identity.id,
                "mfa_missing_privileged",
                "critical",
                {
                    "username": identity.username,
                    "privilege_level": privilege_level,
                    "reason": "privileged identity has no MFA enrolled",
                },
            ):
                created += 1

        # 3) stale_credential (password > 180 days old)
        last_pw = _parse_iso(getattr(identity, "last_password_change", None))
        if last_pw is not None and last_pw < cutoff_180d:
            age_days = (now - last_pw).days
            if _create_threat(
                identity.id,
                "stale_credential",
                "medium",
                {
                    "username": identity.username,
                    "last_password_change": last_pw.isoformat(),
                    "age_days": age_days,
                },
            ):
                created += 1

    await db.flush()

    logger.info(
        f"Identity threat scan complete: scanned={scanned} created={created}"
    )
    return {
        "status": "completed",
        "organization_id": org_id,
        "identities_scanned": scanned,
        "threats_created": created,
        "completed_at": now.isoformat(),
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

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(CredentialExposure.organization_id == org_id)

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
        items=[CredentialExposureResponse.model_validate(e) for e in exposures],
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
    return CredentialExposureResponse.model_validate(exposure)


@router.post("/credential-exposures/check")
async def check_credential_exposure(
    identity_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Check an identity's credentials against known exposure sources.

    Queries the ``darkweb_credential_leaks`` table for any leaks that
    match this identity's email or username, and creates a new
    ``CredentialExposure`` row for each unique hit that isn't already
    tracked for this identity. Returns the number of new exposures
    found plus the existing ones so the operator can act immediately.

    Previous version just returned ``{"status": "check_initiated"}``
    and did nothing — the button was theater.
    """
    from src.darkweb.models import CredentialLeak

    identity = await get_identity_or_404(db, identity_id)
    org_id = getattr(current_user, "organization_id", None)

    # Match leaks by email OR username (case-insensitive)
    email = (identity.email or "").lower()
    username = (identity.username or "").lower()

    leak_query = select(CredentialLeak).where(
        CredentialLeak.organization_id == org_id
    )
    if email or username:
        conditions = []
        if email:
            conditions.append(func.lower(CredentialLeak.email) == email)
        if username:
            conditions.append(func.lower(CredentialLeak.username) == username)
        leak_query = leak_query.where(or_(*conditions))
    else:
        leak_query = leak_query.where(CredentialLeak.email.is_(None))  # no-op

    leak_rows = list((await db.execute(leak_query)).scalars().all())

    # Dedupe against existing CredentialExposure rows for this identity
    existing_q = select(CredentialExposure).where(
        and_(
            CredentialExposure.organization_id == org_id,
            CredentialExposure.identity_id == identity_id,
        )
    )
    existing = list((await db.execute(existing_q)).scalars().all())
    existing_sources = {
        f"{e.exposure_source}:{e.breach_name or ''}" for e in existing
    }

    new_exposures: list[CredentialExposure] = []
    for leak in leak_rows:
        key = f"darkweb:{leak.breach_source or ''}"
        if key in existing_sources:
            continue
        exposure = CredentialExposure(
            organization_id=org_id,
            identity_id=identity_id,
            exposure_source="darkweb",
            credential_type=leak.password_type or "password",
            exposure_date=leak.breach_date,
            discovery_date=datetime.now(timezone.utc).isoformat(),
            breach_name=leak.breach_source,
            is_remediated=leak.is_remediated,
        )
        db.add(exposure)
        new_exposures.append(exposure)
        existing_sources.add(key)

    await db.flush()

    logger.info(
        f"Credential exposure check for {identity_id}: "
        f"{len(leak_rows)} leaks matched, {len(new_exposures)} new exposures created"
    )

    return {
        "status": "completed",
        "identity_id": identity_id,
        "leaks_matched": len(leak_rows),
        "new_exposures_created": len(new_exposures),
        "total_exposures_now": len(existing) + len(new_exposures),
        "sources_checked": ["darkweb_credential_leaks"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/credential-exposures/remediate")
async def remediate_exposures(
    data: CredentialRemediationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Mark credential exposures as remediated and record the action.

    Previously returned ``remediation_initiated`` without touching the
    database — the exposure rows stayed unremediated forever. Now
    updates each CredentialExposure row with ``is_remediated=True``,
    the remediation_action string, and a remediation_date stamp.
    Only exposures belonging to the caller's org are touched, so one
    tenant can't remediate another tenant's exposures.
    """
    org_id = getattr(current_user, "organization_id", None)
    now_iso = datetime.now(timezone.utc).isoformat()

    updated_count = 0
    skipped_count = 0

    if not data.exposure_ids:
        return {
            "status": "no_exposures_provided",
            "updated": 0,
            "skipped": 0,
        }

    query = select(CredentialExposure).where(
        and_(
            CredentialExposure.id.in_(data.exposure_ids),
            CredentialExposure.organization_id == org_id,
        )
    )
    exposures = list((await db.execute(query)).scalars().all())

    for exposure in exposures:
        if exposure.is_remediated:
            skipped_count += 1
            continue
        exposure.is_remediated = True
        exposure.remediation_date = now_iso
        exposure.remediation_action = data.remediation_type
        updated_count += 1

    # Any IDs the caller supplied that didn't belong to this org or
    # didn't exist get counted as skipped so the operator can see they
    # were ignored rather than silently succeeded.
    missing = set(data.exposure_ids) - {e.id for e in exposures}
    skipped_count += len(missing)

    await db.flush()

    logger.info(
        f"Credential remediation: updated={updated_count} skipped={skipped_count}"
    )

    return {
        "status": "completed",
        "updated": updated_count,
        "skipped": skipped_count,
        "remediation_type": data.remediation_type,
        "timestamp": now_iso,
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

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(AccessAnomaly.organization_id == org_id)

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
        items=[AccessAnomalyResponse.model_validate(a) for a in anomalies],
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
    return AccessAnomalyResponse.model_validate(anomaly)


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

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(PrivilegedAccessEvent.organization_id == org_id)

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
        items=[PrivilegedAccessEventResponse.model_validate(e) for e in events],
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
        organization_id=getattr(current_user, "organization_id", None),
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
    org_id = getattr(current_user, "organization_id", None)

    identity_base = select(func.count()).select_from(IdentityProfile)
    threat_base = select(func.count()).select_from(IdentityThreat)
    exposure_base = select(func.count()).select_from(CredentialExposure)
    anomaly_base = select(func.count()).select_from(AccessAnomaly)
    priv_base = select(func.count()).select_from(PrivilegedAccessEvent)

    if org_id:
        identity_base = identity_base.where(IdentityProfile.organization_id == org_id)
        threat_base = threat_base.where(IdentityThreat.organization_id == org_id)
        exposure_base = exposure_base.where(CredentialExposure.organization_id == org_id)
        anomaly_base = anomaly_base.where(AccessAnomaly.organization_id == org_id)
        priv_base = priv_base.where(PrivilegedAccessEvent.organization_id == org_id)

    identities_result = await db.execute(identity_base)
    total_identities = identities_result.scalar() or 0

    at_risk_result = await db.execute(
        identity_base.where(IdentityProfile.risk_score >= 50)
    )
    at_risk = at_risk_result.scalar() or 0

    critical_threats_result = await db.execute(
        threat_base.where(IdentityThreat.severity == "critical")
    )
    critical_threats = critical_threats_result.scalar() or 0

    high_threats_result = await db.execute(
        threat_base.where(IdentityThreat.severity == "high")
    )
    high_threats = high_threats_result.scalar() or 0

    exposures_result = await db.execute(
        exposure_base.where(CredentialExposure.is_remediated == False)
    )
    exposures = exposures_result.scalar() or 0

    anomalies_result = await db.execute(
        anomaly_base.where(AccessAnomaly.is_reviewed == False)
    )
    anomalies = anomalies_result.scalar() or 0

    service_accounts_result = await db.execute(
        identity_base.where(IdentityProfile.is_service_account == True)
    )
    service_accounts = service_accounts_result.scalar() or 0

    dormant_result = await db.execute(
        identity_base.where(IdentityProfile.is_dormant == True)
    )
    dormant = dormant_result.scalar() or 0

    jit_result = await db.execute(
        priv_base.where(PrivilegedAccessEvent.event_type == "just_in_time_access")
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
    """Get ITDR risk overview with real trend + compliance data.

    Previous version returned hardcoded ``risk_trends: {"trend":
    "stable", "30day_change": "-5%"}`` and
    ``compliance_status: {pci_dss: compliant, sox: compliant,
    hipaa: compliant}`` regardless of actual posture. A compliance
    officer seeing "everything compliant" on a tenant that hasn't
    even loaded a framework would have caught the lie immediately.

    Now:
      - ``risk_trends.30day_change`` compares threat count in the
        last 30 days vs the prior 30 days and reports real delta.
      - ``compliance_status`` queries ComplianceFramework rows scoped
        to this org and reports each framework's real ``status``
        column value. If no framework is loaded, the key is absent
        rather than falsely claiming compliant.
    """
    org_id = getattr(current_user, "organization_id", None)

    threat_base = select(func.count()).select_from(IdentityThreat)
    if org_id:
        threat_base = threat_base.where(IdentityThreat.organization_id == org_id)

    critical_threats_result = await db.execute(
        threat_base.where(IdentityThreat.severity == "critical")
    )
    critical_count = critical_threats_result.scalar() or 0

    high_threats_result = await db.execute(
        threat_base.where(IdentityThreat.severity == "high")
    )
    high_count = high_threats_result.scalar() or 0

    critical_findings = []
    if critical_count > 0:
        critical_findings.append(f"{critical_count} critical threats detected")
    if high_count > 0:
        critical_findings.append(f"{high_count} high-severity threats")

    # --- Real 30-day trend comparison ---
    now = datetime.now(timezone.utc)
    last_30_start = now - timedelta(days=30)
    prior_30_start = now - timedelta(days=60)

    last_30_q = threat_base.where(
        IdentityThreat.created_at >= last_30_start
    )
    prior_30_q = threat_base.where(
        and_(
            IdentityThreat.created_at >= prior_30_start,
            IdentityThreat.created_at < last_30_start,
        )
    )
    last_30_count = (await db.execute(last_30_q)).scalar() or 0
    prior_30_count = (await db.execute(prior_30_q)).scalar() or 0

    if prior_30_count == 0 and last_30_count == 0:
        trend_label = "stable"
        change_pct_str = "0%"
    elif prior_30_count == 0:
        trend_label = "rising"
        change_pct_str = "+new"  # no prior baseline to compare against
    else:
        delta = last_30_count - prior_30_count
        change = (delta / prior_30_count) * 100.0
        change_pct_str = f"{'+' if change >= 0 else ''}{change:.0f}%"
        if change > 10:
            trend_label = "rising"
        elif change < -10:
            trend_label = "improving"
        else:
            trend_label = "stable"

    # --- Real compliance_status ---
    compliance_status: dict[str, str] = {}
    try:
        from src.compliance.models import ComplianceFramework
        fw_q = select(ComplianceFramework)
        if org_id:
            fw_q = fw_q.where(ComplianceFramework.organization_id == org_id)
        for fw in (await db.execute(fw_q)).scalars().all():
            if fw.short_name:
                compliance_status[fw.short_name] = fw.status or "unknown"
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"compliance_status lookup failed: {exc}")

    return ITDRRiskOverview(
        summary=(
            f"Identity security posture: {len(critical_findings)} critical issues"
            if critical_findings
            else "Identity security posture: healthy"
        ),
        critical_findings=critical_findings,
        risk_trends={
            "trend": trend_label,
            "30day_change": change_pct_str,
            "threats_last_30d": last_30_count,
            "threats_prior_30d": prior_30_count,
        },
        recommendations=[
            "Review and revoke excessive privileges",
            "Enforce MFA on all identities",
            "Rotate exposed credentials immediately",
            "Remediate detected threats",
        ],
        compliance_status=compliance_status,
    )
