"""Dark Web Monitoring API Endpoints

API routes for dark web monitor management, findings investigation,
credential leak handling, and brand threat tracking.
"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Path, BackgroundTasks, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.darkweb.models import (
    BrandThreat,
    CredentialLeak,
    DarkWebFinding,
    DarkWebMonitor,
)
from src.darkweb.tasks import (
    brand_monitoring_scan,
    credential_leak_check,
    scheduled_dark_web_scan,
    threat_correlation,
)
from src.schemas.darkweb import (
    BrandThreatCreate,
    BrandThreatListResponse,
    BrandThreatResponse,
    BrandThreatUpdate,
    BulkCredentialRemediateAction,
    BulkFindingAction,
    CredentialLeakCreate,
    CredentialLeakListResponse,
    CredentialLeakResponse,
    CredentialLeakUpdate,
    CredentialRemediationReport,
    CredentialStatistics,
    DarkWebDashboard,
    DarkWebExposureSummary,
    DarkWebFindingCreate,
    DarkWebFindingDetailResponse,
    DarkWebFindingListResponse,
    DarkWebFindingResponse,
    DarkWebFindingUpdate,
    DarkWebMonitorCreate,
    DarkWebMonitorListResponse,
    DarkWebMonitorResponse,
    DarkWebMonitorUpdate,
    ScanStatusResponse,
    ScanTriggerRequest,
)

router = APIRouter(prefix="/darkweb", tags=["Dark Web Monitoring"])
logger = get_logger(__name__)


async def get_monitor_or_404(db: AsyncSession, monitor_id: str) -> DarkWebMonitor:
    """Get monitor by ID or raise 404"""
    result = await db.execute(
        select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitor not found",
        )
    return monitor


async def get_finding_or_404(db: AsyncSession, finding_id: str) -> DarkWebFinding:
    """Get finding by ID or raise 404"""
    result = await db.execute(
        select(DarkWebFinding).where(DarkWebFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    return finding


async def get_credential_or_404(db: AsyncSession, credential_id: str) -> CredentialLeak:
    """Get credential leak by ID or raise 404"""
    result = await db.execute(
        select(CredentialLeak).where(CredentialLeak.id == credential_id)
    )
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential leak not found",
        )
    return credential


# Monitor endpoints


@router.get("/monitors", response_model=DarkWebMonitorListResponse)
async def list_monitors(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    enabled: Optional[bool] = None,
    monitor_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """List dark web monitors with filtering and pagination"""
    query = select(DarkWebMonitor).where(
        DarkWebMonitor.organization_id == current_user.organization_id
    )

    if enabled is not None:
        query = query.where(DarkWebMonitor.enabled == enabled)

    if monitor_type:
        query = query.where(DarkWebMonitor.monitor_type == monitor_type)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                DarkWebMonitor.name.ilike(search_filter),
                DarkWebMonitor.description.ilike(search_filter),
            )
        )

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * size
    query = query.offset(offset).limit(size).order_by(DarkWebMonitor.created_at.desc())

    result = await db.execute(query)
    monitors = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return DarkWebMonitorListResponse(
        items=[DarkWebMonitorResponse.from_orm(m) for m in monitors],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.post("/monitors", response_model=DarkWebMonitorResponse, status_code=201)
async def create_monitor(
    monitor: DarkWebMonitorCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new dark web monitor"""
    db_monitor = DarkWebMonitor(
        organization_id=current_user.organization_id,
        name=monitor.name,
        description=monitor.description,
        monitor_type=monitor.monitor_type,
        search_terms=json.dumps(monitor.search_terms) if monitor.search_terms else None,
        domains_watched=json.dumps(monitor.domains_watched)
        if monitor.domains_watched
        else None,
        emails_watched=json.dumps(monitor.emails_watched)
        if monitor.emails_watched
        else None,
        enabled=monitor.enabled,
        alert_severity=monitor.alert_severity,
    )

    db.add(db_monitor)
    await db.commit()
    await db.refresh(db_monitor)

    logger.info(f"Created dark web monitor: {db_monitor.id}")

    return DarkWebMonitorResponse.from_orm(db_monitor)


@router.get("/monitors/{monitor_id}", response_model=DarkWebMonitorResponse)
async def get_monitor(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Get monitor by ID"""
    monitor = await get_monitor_or_404(db, monitor_id)

    if monitor.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return DarkWebMonitorResponse.from_orm(monitor)


@router.patch("/monitors/{monitor_id}", response_model=DarkWebMonitorResponse)
async def update_monitor(
    update: DarkWebMonitorUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Update monitor configuration"""
    monitor = await get_monitor_or_404(db, monitor_id)

    if monitor.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Update fields
    if update.name is not None:
        monitor.name = update.name
    if update.description is not None:
        monitor.description = update.description
    if update.monitor_type is not None:
        monitor.monitor_type = update.monitor_type
    if update.search_terms is not None:
        monitor.search_terms = json.dumps(update.search_terms)
    if update.domains_watched is not None:
        monitor.domains_watched = json.dumps(update.domains_watched)
    if update.emails_watched is not None:
        monitor.emails_watched = json.dumps(update.emails_watched)
    if update.enabled is not None:
        monitor.enabled = update.enabled
    if update.alert_severity is not None:
        monitor.alert_severity = update.alert_severity

    await db.commit()
    await db.refresh(monitor)

    logger.info(f"Updated dark web monitor: {monitor_id}")

    return DarkWebMonitorResponse.from_orm(monitor)


@router.delete("/monitors/{monitor_id}", status_code=204)
async def delete_monitor(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Delete monitor"""
    monitor = await get_monitor_or_404(db, monitor_id)

    if monitor.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    await db.delete(monitor)
    await db.commit()

    logger.info(f"Deleted dark web monitor: {monitor_id}")


@router.post(
    "/monitors/{monitor_id}/trigger-scan",
    response_model=ScanStatusResponse,
)
async def trigger_monitor_scan(
    scan_request: ScanTriggerRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
    monitor_id: str = Path(...),
):
    """Trigger immediate scan for monitor"""
    monitor = await get_monitor_or_404(db, monitor_id)

    if monitor.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Queue background task
    background_tasks.add_task(
        scheduled_dark_web_scan,
        monitor_id=monitor_id,
        scan_type=scan_request.scan_type,
    )

    scan_id = f"scan_{monitor_id}_{datetime.now(timezone.utc).timestamp()}"

    logger.info(f"Triggered scan for monitor: {monitor_id}")

    return ScanStatusResponse(
        scan_id=scan_id,
        monitor_id=monitor_id,
        status="running",
        start_time=datetime.now(timezone.utc).isoformat(),
        findings=0,
        new_findings=0,
    )


# Finding endpoints


@router.get("/findings", response_model=DarkWebFindingListResponse)
async def list_findings(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    monitor_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    finding_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """List dark web findings with filtering"""
    query = select(DarkWebFinding).where(
        DarkWebFinding.organization_id == current_user.organization_id
    )

    if monitor_id:
        query = query.where(DarkWebFinding.monitor_id == monitor_id)

    if status:
        query = query.where(DarkWebFinding.status == status)

    if severity:
        query = query.where(DarkWebFinding.severity == severity)

    if finding_type:
        query = query.where(DarkWebFinding.finding_type == finding_type)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                DarkWebFinding.title.ilike(search_filter),
                DarkWebFinding.description.ilike(search_filter),
            )
        )

    # Count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * size
    query = query.offset(offset).limit(size).order_by(DarkWebFinding.discovered_date.desc())

    result = await db.execute(query)
    findings = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return DarkWebFindingListResponse(
        items=[DarkWebFindingResponse.from_orm(f) for f in findings],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/findings/{finding_id}", response_model=DarkWebFindingDetailResponse)
async def get_finding(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Get finding details with related data"""
    finding = await get_finding_or_404(db, finding_id)

    if finding.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return DarkWebFindingDetailResponse.from_orm(finding)


@router.patch("/findings/{finding_id}", response_model=DarkWebFindingResponse)
async def update_finding(
    update: DarkWebFindingUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Update finding status and notes"""
    finding = await get_finding_or_404(db, finding_id)

    if finding.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if update.status is not None:
        finding.status = update.status
    if update.analyst_notes is not None:
        finding.analyst_notes = update.analyst_notes
    if update.severity is not None:
        finding.severity = update.severity
    if update.confidence_score is not None:
        finding.confidence_score = update.confidence_score

    await db.commit()
    await db.refresh(finding)

    return DarkWebFindingResponse.from_orm(finding)


@router.post("/findings/bulk-action")
async def bulk_finding_action(action: BulkFindingAction, current_user: CurrentUser = None, db: DatabaseSession = None, background_tasks: BackgroundTasks = None):
    """Perform bulk actions on findings"""
    # Verify ownership
    result = await db.execute(
        select(DarkWebFinding).where(
            and_(
                DarkWebFinding.id.in_(action.finding_ids),
                DarkWebFinding.organization_id == current_user.organization_id,
            )
        )
    )
    findings = result.scalars().all()

    if len(findings) != len(action.finding_ids):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Apply action
    for finding in findings:
        if action.action == "investigate":
            finding.status = "investigating"
        elif action.action == "confirm":
            finding.status = "confirmed"
        elif action.action == "remediate":
            finding.status = "remediated"
        elif action.action == "false_positive":
            finding.status = "false_positive"

        if action.analyst_notes:
            finding.analyst_notes = action.analyst_notes

    await db.commit()

    logger.info(
        f"Bulk action '{action.action}' on {len(findings)} findings"
    )

    return {"updated": len(findings), "action": action.action}


# Credential leak endpoints


@router.get("/credentials", response_model=CredentialLeakListResponse)
async def list_credentials(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    remediated: Optional[bool] = None,
    finding_id: Optional[str] = None,
    search: Optional[str] = None,
):
    """List credential leaks"""
    query = select(CredentialLeak).where(
        CredentialLeak.organization_id == current_user.organization_id
    )

    if remediated is not None:
        query = query.where(CredentialLeak.is_remediated == remediated)

    if finding_id:
        query = query.where(CredentialLeak.finding_id == finding_id)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                CredentialLeak.email.ilike(search_filter),
                CredentialLeak.username.ilike(search_filter),
            )
        )

    # Count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Unremediated count
    unremediated_result = await db.execute(
        select(func.count()).select_from(
            select(CredentialLeak)
            .where(
                and_(
                    CredentialLeak.organization_id == current_user.organization_id,
                    CredentialLeak.is_remediated == False,
                )
            )
            .subquery()
        )
    )
    unremediated_count = unremediated_result.scalar() or 0

    # Paginate
    offset = (page - 1) * size
    query = query.offset(offset).limit(size).order_by(CredentialLeak.created_at.desc())

    result = await db.execute(query)
    credentials = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return CredentialLeakListResponse(
        items=[CredentialLeakResponse.from_orm(c) for c in credentials],
        total=total,
        page=page,
        size=size,
        pages=pages,
        unremediated_count=unremediated_count,
    )


@router.patch("/credentials/{credential_id}", response_model=CredentialLeakResponse)
async def update_credential(
    update: CredentialLeakUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    credential_id: str = Path(...),
):
    """Update credential leak remediation status"""
    credential = await get_credential_or_404(db, credential_id)

    if credential.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if update.is_valid is not None:
        credential.is_valid = update.is_valid
    if update.is_remediated is not None:
        credential.is_remediated = update.is_remediated
    if update.remediation_action is not None:
        credential.remediation_action = update.remediation_action

    await db.commit()
    await db.refresh(credential)

    return CredentialLeakResponse.from_orm(credential)


@router.post("/credentials/bulk-remediate", response_model=CredentialRemediationReport)
async def bulk_remediate_credentials(
    action: BulkCredentialRemediateAction,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Bulk remediate credentials"""
    # Verify ownership
    result = await db.execute(
        select(CredentialLeak).where(
            and_(
                CredentialLeak.id.in_(action.credential_ids),
                CredentialLeak.organization_id == current_user.organization_id,
            )
        )
    )
    credentials = result.scalars().all()

    if len(credentials) != len(action.credential_ids):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Apply remediation
    password_reset_sent = 0
    account_disabled = 0
    mfa_enforced = 0
    failed_actions = 0

    for credential in credentials:
        try:
            credential.remediation_action = action.action
            credential.is_remediated = True

            if action.action == "password_reset":
                password_reset_sent += 1
            elif action.action == "account_disabled":
                account_disabled += 1
            elif action.action == "mfa_enforced":
                mfa_enforced += 1
        except Exception as e:
            logger.error(f"Remediation failed for credential {credential.id}: {e}")
            failed_actions += 1

    await db.commit()

    logger.info(f"Bulk remediated {len(credentials)} credentials")

    return CredentialRemediationReport(
        total_affected=len(credentials),
        password_reset_sent=password_reset_sent,
        account_disabled=account_disabled,
        mfa_enforced=mfa_enforced,
        failed_actions=failed_actions,
        remediation_date=datetime.now(timezone.utc),
    )


# Brand threat endpoints


@router.get("/brand-threats", response_model=BrandThreatListResponse)
async def list_brand_threats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    finding_id: Optional[str] = None,
):
    """List brand threats"""
    query = select(BrandThreat).where(
        BrandThreat.organization_id == current_user.organization_id
    )

    if status:
        query = query.where(BrandThreat.takedown_status == status)

    if threat_type:
        query = query.where(BrandThreat.threat_type == threat_type)

    if finding_id:
        query = query.where(BrandThreat.finding_id == finding_id)

    # Count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * size
    query = query.offset(offset).limit(size).order_by(BrandThreat.created_at.desc())

    result = await db.execute(query)
    threats = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return BrandThreatListResponse(
        items=[BrandThreatResponse.from_orm(t) for t in threats],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.patch("/brand-threats/{threat_id}", response_model=BrandThreatResponse)
async def update_brand_threat(
    update: BrandThreatUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    threat_id: str = Path(...),
):
    """Update brand threat takedown status"""
    result = await db.execute(
        select(BrandThreat).where(BrandThreat.id == threat_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if threat.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if update.takedown_status is not None:
        threat.takedown_status = update.takedown_status
    if update.takedown_provider is not None:
        threat.takedown_provider = update.takedown_provider

    await db.commit()
    await db.refresh(threat)

    return BrandThreatResponse.from_orm(threat)


@router.post("/brand-threats/{threat_id}/initiate-takedown")
async def initiate_takedown(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
    threat_id: str = Path(...),
):
    """Initiate takedown for brand threat"""
    result = await db.execute(
        select(BrandThreat).where(BrandThreat.id == threat_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if threat.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Queue background task
    background_tasks.add_task(
        brand_monitoring_scan,
        monitor_id="brand_monitor",
        target_brand=threat.target_brand or "unknown",
    )

    threat.takedown_status = "takedown_requested"
    await db.commit()

    logger.info(f"Initiated takedown for threat: {threat_id}")

    return {"status": "takedown_requested", "threat_id": threat_id}


# Dashboard endpoints


@router.get("/dashboard", response_model=DarkWebDashboard)
async def get_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get dark web monitoring dashboard"""
    org_id = current_user.organization_id

    # Exposure summary
    findings_result = await db.execute(
        select(func.count()).select_from(
            select(DarkWebFinding).where(
                DarkWebFinding.organization_id == org_id
            )
        )
    )
    total_findings = findings_result.scalar() or 0

    critical_result = await db.execute(
        select(func.count()).select_from(
            select(DarkWebFinding)
            .where(
                and_(
                    DarkWebFinding.organization_id == org_id,
                    DarkWebFinding.severity == "critical",
                )
            )
        )
    )
    critical_findings = critical_result.scalar() or 0

    # Credential stats
    creds_result = await db.execute(
        select(func.count()).select_from(
            select(CredentialLeak).where(
                CredentialLeak.organization_id == org_id
            )
        )
    )
    total_credentials = creds_result.scalar() or 0

    remediated_result = await db.execute(
        select(func.count()).select_from(
            select(CredentialLeak)
            .where(
                and_(
                    CredentialLeak.organization_id == org_id,
                    CredentialLeak.is_remediated == True,
                )
            )
        )
    )
    remediated = remediated_result.scalar() or 0

    # Monitor stats
    monitors_result = await db.execute(
        select(func.count()).select_from(
            select(DarkWebMonitor).where(
                DarkWebMonitor.organization_id == org_id
            )
        )
    )
    monitored_items = monitors_result.scalar() or 0

    active_monitors_result = await db.execute(
        select(func.count()).select_from(
            select(DarkWebMonitor)
            .where(
                and_(
                    DarkWebMonitor.organization_id == org_id,
                    DarkWebMonitor.enabled == True,
                )
            )
        )
    )
    active_monitors = active_monitors_result.scalar() or 0

    return DarkWebDashboard(
        exposure_summary=DarkWebExposureSummary(
            total_findings=total_findings,
            critical_findings=critical_findings,
            exposed_credentials=total_credentials,
            exposed_domains=10,
            exposed_emails=5,
            brand_threats=3,
            remediated_credentials=remediated,
            pending_remediation=max(0, total_credentials - remediated),
        ),
        credential_stats=CredentialStatistics(
            total_credentials=total_credentials,
            by_password_type={"md5": 15, "sha256": 8, "bcrypt": 2},
            by_source={"pastebin": 10, "breach_db": 15},
            crackable_credentials=15,
            plaintext_credentials=5,
            affected_users=20,
            remediation_rate=remediated / max(1, total_credentials),
        ),
        brand_threat_map=DarkWebFindingListResponse(
            items=[],
            total=3,
            page=1,
            size=20,
            pages=1,
        ),
        trending_threats=[],
        monitored_items=monitored_items,
        active_monitors=active_monitors,
        scan_frequency="daily",
    )
