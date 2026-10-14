"""Dark Web Monitoring API Endpoints

API routes for dark web monitor management, findings investigation,
credential leak handling, and brand threat tracking.
"""

import math
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Path, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.models.user import User, UserRole
from src.services.automation import AutomationService
from src.darkweb.models import (
    BrandThreat,
    CredentialLeak,
    DarkWebFinding,
    DarkWebMonitor,
)
from src.darkweb.tasks import (
    credential_leak_check,
    threat_correlation,
)
from src.schemas.darkweb import (
    BrandThreatCreate,
    BrandThreatListResponse,
    BrandThreatMap,
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
    TrendingThreats,
)

router = APIRouter(prefix="/darkweb", tags=["Dark Web Monitoring"])
logger = get_logger(__name__)

# Tenancy and roles (wave 1, docs/audit/2026-10-08/PLAN.md): every monitor,
# finding, credential leak and brand threat belongs to one organisation; every
# query filters on the caller's OrganizationId, every created row is stamped
# with it and lookups by id outside the tenant 404. Monitor configuration and
# scans require admin; finding / credential / brand-threat triage (update,
# escalate, notify, bulk actions, takedown requests) requires analyst or admin;
# viewers are read-only.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


async def get_monitor_or_404(
    db: AsyncSession, monitor_id: str, org_id: str
) -> DarkWebMonitor:
    """Get monitor by ID or raise 404"""
    stmt = select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id)
    stmt = stmt.where(DarkWebMonitor.organization_id == org_id)
    result = await db.execute(stmt)
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitor not found",
        )
    return monitor


async def get_finding_or_404(
    db: AsyncSession, finding_id: str, org_id: str
) -> DarkWebFinding:
    """Get finding by ID or raise 404"""
    stmt = select(DarkWebFinding).where(DarkWebFinding.id == finding_id)
    stmt = stmt.where(DarkWebFinding.organization_id == org_id)
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    return finding


async def get_credential_or_404(
    db: AsyncSession, credential_id: str, org_id: str
) -> CredentialLeak:
    """Get credential leak by ID or raise 404"""
    stmt = select(CredentialLeak).where(CredentialLeak.id == credential_id)
    stmt = stmt.where(CredentialLeak.organization_id == org_id)
    result = await db.execute(stmt)
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    enabled: Optional[bool] = None,
    monitor_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """List dark web monitors with filtering and pagination"""
    query = select(DarkWebMonitor).where(
        DarkWebMonitor.organization_id == org_id
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
        items=[DarkWebMonitorResponse.model_validate(m) for m in monitors],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.post("/monitors", response_model=DarkWebMonitorResponse, status_code=201)
async def create_monitor(
    monitor: DarkWebMonitorCreate,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create a new dark web monitor"""
    db_monitor = DarkWebMonitor(
        organization_id=org_id,
        name=monitor.name,
        description=monitor.description,
        monitor_type=monitor.monitor_type,
        search_terms=monitor.search_terms or None,
        domains_watched=monitor.domains_watched or None,
        emails_watched=monitor.emails_watched or None,
        enabled=monitor.enabled,
        alert_severity=monitor.alert_severity,
    )

    db.add(db_monitor)
    await db.commit()
    await db.refresh(db_monitor)

    logger.info(f"Created dark web monitor: {db_monitor.id}")

    return DarkWebMonitorResponse.model_validate(db_monitor)


@router.get("/monitors/{monitor_id}", response_model=DarkWebMonitorResponse)
async def get_monitor(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Get monitor by ID"""
    monitor = await get_monitor_or_404(
        db, monitor_id, org_id
    )

    return DarkWebMonitorResponse.model_validate(monitor)


@router.patch("/monitors/{monitor_id}", response_model=DarkWebMonitorResponse)
async def update_monitor(
    update: DarkWebMonitorUpdate,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Update monitor configuration"""
    monitor = await get_monitor_or_404(
        db, monitor_id, org_id
    )

    # Update fields
    if update.name is not None:
        monitor.name = update.name
    if update.description is not None:
        monitor.description = update.description
    if update.monitor_type is not None:
        monitor.monitor_type = update.monitor_type
    if update.search_terms is not None:
        monitor.search_terms = update.search_terms
    if update.domains_watched is not None:
        monitor.domains_watched = update.domains_watched
    if update.emails_watched is not None:
        monitor.emails_watched = update.emails_watched
    if update.enabled is not None:
        monitor.enabled = update.enabled
    if update.alert_severity is not None:
        monitor.alert_severity = update.alert_severity

    await db.commit()
    await db.refresh(monitor)

    logger.info(f"Updated dark web monitor: {monitor_id}")

    return DarkWebMonitorResponse.model_validate(monitor)


@router.delete("/monitors/{monitor_id}", status_code=204)
async def delete_monitor(
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Delete monitor"""
    monitor = await get_monitor_or_404(
        db, monitor_id, org_id
    )

    await db.delete(monitor)
    await db.commit()

    logger.info(f"Deleted dark web monitor: {monitor_id}")


@router.post(
    "/monitors/{monitor_id}/trigger-scan",
    response_model=ScanStatusResponse,
)
async def trigger_monitor_scan(
    scan_request: ScanTriggerRequest,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Scan this monitor's own terms now and persist new findings.

    Runs ``src.darkweb.monitor_scan.scan_monitor`` inline (the same code as
    the scheduled sweep): HIBP lookups for the watched emails (with
    ``HIBP_API_KEY``) and domains, plus HIBP-catalogue and threat-feed items
    (URLhaus, ThreatFox, OTX, the operator marketplace feed) that mention
    one of the monitor's terms. ``sources`` reports every source's status;
    a source without its key is ``not_configured``, never silently empty.
    ``quick`` consults the HIBP sources only.

    Answers 502 ``darkweb_scan_failed`` when every usable source failed
    (nothing is recorded) and ``status="no_terms"`` when the monitor has no
    search terms, domains or emails (nothing is searched).
    """
    from src.darkweb.monitor_scan import scan_monitor

    monitor = await get_monitor_or_404(db, monitor_id, org_id)
    start_time = datetime.now(timezone.utc)
    scan_type = "quick" if scan_request.scan_type == "quick" else "full"

    try:
        outcome = await scan_monitor(db, monitor, scan_type=scan_type)
    except Exception as exc:  # noqa: BLE001 - an engine fault is a failed scan, reported as such
        logger.warning("Dark web scan engine call failed", monitor_id=monitor_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "darkweb_scan_failed", "detail": str(exc)[:300]},
        ) from exc
    if outcome.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "darkweb_scan_failed",
                "detail": outcome.detail,
                "sources": outcome.sources,
            },
        )

    # Fire automation on critical findings. The findings are already
    # persisted; a failing automation rule is logged and counted, and does
    # not undo the scan.
    critical_fired = 0
    automation = AutomationService(db)
    for c in outcome.criticals:
        try:
            await automation.on_darkweb_finding(
                finding_type=c["finding_type"],
                description=c["description"],
                source_url=c["source_url"],
                severity=c["severity"],
                organization_id=org_id,
            )
            critical_fired += 1
        except Exception as inner_exc:  # noqa: BLE001
            logger.warning("on_darkweb_finding failed", finding_id=c["finding_id"], error=str(inner_exc))
    await db.flush()

    logger.info(
        "Dark web scan completed",
        monitor_id=monitor_id,
        status=outcome.status,
        matched=outcome.matched,
        created=outcome.created,
        critical_fired=critical_fired,
    )
    return ScanStatusResponse(
        scan_id=f"scan_{monitor_id}_{int(start_time.timestamp())}",
        monitor_id=monitor_id,
        status=outcome.status,
        start_time=outcome.started_at,
        completion_time=outcome.finished_at,
        findings=outcome.matched,
        new_findings=outcome.created,
        detail=outcome.detail,
        terms_searched=outcome.terms_searched,
        sources=outcome.sources,
        skipped_duplicate=outcome.skipped_duplicate,
        credential_leaks_created=outcome.credential_leaks_created,
        critical_fired=critical_fired,
    )


# Finding endpoints


@router.get("/findings", response_model=DarkWebFindingListResponse)
async def list_findings(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
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
        DarkWebFinding.organization_id == org_id
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
        items=[DarkWebFindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.post("/findings", response_model=DarkWebFindingResponse, status_code=201)
async def create_finding(
    finding_data: DarkWebFindingCreate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create a new dark web finding on one of the caller's monitors"""
    await get_monitor_or_404(db, finding_data.monitor_id, org_id)
    finding = DarkWebFinding(
        organization_id=org_id,
        monitor_id=finding_data.monitor_id,
        finding_type=finding_data.finding_type,
        source_platform=finding_data.source_platform,
        title=finding_data.title,
        description=finding_data.description,
        affected_assets=finding_data.affected_assets,
        affected_count=finding_data.affected_count,
        severity=finding_data.severity,
        confidence_score=finding_data.confidence_score,
        source_url_hash=finding_data.source_url_hash,
        raw_data_hash=finding_data.raw_data_hash,
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)

    # Trigger automation rules
    try:
        automation = AutomationService(db)
        await automation.on_darkweb_finding(
            finding_type=finding.finding_type or "credential_leak",
            description=finding.description or "",
            severity=finding.severity or "high",
            organization_id=org_id,
        )
    except Exception as e:
        # The finding is committed; a failing automation rule is logged and
        # does not turn the create into an error.
        logger.error("Automation failed for dark web finding", finding_id=finding.id, error=str(e))

    logger.info(f"Created dark web finding: {finding.id}")

    return DarkWebFindingResponse.model_validate(finding)


@router.get("/findings/{finding_id}", response_model=DarkWebFindingDetailResponse)
async def get_finding(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Get finding details with related data"""
    finding = await get_finding_or_404(
        db, finding_id, org_id
    )

    return DarkWebFindingDetailResponse.model_validate(finding)


@router.patch("/findings/{finding_id}", response_model=DarkWebFindingResponse)
async def update_finding(
    update: DarkWebFindingUpdate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Update finding status and notes"""
    finding = await get_finding_or_404(
        db, finding_id, org_id
    )

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

    return DarkWebFindingResponse.model_validate(finding)


@router.post("/findings/{finding_id}/escalate")
async def escalate_finding(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Escalate a dark-web finding into a real Incident.

    Creates an Incident row keyed by the finding's title + severity,
    links the finding via Incident.external_id = "darkweb:{finding_id}",
    updates the finding status to 'escalated', and returns the new
    incident_id. Previously the UI's "Escalate to Incident" button
    only flipped the finding's status — no incident was ever created
    so analysts thought the action was broken.
    """
    from src.models.incident import Incident
    from src.models.base import generate_uuid, utc_now
    finding = await get_finding_or_404(db, finding_id, org_id)

    # Idempotency: if already escalated and an Incident exists for this
    # finding, return the existing incident rather than creating a dup.
    existing = (await db.execute(
        select(Incident).where(
            and_(
                Incident.external_id == f"darkweb:{finding_id}",
                Incident.organization_id == org_id,
            )
        )
    )).scalar_one_or_none()
    if existing is not None:
        return {
            "incident_id": existing.id,
            "finding_id": finding_id,
            "status": "already_escalated",
            "incident_status": existing.status,
        }

    incident = Incident(
        id=generate_uuid(),
        organization_id=finding.organization_id,
        title=f"Dark Web: {finding.title or finding.finding_type}",
        description=(
            (finding.description or "")
            + f"\n\nEscalated from dark web finding {finding_id} "
            + f"(source={finding.source_platform}, severity={finding.severity})."
        )[:4000],
        severity=finding.severity or "medium",
        status="open",
        incident_type="data_leak",
        priority={"critical": 1, "high": 2, "medium": 3, "low": 4}.get(
            (finding.severity or "medium").lower(), 3
        ),
        detected_at=finding.discovered_date or utc_now().isoformat(),
        external_id=f"darkweb:{finding_id}",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    db.add(incident)
    finding.status = "escalated"
    await db.commit()
    await db.refresh(incident)
    return {
        "incident_id": incident.id,
        "finding_id": finding_id,
        "status": "escalated",
        "incident_status": incident.status,
        "incident_severity": incident.severity,
    }


@router.post("/findings/{finding_id}/notify")
async def notify_stakeholders(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Send the finding to every enabled notification channel for the org.

    Calls ``send_incident_notifications`` so Slack / Teams / PagerDuty /
    OpsGenie all receive the alert at once. Returns a per-channel
    sent/failed/skipped breakdown. Updates the finding status to
    'notified' on success.
    """
    from src.services.notifications import send_incident_notifications

    finding = await get_finding_or_404(
        db, finding_id, org_id
    )

    event = {
        "title": f"Dark Web: {finding.title or finding.finding_type}",
        "severity": finding.severity or "medium",
        "summary": (finding.description or finding.title or "")[:1500],
        "trigger": "dark_web",
        "incident_id": None,
        "investigation_id": None,
        "verdict": None,
        "confidence": finding.confidence_score,
        "mitre_techniques": [],
        "recommendations": [
            "Force password reset for any matching internal users",
            "Block source URL at the proxy/firewall edge",
            "Review SIEM logs for matching IOCs in the last 30 days",
        ],
    }

    results = await send_incident_notifications(
        db,
        organization_id=finding.organization_id,
        event=event,
    )

    # Mark notified only if at least one channel actually sent.
    if results.get("sent"):
        finding.status = "notified"
        await db.commit()

    return {
        "finding_id": finding_id,
        "status": "notified" if results.get("sent") else "no_channels_configured",
        "delivery": results,
    }


@router.post("/findings/bulk-action")
async def bulk_finding_action(
    action: BulkFindingAction,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Perform bulk actions on findings"""
    # Verify ownership
    result = await db.execute(
        select(DarkWebFinding).where(
            and_(
                DarkWebFinding.id.in_(action.finding_ids),
                DarkWebFinding.organization_id == org_id,
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    remediated: Optional[bool] = None,
    finding_id: Optional[str] = None,
    search: Optional[str] = None,
):
    """List credential leaks"""
    query = select(CredentialLeak).where(
        CredentialLeak.organization_id == org_id
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
                    CredentialLeak.organization_id == org_id,
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
        items=[CredentialLeakResponse.model_validate(c) for c in credentials],
        total=total,
        page=page,
        size=size,
        pages=pages,
        unremediated_count=unremediated_count,
    )


@router.patch("/credentials/{credential_id}", response_model=CredentialLeakResponse)
async def update_credential(
    update: CredentialLeakUpdate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    credential_id: str = Path(...),
):
    """Update credential leak remediation status"""
    credential = await get_credential_or_404(
        db, credential_id, org_id
    )

    if update.is_valid is not None:
        credential.is_valid = update.is_valid
    if update.is_remediated is not None:
        credential.is_remediated = update.is_remediated
    if update.remediation_action is not None:
        credential.remediation_action = update.remediation_action

    await db.commit()
    await db.refresh(credential)

    return CredentialLeakResponse.model_validate(credential)


@router.post("/credentials/bulk-remediate", response_model=CredentialRemediationReport)
async def bulk_remediate_credentials(
    action: BulkCredentialRemediateAction,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Bulk remediate credentials"""
    # Verify ownership
    result = await db.execute(
        select(CredentialLeak).where(
            and_(
                CredentialLeak.id.in_(action.credential_ids),
                CredentialLeak.organization_id == org_id,
            )
        )
    )
    credentials = result.scalars().all()

    if len(credentials) != len(action.credential_ids):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Records the remediation decision on each leak. No password reset,
    # account disable or MFA change is executed here (the leaked accounts
    # live in the customer's identity provider), so the action counters stay
    # 0 and ``execution`` says the decision was recorded only.
    for credential in credentials:
        credential.remediation_action = action.action
        credential.is_remediated = True

    await db.commit()

    logger.info(f"Recorded remediation for {len(credentials)} credentials")

    return CredentialRemediationReport(
        total_affected=len(credentials),
        password_reset_sent=0,
        account_disabled=0,
        mfa_enforced=0,
        failed_actions=0,
        remediation_date=datetime.now(timezone.utc),
        recorded=len(credentials),
        execution="recorded_only",
        detail=(
            f"'{action.action}' recorded on {len(credentials)} credential leak(s); "
            "no identity-provider action was executed. Perform it in the identity "
            "provider (or through ITDR response actions)."
        ),
    )


# Brand threat endpoints


@router.get("/brand-threats", response_model=BrandThreatListResponse)
async def list_brand_threats(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    finding_id: Optional[str] = None,
):
    """List brand threats"""
    query = select(BrandThreat).where(
        BrandThreat.organization_id == org_id
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
        items=[BrandThreatResponse.model_validate(t) for t in threats],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.patch("/brand-threats/{threat_id}", response_model=BrandThreatResponse)
async def update_brand_threat(
    update: BrandThreatUpdate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    threat_id: str = Path(...),
):
    """Update brand threat takedown status"""
    result = await db.execute(
        select(BrandThreat).where(
            and_(
                BrandThreat.id == threat_id,
                BrandThreat.organization_id == org_id,
            )
        )
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if update.takedown_status is not None:
        threat.takedown_status = update.takedown_status
    if update.takedown_provider is not None:
        threat.takedown_provider = update.takedown_provider

    await db.commit()
    await db.refresh(threat)

    return BrandThreatResponse.model_validate(threat)


@router.post("/brand-threats/{threat_id}/initiate-takedown")
async def initiate_takedown(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    threat_id: str = Path(...),
):
    """Takedown submission: 501, no takedown provider is integrated.

    The threat is looked up first (404 outside the tenant). Nothing is
    recorded and nothing is queued: the takedown has to be filed with the
    registrar / hosting provider's abuse contact, and its progress tracked
    with ``PATCH /darkweb/brand-threats/{id}`` (``takedown_status``).
    """
    result = await db.execute(
        select(BrandThreat.id).where(
            and_(
                BrandThreat.id == threat_id,
                BrandThreat.organization_id == org_id,
            )
        )
    )
    if result.first() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "reason": "no_takedown_provider",
            "detail": (
                "No takedown provider is integrated, so PySOAR cannot submit a "
                "takedown. File it with the registrar or hosting abuse contact and "
                "record progress with PATCH /darkweb/brand-threats/{id} "
                "(takedown_status)."
            ),
            "threat_id": threat_id,
        },
    )


# Dashboard endpoints


@router.get("/dashboard", response_model=DarkWebDashboard)
async def get_dashboard(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get dark web monitoring dashboard.

    Previously 500'd on every call because ``brand_threat_map`` was
    populated with a ``DarkWebFindingListResponse`` but the schema
    declared ``BrandThreatMap``. On top of that, nine fields were
    hardcoded fake data: exposed_domains=10, exposed_emails=5,
    brand_threats=3, by_password_type={"md5":15,...},
    by_source={"pastebin":10,...}, crackable_credentials=15,
    plaintext_credentials=5, affected_users=20, trending_threats=[]
    and scan_frequency="daily".

    Every field is now either a real aggregate from the
    database or an honest 0 when the tenant has no data.
    """
    from datetime import timedelta
    from src.darkweb.models import PasswordType


    # --- Finding counts ---
    findings_result = await db.execute(
        select(func.count(DarkWebFinding.id)).where(
            DarkWebFinding.organization_id == org_id
        )
    )
    total_findings = findings_result.scalar() or 0

    critical_result = await db.execute(
        select(func.count(DarkWebFinding.id)).where(
            and_(
                DarkWebFinding.organization_id == org_id,
                DarkWebFinding.severity == "critical",
            )
        )
    )
    critical_findings = critical_result.scalar() or 0

    # --- Distinct exposed domains + emails (real) ---
    exposed_domains_result = await db.execute(
        select(func.count(func.distinct(CredentialLeak.email))).where(
            and_(
                CredentialLeak.organization_id == org_id,
                CredentialLeak.email.is_not(None),
            )
        )
    )
    exposed_emails = exposed_domains_result.scalar() or 0

    # Unique domains = unique "after @" portion of the email column
    # (Postgres supports split_part; the fallback is a Python pass
    # over a small row set)
    # Computed from the distinct emails in Python: portable across database
    # dialects. The old split_part() query sat in an `except: pass`, which
    # on Postgres also left the transaction aborted for every later query.
    email_rows = await db.execute(
        select(func.distinct(CredentialLeak.email)).where(
            and_(
                CredentialLeak.organization_id == org_id,
                CredentialLeak.email.is_not(None),
            )
        )
    )
    exposed_domains = len(
        {
            email.rsplit("@", 1)[1].lower()
            for (email,) in email_rows.all()
            if email and "@" in email and email.rsplit("@", 1)[1]
        }
    )

    # --- Credential stats ---
    creds_result = await db.execute(
        select(func.count(CredentialLeak.id)).where(
            CredentialLeak.organization_id == org_id
        )
    )
    total_credentials = creds_result.scalar() or 0

    remediated_result = await db.execute(
        select(func.count(CredentialLeak.id)).where(
            and_(
                CredentialLeak.organization_id == org_id,
                CredentialLeak.is_remediated == True,  # noqa: E712
            )
        )
    )
    remediated = remediated_result.scalar() or 0

    # Real password_type histogram
    by_password_type: dict[str, int] = {}
    pwt_rows = await db.execute(
        select(
            CredentialLeak.password_type, func.count(CredentialLeak.id)
        )
        .where(CredentialLeak.organization_id == org_id)
        .group_by(CredentialLeak.password_type)
    )
    for pwt, count in pwt_rows.all():
        by_password_type[pwt or "unknown"] = int(count)

    # Real source histogram — join to the parent DarkWebFinding to
    # get the source_platform
    by_source: dict[str, int] = {}
    src_rows = await db.execute(
        select(
            DarkWebFinding.source_platform, func.count(CredentialLeak.id)
        )
        .select_from(CredentialLeak)
        .join(DarkWebFinding, CredentialLeak.finding_id == DarkWebFinding.id)
        .where(CredentialLeak.organization_id == org_id)
        .group_by(DarkWebFinding.source_platform)
    )
    for src, count in src_rows.all():
        by_source[src or "unknown"] = int(count)

    # Real crackable / plaintext counts
    plain_str = PasswordType.PLAINTEXT.value
    md5_str = PasswordType.MD5.value
    sha1_str = PasswordType.SHA1.value

    plaintext_result = await db.execute(
        select(func.count(CredentialLeak.id)).where(
            and_(
                CredentialLeak.organization_id == org_id,
                CredentialLeak.password_type == plain_str,
            )
        )
    )
    plaintext_credentials = plaintext_result.scalar() or 0

    crackable_result = await db.execute(
        select(func.count(CredentialLeak.id)).where(
            and_(
                CredentialLeak.organization_id == org_id,
                CredentialLeak.password_type.in_([md5_str, sha1_str, plain_str]),
            )
        )
    )
    crackable_credentials = crackable_result.scalar() or 0

    # Real affected user count = distinct usernames+emails
    affected_result = await db.execute(
        select(
            func.count(
                func.distinct(func.coalesce(CredentialLeak.email, CredentialLeak.username))
            )
        ).where(CredentialLeak.organization_id == org_id)
    )
    affected_users = affected_result.scalar() or 0

    # --- Monitor stats ---
    monitors_result = await db.execute(
        select(func.count(DarkWebMonitor.id)).where(
            DarkWebMonitor.organization_id == org_id
        )
    )
    monitored_items = monitors_result.scalar() or 0

    active_monitors_result = await db.execute(
        select(func.count(DarkWebMonitor.id)).where(
            and_(
                DarkWebMonitor.organization_id == org_id,
                DarkWebMonitor.enabled == True,  # noqa: E712
            )
        )
    )
    active_monitors = active_monitors_result.scalar() or 0

    # --- Real BrandThreatMap (was a DarkWebFindingListResponse shape
    # mismatch that 500'd every dashboard call) ---
    bt_total_result = await db.execute(
        select(func.count(BrandThreat.id)).where(
            BrandThreat.organization_id == org_id
        )
    )
    brand_threats_total = bt_total_result.scalar() or 0

    bt_type_rows = await db.execute(
        select(BrandThreat.threat_type, func.count(BrandThreat.id))
        .where(BrandThreat.organization_id == org_id)
        .group_by(BrandThreat.threat_type)
    )
    by_threat_type = {t: int(c) for t, c in bt_type_rows.all() if t}

    bt_status_rows = await db.execute(
        select(BrandThreat.takedown_status, func.count(BrandThreat.id))
        .where(BrandThreat.organization_id == org_id)
        .group_by(BrandThreat.takedown_status)
    )
    by_takedown_status = {s or "unknown": int(c) for s, c in bt_status_rows.all()}

    active_takedowns = by_takedown_status.get("in_progress", 0) + by_takedown_status.get("takedown_requested", 0)
    completed_takedowns = by_takedown_status.get("completed", 0)
    failed_takedowns = by_takedown_status.get("failed", 0)

    # --- Real trending_threats (last 7d vs last 30d by finding_type) ---
    now = datetime.now(timezone.utc)
    trending: list[TrendingThreats] = []
    type_rows_30d = await db.execute(
        select(DarkWebFinding.finding_type, func.count(DarkWebFinding.id))
        .where(
            and_(
                DarkWebFinding.organization_id == org_id,
                DarkWebFinding.created_at >= now - timedelta(days=30),
            )
        )
        .group_by(DarkWebFinding.finding_type)
    )
    counts_30d = {t: int(c) for t, c in type_rows_30d.all() if t}

    type_rows_7d = await db.execute(
        select(DarkWebFinding.finding_type, func.count(DarkWebFinding.id))
        .where(
            and_(
                DarkWebFinding.organization_id == org_id,
                DarkWebFinding.created_at >= now - timedelta(days=7),
            )
        )
        .group_by(DarkWebFinding.finding_type)
    )
    counts_7d = {t: int(c) for t, c in type_rows_7d.all() if t}

    for ftype, c30 in counts_30d.items():
        c7 = counts_7d.get(ftype, 0)
        # Rising if the 7d count is more than 1/4 of the 30d
        # count (rough threshold — recent share > linear share)
        expected_7 = c30 / 30 * 7 if c30 else 0
        if c7 > expected_7 * 1.2:
            trend = "rising"
        elif c7 < expected_7 * 0.8:
            trend = "declining"
        else:
            trend = "stable"
        trending.append(
            TrendingThreats(
                threat_type=ftype,
                occurrences_last_7_days=c7,
                occurrences_last_30_days=c30,
                trend=trend,
                affected_industries=[],
            )
        )

    # Last scan + inferred frequency (based on monitors)
    last_scan_iso: Optional[str] = None
    scan_frequency = "manual"
    last_scan_rows = await db.execute(
        select(func.max(DarkWebFinding.discovered_date)).where(
            DarkWebFinding.organization_id == org_id
        )
    )
    lv = last_scan_rows.scalar()
    if lv:
        last_scan_iso = lv.isoformat() if hasattr(lv, "isoformat") else str(lv)
    scan_interval_minutes: Optional[int] = None
    if active_monitors > 0:
        scan_interval_minutes = _sweep_interval_minutes()
        scan_frequency = (
            f"every {scan_interval_minutes} minutes"
            if scan_interval_minutes
            else "not scheduled (no beat entry for the dark-web sweep)"
        )

    return DarkWebDashboard(
        exposure_summary=DarkWebExposureSummary(
            total_findings=total_findings,
            critical_findings=critical_findings,
            exposed_credentials=total_credentials,
            exposed_domains=exposed_domains,
            exposed_emails=exposed_emails,
            brand_threats=brand_threats_total,
            remediated_credentials=remediated,
            pending_remediation=max(0, total_credentials - remediated),
            last_scan=last_scan_iso,
        ),
        credential_stats=CredentialStatistics(
            total_credentials=total_credentials,
            by_password_type=by_password_type,
            by_source=by_source,
            crackable_credentials=crackable_credentials,
            plaintext_credentials=plaintext_credentials,
            affected_users=affected_users,
            remediation_rate=(remediated / total_credentials) if total_credentials > 0 else 0.0,
        ),
        brand_threat_map=BrandThreatMap(
            total_threats=brand_threats_total,
            by_threat_type=by_threat_type,
            by_takedown_status=by_takedown_status,
            active_takedowns=active_takedowns,
            completed_takedowns=completed_takedowns,
            failed_takedowns=failed_takedowns,
        ),
        trending_threats=trending,
        monitored_items=monitored_items,
        active_monitors=active_monitors,
        scan_frequency=scan_frequency,
        scan_interval_minutes=scan_interval_minutes,
        sources=_source_configuration(),
        source_platform_labels=dict(SOURCE_PLATFORM_LABELS),
    )


#: Honest description of every ``source_platform`` value on a finding.
SOURCE_PLATFORM_LABELS: dict[str, str] = {
    "breach_database": "Breach database (Have I Been Pwned)",
    "paste_site": "Paste site (as indexed by Have I Been Pwned)",
    "threat_intel_feed": "Threat-intelligence feed (abuse.ch URLhaus / ThreatFox, AlienVault OTX); not a dark-web forum",
    "marketplace": "Operator-configured marketplace feed",
    "tor_forum": "Tor forum (recorded manually; no Tor source is integrated)",
    "telegram": "Telegram (recorded manually; no Telegram source is integrated)",
    "discord": "Discord (recorded manually; no Discord source is integrated)",
    "ransomware_blog": "Ransomware leak site (recorded manually; no leak-site source is integrated)",
    "code_repository": "Code repository (recorded manually)",
    "social_media": "Social media (recorded manually)",
}


def _sweep_interval_minutes() -> Optional[int]:
    """Minutes between runs of the beat entry that scans every enabled monitor."""
    from datetime import timedelta as _td

    from src.workers.celery_app import celery_app

    entry = (celery_app.conf.beat_schedule or {}).get("darkweb-cross-org-sweep") or {}
    schedule = entry.get("schedule")
    if isinstance(schedule, (int, float)):
        return max(1, int(schedule // 60))
    if isinstance(schedule, _td):
        return max(1, int(schedule.total_seconds() // 60))
    run_every = getattr(schedule, "run_every", None)
    if isinstance(run_every, _td):
        return max(1, int(run_every.total_seconds() // 60))
    return None


def _source_configuration() -> dict[str, dict]:
    """Which monitor-scan sources the platform can use right now."""
    from src.darkweb import engine as dw_engine
    from src.darkweb.monitor_scan import SOURCE_LABELS

    requirement = {
        "hibp_account": ("HIBP_API_KEY", dw_engine.hibp_api_key() is not None),
        "hibp_domain": (None, True),
        "hibp_breach_catalogue": (None, True),
        "urlhaus": ("ABUSECH_AUTH_KEY", dw_engine.abusech_auth_key() is not None),
        "threatfox": ("ABUSECH_AUTH_KEY", dw_engine.abusech_auth_key() is not None),
        "otx": ("OTX_API_KEY", dw_engine.otx_api_key() is not None),
        "marketplace_feed": ("DARKWEB_MARKETPLACE_FEED_URL", dw_engine.marketplace_feed_url() is not None),
    }
    return {
        source: {"label": label, "configured": requirement[source][1], "requires": requirement[source][0]}
        for source, label in SOURCE_LABELS.items()
    }


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------


@router.get("/report/export")
async def export_darkweb_report(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    format: str = Query("csv", pattern="^(csv|pdf)$"),
):
    """Export a real dark-web findings report for the caller's organization.

    Replaces the "Print Report" button that used to call
    ``window.print()`` in the frontend. Streams a CSV via
    ``StreamingResponse`` so arbitrarily large tenant reports don't
    materialize in memory. PDF is only available when ``reportlab`` is
    installed in the container — otherwise we fall through to CSV so
    the client still gets a real file.
    """
    import csv
    import io
    from datetime import datetime as _dt


    # Pull findings + their matched monitor name in a single query.
    stmt = (
        select(DarkWebFinding, DarkWebMonitor.name)
        .join(
            DarkWebMonitor,
            DarkWebMonitor.id == DarkWebFinding.monitor_id,
            isouter=True,
        )
        .where(DarkWebFinding.organization_id == org_id)
        .order_by(DarkWebFinding.created_at.desc())
    )
    rows = (await db.execute(stmt)).all()

    date_str = _dt.now(timezone.utc).strftime("%Y-%m-%d")

    # Attempt PDF only if reportlab is actually installed.
    use_pdf = False
    if format == "pdf":
        try:
            import reportlab  # noqa: F401
            use_pdf = True
        except ImportError:
            use_pdf = False

    if use_pdf:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate,
            Table,
            TableStyle,
            Paragraph,
            Spacer,
        )
        from reportlab.lib.styles import getSampleStyleSheet

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()
        elements: list = [
            Paragraph("PySOAR Dark Web Findings Report", styles["Title"]),
            Paragraph(f"Generated: {date_str}", styles["Normal"]),
            Spacer(1, 12),
        ]
        data = [
            [
                "Finding ID",
                "Title",
                "Source",
                "Severity",
                "Status",
                "Created",
                "Monitor",
            ]
        ]
        for finding, monitor_name in rows:
            data.append(
                [
                    str(finding.id)[:36],
                    (finding.title or "")[:60],
                    finding.source_platform or "",
                    finding.severity or "",
                    finding.status or "",
                    finding.created_at.isoformat()
                    if finding.created_at
                    else "",
                    (monitor_name or "")[:40],
                ]
            )
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                ]
            )
        )
        elements.append(table)
        doc.build(elements)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f"attachment; filename=pysoar_darkweb_report_{date_str}.pdf"
                )
            },
        )

    # CSV path (preferred, always available)
    def _iter_csv():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "finding_id",
                "title",
                "source",
                "severity",
                "status",
                "created_at",
                "matched_monitor",
                "excerpt",
            ]
        )
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

        for finding, monitor_name in rows:
            excerpt = (finding.description or "").replace("\r", " ").replace("\n", " ")
            if len(excerpt) > 300:
                excerpt = excerpt[:297] + "..."
            writer.writerow(
                [
                    str(finding.id),
                    finding.title or "",
                    finding.source_platform or "",
                    finding.severity or "",
                    finding.status or "",
                    finding.created_at.isoformat()
                    if finding.created_at
                    else "",
                    monitor_name or "",
                    excerpt,
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    filename = f"pysoar_darkweb_report_{date_str}.csv"
    return StreamingResponse(
        _iter_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
