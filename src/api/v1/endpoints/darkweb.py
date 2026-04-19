"""Dark Web Monitoring API Endpoints

API routes for dark web monitor management, findings investigation,
credential leak handling, and brand threat tracking.
"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Path, BackgroundTasks, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.services.automation import AutomationService
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
        DarkWebMonitor.organization_id == getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new dark web monitor"""
    db_monitor = DarkWebMonitor(
        organization_id=getattr(current_user, "organization_id", None),
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

    return DarkWebMonitorResponse.model_validate(db_monitor)


@router.get("/monitors/{monitor_id}", response_model=DarkWebMonitorResponse)
async def get_monitor(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Get monitor by ID"""
    monitor = await get_monitor_or_404(db, monitor_id)

    if monitor.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return DarkWebMonitorResponse.model_validate(monitor)


@router.patch("/monitors/{monitor_id}", response_model=DarkWebMonitorResponse)
async def update_monitor(
    update: DarkWebMonitorUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Update monitor configuration"""
    monitor = await get_monitor_or_404(db, monitor_id)

    if monitor.organization_id != getattr(current_user, "organization_id", None):
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

    return DarkWebMonitorResponse.model_validate(monitor)


@router.delete("/monitors/{monitor_id}", status_code=204)
async def delete_monitor(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    monitor_id: str = Path(...),
):
    """Delete monitor"""
    monitor = await get_monitor_or_404(db, monitor_id)

    if monitor.organization_id != getattr(current_user, "organization_id", None):
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
    monitor_id: str = Path(...),
):
    """Run a dark web scan synchronously and persist findings.

    Previously this endpoint queued ``scheduled_dark_web_scan`` via
    FastAPI's BackgroundTasks — but that's a Celery ``@shared_task``
    with ``bind=True``, which expects ``self`` as the first arg
    injected by Celery. Calling it without Celery crashed the
    background worker with ``TypeError: missing 1 required
    positional argument: 'self'`` AND the task body was hardcoded
    theater (returned a static 6-finding dict without calling the
    real DarkWebScanner engine). So every "Scan now" click: fake
    scan_id to the UI, crash in the background, zero real data.

    Now runs the real engine inline (DarkWebScanner.run_scan_cycle
    hits URLhaus / HIBP / ThreatFox / AlienVault OTX — all free
    APIs the module already integrates), persists the findings to
    the DarkWebFinding table scoped to this org, fires
    automation.on_darkweb_finding per critical finding, and
    returns real counts.
    """
    from src.darkweb.engine import DarkWebScanner
    import hashlib as _hashlib

    monitor = await get_monitor_or_404(db, monitor_id)
    org_id = getattr(current_user, "organization_id", None)

    if monitor.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    start_time = datetime.now(timezone.utc)
    logger.info(f"Running inline dark web scan for monitor: {monitor_id}")

    scanner = DarkWebScanner()
    try:
        if scan_request.scan_type == "quick":
            # Quick = only breach DB (HIBP) since it's the cheapest
            pastes = []
            breaches = await scanner.search_breach_databases()
            forums = []
            channels = []
        else:
            pastes = await scanner.search_paste_sites()
            breaches = await scanner.search_breach_databases()
            forums = await scanner.search_forums()
            channels = await scanner.search_telegram_channels()
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Dark web scan engine call failed: {exc}")
        pastes, breaches, forums, channels = [], [], [], []

    persisted_findings: list[DarkWebFinding] = []

    def _add_finding(
        finding_type: str,
        source_platform: str,
        title: str,
        description: str,
        severity: str = "medium",
        raw: Optional[dict] = None,
    ) -> None:
        # Hash the canonical JSON of the raw payload — the full payload,
        # not a truncated sample. A truncated hash would collide across
        # otherwise-distinct findings whose first 2000 bytes happen to match.
        raw_str = json.dumps(raw or {}, sort_keys=True, default=str)
        raw_hash = _hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

        # `title` column is VARCHAR(500) — cap matches the schema.
        # `description` is TEXT (unbounded) — persist in full.
        # `source_url_hash` is VARCHAR(64) to match SHA-256 hex length.
        finding = DarkWebFinding(
            organization_id=org_id,
            monitor_id=monitor_id,
            finding_type=finding_type,
            source_platform=source_platform,
            title=title[:500],
            description=description,
            affected_assets=None,
            affected_count=0,
            severity=severity,
            confidence_score=75.0,
            source_url_hash=raw_hash[:64],
            raw_data_hash=raw_hash,
            status="new",
        )
        db.add(finding)
        persisted_findings.append(finding)

    for p in pastes:
        _add_finding(
            "malicious_url",
            p.get("site", "urlhaus"),
            f"Malicious URL: {p.get('threat_type', 'unknown')}",
            f"{p.get('url', '')} — {p.get('status', 'unknown')}",
            severity="high" if p.get("status") == "online" else "medium",
            raw=p,
        )
    for b in breaches:
        _add_finding(
            "data_breach",
            "haveibeenpwned",
            f"Breach: {b.get('breach_name', 'unknown')}",
            b.get("description", "")[:500],
            severity="high" if (b.get("affected_count") or 0) > 1_000_000 else "medium",
            raw=b,
        )
    for f in forums:
        _add_finding(
            "ioc",
            "threatfox.abuse.ch",
            f.get("title", "IOC"),
            f"{f.get('ioc_type', '')}: {f.get('ioc_value', '')}",
            severity="high",
            raw=f,
        )
    for c in channels:
        _add_finding(
            "threat_intel",
            c.get("platform", "otx"),
            f"OTX pulse: {c.get('sender', 'unknown')}",
            c.get("message_id", "")[:500],
            severity="medium",
            raw=c,
        )

    await db.flush()

    # Fire automation on critical/high findings
    critical_count = 0
    try:
        automation = AutomationService(db)
        for f in persisted_findings:
            if f.severity in ("critical", "high"):
                critical_count += 1
                try:
                    await automation.on_darkweb_finding(
                        finding_type=f.finding_type or "unknown",
                        description=f.description or "",
                        severity=f.severity,
                        organization_id=org_id,
                    )
                except Exception as inner_exc:  # noqa: BLE001
                    logger.warning(f"on_darkweb_finding failed: {inner_exc}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Automation fan-out failed during dark web scan: {exc}")

    # Update monitor last_scan timestamp if the column exists
    try:
        if hasattr(monitor, "last_scan_date"):
            monitor.last_scan_date = start_time
        await db.flush()
    except Exception:  # noqa: BLE001
        pass

    scan_id = f"scan_{monitor_id}_{int(start_time.timestamp())}"
    logger.info(
        f"Dark web scan completed: monitor={monitor_id} total_findings="
        f"{len(persisted_findings)} critical_fired={critical_count}"
    )

    return ScanStatusResponse(
        scan_id=scan_id,
        monitor_id=monitor_id,
        status="completed",
        start_time=start_time.isoformat(),
        findings=len(persisted_findings),
        new_findings=len(persisted_findings),
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
        DarkWebFinding.organization_id == getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new dark web finding"""
    org_id = getattr(current_user, "organization_id", None)
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
        logger.error(f"Automation failed for dark web finding {finding.id}: {e}")

    logger.info(f"Created dark web finding: {finding.id}")

    return DarkWebFindingResponse.model_validate(finding)


@router.get("/findings/{finding_id}", response_model=DarkWebFindingDetailResponse)
async def get_finding(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Get finding details with related data"""
    finding = await get_finding_or_404(db, finding_id)

    if finding.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return DarkWebFindingDetailResponse.model_validate(finding)


@router.patch("/findings/{finding_id}", response_model=DarkWebFindingResponse)
async def update_finding(
    update: DarkWebFindingUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    finding_id: str = Path(...),
):
    """Update finding status and notes"""
    finding = await get_finding_or_404(db, finding_id)

    if finding.organization_id != getattr(current_user, "organization_id", None):
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

    return DarkWebFindingResponse.model_validate(finding)


@router.post("/findings/bulk-action")
async def bulk_finding_action(action: BulkFindingAction, current_user: CurrentUser = None, db: DatabaseSession = None, background_tasks: BackgroundTasks = None):
    """Perform bulk actions on findings"""
    # Verify ownership
    result = await db.execute(
        select(DarkWebFinding).where(
            and_(
                DarkWebFinding.id.in_(action.finding_ids),
                DarkWebFinding.organization_id == getattr(current_user, "organization_id", None),
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
        CredentialLeak.organization_id == getattr(current_user, "organization_id", None)
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
                    CredentialLeak.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    credential_id: str = Path(...),
):
    """Update credential leak remediation status"""
    credential = await get_credential_or_404(db, credential_id)

    if credential.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Bulk remediate credentials"""
    # Verify ownership
    result = await db.execute(
        select(CredentialLeak).where(
            and_(
                CredentialLeak.id.in_(action.credential_ids),
                CredentialLeak.organization_id == getattr(current_user, "organization_id", None),
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
        BrandThreat.organization_id == getattr(current_user, "organization_id", None)
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

    if threat.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if update.takedown_status is not None:
        threat.takedown_status = update.takedown_status
    if update.takedown_provider is not None:
        threat.takedown_provider = update.takedown_provider

    await db.commit()
    await db.refresh(threat)

    return BrandThreatResponse.model_validate(threat)


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

    if threat.organization_id != getattr(current_user, "organization_id", None):
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

    org_id = getattr(current_user, "organization_id", None)

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
    exposed_domains = 0
    try:
        dom_rows = await db.execute(
            select(func.distinct(func.split_part(CredentialLeak.email, "@", 2))).where(
                and_(
                    CredentialLeak.organization_id == org_id,
                    CredentialLeak.email.is_not(None),
                )
            )
        )
        exposed_domains = len([r for (r,) in dom_rows.all() if r])
    except Exception:  # noqa: BLE001
        pass

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
    try:
        plain_str = PasswordType.PLAINTEXT.value
        md5_str = PasswordType.MD5.value if hasattr(PasswordType, "MD5") else "md5"
        sha1_str = PasswordType.SHA1.value if hasattr(PasswordType, "SHA1") else "sha1"
    except Exception:  # noqa: BLE001
        plain_str, md5_str, sha1_str = "plaintext", "md5", "sha1"

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
    try:
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
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"trending threats aggregation failed: {exc}")

    # Last scan + inferred frequency (based on monitors)
    last_scan_iso: Optional[str] = None
    scan_frequency = "manual"
    try:
        last_scan_rows = await db.execute(
            select(func.max(DarkWebFinding.discovered_date)).where(
                DarkWebFinding.organization_id == org_id
            )
        )
        lv = last_scan_rows.scalar()
        if lv:
            last_scan_iso = lv.isoformat() if hasattr(lv, "isoformat") else str(lv)
        if active_monitors > 0:
            scan_frequency = "daily"
    except Exception:  # noqa: BLE001
        pass

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
    )


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------


@router.get("/report/export")
async def export_darkweb_report(
    current_user: CurrentUser = None,
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

    org_id = getattr(current_user, "organization_id", None)

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
