"""Vulnerability management API endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status
from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.core.logging import get_logger
from src.models.audit import AuditLog
from src.models.user import User, UserRole
from src.schemas.vulnmgmt import (
    BulkAction,
    DashboardMetrics,
    KEVComplianceReport,
    PatchDeploymentRequest,
    PatchOperationListResponse,
    PatchOperationResponse,
    PatchPlanRequest,
    PatchRollbackRequest,
    PatchVerificationRequest,
    RiskMatrix,
    ScanImportRequest,
    ScanProfileCreate,
    ScanProfileListResponse,
    ScanProfileResponse,
    ScanProfileUpdate,
    SLAComplianceMetrics,
    VulnerabilityCreate,
    VulnerabilityExceptionCreate,
    VulnerabilityExceptionResponse,
    VulnerabilityExceptionUpdate,
    VulnerabilityInstanceCreate,
    VulnerabilityInstanceListResponse,
    VulnerabilityInstanceResponse,
    VulnerabilityInstanceUpdate,
    VulnerabilityListResponse,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)
from src.services.automation import AutomationService
from src.vulnmgmt.engine import (
    EXCEPTION_STATUS,
    OPEN_STATUSES,
    VALID_STATUSES,
    KEVFeedUnavailable,
    KEVMonitor,
    PatchOrchestrator,
    RiskPrioritizer,
    ScanImportError,
    VulnerabilityLifecycle,
    VulnerabilityScanner,
    apply_status_change,
    asset_reference,
    fetch_kev_catalog,
    instance_dedupe_key,
    now_iso,
    parse_iso,
    refresh_instances,
)
from src.vulnmgmt.models import (
    ExceptionType,
    PatchOperation,
    ScanProfile,
    Vulnerability,
    VulnerabilityException,
    VulnerabilityInstance,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/vulnmgmt", tags=["Vulnerability Management"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

#: Instance fields sortable through ``sort_by`` (anything else -> created_at).
_INSTANCE_SORT = {"created_at", "updated_at", "risk_score", "first_seen", "last_seen", "status", "sla_status"}
_VULN_SORT = {"created_at", "updated_at", "cve_id", "title", "severity", "cvss_v3_score", "epss_score"}


async def get_or_404(db: AsyncSession, model: type, item_id: str, org_id: str) -> Any:
    """Get model instance or raise 404"""
    result = await db.execute(
        select(model).where(
            and_(
                model.id == item_id,
                model.organization_id == org_id,
            )
        )
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{model.__name__} not found",
        )
    return item


def _audit(
    db: AsyncSession,
    user: User,
    org_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    description: str,
    payload: Optional[dict[str, Any]] = None,
    success: bool = True,
) -> None:
    """Add an AuditLog row for a vulnerability-management action."""
    db.add(
        AuditLog(
            user_id=user.id,
            organization_id=org_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description[:4000],
            new_value=json.dumps(payload, default=str)[:20000] if payload is not None else None,
            success=success,
        )
    )


async def _instance_responses(
    db: AsyncSession, org_id: str, instances: list[VulnerabilityInstance],
) -> list[VulnerabilityInstanceResponse]:
    """Instance responses enriched with the parent catalogue row."""
    vuln_ids = {i.vulnerability_id for i in instances}
    vulns: dict[str, Vulnerability] = {}
    if vuln_ids:
        vulns = {
            v.id: v
            for v in (
                await db.execute(
                    select(Vulnerability).where(Vulnerability.organization_id == org_id, Vulnerability.id.in_(vuln_ids))
                )
            ).scalars()
        }
    out = []
    for inst in instances:
        resp = VulnerabilityInstanceResponse.model_validate(inst)
        vuln = vulns.get(inst.vulnerability_id)
        if vuln is not None:
            resp.cve_id = vuln.cve_id
            resp.vulnerability_title = vuln.title
            resp.severity = vuln.severity
            resp.kev_listed = vuln.kev_listed
        out.append(resp)
    return out


def _exception_status(expiry_date: Optional[str], now: datetime) -> str:
    expiry = parse_iso(expiry_date)
    return "expired" if expiry is not None and expiry < now else "active"


async def _exception_responses(
    db: AsyncSession, org_id: str, rows: list[VulnerabilityException],
) -> list[VulnerabilityExceptionResponse]:
    instance_ids = {r.vulnerability_instance_id for r in rows}
    info: dict[str, tuple[str, Optional[str], Optional[str]]] = {}
    if instance_ids:
        for inst_id, vuln_id, cve_id, asset_name in (
            await db.execute(
                select(
                    VulnerabilityInstance.id,
                    VulnerabilityInstance.vulnerability_id,
                    Vulnerability.cve_id,
                    VulnerabilityInstance.asset_name,
                )
                .join(Vulnerability, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
                .where(VulnerabilityInstance.organization_id == org_id, VulnerabilityInstance.id.in_(instance_ids))
            )
        ).all():
            info[inst_id] = (vuln_id, cve_id, asset_name)
    now = datetime.now(timezone.utc)
    out = []
    for r in rows:
        resp = VulnerabilityExceptionResponse.model_validate(r)
        resp.status = _exception_status(r.expiry_date, now)
        if r.vulnerability_instance_id in info:
            resp.vulnerability_id, resp.cve_id, resp.asset_name = info[r.vulnerability_instance_id]
        out.append(resp)
    return out


# Vulnerability Database Endpoints
@router.get("/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    cve_only: bool = False,
    kev_only: bool = False,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List catalogue vulnerabilities with per-row instance counts.

    ``affected_instance_count`` / ``open_instance_count`` / ``days_open`` are
    computed from the stored instances of the rows on this page.
    """

    query = select(Vulnerability).where(Vulnerability.organization_id == org_id)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (Vulnerability.cve_id.ilike(search_filter))
            | (Vulnerability.title.ilike(search_filter))
            | (Vulnerability.description.ilike(search_filter))
        )

    if severity:
        query = query.where(Vulnerability.severity.in_([s.strip() for s in severity.split(",") if s.strip()]))

    if kev_only:
        query = query.where(Vulnerability.kev_listed == True)  # noqa: E712

    if cve_only:
        query = query.where(Vulnerability.cve_id.like("CVE-%"))

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    sort_column = getattr(Vulnerability, sort_by if sort_by in _VULN_SORT else "created_at")
    query = query.order_by(sort_column.asc() if sort_order == "asc" else sort_column.desc())

    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    items = list(result.scalars().all())

    stats: dict[str, tuple[int, int, Optional[str]]] = {}
    if items:
        is_open = VulnerabilityInstance.status.in_(sorted(OPEN_STATUSES))
        for vuln_id, total_n, open_n, oldest in (
            await db.execute(
                select(
                    VulnerabilityInstance.vulnerability_id,
                    func.count(VulnerabilityInstance.id),
                    func.sum(case((is_open, 1), else_=0)),
                    func.min(case((is_open, VulnerabilityInstance.first_seen), else_=None)),
                )
                .where(
                    VulnerabilityInstance.organization_id == org_id,
                    VulnerabilityInstance.vulnerability_id.in_([v.id for v in items]),
                )
                .group_by(VulnerabilityInstance.vulnerability_id)
            )
        ).all():
            stats[vuln_id] = (int(total_n or 0), int(open_n or 0), oldest)

    now = datetime.now(timezone.utc)
    responses = []
    for item in items:
        resp = VulnerabilityResponse.model_validate(item)
        total_n, open_n, oldest = stats.get(item.id, (0, 0, None))
        resp.affected_instance_count = total_n
        resp.open_instance_count = open_n
        first = parse_iso(oldest)
        resp.days_open = (now - first).days if (open_n and first is not None) else None
        responses.append(resp)

    return VulnerabilityListResponse(
        items=responses,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 1,
    )


@router.post("/vulnerabilities", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    vuln_data: VulnerabilityCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a vulnerability record (409 when the CVE is already tracked)."""
    vuln_data.organization_id = org_id
    existing = (
        await db.execute(
            select(Vulnerability.id).where(Vulnerability.organization_id == org_id, Vulnerability.cve_id == vuln_data.cve_id)
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "duplicate_cve", "vulnerability_id": existing},
        )

    vuln = Vulnerability(**vuln_data.model_dump())
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)

    # Trigger automation for new vulnerability
    try:
        automation = AutomationService(db)
        await automation.on_vulnerability_found(
            cve_id=vuln.cve_id,
            title=vuln.title,
            affected_asset="",
            severity=vuln.severity,
            organization_id=org_id,
        )
    except Exception as e:  # noqa: BLE001 - the record is stored; automation failure is logged
        logger.error(f"Automation on_vulnerability_found failed: {e}", exc_info=True)

    return VulnerabilityResponse.model_validate(vuln)


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    vuln_id: str = Path(...),
):
    """Get vulnerability by ID"""
    vuln = await get_or_404(db, Vulnerability, vuln_id, org_id)
    return VulnerabilityResponse.model_validate(vuln)


@router.put("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_data: VulnerabilityUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    vuln_id: str = Path(...),
):
    """Update a vulnerability; instance risk and SLA follow the new values."""
    vuln = await get_or_404(db, Vulnerability, vuln_id, org_id)

    update_data = vuln_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(vuln, key, value)
    await db.flush()

    instance_ids = list(
        (
            await db.execute(
                select(VulnerabilityInstance.id).where(
                    VulnerabilityInstance.organization_id == org_id,
                    VulnerabilityInstance.vulnerability_id == vuln.id,
                )
            )
        ).scalars()
    )
    if instance_ids:
        await refresh_instances(db, org_id, instance_ids)

    await db.commit()
    await db.refresh(vuln)
    return VulnerabilityResponse.model_validate(vuln)


@router.post("/vulnerabilities/import-scan", response_model=None)
async def import_scan_results(
    scan_request: ScanImportRequest,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Import a scanner export into vulnerability instances.

    Formats: Nessus (.nessus XML / JSON / CSV), OpenVAS (XML / CSV), Qualys
    (CSV / JSON), generic JSON or CSV. Each finding is linked to an inventory
    asset (matched by IP then hostname, created from the scanned host
    otherwise) and stored as one instance per (asset, CVE or plugin id, port /
    protocol). The response reports instances created / updated / reopened,
    catalogue rows and assets created, and skipped findings with reasons.
    422 ``scan_parse_failed`` when nothing in the payload could be read.

    New critical / high instances fan out (at most 50 per import) into
    ``automation.on_vulnerability_found``.
    """
    if scan_request.scan_profile_id:
        await get_or_404(db, ScanProfile, scan_request.scan_profile_id, org_id)

    scanner = VulnerabilityScanner(org_id)
    try:
        result = await scanner.import_scan_results(
            db,
            scan_format=scan_request.scan_format,
            scan_data=scan_request.scan_data,
            scan_id=scan_request.scan_profile_id,
            discovery_source=scan_request.scan_format,
            scan_profile_id=scan_request.scan_profile_id or None,
        )
    except ScanImportError as exc:
        # Raised before anything is written; record the refusal and answer 422.
        _audit(
            db, current_user, org_id, "vulnmgmt.scan_import", "vulnerability_scan", None,
            f"Scan import ({scan_request.scan_format}) failed: {exc}", {"errors": exc.errors}, success=False,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "scan_parse_failed", "errors": exc.errors},
        )

    new_critical = result.get("new_critical") or []
    automation_fired = 0
    automation_failed = 0
    if new_critical:
        automation = AutomationService(db)
        for finding in new_critical[:50]:
            try:
                await automation.on_vulnerability_found(
                    cve_id=finding.get("cve_id") or "UNKNOWN",
                    title=finding.get("title") or "Unknown",
                    affected_asset=finding.get("asset_name") or "unknown",
                    severity=finding.get("severity") or "high",
                    organization_id=org_id,
                )
                automation_fired += 1
            except Exception as inner_exc:  # noqa: BLE001 - counted and reported
                automation_failed += 1
                logger.warning("on_vulnerability_found failed", cve=finding.get("cve_id"), error=str(inner_exc))
    result["automation_events_fired"] = automation_fired
    result["automation_events_failed"] = automation_failed
    result["new_critical"] = new_critical[:100]

    _audit(
        db, current_user, org_id, "vulnmgmt.scan_import", "vulnerability_scan", scan_request.scan_profile_id or None,
        (
            f"Imported {result['findings_read']} {result['scan_format']} finding(s): "
            f"{result['instances_created']} new, {result['updated']} updated, {result['skipped_count']} skipped"
        ),
        {k: v for k, v in result.items() if k not in ("new_critical",)},
    )
    await db.commit()
    logger.info("Scan imported", org_id=org_id, created=result["instances_created"], updated=result["updated"])
    return result


@router.post("/vulnerabilities/sync-kev")
async def sync_kev(
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
    kev_data: Optional[dict] = Body(None),
):
    """Flag tracked CVEs that CISA lists as Known Exploited.

    Without a body the CISA feed is fetched server-side (pinned outbound
    transport); a body with a ``vulnerabilities`` array (the KEV JSON
    document, e.g. for air-gapped installs) is used as given. Only catalogue
    rows the tenant already tracks are flagged; nothing is created from the
    feed. 502 ``kev_feed_unavailable`` when the feed cannot be fetched.
    """
    source = "request_body"
    if not kev_data or not isinstance(kev_data.get("vulnerabilities"), list):
        source = "cisa_feed"
        try:
            kev_data = await fetch_kev_catalog()
        except KEVFeedUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={"error": "kev_feed_unavailable", "detail": str(exc)},
            )

    monitor = KEVMonitor(org_id)
    result = await monitor.sync_cisa_kev(db, kev_data)
    result["source"] = source
    _audit(
        db, current_user, org_id, "vulnmgmt.kev_sync", "vulnerability", None,
        f"KEV sync from {source}: {result['matched']} tracked CVE(s) listed, {result['newly_flagged']} newly flagged",
        result,
    )
    await db.commit()
    return result


# Vulnerability Instance Endpoints
@router.get("/instances", response_model=VulnerabilityInstanceListResponse)
async def list_instances(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    asset_id: Optional[str] = None,
    vulnerability_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    sla_status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    kev_only: bool = False,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List vulnerability instances with filtering.

    ``severity`` / ``status`` accept comma-separated values; ``severity`` and
    ``kev_only`` filter on the parent catalogue row.
    """

    query = select(VulnerabilityInstance).where(VulnerabilityInstance.organization_id == org_id)

    if asset_id:
        query = query.where(VulnerabilityInstance.asset_id == asset_id)
    if vulnerability_id:
        query = query.where(VulnerabilityInstance.vulnerability_id == vulnerability_id)
    if status:
        query = query.where(VulnerabilityInstance.status.in_([s.strip() for s in status.split(",") if s.strip()]))
    if sla_status:
        query = query.where(VulnerabilityInstance.sla_status == sla_status)
    if assigned_to:
        query = query.where(VulnerabilityInstance.assigned_to == assigned_to)
    if severity or kev_only:
        catalogue = select(Vulnerability.id).where(Vulnerability.organization_id == org_id)
        if severity:
            catalogue = catalogue.where(Vulnerability.severity.in_([s.strip() for s in severity.split(",") if s.strip()]))
        if kev_only:
            catalogue = catalogue.where(Vulnerability.kev_listed == True)  # noqa: E712
        query = query.where(VulnerabilityInstance.vulnerability_id.in_(catalogue))
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (VulnerabilityInstance.asset_name.ilike(search_filter))
            | (VulnerabilityInstance.asset_ip.ilike(search_filter))
        )

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    sort_column = getattr(VulnerabilityInstance, sort_by if sort_by in _INSTANCE_SORT else "created_at")
    query = query.order_by(sort_column.asc() if sort_order == "asc" else sort_column.desc())

    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    items = list(result.scalars().all())

    return VulnerabilityInstanceListResponse(
        items=await _instance_responses(db, org_id, items),
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 1,
    )


@router.post("/instances", response_model=VulnerabilityInstanceResponse, status_code=status.HTTP_201_CREATED)
async def create_instance(
    instance_data: VulnerabilityInstanceCreate,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a vulnerability instance (its vulnerability must be in the caller's org).

    409 ``duplicate_instance`` when the same (asset, vulnerability, port /
    protocol) is already tracked. Risk and SLA are computed from the stored
    catalogue row; client-supplied values for them are ignored.
    """
    instance_data.organization_id = org_id
    vuln = await get_or_404(db, Vulnerability, instance_data.vulnerability_id, org_id)
    if instance_data.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_status", "allowed": sorted(VALID_STATUSES)},
        )
    if instance_data.asset_id:
        from src.models.asset import Asset

        await get_or_404(db, Asset, instance_data.asset_id, org_id)

    ref = asset_reference(instance_data.asset_id, instance_data.asset_ip, instance_data.asset_name)
    data = instance_data.model_dump(exclude={"risk_score", "exploitability_score", "sla_status"})
    if ref:
        data["dedupe_key"] = instance_dedupe_key(ref, vuln.id, instance_data.port, instance_data.protocol)
        clash = (
            await db.execute(
                select(VulnerabilityInstance.id).where(
                    VulnerabilityInstance.organization_id == org_id,
                    VulnerabilityInstance.dedupe_key == data["dedupe_key"],
                )
            )
        ).scalar_one_or_none()
        if clash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "duplicate_instance", "instance_id": clash},
            )
    now = now_iso()
    data["first_seen"] = data.get("first_seen") or now
    data["last_seen"] = data.get("last_seen") or now
    if data["status"] in ("patched", "mitigated"):
        data["remediated_at"] = now

    instance = VulnerabilityInstance(**data)
    db.add(instance)
    await db.flush()
    await refresh_instances(db, org_id, [instance.id])
    _audit(db, current_user, org_id, "vulnmgmt.instance_create", "vulnerability_instance", instance.id,
           f"Instance of {vuln.cve_id} on {instance.asset_name or instance.asset_ip or instance.asset_id or 'unknown asset'}")
    await db.commit()
    await db.refresh(instance)

    return (await _instance_responses(db, org_id, [instance]))[0]


@router.get("/instances/{instance_id}", response_model=VulnerabilityInstanceResponse)
async def get_instance(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    instance_id: str = Path(...),
):
    """Get vulnerability instance by ID"""
    instance = await get_or_404(db, VulnerabilityInstance, instance_id, org_id)
    return (await _instance_responses(db, org_id, [instance]))[0]


@router.put("/instances/{instance_id}", response_model=VulnerabilityInstanceResponse)
async def update_instance(
    instance_data: VulnerabilityInstanceUpdate,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
    instance_id: str = Path(...),
):
    """Update a vulnerability instance.

    ``status`` must be a known status; moving to patched / mitigated stamps
    ``remediated_at``. Risk and SLA status are recomputed from stored rows
    (values sent for them are ignored).
    """
    instance = await get_or_404(db, VulnerabilityInstance, instance_id, org_id)

    update_data = instance_data.model_dump(exclude_unset=True)
    for computed in ("risk_score", "exploitability_score", "sla_status"):
        update_data.pop(computed, None)
    new_status = update_data.pop("status", None)
    old_status = instance.status
    if new_status is not None:
        try:
            apply_status_change(instance, new_status)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "invalid_status", "detail": str(exc)},
            )
    for key, value in update_data.items():
        setattr(instance, key, value)
    await db.flush()
    await refresh_instances(db, org_id, [instance.id])
    if new_status is not None and new_status != old_status:
        _audit(db, current_user, org_id, "vulnmgmt.instance_status", "vulnerability_instance", instance.id,
               f"Instance status {old_status} -> {new_status}", {"from": old_status, "to": new_status})

    await db.commit()
    await db.refresh(instance)
    return (await _instance_responses(db, org_id, [instance]))[0]


_BULK_ACTIONS = {"update_status", "assign", "set_deadline"}


@router.post("/instances/bulk-action")
async def bulk_action_instances(
    action_request: BulkAction,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Apply ``update_status`` / ``assign`` / ``set_deadline`` to instances by id.

    Ids outside the caller's org are reported in ``not_found`` (404 when none
    match). Statuses are validated; patched / mitigated stamp
    ``remediated_at``. Audited.
    """
    if action_request.action not in _BULK_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_action", "allowed": sorted(_BULK_ACTIONS)},
        )
    if action_request.action == "update_status" and action_request.value not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_status", "allowed": sorted(VALID_STATUSES)},
        )
    if action_request.action == "set_deadline" and action_request.value and parse_iso(action_request.value) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_deadline", "detail": "value must be an ISO date or datetime"},
        )
    ids = list(dict.fromkeys(action_request.instance_ids))[:1000]
    result = await db.execute(
        select(VulnerabilityInstance).where(
            and_(
                VulnerabilityInstance.id.in_(ids),
                VulnerabilityInstance.organization_id == org_id,
            )
        )
    )
    instances = list(result.scalars().all())

    if not instances:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No instances found",
        )

    for instance in instances:
        if action_request.action == "update_status":
            apply_status_change(instance, action_request.value)
        elif action_request.action == "assign":
            instance.assigned_to = action_request.value
        elif action_request.action == "set_deadline":
            instance.remediation_deadline = action_request.value or None
    await db.flush()
    await refresh_instances(db, org_id, [i.id for i in instances])

    found = {i.id for i in instances}
    not_found = [i for i in ids if i not in found]
    _audit(
        db, current_user, org_id, f"vulnmgmt.bulk_{action_request.action}", "vulnerability_instance", None,
        f"Bulk {action_request.action} on {len(instances)} instance(s)",
        {"instance_ids": sorted(found), "value": action_request.value},
    )
    await db.commit()
    return {"updated": len(instances), "not_found": not_found}


# Scan Profile Endpoints
@router.get("/scan-profiles", response_model=ScanProfileListResponse)
async def list_scan_profiles(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    enabled_only: bool = False,
):
    """List scan profiles"""

    query = select(ScanProfile).where(ScanProfile.organization_id == org_id)

    if enabled_only:
        query = query.where(ScanProfile.enabled == True)  # noqa: E712

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    result = await db.execute(query.order_by(ScanProfile.created_at.desc()).offset(offset).limit(size))
    items = result.scalars().all()

    return ScanProfileListResponse(
        items=[ScanProfileResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 1,
    )


@router.post("/scan-profiles", response_model=ScanProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_profile(
    profile_data: ScanProfileCreate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Create scan profile"""
    profile_data.organization_id = org_id

    profile = ScanProfile(**profile_data.model_dump())
    db.add(profile)
    await db.commit()
    await db.refresh(profile)

    return ScanProfileResponse.model_validate(profile)


@router.put("/scan-profiles/{profile_id}", response_model=ScanProfileResponse)
async def update_scan_profile(
    profile_data: ScanProfileUpdate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    profile_id: str = Path(...),
):
    """Update scan profile"""
    profile = await get_or_404(db, ScanProfile, profile_id, org_id)

    update_data = profile_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(profile, key, value)

    await db.commit()
    await db.refresh(profile)
    return ScanProfileResponse.model_validate(profile)


# Patch Operation Endpoints
@router.get("/patch-operations", response_model=PatchOperationListResponse)
async def list_patch_operations(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """List patch operations (newest first) with their instance and CVE."""

    query = select(PatchOperation).where(PatchOperation.organization_id == org_id)

    if status:
        query = query.where(PatchOperation.deployment_status == status)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    result = await db.execute(query.order_by(PatchOperation.created_at.desc()).offset(offset).limit(size))
    items = list(result.scalars().all())

    info: dict[str, tuple] = {}
    if items:
        for inst_id, vuln_id, cve_id, severity, asset_name, asset_ip, inst_status in (
            await db.execute(
                select(
                    VulnerabilityInstance.id,
                    Vulnerability.id,
                    Vulnerability.cve_id,
                    Vulnerability.severity,
                    VulnerabilityInstance.asset_name,
                    VulnerabilityInstance.asset_ip,
                    VulnerabilityInstance.status,
                )
                .join(Vulnerability, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
                .where(
                    VulnerabilityInstance.organization_id == org_id,
                    VulnerabilityInstance.id.in_({op.vulnerability_instance_id for op in items}),
                )
            )
        ).all():
            info[inst_id] = (vuln_id, cve_id, severity, asset_name or asset_ip, inst_status)

    responses = []
    for op in items:
        resp = PatchOperationResponse.model_validate(op)
        if op.vulnerability_instance_id in info:
            resp.vulnerability_id, resp.cve_id, resp.severity, resp.asset_name, resp.instance_status = info[
                op.vulnerability_instance_id
            ]
        responses.append(resp)

    return PatchOperationListResponse(
        items=responses,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 1,
    )


@router.post("/patch-operations/create-plan")
async def create_patch_plan(
    plan_request: PatchPlanRequest,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create one patch operation per vulnerability instance id.

    Instances with an active (pending / scheduled / deploying) operation or a
    closed status are skipped with the reason. ``maintenance_window`` becomes
    the deployment date (status ``scheduled``). Open instances move to
    ``in_progress``. Record-keeping: nothing is pushed to hosts.
    """
    result = await db.execute(
        select(VulnerabilityInstance).where(
            and_(
                VulnerabilityInstance.id.in_(plan_request.vulnerability_instance_ids),
                VulnerabilityInstance.organization_id == org_id,
            )
        )
    )
    instances = list(result.scalars().all())

    if not instances:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No instances found",
        )
    if plan_request.maintenance_window and parse_iso(plan_request.maintenance_window) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_maintenance_window", "detail": "maintenance_window must be an ISO datetime"},
        )

    orchestrator = PatchOrchestrator(org_id)
    created, skipped = await orchestrator.create_patch_operations(
        db, instances, plan_request.maintenance_window, plan_request.notes,
    )
    found = {i.id for i in instances}
    skipped.extend(
        {"instance_id": i, "reason": "not_found"} for i in plan_request.vulnerability_instance_ids if i not in found
    )
    _audit(
        db, current_user, org_id, "vulnmgmt.patch_plan", "patch_operation", created[0].id if created else None,
        f"Patch plan: {len(created)} operation(s) created, {len(skipped)} skipped",
        {"patch_operation_ids": [op.id for op in created], "skipped": skipped},
    )
    await db.commit()
    if not created:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "nothing_to_plan", "skipped": skipped},
        )

    return {
        "plan_id": created[0].id,
        "instances": len(instances),
        "patch_operation_ids": [op.id for op in created],
        "created": len(created),
        "skipped": skipped,
        "deployment_dispatched": False,
    }


@router.post("/patch-operations/{patch_id}/schedule")
async def schedule_patch(
    schedule_request: PatchDeploymentRequest,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Record the planned deployment date of a patch operation.

    Record-keeping only. There is no patch deployment integration: nothing is
    sent to hosts and the response says so (``deployment_dispatched: false``).
    409 ``not_schedulable`` for an operation already deployed, verified or
    rolled back.
    """
    patch = await get_or_404(db, PatchOperation, patch_id, org_id)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.schedule_deployment(db, patch.id, schedule_request.deployment_date)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "not_schedulable", "deployment_status": patch.deployment_status},
        )

    if schedule_request.change_ticket_id:
        patch.change_ticket_id = schedule_request.change_ticket_id
    _audit(db, current_user, org_id, "vulnmgmt.patch_schedule", "patch_operation", patch.id,
           f"Patch deployment date recorded: {schedule_request.deployment_date}")
    await db.commit()
    await db.refresh(patch)
    response_dict = PatchOperationResponse.model_validate(patch).model_dump()
    response_dict["agent_command_id"] = None
    response_dict["deployment_dispatched"] = False
    response_dict["detail"] = (
        "Deployment date recorded. No patch was pushed to any host: "
        "automated patch deployment is not implemented."
    )
    return response_dict


@router.post("/patch-operations/{patch_id}/verify")
async def verify_patch(
    verification_request: PatchVerificationRequest,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Record the caller's verification result for a patch deployment.

    Record-keeping: the status follows the submitted ``passed`` flag; the
    platform does not re-check the host. A pass marks the instance patched
    (``remediated_at`` stamped); a failure re-opens it. The next scanner
    import re-opens a "patched" instance the scanner still reports.
    """
    patch = await get_or_404(db, PatchOperation, patch_id, org_id)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.verify_patch(db, patch.id, verification_request.verification_results)
    _audit(db, current_user, org_id, "vulnmgmt.patch_verify", "patch_operation", patch.id,
           f"Patch verification recorded: {'passed' if success else 'failed'}",
           {"verification_results": verification_request.verification_results})
    await db.commit()

    await db.refresh(patch)
    return {
        "success": success,
        "patch_id": patch_id,
        "status": patch.deployment_status,
        "recorded_only": True,
    }


@router.post("/patch-operations/{patch_id}/rollback")
async def rollback_patch(
    rollback_request: PatchRollbackRequest,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Record a rollback of a patch deployment.

    Record-keeping: marks the operation rolled back with the reason (and
    re-opens a patched instance); nothing is executed on hosts. 409
    ``not_reversible`` when nothing was deployed (pending / scheduled) or the
    operation is not rollback-capable.
    """
    patch = await get_or_404(db, PatchOperation, patch_id, org_id)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.rollback_patch(db, patch.id, rollback_request.reason)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "not_reversible", "deployment_status": patch.deployment_status},
        )

    _audit(db, current_user, org_id, "vulnmgmt.patch_rollback", "patch_operation", patch.id,
           f"Patch rollback recorded: {rollback_request.reason}")
    await db.commit()
    await db.refresh(patch)
    return {
        "success": success,
        "patch_id": patch_id,
        "status": patch.deployment_status,
        "recorded_only": True,
    }


# Exception and Risk Acceptance Endpoints
@router.get("/exceptions")
async def list_exceptions(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None, description="active or expired"),
):
    """List vulnerability exceptions for the caller's tenant.

    ``{items, total, page, size, pages}``; each item carries the computed
    ``status`` (active / expired by ``expiry_date``), the instance's
    ``vulnerability_id`` / ``cve_id`` / ``asset_name``.
    """
    query = select(VulnerabilityException).where(VulnerabilityException.organization_id == org_id)
    now = now_iso()
    if status == "expired":
        query = query.where(VulnerabilityException.expiry_date.is_not(None), VulnerabilityException.expiry_date < now)
    elif status == "active":
        query = query.where(
            (VulnerabilityException.expiry_date.is_(None)) | (VulnerabilityException.expiry_date >= now)
        )
    elif status:
        # ``status`` is the query parameter here (it shadows fastapi.status).
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_status", "allowed": ["active", "expired"]},
        )

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    result = await db.execute(query.order_by(VulnerabilityException.created_at.desc()).limit(size).offset(offset))
    rows = list(result.scalars().all())
    items = [r.model_dump() for r in await _exception_responses(db, org_id, rows)]

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total else 0,
    }


@router.post("/exceptions", response_model=VulnerabilityExceptionResponse, status_code=status.HTTP_201_CREATED)
async def create_exception(
    exception_data: VulnerabilityExceptionCreate,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Record an exception on a vulnerability instance.

    The instance takes the status the exception type implies (risk_accepted /
    not_applicable -> accepted, false_positive -> false_positive,
    compensating_control -> mitigated, deferred -> deferred); when every
    exception on it has expired the hourly refresh re-opens it. Audited.
    """
    exception_data.organization_id = org_id
    instance = await get_or_404(db, VulnerabilityInstance, exception_data.vulnerability_instance_id, org_id)
    exception_type = exception_data.exception_type or ExceptionType.RISK_ACCEPTED.value
    if exception_type not in EXCEPTION_STATUS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_exception_type", "allowed": sorted(EXCEPTION_STATUS)},
        )
    if exception_data.expiry_date and parse_iso(exception_data.expiry_date) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_expiry_date", "detail": "expiry_date must be an ISO date or datetime"},
        )

    data = exception_data.model_dump()
    data["exception_type"] = exception_type
    exception = VulnerabilityException(**data)
    db.add(exception)
    old_status = instance.status
    apply_status_change(instance, EXCEPTION_STATUS[exception_type])
    await db.flush()
    await refresh_instances(db, org_id, [instance.id])
    _audit(
        db, current_user, org_id, "vulnmgmt.exception_create", "vulnerability_exception", exception.id,
        f"{exception_type} exception on instance {instance.id} (status {old_status} -> {instance.status})",
        {"instance_id": instance.id, "expiry_date": exception.expiry_date},
    )
    await db.commit()
    await db.refresh(exception)

    return (await _exception_responses(db, org_id, [exception]))[0]


@router.put("/exceptions/{exception_id}", response_model=VulnerabilityExceptionResponse)
async def update_exception(
    exception_data: VulnerabilityExceptionUpdate,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
    exception_id: str = Path(...),
):
    """Update a vulnerability exception (audited)."""
    exception = await get_or_404(db, VulnerabilityException, exception_id, org_id)

    update_data = exception_data.model_dump(exclude_unset=True)
    if "exception_type" in update_data and update_data["exception_type"] not in EXCEPTION_STATUS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_exception_type", "allowed": sorted(EXCEPTION_STATUS)},
        )
    if update_data.get("expiry_date") and parse_iso(update_data["expiry_date"]) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_expiry_date", "detail": "expiry_date must be an ISO date or datetime"},
        )
    for key, value in update_data.items():
        setattr(exception, key, value)
    _audit(db, current_user, org_id, "vulnmgmt.exception_update", "vulnerability_exception", exception.id,
           "Exception updated", update_data)

    await db.commit()
    await db.refresh(exception)
    return (await _exception_responses(db, org_id, [exception]))[0]


# Dashboard and Reporting Endpoints
@router.get("/dashboard", response_model=DashboardMetrics)
async def get_dashboard(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Vulnerability management dashboard, aggregated from stored rows.

    ``total_vulnerabilities`` / ``critical_vulnerabilities`` count catalogue
    rows; ``by_severity`` / ``open_findings`` count open instances; SLA and
    risk read the values the import / hourly refresh wrote on each instance;
    ``mttr_days`` is None until an instance has been remediated; KEV
    compliance covers instances of KEV-listed CVEs only.
    """

    prioritizer = RiskPrioritizer(org_id)
    orchestrator = PatchOrchestrator(org_id)
    lifecycle = VulnerabilityLifecycle(org_id)
    kev_monitor = KEVMonitor(org_id)

    sla_compliance = await prioritizer.assess_sla_compliance(db)
    patch_report = await orchestrator.generate_patch_report(db)
    trends = await lifecycle.trend_analysis(db, days=30)
    aging = await lifecycle.aging_analysis(db)
    kev_compliance = await kev_monitor.check_kev_compliance(db)
    risk_matrix_counts = await prioritizer.generate_risk_matrix(db)
    by_severity = await lifecycle.severity_counts(db, open_only=True)
    mttr_days = await lifecycle.track_mean_time_to_remediate(db)

    open_filter = and_(
        VulnerabilityInstance.organization_id == org_id,
        VulnerabilityInstance.status.in_(sorted(OPEN_STATUSES)),
    )
    result = await db.execute(
        select(VulnerabilityInstance)
        .where(open_filter, VulnerabilityInstance.risk_score.is_not(None))
        .order_by(VulnerabilityInstance.risk_score.desc())
        .limit(10)
    )
    top_vulns = list(result.scalars().all())

    async def _count(stmt: Any) -> int:
        return int((await db.execute(stmt)).scalar() or 0)

    total_vulnerabilities = await _count(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.organization_id == org_id)
    )
    critical_vulnerabilities = await _count(
        select(func.count())
        .select_from(Vulnerability)
        .where(and_(Vulnerability.organization_id == org_id, Vulnerability.severity == "critical"))
    )
    kev_listed_count = await _count(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.organization_id == org_id, Vulnerability.kev_listed == True)  # noqa: E712
    )
    total_instances = await _count(
        select(func.count(VulnerabilityInstance.id)).where(VulnerabilityInstance.organization_id == org_id)
    )
    open_findings = await _count(select(func.count(VulnerabilityInstance.id)).where(open_filter))
    assets_affected = await _count(
        select(
            func.count(
                func.distinct(
                    func.coalesce(
                        VulnerabilityInstance.asset_id, VulnerabilityInstance.asset_ip, VulnerabilityInstance.asset_name,
                    )
                )
            )
        ).where(open_filter)
    )
    open_kev_instances = await _count(
        select(func.count(VulnerabilityInstance.id)).where(
            open_filter,
            VulnerabilityInstance.vulnerability_id.in_(
                select(Vulnerability.id).where(Vulnerability.organization_id == org_id, Vulnerability.kev_listed == True)  # noqa: E712
            ),
        )
    )

    # Patch compliance: verified + deployed operations over all operations.
    total_ops = patch_report.get("total_operations", 0) or 0
    patched_ops = (patch_report.get("verified", 0) or 0) + (patch_report.get("deployed", 0) or 0)
    patch_pct = round((patched_ops / total_ops) * 100.0, 1) if total_ops > 0 else 0.0

    return DashboardMetrics(
        total_vulnerabilities=total_vulnerabilities,
        critical_vulnerabilities=critical_vulnerabilities,
        mttr_days=mttr_days,
        mean_time_to_remediate_days=mttr_days,
        risk_matrix=RiskMatrix(severity_x_exploitability=risk_matrix_counts),
        sla_compliance=SLAComplianceMetrics(**sla_compliance),
        patch_compliance={
            "total_vulnerabilities": total_ops,
            "patched": patched_ops,
            "compliance_percentage": patch_pct,
        },
        trends_30_days=trends,
        aging=aging,
        top_vulnerabilities=await _instance_responses(db, org_id, top_vulns),
        kev_compliance=KEVComplianceReport(
            report_date=datetime.now(timezone.utc).isoformat(),
            total_kev_tracked=kev_compliance["tracked"],
            kev_patched=kev_compliance["patched"],
            kev_compliant=kev_compliance["compliant"],
            kev_non_compliant=kev_compliance["non_compliant"],
            compliance_percentage=kev_compliance["compliance_percentage"],
        ),
        by_severity=by_severity,
        open_findings=open_findings,
        total_instances=total_instances,
        assets_affected=assets_affected,
        kev_listed_count=kev_listed_count,
        open_kev_instances=open_kev_instances,
    )


@router.get("/report/executive")
async def get_executive_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Executive summary from stored instances (MTTR None until something is remediated)."""
    lifecycle = VulnerabilityLifecycle(org_id)
    return await lifecycle.generate_executive_report(db)


@router.get("/report/kev-compliance")
async def get_kev_compliance_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """BOD 22-01 report over instances of KEV-listed CVEs only
    (``compliance_percentage`` None when none is tracked)."""
    kev_monitor = KEVMonitor(org_id)
    return await kev_monitor.generate_bod_22_01_report(db)


@router.post("/instances/refresh-scores")
async def refresh_instance_scores(
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Recompute risk / SLA on every instance of the org now (capped at
    50,000 rows per call; the hourly task covers the rest) and re-open
    instances whose exceptions have all expired."""
    from src.vulnmgmt.engine import reopen_expired_exceptions

    reopened = await reopen_expired_exceptions(db, org_id)
    result = await refresh_instances(db, org_id)
    result["reopened_after_exception_expiry"] = reopened
    _audit(db, current_user, org_id, "vulnmgmt.refresh_scores", "vulnerability_instance", None,
           f"Risk / SLA refreshed on {result['instances_refreshed']} instance(s)", result)
    await db.commit()
    return result
