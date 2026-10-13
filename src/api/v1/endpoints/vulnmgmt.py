"""Vulnerability management API endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import Depends, APIRouter, Path, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.models.user import User, UserRole
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.services.automation import AutomationService
from src.schemas.vulnmgmt import (
    BulkAction,
    DashboardMetrics,
    ExecutiveReport,
    KEVComplianceReport,
    PatchDeploymentRequest,
    PatchOperationCreate,
    PatchOperationListResponse,
    PatchOperationResponse,
    PatchOperationUpdate,
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
from src.vulnmgmt.engine import (
    KEVMonitor,
    PatchOrchestrator,
    RiskPrioritizer,
    VulnerabilityLifecycle,
    VulnerabilityScanner,
)
from src.vulnmgmt.models import (
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


async def get_or_404(db: AsyncSession, model: type, item_id: str, org_id: str) -> any:
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
    """List vulnerabilities with filtering and pagination"""

    query = select(Vulnerability).where(Vulnerability.organization_id == org_id)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (Vulnerability.cve_id.ilike(search_filter))
            | (Vulnerability.title.ilike(search_filter))
            | (Vulnerability.description.ilike(search_filter))
        )

    if severity:
        query = query.where(Vulnerability.severity == severity)

    if kev_only:
        query = query.where(Vulnerability.kev_listed == True)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(Vulnerability, sort_by, Vulnerability.created_at)
    if sort_order == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    items = result.scalars().all()

    return VulnerabilityListResponse(
        items=[VulnerabilityResponse.model_validate(item) for item in items],
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
    """Create a vulnerability record"""
    vuln_data.organization_id = org_id

    vuln = Vulnerability(**vuln_data.dict())
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
    except Exception as e:
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
    """Update a vulnerability"""
    vuln = await get_or_404(db, Vulnerability, vuln_id, org_id)

    update_data = vuln_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(vuln, key, value)

    await db.commit()
    await db.refresh(vuln)
    return VulnerabilityResponse.model_validate(vuln)


@router.post("/vulnerabilities/import-scan", response_model=None)
async def import_scan_results(
    scan_request: ScanImportRequest,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Import vulnerability scan results.

    Critical + high-severity new vulnerabilities fire
    ``automation.on_vulnerability_found`` one by one so each lands an
    Alert that runs the full cross-module pipeline (IOC match,
    auto-incident, war room, remediation policy eval, agent
    containment). This closes the loop from scanner import through
    to agent-level response — previously a Nessus import of 500
    critical CVEs created DB rows (or before Page 18, not even that)
    without ever notifying anyone.
    """

    try:
        scanner = VulnerabilityScanner(org_id)
        result = await scanner.import_scan_results(
            db,
            scan_format=scan_request.scan_format,
            scan_data=scan_request.scan_data,
            scan_id=scan_request.scan_profile_id,
            discovery_source=scan_request.scan_format,
        )

        # Fan out each new critical/high finding into the automation
        # pipeline. Capped at 50 events per import to protect against
        # a poisoned scan file producing 50,000 alerts in a loop.
        new_critical = result.get("new_critical") or []
        automation_fired = 0
        if new_critical:
            try:
                automation = AutomationService(db)
                for finding in new_critical[:50]:
                    try:
                        await automation.on_vulnerability_found(
                            cve_id=finding.get("cve_id", "UNKNOWN"),
                            title=finding.get("title", "Unknown"),
                            affected_asset=finding.get("asset_name", "unknown"),
                            severity=finding.get("severity", "high"),
                            organization_id=org_id,
                        )
                        automation_fired += 1
                    except Exception as inner_exc:  # noqa: BLE001
                        logger.warning(
                            "on_vulnerability_found failed",
                            cve=finding.get("cve_id"),
                            error=str(inner_exc),
                        )
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"Automation fan-out failed on import: {exc}")
        result["automation_events_fired"] = automation_fired

        logger.info(
            "Scan imported successfully",
            org_id=org_id,
            result=result,
        )
        return result
    except Exception as e:
        logger.error(
            "Scan import failed",
            org_id=org_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan import failed: {str(e)}",
        )


@router.post("/vulnerabilities/sync-kev")
async def sync_kev(
    kev_data: dict,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Sync CISA Known Exploited Vulnerabilities"""

    try:
        monitor = KEVMonitor(org_id)
        result = await monitor.sync_cisa_kev(db, kev_data)
        logger.info(
            "KEV sync completed",
            org_id=org_id,
            result=result,
        )
        return result
    except Exception as e:
        logger.error(
            "KEV sync failed",
            org_id=org_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"KEV sync failed: {str(e)}",
        )


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
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List vulnerability instances with filtering"""

    query = select(VulnerabilityInstance).where(
        VulnerabilityInstance.organization_id == org_id
    )

    # Apply filters
    if asset_id:
        query = query.where(VulnerabilityInstance.asset_id == asset_id)

    if vulnerability_id:
        query = query.where(VulnerabilityInstance.vulnerability_id == vulnerability_id)

    if status:
        query = query.where(VulnerabilityInstance.status == status)

    if assigned_to:
        query = query.where(VulnerabilityInstance.assigned_to == assigned_to)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (VulnerabilityInstance.asset_name.ilike(search_filter))
            | (VulnerabilityInstance.asset_ip.ilike(search_filter))
        )

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(VulnerabilityInstance, sort_by, VulnerabilityInstance.created_at)
    if sort_order == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    items = result.scalars().all()

    return VulnerabilityInstanceListResponse(
        items=[VulnerabilityInstanceResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 1,
    )


@router.post("/instances", response_model=VulnerabilityInstanceResponse, status_code=status.HTTP_201_CREATED)
async def create_instance(
    instance_data: VulnerabilityInstanceCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create vulnerability instance (its vulnerability must be in the caller's org)."""
    instance_data.organization_id = org_id
    await get_or_404(db, Vulnerability, instance_data.vulnerability_id, org_id)

    instance = VulnerabilityInstance(**instance_data.dict())
    db.add(instance)
    await db.commit()
    await db.refresh(instance)

    return VulnerabilityInstanceResponse.model_validate(instance)


@router.get("/instances/{instance_id}", response_model=VulnerabilityInstanceResponse)
async def get_instance(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    instance_id: str = Path(...),
):
    """Get vulnerability instance by ID"""
    instance = await get_or_404(
        db, VulnerabilityInstance, instance_id, org_id
    )
    return VulnerabilityInstanceResponse.model_validate(instance)


@router.put("/instances/{instance_id}", response_model=VulnerabilityInstanceResponse)
async def update_instance(
    instance_data: VulnerabilityInstanceUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    instance_id: str = Path(...),
):
    """Update vulnerability instance"""
    instance = await get_or_404(
        db, VulnerabilityInstance, instance_id, org_id
    )

    update_data = instance_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(instance, key, value)

    await db.commit()
    await db.refresh(instance)
    return VulnerabilityInstanceResponse.model_validate(instance)


@router.post("/instances/bulk-action")
async def bulk_action_instances(
    action_request: BulkAction,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Perform bulk action on vulnerability instances"""

    result = await db.execute(
        select(VulnerabilityInstance).where(
            and_(
                VulnerabilityInstance.id.in_(action_request.instance_ids),
                VulnerabilityInstance.organization_id == org_id,
            )
        )
    )
    instances = result.scalars().all()

    if not instances:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No instances found",
        )

    # Apply bulk action
    for instance in instances:
        if action_request.action == "update_status":
            instance.status = action_request.value
        elif action_request.action == "assign":
            instance.assigned_to = action_request.value
        elif action_request.action == "set_deadline":
            instance.remediation_deadline = action_request.value

    await db.commit()
    return {"updated": len(instances)}


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
        query = query.where(ScanProfile.enabled == True)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
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

    profile = ScanProfile(**profile_data.dict())
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
    profile = await get_or_404(
        db, ScanProfile, profile_id, org_id
    )

    update_data = profile_data.dict(exclude_unset=True)
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
    """List patch operations"""

    query = select(PatchOperation).where(PatchOperation.organization_id == org_id)

    if status:
        query = query.where(PatchOperation.deployment_status == status)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    items = result.scalars().all()

    return PatchOperationListResponse(
        items=[PatchOperationResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 1,
    )


@router.post("/patch-operations/create-plan")
async def create_patch_plan(
    plan_request: PatchPlanRequest,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create patch deployment plan"""

    # Get instances
    result = await db.execute(
        select(VulnerabilityInstance).where(
            and_(
                VulnerabilityInstance.id.in_(plan_request.vulnerability_instance_ids),
                VulnerabilityInstance.organization_id == org_id,
            )
        )
    )
    instances = result.scalars().all()

    if not instances:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No instances found",
        )

    orchestrator = PatchOrchestrator(org_id)
    plan_id = await orchestrator.create_patch_plan(db, instances)

    return {"plan_id": plan_id, "instances": len(instances)}


@router.post("/patch-operations/{patch_id}/schedule")
async def schedule_patch(
    schedule_request: PatchDeploymentRequest,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Record the planned deployment date of a patch operation.

    Record-keeping only. There is no patch deployment integration: the old
    handler queued an agent command that merely echoed "scheduled" on the
    host while reporting a dispatch. Nothing is sent to hosts now, and the
    response says so (``deployment_dispatched: false``).
    """
    patch = await get_or_404(db, PatchOperation, patch_id, org_id)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.schedule_deployment(db, patch.id, schedule_request.deployment_date)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to schedule patch",
        )

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
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Record the caller's verification result for a patch deployment.

    Record-keeping: the status follows the submitted ``passed`` flag; the
    platform does not re-check the host.
    """
    patch = await get_or_404(db, PatchOperation, patch_id, org_id)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.verify_patch(
        db,
        patch.id,
        verification_request.verification_results,
    )

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
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Record a rollback of a patch deployment.

    Record-keeping: marks the operation rolled back with the reason; nothing
    is executed on hosts.
    """
    patch = await get_or_404(db, PatchOperation, patch_id, org_id)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.rollback_patch(db, patch.id, rollback_request.reason)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to rollback patch",
        )

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
    status: Optional[str] = Query(None, description="Filter by exception status"),
):
    """List vulnerability exceptions for the caller's tenant.

    Backs the VulnManagement "Exceptions" tab. Returns a simple paginated
    payload shaped like the other list endpoints: ``{items, total, page,
    size, pages}``. Tenant-scoped on ``organization_id`` so one org can
    never see another org's exceptions.
    """
    query = select(VulnerabilityException).where(VulnerabilityException.organization_id == org_id)
    if status and hasattr(VulnerabilityException, "status"):
        query = query.where(VulnerabilityException.status == status)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    result = await db.execute(
        query.order_by(VulnerabilityException.created_at.desc()).limit(size).offset(offset)
    )
    rows = result.scalars().all()
    items = [VulnerabilityExceptionResponse.model_validate(r).model_dump() for r in rows]

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
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create vulnerability exception"""
    exception_data.organization_id = org_id
    await get_or_404(db, VulnerabilityInstance, exception_data.vulnerability_instance_id, org_id)

    exception = VulnerabilityException(**exception_data.dict())
    db.add(exception)
    await db.commit()
    await db.refresh(exception)

    return VulnerabilityExceptionResponse.model_validate(exception)


@router.put("/exceptions/{exception_id}", response_model=VulnerabilityExceptionResponse)
async def update_exception(
    exception_data: VulnerabilityExceptionUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    exception_id: str = Path(...),
):
    """Update vulnerability exception"""
    exception = await get_or_404(
        db, VulnerabilityException, exception_id, org_id
    )

    update_data = exception_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(exception, key, value)

    await db.commit()
    await db.refresh(exception)
    return VulnerabilityExceptionResponse.model_validate(exception)


# Dashboard and Reporting Endpoints
@router.get("/dashboard", response_model=DashboardMetrics)
async def get_dashboard(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get vulnerability management dashboard metrics.

    Previously shipped three hardcoded fake fields:
      - risk_matrix.severity_x_exploitability = {} (empty dict)
      - patch_compliance.compliance_percentage = 0.0
      - kev_compliance.total_kev_tracked / kev_patched = 0

    All three are now computed from real data.
    """

    prioritizer = RiskPrioritizer(org_id)
    orchestrator = PatchOrchestrator(org_id)
    lifecycle = VulnerabilityLifecycle(org_id)
    kev_monitor = KEVMonitor(org_id)

    # Gather metrics
    sla_compliance = await prioritizer.assess_sla_compliance(db)
    patch_report = await orchestrator.generate_patch_report(db)
    trends = await lifecycle.trend_analysis(db, days=30)
    aging = await lifecycle.aging_analysis(db)
    kev_compliance = await kev_monitor.check_kev_compliance(db)
    # Real severity × exploit counts (was hardcoded {})
    risk_matrix_counts = await prioritizer.generate_risk_matrix(db)

    # Get top vulnerabilities
    result = await db.execute(
        select(VulnerabilityInstance).where(
            VulnerabilityInstance.organization_id == org_id
        ).order_by(VulnerabilityInstance.risk_score.desc()).limit(10)
    )
    top_vulns = result.scalars().all()

    # Catalog counts for the summary cards (org-scoped).
    total_vulnerabilities = (
        await db.execute(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.organization_id == org_id)
        )
    ).scalar() or 0
    critical_vulnerabilities = (
        await db.execute(
            select(func.count())
            .select_from(Vulnerability)
            .where(and_(Vulnerability.organization_id == org_id, Vulnerability.severity == "critical"))
        )
    ).scalar() or 0

    # MTTR only exists once something has been remediated; with nothing
    # remediated it is unknown (None), not 0 days.
    remediated_count = (
        await db.execute(
            select(func.count())
            .select_from(VulnerabilityInstance)
            .where(
                and_(
                    VulnerabilityInstance.organization_id == org_id,
                    VulnerabilityInstance.status.in_(["patched", "mitigated"]),
                )
            )
        )
    ).scalar() or 0
    mttr_days = await lifecycle.track_mean_time_to_remediate(db) if remediated_count else None

    # --- Real patch_compliance_percentage ---
    total_ops = patch_report.get("total_operations", 0) or 0
    patched_ops = (patch_report.get("verified", 0) or 0) + (patch_report.get("deployed", 0) or 0)
    patch_pct = round((patched_ops / total_ops) * 100.0, 1) if total_ops > 0 else 0.0

    # --- Real KEV tracked/patched totals ---
    # check_kev_compliance returns compliant/non_compliant; total is
    # their sum, and kev_patched is the compliant count (BOD 22-01
    # defines compliant as "patched within the due date").
    kev_total = int(kev_compliance.get("compliant", 0) or 0) + int(
        kev_compliance.get("non_compliant", 0) or 0
    )
    kev_patched = int(kev_compliance.get("compliant", 0) or 0)

    return DashboardMetrics(
        total_vulnerabilities=total_vulnerabilities,
        critical_vulnerabilities=critical_vulnerabilities,
        mttr_days=mttr_days,
        risk_matrix=RiskMatrix(severity_x_exploitability=risk_matrix_counts),
        sla_compliance=SLAComplianceMetrics(
            total=sla_compliance["total"],
            within_sla=sla_compliance["within_sla"],
            approaching=sla_compliance["approaching"],
            breached=sla_compliance["breached"],
            compliance_percentage=sla_compliance["compliance_percentage"],
        ),
        patch_compliance={
            "total_vulnerabilities": total_ops,
            "patched": patched_ops,
            "compliance_percentage": patch_pct,
        },
        trends_30_days=trends,
        aging=aging,
        top_vulnerabilities=[VulnerabilityInstanceResponse.model_validate(v) for v in top_vulns],
        kev_compliance=KEVComplianceReport(
            report_date=datetime.now(timezone.utc).isoformat(),
            total_kev_tracked=kev_total,
            kev_patched=kev_patched,
            kev_compliant=kev_compliance["compliant"],
            kev_non_compliant=kev_compliance["non_compliant"],
            compliance_percentage=kev_compliance["compliance_percentage"],
        ),
    )


@router.get("/report/executive")
async def get_executive_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get executive summary report"""

    lifecycle = VulnerabilityLifecycle(org_id)
    report = await lifecycle.generate_executive_report(db)

    return report


@router.get("/report/kev-compliance")
async def get_kev_compliance_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get BOD 22-01 KEV compliance report"""

    kev_monitor = KEVMonitor(org_id)
    report = await kev_monitor.generate_bod_22_01_report(db)

    return report
