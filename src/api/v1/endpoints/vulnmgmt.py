"""Vulnerability management API endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Path, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
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
    current_user: CurrentUser = None,
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
    org_id = getattr(current_user, "organization_id", None)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a vulnerability record"""
    vuln_data.organization_id = getattr(current_user, "organization_id", None)

    vuln = Vulnerability(**vuln_data.dict())
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)

    # Trigger automation for new vulnerability
    try:
        org_id = getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    vuln_id: str = Path(...),
):
    """Get vulnerability by ID"""
    vuln = await get_or_404(db, Vulnerability, vuln_id, getattr(current_user, "organization_id", None))
    return VulnerabilityResponse.model_validate(vuln)


@router.put("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_data: VulnerabilityUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    vuln_id: str = Path(...),
):
    """Update a vulnerability"""
    vuln = await get_or_404(db, Vulnerability, vuln_id, getattr(current_user, "organization_id", None))

    update_data = vuln_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(vuln, key, value)

    await db.commit()
    await db.refresh(vuln)
    return VulnerabilityResponse.model_validate(vuln)


@router.post("/vulnerabilities/import-scan", response_model=None)
async def import_scan_results(
    scan_request: ScanImportRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Import vulnerability scan results"""
    org_id = getattr(current_user, "organization_id", None)

    try:
        scanner = VulnerabilityScanner(org_id)
        result = await scanner.import_scan_results(
            db,
            scan_format=scan_request.scan_format,
            scan_data=scan_request.scan_data,
            scan_id=scan_request.scan_profile_id,
            discovery_source=scan_request.scan_format,
        )
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Sync CISA Known Exploited Vulnerabilities"""
    org_id = getattr(current_user, "organization_id", None)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    asset_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List vulnerability instances with filtering"""
    org_id = getattr(current_user, "organization_id", None)

    query = select(VulnerabilityInstance).where(
        VulnerabilityInstance.organization_id == org_id
    )

    # Apply filters
    if asset_id:
        query = query.where(VulnerabilityInstance.asset_id == asset_id)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create vulnerability instance"""
    instance_data.organization_id = getattr(current_user, "organization_id", None)

    instance = VulnerabilityInstance(**instance_data.dict())
    db.add(instance)
    await db.commit()
    await db.refresh(instance)

    return VulnerabilityInstanceResponse.model_validate(instance)


@router.get("/instances/{instance_id}", response_model=VulnerabilityInstanceResponse)
async def get_instance(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    instance_id: str = Path(...),
):
    """Get vulnerability instance by ID"""
    instance = await get_or_404(
        db, VulnerabilityInstance, instance_id, getattr(current_user, "organization_id", None)
    )
    return VulnerabilityInstanceResponse.model_validate(instance)


@router.put("/instances/{instance_id}", response_model=VulnerabilityInstanceResponse)
async def update_instance(
    instance_data: VulnerabilityInstanceUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    instance_id: str = Path(...),
):
    """Update vulnerability instance"""
    instance = await get_or_404(
        db, VulnerabilityInstance, instance_id, getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Perform bulk action on vulnerability instances"""
    org_id = getattr(current_user, "organization_id", None)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    enabled_only: bool = False,
):
    """List scan profiles"""
    org_id = getattr(current_user, "organization_id", None)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create scan profile"""
    profile_data.organization_id = getattr(current_user, "organization_id", None)

    profile = ScanProfile(**profile_data.dict())
    db.add(profile)
    await db.commit()
    await db.refresh(profile)

    return ScanProfileResponse.model_validate(profile)


@router.put("/scan-profiles/{profile_id}", response_model=ScanProfileResponse)
async def update_scan_profile(
    profile_data: ScanProfileUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    profile_id: str = Path(...),
):
    """Update scan profile"""
    profile = await get_or_404(
        db, ScanProfile, profile_id, getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """List patch operations"""
    org_id = getattr(current_user, "organization_id", None)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create patch deployment plan"""
    org_id = getattr(current_user, "organization_id", None)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Schedule patch deployment"""
    org_id = getattr(current_user, "organization_id", None)

    patch = await get_or_404(db, PatchOperation, patch_id, org_id)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.schedule_deployment(db, patch_id, schedule_request.deployment_date)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to schedule patch",
        )

    await db.refresh(patch)
    return PatchOperationResponse.model_validate(patch)


@router.post("/patch-operations/{patch_id}/verify")
async def verify_patch(
    verification_request: PatchVerificationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Verify patch deployment"""
    org_id = getattr(current_user, "organization_id", None)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.verify_patch(
        db,
        patch_id,
        verification_request.verification_results,
    )

    patch = await get_or_404(db, PatchOperation, patch_id, org_id)
    return {
        "success": success,
        "patch_id": patch_id,
        "status": patch.deployment_status,
    }


@router.post("/patch-operations/{patch_id}/rollback")
async def rollback_patch(
    rollback_request: PatchRollbackRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    patch_id: str = Path(...),
):
    """Rollback patch deployment"""
    org_id = getattr(current_user, "organization_id", None)

    orchestrator = PatchOrchestrator(org_id)
    success = await orchestrator.rollback_patch(db, patch_id, rollback_request.reason)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to rollback patch",
        )

    patch = await get_or_404(db, PatchOperation, patch_id, org_id)
    return {
        "success": success,
        "patch_id": patch_id,
        "status": patch.deployment_status,
    }


# Exception and Risk Acceptance Endpoints
@router.post("/exceptions", response_model=VulnerabilityExceptionResponse, status_code=status.HTTP_201_CREATED)
async def create_exception(
    exception_data: VulnerabilityExceptionCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create vulnerability exception"""
    exception_data.organization_id = getattr(current_user, "organization_id", None)

    exception = VulnerabilityException(**exception_data.dict())
    db.add(exception)
    await db.commit()
    await db.refresh(exception)

    return VulnerabilityExceptionResponse.model_validate(exception)


@router.put("/exceptions/{exception_id}", response_model=VulnerabilityExceptionResponse)
async def update_exception(
    exception_data: VulnerabilityExceptionUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    exception_id: str = Path(...),
):
    """Update vulnerability exception"""
    exception = await get_or_404(
        db, VulnerabilityException, exception_id, getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get vulnerability management dashboard metrics"""
    org_id = getattr(current_user, "organization_id", None)

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

    # Get top vulnerabilities
    result = await db.execute(
        select(VulnerabilityInstance).where(
            VulnerabilityInstance.organization_id == org_id
        ).order_by(VulnerabilityInstance.risk_score.desc()).limit(10)
    )
    top_vulns = result.scalars().all()

    return DashboardMetrics(
        risk_matrix=RiskMatrix(severity_x_exploitability={}),
        sla_compliance=SLAComplianceMetrics(
            total=sla_compliance["total"],
            within_sla=sla_compliance["within_sla"],
            approaching=sla_compliance["approaching"],
            breached=sla_compliance["breached"],
            compliance_percentage=sla_compliance["compliance_percentage"],
        ),
        patch_compliance={
            "total_vulnerabilities": patch_report.get("total_operations", 0),
            "patched": patch_report.get("verified", 0),
            "compliance_percentage": 0.0,
        },
        trends_30_days=trends,
        aging=aging,
        top_vulnerabilities=[VulnerabilityInstanceResponse.model_validate(v) for v in top_vulns],
        kev_compliance=KEVComplianceReport(
            report_date=datetime.now(timezone.utc).isoformat(),
            total_kev_tracked=0,
            kev_patched=0,
            kev_compliant=kev_compliance["compliant"],
            kev_non_compliant=kev_compliance["non_compliant"],
            compliance_percentage=kev_compliance["compliance_percentage"],
        ),
    )


@router.get("/report/executive")
async def get_executive_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get executive summary report"""
    org_id = getattr(current_user, "organization_id", None)

    lifecycle = VulnerabilityLifecycle(org_id)
    report = await lifecycle.generate_executive_report(db)

    return report


@router.get("/report/kev-compliance")
async def get_kev_compliance_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get BOD 22-01 KEV compliance report"""
    org_id = getattr(current_user, "organization_id", None)

    kev_monitor = KEVMonitor(org_id)
    report = await kev_monitor.generate_bod_22_01_report(db)

    return report
