"""API Security Governance endpoints"""

import asyncio
import math
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status, Body
from sqlalchemy import func, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, require_role, OrganizationId
from src.core.logging import get_logger
from src.core.url_validator import validate_url
from src.services.automation import AutomationService

logger = get_logger(__name__)
from src.models.user import User, UserRole
from src.api_security.models import (
    APIEndpointInventory,
    APIVulnerability,
    APISecurityPolicy,
    APIAnomalyDetection,
    APIComplianceCheck,
)
from src.api_security.tasks import (
    security_assessment,
    compliance_check,
    shadow_api_detection,
)
from src.schemas.api_security import (
    APIEndpointInventoryCreate,
    APIEndpointInventoryUpdate,
    APIEndpointInventoryResponse,
    APIEndpointInventoryListResponse,
    APIVulnerabilityCreate,
    APIVulnerabilityUpdate,
    APIVulnerabilityResponse,
    APIVulnerabilityListResponse,
    APIVulnerabilityBulkUpdate,
    APISecurityPolicyCreate,
    APISecurityPolicyUpdate,
    APISecurityPolicyResponse,
    APISecurityPolicyListResponse,
    APIAnomalyDetectionCreate,
    APIAnomalyDetectionUpdate,
    APIAnomalyDetectionResponse,
    APIAnomalyDetectionListResponse,
    APIComplianceCheckCreate,
    APIComplianceCheckUpdate,
    APIComplianceCheckResponse,
    APIComplianceCheckListResponse,
    APISummaryStats,
    APISecurityDashboardResponse,
    APIComplianceReportResponse,
)

router = APIRouter(prefix="/api-security", tags=["API Security"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


# ============================================================================
# API Endpoint Inventory Endpoints
# ============================================================================


async def require_own_endpoint_field(db: AsyncSession, endpoint_id: str, org_id: str) -> None:
    """422 naming ``endpoint_id`` when a supplied id is not an endpoint of this tenant."""
    if not endpoint_id:
        return
    result = await db.execute(
        select(APIEndpointInventory.id).where(
            and_(
                APIEndpointInventory.id == endpoint_id,
                APIEndpointInventory.organization_id == org_id,
            )
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_field",
                "field": "endpoint_id",
                "detail": "endpoint_id is not an API endpoint of this organisation",
            },
        )


async def get_endpoint_or_404(db: AsyncSession, endpoint_id: str, org_id: str) -> APIEndpointInventory:
    """Get endpoint by ID or raise 404 (tenant-scoped)"""
    result = await db.execute(
        select(APIEndpointInventory).where(
            and_(
                APIEndpointInventory.id == endpoint_id,
                APIEndpointInventory.organization_id == org_id,
            )
        )
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found",
        )
    return endpoint


@router.get("/endpoints", response_model=APIEndpointInventoryListResponse)
async def list_endpoints(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    service_name: Optional[str] = None,
    method: Optional[str] = None,
    is_shadow: Optional[bool] = None,
    is_documented: Optional[bool] = None,
    is_deprecated: Optional[bool] = None,
    authentication_type: Optional[str] = None,
    data_classification: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List API endpoints with filtering and pagination"""
    query = select(APIEndpointInventory).where(APIEndpointInventory.organization_id == org_id)

    # Apply filters
    filters = []
    if service_name:
        filters.append(APIEndpointInventory.service_name.ilike(f"%{service_name}%"))
    if method:
        filters.append(APIEndpointInventory.method == method)
    if is_shadow is not None:
        filters.append(APIEndpointInventory.is_shadow == is_shadow)
    if is_documented is not None:
        filters.append(APIEndpointInventory.is_documented == is_documented)
    if is_deprecated is not None:
        filters.append(APIEndpointInventory.is_deprecated == is_deprecated)
    if authentication_type:
        filters.append(APIEndpointInventory.authentication_type == authentication_type)
    if data_classification:
        filters.append(APIEndpointInventory.data_classification == data_classification)

    if filters:
        query = query.where(and_(*filters))

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(APIEndpointInventory, sort_by, APIEndpointInventory.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    endpoints = list(result.scalars().all())

    return APIEndpointInventoryListResponse(
        items=[APIEndpointInventoryResponse.model_validate(e) for e in endpoints],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/endpoints", response_model=APIEndpointInventoryResponse, status_code=status.HTTP_201_CREATED)
async def create_endpoint(
    endpoint_data: APIEndpointInventoryCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new API endpoint"""
    endpoint = APIEndpointInventory(
        **endpoint_data.model_dump(),
        organization_id=org_id,
    )
    db.add(endpoint)
    await db.commit()
    await db.refresh(endpoint)
    return APIEndpointInventoryResponse.model_validate(endpoint)


@router.get("/endpoints/{endpoint_id}", response_model=APIEndpointInventoryResponse)
async def get_endpoint(
    endpoint_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get endpoint by ID"""
    endpoint = await get_endpoint_or_404(db, endpoint_id, org_id)
    return APIEndpointInventoryResponse.model_validate(endpoint)


@router.put("/endpoints/{endpoint_id}", response_model=APIEndpointInventoryResponse)
async def update_endpoint(
    endpoint_id: str,
    endpoint_data: APIEndpointInventoryUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update an API endpoint"""
    endpoint = await get_endpoint_or_404(db, endpoint_id, org_id)

    update_data = endpoint_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(endpoint, field, value)

    await db.commit()
    await db.refresh(endpoint)
    return APIEndpointInventoryResponse.model_validate(endpoint)


@router.delete("/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_endpoint(
    endpoint_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Delete an API endpoint"""
    endpoint = await get_endpoint_or_404(db, endpoint_id, org_id)
    await db.delete(endpoint)
    await db.commit()


# ============================================================================
# API Vulnerability Management Endpoints
# ============================================================================


async def get_vulnerability_or_404(db: AsyncSession, vuln_id: str, org_id: str) -> APIVulnerability:
    """Get vulnerability by ID or raise 404 (tenant-scoped)"""
    result = await db.execute(
        select(APIVulnerability).where(
            and_(APIVulnerability.id == vuln_id, APIVulnerability.organization_id == org_id)
        )
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )
    return vuln


@router.get("/vulnerabilities", response_model=APIVulnerabilityListResponse)
async def list_vulnerabilities(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    endpoint_id: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List API vulnerabilities with filtering and pagination"""
    query = select(APIVulnerability).where(APIVulnerability.organization_id == org_id)

    # Apply filters
    filters = []
    if endpoint_id:
        filters.append(APIVulnerability.endpoint_id == endpoint_id)
    if vulnerability_type:
        filters.append(APIVulnerability.vulnerability_type == vulnerability_type)
    if severity:
        filters.append(APIVulnerability.severity == severity)
    if status:
        filters.append(APIVulnerability.status == status)

    if filters:
        query = query.where(and_(*filters))

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(APIVulnerability, sort_by, APIVulnerability.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    vulns = list(result.scalars().all())

    return APIVulnerabilityListResponse(
        items=[APIVulnerabilityResponse.model_validate(v) for v in vulns],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/vulnerabilities", response_model=APIVulnerabilityResponse, status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    vuln_data: APIVulnerabilityCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new vulnerability"""
    await require_own_endpoint_field(db, vuln_data.endpoint_id, org_id)
    vuln = APIVulnerability(
        **vuln_data.model_dump(),
        organization_id=org_id,
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)

    try:
        automation = AutomationService(db)
        await automation.on_api_security_threat(
            api_endpoint=getattr(vuln, "endpoint", None) or getattr(vuln, "endpoint_id", None) or "",
            threat_type=getattr(vuln, "vulnerability_type", None) or "",
            severity=vuln.severity,
            organization_id=org_id,
        )
    except Exception as automation_exc:
        logger.warning(f"Automation on_api_security_threat failed: {automation_exc}")

    return APIVulnerabilityResponse.model_validate(vuln)


@router.get("/vulnerabilities/{vuln_id}", response_model=APIVulnerabilityResponse)
async def get_vulnerability(
    vuln_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get vulnerability by ID"""
    vuln = await get_vulnerability_or_404(db, vuln_id, org_id)
    return APIVulnerabilityResponse.model_validate(vuln)


@router.put("/vulnerabilities/{vuln_id}", response_model=APIVulnerabilityResponse)
async def update_vulnerability(
    vuln_id: str,
    vuln_data: APIVulnerabilityUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update a vulnerability"""
    vuln = await get_vulnerability_or_404(db, vuln_id, org_id)

    update_data = vuln_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(vuln, field, value)

    await db.commit()
    await db.refresh(vuln)
    return APIVulnerabilityResponse.model_validate(vuln)


@router.post("/vulnerabilities/bulk-update")
async def bulk_update_vulnerabilities(
    bulk_data: APIVulnerabilityBulkUpdate,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Bulk update vulnerabilities in the caller's organization.

    Ids that do not exist in the caller's organization are not touched and
    are returned in ``ignored_ids``.
    """
    result = await db.execute(
        select(APIVulnerability).where(
            APIVulnerability.id.in_(bulk_data.vulnerability_ids),
            APIVulnerability.organization_id == org_id,
        )
    )
    vulns = result.scalars().all()

    for vuln in vulns:
        if bulk_data.status:
            vuln.status = bulk_data.status
        if bulk_data.remediation:
            vuln.remediation = bulk_data.remediation

    await db.commit()
    updated_ids = {str(v.id) for v in vulns}
    ignored_ids = [i for i in dict.fromkeys(bulk_data.vulnerability_ids) if i not in updated_ids]
    if ignored_ids:
        logger.warning(
            "api_security_bulk_update_ignored_ids",
            user_id=str(getattr(current_user, "id", "")),
            organization_id=org_id,
            ignored_count=len(ignored_ids),
        )
    return {"updated_count": len(vulns), "ignored_ids": ignored_ids}


# ============================================================================
# API Security Policy Endpoints
# ============================================================================


async def get_policy_or_404(db: AsyncSession, policy_id: str, org_id: str) -> APISecurityPolicy:
    """Get policy by ID or raise 404 (tenant-scoped)"""
    result = await db.execute(
        select(APISecurityPolicy).where(
            and_(APISecurityPolicy.id == policy_id, APISecurityPolicy.organization_id == org_id)
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )
    return policy


@router.get("/policies", response_model=APISecurityPolicyListResponse)
async def list_policies(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    policy_type: Optional[str] = None,
    enforcement_level: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List API security policies"""
    query = select(APISecurityPolicy).where(APISecurityPolicy.organization_id == org_id)

    # Apply filters
    filters = []
    if policy_type:
        filters.append(APISecurityPolicy.policy_type == policy_type)
    if enforcement_level:
        filters.append(APISecurityPolicy.enforcement_level == enforcement_level)

    if filters:
        query = query.where(and_(*filters))

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(APISecurityPolicy, sort_by, APISecurityPolicy.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    policies = list(result.scalars().all())

    return APISecurityPolicyListResponse(
        items=[APISecurityPolicyResponse.model_validate(p) for p in policies],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/policies", response_model=APISecurityPolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_data: APISecurityPolicyCreate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Create a new security policy"""
    policy = APISecurityPolicy(
        **policy_data.model_dump(),
        organization_id=org_id,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return APISecurityPolicyResponse.model_validate(policy)


@router.get("/policies/{policy_id}", response_model=APISecurityPolicyResponse)
async def get_policy(
    policy_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get policy by ID"""
    policy = await get_policy_or_404(db, policy_id, org_id)
    return APISecurityPolicyResponse.model_validate(policy)


@router.put("/policies/{policy_id}", response_model=APISecurityPolicyResponse)
async def update_policy(
    policy_id: str,
    policy_data: APISecurityPolicyUpdate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Update a security policy"""
    policy = await get_policy_or_404(db, policy_id, org_id)

    update_data = policy_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)

    await db.commit()
    await db.refresh(policy)
    return APISecurityPolicyResponse.model_validate(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Delete a security policy"""
    policy = await get_policy_or_404(db, policy_id, org_id)
    await db.delete(policy)
    await db.commit()


# ============================================================================
# API Anomaly Detection Endpoints
# ============================================================================


async def get_anomaly_or_404(db: AsyncSession, anomaly_id: str, org_id: str) -> APIAnomalyDetection:
    """Get anomaly by ID or raise 404 (tenant-scoped)"""
    result = await db.execute(
        select(APIAnomalyDetection).where(
            and_(APIAnomalyDetection.id == anomaly_id, APIAnomalyDetection.organization_id == org_id)
        )
    )
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anomaly not found",
        )
    return anomaly


@router.get("/anomalies", response_model=APIAnomalyDetectionListResponse)
async def list_anomalies(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    endpoint_id: Optional[str] = None,
    anomaly_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List anomalies with filtering and pagination"""
    query = select(APIAnomalyDetection).where(APIAnomalyDetection.organization_id == org_id)

    # Apply filters
    filters = []
    if endpoint_id:
        filters.append(APIAnomalyDetection.endpoint_id == endpoint_id)
    if anomaly_type:
        filters.append(APIAnomalyDetection.anomaly_type == anomaly_type)
    if severity:
        filters.append(APIAnomalyDetection.severity == severity)
    if status:
        filters.append(APIAnomalyDetection.status == status)

    if filters:
        query = query.where(and_(*filters))

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(APIAnomalyDetection, sort_by, APIAnomalyDetection.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    anomalies = list(result.scalars().all())

    return APIAnomalyDetectionListResponse(
        items=[APIAnomalyDetectionResponse.model_validate(a) for a in anomalies],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/anomalies", response_model=APIAnomalyDetectionResponse, status_code=status.HTTP_201_CREATED)
async def create_anomaly(
    anomaly_data: APIAnomalyDetectionCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new anomaly detection record"""
    await require_own_endpoint_field(db, anomaly_data.endpoint_id, org_id)
    anomaly = APIAnomalyDetection(
        **anomaly_data.model_dump(),
        organization_id=org_id,
    )
    db.add(anomaly)
    await db.commit()
    await db.refresh(anomaly)
    return APIAnomalyDetectionResponse.model_validate(anomaly)


@router.get("/anomalies/{anomaly_id}", response_model=APIAnomalyDetectionResponse)
async def get_anomaly(
    anomaly_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get anomaly by ID"""
    anomaly = await get_anomaly_or_404(db, anomaly_id, org_id)
    return APIAnomalyDetectionResponse.model_validate(anomaly)


@router.put("/anomalies/{anomaly_id}", response_model=APIAnomalyDetectionResponse)
async def update_anomaly(
    anomaly_id: str,
    anomaly_data: APIAnomalyDetectionUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update an anomaly detection record"""
    anomaly = await get_anomaly_or_404(db, anomaly_id, org_id)

    update_data = anomaly_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(anomaly, field, value)

    await db.commit()
    await db.refresh(anomaly)
    return APIAnomalyDetectionResponse.model_validate(anomaly)


# ============================================================================
# API Compliance Check Endpoints
# ============================================================================


async def get_compliance_check_or_404(db: AsyncSession, check_id: str, org_id: str) -> APIComplianceCheck:
    """Get compliance check by ID or raise 404 (tenant-scoped)"""
    result = await db.execute(
        select(APIComplianceCheck).where(
            and_(APIComplianceCheck.id == check_id, APIComplianceCheck.organization_id == org_id)
        )
    )
    check = result.scalar_one_or_none()
    if not check:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compliance check not found",
        )
    return check


@router.get("/compliance-checks", response_model=APIComplianceCheckListResponse)
async def list_compliance_checks(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    endpoint_id: Optional[str] = None,
    check_type: Optional[str] = None,
    passed: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List compliance checks with filtering and pagination"""
    query = select(APIComplianceCheck).where(APIComplianceCheck.organization_id == org_id)

    # Apply filters
    filters = []
    if endpoint_id:
        filters.append(APIComplianceCheck.endpoint_id == endpoint_id)
    if check_type:
        filters.append(APIComplianceCheck.check_type == check_type)
    if passed is not None:
        filters.append(APIComplianceCheck.passed == passed)

    if filters:
        query = query.where(and_(*filters))

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(APIComplianceCheck, sort_by, APIComplianceCheck.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    checks = list(result.scalars().all())

    return APIComplianceCheckListResponse(
        items=[APIComplianceCheckResponse.model_validate(c) for c in checks],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/compliance-checks", response_model=APIComplianceCheckResponse, status_code=status.HTTP_201_CREATED)
async def create_compliance_check(
    check_data: APIComplianceCheckCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new compliance check"""
    await require_own_endpoint_field(db, check_data.endpoint_id, org_id)
    check = APIComplianceCheck(
        **check_data.model_dump(),
        organization_id=org_id,
    )
    db.add(check)
    await db.commit()
    await db.refresh(check)
    return APIComplianceCheckResponse.model_validate(check)


@router.get("/compliance-checks/{check_id}", response_model=APIComplianceCheckResponse)
async def get_compliance_check(
    check_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get compliance check by ID"""
    check = await get_compliance_check_or_404(db, check_id, org_id)
    return APIComplianceCheckResponse.model_validate(check)


@router.put("/compliance-checks/{check_id}", response_model=APIComplianceCheckResponse)
async def update_compliance_check(
    check_id: str,
    check_data: APIComplianceCheckUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update a compliance check"""
    check = await get_compliance_check_or_404(db, check_id, org_id)

    update_data = check_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(check, field, value)

    await db.commit()
    await db.refresh(check)
    return APIComplianceCheckResponse.model_validate(check)


# ============================================================================
# API Security Dashboard Endpoints
# ============================================================================


@router.get("/dashboard", response_model=APISecurityDashboardResponse)
async def get_dashboard(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get API security dashboard"""
    from datetime import timedelta as _timedelta

    # Total endpoints
    endpoints_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory).where(
            APIEndpointInventory.organization_id == org_id
        )
    )
    total_endpoints = endpoints_result.scalar() or 0

    # Documented vs shadow
    doc_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory).where(
            and_(
                APIEndpointInventory.organization_id == org_id,
                APIEndpointInventory.is_documented == True,
            )
        )
    )
    documented = doc_result.scalar() or 0

    shadow_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory).where(
            and_(
                APIEndpointInventory.organization_id == org_id,
                APIEndpointInventory.is_shadow == True,
            )
        )
    )
    shadow = shadow_result.scalar() or 0

    # Zombie APIs (documented but not seen for 30+ days)
    zombie_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory).where(
            and_(
                APIEndpointInventory.organization_id == org_id,
                APIEndpointInventory.is_documented == True,
                APIEndpointInventory.last_seen < datetime.now(timezone.utc) - _timedelta(days=30),
            )
        )
    )
    zombie = zombie_result.scalar() or 0

    # Vulnerabilities
    crit_vuln = await db.execute(
        select(func.count()).select_from(APIVulnerability).where(
            and_(
                APIVulnerability.organization_id == org_id,
                APIVulnerability.severity == "critical",
            )
        )
    )
    critical_count = crit_vuln.scalar() or 0

    high_vuln = await db.execute(
        select(func.count()).select_from(APIVulnerability).where(
            and_(
                APIVulnerability.organization_id == org_id,
                APIVulnerability.severity == "high",
            )
        )
    )
    high_count = high_vuln.scalar() or 0

    # Policy violations
    violations_result = await db.execute(
        select(func.count()).select_from(APISecurityPolicy).where(
            APISecurityPolicy.organization_id == org_id
        )
    )
    violations = violations_result.scalar() or 0

    # Compliance pass rate
    compliance_total = await db.execute(
        select(func.count()).select_from(APIComplianceCheck).where(
            APIComplianceCheck.organization_id == org_id
        )
    )
    total_checks = compliance_total.scalar() or 0

    compliance_passed = await db.execute(
        select(func.count()).select_from(APIComplianceCheck).where(
            and_(
                APIComplianceCheck.organization_id == org_id,
                APIComplianceCheck.passed == True,
            )
        )
    )
    passed_checks = compliance_passed.scalar() or 0
    pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0

    # Recent vulnerabilities
    recent_vulns = await db.execute(
        select(APIVulnerability)
        .where(APIVulnerability.organization_id == org_id)
        .order_by(APIVulnerability.created_at.desc())
        .limit(5)
    )
    recent_vuln_list = list(recent_vulns.scalars().all())

    # Critical anomalies
    anomalies = await db.execute(
        select(APIAnomalyDetection)
        .where(
            and_(
                APIAnomalyDetection.organization_id == org_id,
                APIAnomalyDetection.severity == "critical",
            )
        )
        .order_by(APIAnomalyDetection.created_at.desc())
        .limit(5)
    )
    critical_anomalies = list(anomalies.scalars().all())

    # Failed compliance
    failed_checks = await db.execute(
        select(APIComplianceCheck)
        .where(
            and_(
                APIComplianceCheck.organization_id == org_id,
                APIComplianceCheck.passed == False,
            )
        )
        .order_by(APIComplianceCheck.created_at.desc())
        .limit(5)
    )
    failed_check_list = list(failed_checks.scalars().all())

    # Top endpoints by 24h traffic (tenant-scoped)
    vuln_endpoints = await db.execute(
        select(APIEndpointInventory)
        .where(APIEndpointInventory.organization_id == org_id)
        .order_by(APIEndpointInventory.request_count_24h.desc())
        .limit(5)
    )
    top_endpoints = list(vuln_endpoints.scalars().all())

    stats = APISummaryStats(
        total_endpoints=total_endpoints,
        documented_endpoints=documented,
        shadow_apis=shadow,
        zombie_apis=zombie,
        critical_vulnerabilities=critical_count,
        high_vulnerabilities=high_count,
        policy_violations=violations,
        compliance_pass_rate=pass_rate,
    )

    return APISecurityDashboardResponse(
        stats=stats,
        recent_vulnerabilities=[
            APIVulnerabilityResponse.model_validate(v) for v in recent_vuln_list
        ],
        critical_anomalies=[
            APIAnomalyDetectionResponse.model_validate(a) for a in critical_anomalies
        ],
        failed_compliance_checks=[
            APIComplianceCheckResponse.model_validate(c) for c in failed_check_list
        ],
        top_vulnerable_endpoints=[
            APIEndpointInventoryResponse.model_validate(e) for e in top_endpoints
        ],
    )


@router.get("/dashboard/risk-trend")
async def get_risk_trend(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    days: int = Query(30, ge=1, le=90, description="Trailing window size in days"),
):
    """Daily API vulnerability findings by severity over the trailing window.

    Real time series for the dashboard's severity risk-trend chart:
    counts the org's APIVulnerability rows bucketed by ``created_at``
    day and severity (critical/high/medium/low). Org-scoped exactly like
    the sibling /dashboard endpoint. Returns an empty ``points`` list
    when no findings exist in the window so the UI renders an honest
    empty state instead of a fabricated line.
    """
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    rows = (await db.execute(
        select(APIVulnerability.created_at, APIVulnerability.severity).where(
            and_(
                APIVulnerability.organization_id == org_id,
                APIVulnerability.created_at >= window_start,
            )
        )
    )).all()

    severities = ("critical", "high", "medium", "low")
    by_day: dict[str, dict[str, int]] = {}
    total_findings = 0
    for created_at, severity in rows:
        if created_at is None:
            continue
        total_findings += 1
        sev = str(severity or "").lower()
        if sev not in severities:
            continue  # unknown severity: counted in total, not in a series
        day_key = created_at.date().isoformat()
        bucket = by_day.setdefault(day_key, {s: 0 for s in severities})
        bucket[sev] += 1

    points: list[dict] = []
    if total_findings > 0:
        # Dense daily series (zero-filled) so the chart line is continuous.
        for i in range(days):
            day_key = (window_start + timedelta(days=i)).date().isoformat()
            counts = by_day.get(day_key, {s: 0 for s in severities})
            points.append({"date": day_key, **counts})

    return {
        "window_days": days,
        "points": points,
        "total_findings": total_findings,
        "generated_at": now.isoformat(),
    }


# ============================================================================
# Background Task Endpoints
# ============================================================================


@router.post("/scan/security/{endpoint_id}")
async def trigger_security_scan(
    endpoint_id: str,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
) -> dict[str, str]:
    """Queue a security assessment of an endpoint in the caller's organization.

    Scans against live APIs are admin-only. The endpoint must belong to the
    caller's tenant (404 otherwise). The response no longer reports zero
    findings as if the scan had run: it only says the scan was queued; the
    findings appear under ``GET /vulnerabilities`` when it finishes.
    """
    await get_endpoint_or_404(db, endpoint_id, org_id)
    background_tasks.add_task(
        security_assessment,
        endpoint_id,
        org_id,
    )
    return {
        "status": "security_scan_queued",
        "endpoint_id": endpoint_id,
        "detail": "findings are written to /api-security/vulnerabilities when the scan completes",
    }


@router.post("/scan/compliance/{endpoint_id}")
async def trigger_compliance_check(
    endpoint_id: str,
    org_id: OrganizationId,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
):
    """Trigger compliance checks for an endpoint in the caller's organization.

    The check issues a live server-side GET to the endpoint's URL, so it is
    admin-only, limited to the caller's own inventory, and refused for
    private / loopback / link-local targets.
    """
    endpoint = await get_endpoint_or_404(db, endpoint_id, org_id)
    base_url = (endpoint.base_url or "").strip()
    if base_url:
        target = f"{base_url.rstrip('/')}/{(endpoint.path or '').lstrip('/')}"
        allowed, reason = await asyncio.to_thread(validate_url, target)
        if not allowed:
            logger.warning(
                "api_security_compliance_scan_refused",
                user_id=str(getattr(current_user, "id", "")),
                endpoint_id=endpoint_id,
                reason=reason,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "scan_target_not_allowed", "detail": reason},
            )
    background_tasks.add_task(
        compliance_check,
        endpoint_id,
        org_id,
    )
    return {"status": "compliance_check_queued", "endpoint_id": endpoint_id}


@router.post("/scan/shadows")
async def trigger_shadow_api_detection(
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
    traffic_logs: Optional[List[dict]] = Body(None),
):
    """Trigger shadow API detection"""
    background_tasks.add_task(
        shadow_api_detection,
        org_id,
        traffic_logs or [],
    )
    return {"status": "shadow_api_detection_queued"}


# ============================================================================
# Report Endpoints
# ============================================================================


@router.get("/reports/compliance", response_model=APIComplianceReportResponse)
async def get_compliance_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get the compliance report for the caller's organization."""
    in_org = APIComplianceCheck.organization_id == org_id

    total_result = await db.execute(
        select(func.count()).select_from(APIComplianceCheck).where(in_org)
    )
    total_checks = total_result.scalar() or 0

    passed_result = await db.execute(
        select(func.count()).select_from(APIComplianceCheck).where(
            and_(in_org, APIComplianceCheck.passed == True)  # noqa: E712
        )
    )
    passed_checks = passed_result.scalar() or 0
    failed_checks = total_checks - passed_checks
    pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0

    endpoints_checked = (
        await db.execute(
            select(func.count(func.distinct(APIComplianceCheck.endpoint_id))).where(in_org)
        )
    ).scalar() or 0
    total_endpoints = (
        await db.execute(
            select(func.count()).select_from(APIEndpointInventory).where(
                APIEndpointInventory.organization_id == org_id
            )
        )
    ).scalar() or 0

    # By check type (pass/fail used to be hardcoded 0)
    by_type_result = await db.execute(
        select(
            APIComplianceCheck.check_type,
            APIComplianceCheck.passed,
            func.count(APIComplianceCheck.id),
        )
        .where(in_org)
        .group_by(APIComplianceCheck.check_type, APIComplianceCheck.passed)
    )
    by_type: dict[str, dict[str, int]] = {}
    for check_type, passed, count in by_type_result.all():
        bucket = by_type.setdefault(check_type, {"total": 0, "passed": 0, "failed": 0})
        bucket["total"] += count
        bucket["passed" if passed else "failed"] += count

    return APIComplianceReportResponse(
        total_endpoints=total_endpoints,
        endpoints_checked=endpoints_checked,
        checks_passed=passed_checks,
        checks_failed=failed_checks,
        pass_rate=pass_rate,
        by_check_type=by_type,
        report_date=datetime.now(timezone.utc),
    )
