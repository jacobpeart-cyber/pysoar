"""API Security Governance endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status, Body
from sqlalchemy import func, select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.models.alert import Alert
from src.api_security.models import (
    APIEndpointInventory,
    APIVulnerability,
    APISecurityPolicy,
    APIAnomalyDetection,
    APIComplianceCheck,
)
from src.api_security.tasks import (
    api_discovery_scan,
    security_assessment,
    anomaly_baseline_update,
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
    APIDiscoveryResultsResponse,
    APIScanResultResponse,
    APIComplianceReportResponse,
)

router = APIRouter(prefix="/api-security", tags=["API Security"])


# ============================================================================
# API Endpoint Inventory Endpoints
# ============================================================================


async def get_endpoint_or_404(db: AsyncSession, endpoint_id: str) -> APIEndpointInventory:
    """Get endpoint by ID or raise 404"""
    result = await db.execute(
        select(APIEndpointInventory).where(APIEndpointInventory.id == endpoint_id)
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
    current_user: CurrentUser = None,
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
    query = select(APIEndpointInventory)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new API endpoint"""
    endpoint = APIEndpointInventory(
        **endpoint_data.model_dump(),
        organization_id=current_user.organization_id,
    )
    db.add(endpoint)
    await db.commit()
    await db.refresh(endpoint)
    return APIEndpointInventoryResponse.model_validate(endpoint)


@router.get("/endpoints/{endpoint_id}", response_model=APIEndpointInventoryResponse)
async def get_endpoint(
    endpoint_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get endpoint by ID"""
    endpoint = await get_endpoint_or_404(db, endpoint_id)
    return APIEndpointInventoryResponse.model_validate(endpoint)


@router.put("/endpoints/{endpoint_id}", response_model=APIEndpointInventoryResponse)
async def update_endpoint(
    endpoint_id: str,
    endpoint_data: APIEndpointInventoryUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an API endpoint"""
    endpoint = await get_endpoint_or_404(db, endpoint_id)

    update_data = endpoint_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(endpoint, field, value)

    await db.commit()
    await db.refresh(endpoint)
    return APIEndpointInventoryResponse.model_validate(endpoint)


@router.delete("/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_endpoint(
    endpoint_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete an API endpoint"""
    endpoint = await get_endpoint_or_404(db, endpoint_id)
    await db.delete(endpoint)
    await db.commit()


# ============================================================================
# API Vulnerability Management Endpoints
# ============================================================================


async def get_vulnerability_or_404(db: AsyncSession, vuln_id: str) -> APIVulnerability:
    """Get vulnerability by ID or raise 404"""
    result = await db.execute(
        select(APIVulnerability).where(APIVulnerability.id == vuln_id)
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
    current_user: CurrentUser = None,
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
    query = select(APIVulnerability)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new vulnerability"""
    vuln = APIVulnerability(
        **vuln_data.model_dump(),
        organization_id=current_user.organization_id,
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)
    return APIVulnerabilityResponse.model_validate(vuln)


@router.get("/vulnerabilities/{vuln_id}", response_model=APIVulnerabilityResponse)
async def get_vulnerability(
    vuln_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get vulnerability by ID"""
    vuln = await get_vulnerability_or_404(db, vuln_id)
    return APIVulnerabilityResponse.model_validate(vuln)


@router.put("/vulnerabilities/{vuln_id}", response_model=APIVulnerabilityResponse)
async def update_vulnerability(
    vuln_id: str,
    vuln_data: APIVulnerabilityUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a vulnerability"""
    vuln = await get_vulnerability_or_404(db, vuln_id)

    update_data = vuln_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(vuln, field, value)

    await db.commit()
    await db.refresh(vuln)
    return APIVulnerabilityResponse.model_validate(vuln)


@router.post("/vulnerabilities/bulk-update")
async def bulk_update_vulnerabilities(
    bulk_data: APIVulnerabilityBulkUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Bulk update vulnerabilities"""
    result = await db.execute(
        select(APIVulnerability).where(APIVulnerability.id.in_(bulk_data.vulnerability_ids))
    )
    vulns = result.scalars().all()

    for vuln in vulns:
        if bulk_data.status:
            vuln.status = bulk_data.status
        if bulk_data.remediation:
            vuln.remediation = bulk_data.remediation

    await db.commit()
    return {"updated_count": len(vulns)}


# ============================================================================
# API Security Policy Endpoints
# ============================================================================


async def get_policy_or_404(db: AsyncSession, policy_id: str) -> APISecurityPolicy:
    """Get policy by ID or raise 404"""
    result = await db.execute(
        select(APISecurityPolicy).where(APISecurityPolicy.id == policy_id)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    policy_type: Optional[str] = None,
    enforcement_level: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List API security policies"""
    query = select(APISecurityPolicy)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new security policy"""
    policy = APISecurityPolicy(
        **policy_data.model_dump(),
        organization_id=current_user.organization_id,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return APISecurityPolicyResponse.model_validate(policy)


@router.get("/policies/{policy_id}", response_model=APISecurityPolicyResponse)
async def get_policy(
    policy_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get policy by ID"""
    policy = await get_policy_or_404(db, policy_id)
    return APISecurityPolicyResponse.model_validate(policy)


@router.put("/policies/{policy_id}", response_model=APISecurityPolicyResponse)
async def update_policy(
    policy_id: str,
    policy_data: APISecurityPolicyUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a security policy"""
    policy = await get_policy_or_404(db, policy_id)

    update_data = policy_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)

    await db.commit()
    await db.refresh(policy)
    return APISecurityPolicyResponse.model_validate(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a security policy"""
    policy = await get_policy_or_404(db, policy_id)
    await db.delete(policy)
    await db.commit()


# ============================================================================
# API Anomaly Detection Endpoints
# ============================================================================


async def get_anomaly_or_404(db: AsyncSession, anomaly_id: str) -> APIAnomalyDetection:
    """Get anomaly by ID or raise 404"""
    result = await db.execute(
        select(APIAnomalyDetection).where(APIAnomalyDetection.id == anomaly_id)
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
    current_user: CurrentUser = None,
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
    query = select(APIAnomalyDetection)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new anomaly detection record"""
    anomaly = APIAnomalyDetection(
        **anomaly_data.model_dump(),
        organization_id=current_user.organization_id,
    )
    db.add(anomaly)
    await db.commit()
    await db.refresh(anomaly)
    return APIAnomalyDetectionResponse.model_validate(anomaly)


@router.get("/anomalies/{anomaly_id}", response_model=APIAnomalyDetectionResponse)
async def get_anomaly(
    anomaly_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get anomaly by ID"""
    anomaly = await get_anomaly_or_404(db, anomaly_id)
    return APIAnomalyDetectionResponse.model_validate(anomaly)


@router.put("/anomalies/{anomaly_id}", response_model=APIAnomalyDetectionResponse)
async def update_anomaly(
    anomaly_id: str,
    anomaly_data: APIAnomalyDetectionUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an anomaly detection record"""
    anomaly = await get_anomaly_or_404(db, anomaly_id)

    update_data = anomaly_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(anomaly, field, value)

    await db.commit()
    await db.refresh(anomaly)
    return APIAnomalyDetectionResponse.model_validate(anomaly)


# ============================================================================
# API Compliance Check Endpoints
# ============================================================================


async def get_compliance_check_or_404(db: AsyncSession, check_id: str) -> APIComplianceCheck:
    """Get compliance check by ID or raise 404"""
    result = await db.execute(
        select(APIComplianceCheck).where(APIComplianceCheck.id == check_id)
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
    current_user: CurrentUser = None,
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
    query = select(APIComplianceCheck)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new compliance check"""
    check = APIComplianceCheck(
        **check_data.model_dump(),
        organization_id=current_user.organization_id,
    )
    db.add(check)
    await db.commit()
    await db.refresh(check)
    return APIComplianceCheckResponse.model_validate(check)


@router.get("/compliance-checks/{check_id}", response_model=APIComplianceCheckResponse)
async def get_compliance_check(
    check_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get compliance check by ID"""
    check = await get_compliance_check_or_404(db, check_id)
    return APIComplianceCheckResponse.model_validate(check)


@router.put("/compliance-checks/{check_id}", response_model=APIComplianceCheckResponse)
async def update_compliance_check(
    check_id: str,
    check_data: APIComplianceCheckUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a compliance check"""
    check = await get_compliance_check_or_404(db, check_id)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get API security dashboard"""
    # Total endpoints
    endpoints_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory)
    )
    total_endpoints = endpoints_result.scalar() or 0

    # Documented vs shadow
    doc_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory).where(
            APIEndpointInventory.is_documented == True
        )
    )
    documented = doc_result.scalar() or 0

    shadow_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory).where(
            APIEndpointInventory.is_shadow == True
        )
    )
    shadow = shadow_result.scalar() or 0

    # Zombie APIs
    zombie_result = await db.execute(
        select(func.count()).select_from(APIEndpointInventory).where(
            and_(
                APIEndpointInventory.is_documented == True,
                APIEndpointInventory.last_seen < datetime.now(timezone.utc) - __import__('datetime').timedelta(days=30)
            )
        )
    )
    zombie = zombie_result.scalar() or 0

    # Vulnerabilities
    crit_vuln = await db.execute(
        select(func.count()).select_from(APIVulnerability).where(
            APIVulnerability.severity == "critical"
        )
    )
    critical_count = crit_vuln.scalar() or 0

    high_vuln = await db.execute(
        select(func.count()).select_from(APIVulnerability).where(
            APIVulnerability.severity == "high"
        )
    )
    high_count = high_vuln.scalar() or 0

    # Policy violations
    violations_result = await db.execute(
        select(func.count()).select_from(APISecurityPolicy)
    )
    violations = violations_result.scalar() or 0

    # Compliance pass rate
    compliance_total = await db.execute(
        select(func.count()).select_from(APIComplianceCheck)
    )
    total_checks = compliance_total.scalar() or 1

    compliance_passed = await db.execute(
        select(func.count()).select_from(APIComplianceCheck).where(
            APIComplianceCheck.passed == True
        )
    )
    passed_checks = compliance_passed.scalar() or 0
    pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0

    # Recent vulnerabilities
    recent_vulns = await db.execute(
        select(APIVulnerability).order_by(APIVulnerability.created_at.desc()).limit(5)
    )
    recent_vuln_list = list(recent_vulns.scalars().all())

    # Critical anomalies
    anomalies = await db.execute(
        select(APIAnomalyDetection)
        .where(APIAnomalyDetection.severity == "critical")
        .order_by(APIAnomalyDetection.created_at.desc())
        .limit(5)
    )
    critical_anomalies = list(anomalies.scalars().all())

    # Failed compliance
    failed_checks = await db.execute(
        select(APIComplianceCheck)
        .where(APIComplianceCheck.passed == False)
        .order_by(APIComplianceCheck.created_at.desc())
        .limit(5)
    )
    failed_check_list = list(failed_checks.scalars().all())

    # Top vulnerable endpoints
    vuln_endpoints = await db.execute(
        select(APIEndpointInventory)
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


# ============================================================================
# Background Task Endpoints
# ============================================================================


@router.post("/scan/discover", response_model=APIDiscoveryResultsResponse)
async def trigger_api_discovery(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
    traffic_logs: Optional[List[dict]] = Body(None),
):
    """Trigger API discovery scan from traffic"""
    background_tasks.add_task(
        api_discovery_scan,
        current_user.organization_id,
        traffic_logs or [],
    )
    return APIDiscoveryResultsResponse(
        new_endpoints_count=0,
        shadow_apis_count=0,
        zombie_apis_count=0,
        total_discovered=0,
        discovery_summary={"status": "scan_queued"},
    )


@router.post("/scan/security/{endpoint_id}", response_model=APIScanResultResponse)
async def trigger_security_scan(endpoint_id: str, current_user: CurrentUser = None, db: DatabaseSession = None, background_tasks: BackgroundTasks = None):
    """Trigger security assessment for endpoint"""
    background_tasks.add_task(
        security_assessment,
        endpoint_id,
        current_user.organization_id,
    )
    return APIScanResultResponse(
        endpoint_id=endpoint_id,
        vulnerabilities_found=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        scan_timestamp=datetime.now(timezone.utc),
        remediation_guidance="Scan in progress",
    )


@router.post("/scan/compliance/{endpoint_id}")
async def trigger_compliance_check(endpoint_id: str, current_user: CurrentUser = None, db: DatabaseSession = None, background_tasks: BackgroundTasks = None):
    """Trigger compliance checks for endpoint"""
    background_tasks.add_task(
        compliance_check,
        endpoint_id,
        current_user.organization_id,
    )
    return {"status": "compliance_check_queued", "endpoint_id": endpoint_id}


@router.post("/scan/shadows")
async def trigger_shadow_api_detection(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
    traffic_logs: Optional[List[dict]] = Body(None),
):
    """Trigger shadow API detection"""
    background_tasks.add_task(
        shadow_api_detection,
        current_user.organization_id,
        traffic_logs or [],
    )
    return {"status": "shadow_api_detection_queued"}


# ============================================================================
# Report Endpoints
# ============================================================================


@router.get("/reports/compliance", response_model=APIComplianceReportResponse)
async def get_compliance_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get comprehensive compliance report"""
    # Total checks
    total_result = await db.execute(
        select(func.count()).select_from(APIComplianceCheck)
    )
    total_checks = total_result.scalar() or 0

    # Passed checks
    passed_result = await db.execute(
        select(func.count()).select_from(APIComplianceCheck).where(
            APIComplianceCheck.passed == True
        )
    )
    passed_checks = passed_result.scalar() or 0

    # Failed checks
    failed_checks = total_checks - passed_checks

    pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0

    # By check type
    by_type_result = await db.execute(
        select(APIComplianceCheck.check_type, func.count(APIComplianceCheck.id))
        .group_by(APIComplianceCheck.check_type)
    )
    by_type_data = dict(by_type_result.all())

    by_type = {
        check_type: {
            "total": count,
            "passed": 0,
            "failed": 0,
        }
        for check_type, count in by_type_data.items()
    }

    return APIComplianceReportResponse(
        total_endpoints=total_checks,
        endpoints_checked=total_checks,
        checks_passed=passed_checks,
        checks_failed=failed_checks,
        pass_rate=pass_rate,
        by_check_type=by_type,
        report_date=datetime.now(timezone.utc),
    )
