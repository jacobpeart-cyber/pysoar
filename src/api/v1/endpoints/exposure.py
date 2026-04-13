"""Exposure Management and CTEM API endpoints"""

import math
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status, UploadFile, File
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user, get_db
from src.exposure.models import (
    ExposureAsset,
    ExposureVulnerability as Vulnerability,
    AssetVulnerability,
    ExposureScan,
    RemediationTicket,
    AttackSurface,
)
from src.schemas.exposure import (
    # Asset schemas
    ExposureAssetCreate,
    ExposureAssetListResponse,
    ExposureAssetResponse,
    ExposureAssetUpdate,
    # Vulnerability schemas
    VulnerabilityCreate,
    VulnerabilityListResponse,
    VulnerabilityResponse,
    VulnerabilityUpdate,
    # Asset-Vulnerability schemas
    AssetVulnerabilityCreate,
    AssetVulnerabilityListResponse,
    AssetVulnerabilityResponse,
    AssetVulnerabilityUpdate,
    # Scan schemas
    ExposureScanCreate,
    ExposureScanListResponse,
    ExposureScanResponse,
    # Remediation schemas
    RemediationTicketCreate,
    RemediationTicketListResponse,
    RemediationTicketResponse,
    RemediationTicketUpdate,
    RemediationVerificationRequest,
    RemediationVerificationResult,
    # Attack Surface schemas
    AttackSurfaceCreate,
    AttackSurfaceListResponse,
    AttackSurfaceResponse,
    AttackSurfaceUpdate,
    # Dashboard and reporting
    ExposureDashboardStats,
    RiskMatrix,
    ComplianceSummary,
    ExposureSearchRequest,
    ExposureReport,
    # Discovery and assessment
    AssetDiscoveryRequest,
    DiscoveryResult,
    AssessmentResult,
    # Import schemas
    BulkAssetImportRequest,
    BulkImportResult,
    ExternalScannerImportRequest,
    ScannerImportResult,
)

router = APIRouter(prefix="/exposure", tags=["Exposure Management"])


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


async def get_asset_or_404(db: AsyncSession, asset_id: str, organization_id: str) -> ExposureAsset:
    """Get exposure asset by ID or raise 404"""
    result = await db.execute(
        select(ExposureAsset).where(
            and_(
                ExposureAsset.id == asset_id,
                ExposureAsset.organization_id == organization_id,
            )
        )
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )
    return asset


async def get_vulnerability_or_404(db: AsyncSession, vuln_id: str, organization_id: str) -> Vulnerability:
    """Get vulnerability by ID or raise 404"""
    result = await db.execute(
        select(Vulnerability).where(
            and_(
                Vulnerability.id == vuln_id,
                Vulnerability.organization_id == organization_id,
            )
        )
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )
    return vuln


async def get_asset_vulnerability_or_404(db: AsyncSession, mapping_id: str, organization_id: str) -> AssetVulnerability:
    """Get asset-vulnerability mapping by ID or raise 404"""
    result = await db.execute(
        select(AssetVulnerability).where(
            and_(
                AssetVulnerability.id == mapping_id,
                AssetVulnerability.organization_id == organization_id,
            )
        )
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset-vulnerability mapping not found",
        )
    return mapping


async def get_scan_or_404(db: AsyncSession, scan_id: str, organization_id: str) -> ExposureScan:
    """Get scan by ID or raise 404"""
    result = await db.execute(
        select(ExposureScan).where(
            and_(
                ExposureScan.id == scan_id,
                ExposureScan.organization_id == organization_id,
            )
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan


async def get_ticket_or_404(db: AsyncSession, ticket_id: str, organization_id: str) -> RemediationTicket:
    """Get remediation ticket by ID or raise 404"""
    result = await db.execute(
        select(RemediationTicket).where(
            and_(
                RemediationTicket.id == ticket_id,
                RemediationTicket.organization_id == organization_id,
            )
        )
    )
    ticket = result.scalar_one_or_none()
    if not ticket:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation ticket not found",
        )
    return ticket


async def get_attack_surface_or_404(db: AsyncSession, surface_id: str, organization_id: str) -> AttackSurface:
    """Get attack surface by ID or raise 404"""
    result = await db.execute(
        select(AttackSurface).where(
            and_(
                AttackSurface.id == surface_id,
                AttackSurface.organization_id == organization_id,
            )
        )
    )
    surface = result.scalar_one_or_none()
    if not surface:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack surface not found",
        )
    return surface


# ============================================================================
# EXPOSURE ASSETS ENDPOINTS
# ============================================================================


@router.post("/assets", response_model=ExposureAssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_data: ExposureAssetCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new exposure asset"""
    asset = ExposureAsset(
        id=str(uuid.uuid4()),
        hostname=asset_data.hostname,
        ip_address=asset_data.ip_address,
        mac_address=asset_data.mac_address,
        asset_type=asset_data.asset_type,
        os_type=asset_data.os_type,
        os_version=asset_data.os_version,
        environment=asset_data.environment,
        criticality=asset_data.criticality,
        business_unit=asset_data.business_unit,
        owner=asset_data.owner,
        location=asset_data.location,
        cloud_provider=asset_data.cloud_provider,
        cloud_region=asset_data.cloud_region,
        cloud_resource_id=asset_data.cloud_resource_id,
        is_internet_facing=asset_data.is_internet_facing,
        services=asset_data.services,
        software_inventory=asset_data.software_inventory,
        tags=asset_data.tags,
        network_zone=asset_data.network_zone,
        extra_metadata=asset_data.extra_metadata or {},
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(asset)
    await db.flush()
    await db.refresh(asset)

    return asset


@router.get("/assets", response_model=ExposureAssetListResponse)
async def list_assets(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    search: Optional[str] = None,
    asset_type: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    is_internet_facing: Optional[bool] = None,
    min_risk_score: Optional[float] = Query(None, ge=0.0),
    max_risk_score: Optional[float] = Query(None, le=100.0),
):
    """List exposure assets with filtering and pagination"""
    org_id = getattr(current_user, "organization_id", None)
    query = select(ExposureAsset)
    if org_id is not None:
        query = query.where(ExposureAsset.organization_id == org_id)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                ExposureAsset.hostname.ilike(search_filter),
                ExposureAsset.ip_address.ilike(search_filter),
                ExposureAsset.business_unit.ilike(search_filter),
                ExposureAsset.owner.ilike(search_filter),
            )
        )

    if asset_type:
        query = query.where(ExposureAsset.asset_type == asset_type)

    if environment:
        query = query.where(ExposureAsset.environment == environment)

    if criticality:
        query = query.where(ExposureAsset.criticality == criticality)

    if is_internet_facing is not None:
        query = query.where(ExposureAsset.is_internet_facing == is_internet_facing)

    if min_risk_score is not None:
        query = query.where(ExposureAsset.risk_score >= min_risk_score)

    if max_risk_score is not None:
        query = query.where(ExposureAsset.risk_score <= max_risk_score)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(desc(ExposureAsset.created_at))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    assets = list(result.scalars().all())

    return {
        "items": assets,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


@router.get("/assets/{asset_id}", response_model=ExposureAssetResponse)
async def get_asset(
    asset_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific exposure asset with details and vulnerabilities"""
    asset = await get_asset_or_404(db, asset_id, getattr(current_user, "organization_id", None))
    return asset


@router.put("/assets/{asset_id}", response_model=ExposureAssetResponse)
async def update_asset(
    asset_id: str,
    asset_data: ExposureAssetUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an exposure asset"""
    asset = await get_asset_or_404(db, asset_id, getattr(current_user, "organization_id", None))

    update_data = asset_data.model_dump(exclude_unset=True, exclude_none=True)
    # Map 'metadata' field to 'extra_metadata' column if present
    if "metadata" in update_data:
        update_data["extra_metadata"] = update_data.pop("metadata")

    for key, value in update_data.items():
        setattr(asset, key, value)

    await db.flush()
    await db.refresh(asset)

    return asset


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_asset(
    asset_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Deactivate an exposure asset"""
    asset = await get_asset_or_404(db, asset_id, getattr(current_user, "organization_id", None))
    asset.is_active = False
    await db.flush()


@router.post("/assets/discover", response_model=DiscoveryResult)
async def trigger_asset_discovery(
    discovery_request: AssetDiscoveryRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Trigger asset discovery scan (network, cloud, AD, DNS)"""
    scan = ExposureScan(
        id=str(uuid.uuid4()),
        scan_type="discovery",
        scan_name=f"Discovery scan - {datetime.now(timezone.utc).isoformat()}",
        status="running",
        target_assets=[],
        scanner="builtin",
        initiated_by=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    return {
        "scan_id": scan.id,
        "discovered_assets": 0,
        "new_assets": 0,
        "updated_assets": 0,
        "status": "running",
    }


@router.post("/assets/import", response_model=BulkImportResult)
async def import_assets(
    import_data: BulkAssetImportRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Bulk import assets from CSV or JSON"""
    imported = 0
    failed = 0
    errors = []

    for item in import_data.assets if hasattr(import_data, "assets") else []:
        try:
            asset = ExposureAsset(
                id=str(uuid.uuid4()),
                hostname=getattr(item, "hostname", None),
                ip_address=getattr(item, "ip_address", None),
                asset_type=getattr(item, "asset_type", "server"),
                environment=getattr(item, "environment", "production"),
                criticality=getattr(item, "criticality", "medium"),
                organization_id=getattr(current_user, "organization_id", None),
            )
            db.add(asset)
            imported += 1
        except Exception as e:
            failed += 1
            errors.append(str(e))

    if imported > 0:
        await db.flush()

    return {
        "imported": imported,
        "failed": failed,
        "errors": errors,
        "skipped": 0,
    }


@router.get("/assets/{asset_id}/vulnerabilities", response_model=AssetVulnerabilityListResponse)
async def get_asset_vulnerabilities(
    asset_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    status: Optional[str] = None,
    severity: Optional[str] = None,
):
    """Get vulnerabilities affecting a specific asset"""
    org_id = getattr(current_user, "organization_id", None)
    await get_asset_or_404(db, asset_id, org_id)

    conditions = [AssetVulnerability.asset_id == asset_id]
    if org_id is not None:
        conditions.append(AssetVulnerability.organization_id == org_id)
    query = select(AssetVulnerability).where(and_(*conditions))

    if status:
        query = query.where(AssetVulnerability.status == status)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(desc(AssetVulnerability.created_at))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    items = list(result.scalars().all())

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


# ============================================================================
# VULNERABILITY ENDPOINTS
# ============================================================================


@router.post("/vulnerabilities", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    vuln_data: VulnerabilityCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new vulnerability record"""
    vuln = Vulnerability(
        id=str(uuid.uuid4()),
        cve_id=vuln_data.cve_id,
        title=vuln_data.title,
        description=vuln_data.description,
        severity=vuln_data.severity,
        cvss_v3_score=vuln_data.cvss_v3_score,
        cvss_v3_vector=vuln_data.cvss_v3_vector,
        epss_score=vuln_data.epss_score,
        is_exploited_in_wild=vuln_data.is_exploited_in_wild,
        exploit_available=vuln_data.exploit_available,
        exploit_maturity=vuln_data.exploit_maturity,
        affected_products=vuln_data.affected_products,
        patch_available=vuln_data.patch_available,
        patch_url=vuln_data.patch_url,
        references=vuln_data.references,
        mitre_techniques=vuln_data.mitre_techniques,
        tags=vuln_data.tags,
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(vuln)
    await db.flush()
    await db.refresh(vuln)

    return vuln


@router.get("/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    search: Optional[str] = None,
    severity: Optional[list[str]] = Query(None),
    cve_id: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    exploited_in_wild: Optional[bool] = None,
):
    """List vulnerabilities with filtering"""
    org_id = getattr(current_user, "organization_id", None)
    query = select(Vulnerability)
    if org_id is not None:
        query = query.where(Vulnerability.organization_id == org_id)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                Vulnerability.title.ilike(search_filter),
                Vulnerability.description.ilike(search_filter),
                Vulnerability.cve_id.ilike(search_filter),
            )
        )

    if severity:
        query = query.where(Vulnerability.severity.in_(severity))

    if cve_id:
        query = query.where(Vulnerability.cve_id == cve_id)

    if has_exploit is not None:
        query = query.where(Vulnerability.exploit_available == has_exploit)

    if exploited_in_wild is not None:
        query = query.where(Vulnerability.is_exploited_in_wild == exploited_in_wild)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(desc(Vulnerability.created_at))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    vulns = list(result.scalars().all())

    return {
        "items": vulns,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


@router.get("/vulnerabilities/kev")
async def get_cisa_kev_list_early(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """CISA Known Exploited Vulnerabilities list.

    NOTE: This route MUST be declared before GET /vulnerabilities/{vuln_id}
    because FastAPI matches routes in definition order — if the dynamic
    route comes first, the literal path 'kev' is captured as a vuln_id
    and the endpoint 404s with "Vulnerability not found".
    """
    org_id = getattr(current_user, "organization_id", None)
    query = select(Vulnerability).where(Vulnerability.is_exploited_in_wild == True)  # noqa: E712
    if org_id is not None:
        query = query.where(Vulnerability.organization_id == org_id)
    result = await db.execute(query)
    kev_vulns = list(result.scalars().all())

    return {
        "kev_vulnerabilities": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "is_exploited_in_wild": v.is_exploited_in_wild,
                "kev_date_added": v.kev_date_added.isoformat() if getattr(v, "kev_date_added", None) else None,
                "published_date": v.published_date.isoformat() if getattr(v, "published_date", None) else None,
                "description": v.description,
            }
            for v in kev_vulns
        ],
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "count": len(kev_vulns),
    }


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific vulnerability with affected assets"""
    vuln = await get_vulnerability_or_404(db, vuln_id, getattr(current_user, "organization_id", None))
    return vuln


@router.put("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: str,
    vuln_data: VulnerabilityUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update vulnerability information"""
    vuln = await get_vulnerability_or_404(db, vuln_id, getattr(current_user, "organization_id", None))

    update_data = vuln_data.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in update_data.items():
        setattr(vuln, key, value)

    await db.flush()
    await db.refresh(vuln)

    return vuln


@router.delete("/vulnerabilities/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vulnerability(
    vuln_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a vulnerability record"""
    vuln = await get_vulnerability_or_404(db, vuln_id, getattr(current_user, "organization_id", None))
    await db.delete(vuln)
    await db.flush()


# /vulnerabilities/kev moved above /vulnerabilities/{vuln_id} — see
# get_cisa_kev_list_early above. Route ordering matters in FastAPI.


@router.post("/vulnerabilities/search", response_model=VulnerabilityListResponse)
async def advanced_vulnerability_search(
    search_request: ExposureSearchRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
):
    """Advanced vulnerability search with complex filtering"""
    query = select(Vulnerability).where(
        Vulnerability.organization_id == getattr(current_user, "organization_id", None)
    )

    if hasattr(search_request, "query") and search_request.query:
        search_filter = f"%{search_request.query}%"
        query = query.where(
            or_(
                Vulnerability.title.ilike(search_filter),
                Vulnerability.description.ilike(search_filter),
                Vulnerability.cve_id.ilike(search_filter),
            )
        )

    if hasattr(search_request, "severity") and search_request.severity:
        query = query.where(Vulnerability.severity.in_(search_request.severity))

    if hasattr(search_request, "has_exploit") and search_request.has_exploit is not None:
        query = query.where(Vulnerability.exploit_available == search_request.has_exploit)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(desc(Vulnerability.created_at))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    vulns = list(result.scalars().all())

    return {
        "items": vulns,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


# ============================================================================
# ASSET-VULNERABILITY ENDPOINTS
# ============================================================================


@router.post("/asset-vulns", response_model=AssetVulnerabilityResponse, status_code=status.HTTP_201_CREATED)
async def create_asset_vulnerability(
    mapping_data: AssetVulnerabilityCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create asset-vulnerability mapping"""
    mapping = AssetVulnerability(
        id=str(uuid.uuid4()),
        asset_id=mapping_data.asset_id,
        vulnerability_id=mapping_data.vulnerability_id,
        status=mapping_data.status if hasattr(mapping_data, "status") and mapping_data.status else "open",
        assigned_to=mapping_data.assigned_to,
        due_date=mapping_data.due_date,
        remediation_notes=mapping_data.remediation_notes,
        compensating_controls=mapping_data.compensating_controls if hasattr(mapping_data, "compensating_controls") else [],
        detected_by=mapping_data.detected_by,
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(mapping)
    await db.flush()
    await db.refresh(mapping)

    return mapping


@router.put("/asset-vulns/{mapping_id}", response_model=AssetVulnerabilityResponse)
async def update_asset_vulnerability(
    mapping_id: str,
    mapping_data: AssetVulnerabilityUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update asset-vulnerability status (open, remediated, accepted, false-positive)"""
    mapping = await get_asset_vulnerability_or_404(db, mapping_id, getattr(current_user, "organization_id", None))

    update_data = mapping_data.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in update_data.items():
        setattr(mapping, key, value)

    await db.flush()
    await db.refresh(mapping)

    return mapping


@router.post("/asset-vulns/{mapping_id}/remediate", response_model=AssetVulnerabilityResponse)
async def mark_as_remediated(
    mapping_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    remediation_notes: Optional[str] = Query(None),
):
    """Mark asset-vulnerability as remediated"""
    mapping = await get_asset_vulnerability_or_404(db, mapping_id, getattr(current_user, "organization_id", None))

    mapping.status = "remediated"
    mapping.remediated_at = datetime.now(timezone.utc)
    if remediation_notes:
        mapping.remediation_notes = remediation_notes

    await db.flush()
    await db.refresh(mapping)

    return mapping


@router.get("/asset-vulns/prioritized", response_model=AssetVulnerabilityListResponse)
async def get_prioritized_remediation_list(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    criticality: Optional[str] = None,
    severity: Optional[str] = None,
):
    """Get prioritized list of asset-vulnerabilities for remediation"""
    query = select(AssetVulnerability).where(
        and_(
            AssetVulnerability.organization_id == getattr(current_user, "organization_id", None),
            AssetVulnerability.status == "open",
        )
    )

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Order by risk score descending for prioritization
    query = query.order_by(desc(AssetVulnerability.risk_score))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    items = list(result.scalars().all())

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


# ============================================================================
# SCAN ENDPOINTS
# ============================================================================


@router.post("/scans", response_model=ExposureScanResponse, status_code=status.HTTP_201_CREATED)
async def launch_scan(
    scan_data: ExposureScanCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Launch a new exposure scan"""
    scan = ExposureScan(
        id=str(uuid.uuid4()),
        scan_type=scan_data.scan_type,
        scan_name=scan_data.scan_name,
        target_assets=scan_data.target_assets,
        scanner=scan_data.scanner,
        scan_profile=scan_data.scan_profile,
        status="pending",
        initiated_by=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    return scan


@router.get("/scans", response_model=ExposureScanListResponse)
async def list_scans(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    scan_type: Optional[str] = None,
    status: Optional[str] = None,
    date_from: Optional[str] = Query(None),
):
    """List exposure scans with filtering"""
    org_id = getattr(current_user, "organization_id", None)
    query = select(ExposureScan)
    if org_id is not None:
        query = query.where(ExposureScan.organization_id == org_id)

    if scan_type:
        query = query.where(ExposureScan.scan_type == scan_type)

    if status:
        query = query.where(ExposureScan.status == status)

    if date_from:
        query = query.where(ExposureScan.created_at >= date_from)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(desc(ExposureScan.created_at))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    scans = list(result.scalars().all())

    return {
        "items": scans,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


@router.get("/scans/{scan_id}", response_model=ExposureScanResponse)
async def get_scan(
    scan_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get scan results and details"""
    scan = await get_scan_or_404(db, scan_id, getattr(current_user, "organization_id", None))
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ExposureScanResponse)
async def cancel_scan(
    scan_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Cancel a running scan"""
    scan = await get_scan_or_404(db, scan_id, getattr(current_user, "organization_id", None))

    if scan.status not in ("pending", "running"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status '{scan.status}'",
        )

    scan.status = "cancelled"
    await db.flush()
    await db.refresh(scan)

    return scan


@router.post("/scans/import", response_model=ScannerImportResult)
async def import_scan_results(
    import_data: ExternalScannerImportRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Import results from external scanners (Nessus, Qualys, etc.)"""
    import_id = str(uuid.uuid4())

    scan = ExposureScan(
        id=import_id,
        scan_type="vulnerability",
        scan_name=f"Import from {import_data.scanner_name}",
        status="processing",
        scanner=import_data.scanner_name,
        target_assets=[],
        initiated_by=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(scan)
    await db.flush()

    return {
        "import_id": import_id,
        "scanner_name": import_data.scanner_name,
        "vulnerabilities_imported": 0,
        "assets_updated": 0,
        "status": "processing",
        "errors": [],
    }


# ============================================================================
# REMEDIATION TICKET ENDPOINTS
# ============================================================================


@router.post("/tickets", response_model=RemediationTicketResponse, status_code=status.HTTP_201_CREATED)
async def create_remediation_ticket(
    ticket_data: RemediationTicketCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a remediation ticket"""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        # Find first org from organization_members or organizations table
        from src.models.organization import Organization
        org_result = await db.execute(select(Organization).limit(1))
        org = org_result.scalars().first()
        org_id = org.id if org else None

    if not org_id:
        raise HTTPException(status_code=400, detail="No organization found. Create an organization first.")

    ticket = RemediationTicket(
        id=str(uuid.uuid4()),
        title=ticket_data.title,
        description=ticket_data.description,
        priority=ticket_data.priority,
        assigned_to=ticket_data.assigned_to,
        assigned_team=ticket_data.assigned_team,
        asset_vulnerabilities=ticket_data.asset_vulnerabilities,
        affected_assets=ticket_data.affected_assets,
        remediation_type=ticket_data.remediation_type,
        remediation_steps=ticket_data.remediation_steps,
        due_date=ticket_data.due_date,
        external_ticket_id=ticket_data.external_ticket_id,
        status="open",
        organization_id=org_id,
    )

    db.add(ticket)
    await db.flush()
    await db.refresh(ticket)

    return ticket


@router.get("/tickets", response_model=RemediationTicketListResponse)
async def list_remediation_tickets(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    overdue_only: Optional[bool] = False,
):
    """List remediation tickets with filtering"""
    org_id = getattr(current_user, "organization_id", None)
    query = select(RemediationTicket)
    if org_id is not None:
        query = query.where(RemediationTicket.organization_id == org_id)

    if status:
        query = query.where(RemediationTicket.status == status)

    if priority:
        query = query.where(RemediationTicket.priority == priority)

    if assigned_to:
        query = query.where(RemediationTicket.assigned_to == assigned_to)

    if overdue_only:
        query = query.where(
            and_(
                RemediationTicket.due_date < datetime.now(timezone.utc),
                RemediationTicket.status.notin_(["closed", "verification"]),
            )
        )

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(desc(RemediationTicket.created_at))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    tickets = list(result.scalars().all())

    return {
        "items": tickets,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


@router.get("/tickets/{ticket_id}", response_model=RemediationTicketResponse)
async def get_remediation_ticket(
    ticket_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific remediation ticket"""
    ticket = await get_ticket_or_404(db, ticket_id, getattr(current_user, "organization_id", None))
    return ticket


@router.put("/tickets/{ticket_id}", response_model=RemediationTicketResponse)
async def update_remediation_ticket(
    ticket_id: str,
    ticket_data: RemediationTicketUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a remediation ticket"""
    ticket = await get_ticket_or_404(db, ticket_id, getattr(current_user, "organization_id", None))

    update_data = ticket_data.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in update_data.items():
        setattr(ticket, key, value)

    await db.flush()
    await db.refresh(ticket)

    return ticket


@router.post("/tickets/{ticket_id}/verify", response_model=RemediationVerificationResult)
async def verify_remediation(
    ticket_id: str,
    verification_data: RemediationVerificationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Verify remediation completion"""
    ticket = await get_ticket_or_404(db, ticket_id, getattr(current_user, "organization_id", None))

    now = datetime.now(timezone.utc)
    ticket.verification_status = "verified"
    ticket.verified_at = now
    ticket.verified_by = current_user.id
    ticket.status = "closed"
    ticket.resolved_at = now

    await db.flush()
    await db.refresh(ticket)

    return {
        "ticket_id": ticket_id,
        "verified": True,
        "verification_date": now.isoformat(),
        "verified_by": current_user.id,
        "notes": verification_data.verification_notes if hasattr(verification_data, "verification_notes") else None,
    }


@router.get("/tickets/overdue", response_model=RemediationTicketListResponse)
async def get_overdue_tickets(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
):
    """Get overdue remediation tickets"""
    query = select(RemediationTicket).where(
        and_(
            RemediationTicket.organization_id == getattr(current_user, "organization_id", None),
            RemediationTicket.due_date < datetime.now(timezone.utc),
            RemediationTicket.status.notin_(["closed", "verification"]),
        )
    )

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(RemediationTicket.due_date.asc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    tickets = list(result.scalars().all())

    return {
        "items": tickets,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


# ============================================================================
# ATTACK SURFACE ENDPOINTS
# ============================================================================


@router.post("/attack-surface", response_model=AttackSurfaceResponse, status_code=status.HTTP_201_CREATED)
async def define_attack_surface(
    surface_data: AttackSurfaceCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Define an attack surface"""
    surface = AttackSurface(
        id=str(uuid.uuid4()),
        name=surface_data.name,
        surface_type=surface_data.surface_type,
        description=surface_data.description,
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(surface)
    await db.flush()
    await db.refresh(surface)

    return surface


@router.get("/attack-surface", response_model=AttackSurfaceListResponse)
async def list_attack_surfaces(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    surface_type: Optional[str] = None,
):
    """List attack surfaces"""
    org_id = getattr(current_user, "organization_id", None)
    query = select(AttackSurface)
    if org_id is not None:
        query = query.where(AttackSurface.organization_id == org_id)

    if surface_type:
        query = query.where(AttackSurface.surface_type == surface_type)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(desc(AttackSurface.created_at))
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    surfaces = list(result.scalars().all())

    return {
        "items": surfaces,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


@router.get("/attack-surface/{surface_id}", response_model=AttackSurfaceResponse)
async def get_attack_surface(
    surface_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get attack surface details and composition"""
    surface = await get_attack_surface_or_404(db, surface_id, getattr(current_user, "organization_id", None))
    return surface


@router.put("/attack-surface/{surface_id}", response_model=AttackSurfaceResponse)
async def update_attack_surface(
    surface_id: str,
    surface_data: AttackSurfaceUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update attack surface"""
    surface = await get_attack_surface_or_404(db, surface_id, getattr(current_user, "organization_id", None))

    update_data = surface_data.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in update_data.items():
        setattr(surface, key, value)

    await db.flush()
    await db.refresh(surface)

    return surface


@router.post("/attack-surface/assess", response_model=AssessmentResult)
async def trigger_assessment(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    surface_id: str = Query(...),
):
    """Trigger assessment of an attack surface"""
    surface = await get_attack_surface_or_404(db, surface_id, getattr(current_user, "organization_id", None))

    # Count exposures for this surface
    asset_count_result = await db.execute(
        select(func.count(ExposureAsset.id)).where(
            ExposureAsset.organization_id == getattr(current_user, "organization_id", None)
        )
    )
    total_exposures = asset_count_result.scalar() or 0

    critical_count_result = await db.execute(
        select(func.count(AssetVulnerability.id)).where(
            and_(
                AssetVulnerability.organization_id == getattr(current_user, "organization_id", None),
                AssetVulnerability.status == "open",
            )
        )
    )
    critical_exposures = critical_count_result.scalar() or 0

    assessment_id = str(uuid.uuid4())

    return {
        "assessment_id": assessment_id,
        "surface_id": surface_id,
        "total_exposures": total_exposures,
        "critical_exposures": critical_exposures,
        "risk_score": surface.risk_score,
        "status": "running",
        "findings": surface.findings,
    }


# ============================================================================
# DASHBOARD AND REPORTING ENDPOINTS
# ============================================================================


@router.get("/dashboard", response_model=ExposureDashboardStats)
async def get_dashboard_statistics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get exposure management dashboard statistics"""
    org_id = getattr(current_user, "organization_id", None)

    # Total and active assets
    asset_conditions = [ExposureAsset.organization_id == org_id] if org_id is not None else []
    total_assets_result = await db.execute(
        select(func.count(ExposureAsset.id)).where(*asset_conditions) if asset_conditions else select(func.count(ExposureAsset.id))
    )
    total_assets = total_assets_result.scalar() or 0

    active_conditions = [ExposureAsset.is_active == True]
    if org_id is not None:
        active_conditions.append(ExposureAsset.organization_id == org_id)
    active_assets_result = await db.execute(
        select(func.count(ExposureAsset.id)).where(and_(*active_conditions))
    )
    active_assets = active_assets_result.scalar() or 0

    inet_conditions = [ExposureAsset.is_internet_facing == True]
    if org_id is not None:
        inet_conditions.append(ExposureAsset.organization_id == org_id)
    internet_facing_result = await db.execute(
        select(func.count(ExposureAsset.id)).where(and_(*inet_conditions))
    )
    internet_facing_assets = internet_facing_result.scalar() or 0

    # Vulnerability counts by severity
    vuln_query = select(func.count(Vulnerability.id))
    if org_id is not None:
        vuln_query = vuln_query.where(Vulnerability.organization_id == org_id)
    total_vulns_result = await db.execute(vuln_query)
    total_vulnerabilities = total_vulns_result.scalar() or 0

    sev_query = select(Vulnerability.severity, func.count(Vulnerability.id))
    if org_id is not None:
        sev_query = sev_query.where(Vulnerability.organization_id == org_id)
    severity_result = await db.execute(sev_query.group_by(Vulnerability.severity))
    severity_counts = dict(severity_result.all())

    # Overdue tickets
    overdue_conditions = [
        RemediationTicket.due_date < datetime.now(timezone.utc),
        RemediationTicket.status.notin_(["closed", "verification"]),
    ]
    if org_id is not None:
        overdue_conditions.append(RemediationTicket.organization_id == org_id)
    overdue_result = await db.execute(
        select(func.count(RemediationTicket.id)).where(and_(*overdue_conditions))
    )
    overdue_tickets = overdue_result.scalar() or 0

    # Assets by criticality
    crit_query = select(ExposureAsset.criticality, func.count(ExposureAsset.id))
    if org_id is not None:
        crit_query = crit_query.where(ExposureAsset.organization_id == org_id)
    criticality_result = await db.execute(crit_query.group_by(ExposureAsset.criticality))
    assets_by_criticality = dict(criticality_result.all())

    # Vulns by status
    vs_query = select(AssetVulnerability.status, func.count(AssetVulnerability.id))
    if org_id is not None:
        vs_query = vs_query.where(AssetVulnerability.organization_id == org_id)
    vuln_status_result = await db.execute(vs_query.group_by(AssetVulnerability.status))
    vulns_by_status = dict(vuln_status_result.all())

    # --- REAL MTTR: average (resolved_at - created_at) over closed tickets ---
    mttr_query = select(RemediationTicket.created_at, RemediationTicket.resolved_at)
    if org_id is not None:
        mttr_query = mttr_query.where(RemediationTicket.organization_id == org_id)
    mttr_query = mttr_query.where(
        RemediationTicket.status == "closed",
        RemediationTicket.resolved_at.is_not(None),
    )
    mttr_result = await db.execute(mttr_query)
    durations_days: list[float] = []
    for created_at, resolved_at in mttr_result.all():
        if not created_at or not resolved_at:
            continue
        delta = (resolved_at - created_at).total_seconds() / 86400.0
        if delta > 0:
            durations_days.append(delta)
    mean_time_to_remediate_days = (
        round(sum(durations_days) / len(durations_days), 2) if durations_days else None
    )

    # --- REAL OVERALL RISK SCORE: weighted blend of open vulns by severity ---
    # Simple FAIR-adjacent heuristic: critical=10, high=5, medium=2, low=1.
    # Normalize to 0-100 with 100 = "every asset has a critical vuln".
    severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "informational": 0}
    weighted_sum = sum(
        severity_counts.get(k, 0) * w for k, w in severity_weights.items()
    )
    max_possible = max(total_assets, 1) * 10  # ceiling: every asset critical
    overall_risk_score = round(min(100.0, (weighted_sum / max_possible) * 100.0), 1) if max_possible > 0 else 0.0

    # --- REAL TOP VULNERABLE ASSETS: top 10 by risk_score ---
    top_query = select(ExposureAsset).order_by(ExposureAsset.risk_score.desc()).limit(10)
    if org_id is not None:
        top_query = top_query.where(ExposureAsset.organization_id == org_id)
    top_result = await db.execute(top_query)
    top_vulnerable_assets = [
        {
            "id": a.id,
            "hostname": a.hostname,
            "asset_type": a.asset_type,
            "criticality": a.criticality,
            "risk_score": float(a.risk_score or 0.0),
            "is_internet_facing": a.is_internet_facing,
        }
        for a in top_result.scalars().all()
    ]

    # --- REAL EXPOSURE TREND: daily new vulns over the last 30 days ---
    from datetime import timedelta as _td
    thirty_days_ago = datetime.now(timezone.utc) - _td(days=30)
    trend_query = select(
        func.date_trunc("day", Vulnerability.created_at).label("day"),
        func.count(Vulnerability.id),
    ).where(Vulnerability.created_at >= thirty_days_ago)
    if org_id is not None:
        trend_query = trend_query.where(Vulnerability.organization_id == org_id)
    trend_query = trend_query.group_by("day").order_by("day")
    trend_result = await db.execute(trend_query)
    trend_by_day = {row[0].date().isoformat(): int(row[1]) for row in trend_result.all()}
    # Fill any missing day with 0 to keep the chart dense
    exposure_trend = []
    for i in range(30):
        day = (thirty_days_ago + _td(days=i)).date()
        exposure_trend.append({
            "date": day.strftime("%b %d"),
            "exposures": trend_by_day.get(day.isoformat(), 0),
        })

    # --- REAL COMPLIANCE SUMMARY: pull aggregates from ComplianceFramework if present ---
    compliance_summary = {}
    try:
        from src.compliance.models import ComplianceFramework
        fw_query = select(
            ComplianceFramework.short_name,
            ComplianceFramework.compliance_score,
            ComplianceFramework.total_controls,
            ComplianceFramework.implemented_controls,
        ).where(ComplianceFramework.is_enabled == True)
        if org_id is not None:
            fw_query = fw_query.where(ComplianceFramework.organization_id == org_id)
        fw_result = await db.execute(fw_query)
        for short, score, total, implemented in fw_result.all():
            compliance_summary[short or "unknown"] = {
                "score": float(score or 0.0),
                "total_controls": int(total or 0),
                "implemented_controls": int(implemented or 0),
            }
    except Exception:
        pass  # Compliance module optional — keep the dashboard rendering

    return {
        "total_assets": total_assets,
        "active_assets": active_assets,
        "internet_facing_assets": internet_facing_assets,
        "total_vulnerabilities": total_vulnerabilities,
        "critical_vulns": severity_counts.get("critical", 0),
        "high_vulns": severity_counts.get("high", 0),
        "medium_vulns": severity_counts.get("medium", 0),
        "low_vulns": severity_counts.get("low", 0),
        "info_vulns": severity_counts.get("informational", 0),
        "mean_time_to_remediate_days": mean_time_to_remediate_days,
        "overdue_tickets": overdue_tickets,
        "overall_risk_score": overall_risk_score,
        "assets_by_criticality": assets_by_criticality,
        "vulns_by_status": vulns_by_status,
        "top_vulnerable_assets": top_vulnerable_assets,
        "exposure_trend": exposure_trend,
        "compliance_summary": compliance_summary,
    }


@router.get("/risk-matrix", response_model=RiskMatrix)
async def get_risk_matrix(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Build a real criticality×severity risk matrix.

    Joins every open AssetVulnerability to its parent ExposureAsset +
    Vulnerability, then groups by (asset.criticality × vuln.severity).
    The resulting 4×5 grid (low/medium/high/critical × info/low/medium/high/critical)
    is what the frontend risk heatmap renders.
    """
    org_id = getattr(current_user, "organization_id", None)

    # Total open exposures
    total_conditions = [AssetVulnerability.status == "open"]
    if org_id is not None:
        total_conditions.append(AssetVulnerability.organization_id == org_id)
    total_result = await db.execute(
        select(func.count(AssetVulnerability.id)).where(and_(*total_conditions))
    )
    total_exposures = total_result.scalar() or 0

    # Critical exposures (risk_score >= 80 OR vuln.severity == critical)
    critical_conditions = list(total_conditions) + [AssetVulnerability.risk_score >= 80.0]
    critical_result = await db.execute(
        select(func.count(AssetVulnerability.id)).where(and_(*critical_conditions))
    )
    critical_exposures = critical_result.scalar() or 0

    # Build the matrix: JOIN to asset (for criticality) + vuln (for severity)
    matrix_query = (
        select(
            ExposureAsset.criticality,
            Vulnerability.severity,
            func.count(AssetVulnerability.id),
        )
        .join(ExposureAsset, AssetVulnerability.asset_id == ExposureAsset.id)
        .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .where(AssetVulnerability.status == "open")
        .group_by(ExposureAsset.criticality, Vulnerability.severity)
    )
    if org_id is not None:
        matrix_query = matrix_query.where(AssetVulnerability.organization_id == org_id)
    matrix_result = await db.execute(matrix_query)

    # Initialize the grid so cells with zero exposures render as 0 (not missing)
    criticalities = ["low", "medium", "high", "critical"]
    severities = ["informational", "low", "medium", "high", "critical"]
    matrix: dict = {c: {s: 0 for s in severities} for c in criticalities}

    for crit, sev, count in matrix_result.all():
        if crit in matrix and sev in matrix[crit]:
            matrix[crit][sev] = int(count)

    return {
        "matrix": matrix,
        "total_exposures": total_exposures,
        "critical_exposures": critical_exposures,
    }


@router.get("/compliance", response_model=ComplianceSummary)
async def get_compliance_status(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Compliance status summary for the exposure dashboard.

    Pulls real framework data from the ComplianceFramework + ComplianceControl
    tables, aggregates pass/fail counts per framework, and computes an
    overall compliance score. Frontend consumes this to render the
    Compliance tab list of frameworks.
    """
    org_id = getattr(current_user, "organization_id", None)

    frameworks_data: dict = {}
    total_checks = 0
    passed_checks = 0
    failed_checks = 0
    overall_scores: list[float] = []

    try:
        from src.compliance.models import ComplianceFramework, ComplianceControl

        fw_query = select(ComplianceFramework).where(ComplianceFramework.is_enabled == True)  # noqa: E712
        if org_id is not None:
            fw_query = fw_query.where(ComplianceFramework.organization_id == org_id)
        fw_result = await db.execute(fw_query)
        frameworks = list(fw_result.scalars().all())

        for fw in frameworks:
            # Count controls per framework
            total_q = select(func.count(ComplianceControl.id)).where(
                ComplianceControl.framework_id == fw.id
            )
            total_fw = (await db.execute(total_q)).scalar() or 0

            passed_q = select(func.count(ComplianceControl.id)).where(
                ComplianceControl.framework_id == fw.id,
                ComplianceControl.status == "implemented",
            )
            passed_fw = (await db.execute(passed_q)).scalar() or 0

            failed_q = select(func.count(ComplianceControl.id)).where(
                ComplianceControl.framework_id == fw.id,
                ComplianceControl.status.in_(["not_implemented", "partial", "non_compliant"]),
            )
            failed_fw = (await db.execute(failed_q)).scalar() or 0

            pass_pct = round((passed_fw / total_fw * 100.0), 1) if total_fw > 0 else 0.0

            frameworks_data[fw.short_name or fw.name] = {
                "name": fw.name,
                "score": float(fw.compliance_score or 0.0),
                "pass_percentage": pass_pct,
                "total_controls": int(total_fw),
                "passed_checks": int(passed_fw),
                "failed_checks": int(failed_fw),
                "status": fw.status,
                "last_assessment_at": fw.last_assessment_at.isoformat() if fw.last_assessment_at else None,
            }

            total_checks += total_fw
            passed_checks += passed_fw
            failed_checks += failed_fw
            if fw.compliance_score is not None:
                overall_scores.append(float(fw.compliance_score))
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            f"Compliance summary partial — compliance module unavailable: {e}"
        )

    # Fall back to asset-count if no frameworks exist (fresh install)
    if total_checks == 0:
        asset_q = select(func.count(ExposureAsset.id))
        if org_id is not None:
            asset_q = asset_q.where(ExposureAsset.organization_id == org_id)
        total_checks = (await db.execute(asset_q)).scalar() or 0

    overall_score = round(sum(overall_scores) / len(overall_scores), 1) if overall_scores else 0.0

    return {
        "frameworks": frameworks_data,
        "overall_compliance_score": overall_score,
        "total_compliance_checks": total_checks,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
    }


@router.post("/report", response_model=ExposureReport)
async def generate_exposure_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    title: str = Query(...),
    include_recommendations: bool = Query(True),
):
    """Generate exposure management report"""
    org_id = getattr(current_user, "organization_id", None)

    # Gather statistics
    total_assets_result = await db.execute(
        select(func.count(ExposureAsset.id)).where(ExposureAsset.organization_id == org_id)
    )
    total_assets = total_assets_result.scalar() or 0

    active_assets_result = await db.execute(
        select(func.count(ExposureAsset.id)).where(
            and_(ExposureAsset.organization_id == org_id, ExposureAsset.is_active == True)
        )
    )
    active_assets = active_assets_result.scalar() or 0

    internet_facing_result = await db.execute(
        select(func.count(ExposureAsset.id)).where(
            and_(ExposureAsset.organization_id == org_id, ExposureAsset.is_internet_facing == True)
        )
    )
    internet_facing_assets = internet_facing_result.scalar() or 0

    total_vulns_result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.organization_id == org_id)
    )
    total_vulnerabilities = total_vulns_result.scalar() or 0

    severity_result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.organization_id == org_id)
        .group_by(Vulnerability.severity)
    )
    severity_counts = dict(severity_result.all())

    overdue_result = await db.execute(
        select(func.count(RemediationTicket.id)).where(
            and_(
                RemediationTicket.organization_id == org_id,
                RemediationTicket.due_date < datetime.now(timezone.utc),
                RemediationTicket.status.notin_(["closed", "verification"]),
            )
        )
    )
    overdue_tickets = overdue_result.scalar() or 0

    statistics = {
        "total_assets": total_assets,
        "active_assets": active_assets,
        "internet_facing_assets": internet_facing_assets,
        "total_vulnerabilities": total_vulnerabilities,
        "critical_vulns": severity_counts.get("critical", 0),
        "high_vulns": severity_counts.get("high", 0),
        "medium_vulns": severity_counts.get("medium", 0),
        "low_vulns": severity_counts.get("low", 0),
        "info_vulns": severity_counts.get("informational", 0),
        "mean_time_to_remediate_days": 0.0,
        "overdue_tickets": overdue_tickets,
        "overall_risk_score": 0.0,
        "assets_by_criticality": {},
        "vulns_by_status": {},
        "top_vulnerable_assets": [],
        "exposure_trend": [],
        "compliance_summary": {},
    }

    return {
        "title": title,
        "report_date": datetime.now(timezone.utc).isoformat(),
        "summary": f"Exposure report: {total_assets} assets, {total_vulnerabilities} vulnerabilities tracked",
        "statistics": statistics,
        "top_findings": [],
        "recommendations": [],
        "compliance_status": {
            "frameworks": {},
            "overall_compliance_score": 0.0,
            "total_compliance_checks": 0,
            "passed_checks": 0,
            "failed_checks": 0,
        },
    }
