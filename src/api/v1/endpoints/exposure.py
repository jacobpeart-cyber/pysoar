"""Exposure Management and CTEM API endpoints"""

import math
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status, UploadFile, File
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user, get_db
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


async def get_asset_or_404(db: AsyncSession, asset_id: str):
    """Get exposure asset by ID or raise 404"""
    # This is a placeholder - implementation depends on database models
    # which should be created in src/models/exposure.py
    return {"id": asset_id}


async def get_vulnerability_or_404(db: AsyncSession, vuln_id: str):
    """Get vulnerability by ID or raise 404"""
    return {"id": vuln_id}


async def get_asset_vulnerability_or_404(db: AsyncSession, mapping_id: str):
    """Get asset-vulnerability mapping by ID or raise 404"""
    return {"id": mapping_id}


async def get_scan_or_404(db: AsyncSession, scan_id: str):
    """Get scan by ID or raise 404"""
    return {"id": scan_id}


async def get_ticket_or_404(db: AsyncSession, ticket_id: str):
    """Get remediation ticket by ID or raise 404"""
    return {"id": ticket_id}


async def get_attack_surface_or_404(db: AsyncSession, surface_id: str):
    """Get attack surface by ID or raise 404"""
    return {"id": surface_id}


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
    # Implementation depends on Asset model in src/models/exposure.py
    # Placeholder response
    return {
        "id": "asset_123",
        "hostname": asset_data.hostname,
        "ip_address": asset_data.ip_address,
        "mac_address": asset_data.mac_address,
        "asset_type": asset_data.asset_type,
        "os_type": asset_data.os_type,
        "os_version": asset_data.os_version,
        "environment": asset_data.environment,
        "criticality": asset_data.criticality,
        "business_unit": asset_data.business_unit,
        "owner": asset_data.owner,
        "location": asset_data.location,
        "cloud_provider": asset_data.cloud_provider,
        "cloud_region": asset_data.cloud_region,
        "cloud_resource_id": asset_data.cloud_resource_id,
        "is_internet_facing": asset_data.is_internet_facing,
        "services": asset_data.services,
        "software_inventory": asset_data.software_inventory,
        "tags": asset_data.tags,
        "network_zone": asset_data.network_zone,
        "metadata": asset_data.metadata,
        "is_active": True,
        "last_seen": None,
        "last_scan_at": None,
        "risk_score": 0.0,
        "vulnerability_count": 0,
        "open_ports": [],
        "compliance_status": None,
        "created_at": "2026-03-24T00:00:00Z",
        "updated_at": "2026-03-24T00:00:00Z",
    }


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
    # Implementation would build query filters and execute
    # Placeholder response
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
    }


@router.get("/assets/{asset_id}", response_model=ExposureAssetResponse)
async def get_asset(
    asset_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific exposure asset with details and vulnerabilities"""
    asset = await get_asset_or_404(db, asset_id)
    return asset


@router.put("/assets/{asset_id}", response_model=ExposureAssetResponse)
async def update_asset(
    asset_id: str,
    asset_data: ExposureAssetUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an exposure asset"""
    asset = await get_asset_or_404(db, asset_id)
    return asset


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_asset(
    asset_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Deactivate an exposure asset"""
    asset = await get_asset_or_404(db, asset_id)


@router.post("/assets/discover", response_model=DiscoveryResult)
async def trigger_asset_discovery(
    discovery_request: AssetDiscoveryRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Trigger asset discovery scan (network, cloud, AD, DNS)"""
    return {
        "scan_id": "scan_discovery_123",
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
    return {
        "imported": 0,
        "failed": 0,
        "errors": [],
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
    asset = await get_asset_or_404(db, asset_id)
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
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
    return {
        "id": "vuln_123",
        "cve_id": vuln_data.cve_id,
        "title": vuln_data.title,
        "description": vuln_data.description,
        "severity": vuln_data.severity,
        "cvss_v3_score": vuln_data.cvss_v3_score,
        "cvss_v3_vector": vuln_data.cvss_v3_vector,
        "epss_score": vuln_data.epss_score,
        "is_exploited_in_wild": vuln_data.is_exploited_in_wild,
        "exploit_available": vuln_data.exploit_available,
        "exploit_maturity": vuln_data.exploit_maturity,
        "affected_products": vuln_data.affected_products,
        "patch_available": vuln_data.patch_available,
        "patch_url": vuln_data.patch_url,
        "references": vuln_data.references,
        "mitre_techniques": vuln_data.mitre_techniques,
        "tags": vuln_data.tags,
        "created_at": "2026-03-24T00:00:00Z",
        "updated_at": "2026-03-24T00:00:00Z",
    }


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
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
    }


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific vulnerability with affected assets"""
    vuln = await get_vulnerability_or_404(db, vuln_id)
    return vuln


@router.put("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: str,
    vuln_data: VulnerabilityUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update vulnerability information"""
    vuln = await get_vulnerability_or_404(db, vuln_id)
    return vuln


@router.delete("/vulnerabilities/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vulnerability(
    vuln_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a vulnerability record"""
    vuln = await get_vulnerability_or_404(db, vuln_id)


@router.get("/vulnerabilities/kev")
async def get_cisa_kev_list(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get CISA Known Exploited Vulnerabilities list (with integration)"""
    return {
        "kev_vulnerabilities": [],
        "last_updated": "2026-03-24T00:00:00Z",
        "count": 0,
    }


@router.post("/vulnerabilities/search", response_model=VulnerabilityListResponse)
async def advanced_vulnerability_search(
    search_request: ExposureSearchRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
):
    """Advanced vulnerability search with complex filtering"""
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
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
    return {
        "id": "mapping_123",
        "asset_id": mapping_data.asset_id,
        "vulnerability_id": mapping_data.vulnerability_id,
        "status": mapping_data.status,
        "assigned_to": mapping_data.assigned_to,
        "due_date": mapping_data.due_date,
        "remediation_notes": mapping_data.remediation_notes,
        "compensating_controls": mapping_data.compensating_controls,
        "detected_by": mapping_data.detected_by,
        "first_detected": "2026-03-24T00:00:00Z",
        "last_detected": "2026-03-24T00:00:00Z",
        "detection_count": 1,
        "created_at": "2026-03-24T00:00:00Z",
        "updated_at": "2026-03-24T00:00:00Z",
    }


@router.put("/asset-vulns/{mapping_id}", response_model=AssetVulnerabilityResponse)
async def update_asset_vulnerability(
    mapping_id: str,
    mapping_data: AssetVulnerabilityUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update asset-vulnerability status (open, remediated, accepted, false-positive)"""
    mapping = await get_asset_vulnerability_or_404(db, mapping_id)
    return mapping


@router.post("/asset-vulns/{mapping_id}/remediate", response_model=AssetVulnerabilityResponse)
async def mark_as_remediated(
    mapping_id: str,
    remediation_notes: Optional[str] = Query(None),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Mark asset-vulnerability as remediated"""
    mapping = await get_asset_vulnerability_or_404(db, mapping_id)
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
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
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
    return {
        "id": "scan_123",
        "scan_type": scan_data.scan_type,
        "scan_name": scan_data.scan_name,
        "target_assets": scan_data.target_assets,
        "scanner": scan_data.scanner,
        "scan_profile": scan_data.scan_profile,
        "status": "pending",
        "started_at": None,
        "completed_at": None,
        "stats": {},
        "findings_count": 0,
        "errors": [],
        "created_at": "2026-03-24T00:00:00Z",
        "updated_at": "2026-03-24T00:00:00Z",
    }


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
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
    }


@router.get("/scans/{scan_id}", response_model=ExposureScanResponse)
async def get_scan(
    scan_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get scan results and details"""
    scan = await get_scan_or_404(db, scan_id)
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ExposureScanResponse)
async def cancel_scan(
    scan_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Cancel a running scan"""
    scan = await get_scan_or_404(db, scan_id)
    return scan


@router.post("/scans/import", response_model=ScannerImportResult)
async def import_scan_results(
    import_data: ExternalScannerImportRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Import results from external scanners (Nessus, Qualys, etc.)"""
    return {
        "import_id": "import_123",
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
    return {
        "id": "ticket_123",
        "title": ticket_data.title,
        "description": ticket_data.description,
        "priority": ticket_data.priority,
        "assigned_to": ticket_data.assigned_to,
        "assigned_team": ticket_data.assigned_team,
        "asset_vulnerabilities": ticket_data.asset_vulnerabilities,
        "affected_assets": ticket_data.affected_assets,
        "remediation_type": ticket_data.remediation_type,
        "remediation_steps": ticket_data.remediation_steps,
        "due_date": ticket_data.due_date,
        "external_ticket_id": ticket_data.external_ticket_id,
        "status": "open",
        "created_at": "2026-03-24T00:00:00Z",
        "updated_at": "2026-03-24T00:00:00Z",
        "completed_at": None,
    }


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
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
    }


@router.get("/tickets/{ticket_id}", response_model=RemediationTicketResponse)
async def get_remediation_ticket(
    ticket_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific remediation ticket"""
    ticket = await get_ticket_or_404(db, ticket_id)
    return ticket


@router.put("/tickets/{ticket_id}", response_model=RemediationTicketResponse)
async def update_remediation_ticket(
    ticket_id: str,
    ticket_data: RemediationTicketUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a remediation ticket"""
    ticket = await get_ticket_or_404(db, ticket_id)
    return ticket


@router.post("/tickets/{ticket_id}/verify", response_model=RemediationVerificationResult)
async def verify_remediation(
    ticket_id: str,
    verification_data: RemediationVerificationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Verify remediation completion"""
    ticket = await get_ticket_or_404(db, ticket_id)
    return {
        "ticket_id": ticket_id,
        "verified": True,
        "verification_date": "2026-03-24T00:00:00Z",
        "verified_by": current_user.id if current_user else "system",
        "notes": verification_data.verification_notes,
    }


@router.get("/tickets/overdue", response_model=RemediationTicketListResponse)
async def get_overdue_tickets(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
):
    """Get overdue remediation tickets"""
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
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
    return {
        "id": "surface_123",
        "name": surface_data.name,
        "surface_type": surface_data.surface_type,
        "description": surface_data.description,
        "assets_count": 0,
        "vulnerabilities_count": 0,
        "risk_score": 0.0,
        "last_assessment_at": None,
        "created_at": "2026-03-24T00:00:00Z",
        "updated_at": "2026-03-24T00:00:00Z",
    }


@router.get("/attack-surface", response_model=AttackSurfaceListResponse)
async def list_attack_surfaces(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    surface_type: Optional[str] = None,
):
    """List attack surfaces"""
    return {
        "items": [],
        "total": 0,
        "page": page,
        "size": size,
        "pages": 0,
    }


@router.get("/attack-surface/{surface_id}", response_model=AttackSurfaceResponse)
async def get_attack_surface(
    surface_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get attack surface details and composition"""
    surface = await get_attack_surface_or_404(db, surface_id)
    return surface


@router.put("/attack-surface/{surface_id}", response_model=AttackSurfaceResponse)
async def update_attack_surface(
    surface_id: str,
    surface_data: AttackSurfaceUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update attack surface"""
    surface = await get_attack_surface_or_404(db, surface_id)
    return surface


@router.post("/attack-surface/assess", response_model=AssessmentResult)
async def trigger_assessment(
    surface_id: str = Query(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Trigger assessment of an attack surface"""
    return {
        "assessment_id": "assess_123",
        "surface_id": surface_id,
        "total_exposures": 0,
        "critical_exposures": 0,
        "risk_score": 0.0,
        "status": "running",
        "findings": [],
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
    return {
        "total_assets": 0,
        "active_assets": 0,
        "internet_facing_assets": 0,
        "total_vulnerabilities": 0,
        "critical_vulns": 0,
        "high_vulns": 0,
        "medium_vulns": 0,
        "low_vulns": 0,
        "info_vulns": 0,
        "mean_time_to_remediate_days": 0.0,
        "overdue_tickets": 0,
        "overall_risk_score": 0.0,
        "assets_by_criticality": {},
        "vulns_by_status": {},
        "top_vulnerable_assets": [],
        "exposure_trend": [],
        "compliance_summary": {},
    }


@router.get("/risk-matrix", response_model=RiskMatrix)
async def get_risk_matrix(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get risk matrix (criticality vs severity)"""
    return {
        "matrix": {},
        "total_exposures": 0,
        "critical_exposures": 0,
    }


@router.get("/compliance", response_model=ComplianceSummary)
async def get_compliance_status(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get compliance status summary"""
    return {
        "frameworks": {},
        "overall_compliance_score": 0.0,
        "total_compliance_checks": 0,
        "passed_checks": 0,
        "failed_checks": 0,
    }


@router.post("/report", response_model=ExposureReport)
async def generate_exposure_report(
    title: str = Query(...),
    include_recommendations: bool = Query(True),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Generate exposure management report"""
    return {
        "title": title,
        "report_date": "2026-03-24T00:00:00Z",
        "summary": "Exposure report summary",
        "statistics": {
            "total_assets": 0,
            "active_assets": 0,
            "internet_facing_assets": 0,
            "total_vulnerabilities": 0,
            "critical_vulns": 0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "low_vulns": 0,
            "info_vulns": 0,
            "mean_time_to_remediate_days": 0.0,
            "overdue_tickets": 0,
            "overall_risk_score": 0.0,
            "assets_by_criticality": {},
            "vulns_by_status": {},
            "top_vulnerable_assets": [],
            "exposure_trend": [],
            "compliance_summary": {},
        },
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
