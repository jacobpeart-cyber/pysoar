"""Exposure Management and CTEM schemas for request/response validation"""

import json
from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field, model_validator


# ============================================================================
# EXPOSURE ASSET SCHEMAS
# ============================================================================


class ExposureAssetBase(BaseModel):
    """Base exposure asset schema"""

    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    mac_address: Optional[str] = Field(None, max_length=17)
    asset_type: str = Field(..., max_length=50, description="e.g., server, workstation, network, database, application")
    os_type: Optional[str] = Field(None, max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)
    environment: str = Field(default="production", max_length=50)
    criticality: str = Field(default="medium", max_length=50, description="critical, high, medium, low")
    business_unit: Optional[str] = Field(None, max_length=255)
    owner: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field(None, max_length=255)
    cloud_provider: Optional[str] = Field(None, max_length=50)
    cloud_region: Optional[str] = Field(None, max_length=100)
    cloud_resource_id: Optional[str] = Field(None, max_length=255)
    is_internet_facing: bool = Field(default=False)
    services: list[dict] = Field(default_factory=list, description="List of services running on asset")
    software_inventory: list[dict] = Field(default_factory=list, description="Software and versions installed")
    tags: list[str] = Field(default_factory=list)
    network_zone: Optional[str] = Field(None, max_length=100)
    extra_metadata: dict = Field(default_factory=dict, description="Additional metadata")


class ExposureAssetCreate(ExposureAssetBase):
    """Schema for creating an exposure asset"""

    pass


class ExposureAssetUpdate(BaseModel):
    """Schema for updating an exposure asset"""

    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    mac_address: Optional[str] = Field(None, max_length=17)
    asset_type: Optional[str] = Field(None, max_length=50)
    os_type: Optional[str] = Field(None, max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)
    environment: Optional[str] = Field(None, max_length=50)
    criticality: Optional[str] = Field(None, max_length=50)
    business_unit: Optional[str] = Field(None, max_length=255)
    owner: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field(None, max_length=255)
    cloud_provider: Optional[str] = Field(None, max_length=50)
    cloud_region: Optional[str] = Field(None, max_length=100)
    cloud_resource_id: Optional[str] = Field(None, max_length=255)
    is_internet_facing: Optional[bool] = None
    services: Optional[list[dict]] = None
    software_inventory: Optional[list[dict]] = None
    tags: Optional[list[str]] = None
    network_zone: Optional[str] = Field(None, max_length=100)
    extra_metadata: Optional[dict] = None


class ExposureAssetResponse(ExposureAssetBase, DBModel):
    """Schema for exposure asset response"""

    id: str = ""
    is_active: bool = False
    last_seen: Optional[datetime] = None
    last_scan_at: Optional[datetime] = None
    risk_score: float = 0.0
    vulnerability_count: int = 0
    open_ports: list[int] = Field(default_factory=list)
    compliance_status: Optional[Any] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # "active" / "inactive" (from is_active; DELETE deactivates).
    status: Optional[str] = None

    class Config:
        from_attributes = True

    @model_validator(mode="after")
    def _derive_status(self) -> "ExposureAssetResponse":
        self.status = "active" if self.is_active else "inactive"
        return self


class ExposureAssetListResponse(BaseModel):
    """Schema for paginated exposure asset list"""

    items: list[ExposureAssetResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# VULNERABILITY SCHEMAS
# ============================================================================


class VulnerabilityBase(BaseModel):
    """Base vulnerability schema"""

    cve_id: Optional[str] = Field(None, max_length=50)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: str = Field(default="medium", max_length=50, description="critical, high, medium, low, info")
    cvss_v3_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_v3_vector: Optional[str] = Field(None, max_length=255)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Exploit Prediction Scoring System")
    is_exploited_in_wild: bool = Field(default=False)
    exploit_available: bool = Field(default=False)
    exploit_maturity: str = Field(default="none", max_length=50, description="none, proof-of-concept, functional, high")
    affected_products: list[str] = Field(default_factory=list)
    patch_available: bool = Field(default=False)
    patch_url: Optional[str] = Field(None, max_length=500)
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    tags: list[str] = Field(default_factory=list)


class VulnerabilityCreate(VulnerabilityBase):
    """Schema for creating a vulnerability"""

    pass


class VulnerabilityUpdate(BaseModel):
    """Schema for updating a vulnerability"""

    cve_id: Optional[str] = Field(None, max_length=50)
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[str] = Field(None, max_length=50)
    cvss_v3_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_v3_vector: Optional[str] = Field(None, max_length=255)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    is_exploited_in_wild: Optional[bool] = None
    exploit_available: Optional[bool] = None
    exploit_maturity: Optional[str] = Field(None, max_length=50)
    affected_products: Optional[list[str]] = None
    patch_available: Optional[bool] = None
    patch_url: Optional[str] = Field(None, max_length=500)
    references: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class VulnerabilityResponse(VulnerabilityBase, DBModel):
    """Schema for vulnerability response

    ``affected_assets`` (assets with an open / in-progress link),
    ``total_links`` and ``status`` ("open" when any link is open,
    "remediated" when every link is closed, "unlinked" without links) are
    filled by the list / get routes from the stored asset links.
    """

    affected_assets: Optional[int] = None
    total_links: Optional[int] = None
    status: Optional[str] = None
    epss_percentile: Optional[float] = None
    published_at: Optional[datetime] = None

    id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class VulnerabilityListResponse(BaseModel):
    """Schema for paginated vulnerability list"""

    items: list[VulnerabilityResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# ASSET-VULNERABILITY MAPPING SCHEMAS
# ============================================================================


class AssetVulnerabilityBase(BaseModel):
    """Base asset-vulnerability mapping schema"""

    asset_id: str = Field(..., description="ID of the affected asset")
    vulnerability_id: str = Field(..., description="ID of the vulnerability")
    status: str = Field(default="open", max_length=50, description="open, remediated, accepted, false-positive")
    assigned_to: Optional[str] = Field(None, max_length=255)
    due_date: Optional[datetime] = None
    remediation_notes: Optional[str] = None
    compensating_controls: list[str] = Field(default_factory=list)
    detected_by: str = Field(default="builtin", max_length=100)


class AssetVulnerabilityCreate(AssetVulnerabilityBase):
    """Schema for creating asset-vulnerability mapping"""

    pass


class AssetVulnerabilityUpdate(BaseModel):
    """Schema for updating asset-vulnerability mapping"""

    status: Optional[str] = Field(None, max_length=50)
    assigned_to: Optional[str] = Field(None, max_length=255)
    due_date: Optional[datetime] = None
    remediation_notes: Optional[str] = None
    compensating_controls: Optional[list[str]] = None
    detected_by: Optional[str] = Field(None, max_length=100)


class AssetVulnerabilityResponse(AssetVulnerabilityBase, DBModel):
    """Schema for asset-vulnerability response"""

    id: str = ""
    first_detected: Optional[datetime] = None
    last_detected: Optional[datetime] = None
    detection_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AssetVulnerabilityListResponse(BaseModel):
    """Schema for paginated asset-vulnerability list"""

    items: list[AssetVulnerabilityResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# EXPOSURE SCAN SCHEMAS
# ============================================================================


class ExposureScanBase(BaseModel):
    """Base exposure scan schema"""

    scan_type: str = Field(..., max_length=100, description="vulnerability, port, asset-discovery, config-audit")
    scan_name: str = Field(..., min_length=1, max_length=255)
    target_assets: list[str] = Field(default_factory=list, description="List of asset IDs or filters")
    scanner: str = Field(default="builtin", max_length=100)
    scan_profile: Optional[str] = Field(None, max_length=100)


class ExposureScanCreate(ExposureScanBase):
    """Schema for creating a scan"""

    pass


class ExposureScanResponse(ExposureScanBase, DBModel):
    """Schema for exposure scan response"""

    id: str = ""
    status: str = Field(default="pending", max_length=50, description="pending, running, completed, failed, cancelled")
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    stats: dict = Field(default_factory=dict, description="Scan statistics")
    findings_count: int = 0
    errors: list[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ExposureScanListResponse(BaseModel):
    """Schema for paginated scan list"""

    items: list[ExposureScanResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# REMEDIATION TICKET SCHEMAS
# ============================================================================


class RemediationTicketBase(BaseModel):
    """Base remediation ticket schema"""

    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    priority: str = Field(default="medium", max_length=50, description="critical, high, medium, low")
    assigned_to: Optional[str] = Field(None, max_length=255)
    assigned_team: Optional[str] = Field(None, max_length=255)
    asset_vulnerabilities: list[str] = Field(default_factory=list, description="List of asset-vulnerability IDs")
    affected_assets: list[str] = Field(default_factory=list, description="List of asset IDs")
    remediation_type: str = Field(default="patch", max_length=100, description="patch, config, retire, compensating-control")
    remediation_steps: list[dict] = Field(default_factory=list, description="Step-by-step remediation instructions")
    due_date: Optional[datetime] = None
    external_ticket_id: Optional[str] = Field(None, max_length=255)


class RemediationTicketCreate(RemediationTicketBase):
    """Schema for creating a remediation ticket"""

    pass


class RemediationTicketUpdate(BaseModel):
    """Schema for updating a remediation ticket"""

    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    priority: Optional[str] = Field(None, max_length=50)
    assigned_to: Optional[str] = Field(None, max_length=255)
    assigned_team: Optional[str] = Field(None, max_length=255)
    asset_vulnerabilities: Optional[list[str]] = None
    affected_assets: Optional[list[str]] = None
    remediation_type: Optional[str] = Field(None, max_length=100)
    remediation_steps: Optional[list[dict]] = None
    due_date: Optional[datetime] = None
    external_ticket_id: Optional[str] = Field(None, max_length=255)
    # open, assigned, in_progress, verification, closed, reopened. "closed"
    # stamps resolved_at (MTTR); leaving "closed" clears it.
    status: Optional[str] = Field(None, max_length=50)


class RemediationTicketResponse(RemediationTicketBase, DBModel):
    """Schema for remediation ticket response"""

    id: str = ""
    status: str = Field(default="open", max_length=50, description="open, in-progress, completed, cancelled, overdue")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # ``completed_at`` repeats the stored ``resolved_at``.
    completed_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    verification_status: Optional[str] = None
    sla_breach: Optional[bool] = None

    class Config:
        from_attributes = True

    @model_validator(mode="after")
    def _fill_completed(self) -> "RemediationTicketResponse":
        self.completed_at = self.resolved_at
        return self


class RemediationTicketListResponse(BaseModel):
    """Schema for paginated remediation ticket list"""

    items: list[RemediationTicketResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# ATTACK SURFACE SCHEMAS
# ============================================================================


class AttackSurfaceBase(BaseModel):
    """Base attack surface schema"""

    name: str = Field(..., min_length=1, max_length=255)
    surface_type: str = Field(..., max_length=100, description="internet-facing, internal, supply-chain, third-party")
    description: Optional[str] = None


class AttackSurfaceCreate(AttackSurfaceBase):
    """Schema for creating an attack surface"""

    pass


class AttackSurfaceUpdate(BaseModel):
    """Schema for updating an attack surface"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    surface_type: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None


class AttackSurfaceResponse(AttackSurfaceBase, DBModel):
    """Schema for attack surface response.

    The model columns (``total_assets``, ``exposed_assets``,
    ``critical_exposures``, ``last_assessed_at``) are returned as stored;
    ``type`` / ``last_assessed`` repeat ``surface_type`` / ``last_assessed_at``
    and the older ``assets_count`` / ``vulnerabilities_count`` /
    ``last_assessment_at`` names are filled from the same columns.
    ``assessed`` is false until an assessment has run (risk_score is then
    not a measurement).
    """

    id: str = ""
    assets_count: int = 0
    vulnerabilities_count: int = 0
    risk_score: float = 0.0
    last_assessment_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    type: Optional[str] = None
    total_assets: int = 0
    exposed_assets: int = 0
    critical_exposures: int = 0
    last_assessed_at: Optional[datetime] = None
    last_assessed: Optional[datetime] = None
    assessed: bool = False
    findings: list[dict] = Field(default_factory=list)

    class Config:
        from_attributes = True

    @model_validator(mode="after")
    def _fill_aliases(self) -> "AttackSurfaceResponse":
        self.type = self.surface_type
        self.assets_count = self.total_assets
        self.vulnerabilities_count = self.exposed_assets
        self.last_assessment_at = self.last_assessed_at
        self.last_assessed = self.last_assessed_at
        self.assessed = self.last_assessed_at is not None
        if self.surface_type == "snapshot":
            # Snapshot rows carry whole key lists; return per-change counts.
            self.findings = [
                {"change": f.get("change"), "count": len(f.get("items") or [])}
                for f in self.findings
                if isinstance(f, dict)
            ]
        else:
            self.findings = [f for f in self.findings if isinstance(f, dict)][-5:]
        return self


class AttackSurfaceListResponse(BaseModel):
    """Schema for paginated attack surface list"""

    items: list[AttackSurfaceResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# DASHBOARD AND REPORTING SCHEMAS
# ============================================================================


class ExposureDashboardStats(BaseModel):
    """Schema for exposure dashboard statistics"""

    total_assets: int = 0
    active_assets: int = 0
    internet_facing_assets: int = 0
    total_vulnerabilities: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    info_vulns: int = 0
    mean_time_to_remediate_days: Optional[float] = None
    overdue_tickets: int = 0
    # Mean stored asset risk over active assets; None without active assets.
    overall_risk_score: Optional[float] = None
    assets_by_criticality: dict = Field(default_factory=dict, description="Distribution of assets by criticality")
    vulns_by_status: dict = Field(default_factory=dict, description="Distribution of vulnerabilities by status")
    top_vulnerable_assets: list[dict] = Field(default_factory=list, description="Top assets with most vulnerabilities")
    exposure_trend: list[dict] = Field(default_factory=list, description="Time-series trend data")
    compliance_summary: dict = Field(default_factory=dict, description="Compliance status by framework")
    # Wave 4 additions.
    open_exposures: int = 0
    assets_with_open_exposures: int = 0
    inactive_assets: int = 0
    catalog_vulnerabilities: int = 0
    compliance_trend: list[dict] = Field(default_factory=list, description="Stored daily compliance points")
    trend_source: str = "exposure_daily_snapshots"
    risk_score_basis: str = ""


class RiskMatrix(BaseModel):
    """Schema for risk matrix (criticality vs severity)"""

    matrix: dict = Field(..., description="Risk matrix grid data")
    total_exposures: int = 0
    critical_exposures: int = 0


class ComplianceSummary(BaseModel):
    """Schema for compliance status summary"""

    frameworks: dict = Field(default_factory=dict, description="Compliance status by framework")
    overall_compliance_score: float = 0.0
    total_compliance_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0


class ExposureSearchRequest(BaseModel):
    """Schema for advanced exposure search"""

    query: Optional[str] = Field(None, description="Free-text search query")
    asset_types: Optional[list[str]] = None
    severity: Optional[list[str]] = None
    status: Optional[list[str]] = None
    environment: Optional[list[str]] = None
    criticality: Optional[list[str]] = None
    is_internet_facing: Optional[bool] = None
    has_exploits: Optional[bool] = None
    min_risk_score: Optional[float] = Field(None, ge=0.0)
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None


class ExposureReport(BaseModel):
    """Schema for exposure report"""

    title: str = ""
    report_date: datetime
    summary: str = ""
    statistics: ExposureDashboardStats
    top_findings: list[dict] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    compliance_status: ComplianceSummary


# ============================================================================
# BULK IMPORT SCHEMAS
# ============================================================================


class BulkAssetImportRequest(BaseModel):
    """Schema for bulk asset import"""

    format: str = Field(..., description="csv or json")
    data: str = Field(..., description="File content as string")


class BulkImportResult(BaseModel):
    """Schema for bulk import result"""

    imported: int = 0
    failed: int = 0
    errors: list[dict] = Field(default_factory=list)
    skipped: int = 0
    # ``imported`` = created + updated.
    created: int = 0
    updated: int = 0
    rows_read: int = 0


# ============================================================================
# DISCOVERY AND ASSESSMENT SCHEMAS
# ============================================================================


class AssetDiscoveryRequest(BaseModel):
    """Schema for triggering asset discovery"""

    scan_type: str = Field(..., description="network, cloud, active-directory, dns")
    targets: Optional[list[str]] = None
    scan_profile: Optional[str] = None


class DiscoveryResult(BaseModel):
    """Schema for discovery result"""

    scan_id: str = ""
    discovered_assets: int = 0
    new_assets: int = 0
    updated_assets: int = 0
    status: str = ""
    log_rows_scanned: int = 0
    truncated: bool = False
    detail: Optional[str] = None


class AssessmentResult(BaseModel):
    """Schema for attack surface assessment result"""

    assessment_id: str = ""
    surface_id: str = ""
    total_exposures: int = 0
    critical_exposures: int = 0
    risk_score: float = 0.0
    status: str = ""
    findings: list[dict] = Field(default_factory=list)


# ============================================================================
# REMEDIATION VERIFICATION SCHEMAS
# ============================================================================


class RemediationVerificationRequest(BaseModel):
    """Schema for remediation verification"""

    ticket_id: str = ""
    verification_notes: Optional[str] = None
    evidence: Optional[list[dict]] = Field(None, description="Verification evidence")


class RemediationVerificationResult(BaseModel):
    """Schema for remediation verification result"""

    ticket_id: str = ""
    verified: bool = False
    verification_date: datetime
    verified_by: str = ""
    notes: Optional[str] = None


# ============================================================================
# EXTERNAL SCANNER IMPORT SCHEMAS
# ============================================================================


class ExternalScannerImportRequest(BaseModel):
    """Schema for importing external scanner results"""

    scanner_name: str = Field(..., max_length=100)
    scan_format: str = Field(..., description="nessus, qualys, tenable, openvas, etc.")
    scan_data: str = Field(..., description="Raw scan data")
    scan_date: Optional[datetime] = None


class ScannerImportResult(BaseModel):
    """Schema for scanner import result"""

    import_id: str = ""
    scanner_name: str = ""
    vulnerabilities_imported: int = 0
    assets_updated: int = 0
    status: str = ""
    errors: list[str] = Field(default_factory=list)
    # Wave 4: what the import did. ``vulnerabilities_imported`` = links
    # created; ``assets_updated`` = distinct assets that received a finding.
    findings_read: int = 0
    links_created: int = 0
    links_updated: int = 0
    links_reopened: int = 0
    vulnerabilities_created: int = 0
    assets_created: int = 0
    assets_matched: int = 0
    skipped: list[dict] = Field(default_factory=list)
    skipped_count: int = 0
    assets_rescored: int = 0
