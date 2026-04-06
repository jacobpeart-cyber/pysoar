"""Supply Chain Security and SBOM Schemas

Pydantic schemas for API request/response validation across
SBOM, component, risk, and vendor management endpoints.
"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Base Schemas


class SoftwareComponentBase(BaseModel):
    """Base schema for software components"""

    name: str = Field(..., min_length=1, max_length=500)
    version: str = Field(..., min_length=1, max_length=100)
    vendor: Optional[str] = Field(None, max_length=255)
    package_type: str = Field(default="binary")
    license_type: Optional[str] = None
    license_spdx_id: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    checksum_sha256: Optional[str] = None
    source_url: Optional[str] = None
    is_direct_dependency: bool = True


class SoftwareComponentCreate(SoftwareComponentBase):
    """Schema for creating a software component"""

    parent_component_id: Optional[str] = None


class SoftwareComponentUpdate(BaseModel):
    """Schema for updating a software component"""

    name: Optional[str] = None
    version: Optional[str] = None
    license_type: Optional[str] = None
    license_spdx_id: Optional[str] = None


class SoftwareComponentResponse(SoftwareComponentBase, DBModel):
    """Schema for component response"""

    id: str
    organization_id: str
    parent_component_id: Optional[str] = None
    depth_level: int
    known_vulnerabilities_count: int = 0
    risk_score: float = 0.0
    last_scanned: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SBOMBase(BaseModel):
    """Base schema for SBOM"""

    name: str = Field(..., min_length=1, max_length=500)
    application_name: str = Field(..., min_length=1, max_length=500)
    application_version: str = Field(..., min_length=1, max_length=100)
    sbom_format: str = "spdx_json"
    spec_version: str = "2.3"
    created_by_tool: Optional[str] = None


class SBOMCreate(SBOMBase):
    """Schema for creating an SBOM"""

    sbom_content: Optional[str] = None


class SBOMUpdate(BaseModel):
    """Schema for updating an SBOM"""

    name: Optional[str] = None
    compliance_status: Optional[str] = None


class SBOMResponse(SBOMBase, DBModel):
    """Schema for SBOM response"""

    id: str
    organization_id: str
    components_count: int = 0
    total_dependencies: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0
    license_risk_score: float = 0.0
    vulnerability_risk_score: float = 0.0
    compliance_status: Optional[str] = None
    last_generated: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SBOMComponentBase(BaseModel):
    """Base schema for SBOM component"""

    relationship_type: str = "depends_on"


class SBOMComponentCreate(SBOMComponentBase):
    """Schema for creating SBOM component mapping"""

    sbom_id: str
    component_id: str


class SBOMComponentResponse(SBOMComponentBase, DBModel):
    """Schema for SBOM component response"""

    id: str
    sbom_id: str
    component_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SupplyChainRiskBase(BaseModel):
    """Base schema for supply chain risk"""

    component_id: str
    risk_type: str
    severity: str
    description: str
    evidence: Optional[dict[str, Any]] = None
    cve_ids: Optional[list[str]] = None
    remediation_advice: Optional[str] = None
    status: str = "open"


class SupplyChainRiskCreate(SupplyChainRiskBase):
    """Schema for creating supply chain risk"""

    pass


class SupplyChainRiskUpdate(BaseModel):
    """Schema for updating supply chain risk"""

    status: Optional[str] = None
    remediation_advice: Optional[str] = None
    remediation_date: Optional[datetime] = None


class SupplyChainRiskResponse(SupplyChainRiskBase, DBModel):
    """Schema for supply chain risk response"""

    id: str
    organization_id: str
    detected_date: datetime
    remediation_date: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VendorAssessmentBase(BaseModel):
    """Base schema for vendor assessment"""

    vendor_name: str = Field(..., min_length=1, max_length=500)
    vendor_url: Optional[str] = None
    assessment_type: str = "initial"
    security_score: float = Field(default=0.0, ge=0.0, le=100.0)
    data_handling_classification: str = "confidential"
    risk_tier: str = "medium"


class VendorAssessmentCreate(VendorAssessmentBase):
    """Schema for creating vendor assessment"""

    questionnaire_responses: Optional[dict[str, Any]] = None
    certifications: Optional[list[str]] = None
    third_party_subprocessors: Optional[list[str]] = None
    notes: Optional[str] = None


class VendorAssessmentUpdate(BaseModel):
    """Schema for updating vendor assessment"""

    security_score: Optional[float] = None
    risk_tier: Optional[str] = None
    certifications: Optional[list[str]] = None
    notes: Optional[str] = None


class VendorAssessmentResponse(VendorAssessmentBase, DBModel):
    """Schema for vendor assessment response"""

    id: str
    organization_id: str
    assessment_date: datetime
    last_incident_date: Optional[datetime] = None
    incident_count: int = 0
    contract_expiry: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# List Response Schemas


class SBOMListResponse(BaseModel):
    """List response for SBOMs"""

    items: list[SBOMResponse]
    total: int
    page: int
    size: int
    pages: int


class SoftwareComponentListResponse(BaseModel):
    """List response for software components"""

    items: list[SoftwareComponentResponse]
    total: int
    page: int
    size: int
    pages: int


class SupplyChainRiskListResponse(BaseModel):
    """List response for supply chain risks"""

    items: list[SupplyChainRiskResponse]
    total: int
    page: int
    size: int
    pages: int


class VendorAssessmentListResponse(BaseModel):
    """List response for vendor assessments"""

    items: list[VendorAssessmentResponse]
    total: int
    page: int
    size: int
    pages: int


# Specialized Request/Response Schemas


class SBOMImportRequest(BaseModel):
    """Request for importing SBOM"""

    sbom_content: str = Field(..., min_length=1)
    sbom_format: str = Field(default="spdx_json")
    application_name: Optional[str] = None


class SBOMExportRequest(BaseModel):
    """Request for exporting SBOM"""

    export_format: str = Field(default="spdx_json")
    include_vulnerabilities: bool = True
    include_risks: bool = True


class ComponentDependencyTree(BaseModel):
    """Component with dependency tree"""

    component: SoftwareComponentResponse
    dependencies: list["ComponentDependencyTree"] = []


ComponentDependencyTree.model_rebuild()


class ComponentVulnerabilityLookup(BaseModel):
    """Component with vulnerability information"""

    component: SoftwareComponentResponse
    cves: list[str] = []
    vulnerability_count: int = 0
    highest_severity: Optional[str] = None


class SBOMComparisonRequest(BaseModel):
    """Request for comparing SBOM versions"""

    sbom_id_1: str
    sbom_id_2: str


class SBOMComparisonResponse(BaseModel):
    """Response for SBOM comparison"""

    sbom_1: SBOMResponse
    sbom_2: SBOMResponse
    components_added: list[SoftwareComponentResponse] = []
    components_removed: list[SoftwareComponentResponse] = []
    components_updated: list[dict[str, Any]] = []
    risk_score_change: float = 0.0


class RiskAssessmentResult(BaseModel):
    """Risk assessment result for component"""

    component_id: str
    component_name: str
    risk_score: float
    risk_factors: list[str] = []
    known_vulnerabilities: int = 0
    outdated: bool = False
    license_risk: float = 0.0
    maintainer_risk: float = 0.0
    recommendations: list[str] = []


class SupplyChainRiskReport(BaseModel):
    """Supply chain risk report"""

    report_generated: datetime
    total_components: int
    critical_risks: int
    high_risks: int
    medium_risks: int
    average_risk_score: float
    recommendations: list[str]


class VendorRiskReport(BaseModel):
    """Vendor risk report"""

    report_generated: datetime
    total_vendors: int
    critical_risk_vendors: int
    high_risk_vendors: int
    average_vendor_score: float


class ComplianceValidationResult(BaseModel):
    """SBOM compliance validation result"""

    compliant: bool
    required_elements: dict[str, bool]
    missing_elements: list[str]
    compliance_percentage: float
    recommendations: list[str]


class CISAComplianceReport(BaseModel):
    """CISA compliance report"""

    overall_compliant: bool
    cisa_compliance: ComplianceValidationResult
    ntia_compliance: ComplianceValidationResult
    recommendations: list[str]


class DashboardOverview(BaseModel):
    """Supply chain dashboard overview"""

    total_sboms: int
    total_components: int
    components_with_vulnerabilities: int
    critical_risks_open: int
    high_risks_open: int
    vendors_assessed: int
    critical_risk_vendors: int
    average_component_risk: float
    average_vendor_score: float


class RiskyComponentSummary(BaseModel):
    """Summary of risky components"""

    component_id: str
    component_name: str
    version: str
    risk_score: float
    vulnerability_count: int
    risk_type: str
    severity: str


class VendorScoreSummary(BaseModel):
    """Summary of vendor scores"""

    vendor_id: str
    vendor_name: str
    risk_score: float
    risk_tier: str
    last_assessment: datetime
    incident_count: int


class LicenseBreakdown(BaseModel):
    """License distribution across components"""

    total_components: int
    licenses: dict[str, int]
    gpl_components: int
    proprietary_components: int
    permissive_components: int
    conflicts: list[str]
    compliance_status: str


class ComplianceAudit(BaseModel):
    """Compliance audit record"""

    audit_date: datetime
    sbom_id: str
    cisa_compliant: bool
    ntia_compliant: bool
    license_compliant: bool
    recommendations: list[str]
    auditor: str
