"""Vulnerability management schemas for API validation"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Vulnerability Schemas
class VulnerabilityBase(BaseModel):
    """Base vulnerability schema"""

    cve_id: str = Field(..., min_length=1, max_length=50)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_v3_vector: Optional[str] = None
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    severity: str = "medium"
    vulnerability_type: Optional[str] = None
    cwe_id: Optional[str] = None
    affected_software: Optional[str] = None
    affected_versions: Optional[list[str]] = None
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    exploit_available: bool = False
    exploit_maturity: str = "unproven"
    patch_available: bool = False
    patch_url: Optional[str] = None
    references: Optional[list[dict[str, str]]] = None
    kev_listed: bool = False


class VulnerabilityCreate(VulnerabilityBase):
    """Schema for creating a vulnerability"""

    organization_id: str
    mitre_technique_ids: Optional[list[str]] = None


class VulnerabilityUpdate(BaseModel):
    """Schema for updating a vulnerability"""

    title: Optional[str] = None
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    severity: Optional[str] = None
    exploit_maturity: Optional[str] = None
    patch_available: Optional[bool] = None
    patch_url: Optional[str] = None
    kev_listed: Optional[bool] = None


class VulnerabilityResponse(DBModel):
    """Schema for vulnerability response"""

    id: str
    organization_id: str
    mitre_technique_ids: Optional[list[str]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Vulnerability Instance Schemas
class VulnerabilityInstanceBase(BaseModel):
    """Base vulnerability instance schema"""

    vulnerability_id: str
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    asset_ip: Optional[str] = None
    asset_type: Optional[str] = None
    discovered_by: str = "manual"
    scan_id: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    status: str = "open"
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    exploitability_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    business_criticality: Optional[int] = None
    assigned_to: Optional[str] = None
    remediation_deadline: Optional[str] = None
    sla_status: str = "within_sla"


class VulnerabilityInstanceCreate(VulnerabilityInstanceBase):
    """Schema for creating a vulnerability instance"""

    organization_id: str


class VulnerabilityInstanceUpdate(BaseModel):
    """Schema for updating a vulnerability instance"""

    status: Optional[str] = None
    assigned_to: Optional[str] = None
    remediation_deadline: Optional[str] = None
    sla_status: Optional[str] = None
    risk_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    business_criticality: Optional[int] = None


class VulnerabilityInstanceResponse(DBModel):
    """Schema for vulnerability instance response"""

    id: str
    organization_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Scan Profile Schemas
class ScanProfileBase(BaseModel):
    """Base scan profile schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scanner_type: str
    target_ranges: Optional[list[str]] = None
    scan_policy: Optional[str] = None
    credentials_encrypted: bool = True
    schedule_cron: Optional[str] = None
    enabled: bool = True


class ScanProfileCreate(ScanProfileBase):
    """Schema for creating a scan profile"""

    organization_id: str


class ScanProfileUpdate(BaseModel):
    """Schema for updating a scan profile"""

    name: Optional[str] = None
    description: Optional[str] = None
    scanner_type: Optional[str] = None
    target_ranges: Optional[list[str]] = None
    scan_policy: Optional[str] = None
    schedule_cron: Optional[str] = None
    enabled: Optional[bool] = None


class ScanProfileResponse(DBModel):
    """Schema for scan profile response"""

    id: str
    organization_id: str
    last_scan_date: Optional[str] = None
    next_scan_date: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Patch Operation Schemas
class PatchOperationBase(BaseModel):
    """Base patch operation schema"""

    vulnerability_instance_id: str
    patch_type: str = "os_patch"
    patch_id: Optional[str] = None
    patch_name: Optional[str] = None
    deployment_status: str = "pending"
    deployment_date: Optional[str] = None
    verification_date: Optional[str] = None
    rollback_available: bool = True
    change_ticket_id: Optional[str] = None
    approved_by: Optional[str] = None
    deployment_notes: Optional[str] = None


class PatchOperationCreate(PatchOperationBase):
    """Schema for creating a patch operation"""

    organization_id: str


class PatchOperationUpdate(BaseModel):
    """Schema for updating a patch operation"""

    deployment_status: Optional[str] = None
    deployment_date: Optional[str] = None
    verification_date: Optional[str] = None
    approved_by: Optional[str] = None
    deployment_notes: Optional[str] = None


class PatchOperationResponse(DBModel):
    """Schema for patch operation response"""

    id: str
    organization_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Vulnerability Exception Schemas
class VulnerabilityExceptionBase(BaseModel):
    """Base vulnerability exception schema"""

    vulnerability_instance_id: str
    exception_type: str
    justification: str = Field(..., min_length=10)
    approved_by: Optional[str] = None
    approval_date: Optional[str] = None
    expiry_date: Optional[str] = None
    review_date: Optional[str] = None
    compensating_control_description: Optional[str] = None
    risk_acceptance_level: Optional[str] = None


class VulnerabilityExceptionCreate(VulnerabilityExceptionBase):
    """Schema for creating a vulnerability exception"""

    organization_id: str


class VulnerabilityExceptionUpdate(BaseModel):
    """Schema for updating a vulnerability exception"""

    exception_type: Optional[str] = None
    justification: Optional[str] = None
    approved_by: Optional[str] = None
    approval_date: Optional[str] = None
    expiry_date: Optional[str] = None
    compensating_control_description: Optional[str] = None


class VulnerabilityExceptionResponse(DBModel):
    """Schema for vulnerability exception response"""

    id: str
    organization_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Paginated Response Schemas
class VulnerabilityListResponse(BaseModel):
    """Paginated vulnerability list response"""

    items: list[VulnerabilityResponse]
    total: int
    page: int
    size: int
    pages: int


class VulnerabilityInstanceListResponse(BaseModel):
    """Paginated vulnerability instance list response"""

    items: list[VulnerabilityInstanceResponse]
    total: int
    page: int
    size: int
    pages: int


class ScanProfileListResponse(BaseModel):
    """Paginated scan profile list response"""

    items: list[ScanProfileResponse]
    total: int
    page: int
    size: int
    pages: int


class PatchOperationListResponse(BaseModel):
    """Paginated patch operation list response"""

    items: list[PatchOperationResponse]
    total: int
    page: int
    size: int
    pages: int


# Dashboard and Reporting Schemas
class RiskMatrix(BaseModel):
    """Risk matrix data"""

    severity_x_exploitability: dict[str, dict[str, int]]


class SLAComplianceMetrics(BaseModel):
    """SLA compliance metrics"""

    total: int
    within_sla: int
    approaching: int
    breached: int
    compliance_percentage: float


class PatchComplianceMetrics(BaseModel):
    """Patch deployment compliance metrics"""

    total_vulnerabilities: int
    patched: int
    compliance_percentage: float


class VulnerabilityTrends(BaseModel):
    """Vulnerability trend data"""

    period_days: int
    new_discovered: int
    closed: int
    net_change: int


class VulnerabilityAging(BaseModel):
    """Vulnerability aging analysis"""

    days_0_30: int = Field(alias="0-30_days")
    days_31_60: int = Field(alias="31-60_days")
    days_61_90: int = Field(alias="61-90_days")
    days_90_plus: int = Field(alias="90+_days")


class ExecutiveReport(BaseModel):
    """Executive summary report"""

    total_vulnerabilities: int
    open_vulnerabilities: int
    critical_count: int
    high_count: int
    mttr_days: float
    sla_compliance: SLAComplianceMetrics
    aging: dict[str, int]


class KEVComplianceReport(BaseModel):
    """CISA BOD 22-01 compliance report"""

    report_date: str
    mandate: str = "BOD 22-01"
    deadline_days: int = 15
    total_kev_tracked: int
    kev_patched: int
    kev_compliant: int
    kev_non_compliant: int
    compliance_percentage: float


class DashboardMetrics(BaseModel):
    """Overall dashboard metrics"""

    risk_matrix: RiskMatrix
    sla_compliance: SLAComplianceMetrics
    patch_compliance: PatchComplianceMetrics
    trends_30_days: VulnerabilityTrends
    aging: VulnerabilityAging
    top_vulnerabilities: list[VulnerabilityInstanceResponse]
    kev_compliance: KEVComplianceReport


class BulkAction(BaseModel):
    """Bulk action request"""

    instance_ids: list[str]
    action: str  # update_status, assign, set_deadline, etc.
    value: Optional[Any] = None


class ScanImportRequest(BaseModel):
    """Scan import request"""

    scan_profile_id: str
    scan_format: str  # nessus, qualys, openvas, tenable, trivy, grype
    scan_data: str
    notes: Optional[str] = None


class PatchPlanRequest(BaseModel):
    """Patch deployment plan request"""

    vulnerability_instance_ids: list[str]
    maintenance_window: Optional[str] = None
    priority: Optional[str] = None
    notes: Optional[str] = None


class PatchDeploymentRequest(BaseModel):
    """Patch deployment request"""

    patch_operation_id: str
    deployment_date: str
    change_ticket_id: Optional[str] = None
    notes: Optional[str] = None


class PatchVerificationRequest(BaseModel):
    """Patch verification request"""

    patch_operation_id: str
    verification_results: dict[str, Any]
    verification_date: Optional[str] = None


class PatchRollbackRequest(BaseModel):
    """Patch rollback request"""

    patch_operation_id: str
    reason: str = Field(..., min_length=10)
    approved_by: Optional[str] = None
