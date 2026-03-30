"""API Security Governance schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional, Dict, List

from pydantic import BaseModel, Field


# ============================================================================
# API Endpoint Inventory Schemas
# ============================================================================


class APIEndpointInventoryBase(BaseModel):
    """Base API endpoint inventory schema"""

    service_name: str = Field(..., min_length=1, max_length=255)
    base_url: str = Field(..., min_length=1, max_length=512)
    path: str = Field(..., min_length=1, max_length=512)
    method: str = Field(..., pattern="^(GET|POST|PUT|DELETE|PATCH)$")
    api_version: Optional[str] = Field(None, max_length=50)
    authentication_type: str = Field(default="none")
    authorization_model: Optional[str] = Field(None, max_length=255)
    data_classification: str = Field(default="internal")
    is_public: bool = False
    is_documented: bool = False
    is_shadow: bool = False
    is_deprecated: bool = False
    rate_limit_configured: bool = False
    input_validation_enabled: bool = False
    response_encryption: bool = False
    owner_team: Optional[str] = Field(None, max_length=255)
    openapi_spec_url: Optional[str] = Field(None, max_length=512)


class APIEndpointInventoryCreate(APIEndpointInventoryBase):
    """Schema for creating an API endpoint"""

    pass


class APIEndpointInventoryUpdate(BaseModel):
    """Schema for updating an API endpoint"""

    service_name: Optional[str] = Field(None, min_length=1, max_length=255)
    base_url: Optional[str] = Field(None, min_length=1, max_length=512)
    path: Optional[str] = Field(None, min_length=1, max_length=512)
    authentication_type: Optional[str] = None
    authorization_model: Optional[str] = Field(None, max_length=255)
    data_classification: Optional[str] = None
    is_documented: Optional[bool] = None
    is_shadow: Optional[bool] = None
    is_deprecated: Optional[bool] = None
    rate_limit_configured: Optional[bool] = None
    input_validation_enabled: Optional[bool] = None
    response_encryption: Optional[bool] = None
    owner_team: Optional[str] = Field(None, max_length=255)


class APIEndpointInventoryResponse(APIEndpointInventoryBase):
    """Schema for API endpoint response"""

    id: str
    request_count_24h: int
    error_rate: float
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# API Vulnerability Schemas
# ============================================================================


class APIVulnerabilityBase(BaseModel):
    """Base API vulnerability schema"""

    endpoint_id: str
    vulnerability_type: str
    severity: str = Field(..., pattern="^(critical|high|medium|low)$")
    description: str = Field(..., min_length=1)
    evidence: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    status: str = Field(default="open", pattern="^(open|remediated|accepted|false_positive)$")
    cwe_id: Optional[str] = Field(None, max_length=50)
    detected_by: Optional[str] = Field(None, max_length=255)


class APIVulnerabilityCreate(APIVulnerabilityBase):
    """Schema for creating a vulnerability"""

    pass


class APIVulnerabilityUpdate(BaseModel):
    """Schema for updating a vulnerability"""

    status: Optional[str] = Field(None, pattern="^(open|remediated|accepted|false_positive)$")
    remediation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


class APIVulnerabilityResponse(APIVulnerabilityBase):
    """Schema for vulnerability response"""

    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# API Security Policy Schemas
# ============================================================================


class APISecurityPolicyBase(BaseModel):
    """Base API security policy schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    policy_type: str
    rules: Optional[Dict[str, Any]] = None
    enforcement_level: str = Field(default="enforce", pattern="^(enforce|monitor|disabled)$")
    applies_to: Optional[Dict[str, Any]] = None


class APISecurityPolicyCreate(APISecurityPolicyBase):
    """Schema for creating a policy"""

    pass


class APISecurityPolicyUpdate(BaseModel):
    """Schema for updating a policy"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    policy_type: Optional[str] = None
    rules: Optional[Dict[str, Any]] = None
    enforcement_level: Optional[str] = Field(None, pattern="^(enforce|monitor|disabled)$")
    applies_to: Optional[Dict[str, Any]] = None


class APISecurityPolicyResponse(APISecurityPolicyBase):
    """Schema for policy response"""

    id: str
    violations_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# API Anomaly Detection Schemas
# ============================================================================


class APIAnomalyDetectionBase(BaseModel):
    """Base API anomaly detection schema"""

    endpoint_id: str
    anomaly_type: str
    baseline_value: float
    observed_value: float
    deviation_percentage: float
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    source_ips: Optional[List[str]] = None
    sample_requests: Optional[List[Dict[str, Any]]] = None
    status: str = Field(default="open", pattern="^(open|investigating|resolved|false_positive)$")


class APIAnomalyDetectionCreate(APIAnomalyDetectionBase):
    """Schema for creating an anomaly detection record"""

    pass


class APIAnomalyDetectionUpdate(BaseModel):
    """Schema for updating an anomaly detection record"""

    status: Optional[str] = Field(None, pattern="^(open|investigating|resolved|false_positive)$")
    severity: Optional[str] = Field(None, pattern="^(critical|high|medium|low|info)$")


class APIAnomalyDetectionResponse(APIAnomalyDetectionBase):
    """Schema for anomaly detection response"""

    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# API Compliance Check Schemas
# ============================================================================


class APIComplianceCheckBase(BaseModel):
    """Base API compliance check schema"""

    endpoint_id: str
    check_type: str
    passed: bool
    details: Optional[Dict[str, Any]] = None
    remediation_steps: Optional[str] = None


class APIComplianceCheckCreate(APIComplianceCheckBase):
    """Schema for creating a compliance check"""

    pass


class APIComplianceCheckUpdate(BaseModel):
    """Schema for updating a compliance check"""

    passed: Optional[bool] = None
    details: Optional[Dict[str, Any]] = None
    remediation_steps: Optional[str] = None


class APIComplianceCheckResponse(APIComplianceCheckBase):
    """Schema for compliance check response"""

    id: str
    last_checked: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# List Response Schemas
# ============================================================================


class APIEndpointInventoryListResponse(BaseModel):
    """Schema for paginated API endpoint list"""

    items: List[APIEndpointInventoryResponse]
    total: int
    page: int
    size: int
    pages: int


class APIVulnerabilityListResponse(BaseModel):
    """Schema for paginated vulnerability list"""

    items: List[APIVulnerabilityResponse]
    total: int
    page: int
    size: int
    pages: int


class APISecurityPolicyListResponse(BaseModel):
    """Schema for paginated policy list"""

    items: List[APISecurityPolicyResponse]
    total: int
    page: int
    size: int
    pages: int


class APIAnomalyDetectionListResponse(BaseModel):
    """Schema for paginated anomaly detection list"""

    items: List[APIAnomalyDetectionResponse]
    total: int
    page: int
    size: int
    pages: int


class APIComplianceCheckListResponse(BaseModel):
    """Schema for paginated compliance check list"""

    items: List[APIComplianceCheckResponse]
    total: int
    page: int
    size: int
    pages: int


# ============================================================================
# Dashboard & Report Schemas
# ============================================================================


class APISummaryStats(BaseModel):
    """Summary statistics for API security"""

    total_endpoints: int
    documented_endpoints: int
    shadow_apis: int
    zombie_apis: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    policy_violations: int
    compliance_pass_rate: float


class APISecurityDashboardResponse(BaseModel):
    """API security dashboard data"""

    stats: APISummaryStats
    recent_vulnerabilities: List[APIVulnerabilityResponse]
    critical_anomalies: List[APIAnomalyDetectionResponse]
    failed_compliance_checks: List[APIComplianceCheckResponse]
    top_vulnerable_endpoints: List[APIEndpointInventoryResponse]


class APIDiscoveryResultsResponse(BaseModel):
    """API discovery results"""

    new_endpoints_count: int
    shadow_apis_count: int
    zombie_apis_count: int
    total_discovered: int
    discovery_summary: Optional[Dict[str, Any]] = None


class APIScanResultResponse(BaseModel):
    """API security scan results"""

    endpoint_id: str
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_timestamp: datetime
    remediation_guidance: Optional[str] = None


class APIComplianceReportResponse(BaseModel):
    """API compliance report"""

    total_endpoints: int
    endpoints_checked: int
    checks_passed: int
    checks_failed: int
    pass_rate: float
    by_check_type: Dict[str, Dict[str, int]]
    report_date: datetime


# ============================================================================
# Bulk Action Schemas
# ============================================================================


class APIVulnerabilityBulkUpdate(BaseModel):
    """Bulk update for vulnerabilities"""

    vulnerability_ids: List[str]
    status: Optional[str] = Field(None, pattern="^(open|remediated|accepted|false_positive)$")
    remediation: Optional[str] = None


class APIEndpointBulkUpdate(BaseModel):
    """Bulk update for endpoints"""

    endpoint_ids: List[str]
    is_documented: Optional[bool] = None
    is_deprecated: Optional[bool] = None
    rate_limit_configured: Optional[bool] = None
    input_validation_enabled: Optional[bool] = None


# ============================================================================
# Filter & Search Schemas
# ============================================================================


class APISecurityFilterParams(BaseModel):
    """Filter parameters for API security searches"""

    service_name: Optional[str] = None
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None
    authentication_type: Optional[str] = None
    is_shadow: Optional[bool] = None
    is_documented: Optional[bool] = None
    is_deprecated: Optional[bool] = None
    data_classification: Optional[str] = None
    anomaly_type: Optional[str] = None
    policy_type: Optional[str] = None
    compliance_status: Optional[str] = None
