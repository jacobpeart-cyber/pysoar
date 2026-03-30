"""
ITDR Schemas for API request/response validation

Pydantic schemas for identity profiles, threats, credentials,
access anomalies, and privileged access events.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ============================================================================
# Identity Profile Schemas
# ============================================================================


class IdentityProfileBase(BaseModel):
    """Base identity profile schema"""

    user_id: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=1, max_length=255)
    email: str = Field(..., min_length=5, max_length=255)
    display_name: Optional[str] = Field(None, max_length=500)
    identity_provider: str = "active_directory"
    privilege_level: str = "standard"
    is_service_account: bool = False
    is_dormant: bool = False
    mfa_enabled: bool = False


class IdentityProfileCreate(IdentityProfileBase):
    """Schema for creating identity profile"""

    role_assignments: Optional[list[str]] = None
    group_memberships: Optional[list[str]] = None
    mfa_methods: Optional[list[str]] = None
    authentication_methods: Optional[list[str]] = None


class IdentityProfileUpdate(BaseModel):
    """Schema for updating identity profile"""

    display_name: Optional[str] = Field(None, max_length=500)
    privilege_level: Optional[str] = None
    is_dormant: Optional[bool] = None
    mfa_enabled: Optional[bool] = None
    role_assignments: Optional[list[str]] = None
    group_memberships: Optional[list[str]] = None
    mfa_methods: Optional[list[str]] = None


class IdentityProfileResponse(IdentityProfileBase):
    """Schema for identity profile response"""

    id: str
    organization_id: str
    risk_score: float = Field(0.0, ge=0.0, le=100.0)
    role_assignments: Optional[list[str]] = None
    group_memberships: Optional[list[str]] = None
    mfa_methods: Optional[list[str]] = None
    last_authentication: Optional[str] = None
    last_password_change: Optional[str] = None
    authentication_methods: Optional[list[str]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Identity Threat Schemas
# ============================================================================


class IdentityThreatBase(BaseModel):
    """Base identity threat schema"""

    threat_type: str
    severity: str = Field(..., regex="^(critical|high|medium|low)$")
    confidence_score: float = Field(0.0, ge=0.0, le=100.0)
    source_ip: Optional[str] = None
    source_location: Optional[str] = None
    target_resource: Optional[str] = None
    mitre_technique_id: Optional[str] = None


class IdentityThreatCreate(IdentityThreatBase):
    """Schema for creating identity threat"""

    identity_id: str
    evidence: Optional[dict[str, Any]] = None
    response_actions: Optional[list[dict[str, Any]]] = None


class IdentityThreatUpdate(BaseModel):
    """Schema for updating identity threat"""

    severity: Optional[str] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    status: Optional[str] = None
    response_actions: Optional[list[dict[str, Any]]] = None


class IdentityThreatResponse(IdentityThreatBase):
    """Schema for identity threat response"""

    id: str
    organization_id: str
    identity_id: str
    status: str
    evidence: Optional[dict[str, Any]] = None
    response_actions: Optional[list[dict[str, Any]]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ThreatInvestigationRequest(BaseModel):
    """Schema for threat investigation action"""

    threat_id: str
    investigation_notes: str
    new_status: str = "investigating"
    evidence_summary: Optional[dict[str, Any]] = None


class ThreatResponseAction(BaseModel):
    """Schema for threat response action"""

    threat_id: str
    action_type: str
    action_details: dict[str, Any]
    executed_by: str


# ============================================================================
# Credential Exposure Schemas
# ============================================================================


class CredentialExposureBase(BaseModel):
    """Base credential exposure schema"""

    exposure_source: str
    credential_type: str
    exposure_date: Optional[str] = None
    discovery_date: Optional[str] = None
    breach_name: Optional[str] = None
    is_remediated: bool = False
    remediation_action: Optional[str] = None


class CredentialExposureCreate(CredentialExposureBase):
    """Schema for creating credential exposure"""

    identity_id: str


class CredentialExposureUpdate(BaseModel):
    """Schema for updating credential exposure"""

    is_remediated: Optional[bool] = None
    remediation_action: Optional[str] = None
    remediation_date: Optional[str] = None


class CredentialExposureResponse(CredentialExposureBase):
    """Schema for credential exposure response"""

    id: str
    organization_id: str
    identity_id: str
    remediation_date: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CredentialRemediationRequest(BaseModel):
    """Schema for credential remediation request"""

    exposure_ids: list[str]
    remediation_type: str = Field(..., regex="^(password_reset|token_revoke|key_rotation)$")
    require_approval: bool = True
    justification: str


class PasswordStrengthAssessment(BaseModel):
    """Schema for password strength assessment"""

    password: str
    score: int = Field(0, ge=0, le=100)
    strength: str
    issues: list[str]
    compliant: bool


# ============================================================================
# Access Anomaly Schemas
# ============================================================================


class AccessAnomalyBase(BaseModel):
    """Base access anomaly schema"""

    anomaly_type: str
    deviation_score: float = Field(0.0, ge=0.0, le=1.0)
    is_reviewed: bool = False
    reviewer_notes: Optional[str] = None


class AccessAnomalyCreate(AccessAnomalyBase):
    """Schema for creating access anomaly"""

    identity_id: str
    baseline_data: Optional[dict[str, Any]] = None
    observed_data: Optional[dict[str, Any]] = None


class AccessAnomalyUpdate(BaseModel):
    """Schema for updating access anomaly"""

    is_reviewed: Optional[bool] = None
    reviewer_notes: Optional[str] = None


class AccessAnomalyResponse(AccessAnomalyBase):
    """Schema for access anomaly response"""

    id: str
    organization_id: str
    identity_id: str
    baseline_data: Optional[dict[str, Any]] = None
    observed_data: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AnomalyReviewRequest(BaseModel):
    """Schema for anomaly review action"""

    anomaly_id: str
    is_legitimate: bool
    reviewer_notes: str


class IdentityBaseline(BaseModel):
    """Schema for identity baseline"""

    identity_id: str
    normal_hours: list[int]
    normal_locations: list[str]
    normal_resources: list[str]
    normal_devices: list[str]
    analysis_window_days: int


# ============================================================================
# Privileged Access Schemas
# ============================================================================


class PrivilegedAccessEventBase(BaseModel):
    """Base privileged access event schema"""

    event_type: str
    target_resource: Optional[str] = None
    justification: Optional[str] = None
    was_revoked: bool = False
    revocation_reason: Optional[str] = None


class PrivilegedAccessEventCreate(PrivilegedAccessEventBase):
    """Schema for creating privileged access event"""

    identity_id: str
    approved_by: Optional[str] = None
    expiry_timestamp: Optional[str] = None


class PrivilegedAccessEventUpdate(BaseModel):
    """Schema for updating privileged access event"""

    justification: Optional[str] = None
    was_revoked: Optional[bool] = None
    revocation_reason: Optional[str] = None


class PrivilegedAccessEventResponse(PrivilegedAccessEventBase):
    """Schema for privileged access event response"""

    id: str
    organization_id: str
    identity_id: str
    approved_by: Optional[str] = None
    approval_timestamp: Optional[str] = None
    expiry_timestamp: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ElevationRequest(BaseModel):
    """Schema for privilege elevation request"""

    identity_id: str
    target_resource: str
    justification: str
    required_privilege_level: str
    duration_minutes: int = Field(default=60, ge=15, le=480)
    require_mfa: bool = True


class ElevationApprovalRequest(BaseModel):
    """Schema for elevation approval"""

    request_id: str
    approved: bool
    approver_notes: Optional[str] = None
    approval_duration_minutes: Optional[int] = Field(None, ge=15, le=480)


class PrivilegedAccessAuditRequest(BaseModel):
    """Schema for privileged access audit request"""

    organization_id: str
    audit_scope: str = Field(default="all", regex="^(all|elevation_requests|jit_access)$")
    include_service_accounts: bool = False
    start_date: Optional[str] = None
    end_date: Optional[str] = None


# ============================================================================
# ITDR Dashboard and Reporting Schemas
# ============================================================================


class IdentityRiskProfile(BaseModel):
    """Schema for identity risk profile"""

    identity_id: str
    username: str
    current_risk_score: float = Field(0.0, ge=0.0, le=100.0)
    threat_count: int
    critical_threats: int
    anomalies_count: int
    credential_exposures: int
    privilege_level: str
    last_update: datetime


class ITDRDashboardMetrics(BaseModel):
    """Schema for ITDR dashboard metrics"""

    total_identities: int
    identities_at_risk: int
    critical_threats_active: int
    high_threats_active: int
    credential_exposures_active: int
    anomalies_pending_review: int
    service_accounts_over_privileged: int
    dormant_accounts: int
    jit_access_active: int
    last_scan_timestamp: datetime
    overall_risk_score: float = Field(0.0, ge=0.0, le=100.0)


class ITDRRiskOverview(BaseModel):
    """Schema for ITDR risk overview"""

    summary: str
    critical_findings: list[str]
    risk_trends: dict[str, Any]
    recommendations: list[str]
    compliance_status: dict[str, Any]


class ThreatDetectionReport(BaseModel):
    """Schema for threat detection report"""

    report_type: str
    scan_timestamp: datetime
    total_threats: int
    threat_breakdown: dict[str, int]
    top_threat_types: list[dict[str, Any]]
    affected_identities: int
    critical_threats: list[IdentityThreatResponse]


class CredentialRiskReport(BaseModel):
    """Schema for credential risk report"""

    report_type: str
    timestamp: datetime
    total_issues: int
    critical_issues: int
    risk_score: float
    exposure_count: int
    weak_password_count: int
    shared_credential_count: int
    stale_credential_count: int
    recommendations: list[str]


class PAMComplianceReport(BaseModel):
    """Schema for PAM compliance report"""

    report_type: str
    timestamp: datetime
    jit_grants_total: int
    jit_grants_active: int
    elevation_requests_total: int
    elevation_requests_approved: int
    approval_rate_percent: float
    audit_violations: int
    compliance_score: float = Field(0.0, ge=0.0, le=100.0)
    over_privileged_identities: int


# ============================================================================
# List Response Schemas
# ============================================================================


class IdentityProfileListResponse(BaseModel):
    """Schema for paginated identity profile list"""

    total: int
    page: int
    size: int
    pages: int
    items: list[IdentityProfileResponse]


class IdentityThreatListResponse(BaseModel):
    """Schema for paginated identity threat list"""

    total: int
    page: int
    size: int
    pages: int
    items: list[IdentityThreatResponse]


class CredentialExposureListResponse(BaseModel):
    """Schema for paginated credential exposure list"""

    total: int
    page: int
    size: int
    pages: int
    items: list[CredentialExposureResponse]


class AccessAnomalyListResponse(BaseModel):
    """Schema for paginated access anomaly list"""

    total: int
    page: int
    size: int
    pages: int
    items: list[AccessAnomalyResponse]


class PrivilegedAccessEventListResponse(BaseModel):
    """Schema for paginated privileged access event list"""

    total: int
    page: int
    size: int
    pages: int
    items: list[PrivilegedAccessEventResponse]
