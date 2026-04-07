"""
Data Loss Prevention Schemas

Pydantic schemas for request/response validation across DLP endpoints.
"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Base Schemas

class DLPPolicyBase(BaseModel):
    """Base DLP policy schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    policy_type: str = Field(default="custom_pattern", max_length=50)
    severity: str = Field(default="medium", max_length=20)
    enabled: bool = True
    data_patterns: Optional[list[str]] = None
    file_types_monitored: Optional[list[str]] = None
    channels_monitored: Optional[list[str]] = None
    response_actions: Optional[list[str]] = None
    exceptions: Optional[list[dict[str, Any]]] = None


class DLPPolicyCreate(DLPPolicyBase):
    """Schema for creating a DLP policy"""

    pass


class DLPPolicyUpdate(BaseModel):
    """Schema for updating a DLP policy"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    policy_type: Optional[str] = Field(None, max_length=50)
    severity: Optional[str] = Field(None, max_length=20)
    enabled: Optional[bool] = None
    data_patterns: Optional[list[str]] = None
    file_types_monitored: Optional[list[str]] = None
    channels_monitored: Optional[list[str]] = None
    response_actions: Optional[list[str]] = None
    exceptions: Optional[list[dict[str, Any]]] = None


class DLPPolicyResponse(DLPPolicyBase, DBModel):
    """Schema for DLP policy response"""

    id: str
    organization_id: str
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DLPPolicyListResponse(BaseModel):
    """Schema for paginated policy list"""

    items: list[DLPPolicyResponse]
    total: int
    page: int
    size: int
    pages: int


class DLPPolicyTestRequest(BaseModel):
    """Schema for testing a policy against sample data"""

    sample_content: str = Field(..., min_length=1)
    sample_metadata: Optional[dict[str, Any]] = None


class DLPPolicyTestResponse(BaseModel):
    """Schema for policy test results"""

    policy_id: str
    test_passed: bool
    violations_detected: int
    matched_patterns: list[str]
    sample_result: dict[str, Any]
    timestamp: Optional[datetime] = None


# Violation Schemas

class DLPViolationBase(BaseModel):
    """Base DLP violation schema"""

    policy_id: str
    violation_type: str = Field(default="unauthorized_transfer", max_length=50)
    severity: str = Field(default="medium", max_length=20)
    source_user: Optional[str] = Field(None, max_length=255)
    source_device: Optional[str] = Field(None, max_length=255)
    source_application: Optional[str] = Field(None, max_length=255)
    destination: Optional[str] = Field(None, max_length=255)
    data_classification: Optional[str] = Field(None, max_length=50)
    sensitive_data_types: Optional[list[str]] = None
    file_name: Optional[str] = Field(None, max_length=255)
    file_hash: Optional[str] = Field(None, max_length=128)
    data_volume_bytes: Optional[int] = None
    action_taken: str = Field(default="logged", max_length=50)
    status: str = Field(default="new", max_length=50)
    justification: Optional[str] = None
    reviewed_by: Optional[str] = Field(None, max_length=255)


class DLPViolationCreate(DLPViolationBase):
    """Schema for creating a violation"""

    pass


class DLPViolationUpdate(BaseModel):
    """Schema for updating violation investigation"""

    status: Optional[str] = Field(None, max_length=50)
    justification: Optional[str] = None
    reviewed_by: Optional[str] = Field(None, max_length=255)
    action_taken: Optional[str] = Field(None, max_length=50)


class DLPViolationResponse(DLPViolationBase, DBModel):
    """Schema for violation response"""

    id: str
    organization_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DLPViolationListResponse(BaseModel):
    """Schema for paginated violation list"""

    items: list[DLPViolationResponse]
    total: int
    page: int
    size: int
    pages: int


class DLPViolationResolveRequest(BaseModel):
    """Schema for resolving a violation"""

    status: str = Field(..., max_length=50)
    justification: str = Field(..., min_length=1)
    reviewed_by: Optional[str] = None


class DLPViolationBulkActionRequest(BaseModel):
    """Schema for bulk actions on violations"""

    violation_ids: list[str]
    action: str = Field(..., max_length=50)
    justification: Optional[str] = None


class DLPViolationBulkActionResponse(BaseModel):
    """Schema for bulk action results"""

    successful: int
    failed: int
    total: int
    failed_ids: list[str] = []


# Data Classification Schemas

class DataClassificationBase(BaseModel):
    """Base data classification schema"""

    name: str = Field(..., min_length=1, max_length=255)
    classification_level: str = Field(default="internal", max_length=50)
    description: Optional[str] = None
    handling_rules: Optional[dict[str, Any]] = None
    retention_days: Optional[int] = Field(None, ge=0)
    encryption_required: bool = False
    dlp_policies: Optional[list[str]] = None
    auto_classification_rules: Optional[dict[str, Any]] = None
    color_code: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")


class DataClassificationCreate(DataClassificationBase):
    """Schema for creating a classification"""

    pass


class DataClassificationUpdate(BaseModel):
    """Schema for updating a classification"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    classification_level: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    handling_rules: Optional[dict[str, Any]] = None
    retention_days: Optional[int] = Field(None, ge=0)
    encryption_required: Optional[bool] = None
    dlp_policies: Optional[list[str]] = None
    auto_classification_rules: Optional[dict[str, Any]] = None
    color_code: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")


class DataClassificationResponse(DataClassificationBase, DBModel):
    """Schema for classification response"""

    id: str
    organization_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataClassificationListResponse(BaseModel):
    """Schema for paginated classification list"""

    items: list[DataClassificationResponse]
    total: int
    page: int
    size: int
    pages: int


class DocumentClassificationRequest(BaseModel):
    """Schema for classifying a document"""

    content: str = Field(..., min_length=1)
    file_name: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class DocumentClassificationResponse(BaseModel):
    """Schema for document classification result"""

    classification_level: str
    confidence: float = Field(ge=0.0, le=1.0)
    indicators: list[str]
    content_based: dict[str, Any]
    metadata_based: dict[str, Any]
    timestamp: Optional[datetime] = None


class DataHandlingRequirementsResponse(BaseModel):
    """Schema for data handling requirements"""

    classification_level: str
    encryption: bool
    access_control: str
    retention_days: int
    sharing_restrictions: str


# Data Discovery Schemas

class SensitiveDataDiscoveryBase(BaseModel):
    """Base discovery scan schema"""

    scan_type: str = Field(default="endpoint", max_length=50)
    target: str = Field(..., max_length=255)
    status: str = Field(default="pending", max_length=50)


class DiscoveryScanTriggerRequest(BaseModel):
    """Schema for triggering a discovery scan"""

    scan_type: str = Field(..., max_length=50)
    target: str = Field(..., max_length=255)
    schedule: Optional[str] = None


class SensitiveDataDiscoveryResponse(SensitiveDataDiscoveryBase, DBModel):
    """Schema for discovery scan response"""

    id: str
    organization_id: str
    scan_id: str
    total_files_scanned: int = 0
    sensitive_files_found: int = 0
    classification_breakdown: Optional[dict[str, int]] = None
    findings: Optional[list[dict[str, Any]]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    next_scheduled_scan: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DiscoveryScanListResponse(BaseModel):
    """Schema for paginated scan list"""

    items: list[SensitiveDataDiscoveryResponse]
    total: int
    page: int
    size: int
    pages: int


class DataMapResponse(BaseModel):
    """Schema for data map results"""

    organization_id: str
    generated_at: Optional[datetime] = None
    data_locations: dict[str, Any]
    high_risk_locations: list[dict[str, Any]]
    total_sensitive_data_locations: int


class DataLineageResponse(BaseModel):
    """Schema for data lineage tracking"""

    data_id: str
    origin: str
    current_location: str
    flows: list[dict[str, Any]]
    access_count: int


# Incident Schemas

class DLPIncidentBase(BaseModel):
    """Base incident schema"""

    incident_title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    severity: str = Field(default="high", max_length=20)
    status: str = Field(default="open", max_length=50)
    affected_data_subjects_count: Optional[int] = None
    data_types_involved: Optional[list[str]] = None


class DLPIncidentCreate(DLPIncidentBase):
    """Schema for creating an incident"""

    violation_ids: Optional[list[str]] = None


class DLPIncidentUpdate(BaseModel):
    """Schema for updating incident"""

    incident_title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    severity: Optional[str] = Field(None, max_length=20)
    status: Optional[str] = Field(None, max_length=50)
    affected_data_subjects_count: Optional[int] = None
    incident_commander: Optional[str] = None
    remediation_steps: Optional[list[str]] = None


class DLPIncidentResponse(DLPIncidentBase, DBModel):
    """Schema for incident response"""

    id: str
    organization_id: str
    violation_ids: Optional[list[str]] = None
    breach_notification_required: bool = False
    notification_deadline: Optional[datetime] = None
    notification_sent: Optional[datetime] = None
    incident_commander: Optional[str] = None
    remediation_steps: Optional[list[str]] = None
    regulatory_implications: Optional[dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DLPIncidentListResponse(BaseModel):
    """Schema for paginated incident list"""

    items: list[DLPIncidentResponse]
    total: int
    page: int
    size: int
    pages: int


class BreachAssessmentRequest(BaseModel):
    """Schema for breach assessment"""

    incident_id: str
    affected_count: int
    data_types: list[str]
    description: str


class BreachAssessmentResponse(BaseModel):
    """Schema for breach assessment results"""

    incident_id: str
    assessment_date: Optional[datetime] = None
    severity: str
    affected_subjects: int
    data_types: list[str]
    regulatory_obligations: dict[str, bool]
    notification_deadline: Optional[datetime] = None
    notification_required: bool


class NotificationTrackingResponse(BaseModel):
    """Schema for notification tracking"""

    incident_id: str
    notified_count: int
    total_required: int
    completion_percentage: float
    status: str
    last_updated: Optional[datetime] = None


# Dashboard Schemas

class DLPDashboardResponse(BaseModel):
    """Schema for DLP dashboard summary"""

    organization_id: str
    total_violations: int
    violations_this_month: int
    critical_violations: int
    top_violations: list[dict[str, Any]]
    top_policies_triggered: list[dict[str, Any]]
    data_risk_map: dict[str, Any]
    compliance_status: dict[str, Any]
    remediation_rate: float
    average_response_time_hours: float


class ViolationTrendResponse(BaseModel):
    """Schema for violation trends"""

    period: str
    total_violations: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_status: dict[str, int]
    trend_direction: str


class ComplianceStatusResponse(BaseModel):
    """Schema for compliance status"""

    regulations: dict[str, Any]
    open_incidents: int
    overdue_notifications: int
    compliance_score: float
    recommendations: list[str]
