"""
Privacy Engineering Schemas

Pydantic models for request/response validation across all privacy endpoints.
Supports DSRs, PIAs, Consent Records, Processing Records (ROPA), and Incidents.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

from src.schemas.base import DBModel
from pydantic import BaseModel, Field, field_validator

__all__ = [
    "DSRType",
    "Regulation",
    "DSRStatus",
    "DataSubjectRequestBase",
    "DataSubjectRequestCreate",
    "DataSubjectRequestUpdate",
    "DataSubjectRequestResponse",
    "DataSubjectRequestListResponse",
    "PIAAssessmentType",
    "PIAStatus",
    "RiskLevel",
    "PrivacyImpactAssessmentBase",
    "PrivacyImpactAssessmentCreate",
    "PrivacyImpactAssessmentUpdate",
    "PrivacyImpactAssessmentResponse",
    "ConsentType",
    "LegalBasis",
    "ConsentRecordBase",
    "ConsentRecordCreate",
    "ConsentRecordUpdate",
    "ConsentRecordResponse",
    "DataProcessingRecordBase",
    "DataProcessingRecordCreate",
    "DataProcessingRecordUpdate",
    "DataProcessingRecordResponse",
    "IncidentType",
    "IncidentSeverity",
    "IncidentStatus",
    "PrivacyIncidentBase",
    "PrivacyIncidentCreate",
    "PrivacyIncidentUpdate",
    "PrivacyIncidentResponse",
    "DSRDeadlineAlert",
    "RetentionViolation",
    "PrivacyDashboardStats",
    "PaginationParams",
]


# ============================================================================
# ENUMS
# ============================================================================


class DSRType(str, Enum):
    """Data Subject Request types"""

    ACCESS = "access"
    RECTIFICATION = "rectification"
    ERASURE = "erasure"
    PORTABILITY = "portability"
    RESTRICTION = "restriction"
    OBJECTION = "objection"
    AUTOMATED_DECISION = "automated_decision"


class Regulation(str, Enum):
    """Privacy regulations"""

    GDPR = "gdpr"
    CCPA = "ccpa"
    LGPD = "lgpd"
    PIPA = "pipa"
    PDPA = "pdpa"
    HIPAA_RIGHT = "hipaa_right"
    CUSTOM = "custom"


class DSRStatus(str, Enum):
    """Data Subject Request status"""

    RECEIVED = "received"
    IDENTITY_VERIFIED = "identity_verified"
    PROCESSING = "processing"
    PARTIALLY_COMPLETE = "partially_complete"
    COMPLETED = "completed"
    DENIED = "denied"
    APPEALED = "appealed"


class PIAAssessmentType(str, Enum):
    """Privacy Impact Assessment types"""

    DPIA = "dpia"
    PIA = "pia"
    TIA = "tia"
    LEGITIMATE_INTEREST = "legitimate_interest"


class PIAStatus(str, Enum):
    """Privacy Impact Assessment status"""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REQUIRES_CHANGES = "requires_changes"
    REJECTED = "rejected"


class RiskLevel(str, Enum):
    """Risk assessment levels"""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConsentType(str, Enum):
    """Consent mechanisms"""

    EXPLICIT_OPT_IN = "explicit_opt_in"
    SOFT_OPT_IN = "soft_opt_in"
    IMPLIED = "implied"
    CHECKBOX = "checkbox"
    DOUBLE_OPT_IN = "double_opt_in"


class LegalBasis(str, Enum):
    """Legal bases for processing"""

    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTEREST = "vital_interest"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTEREST = "legitimate_interest"


class IncidentType(str, Enum):
    """Privacy incident types"""

    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH = "data_breach"
    IMPROPER_DISCLOSURE = "improper_disclosure"
    LOSS_OF_DATA = "loss_of_data"
    PROCESSING_VIOLATION = "processing_violation"
    CONSENT_VIOLATION = "consent_violation"
    CROSS_BORDER_VIOLATION = "cross_border_violation"
    RETENTION_VIOLATION = "retention_violation"


class IncidentSeverity(str, Enum):
    """Privacy incident severity"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """Privacy incident status"""

    REPORTED = "reported"
    UNDER_INVESTIGATION = "under_investigation"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


# ============================================================================
# DATA SUBJECT REQUEST SCHEMAS
# ============================================================================


class DataSubjectRequestBase(BaseModel):
    """Base schema for Data Subject Requests"""

    request_type: DSRType
    regulation: Regulation
    subject_name: str = Field(..., min_length=1, max_length=255)
    subject_email: str = Field(..., min_length=5, max_length=255)
    subject_identifier: Optional[str] = Field(None, max_length=255)


class DataSubjectRequestCreate(DataSubjectRequestBase):
    """Create Data Subject Request"""

    pass


class DataSubjectRequestUpdate(BaseModel):
    """Update Data Subject Request"""

    status: Optional[DSRStatus] = None
    processing_notes: Optional[str] = None
    denial_reason: Optional[str] = None


class DataSubjectRequestResponse(DataSubjectRequestBase, DBModel):
    """Data Subject Request response"""

    id: str
    status: DSRStatus
    deadline: Optional[str]
    data_systems_searched: Optional[List[str]] = None
    response_sent: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DataSubjectRequestListResponse(BaseModel):
    """Paginated DSR list response"""

    total: int
    page: int
    size: int
    items: List[DataSubjectRequestResponse]


# ============================================================================
# PRIVACY IMPACT ASSESSMENT SCHEMAS
# ============================================================================


class PrivacyImpactAssessmentBase(BaseModel):
    """Base schema for Privacy Impact Assessment"""

    name: str = Field(..., min_length=1, max_length=255)
    project_name: str = Field(..., min_length=1, max_length=255)
    assessment_type: PIAAssessmentType
    data_types_processed: Optional[List[str]] = None
    processing_purposes: Optional[List[str]] = None
    legal_basis: Optional[str] = Field(None, max_length=100)
    data_subjects_affected: Optional[int] = None


class PrivacyImpactAssessmentCreate(PrivacyImpactAssessmentBase):
    """Create Privacy Impact Assessment"""

    pass


class PrivacyImpactAssessmentUpdate(BaseModel):
    """Update Privacy Impact Assessment"""

    status: Optional[PIAStatus] = None
    risk_level: Optional[RiskLevel] = None
    dpo_approval_date: Optional[str] = None
    supervisory_authority_consulted: Optional[bool] = None


class PrivacyImpactAssessmentResponse(PrivacyImpactAssessmentBase, DBModel):
    """Privacy Impact Assessment response"""

    id: str
    status: PIAStatus
    risk_level: RiskLevel
    dpo_review: bool
    dpo_approval_date: Optional[str]
    mitigations: Optional[List[str]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# CONSENT RECORD SCHEMAS
# ============================================================================


class ConsentRecordBase(BaseModel):
    """Base schema for Consent Record"""

    subject_id: str = Field(..., min_length=1, max_length=255)
    purpose: str = Field(..., min_length=1, max_length=255)
    legal_basis: LegalBasis
    consent_mechanism: ConsentType
    evidence_location: Optional[str] = Field(None, max_length=500)


class ConsentRecordCreate(ConsentRecordBase):
    """Create Consent Record"""

    consent_given: bool = True


class ConsentRecordUpdate(BaseModel):
    """Update Consent Record"""

    consent_given: Optional[bool] = None
    withdrawal_date: Optional[str] = None


class ConsentRecordResponse(ConsentRecordBase, DBModel):
    """Consent Record response"""

    id: str
    consent_given: bool
    consent_date: Optional[str]
    withdrawal_date: Optional[str]
    version: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# DATA PROCESSING RECORD SCHEMAS (ROPA)
# ============================================================================


class DataProcessingRecordBase(BaseModel):
    """Base schema for Data Processing Record"""

    name: str = Field(..., min_length=1, max_length=255)
    purpose: str = Field(..., min_length=1, max_length=500)
    legal_basis: str = Field(..., max_length=100)
    data_categories: Optional[List[str]] = None
    data_subjects: Optional[List[str]] = None
    recipients: Optional[List[str]] = None
    retention_period_days: Optional[int] = None
    dpo_contact: Optional[str] = Field(None, max_length=255)

    @field_validator("data_categories", "data_subjects", "recipients", mode="before")
    @classmethod
    def parse_json_lists(cls, v):
        if v is None:
            return None
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            try:
                import json as _json
                parsed = _json.loads(v)
                return parsed if isinstance(parsed, list) else [str(parsed)]
            except (ValueError, TypeError):
                return [v]
        return v


class DataProcessingRecordCreate(DataProcessingRecordBase):
    """Create Data Processing Record"""

    pass


class DataProcessingRecordUpdate(BaseModel):
    """Update Data Processing Record"""

    last_reviewed: Optional[str] = None
    retention_period_days: Optional[int] = None


class DataProcessingRecordResponse(DataProcessingRecordBase, DBModel):
    """Data Processing Record response"""

    id: str
    last_reviewed: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# PRIVACY INCIDENT SCHEMAS
# ============================================================================


class PrivacyIncidentBase(BaseModel):
    """Base schema for Privacy Incident"""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    incident_type: IncidentType
    severity: IncidentSeverity
    data_types_affected: Optional[List[str]] = None
    subjects_affected_count: Optional[int] = None

    @field_validator("data_types_affected", mode="before")
    @classmethod
    def parse_json_list(cls, v):
        if v is None:
            return None
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            try:
                import json as _json
                parsed = _json.loads(v)
                return parsed if isinstance(parsed, list) else [str(parsed)]
            except (ValueError, TypeError):
                return [v]
        return v


class PrivacyIncidentCreate(PrivacyIncidentBase):
    """Create Privacy Incident"""

    pass


class PrivacyIncidentUpdate(BaseModel):
    """Update Privacy Incident"""

    status: Optional[IncidentStatus] = None
    root_cause: Optional[str] = None
    remediation_steps: Optional[List[str]] = None
    containment_actions: Optional[List[str]] = None
    supervisory_authority_notified: Optional[bool] = None
    subjects_notified: Optional[bool] = None


class PrivacyIncidentResponse(PrivacyIncidentBase, DBModel):
    """Privacy Incident response"""

    id: str
    status: IncidentStatus
    notification_required: bool
    notification_deadline: Optional[str]
    supervisory_authority_notified: bool
    subjects_notified: bool
    root_cause: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# UTILITY SCHEMAS
# ============================================================================


class DSRDeadlineAlert(BaseModel):
    """DSR deadline compliance alert"""

    dsr_id: str
    status: str  # BREACHED, CRITICAL, APPROACHING
    subject: str
    days_remaining: Optional[int] = None
    days_overdue: Optional[int] = None


class RetentionViolation(BaseModel):
    """Data retention compliance violation"""

    record_id: str
    name: str
    status: str  # RETENTION_EXCEEDED
    days_overdue: int


class PrivacyDashboardStats(BaseModel):
    """Privacy module dashboard statistics"""

    total_dsrs: int
    pending_dsrs: int
    dsr_compliance_rate: float
    active_pias: int
    pias_requiring_review: int
    total_consents: int
    withdrawn_consents: int
    processing_records: int
    pending_incidents: int
    incidents_this_month: int
    avg_incident_resolution_days: float


class PaginationParams(BaseModel):
    """Pagination parameters"""

    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)
