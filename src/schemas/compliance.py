"""
Compliance Schemas

Pydantic models for request/response validation across all compliance endpoints.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

from pydantic import BaseModel, Field

__all__ = [
    "ComplianceFrameworkResponse",
    "ComplianceControlResponse",
    "POAMResponse",
    "ComplianceEvidenceResponse",
    "ComplianceAssessmentResponse",
    "CUIMarkingResponse",
    "CISADirectiveResponse",
    "FrameworkAssessmentResponse",
    "POAMCreateRequest",
    "POAMUpdateRequest",
    "SSPGenerationRequest",
    "SSPGenerationResponse",
    "ConMonReportResponse",
    "CUIMarkingRequest",
    "ComplianceDashboardStats",
    "ControlGapAnalysisResponse",
    "CrossFrameworkMappingResponse",
    "CISADirectiveStatusResponse",
]


# Enums
class FrameworkStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PARTIALLY_COMPLIANT = "partially_compliant"
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"


class ControlStatus(str, Enum):
    NOT_IMPLEMENTED = "not_implemented"
    PLANNED = "planned"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"


class AssessmentResult(str, Enum):
    SATISFIED = "satisfied"
    OTHER_THAN_SATISFIED = "other_than_satisfied"
    NOT_ASSESSED = "not_assessed"


class POAMStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    DELAYED = "delayed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ACCEPTED = "accepted"


class RiskLevel(str, Enum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class EvidenceType(str, Enum):
    DOCUMENT = "document"
    SCREENSHOT = "screenshot"
    LOG = "log"
    CONFIGURATION = "configuration"
    SCAN_RESULT = "scan_result"
    POLICY = "policy"
    PROCEDURE = "procedure"
    AUTOMATED_TEST = "automated_test"
    INTERVIEW_NOTES = "interview_notes"
    TRAINING_RECORD = "training_record"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    REJECTED = "rejected"


# Base Response Models
class ComplianceFrameworkResponse(BaseModel):
    """Compliance Framework Response"""

    id: str
    name: str
    short_name: str
    version: str
    description: Optional[str] = None
    authority: str
    total_controls: int
    implemented_controls: int
    compliance_score: float
    status: FrameworkStatus
    last_assessment_at: Optional[datetime] = None
    next_assessment_due: Optional[datetime] = None
    certification_level: Optional[str] = None
    is_enabled: bool
    metadata: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ComplianceControlResponse(BaseModel):
    """Compliance Control Response"""

    id: str
    framework_id: str
    control_id: str
    control_family: str
    title: str
    description: Optional[str] = None
    priority: str
    baseline: Optional[str] = None
    status: ControlStatus
    implementation_status: float
    implementation_details: Optional[str] = None
    responsible_party: Optional[str] = None
    assessment_method: str
    assessment_frequency: str
    last_assessed_at: Optional[datetime] = None
    last_assessment_result: Optional[AssessmentResult] = None
    evidence_ids: List[str] = []
    related_controls: Dict[str, Any] = {}
    mitre_techniques: List[str] = []
    automated_check_id: Optional[str] = None
    risk_if_not_implemented: str
    remediation_guidance: Optional[str] = None
    poam_id: Optional[str] = None
    tags: List[str] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class POAMResponse(BaseModel):
    """Plan of Action & Milestones Response"""

    id: str
    control_id_ref: str
    weakness_name: str
    weakness_description: Optional[str] = None
    weakness_source: str
    risk_level: RiskLevel
    original_risk_rating: Optional[float] = None
    residual_risk_rating: Optional[float] = None
    status: POAMStatus
    milestone_changes: List[Dict[str, Any]] = []
    scheduled_completion_date: datetime
    actual_completion_date: Optional[datetime] = None
    milestones: List[Dict[str, Any]] = []
    resources_required: Optional[str] = None
    cost_estimate: Optional[float] = None
    compensating_controls: Optional[str] = None
    vendor_dependencies: List[str] = []
    assigned_to: Optional[str] = None
    approved_by: Optional[str] = None
    comments: List[Dict[str, Any]] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ComplianceEvidenceResponse(BaseModel):
    """Compliance Evidence Response"""

    id: str
    control_id_ref: str
    evidence_type: EvidenceType
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    content: Optional[str] = None
    source_system: Optional[str] = None
    collected_at: datetime
    collected_by: str
    is_automated: bool
    is_valid: bool
    expires_at: Optional[datetime] = None
    review_status: ReviewStatus
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    tags: List[str] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ComplianceAssessmentResponse(BaseModel):
    """Compliance Assessment Response"""

    id: str
    framework_id: str
    assessment_type: str
    assessor: str
    assessment_date: datetime
    status: str
    scope: Optional[str] = None
    findings_count: int
    satisfied_count: int
    other_than_satisfied_count: int
    overall_result: Optional[str] = None
    report_path: Optional[str] = None
    next_steps: List[Dict[str, Any]] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CUIMarkingResponse(BaseModel):
    """CUI Marking Response"""

    id: str
    asset_id: str
    asset_type: str
    cui_category: str
    cui_designation: str
    dissemination_controls: List[str] = []
    handling_instructions: Optional[str] = None
    classification_authority: str
    declassification_date: Optional[datetime] = None
    access_list: List[str] = []
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CISADirectiveResponse(BaseModel):
    """CISA Directive Response"""

    id: str
    directive_id: str
    title: str
    description: Optional[str] = None
    directive_type: str
    effective_date: datetime
    compliance_deadline: datetime
    status: str
    requirements: List[Dict[str, Any]] = []
    compliance_status: str
    actions_taken: List[Dict[str, Any]] = []
    evidence_ids: List[str] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Request Models
class POAMCreateRequest(BaseModel):
    """Create POA&M Request"""

    control_id_ref: str
    weakness_name: str
    weakness_description: Optional[str] = None
    weakness_source: str
    risk_level: RiskLevel
    scheduled_completion_date: datetime
    resources_required: Optional[str] = None
    cost_estimate: Optional[float] = None
    assigned_to: Optional[str] = None


class POAMUpdateRequest(BaseModel):
    """Update POA&M Request"""

    status: Optional[POAMStatus] = None
    scheduled_completion_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None
    assigned_to: Optional[str] = None
    approved_by: Optional[str] = None
    residual_risk_rating: Optional[float] = None


class SSPGenerationRequest(BaseModel):
    """SSP Generation Request"""

    framework_id: str
    include_controls: Optional[List[str]] = None
    baseline: Optional[str] = None


class CUIMarkingRequest(BaseModel):
    """CUI Marking Request"""

    asset_id: str
    asset_type: str
    cui_category: str
    cui_designation: str
    dissemination_controls: List[str] = []
    handling_instructions: Optional[str] = None
    classification_authority: str
    declassification_date: Optional[datetime] = None
    access_list: List[str] = []


# Complex Response Models
class FrameworkAssessmentResponse(BaseModel):
    """Framework Assessment Response"""

    framework_id: str
    assessment_id: str
    total_controls: int
    implemented: int
    satisfied: int
    compliance_score: float
    status: str
    assessment_date: datetime


class SSPGenerationResponse(BaseModel):
    """SSP Generation Response"""

    framework: str
    baseline: str
    generated_at: datetime
    control_families: Dict[str, Any]


class ConMonReportResponse(BaseModel):
    """Continuous Monitoring Report Response"""

    conmon_type: str
    conmon_date: datetime
    frameworks_assessed: int
    results: List[Dict[str, Any]]


class ComplianceDashboardStats(BaseModel):
    """Compliance Dashboard Statistics"""

    frameworks_total: int
    frameworks_compliant: int
    overall_compliance_score: float
    framework_scores: List[Dict[str, Any]]
    overdue_poams: int
    upcoming_poams: int
    upcoming_assessments: int
    control_status_breakdown: Dict[str, int]
    active_cisa_directives: int
    cui_assets_total: int
    cui_assets_active: int
    last_updated: datetime


class ControlGapAnalysisResponse(BaseModel):
    """Control Gap Analysis Response"""

    framework_id: str
    total_controls: int
    gaps_count: int
    gaps: List[Dict[str, Any]]
    priority_distribution: Dict[str, int]
    risk_distribution: Dict[str, int]


class CrossFrameworkMappingResponse(BaseModel):
    """Cross-Framework Control Mapping Response"""

    source_framework: str
    target_framework: str
    mapped_controls: List[Dict[str, Any]]
    unmapped_source_controls: List[str]
    coverage_percentage: float


class CISADirectiveStatusResponse(BaseModel):
    """CISA Directive Status Response"""

    directive_id: str
    title: str
    directive_type: str
    compliance_deadline: datetime
    compliance_status: str
    actions_taken: int
    evidence_count: int
    days_until_deadline: int


# Pagination Models
class PaginationParams(BaseModel):
    """Pagination Parameters"""

    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=100)


# Control Update Models
class ControlStatusUpdateRequest(BaseModel):
    """Update Control Status Request"""

    status: ControlStatus
    implementation_status: Optional[float] = Field(None, ge=0, le=100)
    responsible_party: Optional[str] = None
    implementation_details: Optional[str] = None


class ControlAssessmentRequest(BaseModel):
    """Control Assessment Request"""

    assessment_method: str
    assessment_frequency: str
    assessor: str
    findings: Optional[List[str]] = None
    result: Optional[AssessmentResult] = None
