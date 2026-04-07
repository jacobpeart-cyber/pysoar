"""
Compliance Schemas

Pydantic models for request/response validation across all compliance endpoints.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

from src.schemas.base import DBModel
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
class ComplianceFrameworkResponse(DBModel):
    """Compliance Framework Response"""

    id: str = ""
    name: str = ""
    short_name: str = ""
    version: str = ""
    description: Optional[str] = None
    authority: str = ""
    total_controls: int = 0
    implemented_controls: int = 0
    compliance_score: float = 0.0
    status: FrameworkStatus
    last_assessment_at: Optional[datetime] = None
    next_assessment_due: Optional[datetime] = None
    certification_level: Optional[str] = None
    is_enabled: bool = False
    metadata: Dict[str, Any] = {}
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ComplianceControlResponse(DBModel):
    """Compliance Control Response"""

    id: str = ""
    framework_id: str = ""
    control_id: str = ""
    control_family: str = ""
    title: str = ""
    description: Optional[str] = None
    priority: str = ""
    baseline: Optional[str] = None
    status: ControlStatus
    implementation_status: float = 0.0
    implementation_details: Optional[str] = None
    responsible_party: Optional[str] = None
    assessment_method: str = ""
    assessment_frequency: str = ""
    last_assessed_at: Optional[datetime] = None
    last_assessment_result: Optional[AssessmentResult] = None
    evidence_ids: List[str] = []
    related_controls: Dict[str, Any] = {}
    mitre_techniques: List[str] = []
    automated_check_id: Optional[str] = None
    risk_if_not_implemented: str = ""
    remediation_guidance: Optional[str] = None
    poam_id: Optional[str] = None
    tags: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class POAMResponse(DBModel):
    """Plan of Action & Milestones Response"""

    id: str = ""
    control_id_ref: str = ""
    weakness_name: str = ""
    weakness_description: Optional[str] = None
    weakness_source: str = ""
    risk_level: RiskLevel
    original_risk_rating: Optional[float] = None
    residual_risk_rating: Optional[float] = None
    status: POAMStatus
    milestone_changes: List[Dict[str, Any]] = []
    scheduled_completion_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None
    milestones: List[Dict[str, Any]] = []
    resources_required: Optional[str] = None
    cost_estimate: Optional[float] = None
    compensating_controls: Optional[str] = None
    vendor_dependencies: List[str] = []
    assigned_to: Optional[str] = None
    approved_by: Optional[str] = None
    comments: List[Dict[str, Any]] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ComplianceEvidenceResponse(DBModel):
    """Compliance Evidence Response"""

    id: str = ""
    control_id_ref: str = ""
    evidence_type: EvidenceType
    title: str = ""
    description: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    content: Optional[str] = None
    source_system: Optional[str] = None
    collected_at: Optional[datetime] = None
    collected_by: str = ""
    is_automated: bool = False
    is_valid: bool = False
    expires_at: Optional[datetime] = None
    review_status: ReviewStatus
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    tags: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ComplianceAssessmentResponse(DBModel):
    """Compliance Assessment Response"""

    id: str = ""
    framework_id: str = ""
    assessment_type: str = ""
    assessor: str = ""
    assessment_date: Optional[datetime] = None
    status: str = ""
    scope: Optional[str] = None
    findings_count: int = 0
    satisfied_count: int = 0
    other_than_satisfied_count: int = 0
    overall_result: Optional[str] = None
    report_path: Optional[str] = None
    next_steps: List[Dict[str, Any]] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CUIMarkingResponse(DBModel):
    """CUI Marking Response"""

    id: str = ""
    asset_id: str = ""
    asset_type: str = ""
    cui_category: str = ""
    cui_designation: str = ""
    dissemination_controls: List[str] = []
    handling_instructions: Optional[str] = None
    classification_authority: str = ""
    declassification_date: Optional[datetime] = None
    access_list: List[str] = []
    is_active: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CISADirectiveResponse(DBModel):
    """CISA Directive Response"""

    id: str = ""
    directive_id: str = ""
    title: str = ""
    description: Optional[str] = None
    directive_type: str = ""
    effective_date: Optional[datetime] = None
    compliance_deadline: Optional[datetime] = None
    status: str = ""
    requirements: List[Dict[str, Any]] = []
    compliance_status: str = ""
    actions_taken: List[Dict[str, Any]] = []
    evidence_ids: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Request Models
class POAMCreateRequest(BaseModel):
    """Create POA&M Request"""

    control_id_ref: str = ""
    weakness_name: str = ""
    weakness_description: Optional[str] = None
    weakness_source: str = ""
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

    framework_id: str = ""
    include_controls: Optional[List[str]] = None
    baseline: Optional[str] = None


class CUIMarkingRequest(BaseModel):
    """CUI Marking Request"""

    asset_id: str = ""
    asset_type: str = ""
    cui_category: str = ""
    cui_designation: str = ""
    dissemination_controls: List[str] = []
    handling_instructions: Optional[str] = None
    classification_authority: str = ""
    declassification_date: Optional[datetime] = None
    access_list: List[str] = []


# Complex Response Models
class FrameworkAssessmentResponse(BaseModel):
    """Framework Assessment Response"""

    framework_id: str = ""
    assessment_id: str = ""
    total_controls: int = 0
    implemented: int = 0
    satisfied: int = 0
    compliance_score: float = 0.0
    status: str = ""
    assessment_date: Optional[datetime] = None


class SSPGenerationResponse(BaseModel):
    """SSP Generation Response"""

    framework: str = ""
    baseline: str = ""
    generated_at: Optional[datetime] = None
    control_families: Dict[str, Any]


class ConMonReportResponse(BaseModel):
    """Continuous Monitoring Report Response"""

    conmon_type: str = ""
    conmon_date: Optional[datetime] = None
    frameworks_assessed: int = 0
    results: List[Dict[str, Any]]


class ComplianceDashboardStats(BaseModel):
    """Compliance Dashboard Statistics"""

    frameworks_total: int = 0
    frameworks_compliant: int = 0
    overall_compliance_score: float = 0.0
    framework_scores: List[Dict[str, Any]]
    overdue_poams: int = 0
    upcoming_poams: int = 0
    upcoming_assessments: int = 0
    control_status_breakdown: Dict[str, int]
    active_cisa_directives: int = 0
    cui_assets_total: int = 0
    cui_assets_active: int = 0
    last_updated: datetime


class ControlGapAnalysisResponse(BaseModel):
    """Control Gap Analysis Response"""

    framework_id: str = ""
    total_controls: int = 0
    gaps_count: int = 0
    gaps: List[Dict[str, Any]]
    priority_distribution: Dict[str, int]
    risk_distribution: Dict[str, int]


class CrossFrameworkMappingResponse(BaseModel):
    """Cross-Framework Control Mapping Response"""

    source_framework: str = ""
    target_framework: str = ""
    mapped_controls: List[Dict[str, Any]]
    unmapped_source_controls: List[str]
    coverage_percentage: float = 0.0


class CISADirectiveStatusResponse(BaseModel):
    """CISA Directive Status Response"""

    directive_id: str = ""
    title: str = ""
    directive_type: str = ""
    compliance_deadline: Optional[datetime] = None
    compliance_status: str = ""
    actions_taken: int = 0
    evidence_count: int = 0
    days_until_deadline: int = 0


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

    assessment_method: str = ""
    assessment_frequency: str = ""
    assessor: str = ""
    findings: Optional[List[str]] = None
    result: Optional[AssessmentResult] = None
