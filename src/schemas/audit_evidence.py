"""
Audit & Evidence Collection Pydantic Schemas

Request/response schemas for audit logging, evidence collection,
and continuous monitoring operations.
"""

from datetime import datetime
from typing import Any, Optional
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict


class EventTypeEnum(str, Enum):
    """Audit event types"""
    ACCESS = "access"
    CHANGE = "change"
    ADMIN = "admin"
    POLICY = "policy"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    DATA = "data"


class RiskLevelEnum(str, Enum):
    """Risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PackageTypeEnum(str, Enum):
    """Evidence package types"""
    FEDRAMP_CONMON = "fedramp_conmon"
    CMMC_ASSESSMENT = "cmmc_assessment"
    SOC2_AUDIT = "soc2_audit"
    HIPAA_AUDIT = "hipaa_audit"
    PCI_AUDIT = "pci_audit"
    CUSTOM = "custom"


class CollectionMethodEnum(str, Enum):
    """Evidence collection methods"""
    API_QUERY = "api_query"
    LOG_QUERY = "log_query"
    CONFIG_CHECK = "config_check"
    SCAN_RESULT = "scan_result"
    METRIC_SNAPSHOT = "metric_snapshot"


# ============================================================================
# Base Schemas
# ============================================================================


class AuditTrailBase(BaseModel):
    """Base audit trail schema"""
    event_type: EventTypeEnum
    action: str = ""
    actor_type: str = ""
    actor_id: str = ""
    actor_ip: Optional[str] = None
    resource_type: str = ""
    resource_id: str = ""
    description: str = ""
    old_value: Optional[dict[str, Any]] = None
    new_value: Optional[dict[str, Any]] = None
    result: str = ""
    risk_level: RiskLevelEnum = RiskLevelEnum.INFO
    session_id: Optional[str] = None
    request_id: Optional[str] = None


class AuditTrailResponse(AuditTrailBase):
    """Audit trail response schema"""
    id: str = ""
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class EvidencePackageBase(BaseModel):
    """Base evidence package schema"""
    name: str = ""
    description: Optional[str] = None
    package_type: PackageTypeEnum
    status: str = "collecting"
    assessor: Optional[str] = None
    due_date: Optional[datetime] = None
    extra_metadata: Optional[dict[str, Any]] = None


class EvidencePackageResponse(EvidencePackageBase):
    """Evidence package response schema"""
    id: str = ""
    framework_id: Optional[str] = None
    evidence_items: dict[str, Any]
    control_mappings: dict[str, Any]
    submitted_at: Optional[datetime] = None
    package_hash: Optional[str] = None
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AutomatedEvidenceRuleBase(BaseModel):
    """Base automated evidence rule schema"""
    name: str = ""
    control_ids: Optional[dict[str, Any]] = None
    evidence_type: str = ""
    collection_method: CollectionMethodEnum
    collection_config: dict[str, Any]
    schedule: str = "daily"
    is_enabled: bool = True


class AutomatedEvidenceRuleResponse(AutomatedEvidenceRuleBase):
    """Automated evidence rule response schema"""
    id: str = ""
    last_collected_at: Optional[datetime] = None
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Request Schemas
# ============================================================================


class AuditLogRequest(BaseModel):
    """Request to log audit event"""
    event_type: EventTypeEnum
    action: str = ""
    actor_type: str = ""
    actor_id: str = ""
    resource_type: str = ""
    resource_id: str = ""
    description: str = ""
    old_value: Optional[dict[str, Any]] = None
    new_value: Optional[dict[str, Any]] = None
    result: str = "success"
    risk_level: RiskLevelEnum = RiskLevelEnum.INFO
    actor_ip: Optional[str] = None


class AuditSearchRequest(BaseModel):
    """Request to search audit trail"""
    event_type: Optional[str] = None
    actor_id: Optional[str] = None
    resource_type: Optional[str] = None
    result: Optional[str] = None
    risk_level: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    skip: int = 0
    limit: int = 50


class EvidencePackageCreateRequest(BaseModel):
    """Request to create evidence package"""
    name: str = Field(..., description="Package name")
    description: Optional[str] = None
    package_type: PackageTypeEnum
    framework_id: Optional[str] = None
    assessor: Optional[str] = None
    due_date: Optional[datetime] = None
    metadata: Optional[dict[str, Any]] = None


class EvidenceCollectRequest(BaseModel):
    """Request to collect evidence"""
    rule_id: str = Field(..., description="Automated evidence rule ID")


class EvidencePackageSubmitRequest(BaseModel):
    """Request to submit evidence package"""
    package_id: str = ""
    assessor_id: Optional[str] = None
    additional_metadata: Optional[dict[str, Any]] = None


class ConMonCheckRequest(BaseModel):
    """Request to run ConMon check"""
    check_type: str = Field(..., description="Type of check to run")


class AutomatedRuleCreateRequest(BaseModel):
    """Request to create automated evidence rule"""
    name: str = ""
    control_ids: Optional[dict[str, Any]] = None
    evidence_type: str = ""
    collection_method: CollectionMethodEnum
    collection_config: dict[str, Any]
    schedule: str = "daily"
    is_enabled: bool = True


# ============================================================================
# Response Schemas
# ============================================================================


class AuditReportResponse(BaseModel):
    """Audit report response"""
    date_range: dict[str, str]
    statistics: dict[str, Any]
    total_entries: int = 0
    generated_at: Optional[datetime] = None


class SuspiciousActivityResponse(BaseModel):
    """Suspicious activity detection response"""
    actor_id: str = ""
    activities: list[dict[str, Any]]
    risk_score: float = 0.0
    recommendations: list[str]


class ConMonReportResponse(BaseModel):
    """FedRAMP ConMon monthly report"""
    report_type: str = ""
    period: dict[str, str]
    overall_status: str = ""
    checks: dict[str, Any]
    generated_at: Optional[datetime] = None


class AuditReadinessResponse(BaseModel):
    """Audit readiness assessment"""
    framework: str = ""
    overall_readiness: str = ""
    readiness_percentage: float = 0.0
    gaps: list[dict[str, Any]]
    recommendations: list[str]


class EvidenceCoverageResponse(BaseModel):
    """Evidence coverage assessment"""
    framework_id: str = ""
    total_controls: int = 0
    controls_with_evidence: int = 0
    controls_without_evidence: int = 0
    coverage_percentage: float = 0.0
    controls_missing_evidence: list[dict[str, Any]]


class EvidenceFreshnessResponse(BaseModel):
    """Evidence freshness assessment"""
    framework_id: str = ""
    assessment_date: Optional[datetime] = None
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    freshness_percentage: float = 0.0
    stale_controls: list[dict[str, Any]]


class AssessorPackageResponse(BaseModel):
    """Assessor package for external audit"""
    package_id: str = ""
    framework_id: str = ""
    coverage: EvidenceCoverageResponse
    freshness: EvidenceFreshnessResponse
    generated_at: Optional[datetime] = None
    ready_for_assessment: bool = False


class AuditDashboardStats(BaseModel):
    """Audit and evidence dashboard statistics"""
    organization_id: str = ""
    total_audit_entries: int = 0
    audit_entries_this_month: int = 0
    event_types_breakdown: dict[str, int] = {}
    risk_distribution: dict[str, int] = {}
    total_evidence_packages: int = 0
    evidence_packages_in_progress: int = 0
    evidence_packages_submitted: int = 0
    avg_evidence_package_compliance: float = 0.0
    suspicious_activities_detected: int = 0
    critical_audit_events: int = 0
    last_conmon_run: Optional[datetime] = None
    conmon_status: str = "not_run"


class EvidenceCollectionResult(BaseModel):
    """Evidence collection result"""
    rule_id: str = ""
    collection_method: str = ""
    status: str = ""
    evidence_count: int = 0
    collected_at: datetime
    next_collection: Optional[datetime] = None


class ControlEvidenceMapping(BaseModel):
    """Control to evidence mapping"""
    control_id: str = ""
    control_title: str = ""
    evidence_items: list[dict[str, Any]]
    coverage_status: str = ""
    last_updated: datetime
