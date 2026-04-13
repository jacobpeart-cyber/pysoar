"""
STIG/SCAP Pydantic Schemas

Request/response schemas for STIG scanning, remediation, and SCAP operations.
"""

from datetime import datetime
from typing import Any, Optional
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict


class SeverityEnum(str, Enum):
    """STIG rule severity levels"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanTypeEnum(str, Enum):
    """STIG scan execution types"""
    MANUAL = "manual"
    SCAP = "scap"
    AUTOMATED = "automated"
    HYBRID = "hybrid"


class ScanStatusEnum(str, Enum):
    """STIG scan status"""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BenchmarkStatusEnum(str, Enum):
    """STIG benchmark status"""
    AVAILABLE = "available"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


# ============================================================================
# Base Schemas
# ============================================================================


class STIGBenchmarkBase(BaseModel):
    """Base STIG Benchmark schema"""
    benchmark_id: str = ""
    title: Optional[str] = None
    version: Optional[str] = None
    release: Optional[str] = None
    description: Optional[str] = None
    platform: Optional[str] = None
    total_rules: int = 0
    category_1_count: int = 0
    category_2_count: int = 0
    category_3_count: int = 0
    status: str = "available"
    tags: Optional[dict[str, Any]] = None


class STIGBenchmarkResponse(STIGBenchmarkBase):
    """STIG Benchmark response schema"""
    id: str = ""
    last_scan_at: Optional[datetime] = None
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class STIGRuleBase(BaseModel):
    """Base STIG Rule schema"""
    rule_id: str = ""
    stig_id: Optional[str] = None
    group_id: Optional[str] = None
    severity: SeverityEnum
    title: str = ""
    description: Optional[str] = None
    check_text: Optional[str] = None
    fix_text: Optional[str] = None
    cci: Optional[dict[str, Any]] = None
    nist_controls: Optional[dict[str, Any]] = None
    automated_check: Optional[dict[str, Any]] = None
    is_automatable: bool = True
    default_status: str = "not_reviewed"


class STIGRuleResponse(STIGRuleBase):
    """STIG Rule response schema"""
    id: str = ""
    benchmark_id_ref: str = ""
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class STIGScanResultBase(BaseModel):
    """Base STIG Scan Result schema"""
    target_host: str = ""
    target_ip: Optional[str] = None
    scan_type: ScanTypeEnum
    scanner: Optional[str] = None
    status: ScanStatusEnum
    total_checks: int = 0
    open_findings: int = 0
    not_a_finding: int = 0
    not_applicable: int = 0
    not_reviewed: int = 0
    compliance_percentage: float = 0.0
    cat1_open: int = 0
    cat2_open: int = 0
    cat3_open: int = 0


class STIGScanResultResponse(STIGScanResultBase):
    """STIG Scan Result response schema"""
    id: str = ""
    benchmark_id_ref: str = ""
    organization_id: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings: Optional[dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SCAPProfileBase(BaseModel):
    """Base SCAP Profile schema"""
    name: str = ""
    profile_type: str = ""
    description: Optional[str] = None
    content_path: Optional[str] = None
    content_hash: Optional[str] = None
    platform_applicable: Optional[dict[str, Any]] = None
    check_count: int = 0
    is_enabled: bool = True


class SCAPProfileResponse(SCAPProfileBase):
    """SCAP Profile response schema"""
    id: str = ""
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Request Schemas
# ============================================================================


class ScanRequest(BaseModel):
    """Request to initiate STIG scan"""
    host: str = Field(..., description="Target hostname or IP")
    benchmark_id: str = Field(..., description="STIG benchmark ID")
    scan_type: ScanTypeEnum = Field(default=ScanTypeEnum.AUTOMATED)
    target_ip: Optional[str] = None


class ScanFleetRequest(BaseModel):
    """Request to scan multiple hosts"""
    hosts: list[str] = Field(..., description="List of target hosts")
    benchmark_id: str = Field(..., description="STIG benchmark ID")
    scan_type: ScanTypeEnum = Field(default=ScanTypeEnum.AUTOMATED)


class RemediationRequest(BaseModel):
    """Request auto-remediation"""
    scan_result_id: str = Field(..., description="STIG scan result ID")
    categories: list[str] = Field(default=["high", "medium"], description="Categories to remediate")


class RemediationScriptRequest(BaseModel):
    """Request remediation script generation"""
    findings: dict[str, Any] = Field(..., description="Findings to remediate")
    platform: str = Field(..., description="Target platform (windows, linux, etc.)")


class ScanComparisonRequest(BaseModel):
    """Request scan comparison"""
    scan_id_1: str = Field(..., description="First scan ID")
    scan_id_2: str = Field(..., description="Second scan ID")


class SCAPImportRequest(BaseModel):
    """Request SCAP content import"""
    content_path: str = Field(..., description="Path to XCCDF/OVAL file")
    profile_type: str = Field(default="xccdf", description="SCAP content type")


class OVALValidationRequest(BaseModel):
    """Request OVAL content validation"""
    content: str = Field(..., description="OVAL XML content")


class ARFReportRequest(BaseModel):
    """Request Assessment Results Format report"""
    scan_id: str = Field(..., description="Scan ID to generate report for")
    report_format: str = Field(default="json", description="json, xml, or html")


# ============================================================================
# Response Schemas
# ============================================================================


class ScanComparisonResponse(BaseModel):
    """Scan comparison result"""
    scan_1: str = ""
    scan_2: str = ""
    host: str = ""
    benchmark: str = ""
    compliance_delta: float = 0.0
    open_delta: int = 0
    cat1_delta: int = 0
    cat2_delta: int = 0
    cat3_delta: int = 0
    improvements: int = 0
    regressions: int = 0
    improved_rules: list[str]
    regressed_rules: list[str]
    trend: str = ""


class RemediationScriptResponse(BaseModel):
    """Remediation script response"""
    platform: str = ""
    script: str = ""
    total_findings: int = 0
    generated_at: Optional[datetime] = None
    script_format: str = "text"


class RemediationResponse(BaseModel):
    """Auto-remediation response"""
    scan_id: str = ""
    host: str = ""
    total_findings: int = 0
    remediated: int = 0
    failed: int = 0
    status: str = ""
    actions: list[dict[str, Any]]


class SCAPScanResponse(BaseModel):
    """SCAP scan result"""
    profile_id: str = ""
    profile_name: str = ""
    target: str = ""
    checks_evaluated: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_notapplicable: int = 0
    status: str = ""
    timestamp: Optional[datetime] = None


class ARFReportResponse(BaseModel):
    """Assessment Results Format report"""
    scan_id: str = ""
    arf_version: str = ""
    asset: dict[str, Any]
    assessment: dict[str, Any]
    findings: dict[str, Any]
    timestamp: Optional[datetime] = None


class STIGDashboardStats(BaseModel):
    """STIG compliance dashboard statistics.

    The bottom three fields (``compliance_by_benchmark``,
    ``findings_by_severity``, ``recent_scans``) are what the frontend's
    Dashboard tab actually renders in its KPI cards, bar chart, and
    recent-scans table. The schema previously omitted them and the
    endpoint returned only the flat counts, so the UI showed zeros /
    empty lists regardless of real scan data.
    """
    organization_id: str = ""
    total_benchmarks: int = 0
    total_scans: int = 0
    average_compliance: float = 0.0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    last_scan_date: Optional[datetime] = None
    scans_this_month: int = 0
    compliance_trend: str = "stable"
    top_failing_rules: list[dict[str, Any]] = []
    compliance_by_benchmark: list[dict[str, Any]] = []
    findings_by_severity: dict[str, int] = {}
    recent_scans: list[dict[str, Any]] = []


class RuleSearchResponse(BaseModel):
    """Rule search result"""
    rule_id: str = ""
    title: str = ""
    severity: str = ""
    benchmark: str = ""
    description: Optional[str] = None


class BenchmarkListResponse(BaseModel):
    """Benchmark list item"""
    id: str = ""
    benchmark_id: str = ""
    title: str = ""
    platform: str = ""
    version: str = ""
    total_rules: int = 0
    category_1_count: int = 0
    category_2_count: int = 0
    category_3_count: int = 0
    status: str = ""
    last_scan_at: Optional[datetime] = None
