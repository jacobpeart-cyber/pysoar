"""Dark Web Monitoring Schemas

Pydantic schemas for API request/response validation.
Includes monitor configurations, findings, credentials, and brand threats.
"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


class DarkWebMonitorBase(BaseModel):
    """Base schema for dark web monitor"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    monitor_type: str = Field(
        default="credential_leak",
        description="Type of monitoring to perform",
    )
    search_terms: Optional[list[str]] = None
    domains_watched: Optional[list[str]] = None
    emails_watched: Optional[list[str]] = None
    enabled: bool = Field(default=True)
    alert_severity: str = Field(default="high")


class DarkWebMonitorCreate(DarkWebMonitorBase):
    """Schema for creating dark web monitor"""

    pass


class DarkWebMonitorUpdate(BaseModel):
    """Schema for updating dark web monitor"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    monitor_type: Optional[str] = None
    search_terms: Optional[list[str]] = None
    domains_watched: Optional[list[str]] = None
    emails_watched: Optional[list[str]] = None
    enabled: Optional[bool] = None
    alert_severity: Optional[str] = None


class DarkWebMonitorResponse(DarkWebMonitorBase, DBModel):
    """Schema for monitor response"""

    id: str = ""
    organization_id: str = ""
    last_check: Optional[str] = None
    findings_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DarkWebMonitorListResponse(BaseModel):
    """Schema for paginated monitor list"""

    items: list[DarkWebMonitorResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class DarkWebFindingBase(BaseModel):
    """Base schema for dark web finding"""

    finding_type: str = Field(default="credential_leak")
    source_platform: str = Field(default="paste_site")
    title: Optional[str] = None
    description: Optional[str] = None
    affected_assets: Optional[dict[str, Any]] = None
    affected_count: int = Field(default=1, ge=1)
    severity: str = Field(default="medium")
    confidence_score: int = Field(default=50, ge=0, le=100)


class DarkWebFindingCreate(DarkWebFindingBase):
    """Schema for creating dark web finding"""

    monitor_id: str = ""
    source_url_hash: Optional[str] = None
    raw_data_hash: Optional[str] = None


class DarkWebFindingUpdate(BaseModel):
    """Schema for updating dark web finding"""

    status: Optional[str] = None
    analyst_notes: Optional[str] = None
    severity: Optional[str] = None
    confidence_score: Optional[int] = Field(None, ge=0, le=100)


class DarkWebFindingResponse(DarkWebFindingBase, DBModel):
    """Schema for finding response"""

    id: str = ""
    monitor_id: str = ""
    organization_id: str = ""
    status: str = "new"
    source_url_hash: Optional[str] = None
    raw_data_hash: Optional[str] = None
    discovered_date: Optional[str] = None
    analyst_notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DarkWebFindingListResponse(BaseModel):
    """Schema for paginated finding list"""

    items: list[DarkWebFindingResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class DarkWebFindingDetailResponse(DarkWebFindingResponse):
    """Detailed finding response with related data"""

    credential_leaks: Optional[list["CredentialLeakResponse"]] = None
    brand_threats: Optional[list["BrandThreatResponse"]] = None


class CredentialLeakBase(BaseModel):
    """Base schema for credential leak"""

    email: Optional[str] = None
    username: Optional[str] = None
    password_hash: Optional[str] = None
    password_type: str = Field(default="unknown")
    breach_source: Optional[str] = None
    breach_date: Optional[str] = None
    is_valid: bool = Field(default=False)


class CredentialLeakCreate(CredentialLeakBase):
    """Schema for creating credential leak"""

    finding_id: str = ""


class CredentialLeakUpdate(BaseModel):
    """Schema for updating credential leak"""

    is_valid: Optional[bool] = None
    is_remediated: Optional[bool] = None
    remediation_action: Optional[str] = None


class CredentialLeakResponse(CredentialLeakBase, DBModel):
    """Schema for credential leak response"""

    id: str = ""
    finding_id: str = ""
    organization_id: str = ""
    is_remediated: bool = False
    remediation_action: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CredentialLeakListResponse(BaseModel):
    """Schema for paginated credential leak list"""

    items: list[CredentialLeakResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0
    unremediated_count: int = 0


class BrandThreatBase(BaseModel):
    """Base schema for brand threat"""

    threat_type: str = Field(default="domain_typosquat")
    target_brand: Optional[str] = None
    target_domain: Optional[str] = None
    malicious_domain: Optional[str] = None
    registrar: Optional[str] = None
    registration_date: Optional[str] = None
    ssl_certificate_info: Optional[dict[str, Any]] = None


class BrandThreatCreate(BrandThreatBase):
    """Schema for creating brand threat"""

    finding_id: str = ""


class BrandThreatUpdate(BaseModel):
    """Schema for updating brand threat"""

    takedown_status: Optional[str] = None
    takedown_provider: Optional[str] = None


class BrandThreatResponse(BrandThreatBase, DBModel):
    """Schema for brand threat response"""

    id: str = ""
    finding_id: str = ""
    organization_id: str = ""
    takedown_status: str = "identified"
    takedown_provider: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class BrandThreatListResponse(BaseModel):
    """Schema for paginated brand threat list"""

    items: list[BrandThreatResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class DarkWebExposureSummary(BaseModel):
    """Summary of organization's dark web exposure"""

    total_findings: int = 0
    critical_findings: int = 0
    exposed_credentials: int = 0
    exposed_domains: int = 0
    exposed_emails: int = 0
    brand_threats: int = 0
    remediated_credentials: int = 0
    pending_remediation: int = 0
    last_scan: Optional[str] = None


class CredentialStatistics(BaseModel):
    """Credential leak statistics"""

    total_credentials: int = 0
    by_password_type: dict[str, int]
    by_source: dict[str, int]
    crackable_credentials: int = 0
    plaintext_credentials: int = 0
    affected_users: int = 0
    remediation_rate: float = 0.0


class BrandThreatMap(BaseModel):
    """Brand threat mapping and statistics"""

    total_threats: int = 0
    by_threat_type: dict[str, int]
    by_takedown_status: dict[str, int]
    active_takedowns: int = 0
    completed_takedowns: int = 0
    failed_takedowns: int = 0


class TrendingThreats(BaseModel):
    """Trending threats in dark web"""

    threat_type: str = ""
    occurrences_last_7_days: int = 0
    occurrences_last_30_days: int = 0
    trend: str  # "rising", "stable", "declining"
    affected_industries: list[str]


class DarkWebDashboard(BaseModel):
    """Dark web monitoring dashboard"""

    exposure_summary: DarkWebExposureSummary
    credential_stats: CredentialStatistics
    brand_threat_map: BrandThreatMap
    trending_threats: list[TrendingThreats]
    monitored_items: int = 0
    active_monitors: int = 0
    scan_frequency: str = ""


class BulkFindingAction(BaseModel):
    """Schema for bulk finding actions"""

    finding_ids: list[str]
    action: str  # investigate, confirm, remediate, false_positive
    analyst_notes: Optional[str] = None


class BulkCredentialRemediateAction(BaseModel):
    """Schema for bulk credential remediation"""

    credential_ids: list[str]
    action: str  # password_reset, account_disabled, mfa_enforced
    send_notification: bool = True
    force_reset: bool = False


class CredentialRemediationReport(BaseModel):
    """Report on credential remediation"""

    total_affected: int = 0
    password_reset_sent: int = 0
    account_disabled: int = 0
    mfa_enforced: int = 0
    failed_actions: int = 0
    remediation_date: datetime
    estimated_completion: Optional[str] = None


class ScanTriggerRequest(BaseModel):
    """Request to trigger an immediate scan"""

    monitor_id: Optional[str] = None
    scan_type: str = Field(default="full", description="full or quick")


class ScanStatusResponse(BaseModel):
    """Response with scan status"""

    scan_id: str = ""
    monitor_id: Optional[str] = None
    status: str  # running, completed, failed
    start_time: str = ""
    completion_time: Optional[str] = None
    findings: int = 0
    new_findings: int = 0
