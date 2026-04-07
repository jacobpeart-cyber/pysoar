"""
Pydantic schemas for Phishing Simulation & Security Awareness module.

Request/response models for REST API endpoints with Base/Create/Update/Response pattern.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# ============================================================================
# PHISHING TEMPLATE SCHEMAS
# ============================================================================


class PhishingTemplateBase(BaseModel):
    """Base schema for phishing templates."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    category: str = Field(
        ...,
        description="credential_harvest, malware_attachment, link_click, data_entry, callback_phishing, mfa_bypass, qr_code",
    )
    difficulty: str = Field(..., description="beginner, intermediate, advanced, expert")
    subject_line: str = Field(..., min_length=1, max_length=255)
    sender_name: str = Field(..., min_length=1, max_length=255)
    sender_email: str = Field(..., min_length=1, max_length=255)
    html_body: str = Field(..., min_length=1)
    text_body: str | None = None
    landing_page_html: str | None = None
    has_attachment: bool = False
    attachment_name: str | None = None
    indicators_of_phishing: list[str] = Field(default_factory=list)
    training_content_on_fail: str | None = None
    language: str = Field(default="en", max_length=10)
    is_seasonal: bool = False


class PhishingTemplateCreateRequest(PhishingTemplateBase):
    """Request schema for creating a phishing template."""

    organization_id: Optional[str] = None


class PhishingTemplateUpdateRequest(BaseModel):
    """Request schema for updating a phishing template."""

    name: str | None = None
    description: str | None = None
    category: str | None = None
    difficulty: str | None = None
    subject_line: str | None = None
    sender_name: str | None = None
    sender_email: str | None = None
    html_body: str | None = None
    text_body: str | None = None
    landing_page_html: str | None = None
    has_attachment: bool | None = None
    attachment_name: str | None = None
    indicators_of_phishing: list[str] | None = None
    training_content_on_fail: str | None = None
    language: str | None = None
    is_seasonal: bool | None = None


class PhishingTemplateResponse(PhishingTemplateBase, DBModel):
    """Response schema for phishing template."""

    id: UUID
    usage_count: int
    average_click_rate: float
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# TARGET GROUP SCHEMAS
# ============================================================================


class TargetMember(BaseModel):
    """Schema for target group member."""

    name: str
    email: str
    role: str | None = None
    department: str | None = None


class TargetGroupBase(BaseModel):
    """Base schema for target groups."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    department: str | None = None
    members: list[TargetMember] = Field(default_factory=list)


class TargetGroupCreateRequest(TargetGroupBase):
    """Request schema for creating a target group."""

    organization_id: Optional[str] = None


class TargetGroupUpdateRequest(BaseModel):
    """Request schema for updating a target group."""

    name: str | None = None
    description: str | None = None
    department: str | None = None
    members: list[TargetMember] | None = None


class TargetGroupResponse(TargetGroupBase, DBModel):
    """Response schema for target group."""

    id: UUID
    member_count: int
    risk_level: str
    avg_click_rate: float
    campaigns_participated: int
    last_campaign_date: datetime | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# PHISHING CAMPAIGN SCHEMAS
# ============================================================================


class SendSchedule(BaseModel):
    """Campaign sending schedule configuration."""

    batch_size: int = Field(default=50, ge=1)
    interval_hours: int = Field(default=1, ge=0)
    send_all_at_once: bool = False


class PhishingCampaignBase(BaseModel):
    """Base schema for phishing campaigns."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    campaign_type: str = Field(
        ...,
        description="email_phishing, spear_phishing, smishing, vishing, usb_drop, qr_code, social_media, business_email_compromise",
    )
    template_id: str | None = None
    target_group_id: str | None = None
    send_schedule: SendSchedule = Field(default_factory=SendSchedule)
    difficulty_level: str = Field(default="intermediate", description="beginner, intermediate, advanced, expert")


class PhishingCampaignCreateRequest(PhishingCampaignBase):
    """Request schema for creating a campaign."""

    organization_id: Optional[str] = None


class PhishingCampaignUpdateRequest(BaseModel):
    """Request schema for updating a campaign."""

    name: str | None = None
    description: str | None = None
    campaign_type: str | None = None
    template_id: str | None = None
    target_group_id: str | None = None
    send_schedule: SendSchedule | None = None
    difficulty_level: str | None = None


class PhishingCampaignResponse(PhishingCampaignBase, DBModel):
    """Response schema for phishing campaign."""

    id: UUID
    status: str
    start_date: datetime | None
    end_date: datetime | None
    total_targets: int
    emails_sent: int
    emails_opened: int
    links_clicked: int
    credentials_submitted: int
    attachments_opened: int
    reported_count: int
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CampaignMetrics(BaseModel):
    """Campaign performance metrics."""

    open_rate: float
    click_rate: float
    submission_rate: float
    report_rate: float
    attachment_open_rate: float
    vulnerability_index: float
    security_score: float
    duration_hours: float


class CampaignDetailResponse(PhishingCampaignResponse):
    """Detailed campaign response with metrics."""

    metrics: CampaignMetrics | None = None


class CampaignLaunchRequest(BaseModel):
    """Request schema for launching a campaign."""

    total_targets: int = Field(..., ge=1)


class CampaignScheduleRequest(BaseModel):
    """Request schema for scheduling a campaign."""

    start_time: datetime


# ============================================================================
# CAMPAIGN EVENT SCHEMAS
# ============================================================================


class CampaignEventBase(BaseModel):
    """Base schema for campaign events."""

    target_email: str
    target_name: str | None = None
    event_type: str = Field(
        ...,
        description="email_sent, email_delivered, email_bounced, email_opened, link_clicked, credential_submitted, attachment_opened, reported_as_phishing, training_started, training_completed, email_forwarded",
    )


class CampaignEventCreateRequest(CampaignEventBase):
    """Request schema for recording a campaign event."""

    ip_address: str | None = None
    user_agent: str | None = None
    geo_location: dict[str, Any] | None = None
    device_type: str | None = None
    time_to_action_seconds: int | None = None


class CampaignEventResponse(CampaignEventBase, DBModel):
    """Response schema for campaign event."""

    id: UUID
    campaign_id: str
    event_timestamp: datetime
    ip_address: str | None
    user_agent: str | None
    geo_location: dict[str, Any] | None
    device_type: str | None
    time_to_action_seconds: int | None
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# SECURITY AWARENESS SCORE SCHEMAS
# ============================================================================


class TrainingAssignment(BaseModel):
    """Training assignment status."""

    module: str
    status: str  # assigned, in_progress, completed
    completion_date: datetime | None = None


class Certification(BaseModel):
    """User certification."""

    name: str
    completed_at: datetime
    valid_until: datetime


class SecurityAwarenessScoreBase(BaseModel):
    """Base schema for awareness scores."""

    user_email: str
    user_name: str
    department: str | None = None


class SecurityAwarenessScoreResponse(SecurityAwarenessScoreBase, DBModel):
    """Response schema for security awareness score."""

    id: UUID
    overall_score: int
    phishing_score: int
    training_completion_rate: float
    campaigns_participated: int
    times_clicked: int
    times_reported: int
    times_submitted_credentials: int
    last_failed_campaign: datetime | None
    risk_category: str
    training_assignments: list[TrainingAssignment]
    certifications: list[Certification]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserScoreCalculationRequest(BaseModel):
    """Request to calculate user score."""

    reported: int = 0
    no_action: int = 0
    clicked: int = 0
    submitted_credentials: int = 0
    training_completed: int = 0


# ============================================================================
# TRAINING SCHEMAS
# ============================================================================


class TrainingModuleResponse(BaseModel):
    """Training module information."""

    id: str
    title: str
    description: str
    duration_minutes: int
    modules: list[str]


class TrainingAssignmentRequest(BaseModel):
    """Request to assign training."""

    module_names: list[str]
    reason: str | None = None


class TrainingCompletionRequest(BaseModel):
    """Request to track training completion."""

    module_name: str
    completion_time_minutes: int


class TrainingCertificateResponse(BaseModel):
    """Training certificate."""

    id: UUID
    user_email: str
    user_name: str
    module: str
    issued_at: datetime
    valid_until: datetime
    certificate_number: str


# ============================================================================
# DASHBOARD & REPORTING SCHEMAS
# ============================================================================


class DepartmentStats(BaseModel):
    """Department statistics."""

    department: str
    user_count: int
    avg_score: float
    avg_phishing_score: float
    min_score: float
    max_score: float
    risk_distribution: dict[str, int]


class RiskReport(BaseModel):
    """Risk assessment report."""

    total_users: int
    total_departments: int
    avg_score: float
    risk_distribution: dict[str, int]
    high_risk_users: list[SecurityAwarenessScoreResponse]
    critical_risk_users: list[SecurityAwarenessScoreResponse]
    top_departments: list[DepartmentStats]


class IndustryBenchmark(BaseModel):
    """Industry benchmark comparison."""

    organization_click_rate: float
    industry_average: float
    vs_industry: str  # below_average, above_average
    percentile: str  # top_25, top_50, bottom_50, bottom_25


class CampaignComparisonResponse(BaseModel):
    """Campaign comparison data."""

    campaign_id: str
    campaign_name: str
    status: str
    click_rate: float
    submission_rate: float
    report_rate: float
    difficulty_level: str
    target_count: int


class DashboardResponse(BaseModel):
    """Phishing simulation dashboard data."""

    total_campaigns: int
    active_campaigns: int
    completed_campaigns: int
    avg_click_rate: float
    avg_submission_rate: float
    total_users_at_risk: int
    high_risk_count: int
    critical_risk_count: int
    recent_campaigns: list[CampaignComparisonResponse]
    department_stats: list[DepartmentStats]
    risk_distribution: dict[str, int]
    industry_benchmark: IndustryBenchmark


# ============================================================================
# TEMPLATE RENDERING & VALIDATION
# ============================================================================


class RenderedTemplate(BaseModel):
    """Rendered template with personalization."""

    subject_line: str
    html_body: str
    sender_name: str
    sender_email: str


class TemplateValidationResult(BaseModel):
    """Template validation results."""

    template_id: str
    is_valid: bool
    issues: list[str]
    placeholders_found: list[str]
    links_found: int


class TemplateEffectivenessResponse(BaseModel):
    """Template effectiveness metrics."""

    template_id: str
    name: str
    usage_count: int
    average_click_rate: float
    category: str
    difficulty: str
    effectiveness_rating: str
