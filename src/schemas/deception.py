"""
Pydantic schemas for Deception Technology module.

Request/response models for REST API endpoints.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Decoy Schemas


class DecoyBase(BaseModel):
    """Base schema for decoy models."""

    name: str = Field(..., min_length=1, max_length=255)
    decoy_type: str = Field(
        ...,
        description="honeypot, honeytoken, honeyfile, honeycred, honeydns, honeynet, canary_file, breadcrumb",
    )
    category: str = Field(
        ...,
        description="network, credential, file, dns, email, cloud, active_directory, database",
    )
    status: str = Field(
        default="inactive",
        description="inactive, deploying, active, triggered, disabled, compromised",
    )
    deployment_target: str | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    emulated_service: str | None = None
    emulated_os: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    fidelity_level: str = Field(
        default="medium", description="low, medium, high"
    )
    alert_on_interaction: bool = True
    capture_credentials: bool = True
    capture_payloads: bool = True
    tags: list[str] = Field(default_factory=list)


class DecoyDeployRequest(DecoyBase):
    """Request schema for deploying a decoy."""

    deployed_by: str | None = None
    organization_id: str


class DecoyResponse(DBModel):
    """Response schema for decoy."""

    id: UUID
    interaction_count: int
    last_interaction_at: datetime | None
    deployed_at: datetime | None
    deployed_by: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DecoyDetailResponse(DecoyResponse):
    """Detailed response schema for decoy with interactions."""

    recent_interactions: list["DecoyInteractionResponse"] = Field(
        default_factory=list
    )
    attacker_profiles: list[dict[str, Any]] = Field(default_factory=list)


# Decoy Interaction Schemas


class DecoyInteractionBase(BaseModel):
    """Base schema for decoy interactions."""

    decoy_id: str
    interaction_type: str = Field(
        ...,
        description="scan, connection, authentication, command, file_access, credential_use, dns_query, data_transfer",
    )
    source_ip: str
    source_port: int | None = None
    source_hostname: str | None = None
    source_user: str | None = None
    protocol: str | None = None
    credentials_captured: dict[str, Any] | None = None
    commands_captured: list[str] = Field(default_factory=list)
    payloads_captured: list[str] = Field(default_factory=list)
    files_accessed: list[str] = Field(default_factory=list)
    session_duration_seconds: int | None = None
    geo_location: dict[str, Any] | None = None
    threat_assessment: str = Field(
        default="high", description="critical, high, medium"
    )
    is_automated_scan: bool = False
    raw_traffic: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)


class DecoyInteractionResponse(DBModel):
    """Response schema for decoy interaction."""

    id: UUID
    alert_generated: bool
    alert_id: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class InteractionAnalysisResponse(BaseModel):
    """Response for interaction analysis."""

    interaction_id: UUID
    interaction_type: str
    threat_level: str
    is_automated: bool
    tools_detected: list[str]
    techniques: list[str]
    skill_level: str
    objectives: list[str]
    confidence: float


# Honey Token Schemas


class HoneyTokenBase(BaseModel):
    """Base schema for honey tokens."""

    name: str = Field(..., min_length=1, max_length=255)
    token_type: str = Field(
        ...,
        description="aws_key, api_key, database_cred, jwt_token, ssh_key, certificate, dns_canary, url_canary, email_canary, document_beacon",
    )
    token_value: str
    deployment_location: str | None = None
    deployment_context: str | None = None
    status: str = Field(
        default="active", description="active, triggered, expired, disabled"
    )
    expires_at: datetime | None = None
    alert_severity: str = Field(default="critical")
    notification_channels: list[str] = Field(default_factory=list)


class HoneyTokenGenerateRequest(BaseModel):
    """Request schema for generating honey token."""

    token_type: str = Field(
        ...,
        description="aws_key, api_key, database_cred, jwt_token, ssh_key, dns_canary, url_canary, email_canary, document_beacon",
    )
    service: str | None = None
    db_type: str | None = None
    domain: str | None = None
    doc_type: str | None = None
    doc_title: str | None = None
    organization_id: str
    deployed_by: str | None = None


class HoneyTokenGenerateResponse(DBModel):
    """Response schema for generated honey token."""

    id: UUID
    token_hash: str
    triggered_count: int
    last_triggered_at: datetime | None
    last_triggered_by: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class HoneyTokenResponse(HoneyTokenGenerateResponse):
    """Response schema for honey token."""

    pass


class HoneyTokenCheckResponse(BaseModel):
    """Response for token usage check."""

    token_id: UUID
    token_hash: str
    has_been_used: bool
    triggered_count: int
    last_triggered_at: datetime | None
    last_triggered_by: str | None


# Campaign Schemas


class DeceptionCampaignBase(BaseModel):
    """Base schema for deception campaign."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    objective: str = Field(
        ...,
        description="detect_lateral_movement, detect_insider, detect_reconnaissance, detect_data_theft, general_detection",
    )
    coverage_zones: list[str] = Field(default_factory=list)


class DeceptionCampaignCreateRequest(DeceptionCampaignBase):
    """Request schema for creating campaign."""

    decoy_configs: list[dict[str, Any]] = Field(default_factory=list)
    organization_id: str
    created_by: str


class DeceptionCampaignResponse(DBModel):
    """Response schema for campaign."""

    id: UUID
    status: str
    decoy_ids: list[str]
    total_interactions: int
    unique_attackers: int
    started_at: datetime | None
    completed_at: datetime | None
    effectiveness_score: float | None
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DeceptionCampaignDetailResponse(DeceptionCampaignResponse):
    """Detailed response for campaign with findings."""

    findings: list[dict[str, Any]]
    decoys: list[DecoyResponse] = Field(default_factory=list)


class CampaignStatusUpdateRequest(BaseModel):
    """Request schema for updating campaign status."""

    status: str = Field(..., description="active, paused, completed")


class CampaignEffectivenessResponse(BaseModel):
    """Response for campaign effectiveness assessment."""

    campaign_id: UUID
    name: str
    objective: str
    status: str
    effectiveness_score: float
    coverage_percentage: float
    total_interactions: int
    unique_attackers: int
    attacks_detected: int
    false_positives: int
    detection_rate: float
    mean_time_to_detection: float
    recommendations: list[str]


# Dashboard Schemas


class DeceptionDashboardStats(BaseModel):
    """Dashboard statistics for deception module."""

    total_decoys: int
    active_decoys: int
    disabled_decoys: int
    total_honeytokens: int
    active_tokens: int
    triggered_tokens: int
    active_campaigns: int
    completed_campaigns: int
    interactions_today: int
    interactions_this_week: int
    unique_attackers_today: int
    unique_attackers_this_week: int
    high_severity_interactions: int
    critical_interactions: int
    average_interaction_response_time_seconds: float


class DeceptionDashboardResponse(BaseModel):
    """Complete dashboard response."""

    stats: DeceptionDashboardStats
    recent_interactions: list[DecoyInteractionResponse] = Field(default_factory=list)
    active_campaigns: list[DeceptionCampaignResponse] = Field(default_factory=list)
    top_attacker_profiles: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# Coverage Schemas


class CoverageZoneInfo(BaseModel):
    """Information about deception coverage in a zone."""

    zone_name: str
    covered: bool
    decoy_count: int
    decoy_types: list[str] = Field(default_factory=list)
    last_interaction: datetime | None = None


class CoverageMapResponse(BaseModel):
    """Network coverage map for deception infrastructure."""

    zones: dict[str, CoverageZoneInfo]
    total_zones: int
    covered_zones: int
    total_coverage_percentage: float
    gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# Recommendations Schemas


class DeploymentRecommendation(BaseModel):
    """Recommendation for decoy deployment."""

    zone: str
    decoy_type: str
    service: str | None = None
    location: str | None = None
    filename: str | None = None
    purpose: str
    priority: str = Field(default="medium", description="high, medium, low")
    estimated_value: str = Field(
        default="high", description="Potential detection value"
    )


class RecommendationsResponse(BaseModel):
    """Recommendations for improving deception coverage."""

    recommendations: list[DeploymentRecommendation]
    coverage_gaps: list[str]
    high_priority_items: list[DeploymentRecommendation]


# Interaction Timeline Schema


class InteractionTimelineEntry(BaseModel):
    """Single entry in interaction timeline."""

    timestamp: datetime
    interaction_id: UUID
    decoy_id: UUID
    decoy_name: str
    source_ip: str
    interaction_type: str
    threat_level: str
    description: str


class InteractionTimelineResponse(BaseModel):
    """Timeline of interactions for analysis."""

    decoy_id: UUID
    entries: list[InteractionTimelineEntry]
    total_count: int
    time_span_hours: int


# Investigation Schemas


class InteractionInvestigationRequest(BaseModel):
    """Request deep investigation of interaction."""

    include_correlation: bool = True
    include_threat_intel: bool = True
    generate_report: bool = True


class InteractionInvestigationResponse(BaseModel):
    """Detailed investigation results."""

    interaction_id: UUID
    analysis: InteractionAnalysisResponse
    correlated_interactions: list[DecoyInteractionResponse] = Field(
        default_factory=list
    )
    attacker_profile: dict[str, Any]
    threat_intel_matches: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    report_url: str | None = None
