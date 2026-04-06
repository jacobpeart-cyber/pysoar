"""Threat Intelligence schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# ============================================================================
# THREAT FEED SCHEMAS
# ============================================================================


class ThreatFeedBase(BaseModel):
    """Base threat feed schema"""

    name: str = Field(..., min_length=1, max_length=255)
    feed_type: str = Field(..., description="Type: stix, csv, json, taxii, misp, openioc")
    url: Optional[str] = None
    provider: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    is_enabled: bool = True
    poll_interval_minutes: int = Field(default=60, ge=1, le=10080)
    confidence_weight: float = Field(default=1.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)


class ThreatFeedCreate(ThreatFeedBase):
    """Schema for creating a threat feed"""

    auth_type: Optional[str] = None
    auth_config: Optional[dict[str, Any]] = None


class ThreatFeedUpdate(BaseModel):
    """Schema for updating a threat feed"""

    name: Optional[str] = None
    feed_type: Optional[str] = None
    url: Optional[str] = None
    provider: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    poll_interval_minutes: Optional[int] = None
    confidence_weight: Optional[float] = None
    tags: Optional[list[str]] = None
    auth_type: Optional[str] = None
    auth_config: Optional[dict[str, Any]] = None


class ThreatFeedResponse(ThreatFeedBase, DBModel):
    """Schema for threat feed response"""

    id: str
    is_builtin: bool
    auth_type: Optional[str] = None
    last_poll_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_error: Optional[str] = None
    total_indicators: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ThreatFeedListResponse(BaseModel):
    """Schema for paginated threat feed list"""

    items: list[ThreatFeedResponse]
    total: int
    page: int
    size: int
    pages: int


# ============================================================================
# THREAT INDICATOR SCHEMAS
# ============================================================================


class ThreatIndicatorBase(BaseModel):
    """Base threat indicator schema"""

    indicator_type: str = Field(..., min_length=1, max_length=50)
    value: str = Field(..., min_length=1, max_length=2048)
    source: Optional[str] = None
    confidence: int = Field(default=50, ge=0, le=100)
    severity: str = Field(default="medium", description="critical, high, medium, low")
    tlp: str = Field(default="amber", description="white, green, amber, red")
    kill_chain_phase: Optional[str] = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None


class ThreatIndicatorCreate(ThreatIndicatorBase):
    """Schema for creating a threat indicator"""

    pass


class ThreatIndicatorUpdate(BaseModel):
    """Schema for updating a threat indicator"""

    indicator_type: Optional[str] = None
    value: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    severity: Optional[str] = None
    tlp: Optional[str] = None
    kill_chain_phase: Optional[str] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    context: Optional[dict[str, Any]] = None
    expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None
    is_whitelisted: Optional[bool] = None


class ThreatIndicatorResponse(ThreatIndicatorBase, DBModel):
    """Schema for threat indicator response"""

    id: str
    feed_id: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_active: bool
    is_whitelisted: bool
    sighting_count: int
    last_sighting_at: Optional[datetime] = None
    false_positive_count: int
    related_indicators: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ThreatIndicatorListResponse(BaseModel):
    """Schema for paginated threat indicator list"""

    items: list[ThreatIndicatorResponse]
    total: int
    page: int
    size: int
    pages: int


class BulkIndicatorImport(BaseModel):
    """Schema for bulk indicator import"""

    indicators: list[ThreatIndicatorCreate]
    feed_id: Optional[str] = None
    source: str


# ============================================================================
# THREAT ACTOR SCHEMAS
# ============================================================================


class ThreatActorBase(BaseModel):
    """Base threat actor schema"""

    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] = Field(default_factory=list)
    description: Optional[str] = None
    actor_type: str = Field(default="unknown", description="unknown, individual, group, organization")
    sophistication: str = Field(default="unknown", description="none, minimal, intermediate, advanced, expert")
    country_of_origin: Optional[str] = None
    primary_motivation: Optional[str] = None
    secondary_motivations: list[str] = Field(default_factory=list)
    mitre_groups: list[str] = Field(default_factory=list)
    known_ttps: list[str] = Field(default_factory=list)
    target_sectors: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)
    confidence: int = Field(default=50, ge=0, le=100)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ThreatActorCreate(ThreatActorBase):
    """Schema for creating a threat actor"""

    pass


class ThreatActorUpdate(BaseModel):
    """Schema for updating a threat actor"""

    name: Optional[str] = None
    aliases: Optional[list[str]] = None
    description: Optional[str] = None
    actor_type: Optional[str] = None
    sophistication: Optional[str] = None
    country_of_origin: Optional[str] = None
    primary_motivation: Optional[str] = None
    secondary_motivations: Optional[list[str]] = None
    mitre_groups: Optional[list[str]] = None
    known_ttps: Optional[list[str]] = None
    target_sectors: Optional[list[str]] = None
    target_countries: Optional[list[str]] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    references: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class ThreatActorResponse(ThreatActorBase, DBModel):
    """Schema for threat actor response"""

    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ThreatActorListResponse(BaseModel):
    """Schema for paginated threat actor list"""

    items: list[ThreatActorResponse]
    total: int
    page: int
    size: int
    pages: int


# ============================================================================
# THREAT CAMPAIGN SCHEMAS
# ============================================================================


class ThreatCampaignBase(BaseModel):
    """Base threat campaign schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    status: str = Field(default="ongoing", description="planning, ongoing, concluded")
    objectives: list[str] = Field(default_factory=list)
    target_sectors: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)
    associated_indicators: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: int = Field(default=50, ge=0, le=100)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ThreatCampaignCreate(ThreatCampaignBase):
    """Schema for creating a threat campaign"""

    actor_id: Optional[str] = None


class ThreatCampaignUpdate(BaseModel):
    """Schema for updating a threat campaign"""

    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    objectives: Optional[list[str]] = None
    target_sectors: Optional[list[str]] = None
    target_countries: Optional[list[str]] = None
    associated_indicators: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    references: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    actor_id: Optional[str] = None


class ThreatCampaignResponse(ThreatCampaignBase, DBModel):
    """Schema for threat campaign response"""

    id: str
    actor_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ThreatCampaignListResponse(BaseModel):
    """Schema for paginated threat campaign list"""

    items: list[ThreatCampaignResponse]
    total: int
    page: int
    size: int
    pages: int


# ============================================================================
# INTEL REPORT SCHEMAS
# ============================================================================


class IntelReportBase(BaseModel):
    """Base intel report schema"""

    title: str = Field(..., min_length=1, max_length=500)
    report_type: str = Field(..., description="threat_analysis, incident, attack_campaign, trend_analysis")
    tlp: str = Field(default="amber", description="white, green, amber, red")
    severity: str = Field(default="medium", description="critical, high, medium, low")
    executive_summary: str
    detailed_analysis: str
    recommendations: str
    associated_actors: list[str] = Field(default_factory=list)
    associated_campaigns: list[str] = Field(default_factory=list)
    associated_indicators: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_sectors: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class IntelReportCreate(IntelReportBase):
    """Schema for creating an intel report"""

    pass


class IntelReportUpdate(BaseModel):
    """Schema for updating an intel report"""

    title: Optional[str] = None
    report_type: Optional[str] = None
    tlp: Optional[str] = None
    severity: Optional[str] = None
    executive_summary: Optional[str] = None
    detailed_analysis: Optional[str] = None
    recommendations: Optional[str] = None
    associated_actors: Optional[list[str]] = None
    associated_campaigns: Optional[list[str]] = None
    associated_indicators: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    affected_sectors: Optional[list[str]] = None
    affected_products: Optional[list[str]] = None
    references: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    status: Optional[str] = None


class IntelReportResponse(IntelReportBase, DBModel):
    """Schema for intel report response"""

    id: str
    author_id: str
    status: str
    published_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class IntelReportListResponse(BaseModel):
    """Schema for paginated intel report list"""

    items: list[IntelReportResponse]
    total: int
    page: int
    size: int
    pages: int


# ============================================================================
# SIGHTING SCHEMAS
# ============================================================================


class IndicatorSightingCreate(BaseModel):
    """Schema for recording an indicator sighting"""

    indicator_id: str
    source: str
    sighting_type: str = Field(default="detected", description="detected, reported, confirmed")
    context: dict[str, Any] = Field(default_factory=dict)


class IndicatorSightingResponse(DBModel):
    """Schema for indicator sighting response"""

    id: str
    indicator_id: str
    source: Optional[str] = None
    sighting_type: str
    source_ref: Optional[str] = None
    raw_data: Optional[dict[str, Any]] = None
    context: dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# SEARCH AND DASHBOARD SCHEMAS
# ============================================================================


class IntelSearchRequest(BaseModel):
    """Schema for advanced intel search"""

    query: Optional[str] = None
    indicator_types: Optional[list[str]] = None
    severity: Optional[list[str]] = None
    tlp: Optional[list[str]] = None
    is_active: Optional[bool] = None
    tags: Optional[list[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    min_confidence: Optional[int] = Field(None, ge=0, le=100)


class IntelDashboardStats(BaseModel):
    """Schema for intel dashboard statistics"""

    total_indicators: int
    active_indicators: int
    feeds_enabled: int
    feeds_total: int
    indicators_by_type: dict[str, int]
    indicators_by_severity: dict[str, int]
    recent_sightings: int
    actors_tracked: int
    active_campaigns: int
    top_tags: list[str]
    coverage_score: float = Field(ge=0.0, le=100.0)
