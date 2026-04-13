"""
UEBA Pydantic Schemas
Request/response schemas for UEBA API endpoints.
"""

from datetime import datetime
from typing import Optional
from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# ============================================================================
# Entity Profile Schemas
# ============================================================================

class EntityProfileBase(BaseModel):
    """Base schema for entity profile."""

    entity_type: str = Field(..., description="Type: user, host, service_account, application")
    entity_id: str = Field(..., description="Unique identifier")
    display_name: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    manager: Optional[str] = None
    peer_group: Optional[str] = None
    is_watched: bool = False
    watch_reason: Optional[str] = None
    tags: list = Field(default_factory=list)
    # Field name `metadata` collides with SQLAlchemy Base.metadata; mirror
    # the model attribute name so getattr resolves to the JSON column.
    extra_metadata: dict = Field(default_factory=dict)


class EntityProfileCreate(EntityProfileBase):
    """Schema for creating entity profile."""

    pass


class EntityProfileUpdate(BaseModel):
    """Schema for updating entity profile."""

    entity_type: Optional[str] = None
    display_name: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    manager: Optional[str] = None
    peer_group: Optional[str] = None
    is_watched: Optional[bool] = None
    watch_reason: Optional[str] = None
    tags: Optional[list] = None
    extra_metadata: Optional[dict] = None


class EntityProfileResponse(EntityProfileBase, DBModel):
    """Response schema for entity profile with full details."""

    id: str = ""
    risk_score: float = 0.0
    risk_level: str = ""
    baseline_data: dict
    current_behavior: dict
    anomaly_count_30d: int = 0
    last_activity_at: Optional[datetime] = None
    last_anomaly_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============================================================================
# Behavior Baseline Schemas
# ============================================================================

class BehaviorBaselineResponse(DBModel):
    """Response schema for behavior baseline."""

    id: str = ""
    entity_profile_id: str = ""
    behavior_type: str = ""
    baseline_period_days: int = 0
    statistical_model: dict
    typical_values: list
    time_patterns: dict
    peer_comparison: dict
    confidence: float = 0.0
    sample_count: int = 0
    last_updated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============================================================================
# Behavior Event Schemas
# ============================================================================

class BehaviorEventBase(BaseModel):
    """Base schema for behavior event."""

    entity_id: str = ""
    event_type: str = Field(..., description="Type: authentication, resource_access, network_connection, etc.")
    event_data: dict
    source_ip: Optional[str] = None
    destination: Optional[str] = None
    geo_location: Optional[dict] = None
    device_info: Optional[dict] = None


class BehaviorEventCreate(BehaviorEventBase):
    """Schema for creating behavior event."""

    pass


class BehaviorEventResponse(BehaviorEventBase, DBModel):
    """Response schema for behavior event."""

    id: str = ""
    entity_profile_id: str = ""
    risk_contribution: float = 0.0
    is_anomalous: bool = False
    anomaly_reasons: list
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class BehaviorEventBatch(BaseModel):
    """Schema for batch behavior event ingestion."""

    events: list[BehaviorEventCreate] = Field(..., min_items=1, max_items=1000)


# ============================================================================
# UEBA Risk Alert Schemas
# ============================================================================

class UEBARiskAlertBase(BaseModel):
    """Base schema for UEBA risk alert."""

    entity_id: str = ""
    alert_type: str = ""
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    description: str = ""
    evidence: list = Field(default_factory=list)
    mitre_techniques: list = Field(default_factory=list)


class UEBARiskAlertCreate(UEBARiskAlertBase):
    """Schema for creating UEBA alert."""

    risk_score_delta: float = 0.0
    contributing_events: list = Field(default_factory=list)


class UEBARiskAlertUpdate(BaseModel):
    """Schema for updating UEBA alert."""

    status: Optional[str] = None
    analyst_notes: Optional[str] = None
    escalated_to_incident: Optional[str] = None


class UEBARiskAlertResponse(UEBARiskAlertBase, DBModel):
    """Response schema for UEBA risk alert."""

    id: str = ""
    entity_profile_id: str = ""
    risk_score_delta: float = 0.0
    contributing_events: list
    status: str = ""
    analyst_notes: Optional[str] = None
    escalated_to_incident: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============================================================================
# Peer Group Schemas
# ============================================================================

class PeerGroupBase(BaseModel):
    """Base schema for peer group."""

    name: str = ""
    description: Optional[str] = None
    group_type: str = Field(..., description="Type: department, role, custom, auto_clustered")
    risk_threshold: float = 70.0


class PeerGroupCreate(PeerGroupBase):
    """Schema for creating peer group."""

    pass


class PeerGroupResponse(PeerGroupBase, DBModel):
    """Response schema for peer group."""

    id: str = ""
    member_count: int = 0
    baseline_data: dict
    members: list
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============================================================================
# Risk Analysis Schemas
# ============================================================================

class RiskFactorResponse(BaseModel):
    """Schema for risk factor breakdown."""

    factor: str = ""
    count: int = 0
    contribution: float = 0.0


class RiskTrendPoint(BaseModel):
    """Schema for single point in risk trend."""

    date: str = ""
    risk_score: float = 0.0


class EntityRiskResponse(BaseModel):
    """Response schema for entity risk detail."""

    entity_id: str = ""
    risk_score: float = 0.0
    risk_level: str = ""
    risk_factors: list[RiskFactorResponse]
    risk_trend: list[RiskTrendPoint]
    updated_at: Optional[datetime] = None


# ============================================================================
# Timeline Schemas
# ============================================================================

class BehaviorTimelineEvent(BaseModel):
    """Schema for event in behavior timeline."""

    id: str = ""
    event_type: str = ""
    timestamp: datetime
    description: str = ""
    is_anomalous: bool = False
    anomaly_reasons: list
    risk_contribution: float = 0.0


class BehaviorTimelineResponse(BaseModel):
    """Response schema for behavior timeline."""

    entity_id: str = ""
    event_count: int = 0
    anomaly_count: int = 0
    events: list[BehaviorTimelineEvent]


# ============================================================================
# Peer Comparison Schemas
# ============================================================================

class PercentileComparison(BaseModel):
    """Schema for percentile comparison metric."""

    metric: str = ""
    entity_value: float = 0.0
    peer_average: float = 0.0
    percentile: float = 0.0


class PeerComparisonResponse(BaseModel):
    """Response schema for peer comparison."""

    entity_id: str = ""
    peer_group_id: str = ""
    peer_group_name: str = ""
    member_count: int = 0
    comparisons: list[PercentileComparison]
    deviations: list[dict]


# ============================================================================
# Dashboard Schemas
# ============================================================================

class RiskDistribution(BaseModel):
    """Schema for risk level distribution."""

    level: str = ""
    count: int = 0
    percentage: float = 0.0


class AlertDistribution(BaseModel):
    """Schema for alert type distribution."""

    alert_type: str = ""
    count: int = 0
    percentage: float = 0.0


class HighRiskEntity(BaseModel):
    """Schema for high risk entity in dashboard."""

    id: str = ""
    entity_id: str = ""
    entity_type: str = ""
    risk_score: float = 0.0
    risk_level: str = ""
    latest_alert: Optional[str] = None
    last_anomaly_at: Optional[datetime] = None


class UEBADashboardStats(BaseModel):
    """Response schema for UEBA dashboard."""

    total_entities: int = 0
    watched_entities: int = 0
    high_risk_entities: list[HighRiskEntity]
    risk_distribution: list[RiskDistribution]
    alert_distribution: list[AlertDistribution]
    alerts_last_7d: int = 0
    alerts_last_30d: int = 0
    anomalies_last_7d: int = 0
    anomalies_last_30d: int = 0
    updated_at: datetime


# ============================================================================
# Risk Heatmap Schemas
# ============================================================================

class RiskHeatmapCell(BaseModel):
    """Schema for single heatmap cell."""

    entity_type: str = ""
    risk_level: str = ""
    count: int = 0
    percentage: float = 0.0


class RiskHeatmapResponse(BaseModel):
    """Response schema for risk heatmap."""

    heatmap_data: list[RiskHeatmapCell]
    total_entities: int = 0
    generated_at: Optional[datetime] = None


# ============================================================================
# Batch Ingestion Response
# ============================================================================

class BatchIngestionResponse(BaseModel):
    """Response schema for batch event ingestion."""

    total_events: int = 0
    processed_events: int = 0
    failed_events: int = 0
    anomalies_detected: int = 0
    alerts_created: int = 0
    processing_time_ms: float = 0.0


# ============================================================================
# List Query Schemas
# ============================================================================

class EntityListFilter(BaseModel):
    """Query filters for entity list."""

    entity_type: Optional[str] = None
    risk_level: Optional[str] = None
    is_watched: Optional[bool] = None
    department: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0


class AlertListFilter(BaseModel):
    """Query filters for alert list."""

    alert_type: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0


class EventListFilter(BaseModel):
    """Query filters for event list."""

    entity_id: Optional[str] = None
    event_type: Optional[str] = None
    is_anomalous: Optional[bool] = None
    source_ip: Optional[str] = None
    destination: Optional[str] = None
    days: int = 7
    limit: int = 100
    offset: int = 0
