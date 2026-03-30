"""
UEBA Database Models
Defines the data structures for user and entity behavior analytics.
"""

from typing import Any
from datetime import datetime
from sqlalchemy import String, Float, Integer, Boolean, Text, DateTime, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, BaseModel, generate_uuid, utc_now


class EntityProfile(BaseModel):
    """
    Profile for a user or entity being monitored for behavior analytics.
    Tracks identity, risk assessment, and behavioral baselines.
    """

    __tablename__ = "entity_profiles"

    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    """Type of entity: user, host, service_account, application"""

    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    """Unique identifier: username, hostname, service account name, etc."""

    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Human-readable name for the entity"""

    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Department or organizational unit"""

    role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Job role or function"""

    manager: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Manager or administrator"""

    peer_group: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Assigned peer group for comparison"""

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    """Current risk score (0-100)"""

    risk_level: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    """Risk level: critical, high, medium, low"""

    baseline_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Normal behavior patterns baseline"""

    current_behavior: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Recent activity summary"""

    anomaly_count_30d: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    """Anomaly count in last 30 days"""

    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    """Timestamp of last recorded activity"""

    last_anomaly_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    """Timestamp of last detected anomaly"""

    is_watched: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    """Flag indicating if entity is on watchlist"""

    watch_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Reason for adding to watchlist"""

    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    """Custom tags for categorization"""

    metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Additional metadata"""

    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    """Organization the entity belongs to"""

    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", "organization_id", name="uix_entity_profile"),
    )


class BehaviorBaseline(BaseModel):
    """
    Statistical baseline for normal entity behavior.
    Used to detect anomalies through deviation analysis.
    """

    __tablename__ = "behavior_baselines"

    entity_profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("entity_profiles.id"), nullable=False
    )
    """Reference to the entity profile"""

    behavior_type: Mapped[str] = mapped_column(String(100), nullable=False)
    """Type of behavior: login_pattern, access_pattern, network_activity, etc."""

    baseline_period_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    """Number of days used to build the baseline"""

    statistical_model: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Statistical parameters: mean, std, quartiles, distribution params"""

    typical_values: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    """Common values observed in baseline period"""

    time_patterns: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Hourly, daily, weekly pattern data"""

    peer_comparison: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Percentile rankings vs peer group"""

    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    """Confidence in baseline (0-1), increases with data volume"""

    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    """Number of samples used to build baseline"""

    last_updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    """When baseline was last recalculated"""


class BehaviorEvent(BaseModel):
    """
    Individual behavior event for an entity.
    Represents a specific activity that can be analyzed for anomalies.
    """

    __tablename__ = "behavior_events"

    entity_profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("entity_profiles.id"), nullable=False
    )
    """Reference to the entity profile"""

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    """Type of event: authentication, resource_access, network_connection, etc."""

    event_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Raw event data and context"""

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    """Source IP address (IPv4 or IPv6)"""

    destination: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Destination host, IP, or resource"""

    geo_location: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    """Geolocation data: country, city, coordinates"""

    device_info: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    """Device information: OS, browser, device type"""

    risk_contribution: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    """How much this event contributed to entity risk score"""

    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    """Whether event was flagged as anomalous"""

    anomaly_reasons: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    """Reasons why event was anomalous"""

    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    """Organization context for multi-tenancy"""


class UEBARiskAlert(BaseModel):
    """
    Alert generated from UEBA analysis.
    Represents a detected threat or suspicious behavior.
    """

    __tablename__ = "ueba_risk_alerts"

    entity_profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("entity_profiles.id"), nullable=False
    )
    """Reference to the entity profile"""

    alert_type: Mapped[str] = mapped_column(String(100), nullable=False)
    """Type of alert: impossible_travel, unusual_access_time, privilege_abuse, etc."""

    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    """Severity level: critical, high, medium, low"""

    risk_score_delta: Mapped[float] = mapped_column(Float, nullable=False)
    """How much this alert raised the entity's risk score"""

    description: Mapped[str] = mapped_column(Text, nullable=False)
    """Human-readable description of the alert"""

    evidence: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    """Supporting evidence and details"""

    contributing_events: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    """IDs of behavior events that triggered alert"""

    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    """MITRE ATT&CK techniques relevant to alert"""

    status: Mapped[str] = mapped_column(String(50), default="new", nullable=False)
    """Alert status: new, investigating, confirmed, dismissed"""

    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Notes added by security analysts"""

    escalated_to_incident: Mapped[str | None] = mapped_column(String(36), nullable=True)
    """Reference to escalated incident ID, if any"""

    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    """Organization context for multi-tenancy"""


class PeerGroup(BaseModel):
    """
    Grouping of entities for comparative behavior analysis.
    Enables detection of outliers within peer populations.
    """

    __tablename__ = "peer_groups"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    """Name of the peer group"""

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Description of the group's purpose"""

    group_type: Mapped[str] = mapped_column(String(50), nullable=False)
    """Type: department, role, custom, auto_clustered"""

    member_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    """Current number of members"""

    baseline_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    """Aggregate baseline for peer group"""

    risk_threshold: Mapped[float] = mapped_column(Float, default=70.0, nullable=False)
    """Risk threshold for peer group members"""

    members: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    """List of entity_profile IDs in group"""

    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    """Organization that owns the peer group"""
