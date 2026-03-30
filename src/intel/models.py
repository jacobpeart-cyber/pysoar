"""SQLAlchemy models for Threat Intelligence Platform"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel, utc_now


class ThreatFeed(BaseModel):
    """Threat feed source model for ingesting threat intelligence data"""

    __tablename__ = "threat_feeds"

    # Basic information
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    feed_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # stix, csv, json, taxii, misp, openioc
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provider: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status and configuration
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Authentication
    auth_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # none, api_key, basic, oauth, certificate
    auth_config: Mapped[Optional[dict]] = mapped_column(
        JSON, nullable=True
    )  # encrypted credentials reference

    # Polling configuration
    poll_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_poll_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Statistics
    total_indicators: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence_weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    # Metadata
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Organization association
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    # Relationships
    indicators: Mapped[list["ThreatIndicator"]] = relationship(
        "ThreatIndicator",
        back_populates="feed",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ThreatFeed {self.name} ({self.feed_type})>"


class ThreatIndicator(BaseModel):
    """Threat indicator/IOC model with enrichment data"""

    __tablename__ = "threat_indicators"
    __table_args__ = (
        Index("ix_indicator_type_value", "indicator_type", "value"),
        Index("ix_indicator_value", "value"),
        Index("ix_indicator_active", "is_active"),
        Index("ix_indicator_expires", "expires_at"),
    )

    # Core indicator data
    indicator_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # ipv4, ipv6, domain, url, md5, sha1, sha256, email, filename, mutex, registry_key, user_agent, cidr, asn, cve
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    # Feed association
    feed_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("threat_feeds.id"), nullable=True
    )

    # Source and validity
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # 0-100 confidence score
    severity: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )  # critical, high, medium, low, informational
    tlp: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )  # red, amber+strict, amber, green, clear

    # Temporal information
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # MITRE ATT&CK mapping
    kill_chain_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_tactics: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Enrichment and relationships
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    context: Mapped[dict] = mapped_column(
        JSON, default=dict, nullable=False
    )  # additional enrichment data
    related_indicators: Mapped[list] = mapped_column(
        JSON, default=list, nullable=False
    )  # list of related indicator IDs

    # Sighting tracking
    sighting_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_sighting_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Organization association
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    # Relationships
    feed: Mapped[Optional["ThreatFeed"]] = relationship("ThreatFeed", back_populates="indicators")
    sightings: Mapped[list["IndicatorSighting"]] = relationship(
        "IndicatorSighting",
        back_populates="indicator",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ThreatIndicator {self.indicator_type}:{self.value[:50]}>"


class ThreatActor(BaseModel):
    """Threat actor/group model for tracking known adversaries"""

    __tablename__ = "threat_actors"

    # Basic information
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    aliases: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Classification
    actor_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # apt, criminal, hacktivist, insider, nation_state, unknown
    sophistication: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # none, minimal, intermediate, advanced, expert, innovator
    country_of_origin: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Temporal information
    first_observed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_observed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Motivation and behavior
    primary_motivation: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    secondary_motivations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # MITRE ATT&CK mappings
    mitre_groups: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # MITRE ATT&CK group IDs
    known_ttps: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # technique IDs

    # Targeting information
    target_sectors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    target_countries: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    associated_campaigns: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Assessment
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # external report URLs
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Organization association
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    # Relationships
    campaigns: Mapped[list["ThreatCampaign"]] = relationship(
        "ThreatCampaign",
        back_populates="actor",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ThreatActor {self.name}>"


class ThreatCampaign(BaseModel):
    """Threat campaign model for correlating indicators and actors"""

    __tablename__ = "threat_campaigns"

    # Basic information
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status
    status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # active, inactive, historic

    # Actor association
    actor_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("threat_actors.id"), nullable=True
    )

    # Temporal information
    first_observed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_observed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Campaign details
    objectives: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    target_sectors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    target_countries: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Related data
    associated_indicators: Mapped[list] = mapped_column(
        JSON, default=list, nullable=False
    )  # indicator IDs
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Assessment
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Organization association
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    # Relationships
    actor: Mapped[Optional["ThreatActor"]] = relationship("ThreatActor", back_populates="campaigns")

    def __repr__(self) -> str:
        return f"<ThreatCampaign {self.name}>"


class IntelReport(BaseModel):
    """Threat intelligence report model"""

    __tablename__ = "intel_reports"

    # Basic information
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    report_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # threat_assessment, campaign_analysis, actor_profile, vulnerability_advisory, situational_awareness, flash_alert

    # Classification
    tlp: Mapped[str] = mapped_column(String(20), default="amber", nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)

    # Content
    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detailed_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Associated data
    associated_actors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    associated_campaigns: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    associated_indicators: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Impact information
    affected_sectors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    affected_products: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # References and metadata
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Authorship and lifecycle
    author_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # draft, review, published, archived
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Organization association
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<IntelReport {self.title[:50]}>"


class IndicatorSighting(BaseModel):
    """Indicator sighting record for tracking when indicators are detected"""

    __tablename__ = "indicator_sightings"

    # Indicator reference
    indicator_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("threat_indicators.id"), nullable=False
    )

    # Sighting source
    source: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # where the sighting occurred (SIEM, firewall, etc.)
    source_ref: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # reference ID in source system

    # Sighting type
    sighting_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # detected, blocked, allowed, correlated

    # Context and raw data
    context: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Organization association
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    # Relationships
    indicator: Mapped["ThreatIndicator"] = relationship(
        "ThreatIndicator",
        back_populates="sightings",
    )

    def __repr__(self) -> str:
        return f"<IndicatorSighting {self.indicator_id} on {self.created_at}>"
