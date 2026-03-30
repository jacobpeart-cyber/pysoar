"""
SQLAlchemy models for Deception Technology module.

Defines Decoy, DecoyInteraction, DeceptionCampaign, and HoneyToken models.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, Boolean, Float
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel, generate_uuid, utc_now


class Decoy(BaseModel):
    """Decoy asset deployment model."""

    __tablename__ = "decoys"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    decoy_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # honeypot, honeytoken, honeyfile, honeycred, honeydns, honeynet, canary_file, breadcrumb
    category: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # network, credential, file, dns, email, cloud, active_directory, database
    status: Mapped[str] = mapped_column(
        String(50), default="inactive", nullable=False
    )  # inactive, deploying, active, triggered, disabled, compromised
    deployment_target: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Where it's deployed
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSON, default={}, nullable=False
    )  # Type-specific config
    emulated_service: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )  # SSH, RDP, HTTP, SMB, FTP, MySQL, etc.
    emulated_os: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True
    )  # IPv4 or IPv6
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fidelity_level: Mapped[str] = mapped_column(
        String(50), default="medium", nullable=False
    )  # low, medium, high (interaction depth)
    interaction_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_interaction_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    alert_on_interaction: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    capture_credentials: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    capture_payloads: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deployed_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    tags: Mapped[list[str]] = mapped_column(JSON, default=[], nullable=False)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )


class DecoyInteraction(BaseModel):
    """Record of attacker interaction with decoy asset."""

    __tablename__ = "decoy_interactions"

    decoy_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("decoys.id"), nullable=False
    )
    interaction_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # scan, connection, authentication, command, file_access, credential_use, dns_query, data_transfer
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(50), nullable=True)
    credentials_captured: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )  # username, password hash - NEVER plain text
    commands_captured: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )
    payloads_captured: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )
    files_accessed: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )
    session_duration_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    threat_assessment: Mapped[str] = mapped_column(
        String(20), default="high", nullable=False
    )  # critical, high, medium
    is_automated_scan: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # likely automated scanner vs human
    raw_traffic: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # sanitized
    alert_generated: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    alert_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )  # Linked alert
    mitre_techniques: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )


class DeceptionCampaign(BaseModel):
    """Coordinated deception campaign across multiple decoys."""

    __tablename__ = "deception_campaigns"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), default="draft", nullable=False
    )  # draft, active, paused, completed
    objective: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # detect_lateral_movement, detect_insider, detect_reconnaissance, detect_data_theft, general_detection
    decoy_ids: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )  # Deployed decoys
    coverage_zones: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )  # Network zones covered
    total_interactions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unique_attackers: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=[], nullable=False
    )
    effectiveness_score: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )  # 0-100
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )


class HoneyToken(BaseModel):
    """Honeytokens for tracking credential/data access."""

    __tablename__ = "honey_tokens"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # aws_key, api_key, database_cred, jwt_token, ssh_key, certificate, dns_canary, url_canary, email_canary, document_beacon
    token_value: Mapped[str] = mapped_column(String(500), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # For quick matching without exposing value
    deployment_location: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )
    deployment_context: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # e.g., "placed in shared drive as aws_credentials.txt"
    status: Mapped[str] = mapped_column(
        String(50), default="active", nullable=False
    )  # active, triggered, expired, disabled
    triggered_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    last_triggered_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Source IP/user
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    alert_severity: Mapped[str] = mapped_column(
        String(20), default="critical", nullable=False
    )
    notification_channels: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )  # email, slack, webhook
    deployed_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )
