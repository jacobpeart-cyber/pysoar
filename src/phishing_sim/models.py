"""
SQLAlchemy models for Phishing Simulation & Security Awareness module.

Defines PhishingCampaign, PhishingTemplate, TargetGroup, CampaignEvent,
and SecurityAwarenessScore models for comprehensive phishing simulation
and user awareness tracking.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel, utc_now


class PhishingTemplate(BaseModel):
    """Phishing template for campaign use."""

    __tablename__ = "phishing_templates"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # credential_harvest, malware_attachment, link_click, data_entry, callback_phishing, mfa_bypass, qr_code
    difficulty: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # beginner, intermediate, advanced, expert
    subject_line: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_name: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    html_body: Mapped[str] = mapped_column(Text, nullable=False)
    text_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    landing_page_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    has_attachment: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    attachment_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    indicators_of_phishing: Mapped[list[str]] = mapped_column(
        JSON, default=[], nullable=False
    )  # List of clues users should spot
    training_content_on_fail: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str] = mapped_column(String(10), default="en", nullable=False)
    is_seasonal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    usage_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    average_click_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )


class TargetGroup(BaseModel):
    """Group of target users for phishing campaigns."""

    __tablename__ = "target_groups"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    members: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=[], nullable=False
    )  # [{name, email, role, department}]
    member_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_level: Mapped[str] = mapped_column(
        String(50), default="moderate_risk", nullable=False
    )  # champion, low_risk, moderate_risk, high_risk, critical_risk
    avg_click_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    campaigns_participated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_campaign_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )


class PhishingCampaign(BaseModel):
    """Phishing simulation campaign."""

    __tablename__ = "phishing_campaigns"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    campaign_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # email_phishing, spear_phishing, smishing, vishing, usb_drop, qr_code, social_media, business_email_compromise
    status: Mapped[str] = mapped_column(
        String(50), default="draft", nullable=False
    )  # draft, scheduled, active, paused, completed, cancelled
    template_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("phishing_templates.id"), nullable=True
    )
    target_group_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("target_groups.id"), nullable=True
    )
    send_schedule: Mapped[dict[str, Any]] = mapped_column(
        JSON, default={}, nullable=False
    )  # {batch_size, interval_hours, send_all_at_once}
    start_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    end_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_targets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    emails_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    emails_opened: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    links_clicked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    credentials_submitted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attachments_opened: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reported_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    difficulty_level: Mapped[str] = mapped_column(
        String(50), default="intermediate", nullable=False
    )  # beginner, intermediate, advanced, expert
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )


class CampaignEvent(BaseModel):
    """Record of user interaction with phishing campaign."""

    __tablename__ = "campaign_events"

    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("phishing_campaigns.id"), nullable=False
    )
    target_email: Mapped[str] = mapped_column(String(255), nullable=False)
    target_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # email_sent, email_delivered, email_bounced, email_opened, link_clicked, credential_submitted, attachment_opened, reported_as_phishing, training_started, training_completed, email_forwarded
    event_timestamp: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    time_to_action_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )


class SecurityAwarenessScore(BaseModel):
    """User security awareness and risk score."""

    __tablename__ = "security_awareness_scores"

    user_email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    user_name: Mapped[str] = mapped_column(String(255), nullable=False)
    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    overall_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)  # 0-100
    phishing_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)  # 0-100
    training_completion_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    campaigns_participated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    times_clicked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    times_reported: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    times_submitted_credentials: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_failed_campaign: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    risk_category: Mapped[str] = mapped_column(
        String(50), default="moderate_risk", nullable=False
    )  # champion, low_risk, moderate_risk, high_risk, critical_risk
    training_assignments: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=[], nullable=False
    )  # [{module, status, completion_date}]
    certifications: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=[], nullable=False
    )  # [{name, completed_at, valid_until}]
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False
    )
