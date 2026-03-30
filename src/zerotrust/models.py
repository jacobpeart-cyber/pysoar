"""Zero Trust Architecture models for NIST 800-207 implementation"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel


class ZeroTrustPolicy(BaseModel):
    """Zero Trust access policy defining rules and conditions"""

    __tablename__ = "zero_trust_policies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # access, network, identity, device, data, workload, visibility
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Policy conditions as JSON: [{attribute, operator, value}]
    conditions: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array

    # Policy actions as JSON: [allow, deny, mfa_challenge, step_up_auth, isolate, log_only]
    actions: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array

    # Risk scoring
    risk_threshold: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)

    # Authentication requirements
    requires_mfa: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_device_trust: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    minimum_device_trust_score: Mapped[float] = mapped_column(
        Float, default=70.0, nullable=False
    )

    # Location constraints
    allowed_locations: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array
    blocked_locations: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array

    # Time restrictions as JSON: {start_time, end_time, days_of_week}
    time_restrictions: Mapped[str] = mapped_column(
        Text, default="{}", nullable=False
    )  # JSON object

    # Data classification requirements
    data_classification_required: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # public, internal, confidential, restricted

    # Micro-segmentation association
    microsegment_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )

    # Policy state
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    priority: Mapped[int] = mapped_column(
        Integer, default=50, nullable=False
    )  # Higher = higher priority

    # Usage tracking
    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Metadata
    tags: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON array
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<ZeroTrustPolicy {self.name} ({self.policy_type})>"


class DeviceTrustProfile(BaseModel):
    """Device trust and compliance assessment"""

    __tablename__ = "device_trust_profiles"

    device_id: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True, unique=True
    )
    device_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # workstation, laptop, mobile, server, iot, virtual

    # Device identification
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Trust assessment
    trust_score: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )  # 0-100
    trust_level: Mapped[str] = mapped_column(
        String(20), default="untrusted", nullable=False
    )  # trusted, conditional, untrusted, blocked

    # Compliance status as JSON: {os_patched, av_active, encryption_enabled, firewall_on, etc}
    compliance_status: Mapped[str] = mapped_column(
        Text, default="{}", nullable=False
    )  # JSON object

    # Security posture
    last_patch_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    encryption_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    antivirus_active: Mapped[bool] = mapped_column(Boolean, default=False)
    firewall_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    jailbroken: Mapped[bool] = mapped_column(Boolean, default=False)
    certificate_valid: Mapped[bool] = mapped_column(Boolean, default=False)

    # Activity tracking
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_assessment_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Risk assessment
    risk_factors: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array

    # Device management
    owner_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    enrolled_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Metadata
    tags: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON array
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<DeviceTrustProfile {self.device_id} ({self.trust_level})>"


class AccessDecision(BaseModel):
    """Access control decision and evaluation result"""

    __tablename__ = "access_decisions"

    # Policy evaluation
    policy_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )

    # Subject (who is accessing)
    subject_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # user, service, device, application
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Resource (what is being accessed)
    resource_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # application, data, network_segment, api, file, database
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Decision
    decision: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # allow, deny, challenge, step_up, isolate

    # Risk assessment
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_factors: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array

    # Contextual information
    context: Mapped[str] = mapped_column(
        Text, default="{}", nullable=False
    )  # JSON: {location, device, time, behavior_score}

    # Authentication details
    authentication_method: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # password, mfa_totp, biometric, certificate, etc
    mfa_completed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Device context
    device_trust_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Session tracking
    session_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Decision explanation
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Organization
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<AccessDecision {self.subject_id} -> {self.resource_id} ({self.decision})>"


class MicroSegment(BaseModel):
    """Micro-segmentation policy for network and application isolation"""

    __tablename__ = "micro_segments"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    segment_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # network, application, data, workload

    # Description
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Network configuration
    cidr_ranges: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array
    allowed_protocols: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array
    allowed_ports: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array
    allowed_services: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array

    # Access policies
    ingress_policies: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array
    egress_policies: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array

    # Segment membership
    member_assets: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )  # JSON array (asset IDs)

    # Trust posture
    trust_level: Mapped[str] = mapped_column(
        String(20), default="zero", nullable=False
    )  # zero, basic, advanced

    # State
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Traffic monitoring
    traffic_stats: Mapped[str] = mapped_column(
        Text, default="{}", nullable=False
    )  # JSON object

    # Violation tracking
    violation_count: Mapped[int] = mapped_column(Integer, default=0)
    last_violation_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Organization
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<MicroSegment {self.name} ({self.segment_type})>"


class IdentityVerification(BaseModel):
    """Identity verification attempt and result"""

    __tablename__ = "identity_verifications"

    # Subject
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Verification context
    verification_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # initial_auth, step_up, continuous, re_auth, mfa_challenge
    method: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # password, mfa_totp, mfa_push, biometric, certificate, fido2, sso

    # Result
    result: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # success, failure, timeout, cancelled

    # Risk scoring
    risk_score_before: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score_after: Mapped[float] = mapped_column(Float, nullable=False)

    # Context
    trigger_reason: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # why verification was needed
    device_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Geographic information
    geo_location: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: {country, city, latitude, longitude}

    # Session
    session_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Organization
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<IdentityVerification {self.user_id} ({self.verification_type})>"
