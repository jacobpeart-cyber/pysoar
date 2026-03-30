"""Pydantic schemas for Zero Trust Architecture API"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ZeroTrustPolicyBase(BaseModel):
    """Base schema for Zero Trust policies"""

    name: str = Field(..., min_length=1, max_length=255)
    policy_type: str = Field(
        ..., description="access, network, identity, device, data, workload, visibility"
    )
    description: Optional[str] = None
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    risk_threshold: float = Field(default=50.0, ge=0, le=100)
    requires_mfa: bool = True
    requires_device_trust: bool = True
    minimum_device_trust_score: float = Field(default=70.0, ge=0, le=100)
    allowed_locations: list[str] = Field(default_factory=list)
    blocked_locations: list[str] = Field(default_factory=list)
    time_restrictions: dict[str, Any] = Field(default_factory=dict)
    data_classification_required: Optional[str] = None
    microsegment_id: Optional[str] = None
    is_enabled: bool = True
    priority: int = Field(default=50, ge=1, le=100)
    tags: list[str] = Field(default_factory=list)


class ZeroTrustPolicyCreate(ZeroTrustPolicyBase):
    """Schema for creating a Zero Trust policy"""

    pass


class ZeroTrustPolicyUpdate(BaseModel):
    """Schema for updating a Zero Trust policy"""

    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[list[dict[str, Any]]] = None
    actions: Optional[list[str]] = None
    risk_threshold: Optional[float] = None
    requires_mfa: Optional[bool] = None
    requires_device_trust: Optional[bool] = None
    minimum_device_trust_score: Optional[float] = None
    is_enabled: Optional[bool] = None
    priority: Optional[int] = None


class ZeroTrustPolicyResponse(ZeroTrustPolicyBase):
    """Schema for policy response"""

    id: str
    hit_count: int
    last_triggered_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DeviceTrustProfileBase(BaseModel):
    """Base schema for device trust profiles"""

    device_id: str
    device_type: str
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    compliance_status: dict[str, Any] = Field(default_factory=dict)
    encryption_enabled: bool = False
    antivirus_active: bool = False
    firewall_enabled: bool = False
    jailbroken: bool = False
    certificate_valid: bool = False
    owner_id: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class DeviceTrustProfileCreate(DeviceTrustProfileBase):
    """Schema for creating device trust profile"""

    pass


class DeviceComplianceUpdate(BaseModel):
    """Schema for updating device compliance"""

    os_patched: Optional[bool] = None
    av_active: Optional[bool] = None
    encryption_enabled: Optional[bool] = None
    firewall_on: Optional[bool] = None
    certificate_valid: Optional[bool] = None
    jailbroken: Optional[bool] = None
    rooted: Optional[bool] = None


class DeviceTrustProfileResponse(DeviceTrustProfileBase):
    """Schema for device trust profile response"""

    id: str
    trust_score: float
    trust_level: str
    last_seen_at: Optional[datetime] = None
    last_assessment_at: Optional[datetime] = None
    risk_factors: list[str] = Field(default_factory=list)
    enrolled_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AccessRequestSchema(BaseModel):
    """Schema for access request evaluation"""

    subject_type: str = Field(..., description="user, service, device, application")
    subject_id: str
    resource_type: str = Field(
        ..., description="application, data, network_segment, api, file, database"
    )
    resource_id: str
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="location, device, time, behavior_score, etc",
    )


class AccessDecisionResponse(BaseModel):
    """Schema for access decision response"""

    id: str
    decision: str = Field(..., description="allow, deny, challenge, step_up, isolate")
    risk_score: float
    risk_factors: list[str] = Field(default_factory=list)
    reason: str
    required_actions: list[str] = Field(default_factory=list)
    mfa_required: bool = False
    challenge_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class MicroSegmentBase(BaseModel):
    """Base schema for micro-segments"""

    name: str = Field(..., min_length=1, max_length=255)
    segment_type: str = Field(..., description="network, application, data, workload")
    description: Optional[str] = None
    cidr_ranges: list[str] = Field(default_factory=list)
    allowed_protocols: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_services: list[str] = Field(default_factory=list)
    ingress_policies: list[dict[str, Any]] = Field(default_factory=list)
    egress_policies: list[dict[str, Any]] = Field(default_factory=list)
    member_assets: list[str] = Field(default_factory=list)
    trust_level: str = Field(default="zero", description="zero, basic, advanced")
    is_active: bool = True


class MicroSegmentCreate(MicroSegmentBase):
    """Schema for creating micro-segment"""

    pass


class MicroSegmentUpdate(BaseModel):
    """Schema for updating micro-segment"""

    name: Optional[str] = None
    description: Optional[str] = None
    cidr_ranges: Optional[list[str]] = None
    allowed_protocols: Optional[list[str]] = None
    allowed_ports: Optional[list[int]] = None
    is_active: Optional[bool] = None


class MicroSegmentResponse(MicroSegmentBase):
    """Schema for micro-segment response"""

    id: str
    violation_count: int
    last_violation_at: Optional[datetime] = None
    traffic_stats: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SegmentTrafficRequest(BaseModel):
    """Schema for evaluating segment traffic"""

    source: str
    destination: str
    protocol: str
    port: int


class SegmentTrafficResponse(BaseModel):
    """Schema for segment traffic evaluation response"""

    allowed: bool
    reason: str
    segments: list[dict[str, Any]]


class IdentityVerificationBase(BaseModel):
    """Base schema for identity verifications"""

    user_id: str
    verification_type: str = Field(
        ..., description="initial_auth, step_up, continuous, re_auth, mfa_challenge"
    )
    method: str = Field(
        ..., description="password, mfa_totp, mfa_push, biometric, certificate, fido2, sso"
    )
    trigger_reason: Optional[str] = None
    device_id: Optional[str] = None
    source_ip: Optional[str] = None
    geo_location: Optional[dict[str, Any]] = None


class IdentityVerificationCreate(IdentityVerificationBase):
    """Schema for creating identity verification"""

    pass


class IdentityVerificationResponse(IdentityVerificationBase):
    """Schema for identity verification response"""

    id: str
    result: str = Field(..., description="success, failure, timeout, cancelled")
    risk_score_before: float
    risk_score_after: float
    session_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ZeroTrustMaturityResponse(BaseModel):
    """Schema for Zero Trust maturity assessment"""

    overall_score: float = Field(..., ge=0, le=100)
    maturity_level: str = Field(
        ..., description="traditional, initial, advanced, optimal"
    )
    pillars: dict[str, dict[str, Any]]
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    assessed_at: datetime


class PillarAssessmentResponse(BaseModel):
    """Schema for individual pillar assessment"""

    pillar: str = Field(
        ..., description="identity, devices, networks, applications, data"
    )
    score: float = Field(..., ge=0, le=100)
    maturity_level: str
    details: dict[str, Any] = Field(default_factory=dict)


class ZeroTrustDashboardStats(BaseModel):
    """Schema for Zero Trust dashboard statistics"""

    total_policies: int
    enabled_policies: int
    total_devices: int
    compliant_devices: int
    non_compliant_devices: int
    average_device_trust_score: float
    total_access_decisions: int
    allowed_decisions: int
    denied_decisions: int
    challenged_decisions: int
    total_segments: int
    active_segments: int
    violation_count: int
    maturity_score: float
    maturity_level: str
    last_updated: datetime


class ZeroTrustRecommendation(BaseModel):
    """Schema for improvement recommendation"""

    priority: int = Field(..., ge=1, le=5, description="1=highest, 5=lowest")
    category: str
    title: str
    description: str
    impact: str = Field(..., description="high, medium, low")
    effort: str = Field(..., description="high, medium, low")
    estimated_cost: Optional[str] = None
