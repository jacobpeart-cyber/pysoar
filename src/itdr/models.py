"""
ITDR Models for Identity Threat Detection & Response

Defines data structures for identity profiles, threat detection,
credential exposure tracking, access anomalies, and privileged access events.
"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class IdentityProvider(str, Enum):
    """Identity provider types"""

    ACTIVE_DIRECTORY = "active_directory"
    AZURE_AD = "azure_ad"
    OKTA = "okta"
    PING = "ping"
    CUSTOM_SAML = "custom_saml"
    LDAP = "ldap"


class PrivilegeLevel(str, Enum):
    """User privilege levels"""

    STANDARD = "standard"
    ELEVATED = "elevated"
    ADMIN = "admin"
    SERVICE_ACCOUNT = "service_account"
    PRIVILEGED_ACCESS = "privileged_access"


class ThreatType(str, Enum):
    """Identity threat types"""

    CREDENTIAL_STUFFING = "credential_stuffing"
    PASSWORD_SPRAY = "password_spray"
    BRUTE_FORCE = "brute_force"
    TOKEN_THEFT = "token_theft"
    SESSION_HIJACK = "session_hijack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    KERBEROASTING = "kerberoasting"
    PASS_THE_HASH = "pass_the_hash"
    OAUTH_ABUSE = "oauth_abuse"
    MFA_FATIGUE = "mfa_fatigue"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    ACCOUNT_TAKEOVER = "account_takeover"


class ThreatStatus(str, Enum):
    """Identity threat status"""

    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class CredentialType(str, Enum):
    """Types of exposed credentials"""

    PASSWORD = "password"
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"
    SESSION_TOKEN = "session_token"


class ExposureSource(str, Enum):
    """Sources of credential exposure"""

    DARK_WEB = "dark_web"
    PASTE_SITE = "paste_site"
    DATA_BREACH = "data_breach"
    PHISHING = "phishing"
    MALWARE_LOG = "malware_log"
    INTERNAL_LEAK = "internal_leak"


class AnomalyType(str, Enum):
    """Types of access anomalies"""

    UNUSUAL_TIME = "unusual_time"
    UNUSUAL_LOCATION = "unusual_location"
    UNUSUAL_RESOURCE = "unusual_resource"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EXCESSIVE_ACCESS = "excessive_access"
    DORMANT_ACTIVATION = "dormant_activation"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_DEVICE = "new_device"
    FAILED_MFA_BURST = "failed_mfa_burst"
    CONSENT_PHISHING = "consent_phishing"


class PrivilegedEventType(str, Enum):
    """Types of privileged access events"""

    ELEVATION_REQUEST = "elevation_request"
    JUST_IN_TIME_ACCESS = "just_in_time_access"
    EMERGENCY_ACCESS = "emergency_access"
    ROLE_ASSIGNMENT = "role_assignment"
    GROUP_CHANGE = "group_change"
    PERMISSION_GRANT = "permission_grant"
    ADMIN_ACTION = "admin_action"
    SERVICE_ACCOUNT_USAGE = "service_account_usage"


class IdentityProfile(BaseModel):
    """Identity profile and baseline establishment"""

    __tablename__ = "identity_profiles"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Identity attributes
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    identity_provider: Mapped[str] = mapped_column(
        String(50), default=IdentityProvider.ACTIVE_DIRECTORY.value, nullable=False
    )

    # Role and group assignments
    role_assignments: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # ["admin", "analyst"]
    group_memberships: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # ["security", "it"]
    privilege_level: Mapped[str] = mapped_column(
        String(50),
        default=PrivilegeLevel.STANDARD.value,
        nullable=False,
        index=True,
    )

    # MFA Configuration
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_methods: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # ["totp", "sms"]

    # Authentication history
    last_authentication: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp
    last_password_change: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp

    # Authentication methods
    authentication_methods: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # ["password", "mfa", "sso"]

    # Account classification
    is_service_account: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    is_dormant: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Risk assessment
    risk_score: Mapped[float] = mapped_column(
        default=0.0, nullable=False
    )  # 0.0-100.0

    def __repr__(self) -> str:
        return f"<IdentityProfile {self.username}@{self.organization_id}>"


class IdentityThreat(BaseModel):
    """Detected identity threats"""

    __tablename__ = "identity_threats"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    identity_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("identity_profiles.id"), nullable=True, index=True
    )

    # Threat classification
    threat_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # critical, high, medium, low
    confidence_score: Mapped[float] = mapped_column(
        default=0.0, nullable=False
    )  # 0.0-100.0

    # Threat origin
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    source_location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Target information
    target_resource: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # MITRE ATT&CK mapping
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )  # e.g., T1110

    # Evidence and investigation
    evidence: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # {indicators, events, logs}
    status: Mapped[str] = mapped_column(
        String(50), default=ThreatStatus.DETECTED.value, nullable=False, index=True
    )
    response_actions: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # [{action, timestamp, result}]

    def __repr__(self) -> str:
        return f"<IdentityThreat {self.threat_type}:{self.status}>"


class CredentialExposure(BaseModel):
    """Exposed credential tracking and remediation"""

    __tablename__ = "credential_exposures"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_profiles.id"), nullable=False, index=True
    )

    # Exposure details
    exposure_source: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False)
    exposure_date: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp
    discovery_date: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp
    breach_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Remediation status
    is_remediated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_date: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp
    remediation_action: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )

    def __repr__(self) -> str:
        return f"<CredentialExposure {self.credential_type}:{self.exposure_source}>"


class AccessAnomaly(BaseModel):
    """Access behavior anomalies"""

    __tablename__ = "access_anomalies"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_profiles.id"), nullable=False, index=True
    )

    # Anomaly classification
    anomaly_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Baseline vs observed
    baseline_data: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # {normal_hours, normal_locations, normal_resources}
    observed_data: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # {actual_hour, actual_location, actual_resource}

    # Deviation metrics
    deviation_score: Mapped[float] = mapped_column(
        default=0.0, nullable=False
    )  # 0.0-100.0

    # Review status
    is_reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reviewer_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<AccessAnomaly {self.anomaly_type}>"


class PrivilegedAccessEvent(BaseModel):
    """Privileged access requests and audits"""

    __tablename__ = "privileged_access_events"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_profiles.id"), nullable=False, index=True
    )

    # Event details
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    target_resource: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Approval workflow
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approval_timestamp: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp

    # Time-bound access
    expiry_timestamp: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp

    # Revocation
    was_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    def __repr__(self) -> str:
        return f"<PrivilegedAccessEvent {self.event_type}>"
