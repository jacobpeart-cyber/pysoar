"""Dark Web Monitoring Models

Models for dark web monitoring, credential leak detection, and brand protection.
Includes monitoring configurations, findings, credential leaks, and brand threats.
"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    pass


class DarkWebMonitorType(str, Enum):
    """Monitor type for dark web scanning"""

    CREDENTIAL_LEAK = "credential_leak"
    BRAND_IMPERSONATION = "brand_impersonation"
    DATA_SALE = "data_sale"
    EXECUTIVE_TARGETING = "executive_targeting"
    DOMAIN_SPOOFING = "domain_spoofing"
    CODE_LEAK = "code_leak"
    INFRASTRUCTURE_EXPOSURE = "infrastructure_exposure"
    RANSOMWARE_MENTION = "ransomware_mention"


class FindingType(str, Enum):
    """Type of dark web finding"""

    CREDENTIAL_LEAK = "credential_leak"
    DATA_BREACH_LISTING = "data_breach_listing"
    PASTE_SITE_EXPOSURE = "paste_site_exposure"
    FORUM_MENTION = "forum_mention"
    MARKETPLACE_LISTING = "marketplace_listing"
    RANSOMWARE_VICTIM_POST = "ransomware_victim_post"
    PHISHING_KIT = "phishing_kit"
    CLONED_WEBSITE = "cloned_website"
    LEAKED_SOURCE_CODE = "leaked_source_code"
    EXPOSED_API_KEY = "exposed_api_key"
    EXECUTIVE_PII_EXPOSURE = "executive_pii_exposure"


class SourcePlatform(str, Enum):
    """Source platform for dark web findings"""

    TOR_FORUM = "tor_forum"
    PASTE_SITE = "paste_site"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    RANSOMWARE_BLOG = "ransomware_blog"
    MARKETPLACE = "marketplace"
    BREACH_DATABASE = "breach_database"
    CODE_REPOSITORY = "code_repository"
    SOCIAL_MEDIA = "social_media"


class AlertSeverity(str, Enum):
    """Alert severity for dark web findings"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Status of dark web finding"""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class PasswordType(str, Enum):
    """Type of password hash in credential leak"""

    PLAINTEXT = "plaintext"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    BCRYPT = "bcrypt"
    ARGON2 = "argon2"
    NTLM = "ntlm"
    UNKNOWN = "unknown"


class RemediationAction(str, Enum):
    """Remediation actions for credential leaks"""

    PASSWORD_RESET = "password_reset"
    ACCOUNT_DISABLED = "account_disabled"
    MFA_ENFORCED = "mfa_enforced"
    TOKEN_REVOKED = "token_revoked"
    MONITORING_ENHANCED = "monitoring_enhanced"


class BrandThreatType(str, Enum):
    """Type of brand threat"""

    DOMAIN_TYPOSQUAT = "domain_typosquat"
    LOOKALIKE_SITE = "lookalike_site"
    SOCIAL_MEDIA_IMPERSONATION = "social_media_impersonation"
    PHISHING_CAMPAIGN = "phishing_campaign"
    FAKE_APP = "fake_app"
    TRADEMARK_ABUSE = "trademark_abuse"
    EXECUTIVE_IMPERSONATION = "executive_impersonation"


class TakedownStatus(str, Enum):
    """Status of takedown process"""

    IDENTIFIED = "identified"
    TAKEDOWN_REQUESTED = "takedown_requested"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class DarkWebMonitor(BaseModel):
    """Dark web monitor configuration"""

    __tablename__ = "darkweb_monitors"

    # Core fields
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Monitor configuration
    monitor_type: Mapped[str] = mapped_column(
        String(50),
        default=DarkWebMonitorType.CREDENTIAL_LEAK.value,
        nullable=False,
        index=True,
    )
    search_terms: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # List[str]
    domains_watched: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # List[str]
    emails_watched: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # List[str]

    # Status and configuration
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)
    alert_severity: Mapped[str] = mapped_column(
        String(50),
        default=AlertSeverity.HIGH.value,
        nullable=False,
    )

    # Statistics
    last_check: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    findings: Mapped[list["DarkWebFinding"]] = relationship(
        "DarkWebFinding",
        back_populates="monitor",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<DarkWebMonitor {self.id}: {self.name}>"


class DarkWebFinding(BaseModel):
    """Dark web finding/exposure"""

    __tablename__ = "darkweb_findings"

    # Organization and monitor
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    monitor_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("darkweb_monitors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Finding classification
    finding_type: Mapped[str] = mapped_column(
        String(50),
        default=FindingType.CREDENTIAL_LEAK.value,
        nullable=False,
        index=True,
    )
    source_platform: Mapped[str] = mapped_column(
        String(50),
        default=SourcePlatform.PASTE_SITE.value,
        nullable=False,
        index=True,
    )

    # Source information
    source_url_hash: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, index=True
    )
    title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_data_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Affected assets
    affected_assets: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # Dict
    affected_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Risk assessment
    severity: Mapped[str] = mapped_column(
        String(50),
        default=AlertSeverity.MEDIUM.value,
        nullable=False,
        index=True,
    )
    confidence_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        default=FindingStatus.NEW.value,
        nullable=False,
        index=True,
    )

    # Timeline
    discovered_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    monitor: Mapped[DarkWebMonitor] = relationship(
        "DarkWebMonitor",
        back_populates="findings",
    )
    credential_leaks: Mapped[list["CredentialLeak"]] = relationship(
        "CredentialLeak",
        back_populates="finding",
        cascade="all, delete-orphan",
    )
    brand_threats: Mapped[list["BrandThreat"]] = relationship(
        "BrandThreat",
        back_populates="finding",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_darkweb_findings_organization_status", organization_id, status),
        Index("ix_darkweb_findings_organization_severity", organization_id, severity),
    )

    def __repr__(self) -> str:
        return f"<DarkWebFinding {self.id}: {self.title[:50] if self.title else 'N/A'}>"


class CredentialLeak(BaseModel):
    """Credential leak details from dark web finding"""

    __tablename__ = "darkweb_credential_leaks"

    # Organization and finding
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("darkweb_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Credential information
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    password_type: Mapped[str] = mapped_column(
        String(50),
        default=PasswordType.UNKNOWN.value,
        nullable=False,
    )

    # Breach information
    breach_source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    breach_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Validation and remediation
    is_valid: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_remediated: Mapped[bool] = mapped_column(default=False, nullable=False)
    remediation_action: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Relationships
    finding: Mapped[DarkWebFinding] = relationship(
        "DarkWebFinding",
        back_populates="credential_leaks",
    )

    __table_args__ = (
        Index("ix_darkweb_credential_leaks_organization_remediated", organization_id, is_remediated),
    )

    def __repr__(self) -> str:
        return f"<CredentialLeak {self.id}: {self.email or self.username}>"


class BrandThreat(BaseModel):
    """Brand threat from dark web finding"""

    __tablename__ = "darkweb_brand_threats"

    # Organization and finding
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("darkweb_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Threat classification
    threat_type: Mapped[str] = mapped_column(
        String(50),
        default=BrandThreatType.DOMAIN_TYPOSQUAT.value,
        nullable=False,
        index=True,
    )

    # Target information
    target_brand: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_domain: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )

    # Malicious asset
    malicious_domain: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )
    registrar: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    registration_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ssl_certificate_info: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Takedown tracking
    takedown_status: Mapped[str] = mapped_column(
        String(50),
        default=TakedownStatus.IDENTIFIED.value,
        nullable=False,
        index=True,
    )
    takedown_provider: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    finding: Mapped[DarkWebFinding] = relationship(
        "DarkWebFinding",
        back_populates="brand_threats",
    )

    __table_args__ = (
        Index("ix_darkweb_brand_threats_organization_status", organization_id, takedown_status),
    )

    def __repr__(self) -> str:
        return f"<BrandThreat {self.id}: {self.malicious_domain}>"
