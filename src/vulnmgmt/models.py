"""Vulnerability management database models"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Integer, JSON, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    pass


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels per CVSS v3.1"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities"""

    RCE = "rce"
    SQLI = "sqli"
    XSS = "xss"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BUFFER_OVERFLOW = "buffer_overflow"
    DESERIALIZATION = "deserialization"
    MISCONFIG = "misconfig"
    INFO_DISCLOSURE = "info_disclosure"
    DOS = "dos"
    AUTHENTICATION_BYPASS = "authentication_bypass"


class ExploitMaturity(str, Enum):
    """CVSS Exploit Maturity levels"""

    UNPROVEN = "unproven"
    POC = "poc"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"


class DiscoverySource(str, Enum):
    """Vulnerability discovery source"""

    NESSUS = "nessus"
    QUALYS = "qualys"
    TENABLE = "tenable"
    RAPID7 = "rapid7"
    OPENVAS = "openvas"
    TRIVY = "trivy"
    GRYPE = "grype"
    MANUAL = "manual"
    API_SCAN = "api_scan"


class VulnerabilityStatus(str, Enum):
    """Status of a vulnerability instance"""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PATCHED = "patched"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    DEFERRED = "deferred"


class SLAStatus(str, Enum):
    """SLA compliance status"""

    WITHIN_SLA = "within_sla"
    APPROACHING = "approaching"
    BREACHED = "breached"


class PatchType(str, Enum):
    """Type of patch or remediation"""

    OS_PATCH = "os_patch"
    APPLICATION_UPDATE = "application_update"
    CONFIGURATION_CHANGE = "configuration_change"
    VIRTUAL_PATCH = "virtual_patch"
    COMPENSATING_CONTROL = "compensating_control"
    FIRMWARE_UPDATE = "firmware_update"


class DeploymentStatus(str, Enum):
    """Status of patch deployment"""

    PENDING = "pending"
    SCHEDULED = "scheduled"
    DEPLOYING = "deploying"
    DEPLOYED = "deployed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    VERIFIED = "verified"


class ExceptionType(str, Enum):
    """Type of vulnerability exception"""

    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    COMPENSATING_CONTROL = "compensating_control"
    DEFERRED = "deferred"
    NOT_APPLICABLE = "not_applicable"


class Vulnerability(BaseModel):
    """Vulnerability record in database"""

    __tablename__ = "vulnerabilities"

    # CVE and identification
    cve_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True, unique=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Scoring and severity
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Numeric(4, 1), nullable=True)
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4), nullable=True)
    severity: Mapped[str] = mapped_column(
        String(50),
        default=VulnerabilitySeverity.MEDIUM.value,
        nullable=False,
        index=True,
    )

    # Classification
    vulnerability_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    mitre_technique_ids: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Affected software and versions
    affected_software: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_versions: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Timeline
    published_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    modified_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Exploit information
    exploit_available: Mapped[bool] = mapped_column(default=False, nullable=False)
    exploit_maturity: Mapped[str] = mapped_column(
        String(50),
        default=ExploitMaturity.UNPROVEN.value,
        nullable=False,
    )

    # Patch status
    patch_available: Mapped[bool] = mapped_column(default=False, nullable=False)
    patch_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # References and metadata
    references: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    kev_listed: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        index=True,
    )

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    instances: Mapped[list["VulnerabilityInstance"]] = relationship(
        "VulnerabilityInstance",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id}: {self.title[:50]}>"


class VulnerabilityInstance(BaseModel):
    """Instance of vulnerability on a specific asset"""

    __tablename__ = "vulnerability_instances"

    # Reference to vulnerability definition
    vulnerability_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vulnerabilities.id"),
        nullable=False,
        index=True,
    )

    # Asset information
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    asset_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asset_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    asset_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Discovery
    discovered_by: Mapped[str] = mapped_column(
        String(50),
        default=DiscoverySource.MANUAL.value,
        nullable=False,
    )
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Temporal
    first_seen: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_seen: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Status and severity
    status: Mapped[str] = mapped_column(
        String(50),
        default=VulnerabilityStatus.OPEN.value,
        nullable=False,
        index=True,
    )
    risk_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 2), nullable=True)
    exploitability_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 2), nullable=True)
    business_criticality: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Assignment and remediation
    assigned_to: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    remediation_deadline: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    sla_status: Mapped[str] = mapped_column(
        String(50),
        default=SLAStatus.WITHIN_SLA.value,
        nullable=False,
    )

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    vulnerability: Mapped["Vulnerability"] = relationship(
        "Vulnerability",
        back_populates="instances",
        foreign_keys=[vulnerability_id],
    )
    exceptions: Mapped[list["VulnerabilityException"]] = relationship(
        "VulnerabilityException",
        back_populates="vulnerability_instance",
        cascade="all, delete-orphan",
    )
    patch_operations: Mapped[list["PatchOperation"]] = relationship(
        "PatchOperation",
        back_populates="vulnerability_instance",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<VulnerabilityInstance {self.id}: {self.asset_name}>"


class ScanProfile(BaseModel):
    """Scan configuration and schedule"""

    __tablename__ = "scan_profiles"

    # Basic information
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Scanner configuration
    scanner_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_ranges: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    scan_policy: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    credentials_encrypted: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Schedule
    schedule_cron: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_scan_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    next_scan_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Status
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<ScanProfile {self.name}>"


class PatchOperation(BaseModel):
    """Patch deployment record"""

    __tablename__ = "patch_operations"

    # Reference to vulnerability instance
    vulnerability_instance_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vulnerability_instances.id"),
        nullable=False,
        index=True,
    )

    # Patch information
    patch_type: Mapped[str] = mapped_column(
        String(50),
        default=PatchType.OS_PATCH.value,
        nullable=False,
    )
    patch_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    patch_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Deployment
    deployment_status: Mapped[str] = mapped_column(
        String(50),
        default=DeploymentStatus.PENDING.value,
        nullable=False,
        index=True,
    )
    deployment_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    verification_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Rollback capability
    rollback_available: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Change management
    change_ticket_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    deployment_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    vulnerability_instance: Mapped["VulnerabilityInstance"] = relationship(
        "VulnerabilityInstance",
        back_populates="patch_operations",
        foreign_keys=[vulnerability_instance_id],
    )

    def __repr__(self) -> str:
        return f"<PatchOperation {self.id}: {self.patch_name}>"


class VulnerabilityException(BaseModel):
    """Vulnerability exception or risk acceptance"""

    __tablename__ = "vulnerability_exceptions"

    # Reference to vulnerability instance
    vulnerability_instance_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vulnerability_instances.id"),
        nullable=False,
        index=True,
    )

    # Exception details
    exception_type: Mapped[str] = mapped_column(
        String(50),
        default=ExceptionType.RISK_ACCEPTED.value,
        nullable=False,
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False)

    # Approval
    approved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    approval_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Timeline
    expiry_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    review_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Compensating control (if applicable)
    compensating_control_description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Risk acceptance (if applicable)
    risk_acceptance_level: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    vulnerability_instance: Mapped["VulnerabilityInstance"] = relationship(
        "VulnerabilityInstance",
        back_populates="exceptions",
        foreign_keys=[vulnerability_instance_id],
    )

    def __repr__(self) -> str:
        return f"<VulnerabilityException {self.id}: {self.exception_type}>"
