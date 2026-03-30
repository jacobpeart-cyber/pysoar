"""
SQLAlchemy models for Continuous Threat Exposure Management (CTEM)

This module defines the data models for tracking assets, vulnerabilities,
exposure scans, and remediation efforts across the organization.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SQLEnum,
    Float,
    Integer,
    JSON,
    String,
    Text,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel, utc_now


class AssetType(str, Enum):
    """Enumeration of asset types in the exposure management system"""

    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    APPLICATION = "application"
    DATABASE = "database"
    IOT_DEVICE = "iot_device"
    MOBILE = "mobile"
    VIRTUAL_MACHINE = "virtual_machine"


class Environment(str, Enum):
    """Enumeration of deployment environments"""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DMZ = "dmz"


class Criticality(str, Enum):
    """Enumeration of asset criticality levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CloudProvider(str, Enum):
    """Enumeration of cloud service providers"""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ORACLE = "oracle"
    ON_PREMISES = "on_premises"


class Severity(str, Enum):
    """Enumeration of vulnerability severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ExploitMaturity(str, Enum):
    """Enumeration of exploit maturity levels"""

    NONE = "none"
    POC = "poc"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"


class VulnerabilityStatus(str, Enum):
    """Enumeration of vulnerability statuses on an asset"""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"


class VerificationStatus(str, Enum):
    """Enumeration of verification statuses"""

    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    DISPUTED = "disputed"


class ScanType(str, Enum):
    """Enumeration of exposure scan types"""

    VULNERABILITY = "vulnerability"
    PORT = "port"
    COMPLIANCE = "compliance"
    DISCOVERY = "discovery"
    CONFIGURATION = "configuration"


class ScanStatus(str, Enum):
    """Enumeration of scan execution statuses"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scanner(str, Enum):
    """Enumeration of supported vulnerability scanners"""

    BUILTIN = "builtin"
    NESSUS = "nessus"
    QUALYS = "qualys"
    RAPID7 = "rapid7"
    OPENVAS = "openvas"
    NUCLEI = "nuclei"


class RemediationStatus(str, Enum):
    """Enumeration of remediation ticket statuses"""

    OPEN = "open"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    VERIFICATION = "verification"
    CLOSED = "closed"
    REOPENED = "reopened"


class RemediationType(str, Enum):
    """Enumeration of remediation types"""

    PATCH = "patch"
    CONFIGURATION = "configuration"
    UPGRADE = "upgrade"
    WORKAROUND = "workaround"
    ACCEPT_RISK = "accept_risk"
    DECOMMISSION = "decommission"


class Priority(str, Enum):
    """Enumeration of ticket priorities"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackSurfaceType(str, Enum):
    """Enumeration of attack surface types"""

    EXTERNAL = "external"
    INTERNAL = "internal"
    CLOUD = "cloud"
    APPLICATION = "application"
    SUPPLY_CHAIN = "supply_chain"


class ExposureAsset(BaseModel):
    """
    Represents an asset in the organization's IT infrastructure.

    Assets can be physical servers, virtual machines, cloud instances, network devices,
    applications, or any other component that needs vulnerability and exposure tracking.
    """

    __tablename__ = "exposure_assets"

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    os_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    environment: Mapped[str] = mapped_column(String(50), default="production")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    business_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cloud_provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cloud_region: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cloud_account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cloud_resource_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    services: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=[])
    software_inventory: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=[])
    tags: Mapped[list[str]] = mapped_column(JSON, default=[])
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[list[int]] = mapped_column(JSON, default=[])
    network_zone: Mapped[str | None] = mapped_column(String(100), nullable=True)
    compliance_status: Mapped[dict[str, Any]] = mapped_column(JSON, default={})
    extra_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default={})
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    # Relationships
    vulnerabilities = relationship(
        "AssetVulnerability",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_exposure_assets_hostname", "hostname"),
        Index("ix_exposure_assets_ip_address", "ip_address"),
        Index("ix_exposure_assets_asset_type", "asset_type"),
        Index("ix_exposure_assets_is_active", "is_active"),
        Index("ix_exposure_assets_risk_score", "risk_score"),
        Index("ix_exposure_assets_organization_id", "organization_id"),
    )


class Vulnerability(BaseModel):
    """
    Represents a known vulnerability that may affect assets in the organization.

    Vulnerabilities are typically identified by CVE ID and include CVSS, EPSS scores,
    and information about available patches and exploits.
    """

    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cvss_v2_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_exploited_in_wild: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_maturity: Mapped[str] = mapped_column(String(50), default="none")
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=[])
    affected_versions: Mapped[list[str]] = mapped_column(JSON, default=[])
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor_advisory_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, default=[])
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=[])
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=[])
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    # Relationships
    asset_vulnerabilities = relationship(
        "AssetVulnerability",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_vulnerabilities_cve_id", "cve_id"),
        Index("ix_vulnerabilities_organization_id", "organization_id"),
    )


class AssetVulnerability(BaseModel):
    """
    Represents the relationship between an asset and a vulnerability.

    Tracks the status of vulnerability remediation on specific assets, including
    detection metadata, remediation progress, and contextual risk assessment.
    """

    __tablename__ = "asset_vulnerabilities"

    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("exposure_assets.id"), nullable=False)
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), default="open")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    compensating_controls: Mapped[list[str]] = mapped_column(JSON, default=[])
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    exploitability_score: Mapped[float] = mapped_column(Float, default=0.0)
    impact_score: Mapped[float] = mapped_column(Float, default=0.0)
    detected_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scan_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_status: Mapped[str] = mapped_column(String(50), default="unverified")
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    # Relationships
    asset = relationship("ExposureAsset", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability", back_populates="asset_vulnerabilities")

    __table_args__ = (
        Index("ix_asset_vulnerabilities_asset_id", "asset_id"),
        Index("ix_asset_vulnerabilities_vulnerability_id", "vulnerability_id"),
        Index("ix_asset_vulnerabilities_status", "status"),
        Index("ix_asset_vulnerabilities_organization_id", "organization_id"),
        Index("ix_asset_vuln_composite", "asset_id", "vulnerability_id"),
    )


class ExposureScan(BaseModel):
    """
    Represents a vulnerability assessment or network discovery scan.

    Scans can be executed using built-in scanners or integrated with external
    vulnerability scanning platforms like Nessus, Qualys, or Rapid7.
    """

    __tablename__ = "exposure_scans"

    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    target_assets: Mapped[list[str]] = mapped_column(JSON, default=[])
    scanner: Mapped[str] = mapped_column(String(100), default="builtin")
    scan_profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_hosts: Mapped[int] = mapped_column(Integer, default=0)
    hosts_scanned: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_found: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    results_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default={})
    initiated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    __table_args__ = (
        Index("ix_exposure_scans_scan_type", "scan_type"),
        Index("ix_exposure_scans_status", "status"),
        Index("ix_exposure_scans_organization_id", "organization_id"),
    )


class RemediationTicket(BaseModel):
    """
    Represents a remediation effort for vulnerabilities across one or more assets.

    Tickets track the entire lifecycle of remediation, from identification through
    verification, with support for external ticket system integration (Jira, ServiceNow).
    """

    __tablename__ = "remediation_tickets"

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open")
    priority: Mapped[str] = mapped_column(String(20), default="medium")
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assigned_team: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asset_vulnerabilities: Mapped[list[str]] = mapped_column(JSON, default=[])
    affected_assets: Mapped[list[str]] = mapped_column(JSON, default=[])
    remediation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    remediation_steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=[])
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breach: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_status: Mapped[str] = mapped_column(String(50), default="pending")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    external_ticket_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    external_ticket_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=[])
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    __table_args__ = (
        Index("ix_remediation_tickets_status", "status"),
        Index("ix_remediation_tickets_priority", "priority"),
        Index("ix_remediation_tickets_organization_id", "organization_id"),
    )


class AttackSurface(BaseModel):
    """
    Represents a categorized view of an organization's attack surface.

    Attack surfaces can be segmented by type (external, internal, cloud, etc.)
    and provide high-level metrics about the organization's overall exposure.
    """

    __tablename__ = "attack_surfaces"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    surface_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_assets: Mapped[int] = mapped_column(Integer, default=0)
    exposed_assets: Mapped[int] = mapped_column(Integer, default=0)
    critical_exposures: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=[])
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default={})
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    __table_args__ = (
        Index("ix_attack_surfaces_surface_type", "surface_type"),
        Index("ix_attack_surfaces_organization_id", "organization_id"),
    )
