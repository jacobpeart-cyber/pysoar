"""Supply Chain Security and SBOM Models

Comprehensive models for software component tracking, SBOM management,
supply chain risk assessment, and vendor management.
"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.organization import Organization


class PackageType(str, Enum):
    """Package/component type enumeration"""

    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    GEM = "gem"
    CARGO = "cargo"
    GO_MODULE = "go_module"
    APT = "apt"
    RPM = "rpm"
    CONTAINER_IMAGE = "container_image"
    BINARY = "binary"


class SBOMFormat(str, Enum):
    """SBOM format enumeration"""

    SPDX_JSON = "spdx_json"
    SPDX_XML = "spdx_xml"
    CYCLONEDX_JSON = "cyclonedx_json"
    CYCLONEDX_XML = "cyclonedx_xml"
    SWID = "swid"


class ComponentRelationshipType(str, Enum):
    """Component relationship types"""

    DEPENDS_ON = "depends_on"
    DEV_DEPENDS_ON = "dev_depends_on"
    OPTIONAL_DEPENDS_ON = "optional_depends_on"
    BUILD_DEPENDS_ON = "build_depends_on"
    RUNTIME_DEPENDS_ON = "runtime_depends_on"
    CONTAINS = "contains"
    GENERATES = "generates"
    DESCRIBED_BY = "described_by"


class RiskType(str, Enum):
    """Supply chain risk types"""

    KNOWN_VULNERABILITY = "known_vulnerability"
    LICENSE_CONFLICT = "license_conflict"
    ABANDONED_PROJECT = "abandoned_project"
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    MALICIOUS_PACKAGE = "malicious_package"
    SINGLE_MAINTAINER = "single_maintainer"
    NO_SECURITY_POLICY = "no_security_policy"
    OUTDATED_DEPENDENCY = "outdated_dependency"
    PROVENANCE_UNKNOWN = "provenance_unknown"


class RiskStatus(str, Enum):
    """Risk status enumeration"""

    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class AssessmentType(str, Enum):
    """Vendor assessment type"""

    INITIAL = "initial"
    ANNUAL_REVIEW = "annual_review"
    INCIDENT_TRIGGERED = "incident_triggered"
    CONTINUOUS = "continuous"


class RiskTier(str, Enum):
    """Vendor risk tier"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SoftwareComponent(BaseModel):
    """Software component in supply chain"""

    __tablename__ = "software_components"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Component identification
    name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    package_type: Mapped[str] = mapped_column(
        String(50),
        default=PackageType.BINARY.value,
        nullable=False,
        index=True,
    )

    # Licensing
    license_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    license_spdx_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Identification standards
    purl: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True, unique=True)
    cpe: Mapped[Optional[str]] = mapped_column(String(500), nullable=True, unique=True)
    checksum_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True)

    # Source and provenance
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_direct_dependency: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Dependency hierarchy
    parent_component_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("software_components.id"),
        nullable=True,
    )
    depth_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Risk indicators
    known_vulnerabilities_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)

    # Timestamps
    last_scanned: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Relationships
    parent_component: Mapped[Optional["SoftwareComponent"]] = relationship(
        "SoftwareComponent",
        remote_side=[__table__.c.id],
        back_populates="child_components",
        foreign_keys=[parent_component_id],
    )
    child_components: Mapped[list["SoftwareComponent"]] = relationship(
        "SoftwareComponent",
        back_populates="parent_component",
        foreign_keys=[parent_component_id],
    )
    sbom_components: Mapped[list["SBOMComponent"]] = relationship(
        "SBOMComponent",
        back_populates="component",
    )
    supply_chain_risks: Mapped[list["SupplyChainRisk"]] = relationship(
        "SupplyChainRisk",
        back_populates="component",
    )

    __table_args__ = (
        Index("idx_component_name_version", "name", "version"),
        Index("idx_component_org", "organization_id"),
        Index("idx_component_purl", "purl"),
        Index("idx_component_cpe", "cpe"),
    )

    def __repr__(self) -> str:
        return f"<SoftwareComponent {self.name}@{self.version}>"


class SBOM(BaseModel):
    """Software Bill of Materials"""

    __tablename__ = "sboms"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # SBOM identification
    name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    application_name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    application_version: Mapped[str] = mapped_column(String(100), nullable=False)

    # Format and specification
    sbom_format: Mapped[str] = mapped_column(
        String(50),
        default=SBOMFormat.SPDX_JSON.value,
        nullable=False,
    )
    spec_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # Metadata
    created_by_tool: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_by_user: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Component statistics
    components_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_dependencies: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    direct_dependencies: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    transitive_dependencies: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Risk assessment
    license_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    vulnerability_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Compliance
    compliance_status: Mapped[str] = mapped_column(String(100), nullable=True)

    # Raw SBOM content
    sbom_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    last_generated: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Relationships
    components: Mapped[list["SBOMComponent"]] = relationship(
        "SBOMComponent",
        back_populates="sbom",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_sbom_org_app", "organization_id", "application_name"),
        Index("idx_sbom_risk", "vulnerability_risk_score", "license_risk_score"),
    )

    def __repr__(self) -> str:
        return f"<SBOM {self.application_name}@{self.application_version}>"


class SBOMComponent(BaseModel):
    """Mapping of components to SBOMs with relationship types"""

    __tablename__ = "sbom_components"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    sbom_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("sboms.id"),
        nullable=False,
        index=True,
    )

    component_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("software_components.id"),
        nullable=False,
        index=True,
    )

    # Relationship in context of this SBOM
    relationship_type: Mapped[str] = mapped_column(
        String(50),
        default=ComponentRelationshipType.DEPENDS_ON.value,
        nullable=False,
    )

    # Relationships
    sbom: Mapped["SBOM"] = relationship(
        "SBOM",
        back_populates="components",
        foreign_keys=[sbom_id],
    )
    component: Mapped["SoftwareComponent"] = relationship(
        "SoftwareComponent",
        back_populates="sbom_components",
        foreign_keys=[component_id],
    )

    __table_args__ = (
        Index("idx_sbom_component_unique", "sbom_id", "component_id", unique=True),
        Index("idx_sbom_component_org", "organization_id"),
    )

    def __repr__(self) -> str:
        return f"<SBOMComponent sbom={self.sbom_id[:8]} component={self.component_id[:8]}>"


class SupplyChainRisk(BaseModel):
    """Supply chain risk assessment"""

    __tablename__ = "supply_chain_risks"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    component_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("software_components.id"),
        nullable=False,
        index=True,
    )

    # Risk classification
    risk_type: Mapped[str] = mapped_column(
        String(100),
        default=RiskType.KNOWN_VULNERABILITY.value,
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Description and evidence
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # CVEs and remediation
    cve_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    remediation_advice: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status tracking
    status: Mapped[str] = mapped_column(
        String(50),
        default=RiskStatus.OPEN.value,
        nullable=False,
        index=True,
    )
    detected_date: Mapped[datetime] = mapped_column(nullable=False)
    remediation_date: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Relationships
    component: Mapped["SoftwareComponent"] = relationship(
        "SoftwareComponent",
        back_populates="supply_chain_risks",
        foreign_keys=[component_id],
    )

    __table_args__ = (
        Index("idx_risk_component_type", "component_id", "risk_type"),
        Index("idx_risk_org_status", "organization_id", "status"),
        Index("idx_risk_severity", "severity"),
    )

    def __repr__(self) -> str:
        return f"<SupplyChainRisk {self.risk_type}: {self.severity}>"


class VendorAssessment(BaseModel):
    """Third-party vendor security assessment"""

    __tablename__ = "vendor_assessments"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Vendor identification
    vendor_name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    vendor_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Assessment details
    assessment_type: Mapped[str] = mapped_column(
        String(100),
        default=AssessmentType.INITIAL.value,
        nullable=False,
    )
    assessment_date: Mapped[datetime] = mapped_column(nullable=False)

    # Security scoring
    security_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)

    # Questionnaire and compliance
    questionnaire_responses: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    certifications: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Incident tracking
    last_incident_date: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    incident_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Contract and data handling
    contract_expiry: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    data_handling_classification: Mapped[str] = mapped_column(
        String(100),
        default="confidential",
        nullable=False,
    )

    # Third-party risk
    third_party_subprocessors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Risk tier
    risk_tier: Mapped[str] = mapped_column(
        String(50),
        default=RiskTier.MEDIUM.value,
        nullable=False,
        index=True,
    )

    # Notes
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_vendor_org", "organization_id"),
        Index("idx_vendor_name_org", "vendor_name", "organization_id"),
        Index("idx_vendor_risk_tier", "risk_tier"),
    )

    def __repr__(self) -> str:
        return f"<VendorAssessment {self.vendor_name}: {self.risk_tier}>"
