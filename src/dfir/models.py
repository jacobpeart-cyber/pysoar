"""DFIR Models for forensic case management, evidence, timeline, and artifacts"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class CaseType(str, Enum):
    """Types of forensic cases"""

    INCIDENT_RESPONSE = "incident_response"
    MALWARE_ANALYSIS = "malware_analysis"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    LEGAL_INVESTIGATION = "legal_investigation"
    COMPLIANCE_AUDIT = "compliance_audit"


class CaseStatus(str, Enum):
    """Status of a forensic case"""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    EVIDENCE_COLLECTION = "evidence_collection"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    CLOSED = "closed"
    LEGAL_HOLD = "legal_hold"


class EvidenceType(str, Enum):
    """Types of forensic evidence"""

    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    LOG_FILES = "log_files"
    REGISTRY_HIVE = "registry_hive"
    EMAIL_ARCHIVE = "email_archive"
    MOBILE_DEVICE = "mobile_device"
    CLOUD_ARTIFACT = "cloud_artifact"
    MALWARE_SAMPLE = "malware_sample"
    SCREENSHOT = "screenshot"


class AcquisitionMethod(str, Enum):
    """Methods for evidence acquisition"""

    LIVE_ACQUISITION = "live_acquisition"
    DEAD_ACQUISITION = "dead_acquisition"
    NETWORK_TAP = "network_tap"
    API_COLLECTION = "api_collection"
    MANUAL_UPLOAD = "manual_upload"


class ArtifactType(str, Enum):
    """Types of forensic artifacts"""

    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    BROWSER_HISTORY = "browser_history"
    EVENT_LOG = "event_log"
    PROCESS = "process"
    NETWORK_CONNECTION = "network_connection"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    USER_ACCOUNT = "user_account"
    PREFETCH = "prefetch"
    SHIMCACHE = "shimcache"
    AMCACHE = "amcache"
    USN_JOURNAL = "usn_journal"
    MFT_ENTRY = "mft_entry"


class HoldType(str, Enum):
    """Types of legal holds"""

    LITIGATION_HOLD = "litigation_hold"
    REGULATORY_HOLD = "regulatory_hold"
    INVESTIGATION_HOLD = "investigation_hold"
    PRESERVATION_ORDER = "preservation_order"


class ForensicCase(BaseModel):
    """Forensic investigation case"""

    __tablename__ = "forensic_cases"

    # Core fields
    case_number: Mapped[str] = mapped_column(String(100), nullable=False, index=True, unique=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    case_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=CaseStatus.OPEN.value,
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="medium")

    # Investigation team
    lead_investigator_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )
    assigned_team: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Legal and compliance
    legal_hold_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    chain_of_custody_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    classification_level: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    court_admissible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Organization multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    lead_investigator: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="forensic_cases",
        foreign_keys=[lead_investigator_id],
    )
    evidence: Mapped[list["ForensicEvidence"]] = relationship(
        "ForensicEvidence",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    timeline_events: Mapped[list["ForensicTimeline"]] = relationship(
        "ForensicTimeline",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    artifacts: Mapped[list["ForensicArtifact"]] = relationship(
        "ForensicArtifact",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    legal_holds: Mapped[list["LegalHold"]] = relationship(
        "LegalHold",
        back_populates="case",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ForensicCase {self.case_number}: {self.title[:50]}>"


class ForensicEvidence(BaseModel):
    """Forensic evidence collection and tracking"""

    __tablename__ = "forensic_evidence"

    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_device: Mapped[str] = mapped_column(String(255), nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Acquisition
    acquisition_method: Mapped[str] = mapped_column(String(50), nullable=False)

    # Integrity verification
    original_hash_md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    original_hash_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    chain_of_custody_log: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Storage
    storage_location: Mapped[str] = mapped_column(Text, nullable=False)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Verification
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verified_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    verification_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Notes
    handling_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Organization multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    case: Mapped["ForensicCase"] = relationship(
        "ForensicCase",
        back_populates="evidence",
    )
    artifacts: Mapped[list["ForensicArtifact"]] = relationship(
        "ForensicArtifact",
        back_populates="evidence",
        cascade="all, delete-orphan",
    )
    timeline_events: Mapped[list["ForensicTimeline"]] = relationship(
        "ForensicTimeline",
        back_populates="evidence",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ForensicEvidence {self.id}: {self.evidence_type} from {self.source_device}>"


class ForensicTimeline(BaseModel):
    """Timeline of forensic events for case reconstruction"""

    __tablename__ = "forensic_timeline"

    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True)
    event_timestamp: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    source_evidence_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("forensic_evidence.id"),
        nullable=True,
    )

    # Details
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    artifact_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Analysis
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity_score: Mapped[float] = mapped_column(default=0.0, nullable=False)
    is_pivotal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Organization multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    case: Mapped["ForensicCase"] = relationship(
        "ForensicCase",
        back_populates="timeline_events",
    )
    evidence: Mapped[Optional["ForensicEvidence"]] = relationship(
        "ForensicEvidence",
        back_populates="timeline_events",
    )

    def __repr__(self) -> str:
        return f"<ForensicTimeline {self.id}: {self.event_type} @ {self.event_timestamp}>"


class ForensicArtifact(BaseModel):
    """Parsed forensic artifacts extracted from evidence"""

    __tablename__ = "forensic_artifacts"

    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_evidence.id"), nullable=False, index=True)
    artifact_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Artifact content
    artifact_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    analysis_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # IOC extraction
    ioc_extracted: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Threat mapping
    mitre_mapping: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    risk_score: Mapped[float] = mapped_column(default=0.0, nullable=False)

    # Organization multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    case: Mapped["ForensicCase"] = relationship(
        "ForensicCase",
        back_populates="artifacts",
    )
    evidence: Mapped["ForensicEvidence"] = relationship(
        "ForensicEvidence",
        back_populates="artifacts",
    )

    def __repr__(self) -> str:
        return f"<ForensicArtifact {self.id}: {self.artifact_type} (risk={self.risk_score:.2f})>"


class LegalHold(BaseModel):
    """Legal hold tracking and compliance"""

    __tablename__ = "legal_holds"

    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True)
    hold_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Custodians and data sources
    custodians: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # JSON array
    data_sources: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # JSON array

    # Issuance
    issued_by: Mapped[str] = mapped_column(String(255), nullable=False)
    issued_date: Mapped[str] = mapped_column(String(50), nullable=False)
    expiry_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Acknowledgments
    acknowledgments: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)

    # Organization multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationships
    case: Mapped["ForensicCase"] = relationship(
        "ForensicCase",
        back_populates="legal_holds",
    )

    def __repr__(self) -> str:
        return f"<LegalHold {self.id}: {self.hold_type} (status={self.status})>"
