"""
Privacy Engineering Models

SQLAlchemy models for GDPR, CCPA, LGPD, PIPA, PDPA, and HIPAA compliance.
Manages Data Subject Requests, Privacy Impact Assessments, Consent Records,
Data Processing Activities, and Privacy Incidents.
"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class DSRType(str, Enum):
    """Data Subject Request types per GDPR/CCPA/LGPD"""

    ACCESS = "access"  # Right to access
    RECTIFICATION = "rectification"  # Right to correct
    ERASURE = "erasure"  # Right to be forgotten
    PORTABILITY = "portability"  # Right to data portability
    RESTRICTION = "restriction"  # Right to restrict processing
    OBJECTION = "objection"  # Right to object
    AUTOMATED_DECISION = "automated_decision"  # Right to human review


class Regulation(str, Enum):
    """Privacy regulations"""

    GDPR = "gdpr"  # EU General Data Protection Regulation
    CCPA = "ccpa"  # California Consumer Privacy Act
    LGPD = "lgpd"  # Brazilian Lei Geral de Proteção de Dados
    PIPA = "pipa"  # Canadian Personal Information Protection Act
    PDPA = "pdpa"  # Singapore/Thailand Personal Data Protection Act
    HIPAA_RIGHT = "hipaa_right"  # HIPAA privacy rights
    CUSTOM = "custom"


class DSRStatus(str, Enum):
    """Data Subject Request status"""

    RECEIVED = "received"
    IDENTITY_VERIFIED = "identity_verified"
    PROCESSING = "processing"
    PARTIALLY_COMPLETE = "partially_complete"
    COMPLETED = "completed"
    DENIED = "denied"
    APPEALED = "appealed"


class DataSubjectRequest(BaseModel):
    """
    Data Subject Request (DSR) model for GDPR Article 12-22, CCPA § 1798.100-1798.120.
    Tracks access requests, erasure requests, portability requests, and other privacy rights.
    """

    __tablename__ = "data_subject_requests"

    # Organization
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Request metadata
    request_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    regulation: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=DSRStatus.RECEIVED.value,
        nullable=False,
        index=True,
    )

    # Subject information
    subject_name: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_email: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_identifier: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )

    # Timelines
    deadline: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    response_sent: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Processing details
    data_systems_searched: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: list of systems
    data_found: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Resolution
    denial_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    processing_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_dsr_org_status", "organization_id", "status"),
        Index("idx_dsr_org_subject", "organization_id", "subject_email"),
        Index("idx_dsr_deadline", "deadline"),
    )

    def __repr__(self) -> str:
        return f"<DSR {self.id}: {self.request_type} - {self.subject_email}>"


class PIAAssessmentType(str, Enum):
    """Privacy Impact Assessment types"""

    DPIA = "dpia"  # GDPR Data Protection Impact Assessment
    PIA = "pia"  # General Privacy Impact Assessment
    TIA = "tia"  # Technology Impact Assessment
    LEGITIMATE_INTEREST = "legitimate_interest"  # Legitimate Interest Assessment


class PIAStatus(str, Enum):
    """Privacy Impact Assessment status"""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REQUIRES_CHANGES = "requires_changes"
    REJECTED = "rejected"


class RiskLevel(str, Enum):
    """Risk assessment levels"""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PrivacyImpactAssessment(BaseModel):
    """
    Privacy Impact Assessment model for GDPR Article 35 (DPIA) and PIA best practices.
    Evaluates processing necessity, proportionality, and risk mitigation.
    """

    __tablename__ = "privacy_impact_assessments"

    # Organization
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Assessment metadata
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    project_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    assessment_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        default=PIAStatus.DRAFT.value,
        nullable=False,
        index=True,
    )

    # Processing details
    data_types_processed: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON
    processing_purposes: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON
    legal_basis: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Data subject scope
    data_subjects_affected: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cross_border_transfers: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: countries

    # Risk assessment
    risk_level: Mapped[str] = mapped_column(
        String(50),
        default=RiskLevel.MEDIUM.value,
        nullable=False,
    )
    mitigations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # DPO engagement
    dpo_review: Mapped[bool] = mapped_column(Boolean, default=False)
    dpo_approval_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    supervisory_authority_consulted: Mapped[bool] = mapped_column(
        Boolean, default=False
    )

    __table_args__ = (
        Index("idx_pia_org_status", "organization_id", "status"),
        Index("idx_pia_project", "project_name"),
    )

    def __repr__(self) -> str:
        return f"<PIA {self.id}: {self.name}>"


class ConsentType(str, Enum):
    """Legal basis for processing"""

    EXPLICIT_OPT_IN = "explicit_opt_in"  # Explicit consent
    SOFT_OPT_IN = "soft_opt_in"  # Soft opt-in (pre-checked)
    IMPLIED = "implied"  # Implied consent
    CHECKBOX = "checkbox"  # Checkbox consent
    DOUBLE_OPT_IN = "double_opt_in"  # Double opt-in confirmation


class LegalBasis(str, Enum):
    """Legal bases for processing per GDPR/CCPA"""

    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTEREST = "vital_interest"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTEREST = "legitimate_interest"


class ConsentRecord(BaseModel):
    """
    Consent Record model for GDPR Articles 4, 7 and CCPA § 1798.115.
    Tracks explicit consent, withdrawal, and audit trail.
    """

    __tablename__ = "consent_records"

    # Organization
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Subject and consent
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(255), nullable=False)
    legal_basis: Mapped[str] = mapped_column(String(50), nullable=False)

    # Consent status
    consent_given: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    consent_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    withdrawal_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Mechanism
    consent_mechanism: Mapped[str] = mapped_column(
        String(50),
        default=ConsentType.CHECKBOX.value,
        nullable=False,
    )
    evidence_location: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )  # URL/path to consent form

    # Granularity
    granularity: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: per-purpose consent
    version: Mapped[int] = mapped_column(Integer, default=1)
    privacy_policy_version: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )

    __table_args__ = (
        Index("idx_consent_org_subject", "organization_id", "subject_id"),
        Index("idx_consent_given", "consent_given"),
        UniqueConstraint(
            "organization_id", "subject_id", "purpose", name="uq_consent_subject_purpose"
        ),
    )

    def __repr__(self) -> str:
        return f"<ConsentRecord {self.id}: {self.subject_id} - {self.purpose}>"


class DataProcessingRecord(BaseModel):
    """
    Data Processing Record model for GDPR Article 30 (Record of Processing Activities).
    Comprehensive record of all data processing, legal basis, retention, and measures.
    """

    __tablename__ = "data_processing_records"

    # Organization
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Processing activity
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    legal_basis: Mapped[str] = mapped_column(String(100), nullable=False)

    # Data scope
    data_categories: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: types of data
    data_subjects: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: categories
    recipients: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: who receives data

    # Cross-border
    cross_border_transfers: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: destinations

    # Data management
    retention_period_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    technical_measures: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: encryption, access controls
    organizational_measures: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: training, policies

    # Contacts and agreements
    dpo_contact: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    processor_agreements: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: DPA references

    # Audit
    last_reviewed: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    __table_args__ = (
        Index("idx_dpr_org_name", "organization_id", "name"),
        Index("idx_dpr_reviewed", "last_reviewed"),
    )

    def __repr__(self) -> str:
        return f"<DataProcessingRecord {self.id}: {self.name}>"


class IncidentType(str, Enum):
    """Privacy incident types"""

    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH = "data_breach"
    IMPROPER_DISCLOSURE = "improper_disclosure"
    LOSS_OF_DATA = "loss_of_data"
    PROCESSING_VIOLATION = "processing_violation"
    CONSENT_VIOLATION = "consent_violation"
    CROSS_BORDER_VIOLATION = "cross_border_violation"
    RETENTION_VIOLATION = "retention_violation"


class IncidentSeverity(str, Enum):
    """Privacy incident severity"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """Privacy incident status"""

    REPORTED = "reported"
    UNDER_INVESTIGATION = "under_investigation"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class PrivacyIncident(BaseModel):
    """
    Privacy Incident model for GDPR Article 33-34 and CCPA § 1798.82.
    Tracks data breaches and processing violations with notification obligations.
    """

    __tablename__ = "privacy_incidents"

    # Organization
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Incident metadata
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    incident_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(50),
        default=IncidentSeverity.MEDIUM.value,
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=IncidentStatus.REPORTED.value,
        nullable=False,
        index=True,
    )

    # Impact assessment
    data_types_affected: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON
    subjects_affected_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    regulations_implicated: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON: GDPR, CCPA, etc.

    # Notification obligations
    notification_required: Mapped[bool] = mapped_column(Boolean, default=True)
    notification_deadline: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    supervisory_authority_notified: Mapped[bool] = mapped_column(
        Boolean, default=False
    )
    subjects_notified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Response actions
    containment_actions: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_steps: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON

    __table_args__ = (
        Index("idx_incident_org_status", "organization_id", "status"),
        Index("idx_incident_severity", "severity"),
        Index("idx_incident_deadline", "notification_deadline"),
    )

    def __repr__(self) -> str:
        return f"<PrivacyIncident {self.id}: {self.title}>"
