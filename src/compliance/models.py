"""
Compliance Models

SQLAlchemy models for all compliance frameworks, controls, evidence, and assessments.
Supports multi-tenant compliance tracking with full audit trail.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import (
    String,
    Integer,
    Float,
    Text,
    DateTime,
    Boolean,
    JSON,
    Index,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base, BaseModel, utc_now

__all__ = [
    "ComplianceFramework",
    "ComplianceControl",
    "POAM",
    "ComplianceEvidence",
    "ComplianceAssessment",
    "CUIMarking",
    "CISADirective",
]


class ComplianceFramework(BaseModel):
    """
    Compliance Framework registration and tracking.

    Stores framework metadata, baseline controls, and current compliance status.
    Supports multiple frameworks per organization for gap analysis and cross-mapping.
    """

    __tablename__ = "compliance_frameworks"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    short_name: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # fedramp, nist_800_53, cmmc, etc.
    version: Mapped[str] = mapped_column(String(50))
    description: Mapped[Optional[str]] = mapped_column(Text)
    authority: Mapped[str] = mapped_column(String(255))  # NIST, DoD, HHS, PCI SSC, etc.

    total_controls: Mapped[int] = mapped_column(Integer, default=0)
    implemented_controls: Mapped[int] = mapped_column(Integer, default=0)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)

    status: Mapped[str] = mapped_column(
        String(50), default="not_started"
    )  # not_started, in_progress, partially_compliant, compliant, non_compliant

    last_assessment_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_assessment_due: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True, index=True
    )
    certification_level: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # FedRAMP High, CMMC Level 2, IL4, etc.

    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    extra_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "short_name", name="uq_org_framework"),
    )


class ComplianceControl(BaseModel):
    """
    Individual compliance control across all frameworks.

    Tracks implementation status, assessment results, evidence, and remediation.
    Supports cross-framework mappings (e.g., NIST 800-53 AC-1 -> CMMC 1.001, etc.)
    """

    __tablename__ = "compliance_controls"

    framework_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("compliance_frameworks.id"), nullable=False, index=True
    )

    control_id: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # AC-1, SC-12, 3.1.1, etc.
    control_family: Mapped[str] = mapped_column(
        String(100)
    )  # Access Control, System Communications, etc.
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    priority: Mapped[str] = mapped_column(String(20), default="p2")  # p1, p2, p3
    baseline: Mapped[Optional[str]] = mapped_column(
        String(50)
    )  # low, moderate, high (FedRAMP)

    status: Mapped[str] = mapped_column(
        String(50), default="not_implemented", index=True
    )  # not_implemented, planned, partially_implemented, implemented, not_applicable
    implementation_status: Mapped[float] = mapped_column(
        Float, default=0.0
    )  # 0-100%
    implementation_details: Mapped[Optional[str]] = mapped_column(Text)
    responsible_party: Mapped[Optional[str]] = mapped_column(String(255))

    assessment_method: Mapped[str] = mapped_column(
        String(50), default="examine"
    )  # examine, interview, test, automated
    assessment_frequency: Mapped[str] = mapped_column(
        String(50), default="annual"
    )  # continuous, monthly, quarterly, annual
    last_assessed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True, index=True
    )
    last_assessment_result: Mapped[Optional[str]] = mapped_column(
        String(50)
    )  # satisfied, other_than_satisfied, not_assessed

    evidence_ids: Mapped[List[str]] = mapped_column(JSON, default=[])
    related_controls: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})
    mitre_techniques: Mapped[List[str]] = mapped_column(JSON, default=[])
    automated_check_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    risk_if_not_implemented: Mapped[str] = mapped_column(
        String(20), default="high"
    )  # high, medium, low, critical
    remediation_guidance: Mapped[Optional[str]] = mapped_column(Text)
    poam_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("poams.id"), nullable=True
    )

    tags: Mapped[List[str]] = mapped_column(JSON, default=[])
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_control_framework_id", "framework_id", "control_id"),
        UniqueConstraint("framework_id", "control_id", name="uq_framework_control"),
    )


class POAM(BaseModel):
    """
    Plan of Action & Milestones (POA&M)

    Tracks weaknesses, remediation efforts, and milestones for non-compliant controls.
    Includes risk rating, resource requirements, and approval workflow.
    """

    __tablename__ = "poams"

    control_id_ref: Mapped[str] = mapped_column(
        String(36), ForeignKey("compliance_controls.id"), nullable=False, index=True
    )

    weakness_name: Mapped[str] = mapped_column(String(500), nullable=False)
    weakness_description: Mapped[Optional[str]] = mapped_column(Text)
    weakness_source: Mapped[str] = mapped_column(
        String(100)
    )  # assessment, audit, scan, incident, self_identified

    risk_level: Mapped[str] = mapped_column(
        String(20), default="high"
    )  # very_high, high, moderate, low
    original_risk_rating: Mapped[Optional[float]] = mapped_column(Float)
    residual_risk_rating: Mapped[Optional[float]] = mapped_column(Float)

    status: Mapped[str] = mapped_column(
        String(50), default="open", index=True
    )  # open, in_progress, delayed, completed, cancelled, accepted
    milestone_changes: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=[])
    scheduled_completion_date: Mapped[datetime] = mapped_column(DateTime, index=True)
    actual_completion_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    milestones: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=[])
    resources_required: Mapped[Optional[str]] = mapped_column(Text)
    cost_estimate: Mapped[Optional[float]] = mapped_column(Float)
    compensating_controls: Mapped[Optional[str]] = mapped_column(Text)
    vendor_dependencies: Mapped[List[str]] = mapped_column(JSON, default=[])

    assigned_to: Mapped[Optional[str]] = mapped_column(String(255))
    approved_by: Mapped[Optional[str]] = mapped_column(String(255))
    comments: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=[])

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )


class ComplianceEvidence(BaseModel):
    """
    Compliance Evidence Repository

    Stores all supporting evidence for control implementation and assessment.
    Includes file integrity tracking, automated evidence collection, and review workflow.
    """

    __tablename__ = "compliance_evidence"

    control_id_ref: Mapped[str] = mapped_column(
        String(36), ForeignKey("compliance_controls.id"), nullable=False, index=True
    )

    evidence_type: Mapped[str] = mapped_column(
        String(50)
    )  # document, screenshot, log, configuration, scan_result, policy, procedure, automated_test, interview_notes, training_record
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text)

    file_path: Mapped[Optional[str]] = mapped_column(String(500))
    file_hash: Mapped[Optional[str]] = mapped_column(String(128))  # SHA-512
    content: Mapped[Optional[str]] = mapped_column(Text)
    source_system: Mapped[Optional[str]] = mapped_column(String(255))

    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    collected_by: Mapped[str] = mapped_column(String(255))
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True, index=True
    )

    review_status: Mapped[str] = mapped_column(
        String(50), default="pending"
    )  # pending, reviewed, approved, rejected
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(255))
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    tags: Mapped[List[str]] = mapped_column(JSON, default=[])
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )


class ComplianceAssessment(BaseModel):
    """
    Compliance Assessment Execution Record

    Tracks assessment runs, findings, and overall results per framework.
    Supports multiple assessment types and assessment agencies.
    """

    __tablename__ = "compliance_assessments"

    framework_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("compliance_frameworks.id"), nullable=False, index=True
    )

    assessment_type: Mapped[str] = mapped_column(
        String(50)
    )  # self_assessment, third_party, conmon, annual_review, readiness, gap_analysis
    assessor: Mapped[str] = mapped_column(String(255), index=True)
    assessment_date: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)

    status: Mapped[str] = mapped_column(
        String(50), default="in_progress"
    )  # planned, in_progress, completed, submitted
    scope: Mapped[Optional[str]] = mapped_column(Text)

    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    satisfied_count: Mapped[int] = mapped_column(Integer, default=0)
    other_than_satisfied_count: Mapped[int] = mapped_column(Integer, default=0)
    overall_result: Mapped[Optional[str]] = mapped_column(String(50))

    report_path: Mapped[Optional[str]] = mapped_column(String(500))
    next_steps: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=[])

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )


class CUIMarking(BaseModel):
    """
    Controlled Unclassified Information (CUI) Marking and Handling

    Tracks CUI assets, dissemination controls, and authorized access per NIST 800-171.
    Supports DoD and Federal CUI categories and handling requirements.
    """

    __tablename__ = "cui_markings"

    asset_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(
        String(50)
    )  # document, email, database_record, file, system
    cui_category: Mapped[str] = mapped_column(
        String(100)
    )  # CTI, ITAR, EXPT, PRVCY, PROPIN, DCRIT, etc.
    cui_designation: Mapped[str] = mapped_column(
        String(50)
    )  # CUI, CUI//SP-CTI, CUI//SP-EXPT, etc.

    dissemination_controls: Mapped[List[str]] = mapped_column(
        JSON, default=[]
    )  # NOFORN, FEDCON, DL ONLY, etc.
    handling_instructions: Mapped[Optional[str]] = mapped_column(Text)
    classification_authority: Mapped[str] = mapped_column(String(255))
    declassification_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    access_list: Mapped[List[str]] = mapped_column(JSON, default=[])
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_cui_asset_org", "asset_id", "organization_id"),
    )


class CISADirective(BaseModel):
    """
    CISA Binding Operational Directive (BOD) and Emergency Directive (ED) Tracking

    Tracks active CISA directives, compliance deadlines, and remediation actions.
    BODs and EDs are mandatory requirements for federal agencies.
    """

    __tablename__ = "cisa_directives"

    directive_id: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True, unique=True
    )  # BOD 22-01, ED 24-01, etc.
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    directive_type: Mapped[str] = mapped_column(String(50))  # bod, ed
    effective_date: Mapped[datetime] = mapped_column(DateTime)
    compliance_deadline: Mapped[datetime] = mapped_column(DateTime, index=True)

    status: Mapped[str] = mapped_column(
        String(50), default="active"
    )  # active, superseded, expired
    requirements: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=[])
    compliance_status: Mapped[str] = mapped_column(
        String(50), default="in_progress"
    )  # in_progress, compliant, non_compliant

    actions_taken: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=[])
    evidence_ids: Mapped[List[str]] = mapped_column(JSON, default=[])

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )
