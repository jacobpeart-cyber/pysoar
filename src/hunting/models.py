"""SQLAlchemy models for the Threat Hunting subsystem

Provides data models for structured, hypothesis-driven security investigations
with support for MITRE ATT&CK framework integration, findings management, and
investigation notebooks.
"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class HuntStatus(str, Enum):
    """Status of a hunt hypothesis"""

    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class HuntPriority(str, Enum):
    """Priority level for a hunt"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class HuntType(str, Enum):
    """Type of hunt investigation"""

    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    IOC_SWEEP = "ioc_sweep"
    BEHAVIORAL = "behavioral"
    ANOMALY = "anomaly"
    THREAT_ACTOR = "threat_actor"


class SessionStatus(str, Enum):
    """Status of a hunt execution session"""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    """Severity level of a finding"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingClassification(str, Enum):
    """Classification of a finding"""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class TemplateDifficulty(str, Enum):
    """Difficulty level of a hunt template"""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class HuntHypothesis(BaseModel):
    """A hunt hypothesis before execution

    Represents a structured security investigation hypothesis with MITRE
    framework integration, defining what to look for and why.
    """

    __tablename__ = "hunt_hypotheses"

    # Core fields
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50),
        default=HuntStatus.DRAFT.value,
        nullable=False,
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        String(50),
        default=HuntPriority.MEDIUM.value,
        nullable=False,
        index=True,
    )
    hunt_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    # MITRE ATT&CK Framework integration
    mitre_tactics: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of tactic IDs
    mitre_techniques: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of technique IDs

    # Data sources and evidence
    data_sources: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of data source names
    expected_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Organization
    tags: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Relationships
    created_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<HuntHypothesis {self.id}: {self.title[:50]}>"


class HuntSession(BaseModel):
    """An execution of a hunt hypothesis

    Tracks the execution state, queries run, and results collected during
    a hunt investigation.
    """

    __tablename__ = "hunt_sessions"

    # Relationship to hypothesis
    hypothesis_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hunt_hypotheses.id"),
        nullable=False,
        index=True,
    )

    # Execution state
    status: Mapped[str] = mapped_column(
        String(50),
        default=SessionStatus.PENDING.value,
        nullable=False,
        index=True,
    )
    started_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Execution statistics
    query_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events_analyzed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Query execution details
    queries_executed: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of query dicts with timing

    # Runtime parameters
    parameters: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # time_range, scope, etc.

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # User tracking
    created_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<HuntSession {self.id}: hypothesis={self.hypothesis_id[:8]}... status={self.status}>"


class HuntFinding(BaseModel):
    """A finding discovered during a hunt session

    Documents potential security findings with evidence, severity, and
    classification for further review and escalation.
    """

    __tablename__ = "hunt_findings"

    # Relationship to session
    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hunt_sessions.id"),
        nullable=False,
        index=True,
    )

    # Finding details
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Classification
    severity: Mapped[str] = mapped_column(
        String(50),
        default=FindingSeverity.MEDIUM.value,
        nullable=False,
        index=True,
    )
    classification: Mapped[str] = mapped_column(
        String(50),
        default=FindingClassification.NEEDS_REVIEW.value,
        nullable=False,
        index=True,
    )

    # Evidence and artifacts
    evidence: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of evidence items
    affected_assets: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of hostnames/IPs
    iocs_found: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # List of IOCs
    mitre_techniques: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # Associated techniques
    log_entry_ids: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # Related log IDs

    # Analysis
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Escalation
    escalated_to_case: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    case_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # User tracking
    created_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<HuntFinding {self.id}: {self.title[:50]} severity={self.severity}>"


class HuntTemplate(BaseModel):
    """A reusable hunt template

    Provides pre-built investigation templates for common threat hunting
    scenarios with hypothesis templates and default queries.
    """

    __tablename__ = "hunt_templates"

    # Core fields
    name: Mapped[str] = mapped_column(String(500), nullable=False, index=True, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)

    # Hunt configuration
    hunt_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    hypothesis_template: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # Template text with placeholders
    default_queries: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of query templates

    # MITRE ATT&CK Framework
    mitre_tactics: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    mitre_techniques: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Requirements
    data_sources_required: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    estimated_duration_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Difficulty and organization
    difficulty: Mapped[str] = mapped_column(
        String(50),
        default=TemplateDifficulty.INTERMEDIATE.value,
        nullable=False,
    )
    tags: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Status
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    def __repr__(self) -> str:
        return f"<HuntTemplate {self.id}: {self.name}>"


class HuntNotebook(BaseModel):
    """Investigation notebook for documenting a hunt

    Provides an interactive notebook interface for documenting hunt
    investigations with markdown notes, queries, and visualizations.
    """

    __tablename__ = "hunt_notebooks"

    # Relationship to session
    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hunt_sessions.id"),
        nullable=False,
        index=True,
    )

    # Content
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    content: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of cell dicts

    # Version control
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Publishing
    is_published: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    published_at: Mapped[Optional[DateTime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<HuntNotebook {self.id}: {self.title}>"
