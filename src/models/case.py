"""Case management models for notes, attachments, and timeline"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User
    from src.models.incident import Incident


class NoteType(str, Enum):
    """Types of case notes"""

    GENERAL = "general"
    INVESTIGATION = "investigation"
    EVIDENCE = "evidence"
    REMEDIATION = "remediation"
    COMMUNICATION = "communication"
    ESCALATION = "escalation"


class CaseNote(BaseModel):
    """Notes attached to incidents/cases"""

    __tablename__ = "case_notes"

    # Content
    content: Mapped[str] = mapped_column(Text, nullable=False)
    note_type: Mapped[str] = mapped_column(
        String(50),
        default=NoteType.GENERAL.value,
        nullable=False,
    )

    # Visibility
    is_internal: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
    )

    # Relations
    incident: Mapped["Incident"] = relationship("Incident", back_populates="notes")
    author: Mapped["User"] = relationship("User")

    def __repr__(self) -> str:
        return f"<CaseNote {self.id}>"


class AttachmentType(str, Enum):
    """Types of attachments"""

    DOCUMENT = "document"
    IMAGE = "image"
    LOG = "log"
    PCAP = "pcap"
    MEMORY_DUMP = "memory_dump"
    MALWARE_SAMPLE = "malware_sample"
    SCREENSHOT = "screenshot"
    OTHER = "other"


class CaseAttachment(BaseModel):
    """File attachments for incidents/cases"""

    __tablename__ = "case_attachments"

    # File info
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA256

    # Classification
    attachment_type: Mapped[str] = mapped_column(
        String(50),
        default=AttachmentType.OTHER.value,
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Security
    is_malware: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )
    uploaded_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
    )

    # Relations
    incident: Mapped["Incident"] = relationship("Incident", back_populates="attachments")
    uploader: Mapped["User"] = relationship("User")

    def __repr__(self) -> str:
        return f"<CaseAttachment {self.filename}>"


class TimelineEventType(str, Enum):
    """Types of timeline events"""

    CREATED = "created"
    UPDATED = "updated"
    STATUS_CHANGE = "status_change"
    SEVERITY_CHANGE = "severity_change"
    ASSIGNMENT = "assignment"
    NOTE_ADDED = "note_added"
    ATTACHMENT_ADDED = "attachment_added"
    ALERT_LINKED = "alert_linked"
    PLAYBOOK_EXECUTED = "playbook_executed"
    ESCALATED = "escalated"
    CUSTOM = "custom"


class CaseTimeline(BaseModel):
    """Timeline events for incidents/cases"""

    __tablename__ = "case_timeline"

    # Event details
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Change tracking
    old_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Additional data (JSON)
    metadata: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    # Relations
    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline")
    actor: Mapped[Optional["User"]] = relationship("User")

    def __repr__(self) -> str:
        return f"<CaseTimeline {self.event_type}: {self.title}>"


class Task(BaseModel):
    """Tasks/action items for incidents"""

    __tablename__ = "case_tasks"

    # Task details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=3, nullable=False)

    # Dates
    due_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Assignment
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )
    created_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
    )

    # Relations
    incident: Mapped["Incident"] = relationship("Incident", back_populates="tasks")
    assignee: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_to])
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<Task {self.title}>"
