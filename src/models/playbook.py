"""Playbook models for security automation"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.incident import Incident


class PlaybookStatus(str, Enum):
    """Playbook status"""

    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class PlaybookTrigger(str, Enum):
    """Playbook trigger types"""

    MANUAL = "manual"
    ALERT = "alert"
    INCIDENT = "incident"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"


class ExecutionStatus(str, Enum):
    """Playbook execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class Playbook(BaseModel):
    """Playbook model for automation workflows"""

    __tablename__ = "playbooks"

    # Core fields
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50),
        default=PlaybookStatus.DRAFT.value,
        nullable=False,
    )

    # Trigger configuration
    trigger_type: Mapped[str] = mapped_column(
        String(50),
        default=PlaybookTrigger.MANUAL.value,
        nullable=False,
    )
    trigger_conditions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Playbook definition
    steps: Mapped[str] = mapped_column(Text, nullable=False)  # JSON - list of steps
    variables: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Metadata
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Settings
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=3, nullable=False)

    # Author
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Relationships
    executions: Mapped[list["PlaybookExecution"]] = relationship(
        "PlaybookExecution",
        back_populates="playbook",
    )

    def __repr__(self) -> str:
        return f"<Playbook {self.name}>"


class PlaybookExecution(BaseModel):
    """Playbook execution record"""

    __tablename__ = "playbook_executions"

    # Foreign keys
    playbook_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("playbooks.id"),
        nullable=False,
    )
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("incidents.id"),
        nullable=True,
    )

    # Execution status
    status: Mapped[str] = mapped_column(
        String(50),
        default=ExecutionStatus.PENDING.value,
        nullable=False,
    )
    current_step: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_steps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timing
    started_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Results
    input_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    output_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    step_results: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_step: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Triggered by
    triggered_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    trigger_source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Relationships
    playbook: Mapped["Playbook"] = relationship(
        "Playbook",
        back_populates="executions",
    )
    incident: Mapped[Optional["Incident"]] = relationship(
        "Incident",
        back_populates="playbook_executions",
    )

    def __repr__(self) -> str:
        return f"<PlaybookExecution {self.id} - {self.status}>"
