"""Incident model for security incident management"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User
    from src.models.alert import Alert
    from src.models.playbook import PlaybookExecution


class IncidentSeverity(str, Enum):
    """Incident severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    """Incident status values"""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"


class IncidentType(str, Enum):
    """Types of security incidents"""

    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS = "denial_of_service"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE = "ransomware"
    APT = "advanced_persistent_threat"
    OTHER = "other"


class Incident(BaseModel):
    """Security incident model"""

    __tablename__ = "incidents"

    # Core fields
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(50),
        default=IncidentSeverity.MEDIUM.value,
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=IncidentStatus.OPEN.value,
        nullable=False,
        index=True,
    )
    incident_type: Mapped[str] = mapped_column(
        String(100),
        default=IncidentType.OTHER.value,
        nullable=False,
    )

    # Priority and impact
    priority: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_systems: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    affected_users: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Timeline
    detected_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    contained_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resolved_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Assignment
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    # Investigation
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicators: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON - IOCs
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON - file paths, logs

    # Resolution
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # External references
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ticket_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Tags and classification
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    mitre_tactics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Relationships
    assignee: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="assigned_incidents",
        foreign_keys=[assigned_to],
    )
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="incident",
        foreign_keys="Alert.incident_id",
    )
    playbook_executions: Mapped[list["PlaybookExecution"]] = relationship(
        "PlaybookExecution",
        back_populates="incident",
    )

    def __repr__(self) -> str:
        return f"<Incident {self.id}: {self.title[:50]}>"
