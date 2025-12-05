"""Alert model for security alerts"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User
    from src.models.incident import Incident


class AlertSeverity(str, Enum):
    """Alert severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Alert status values"""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertSource(str, Enum):
    """Source of the alert"""

    SIEM = "siem"
    EDR = "edr"
    IDS = "ids"
    FIREWALL = "firewall"
    EMAIL_GATEWAY = "email_gateway"
    CLOUD = "cloud"
    MANUAL = "manual"
    API = "api"
    INTEGRATION = "integration"


class Alert(BaseModel):
    """Security alert model"""

    __tablename__ = "alerts"

    # Core fields
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(50),
        default=AlertSeverity.MEDIUM.value,
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=AlertStatus.NEW.value,
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        default=AlertSource.MANUAL.value,
        nullable=False,
        index=True,
    )

    # Source reference
    source_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Classification
    alert_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Impact and priority
    priority: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    # Raw data and enrichment
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    enrichment_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Related entities
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Assignment
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    # Incident linkage
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("incidents.id"),
        nullable=True,
    )

    # Resolution
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Relationships
    assignee: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="assigned_alerts",
        foreign_keys=[assigned_to],
    )
    incident: Mapped[Optional["Incident"]] = relationship(
        "Incident",
        back_populates="alerts",
        foreign_keys=[incident_id],
    )

    def __repr__(self) -> str:
        return f"<Alert {self.id}: {self.title[:50]}>"
