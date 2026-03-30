"""Collaboration models for real-time war room and incident coordination"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.incident import Incident


class WarRoomType(str, Enum):
    """Types of war rooms"""

    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNT = "threat_hunt"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    TABLETOP_EXERCISE = "tabletop_exercise"
    POST_MORTEM = "post_mortem"
    GENERAL = "general"


class WarRoomStatus(str, Enum):
    """War room status"""

    ACTIVE = "active"
    STANDBY = "standby"
    ARCHIVED = "archived"


class MessageType(str, Enum):
    """Types of messages in war room"""

    TEXT = "text"
    STATUS_UPDATE = "status_update"
    EVIDENCE = "evidence"
    ACTION_ITEM = "action_item"
    DECISION = "decision"
    TIMELINE_EVENT = "timeline_event"
    ALERT_LINK = "alert_link"
    ARTIFACT = "artifact"
    COMMAND_OUTPUT = "command_output"
    AI_ANALYSIS = "ai_analysis"
    SYSTEM_NOTIFICATION = "system_notification"


class ArtifactType(str, Enum):
    """Types of artifacts in war room"""

    SCREENSHOT = "screenshot"
    PCAP = "pcap"
    LOG_FILE = "log_file"
    MEMORY_DUMP = "memory_dump"
    IOC_LIST = "ioc_list"
    TIMELINE = "timeline"
    REPORT = "report"
    CONFIG_FILE = "config_file"
    MALWARE_SAMPLE = "malware_sample"
    NETWORK_DIAGRAM = "network_diagram"
    PLAYBOOK_OUTPUT = "playbook_output"


class ActionPriority(str, Enum):
    """Action item priority levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ActionStatus(str, Enum):
    """Action item status"""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class TimelineEventType(str, Enum):
    """Types of timeline events"""

    DETECTION = "detection"
    TRIAGE = "triage"
    ESCALATION = "escalation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    COMMUNICATION = "communication"
    DECISION = "decision"
    ACTION = "action"
    EVIDENCE_COLLECTED = "evidence_collected"
    STATUS_CHANGE = "status_change"


class WarRoom(BaseModel):
    """Real-time incident command war room"""

    __tablename__ = "war_rooms"

    # Core fields
    organization_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Linking
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("incidents.id"),
        nullable=True,
        index=True,
    )

    # Room configuration
    room_type: Mapped[str] = mapped_column(
        String(50),
        default=WarRoomType.INCIDENT_RESPONSE.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=WarRoomStatus.ACTIVE.value,
        nullable=False,
        index=True,
    )
    severity_level: Mapped[str] = mapped_column(String(50), nullable=False)
    commander_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Participants (JSON array of user IDs)
    participants: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    max_participants: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    # Auto-archival
    auto_archive_hours: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)

    # Content management
    pinned_items: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    messages: Mapped[list["WarRoomMessage"]] = relationship(
        "WarRoomMessage",
        back_populates="war_room",
        cascade="all, delete-orphan",
        foreign_keys="WarRoomMessage.room_id",
    )
    artifacts: Mapped[list["SharedArtifact"]] = relationship(
        "SharedArtifact",
        back_populates="war_room",
        cascade="all, delete-orphan",
        foreign_keys="SharedArtifact.room_id",
    )
    action_items: Mapped[list["ActionItem"]] = relationship(
        "ActionItem",
        back_populates="war_room",
        cascade="all, delete-orphan",
        foreign_keys="ActionItem.room_id",
    )
    timeline_events: Mapped[list["IncidentTimeline"]] = relationship(
        "IncidentTimeline",
        back_populates="war_room",
        cascade="all, delete-orphan",
        foreign_keys="IncidentTimeline.room_id",
    )

    def __repr__(self) -> str:
        return f"<WarRoom {self.id}: {self.name}>"


class WarRoomMessage(BaseModel):
    """Real-time messages in war room"""

    __tablename__ = "war_room_messages"

    # Core fields
    organization_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    room_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("war_rooms.id"),
        nullable=False,
        index=True,
    )

    # Author
    sender_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sender_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Message content
    message_type: Mapped[str] = mapped_column(
        String(50),
        default=MessageType.TEXT.value,
        nullable=False,
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    attachments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Interactions
    mentioned_users: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    is_pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_edited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    edited_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Threading
    parent_message_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("war_room_messages.id"),
        nullable=True,
    )

    # Reactions and metadata
    reactions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    metadata: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Relationships
    war_room: Mapped["WarRoom"] = relationship(
        "WarRoom",
        back_populates="messages",
        foreign_keys=[room_id],
    )
    replies: Mapped[list["WarRoomMessage"]] = relationship(
        "WarRoomMessage",
        remote_side=[id],
        back_populates="parent_message",
        cascade="all, delete-orphan",
    )
    parent_message: Mapped[Optional["WarRoomMessage"]] = relationship(
        "WarRoomMessage",
        back_populates="replies",
        remote_side=[parent_message_id],
    )

    def __repr__(self) -> str:
        return f"<WarRoomMessage {self.id}: {self.message_type}>"


class SharedArtifact(BaseModel):
    """Artifacts shared in war room"""

    __tablename__ = "shared_artifacts"

    # Core fields
    organization_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    room_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("war_rooms.id"),
        nullable=False,
        index=True,
    )

    # Metadata
    uploaded_by: Mapped[str] = mapped_column(String(36), nullable=False)
    artifact_type: Mapped[str] = mapped_column(
        String(50),
        default=ArtifactType.REPORT.value,
        nullable=False,
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Security
    classification_level: Mapped[str] = mapped_column(String(50), nullable=False)
    access_restricted_to: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Tracking
    download_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    analysis_status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)

    # Relationships
    war_room: Mapped["WarRoom"] = relationship(
        "WarRoom",
        back_populates="artifacts",
        foreign_keys=[room_id],
    )

    def __repr__(self) -> str:
        return f"<SharedArtifact {self.id}: {self.file_name}>"


class ActionItem(BaseModel):
    """Action items tracked in war room"""

    __tablename__ = "action_items"

    # Core fields
    organization_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    room_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("war_rooms.id"),
        nullable=False,
        index=True,
    )

    # Task details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Assignment
    assigned_to: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    assigned_by: Mapped[str] = mapped_column(String(36), nullable=False)

    # Priority and status
    priority: Mapped[str] = mapped_column(
        String(50),
        default=ActionPriority.MEDIUM.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=ActionStatus.PENDING.value,
        nullable=False,
        index=True,
    )

    # Tracking
    due_date: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Linking
    linked_alert_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    linked_incident_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Additional info
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    checklist: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Relationships
    war_room: Mapped["WarRoom"] = relationship(
        "WarRoom",
        back_populates="action_items",
        foreign_keys=[room_id],
    )

    def __repr__(self) -> str:
        return f"<ActionItem {self.id}: {self.title}>"


class IncidentTimeline(BaseModel):
    """Timeline events for incident"""

    __tablename__ = "incident_timeline"

    # Core fields
    organization_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    room_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("war_rooms.id"),
        nullable=False,
        index=True,
    )

    # Event details
    event_time: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(
        String(50),
        default=TimelineEventType.ACTION.value,
        nullable=False,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)

    # Linking
    evidence_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    is_key_event: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    war_room: Mapped["WarRoom"] = relationship(
        "WarRoom",
        back_populates="timeline_events",
        foreign_keys=[room_id],
    )

    def __repr__(self) -> str:
        return f"<IncidentTimeline {self.id}: {self.event_type}>"
