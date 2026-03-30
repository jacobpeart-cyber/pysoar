"""Real-Time War Room / Collaboration Module for PySOAR

Provides incident command, real-time messaging, artifact sharing, and post-mortem
analysis capabilities for coordinated incident response.

Components:
- WarRoom: Central coordination hub for incident response teams
- Messages: Real-time communication with threading and status updates
- SharedArtifacts: Secure file and evidence sharing
- ActionItems: Task tracking and assignment
- Timeline: Chronological event tracking and reporting
- PostMortem: Automated analysis and lessons learned extraction
"""

from src.collaboration.models import (
    WarRoom,
    WarRoomMessage,
    SharedArtifact,
    ActionItem,
    IncidentTimeline,
    WarRoomType,
    WarRoomStatus,
    MessageType,
    ArtifactType,
    ActionPriority,
    ActionStatus,
    TimelineEventType,
)
from src.collaboration.engine import (
    WarRoomManager,
    MessageEngine,
    ArtifactManager,
    ActionTracker,
    TimelineManager,
    PostMortemGenerator,
)

__all__ = [
    # Models
    "WarRoom",
    "WarRoomMessage",
    "SharedArtifact",
    "ActionItem",
    "IncidentTimeline",
    # Enums
    "WarRoomType",
    "WarRoomStatus",
    "MessageType",
    "ArtifactType",
    "ActionPriority",
    "ActionStatus",
    "TimelineEventType",
    # Engines
    "WarRoomManager",
    "MessageEngine",
    "ArtifactManager",
    "ActionTracker",
    "TimelineManager",
    "PostMortemGenerator",
]
