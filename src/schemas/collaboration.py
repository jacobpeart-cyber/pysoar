"""Pydantic schemas for war room and collaboration module"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# ============================================================================
# War Room Schemas
# ============================================================================


class WarRoomBase(BaseModel):
    """Base war room schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    room_type: str
    severity_level: str
    max_participants: int = Field(default=50, ge=1, le=500)
    auto_archive_hours: Optional[int] = Field(None, ge=1)
    is_encrypted: bool = False
    tags: Optional[list[str]] = None


class WarRoomCreate(WarRoomBase):
    """Schema for creating a war room"""

    incident_id: Optional[str] = None
    commander_id: Optional[str] = None


class WarRoomUpdate(BaseModel):
    """Schema for updating a war room"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    commander_id: Optional[str] = None
    severity_level: Optional[str] = None
    tags: Optional[list[str]] = None


class WarRoomResponse(WarRoomBase, DBModel):
    """Schema for war room response"""

    id: str
    organization_id: str
    incident_id: Optional[str] = None
    status: str
    commander_id: Optional[str] = None
    participants: list[str] = Field(default_factory=list)
    created_by: str
    pinned_items: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WarRoomListResponse(BaseModel):
    """Schema for paginated war room list"""

    items: list[WarRoomResponse]
    total: int
    page: int
    size: int
    pages: int


class WarRoomSummary(BaseModel):
    """War room summary with metrics"""

    id: str
    name: str
    status: str
    room_type: str
    severity_level: str
    participants: list[str]
    message_count: int
    action_count: int
    artifact_count: int
    created_at: datetime
    updated_at: datetime


# ============================================================================
# Message Schemas
# ============================================================================


class WarRoomMessageBase(BaseModel):
    """Base message schema"""

    content: str = Field(..., min_length=1)
    message_type: str = "text"
    mentioned_users: Optional[list[str]] = None
    metadata: Optional[dict[str, Any]] = None


class WarRoomMessageCreate(WarRoomMessageBase):
    """Schema for creating a message"""

    attachments: Optional[list[str]] = None


class WarRoomMessageUpdate(BaseModel):
    """Schema for updating a message"""

    content: str = Field(..., min_length=1)


class WarRoomMessageResponse(WarRoomMessageBase, DBModel):
    """Schema for message response"""

    id: str
    room_id: str
    sender_id: str
    sender_name: str
    is_pinned: bool
    is_edited: bool
    edited_at: Optional[datetime] = None
    parent_message_id: Optional[str] = None
    reactions: dict[str, list[str]] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WarRoomMessageListResponse(BaseModel):
    """Schema for paginated message list"""

    items: list[WarRoomMessageResponse]
    total: int
    page: int
    size: int


class MessageThreadResponse(BaseModel):
    """Response for message thread"""

    parent: WarRoomMessageResponse
    replies: list[WarRoomMessageResponse]


# ============================================================================
# Artifact Schemas
# ============================================================================


class SharedArtifactBase(BaseModel):
    """Base artifact schema"""

    artifact_type: str
    file_name: str = Field(..., min_length=1, max_length=255)
    classification_level: str
    description: Optional[str] = None


class SharedArtifactCreate(SharedArtifactBase):
    """Schema for creating an artifact"""

    file_hash: str
    file_size_bytes: int = Field(..., ge=0)
    access_restricted_to: Optional[list[str]] = None


class SharedArtifactResponse(SharedArtifactBase, DBModel):
    """Schema for artifact response"""

    id: str
    room_id: str
    uploaded_by: str
    file_hash: str
    file_size_bytes: int
    download_count: int
    analysis_status: str
    access_restricted_to: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SharedArtifactListResponse(BaseModel):
    """Schema for paginated artifact list"""

    items: list[SharedArtifactResponse]
    total: int
    page: int
    size: int


class ArtifactIndex(BaseModel):
    """Index of artifacts in room"""

    total: int
    by_type: dict[str, int]
    artifacts: list[dict[str, Any]]


# ============================================================================
# Action Item Schemas
# ============================================================================


class ActionItemBase(BaseModel):
    """Base action item schema"""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    priority: str = "medium"
    due_date: Optional[datetime] = None


class ActionItemCreate(ActionItemBase):
    """Schema for creating an action item"""

    assigned_to: Optional[str] = None


class ActionItemUpdate(BaseModel):
    """Schema for updating an action item"""

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    notes: Optional[str] = None


class ActionItemResponse(ActionItemBase, DBModel):
    """Schema for action item response"""

    id: str
    room_id: str
    status: str
    assigned_to: Optional[str] = None
    assigned_by: str
    linked_alert_id: Optional[str] = None
    linked_incident_id: Optional[str] = None
    notes: Optional[str] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ActionItemListResponse(BaseModel):
    """Schema for paginated action item list"""

    items: list[ActionItemResponse]
    total: int
    page: int
    size: int


class ActionReport(BaseModel):
    """Action items report"""

    total: int
    by_status: dict[str, int]
    by_priority: dict[str, int]
    overdue: int
    actions: list[dict[str, Any]]


# ============================================================================
# Timeline Schemas
# ============================================================================


class IncidentTimelineBase(BaseModel):
    """Base timeline event schema"""

    event_type: str
    description: str = Field(..., min_length=1)
    event_time: Optional[datetime] = None
    is_key_event: bool = False
    mitre_technique: Optional[str] = None


class IncidentTimelineCreate(IncidentTimelineBase):
    """Schema for creating timeline event"""

    evidence_ids: Optional[list[str]] = None


class IncidentTimelineResponse(IncidentTimelineBase, DBModel):
    """Schema for timeline event response"""

    id: str
    room_id: str
    created_by: str
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class IncidentTimelineListResponse(BaseModel):
    """Schema for paginated timeline list"""

    items: list[IncidentTimelineResponse]
    total: int
    page: int
    size: int


# ============================================================================
# Report Schemas
# ============================================================================


class PostMortemReport(BaseModel):
    """Post-mortem report"""

    title: str
    incident_id: Optional[str] = None
    room_type: str
    severity: str
    duration_minutes: int
    timeline: list[dict[str, Any]]
    actions_taken: int
    key_decisions: list[str]
    participants: list[str]
    generated_at: datetime


class SituationReport(BaseModel):
    """Situation report (SITREP)"""

    room_id: str
    period_hours: int
    generated_at: datetime
    message_count: int
    key_updates: list[str]
    decisions: list[str]
    action_items_open: int
    action_items_completed: int


class ResponseMetrics(BaseModel):
    """Response metrics for incident"""

    mttd: Optional[float] = None  # Mean time to detect (minutes)
    mttr: Optional[float] = None  # Mean time to respond (minutes)
    mttc: Optional[float] = None  # Mean time to contain (minutes)
    total_timeline_events: int
    key_events: int


class ImprovementRecommendation(BaseModel):
    """Improvement recommendation"""

    category: str
    recommendation: str
    priority: str = "medium"
    implementation_effort: str = "medium"


class PostMortemAnalysis(BaseModel):
    """Complete post-mortem analysis"""

    report: PostMortemReport
    metrics: ResponseMetrics
    lessons_learned: list[str]
    recommendations: list[ImprovementRecommendation]


# ============================================================================
# Dashboard Schemas
# ============================================================================


class RoomActivityMetrics(BaseModel):
    """Activity metrics for a room"""

    messages_last_hour: int
    messages_last_24h: int
    active_participants_last_hour: int
    pending_actions: int
    overdue_actions: int


class CollaborationDashboard(BaseModel):
    """Collaboration module dashboard"""

    active_rooms: int
    total_participants: int
    pending_actions: int
    overdue_actions: int
    recent_rooms: list[WarRoomSummary]
    critical_actions: list[ActionItemResponse]
    response_metrics: dict[str, Optional[float]]


class SearchResultsResponse(BaseModel):
    """Search results from messages and artifacts"""

    messages: list[WarRoomMessageResponse] = Field(default_factory=list)
    artifacts: list[SharedArtifactResponse] = Field(default_factory=list)
    total_results: int


# ============================================================================
# Bulk Operations
# ============================================================================


class BulkActionUpdate(BaseModel):
    """Bulk update action items"""

    action_ids: list[str]
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None


class BulkParticipantUpdate(BaseModel):
    """Bulk add/remove participants"""

    room_id: str
    user_ids: list[str]
    action: str = Field(..., pattern="^(add|remove)$")
