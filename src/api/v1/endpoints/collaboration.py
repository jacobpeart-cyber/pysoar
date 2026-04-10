"""Collaboration and war room API endpoints"""

import json
import math
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Path, HTTPException, Query, status, BackgroundTasks
from sqlalchemy import func, select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.collaboration.models import (
    WarRoom,
    WarRoomMessage,
    SharedArtifact,
    ActionItem,
    IncidentTimeline,
    WarRoomStatus,
    ActionStatus,
)
from src.collaboration.engine import (
    WarRoomManager,
    MessageEngine,
    ArtifactManager,
    ActionTracker,
    TimelineManager,
    PostMortemGenerator,
)
from src.schemas.collaboration import (
    WarRoomCreate,
    WarRoomUpdate,
    WarRoomResponse,
    WarRoomListResponse,
    WarRoomSummary,
    WarRoomMessageCreate,
    WarRoomMessageUpdate,
    WarRoomMessageResponse,
    WarRoomMessageListResponse,
    MessageThreadResponse,
    SharedArtifactCreate,
    SharedArtifactResponse,
    SharedArtifactListResponse,
    ArtifactIndex,
    ActionItemCreate,
    ActionItemUpdate,
    ActionItemResponse,
    ActionItemListResponse,
    ActionReport,
    IncidentTimelineCreate,
    IncidentTimelineResponse,
    IncidentTimelineListResponse,
    PostMortemReport,
    SituationReport,
    ResponseMetrics,
    ImprovementRecommendation,
    PostMortemAnalysis,
    CollaborationDashboard,
    RoomActivityMetrics,
    SearchResultsResponse,
    BulkActionUpdate,
    BulkParticipantUpdate,
)
from src.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/collaboration", tags=["Collaboration"])


# ============================================================================
# Helper Functions
# ============================================================================


async def get_war_room_or_404(db: AsyncSession, room_id: str) -> WarRoom:
    """Get war room by ID or raise 404"""
    result = await db.execute(select(WarRoom).where(WarRoom.id == room_id))
    room = result.scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="War room not found")
    return room


async def get_message_or_404(db: AsyncSession, message_id: str) -> WarRoomMessage:
    """Get message by ID or raise 404"""
    result = await db.execute(
        select(WarRoomMessage).where(WarRoomMessage.id == message_id)
    )
    message = result.scalar_one_or_none()
    if not message:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    return message


async def get_artifact_or_404(db: AsyncSession, artifact_id: str) -> SharedArtifact:
    """Get artifact by ID or raise 404"""
    result = await db.execute(
        select(SharedArtifact).where(SharedArtifact.id == artifact_id)
    )
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    return artifact


async def get_action_or_404(db: AsyncSession, action_id: str) -> ActionItem:
    """Get action item by ID or raise 404"""
    result = await db.execute(select(ActionItem).where(ActionItem.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action item not found")
    return action


# ============================================================================
# War Room Endpoints
# ============================================================================


@router.post("/rooms", response_model=WarRoomResponse, status_code=status.HTTP_201_CREATED)
async def create_war_room(
    room_data: WarRoomCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new war room"""
    manager = WarRoomManager(db)
    room = await manager.create_room(
        organization_id=getattr(current_user, "organization_id", None),
        name=room_data.name,
        room_type=room_data.room_type,
        severity_level=room_data.severity_level,
        created_by=str(current_user.id),
        incident_id=room_data.incident_id,
        description=room_data.description,
        commander_id=room_data.commander_id,
        max_participants=room_data.max_participants,
        auto_archive_hours=room_data.auto_archive_hours,
        is_encrypted=room_data.is_encrypted,
        tags=room_data.tags,
    )
    await db.commit()
    return room


@router.get("/rooms", response_model=WarRoomListResponse)
async def list_war_rooms(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    room_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """List war rooms with filtering"""
    query = select(WarRoom).where(WarRoom.organization_id == getattr(current_user, "organization_id", None))

    if status:
        query = query.where(WarRoom.status == status)

    if room_type:
        query = query.where(WarRoom.room_type == room_type)

    if search:
        query = query.where(WarRoom.name.ilike(f"%{search}%"))

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * size
    result = await db.execute(
        query.order_by(desc(WarRoom.created_at)).offset(offset).limit(size)
    )
    rooms = result.scalars().all()

    return WarRoomListResponse(
        items=rooms,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/rooms/{room_id}", response_model=WarRoomResponse)
async def get_war_room(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Get war room details"""
    room = await get_war_room_or_404(db, room_id)
    return room


@router.patch("/rooms/{room_id}", response_model=WarRoomResponse)
async def update_war_room(
    room_data: WarRoomUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Update war room"""
    room = await get_war_room_or_404(db, room_id)

    if room_data.name:
        room.name = room_data.name
    if room_data.description is not None:
        room.description = room_data.description
    if room_data.status:
        room.status = room_data.status
    if room_data.commander_id:
        room.commander_id = room_data.commander_id
    if room_data.severity_level:
        room.severity_level = room_data.severity_level
    if room_data.tags is not None:
        room.tags = json.dumps(room_data.tags)

    await db.commit()
    await db.refresh(room)
    return room


@router.post("/rooms/{room_id}/archive")
async def archive_war_room(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Archive war room"""
    room = await get_war_room_or_404(db, room_id)
    manager = WarRoomManager(db)
    await manager.archive_room(room_id)
    await db.commit()
    return {"status": "archived", "room_id": room_id}


@router.get("/rooms/{room_id}/summary", response_model=WarRoomSummary)
async def get_room_summary(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Get war room summary with metrics"""
    room = await get_war_room_or_404(db, room_id)
    manager = WarRoomManager(db)
    summary = await manager.get_room_summary(room_id)
    return WarRoomSummary(**summary)


@router.post("/rooms/{room_id}/join")
async def join_war_room(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Join a war room"""
    room = await get_war_room_or_404(db, room_id)
    manager = WarRoomManager(db)
    success = await manager.join_room(room_id, current_user.id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot join room - at capacity or invalid room",
        )

    await db.commit()
    return {"status": "joined", "room_id": room_id}


@router.post("/rooms/{room_id}/leave")
async def leave_war_room(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Leave a war room"""
    room = await get_war_room_or_404(db, room_id)
    manager = WarRoomManager(db)
    await manager.leave_room(room_id, current_user.id)
    await db.commit()
    return {"status": "left", "room_id": room_id}


@router.post("/rooms/{room_id}/commander/{user_id}")
async def set_war_room_commander(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    user_id: str = Path(...),
):
    """Set incident commander for war room"""
    room = await get_war_room_or_404(db, room_id)
    manager = WarRoomManager(db)
    success = await manager.set_commander(room_id, user_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to set commander")

    await db.commit()
    return {"status": "updated", "commander_id": user_id}


# ============================================================================
# Message Endpoints
# ============================================================================


@router.post("/rooms/{room_id}/messages", response_model=WarRoomMessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    msg_data: WarRoomMessageCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Send message to war room"""
    room = await get_war_room_or_404(db, room_id)
    engine = MessageEngine(db)

    message = await engine.send_message(
        room_id=room_id,
        organization_id=getattr(current_user, "organization_id", None),
        sender_id=str(current_user.id),
        sender_name=getattr(current_user, "full_name", None) or getattr(current_user, "email", "Unknown"),
        content=msg_data.content,
        message_type=msg_data.message_type,
        attachments=msg_data.attachments,
        mentioned_users=msg_data.mentioned_users,
        metadata=msg_data.metadata,
    )
    await db.commit()
    return message


@router.get("/rooms/{room_id}/messages", response_model=WarRoomMessageListResponse)
async def get_room_messages(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
):
    """Get room message history"""
    room = await get_war_room_or_404(db, room_id)
    engine = MessageEngine(db)
    messages, total = await engine.get_message_history(room_id, page=page, size=size)

    return WarRoomMessageListResponse(
        items=messages,
        total=total,
        page=page,
        size=size,
    )


@router.patch("/messages/{message_id}", response_model=WarRoomMessageResponse)
async def edit_message(
    msg_data: WarRoomMessageUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    message_id: str = Path(...),
):
    """Edit message"""
    message = await get_message_or_404(db, message_id)
    engine = MessageEngine(db)
    success = await engine.edit_message(message_id, msg_data.content)

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to edit message")

    await db.commit()
    await db.refresh(message)
    return message


@router.post("/messages/{message_id}/pin")
async def pin_message(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    message_id: str = Path(...),
):
    """Pin message in room"""
    message = await get_message_or_404(db, message_id)
    engine = MessageEngine(db)
    success = await engine.pin_message(message.room_id, message_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to pin message")

    await db.commit()
    return {"status": "pinned", "message_id": message_id}


@router.get("/rooms/{room_id}/messages/search", response_model=list[WarRoomMessageResponse])
async def search_messages(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
):
    """Search messages in room"""
    room = await get_war_room_or_404(db, room_id)
    engine = MessageEngine(db)
    messages = await engine.search_messages(room_id, q, limit=limit)
    return messages


@router.get("/rooms/{room_id}/messages/{message_id}/thread", response_model=MessageThreadResponse)
async def get_message_thread(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    message_id: str = Path(...),
):
    """Get message thread"""
    room = await get_war_room_or_404(db, room_id)
    parent = await get_message_or_404(db, message_id)

    # Get replies
    result = await db.execute(
        select(WarRoomMessage).where(
            WarRoomMessage.parent_message_id == message_id
        )
    )
    replies = result.scalars().all()

    return MessageThreadResponse(parent=parent, replies=replies)


# ============================================================================
# Artifact Endpoints
# ============================================================================


@router.post("/rooms/{room_id}/artifacts", response_model=SharedArtifactResponse, status_code=status.HTTP_201_CREATED)
async def upload_artifact(
    artifact_data: SharedArtifactCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Upload artifact to war room"""
    room = await get_war_room_or_404(db, room_id)
    manager = ArtifactManager(db)

    artifact = await manager.upload_artifact(
        room_id=room_id,
        organization_id=getattr(current_user, "organization_id", None),
        uploaded_by=current_user.id,
        file_name=artifact_data.file_name,
        file_hash=artifact_data.file_hash,
        file_size_bytes=artifact_data.file_size_bytes,
        artifact_type=artifact_data.artifact_type,
        classification_level=artifact_data.classification_level,
        description=artifact_data.description,
        access_restricted_to=artifact_data.access_restricted_to,
    )
    await db.commit()
    return artifact


@router.get("/rooms/{room_id}/artifacts", response_model=SharedArtifactListResponse)
async def list_room_artifacts(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    artifact_type: Optional[str] = None,
):
    """List artifacts in room"""
    room = await get_war_room_or_404(db, room_id)

    query = select(SharedArtifact).where(SharedArtifact.room_id == room_id)

    if artifact_type:
        query = query.where(SharedArtifact.artifact_type == artifact_type)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * size
    result = await db.execute(
        query.order_by(desc(SharedArtifact.created_at)).offset(offset).limit(size)
    )
    artifacts = result.scalars().all()

    return SharedArtifactListResponse(
        items=artifacts,
        total=total,
        page=page,
        size=size,
    )


@router.get("/artifacts/{artifact_id}", response_model=SharedArtifactResponse)
async def get_artifact(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    artifact_id: str = Path(...),
):
    """Get artifact details"""
    artifact = await get_artifact_or_404(db, artifact_id)
    return artifact


@router.post("/artifacts/{artifact_id}/download")
async def download_artifact(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    artifact_id: str = Path(...),
):
    """Track artifact download"""
    artifact = await get_artifact_or_404(db, artifact_id)
    manager = ArtifactManager(db)
    await manager.track_downloads(artifact_id)
    await db.commit()
    return {"status": "tracked", "download_count": artifact.download_count + 1}


@router.get("/rooms/{room_id}/artifacts/index")
async def get_artifact_index(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Get artifact index for room"""
    room = await get_war_room_or_404(db, room_id)
    manager = ArtifactManager(db)
    index = await manager.generate_artifact_index(room_id)
    return index


# ============================================================================
# Action Item Endpoints
# ============================================================================


@router.post("/rooms/{room_id}/actions", response_model=ActionItemResponse, status_code=status.HTTP_201_CREATED)
async def create_action_item(
    action_data: ActionItemCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Create action item"""
    room = await get_war_room_or_404(db, room_id)
    tracker = ActionTracker(db)

    action = await tracker.create_action_item(
        room_id=room_id,
        organization_id=getattr(current_user, "organization_id", None),
        title=action_data.title,
        description=action_data.description,
        assigned_by=str(current_user.id),
        assigned_to=action_data.assigned_to,
        priority=action_data.priority,
        due_date=action_data.due_date,
    )
    await db.commit()
    return action


@router.get("/rooms/{room_id}/actions", response_model=ActionItemListResponse)
async def list_room_actions(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
):
    """List action items in room"""
    room = await get_war_room_or_404(db, room_id)

    query = select(ActionItem).where(ActionItem.room_id == room_id)

    if status:
        query = query.where(ActionItem.status == status)

    if assigned_to:
        query = query.where(ActionItem.assigned_to == assigned_to)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * size
    result = await db.execute(
        query.order_by(ActionItem.priority).offset(offset).limit(size)
    )
    actions = result.scalars().all()

    return ActionItemListResponse(
        items=actions,
        total=total,
        page=page,
        size=size,
    )


@router.patch("/actions/{action_id}", response_model=ActionItemResponse)
async def update_action_item(
    action_data: ActionItemUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    action_id: str = Path(...),
):
    """Update action item"""
    action = await get_action_or_404(db, action_id)

    if action_data.title:
        action.title = action_data.title
    if action_data.description is not None:
        action.description = action_data.description
    if action_data.status:
        action.status = action_data.status
        if action_data.status == ActionStatus.COMPLETED.value:
            from src.models.base import utc_now
            action.completed_at = utc_now()
    if action_data.priority:
        action.priority = action_data.priority
    if action_data.assigned_to:
        action.assigned_to = action_data.assigned_to
    if action_data.due_date:
        action.due_date = action_data.due_date

    await db.commit()
    await db.refresh(action)
    return action


@router.get("/rooms/{room_id}/actions/report", response_model=ActionReport)
async def get_action_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Get action items report"""
    room = await get_war_room_or_404(db, room_id)
    tracker = ActionTracker(db)
    report = await tracker.generate_action_report(room_id)
    return ActionReport(**report)


# ============================================================================
# Timeline Endpoints
# ============================================================================


@router.post("/rooms/{room_id}/timeline", response_model=IncidentTimelineResponse, status_code=status.HTTP_201_CREATED)
async def add_timeline_event(
    event_data: IncidentTimelineCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Add event to timeline"""
    room = await get_war_room_or_404(db, room_id)
    manager = TimelineManager(db)

    event = await manager.add_event(
        room_id=room_id,
        organization_id=getattr(current_user, "organization_id", None),
        event_type=event_data.event_type,
        description=event_data.description,
        created_by=str(current_user.id),
        event_time=event_data.event_time,
        evidence_ids=event_data.evidence_ids,
        is_key_event=event_data.is_key_event,
        mitre_technique=event_data.mitre_technique,
    )
    await db.commit()
    return event


@router.get("/rooms/{room_id}/timeline", response_model=IncidentTimelineListResponse)
async def get_timeline(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = None,
    key_only: bool = False,
):
    """Get timeline events"""
    room = await get_war_room_or_404(db, room_id)
    manager = TimelineManager(db)

    event_types = [event_type] if event_type else None
    events = await manager.build_timeline(room_id, event_types=event_types, include_key_only=key_only)

    # Pagination
    total = len(events)
    offset = (page - 1) * size
    paginated = events[offset : offset + size]

    return IncidentTimelineListResponse(
        items=paginated,
        total=total,
        page=page,
        size=size,
    )


@router.get("/rooms/{room_id}/timeline/report")
async def get_timeline_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Get timeline report"""
    room = await get_war_room_or_404(db, room_id)
    manager = TimelineManager(db)
    report = await manager.generate_timeline_report(room_id)
    return {"report": report}


@router.get("/rooms/{room_id}/timeline/export")
async def export_timeline(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    format: str = Query("json", pattern="^(json|text)$"),
):
    """Export timeline"""
    room = await get_war_room_or_404(db, room_id)
    manager = TimelineManager(db)
    export_data = await manager.export_timeline(room_id, format=format)
    return {"data": export_data, "format": format}


# ============================================================================
# Post-Mortem Endpoints
# ============================================================================


@router.post("/rooms/{room_id}/postmortem", response_model=PostMortemReport)
async def generate_post_mortem(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Generate post-mortem report"""
    room = await get_war_room_or_404(db, room_id)
    generator = PostMortemGenerator(db)
    report = await generator.generate_post_mortem(room_id)
    return PostMortemReport(**report)


@router.get("/rooms/{room_id}/postmortem/analysis", response_model=PostMortemAnalysis)
async def get_postmortem_analysis(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Get complete post-mortem analysis"""
    room = await get_war_room_or_404(db, room_id)
    generator = PostMortemGenerator(db)

    report = await generator.generate_post_mortem(room_id)
    metrics = await generator.calculate_response_metrics(room_id)
    lessons = await generator.extract_lessons_learned(room_id)
    recommendations = await generator.generate_improvement_recommendations(room_id)

    return PostMortemAnalysis(
        report=PostMortemReport(**report),
        metrics=ResponseMetrics(**metrics),
        lessons_learned=lessons,
        recommendations=[
            ImprovementRecommendation(
                category="process",
                recommendation=rec,
                priority="medium",
                implementation_effort="medium",
            )
            for rec in recommendations
        ],
    )


# ============================================================================
# Dashboard Endpoints
# ============================================================================


@router.get("/dashboard", response_model=CollaborationDashboard)
async def get_collaboration_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get collaboration dashboard"""
    manager = WarRoomManager(db)

    # Get active rooms
    active_rooms = await manager.get_active_rooms(getattr(current_user, "organization_id", None))

    # Build dashboard
    pending_actions_result = await db.execute(
        select(func.count(ActionItem.id)).where(
            ActionItem.status == ActionStatus.PENDING.value
        )
    )
    pending_actions = pending_actions_result.scalar() or 0

    overdue_actions_result = await db.execute(
        select(func.count(ActionItem.id)).where(
            and_(
                ActionItem.due_date < datetime.utcnow(),
                ActionItem.status != ActionStatus.COMPLETED.value,
            )
        )
    )
    overdue_actions = overdue_actions_result.scalar() or 0

    # Recent rooms summaries
    recent_summaries = []
    for room in active_rooms[:5]:
        summary = await manager.get_room_summary(room.id)
        recent_summaries.append(WarRoomSummary(**summary))

    # Critical actions
    critical_result = await db.execute(
        select(ActionItem)
        .where(ActionItem.status == ActionStatus.PENDING.value)
        .order_by(ActionItem.priority)
        .limit(5)
    )
    critical_actions = critical_result.scalars().all()

    return CollaborationDashboard(
        active_rooms=len(active_rooms),
        total_participants=sum(
            len(json.loads(r.participants or "[]")) for r in active_rooms
        ),
        pending_actions=pending_actions,
        overdue_actions=overdue_actions,
        recent_rooms=recent_summaries,
        critical_actions=critical_actions,
        response_metrics={
            "avg_mttr": None,
            "avg_mttc": None,
            "total_incidents": len(active_rooms),
        },
    )


@router.get("/rooms/{room_id}/activity-metrics", response_model=RoomActivityMetrics)
async def get_room_activity_metrics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
):
    """Get activity metrics for room"""
    room = await get_war_room_or_404(db, room_id)
    from datetime import timedelta
    from src.models.base import utc_now

    now = utc_now()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)

    # Messages last hour
    msg_hour_result = await db.execute(
        select(func.count(WarRoomMessage.id)).where(
            and_(
                WarRoomMessage.room_id == room_id,
                WarRoomMessage.created_at >= hour_ago,
            )
        )
    )
    messages_last_hour = msg_hour_result.scalar() or 0

    # Messages last 24h
    msg_day_result = await db.execute(
        select(func.count(WarRoomMessage.id)).where(
            and_(
                WarRoomMessage.room_id == room_id,
                WarRoomMessage.created_at >= day_ago,
            )
        )
    )
    messages_last_24h = msg_day_result.scalar() or 0

    # Pending actions
    pending_result = await db.execute(
        select(func.count(ActionItem.id)).where(
            and_(
                ActionItem.room_id == room_id,
                ActionItem.status == ActionStatus.PENDING.value,
            )
        )
    )
    pending_actions = pending_result.scalar() or 0

    # Overdue actions
    overdue_result = await db.execute(
        select(func.count(ActionItem.id)).where(
            and_(
                ActionItem.room_id == room_id,
                ActionItem.due_date < now,
                ActionItem.status != ActionStatus.COMPLETED.value,
            )
        )
    )
    overdue_actions = overdue_result.scalar() or 0

    return RoomActivityMetrics(
        messages_last_hour=messages_last_hour,
        messages_last_24h=messages_last_24h,
        active_participants_last_hour=1,  # Simplified
        pending_actions=pending_actions,
        overdue_actions=overdue_actions,
    )


@router.get("/search", response_model=SearchResultsResponse)
async def search_collaboration(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    room_id: str = Path(...),
    q: str = Query(..., min_length=1),
):
    """Search across messages and artifacts"""
    room = await get_war_room_or_404(db, room_id)
    msg_engine = MessageEngine(db)

    messages = await msg_engine.search_messages(room_id, q, limit=50)

    # Search artifacts
    artifact_result = await db.execute(
        select(SharedArtifact).where(
            and_(
                SharedArtifact.room_id == room_id,
                SharedArtifact.file_name.ilike(f"%{q}%"),
            )
        )
    )
    artifacts = artifact_result.scalars().all()

    return SearchResultsResponse(
        messages=messages,
        artifacts=artifacts,
        total_results=len(messages) + len(artifacts),
    )
