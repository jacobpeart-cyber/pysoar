"""War room and collaboration engine for incident response coordination"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.base import generate_uuid, utc_now
from src.collaboration.models import (
    WarRoom,
    WarRoomMessage,
    SharedArtifact,
    ActionItem,
    IncidentTimeline,
    WarRoomStatus,
    MessageType,
    ActionStatus,
    TimelineEventType,
)
from src.core.logging import get_logger

logger = get_logger(__name__)


class WarRoomManager:
    """Manages war room lifecycle and participant coordination"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_room(
        self,
        organization_id: str,
        name: str,
        room_type: str,
        severity_level: str,
        created_by: str,
        incident_id: Optional[str] = None,
        description: Optional[str] = None,
        commander_id: Optional[str] = None,
        max_participants: int = 50,
        auto_archive_hours: Optional[int] = None,
        is_encrypted: bool = False,
        tags: Optional[list[str]] = None,
    ) -> WarRoom:
        """Create a new war room"""
        room = WarRoom(
            id=generate_uuid(),
            organization_id=organization_id,
            name=name,
            description=description,
            incident_id=incident_id,
            room_type=room_type,
            status=WarRoomStatus.ACTIVE.value,
            severity_level=severity_level,
            commander_id=commander_id,
            participants=json.dumps([created_by]),
            max_participants=max_participants,
            auto_archive_hours=auto_archive_hours,
            created_by=created_by,
            pinned_items=json.dumps([]),
            tags=json.dumps(tags or []),
            is_encrypted=is_encrypted,
        )
        self.db.add(room)
        await self.db.flush()
        logger.info(f"Created war room {room.id} for incident {incident_id}")

        # Audit trail — record war room creation in the generic audit_logs
        # table. `created_by` is the actor here; when automation kicks this
        # off there may not be a human user, so we fall back to `None` which
        # the AuditLog schema tolerates (nullable user_id).
        try:
            from src.models.audit import AuditLog
            self.db.add(AuditLog(
                user_id=created_by if created_by and created_by != "system" else None,
                action="war_room_create",
                resource_type="war_room",
                resource_id=str(room.id),
                description=f"Created war room '{name[:180]}' (type={room_type}, severity={severity_level})"[:500],
                new_value=json.dumps({
                    "name": name[:200],
                    "room_type": room_type,
                    "severity_level": severity_level,
                    "incident_id": incident_id,
                    "organization_id": organization_id,
                })[:2000],
                success=True,
            ))
            await self.db.flush()
        except Exception as exc:
            logger.warning(f"Failed to write audit_log for war_room_create {room.id}: {exc}")

        return room

    async def join_room(self, room_id: str, user_id: str) -> bool:
        """Add user to war room"""
        result = await self.db.execute(select(WarRoom).where(WarRoom.id == room_id))
        room = result.scalar_one_or_none()
        if not room:
            logger.warning(f"War room {room_id} not found")
            return False

        participants = json.loads(room.participants or "[]")
        if user_id not in participants:
            participants.append(user_id)
            if len(participants) > room.max_participants:
                logger.warning(f"War room {room_id} at max capacity")
                return False
            room.participants = json.dumps(participants)
            logger.info(f"User {user_id} joined war room {room_id}")
        return True

    async def leave_room(self, room_id: str, user_id: str) -> bool:
        """Remove user from war room"""
        result = await self.db.execute(select(WarRoom).where(WarRoom.id == room_id))
        room = result.scalar_one_or_none()
        if not room:
            return False

        participants = json.loads(room.participants or "[]")
        if user_id in participants:
            participants.remove(user_id)
            room.participants = json.dumps(participants)
            logger.info(f"User {user_id} left war room {room_id}")
        return True

    async def archive_room(self, room_id: str) -> bool:
        """Archive a war room"""
        result = await self.db.execute(select(WarRoom).where(WarRoom.id == room_id))
        room = result.scalar_one_or_none()
        if not room:
            return False
        room.status = WarRoomStatus.ARCHIVED.value
        logger.info(f"Archived war room {room_id}")
        return True

    async def set_commander(self, room_id: str, user_id: str) -> bool:
        """Set incident commander"""
        result = await self.db.execute(select(WarRoom).where(WarRoom.id == room_id))
        room = result.scalar_one_or_none()
        if not room:
            return False
        room.commander_id = user_id
        logger.info(f"Set commander {user_id} for room {room_id}")
        return True

    async def get_active_rooms(self, organization_id: str) -> list[WarRoom]:
        """Get all active war rooms for organization"""
        result = await self.db.execute(
            select(WarRoom)
            .where(
                and_(
                    WarRoom.organization_id == organization_id,
                    WarRoom.status == WarRoomStatus.ACTIVE.value,
                )
            )
            .order_by(desc(WarRoom.created_at))
        )
        return result.scalars().all()

    async def auto_create_for_incident(
        self,
        organization_id: str,
        incident_id: str,
        incident_title: str,
        severity_level: str,
        created_by: str,
    ) -> WarRoom:
        """Auto-create war room when critical incident is created"""
        room = await self.create_room(
            organization_id=organization_id,
            name=f"IR: {incident_title}",
            room_type="incident_response",
            severity_level=severity_level,
            incident_id=incident_id,
            created_by=created_by,
            description=f"Incident response room for {incident_title}",
            is_encrypted=severity_level in ["critical", "high"],
        )
        logger.info(f"Auto-created war room for incident {incident_id}")
        return room

    async def get_room_summary(self, room_id: str) -> dict[str, Any]:
        """Get war room summary with key metrics"""
        result = await self.db.execute(select(WarRoom).where(WarRoom.id == room_id))
        room = result.scalar_one_or_none()
        if not room:
            return {}

        # Count messages
        msg_result = await self.db.execute(
            select(func.count(WarRoomMessage.id)).where(WarRoomMessage.room_id == room_id)
        )
        msg_count = msg_result.scalar() or 0

        # Count action items
        action_result = await self.db.execute(
            select(func.count(ActionItem.id)).where(ActionItem.room_id == room_id)
        )
        action_count = action_result.scalar() or 0

        # Count artifacts
        artifact_result = await self.db.execute(
            select(func.count(SharedArtifact.id)).where(SharedArtifact.room_id == room_id)
        )
        artifact_count = artifact_result.scalar() or 0

        return {
            "id": room.id,
            "name": room.name,
            "status": room.status,
            "room_type": room.room_type,
            "severity_level": room.severity_level,
            "participants": json.loads(room.participants or "[]"),
            "message_count": msg_count,
            "action_count": action_count,
            "artifact_count": artifact_count,
            "created_at": room.created_at,
            "updated_at": room.updated_at,
        }


class MessageEngine:
    """Handles real-time messaging and communication"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def send_message(
        self,
        room_id: str,
        organization_id: str,
        sender_id: str,
        sender_name: str,
        content: str,
        message_type: str = MessageType.TEXT.value,
        attachments: Optional[list[str]] = None,
        mentioned_users: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> WarRoomMessage:
        """Send message to war room"""
        message = WarRoomMessage(
            id=generate_uuid(),
            organization_id=organization_id,
            room_id=room_id,
            sender_id=sender_id,
            sender_name=sender_name,
            message_type=message_type,
            content=content,
            attachments=json.dumps(attachments or []),
            mentioned_users=json.dumps(mentioned_users or []),
            reactions=json.dumps({}),
            extra_metadata=json.dumps(metadata or {}),
        )
        self.db.add(message)
        await self.db.flush()
        logger.info(f"Message {message.id} sent to room {room_id}")
        return message

    async def edit_message(self, message_id: str, new_content: str) -> bool:
        """Edit a message"""
        result = await self.db.execute(
            select(WarRoomMessage).where(WarRoomMessage.id == message_id)
        )
        message = result.scalar_one_or_none()
        if not message:
            return False
        message.content = new_content
        message.is_edited = True
        message.edited_at = utc_now()
        logger.info(f"Message {message_id} edited")
        return True

    async def pin_message(self, room_id: str, message_id: str) -> bool:
        """Pin message in room"""
        result = await self.db.execute(
            select(WarRoomMessage).where(WarRoomMessage.id == message_id)
        )
        message = result.scalar_one_or_none()
        if not message:
            return False
        message.is_pinned = True

        # Update room's pinned_items
        room_result = await self.db.execute(select(WarRoom).where(WarRoom.id == room_id))
        room = room_result.scalar_one_or_none()
        if room:
            pinned = json.loads(room.pinned_items or "[]")
            if message_id not in pinned:
                pinned.append(message_id)
                room.pinned_items = json.dumps(pinned)
        return True

    async def create_thread(self, room_id: str, parent_message_id: str) -> Optional[str]:
        """Create reply thread on message"""
        result = await self.db.execute(
            select(WarRoomMessage).where(WarRoomMessage.id == parent_message_id)
        )
        parent = result.scalar_one_or_none()
        if not parent or parent.room_id != room_id:
            return None
        return parent_message_id

    async def search_messages(
        self,
        room_id: str,
        query: str,
        limit: int = 50,
    ) -> list[WarRoomMessage]:
        """Search messages in room"""
        result = await self.db.execute(
            select(WarRoomMessage)
            .where(
                and_(
                    WarRoomMessage.room_id == room_id,
                    WarRoomMessage.content.ilike(f"%{query}%"),
                )
            )
            .order_by(desc(WarRoomMessage.created_at))
            .limit(limit)
        )
        return result.scalars().all()

    async def get_message_history(
        self,
        room_id: str,
        page: int = 1,
        size: int = 50,
    ) -> tuple[list[WarRoomMessage], int]:
        """Get paginated message history"""
        # Get total count
        count_result = await self.db.execute(
            select(func.count(WarRoomMessage.id)).where(WarRoomMessage.room_id == room_id)
        )
        total = count_result.scalar() or 0

        # Get paginated messages
        offset = (page - 1) * size
        result = await self.db.execute(
            select(WarRoomMessage)
            .where(WarRoomMessage.room_id == room_id)
            .order_by(desc(WarRoomMessage.created_at))
            .offset(offset)
            .limit(size)
        )
        messages = result.scalars().all()
        return list(reversed(messages)), total

    def format_status_update(
        self,
        status: str,
        changed_by: str,
        details: Optional[str] = None,
    ) -> str:
        """Format status update message"""
        msg = f"Status changed to {status} by {changed_by}"
        if details:
            msg += f": {details}"
        return msg

    async def broadcast_alert(
        self,
        room_id: str,
        organization_id: str,
        alert_title: str,
        alert_severity: str,
        alert_id: str,
    ) -> WarRoomMessage:
        """Broadcast alert to all room participants"""
        metadata = {
            "alert_id": alert_id,
            "alert_severity": alert_severity,
        }
        message = await self.send_message(
            room_id=room_id,
            organization_id=organization_id,
            sender_id="system",
            sender_name="System",
            content=f"ALERT: {alert_title} ({alert_severity})",
            message_type=MessageType.ALERT_LINK.value,
            metadata=metadata,
        )
        return message

    async def generate_sitrep(self, room_id: str, hours: int = 1) -> str:
        """Generate situation report from recent messages"""
        cutoff_time = utc_now() - timedelta(hours=hours)
        result = await self.db.execute(
            select(WarRoomMessage)
            .where(
                and_(
                    WarRoomMessage.room_id == room_id,
                    WarRoomMessage.created_at >= cutoff_time,
                )
            )
            .order_by(WarRoomMessage.created_at)
        )
        messages = result.scalars().all()

        # Build SITREP
        sitrep = f"SITUATION REPORT - Last {hours} hour(s)\n"
        sitrep += f"Messages: {len(messages)}\n\n"

        for msg in messages:
            if msg.message_type in [MessageType.STATUS_UPDATE.value, MessageType.DECISION.value]:
                sitrep += f"[{msg.created_at.isoformat()}] {msg.sender_name}: {msg.content}\n"

        return sitrep


class ArtifactManager:
    """Manages artifact sharing and lifecycle"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def upload_artifact(
        self,
        room_id: str,
        organization_id: str,
        uploaded_by: str,
        file_name: str,
        file_hash: str,
        file_size_bytes: int,
        artifact_type: str,
        classification_level: str,
        description: Optional[str] = None,
        access_restricted_to: Optional[list[str]] = None,
    ) -> SharedArtifact:
        """Upload artifact to war room"""
        artifact = SharedArtifact(
            id=generate_uuid(),
            organization_id=organization_id,
            room_id=room_id,
            uploaded_by=uploaded_by,
            artifact_type=artifact_type,
            file_name=file_name,
            file_hash=file_hash,
            file_size_bytes=file_size_bytes,
            description=description,
            classification_level=classification_level,
            access_restricted_to=json.dumps(access_restricted_to or []),
            download_count=0,
            analysis_status="pending",
        )
        self.db.add(artifact)
        await self.db.flush()
        logger.info(f"Artifact {artifact.id} uploaded to room {room_id}")
        return artifact

    async def share_artifact(
        self,
        artifact_id: str,
        shared_with: list[str],
    ) -> bool:
        """Share artifact with additional users"""
        result = await self.db.execute(
            select(SharedArtifact).where(SharedArtifact.id == artifact_id)
        )
        artifact = result.scalar_one_or_none()
        if not artifact:
            return False

        current = json.loads(artifact.access_restricted_to or "[]")
        for user_id in shared_with:
            if user_id not in current:
                current.append(user_id)
        artifact.access_restricted_to = json.dumps(current)
        return True

    async def get_artifact(self, artifact_id: str) -> Optional[SharedArtifact]:
        """Get artifact by ID"""
        result = await self.db.execute(
            select(SharedArtifact).where(SharedArtifact.id == artifact_id)
        )
        return result.scalar_one_or_none()

    async def restrict_access(
        self,
        artifact_id: str,
        user_ids: list[str],
    ) -> bool:
        """Restrict artifact access to specific users"""
        result = await self.db.execute(
            select(SharedArtifact).where(SharedArtifact.id == artifact_id)
        )
        artifact = result.scalar_one_or_none()
        if not artifact:
            return False
        artifact.access_restricted_to = json.dumps(user_ids)
        return True

    async def track_downloads(self, artifact_id: str) -> bool:
        """Track artifact download"""
        result = await self.db.execute(
            select(SharedArtifact).where(SharedArtifact.id == artifact_id)
        )
        artifact = result.scalar_one_or_none()
        if not artifact:
            return False
        artifact.download_count += 1
        return True

    async def generate_artifact_index(self, room_id: str) -> dict[str, Any]:
        """Generate index of all artifacts in room"""
        result = await self.db.execute(
            select(SharedArtifact)
            .where(SharedArtifact.room_id == room_id)
            .order_by(desc(SharedArtifact.created_at))
        )
        artifacts = result.scalars().all()

        index = {
            "total": len(artifacts),
            "by_type": {},
            "artifacts": [],
        }

        for artifact in artifacts:
            artifact_type = artifact.artifact_type
            index["by_type"][artifact_type] = index["by_type"].get(artifact_type, 0) + 1
            index["artifacts"].append(
                {
                    "id": artifact.id,
                    "file_name": artifact.file_name,
                    "artifact_type": artifact.artifact_type,
                    "size_bytes": artifact.file_size_bytes,
                    "uploaded_at": artifact.created_at.isoformat(),
                    "download_count": artifact.download_count,
                }
            )

        return index


class ActionTracker:
    """Tracks action items and assignments"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_action_item(
        self,
        room_id: str,
        organization_id: str,
        title: str,
        assigned_by: str,
        priority: str = "medium",
        description: Optional[str] = None,
        assigned_to: Optional[str] = None,
        due_date: Optional[datetime] = None,
    ) -> ActionItem:
        """Create action item"""
        action = ActionItem(
            id=generate_uuid(),
            organization_id=organization_id,
            room_id=room_id,
            title=title,
            description=description,
            assigned_to=assigned_to,
            assigned_by=assigned_by,
            priority=priority,
            status=ActionStatus.PENDING.value,
            due_date=due_date,
            notes="",
            checklist=json.dumps([]),
        )
        self.db.add(action)
        await self.db.flush()
        logger.info(f"Action item {action.id} created in room {room_id}")
        return action

    async def assign_action(
        self,
        action_id: str,
        assigned_to: str,
    ) -> bool:
        """Assign action to user"""
        result = await self.db.execute(
            select(ActionItem).where(ActionItem.id == action_id)
        )
        action = result.scalar_one_or_none()
        if not action:
            return False
        action.assigned_to = assigned_to
        return True

    async def update_status(
        self,
        action_id: str,
        status: str,
    ) -> bool:
        """Update action status"""
        result = await self.db.execute(
            select(ActionItem).where(ActionItem.id == action_id)
        )
        action = result.scalar_one_or_none()
        if not action:
            return False
        action.status = status
        if status == ActionStatus.COMPLETED.value:
            action.completed_at = utc_now()
        return True

    async def get_overdue_actions(self, room_id: str) -> list[ActionItem]:
        """Get overdue action items"""
        now = utc_now()
        result = await self.db.execute(
            select(ActionItem).where(
                and_(
                    ActionItem.room_id == room_id,
                    ActionItem.due_date < now,
                    ActionItem.status != ActionStatus.COMPLETED.value,
                )
            )
        )
        return result.scalars().all()

    async def get_actions_by_assignee(
        self,
        room_id: str,
        user_id: str,
    ) -> list[ActionItem]:
        """Get actions assigned to user"""
        result = await self.db.execute(
            select(ActionItem)
            .where(
                and_(
                    ActionItem.room_id == room_id,
                    ActionItem.assigned_to == user_id,
                )
            )
            .order_by(ActionItem.priority)
        )
        return result.scalars().all()

    async def generate_action_report(self, room_id: str) -> dict[str, Any]:
        """Generate action items report"""
        result = await self.db.execute(
            select(ActionItem).where(ActionItem.room_id == room_id)
        )
        actions = result.scalars().all()

        report = {
            "total": len(actions),
            "by_status": {},
            "by_priority": {},
            "overdue": 0,
            "actions": [],
        }

        now = utc_now()
        for action in actions:
            status = action.status
            priority = action.priority
            report["by_status"][status] = report["by_status"].get(status, 0) + 1
            report["by_priority"][priority] = report["by_priority"].get(priority, 0) + 1

            if action.due_date and action.due_date < now and status != ActionStatus.COMPLETED.value:
                report["overdue"] += 1

            report["actions"].append(
                {
                    "id": action.id,
                    "title": action.title,
                    "status": action.status,
                    "priority": action.priority,
                    "assigned_to": action.assigned_to,
                    "due_date": action.due_date.isoformat() if action.due_date else None,
                }
            )

        return report

    async def auto_create_from_playbook(
        self,
        room_id: str,
        organization_id: str,
        playbook_name: str,
        tasks: list[dict[str, Any]],
        created_by: str,
    ) -> list[ActionItem]:
        """Auto-create action items from playbook execution"""
        actions = []
        for task in tasks:
            action = await self.create_action_item(
                room_id=room_id,
                organization_id=organization_id,
                title=task.get("name", "Unnamed task"),
                description=f"From playbook: {playbook_name}",
                assigned_by=created_by,
                priority=task.get("priority", "medium"),
            )
            actions.append(action)
        logger.info(f"Created {len(actions)} actions from playbook {playbook_name}")
        return actions


class TimelineManager:
    """Manages incident timeline"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def add_event(
        self,
        room_id: str,
        organization_id: str,
        event_type: str,
        description: str,
        created_by: str,
        event_time: Optional[datetime] = None,
        evidence_ids: Optional[list[str]] = None,
        is_key_event: bool = False,
        mitre_technique: Optional[str] = None,
    ) -> IncidentTimeline:
        """Add event to timeline"""
        event = IncidentTimeline(
            id=generate_uuid(),
            organization_id=organization_id,
            room_id=room_id,
            event_time=event_time or utc_now(),
            event_type=event_type,
            description=description,
            created_by=created_by,
            evidence_ids=json.dumps(evidence_ids or []),
            is_key_event=is_key_event,
            mitre_technique=mitre_technique,
        )
        self.db.add(event)
        await self.db.flush()
        logger.info(f"Timeline event {event.id} added to room {room_id}")
        return event

    async def build_timeline(
        self,
        room_id: str,
        event_types: Optional[list[str]] = None,
        include_key_only: bool = False,
    ) -> list[IncidentTimeline]:
        """Build chronological timeline with filters"""
        query = select(IncidentTimeline).where(IncidentTimeline.room_id == room_id)

        if event_types:
            query = query.where(IncidentTimeline.event_type.in_(event_types))

        if include_key_only:
            query = query.where(IncidentTimeline.is_key_event == True)

        result = await self.db.execute(
            query.order_by(IncidentTimeline.event_time)
        )
        return result.scalars().all()

    async def identify_key_events(self, room_id: str) -> list[IncidentTimeline]:
        """Get key events from timeline"""
        result = await self.db.execute(
            select(IncidentTimeline)
            .where(
                and_(
                    IncidentTimeline.room_id == room_id,
                    IncidentTimeline.is_key_event == True,
                )
            )
            .order_by(IncidentTimeline.event_time)
        )
        return result.scalars().all()

    async def generate_timeline_report(self, room_id: str) -> str:
        """Generate text report of timeline"""
        events = await self.build_timeline(room_id)

        report = "INCIDENT TIMELINE REPORT\n"
        report += "=" * 50 + "\n\n"

        for event in events:
            key_marker = "[KEY EVENT]" if event.is_key_event else ""
            report += f"{event.event_time.isoformat()} - {event.event_type} {key_marker}\n"
            report += f"  {event.description}\n"
            if event.mitre_technique:
                report += f"  MITRE: {event.mitre_technique}\n"
            report += "\n"

        return report

    async def export_timeline(
        self,
        room_id: str,
        format: str = "json",
    ) -> str:
        """Export timeline in specified format"""
        events = await self.build_timeline(room_id)

        if format == "json":
            data = [
                {
                    "time": event.event_time.isoformat(),
                    "type": event.event_type,
                    "description": event.description,
                    "is_key": event.is_key_event,
                    "mitre_technique": event.mitre_technique,
                }
                for event in events
            ]
            return json.dumps(data, indent=2)
        else:
            return await self.generate_timeline_report(room_id)

    async def correlate_with_alerts(
        self,
        room_id: str,
        alert_timestamps: list[datetime],
    ) -> dict[str, Any]:
        """Correlate timeline events with alerts"""
        events = await self.build_timeline(room_id)

        correlation = {
            "total_events": len(events),
            "correlated_alerts": 0,
            "gap_analysis": [],
        }

        for alert_time in alert_timestamps:
            for event in events:
                time_diff = abs((event.event_time - alert_time).total_seconds())
                if time_diff < 300:  # 5 minute window
                    correlation["correlated_alerts"] += 1

        return correlation


class PostMortemGenerator:
    """Generates post-mortem reports and analysis"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_post_mortem(self, room_id: str) -> dict[str, Any]:
        """Generate comprehensive post-mortem report"""
        # Get room details
        room_result = await self.db.execute(
            select(WarRoom).where(WarRoom.id == room_id)
        )
        room = room_result.scalar_one_or_none()
        if not room:
            return {}

        # Get timeline
        timeline_mgr = TimelineManager(self.db)
        timeline_events = await timeline_mgr.build_timeline(room_id)

        # Get actions
        action_result = await self.db.execute(
            select(ActionItem).where(ActionItem.room_id == room_id)
        )
        actions = action_result.scalars().all()

        # Get messages
        msg_result = await self.db.execute(
            select(WarRoomMessage)
            .where(WarRoomMessage.room_id == room_id)
            .order_by(WarRoomMessage.created_at)
        )
        messages = msg_result.scalars().all()

        # Extract decisions
        decisions = [
            m for m in messages
            if m.message_type == MessageType.DECISION.value
        ]

        post_mortem = {
            "title": f"Post-Mortem: {room.name}",
            "incident_id": room.incident_id,
            "room_type": room.room_type,
            "severity": room.severity_level,
            "duration_minutes": self._calculate_duration(timeline_events),
            "timeline": [
                {
                    "time": e.event_time.isoformat(),
                    "event": e.description,
                    "type": e.event_type,
                }
                for e in timeline_events
            ],
            "actions_taken": len([a for a in actions if a.status == ActionStatus.COMPLETED.value]),
            "key_decisions": [d.content for d in decisions],
            "participants": json.loads(room.participants or "[]"),
            "generated_at": utc_now().isoformat(),
        }

        return post_mortem

    async def extract_lessons_learned(self, room_id: str) -> list[str]:
        """Extract lessons learned from incident"""
        # Get messages with lessons/recommendations
        result = await self.db.execute(
            select(WarRoomMessage)
            .where(WarRoomMessage.room_id == room_id)
            .order_by(desc(WarRoomMessage.created_at))
        )
        messages = result.scalars().all()

        lessons = []
        keywords = ["lesson", "learned", "improvement", "recommendation", "improve"]

        for msg in messages:
            if any(kw in msg.content.lower() for kw in keywords):
                lessons.append(msg.content)

        return lessons[:10]  # Top 10 lessons

    async def calculate_response_metrics(
        self,
        room_id: str,
    ) -> dict[str, Any]:
        """Calculate MTTD, MTTR, MTTC response metrics"""
        timeline_mgr = TimelineManager(self.db)
        timeline = await timeline_mgr.build_timeline(room_id)

        metrics = {
            "mttd": None,  # Mean time to detect
            "mttr": None,  # Mean time to respond
            "mttc": None,  # Mean time to contain
        }

        # Find key events
        detection_time = None
        response_time = None
        contain_time = None

        for event in timeline:
            if event.event_type == TimelineEventType.DETECTION.value and not detection_time:
                detection_time = event.event_time
            if event.event_type == TimelineEventType.ACTION.value and not response_time:
                response_time = event.event_time
            if event.event_type == TimelineEventType.CONTAINMENT.value and not contain_time:
                contain_time = event.event_time

        if detection_time and response_time:
            metrics["mttr"] = (response_time - detection_time).total_seconds() / 60
        if response_time and contain_time:
            metrics["mttc"] = (contain_time - response_time).total_seconds() / 60

        return metrics

    async def generate_improvement_recommendations(
        self,
        room_id: str,
    ) -> list[str]:
        """Generate recommendations for process improvement"""
        metrics = await self.calculate_response_metrics(room_id)
        lessons = await self.extract_lessons_learned(room_id)

        recommendations = []

        # Time-based recommendations
        if metrics["mttr"] and metrics["mttr"] > 30:
            recommendations.append(
                "Consider improving response time - MTTR exceeded 30 minutes"
            )
        if metrics["mttc"] and metrics["mttc"] > 120:
            recommendations.append(
                "Review containment procedures - MTTC exceeded 2 hours"
            )

        # Process improvements
        recommendations.append("Schedule post-incident review meeting")
        recommendations.append("Update incident response playbooks")
        recommendations.append("Review war room effectiveness")

        return recommendations

    def _calculate_duration(self, events: list[IncidentTimeline]) -> int:
        """Calculate incident duration in minutes"""
        if not events:
            return 0
        first = events[0].event_time
        last = events[-1].event_time
        return int((last - first).total_seconds() / 60)
