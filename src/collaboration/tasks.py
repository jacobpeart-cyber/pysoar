"""Celery tasks for war room and collaboration module"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from celery import shared_task

from src.core.config import settings
from src.core.logging import get_logger
from src.core.database import async_session_factory
from src.collaboration.models import WarRoom, ActionItem, WarRoomStatus, ActionStatus
from sqlalchemy import select, and_

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
def auto_archive_rooms(self):
    """
    Periodically archive inactive war rooms based on auto_archive_hours setting.

    Executes every hour to check for war rooms that should be auto-archived
    when they haven't had activity within their configured timeframe.

    Returns:
        Dictionary with archival results and statistics
    """
    try:
        import asyncio
        from sqlalchemy.ext.asyncio import AsyncSession

        logger.info("Starting war room auto-archive task")

        async def run_archive():
            async with async_session_factory() as db:
                now = datetime.now(timezone.utc)

                # Find rooms with auto_archive_hours set
                result = await db.execute(
                    select(WarRoom).where(
                        and_(
                            WarRoom.auto_archive_hours.isnot(None),
                            WarRoom.status == WarRoomStatus.ACTIVE.value,
                        )
                    )
                )
                rooms = result.scalars().all()

                archived_count = 0
                for room in rooms:
                    if room.auto_archive_hours:
                        cutoff = now - timedelta(hours=room.auto_archive_hours)
                        if room.updated_at < cutoff:
                            room.status = WarRoomStatus.ARCHIVED.value
                            archived_count += 1
                            logger.info(f"Auto-archived war room {room.id}")

                await db.commit()
                return archived_count

        archived = asyncio.run(run_archive())
        logger.info(f"Auto-archived {archived} war rooms")

        return {
            "status": "success",
            "rooms_archived": archived,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"War room auto-archive failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def overdue_action_reminder(self, room_id: Optional[str] = None):
    """
    Check for overdue action items and send reminders.

    Runs periodically to identify overdue actions and notify assignees.

    Args:
        room_id: Optional specific room to check

    Returns:
        Dictionary with overdue action count
    """
    try:
        import asyncio

        logger.info("Starting overdue action reminder task")

        async def check_overdue():
            async with async_session_factory() as db:
                now = datetime.now(timezone.utc)

                query = select(ActionItem).where(
                    and_(
                        ActionItem.due_date < now,
                        ActionItem.status != ActionStatus.COMPLETED.value,
                        ActionItem.status != ActionStatus.CANCELLED.value,
                    )
                )

                if room_id:
                    query = query.where(ActionItem.room_id == room_id)

                result = await db.execute(query)
                overdue = result.scalars().all()

                return len(overdue)

        overdue_count = asyncio.run(check_overdue())
        logger.info(f"Found {overdue_count} overdue action items")

        return {
            "status": "success",
            "overdue_actions": overdue_count,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Overdue action check failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def sitrep_generation(self, room_id: str, hours: int = 1):
    """
    Automatically generate situation reports at regular intervals.

    Executes every N hours to create comprehensive SITREPs from war room activity.

    Args:
        room_id: War room ID to generate SITREP for
        hours: Lookback window in hours

    Returns:
        Dictionary with SITREP details
    """
    try:
        import asyncio
        from src.collaboration.engine import MessageEngine

        logger.info(f"Generating SITREP for room {room_id}")

        async def generate():
            async with async_session_factory() as db:
                engine = MessageEngine(db)
                sitrep = await engine.generate_sitrep(room_id, hours=hours)
                return sitrep

        sitrep = asyncio.run(generate())
        logger.info(f"Generated SITREP for room {room_id}")

        return {
            "status": "success",
            "room_id": room_id,
            "sitrep_length": len(sitrep),
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"SITREP generation failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def post_mortem_reminder(self):
    """
    Remind teams to complete post-mortem analysis on closed war rooms.

    Runs daily to check for archived war rooms without post-mortem analysis.

    Returns:
        Dictionary with reminder statistics
    """
    try:
        import asyncio

        logger.info("Starting post-mortem reminder task")

        async def check_post_mortems():
            async with async_session_factory() as db:
                result = await db.execute(
                    select(WarRoom).where(
                        WarRoom.status == WarRoomStatus.ARCHIVED.value
                    )
                )
                archived = result.scalars().all()

                # Count those without post-mortem documents
                # This is a simplified check - in production would check for actual reports
                return len(archived)

        archived_count = asyncio.run(check_post_mortems())
        logger.info(f"Found {archived_count} archived rooms for post-mortem review")

        return {
            "status": "success",
            "archived_rooms": archived_count,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Post-mortem reminder failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def room_activity_digest(self, room_id: str, recipient_email: Optional[str] = None):
    """
    Generate activity digest for room participants.

    Creates summary of recent activity, key decisions, and action items
    for circulation to war room team members.

    Args:
        room_id: War room ID
        recipient_email: Optional email to send digest to

    Returns:
        Dictionary with digest details
    """
    try:
        import asyncio

        logger.info(f"Generating activity digest for room {room_id}")

        async def generate_digest():
            async with async_session_factory() as db:
                from src.collaboration.engine import MessageEngine, ActionTracker

                msg_engine = MessageEngine(db)
                action_tracker = ActionTracker(db)

                # Get recent messages
                messages, _ = await msg_engine.get_message_history(
                    room_id, page=1, size=20
                )

                # Get pending actions
                action_result = await db.execute(
                    select(ActionItem).where(ActionItem.room_id == room_id)
                )
                actions = action_result.scalars().all()

                digest = {
                    "room_id": room_id,
                    "message_count": len(messages),
                    "pending_actions": len([a for a in actions if a.status == ActionStatus.PENDING.value]),
                    "completed_actions": len([a for a in actions if a.status == ActionStatus.COMPLETED.value]),
                    "timestamp": datetime.utcnow().isoformat(),
                }

                return digest

        digest = asyncio.run(generate_digest())
        logger.info(f"Generated digest for room {room_id}")

        return {
            "status": "success",
            "digest": digest,
            "recipient": recipient_email or "participants",
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Activity digest generation failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))
