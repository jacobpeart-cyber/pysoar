"""Celery tasks for Visual Playbook Builder.

``async_playbook_execution`` drives a persisted ``VisualPlaybookExecution``
through ``src.playbook_builder.engine.run_visual_execution``; node results are
written as ``PlaybookNodeExecution`` rows and the run status is whatever the
engine concluded (``completed`` / ``partial`` / ``failed``). Runs are never
retried automatically: a step may already have contained a host.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task

from src.core.logging import get_logger

logger = get_logger(__name__)


async def _run(execution_id: str) -> dict[str, Any]:
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import NullPool

    from src.core.config import settings
    from src.playbook_builder.engine import run_visual_execution
    from src.playbook_builder.models import VisualPlaybookExecution

    # NullPool: each task runs in its own asyncio.run() loop.
    engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as db:
            execution = await db.get(VisualPlaybookExecution, execution_id)
            if execution is None:
                return {"execution_id": execution_id, "status": "failed", "error": "execution not found"}
            if execution.status != "pending":
                return {"execution_id": execution_id, "skipped": True, "status": execution.status}
            try:
                result = await run_visual_execution(db, execution_id)
                await db.commit()
                return {"execution_id": execution_id, "status": result.status, "duration_ms": result.duration_ms}
            except Exception as exc:  # record the truth on the row, then report it
                logger.error("visual_playbook_execution_crashed", execution_id=execution_id, error=str(exc))
                await db.rollback()
                execution = await db.get(VisualPlaybookExecution, execution_id)
                if execution is not None:
                    execution.status = "failed"
                    execution.error_message = str(exc)
                    execution.completed_at = datetime.now(timezone.utc).isoformat()
                    await db.commit()
                return {"execution_id": execution_id, "status": "failed", "error": str(exc)}
    finally:
        await engine.dispose()


@shared_task
def async_playbook_execution(
    playbook_id: str,
    execution_id: str,
    trigger_event: Optional[dict] = None,
    variables: Optional[dict] = None,
) -> dict[str, Any]:
    """Execute a pending visual playbook execution.

    ``trigger_event`` / ``variables`` are read from the execution row; the
    arguments are accepted for backwards compatibility with queued messages.
    """
    logger.info("visual_playbook_execution_start", playbook_id=playbook_id, execution_id=execution_id)
    return asyncio.run(_run(execution_id))


async def _create_scheduled_execution(playbook_id: str, schedule_name: str) -> Optional[str]:
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import NullPool

    from src.core.config import settings
    from src.playbook_builder.models import VisualPlaybook, VisualPlaybookExecution

    engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as db:
            playbook = await db.get(VisualPlaybook, playbook_id)
            if playbook is None or playbook.status != "active":
                return None
            trigger = {"trigger_type": "schedule", "schedule_name": schedule_name}
            execution = VisualPlaybookExecution(
                playbook_id=playbook.id,
                organization_id=playbook.organization_id,
                status="pending",
                trigger_event=json.dumps(trigger),
            )
            db.add(execution)
            await db.commit()
            return execution.id
    finally:
        await engine.dispose()


@shared_task
def scheduled_playbook_trigger(playbook_id: str, schedule_name: str) -> dict[str, Any]:
    """Create a real pending execution for an active playbook and dispatch it."""
    execution_id = asyncio.run(_create_scheduled_execution(playbook_id, schedule_name))
    if execution_id is None:
        return {"playbook_id": playbook_id, "status": "skipped", "reason": "playbook missing or not active"}
    async_playbook_execution.delay(playbook_id=playbook_id, execution_id=execution_id)
    return {"execution_id": execution_id, "playbook_id": playbook_id, "status": "pending"}


async def _cleanup(cutoff: datetime, batch_size: int) -> int:
    from sqlalchemy import delete, select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import NullPool

    from src.core.config import settings
    from src.playbook_builder.models import PlaybookNodeExecution, VisualPlaybookExecution

    engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    deleted = 0
    try:
        async with session_factory() as db:
            while True:
                ids = list((await db.execute(
                    select(VisualPlaybookExecution.id)
                    .where(VisualPlaybookExecution.created_at < cutoff)
                    .limit(batch_size)
                )).scalars().all())
                if not ids:
                    break
                await db.execute(delete(PlaybookNodeExecution).where(PlaybookNodeExecution.execution_id.in_(ids)))
                await db.execute(delete(VisualPlaybookExecution).where(VisualPlaybookExecution.id.in_(ids)))
                await db.commit()
                deleted += len(ids)
    finally:
        await engine.dispose()
    return deleted


@shared_task
def execution_cleanup(max_age_hours: int = 7 * 24, batch_size: int = 100) -> dict[str, Any]:
    """Delete visual playbook executions (and their node executions) older than ``max_age_hours``."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    deleted = asyncio.run(_cleanup(cutoff, batch_size))
    logger.info("visual_playbook_execution_cleanup", deleted=deleted, cutoff=cutoff.isoformat())
    return {"deleted_count": deleted, "cutoff_time": cutoff.isoformat()}


@shared_task
def template_sync(template_source: str = "builtin") -> dict[str, Any]:
    """Report the built-in template library (there is no external template source)."""
    from src.playbook_builder.engine import TemplateLibrary

    if template_source != "builtin":
        return {"source": template_source, "synced_count": 0, "error": "only the builtin template library exists"}
    templates = TemplateLibrary.get_templates()
    return {
        "source": template_source,
        "synced_count": len(templates),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
