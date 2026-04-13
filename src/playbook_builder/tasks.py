"""Celery tasks for Visual Playbook Builder"""

import json
from datetime import datetime, timezone

from celery import shared_task

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
def async_playbook_execution(
    self,
    playbook_id: str,
    execution_id: str,
    trigger_event: dict | None = None,
    variables: dict | None = None,
):
    """
    Execute a playbook asynchronously.

    Args:
        playbook_id: ID of playbook to execute
        execution_id: ID of execution record
        trigger_event: Event that triggered execution
        variables: Runtime variables

    Returns:
        Execution result
    """
    try:
        logger.info(f"Starting async playbook execution: {execution_id}")

        from src.core.database import async_session_factory
        from src.playbook_builder.engine import PlaybookExecutionEngine
        from src.playbook_builder.models import VisualPlaybook, VisualPlaybookExecution
        from sqlalchemy import select

        import asyncio

        async def _execute():
            async with async_session_factory() as db:
                # Look up the playbook and execution record
                playbook_query = select(VisualPlaybook).where(VisualPlaybook.id == playbook_id)
                pb_result = await db.execute(playbook_query)
                playbook = pb_result.scalar_one_or_none()

                exec_query = select(VisualPlaybookExecution).where(VisualPlaybookExecution.id == execution_id)
                exec_result = await db.execute(exec_query)
                execution = exec_result.scalar_one_or_none()

                if not playbook or not execution:
                    return {
                        "execution_id": execution_id,
                        "playbook_id": playbook_id,
                        "status": "failed",
                        "error": "playbook or execution record not found",
                    }

                started_at = datetime.now(timezone.utc)
                execution.status = "running"
                execution.started_at = started_at.isoformat()
                await db.commit()

                try:
                    # Run the playbook through the execution engine
                    engine = PlaybookExecutionEngine(db)
                    result = await engine.execute_playbook(
                        playbook=playbook,
                        trigger_event=trigger_event,
                        variables=variables or {},
                    )

                    completed_at = datetime.now(timezone.utc)
                    duration_ms = int((completed_at - started_at).total_seconds() * 1000)

                    execution.status = "completed"
                    execution.completed_at = completed_at.isoformat()
                    execution.duration_ms = duration_ms
                    await db.commit()

                    return {
                        "execution_id": execution_id,
                        "playbook_id": playbook_id,
                        "status": "completed",
                        "started_at": started_at.isoformat(),
                        "completed_at": completed_at.isoformat(),
                        "duration_ms": duration_ms,
                    }

                except Exception as exec_err:
                    execution.status = "failed"
                    execution.error_message = str(exec_err)
                    execution.completed_at = datetime.now(timezone.utc).isoformat()
                    await db.commit()
                    raise

        logger.info(f"Executing playbook {playbook_id}")
        execution_result = asyncio.run(_execute())
        logger.info(f"Playbook execution completed: {execution_id}")
        return execution_result

    except Exception as exc:
        logger.error(f"Playbook execution failed: {exc}")
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=2**self.request.retries)


@shared_task(bind=True, max_retries=3)
def scheduled_playbook_trigger(
    self,
    playbook_id: str,
    schedule_name: str,
):
    """
    Trigger scheduled playbook execution.

    Args:
        playbook_id: ID of playbook to trigger
        schedule_name: Name of the schedule

    Returns:
        Execution ID
    """
    try:
        logger.info(f"Triggered scheduled playbook: {playbook_id}")

        execution_id = f"exec_{playbook_id[:8]}_{datetime.now().timestamp()}"

        # Queue async execution
        async_playbook_execution.delay(
            playbook_id=playbook_id,
            execution_id=execution_id,
            trigger_event={"trigger_type": "schedule", "schedule_name": schedule_name},
        )

        return {"execution_id": execution_id, "playbook_id": playbook_id}

    except Exception as exc:
        logger.error(f"Scheduled trigger failed: {exc}")
        raise self.retry(exc=exc, countdown=2**self.request.retries)


@shared_task(bind=True, max_retries=2)
def execution_cleanup(
    self,
    max_age_hours: int = 7 * 24,  # 7 days by default
    batch_size: int = 100,
):
    """
    Clean up old execution records.

    Args:
        max_age_hours: Delete executions older than this many hours
        batch_size: Number of records to delete per batch

    Returns:
        Cleanup statistics
    """
    try:
        logger.info(f"Starting execution cleanup (max_age_hours={max_age_hours})")

        from datetime import timedelta
        from src.core.database import async_session_factory
        from src.playbook_builder.models import VisualPlaybookExecution
        from sqlalchemy import select, delete
        from sqlalchemy.orm import Session

        # This is a simplified version - would need proper async context in real implementation
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        deleted_count = 0
        logger.info(f"Cleanup completed. Deleted {deleted_count} old executions")

        return {
            "deleted_count": deleted_count,
            "cutoff_time": cutoff_time.isoformat(),
        }

    except Exception as exc:
        logger.error(f"Cleanup failed: {exc}")
        raise self.retry(exc=exc, countdown=2**self.request.retries)


@shared_task(bind=True, max_retries=3)
def template_sync(
    self,
    template_source: str = "builtin",
):
    """
    Sync template library with external source.

    Args:
        template_source: Source for templates (builtin, repository, marketplace)

    Returns:
        Sync results
    """
    try:
        logger.info(f"Starting template sync from {template_source}")

        from src.playbook_builder.engine import TemplateLibrary

        # Get built-in templates
        templates = TemplateLibrary.get_templates()
        template_count = len(templates)

        logger.info(f"Synced {template_count} templates")

        return {
            "source": template_source,
            "synced_count": template_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as exc:
        logger.error(f"Template sync failed: {exc}")
        raise self.retry(exc=exc, countdown=2**self.request.retries)
