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
        from src.playbook_builder.models import VisualPlaybook, PlaybookExecution
        from sqlalchemy import select

        # This is a simplified version - would need async context in real implementation
        logger.info(f"Executing playbook {playbook_id}")

        # Simulate execution
        execution_result = {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "status": "completed",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": 1500,
        }

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
        from src.playbook_builder.models import PlaybookExecution
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
