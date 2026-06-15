"""Celery tasks for the playbook execution loop.

This module is what makes playbooks actually RUN outside a web request:

- ``run_playbook_execution`` — worker-side runner that picks up a
  ``pending`` PlaybookExecution row and drives it through the real
  engine (``src.services.playbook_engine.PlaybookEngine``).
- ``sweep_scheduled_playbooks`` — the implementation behind the beat
  task ``check_scheduled_playbooks``: finds enabled playbooks with
  ``trigger_type="scheduled"`` whose schedule is due, creates a pending
  execution, and dispatches the runner.

Schedule format (defined here — ``trigger_conditions`` JSON):
  {"interval_minutes": 30}   — run every N minutes
  {"cron": "0 8 * * *"}      — standard 5-field cron (m h dom mon dow)

Due-ness derives from the most recent execution with
``trigger_source="schedule"`` — no schema changes needed.

Spec: docs/superpowers/specs/2026-06-11-playbook-execution-loop-design.md
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from celery.schedules import crontab
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from src.core.config import settings
from src.core.logging import get_logger
from src.models.playbook import (
    ExecutionStatus,
    Playbook,
    PlaybookExecution,
    PlaybookTrigger,
)

logger = get_logger(__name__)

# NullPool: each celery task invocation runs in its own asyncio.run()
# loop, and pooled asyncpg/aiosqlite connections must not outlive the
# loop they were created on.
_engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
AsyncSessionLocal = sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


# ---------------------------------------------------------------------------
# Schedule due-logic
# ---------------------------------------------------------------------------

def schedule_is_due(
    conditions: Any,
    last_run: Optional[datetime],
    now: datetime,
) -> bool:
    """Decide whether a scheduled playbook is due to run.

    ``conditions`` is the parsed ``trigger_conditions`` JSON. Malformed
    or unrecognized conditions are never due — a misconfigured playbook
    must not fire every sweep.
    """
    if not isinstance(conditions, dict):
        return False

    interval = conditions.get("interval_minutes")
    if interval is not None:
        try:
            interval = float(interval)
        except (TypeError, ValueError):
            return False
        if interval <= 0:
            return False
        if last_run is None:
            return True
        return now - last_run >= timedelta(minutes=interval)

    cron_expr = conditions.get("cron")
    if cron_expr:
        try:
            minute, hour, dom, month, dow = str(cron_expr).split()
            # nowfun pins evaluation to the caller's `now`. Without it,
            # crontab.remaining_estimate() uses real wall-clock time,
            # which silently couples due-ness to the actual date.
            spec = crontab(
                minute=minute,
                hour=hour,
                day_of_month=dom,
                month_of_year=month,
                day_of_week=dow,
                nowfun=lambda: now,
            )
        except (ValueError, TypeError) as exc:
            logger.warning("Invalid cron expression", cron=cron_expr, error=str(exc))
            return False
        if last_run is None:
            return True
        # remaining_estimate(last_run) = (first fire strictly after
        # last_run) - now. Due once that fire time has reached `now`,
        # i.e. the remaining time is zero or negative.
        return spec.remaining_estimate(last_run) <= timedelta(0)

    return False


# ---------------------------------------------------------------------------
# Scheduler sweep
# ---------------------------------------------------------------------------

async def sweep_scheduled_playbooks(db: AsyncSession) -> dict[str, Any]:
    """Find due scheduled playbooks, create executions, dispatch the runner.

    Per-playbook try/except: one broken playbook must not starve the rest.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)  # created_at is naive UTC
    result = await db.execute(
        select(Playbook).where(
            Playbook.trigger_type == PlaybookTrigger.SCHEDULED.value,
            Playbook.is_enabled == True,  # noqa: E712
        )
    )
    playbooks = result.scalars().all()

    executed = 0
    for pb in playbooks:
        try:
            try:
                conditions = json.loads(pb.trigger_conditions) if pb.trigger_conditions else None
            except json.JSONDecodeError:
                logger.warning("Unparseable trigger_conditions", playbook_id=pb.id)
                continue

            last = (
                await db.execute(
                    select(PlaybookExecution)
                    .where(
                        PlaybookExecution.playbook_id == pb.id,
                        PlaybookExecution.trigger_source == "schedule",
                    )
                    .order_by(PlaybookExecution.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()

            if not schedule_is_due(conditions, last.created_at if last else None, now):
                continue

            execution = PlaybookExecution(
                playbook_id=pb.id,
                status=ExecutionStatus.PENDING.value,
                trigger_source="schedule",
                input_data=json.dumps({"scheduled_at": now.isoformat()}),
            )
            db.add(execution)
            await db.commit()
            run_playbook_execution.delay(execution.id)
            executed += 1
            logger.info("Dispatched scheduled playbook", playbook_id=pb.id, execution_id=execution.id)
        except Exception as exc:
            logger.error("Scheduled-playbook sweep failed for playbook", playbook_id=pb.id, error=str(exc))
            await db.rollback()

    return {"executed": executed, "checked": len(playbooks), "task": "check_scheduled_playbooks"}


async def _sweep_entry() -> dict[str, Any]:
    async with AsyncSessionLocal() as db:
        return await sweep_scheduled_playbooks(db)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

async def _run_playbook_execution(execution_id: str) -> dict[str, Any]:
    """Async core of the runner — drives one pending execution through
    the real engine and persists the outcome, whatever it is."""
    async with AsyncSessionLocal() as db:
        execution = (
            await db.execute(
                select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
            )
        ).scalar_one_or_none()
        if not execution:
            logger.error("Playbook execution not found", execution_id=execution_id)
            return {"error": "Execution not found", "execution_id": execution_id}

        if execution.status != ExecutionStatus.PENDING.value:
            # Idempotency guard: dispatched twice, or already handled.
            logger.info(
                "Skipping non-pending execution",
                execution_id=execution_id,
                status=execution.status,
            )
            return {"skipped": True, "status": execution.status, "execution_id": execution_id}

        from src.services.playbook_engine import PlaybookEngine

        try:
            engine = PlaybookEngine(db)
            result = await engine.execute(execution_id)
            await db.commit()
            return {
                "execution_id": execution_id,
                "status": result.status,
                "steps_completed": result.current_step,
            }
        except Exception as exc:
            logger.error("Playbook execution failed", execution_id=execution_id, error=str(exc))
            await db.rollback()
            # Re-fetch in the post-rollback session state and mark failed
            # so the execution-history UI shows the truth.
            execution = (
                await db.execute(
                    select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
                )
            ).scalar_one_or_none()
            if execution:
                execution.status = ExecutionStatus.FAILED.value
                execution.error_message = str(exc)
                execution.completed_at = datetime.now(timezone.utc).isoformat()
                await db.commit()
            return {
                "execution_id": execution_id,
                "status": ExecutionStatus.FAILED.value,
                "error": str(exc),
            }


@shared_task(name="playbooks.run_playbook_execution")
def run_playbook_execution(execution_id: str) -> dict[str, Any]:
    """Run one pending PlaybookExecution through the engine."""
    return asyncio.run(_run_playbook_execution(execution_id))


@shared_task(name="playbooks.check_scheduled_playbooks")
def check_scheduled_playbooks_sweep() -> dict[str, Any]:
    """Beat-friendly wrapper around the scheduler sweep."""
    return asyncio.run(_sweep_entry())
