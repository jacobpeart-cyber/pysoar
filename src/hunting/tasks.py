"""Celery tasks for threat hunting.

``hunting.reap_stale_sessions`` closes hunt sessions whose executor is gone.
A hunt runs as a background task of the API process that started it and
stamps a heartbeat (``updated_at``) at every query boundary and on every
poll while paused (src/api/v1/endpoints/hunting.py ``_hunt_checkpoint``).
When that process stops (deploy, crash, OOM) the session would otherwise
stay PENDING / RUNNING / PAUSED forever and count as an active hunt. The
sweep marks such sessions FAILED with the reason; it never restarts a hunt
(an analyst starts a new session).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import select, update

from src.core.logging import get_logger

logger = get_logger(__name__)

#: A live session's heartbeat is at most a few seconds old; this much
#: silence means its executor is gone.
STALE_AFTER = timedelta(minutes=15)
#: Sessions closed per run (the sweep runs every 10 minutes).
MAX_SESSIONS_PER_RUN = 500
_LIVE_STATES = ("PENDING", "RUNNING", "PAUSED")


async def reap_stale_sessions(db, now: datetime | None = None) -> dict[str, Any]:
    """Mark live sessions without a recent heartbeat FAILED (bounded per run).

    Returns ``{"reaped": n, "by_organization": {org_id: count}}``.
    """
    from src.hunting.models import HuntSession

    now = now or datetime.now(timezone.utc)
    cutoff = now - STALE_AFTER
    rows = (
        await db.execute(
            select(HuntSession.id, HuntSession.organization_id, HuntSession.status)
            .where(HuntSession.status.in_(_LIVE_STATES), HuntSession.updated_at < cutoff)
            .order_by(HuntSession.updated_at.asc())
            .limit(MAX_SESSIONS_PER_RUN),
        )
    ).all()
    reaped = 0
    by_org: dict[str, int] = {}
    for session_id, org_id, status in rows:
        message = (
            f"executor stopped: no heartbeat since before {cutoff.isoformat()} "
            f"(was {status}); start a new session to hunt again"
        )
        result = await db.execute(
            update(HuntSession)
            .where(
                HuntSession.id == session_id,
                HuntSession.status == status,
                HuntSession.updated_at < cutoff,
            )
            .values(status="FAILED", completed_at=now, error_message=message)
            .execution_options(synchronize_session=False),
        )
        if result.rowcount == 1:
            reaped += 1
            by_org[str(org_id)] = by_org.get(str(org_id), 0) + 1
    if reaped:
        logger.warning("Stale hunt sessions closed", reaped=reaped, by_organization=by_org)
    return {"reaped": reaped, "by_organization": by_org}


@shared_task(name="hunting.reap_stale_sessions")
def reap_stale_sessions_task() -> dict[str, Any]:
    """Beat entry point for ``reap_stale_sessions`` (every 10 minutes)."""
    from src.siem.tasks import run_async

    async def _runner() -> dict[str, Any]:
        from src.core.database import async_session_factory

        async with async_session_factory() as db:
            outcome = await reap_stale_sessions(db)
            await db.commit()
        return outcome

    return run_async(_runner())
