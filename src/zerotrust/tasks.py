"""Celery tasks for Zero Trust operations.

One task does real work on a schedule: the continuous session evaluation
sweep (NIST SP 800-207 continuous verification). For every session that
received an ``allow`` decision inside the session lifetime window it asks
the policy decision point to re-score the subject; a material risk increase
records a new ``AccessDecision`` and pushes the verdict into the session
gate cache (``src/zerotrust/session_gate.py``), so the next request on that
session is challenged or refused.

Wave 5 removed the other tasks that used to live here. They were declared
``async def`` under ``@shared_task`` (Celery never awaits them, so none of
them could ever run) and none was scheduled. On inspection they did no work
worth keeping: the device "fleet assessment" re-derived trust scores that
are already recomputed whenever posture is reported, the micro-segment
"update" only touched ``updated_at``, the violation detector and maturity
calculation only logged values the API computes on demand, the report task
returned a report location that never existed, and the "token rotation"
rewrote historical allow decisions to ``challenge`` (falsifying the audit
trail without revoking anything).
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import func, select

from src.core.logging import get_logger
from src.zerotrust.engine import PolicyDecisionPoint
from src.zerotrust.models import AccessDecision

logger = get_logger(__name__)

#: Sessions older than this are expired by the session gate anyway.
SESSION_WINDOW_HOURS = 8
#: Organisations one sweep walks (those with recent allow decisions only).
MAX_ORGS_PER_SWEEP = 500
#: Sessions re-evaluated per organisation per run (most recent first).
MAX_SESSIONS_PER_ORG = 2_000


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _fresh_session_factory():
    """Per-task NullPool engine (same pattern as src.itdr.tasks): the shared
    module-level engine is bound to another event loop in a prefork child."""
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import NullPool

    from src.core.config import settings

    engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    return engine, sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def evaluate_active_sessions(
    db: Any,
    organization_id: str,
    *,
    now: Optional[datetime] = None,
    limit: int = MAX_SESSIONS_PER_ORG,
) -> dict[str, Any]:
    """Re-evaluate one organisation's sessions allowed within the window.

    Returns the counts; a session whose re-evaluation produced a non-allow
    decision is counted as escalated (the PDP has already recorded it and
    pushed it to the session gate).
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=SESSION_WINDOW_HOURS)
    session_ids = list((await db.execute(
        select(AccessDecision.session_id)
        .where(
            AccessDecision.organization_id == organization_id,
            AccessDecision.session_id.isnot(None),
            AccessDecision.decision == "allow",
            AccessDecision.created_at >= cutoff,
        )
        .group_by(AccessDecision.session_id)
        .order_by(func.max(AccessDecision.created_at).desc())
        .limit(limit)
    )).scalars().all())

    pdp = PolicyDecisionPoint(db, organization_id)
    evaluated = 0
    escalated = 0
    for session_id in session_ids:
        new_decision = await pdp.continuous_evaluation(session_id)
        evaluated += 1
        if new_decision is not None and new_decision.decision != "allow":
            escalated += 1
            logger.info(
                "zt_session_escalated",
                session_id=session_id[:8],
                decision=new_decision.decision,
                organization_id=organization_id,
            )
    return {"evaluated_sessions": evaluated, "escalated": escalated}


async def _continuous_session_sweep_async(session_factory=None) -> dict[str, Any]:
    engine = None
    if session_factory is None:
        engine, session_factory = _fresh_session_factory()
    totals = {"organizations": 0, "evaluated_sessions": 0, "escalated": 0, "failed_organizations": 0}
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=SESSION_WINDOW_HOURS)
        async with session_factory() as db:
            org_ids = list((await db.execute(
                select(AccessDecision.organization_id)
                .where(
                    AccessDecision.session_id.isnot(None),
                    AccessDecision.decision == "allow",
                    AccessDecision.created_at >= cutoff,
                )
                .group_by(AccessDecision.organization_id)
                .order_by(AccessDecision.organization_id)
                .limit(MAX_ORGS_PER_SWEEP)
            )).scalars().all())
        for org_id in org_ids:
            try:
                async with session_factory() as db:
                    result = await evaluate_active_sessions(db, org_id)
                    await db.commit()
            except Exception as exc:  # noqa: BLE001 - one tenant must not stop the sweep
                totals["failed_organizations"] += 1
                logger.warning("zt_session_sweep_org_failed", organization_id=org_id, error=str(exc)[:200])
                continue
            totals["organizations"] += 1
            totals["evaluated_sessions"] += result["evaluated_sessions"]
            totals["escalated"] += result["escalated"]
    finally:
        if engine is not None:
            await engine.dispose()
    return totals


@shared_task(bind=True, max_retries=0, name="src.zerotrust.tasks.continuous_session_evaluation")
def continuous_session_evaluation(self: Any) -> dict[str, Any]:
    """Every 5 minutes: re-evaluate active sessions of every organisation."""
    result = _run_async(_continuous_session_sweep_async())
    logger.info("zt_continuous_session_sweep_complete", **result)
    return result
