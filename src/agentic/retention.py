"""Nightly retention purge for LLM call logs and agent run transcripts.

Decision 2026-10-06 (docs/agentic-soc.md section 11): raw ``llm_call_logs``
rows and ``agent_run_transcripts`` are kept for the organization's
``llm_call_log_retention_days`` / ``agent_transcript_retention_days``
(``agentic_policy`` settings section, 30..1095 days, default 365).

Per organization, :func:`run_retention_purge`:

1. rolls every whole UTC day about to leave the call-log window into
   ``llm_usage_daily`` (skipping days that already have a rollup, so a partly
   purged day is never re-aggregated from what is left of it). The call-log
   cutoff is aligned to UTC midnight, so a day is purged whole, never half;
2. deletes call-log rows older than that cutoff;
3. deletes transcripts whose stamped ``retention_until`` has passed. A
   transcript's expiry is fixed when it is written
   (:func:`src.agentic.transcript.transcript_retention_until`), so changing
   the setting affects new transcripts and leaves existing ones alone.

Every delete is a window of at most :data:`PURGE_BATCH_SIZE` rows committed on
its own, and a run stops after :data:`MAX_PURGE_BATCHES_PER_RUN` windows with
``truncated=True`` (the next night continues). Organizations are paged by
primary key in windows of :data:`ORG_WINDOW`; every statement carries an
``organization_id`` predicate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.policy import AGENTIC_POLICY_SECTION, OrgPolicySettings, org_policy_settings_from_section
from src.agentic.transcript import AgentRunTranscript
from src.core.logging import get_logger
from src.llm.calllog import purge_call_logs, rollup_usage_daily
from src.llm.models import LLMCallLog, LLMUsageDaily
from src.models.organization import Organization
from src.models.settings import AppSetting

logger = get_logger(__name__)

__all__ = [
    "MAX_PURGE_BATCHES_PER_RUN",
    "MAX_ROLLUP_DAYS_PER_ORG",
    "ORG_WINDOW",
    "PURGE_BATCH_SIZE",
    "RetentionPurgeResult",
    "call_log_cutoff",
    "purge_expired_transcripts",
    "run_retention_purge",
]

#: Rows deleted per committed window.
PURGE_BATCH_SIZE = 10_000
#: Deleted windows per run across every organization and both tables.
MAX_PURGE_BATCHES_PER_RUN = 100
#: Organizations read per keyset page.
ORG_WINDOW = 1_000
#: Days rolled up per organization per run (a first run after a retention
#: change can face a long backlog; the rest is handled on following nights).
MAX_ROLLUP_DAYS_PER_ORG = 400

SessionFactory = Callable[[], Any]


@dataclass
class RetentionPurgeResult:
    """Return contract of the purge (and of the Celery task)."""

    organizations: int = 0
    call_logs_deleted: int = 0
    transcripts_deleted: int = 0
    days_rolled_up: int = 0
    batches: int = 0
    failed_organizations: int = 0
    truncated: bool = False
    per_org: dict[str, dict[str, int]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "completed",
            "organizations": self.organizations,
            "call_logs_deleted": self.call_logs_deleted,
            "transcripts_deleted": self.transcripts_deleted,
            "days_rolled_up": self.days_rolled_up,
            "batches": self.batches,
            "failed_organizations": self.failed_organizations,
            "truncated": self.truncated,
            "per_org": self.per_org,
        }


def _midnight(day: date) -> datetime:
    return datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)


def _as_utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes for timezone-aware columns.
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def call_log_cutoff(now: datetime, retention_days: int) -> datetime:
    """UTC midnight of the first day still inside the retention window.

    Rows created before it are purged, so a row is always kept at least
    ``retention_days`` days and a day is always purged whole.
    """
    return _midnight((_as_utc(now) - timedelta(days=int(retention_days))).date())


async def purge_expired_transcripts(
    db: AsyncSession, *, organization_id: str, now: datetime, limit: int = PURGE_BATCH_SIZE,
) -> int:
    """Delete at most ``limit`` transcripts of one organization whose
    ``retention_until`` has passed; returns the number deleted. Caller commits."""
    window = (
        select(AgentRunTranscript.id)
        .where(
            AgentRunTranscript.organization_id == organization_id,
            AgentRunTranscript.retention_until < now,
        )
        .order_by(AgentRunTranscript.id)
        .limit(int(limit))
    )
    result = await db.execute(
        delete(AgentRunTranscript)
        .where(AgentRunTranscript.organization_id == organization_id, AgentRunTranscript.id.in_(window))
        .execution_options(synchronize_session=False),
    )
    return int(result.rowcount or 0)


class _Budget:
    """Shared per-run cap on deleted windows."""

    def __init__(self, max_batches: int) -> None:
        self.remaining = int(max_batches)
        self.used = 0
        self.exhausted = False

    def take(self) -> bool:
        if self.remaining <= 0:
            self.exhausted = True
            return False
        self.remaining -= 1
        self.used += 1
        return True


async def _rollup_before_purge(
    db: AsyncSession, org_id: str, cutoff: datetime,
) -> tuple[int, datetime, bool]:
    """Roll up each whole day before ``cutoff`` that has raw rows and no rollup.

    Returns ``(days_rolled_up, effective_cutoff, truncated)``. When more than
    :data:`MAX_ROLLUP_DAYS_PER_ORG` days are pending the cutoff is pulled back
    to the end of the last day handled, so nothing unrolled is deleted.
    """
    oldest = (
        await db.execute(
            select(func.min(LLMCallLog.created_at)).where(
                LLMCallLog.organization_id == org_id, LLMCallLog.created_at < cutoff,
            ),
        )
    ).scalar_one_or_none()
    if oldest is None:
        return 0, cutoff, False
    first_day = _as_utc(oldest).date()
    last_day = cutoff.date()  # exclusive
    span = (last_day - first_day).days
    truncated = span > MAX_ROLLUP_DAYS_PER_ORG
    if truncated:
        last_day = first_day + timedelta(days=MAX_ROLLUP_DAYS_PER_ORG)
    already = {
        d
        for (d,) in (
            await db.execute(
                select(LLMUsageDaily.day)
                .where(
                    LLMUsageDaily.organization_id == org_id,
                    LLMUsageDaily.day >= first_day,
                    LLMUsageDaily.day < last_day,
                )
                .distinct(),
            )
        ).all()
    }
    rolled = 0
    day = first_day
    while day < last_day:
        if day not in already:
            if await rollup_usage_daily(db, day, organization_id=org_id):
                rolled += 1
            await db.commit()
            db.expunge_all()
        day += timedelta(days=1)
    return rolled, _midnight(last_day), truncated


async def _purge_org(
    session_factory: SessionFactory,
    org_id: str,
    policy: OrgPolicySettings,
    now: datetime,
    budget: _Budget,
    result: RetentionPurgeResult,
) -> None:
    counts = {"call_logs": 0, "transcripts": 0, "days_rolled_up": 0}
    async with session_factory() as db:
        cutoff = call_log_cutoff(now, policy.llm_call_log_retention_days)
        rolled, cutoff, rollup_truncated = await _rollup_before_purge(db, org_id, cutoff)
        counts["days_rolled_up"] = rolled
        if rollup_truncated:
            result.truncated = True

        while budget.take():
            n = await purge_call_logs(db, organization_id=org_id, cutoff=cutoff, limit=PURGE_BATCH_SIZE)
            await db.commit()
            counts["call_logs"] += n
            if n < PURGE_BATCH_SIZE:
                break

        while budget.take():
            n = await purge_expired_transcripts(db, organization_id=org_id, now=now, limit=PURGE_BATCH_SIZE)
            await db.commit()
            counts["transcripts"] += n
            if n < PURGE_BATCH_SIZE:
                break

    result.call_logs_deleted += counts["call_logs"]
    result.transcripts_deleted += counts["transcripts"]
    result.days_rolled_up += counts["days_rolled_up"]
    if any(counts.values()):
        result.per_org[org_id] = counts
        logger.info(
            "agentic_retention_org_purged",
            organization_id=org_id,
            call_log_retention_days=policy.llm_call_log_retention_days,
            transcript_retention_days=policy.agent_transcript_retention_days,
            call_logs_deleted=counts["call_logs"],
            transcripts_deleted=counts["transcripts"],
            days_rolled_up=counts["days_rolled_up"],
            call_log_cutoff=cutoff.isoformat(),
        )


async def run_retention_purge(
    session_factory: SessionFactory,
    *,
    now: Optional[datetime] = None,
    max_batches: int = MAX_PURGE_BATCHES_PER_RUN,
) -> RetentionPurgeResult:
    """Apply every organization's retention to call logs and transcripts.

    ``session_factory`` opens an ``AsyncSession``; each organization gets its
    own session and every deleted window is committed on its own. One
    organization failing is logged and counted, and the sweep continues.
    """
    now = _as_utc(now or datetime.now(timezone.utc))
    budget = _Budget(max_batches)
    result = RetentionPurgeResult()
    last_id: Optional[str] = None

    while True:
        async with session_factory() as db:
            stmt = select(Organization.id).order_by(Organization.id).limit(ORG_WINDOW)
            if last_id is not None:
                stmt = stmt.where(Organization.id > last_id)
            org_ids = [str(o) for (o,) in (await db.execute(stmt)).all()]
            if not org_ids:
                break
            sections = {
                str(org): value
                for org, value in (
                    await db.execute(
                        select(AppSetting.organization_id, AppSetting.value).where(
                            AppSetting.section == AGENTIC_POLICY_SECTION,
                            AppSetting.organization_id.in_(org_ids),
                        ),
                    )
                ).all()
            }
        last_id = org_ids[-1]

        for org_id in org_ids:
            if budget.remaining <= 0:
                budget.exhausted = True
                break
            stored = sections.get(org_id)
            policy = org_policy_settings_from_section(stored if isinstance(stored, dict) else None)
            result.organizations += 1
            try:
                await _purge_org(session_factory, org_id, policy, now, budget, result)
            except SQLAlchemyError as exc:
                result.failed_organizations += 1
                logger.error(
                    "agentic_retention_org_failed",
                    organization_id=org_id,
                    error_class=type(exc).__name__,
                    error=str(exc)[:200],
                )
        if budget.exhausted or len(org_ids) < ORG_WINDOW:
            break

    result.batches = budget.used
    if budget.exhausted:
        result.truncated = True
    return result
