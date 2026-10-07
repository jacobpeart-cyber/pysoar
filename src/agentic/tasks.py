"""Celery tasks for the agentic SOC (design v2 sections 6 and 8).

``run_investigation`` is the only task that talks to an LLM. It runs on its
own ``investigations`` queue with its own time limits (see
``src/workers/celery_app.py``) and classifies provider failures instead of
retrying blindly:

* ``llm_auth`` / ``llm_not_configured`` / ``llm_quota_exceeded`` /
  ``llm_invalid_response`` are not retryable. The investigation is recorded
  once as escalated and a per-organization ``llm:disabled:{org}`` flag (TTL
  1 h) stops the sweeps from enqueueing more work that cannot succeed.
* ``llm_transient`` retries at most twice, honouring ``Retry-After``.

Admission happens before anything is enqueued (:class:`_Kickoff`): the
organization's autonomous token budget, at most 3 investigations running and
at most 20 started per hour. A budget denial is persisted as an
``Investigation`` with ``outcome='queued_budget_exceeded'`` and no LLM call,
so an operator can see why nothing ran.

Every Redis and database client is created inside the task's own event loop:
Celery prefork workers call ``asyncio.run`` once per task and asyncpg ties
connections to the loop that opened them.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import func as sqlfunc, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from src.agentic.models import (
    ActionExecutionStatus,
    AgentAction,
    Investigation,
    InvestigationStatus,
    SOCAgent,
)
from src.core.config import settings
from src.core.logging import get_logger
from src.llm.base import (
    LLMAuthError,
    LLMInvalidResponse,
    LLMNotConfigured,
    LLMQuotaExceeded,
    LLMRateLimitError,
    LLMTransientError,
)

logger = get_logger(__name__)

#: Provider error codes that no amount of retrying will fix.
NON_RETRYABLE_CODES: frozenset[str] = frozenset({
    LLMAuthError.code,
    LLMNotConfigured.code,
    LLMQuotaExceeded.code,
    LLMInvalidResponse.code,
})

#: ``llm:disabled:{org}`` time to live, in seconds.
LLM_DISABLED_TTL = 3600

#: Autonomous admission caps (design section 6).
MAX_RUNNING_PER_ORG = 3
MAX_STARTED_PER_ORG_PER_HOUR = 20

#: Tokens reserved as an admission probe at enqueue time. The real spend is
#: reserved and settled inside ``run_investigation``; this reservation is
#: released immediately so a queued investigation is never double-charged.
KICKOFF_RESERVE_TOKENS = 20_000

#: Tokens reserved for one investigation before the run, settled afterwards
#: with the usage the runner actually reports.
RUN_RESERVE_TOKENS = 60_000


def _fresh_async_session_factory() -> tuple[Any, Any]:
    """A per-call engine with NullPool.

    Celery prefork workers re-enter ``asyncio.run`` per task and asyncpg pools
    tie futures to the loop that opened them. Sharing one engine across tasks
    produces ``got Future attached to a different loop`` on the second call.
    """
    engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    return engine, sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _redis_client() -> Any:
    """A Redis client for the *current* event loop (never module-level)."""
    from src.llm.quota import default_redis_factory

    return default_redis_factory(settings)()


async def _close(client: Any) -> None:
    closer = getattr(client, "aclose", None) or getattr(client, "close", None)
    if closer is None:
        return
    try:
        result = closer()
        if asyncio.iscoroutine(result):
            await result
    except Exception as exc:  # noqa: BLE001 - closing is best effort
        logger.warning("agentic_task_client_close_failed", error=str(exc)[:200])


def _hour_key(now: Optional[datetime] = None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y%m%d%H")


async def llm_disabled(redis: Any, org_id: str) -> bool:
    """Whether this organization's LLM is flagged unusable right now.

    Redis being unreachable is reported, not treated as "enabled": the caller
    decides, and the sweeps choose to keep enqueueing rather than stall the
    SOC on a cache outage.
    """
    if redis is None:
        return False
    try:
        return bool(await redis.exists(f"llm:disabled:{org_id}"))
    except Exception as exc:  # noqa: BLE001 - a cache outage must not hide work
        logger.warning("llm_disabled_check_failed", organization_id=org_id, error=str(exc)[:200])
        return False


async def set_llm_disabled(redis: Any, org_id: str, reason: str) -> None:
    """Flag the org's LLM as unusable for an hour after a non-retryable error."""
    if redis is None:
        return
    try:
        await redis.set(f"llm:disabled:{org_id}", reason[:200], ex=LLM_DISABLED_TTL)
        logger.warning("llm_disabled_flag_set", organization_id=org_id, reason=reason[:200])
    except Exception as exc:  # noqa: BLE001
        logger.error("llm_disabled_flag_failed", organization_id=org_id, error=str(exc)[:200])


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------


class _Kickoff:
    """Enqueues investigations under the autonomous admission caps.

    One instance per sweep run; it owns the Redis client and the per-org agent
    lookup cache for that sweep.
    """

    def __init__(self, db: AsyncSession, redis: Any, quota: Any = None) -> None:
        self.db = db
        self.redis = redis
        self._quota = quota
        self._agents: dict[str, Optional[str]] = {}
        self.enqueued: list[dict[str, str]] = []
        self.skipped: dict[str, int] = {}

    @property
    def quota(self) -> Any:
        if self._quota is None:
            from src.llm.quota import TokenQuota

            self._quota = TokenQuota(redis_factory=(lambda: self.redis) if self.redis is not None else None)
        return self._quota

    def _skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    async def agent_for(self, org_id: str) -> Optional[str]:
        """The org's investigation-capable SOC agent, if it has one."""
        if org_id in self._agents:
            return self._agents[org_id]
        agent = (await self.db.execute(
            select(SOCAgent).where(
                SOCAgent.organization_id == org_id,
                SOCAgent.agent_type.in_(["investigation", "triage_analyst"]),
            ).limit(1)
        )).scalar_one_or_none()
        if agent is None:
            agent = (await self.db.execute(
                select(SOCAgent).where(SOCAgent.organization_id == org_id).limit(1)
            )).scalar_one_or_none()
        self._agents[org_id] = agent.id if agent is not None else None
        return self._agents[org_id]

    async def already_investigated(self, org_id: str, trigger_type: str, trigger_source_id: str) -> bool:
        existing = (await self.db.execute(
            select(Investigation.id).where(
                Investigation.organization_id == org_id,
                Investigation.trigger_type == trigger_type,
                Investigation.trigger_source_id == trigger_source_id,
            ).limit(1)
        )).scalar_one_or_none()
        return existing is not None

    async def _concurrency_ok(self, org_id: str) -> bool:
        """At most ``MAX_RUNNING_PER_ORG`` investigations in flight per org."""
        if self.redis is None:
            return True
        try:
            running = int(await self.redis.get(f"llm:auto:running:{org_id}") or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("auto_running_check_failed", organization_id=org_id, error=str(exc)[:200])
            return True
        return running < MAX_RUNNING_PER_ORG

    async def _hourly_ok(self, org_id: str) -> bool:
        """At most ``MAX_STARTED_PER_ORG_PER_HOUR`` starts per org per hour."""
        if self.redis is None:
            return True
        key = f"llm:auto:started:{org_id}:{_hour_key()}"
        try:
            started = int(await self.redis.incr(key))
            if started == 1:
                await self.redis.expire(key, LLM_DISABLED_TTL)
            if started > MAX_STARTED_PER_ORG_PER_HOUR:
                await self.redis.decr(key)
                return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("auto_started_check_failed", organization_id=org_id, error=str(exc)[:200])
            return True
        return True

    async def _budget_ok(self, org_id: str) -> bool:
        """Probe the org's autonomous token budget and release the probe."""
        quota = self.quota
        try:
            reservation = await quota.reserve(org_id, "autonomous", KICKOFF_RESERVE_TOKENS)
        except LLMQuotaExceeded as exc:
            logger.warning("autonomous_budget_denied", organization_id=org_id, detail=str(exc)[:200])
            return False
        try:
            await quota.settle(reservation, 0)
        except Exception as exc:  # noqa: BLE001 - the probe must not hold budget
            logger.warning("autonomous_budget_probe_release_failed", organization_id=org_id, error=str(exc)[:200])
        return True

    async def _record_budget_denied(
        self, org_id: str, agent_id: str, trigger_type: str, trigger_source_id: str, title: str
    ) -> None:
        """Persist the denial so the operator sees why nothing ran. No LLM call."""
        self.db.add(Investigation(
            agent_id=agent_id,
            organization_id=org_id,
            trigger_type=trigger_type,
            trigger_source_id=trigger_source_id,
            title=title[:500],
            status=InvestigationStatus.AWAITING_HUMAN.value,
            priority=3,
            confidence_score=None,
            outcome="queued_budget_exceeded",
            failure_reason="autonomous daily token budget exhausted for this organization",
            findings_summary=(
                "Not investigated: this organization's autonomous LLM token budget is exhausted, "
                "so no analysis was attempted. Raise the budget or triage this trigger manually."
            ),
        ))
        await self.db.commit()

    async def submit(
        self,
        org_id: str,
        trigger_type: str,
        trigger_source_id: str,
        title: str,
        severity: str,
    ) -> bool:
        """Enqueue one investigation if every admission check passes."""
        if not org_id or not trigger_source_id:
            self._skip("missing_org_or_trigger")
            return False
        agent_id = await self.agent_for(org_id)
        if not agent_id:
            self._skip("no_soc_agent")
            return False
        if await self.already_investigated(org_id, trigger_type, trigger_source_id):
            self._skip("already_investigated")
            return False
        if await llm_disabled(self.redis, org_id):
            self._skip("llm_disabled")
            return False
        if not await self._concurrency_ok(org_id):
            self._skip("org_concurrency_cap")
            return False
        if not await self._budget_ok(org_id):
            self._skip("budget_exceeded")
            await self._record_budget_denied(
                org_id, agent_id, trigger_type, trigger_source_id, f"Auto-triage: {title[:160]}"
            )
            return False
        if not await self._hourly_ok(org_id):
            self._skip("org_hourly_cap")
            return False

        run_investigation.delay(
            agent_id=agent_id,
            organization_id=org_id,
            trigger_type=trigger_type,
            trigger_source_id=trigger_source_id,
            title=f"Auto-triage: {title[:160]}",
            initial_context={"auto_triage": True, "severity": severity, "source": trigger_type},
        )
        self.enqueued.append({"type": trigger_type, "id": trigger_source_id})
        return True

    def summary(self) -> dict[str, Any]:
        return {
            "enqueued": len(self.enqueued),
            "items": self.enqueued[:10],
            "skipped": dict(self.skipped),
        }


# ---------------------------------------------------------------------------
# The investigation task
# ---------------------------------------------------------------------------


async def _load_or_create_investigation(
    db: AsyncSession,
    *,
    agent_id: str,
    organization_id: str,
    trigger_type: str,
    trigger_source_id: str,
    title: str,
    initial_context: Optional[dict[str, Any]],
) -> Investigation:
    """Reuse an open investigation for this trigger, else create one."""
    existing = None
    if trigger_source_id:
        existing = (await db.execute(
            select(Investigation).where(
                Investigation.organization_id == organization_id,
                Investigation.trigger_source_id == trigger_source_id,
                Investigation.trigger_type == trigger_type,
                Investigation.status.notin_([
                    InvestigationStatus.COMPLETED.value,
                    InvestigationStatus.ABANDONED.value,
                ]),
            ).limit(1)
        )).scalar_one_or_none()
    if existing is not None:
        return existing
    row = Investigation(
        agent_id=agent_id,
        organization_id=organization_id,
        trigger_type=trigger_type,
        trigger_source_id=trigger_source_id,
        title=title[:500],
        status=InvestigationStatus.INITIATED.value,
        priority=3,
        confidence_score=None,
        reasoning_chain=json.dumps([]),
        evidence_collected=json.dumps(initial_context or {}),
        actions_taken=json.dumps([]),
    )
    db.add(row)
    await db.flush()
    return row


async def _run_one_investigation(
    *,
    agent_id: str,
    organization_id: str,
    trigger_type: str,
    trigger_source_id: str,
    title: str,
    initial_context: Optional[dict[str, Any]],
    session_factory: Any = None,
    redis: Any = None,
    quota: Any = None,
) -> dict[str, Any]:
    """One investigation, end to end, inside this task's event loop.

    ``session_factory`` / ``redis`` / ``quota`` default to the per-loop
    production clients; the tests inject their own so this classification
    path can be exercised without a worker.
    """
    from src.agentic.investigator import AutonomousInvestigator, InvestigationSetupError
    from src.llm.quota import TokenQuota

    engine = None
    if session_factory is None:
        engine, session_factory = _fresh_async_session_factory()
    owns_redis = redis is None
    redis = redis if redis is not None else _redis_client()
    owns_quota = quota is None
    quota = quota if quota is not None else TokenQuota(redis_factory=lambda: redis)
    running_key = f"llm:auto:running:{organization_id}"
    counted = False
    reservation = None
    out: dict[str, Any] = {"organization_id": organization_id}

    try:
        try:
            await redis.incr(running_key)
            await redis.expire(running_key, 3600)
            counted = True
        except Exception as exc:  # noqa: BLE001 - the gauge is advisory
            logger.warning("auto_running_incr_failed", organization_id=organization_id, error=str(exc)[:200])

        async with session_factory() as db:
            investigation = await _load_or_create_investigation(
                db,
                agent_id=agent_id,
                organization_id=organization_id,
                trigger_type=trigger_type,
                trigger_source_id=trigger_source_id,
                title=title,
                initial_context=initial_context,
            )
            out["investigation_id"] = investigation.id
            try:
                reservation = await quota.reserve(organization_id, "autonomous", RUN_RESERVE_TOKENS)
            except LLMQuotaExceeded as exc:
                investigation.outcome = "queued_budget_exceeded"
                investigation.failure_reason = str(exc)[:2000]
                investigation.confidence_score = None
                investigation.status = InvestigationStatus.AWAITING_HUMAN.value
                investigation.findings_summary = (
                    "Not investigated: this organization's autonomous LLM token budget is exhausted, "
                    "so no provider call was made."
                )
                await db.commit()
                out.update({"outcome": investigation.outcome, "error_code": exc.code})
                return out

            investigator = AutonomousInvestigator(db, redis=redis, quota=quota)
            try:
                await investigator.run(investigation)
            except InvestigationSetupError as exc:
                await db.rollback()
                investigation.outcome = "setup_error"
                investigation.failure_reason = f"{exc.reason}: {exc}"[:2000]
                investigation.confidence_score = None
                investigation.status = InvestigationStatus.ESCALATED.value
                investigation.findings_summary = (
                    f"Investigation could not start: {exc}. No analysis was performed."
                )
                await db.commit()
                out.update({"outcome": investigation.outcome, "error_code": "setup_error"})
                return out

            out.update({
                "status": investigation.status,
                "outcome": investigation.outcome,
                "resolution_type": investigation.resolution_type,
                "confidence": investigation.confidence_score,
                "findings_summary": investigation.findings_summary,
                "tokens_used": investigation.tokens_used or 0,
            })
            if investigation.outcome == "provider_error":
                out["error_code"] = _error_code_from(investigation.failure_reason)
            elif investigation.outcome == "llm_not_configured":
                out["error_code"] = LLMNotConfigured.code

        code = out.get("error_code")
        if code in NON_RETRYABLE_CODES:
            await set_llm_disabled(redis, organization_id, f"{code} on investigation {out.get('investigation_id')}")
        return out
    finally:
        if reservation is not None:
            try:
                await quota.settle(reservation, int(out.get("tokens_used") or 0))
            except Exception as exc:  # noqa: BLE001
                logger.warning("autonomous_settle_failed", organization_id=organization_id, error=str(exc)[:200])
        if counted:
            try:
                await redis.decr(running_key)
            except Exception as exc:  # noqa: BLE001
                logger.warning("auto_running_decr_failed", organization_id=organization_id, error=str(exc)[:200])
        if owns_quota:
            await quota.aclose()
        if owns_redis:
            await _close(redis)
        if engine is not None:
            await engine.dispose()


def _error_code_from(failure_reason: Optional[str]) -> Optional[str]:
    """The provider error code the investigator recorded, if any."""
    if not failure_reason:
        return None
    for code in (*NON_RETRYABLE_CODES, LLMTransientError.code, LLMRateLimitError.code):
        if code in failure_reason:
            return code
    return None


@shared_task(bind=True, max_retries=2)
def run_investigation(
    self,
    agent_id: str,
    organization_id: str,
    trigger_type: str,
    trigger_source_id: str,
    title: str,
    initial_context: Optional[dict] = None,
):
    """Run one autonomous investigation on the ``investigations`` queue.

    Non-retryable provider failures are recorded once and disable the org's
    LLM for an hour; transient failures retry at most twice.
    """
    try:
        result = asyncio.run(_run_one_investigation(
            agent_id=agent_id,
            organization_id=organization_id,
            trigger_type=trigger_type,
            trigger_source_id=trigger_source_id,
            title=title,
            initial_context=initial_context,
        ))
    except (LLMAuthError, LLMNotConfigured, LLMQuotaExceeded, LLMInvalidResponse) as exc:
        # Raised outside the investigator's own handling (e.g. during
        # admission). Record nothing twice; just stop retrying.
        logger.error(
            "investigation_not_retryable",
            organization_id=organization_id,
            code=exc.code,
            error=str(exc)[:300],
        )
        return {"organization_id": organization_id, "outcome": "llm_error", "error_code": exc.code}
    except LLMTransientError as exc:
        countdown = int(exc.retry_after or 60 * (2 ** self.request.retries))
        logger.warning(
            "investigation_transient_retry",
            organization_id=organization_id,
            retries=self.request.retries,
            countdown=countdown,
        )
        raise self.retry(exc=exc, countdown=countdown, max_retries=2)

    code = result.get("error_code")
    if code == LLMTransientError.code and self.request.retries < 2:
        countdown = 60 * (2 ** self.request.retries)
        logger.warning(
            "investigation_transient_retry",
            organization_id=organization_id,
            investigation_id=result.get("investigation_id"),
            countdown=countdown,
        )
        raise self.retry(countdown=countdown, max_retries=2)
    logger.info(
        "investigation_task_finished",
        organization_id=organization_id,
        investigation_id=result.get("investigation_id"),
        outcome=result.get("outcome"),
    )
    return result


# ---------------------------------------------------------------------------
# Sweeps
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=0)
def autonomous_triage(self, organization_id: str, alert_batch_size: int = 10):
    """Triage one organization's newest untriaged alerts.

    Picks the highest-severity ``new`` alerts and hands each to
    ``run_investigation`` through the shared admission path. Alert status is
    advanced only for the alerts actually enqueued.
    """

    async def _run() -> dict[str, Any]:
        from src.models.alert import Alert, AlertStatus

        engine, session_factory = _fresh_async_session_factory()
        redis = _redis_client()
        try:
            async with session_factory() as db:
                kickoff = _Kickoff(db, redis)
                alerts = list(await db.scalars(
                    select(Alert).where(
                        Alert.organization_id == organization_id,
                        Alert.status == AlertStatus.NEW.value,
                    ).order_by(Alert.severity.desc()).limit(int(alert_batch_size))
                ))
                for alert in alerts:
                    if await kickoff.submit(
                        organization_id, "alert", alert.id, alert.title or alert.id, alert.severity or "medium"
                    ):
                        alert.status = "triaged"
                await db.commit()
                out = kickoff.summary()
                out["alerts_considered"] = len(alerts)
                return out
        finally:
            await _close(redis)
            await engine.dispose()

    result = asyncio.run(_run())
    logger.info("autonomous_triage_complete", organization_id=organization_id, **{
        k: v for k, v in result.items() if k != "items"
    })
    return result


@shared_task(bind=True, max_retries=0)
def auto_triage_new_alerts(self):
    """Cross-org sweep: investigate fresh critical/high alerts.

    Runs every 60 s. Idempotent by (trigger_type, trigger_source_id); the
    10-minute lookback caps backlog processing on a slow worker.
    """

    async def _scan() -> dict[str, Any]:
        from src.models.alert import Alert

        since = datetime.now(timezone.utc) - timedelta(minutes=10)
        engine, session_factory = _fresh_async_session_factory()
        redis = _redis_client()
        try:
            async with session_factory() as db:
                kickoff = _Kickoff(db, redis)
                alerts = list(await db.scalars(
                    select(Alert).where(
                        Alert.created_at >= since,
                        Alert.severity.in_(["critical", "high"]),
                        Alert.status.in_(["new", "open", "investigating"]),
                    ).limit(25)
                ))
                for alert in alerts:
                    if not alert.organization_id:
                        continue
                    await kickoff.submit(
                        alert.organization_id, "alert", alert.id,
                        alert.title or alert.id, alert.severity or "high",
                    )
                out = kickoff.summary()
                out["checked"] = len(alerts)
                return out
        finally:
            await _close(redis)
            await engine.dispose()

    result = asyncio.run(_scan())
    if result.get("enqueued"):
        logger.info("auto_triage_new_alerts_enqueued", count=result["enqueued"])
    return result


@shared_task(bind=True, max_retries=0)
def auto_triage_broad_sweep(self):
    """Cross-org sweep over the non-alert detectors.

    A real SOC watches every signal source, not just the alerts table: UEBA
    risk alerts, dark-web findings and decoy interactions all fan into the
    same autonomous investigator under the same admission caps. Each source
    is scanned within a 30-minute lookback window.
    """

    async def _sweep() -> dict[str, Any]:
        since = datetime.now(timezone.utc) - timedelta(minutes=30)
        engine, session_factory = _fresh_async_session_factory()
        redis = _redis_client()
        try:
            async with session_factory() as db:
                kickoff = _Kickoff(db, redis)

                try:
                    from src.ueba.models import EntityProfile, UEBARiskAlert

                    rows = list(await db.scalars(
                        select(UEBARiskAlert).where(
                            UEBARiskAlert.created_at >= since,
                            UEBARiskAlert.severity.in_(["critical", "high"]),
                        ).limit(25)
                    ))
                    for r in rows:
                        entity = await db.get(EntityProfile, r.entity_profile_id)
                        if entity is None or not entity.organization_id:
                            continue
                        await kickoff.submit(
                            entity.organization_id, "ueba_alert", r.id,
                            f"UEBA {r.severity} risk alert: {r.alert_type} on "
                            f"{entity.display_name or entity.entity_id}",
                            r.severity,
                        )
                except Exception as exc:  # noqa: BLE001 - one detector must not stop the sweep
                    logger.warning("broad_sweep_ueba_failed", error_class=exc.__class__.__name__, error=str(exc)[:200])

                try:
                    from src.darkweb.models import DarkWebFinding

                    rows = list(await db.scalars(
                        select(DarkWebFinding).where(
                            DarkWebFinding.created_at >= since,
                            DarkWebFinding.severity.in_(["critical", "high"]),
                            DarkWebFinding.status.in_(["new", "reviewing"]),
                        ).limit(25)
                    ))
                    for r in rows:
                        if not r.organization_id:
                            continue
                        await kickoff.submit(
                            r.organization_id, "darkweb_finding", r.id,
                            f"Dark web {r.severity} finding ({r.finding_type}): {r.title or r.id}",
                            r.severity,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("broad_sweep_darkweb_failed", error_class=exc.__class__.__name__, error=str(exc)[:200])

                try:
                    from src.deception.models import Decoy, DecoyInteraction

                    rows = list(await db.scalars(
                        select(DecoyInteraction).where(DecoyInteraction.created_at >= since).limit(25)
                    ))
                    for r in rows:
                        decoy = await db.get(Decoy, r.decoy_id)
                        org_id = getattr(decoy, "organization_id", None) if decoy is not None else None
                        if not org_id:
                            continue
                        await kickoff.submit(
                            org_id, "decoy_interaction", r.id,
                            f"Decoy touched: {r.interaction_type} from {r.source_ip} on "
                            f"{decoy.name if decoy is not None else r.decoy_id}",
                            "high",  # there is no legitimate reason to touch a decoy
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("broad_sweep_decoy_failed", error_class=exc.__class__.__name__, error=str(exc)[:200])

                return kickoff.summary()
        finally:
            await _close(redis)
            await engine.dispose()

    result = asyncio.run(_sweep())
    if result.get("enqueued"):
        logger.info("broad_sweep_enqueued", count=result["enqueued"])
    return result


@shared_task(bind=True, max_retries=0)
def followup_open_incidents(self):
    """Nudge on incidents whose recommended actions are still unapproved.

    Scans incidents open >= 4 hours, finds the investigation that opened each
    one (``Alert.incident_id`` is the link the investigator writes), and
    re-sends the notification when proposals are still pending. This is the
    bot-level "did anyone ever approve the isolate-host action?".
    """

    async def _followup() -> dict[str, Any]:
        from src.models.alert import Alert
        from src.models.incident import Incident

        cutoff = datetime.now(timezone.utc) - timedelta(hours=4)
        nudged: list[str] = []
        engine, session_factory = _fresh_async_session_factory()
        try:
            async with session_factory() as db:
                incidents = list(await db.scalars(
                    select(Incident).where(
                        Incident.created_at <= cutoff,
                        Incident.status.in_(["open", "investigating", "triaged"]),
                    ).limit(50)
                ))
                for inc in incidents:
                    alert_id = (await db.execute(
                        select(Alert.id).where(
                            Alert.incident_id == inc.id,
                            Alert.organization_id == inc.organization_id,
                        ).limit(1)
                    )).scalar_one_or_none()
                    if not alert_id:
                        continue
                    inv = (await db.execute(
                        select(Investigation).where(
                            Investigation.organization_id == inc.organization_id,
                            Investigation.trigger_source_id == alert_id,
                            Investigation.trigger_type.in_(["alert", "alert_manual"]),
                        ).limit(1)
                    )).scalar_one_or_none()
                    if inv is None:
                        continue
                    pending = await db.scalar(
                        select(sqlfunc.count(AgentAction.id)).where(
                            AgentAction.organization_id == inc.organization_id,
                            AgentAction.investigation_id == inv.id,
                            AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value,
                        )
                    )
                    if not pending:
                        continue
                    hours = int((datetime.now(timezone.utc) - inc.created_at).total_seconds() / 3600)
                    try:
                        from src.services.notifications import send_incident_notifications

                        await send_incident_notifications(
                            db,
                            organization_id=inc.organization_id,
                            event={
                                "incident_id": inc.id,
                                "title": f"[FOLLOW-UP] {inc.title}",
                                "severity": inc.severity,
                                "summary": (
                                    f"Incident has been open {hours} hours with {pending} agent-recommended "
                                    f"action(s) still awaiting approval. Verdict: "
                                    f"{inv.resolution_type or inv.outcome or 'unknown'}. "
                                    "Open /agentic -> Approvals to review."
                                ),
                                "trigger": "followup-check",
                            },
                        )
                        nudged.append(inc.id)
                    except Exception as exc:  # noqa: BLE001 - one failed channel must not stop the sweep
                        logger.warning(
                            "followup_notify_failed", incident_id=inc.id, error_class=exc.__class__.__name__
                        )
            return {"nudged": len(nudged), "incidents": nudged}
        finally:
            await engine.dispose()

    return asyncio.run(_followup())


@shared_task(bind=True, max_retries=0)
def cleanup_stale_investigations(self, days_old: int = 30):
    """Abandon investigations that have been stuck short of a terminal state.

    Anything still in a working state after ``days_old`` days is marked
    abandoned with an honest reason, so the queue stops showing work nobody
    is doing. Completed and already-abandoned rows are left alone.
    """

    async def _run() -> dict[str, Any]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(days_old))
        engine, session_factory = _fresh_async_session_factory()
        try:
            async with session_factory() as db:
                stale = list(await db.scalars(
                    select(Investigation).where(
                        Investigation.created_at < cutoff,
                        Investigation.status.notin_([
                            InvestigationStatus.COMPLETED.value,
                            InvestigationStatus.ABANDONED.value,
                        ]),
                    ).limit(500)
                ))
                for inv in stale:
                    inv.status = InvestigationStatus.ABANDONED.value
                    if not inv.outcome:
                        inv.outcome = "inconclusive_budget"
                        inv.failure_reason = f"abandoned after {days_old} days without reaching a verdict"
                await db.commit()
                return {
                    "investigations_abandoned": len(stale),
                    "cutoff_date": cutoff.isoformat(),
                }
        finally:
            await engine.dispose()

    result = asyncio.run(_run())
    logger.info("cleanup_stale_investigations", **result)
    return result


@shared_task(max_retries=0)
def purge_agentic_retention() -> dict[str, Any]:
    """Nightly retention purge of ``llm_call_logs`` and ``agent_run_transcripts``.

    Honours each organization's ``llm_call_log_retention_days`` and
    ``agent_transcript_retention_days`` (``agentic_policy`` settings, 30..1095
    days, default 365); see :mod:`src.agentic.retention` for the rollup-then-
    delete order and the window/commit bounds. ``truncated`` in the result
    means the per-run cap was reached and the next run continues.
    """
    from src.agentic.retention import run_retention_purge

    async def _run() -> dict[str, Any]:
        engine, session_factory = _fresh_async_session_factory()
        try:
            return (await run_retention_purge(session_factory)).as_dict()
        finally:
            await engine.dispose()

    result = asyncio.run(_run())
    logger.info(
        "agentic_retention_purge_complete",
        **{k: v for k, v in result.items() if k != "per_org"},
    )
    return result
