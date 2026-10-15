"""
Audit & Evidence Celery Tasks (wave 4)

* ``collect_automated_evidence``: run one automated evidence rule.
* ``run_conmon_cycle``: run and store one organisation's ConMon cycle.
* ``audit_evidence_daily_sweep`` (beat): per organisation, run the enabled
  evidence rules that are due by their schedule and store a ConMon cycle
  when the last stored one is older than ``CONMON_INTERVAL_DAYS``.

The previous tasks in this module only returned ``{"status": "queued"}``
and did nothing; the ones nobody could use (freshness, report, packaging,
anomaly detection) were removed: their routes compute the same results.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import select

from src.core.logging import get_logger

logger = get_logger(__name__)

__all__ = ["audit_evidence_daily_sweep", "collect_automated_evidence", "run_conmon_cycle"]

#: Rule schedule -> minimum days between collections.
SCHEDULE_DAYS = {"hourly": 0, "daily": 1, "weekly": 7, "monthly": 30, "quarterly": 90}
CONMON_INTERVAL_DAYS = 7
MAX_ORGS_PER_SWEEP = 500
MAX_RULES_PER_ORG = 200


def _factory() -> Any:
    from src.core.database import async_session_factory

    return async_session_factory


def _run(coro: Any) -> Any:
    from src.siem.tasks import run_async

    return run_async(coro)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def rule_is_due(schedule: Optional[str], last_collected_at: Optional[datetime], now: datetime) -> bool:
    """True when a rule with ``schedule`` should run now."""
    last = _aware(last_collected_at)
    if last is None:
        return True
    days = SCHEDULE_DAYS.get((schedule or "daily").lower(), 1)
    return now - last >= timedelta(days=days) - timedelta(minutes=5)


async def collect_rule_async(rule_id: str, org_id: str, factory: Any = None) -> dict[str, Any]:
    from src.audit_evidence.engine import EvidenceCollector

    async with (factory or _factory())() as db:
        return await EvidenceCollector(db, org_id).collect_evidence(rule_id)


async def run_conmon_async(org_id: str, factory: Any = None) -> dict[str, Any]:
    from src.audit_evidence.engine import ContinuousMonitor

    async with (factory or _factory())() as db:
        report = await ContinuousMonitor(db, org_id).run_and_persist(assessor="system:conmon-schedule")
        await db.commit()
        return {"assessment_id": report.get("assessment_id"), "overall_status": report.get("overall_status")}


async def audit_evidence_daily_sweep_async(factory: Any = None) -> dict[str, Any]:
    from src.audit_evidence.engine import ContinuousMonitor, EvidenceCollector
    from src.audit_evidence.models import AutomatedEvidenceRule
    from src.models.organization import Organization

    factory = factory or _factory()
    now = datetime.now(timezone.utc)
    totals: dict[str, Any] = {"orgs": 0, "rules_run": 0, "evidence_written": 0, "conmon_cycles": 0, "truncated": False}
    async with factory() as db:
        org_ids = list((await db.execute(
            select(Organization.id).where(Organization.is_active.is_(True))
            .order_by(Organization.id).limit(MAX_ORGS_PER_SWEEP + 1)
        )).scalars())
    if len(org_ids) > MAX_ORGS_PER_SWEEP:
        org_ids = org_ids[:MAX_ORGS_PER_SWEEP]
        totals["truncated"] = True

    for org_id in org_ids:
        async with factory() as db:
            rules = (await db.execute(
                select(AutomatedEvidenceRule.id, AutomatedEvidenceRule.schedule, AutomatedEvidenceRule.last_collected_at)
                .where(AutomatedEvidenceRule.organization_id == org_id, AutomatedEvidenceRule.is_enabled.is_(True))
                .order_by(AutomatedEvidenceRule.id).limit(MAX_RULES_PER_ORG)
            )).all()
            collector = EvidenceCollector(db, org_id)
            for rule in rules:
                if not rule_is_due(rule.schedule, rule.last_collected_at, now):
                    continue
                try:
                    result = await collector.collect_evidence(rule.id)
                except LookupError:
                    continue
                totals["rules_run"] += 1
                totals["evidence_written"] += int(result.get("evidence_written") or 0)

            monitor = ContinuousMonitor(db, org_id)
            latest = await monitor.latest_cycle()
            ran_at = _aware(datetime.fromisoformat(latest["ran_at"])) if latest and latest.get("ran_at") else None
            if ran_at is None or now - ran_at >= timedelta(days=CONMON_INTERVAL_DAYS):
                await monitor.run_and_persist(assessor="system:conmon-schedule")
                totals["conmon_cycles"] += 1
            await db.commit()
        totals["orgs"] += 1

    if totals["truncated"]:
        logger.warning("audit_evidence_sweep_capped", cap=MAX_ORGS_PER_SWEEP)
    return totals


@shared_task(name="src.audit_evidence.tasks.collect_automated_evidence")
def collect_automated_evidence(rule_id: str, org_id: str) -> dict[str, Any]:
    """Run one automated evidence rule for ``org_id``."""
    return _run(collect_rule_async(rule_id, org_id))


@shared_task(name="src.audit_evidence.tasks.run_conmon_cycle")
def run_conmon_cycle(org_id: str) -> dict[str, Any]:
    """Run and store one ConMon cycle for ``org_id``."""
    return _run(run_conmon_async(org_id))


@shared_task(name="src.audit_evidence.tasks.audit_evidence_daily_sweep")
def audit_evidence_daily_sweep() -> dict[str, Any]:
    """Due evidence rules and the weekly ConMon cycle for every organisation."""
    return _run(audit_evidence_daily_sweep_async())
