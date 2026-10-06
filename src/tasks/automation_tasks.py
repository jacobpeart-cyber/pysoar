"""
Periodic scheduled automation Celery tasks for PySOAR.

These tasks run on Celery Beat schedules to continuously monitor the platform
and drive cross-module automation through the AutomationService. They cover:

  * Auto-escalation of stale alerts
  * Auto-closing of long-resolved alerts
  * Periodic IOC sweeps against recent alerts
  * Daily threat briefings
  * Hourly correlation sweeps that cluster related alerts into incidents

Memory bounds (prod OOM post-mortem 2026-09-01)
-----------------------------------------------
Every sweep in this module used to run one unfiltered ``SELECT`` and
materialise it with ``.scalars().all()``:

  * ``auto_escalate_stale_alerts`` / ``auto_close_resolved_alerts`` had no
    lower time bound at all — every matching alert ever written, as full ORM
    objects (``raw_data`` / ``description`` blobs included).
  * ``periodic_ioc_sweep`` additionally loaded the **entire**
    ``threat_indicators`` table as ORM objects, every 15 minutes, just to
    build a set of strings. ``intel.poll_threat_feeds`` grows that table by
    tens of thousands of rows a day, so on a month-old deployment this is a
    multi-hundred-MB-to-GB allocation inside a single task.
  * ``hourly_correlation_sweep`` held every alert in a 2 h window as ORM
    objects inside a cluster dict.

A Celery per-child memory cap only recycles a child *between* tasks, so a
single task whose working set grows past the container limit is what gets
OOM-killed. Each sweep below now reads in fixed-size windows with a
per-window commit, keeps only the columns it actually uses, and caps its
per-run work with the cap logged.

Each task delegates to a module-level ``_*_async`` coroutine so the real
logic is directly awaitable from tests, matching the convention in
``src/ueba/tasks.py`` and ``src/integrations/tasks.py``.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import func, or_, select, update

from src.core.database import async_session_factory
from src.models.alert import Alert
from src.models.incident import Incident
from src.intel.models import ThreatIndicator as IOC
from src.services.automation import AutomationService

logger = logging.getLogger(__name__)


# --- Memory bounds ---------------------------------------------------------
# Rows pulled per round-trip. Small enough that one window of full ORM Alert
# objects is a few MB; large enough that a sweep still clears a big backlog.
BATCH_SIZE = 1_000

# Per-run ceilings. Hit means "the rest is deferred to the next run" (these
# sweeps run every 30-60 minutes), never "silently dropped" — every cap that
# fires is logged.
MAX_ESCALATE_PER_RUN = 20_000
MAX_CLOSE_PER_RUN = 50_000
MAX_IOC_SWEEP_ALERTS = 50_000
MAX_CORRELATION_ALERTS = 50_000

# Fields on Alert that carry an indicator value worth checking against the
# IOC table. Unchanged from the original sweep.
_IOC_ALERT_FIELDS = ("source_ip", "destination_ip", "domain", "url", "file_hash")


def _alert_indicators(alert: Any) -> list[str]:
    """Indicator values carried by one alert (same fields as before)."""
    return [
        v
        for v in (getattr(alert, field, None) for field in _IOC_ALERT_FIELDS)
        if v
    ]


# ---------------------------------------------------------------------------
# 1. Auto-escalate stale alerts
# ---------------------------------------------------------------------------
async def _auto_escalate_stale_alerts_async() -> dict[str, Any]:
    """Escalate alerts that have been sitting unassigned for too long.

    Finds alerts that are still ``new``/``open``, were created more than 2
    hours ago, and have no assignee. Moves them to ``investigating`` and, for
    high/critical severity, creates an incident via the automation pipeline.

    Processed in windows of ``BATCH_SIZE``: each escalated alert leaves the
    ``new``/``open`` filter, so re-querying with a LIMIT walks the backlog
    without holding it all in memory.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
    escalated = 0
    incidents_created = 0
    cap_hit = False

    async with async_session_factory() as db:
        automation = AutomationService(db)

        while escalated < MAX_ESCALATE_PER_RUN:
            window = min(BATCH_SIZE, MAX_ESCALATE_PER_RUN - escalated)
            result = await db.execute(
                select(Alert)
                .where(
                    Alert.status.in_(["new", "open"]),
                    Alert.created_at <= cutoff,
                    or_(Alert.assigned_to.is_(None), Alert.assigned_to == ""),
                )
                .order_by(Alert.created_at)
                .limit(window)
            )
            alerts = result.scalars().all()
            if not alerts:
                break

            for alert in alerts:
                alert.status = "investigating"
                escalated += 1

                if (alert.severity or "").lower() in ("high", "critical"):
                    try:
                        pipeline = await automation.on_alert_created(
                            alert,
                            organization_id=getattr(alert, "organization_id", None),
                            created_by="system:auto_escalate",
                        )
                        if pipeline.get("incident_created"):
                            incidents_created += 1
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "auto_escalate_stale_alerts: pipeline failed for alert %s: %s",
                            alert.id,
                            exc,
                        )

            # Commit + expunge per window so neither the pending-changes set
            # nor the identity map grows with the size of the backlog.
            await db.commit()
            db.expunge_all()

            # Compare against the window actually requested, not BATCH_SIZE:
            # on the last window before the per-run cap the LIMIT is smaller,
            # and a short read there means "backlog exhausted", not "capped".
            if len(alerts) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "auto_escalate_stale_alerts: hit per-run cap of %d alerts — "
            "remainder deferred to the next run",
            MAX_ESCALATE_PER_RUN,
        )

    logger.info(
        "auto_escalate_stale_alerts: escalated=%d incidents_created=%d",
        escalated,
        incidents_created,
    )
    return {
        "escalated": escalated,
        "incidents_created": incidents_created,
        "truncated": cap_hit,
        "cutoff": cutoff.isoformat(),
    }


@shared_task(name="automation.auto_escalate_stale_alerts")
def auto_escalate_stale_alerts():
    """Escalate alerts that have been sitting unassigned for too long."""
    return asyncio.run(_auto_escalate_stale_alerts_async())


# ---------------------------------------------------------------------------
# 2. Auto-close resolved alerts
# ---------------------------------------------------------------------------
async def _auto_close_resolved_alerts_async() -> dict[str, Any]:
    """Close alerts that have been in ``resolved`` status for 24h+.

    Pure status transition with no per-alert logic, so the rows never need to
    become ORM objects: ids are read in windows and flipped with a bulk
    UPDATE. Same rows, same resulting status, bounded memory.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_iso = cutoff.isoformat()
    closed = 0
    cap_hit = False

    async with async_session_factory() as db:
        while closed < MAX_CLOSE_PER_RUN:
            window = min(BATCH_SIZE, MAX_CLOSE_PER_RUN - closed)
            id_rows = await db.execute(
                select(Alert.id)
                .where(
                    Alert.status == "resolved",
                    or_(
                        Alert.resolved_at.is_(None),
                        Alert.resolved_at <= cutoff_iso,
                    ),
                    Alert.updated_at <= cutoff,
                )
                .order_by(Alert.id)
                .limit(window)
            )
            batch_ids = list(id_rows.scalars().all())
            if not batch_ids:
                break

            await db.execute(
                update(Alert)
                .where(Alert.id.in_(batch_ids))
                .values(status="closed")
            )
            await db.commit()
            closed += len(batch_ids)

            # See the note in _auto_escalate_stale_alerts_async: compare with
            # the window requested, which shrinks on the last pass.
            if len(batch_ids) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "auto_close_resolved_alerts: hit per-run cap of %d alerts — "
            "remainder deferred to the next run",
            MAX_CLOSE_PER_RUN,
        )

    logger.info("auto_close_resolved_alerts: closed=%d", closed)
    return {"closed": closed, "truncated": cap_hit, "cutoff": cutoff.isoformat()}


@shared_task(name="automation.auto_close_resolved_alerts")
def auto_close_resolved_alerts():
    """Close alerts that have been in ``resolved`` status for 24h+."""
    return asyncio.run(_auto_close_resolved_alerts_async())


# ---------------------------------------------------------------------------
# 3. Periodic IOC sweep
# ---------------------------------------------------------------------------
async def _periodic_ioc_sweep_async() -> dict[str, Any]:
    """Re-check recent alerts against the active IOC database.

    Runs over alerts from the last 24 hours whose description has not already
    been stamped with ``[AUTO] IOC Match``. Any match escalates the alert to
    critical via the automation pipeline.

    The IOC side is resolved per batch with an indexed
    ``value IN (<this batch's indicators>)`` lookup instead of loading the
    whole ``threat_indicators`` table. The membership test is identical (an
    active, non-whitelisted indicator whose ``value`` equals one of the
    alert's indicator fields) — it just runs in the database.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    checked = 0
    matched = 0
    escalated = 0
    cap_hit = False

    async with async_session_factory() as db:
        automation = AutomationService(db)
        last_id: str | None = None

        while checked < MAX_IOC_SWEEP_ALERTS:
            window = min(BATCH_SIZE, MAX_IOC_SWEEP_ALERTS - checked)
            stmt = (
                select(Alert)
                .where(
                    Alert.created_at >= since,
                    or_(
                        Alert.description.is_(None),
                        ~Alert.description.contains("[AUTO] IOC Match"),
                    ),
                )
                .order_by(Alert.id)
                .limit(window)
            )
            # Keyset pagination on the primary key: a plain OFFSET would skip
            # rows as the sweep rewrites descriptions underneath itself.
            if last_id is not None:
                stmt = stmt.where(Alert.id > last_id)

            alerts = (await db.execute(stmt)).scalars().all()
            if not alerts:
                break
            last_id = alerts[-1].id
            checked += len(alerts)
            batch_len = len(alerts)

            batch_indicators = {
                value for alert in alerts for value in _alert_indicators(alert)
            }
            ioc_values: set[str] = set()
            if batch_indicators:
                ioc_rows = await db.execute(
                    select(IOC.value).where(
                        IOC.value.in_(batch_indicators),
                        IOC.is_active == True,  # noqa: E712
                        IOC.is_whitelisted == False,  # noqa: E712
                    )
                )
                ioc_values = {v for v in ioc_rows.scalars().all() if v}

            if ioc_values:
                for alert in alerts:
                    if not any(
                        ind in ioc_values for ind in _alert_indicators(alert)
                    ):
                        continue

                    matched += 1
                    try:
                        pipeline = await automation.on_alert_created(
                            alert,
                            organization_id=getattr(alert, "organization_id", None),
                            created_by="system:ioc_sweep",
                        )
                        if pipeline.get("ioc_matches") or pipeline.get(
                            "incident_created"
                        ):
                            escalated += 1
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "periodic_ioc_sweep: pipeline failed for alert %s: %s",
                            alert.id,
                            exc,
                        )

            await db.commit()
            db.expunge_all()
            del alerts

            # See the note in _auto_escalate_stale_alerts_async.
            if batch_len < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "periodic_ioc_sweep: hit per-run cap of %d alerts — remainder "
            "deferred to the next run",
            MAX_IOC_SWEEP_ALERTS,
        )

    logger.info(
        "periodic_ioc_sweep: checked=%d matched=%d escalated=%d",
        checked,
        matched,
        escalated,
    )
    return {
        "checked": checked,
        "matched": matched,
        "escalated": escalated,
        "truncated": cap_hit,
    }


@shared_task(name="automation.periodic_ioc_sweep")
def periodic_ioc_sweep():
    """Re-check recent alerts against the active IOC database."""
    return asyncio.run(_periodic_ioc_sweep_async())


# ---------------------------------------------------------------------------
# 4. Daily threat briefing
# ---------------------------------------------------------------------------
async def _daily_threat_briefing_async() -> dict[str, Any]:
    """Generate a daily threat briefing with alert/incident stats.

    Already aggregate-only (``COUNT`` / ``GROUP BY`` with a LIMIT 10 on the
    source breakdown) — no row ever reaches Python, so there is nothing to
    bound here.
    """
    async with async_session_factory() as db:
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=24)

        # Alert totals
        total_alerts_row = await db.execute(
            select(func.count(Alert.id)).where(Alert.created_at >= since)
        )
        total_alerts = total_alerts_row.scalar() or 0

        severity_rows = await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.created_at >= since)
            .group_by(Alert.severity)
        )
        by_severity = {sev or "unknown": int(cnt) for sev, cnt in severity_rows.all()}

        source_rows = await db.execute(
            select(Alert.source, func.count(Alert.id))
            .where(Alert.created_at >= since)
            .group_by(Alert.source)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )
        top_sources = [
            {"source": src or "unknown", "count": int(cnt)}
            for src, cnt in source_rows.all()
        ]

        open_alerts_row = await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_(["new", "open", "investigating"])
            )
        )
        open_alerts = open_alerts_row.scalar() or 0

        # Incidents
        total_incidents_row = await db.execute(
            select(func.count(Incident.id)).where(Incident.created_at >= since)
        )
        total_incidents = total_incidents_row.scalar() or 0

        open_incidents_row = await db.execute(
            select(func.count(Incident.id)).where(
                Incident.status.in_(["open", "investigating", "contained"])
            )
        )
        open_incidents = open_incidents_row.scalar() or 0

        briefing = {
            "generated_at": now.isoformat(),
            "window_hours": 24,
            "alerts": {
                "total_24h": int(total_alerts),
                "by_severity": by_severity,
                "top_sources": top_sources,
                "open_total": int(open_alerts),
            },
            "incidents": {
                "total_24h": int(total_incidents),
                "open_total": int(open_incidents),
            },
        }

        logger.info("daily_threat_briefing: %s", briefing)
        return briefing


@shared_task(name="automation.daily_threat_briefing")
def daily_threat_briefing():
    """Generate a daily threat briefing with alert/incident stats."""
    return asyncio.run(_daily_threat_briefing_async())


# ---------------------------------------------------------------------------
# 5. Hourly correlation sweep
# ---------------------------------------------------------------------------
async def _hourly_correlation_sweep_async() -> dict[str, Any]:
    """Group unlinked alerts sharing a source IP or category and correlate.

    Looks at alerts from the last 2 hours that are not yet tied to an
    incident, clusters them by ``(source_ip, category)`` and, for any cluster
    of 3+ alerts, drives the automation pipeline on the first alert to
    materialize an incident and link the cluster to it.

    Clustering genuinely needs the whole window at once, so the bound here is
    (a) only the four columns clustering uses are read — not full ORM Alert
    objects with their ``raw_data``/``description`` blobs — and (b) a hard
    per-run row cap. The anchor row is loaded as an ORM object one at a time,
    and the rest of a cluster is linked with a bulk UPDATE.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=2)
    clusters: dict[tuple, list[str]] = defaultdict(list)
    scanned = 0

    async with async_session_factory() as db:
        stmt = (
            select(Alert.id, Alert.source_ip, Alert.category)
            .where(
                Alert.created_at >= since,
                Alert.incident_id.is_(None),
                Alert.status.in_(["new", "open", "investigating"]),
            )
            .order_by(Alert.created_at)
            .limit(MAX_CORRELATION_ALERTS)
            .execution_options(yield_per=BATCH_SIZE)
        )
        result = await db.stream(stmt)
        async for chunk in result.partitions(BATCH_SIZE):
            for alert_id, src_ip, category in chunk:
                scanned += 1
                if not src_ip and not category:
                    continue
                clusters[(src_ip or "-", category or "-")].append(alert_id)

        cap_hit = scanned >= MAX_CORRELATION_ALERTS
        if cap_hit:
            logger.warning(
                "hourly_correlation_sweep: hit per-run cap of %d alerts — "
                "remainder deferred to the next run",
                MAX_CORRELATION_ALERTS,
            )

        automation = AutomationService(db)
        incidents_created = 0
        alerts_linked = 0
        clusters_examined = 0

        for key, cluster_ids in clusters.items():
            if len(cluster_ids) < 3:
                continue
            clusters_examined += 1

            anchor = (
                await db.execute(select(Alert).where(Alert.id == cluster_ids[0]))
            ).scalar_one_or_none()
            if anchor is None:
                continue

            # Bump severity so _auto_create_incident will trigger.
            if (anchor.severity or "").lower() not in ("critical", "high"):
                anchor.severity = "high"
            await db.flush()

            try:
                pipeline = await automation.on_alert_created(
                    anchor,
                    organization_id=getattr(anchor, "organization_id", None),
                    created_by="system:correlation_sweep",
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "hourly_correlation_sweep: pipeline failed for cluster %s: %s",
                    key,
                    exc,
                )
                continue

            incident_id = pipeline.get("incident_created")
            if not incident_id:
                continue
            incidents_created += 1

            rest = cluster_ids[1:]
            for offset in range(0, len(rest), BATCH_SIZE):
                batch = rest[offset : offset + BATCH_SIZE]
                await db.execute(
                    update(Alert)
                    .where(Alert.id.in_(batch))
                    .values(incident_id=incident_id)
                )
                alerts_linked += len(batch)

            await db.commit()
            db.expunge_all()

        await db.commit()

    logger.info(
        "hourly_correlation_sweep: clusters=%d incidents=%d linked=%d",
        clusters_examined,
        incidents_created,
        alerts_linked,
    )
    return {
        "clusters_correlated": clusters_examined,
        "incidents_created": incidents_created,
        "alerts_linked": alerts_linked,
        "alerts_scanned": scanned,
        "truncated": cap_hit,
    }


@shared_task(name="automation.hourly_correlation_sweep")
def hourly_correlation_sweep():
    """Group unlinked alerts sharing a source IP or category and correlate."""
    return asyncio.run(_hourly_correlation_sweep_async())
