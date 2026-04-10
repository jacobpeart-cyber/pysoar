"""
Periodic scheduled automation Celery tasks for PySOAR.

These tasks run on Celery Beat schedules to continuously monitor the platform
and drive cross-module automation through the AutomationService. They cover:

  * Auto-escalation of stale alerts
  * Auto-closing of long-resolved alerts
  * Periodic IOC sweeps against recent alerts
  * Daily threat briefings
  * Hourly correlation sweeps that cluster related alerts into incidents
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from celery import shared_task
from sqlalchemy import and_, func, or_, select

from src.core.database import async_session_factory
from src.models.alert import Alert
from src.models.incident import Incident
from src.models.ioc import IOC
from src.services.automation import AutomationService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Auto-escalate stale alerts
# ---------------------------------------------------------------------------
@shared_task(name="automation.auto_escalate_stale_alerts")
def auto_escalate_stale_alerts():
    """Escalate alerts that have been sitting unassigned for too long.

    Every 30 minutes, find alerts that are still ``new``/``open``, were
    created more than 2 hours ago, and have no assignee. Move them to
    ``investigating`` and, for high/critical severity, create an incident
    via the automation pipeline.
    """

    async def _run():
        async with async_session_factory() as db:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
            result = await db.execute(
                select(Alert).where(
                    Alert.status.in_(["new", "open"]),
                    Alert.created_at <= cutoff,
                    or_(Alert.assigned_to.is_(None), Alert.assigned_to == ""),
                )
            )
            alerts = result.scalars().all()

            automation = AutomationService(db)
            escalated = 0
            incidents_created = 0

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

            await db.commit()
            logger.info(
                "auto_escalate_stale_alerts: escalated=%d incidents_created=%d",
                escalated,
                incidents_created,
            )
            return {
                "escalated": escalated,
                "incidents_created": incidents_created,
                "cutoff": cutoff.isoformat(),
            }

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. Auto-close resolved alerts
# ---------------------------------------------------------------------------
@shared_task(name="automation.auto_close_resolved_alerts")
def auto_close_resolved_alerts():
    """Close alerts that have been in ``resolved`` status for 24h+."""

    async def _run():
        async with async_session_factory() as db:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            cutoff_iso = cutoff.isoformat()

            result = await db.execute(
                select(Alert).where(
                    Alert.status == "resolved",
                    or_(
                        Alert.resolved_at.is_(None),
                        Alert.resolved_at <= cutoff_iso,
                    ),
                    Alert.updated_at <= cutoff,
                )
            )
            alerts = result.scalars().all()

            closed = 0
            for alert in alerts:
                alert.status = "closed"
                closed += 1

            await db.commit()
            logger.info("auto_close_resolved_alerts: closed=%d", closed)
            return {"closed": closed, "cutoff": cutoff.isoformat()}

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. Periodic IOC sweep
# ---------------------------------------------------------------------------
@shared_task(name="automation.periodic_ioc_sweep")
def periodic_ioc_sweep():
    """Re-check recent alerts against the active IOC database.

    Runs every 15 minutes over alerts from the last 24 hours whose
    description has not already been stamped with ``[AUTO] IOC Match``.
    Any match escalates the alert to critical via the automation pipeline.
    """

    async def _run():
        async with async_session_factory() as db:
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            result = await db.execute(
                select(Alert).where(
                    Alert.created_at >= since,
                    or_(
                        Alert.description.is_(None),
                        ~Alert.description.contains("[AUTO] IOC Match"),
                    ),
                )
            )
            alerts = result.scalars().all()

            # Load active IOC values once
            ioc_result = await db.execute(
                select(IOC).where(IOC.status == "active")
            )
            iocs = ioc_result.scalars().all()
            ioc_values = {ioc.value for ioc in iocs if ioc.value}

            if not ioc_values:
                logger.info("periodic_ioc_sweep: no active IOCs loaded")
                return {"checked": len(alerts), "matched": 0, "escalated": 0}

            automation = AutomationService(db)
            matched = 0
            escalated = 0

            for alert in alerts:
                indicators = [
                    v
                    for v in (
                        getattr(alert, "source_ip", None),
                        getattr(alert, "destination_ip", None),
                        getattr(alert, "domain", None),
                        getattr(alert, "url", None),
                        getattr(alert, "file_hash", None),
                    )
                    if v
                ]
                if not any(ind in ioc_values for ind in indicators):
                    continue

                matched += 1
                try:
                    pipeline = await automation.on_alert_created(
                        alert,
                        organization_id=getattr(alert, "organization_id", None),
                        created_by="system:ioc_sweep",
                    )
                    if pipeline.get("ioc_matches") or pipeline.get("incident_created"):
                        escalated += 1
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "periodic_ioc_sweep: pipeline failed for alert %s: %s",
                        alert.id,
                        exc,
                    )

            await db.commit()
            logger.info(
                "periodic_ioc_sweep: checked=%d matched=%d escalated=%d",
                len(alerts),
                matched,
                escalated,
            )
            return {
                "checked": len(alerts),
                "matched": matched,
                "escalated": escalated,
            }

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Daily threat briefing
# ---------------------------------------------------------------------------
@shared_task(name="automation.daily_threat_briefing")
def daily_threat_briefing():
    """Generate a daily threat briefing with alert/incident stats.

    Intended to run every 24h at 08:00 UTC. Computes rolling 24h metrics
    across severities, sources, and incident counts, then logs a
    structured briefing for downstream shipping (SIEM, SOC feed, etc.).
    """

    async def _run():
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

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Hourly correlation sweep
# ---------------------------------------------------------------------------
@shared_task(name="automation.hourly_correlation_sweep")
def hourly_correlation_sweep():
    """Group unlinked alerts sharing a source IP or category and correlate.

    Every hour, look at alerts from the last 2 hours that are not yet tied
    to an incident. Cluster them by ``(source_ip, category)`` and, for any
    cluster of 3+ alerts, drive the automation pipeline on the first alert
    to materialize an incident and link the cluster to it.
    """

    async def _run():
        async with async_session_factory() as db:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            result = await db.execute(
                select(Alert).where(
                    Alert.created_at >= since,
                    Alert.incident_id.is_(None),
                    Alert.status.in_(["new", "open", "investigating"]),
                )
            )
            alerts = result.scalars().all()

            clusters: dict[tuple, list[Alert]] = defaultdict(list)
            for alert in alerts:
                src_ip = getattr(alert, "source_ip", None)
                category = getattr(alert, "category", None)
                if not src_ip and not category:
                    continue
                clusters[(src_ip or "-", category or "-")].append(alert)

            automation = AutomationService(db)
            incidents_created = 0
            alerts_linked = 0
            clusters_examined = 0

            for key, cluster in clusters.items():
                if len(cluster) < 3:
                    continue
                clusters_examined += 1

                anchor = cluster[0]
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

                for other in cluster[1:]:
                    if hasattr(other, "incident_id"):
                        other.incident_id = incident_id
                        alerts_linked += 1

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
            }

    return asyncio.run(_run())
