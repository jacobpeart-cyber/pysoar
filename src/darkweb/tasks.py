"""Celery Tasks for Dark Web Monitoring

Scheduled and background tasks for dark web monitor scans (each monitor's own
terms, see src/darkweb/monitor_scan.py), credential leak checks and threat
intelligence correlation. Brand monitoring and takedown-status tasks were
removed in wave 3: their output was discarded and no takedown provider exists.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import func, select

from src.core.config import settings
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.darkweb.engine import (
    CredentialAnalyzer,
    ThreatIntelCorrelator,
)
from src.darkweb.models import (
    DarkWebFinding,
    DarkWebMonitor,
)
from src.darkweb.monitor_scan import parse_term_list
from src.intel.models import ThreatIndicator as IOC
from src.models.incident import Incident

logger = get_logger(__name__)


# --- Memory bounds ---------------------------------------------------------
# darkweb_cross_org_sweep loaded every Organization and then every enabled
# monitor per org as full ORM rows; credential_leak_check loaded every
# monitor of the org as ORM rows; threat_correlation loaded every IOC the org
# saw in 90 days and every incident created in 90 days (all tenants) as ORM
# rows, just to compare one or two strings against them. All of these now
# page in keyset windows of DARKWEB_BATCH_SIZE on the primary key and read
# only the columns they use; caps that fire set ``truncated``.
DARKWEB_BATCH_SIZE = 1_000
MAX_DARKWEB_MONITORS_PER_SWEEP = 5_000
MAX_MONITORS_PER_CREDENTIAL_CHECK = 10_000
MAX_CORRELATION_IOC_MATCHES = 10_000
MAX_CORRELATION_INCIDENTS = 50_000


def _fresh_darkweb_session_factory():
    """Per-task NullPool engine to avoid 'Future attached to a different loop'
    errors under Celery prefork — same pattern as itdr/agentic/supplychain."""
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import NullPool
    e = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    return e, sessionmaker(e, class_=AsyncSession, expire_on_commit=False)


@shared_task(bind=True, max_retries=3)
def scheduled_dark_web_scan(
    self,
    monitor_id: str,
    scan_type: str = "full",
) -> dict[str, Any]:
    """Scan one dark-web monitor against its own terms.

    Delegates to ``src.darkweb.monitor_scan.scan_monitor`` (the same code the
    trigger-scan route runs): HIBP lookups for the watched emails and
    domains, plus threat-feed items that mention the monitor's terms. New
    findings are committed (dedup by content hash inside the organisation),
    ``last_check`` / ``findings_count`` are updated, and
    ``AutomationService.on_darkweb_finding`` fires for critical findings.
    The result carries every source's status; a scan in which every usable
    source failed reports ``status="failed"`` and is not retried (the next
    sweep tries again).

    Args:
        monitor_id: the monitor to scan (findings belong to its organisation).
        scan_type: "full" for every source, "quick" for the HIBP sources only.
    """
    from src.darkweb.monitor_scan import scan_monitor

    async def _run() -> dict[str, Any]:
        engine, factory = _fresh_darkweb_session_factory()
        try:
            async with factory() as db:
                monitor = (await db.execute(
                    select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id),
                )).scalar_one_or_none()
                if monitor is None:
                    return {"status": "error", "error": f"monitor {monitor_id} not found"}
                org_id = monitor.organization_id

                outcome = await scan_monitor(db, monitor, scan_type=scan_type)
                await db.commit()

                automation_fired = 0
                automation_errors: list[str] = []
                if outcome.criticals:
                    from src.services.automation import AutomationService
                    svc = AutomationService(db)
                    for c in outcome.criticals:
                        try:
                            await svc.on_darkweb_finding(
                                finding_type=c["finding_type"],
                                description=c["description"],
                                source_url=c["source_url"],
                                severity=c["severity"],
                                organization_id=org_id,
                            )
                            automation_fired += 1
                        except Exception as exc:  # noqa: BLE001 - one rule must not undo the scan
                            automation_errors.append(f"{c['finding_id']}: {exc}"[:300])
                            logger.warning(f"on_darkweb_finding fire failed: {exc}")
                    # on_darkweb_finding only flushes; commit the alerts.
                    if automation_fired:
                        await db.commit()

                return {
                    "monitor_id": monitor_id,
                    "organization_id": org_id,
                    "status": outcome.status,
                    "detail": outcome.detail,
                    "terms_searched": outcome.terms_searched,
                    "sources": outcome.sources,
                    "matched": outcome.matched,
                    "created": outcome.created,
                    "credential_leaks_created": outcome.credential_leaks_created,
                    "skipped_duplicate": outcome.skipped_duplicate,
                    "critical_fired": automation_fired,
                    "automation_errors": automation_errors,
                    "timestamp": outcome.finished_at,
                }
        finally:
            await engine.dispose()

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as exc:
        logger.error(f"Dark web scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


async def _enabled_monitor_window(
    factory: Any, after_id: str | None, limit: int,
) -> list[tuple[str, str]]:
    """One keyset window of (monitor id, org id) for enabled monitors whose
    organization exists (the old per-org loop only visited those)."""
    from src.models.organization import Organization

    async with factory() as db:
        stmt = select(DarkWebMonitor.id, DarkWebMonitor.organization_id).where(
            DarkWebMonitor.enabled == True,  # noqa: E712
            DarkWebMonitor.organization_id.in_(select(Organization.id)),
        )
        if after_id is not None:
            stmt = stmt.where(DarkWebMonitor.id > after_id)
        rows = (await db.execute(stmt.order_by(DarkWebMonitor.id).limit(limit))).all()
    return [(r.id, r.organization_id) for r in rows]


def _scan_monitor(monitor_id: str) -> Any:
    """Run the per-monitor scan in-process (sync Celery ``.apply()`` so the
    sweep can collect totals)."""
    return scheduled_dark_web_scan.apply(
        kwargs={"monitor_id": monitor_id, "scan_type": "full"},
    ).get()


def _run_darkweb_cross_org_sweep() -> dict[str, Any]:
    """Synchronous driver for ``darkweb_cross_org_sweep``.

    Monitor ids are fetched one window at a time on this function's own
    event loop, and each per-monitor scan runs *between* those fetches, never
    inside a running loop. (The previous version called
    ``scheduled_dark_web_scan.apply(...)`` from inside its coroutine; that
    task starts its own event loop, which raises "Cannot run the event loop
    while another loop is running", so the sweep failed at the first
    enabled monitor.)
    """
    totals: dict[str, Any] = {
        "orgs_scanned": 0, "monitors_scanned": 0, "monitors_failed": 0, "findings_created": 0,
    }
    orgs_seen: set[str] = set()
    cap_hit = False
    last_id: str | None = None

    engine, factory = _fresh_darkweb_session_factory()
    loop = asyncio.new_event_loop()
    try:
        while totals["monitors_scanned"] < MAX_DARKWEB_MONITORS_PER_SWEEP:
            window = min(
                DARKWEB_BATCH_SIZE,
                MAX_DARKWEB_MONITORS_PER_SWEEP - totals["monitors_scanned"],
            )
            monitors = loop.run_until_complete(
                _enabled_monitor_window(factory, last_id, window),
            )
            if not monitors:
                break
            last_id = monitors[-1][0]

            for monitor_id, org_id in monitors:
                orgs_seen.add(org_id)
                totals["monitors_scanned"] += 1
                res = _scan_monitor(monitor_id)
                if isinstance(res, dict):
                    totals["findings_created"] += int(res.get("created") or 0)
                    if res.get("status") in ("failed", "error"):
                        totals["monitors_failed"] += 1

            if len(monitors) < window:
                break
        else:
            cap_hit = True
    finally:
        try:
            loop.run_until_complete(engine.dispose())
        finally:
            loop.close()

    totals["orgs_scanned"] = len(orgs_seen)
    totals["truncated"] = cap_hit
    if cap_hit:
        logger.warning(
            f"darkweb_cross_org_sweep: hit per-run cap of {MAX_DARKWEB_MONITORS_PER_SWEEP} "
            f"monitors; remainder deferred to the next run",
        )
    logger.info(f"darkweb_cross_org_sweep: {totals}")
    return totals


@shared_task(bind=True, max_retries=1)
def darkweb_cross_org_sweep(self) -> dict[str, Any]:
    """Periodic cross-org dark-web sweep.

    Iterates every Organization with at least one enabled DarkWebMonitor
    and runs ``scheduled_dark_web_scan`` against each monitor. Gives us
    a single beat-schedule entry that fans out properly instead of
    requiring one beat entry per monitor.
    """
    try:
        return _run_darkweb_cross_org_sweep()
    except Exception as exc:
        logger.warning(f"darkweb_cross_org_sweep failed: {exc}")
        return {"error": str(exc)[:200]}


async def _credential_context_async(finding_id: str) -> dict[str, Any]:
    """The finding's text plus its org's watched domains/emails.

    Monitors are read as two JSON columns per keyset window instead of full
    ORM rows.
    """
    async with async_session_factory() as session:
        # Load the specific finding
        finding_stmt = select(DarkWebFinding).where(
            DarkWebFinding.id == finding_id,
        )
        finding = (await session.scalars(finding_stmt)).first()

        raw_text = ""
        org_id: str | None = None
        monitor_id: str | None = None
        if finding is not None:
            org_id = finding.organization_id
            monitor_id = finding.monitor_id
            # DarkWebFinding stores a raw_data_hash, not raw text; use the
            # finding description and any analyst notes as the credential
            # text source. (Full raw payloads live in object storage
            # which is not yet wired up to the DB layer.)
            raw_text = "\n".join(
                part
                for part in (finding.description, finding.analyst_notes)
                if part
            )

        monitored_domains: set[str] = set()
        monitored_emails: set[str] = set()
        monitors_read = 0
        cap_hit = False
        if org_id:
            last_id: str | None = None
            while monitors_read < MAX_MONITORS_PER_CREDENTIAL_CHECK:
                window = min(
                    DARKWEB_BATCH_SIZE, MAX_MONITORS_PER_CREDENTIAL_CHECK - monitors_read,
                )
                mon_stmt = select(
                    DarkWebMonitor.id,
                    DarkWebMonitor.domains_watched,
                    DarkWebMonitor.emails_watched,
                ).where(DarkWebMonitor.organization_id == org_id)
                if last_id is not None:
                    mon_stmt = mon_stmt.where(DarkWebMonitor.id > last_id)
                monitors = (
                    await session.execute(mon_stmt.order_by(DarkWebMonitor.id).limit(window))
                ).all()
                if not monitors:
                    break
                last_id = monitors[-1].id
                monitors_read += len(monitors)
                for m in monitors:
                    # Older rows hold a JSON-encoded string, not a list;
                    # set.update() on that string added single characters.
                    monitored_domains.update(parse_term_list(m.domains_watched))
                    monitored_emails.update(parse_term_list(m.emails_watched))
                if len(monitors) < window:
                    break
            else:
                cap_hit = True

        if cap_hit:
            logger.warning(
                f"credential_leak_check: monitor cap {MAX_MONITORS_PER_CREDENTIAL_CHECK} "
                f"hit for org {org_id}; watched assets beyond it not considered",
            )
        return {
            "raw_text": raw_text,
            "monitored_domains": sorted(monitored_domains),
            "monitored_emails": sorted(monitored_emails),
            "organization_id": org_id,
            "monitor_id": monitor_id,
            "finding_found": finding is not None,
            "truncated": cap_hit,
        }


@shared_task(bind=True, max_retries=3)
def credential_leak_check(
    self,
    finding_id: str,
    extract_credentials: bool = True,
) -> dict[str, Any]:
    """
    Check credential leak for organizational exposure.

    Extracts credentials from leaked data, analyzes hash types,
    and correlates with organizational user database.

    Args:
        finding_id: ID of the dark web finding to analyze
        extract_credentials: Whether to extract and parse credentials

    Returns:
        Dictionary with credential analysis results
    """
    try:
        logger.info(
            f"Analyzing credential leak (finding={finding_id}, "
            f"extract={extract_credentials})",
        )

        analyzer = CredentialAnalyzer()

        ctx = asyncio.run(_credential_context_async(finding_id))

        if not ctx["finding_found"]:
            logger.warning(f"Credential leak check: finding {finding_id} not found")
            return {
                "finding_id": finding_id,
                "credentials_extracted": 0,
                "organizational_credentials": 0,
                "analyzed_credentials": [],
                "organizational_matches": [],
                "truncated": False,
                "status": "finding_not_found",
            }

        # Parse credentials from the finding's actual content
        credentials = (
            analyzer.parse_credential_dumps(ctx["raw_text"])
            if extract_credentials and ctx["raw_text"]
            else []
        )
        logger.info(f"Extracted {len(credentials)} credentials")

        # Assess password risk for each credential
        analyzed_creds = []
        for cred in credentials:
            password_hash = cred.get("password", "")
            risk_assessment = analyzer.assess_password_risk(password_hash)

            analyzed_creds.append(
                {
                    "credential": cred,
                    "risk_assessment": risk_assessment,
                },
            )

        # Identify organizational credentials against this org's monitored assets
        organizational_creds = analyzer.identify_organizational_credentials(
            credentials,
            monitored_domains=ctx["monitored_domains"],
            monitored_emails=ctx["monitored_emails"],
        )

        logger.info(f"Found {len(organizational_creds)} organizational credentials")

        return {
            "finding_id": finding_id,
            "credentials_extracted": len(credentials),
            "organizational_credentials": len(organizational_creds),
            "analyzed_credentials": analyzed_creds,
            "organizational_matches": organizational_creds,
            "truncated": ctx["truncated"],
            "status": "completed",
        }

    except Exception as exc:
        logger.error(f"Credential leak check failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


async def _threat_correlation_async(
    finding_id: str, organization_id: str, correlator: ThreatIntelCorrelator,
) -> dict[str, Any]:
    """Correlate one finding with the org's recent IOCs and incidents.

    ``correlate_with_iocs`` only ever matches an IOC whose value equals the
    finding's domain or email, so instead of loading every 90-day IOC the
    candidates are fetched with ``value IN (domain, email)`` and the 90-day
    total comes from a COUNT. ``correlate_with_incidents`` only matches
    incidents whose indicator list contains the finding's domain, so
    incidents are scanned in keyset windows of five columns and only the
    matches are kept.
    """
    import json as _json

    async with async_session_factory() as session:
        # Load finding
        finding = (
            await session.scalars(
                select(DarkWebFinding).where(DarkWebFinding.id == finding_id),
            )
        ).first()
        if finding is None:
            return {"finding_found": False}

        affected = finding.affected_assets or {}
        if isinstance(affected, str):
            try:
                affected = _json.loads(affected)
            except Exception:
                affected = {}

        finding_data = {
            "id": finding.id,
            "domain": affected.get("domain") if isinstance(affected, dict) else None,
            "ip": affected.get("ip") if isinstance(affected, dict) else None,
            "email": affected.get("email") if isinstance(affected, dict) else None,
            "hash": finding.raw_data_hash,
            "severity": finding.severity,
            "confidence_score": finding.confidence_score,
            "finding_type": finding.finding_type,
            "source_platform": finding.source_platform,
            "title": finding.title,
            "description": finding.description,
        }

        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        truncated = False

        # --- IOCs (last 90 days) for this org ---
        ioc_scope = (
            (IOC.organization_id == organization_id) & (IOC.created_at >= cutoff)
        )
        ioc_count = (
            await session.execute(select(func.count(IOC.id)).where(ioc_scope))
        ).scalar_one()
        match_values = sorted(
            {v for v in (finding_data["domain"], finding_data["email"]) if v},
        )
        ioc_correlations: list[dict[str, Any]] = []
        if match_values:
            ioc_rows = (
                await session.execute(
                    select(
                        IOC.id,
                        IOC.value,
                        IOC.indicator_type,
                        IOC.source,
                        IOC.severity,
                        IOC.confidence,
                    )
                    .where(ioc_scope, IOC.value.in_(match_values))
                    .order_by(IOC.id)
                    .limit(MAX_CORRELATION_IOC_MATCHES + 1),
                )
            ).all()
            if len(ioc_rows) > MAX_CORRELATION_IOC_MATCHES:
                truncated = True
                ioc_rows = ioc_rows[:MAX_CORRELATION_IOC_MATCHES]
            ioc_correlations = await correlator.correlate_with_iocs(
                finding_data,
                [
                    {
                        "id": i.id,
                        "value": i.value,
                        "type": i.indicator_type,
                        "source": i.source,
                        "threat_level": i.severity,
                        "confidence": i.confidence,
                    }
                    for i in ioc_rows
                ],
            )

        # --- Incidents (last 90 days) for this org ---
        # The previous query had no organization filter and correlated the
        # finding with every tenant's incidents; scoped to the org now.
        inc_scope = (Incident.created_at >= cutoff) & (
            Incident.organization_id == organization_id
        )
        incident_count = (
            await session.execute(select(func.count(Incident.id)).where(inc_scope))
        ).scalar_one()
        incident_correlations: list[dict[str, Any]] = []
        if finding_data["domain"] is not None and incident_count:
            scanned = 0
            last_id: str | None = None
            while scanned < MAX_CORRELATION_INCIDENTS:
                window = min(DARKWEB_BATCH_SIZE, MAX_CORRELATION_INCIDENTS - scanned)
                stmt = select(
                    Incident.id,
                    Incident.title,
                    Incident.status,
                    Incident.severity,
                    Incident.indicators,
                ).where(inc_scope)
                if last_id is not None:
                    stmt = stmt.where(Incident.id > last_id)
                rows = (await session.execute(stmt.order_by(Incident.id).limit(window))).all()
                if not rows:
                    break
                last_id = rows[-1].id
                scanned += len(rows)

                incident_window = []
                for inc in rows:
                    iocs_list: list[str] = []
                    if inc.indicators:
                        try:
                            parsed = _json.loads(inc.indicators)
                            if isinstance(parsed, list):
                                iocs_list = [str(x) for x in parsed]
                        except Exception:
                            pass
                    incident_window.append(
                        {
                            "id": inc.id,
                            "title": inc.title,
                            "status": inc.status,
                            "severity": inc.severity,
                            "iocs": iocs_list,
                        },
                    )
                incident_correlations.extend(
                    await correlator.correlate_with_incidents(finding_data, incident_window),
                )
                if len(rows) < window:
                    break
            else:
                truncated = True

        score = await correlator.calculate_risk_score(finding_data)

        if truncated:
            logger.warning(
                f"threat_correlation finding={finding_id}: correlation cap hit; "
                f"partial matches returned",
            )
        return {
            "finding_found": True,
            "finding_data": finding_data,
            "ioc_correlations": ioc_correlations,
            "incident_correlations": incident_correlations,
            "risk_score": score,
            "ioc_count": ioc_count,
            "incident_count": incident_count,
            "truncated": truncated,
        }


@shared_task(bind=True, max_retries=3)
def threat_correlation(
    self,
    finding_id: str,
    organization_id: str,
) -> dict[str, Any]:
    """
    Correlate dark web finding with threat intelligence and incidents.

    Matches findings against IOC databases, active incidents,
    and historical threat intelligence.

    Args:
        finding_id: ID of the dark web finding
        organization_id: ID of the organization

    Returns:
        Dictionary with correlation results
    """
    try:
        logger.info(
            f"Correlating dark web finding (finding={finding_id}, "
            f"org={organization_id})",
        )

        correlator = ThreatIntelCorrelator()

        result = asyncio.run(
            _threat_correlation_async(finding_id, organization_id, correlator),
        )

        if not result.get("finding_found"):
            logger.warning(f"Threat correlation: finding {finding_id} not found")
            return {
                "finding_id": finding_id,
                "ioc_matches": 0,
                "incident_matches": 0,
                "risk_score": 0,
                "ioc_correlations": [],
                "incident_correlations": [],
                "truncated": False,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "finding_not_found",
            }

        ioc_correlations = result["ioc_correlations"]
        incident_correlations = result["incident_correlations"]
        risk_score = result["risk_score"]

        logger.info(
            f"Finding {finding_id} correlated: "
            f"{len(ioc_correlations)} IOC matches, "
            f"risk_score={risk_score}",
        )

        return {
            "finding_id": finding_id,
            "ioc_matches": len(ioc_correlations),
            "incident_matches": len(incident_correlations),
            "risk_score": risk_score,
            "ioc_correlations": ioc_correlations,
            "incident_correlations": incident_correlations,
            "truncated": result["truncated"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
        }

    except Exception as exc:
        logger.error(f"Threat correlation failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
