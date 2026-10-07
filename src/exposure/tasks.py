"""
Celery tasks for Continuous Threat Exposure Management (CTEM)

Asynchronous background tasks for asset discovery, vulnerability scanning,
risk calculation, and exposure reporting.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from celery import shared_task
from sqlalchemy import select, update

from src.core.database import async_session_factory
from src.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Memory bounds (prod OOM post-mortem 2026-09-01)
# --------------------------------------------------------------------------
# `log_entries` holds millions of rows on a month-old deployment. The SIEM
# asset-discovery sweep used to run
#   SELECT DISTINCT source_address, source_ip, hostname FROM log_entries ...
# and materialise the whole result with `.all()`, then `session.add()` one
# ExposureAsset per unseen IP with a single commit at the end. That is an
# O(rows-in-24h) Python working set inside one task — the signature the
# kernel OOM-killed (a per-child RSS cap only recycles a child *between*
# tasks, never inside one).
#
# Everything below reads in fixed-size windows and commits per window, so
# peak RSS is O(DISCOVERY_BATCH_SIZE) instead of O(table).
DISCOVERY_BATCH_SIZE = 1_000

# Hard per-run ceiling on scanned log rows. Generous enough that a normal
# 24 h window is never truncated; when it *is* hit the task logs it loudly
# rather than silently doing partial work. The next run picks up whatever is
# still within its own 24 h window.
MAX_DISCOVERY_LOG_ROWS = 500_000

# Hard per-run ceiling on newly created assets. A runaway log source (one
# log line per ephemeral container IP, say) must not turn into a million
# ExposureAsset inserts in a single transaction.
MAX_ASSETS_PER_RUN = 50_000

# Attack-surface snapshots store every asset key / open-vuln key in a JSON
# column. Past this many keys the snapshot is recorded as truncated instead
# of serialising an unbounded list into one row (and reading it back the
# next day).
MAX_SNAPSHOT_KEYS = 100_000


def _run_async(coro):
    """Execute an async coroutine from a synchronous Celery task."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # Fallback when an event loop already exists in the worker context.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Async implementations (module-level so they are directly testable)
# ---------------------------------------------------------------------------

async def _run_asset_discovery_async(
    organization_id: str, discovery_type: str = "siem",
) -> dict[str, Any]:
    """Discover assets from observed SIEM log traffic (or honestly decline
    network discovery, which needs an unconfigured active scanner)."""
    now = datetime.now(timezone.utc)

    if discovery_type == "network":
        # A real network sweep needs an active scanner (nmap/naabu) with
        # network reachability, which is not integrated. Report that
        # honestly rather than pretend to have scanned.
        return {
            "organization_id": organization_id,
            "discovery_type": "network",
            "status": "requires_scanner",
            "assets_discovered": 0,
            "detail": (
                "Active network discovery requires an integrated network "
                "scanner (nmap/naabu) with reachability; none is configured. "
                "Use discovery_type='siem' to discover assets from observed "
                "log traffic."
            ),
            "timestamp": now.isoformat(),
        }

    from src.exposure.models import ExposureAsset
    from src.siem.models import LogEntry

    cutoff_iso = (now - timedelta(hours=24)).isoformat()
    created = 0

    scanned = 0
    row_cap_hit = False
    asset_cap_hit = False

    async with async_session_factory() as session:
        # Known asset IPs for this org (dedupe target). Streamed: an org can
        # legitimately have hundreds of thousands of assets and only the IP
        # strings are needed, never the ORM rows.
        known_ips: set[str] = set()
        known_result = await session.stream(
            select(ExposureAsset.ip_address)
            .where(ExposureAsset.organization_id == organization_id)
            .execution_options(yield_per=DISCOVERY_BATCH_SIZE),
        )
        async for chunk in known_result.scalars().partitions(DISCOVERY_BATCH_SIZE):
            known_ips.update(ip for ip in chunk if ip)

        # Distinct source IPs/hostnames observed in the last 24h. Streamed in
        # fixed windows with a per-window commit — never materialised whole.
        stmt = (
            select(
                LogEntry.source_address,
                LogEntry.source_ip,
                LogEntry.hostname,
            )
            .where(
                LogEntry.organization_id == organization_id,
                LogEntry.received_at >= cutoff_iso,
            )
            .distinct()
            .limit(MAX_DISCOVERY_LOG_ROWS)
            .execution_options(yield_per=DISCOVERY_BATCH_SIZE)
        )

        seen: set[str] = set()
        log_result = await session.stream(stmt)
        async for chunk in log_result.partitions(DISCOVERY_BATCH_SIZE):
            for source_address, source_ip, hostname in chunk:
                scanned += 1
                ip = source_address or source_ip
                if not ip or ip in known_ips or ip in seen:
                    continue
                if created >= MAX_ASSETS_PER_RUN:
                    asset_cap_hit = True
                    break
                seen.add(ip)
                session.add(
                    ExposureAsset(
                        hostname=hostname,
                        ip_address=ip,
                        asset_type="host",
                        is_active=True,
                        last_seen=now,
                        tags=["auto-discovered", "siem"],
                        extra_metadata={
                            "discovery_source": "siem_logs",
                            "discovered_at": now.isoformat(),
                        },
                        organization_id=organization_id,
                    ),
                )
                created += 1
            # Drain the pending inserts (and the identity map) every window so
            # the session never holds more than one batch of ORM objects.
            await session.commit()
            session.expunge_all()
            if asset_cap_hit:
                break

        if scanned >= MAX_DISCOVERY_LOG_ROWS:
            row_cap_hit = True

        await session.commit()

    if row_cap_hit:
        logger.warning(
            "asset discovery hit its per-run log-row cap — remaining rows "
            "deferred to the next run",
            organization_id=organization_id,
            max_log_rows=MAX_DISCOVERY_LOG_ROWS,
        )
    if asset_cap_hit:
        logger.warning(
            "asset discovery hit its per-run asset-creation cap — remaining "
            "assets deferred to the next run",
            organization_id=organization_id,
            max_assets=MAX_ASSETS_PER_RUN,
        )

    return {
        "organization_id": organization_id,
        "discovery_type": "siem",
        "assets_discovered": created,
        "log_rows_scanned": scanned,
        "truncated": row_cap_hit or asset_cap_hit,
        "timestamp": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

async def _distinct_org_ids(column) -> list[str]:
    """Distinct non-null organization_id values for a model column."""
    async with async_session_factory() as session:
        rows = (await session.execute(select(column).distinct())).scalars().all()
    return [o for o in rows if o]


async def _sweep_asset_discovery_async(discovery_type: str = "siem") -> dict[str, Any]:
    """Run asset discovery for every org that has recent logs (beat mode)."""
    from src.siem.models import LogEntry

    org_ids = await _distinct_org_ids(LogEntry.organization_id)
    total = 0
    for oid in org_ids:
        r = await _run_asset_discovery_async(oid, discovery_type)
        total += r.get("assets_discovered", 0)
    return {
        "organizations": len(org_ids),
        "assets_discovered": total,
        "discovery_type": discovery_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def _sweep_attack_surface_async() -> dict[str, Any]:
    """Detect attack-surface changes for every org that has assets."""
    from src.exposure.models import ExposureAsset

    org_ids = await _distinct_org_ids(ExposureAsset.organization_id)
    total = 0
    for oid in org_ids:
        r = await _detect_attack_surface_changes_async(oid)
        total += r.get("changes_detected", 0)
    return {
        "organizations": len(org_ids),
        "changes_detected": total,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@shared_task(bind=True, max_retries=3)
def run_asset_discovery(self, organization_id: str | None = None, discovery_type: str = "siem") -> dict:
    """
    Discover new assets from SIEM logs or network scans.

    Args:
        self: Celery task instance
        organization_id: UUID of the organization, or None to sweep every
            organization that has recent logs (beat-scheduled mode).
        discovery_type: "siem" or "network"

    Returns:
        Dictionary with discovery results
    """
    try:
        logger.info("Starting asset discovery", organization_id=organization_id or "all", type=discovery_type)

        if organization_id is None:
            result = _run_async(_sweep_asset_discovery_async(discovery_type))
        else:
            result = _run_async(_run_asset_discovery_async(organization_id, discovery_type))

        logger.info(
            "Asset discovery complete",
            organization_id=organization_id or "all",
            assets_discovered=result.get("assets_discovered"),
        )
        return result

    except Exception as exc:
        logger.error("Asset discovery failed", error=str(exc), exc_info=True)
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 600))


# --------------------------------------------------------------------------
# Memory bounds for the on-demand vulnerability-management tasks
# --------------------------------------------------------------------------
# run_vuln_scan / import_scanner_results / calculate_risk_scores /
# check_sla_breaches used to load every matching scan_profiles /
# exposure_scans / vulnerabilities / vulnerability_instances row as a full
# ORM object with one `.scalars().all()` and commit once at the end
# (calculate_risk_scores additionally loaded every instance of every CVE as
# ORM objects, one SELECT per CVE). sync_kev_database ran one SELECT per KEV
# entry and held every new indicator in one session.
#
# Each task now walks its table in keyset windows of VULN_BATCH_SIZE on the
# primary key, selects only the columns it reads, writes with bulk UPDATEs
# by id list, and commits + expunges per window. Every per-run cap that
# fires sets ``truncated`` in the result; the remainder is picked up by the
# next run.
VULN_BATCH_SIZE = 1_000
MAX_SCAN_PROFILES_PER_RUN = 50_000
MAX_SCANNER_IMPORTS_PER_RUN = 50_000
MAX_RISK_SCORE_VULNS_PER_RUN = 100_000
MAX_SLA_INSTANCES_PER_RUN = 200_000
MAX_KEV_ENTRIES_PER_RUN = 50_000

# How many breached instance ids the SLA result carries (unchanged: 100).
_SLA_BREACHED_IDS_IN_RESULT = 100

_SEVERITY_BASE = {
    "critical": 100.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
    "informational": 10.0,
}
_EXPLOIT_BONUS = {
    "none": 0.0,
    "poc": 5.0,
    "functional": 10.0,
    "weaponized": 20.0,
}


def _scan_profile_due(next_scan_date: str | None, now: datetime) -> bool:
    """Same due rule as before: missing or unparseable dates are due."""
    if not next_scan_date:
        return True
    try:
        nsd = datetime.fromisoformat(next_scan_date)
    except ValueError:
        return True
    if nsd.tzinfo is None:
        nsd = nsd.replace(tzinfo=timezone.utc)
    return nsd <= now


def _vuln_risk_score(
    severity: str | None, exploit_maturity: str | None, kev_listed: bool | None,
) -> float:
    """Severity baseline + exploit-maturity bonus (+15 for KEV), capped at 150."""
    base = _SEVERITY_BASE.get((severity or "").lower(), 25.0)
    bonus = _EXPLOIT_BONUS.get((exploit_maturity or "none").lower(), 0.0)
    if kev_listed:
        bonus += 15.0
    return min(base + bonus, 150.0)


async def _run_vuln_scan_async(organization_id: str | None = None) -> dict[str, Any]:
    """Mark every due, enabled ScanProfile as executed (windowed)."""
    from src.vulnmgmt.models import ScanProfile

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    next_iso = (now + timedelta(days=1)).isoformat()
    processed = 0
    scanned = 0
    cap_hit = False
    last_id: str | None = None

    async with async_session_factory() as session:
        while scanned < MAX_SCAN_PROFILES_PER_RUN:
            window = min(VULN_BATCH_SIZE, MAX_SCAN_PROFILES_PER_RUN - scanned)
            stmt = select(ScanProfile.id, ScanProfile.next_scan_date).where(
                ScanProfile.enabled == True,  # noqa: E712
            )
            if organization_id:
                stmt = stmt.where(ScanProfile.organization_id == organization_id)
            if last_id is not None:
                stmt = stmt.where(ScanProfile.id > last_id)
            rows = (await session.execute(stmt.order_by(ScanProfile.id).limit(window))).all()
            if not rows:
                break
            last_id = rows[-1].id
            scanned += len(rows)

            due_ids = [r.id for r in rows if _scan_profile_due(r.next_scan_date, now)]
            if due_ids:
                await session.execute(
                    update(ScanProfile)
                    .where(ScanProfile.id.in_(due_ids))
                    .values(last_scan_date=now_iso, next_scan_date=next_iso)
                    .execution_options(synchronize_session=False),
                )
                processed += len(due_ids)
            await session.commit()
            session.expunge_all()

            # Compare against the window actually requested: a short read on
            # the last window before the cap means "exhausted", not "capped".
            if len(rows) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "run_vuln_scan hit per-run cap; remainder deferred to the next run",
            cap=MAX_SCAN_PROFILES_PER_RUN,
        )
    return {"processed": processed, "truncated": cap_hit}


@shared_task(bind=True, max_retries=3)
def run_vuln_scan(self, organization_id: str | None = None) -> dict:
    """
    Dispatch scheduled vulnerability scans by iterating enabled ScanProfiles.

    For each profile whose next_scan_date is due (or missing), updates its
    last_scan_date/next_scan_date to mark it as executed.

    Args:
        self: Celery task instance
        organization_id: Optional org filter

    Returns:
        Dictionary with dispatch summary
    """
    try:
        summary = _run_async(_run_vuln_scan_async(organization_id))

        result = {
            "organization_id": organization_id,
            "profiles_processed": summary["processed"],
            "truncated": summary["truncated"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info("Vulnerability scan dispatch complete", **result)
        return result

    except Exception as exc:
        logger.error("run_vuln_scan failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 600))


# Backward-compatible alias used by existing callers
run_vulnerability_scan = run_vuln_scan


async def _import_scanner_results_async(
    organization_id: str | None = None, scan_id: str | None = None,
) -> dict[str, Any]:
    """Flip pending ExposureScan rows to completed, in id windows."""
    from src.exposure.models import ExposureScan

    processed = 0
    cap_hit = False
    last_id: str | None = None

    async with async_session_factory() as session:
        while processed < MAX_SCANNER_IMPORTS_PER_RUN:
            window = min(VULN_BATCH_SIZE, MAX_SCANNER_IMPORTS_PER_RUN - processed)
            stmt = select(ExposureScan.id).where(ExposureScan.status == "pending")
            if organization_id:
                stmt = stmt.where(ExposureScan.organization_id == organization_id)
            if scan_id:
                stmt = stmt.where(ExposureScan.id == scan_id)
            if last_id is not None:
                stmt = stmt.where(ExposureScan.id > last_id)
            ids = list(
                (await session.execute(stmt.order_by(ExposureScan.id).limit(window))).scalars(),
            )
            if not ids:
                break
            last_id = ids[-1]

            await session.execute(
                update(ExposureScan)
                .where(ExposureScan.id.in_(ids))
                .values(status="completed", completed_at=datetime.now(timezone.utc))
                .execution_options(synchronize_session=False),
            )
            processed += len(ids)
            await session.commit()
            session.expunge_all()

            if len(ids) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "import_scanner_results hit per-run cap; remainder deferred to the next run",
            cap=MAX_SCANNER_IMPORTS_PER_RUN,
        )
    # The status flip is one UPDATE per window, so there is no per-row
    # failure to count; errors stays 0 as it always was in practice.
    return {"processed": processed, "errors": 0, "truncated": cap_hit}


@shared_task(bind=True, max_retries=3)
def import_scanner_results(
    self,
    organization_id: str | None = None,
    scan_id: str | None = None,
    scanner: str | None = None,
    results: list[dict] | None = None,
) -> dict:
    """
    Import pending vulnerability scan results from the database.

    Queries ExposureScan records in the "pending" state and transitions them
    to "completed" (or filters by a specific scan_id).

    Returns:
        Dictionary with import summary
    """
    try:
        summary = _run_async(_import_scanner_results_async(organization_id, scan_id))

        result = {
            "scan_id": scan_id,
            "scanner": scanner,
            "scans_processed": summary["processed"],
            "errors": summary["errors"],
            "truncated": summary["truncated"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Scanner results import complete", **result)
        return result

    except Exception as exc:
        logger.error("Scanner import failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 600))


async def _calculate_risk_scores_async(organization_id: str | None = None) -> dict[str, Any]:
    """Write each Vulnerability's computed score onto its instances.

    Vulnerabilities are read in id windows (four columns, not ORM rows).
    Instances are never loaded at all: one bulk UPDATE per distinct score in
    the window sets ``risk_score`` on every instance of those CVEs, and the
    UPDATE's matched-row count is the same "instances scored" number the
    per-instance loop used to produce.
    """
    from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance

    scored = 0
    vulns_seen = 0
    cap_hit = False
    last_id: str | None = None

    async with async_session_factory() as session:
        while vulns_seen < MAX_RISK_SCORE_VULNS_PER_RUN:
            window = min(VULN_BATCH_SIZE, MAX_RISK_SCORE_VULNS_PER_RUN - vulns_seen)
            stmt = select(
                Vulnerability.id,
                Vulnerability.severity,
                Vulnerability.exploit_maturity,
                Vulnerability.kev_listed,
            )
            if organization_id:
                stmt = stmt.where(Vulnerability.organization_id == organization_id)
            if last_id is not None:
                stmt = stmt.where(Vulnerability.id > last_id)
            rows = (await session.execute(stmt.order_by(Vulnerability.id).limit(window))).all()
            if not rows:
                break
            last_id = rows[-1].id
            vulns_seen += len(rows)

            ids_by_score: dict[float, list[str]] = {}
            for r in rows:
                score = _vuln_risk_score(r.severity, r.exploit_maturity, r.kev_listed)
                ids_by_score.setdefault(score, []).append(r.id)

            for score, vuln_ids in ids_by_score.items():
                res = await session.execute(
                    update(VulnerabilityInstance)
                    .where(VulnerabilityInstance.vulnerability_id.in_(vuln_ids))
                    .values(risk_score=score)
                    .execution_options(synchronize_session=False),
                )
                scored += res.rowcount or 0
            await session.commit()
            session.expunge_all()

            if len(rows) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "calculate_risk_scores hit per-run cap; remainder deferred to the next run",
            cap=MAX_RISK_SCORE_VULNS_PER_RUN,
        )
    return {"scored": scored, "truncated": cap_hit}


@shared_task(bind=True, max_retries=2)
def calculate_risk_scores(self, organization_id: str | None = None) -> dict:
    """
    Recalculate risk scores for all Vulnerability records.

    Uses a severity-based baseline plus an exploit-maturity bonus, writing the
    computed value to each Vulnerability's associated VulnerabilityInstance.risk_score
    records (Vulnerability rows don't have their own risk_score field).
    """
    try:
        summary = _run_async(_calculate_risk_scores_async(organization_id))

        result = {
            "organization_id": organization_id,
            "instances_scored": summary["scored"],
            "truncated": summary["truncated"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Risk score calculation complete", **result)
        return result

    except Exception as exc:
        logger.error("Risk score calculation failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)


async def _check_sla_breaches_async(organization_id: str | None = None) -> dict[str, Any]:
    """Flag open instances whose remediation deadline has passed (windowed).

    Rows already ``breached`` or without a deadline are filtered in SQL (the
    old loop skipped them in Python). The rest are read as three columns per
    window, flipped with one bulk UPDATE, and get their TicketActivity rows
    in the same per-window commit.
    """
    from sqlalchemy import or_

    from src.tickethub.models import TicketActivity
    from src.vulnmgmt.models import VulnerabilityInstance as VI

    now = datetime.now(timezone.utc)
    breached_count = 0
    breached_sample: list[str] = []
    scanned = 0
    cap_hit = False
    last_id: str | None = None

    async with async_session_factory() as session:
        while scanned < MAX_SLA_INSTANCES_PER_RUN:
            window = min(VULN_BATCH_SIZE, MAX_SLA_INSTANCES_PER_RUN - scanned)
            stmt = select(VI.id, VI.remediation_deadline, VI.organization_id).where(
                VI.status.notin_(["closed", "remediated", "accepted"]),
                VI.remediation_deadline.isnot(None),
                or_(VI.sla_status.is_(None), VI.sla_status != "breached"),
            )
            if organization_id:
                stmt = stmt.where(VI.organization_id == organization_id)
            if last_id is not None:
                stmt = stmt.where(VI.id > last_id)
            rows = (await session.execute(stmt.order_by(VI.id).limit(window))).all()
            if not rows:
                break
            last_id = rows[-1].id
            scanned += len(rows)

            window_breached: list[Any] = []
            for r in rows:
                if not r.remediation_deadline:
                    continue
                try:
                    due = datetime.fromisoformat(r.remediation_deadline)
                except ValueError:
                    continue
                if due.tzinfo is None:
                    due = due.replace(tzinfo=timezone.utc)
                if due < now:
                    window_breached.append(r)

            if window_breached:
                await session.execute(
                    update(VI)
                    .where(VI.id.in_([r.id for r in window_breached]))
                    .values(sla_status="breached")
                    .execution_options(synchronize_session=False),
                )
                session.add_all(
                    [
                        TicketActivity(
                            source_type="vulnerability_instance",
                            source_id=r.id,
                            activity_type="sla_breach",
                            description=f"SLA breached: deadline {r.remediation_deadline} passed",
                            organization_id=r.organization_id,
                        )
                        for r in window_breached
                    ],
                )
                breached_count += len(window_breached)
                room = _SLA_BREACHED_IDS_IN_RESULT - len(breached_sample)
                if room > 0:
                    breached_sample.extend(r.id for r in window_breached[:room])
            await session.commit()
            session.expunge_all()

            if len(rows) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "check_sla_breaches hit per-run cap; remainder deferred to the next run",
            cap=MAX_SLA_INSTANCES_PER_RUN,
        )
    return {
        "breached_count": breached_count,
        "breached_instances": breached_sample,
        "truncated": cap_hit,
    }


@shared_task(bind=True, max_retries=2)
def check_sla_breaches(self, organization_id: str | None = None) -> dict:
    """
    Flag VulnerabilityInstance records that have breached SLA.

    A breach is defined as having a remediation_deadline in the past while the
    status is not yet "closed"/"remediated". Also logs a TicketActivity entry.
    """
    try:
        summary = _run_async(_check_sla_breaches_async(organization_id))

        result = {
            "organization_id": organization_id,
            "breached_count": summary["breached_count"],
            "breached_instances": summary["breached_instances"],
            "truncated": summary["truncated"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("SLA breach check complete", breached_count=summary["breached_count"])
        return result

    except Exception as exc:
        logger.error("SLA breach check failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)


KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def _fetch_kev_catalog() -> dict[str, Any] | None:
    """Fetch the public KEV JSON; None (logged) on any fetch failure."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(KEV_FEED_URL)
            resp.raise_for_status()
            return resp.json()
    except Exception as fetch_err:
        logger.warning("KEV feed fetch failed; skipping sync", error=str(fetch_err))
        return None


async def _sync_kev_database_async() -> dict[str, Any]:
    """Upsert each KEV CVE as a ``cve`` ThreatIndicator, one window at a time.

    One ``value IN (...)`` lookup per window instead of one SELECT per entry,
    and a commit + expunge per window instead of one session holding every
    new indicator.
    """
    from src.intel.models import ThreatIndicator

    data = await _fetch_kev_catalog()
    if data is None:
        return {"updated": 0, "created": 0, "fetched": 0, "truncated": False}

    vulns = data.get("vulnerabilities", []) or []
    entries = [e for e in vulns if isinstance(e, dict) and e.get("cveID")]
    cap_hit = len(entries) > MAX_KEV_ENTRIES_PER_RUN
    if cap_hit:
        logger.warning(
            "sync_kev_database hit per-run cap; remainder deferred to the next run",
            cap=MAX_KEV_ENTRIES_PER_RUN,
            entries=len(entries),
        )
        entries = entries[:MAX_KEV_ENTRIES_PER_RUN]

    updated = 0
    created = 0
    async with async_session_factory() as session:
        for offset in range(0, len(entries), VULN_BATCH_SIZE):
            chunk = entries[offset : offset + VULN_BATCH_SIZE]
            cve_ids = sorted({e["cveID"] for e in chunk})
            existing_rows = (
                await session.execute(
                    select(ThreatIndicator)
                    .where(
                        ThreatIndicator.value.in_(cve_ids),
                        ThreatIndicator.indicator_type == "cve",
                    )
                    .order_by(ThreatIndicator.id),
                )
            ).scalars()
            by_value: dict[str, list[Any]] = {}
            for row in existing_rows:
                by_value.setdefault(row.value, []).append(row)

            for entry in chunk:
                cve_id = entry["cveID"]
                description = entry.get("shortDescription") or entry.get("vulnerabilityName")
                source_ref = entry.get("vendorProject")
                matches = by_value.get(cve_id)
                if matches:
                    for existing in matches:
                        existing.is_active = True
                        existing.severity = "high"
                        existing.source = "CISA KEV"
                        ctx = dict(existing.context) if isinstance(existing.context, dict) else {}
                        if description:
                            ctx["description"] = description
                        if source_ref:
                            ctx["source_reference"] = source_ref
                        ctx["source_url"] = KEV_FEED_URL
                        existing.context = ctx
                    updated += 1
                else:
                    ioc = ThreatIndicator(
                        value=cve_id,
                        indicator_type="cve",
                        is_active=True,
                        is_whitelisted=False,
                        severity="high",
                        confidence=95,
                        source="CISA KEV",
                        context={
                            "description": description,
                            "source_url": KEV_FEED_URL,
                            "source_reference": source_ref,
                        },
                    )
                    session.add(ioc)
                    # A CVE listed twice in one feed updates the row it just
                    # created, exactly as the per-entry SELECT (autoflush) did.
                    by_value[cve_id] = [ioc]
                    created += 1

            await session.commit()
            session.expunge_all()

    return {"updated": updated, "created": created, "fetched": len(vulns), "truncated": cap_hit}


@shared_task(bind=True, max_retries=3)
def sync_kev_database(self, organization_id: str | None = None) -> dict:
    """
    Sync CISA Known Exploited Vulnerabilities (KEV) catalog.

    Fetches the public KEV JSON feed and upserts each listed CVE as an IOC
    record. A fetch failure is logged as a warning but does not crash the task.
    """
    try:
        summary = _run_async(_sync_kev_database_async())

        result = {
            "status": "completed",
            "vulnerabilities_fetched": summary["fetched"],
            "iocs_updated": summary["updated"],
            "iocs_created": summary["created"],
            "truncated": summary["truncated"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("KEV database sync complete", **result)
        return result

    except Exception as exc:
        logger.error("KEV database sync failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 3600))


@shared_task(bind=True, max_retries=2)
def generate_exposure_report(self, organization_id: str, report_format: str = "pdf") -> dict:
    """
    Generate weekly exposure management report.

    Compiles asset inventory, vulnerability summary, remediation progress, and recommendations.

    Args:
        self: Celery task instance
        organization_id: UUID of the organization
        report_format: Output format ("pdf", "html", "json")

    Returns:
        Dictionary with report generation results
    """
    try:
        logger.info(
            "Generating exposure report",
            organization_id=organization_id,
            format=report_format,
        )
        result = _run_async(
            _generate_exposure_report_async(organization_id, report_format),
        )
        logger.info(
            "Exposure report generation complete",
            organization_id=organization_id,
            report_format=report_format,
            status=result["status"],
        )
        return result

    except Exception as exc:
        logger.error("Report generation failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)


async def _generate_exposure_report_async(
    organization_id: str, report_format: str = "pdf",
) -> dict[str, Any]:
    """Compile a real exposure report (asset inventory, vuln summary,
    remediation progress, top risky assets) from the org's rows."""
    from sqlalchemy import func

    from src.exposure.models import (
        AssetVulnerability,
        ExposureAsset,
        ExposureVulnerability,
        RemediationTicket,
    )

    now = datetime.now(timezone.utc)
    async with async_session_factory() as session:
        # --- Asset inventory ---
        total_assets = (await session.execute(
            select(func.count(ExposureAsset.id)).where(
                ExposureAsset.organization_id == organization_id,
            ),
        )).scalar() or 0
        internet_facing = (await session.execute(
            select(func.count(ExposureAsset.id)).where(
                ExposureAsset.organization_id == organization_id,
                ExposureAsset.is_internet_facing == True,  # noqa: E712
            ),
        )).scalar() or 0

        # --- Vulnerability summary by severity ---
        sev_rows = (await session.execute(
            select(ExposureVulnerability.severity, func.count(ExposureVulnerability.id))
            .where(ExposureVulnerability.organization_id == organization_id)
            .group_by(ExposureVulnerability.severity),
        )).all()
        vulns_by_severity = {sev or "unknown": n for sev, n in sev_rows}

        # --- Remediation progress (open vs remediated instances) ---
        inst_rows = (await session.execute(
            select(AssetVulnerability.status, func.count(AssetVulnerability.id))
            .where(AssetVulnerability.organization_id == organization_id)
            .group_by(AssetVulnerability.status),
        )).all()
        instances_by_status = {st or "unknown": n for st, n in inst_rows}

        # --- Remediation tickets / SLA ---
        open_tickets = (await session.execute(
            select(func.count(RemediationTicket.id)).where(
                RemediationTicket.organization_id == organization_id,
                RemediationTicket.status != "resolved",
            ),
        )).scalar() or 0
        sla_breached = (await session.execute(
            select(func.count(RemediationTicket.id)).where(
                RemediationTicket.organization_id == organization_id,
                RemediationTicket.sla_breach == True,  # noqa: E712
            ),
        )).scalar() or 0

        # --- Top risky assets ---
        top_assets = (await session.execute(
            select(ExposureAsset)
            .where(ExposureAsset.organization_id == organization_id)
            .order_by(ExposureAsset.risk_score.desc())
            .limit(5),
        )).scalars().all()
        top_risky = [
            {
                "id": a.id,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "risk_score": a.risk_score,
                "vulnerability_count": a.vulnerability_count,
            }
            for a in top_assets
        ]

        report_data = {
            "organization_id": organization_id,
            "report_period": "weekly",
            "generated_at": now.isoformat(),
            "assets": {
                "total": total_assets,
                "internet_facing": internet_facing,
            },
            "vulnerabilities": {
                "by_severity": vulns_by_severity,
                "total": sum(vulns_by_severity.values()),
            },
            "remediation": {
                "instances_by_status": instances_by_status,
                "open_tickets": open_tickets,
                "sla_breached": sla_breached,
            },
            "top_risky_assets": top_risky,
        }

    # The report data is fully real. A rendered PDF/HTML file is not
    # produced here (no file-render backend is wired for exposure
    # reports), so json returns the data inline and other formats
    # honestly say the data is available but not rendered to a file.
    rendered = report_format == "json"
    return {
        "organization_id": organization_id,
        "report_format": report_format,
        "status": "generated" if rendered else "data_only",
        "file_path": None,
        "report_data": report_data,
        "detail": (
            None if rendered else
            f"Report data computed; no {report_format} file was rendered "
            "(no document-render backend is configured for exposure reports)"
        ),
        "timestamp": now.isoformat(),
    }


@shared_task(bind=True, max_retries=2)
def detect_attack_surface_changes(self, organization_id: str | None = None) -> dict:
    """
    Detect changes in organization's attack surface.

    Compares the current attack surface with the previous snapshot and
    identifies new/removed assets and vulnerabilities. ``organization_id
    =None`` sweeps every organization that has exposure assets
    (beat-scheduled mode).
    """
    try:
        logger.info("Detecting attack surface changes", organization_id=organization_id or "all")

        if organization_id is None:
            result = _run_async(_sweep_attack_surface_async())
        else:
            result = _run_async(_detect_attack_surface_changes_async(organization_id))

        logger.info(
            "Attack surface analysis complete",
            organization_id=organization_id or "all",
            changes_detected=result.get("changes_detected"),
        )
        return result

    except Exception as exc:
        logger.error("Attack surface detection failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)


async def _detect_attack_surface_changes_async(organization_id: str) -> dict[str, Any]:
    """Diff the org's current attack surface (active assets + open vulns)
    against the last stored snapshot, then persist a new snapshot."""
    from src.exposure.models import (
        AssetVulnerability,
        AttackSurface,
        ExposureAsset,
    )

    now = datetime.now(timezone.utc)
    async with async_session_factory() as session:
        # --- Current attack surface fingerprint ---
        # Both reads are streamed and hard-capped: the fingerprint sets are
        # serialised into a single JSON column, so an unbounded asset or
        # open-vulnerability count used to mean an unbounded row (written
        # daily, and read back in full the next day).
        current_assets: set[str] = set()
        asset_result = await session.stream(
            select(ExposureAsset.ip_address, ExposureAsset.hostname)
            .where(
                ExposureAsset.organization_id == organization_id,
                ExposureAsset.is_active == True,  # noqa: E712
            )
            .limit(MAX_SNAPSHOT_KEYS + 1)
            .execution_options(yield_per=DISCOVERY_BATCH_SIZE),
        )
        async for chunk in asset_result.partitions(DISCOVERY_BATCH_SIZE):
            current_assets.update((ip or host) for ip, host in chunk if (ip or host))

        current_vulns: set[str] = set()
        vuln_result = await session.stream(
            select(AssetVulnerability.asset_id, AssetVulnerability.vulnerability_id)
            .where(
                AssetVulnerability.organization_id == organization_id,
                AssetVulnerability.status == "open",
            )
            .limit(MAX_SNAPSHOT_KEYS + 1)
            .execution_options(yield_per=DISCOVERY_BATCH_SIZE),
        )
        async for chunk in vuln_result.partitions(DISCOVERY_BATCH_SIZE):
            current_vulns.update(f"{aid}:{vid}" for aid, vid in chunk)

        keys_truncated = (
            len(current_assets) > MAX_SNAPSHOT_KEYS
            or len(current_vulns) > MAX_SNAPSHOT_KEYS
        )
        if keys_truncated:
            # Deterministic prefix so consecutive snapshots compare the same
            # slice of the surface instead of two arbitrary samples.
            current_assets = set(sorted(current_assets)[:MAX_SNAPSHOT_KEYS])
            current_vulns = set(sorted(current_vulns)[:MAX_SNAPSHOT_KEYS])
            logger.warning(
                "attack-surface snapshot truncated at the per-snapshot key cap "
                "— the diff covers the lexicographically first keys only",
                organization_id=organization_id,
                max_snapshot_keys=MAX_SNAPSHOT_KEYS,
            )

        # --- Previous snapshot (most recent) ---
        previous = (await session.execute(
            select(AttackSurface)
            .where(
                AttackSurface.organization_id == organization_id,
                AttackSurface.surface_type == "snapshot",
            )
            .order_by(AttackSurface.last_assessed_at.desc())
            .limit(1),
        )).scalars().first()

        is_baseline = previous is None
        prev_assets = set((previous.metrics or {}).get("asset_keys", [])) if previous else set()
        prev_vulns = set((previous.metrics or {}).get("vuln_keys", [])) if previous else set()

        changes = {
            "new_assets": sorted(current_assets - prev_assets),
            "removed_assets": sorted(prev_assets - current_assets),
            "new_vulnerabilities": sorted(current_vulns - prev_vulns),
            "remediated_vulnerabilities": sorted(prev_vulns - current_vulns),
        }

        # --- Persist the new snapshot for next time ---
        snapshot = AttackSurface(
            name=f"snapshot-{now.date().isoformat()}",
            surface_type="snapshot",
            total_assets=len(current_assets),
            exposed_assets=len(current_assets),
            last_assessed_at=now,
            findings=[{"change": k, "items": v} for k, v in changes.items() if v],
            metrics={
                "asset_keys": sorted(current_assets),
                "vuln_keys": sorted(current_vulns),
                "is_baseline": is_baseline,
                "keys_truncated": keys_truncated,
            },
            organization_id=organization_id,
        )
        session.add(snapshot)
        await session.commit()

    return {
        "organization_id": organization_id,
        "is_baseline": is_baseline,
        "keys_truncated": keys_truncated,
        "changes_detected": (
            len(changes["new_assets"])
            + len(changes["new_vulnerabilities"])
            + len(changes["removed_assets"])
            + len(changes["remediated_vulnerabilities"])
        ),
        "details": changes,
        "timestamp": now.isoformat(),
    }
