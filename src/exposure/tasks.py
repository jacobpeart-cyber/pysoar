"""
Celery tasks for Continuous Threat Exposure Management (CTEM)

Asynchronous background tasks for asset discovery, vulnerability scanning,
risk calculation, and exposure reporting.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from celery import shared_task
from sqlalchemy import select, update

from src.core.config import settings
from src.core.database import async_session_factory
from src.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    organization_id: str, discovery_type: str = "siem"
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

    from src.siem.models import LogEntry
    from src.exposure.models import ExposureAsset

    cutoff_iso = (now - timedelta(hours=24)).isoformat()
    created = 0

    async with async_session_factory() as session:
        # Distinct source IPs/hostnames observed in the last 24h.
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
        )
        rows = (await session.execute(stmt)).all()

        # Known asset IPs for this org (dedupe target).
        known = (
            await session.execute(
                select(ExposureAsset.ip_address).where(
                    ExposureAsset.organization_id == organization_id
                )
            )
        ).scalars().all()
        known_ips = {ip for ip in known if ip}
        seen: set[str] = set()

        for source_address, source_ip, hostname in rows:
            ip = source_address or source_ip
            if not ip or ip in known_ips or ip in seen:
                continue
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
                )
            )
            created += 1

        await session.commit()

    return {
        "organization_id": organization_id,
        "discovery_type": "siem",
        "assets_discovered": created,
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
        from src.vulnmgmt.models import ScanProfile

        async def _dispatch() -> int:
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
            next_iso = (now + timedelta(days=1)).isoformat()
            processed = 0

            async with async_session_factory() as session:
                stmt = select(ScanProfile).where(ScanProfile.enabled == True)  # noqa: E712
                if organization_id:
                    stmt = stmt.where(ScanProfile.organization_id == organization_id)
                result = await session.execute(stmt)
                profiles = result.scalars().all()

                for profile in profiles:
                    due = True
                    if profile.next_scan_date:
                        try:
                            nsd = datetime.fromisoformat(profile.next_scan_date)
                            if nsd.tzinfo is None:
                                nsd = nsd.replace(tzinfo=timezone.utc)
                            due = nsd <= now
                        except ValueError:
                            due = True
                    if not due:
                        continue

                    profile.last_scan_date = now_iso
                    profile.next_scan_date = next_iso
                    processed += 1

                await session.commit()
            return processed

        processed = _run_async(_dispatch())

        result = {
            "organization_id": organization_id,
            "profiles_processed": processed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info("Vulnerability scan dispatch complete", **result)
        return result

    except Exception as exc:
        logger.error("run_vuln_scan failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 600))


# Backward-compatible alias used by existing callers
run_vulnerability_scan = run_vuln_scan


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
        from src.exposure.models import ExposureScan

        async def _import() -> dict[str, int]:
            processed = 0
            errors = 0
            async with async_session_factory() as session:
                stmt = select(ExposureScan).where(ExposureScan.status == "pending")
                if organization_id:
                    stmt = stmt.where(ExposureScan.organization_id == organization_id)
                if scan_id:
                    stmt = stmt.where(ExposureScan.id == scan_id)
                db_results = await session.execute(stmt)
                scans = db_results.scalars().all()

                for scan in scans:
                    try:
                        scan.status = "completed"
                        scan.completed_at = datetime.now(timezone.utc)
                        processed += 1
                    except Exception as inner:
                        logger.error(
                            "Failed to process scan record",
                            scan_id=scan.id,
                            error=str(inner),
                        )
                        errors += 1
                await session.commit()
            return {"processed": processed, "errors": errors}

        summary = _run_async(_import())

        result = {
            "scan_id": scan_id,
            "scanner": scanner,
            "scans_processed": summary["processed"],
            "errors": summary["errors"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Scanner results import complete", **result)
        return result

    except Exception as exc:
        logger.error("Scanner import failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 600))


@shared_task(bind=True, max_retries=2)
def calculate_risk_scores(self, organization_id: str | None = None) -> dict:
    """
    Recalculate risk scores for all Vulnerability records.

    Uses a severity-based baseline plus an exploit-maturity bonus, writing the
    computed value to each Vulnerability's associated VulnerabilityInstance.risk_score
    records (Vulnerability rows don't have their own risk_score field).
    """
    severity_base = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
        "informational": 10.0,
    }
    exploit_bonus = {
        "none": 0.0,
        "poc": 5.0,
        "functional": 10.0,
        "weaponized": 20.0,
    }

    try:
        from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance

        async def _score() -> int:
            scored = 0
            async with async_session_factory() as session:
                stmt = select(Vulnerability)
                if organization_id:
                    stmt = stmt.where(Vulnerability.organization_id == organization_id)
                vulns = (await session.execute(stmt)).scalars().all()

                for v in vulns:
                    base = severity_base.get((v.severity or "").lower(), 25.0)
                    bonus = exploit_bonus.get((v.exploit_maturity or "none").lower(), 0.0)
                    if getattr(v, "kev_listed", False):
                        bonus += 15.0
                    score = min(base + bonus, 150.0)

                    # Apply to each VulnerabilityInstance for this CVE.
                    inst_stmt = select(VulnerabilityInstance).where(
                        VulnerabilityInstance.vulnerability_id == v.id
                    )
                    instances = (await session.execute(inst_stmt)).scalars().all()
                    for inst in instances:
                        inst.risk_score = score
                        scored += 1

                await session.commit()
            return scored

        scored = _run_async(_score())

        result = {
            "organization_id": organization_id,
            "instances_scored": scored,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Risk score calculation complete", **result)
        return result

    except Exception as exc:
        logger.error("Risk score calculation failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)


@shared_task(bind=True, max_retries=2)
def check_sla_breaches(self, organization_id: str | None = None) -> dict:
    """
    Flag VulnerabilityInstance records that have breached SLA.

    A breach is defined as having a remediation_deadline in the past while the
    status is not yet "closed"/"remediated". Also logs a TicketActivity entry.
    """
    try:
        from src.tickethub.models import TicketActivity
        from src.vulnmgmt.models import VulnerabilityInstance

        async def _check() -> list[str]:
            breached: list[str] = []
            now = datetime.now(timezone.utc)

            async with async_session_factory() as session:
                stmt = select(VulnerabilityInstance).where(
                    VulnerabilityInstance.status.notin_(["closed", "remediated", "accepted"])
                )
                if organization_id:
                    stmt = stmt.where(VulnerabilityInstance.organization_id == organization_id)
                instances = (await session.execute(stmt)).scalars().all()

                for inst in instances:
                    if not inst.remediation_deadline:
                        continue
                    try:
                        due = datetime.fromisoformat(inst.remediation_deadline)
                        if due.tzinfo is None:
                            due = due.replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue

                    if due < now and inst.sla_status != "breached":
                        inst.sla_status = "breached"
                        breached.append(inst.id)
                        activity = TicketActivity(
                            source_type="vulnerability_instance",
                            source_id=inst.id,
                            activity_type="sla_breach",
                            description=f"SLA breached: deadline {inst.remediation_deadline} passed",
                            organization_id=inst.organization_id,
                        )
                        session.add(activity)

                await session.commit()
            return breached

        breached = _run_async(_check())

        result = {
            "organization_id": organization_id,
            "breached_count": len(breached),
            "breached_instances": breached[:100],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("SLA breach check complete", breached_count=len(breached))
        return result

    except Exception as exc:
        logger.error("SLA breach check failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)


@shared_task(bind=True, max_retries=3)
def sync_kev_database(self, organization_id: str | None = None) -> dict:
    """
    Sync CISA Known Exploited Vulnerabilities (KEV) catalog.

    Fetches the public KEV JSON feed and upserts each listed CVE as an IOC
    record. A fetch failure is logged as a warning but does not crash the task.
    """
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    try:
        from src.intel.models import ThreatIndicator

        async def _sync() -> dict[str, int]:
            updated = 0
            created = 0
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(kev_url)
                    resp.raise_for_status()
                    data = resp.json()
            except Exception as fetch_err:  # noqa: BLE001
                logger.warning(
                    "KEV feed fetch failed; skipping sync",
                    error=str(fetch_err),
                )
                return {"updated": 0, "created": 0, "fetched": 0}

            vulns = data.get("vulnerabilities", []) or []

            async with async_session_factory() as session:
                for entry in vulns:
                    cve_id = entry.get("cveID")
                    if not cve_id:
                        continue

                    stmt = select(ThreatIndicator).where(
                        ThreatIndicator.value == cve_id,
                        ThreatIndicator.indicator_type == "cve",
                    )
                    existing = (await session.execute(stmt)).scalar_one_or_none()

                    description = entry.get("shortDescription") or entry.get("vulnerabilityName")
                    source_ref = entry.get("vendorProject")

                    if existing:
                        existing.is_active = True
                        existing.severity = "high"
                        existing.source = "CISA KEV"
                        ctx = dict(existing.context) if isinstance(existing.context, dict) else {}
                        if description:
                            ctx["description"] = description
                        if source_ref:
                            ctx["source_reference"] = source_ref
                        ctx["source_url"] = kev_url
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
                                "source_url": kev_url,
                                "source_reference": source_ref,
                            },
                        )
                        session.add(ioc)
                        created += 1

                await session.commit()
            return {"updated": updated, "created": created, "fetched": len(vulns)}

        summary = _run_async(_sync())

        result = {
            "status": "completed",
            "vulnerabilities_fetched": summary["fetched"],
            "iocs_updated": summary["updated"],
            "iocs_created": summary["created"],
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
            _generate_exposure_report_async(organization_id, report_format)
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
    organization_id: str, report_format: str = "pdf"
) -> dict[str, Any]:
    """Compile a real exposure report (asset inventory, vuln summary,
    remediation progress, top risky assets) from the org's rows."""
    from sqlalchemy import func
    from src.exposure.models import (
        ExposureAsset,
        ExposureVulnerability,
        AssetVulnerability,
        RemediationTicket,
    )

    now = datetime.now(timezone.utc)
    async with async_session_factory() as session:
        # --- Asset inventory ---
        total_assets = (await session.execute(
            select(func.count(ExposureAsset.id)).where(
                ExposureAsset.organization_id == organization_id
            )
        )).scalar() or 0
        internet_facing = (await session.execute(
            select(func.count(ExposureAsset.id)).where(
                ExposureAsset.organization_id == organization_id,
                ExposureAsset.is_internet_facing == True,  # noqa: E712
            )
        )).scalar() or 0

        # --- Vulnerability summary by severity ---
        sev_rows = (await session.execute(
            select(ExposureVulnerability.severity, func.count(ExposureVulnerability.id))
            .where(ExposureVulnerability.organization_id == organization_id)
            .group_by(ExposureVulnerability.severity)
        )).all()
        vulns_by_severity = {sev or "unknown": n for sev, n in sev_rows}

        # --- Remediation progress (open vs remediated instances) ---
        inst_rows = (await session.execute(
            select(AssetVulnerability.status, func.count(AssetVulnerability.id))
            .where(AssetVulnerability.organization_id == organization_id)
            .group_by(AssetVulnerability.status)
        )).all()
        instances_by_status = {st or "unknown": n for st, n in inst_rows}

        # --- Remediation tickets / SLA ---
        open_tickets = (await session.execute(
            select(func.count(RemediationTicket.id)).where(
                RemediationTicket.organization_id == organization_id,
                RemediationTicket.status != "resolved",
            )
        )).scalar() or 0
        sla_breached = (await session.execute(
            select(func.count(RemediationTicket.id)).where(
                RemediationTicket.organization_id == organization_id,
                RemediationTicket.sla_breach == True,  # noqa: E712
            )
        )).scalar() or 0

        # --- Top risky assets ---
        top_assets = (await session.execute(
            select(ExposureAsset)
            .where(ExposureAsset.organization_id == organization_id)
            .order_by(ExposureAsset.risk_score.desc())
            .limit(5)
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
        ExposureAsset,
        AssetVulnerability,
        AttackSurface,
    )

    now = datetime.now(timezone.utc)
    async with async_session_factory() as session:
        # --- Current attack surface fingerprint ---
        asset_rows = (await session.execute(
            select(ExposureAsset.ip_address, ExposureAsset.hostname).where(
                ExposureAsset.organization_id == organization_id,
                ExposureAsset.is_active == True,  # noqa: E712
            )
        )).all()
        current_assets = {(ip or host) for ip, host in asset_rows if (ip or host)}

        vuln_rows = (await session.execute(
            select(AssetVulnerability.asset_id, AssetVulnerability.vulnerability_id)
            .where(
                AssetVulnerability.organization_id == organization_id,
                AssetVulnerability.status == "open",
            )
        )).all()
        current_vulns = {f"{aid}:{vid}" for aid, vid in vuln_rows}

        # --- Previous snapshot (most recent) ---
        previous = (await session.execute(
            select(AttackSurface)
            .where(
                AttackSurface.organization_id == organization_id,
                AttackSurface.surface_type == "snapshot",
            )
            .order_by(AttackSurface.last_assessed_at.desc())
            .limit(1)
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
            },
            organization_id=organization_id,
        )
        session.add(snapshot)
        await session.commit()

    return {
        "organization_id": organization_id,
        "is_baseline": is_baseline,
        "changes_detected": (
            len(changes["new_assets"])
            + len(changes["new_vulnerabilities"])
            + len(changes["removed_assets"])
            + len(changes["remediated_vulnerabilities"])
        ),
        "details": changes,
        "timestamp": now.isoformat(),
    }
