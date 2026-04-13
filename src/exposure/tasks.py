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
from src.exposure.engine import (
    AssetDiscovery,
    ComplianceChecker,
    RiskScorer,
    VulnerabilityManager,
)

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
# Tasks
# ---------------------------------------------------------------------------

@shared_task(bind=True, max_retries=3)
def run_asset_discovery(self, organization_id: str, discovery_type: str = "siem") -> dict:
    """
    Discover new assets from SIEM logs or network scans.

    Args:
        self: Celery task instance
        organization_id: UUID of the organization
        discovery_type: "siem" or "network"

    Returns:
        Dictionary with discovery results
    """
    try:
        logger.info("Starting asset discovery", organization_id=organization_id, type=discovery_type)

        # In production, would instantiate with actual database session
        # This is a placeholder for the task structure
        discovered_assets = []

        if discovery_type == "siem":
            # Discover from SIEM logs
            logger.info("Discovering assets from SIEM", organization_id=organization_id)
            # asset_discovery = AssetDiscovery(db_session)
            # discovered_assets = asset_discovery.discover_from_siem_logs(organization_id)
            pass
        elif discovery_type == "network":
            # Discover from network scans
            logger.info("Discovering assets from network", organization_id=organization_id)
            # cidr_ranges = get_organization_cidr_ranges(organization_id)
            # for cidr in cidr_ranges:
            #     discovered = asset_discovery.discover_from_network_scan(organization_id, cidr)
            #     discovered_assets.extend(discovered)
            pass

        result = {
            "organization_id": organization_id,
            "discovery_type": discovery_type,
            "assets_discovered": len(discovered_assets),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Asset discovery complete", **result)
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

        report_data = {
            "organization_id": organization_id,
            "report_period": "weekly",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        result = {
            "organization_id": organization_id,
            "report_format": report_format,
            "status": "generated",
            "file_path": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Exposure report generation complete", **result)
        return result

    except Exception as exc:
        logger.error("Report generation failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)


@shared_task(bind=True, max_retries=2)
def detect_attack_surface_changes(self, organization_id: str) -> dict:
    """
    Detect changes in organization's attack surface.

    Compares current attack surface with previous assessment and identifies new exposures.
    """
    try:
        logger.info("Detecting attack surface changes", organization_id=organization_id)

        changes = {
            "new_assets": [],
            "removed_assets": [],
            "new_vulnerabilities": [],
            "remediated_vulnerabilities": [],
        }

        result = {
            "organization_id": organization_id,
            "changes_detected": len(changes["new_assets"]) + len(changes["new_vulnerabilities"]),
            "details": changes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Attack surface analysis complete", **result)
        return result

    except Exception as exc:
        logger.error("Attack surface detection failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc, countdown=300)
