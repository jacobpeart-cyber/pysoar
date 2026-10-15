"""Celery tasks for vulnerability management background processing"""

import asyncio
from typing import Any, Optional

from celery import shared_task

from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.vulnmgmt.engine import (
    KEVMonitor,
    PatchOrchestrator,
    RiskPrioritizer,
    ScanImportError,
    VulnerabilityLifecycle,
    VulnerabilityScanner,
)

logger = get_logger(__name__)


def run_async(coro):
    """Helper to run async code in sync context.

    Celery prefork worker threads have no event loop, and once a prior
    ``asyncio.run()`` clears it, ``get_event_loop()`` raises RuntimeError
    (Python 3.10+). Create a fresh loop in that case.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if loop.is_running():
        import nest_asyncio
        nest_asyncio.apply()
    return loop.run_until_complete(coro)


@shared_task(bind=True, max_retries=3)
def scheduled_scan_task(
    self,
    organization_id: str,
    scan_profile_id: str,
    scan_format: str,
    scan_data: str,
) -> dict[str, Any]:
    """Execute scheduled vulnerability scan

    Args:
        organization_id: Organization ID
        scan_profile_id: Scan profile identifier
        scan_format: Format of scan data (nessus, qualys, openvas)
        scan_data: Raw scan data

    Returns:
        Scan execution result
    """
    logger.info(
        "Starting scheduled scan task",
        organization_id=organization_id,
        scan_profile_id=scan_profile_id,
    )

    try:
        async def execute_scan():
            async with async_session_factory() as db:
                scanner = VulnerabilityScanner(organization_id)
                result = await scanner.import_scan_results(
                    db,
                    scan_format=scan_format,
                    scan_data=scan_data,
                    scan_id=scan_profile_id,
                    discovery_source=scan_format,
                )
                return result

        result = run_async(execute_scan())
        logger.info(
            "Scheduled scan completed",
            scan_profile_id=scan_profile_id,
            result=result,
        )
        return result

    except ScanImportError as e:
        # An unreadable payload will not parse on retry either.
        logger.error("Scheduled scan import rejected", scan_profile_id=scan_profile_id, errors=e.errors)
        return {"status": "failed", "errors": e.errors}
    except Exception as e:
        logger.error(
            "Scheduled scan failed",
            scan_profile_id=scan_profile_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def kev_sync_task(
    self,
    organization_id: str,
    kev_data: dict[str, Any],
) -> dict[str, Any]:
    """Sync CISA Known Exploited Vulnerabilities

    Args:
        organization_id: Organization ID
        kev_data: KEV feed data from CISA

    Returns:
        Sync result with counts
    """
    logger.info(
        "Starting KEV sync task",
        organization_id=organization_id,
    )

    try:
        async def sync_kev():
            async with async_session_factory() as db:
                monitor = KEVMonitor(organization_id)
                result = await monitor.sync_cisa_kev(db, kev_data)
                return result

        result = run_async(sync_kev())
        logger.info(
            "KEV sync completed",
            organization_id=organization_id,
            result=result,
        )
        return result

    except Exception as e:
        logger.error(
            "KEV sync failed",
            organization_id=organization_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=600)


@shared_task(bind=True, max_retries=3)
def sla_check_task(
    self,
    organization_id: str,
) -> dict[str, Any]:
    """Check SLA compliance across vulnerabilities

    Args:
        organization_id: Organization ID

    Returns:
        SLA compliance metrics
    """
    logger.info(
        "Starting SLA check task",
        organization_id=organization_id,
    )

    try:
        async def check_sla():
            async with async_session_factory() as db:
                prioritizer = RiskPrioritizer(organization_id)
                compliance = await prioritizer.assess_sla_compliance(db)
                return compliance

        compliance = run_async(check_sla())
        logger.info(
            "SLA check completed",
            organization_id=organization_id,
            compliance=compliance,
        )
        return compliance

    except Exception as e:
        logger.error(
            "SLA check failed",
            organization_id=organization_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def patch_verification_task(
    self,
    organization_id: str,
    patch_operation_id: str,
    verification_results: dict[str, Any],
) -> dict[str, Any]:
    """Verify patch deployment success

    Args:
        organization_id: Organization ID
        patch_operation_id: Patch operation identifier
        verification_results: Results from verification tests

    Returns:
        Verification status
    """
    logger.info(
        "Starting patch verification task",
        organization_id=organization_id,
        patch_operation_id=patch_operation_id,
    )

    try:
        async def verify():
            async with async_session_factory() as db:
                orchestrator = PatchOrchestrator(organization_id)
                success = await orchestrator.verify_patch(
                    db,
                    patch_operation_id,
                    verification_results,
                )
                return {"success": success, "verification_results": verification_results}

        result = run_async(verify())
        logger.info(
            "Patch verification completed",
            patch_operation_id=patch_operation_id,
            result=result,
        )
        return result

    except Exception as e:
        logger.error(
            "Patch verification failed",
            patch_operation_id=patch_operation_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def vulnerability_aging_report_task(
    self,
    organization_id: str,
) -> dict[str, Any]:
    """Generate vulnerability aging and lifecycle report

    Args:
        organization_id: Organization ID

    Returns:
        Aging analysis and metrics
    """
    logger.info(
        "Starting vulnerability aging report task",
        organization_id=organization_id,
    )

    try:
        async def generate_report():
            async with async_session_factory() as db:
                lifecycle = VulnerabilityLifecycle(organization_id)
                aging = await lifecycle.aging_analysis(db)
                mttr = await lifecycle.track_mean_time_to_remediate(db)
                trends = await lifecycle.trend_analysis(db, days=30)
                executive_report = await lifecycle.generate_executive_report(db)

                return {
                    "aging": aging,
                    "mttr_days": mttr,
                    "trends_30_days": trends,
                    "executive_summary": executive_report,
                }

        report = run_async(generate_report())
        logger.info(
            "Vulnerability aging report generated",
            organization_id=organization_id,
            report_keys=list(report.keys()),
        )
        return report

    except Exception as e:
        logger.error(
            "Vulnerability aging report failed",
            organization_id=organization_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=600)


# ---------------------------------------------------------------------------
# Wave 4: scheduled sweeps (beat entries in src/workers/celery_app.py)
# ---------------------------------------------------------------------------
# Both walk organisations that have vulnerability rows, one session and one
# commit per organisation. refresh_instances reads/writes in windows of 500
# rows and stops at 50,000 instances per organisation per run (the next run
# continues from the start; the hourly cadence keeps every row fresh for
# any realistic tenant size).
MAX_ORGS_PER_SWEEP = 10_000


async def _org_ids_with(column) -> list[str]:
    from sqlalchemy import select

    async with async_session_factory() as db:
        rows = (await db.execute(select(column).distinct().limit(MAX_ORGS_PER_SWEEP))).scalars().all()
    return [o for o in rows if o]


async def _refresh_scores_sweep(organization_id: Optional[str] = None) -> dict[str, Any]:
    from src.vulnmgmt.engine import refresh_instances, reopen_expired_exceptions
    from src.vulnmgmt.models import VulnerabilityInstance

    org_ids = [organization_id] if organization_id else await _org_ids_with(VulnerabilityInstance.organization_id)
    refreshed = breached = reopened = 0
    failures: list[dict[str, str]] = []
    for oid in org_ids:
        try:
            async with async_session_factory() as db:
                reopened += await reopen_expired_exceptions(db, oid)
                result = await refresh_instances(db, oid)
                await db.commit()
            refreshed += result["instances_refreshed"]
            breached += result["breached"]
        except Exception as exc:  # one org failing must not stop the sweep
            logger.error("vulnmgmt score refresh failed", organization_id=oid, error=str(exc))
            failures.append({"organization_id": oid, "error": str(exc)[:500]})
    return {
        "organizations": len(org_ids),
        "instances_refreshed": refreshed,
        "breached": breached,
        "reopened_after_exception_expiry": reopened,
        "failures": failures,
    }


@shared_task(bind=True, max_retries=1)
def refresh_instance_scores(self, organization_id: Optional[str] = None) -> dict[str, Any]:
    """Recompute risk, SLA deadline and SLA status on stored instances and
    re-open instances whose exceptions have all expired."""
    try:
        result = run_async(_refresh_scores_sweep(organization_id))
        logger.info("vulnmgmt score refresh complete", **{k: v for k, v in result.items() if k != "failures"})
        return result
    except Exception as exc:
        logger.error("vulnmgmt score refresh failed", error=str(exc))
        raise self.retry(exc=exc, countdown=600) from exc


async def _sync_kev_catalog_all() -> dict[str, Any]:
    from src.vulnmgmt.engine import KEVFeedUnavailable, fetch_kev_catalog
    from src.vulnmgmt.models import Vulnerability

    try:
        kev_data = await fetch_kev_catalog()
    except KEVFeedUnavailable as exc:
        logger.warning("KEV catalogue sync skipped: feed unavailable", error=str(exc))
        return {"status": "feed_unavailable", "error": str(exc), "organizations": 0, "matched": 0, "newly_flagged": 0}
    org_ids = await _org_ids_with(Vulnerability.organization_id)
    matched = newly = 0
    failures: list[dict[str, str]] = []
    for oid in org_ids:
        try:
            async with async_session_factory() as db:
                result = await KEVMonitor(oid).sync_cisa_kev(db, kev_data)
            matched += result["matched"]
            newly += result["newly_flagged"]
        except Exception as exc:  # one org failing must not stop the sweep
            logger.error("KEV catalogue sync failed for org", organization_id=oid, error=str(exc))
            failures.append({"organization_id": oid, "error": str(exc)[:500]})
    return {
        "status": "completed",
        "catalog_entries": len(kev_data.get("vulnerabilities") or []),
        "organizations": len(org_ids),
        "matched": matched,
        "newly_flagged": newly,
        "failures": failures,
    }


@shared_task(bind=True, max_retries=2)
def sync_kev_catalog(self) -> dict[str, Any]:
    """Fetch the CISA KEV catalogue once and flag tracked CVEs in every org
    (never creates vulnerabilities)."""
    try:
        result = run_async(_sync_kev_catalog_all())
        logger.info("KEV catalogue sync complete", **{k: v for k, v in result.items() if k != "failures"})
        return result
    except Exception as exc:
        logger.error("KEV catalogue sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=1800) from exc
