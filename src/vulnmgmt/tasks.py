"""Celery tasks for vulnerability management background processing"""

import asyncio
import json
from typing import Any, Optional

from celery import shared_task

from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.vulnmgmt.engine import (
    KEVMonitor,
    PatchOrchestrator,
    RiskPrioritizer,
    VulnerabilityLifecycle,
    VulnerabilityScanner,
)

logger = get_logger(__name__)


def run_async(coro):
    """Helper to run async code in sync context"""
    loop = asyncio.get_event_loop()
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
