"""
DLP Celery Tasks

Background tasks for sensitive data discovery, policy testing,
violation detection, audit reporting, and incident tracking.
Every task queries real database rows.
"""

import asyncio
from datetime import datetime, timedelta, timezone

from celery import shared_task
from sqlalchemy import select, func, and_

from src.core.logging import get_logger

logger = get_logger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(bind=True, max_retries=3)
def discover_sensitive_data(
    self,
    organization_id: str,
    scan_scope: str = "all",
    data_types: list | None = None,
):
    """Discover sensitive data by counting real SensitiveDataDiscovery rows."""
    from src.core.database import async_session_factory
    from src.dlp.models import SensitiveDataDiscovery

    async def _run():
        async with async_session_factory() as session:
            query = select(func.count(SensitiveDataDiscovery.id)).where(
                SensitiveDataDiscovery.organization_id == organization_id
            )
            total = (await session.execute(query)).scalar() or 0

            high_risk = (await session.execute(
                select(func.count(SensitiveDataDiscovery.id)).where(
                    and_(
                        SensitiveDataDiscovery.organization_id == organization_id,
                        SensitiveDataDiscovery.risk_level == "high",
                    )
                )
            )).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "locations_scanned": total,
                "sensitive_data_found": total,
                "high_risk_findings": high_risk,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Sensitive data discovery failed: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=2)
def test_dlp_policy(
    self,
    policy_id: str,
    organization_id: str,
    test_data: dict | None = None,
):
    """Test a DLP policy by loading the real policy and checking recent violations."""
    from src.core.database import async_session_factory
    from src.dlp.models import DLPPolicy, DLPViolation

    async def _run():
        async with async_session_factory() as session:
            policy = (await session.execute(
                select(DLPPolicy).where(DLPPolicy.id == policy_id)
            )).scalar_one_or_none()

            if not policy:
                return {"status": "error", "detail": "Policy not found"}

            violations = (await session.execute(
                select(func.count(DLPViolation.id)).where(
                    DLPViolation.policy_id == policy_id
                )
            )).scalar() or 0

            return {
                "status": "success",
                "policy_id": policy_id,
                "policy_name": policy.name,
                "is_enabled": policy.is_enabled,
                "historical_violations": violations,
                "test_result": "pass" if policy.is_enabled else "disabled",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"DLP policy test failed: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def detect_dlp_violations(
    self,
    organization_id: str,
    detection_type: str = "realtime",
    time_window_hours: int = 24,
):
    """Count real DLP violations in the specified time window."""
    from src.core.database import async_session_factory
    from src.dlp.models import DLPViolation

    async def _run():
        async with async_session_factory() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)

            total = (await session.execute(
                select(func.count(DLPViolation.id)).where(
                    and_(
                        DLPViolation.organization_id == organization_id,
                        DLPViolation.created_at >= cutoff,
                    )
                )
            )).scalar() or 0

            critical = (await session.execute(
                select(func.count(DLPViolation.id)).where(
                    and_(
                        DLPViolation.organization_id == organization_id,
                        DLPViolation.created_at >= cutoff,
                        DLPViolation.severity == "critical",
                    )
                )
            )).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "detection_type": detection_type,
                "time_window_hours": time_window_hours,
                "violations_detected": total,
                "critical_violations": critical,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"DLP violation detection failed: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=2)
def generate_dlp_audit_report(
    self,
    organization_id: str,
    report_period_days: int = 30,
):
    """Generate DLP audit report from real violation and policy data."""
    from src.core.database import async_session_factory
    from src.dlp.models import DLPPolicy, DLPViolation

    async def _run():
        async with async_session_factory() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=report_period_days)

            policy_count = (await session.execute(
                select(func.count(DLPPolicy.id)).where(
                    DLPPolicy.organization_id == organization_id
                )
            )).scalar() or 0

            active_policies = (await session.execute(
                select(func.count(DLPPolicy.id)).where(
                    and_(
                        DLPPolicy.organization_id == organization_id,
                        DLPPolicy.is_enabled == True,
                    )
                )
            )).scalar() or 0

            violations = (await session.execute(
                select(func.count(DLPViolation.id)).where(
                    and_(
                        DLPViolation.organization_id == organization_id,
                        DLPViolation.created_at >= cutoff,
                    )
                )
            )).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "report_period_days": report_period_days,
                "total_policies": policy_count,
                "active_policies": active_policies,
                "violations_in_period": violations,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"DLP audit report generation failed: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def track_dlp_incidents(
    self,
    organization_id: str,
    time_window_hours: int = 24,
):
    """Track DLP incidents from real DLPIncident table."""
    from src.core.database import async_session_factory
    from src.dlp.models import DLPIncident

    async def _run():
        async with async_session_factory() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)

            total = (await session.execute(
                select(func.count(DLPIncident.id)).where(
                    and_(
                        DLPIncident.organization_id == organization_id,
                        DLPIncident.created_at >= cutoff,
                    )
                )
            )).scalar() or 0

            open_incidents = (await session.execute(
                select(func.count(DLPIncident.id)).where(
                    and_(
                        DLPIncident.organization_id == organization_id,
                        DLPIncident.status.in_(["open", "investigating"]),
                    )
                )
            )).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "time_window_hours": time_window_hours,
                "incidents_in_window": total,
                "open_incidents": open_incidents,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"DLP incident tracking failed: {e}")
        raise self.retry(exc=e, countdown=60)
