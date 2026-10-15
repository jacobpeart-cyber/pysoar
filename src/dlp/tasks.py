"""
DLP Celery Tasks

Background tasks for the DLP content scan (``dlp_content_scan_sweep``, on
beat), policy evaluation status, violation / incident counts and audit
reports. Every task queries real database rows.
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


@shared_task(bind=True, max_retries=0)
def discover_sensitive_data(
    self,
    organization_id: str,
    scan_scope: str = "all",
    data_types: list | None = None,
):
    """Not implemented: no discovery agent or storage connector exists.

    This used to count ``sensitive_data_discoveries`` rows (and read a
    ``risk_level`` column that does not exist) and report them as
    "locations scanned". Content the platform holds is scanned by
    ``dlp_content_scan_sweep`` instead.
    """
    return {
        "status": "not_implemented",
        "organization_id": organization_id,
        "detail": (
            "sensitive data discovery over endpoints / storage is not implemented: no "
            "DLP agent or storage connector exists; stored platform content is scanned "
            "by dlp_content_scan_sweep"
        ),
    }


# ---------------------------------------------------------------------------
# Wave 4: the content scan (beat entry in src/workers/celery_app.py)
# ---------------------------------------------------------------------------
async def _content_scan_sweep(organization_id: str | None = None) -> dict:
    from src.core.database import async_session_factory
    from src.dlp.models import DLPPolicy
    from src.dlp.scanner import MAX_ORGS_PER_SWEEP, scan_organization

    if organization_id:
        org_ids = [organization_id]
    else:
        async with async_session_factory() as session:
            org_ids = [
                o for o in (await session.execute(
                    select(DLPPolicy.organization_id)
                    .where(DLPPolicy.enabled.is_(True))
                    .distinct()
                    .limit(MAX_ORGS_PER_SWEEP)
                )).scalars().all() if o
            ]
    rows = findings = 0
    failures: list[dict] = []
    for oid in org_ids:
        try:
            async with async_session_factory() as session:
                summary = await scan_organization(session, oid)
                await session.commit()
            rows += summary["rows_scanned"]
            findings += summary["findings_created"]
        except Exception as exc:  # one org failing must not stop the sweep
            logger.error("dlp_content_scan_failed", organization_id=oid, error=str(exc))
            failures.append({"organization_id": oid, "error": str(exc)[:500]})
    return {
        "organizations": len(org_ids),
        "rows_scanned": rows,
        "findings_created": findings,
        "failures": failures,
    }


@shared_task(bind=True, max_retries=1)
def dlp_content_scan_sweep(self, organization_id: str | None = None):
    """Evaluate every org's active DLP policies over newly stored logs,
    evidence, ticket comments and incident / case-note text (bounded)."""
    try:
        result = _run_async(_content_scan_sweep(organization_id))
        logger.info("dlp_content_scan_complete", **{k: v for k, v in result.items() if k != "failures"})
        return result
    except Exception as exc:
        logger.error("dlp_content_scan_sweep_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300) from exc


@shared_task(bind=True, max_retries=2)
def test_dlp_policy(
    self,
    policy_id: str,
    organization_id: str,
    test_data: dict | None = None,
):
    """Report a policy's real evaluation status and its stored violations."""
    from src.core.database import async_session_factory
    from src.dlp.models import DLPPolicy, DLPViolation

    async def _run():
        async with async_session_factory() as session:
            policy = (await session.execute(
                select(DLPPolicy).where(
                    DLPPolicy.id == policy_id,
                    DLPPolicy.organization_id == organization_id,
                )
            )).scalar_one_or_none()

            if not policy:
                return {"status": "error", "detail": "Policy not found"}

            from src.dlp.scanner import plan_policy

            violations = (await session.execute(
                select(func.count(DLPViolation.id)).where(
                    DLPViolation.policy_id == policy_id,
                    DLPViolation.organization_id == organization_id,
                )
            )).scalar() or 0
            plan = plan_policy(policy)

            return {
                "status": "success",
                "policy_id": policy_id,
                "policy_name": policy.name,
                "is_enabled": policy.enabled,
                "historical_violations": violations,
                "evaluation_status": plan.status,
                "evaluation_reason": plan.reason,
                "sources": plan.sources,
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
                        DLPPolicy.enabled.is_(True),
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
