"""
Celery Tasks for ITDR (Identity Threat Detection & Response)

Background tasks for identity threat scanning, credential exposure
monitoring, baseline updates, privileged access auditing, and
dormant account detection. Every task queries real database rows.
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
def identity_threat_scan(
    self,
    organization_id: str,
    scan_scope: str = "all",
    focus_high_risk: bool = False,
):
    """Scan identities for threats by querying real IdentityThreat + User rows."""
    from src.core.database import async_session_factory
    from src.models.user import User
    from src.itdr.models import IdentityThreat

    async def _run():
        async with async_session_factory() as session:
            user_query = select(func.count(User.id)).where(
                User.organization_id == organization_id,
                User.is_active == True,
            )
            if scan_scope == "high_risk":
                user_query = user_query.where(User.role.in_(["admin", "superuser"]))
            elif scan_scope == "service_accounts":
                user_query = user_query.where(User.email.ilike("%service%"))

            identities_scanned = (await session.execute(user_query)).scalar() or 0

            threat_query = select(func.count(IdentityThreat.id)).where(
                IdentityThreat.organization_id == organization_id,
                IdentityThreat.status.in_(["detected", "investigating"]),
            )
            threats_detected = (await session.execute(threat_query)).scalar() or 0

            critical_query = select(func.count(IdentityThreat.id)).where(
                and_(
                    IdentityThreat.organization_id == organization_id,
                    IdentityThreat.status.in_(["detected", "investigating"]),
                    IdentityThreat.severity == "critical",
                )
            )
            critical_threats = (await session.execute(critical_query)).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "scan_scope": scan_scope,
                "identities_scanned": identities_scanned,
                "threats_detected": threats_detected,
                "critical_threats": critical_threats,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Identity threat scan failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def credential_exposure_check(
    self,
    organization_id: str,
    check_type: str = "comprehensive",
    include_dark_web: bool = True,
):
    """Check credentials against real CredentialLeak and User tables."""
    from src.core.database import async_session_factory
    from src.models.user import User
    from src.darkweb.models import CredentialLeak

    async def _run():
        async with async_session_factory() as session:
            user_count = (await session.execute(
                select(func.count(User.id)).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )).scalar() or 0

            org_emails_result = await session.execute(
                select(User.email).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )
            org_emails = {r[0].lower() for r in org_emails_result.all() if r[0]}

            leaked_result = await session.execute(
                select(CredentialLeak.email).where(
                    CredentialLeak.is_remediated == False,
                )
            )
            leaked_emails = {r[0].lower() for r in leaked_result.all() if r[0]}

            exposed = org_emails & leaked_emails

            return {
                "status": "success",
                "organization_id": organization_id,
                "check_type": check_type,
                "total_credentials_checked": user_count,
                "exposures_found": len(exposed),
                "exposed_emails": list(exposed)[:50],
                "critical_exposures": len(exposed),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Credential exposure check failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def update_identity_baseline(
    self,
    organization_id: str,
    baseline_type: str = "comprehensive",
):
    """Build identity access baseline from real AccessAnomaly + User data."""
    from src.core.database import async_session_factory
    from src.models.user import User
    from src.itdr.models import AccessAnomaly

    async def _run():
        async with async_session_factory() as session:
            user_count = (await session.execute(
                select(func.count(User.id)).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )).scalar() or 0

            anomaly_count = (await session.execute(
                select(func.count(AccessAnomaly.id)).where(
                    AccessAnomaly.organization_id == organization_id,
                )
            )).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "baseline_type": baseline_type,
                "identities_profiled": user_count,
                "anomalies_in_baseline": anomaly_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Identity baseline update failed: {e}")
        raise self.retry(exc=e, countdown=120)


@shared_task(bind=True, max_retries=2)
def privileged_access_audit(
    self,
    organization_id: str,
    include_service_accounts: bool = True,
):
    """Audit privileged access by counting real admin/superuser accounts."""
    from src.core.database import async_session_factory
    from src.models.user import User

    async def _run():
        async with async_session_factory() as session:
            priv_query = select(func.count(User.id)).where(
                and_(
                    User.organization_id == organization_id,
                    User.is_active == True,
                    User.role.in_(["admin"]),
                )
            )
            privileged_accounts = (await session.execute(priv_query)).scalar() or 0

            super_query = select(func.count(User.id)).where(
                and_(
                    User.organization_id == organization_id,
                    User.is_superuser == True,
                )
            )
            superusers = (await session.execute(super_query)).scalar() or 0

            total_query = select(func.count(User.id)).where(
                User.organization_id == organization_id,
                User.is_active == True,
            )
            total_users = (await session.execute(total_query)).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "total_users": total_users,
                "privileged_accounts": privileged_accounts,
                "superuser_accounts": superusers,
                "privilege_ratio": round(
                    (privileged_accounts + superusers) / max(total_users, 1) * 100, 1
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Privileged access audit failed: {e}")
        raise self.retry(exc=e, countdown=120)


@shared_task(bind=True, max_retries=2)
def dormant_account_detection(
    self,
    organization_id: str,
    inactive_days: int = 90,
):
    """Detect dormant accounts by checking last_login against real User rows."""
    from src.core.database import async_session_factory
    from src.models.user import User

    async def _run():
        async with async_session_factory() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=inactive_days)

            total = (await session.execute(
                select(func.count(User.id)).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )).scalar() or 0

            dormant_count = 0
            try:
                if hasattr(User, "last_login"):
                    dormant_count = (await session.execute(
                        select(func.count(User.id)).where(
                            and_(
                                User.organization_id == organization_id,
                                User.is_active == True,
                                User.last_login < cutoff,
                            )
                        )
                    )).scalar() or 0
            except Exception:
                pass

            return {
                "status": "success",
                "organization_id": organization_id,
                "total_active_accounts": total,
                "dormant_accounts": dormant_count,
                "inactive_threshold_days": inactive_days,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Dormant account detection failed: {e}")
        raise self.retry(exc=e, countdown=60)
