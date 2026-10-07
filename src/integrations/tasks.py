"""Celery tasks for integration management and monitoring.

Each task delegates to a module-level ``_*_async`` coroutine so the real
logic is directly awaitable from tests (and anywhere else that already
has an event loop), while the Celery entrypoints bridge via
``run_async`` exactly like the other task modules.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import delete, or_, select, update

from src.core.logging import get_logger
from src.siem.tasks import run_async

logger = get_logger(__name__)


# --- Memory bounds ---------------------------------------------------------
# Every housekeeping task here used to materialise its whole candidate set
# with one ``.scalars().all()`` (rate_limit_reset as full ORM rows mutated
# one by one under a single commit; connector_update_check as every
# connector row; the health check as every installed-integration id). They
# now walk the table in keyset windows of INTEGRATIONS_BATCH_SIZE on the
# primary key, read only the columns they use, write with bulk UPDATEs by
# id, and commit per window. A per-run cap that fires sets ``truncated``.
INTEGRATIONS_BATCH_SIZE = 1_000
MAX_HEALTH_CHECKS_PER_RUN = 10_000
MAX_RATE_LIMIT_RESETS_PER_RUN = 50_000
MAX_CONNECTORS_PER_RUN = 50_000


def _version_tuple(version: Optional[str]) -> tuple:
    """Parse a version string into a comparable tuple of ints."""
    if not version:
        return (0,)
    parts = tuple(int(p) for p in re.findall(r"\d+", version))
    return parts or (0,)


def _parse_timestamp(raw: Optional[str]) -> Optional[datetime]:
    """Best-effort ISO-8601 parse of a stored timestamp string."""
    if not raw:
        return None
    try:
        ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except ValueError:
        return None


async def _health_check_all_integrations_async(
    organization_id: Optional[str] = None,
) -> dict[str, Any]:
    """Probe every installed integration and persist its health status.

    Delegates each check to ``IntegrationManager.test_connection``,
    which issues a real HTTP probe against the third-party API and
    updates ``health_status`` / ``last_health_check`` on the row.
    """
    from src.core.database import async_session_factory
    from src.integrations.engine import ConnectorRegistry, IntegrationManager
    from src.integrations.models import InstalledIntegration

    manager = IntegrationManager(ConnectorRegistry())
    health_results: dict[str, Any] = {
        "total_checked": 0,
        "healthy": 0,
        "degraded": 0,
        "unhealthy": 0,
        "unknown": 0,
    }
    status_keys = ("healthy", "degraded", "unhealthy", "unknown")

    # Ids are paged one window at a time (each window's session closed
    # before its probes run, as before) instead of listing every id up front.
    last_id: Optional[str] = None
    cap_hit = False
    while health_results["total_checked"] < MAX_HEALTH_CHECKS_PER_RUN:
        window = min(
            INTEGRATIONS_BATCH_SIZE,
            MAX_HEALTH_CHECKS_PER_RUN - health_results["total_checked"],
        )
        async with async_session_factory() as db:
            stmt = select(InstalledIntegration.id).where(
                InstalledIntegration.status != "inactive",
            )
            if organization_id:
                stmt = stmt.where(
                    InstalledIntegration.organization_id == organization_id,
                )
            if last_id is not None:
                stmt = stmt.where(InstalledIntegration.id > last_id)
            integration_ids = list(
                (
                    await db.execute(
                        stmt.order_by(InstalledIntegration.id).limit(window),
                    )
                ).scalars(),
            )
        if not integration_ids:
            break
        last_id = integration_ids[-1]

        for integration_id in integration_ids:
            outcome = await manager.test_connection(integration_id)
            status_key = outcome.get("status") or "unknown"
            if status_key not in status_keys:
                status_key = "unknown"
            health_results[status_key] += 1
            health_results["total_checked"] += 1

        if len(integration_ids) < window:
            break
    else:
        cap_hit = True

    if cap_hit:
        logger.warning(
            f"health_check_all_integrations: hit per-run cap of "
            f"{MAX_HEALTH_CHECKS_PER_RUN} integrations; remainder deferred",
        )
    health_results["truncated"] = cap_hit
    health_results["timestamp"] = datetime.now(timezone.utc).isoformat()
    return health_results


async def _webhook_cleanup_async(days_old: int = 90) -> dict[str, Any]:
    """Delete deactivated webhook endpoints not updated in ``days_old`` days.

    Active endpoints are never deleted regardless of age — they are live
    configuration, not history. (There is no separate webhook-event
    table; per-event payloads are not persisted.)
    """
    from src.core.database import async_session_factory
    from src.integrations.models import WebhookEndpoint

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)

    async with async_session_factory() as db:
        result = await db.execute(
            delete(WebhookEndpoint).where(
                WebhookEndpoint.is_active.is_(False),
                WebhookEndpoint.updated_at < cutoff_date,
            ),
        )
        await db.commit()
        deleted_count = result.rowcount or 0

    return {
        "status": "success",
        "deleted_count": deleted_count,
        "cutoff_date": cutoff_date.isoformat(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def _execution_cleanup_async(days_old: int = 30) -> dict[str, Any]:
    """Delete integration execution history older than ``days_old`` days."""
    from src.core.database import async_session_factory
    from src.integrations.models import IntegrationExecution

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)

    async with async_session_factory() as db:
        result = await db.execute(
            delete(IntegrationExecution).where(
                IntegrationExecution.created_at < cutoff_date,
            ),
        )
        await db.commit()
        deleted_count = result.rowcount or 0

    return {
        "status": "success",
        "deleted_count": deleted_count,
        "cutoff_date": cutoff_date.isoformat(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def _rate_limit_reset_async() -> dict[str, Any]:
    """Clear expired rate-limit tracking on installed integrations.

    Any integration carrying rate-limit state whose ``rate_limit_reset``
    timestamp has passed (or was never recorded) gets its counters
    cleared; integrations parked in ``rate_limited`` status are flipped
    back to ``active``. Future-dated reset windows are left alone.
    """
    from src.core.database import async_session_factory
    from src.integrations.models import InstalledIntegration, IntegrationStatus

    now = datetime.now(timezone.utc)
    reset_count = 0
    scanned = 0
    cap_hit = False
    last_id: Optional[str] = None
    rate_limited = IntegrationStatus.RATE_LIMITED.value

    async with async_session_factory() as db:
        while scanned < MAX_RATE_LIMIT_RESETS_PER_RUN:
            window = min(INTEGRATIONS_BATCH_SIZE, MAX_RATE_LIMIT_RESETS_PER_RUN - scanned)
            stmt = select(
                InstalledIntegration.id,
                InstalledIntegration.rate_limit_reset,
                InstalledIntegration.status,
            ).where(
                or_(
                    InstalledIntegration.rate_limit_remaining.isnot(None),
                    InstalledIntegration.rate_limit_reset.isnot(None),
                    InstalledIntegration.status == rate_limited,
                ),
            )
            if last_id is not None:
                stmt = stmt.where(InstalledIntegration.id > last_id)
            rows = (
                await db.execute(stmt.order_by(InstalledIntegration.id).limit(window))
            ).all()
            if not rows:
                break
            last_id = rows[-1].id
            scanned += len(rows)

            to_reset: list[str] = []
            to_reactivate: list[str] = []
            for row in rows:
                reset_at = _parse_timestamp(row.rate_limit_reset)
                if reset_at and reset_at > now:
                    # Rate-limit window still open — don't lie about capacity.
                    continue
                to_reset.append(row.id)
                if row.status == rate_limited:
                    to_reactivate.append(row.id)

            if to_reset:
                await db.execute(
                    update(InstalledIntegration)
                    .where(InstalledIntegration.id.in_(to_reset))
                    .values(rate_limit_remaining=None, rate_limit_reset=None)
                    .execution_options(synchronize_session=False),
                )
            if to_reactivate:
                await db.execute(
                    update(InstalledIntegration)
                    .where(InstalledIntegration.id.in_(to_reactivate))
                    .values(status=IntegrationStatus.ACTIVE.value)
                    .execution_options(synchronize_session=False),
                )
            reset_count += len(to_reset)
            await db.commit()
            db.expunge_all()

            if len(rows) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            f"rate_limit_reset: hit per-run cap of {MAX_RATE_LIMIT_RESETS_PER_RUN} "
            f"integrations; remainder deferred",
        )
    return {
        "status": "success",
        "reset_count": reset_count,
        "truncated": cap_hit,
        "timestamp": now.isoformat(),
    }


async def _connector_update_check_async() -> dict[str, Any]:
    """Compare DB connector versions against the built-in registry.

    There is no remote marketplace to query — the only source of newer
    connector versions is the code-shipped ``BUILTIN_CONNECTORS``
    registry, whose version bumps do NOT propagate to existing
    ``integration_connectors`` rows on re-seed. This task reports those
    genuine drift cases; anything beyond that does not exist to check.
    """
    from src.core.database import async_session_factory
    from src.integrations.engine import ConnectorRegistry
    from src.integrations.models import IntegrationConnector

    registry = ConnectorRegistry()

    available_updates: list[dict[str, Any]] = []
    scanned = 0
    cap_hit = False
    last_id: Optional[str] = None

    async with async_session_factory() as db:
        while scanned < MAX_CONNECTORS_PER_RUN:
            window = min(INTEGRATIONS_BATCH_SIZE, MAX_CONNECTORS_PER_RUN - scanned)
            stmt = select(
                IntegrationConnector.id,
                IntegrationConnector.name,
                IntegrationConnector.display_name,
                IntegrationConnector.version,
            )
            if last_id is not None:
                stmt = stmt.where(IntegrationConnector.id > last_id)
            rows = (
                await db.execute(stmt.order_by(IntegrationConnector.id).limit(window))
            ).all()
            if not rows:
                break
            last_id = rows[-1].id
            scanned += len(rows)

            for row in rows:
                registry_meta = registry.get_connector_details(row.name)
                if not registry_meta:
                    continue
                registry_version = registry_meta.get("version") or "1.0.0"
                if _version_tuple(registry_version) > _version_tuple(row.version):
                    available_updates.append(
                        {
                            "connector": row.name,
                            "display_name": row.display_name,
                            "installed_version": row.version,
                            "available_version": registry_version,
                        },
                    )

            if len(rows) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            f"connector_update_check: hit per-run cap of {MAX_CONNECTORS_PER_RUN} "
            f"connectors; remainder deferred",
        )
    return {
        "status": "success",
        "source": "builtin_registry",
        "available_updates": available_updates,
        "truncated": cap_hit,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@shared_task(bind=True, max_retries=3)
def health_check_all_integrations(self, organization_id: Optional[str] = None):
    """
    Periodically check health of all installed integrations.

    Probes each integration's third-party API through
    ``IntegrationManager.test_connection`` and persists the resulting
    ``health_status`` / ``last_health_check`` on each row.

    Args:
        organization_id: Optional organization to check. If None, check all.

    Returns:
        Dictionary with health check results and statistics
    """
    try:
        logger.info(
            f"Starting health check for integrations "
            f"(org={organization_id or 'all'})",
        )

        health_results = run_async(
            _health_check_all_integrations_async(organization_id),
        )

        logger.info(f"Health check complete: {health_results}")

        return health_results

    except Exception as e:
        logger.error(f"Health check task failed: {e}")
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=300 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def webhook_cleanup(self, days_old: int = 90):
    """
    Clean up old webhook endpoint records.

    Deletes webhook endpoints that are deactivated (``is_active=False``)
    and have not been updated in ``days_old`` days. Active endpoints are
    live configuration and are never deleted by age.

    Args:
        days_old: Delete deactivated webhook records older than this many days

    Returns:
        Dictionary with cleanup statistics
    """
    try:
        logger.info(f"Starting webhook cleanup (retention: {days_old} days)")

        result = run_async(_webhook_cleanup_async(days_old))

        logger.info(
            f"Webhook cleanup complete: {result['deleted_count']} records deleted",
        )

        return result

    except Exception as e:
        logger.error(f"Webhook cleanup task failed: {e}")
        raise self.retry(exc=e, countdown=600 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def execution_cleanup(self, days_old: int = 30):
    """
    Clean up old integration execution records.

    Deletes ``integration_executions`` rows created more than
    ``days_old`` days ago.

    Args:
        days_old: Delete execution records older than this many days

    Returns:
        Dictionary with cleanup statistics
    """
    try:
        logger.info(f"Starting execution cleanup (retention: {days_old} days)")

        result = run_async(_execution_cleanup_async(days_old))

        logger.info(
            f"Execution cleanup complete: {result['deleted_count']} records deleted",
        )

        return result

    except Exception as e:
        logger.error(f"Execution cleanup task failed: {e}")
        raise self.retry(exc=e, countdown=600 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def rate_limit_reset(self):
    """
    Reset expired rate limit counters for all integrations.

    Called periodically (e.g., hourly). Clears ``rate_limit_remaining``
    / ``rate_limit_reset`` on rows whose reset window has passed and
    flips ``rate_limited`` integrations back to ``active``.

    Returns:
        Dictionary with reset statistics
    """
    try:
        logger.info("Starting rate limit reset")

        result = run_async(_rate_limit_reset_async())

        logger.info(
            f"Rate limit reset complete: {result['reset_count']} integrations reset",
        )

        return result

    except Exception as e:
        logger.error(f"Rate limit reset task failed: {e}")
        raise self.retry(exc=e, countdown=300 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def connector_update_check(self):
    """
    Check for available connector updates.

    There is no remote marketplace — the only update source that exists
    is the code-shipped built-in registry, so this compares each
    ``integration_connectors`` row's version against the registry and
    reports genuine version drift (seeding does not bump versions on
    existing rows).

    Returns:
        Dictionary with available updates
    """
    try:
        logger.info("Starting connector update check")

        result = run_async(_connector_update_check_async())

        logger.info(
            f"Update check complete: {len(result['available_updates'])} updates available",
        )

        return result

    except Exception as e:
        logger.error(f"Connector update check task failed: {e}")
        raise self.retry(exc=e, countdown=600 * (2 ** self.request.retries))
