"""Celery tasks for SIEM log processing.

Only the cloud-log poller lives here. Eight earlier tasks
(``process_siem_log_task``, ``process_siem_batch_task``,
``run_detection_rules_task``, ``correlate_events_task``,
``apply_retention_policy_task``, ``update_siem_stats_task``,
``import_siem_rules_task``, ``start_collector_pipeline_task``) and their
unused ``CELERY_BEAT_SCHEDULE`` were deleted in wave 1: they imported
modules and model APIs that do not exist (``src.siem.models.Alert``,
``DetectionRule.objects``, ``src.siem.detection``, ``src.siem.analytics``,
storage methods such as ``query_logs``), so every run failed, and
``correlate_events_task`` would have correlated every tenant's logs in one
shared engine and written organisation-less correlation rows. Ingestion,
detection and correlation run per organisation in ``src.siem.pipeline``.
"""

import asyncio
from typing import Any

from celery import shared_task

from src.core.logging import get_logger

logger = get_logger(__name__)


def run_async(coro):
    """Helper to run async code in sync context.

    A Celery prefork worker thread has no event loop, and once any prior
    ``asyncio.run()`` in the process has cleared it, ``get_event_loop()``
    raises ``RuntimeError`` (Python 3.10+ no longer auto-creates one).
    Create a fresh loop in that case so beat-scheduled tasks don't fail
    every run with "There is no current event loop in thread 'MainThread'".
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


@shared_task(bind=True, max_retries=2, name="siem.poll_cloud_integrations")
def poll_cloud_integrations_task(self) -> dict[str, Any]:
    """Run every 5 minutes via Celery beat — pulls AWS CloudTrail,
    Azure Activity Log, and GCP Cloud Logging for every installed
    cloud integration into log_entries.

    Each poller persists ``last_poll_at`` on its integration row so
    subsequent runs only fetch incremental events.
    """
    async def _runner() -> dict[str, Any]:
        from src.core.database import async_session_factory
        from src.siem.cloud_poller import poll_all_cloud_integrations
        async with async_session_factory() as db:
            results = await poll_all_cloud_integrations(db)
            await db.commit()
        return {"polled": len(results), "results": results}

    try:
        return run_async(_runner())
    except Exception as exc:  # noqa: BLE001 - logged, then retried; the last failure propagates
        logger.error("Cloud poll task failed", error=str(exc), exc_info=True)
        # self.retry raises Retry (or re-raises exc once retries are used
        # up); it used to be swallowed here, so the task never retried.
        raise self.retry(exc=exc, countdown=60)
