"""Celery tasks for Threat Intelligence Platform

Only feed polling lives here. Six placeholder tasks (enrich_new_indicators,
check_indicator_expiration, update_ioc_cache, generate_intel_summary,
correlate_indicators_with_logs, sync_mitre_mappings) were deleted in wave 1:
they returned hard-coded zero counts, were never scheduled and nothing called
them. IOC enrichment refresh runs as ``src.workers.tasks.refresh_ioc_enrichments``.
"""

from typing import Any

from celery import shared_task

from src.core.logging import get_logger

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3, name="intel.poll_threat_feeds")
def poll_threat_feeds(self) -> dict[str, Any]:
    """Poll all enabled threat feeds for new indicators.

    Actually calls FeedManager.poll_all_feeds() (which for each enabled
    feed: fetches, parses, dedupes, and writes ThreatIndicator rows).
    """
    import asyncio

    try:
        logger.info("Starting threat feed polling task")

        from src.intel.feeds import FeedManager

        async def _run() -> dict[str, int]:
            manager = FeedManager()
            return await manager.poll_all_feeds()

        per_feed = asyncio.run(_run())
        total = sum(int(v or 0) for v in per_feed.values())

        results = {
            "task": "poll_threat_feeds",
            "feeds_polled": len(per_feed),
            "total_indicators_ingested": total,
            "per_feed": per_feed,
        }
        logger.info("Threat feed polling complete", **results)
        return results

    except Exception as e:
        logger.error("Threat feed polling task failed", error=str(e))
        raise self.retry(exc=e, countdown=300)  # Retry after 5 minutes
