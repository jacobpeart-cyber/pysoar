"""Celery tasks for background processing"""

import asyncio
import json
from typing import Any, Optional

from celery import shared_task

from src.core.logging import get_logger

logger = get_logger(__name__)


def run_async(coro):
    """Helper to run async code in sync context"""
    loop = asyncio.get_event_loop()
    if loop.is_running():
        import nest_asyncio
        nest_asyncio.apply()
    return loop.run_until_complete(coro)


@shared_task(bind=True, max_retries=3)
def enrich_ioc_task(
    self,
    ioc_id: str,
    ioc_type: str,
    ioc_value: str,
    providers: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Enrich an IOC with threat intelligence"""
    logger.info(
        "Starting IOC enrichment task",
        ioc_id=ioc_id,
        ioc_type=ioc_type,
    )

    try:
        from src.integrations.manager import threat_intel_manager

        if ioc_type == "ip":
            result = run_async(threat_intel_manager.enrich_ip(ioc_value, providers))
        elif ioc_type == "domain":
            result = run_async(threat_intel_manager.enrich_domain(ioc_value, providers))
        elif ioc_type in ["md5", "sha1", "sha256"]:
            result = run_async(threat_intel_manager.enrich_hash(ioc_value, providers))
        elif ioc_type == "url":
            result = run_async(threat_intel_manager.enrich_url(ioc_value, providers))
        else:
            result = {"error": f"Unsupported IOC type: {ioc_type}"}

        return {
            "ioc_id": ioc_id,
            "ioc_type": ioc_type,
            "enrichment": result,
        }

    except Exception as e:
        logger.error(
            "IOC enrichment task failed",
            ioc_id=ioc_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=60)


@shared_task
def send_notification_task(
    channel: str,
    recipients: list[str],
    subject: str,
    message: str,
    html_message: str = None,
) -> dict[str, Any]:
    """Send a notification via email, Slack, or Teams."""
    import asyncio

    logger.info(
        "Sending notification",
        channel=channel,
        recipients=recipients,
    )

    sent = False

    if channel == "email" and recipients:
        try:
            from src.services.email_service import EmailService
            email_service = EmailService()
            if email_service.is_configured:
                loop = asyncio.new_event_loop()
                sent = loop.run_until_complete(
                    email_service.send_email(
                        to=recipients,
                        subject=subject,
                        body=message,
                        html_body=html_message,
                    )
                )
                loop.close()
                logger.info(f"Email sent to {recipients}: {sent}")
            else:
                logger.warning("Email not configured, skipping")
        except Exception as e:
            logger.error(f"Email send failed: {e}")

    elif channel == "slack":
        try:
            import httpx
            from src.core.config import settings
            webhook_url = settings.slack_webhook_url
            if webhook_url:
                resp = httpx.post(webhook_url, json={"text": f"*{subject}*\n{message}"}, timeout=10)
                sent = resp.status_code == 200
                logger.info(f"Slack notification sent: {sent}")
        except Exception as e:
            logger.error(f"Slack send failed: {e}")

    elif channel == "teams":
        try:
            import httpx
            from src.core.config import settings
            webhook_url = settings.teams_webhook_url
            if webhook_url:
                resp = httpx.post(webhook_url, json={"text": f"**{subject}**\n\n{message}"}, timeout=10)
                sent = resp.status_code == 200
                logger.info(f"Teams notification sent: {sent}")
        except Exception as e:
            logger.error(f"Teams send failed: {e}")

    return {
        "channel": channel,
        "recipients": recipients,
        "sent": sent,
    }


@shared_task
def cleanup_old_executions() -> dict[str, Any]:
    """Clean up old playbook executions"""
    from datetime import datetime, timedelta, timezone

    logger.info("Running cleanup task for old executions")

    retention_days = 90
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cleaned_up = 0

    try:
        from src.core.database import async_session_factory
        from src.models.playbook import PlaybookExecution
        from sqlalchemy import delete

        loop = asyncio.new_event_loop()

        async def _cleanup():
            async with async_session_factory() as session:
                # Delete completed/failed executions older than the retention period
                result = await session.execute(
                    delete(PlaybookExecution).where(
                        PlaybookExecution.completed_at < cutoff.isoformat(),
                        PlaybookExecution.status.in_(["completed", "failed", "cancelled"]),
                    )
                )
                await session.commit()
                return result.rowcount

        cleaned_up = loop.run_until_complete(_cleanup())
        loop.close()
        logger.info(f"Cleaned up {cleaned_up} old executions (older than {retention_days} days)")

    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")

    return {
        "cleaned_up": cleaned_up,
        "task": "cleanup_old_executions",
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
    }


async def _refresh_stale_enrichments(
    staleness_days: int = 7,
    batch_limit: int = 100,
) -> dict[str, Any]:
    """Re-enrich active indicators whose enrichment is stale.

    "Stale" = ``last_seen`` (bumped on every enrichment) is older than
    ``staleness_days`` or has never been set. Whitelisted indicators are
    skipped — re-scoring them wastes provider quota. ``batch_limit``
    bounds external API usage per daily run.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import or_, select

    from src.core.database import async_session_factory
    from src.intel.enrichment import IndicatorEnricher
    from src.intel.models import ThreatIndicator

    cutoff = datetime.now(timezone.utc) - timedelta(days=staleness_days)

    async with async_session_factory() as session:
        result = await session.execute(
            select(ThreatIndicator.id)
            .where(
                ThreatIndicator.is_active == True,  # noqa: E712
                ThreatIndicator.is_whitelisted == False,  # noqa: E712
                or_(
                    ThreatIndicator.last_seen == None,  # noqa: E711
                    ThreatIndicator.last_seen < cutoff,
                ),
            )
            .order_by(ThreatIndicator.last_seen.asc().nulls_first())
            .limit(batch_limit)
        )
        stale_ids = [row[0] for row in result.all()]

    enricher = IndicatorEnricher()
    refreshed = 0
    for indicator_id in stale_ids:
        try:
            await enricher.enrich_indicator(indicator_id)
            refreshed += 1
        except Exception as e:
            logger.warning(
                "Enrichment refresh failed for indicator",
                indicator_id=indicator_id,
                error=str(e),
            )

    return {
        "refreshed": refreshed,
        "candidates": len(stale_ids),
        "staleness_days": staleness_days,
        "task": "refresh_ioc_enrichments",
    }


@shared_task
def refresh_ioc_enrichments() -> dict[str, Any]:
    """Re-enrich IOCs whose enrichment data has gone stale (daily beat)."""
    logger.info("Running IOC enrichment refresh task")
    return asyncio.run(_refresh_stale_enrichments())
