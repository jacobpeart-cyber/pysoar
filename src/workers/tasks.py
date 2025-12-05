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
def execute_playbook_task(
    self,
    execution_id: str,
    playbook_id: str,
    steps: list[dict[str, Any]],
    input_data: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Execute a playbook asynchronously"""
    logger.info(
        "Starting playbook execution task",
        execution_id=execution_id,
        playbook_id=playbook_id,
    )

    try:
        # Import here to avoid circular imports
        from src.playbooks.engine import PlaybookEngine
        from src.models.playbook import PlaybookExecution

        # Create execution object
        execution = PlaybookExecution(
            id=execution_id,
            playbook_id=playbook_id,
        )

        # Run the playbook
        engine = PlaybookEngine()
        result = run_async(engine.execute(execution, steps, input_data))

        return {
            "execution_id": execution_id,
            "status": result.status,
            "steps_completed": result.current_step,
            "error": result.error_message,
        }

    except Exception as e:
        logger.error(
            "Playbook execution task failed",
            execution_id=execution_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=60)


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
def process_alert_task(alert_data: dict[str, Any]) -> dict[str, Any]:
    """Process an incoming alert"""
    logger.info("Processing alert", alert_id=alert_data.get("id"))

    # This would typically:
    # 1. Deduplicate alerts
    # 2. Enrich IOCs found in the alert
    # 3. Check for matching playbook triggers
    # 4. Update alert with enrichment data

    return {
        "alert_id": alert_data.get("id"),
        "processed": True,
    }


@shared_task
def send_notification_task(
    channel: str,
    recipients: list[str],
    subject: str,
    message: str,
) -> dict[str, Any]:
    """Send a notification via various channels"""
    logger.info(
        "Sending notification",
        channel=channel,
        recipients=recipients,
    )

    # This would integrate with email, Slack, Teams, etc.
    # For now, just log and return success

    return {
        "channel": channel,
        "recipients": recipients,
        "sent": True,
    }


@shared_task
def cleanup_old_executions() -> dict[str, Any]:
    """Clean up old playbook executions"""
    logger.info("Running cleanup task for old executions")

    # This would delete executions older than retention period
    # For now, just return a placeholder

    return {
        "cleaned_up": 0,
        "task": "cleanup_old_executions",
    }


@shared_task
def refresh_ioc_enrichments() -> dict[str, Any]:
    """Refresh stale IOC enrichments"""
    logger.info("Running IOC enrichment refresh task")

    # This would find IOCs with stale enrichment data and re-enrich them

    return {
        "refreshed": 0,
        "task": "refresh_ioc_enrichments",
    }


@shared_task
def check_scheduled_playbooks() -> dict[str, Any]:
    """Check for playbooks that need to run on schedule"""
    logger.info("Checking for scheduled playbooks")

    # This would check playbooks with trigger_type="scheduled"
    # and execute them if their schedule matches

    return {
        "executed": 0,
        "task": "check_scheduled_playbooks",
    }


@shared_task
def ingest_alerts_from_source(
    source: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Ingest alerts from an external source"""
    logger.info(f"Ingesting alerts from {source}")

    # This would connect to SIEM, EDR, or other sources
    # and import alerts

    return {
        "source": source,
        "imported": 0,
    }


@shared_task
def generate_report_task(
    report_type: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Generate a report"""
    logger.info(f"Generating {report_type} report")

    # This would generate various reports:
    # - Daily/weekly summary
    # - Incident timeline
    # - IOC report
    # - Metrics dashboard

    return {
        "report_type": report_type,
        "generated": True,
        "url": None,  # Would contain report URL/path
    }
