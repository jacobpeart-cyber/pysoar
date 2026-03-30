"""Celery tasks for SIEM log processing and analysis"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Optional

from celery import shared_task
from celery.schedules import schedule

from src.core.events import EventBus
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
def process_siem_log_task(
    self,
    raw_log: str,
    source_type: str,
    source_name: str,
    source_ip: str,
) -> dict[str, Any]:
    """Ingest a single raw log through the SIEM pipeline"""
    logger.info(
        "Processing single SIEM log",
        source_type=source_type,
        source_name=source_name,
    )

    try:
        from src.siem.storage import LogStorageManager
        from src.siem.models import Alert

        storage_manager = LogStorageManager()

        # Ingest the log through the pipeline
        log_record = storage_manager.ingest_log(
            raw_log=raw_log,
            source_type=source_type,
            source_name=source_name,
            source_ip=source_ip,
        )

        alerts_created = []

        # Check if rule matches were found
        if log_record and hasattr(log_record, "rule_matches") and log_record.rule_matches:
            for rule_match in log_record.rule_matches:
                alert = Alert(
                    log_id=log_record.id,
                    rule_id=rule_match.get("rule_id"),
                    severity=rule_match.get("severity", "medium"),
                    message=rule_match.get("message", "Rule matched"),
                    source=source_name,
                    timestamp=datetime.utcnow(),
                )
                # Save the alert
                alert.save()
                alerts_created.append(alert.id)

        return {
            "log_id": log_record.id if log_record else None,
            "source": source_name,
            "alerts_created": len(alerts_created),
            "alert_ids": alerts_created,
        }

    except Exception as e:
        logger.error(
            "SIEM log processing task failed",
            source_name=source_name,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def process_siem_batch_task(
    self,
    logs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Batch ingestion of logs"""
    logger.info(
        "Processing batch of SIEM logs",
        batch_size=len(logs),
    )

    try:
        from src.siem.storage import LogStorageManager
        from src.siem.models import Alert

        storage_manager = LogStorageManager()

        # Ingest batch of logs
        result = storage_manager.ingest_batch(logs)

        total_alerts = 0
        alert_ids = []

        # Process rule matches for each ingested log
        if result and "logs" in result:
            for log_record in result["logs"]:
                if hasattr(log_record, "rule_matches") and log_record.rule_matches:
                    for rule_match in log_record.rule_matches:
                        alert = Alert(
                            log_id=log_record.id,
                            rule_id=rule_match.get("rule_id"),
                            severity=rule_match.get("severity", "medium"),
                            message=rule_match.get("message", "Rule matched"),
                            source=log_record.source_name,
                            timestamp=datetime.utcnow(),
                        )
                        alert.save()
                        alert_ids.append(alert.id)
                        total_alerts += 1

        return {
            "batch_size": len(logs),
            "logs_ingested": result.get("count", 0) if result else 0,
            "alerts_created": total_alerts,
            "alert_ids": alert_ids,
        }

    except Exception as e:
        logger.error(
            "SIEM batch processing task failed",
            batch_size=len(logs),
            error=str(e),
        )
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=2)
def run_detection_rules_task(
    self,
    rule_id: str,
    time_range_hours: int = 24,
) -> dict[str, Any]:
    """Re-evaluate detection rules against recent logs"""
    logger.info(
        "Running detection rules evaluation",
        rule_id=rule_id,
        time_range_hours=time_range_hours,
    )

    try:
        from src.siem.storage import LogStorageManager
        from src.siem.detection import DetectionEngine
        from src.siem.models import Alert

        storage_manager = LogStorageManager()
        detection_engine = DetectionEngine()

        # Get logs from the specified time range
        cutoff_time = datetime.utcnow() - timedelta(hours=time_range_hours)
        logs = storage_manager.query_logs(
            filters={"timestamp__gte": cutoff_time}
        )

        matches_found = 0
        alerts_created = []

        # Evaluate the rule against all recent logs
        for log_record in logs:
            rule_match = detection_engine.evaluate_rule(rule_id, log_record)

            if rule_match:
                alert = Alert(
                    log_id=log_record.id,
                    rule_id=rule_id,
                    severity=rule_match.get("severity", "medium"),
                    message=rule_match.get("message", "Detection rule matched"),
                    source=log_record.source_name,
                    timestamp=datetime.utcnow(),
                )
                alert.save()
                alerts_created.append(alert.id)
                matches_found += 1

        return {
            "rule_id": rule_id,
            "logs_evaluated": len(logs),
            "matches_found": matches_found,
            "alerts_created": len(alerts_created),
            "alert_ids": alerts_created,
        }

    except Exception as e:
        logger.error(
            "Detection rules task failed",
            rule_id=rule_id,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=2)
def correlate_events_task(
    self,
    time_range_minutes: int = 60,
) -> dict[str, Any]:
    """Run the correlation engine on recent uncorrelated events"""
    logger.info(
        "Running event correlation",
        time_range_minutes=time_range_minutes,
    )

    try:
        from src.siem.correlation import CorrelationEngine
        from src.siem.storage import LogStorageManager
        from src.siem.models import CorrelationEvent

        storage_manager = LogStorageManager()
        correlation_engine = CorrelationEngine()

        # Get uncorrelated logs from the specified time range
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_range_minutes)
        uncorrelated_logs = storage_manager.query_logs(
            filters={
                "timestamp__gte": cutoff_time,
                "correlated": False,
            }
        )

        correlation_results = []

        # Process each uncorrelated event through the correlation engine
        for log_record in uncorrelated_logs:
            result = correlation_engine.process_event(log_record)

            if result and result.get("correlated"):
                # Create CorrelationEvent model instance for results
                correlation_event = CorrelationEvent(
                    correlation_id=result.get("correlation_id"),
                    log_ids=result.get("related_log_ids", [log_record.id]),
                    event_type=result.get("event_type"),
                    severity=result.get("severity", "medium"),
                    description=result.get("description"),
                    timestamp=datetime.utcnow(),
                )
                correlation_event.save()
                correlation_results.append(correlation_event.id)

                # Mark logs as correlated
                storage_manager.mark_correlated(
                    log_ids=result.get("related_log_ids", [log_record.id]),
                    correlation_id=result.get("correlation_id"),
                )

        return {
            "events_processed": len(uncorrelated_logs),
            "correlations_found": len(correlation_results),
            "correlation_event_ids": correlation_results,
        }

    except Exception as e:
        logger.error(
            "Event correlation task failed",
            error=str(e),
        )
        raise self.retry(exc=e, countdown=60)


@shared_task
def apply_retention_policy_task() -> dict[str, Any]:
    """Apply log retention policy and delete old logs"""
    logger.info("Applying SIEM retention policy")

    try:
        from src.siem.storage import LogStorageManager
        from src.core.config import get_config

        storage_manager = LogStorageManager()
        config = get_config()

        # Get retention period from config (default 90 days)
        retention_days = config.get("siem", {}).get("log_retention_days", 90)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        # Delete logs older than retention period
        deleted_count = storage_manager.delete_logs_before(cutoff_date)

        logger.info(
            "Retention policy applied",
            deleted_count=deleted_count,
            retention_days=retention_days,
        )

        return {
            "task": "apply_retention_policy",
            "deleted_records": deleted_count,
            "retention_days": retention_days,
        }

    except Exception as e:
        logger.error(
            "Retention policy task failed",
            error=str(e),
        )
        return {
            "task": "apply_retention_policy",
            "deleted_records": 0,
            "error": str(e),
        }


@shared_task
def update_siem_stats_task() -> dict[str, Any]:
    """Calculate and cache SIEM statistics"""
    logger.info("Updating SIEM statistics")

    try:
        from src.siem.storage import LogStorageManager
        from src.siem.analytics import StatsCalculator

        storage_manager = LogStorageManager()
        stats_calc = StatsCalculator()

        # Calculate statistics
        stats = {
            "total_logs": storage_manager.count_logs(),
            "logs_by_type": storage_manager.count_logs_by_type(),
            "logs_by_source": storage_manager.count_logs_by_source(),
            "logs_by_day": storage_manager.count_logs_by_day(),
            "ingestion_rate": stats_calc.calculate_ingestion_rate(),
            "rule_match_stats": stats_calc.calculate_rule_match_stats(),
            "alert_stats": stats_calc.calculate_alert_stats(),
            "timestamp": datetime.utcnow(),
        }

        # Cache the statistics
        stats_calc.cache_stats(stats)

        logger.info(
            "SIEM statistics updated",
            total_logs=stats["total_logs"],
        )

        return {
            "task": "update_siem_stats",
            "total_logs": stats["total_logs"],
            "logs_by_type_count": len(stats["logs_by_type"]),
            "logs_by_source_count": len(stats["logs_by_source"]),
            "cached": True,
        }

    except Exception as e:
        logger.error(
            "SIEM stats update task failed",
            error=str(e),
        )
        return {
            "task": "update_siem_stats",
            "cached": False,
            "error": str(e),
        }


@shared_task(bind=True, max_retries=2)
def import_siem_rules_task(
    self,
    rules_directory: str,
) -> dict[str, Any]:
    """Load detection rules from YAML files in a directory"""
    logger.info(
        "Importing SIEM rules from directory",
        directory=rules_directory,
    )

    try:
        import os
        import yaml
        from src.siem.models import DetectionRule

        if not os.path.isdir(rules_directory):
            raise ValueError(f"Rules directory does not exist: {rules_directory}")

        imported_count = 0
        updated_count = 0
        errors = []

        # Process all YAML files in the directory
        for filename in os.listdir(rules_directory):
            if not filename.endswith(".yaml") and not filename.endswith(".yml"):
                continue

            filepath = os.path.join(rules_directory, filename)

            try:
                with open(filepath, "r") as f:
                    rules_data = yaml.safe_load(f)

                # Handle both single rule and list of rules
                if isinstance(rules_data, dict):
                    rules_list = [rules_data]
                elif isinstance(rules_data, list):
                    rules_list = rules_data
                else:
                    errors.append(f"Invalid format in {filename}")
                    continue

                for rule_data in rules_list:
                    rule_id = rule_data.get("id")
                    name = rule_data.get("name")
                    description = rule_data.get("description", "")
                    detection_logic = rule_data.get("detection", {})
                    severity = rule_data.get("severity", "medium")

                    # Check if rule already exists
                    existing_rule = DetectionRule.objects.filter(rule_id=rule_id).first()

                    if existing_rule:
                        # Update existing rule
                        existing_rule.name = name
                        existing_rule.description = description
                        existing_rule.detection_logic = detection_logic
                        existing_rule.severity = severity
                        existing_rule.updated_at = datetime.utcnow()
                        existing_rule.save()
                        updated_count += 1
                    else:
                        # Create new rule
                        new_rule = DetectionRule(
                            rule_id=rule_id,
                            name=name,
                            description=description,
                            detection_logic=detection_logic,
                            severity=severity,
                            enabled=True,
                            created_at=datetime.utcnow(),
                        )
                        new_rule.save()
                        imported_count += 1

            except Exception as e:
                errors.append(f"Error processing {filename}: {str(e)}")

        return {
            "task": "import_siem_rules",
            "directory": rules_directory,
            "imported": imported_count,
            "updated": updated_count,
            "errors": errors,
        }

    except Exception as e:
        logger.error(
            "SIEM rules import task failed",
            directory=rules_directory,
            error=str(e),
        )
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True)
def start_collector_pipeline_task(
    self,
    redis_url: str = "redis://localhost:6379",
) -> dict[str, Any]:
    """Initialize and start the SIEM collector pipeline with event bus integration"""
    logger.info("Starting SIEM collector pipeline")

    try:
        from src.siem.collector import CollectorManager

        async def run_collectors():
            # Initialize event bus
            event_bus = EventBus(redis_url=redis_url)
            await event_bus.initialize()

            # Create collector manager and initialize collectors
            manager = CollectorManager(event_bus=event_bus)
            manager.initialize_collectors()

            # Start all collectors
            await manager.start_all()

            logger.info("All collectors started successfully")
            return {
                "status": "started",
                "collectors": list(manager.collectors.keys()),
            }

        result = run_async(run_collectors())
        return result

    except Exception as e:
        logger.error(
            "Failed to start collector pipeline",
            error=str(e),
        )
        raise self.retry(exc=e, countdown=30)


# Celery Beat Schedule Configuration
CELERY_BEAT_SCHEDULE = {
    "start-collector-pipeline": {
        "task": "src.siem.tasks.start_collector_pipeline_task",
        "schedule": 60 * 60,  # Every hour, but usually runs once at startup
        "options": {"queue": "siem"},
    },
    "apply-retention-policy": {
        "task": "src.siem.tasks.apply_retention_policy_task",
        "schedule": 6 * 60 * 60,  # Every 6 hours
        "options": {"queue": "siem"},
    },
    "update-siem-stats": {
        "task": "src.siem.tasks.update_siem_stats_task",
        "schedule": 5 * 60,  # Every 5 minutes
        "options": {"queue": "siem"},
    },
    "correlate-events": {
        "task": "src.siem.tasks.correlate_events_task",
        "schedule": 60,  # Every 1 minute
        "options": {"queue": "siem"},
    },
}
