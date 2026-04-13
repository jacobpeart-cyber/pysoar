"""
UEBA Celery Tasks
Background tasks for behavior analysis, baseline updates, and alert generation.
"""

from datetime import datetime, timedelta
from celery import shared_task

from src.core.logging import get_logger
from src.core.config import settings
from src.ueba.engine import (
    BehaviorAnalyzer,
    RiskScorer,
    ImpossibleTravelDetector,
    PeerGroupAnalyzer,
    BaselineManager,
)

logger = get_logger(__name__)

# Initialize components
baseline_manager = BaselineManager()
behavior_analyzer = BehaviorAnalyzer(baseline_manager)
risk_scorer = RiskScorer()
travel_detector = ImpossibleTravelDetector()
peer_analyzer = PeerGroupAnalyzer()


@shared_task(bind=True, max_retries=3)
def process_behavior_events(self, organization_id: str, event_batch: list[dict]) -> dict:
    """
    Ingest and analyze new behavior events.

    Processes a batch of behavior events, analyzes them for anomalies,
    and creates alerts if needed.

    Args:
        organization_id: Organization context
        event_batch: List of behavior event dictionaries

    Returns:
        Dictionary with processing results
    """
    try:
        logger.info(f"Processing {len(event_batch)} behavior events for org {organization_id}")

        processed_count = 0
        anomaly_count = 0
        alerts_created = 0

        for event in event_batch:
            entity_id = event.get("entity_id")
            event_type = event.get("event_type")

            # Analyze based on event type
            if event_type == "authentication":
                analysis = behavior_analyzer.analyze_authentication(entity_id, event)
            elif event_type == "resource_access":
                analysis = behavior_analyzer.analyze_data_access(entity_id, event)
            elif event_type == "network_connection":
                analysis = behavior_analyzer.analyze_network_activity(entity_id, event)
            elif event_type == "privilege_change":
                analysis = behavior_analyzer.analyze_privilege_usage(entity_id, event)
            else:
                continue

            processed_count += 1

            if analysis.get("is_anomalous"):
                anomaly_count += 1
                # In production, create alert in database
                alerts_created += len(analysis.get("anomalies", []))

        logger.info(
            f"Processed {processed_count} events: {anomaly_count} anomalies, {alerts_created} alerts"
        )

        return {
            "status": "completed",
            "processed_count": processed_count,
            "anomaly_count": anomaly_count,
            "alerts_created": alerts_created
        }

    except Exception as exc:
        logger.error(f"Error processing behavior events: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=2)
def update_entity_baselines(self, organization_id: str, entity_ids: list[str] = None) -> dict:
    """
    Recalculate entity baselines periodically.

    Updates behavior baselines for entities based on recent activity.

    Args:
        organization_id: Organization context
        entity_ids: Specific entity IDs to update (None = all)

    Returns:
        Dictionary with update results
    """
    try:
        logger.info(f"Updating baselines for org {organization_id}")

        baselines_updated = 0
        baselines_skipped = 0

        # In production, would fetch entities from database
        target_entities = entity_ids or []

        for entity_id in target_entities:
            try:
                # Fetch recent events for this entity (lookback 30 days)
                # In production, would query BehaviorEvent table
                recent_events = []

                # Build baselines for each behavior type
                behavior_types = [
                    "login_pattern",
                    "data_access",
                    "network_activity",
                    "privilege_usage"
                ]

                for behavior_type in behavior_types:
                    baseline = baseline_manager.build_baseline(
                        entity_id,
                        behavior_type,
                        recent_events,
                        lookback_days=30
                    )

                    if baseline.get("confidence", 0) > 0.5:
                        baselines_updated += 1
                    else:
                        baselines_skipped += 1

            except Exception as e:
                logger.error(f"Error updating baseline for {entity_id}: {e}")
                baselines_skipped += 1

        logger.info(f"Baseline update completed: {baselines_updated} updated, {baselines_skipped} skipped")

        return {
            "status": "completed",
            "baselines_updated": baselines_updated,
            "baselines_skipped": baselines_skipped
        }

    except Exception as exc:
        logger.error(f"Error in baseline update task: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def calculate_entity_risks(self, organization_id: str, entity_ids: list[str] = None) -> dict:
    """
    Recalculate all entity risk scores.

    Computes risk scores for entities based on recent alerts and events.

    Args:
        organization_id: Organization context
        entity_ids: Specific entity IDs to calculate (None = all)

    Returns:
        Dictionary with calculation results
    """
    try:
        logger.info(f"Calculating entity risks for org {organization_id}")

        entities_updated = 0
        high_risk_count = 0
        critical_risk_count = 0

        target_entities = entity_ids or []

        for entity_id in target_entities:
            try:
                # Fetch recent alerts for entity (last 30 days)
                # In production, would query UEBARiskAlert table
                recent_alerts = []

                # Calculate risk score
                risk_score = risk_scorer.calculate_entity_risk(
                    entity_id,
                    recent_alerts,
                    historical_risk=0.0
                )

                # Map to risk level
                risk_level = risk_scorer.update_risk_level(risk_score)

                # In production, would update EntityProfile in database
                entities_updated += 1

                if risk_level == "critical":
                    critical_risk_count += 1
                elif risk_level == "high":
                    high_risk_count += 1

                logger.debug(f"Entity {entity_id} risk: {risk_score:.1f} ({risk_level})")

            except Exception as e:
                logger.error(f"Error calculating risk for {entity_id}: {e}")

        logger.info(
            f"Risk calculation completed: {entities_updated} updated, "
            f"{critical_risk_count} critical, {high_risk_count} high"
        )

        return {
            "status": "completed",
            "entities_updated": entities_updated,
            "critical_risk_count": critical_risk_count,
            "high_risk_count": high_risk_count
        }

    except Exception as exc:
        logger.error(f"Error in risk calculation task: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=2)
def detect_impossible_travel(self, organization_id: str, entity_ids: list[str] = None) -> dict:
    """
    Check for impossible travel events.

    Detects when entities appear in geographically distant locations
    within physically impossible timeframes.

    Args:
        organization_id: Organization context
        entity_ids: Specific entity IDs to check

    Returns:
        Dictionary with detection results
    """
    try:
        logger.info(f"Detecting impossible travel for org {organization_id}")

        checked_count = 0
        alerts_created = 0

        target_entities = entity_ids or []

        for entity_id in target_entities:
            try:
                # Get last two authentication events with location
                # In production, would query BehaviorEvent table
                recent_auth_events = []

                if len(recent_auth_events) >= 2:
                    latest = recent_auth_events[0]
                    previous = recent_auth_events[1]

                    alert = travel_detector.check_impossible_travel(
                        entity_id,
                        latest.get("geo_location", {}),
                        datetime.fromisoformat(latest.get("timestamp", "")),
                        previous.get("geo_location", {}),
                        datetime.fromisoformat(previous.get("timestamp", ""))
                    )

                    if alert:
                        # In production, would create alert in database
                        alerts_created += 1
                        logger.warning(f"Impossible travel detected for {entity_id}: {alert['description']}")

                checked_count += 1

            except Exception as e:
                logger.error(f"Error checking impossible travel for {entity_id}: {e}")

        logger.info(f"Impossible travel detection completed: {checked_count} checked, {alerts_created} alerts")

        return {
            "status": "completed",
            "checked_count": checked_count,
            "alerts_created": alerts_created
        }

    except Exception as exc:
        logger.error(f"Error in impossible travel detection task: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=2)
def update_peer_groups(self, organization_id: str) -> dict:
    """
    Refresh peer group memberships and baselines.

    Rebuilds peer groups and updates their aggregate baselines.

    Args:
        organization_id: Organization context

    Returns:
        Dictionary with update results
    """
    try:
        logger.info(f"Updating peer groups for org {organization_id}")

        # In production, would fetch entities from database
        entities = []

        # Build peer groups by department
        department_groups = peer_analyzer.build_peer_groups(entities, method="department")

        # Build peer groups by role
        role_groups = peer_analyzer.build_peer_groups(entities, method="role")

        # Auto-cluster based on behavior
        feature_keys = ["entity_type", "department", "role"]
        auto_groups = peer_analyzer.auto_cluster_peers(entities, feature_keys)

        total_groups = len(department_groups) + len(role_groups) + len(auto_groups)

        logger.info(
            f"Peer groups updated: {len(department_groups)} departments, "
            f"{len(role_groups)} roles, {len(auto_groups)} auto-clusters"
        )

        return {
            "status": "completed",
            "department_groups": len(department_groups),
            "role_groups": len(role_groups),
            "auto_clusters": len(auto_groups),
            "total_groups": total_groups
        }

    except Exception as exc:
        logger.error(f"Error in peer group update task: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def generate_ueba_alerts(self, organization_id: str) -> dict:
    """
    Generate alerts for high-risk entities.

    Creates UEBA alerts based on detected anomalies and patterns.

    Args:
        organization_id: Organization context

    Returns:
        Dictionary with alert generation results
    """
    try:
        logger.info(f"Generating UEBA alerts for org {organization_id}")

        alerts_generated = 0
        entities_evaluated = 0

        # In production, would fetch high-risk entities from database
        high_risk_entities = []

        for entity in high_risk_entities:
            try:
                entity_id = entity.get("id")
                risk_score = entity.get("risk_score", 0)

                # Get risk factors
                alerts = entity.get("recent_alerts", [])
                risk_factors = risk_scorer.get_risk_factors(entity_id, alerts)

                # Generate alert if factors present
                if risk_factors and risk_score > 50:
                    # In production, would create alert in database
                    alerts_generated += 1

                entities_evaluated += 1

            except Exception as e:
                logger.error(f"Error generating alerts for entity: {e}")

        logger.info(f"Alert generation completed: {alerts_generated} alerts from {entities_evaluated} entities")

        return {
            "status": "completed",
            "alerts_generated": alerts_generated,
            "entities_evaluated": entities_evaluated
        }

    except Exception as exc:
        logger.error(f"Error in alert generation task: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=1)
def cleanup_old_behavior_events(self, organization_id: str, retention_days: int = 90) -> dict:
    """
    Clean up old behavior events for data retention.

    Deletes behavior events older than retention period.

    Args:
        organization_id: Organization context
        retention_days: Number of days to retain

    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info(f"Cleaning up behavior events for org {organization_id} (retention: {retention_days}d)")

        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        # In production, would delete from BehaviorEvent table
        # DELETE FROM behavior_events
        # WHERE organization_id = organization_id AND created_at < cutoff_date

        deleted_count = 0  # In production, would get actual count from DELETE query

        logger.info(f"Behavior event cleanup completed: {deleted_count} events deleted")

        return {
            "status": "completed",
            "deleted_count": deleted_count,
            "cutoff_date": cutoff_date.isoformat()
        }

    except Exception as exc:
        logger.error(f"Error in cleanup task: {exc}")
        raise self.retry(exc=exc, countdown=300)
