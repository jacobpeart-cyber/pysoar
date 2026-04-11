"""
Celery Tasks for AI/ML Security Engine.

Implements background tasks for anomaly detection, model training, alert triage,
and threat prediction.
"""

import asyncio
from datetime import datetime, timedelta, timezone

from celery import shared_task
from sqlalchemy import func, select

from src.core.config import settings
from src.core.logging import get_logger
from src.ai.engine import AnomalyDetector, AIAnalyzer, ThreatPredictor

logger = get_logger(__name__)


def _run_async(coro):
    """Run an async coroutine from a synchronous Celery task."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Should not happen inside a Celery worker, but fallback
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


@shared_task(bind=True, max_retries=3)
def run_anomaly_detection(self, model_id: str | None = None, time_window_hours: int = 24):
    """
    Run batch anomaly detection on recent security events.

    Queries real alerts from the database for the given time window and feeds
    them to the AnomalyDetector.

    Args:
        model_id: Optional specific model to use
        time_window_hours: Hours of recent data to analyze

    Returns:
        Dictionary with detection results and statistics
    """
    try:
        logger.info(f"Starting anomaly detection (window={time_window_hours}h)")

        detector = AnomalyDetector()

        # Fetch real alerts from the database
        async def _fetch_recent_events():
            from src.core.database import async_session_factory
            from src.models.alert import Alert

            async with async_session_factory() as session:
                cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)
                result = await session.execute(
                    select(Alert)
                    .where(Alert.created_at >= cutoff)
                    .limit(100)
                )
                alerts = list(result.scalars().all())

            # Convert alerts to the dict format the AnomalyDetector expects
            events = []
            for a in alerts:
                events.append({
                    "entity_type": a.source or "unknown",
                    "entity_id": a.id,
                    "severity": a.severity or "medium",
                    "title": a.title,
                    "source": a.source or "unknown",
                    "source_ip": a.source_ip or "",
                    "destination_ip": a.destination_ip or "",
                    "hostname": a.hostname or "",
                    "username": a.username or "",
                    "priority": a.priority or 3,
                    "confidence": a.confidence or 50,
                })
            return events

        recent_events = _run_async(_fetch_recent_events())

        if not recent_events:
            logger.info("No recent events found for anomaly detection")
            return {
                "status": "success",
                "anomalies_detected": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model_used": model_id,
            }

        # Run anomaly detection
        anomalies = detector.detect_anomalies(recent_events, model_id)

        logger.info(f"Anomaly detection complete: {len(anomalies)} anomalies detected")

        return {
            "status": "success",
            "anomalies_detected": len(anomalies),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_used": model_id,
        }

    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def retrain_ml_models(self, model_types: list[str] | None = None):
    """
    Periodically retrain ML models with new data.

    Queries real historical alerts for training data.
    Scheduled to run nightly or on-demand.

    Args:
        model_types: Optional list of specific model types to retrain

    Returns:
        Dictionary with retraining results
    """
    try:
        logger.info(f"Starting ML model retraining (types={model_types})")

        detector = AnomalyDetector()

        # Fetch real historical alerts for training data
        async def _fetch_training_data():
            from src.core.database import async_session_factory
            from src.models.alert import Alert

            async with async_session_factory() as session:
                result = await session.execute(
                    select(Alert)
                    .order_by(Alert.created_at.desc())
                    .limit(500)
                )
                alerts = list(result.scalars().all())

            training_data = []
            for a in alerts:
                training_data.append({
                    "entity_type": a.source or "unknown",
                    "entity_id": a.id,
                    "severity": a.severity or "medium",
                    "priority": a.priority or 3,
                    "confidence": a.confidence or 50,
                    "source": a.source or "unknown",
                    "feature_1": float(a.priority or 3) * 0.5,
                    "feature_2": float(a.confidence or 50) * 0.02,
                    "feature_3": 1.0 if a.severity in ("critical", "high") else 0.0,
                })
            return training_data

        training_data = _run_async(_fetch_training_data())

        # Fall back to minimal synthetic data if DB is empty so models can still train
        if not training_data:
            logger.warning("No historical alerts found; using minimal synthetic data for training")
            training_data = [
                {
                    "entity_type": "unknown",
                    "entity_id": f"synthetic-{i}",
                    "feature_1": i * 0.5,
                    "feature_2": i * 1.2,
                    "feature_3": i * 0.8,
                }
                for i in range(1, 51)
            ]

        models_trained = []
        default_types = model_types or ["isolation_forest", "statistical", "time_series"]

        for model_type in default_types:
            logger.info(f"Training {model_type} model")
            model_metadata = detector.train_model(model_type, training_data)
            models_trained.append(
                {
                    "model_type": model_type,
                    "version": model_metadata["version"],
                    "accuracy": model_metadata["training_metrics"]["accuracy"],
                }
            )

        logger.info(f"Model retraining complete: {len(models_trained)} models trained")

        return {
            "status": "success",
            "models_trained": models_trained,
            "training_data_size": len(training_data),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Model retraining failed: {e}")
        raise self.retry(exc=e, countdown=300 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def ai_triage_pending_alerts(self, alert_ids: list[str] | None = None, limit: int = 50):
    """
    Auto-triage new pending alerts using AI analysis.

    Queries real alerts with status 'new' or 'open', triages them, and writes
    the priority back to each alert record.

    Args:
        alert_ids: Optional specific alert IDs to triage
        limit: Maximum alerts to process

    Returns:
        Dictionary with triage results and statistics
    """
    try:
        logger.info(f"Starting AI alert triage (limit={limit})")

        analyzer = AIAnalyzer(provider="openai")

        # Fetch and triage real pending alerts
        async def _triage_alerts():
            from src.core.database import async_session_factory
            from src.models.alert import Alert

            async with async_session_factory() as session:
                if alert_ids:
                    query = select(Alert).where(Alert.id.in_(alert_ids)).limit(limit)
                else:
                    query = (
                        select(Alert)
                        .where(Alert.status.in_(["new", "open"]))
                        .limit(limit)
                    )
                result = await session.execute(query)
                alerts = list(result.scalars().all())

                triaged = 0
                total_confidence = 0.0

                for alert_obj in alerts:
                    try:
                        alert_dict = {
                            "id": alert_obj.id,
                            "title": alert_obj.title or f"Alert {alert_obj.id}",
                            "description": alert_obj.description or "",
                            "source": alert_obj.source or "unknown",
                            "severity": alert_obj.severity or "medium",
                            "timestamp": alert_obj.created_at.isoformat() if alert_obj.created_at else datetime.now(timezone.utc).isoformat(),
                            "indicators": {
                                "source_ip": alert_obj.source_ip or "",
                                "hostname": alert_obj.hostname or "",
                                "username": alert_obj.username or "",
                            },
                        }
                        triage_result = analyzer.triage_alert(alert_dict)
                        triaged += 1
                        total_confidence += triage_result.get("confidence", 0.5)

                        # Write back the triage priority to the alert record
                        priority_map = {"p1": 1, "p2": 2, "p3": 3, "p4": 4}
                        triage_priority = triage_result.get("priority", "p3")
                        alert_obj.priority = priority_map.get(triage_priority, 3)

                        logger.debug(f"Triaged alert {alert_obj.id}: {triage_priority}")
                    except Exception as e:
                        logger.error(f"Failed to triage alert {alert_obj.id}: {e}")

                await session.commit()
                return triaged, total_confidence

        triaged, total_confidence = _run_async(_triage_alerts())
        avg_confidence = total_confidence / max(1, triaged)

        logger.info(f"Alert triage complete: {triaged} alerts triaged, avg confidence {avg_confidence:.2f}")

        return {
            "status": "success",
            "alerts_triaged": triaged,
            "average_confidence": avg_confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Alert triage failed: {e}")
        raise self.retry(exc=e, countdown=120 * (2 ** self.request.retries))


@shared_task
def generate_daily_threat_briefing():
    """
    Generate daily AI-powered threat briefing.

    Queries real alert/incident stats and IOC counts from the last 24 hours
    and builds the briefing from actual data.

    Returns:
        Dictionary with briefing data
    """
    try:
        logger.info("Generating daily threat briefing")

        analyzer = AIAnalyzer(provider="claude")

        async def _build_briefing():
            from src.core.database import async_session_factory
            from src.models.alert import Alert
            from src.models.incident import Incident
            from src.intel.models import ThreatIndicator as IOC

            async with async_session_factory() as session:
                cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

                # Total alerts in last 24h
                total_result = await session.execute(
                    select(func.count(Alert.id)).where(Alert.created_at >= cutoff)
                )
                total_alerts = total_result.scalar() or 0

                # Alerts by severity
                sev_result = await session.execute(
                    select(Alert.severity, func.count(Alert.id))
                    .where(Alert.created_at >= cutoff)
                    .group_by(Alert.severity)
                )
                severity_counts = dict(sev_result.all())
                critical_alerts = severity_counts.get("critical", 0)
                high_alerts = severity_counts.get("high", 0)
                medium_alerts = severity_counts.get("medium", 0)
                low_alerts = severity_counts.get("low", 0)

                # Incidents in last 24h
                incident_result = await session.execute(
                    select(func.count(Incident.id)).where(Incident.created_at >= cutoff)
                )
                total_incidents = incident_result.scalar() or 0

                # Open incidents
                open_incident_result = await session.execute(
                    select(func.count(Incident.id)).where(
                        Incident.status.in_(["open", "investigating"])
                    )
                )
                open_incidents = open_incident_result.scalar() or 0

                # IOC counts
                ioc_result = await session.execute(
                    select(func.count(IOC.id)).where(IOC.is_active == True)  # noqa: E712
                )
                active_iocs = ioc_result.scalar() or 0

                # Top alert sources in last 24h
                source_result = await session.execute(
                    select(Alert.source, func.count(Alert.id))
                    .where(Alert.created_at >= cutoff)
                    .group_by(Alert.source)
                    .order_by(func.count(Alert.id).desc())
                    .limit(5)
                )
                top_sources = [
                    {"source": row[0], "count": row[1]}
                    for row in source_result.all()
                ]

                # Top alert categories/types in last 24h
                cat_result = await session.execute(
                    select(Alert.category, func.count(Alert.id))
                    .where(Alert.created_at >= cutoff, Alert.category.isnot(None))
                    .group_by(Alert.category)
                    .order_by(func.count(Alert.id).desc())
                    .limit(5)
                )
                top_categories = [
                    {"threat": row[0] or "Unknown", "count": row[1], "recommendation": "Review and respond"}
                    for row in cat_result.all()
                ]

                # False positive rate (resolved as false_positive vs total resolved)
                fp_result = await session.execute(
                    select(func.count(Alert.id)).where(
                        Alert.created_at >= cutoff,
                        Alert.status == "false_positive",
                    )
                )
                fp_count = fp_result.scalar() or 0

                resolved_result = await session.execute(
                    select(func.count(Alert.id)).where(
                        Alert.created_at >= cutoff,
                        Alert.status.in_(["resolved", "closed", "false_positive"]),
                    )
                )
                resolved_count = resolved_result.scalar() or 0

                detection_rate = "N/A"
                fp_rate = f"{(fp_count / resolved_count * 100):.0f}%" if resolved_count > 0 else "N/A"

            # Build summary
            if total_alerts == 0:
                summary = "No alerts detected in the last 24 hours."
            else:
                parts = []
                if critical_alerts:
                    parts.append(f"{critical_alerts} critical")
                if high_alerts:
                    parts.append(f"{high_alerts} high")
                severity_desc = ", ".join(parts) if parts else "mostly low/medium severity"
                summary = (
                    f"{total_alerts} alerts detected ({severity_desc}). "
                    f"{total_incidents} new incidents. "
                    f"{active_iocs} active IOCs being tracked."
                )

            # If no categories found, provide a default entry
            if not top_categories:
                top_categories = [{"threat": "No categorized threats", "count": 0, "recommendation": "N/A"}]

            briefing = {
                "date": datetime.now(timezone.utc).date().isoformat(),
                "total_alerts": total_alerts,
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "medium_alerts": medium_alerts,
                "low_alerts": low_alerts,
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "active_iocs": active_iocs,
                "summary": summary,
                "top_threats": top_categories,
                "top_sources": top_sources,
                "metrics": {
                    "detection_rate": detection_rate,
                    "false_positive_rate": fp_rate,
                },
            }
            return briefing

        briefing = _run_async(_build_briefing())

        logger.info("Daily threat briefing generated successfully")

        return {
            "status": "success",
            "briefing": briefing,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Briefing generation failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@shared_task
def check_model_drift():
    """
    Monitor ML model performance and detect drift.

    Checks all deployed models for performance degradation and alerts
    if retraining is needed.

    Returns:
        Dictionary with drift detection results
    """
    try:
        logger.info("Checking model drift across deployed models")

        detector = AnomalyDetector()

        # Simulate checking multiple models
        models_to_check = ["isolation_forest_v1", "statistical_detector_v2", "lstm_timeseries_v1"]

        drift_results = {}
        models_needing_retrain = []

        for model_id in models_to_check:
            drift_score = detector.check_model_drift(model_id)
            drift_results[model_id] = drift_score

            if drift_score > 0.2:  # Threshold for retraining
                models_needing_retrain.append(model_id)
                logger.warning(f"Model {model_id} showing drift ({drift_score:.2f})")

        logger.info(f"Drift check complete: {len(models_needing_retrain)} models need retraining")

        return {
            "status": "success",
            "drift_results": drift_results,
            "models_needing_retrain": models_needing_retrain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Model drift check failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@shared_task
def update_threat_predictions():
    """
    Refresh threat predictions for all monitored entities.

    Queries real assets from the database and updates predictive risk scores
    based on latest intelligence and behavioral data.

    Returns:
        Dictionary with prediction update results
    """
    try:
        logger.info("Updating threat predictions for all entities")

        predictor = ThreatPredictor()

        # Fetch real assets/entities from the database
        async def _fetch_entities():
            from src.core.database import async_session_factory
            from src.models.asset import Asset

            async with async_session_factory() as session:
                result = await session.execute(
                    select(Asset)
                    .where(Asset.status == "active")
                    .limit(200)
                )
                assets = list(result.scalars().all())

            entities = []
            for asset in assets:
                # Map asset_type to a simpler entity type
                type_map = {
                    "server": "host",
                    "workstation": "host",
                    "laptop": "host",
                    "network_device": "host",
                    "firewall": "host",
                    "database": "application",
                    "application": "application",
                    "cloud_instance": "host",
                    "container": "application",
                    "iot_device": "host",
                    "mobile": "host",
                }
                entities.append({
                    "id": asset.id,
                    "type": type_map.get(asset.asset_type, "host"),
                    "name": asset.name,
                    "criticality": asset.criticality or "medium",
                })
            return entities

        entities = _run_async(_fetch_entities())

        if not entities:
            logger.info("No active assets found for threat prediction updates")
            return {
                "status": "success",
                "predictions_updated": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        predictions_updated = 0

        for entity in entities:
            try:
                prediction = predictor.predict_attack_probability(entity, [])
                predictions_updated += 1
                logger.debug(f"Updated prediction for {entity['id']}: {prediction['probability']:.2f}")
            except Exception as e:
                logger.error(f"Failed to update prediction for {entity['id']}: {e}")

        logger.info(f"Threat predictions updated: {predictions_updated} entities")

        return {
            "status": "success",
            "predictions_updated": predictions_updated,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Threat prediction update failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@shared_task(bind=True, max_retries=3)
def process_nl_query_async(self, query_id: str, natural_language: str, user_id: str):
    """
    Process natural language query asynchronously.

    Handles long-running NL query processing in background, updates results
    when complete.

    Args:
        query_id: Unique query identifier
        natural_language: User's natural language query
        user_id: ID of user who submitted query

    Returns:
        Dictionary with query results
    """
    try:
        logger.info(f"Processing NL query {query_id}")

        from src.ai.engine import NaturalLanguageQueryEngine

        engine = NaturalLanguageQueryEngine()

        result = engine.process_query(natural_language, {"user_id": user_id})

        logger.info(f"NL query {query_id} complete: {result['results_count']} results")

        # In production, would update database with results
        return {
            "status": "success",
            "query_id": query_id,
            "results": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"NL query processing failed: {e}")
        raise self.retry(exc=e, countdown=30 * (2 ** self.request.retries))
