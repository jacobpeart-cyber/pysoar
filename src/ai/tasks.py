"""
Celery Tasks for AI/ML Security Engine.

Implements background tasks for anomaly detection, model training, alert triage,
and threat prediction.
"""

from datetime import datetime, timedelta

from celery import shared_task

from src.core.config import settings
from src.core.logging import get_logger
from src.ai.engine import AnomalyDetector, AIAnalyzer, ThreatPredictor

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
def run_anomaly_detection(self, model_id: str | None = None, time_window_hours: int = 24):
    """
    Run batch anomaly detection on recent security events.

    Executes periodically to detect anomalies in event streams, log data,
    and other security signals.

    Args:
        model_id: Optional specific model to use
        time_window_hours: Hours of recent data to analyze

    Returns:
        Dictionary with detection results and statistics
    """
    try:
        logger.info(f"Starting anomaly detection (window={time_window_hours}h)")

        detector = AnomalyDetector()

        # Simulate fetching recent data
        recent_events = [
            {
                "entity_type": "user",
                "entity_id": "user-123",
                "login_count": 15,
                "failed_logins": 5,
                "data_accessed_gb": 2.5,
            },
            {
                "entity_type": "host",
                "entity_id": "host-456",
                "outbound_connections": 142,
                "unique_destinations": 89,
                "traffic_volume_mb": 2500,
            },
        ]

        # Run anomaly detection
        anomalies = detector.detect_anomalies(recent_events, model_id)

        logger.info(f"Anomaly detection complete: {len(anomalies)} anomalies detected")

        return {
            "status": "success",
            "anomalies_detected": len(anomalies),
            "timestamp": datetime.utcnow().isoformat(),
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

    Retrains models to adapt to changing threats and reduce model drift.
    Scheduled to run nightly or on-demand.

    Args:
        model_types: Optional list of specific model types to retrain

    Returns:
        Dictionary with retraining results
    """
    try:
        logger.info(f"Starting ML model retraining (types={model_types})")

        detector = AnomalyDetector()

        # Simulate fetching training data
        training_data = [
            {
                "entity_type": "user",
                "entity_id": f"user-{i}",
                "feature_1": i * 0.5,
                "feature_2": i * 1.2,
                "feature_3": i * 0.8,
            }
            for i in range(1, 101)
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
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Model retraining failed: {e}")
        raise self.retry(exc=e, countdown=300 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def ai_triage_pending_alerts(self, alert_ids: list[str] | None = None, limit: int = 50):
    """
    Auto-triage new pending alerts using AI analysis.

    Reviews newly created alerts and provides initial triage, priority scoring,
    and false positive detection.

    Args:
        alert_ids: Optional specific alert IDs to triage
        limit: Maximum alerts to process

    Returns:
        Dictionary with triage results and statistics
    """
    try:
        logger.info(f"Starting AI alert triage (limit={limit})")

        analyzer = AIAnalyzer(provider="openai")

        # Simulate fetching pending alerts
        pending_alerts = [
            {
                "id": f"alert-{i}",
                "title": f"Alert {i}",
                "description": f"Description for alert {i}",
                "source": "EDR",
                "timestamp": (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                "indicators": {"process_name": "suspicious.exe", "parent_pid": 1234},
            }
            for i in range(1, min(6, limit))
        ]

        triaged = 0
        total_confidence = 0.0

        for alert in pending_alerts:
            try:
                triage_result = analyzer.triage_alert(alert)
                triaged += 1
                total_confidence += triage_result.get("confidence", 0.5)
                logger.debug(f"Triaged alert {alert['id']}: {triage_result['priority']}")
            except Exception as e:
                logger.error(f"Failed to triage alert {alert.get('id')}: {e}")

        avg_confidence = total_confidence / max(1, triaged)

        logger.info(f"Alert triage complete: {triaged} alerts triaged, avg confidence {avg_confidence:.2f}")

        return {
            "status": "success",
            "alerts_triaged": triaged,
            "average_confidence": avg_confidence,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Alert triage failed: {e}")
        raise self.retry(exc=e, countdown=120 * (2 ** self.request.retries))


@shared_task
def generate_daily_threat_briefing():
    """
    Generate daily AI-powered threat briefing.

    Summarizes threat activity from previous 24 hours, identifies key alerts,
    and provides recommendations. Typically sent to security team each morning.

    Returns:
        Dictionary with briefing data
    """
    try:
        logger.info("Generating daily threat briefing")

        analyzer = AIAnalyzer(provider="claude")

        # Simulate briefing data
        briefing = {
            "date": datetime.utcnow().date().isoformat(),
            "total_alerts": 47,
            "critical_alerts": 3,
            "high_alerts": 12,
            "summary": "Moderate activity with focus on phishing attempts and credential access",
            "top_threats": [
                {
                    "threat": "Phishing campaign",
                    "count": 34,
                    "recommendation": "Increase user awareness training",
                },
                {
                    "threat": "Credential brute force",
                    "count": 8,
                    "recommendation": "Review and enforce MFA policies",
                },
            ],
            "metrics": {
                "detection_rate": "94%",
                "false_positive_rate": "8%",
                "avg_response_time_minutes": 15,
            },
        }

        logger.info("Daily threat briefing generated successfully")

        return {
            "status": "success",
            "briefing": briefing,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Briefing generation failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.utcnow().isoformat(),
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
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Model drift check failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


@shared_task
def update_threat_predictions():
    """
    Refresh threat predictions for all monitored entities.

    Updates predictive risk scores for users, hosts, and other assets
    based on latest intelligence and behavioral data.

    Returns:
        Dictionary with prediction update results
    """
    try:
        logger.info("Updating threat predictions for all entities")

        predictor = ThreatPredictor()

        # Simulate updating predictions for multiple entities
        entities = [
            {"id": "user-123", "type": "user"},
            {"id": "host-456", "type": "host"},
            {"id": "app-789", "type": "application"},
        ]

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
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Threat prediction update failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.utcnow().isoformat(),
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
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"NL query processing failed: {e}")
        raise self.retry(exc=e, countdown=30 * (2 ** self.request.retries))
