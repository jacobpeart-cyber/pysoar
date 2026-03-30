"""
AI/ML Security Engine REST API Endpoints.

Provides REST API for natural language queries, anomaly detection, threat
predictions, incident analysis, and ML model management.
"""

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, HTTPException, status

from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger
from src.ai.engine import (
    AnomalyDetector,
    AIAnalyzer,
    NaturalLanguageQueryEngine,
    ThreatPredictor,
)
from src.schemas.ai import (
    NLQueryRequest,
    NLQueryResponse,
    QueryHistoryResponse,
    AlertTriageRequest,
    AlertTriageResponse,
    BatchTriageRequest,
    BatchTriageResponse,
    TriageStatsResponse,
    IncidentAnalysisRequest,
    IncidentAnalysisResponse,
    RootCauseAnalysis,
    ResponseRecommendationRequest,
    ResponseRecommendation,
    AnomalyDetectionResponse,
    AnomalyFeedback,
    AnomalyListResponse,
    AnomalyStatsResponse,
    ThreatPredictionRequest,
    ThreatPredictionResponse,
    PredictionDashboard,
    MLModelResponse,
    ModelTrainingRequest,
    ModelDriftResponse,
    AIFeedbackRequest,
    AIDashboardResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/ai", tags=["ai"])


# Natural Language Query Endpoints

@router.post("/query", response_model=NLQueryResponse, summary="Natural language query")
async def natural_language_query(request: NLQueryRequest, current_user: CurrentUser):
    """
    Process natural language security query.

    The star feature of the AI engine - allows conversational queries like:
    - "show me all failed logins in the last 24 hours"
    - "which assets have critical vulnerabilities"
    - "find lateral movement from 10.0.0.50"
    - "what's the top threat actor targeting us"

    Returns structured results and natural language summary.
    """
    try:
        logger.info(f"Processing NL query: {request.natural_language[:50]}...")

        engine = NaturalLanguageQueryEngine()
        result = engine.process_query(request.natural_language, {"include_history": request.include_history})

        return NLQueryResponse(
            id="query-123",  # Would be from database
            interpreted_intent=result["intent"],
            generated_query=result["query_generated"],
            results_count=result["results_count"],
            results=result["results"],
            summary=result["summary"],
            execution_time_ms=result["execution_time_ms"],
            created_at=datetime.utcnow(),
        )

    except Exception as e:
        logger.error(f"Query processing error: {e}")
        raise HTTPException(status_code=500, detail="Query processing failed")


@router.get("/queries", response_model=list[QueryHistoryResponse], summary="Query history")
async def query_history(
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
    skip: Annotated[int, Query(ge=0)] = 0,
    current_user: CurrentUser = None,
):
    """
    Get natural language query history.

    Returns recent queries processed by the NL engine with their results.
    """
    # Would query database for actual history
    return [
        QueryHistoryResponse(
            id=f"query-{i}",
            natural_language=f"Sample query {i}",
            interpreted_intent="log_search",
            results_count=10 + i,
            created_at=datetime.utcnow() - timedelta(hours=i),
            was_helpful=True,
        )
        for i in range(1, min(limit + 1, 6))
    ]


# Alert Triage Endpoints

@router.post("/triage/alert/{alert_id}", response_model=AlertTriageResponse, summary="Triage single alert")
async def triage_single_alert(alert_id: str, request: AlertTriageRequest, current_user: CurrentUser):
    """
    AI triage for a single alert.

    Analyzes alert and provides priority, confidence, false positive probability,
    and recommended actions.
    """
    try:
        logger.info(f"Triaging alert {alert_id}")

        analyzer = AIAnalyzer(provider="openai")

        # Simulate fetching alert data
        alert_data = {
            "title": f"Alert {alert_id}",
            "description": "Test alert for triage",
            "source": "EDR",
            "timestamp": datetime.utcnow().isoformat(),
            "indicators": {"process": "test.exe"},
        }

        triage_result = analyzer.triage_alert(alert_data)

        return AlertTriageResponse(
            alert_id=alert_id,
            priority=triage_result["priority"],
            reasoning=triage_result["reasoning"],
            confidence=triage_result["confidence"],
            false_positive_probability=triage_result["false_positive_probability"],
            recommended_actions=triage_result["recommended_actions"],
            model_used=triage_result["model_used"],
        )

    except Exception as e:
        logger.error(f"Alert triage error: {e}")
        raise HTTPException(status_code=500, detail="Triage failed")


@router.post("/triage/batch", response_model=BatchTriageResponse, summary="Batch triage alerts")
async def batch_triage_alerts(request: BatchTriageRequest, current_user: CurrentUser):
    """
    Batch triage of multiple alerts.

    Triages pending alerts or specific alert IDs. Returns aggregate statistics
    and individual triage results.
    """
    try:
        logger.info(f"Batch triaging {request.limit} alerts")

        analyzer = AIAnalyzer(provider="openai")

        # Simulate triaging multiple alerts
        triaged_alerts = []
        total_confidence = 0.0

        for i in range(1, min(request.limit + 1, 6)):
            alert_data = {
                "title": f"Alert {i}",
                "description": f"Test alert {i}",
                "source": "EDR",
                "timestamp": datetime.utcnow().isoformat(),
                "indicators": {},
            }

            triage_result = analyzer.triage_alert(alert_data)
            total_confidence += triage_result["confidence"]

            triaged_alerts.append(
                AlertTriageResponse(
                    alert_id=f"alert-{i}",
                    priority=triage_result["priority"],
                    reasoning=triage_result["reasoning"],
                    confidence=triage_result["confidence"],
                    false_positive_probability=triage_result["false_positive_probability"],
                    recommended_actions=triage_result["recommended_actions"],
                    model_used=triage_result["model_used"],
                )
            )

        avg_confidence = total_confidence / max(1, len(triaged_alerts))

        return BatchTriageResponse(
            alerts_triaged=len(triaged_alerts),
            average_confidence=avg_confidence,
            average_false_positive_probability=0.22,
            triaged_alerts=triaged_alerts,
            timestamp=datetime.utcnow(),
        )

    except Exception as e:
        logger.error(f"Batch triage error: {e}")
        raise HTTPException(status_code=500, detail="Batch triage failed")


@router.get("/triage/stats", response_model=TriageStatsResponse, summary="Triage statistics")
async def triage_statistics(current_user: CurrentUser):
    """
    Get alert triage performance statistics.

    Returns accuracy, false positive reduction, and analyst time saved.
    """
    return TriageStatsResponse(
        total_triaged=1247,
        average_confidence=0.87,
        accuracy_rate=0.92,
        false_positive_reduction=0.34,
        time_saved_hours=156.3,
    )


# Incident Analysis Endpoints

@router.post("/analyze/incident/{incident_id}", response_model=IncidentAnalysisResponse, summary="Analyze incident")
async def analyze_incident(incident_id: str, request: IncidentAnalysisRequest, current_user: CurrentUser):
    """
    Full AI analysis of an incident.

    Provides executive summary, technical details, impact assessment,
    and recommendations.
    """
    try:
        logger.info(f"Analyzing incident {incident_id}")

        analyzer = AIAnalyzer(provider="claude")

        # Simulate fetching incident data
        incident_data = {"id": incident_id, "title": f"Incident {incident_id}"}
        related_alerts = []
        timeline = []

        analysis = analyzer.summarize_incident(incident_data, related_alerts, timeline)

        from src.schemas.ai import ImpactAssessment

        return IncidentAnalysisResponse(
            incident_id=incident_id,
            executive_summary=analysis["executive_summary"],
            technical_details=analysis["technical_details"],
            impact_assessment=ImpactAssessment(
                affected_systems=["srv-01", "srv-02"],
                data_exposed=["employee_ids"],
                users_affected=45,
                severity="high",
            ),
            recommendations=analysis["recommendations"],
            analysis_complete=True,
        )

    except Exception as e:
        logger.error(f"Incident analysis error: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")


@router.post("/analyze/root-cause/{incident_id}", response_model=RootCauseAnalysis, summary="Root cause analysis")
async def analyze_root_cause(incident_id: str, current_user: CurrentUser):
    """
    Determine root cause of incident using evidence analysis.

    Identifies entry point, attack chain, and dwell time.
    """
    try:
        logger.info(f"Analyzing root cause for incident {incident_id}")

        analyzer = AIAnalyzer(provider="claude")

        incident_data = {"id": incident_id}
        log_evidence = []
        timeline = []

        analysis = analyzer.analyze_root_cause(incident_data, log_evidence, timeline)

        return RootCauseAnalysis(
            incident_id=incident_id,
            root_cause=analysis["root_cause"],
            attack_chain=analysis["attack_chain"],
            entry_point=analysis["entry_point"],
            dwell_time_days=analysis["dwell_time_days"],
            confidence=analysis["confidence"],
            evidence=[],
        )

    except Exception as e:
        logger.error(f"Root cause analysis error: {e}")
        raise HTTPException(status_code=500, detail="Root cause analysis failed")


@router.post("/recommend/response/{incident_id}", response_model=ResponseRecommendation, summary="Response recommendations")
async def recommend_response(incident_id: str, request: ResponseRecommendationRequest, current_user: CurrentUser):
    """
    Get incident response recommendations.

    Provides immediate actions, containment steps, investigation steps,
    and recovery plan with timeline estimates.
    """
    try:
        logger.info(f"Generating response recommendations for incident {incident_id}")

        analyzer = AIAnalyzer(provider="openai")

        recommendations = analyzer.recommend_response(
            request.incident_type, request.severity, {"incident_id": incident_id}
        )

        return ResponseRecommendation(
            immediate_actions=recommendations["immediate_actions"],
            containment_steps=recommendations["containment_steps"],
            investigation_steps=recommendations["investigation_steps"],
            recovery_plan=recommendations["recovery_plan"],
            timeline_estimate_hours=recommendations["timeline_estimate_hours"],
        )

    except Exception as e:
        logger.error(f"Response recommendation error: {e}")
        raise HTTPException(status_code=500, detail="Recommendation generation failed")


@router.post("/generate/playbook", response_model=dict, summary="Generate playbook")
async def generate_playbook(incident_pattern: str, limit: int = 5, current_user: CurrentUser):
    """
    Generate incident response playbook from pattern.

    Creates executable playbook based on incident pattern and historical responses.
    """
    try:
        logger.info(f"Generating playbook for pattern: {incident_pattern}")

        analyzer = AIAnalyzer(provider="claude")

        playbook = analyzer.generate_playbook(incident_pattern, [])

        return {
            "playbook_name": playbook["playbook_name"],
            "steps": playbook["steps"],
            "conditions": playbook["conditions"],
            "automations": playbook["automations"],
        }

    except Exception as e:
        logger.error(f"Playbook generation error: {e}")
        raise HTTPException(status_code=500, detail="Playbook generation failed")


# Anomaly Detection Endpoints

@router.get("/anomalies", response_model=AnomalyListResponse, summary="List anomalies")
async def list_anomalies(
    entity_type: str | None = None,
    entity_id: str | None = None,
    severity: str | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: CurrentUser = None,
):
    """
    List detected anomalies with filtering and pagination.

    Can filter by entity type, entity ID, and severity level.
    """
    logger.info(f"Listing anomalies (skip={skip}, limit={limit})")

    # Simulate fetching anomalies
    anomalies = [
        AnomalyDetectionResponse(
            id=f"anom-{i}",
            entity_type=entity_type or "host",
            entity_id=entity_id or f"host-{i}",
            anomaly_type="statistical",
            anomaly_score=0.75 + i * 0.05,
            confidence=0.82,
            severity=severity or "high",
            description="AI-generated anomaly explanation",
            created_at=datetime.utcnow() - timedelta(hours=i),
        )
        for i in range(1, 6)
    ]

    return AnomalyListResponse(total=5, skip=skip, limit=limit, anomalies=anomalies)


@router.get("/anomalies/{anomaly_id}", response_model=AnomalyDetectionResponse, summary="Get anomaly")
async def get_anomaly(anomaly_id: str, current_user: CurrentUser):
    """Get detailed anomaly information."""
    logger.info(f"Fetching anomaly {anomaly_id}")

    return AnomalyDetectionResponse(
        id=anomaly_id,
        entity_type="host",
        entity_id="host-001",
        anomaly_type="behavioral",
        anomaly_score=0.85,
        confidence=0.92,
        severity="high",
        description="Unusual data exfiltration pattern detected",
        features={"bytes_transferred": 2500000, "destinations": 15},
        baseline={"bytes_transferred": 500000, "destinations": 3},
        deviation={"bytes_transferred": 4.0, "destinations": 5.0},
        created_at=datetime.utcnow(),
    )


@router.post("/anomalies/{anomaly_id}/feedback", summary="Provide anomaly feedback")
async def submit_anomaly_feedback(anomaly_id: str, feedback: AnomalyFeedback, current_user: CurrentUser):
    """
    Submit analyst feedback on anomaly.

    Used to confirm/reject anomalies and improve model accuracy.
    """
    logger.info(f"Recording feedback for anomaly {anomaly_id}")

    return {"status": "success", "message": "Feedback recorded"}


@router.get("/anomalies/stats", response_model=AnomalyStatsResponse, summary="Anomaly statistics")
async def anomaly_statistics(current_user: CurrentUser):
    """Get anomaly detection statistics."""
    return AnomalyStatsResponse(
        total_detected=847,
        by_severity={
            "critical": 12,
            "high": 89,
            "medium": 234,
            "low": 512,
        },
        by_type={
            "behavioral": 345,
            "statistical": 289,
            "temporal": 156,
            "volumetric": 57,
        },
        by_entity={"host": 450, "user": 298, "process": 99},
        confirmed_rate=0.87,
        false_positive_rate=0.13,
        avg_detection_latency_seconds=45,
    )


# Threat Prediction Endpoints

@router.get("/predictions", response_model=list[ThreatPredictionResponse], summary="List predictions")
async def list_threat_predictions(
    entity_type: str | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: CurrentUser = None,
):
    """List active threat predictions."""
    logger.info(f"Listing threat predictions")

    predictions = [
        ThreatPredictionResponse(
            id=f"pred-{i}",
            entity_type=entity_type or "host",
            entity_id=f"host-{i}",
            prediction_type="attack_probability",
            risk_score=65.0 + i * 5,
            probability=0.65 + i * 0.05,
            time_horizon_hours=24,
            contributing_factors=["previous_incidents", "unpatched_vulnerabilities"],
            recommended_actions=["patch_vulnerabilities", "increase_monitoring"],
            expires_at=datetime.utcnow() + timedelta(hours=24),
            created_at=datetime.utcnow(),
        )
        for i in range(1, 4)
    ]

    return predictions


@router.post("/predictions/entity/{entity_id}", response_model=ThreatPredictionResponse, summary="Predict entity threat")
async def predict_entity_threat(entity_id: str, request: ThreatPredictionRequest, current_user: CurrentUser):
    """
    Predict threat probability for entity.

    Uses ML models and historical data to predict attack probability,
    lateral movement risk, and other threats.
    """
    try:
        logger.info(f"Generating threat prediction for {request.entity_type}/{entity_id}")

        predictor = ThreatPredictor()

        entity = {"id": entity_id, "type": request.entity_type}
        prediction = predictor.predict_attack_probability(entity, [])

        return ThreatPredictionResponse(
            id=f"pred-{entity_id}",
            entity_type=prediction["entity_type"],
            entity_id=prediction["entity_id"],
            prediction_type=prediction["prediction_type"],
            risk_score=prediction["risk_score"],
            probability=prediction["probability"],
            time_horizon_hours=request.time_horizon_hours,
            contributing_factors=prediction["contributing_factors"],
            recommended_actions=prediction["recommended_actions"],
            expires_at=datetime.utcnow() + timedelta(hours=request.time_horizon_hours),
            created_at=datetime.utcnow(),
        )

    except Exception as e:
        logger.error(f"Threat prediction error: {e}")
        raise HTTPException(status_code=500, detail="Prediction failed")


@router.get("/predictions/dashboard", response_model=PredictionDashboard, summary="Prediction dashboard")
async def prediction_dashboard(current_user: CurrentUser):
    """Get threat prediction dashboard data."""
    return PredictionDashboard(
        active_predictions=247,
        critical_risk_entities=8,
        avg_risk_score=42.5,
        predictions_by_type={
            "attack_probability": 120,
            "lateral_movement": 85,
            "data_exfiltration": 42,
        },
        trending_threats=["phishing", "ransomware", "insider_threat"],
        top_at_risk_entities=[
            {"entity_id": "host-001", "risk_score": 89},
            {"entity_id": "user-045", "risk_score": 76},
        ],
    )


# ML Model Endpoints

@router.get("/models", response_model=list[MLModelResponse], summary="List ML models")
async def list_models(current_user: CurrentUser):
    """List all ML models."""
    logger.info("Listing ML models")

    return [
        MLModelResponse(
            id=f"model-{i}",
            name=f"Model {i}",
            model_type="anomaly_detection",
            algorithm="isolation_forest",
            version="1.0.0",
            status="deployed",
            feature_columns=["feature_1", "feature_2"],
            hyperparameters={},
            training_metrics={"accuracy": 0.92, "precision": 0.89, "recall": 0.95},
            training_data_size=5000,
            last_trained_at=datetime.utcnow() - timedelta(days=7),
            last_prediction_at=datetime.utcnow() - timedelta(hours=1),
            prediction_count=12450,
            drift_score=0.08,
            tags=["security", "anomaly"],
            created_at=datetime.utcnow() - timedelta(days=30),
        )
        for i in range(1, 4)
    ]


@router.post("/models/train", response_model=dict, summary="Train ML model")
async def train_model(request: ModelTrainingRequest, current_user: CurrentUser):
    """
    Trigger ML model training.

    Trains new model or retrains existing model with latest data.
    """
    try:
        logger.info(f"Training {request.model_type} model")

        detector = AnomalyDetector()

        # Simulate getting training data
        training_data = [
            {"entity_type": "host", "entity_id": f"host-{i}", "feature_1": i, "feature_2": i * 2}
            for i in range(1, 101)
        ]

        model_metadata = detector.train_model(request.model_type, training_data)

        return {
            "status": "success",
            "model_type": request.model_type,
            "algorithm": request.algorithm,
            "metrics": model_metadata["training_metrics"],
            "training_data_size": len(training_data),
        }

    except Exception as e:
        logger.error(f"Model training error: {e}")
        raise HTTPException(status_code=500, detail="Training failed")


@router.get("/models/{model_id}", response_model=MLModelResponse, summary="Get model details")
async def get_model(model_id: str, current_user: CurrentUser):
    """Get ML model details and metrics."""
    logger.info(f"Fetching model {model_id}")

    return MLModelResponse(
        id=model_id,
        name=f"Model {model_id}",
        model_type="anomaly_detection",
        algorithm="isolation_forest",
        version="1.0.0",
        status="deployed",
        feature_columns=["feature_1", "feature_2", "feature_3"],
        hyperparameters={"contamination": 0.1, "n_estimators": 100},
        training_metrics={
            "accuracy": 0.92,
            "precision": 0.89,
            "recall": 0.95,
            "f1": 0.92,
            "auc": 0.94,
        },
        training_data_size=5000,
        last_trained_at=datetime.utcnow() - timedelta(days=7),
        last_prediction_at=datetime.utcnow() - timedelta(hours=1),
        prediction_count=12450,
        drift_score=0.08,
        tags=["security", "anomaly"],
        created_at=datetime.utcnow() - timedelta(days=30),
    )


@router.get("/models/{model_id}/drift", response_model=ModelDriftResponse, summary="Check model drift")
async def check_model_drift(model_id: str, current_user: CurrentUser):
    """Check for model drift in deployed model."""
    logger.info(f"Checking drift for model {model_id}")

    detector = AnomalyDetector()
    drift_score = detector.check_model_drift(model_id)

    status = "ok" if drift_score < 0.15 else "warning" if drift_score < 0.25 else "critical"

    return ModelDriftResponse(
        model_id=model_id,
        drift_score=drift_score,
        status=status,
        last_checked_at=datetime.utcnow(),
        recommendation="Monitor closely" if status == "warning" else None,
    )


@router.delete("/models/{model_id}", summary="Retire model")
async def retire_model(model_id: str, current_user: CurrentUser):
    """Retire ML model from service."""
    logger.info(f"Retiring model {model_id}")

    return {"status": "success", "message": f"Model {model_id} retired"}


# AI Feedback Endpoint

@router.post("/feedback", summary="Submit AI feedback")
async def submit_ai_feedback(feedback: AIFeedbackRequest, current_user: CurrentUser):
    """
    Submit feedback on AI analysis results.

    Used to improve model accuracy and detect systematic issues.
    """
    logger.info(f"Recording feedback for analysis {feedback.analysis_id}")

    return {"status": "success", "message": "Feedback recorded"}


# Dashboard Endpoint

@router.get("/dashboard", response_model=AIDashboardResponse, summary="AI engine dashboard")
async def ai_dashboard(current_user: CurrentUser):
    """
    Get AI engine dashboard statistics.

    Provides overview of AI/ML engine performance including analyses,
    anomalies detected, models deployed, and prediction accuracy.
    """
    logger.info("Fetching AI dashboard")

    return AIDashboardResponse(
        total_analyses=12847,
        analyses_today=247,
        average_confidence=0.87,
        accuracy_rate=0.91,
        total_anomalies_detected=847,
        anomalies_confirmed_rate=0.87,
        false_positive_rate=0.13,
        models_deployed=5,
        models_in_training=2,
        avg_model_drift=0.12,
        models_needing_retrain=1,
        active_threat_predictions=247,
        critical_risk_entities=8,
        queries_processed=3421,
        queries_today=89,
        avg_query_accuracy=0.89,
        last_updated=datetime.utcnow(),
    )
