"""
Pydantic schemas for AI/ML Security Engine API.

Defines request/response models for all AI endpoints including natural language
queries, anomaly detection, threat predictions, and incident analysis.
"""

from datetime import datetime
from typing import Any

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Natural Language Queries

class NLQueryRequest(BaseModel):
    """Natural language query request from user."""

    natural_language: str = Field(..., description="Natural language query", min_length=1, max_length=1000)
    include_history: bool = Field(
        default=False, description="Include query execution history"
    )
    user_context: dict[str, Any] | None = Field(
        default=None, description="Optional user context for better results"
    )


class NLQueryResponse(DBModel):
    """Natural language query response with results and summary."""

    id: str = Field(..., description="Query ID")
    interpreted_intent: str = Field(..., description="Classified query intent")
    generated_query: str = Field(..., description="Generated underlying query")
    results_count: int = Field(..., description="Number of results returned")
    results: list[dict] = Field(default=[], description="Query results (top 10)")
    summary: str = Field(..., description="Natural language summary of results")
    execution_time_ms: int = Field(..., description="Query execution time in milliseconds")
    created_at: datetime = Field(..., description="Query creation timestamp")

    class Config:
        from_attributes = True


class QueryHistoryResponse(DBModel):
    """Query history entry."""

    id: str
    natural_language: str
    interpreted_intent: str
    results_count: int
    created_at: Optional[datetime] = None
    was_helpful: bool | None = None

    class Config:
        from_attributes = True


# Alert Triage

class AlertTriageRequest(BaseModel):
    """Alert triage request."""

    alert_id: str = Field(..., description="Alert ID to triage")
    include_context: bool = Field(
        default=False, description="Include related alerts and context"
    )


class AlertTriageResponse(DBModel):
    """Alert triage analysis response."""

    alert_id: str
    priority: str = Field(..., description="p1, p2, p3, or p4")
    reasoning: str = Field(..., description="Explanation of priority assignment")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in analysis")
    false_positive_probability: float = Field(
        ..., ge=0.0, le=1.0, description="Likelihood this is a false positive"
    )
    recommended_actions: list[str] = Field(
        default=[], description="Recommended immediate actions"
    )
    model_used: str = Field(..., description="LLM model used for analysis")

    class Config:
        from_attributes = True


class BatchTriageRequest(BaseModel):
    """Batch alert triage request."""

    alert_ids: list[str] | None = Field(
        default=None, description="Specific alert IDs. If None, triages pending alerts"
    )
    limit: int = Field(default=50, ge=1, le=500, description="Maximum alerts to triage")


class BatchTriageResponse(BaseModel):
    """Batch triage results."""

    alerts_triaged: int
    average_confidence: float
    average_false_positive_probability: float
    triaged_alerts: list[AlertTriageResponse]
    timestamp: Optional[datetime] = None


class TriageStatsResponse(BaseModel):
    """Alert triage statistics."""

    total_triaged: int
    average_confidence: float
    accuracy_rate: float = Field(..., description="Percentage of correct triages")
    false_positive_reduction: float = Field(
        ..., description="Reduction in false positives from AI triage"
    )
    time_saved_hours: float = Field(..., description="Estimated analyst time saved")


# Incident Analysis

class IncidentAnalysisRequest(BaseModel):
    """Incident analysis request."""

    incident_id: str = Field(..., description="Incident ID to analyze")
    include_related: bool = Field(
        default=True, description="Include related alerts and events"
    )


class ImpactAssessment(BaseModel):
    """Impact assessment details."""

    affected_systems: list[str] = Field(default=[], description="Systems affected")
    data_exposed: list[str] = Field(default=[], description="Types of data exposed")
    users_affected: int = Field(default=0, description="Number of affected users")
    severity: str = Field(..., description="Overall impact severity")


class IncidentAnalysisResponse(DBModel):
    """Full incident analysis response."""

    incident_id: str
    executive_summary: str = Field(..., description="1-2 sentence executive summary")
    technical_details: str = Field(..., description="Detailed technical analysis")
    impact_assessment: ImpactAssessment
    recommendations: list[str] = Field(
        default=[], description="Recommended actions and improvements"
    )
    analysis_complete: bool

    class Config:
        from_attributes = True


class RootCauseAnalysis(BaseModel):
    """Root cause analysis results."""

    incident_id: str
    root_cause: str = Field(..., description="Identified root cause")
    attack_chain: list[str] = Field(..., description="Step-by-step attack progression")
    entry_point: str = Field(..., description="Initial compromise entry point")
    dwell_time_days: int = Field(..., description="Estimated attacker dwell time")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence")
    evidence: list[str] = Field(default=[], description="Supporting evidence")


class ResponseRecommendationRequest(BaseModel):
    """Request for incident response recommendations."""

    incident_id: str
    incident_type: str = Field(..., description="Type of incident")
    severity: str = Field(..., description="Severity level")
    include_timeline: bool = Field(default=True, description="Include timeline estimates")


class ResponseRecommendation(BaseModel):
    """Response recommendations."""

    immediate_actions: list[str] = Field(..., description="Actions to take immediately")
    containment_steps: list[str] = Field(..., description="Steps to contain the incident")
    investigation_steps: list[str] = Field(
        ..., description="Investigation activities"
    )
    recovery_plan: list[str] = Field(..., description="Recovery/remediation steps")
    timeline_estimate_hours: int = Field(
        ..., description="Estimated total response timeline"
    )


# Anomaly Detection

class AnomalyDetectionResponse(DBModel):
    """Detected anomaly with explanation."""

    id: str
    entity_type: str = Field(..., description="Type of entity (user, host, etc.)")
    entity_id: str = Field(..., description="ID of entity")
    anomaly_type: str = Field(
        ...,
        description="Type of anomaly (behavioral, statistical, temporal, volumetric, structural)",
    )
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Anomaly score")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")
    severity: str = Field(
        ..., description="Severity level (critical, high, medium, low, info)"
    )
    description: str = Field(..., description="AI-generated explanation of anomaly")
    features: dict[str, Any] = Field(default={}, description="Feature values that triggered anomaly")
    baseline: dict[str, Any] = Field(default={}, description="Expected normal values")
    deviation: dict[str, Any] = Field(default={}, description="How far from normal")
    is_confirmed: bool | None = Field(default=None, description="Analyst confirmation")
    is_false_positive: bool = Field(default=False, description="False positive flag")
    related_alerts: list[str] = Field(default=[], description="Related alert IDs")
    mitre_techniques: list[str] = Field(default=[], description="MITRE ATT&CK techniques")
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AnomalyFeedback(BaseModel):
    """Analyst feedback on anomaly."""

    is_confirmed: bool | None = Field(
        default=None, description="Whether anomaly is confirmed true positive"
    )
    is_false_positive: bool | None = Field(
        default=None, description="Whether this is a false positive"
    )
    notes: str | None = Field(default=None, description="Analyst notes")


class AnomalyListResponse(BaseModel):
    """List of anomalies with filtering and pagination."""

    total: int
    skip: int
    limit: int
    anomalies: list[AnomalyDetectionResponse]


class AnomalyStatsResponse(BaseModel):
    """Anomaly detection statistics."""

    total_detected: int = Field(..., description="Total anomalies detected (30 days)")
    by_severity: dict[str, int] = Field(..., description="Count by severity level")
    by_type: dict[str, int] = Field(..., description="Count by anomaly type")
    by_entity: dict[str, int] = Field(
        ..., description="Count by entity type (user, host, etc.)"
    )
    confirmed_rate: float = Field(..., description="Percentage confirmed as true positive")
    false_positive_rate: float = Field(..., description="Percentage false positives")
    avg_detection_latency_seconds: float


# Threat Predictions

class ThreatPredictionRequest(BaseModel):
    """Request threat prediction for entity."""

    entity_id: str = Field(..., description="Entity ID")
    entity_type: str = Field(
        default="host", description="Entity type (user, host, application, etc.)"
    )
    time_horizon_hours: int = Field(
        default=24, ge=1, le=720, description="Time horizon for prediction"
    )


class ThreatPredictionResponse(DBModel):
    """Threat prediction result."""

    id: str
    entity_type: str
    entity_id: str
    prediction_type: str = Field(
        ...,
        description="Type of prediction (attack_probability, lateral_movement, etc.)",
    )
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score (0-100)")
    probability: float = Field(..., ge=0.0, le=1.0, description="Attack probability")
    time_horizon_hours: int
    contributing_factors: list[str] = Field(
        ..., description="Factors contributing to prediction"
    )
    recommended_actions: list[str] = Field(
        ..., description="Recommended mitigation actions"
    )
    mitre_techniques: list[str] = Field(
        default=[], description="Predicted MITRE techniques"
    )
    expires_at: datetime = Field(..., description="When this prediction expires")
    was_accurate: bool | None = Field(default=None, description="Prediction accuracy feedback")
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class LateralMovementPrediction(BaseModel):
    """Predicted lateral movement path."""

    target: str = Field(..., description="Target system/host")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk score for this path")
    probability: float
    attack_vector: str = Field(..., description="Predicted attack vector")
    supporting_evidence: list[str] = Field(..., description="Evidence supporting prediction")


class PredictionDashboard(BaseModel):
    """Threat prediction dashboard data."""

    active_predictions: int
    critical_risk_entities: int
    avg_risk_score: float
    predictions_by_type: dict[str, int]
    trending_threats: list[str]
    top_at_risk_entities: list[dict[str, Any]]


# ML Models

class ModelTrainingRequest(BaseModel):
    """Request to train ML model."""

    model_type: str = Field(
        ...,
        description="Type of model (anomaly_detection, classification, etc.)",
    )
    algorithm: str = Field(
        ...,
        description="Algorithm to use (isolation_forest, autoencoder, lstm, etc.)",
    )
    version: str | None = Field(default=None, description="Version identifier")
    description: str | None = Field(default=None, description="Model description")
    hyperparameters: dict[str, Any] | None = Field(default=None, description="Model hyperparameters")
    tags: list[str] | None = Field(default=None, description="Tags for organization")
    trigger_retraining: bool = Field(
        default=False, description="Trigger immediate retraining of existing models"
    )


class MLModelResponse(DBModel):
    """ML model details."""

    id: str
    name: str
    model_type: str
    algorithm: str
    version: str
    status: str = Field(..., description="training, ready, deployed, retired, failed")
    description: str | None
    feature_columns: list[str]
    hyperparameters: dict[str, Any]
    training_metrics: dict[str, float]
    training_data_size: int
    last_trained_at: datetime | None
    last_prediction_at: datetime | None
    prediction_count: int
    drift_score: float
    tags: list[str]
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ModelDriftResponse(BaseModel):
    """Model drift check results."""

    model_id: str
    drift_score: float = Field(..., ge=0.0, le=1.0, description="Current drift score")
    status: str = Field(
        ...,
        description="ok, warning, critical - whether retraining is recommended",
    )
    last_checked_at: Optional[datetime] = None
    recommendation: str | None = Field(
        default=None, description="Recommendation for model maintenance"
    )


# AI Feedback

class AIFeedbackRequest(BaseModel):
    """Feedback on AI analysis."""

    analysis_id: str
    feedback_score: int = Field(..., ge=-1, le=1, description="-1 (wrong), 0 (partial), 1 (correct)")
    feedback_notes: str | None = Field(default=None, description="Detailed feedback")


# Dashboard

class AIDashboardResponse(BaseModel):
    """AI engine dashboard statistics."""

    total_analyses: int = Field(..., description="Total AI analyses performed")
    analyses_today: int
    average_confidence: float
    accuracy_rate: float = Field(..., description="Overall analysis accuracy")

    total_anomalies_detected: int
    anomalies_confirmed_rate: float
    false_positive_rate: float

    models_deployed: int
    models_in_training: int
    avg_model_drift: float
    models_needing_retrain: int

    active_threat_predictions: int
    critical_risk_entities: int

    queries_processed: int
    queries_today: int
    avg_query_accuracy: float

    last_updated: Optional[datetime] = None
