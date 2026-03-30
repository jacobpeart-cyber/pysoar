"""
SQLAlchemy models for AI/ML Security Engine.

Models represent ML models, anomaly detections, AI analyses, threat predictions,
and natural language queries.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base, BaseModel, utc_now


class MLModel(BaseModel):
    """
    Machine Learning Model Registry.

    Stores metadata, configuration, and metrics for trained ML models used
    in anomaly detection, threat scoring, and other security operations.
    """

    __tablename__ = "ml_models"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    model_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="anomaly_detection, classification, clustering, nlp, time_series, threat_scoring",
    )
    algorithm: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="isolation_forest, autoencoder, lstm, random_forest, xgboost, transformer, statistical",
    )
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="training",
        comment="training, ready, deployed, retired, failed",
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    feature_columns: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    hyperparameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    training_metrics: Mapped[dict[str, float]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="accuracy, precision, recall, f1, auc",
    )
    model_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    training_data_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_trained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_prediction_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    prediction_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    drift_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))

    # Relationships
    anomaly_detections: Mapped[list["AnomalyDetection"]] = relationship(
        "AnomalyDetection", back_populates="model", cascade="all, delete-orphan"
    )
    threat_predictions: Mapped[list["ThreatPrediction"]] = relationship(
        "ThreatPrediction", back_populates="model", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<MLModel {self.name} v{self.version} ({self.status})>"


class AnomalyDetection(BaseModel):
    """
    Detected Anomalies.

    Records suspicious patterns detected by ML models. Includes anomaly score,
    type, baseline values, and analyst feedback for continuous model improvement.
    """

    __tablename__ = "anomaly_detections"

    model_id: Mapped[str] = mapped_column(String(36), ForeignKey("ml_models.id"))
    entity_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="user, host, network, process, application",
    )
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    anomaly_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="behavioral, statistical, temporal, volumetric, structural",
    )
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="critical, high, medium, low, info",
    )
    features: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False, comment="feature values that triggered the anomaly"
    )
    baseline: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False, comment="expected normal values"
    )
    deviation: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False, comment="how far from normal"
    )
    description: Mapped[str] = mapped_column(
        Text, nullable=False, comment="AI-generated explanation"
    )
    is_confirmed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    related_alerts: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))

    # Relationships
    model: Mapped["MLModel"] = relationship("MLModel", back_populates="anomaly_detections")

    def __repr__(self) -> str:
        return f"<AnomalyDetection {self.entity_type}/{self.entity_id} score={self.anomaly_score:.2f}>"


class AIAnalysis(BaseModel):
    """
    AI Analysis Results.

    Stores results from LLM-powered analysis including alert triage, incident
    summaries, threat assessments, and response recommendations.
    """

    __tablename__ = "ai_analyses"

    analysis_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="alert_triage, incident_summary, threat_assessment, response_recommendation, playbook_generation, root_cause, impact_analysis, natural_language_query",
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="alert, incident, hunt_finding, log_pattern, query",
    )
    source_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    input_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    prompt_used: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_response: Mapped[str] = mapped_column(Text, nullable=False)
    structured_output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    model_used: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="gpt-4, claude, local-llm, ensemble",
    )
    tokens_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    feedback_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    feedback_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))

    def __repr__(self) -> str:
        return f"<AIAnalysis {self.analysis_type} confidence={self.confidence:.2f}>"


class ThreatPrediction(BaseModel):
    """
    Threat Predictions.

    Records ML-generated predictions about potential future threats, including
    attack probability, lateral movement risk, and data exfiltration likelihood.
    """

    __tablename__ = "threat_predictions"

    prediction_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="attack_probability, vulnerability_exploitation, lateral_movement, data_exfiltration, insider_threat",
    )
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    time_horizon_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    contributing_factors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    model_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("ml_models.id"), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    was_accurate: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))

    # Relationships
    model: Mapped["MLModel | None"] = relationship("MLModel", back_populates="threat_predictions")

    def __repr__(self) -> str:
        return f"<ThreatPrediction {self.prediction_type} risk={self.risk_score:.1f}>"


class NLQuery(BaseModel):
    """
    Natural Language Queries.

    Records user natural language queries and their interpretations, generated
    queries, and results. Used for conversational security intelligence.
    """

    __tablename__ = "nl_queries"

    natural_language: Mapped[str] = mapped_column(Text, nullable=False)
    interpreted_intent: Mapped[str] = mapped_column(String(100), nullable=False)
    generated_query: Mapped[str] = mapped_column(Text, nullable=False)
    query_parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    results_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    execution_time_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    was_helpful: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))

    def __repr__(self) -> str:
        return f"<NLQuery intent={self.interpreted_intent} results={self.result_count}>"
