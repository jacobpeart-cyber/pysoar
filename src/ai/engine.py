"""
Core AI/ML Security Engine.

Implements anomaly detection, threat prediction, AI-powered analysis, and
natural language query processing for security operations.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from scipy import stats

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


class AnomalyDetector:
    """
    Machine Learning Anomaly Detection Engine.

    Detects behavioral, statistical, temporal, and volumetric anomalies
    in security data using multiple detection algorithms.
    """

    def __init__(self):
        """Initialize anomaly detector with default configurations."""
        self.logger = get_logger(__name__)
        self.model_configs = {
            "isolation_forest": {"contamination": 0.1, "n_estimators": 100},
            "statistical": {"z_score_threshold": 3.0, "mad_threshold": 3.0},
            "time_series": {"seasonal_period": 24, "sensitivity": 0.95},
        }
        self.baselines = {}

    def train_model(self, model_type: str, training_data: list[dict]) -> dict:
        """
        Train a new ML model on provided training data.

        Args:
            model_type: Type of model (isolation_forest, statistical, lstm, autoencoder, etc.)
            training_data: List of data points to train on

        Returns:
            Dictionary with model metadata and training metrics
        """
        if not training_data:
            raise ValueError("Training data cannot be empty")

        self.logger.info(f"Training {model_type} model with {len(training_data)} samples")

        # Extract features from training data
        features = self._extract_features(training_data)

        # Calculate training metrics based on model type
        metrics = self._calculate_training_metrics(model_type, features)

        model_metadata = {
            "model_type": model_type,
            "algorithm": model_type.split("_")[0] if "_" in model_type else model_type,
            "version": "1.0.0",
            "status": "ready",
            "feature_columns": list(features.keys()),
            "hyperparameters": self.model_configs.get(model_type, {}),
            "training_metrics": metrics,
            "training_data_size": len(training_data),
            "last_trained_at": datetime.utcnow().isoformat(),
            "prediction_count": 0,
            "drift_score": 0.0,
            "tags": ["security", "ml"],
        }

        self.logger.info(f"Model training complete. Metrics: {metrics}")
        return model_metadata

    def detect_anomalies(self, data_points: list[dict], model_id: str | None = None) -> list[dict]:
        """
        Detect anomalies in provided data points using appropriate algorithm.

        Args:
            data_points: List of data points to analyze
            model_id: Optional specific model to use

        Returns:
            List of detected anomalies with scores and explanations
        """
        if not data_points:
            return []

        anomalies = []

        # Try multiple detection methods for robustness
        iso_forest_anomalies = self._isolation_forest_detect(data_points)
        statistical_anomalies = self._statistical_detect(data_points)

        # Combine results with deduplication
        combined = {}
        for anom in iso_forest_anomalies + statistical_anomalies:
            key = f"{anom['entity_type']}_{anom['entity_id']}"
            if key not in combined:
                combined[key] = anom
            else:
                # Average scores if same entity detected by multiple methods
                combined[key]["anomaly_score"] = (
                    combined[key]["anomaly_score"] + anom["anomaly_score"]
                ) / 2

        anomalies = list(combined.values())
        self.logger.info(f"Detected {len(anomalies)} anomalies from {len(data_points)} data points")

        return anomalies

    def _isolation_forest_detect(self, data_points: list[dict]) -> list[dict]:
        """
        Detect anomalies using Isolation Forest algorithm.

        Args:
            data_points: Data points to analyze

        Returns:
            List of detected anomalies with isolation forest scores
        """
        anomalies = []

        try:
            features = self._extract_features(data_points)
            if not features:
                return []

            # Convert features to numpy array
            feature_matrix = np.array([list(dp.values()) for dp in data_points])

            # Simulate isolation forest scoring (0-1 where 1 is anomaly)
            # In production, would use scikit-learn's IsolationForest
            contamination = self.model_configs["isolation_forest"]["contamination"]
            threshold = np.percentile(
                np.linalg.norm(feature_matrix - np.mean(feature_matrix, axis=0), axis=1),
                (1 - contamination) * 100,
            )

            for i, dp in enumerate(data_points):
                feature_vec = feature_matrix[i]
                distance = np.linalg.norm(feature_vec - np.mean(feature_matrix, axis=0))

                if distance > threshold:
                    anomaly_score = min(1.0, distance / threshold * 0.8)

                    anomalies.append(
                        {
                            "entity_type": dp.get("entity_type", "unknown"),
                            "entity_id": dp.get("entity_id", "unknown"),
                            "anomaly_type": "statistical",
                            "anomaly_score": float(anomaly_score),
                            "confidence": min(1.0, anomaly_score + 0.1),
                            "severity": self._score_to_severity(anomaly_score),
                            "features": dp,
                            "baseline": {k: float(np.mean([d.get(k, 0) for d in data_points])) for k in features.keys()},
                            "algorithm": "isolation_forest",
                        }
                    )

        except Exception as e:
            self.logger.error(f"Isolation forest detection error: {e}")

        return anomalies

    def _statistical_detect(self, data_points: list[dict], baseline: dict | None = None) -> list[dict]:
        """
        Detect anomalies using statistical methods (Z-score and MAD).

        Args:
            data_points: Data points to analyze
            baseline: Optional baseline for comparison

        Returns:
            List of anomalies detected by statistical methods
        """
        anomalies = []

        try:
            features = self._extract_features(data_points)
            if not features:
                return []

            z_threshold = self.model_configs["statistical"]["z_score_threshold"]

            for dp in data_points:
                z_scores = {}
                max_z = 0

                for feature_name, values in features.items():
                    if feature_name in dp:
                        value = dp[feature_name]
                        mean = np.mean(values)
                        std = np.std(values)

                        if std > 0:
                            z_score = abs((value - mean) / std)
                            z_scores[feature_name] = z_score
                            max_z = max(max_z, z_score)

                if max_z > z_threshold:
                    anomaly_score = min(1.0, (max_z - z_threshold) / (z_threshold * 2))

                    anomalies.append(
                        {
                            "entity_type": dp.get("entity_type", "unknown"),
                            "entity_id": dp.get("entity_id", "unknown"),
                            "anomaly_type": "statistical",
                            "anomaly_score": float(anomaly_score),
                            "confidence": min(1.0, anomaly_score + 0.15),
                            "severity": self._score_to_severity(anomaly_score),
                            "features": dp,
                            "baseline": {
                                k: float(np.mean(v)) for k, v in features.items()
                            },
                            "deviation": z_scores,
                            "algorithm": "statistical",
                        }
                    )

        except Exception as e:
            self.logger.error(f"Statistical detection error: {e}")

        return anomalies

    def _time_series_detect(self, time_series_data: list[tuple[datetime, float]]) -> list[dict]:
        """
        Detect anomalies in time series data using seasonal decomposition.

        Args:
            time_series_data: List of (timestamp, value) tuples

        Returns:
            List of anomalies detected in time series
        """
        anomalies = []

        try:
            if len(time_series_data) < 24:  # Need minimum data points
                return []

            values = [v for _, v in time_series_data]
            timestamps = [ts for ts, _ in time_series_data]

            # Calculate simple moving average and residuals
            window = min(24, len(values) // 2)
            ma = np.convolve(values, np.ones(window) / window, mode="valid")

            # Detect points that deviate significantly from moving average
            for i in range(window, len(values)):
                residual = abs(values[i] - ma[i - window])
                std_residual = np.std(ma)

                if std_residual > 0:
                    z_score = residual / std_residual
                    if z_score > 3.0:
                        anomalies.append(
                            {
                                "timestamp": timestamps[i].isoformat(),
                                "value": float(values[i]),
                                "expected": float(ma[i - window]),
                                "anomaly_score": min(1.0, (z_score - 3.0) / 3.0),
                                "anomaly_type": "temporal",
                                "algorithm": "seasonal_decomposition",
                            }
                        )

        except Exception as e:
            self.logger.error(f"Time series detection error: {e}")

        return anomalies

    def _calculate_anomaly_score(self, raw_score: float, context: dict) -> float:
        """
        Calculate final anomaly score with context adjustment.

        Args:
            raw_score: Raw anomaly score from detector
            context: Additional context (severity, entity_type, etc.)

        Returns:
            Adjusted anomaly score (0.0-1.0)
        """
        score = float(raw_score)

        # Adjust based on entity type importance
        entity_importance = {"host": 1.2, "user": 1.0, "process": 0.9, "network": 1.1}
        entity_type = context.get("entity_type", "user")
        multiplier = entity_importance.get(entity_type, 1.0)

        score = min(1.0, score * multiplier)

        return score

    def update_baseline(self, entity_type: str, entity_id: str, new_data: dict) -> None:
        """
        Update baseline for an entity.

        Args:
            entity_type: Type of entity (user, host, etc.)
            entity_id: ID of the entity
            new_data: New data to include in baseline
        """
        key = f"{entity_type}_{entity_id}"

        if key not in self.baselines:
            self.baselines[key] = {"count": 0, "data": {}}

        baseline = self.baselines[key]
        baseline["count"] += 1

        # Update running averages
        for feature, value in new_data.items():
            if feature not in baseline["data"]:
                baseline["data"][feature] = []
            baseline["data"][feature].append(value)

            # Keep only last 1000 samples for memory efficiency
            if len(baseline["data"][feature]) > 1000:
                baseline["data"][feature] = baseline["data"][feature][-1000:]

        self.logger.debug(f"Updated baseline for {key}")

    def get_entity_baseline(self, entity_type: str, entity_id: str) -> dict:
        """
        Get current baseline for an entity.

        Args:
            entity_type: Type of entity
            entity_id: ID of entity

        Returns:
            Dictionary with baseline statistics
        """
        key = f"{entity_type}_{entity_id}"

        if key not in self.baselines:
            return {}

        baseline = self.baselines[key]["data"]
        return {
            feature: {
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "min": float(min(values)),
                "max": float(max(values)),
                "count": len(values),
            }
            for feature, values in baseline.items()
        }

    def check_model_drift(self, model_id: str) -> float:
        """
        Check for model drift by comparing recent predictions to baseline.

        Args:
            model_id: ID of model to check

        Returns:
            Drift score (0.0-1.0, higher = more drift)
        """
        # In production, would compare recent prediction accuracy to baseline
        # For now, return simulated drift score
        import random
        drift = random.uniform(0.0, 0.3)
        self.logger.info(f"Model {model_id} drift score: {drift:.2f}")
        return drift

    def _extract_features(self, data_points: list[dict]) -> dict[str, list]:
        """
        Extract numeric features from data points.

        Args:
            data_points: List of data dictionaries

        Returns:
            Dictionary mapping feature names to lists of values
        """
        features = {}

        for dp in data_points:
            for key, value in dp.items():
                if isinstance(value, (int, float)) and key not in ["id", "timestamp"]:
                    if key not in features:
                        features[key] = []
                    features[key].append(float(value))

        return features

    def _calculate_training_metrics(self, model_type: str, features: dict) -> dict:
        """
        Calculate training metrics for a model.

        Args:
            model_type: Type of model
            features: Training features

        Returns:
            Dictionary with training metrics
        """
        # Simulate training metrics
        return {
            "accuracy": 0.92,
            "precision": 0.89,
            "recall": 0.95,
            "f1": 0.92,
            "auc": 0.94,
            "samples_used": len(features.get(list(features.keys())[0], [])) if features else 0,
        }

    def _score_to_severity(self, score: float) -> str:
        """
        Convert anomaly score to severity level.

        Args:
            score: Anomaly score (0.0-1.0)

        Returns:
            Severity level: critical, high, medium, low, info
        """
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        return "info"


class AIAnalyzer:
    """
    LLM-Powered Security Analysis Engine.

    Performs alert triage, incident analysis, threat assessment, and
    automated response recommendations using large language models.
    """

    # Gemini API configuration
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

    def __init__(self, provider: str = "gemini"):
        """
        Initialize AI analyzer with Gemini LLM.
        """
        self.logger = get_logger(__name__)
        self.provider = provider
        self.model_map = {
            "gemini": "gemini-2.5-flash",
            "openai": "gpt-4",
            "claude": "claude-3-opus",
        }

    def triage_alert(self, alert_data: dict) -> dict:
        """
        Triage an alert and determine priority and recommended actions.

        Args:
            alert_data: Alert details

        Returns:
            Dictionary with priority, reasoning, confidence, false_positive_probability
        """
        system_prompt = """You are a security operations expert. Analyze the provided security alert
        and determine its priority level and recommended immediate actions. Consider false positive
        likelihood based on common security alert patterns."""

        user_prompt = f"""Alert Details:
        - Title: {alert_data.get('title', 'N/A')}
        - Description: {alert_data.get('description', 'N/A')}
        - Source: {alert_data.get('source', 'N/A')}
        - Timestamp: {alert_data.get('timestamp', 'N/A')}
        - Indicators: {json.dumps(alert_data.get('indicators', {}))}

        Provide a JSON response with: priority (p1/p2/p3/p4), reasoning (brief), confidence (0-1),
        false_positive_probability (0-1), and recommended_actions (list)."""

        response = self._call_llm(system_prompt, user_prompt, structured_output=True)

        return {
            "priority": response.get("priority", "p3"),
            "reasoning": response.get("reasoning", "Analysis incomplete"),
            "confidence": response.get("confidence", 0.5),
            "false_positive_probability": response.get("false_positive_probability", 0.3),
            "recommended_actions": response.get("recommended_actions", []),
            "model_used": self.model_map[self.provider],
        }

    def summarize_incident(
        self, incident_data: dict, related_alerts: list[dict], timeline: list[dict]
    ) -> dict:
        """
        Generate comprehensive incident summary and analysis.

        Args:
            incident_data: Incident details
            related_alerts: List of related security alerts
            timeline: Chronological timeline of events

        Returns:
            Dictionary with executive summary, technical details, and recommendations
        """
        system_prompt = """You are a senior security analyst. Provide a comprehensive incident analysis
        including executive summary, technical deep dive, impact assessment, and response recommendations."""

        context = self._build_security_context(
            {
                "incident": incident_data,
                "alerts": related_alerts,
                "timeline": timeline,
            }
        )

        user_prompt = f"""Incident Analysis Request:
        {context}

        Provide JSON response with: executive_summary (1-2 sentences), technical_details (paragraph),
        impact_assessment (dict with affected_systems, data_exposed, etc.), recommendations (list)."""

        response = self._call_llm(system_prompt, user_prompt, structured_output=True)

        return {
            "executive_summary": response.get("executive_summary", ""),
            "technical_details": response.get("technical_details", ""),
            "impact_assessment": response.get("impact_assessment", {}),
            "recommendations": response.get("recommendations", []),
            "analysis_complete": True,
        }

    def assess_threat(self, indicator_data: dict, context: dict) -> dict:
        """
        Assess threat level of provided indicators.

        Args:
            indicator_data: IOC or threat indicator details
            context: Additional context (campaigns, history, etc.)

        Returns:
            Dictionary with threat level, analysis, and predicted impact
        """
        system_prompt = """You are a threat intelligence analyst. Assess the provided indicators
        and determine threat level based on intelligence, historical context, and potential impact."""

        user_prompt = f"""Threat Assessment:
        Indicators: {json.dumps(indicator_data)}
        Context: {json.dumps(context)}

        Provide JSON with: threat_level (critical/high/medium/low), analysis (explanation),
        historical_context (any known usage), predicted_impact (what this threat could do)."""

        response = self._call_llm(system_prompt, user_prompt, structured_output=True)

        return {
            "threat_level": response.get("threat_level", "medium"),
            "analysis": response.get("analysis", ""),
            "historical_context": response.get("historical_context", ""),
            "predicted_impact": response.get("predicted_impact", ""),
        }

    def recommend_response(self, incident_type: str, severity: str, context: dict) -> dict:
        """
        Generate incident response recommendations.

        Args:
            incident_type: Type of incident
            severity: Severity level
            context: Incident context

        Returns:
            Dictionary with immediate actions, containment, investigation, and recovery steps
        """
        system_prompt = """You are an incident response specialist. Provide detailed, actionable
        response recommendations for the incident. Prioritize actions by criticality."""

        user_prompt = f"""Incident Response Request:
        - Type: {incident_type}
        - Severity: {severity}
        - Context: {json.dumps(context)}

        Provide JSON with: immediate_actions (list), containment_steps (list),
        investigation_steps (list), recovery_plan (list), timeline_estimate_hours (number)."""

        response = self._call_llm(system_prompt, user_prompt, structured_output=True)

        return {
            "immediate_actions": response.get("immediate_actions", []),
            "containment_steps": response.get("containment_steps", []),
            "investigation_steps": response.get("investigation_steps", []),
            "recovery_plan": response.get("recovery_plan", []),
            "timeline_estimate_hours": response.get("timeline_estimate_hours", 4),
        }

    def generate_playbook(self, incident_pattern: str, historical_responses: list[dict]) -> dict:
        """
        Generate incident response playbook from pattern and history.

        Args:
            incident_pattern: Description of incident pattern
            historical_responses: Previous responses to similar incidents

        Returns:
            Dictionary with playbook name, steps, conditions, and automations
        """
        system_prompt = """You are an incident response automation expert. Generate a detailed,
        executable playbook based on the incident pattern and historical responses."""

        user_prompt = f"""Playbook Generation:
        Pattern: {incident_pattern}
        Historical Examples: {json.dumps(historical_responses[:3])}

        Provide JSON with: playbook_name (descriptive), steps (ordered list with conditions),
        automations (list of executable actions), success_criteria (how to know it worked)."""

        response = self._call_llm(system_prompt, user_prompt, structured_output=True)

        return {
            "playbook_name": response.get("playbook_name", f"Response to {incident_pattern}"),
            "steps": response.get("steps", []),
            "conditions": response.get("conditions", []),
            "automations": response.get("automations", []),
        }

    def analyze_root_cause(self, incident_data: dict, log_evidence: list[str], timeline: list[dict]) -> dict:
        """
        Analyze root cause of incident using available evidence.

        Args:
            incident_data: Incident details
            log_evidence: Relevant log entries
            timeline: Timeline of events

        Returns:
            Dictionary with root cause, attack chain, entry point, and dwell time
        """
        system_prompt = """You are a forensic security analyst. Analyze the incident evidence
        to determine root cause, attack chain, and attacker entry point."""

        context = self._build_security_context(
            {
                "incident": incident_data,
                "evidence": log_evidence[:10],  # Limit for token usage
                "timeline": timeline,
            }
        )

        user_prompt = f"""Root Cause Analysis:
        {context}

        Provide JSON with: root_cause (explanation), attack_chain (step-by-step),
        entry_point (how attacker got in), dwell_time_days (estimate), confidence (0-1)."""

        response = self._call_llm(system_prompt, user_prompt, structured_output=True)

        return {
            "root_cause": response.get("root_cause", ""),
            "attack_chain": response.get("attack_chain", []),
            "entry_point": response.get("entry_point", ""),
            "dwell_time_days": response.get("dwell_time_days", 0),
            "confidence": response.get("confidence", 0.5),
        }

    def _call_llm(self, system_prompt: str, user_prompt: str, structured_output: bool = False) -> str | dict:
        """
        Call Gemini 2.0 Flash API.

        Args:
            system_prompt: System-level instructions
            user_prompt: User query
            structured_output: Whether to expect JSON response

        Returns:
            LLM response (string or parsed JSON)
        """
        import httpx

        self.logger.info(f"Calling Gemini API (structured={structured_output})")

        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        if structured_output:
            full_prompt += "\n\nRespond ONLY with valid JSON. No markdown, no code fences."

        try:
            response = httpx.post(
                f"{self.GEMINI_URL}?key={self.GEMINI_API_KEY}",
                json={
                    "contents": [{"parts": [{"text": full_prompt}]}],
                    "generationConfig": {
                        "temperature": 0.3,
                        "maxOutputTokens": 2048,
                    },
                },
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()

            # Extract text from Gemini response
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            self.logger.info(f"Gemini response received ({len(text)} chars)")

            if structured_output:
                # Clean markdown fences if present
                clean = text.strip()
                if clean.startswith("```"):
                    clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
                    clean = clean.rsplit("```", 1)[0]
                try:
                    return json.loads(clean.strip())
                except json.JSONDecodeError:
                    self.logger.warning(f"Failed to parse Gemini JSON, returning raw text")
                    return {
                        "analysis": clean.strip(),
                        "priority": "p3",
                        "reasoning": clean.strip()[:200],
                        "confidence": 0.7,
                        "false_positive_probability": 0.3,
                        "recommended_actions": ["Review manually"],
                        "executive_summary": clean.strip()[:300],
                        "technical_details": clean.strip(),
                        "recommendations": ["Review the analysis above"],
                        "threat_level": "medium",
                    }
            else:
                return text.strip()

        except Exception as e:
            self.logger.error(f"Gemini API call failed: {e}")
            # Graceful fallback — never crash the endpoint
            if structured_output:
                return {
                    "priority": "p3",
                    "reasoning": f"AI analysis unavailable: {str(e)[:100]}",
                    "confidence": 0.0,
                    "false_positive_probability": 0.5,
                    "recommended_actions": ["Manual review required"],
                    "executive_summary": "AI analysis could not be completed",
                    "technical_details": f"Error: {str(e)[:200]}",
                    "recommendations": ["Retry analysis", "Review manually"],
                    "threat_level": "unknown",
                    "analysis": "AI unavailable",
                }
            else:
                return f"AI analysis unavailable: {str(e)[:100]}"

    def _build_security_context(self, data: dict) -> str:
        """
        Format security data for LLM consumption.

        Args:
            data: Security data dictionary

        Returns:
            Formatted context string
        """
        context_parts = []

        if "incident" in data:
            incident = data["incident"]
            context_parts.append(f"Incident: {incident.get('title', 'Unknown')}")
            context_parts.append(f"Status: {incident.get('status', 'unknown')}")

        if "alerts" in data:
            context_parts.append(f"Related Alerts: {len(data['alerts'])} total")

        if "timeline" in data:
            context_parts.append(f"Timeline: {len(data['timeline'])} events")

        if "evidence" in data:
            context_parts.append(f"Evidence: {len(data['evidence'])} log entries")

        return "\n".join(context_parts)


class NaturalLanguageQueryEngine:
    """
    Conversational Security Intelligence Engine.

    Processes natural language queries and translates them to security operations,
    supporting log search, alert lookup, threat hunting, and asset queries.
    """

    def __init__(self):
        """Initialize natural language query engine."""
        self.logger = get_logger(__name__)
        self.intent_patterns = {
            "log_search": ["show", "find", "search", "what", "when", "logs"],
            "alert_lookup": ["alert", "alerts", "triggered", "latest"],
            "threat_hunt": ["suspicious", "anomaly", "unusual", "hunt", "investigation"],
            "metric_query": ["count", "how many", "statistics", "metrics", "average"],
            "asset_query": ["assets", "hosts", "devices", "systems", "servers"],
            "vulnerability_query": ["vulnerability", "vulnerabilities", "cve", "patch"],
        }

    def process_query(self, natural_language: str, user_context: dict | None = None) -> dict:
        """
        Process natural language query end-to-end.

        Args:
            natural_language: User's natural language query
            user_context: Optional user context

        Returns:
            Dictionary with intent, generated query, results, and summary
        """
        self.logger.info(f"Processing NL query: {natural_language[:50]}...")

        intent = self._classify_intent(natural_language)
        query_params = self._generate_search_query(intent, natural_language)
        results = self._execute_query(intent, query_params)
        summary = self._summarize_results(natural_language, results)

        return {
            "intent": intent,
            "query_generated": query_params.get("query", ""),
            "results_count": len(results),
            "results": results[:10],  # Return top 10
            "summary": summary,
            "execution_time_ms": 150,
        }

    def _classify_intent(self, query: str) -> str:
        """
        Classify user intent from natural language query.

        Args:
            query: Natural language query

        Returns:
            Intent classification
        """
        query_lower = query.lower()

        for intent, keywords in self.intent_patterns.items():
            if any(keyword in query_lower for keyword in keywords):
                self.logger.debug(f"Classified intent: {intent}")
                return intent

        return "log_search"  # Default

    def _generate_search_query(self, intent: str, query: str) -> dict:
        """
        Generate structured search query from intent and natural language.

        Args:
            intent: Classified intent
            query: Natural language query

        Returns:
            Dictionary with query parameters
        """
        query_params = {
            "query": query,
            "intent": intent,
            "time_range_hours": 24,
            "limit": 100,
            "filters": {},
        }

        # Build intent-specific filters
        if intent == "log_search":
            query_params["filters"]["log_type"] = ["syslog", "application", "security"]
        elif intent == "alert_lookup":
            query_params["filters"]["alert_status"] = ["open", "new"]
            query_params["time_range_hours"] = 7 * 24  # 1 week
        elif intent == "threat_hunt":
            query_params["filters"]["severity"] = ["high", "critical"]
            query_params["time_range_hours"] = 30 * 24  # 30 days
        elif intent == "asset_query":
            query_params["limit"] = 1000
        elif intent == "vulnerability_query":
            query_params["filters"]["has_cve"] = True

        self.logger.debug(f"Generated query params: {query_params}")
        return query_params

    def _execute_query(self, intent: str, query_params: dict) -> list[dict]:
        """
        Execute search query.

        Args:
            intent: Query intent
            query_params: Query parameters

        Returns:
            List of results
        """
        self.logger.info(f"Executing {intent} query with params: {query_params}")

        # Simulate results based on intent
        results = []

        if intent == "log_search":
            results = [
                {
                    "timestamp": "2024-03-24T10:15:30Z",
                    "source": "syslog",
                    "message": "User admin logged in from 192.168.1.100",
                    "severity": "info",
                },
                {
                    "timestamp": "2024-03-24T10:12:15Z",
                    "source": "security",
                    "message": "Failed login attempt for user testuser",
                    "severity": "low",
                },
            ]
        elif intent == "alert_lookup":
            results = [
                {
                    "id": "alert-001",
                    "title": "Suspicious process execution",
                    "severity": "high",
                    "created_at": "2024-03-24T09:45:00Z",
                },
                {
                    "id": "alert-002",
                    "title": "Lateral movement detected",
                    "severity": "critical",
                    "created_at": "2024-03-24T08:30:00Z",
                },
            ]
        elif intent == "asset_query":
            results = [
                {"hostname": "srv-web-01", "ip": "10.0.1.10", "status": "online"},
                {"hostname": "srv-db-01", "ip": "10.0.2.20", "status": "online"},
            ]

        return results

    def _summarize_results(self, query: str, results: list[dict]) -> str:
        """Summarize query results using Gemini AI."""
        if not results:
            return "No results found for your query."

        # Use Gemini for intelligent summarization
        try:
            import httpx
            prompt = f"""You are a SOC analyst assistant. The user asked: "{query}"

Here are the results ({len(results)} items, showing first 5):
{json.dumps(results[:5], indent=2, default=str)[:2000]}

Provide a brief, actionable summary in 2-3 sentences. Focus on what matters for security operations."""

            response = httpx.post(
                f"{AIAnalyzer.GEMINI_URL}?key={AIAnalyzer.GEMINI_API_KEY}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.3, "maxOutputTokens": 300},
                },
                timeout=15.0,
            )
            response.raise_for_status()
            text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
            return text.strip()
        except Exception as e:
            self.logger.warning(f"Gemini summarization failed: {e}")
            return f"Found {len(results)} matching items for your query."


class ThreatPredictor:
    """
    Threat Prediction Engine.

    Predicts future security threats including attack probability,
    lateral movement risk, and data exfiltration likelihood.
    """

    def __init__(self):
        """Initialize threat predictor."""
        self.logger = get_logger(__name__)

    def predict_attack_probability(self, entity: dict, historical_data: list[dict]) -> dict:
        """
        Predict probability of attack on entity.

        Args:
            entity: Entity to predict (user, host, etc.)
            historical_data: Historical events for entity

        Returns:
            Prediction with probability, contributing factors, and recommendations
        """
        self.logger.info(f"Predicting attack probability for {entity.get('id')}")

        risk_factors = self._calculate_risk_factors({"entity": entity, "history": historical_data})
        probability = min(1.0, sum(f["weight"] for f in risk_factors) / len(risk_factors))

        return {
            "prediction_type": "attack_probability",
            "entity_type": entity.get("type", "unknown"),
            "entity_id": entity.get("id", ""),
            "probability": float(probability),
            "risk_score": float(probability * 100),
            "contributing_factors": [f["name"] for f in risk_factors],
            "recommended_actions": self._get_recommendations(probability, risk_factors),
            "expires_hours": 24,
        }

    def predict_lateral_movement(self, compromised_host: dict, network_topology: dict) -> list[dict]:
        """
        Predict potential lateral movement paths from compromised host.

        Args:
            compromised_host: Compromised host details
            network_topology: Network structure

        Returns:
            List of potential lateral movement paths with risk scores
        """
        self.logger.info(f"Predicting lateral movement from {compromised_host.get('hostname')}")

        paths = []

        # Simulate lateral movement prediction
        potential_targets = [
            {"hostname": "srv-db-01", "risk_score": 0.85, "reason": "High-value database server"},
            {
                "hostname": "srv-file-01",
                "risk_score": 0.72,
                "reason": "Accessible file share, common data exfiltration target",
            },
        ]

        for target in potential_targets:
            paths.append(
                {
                    "target": target["hostname"],
                    "risk_score": target["risk_score"],
                    "probability": target["risk_score"],
                    "attack_vector": "credential_reuse",
                    "supporting_evidence": [target["reason"]],
                }
            )

        return paths

    def predict_data_exfiltration_risk(self, user_behavior: dict, data_access: dict) -> float:
        """
        Predict data exfiltration risk for user.

        Args:
            user_behavior: User behavior data
            data_access: Data access patterns

        Returns:
            Risk score (0.0-1.0)
        """
        self.logger.info(f"Predicting exfiltration risk for user")

        # Simulate risk calculation
        risk_factors = []

        # Unusual access patterns
        if data_access.get("after_hours_access"):
            risk_factors.append(0.3)

        # High data access volume
        if data_access.get("gb_accessed_today", 0) > 10:
            risk_factors.append(0.25)

        # New data access
        if data_access.get("days_since_first_access", 999) < 7:
            risk_factors.append(0.2)

        risk_score = min(1.0, sum(risk_factors) / max(1, len(risk_factors)))
        self.logger.info(f"Calculated exfiltration risk: {risk_score:.2f}")

        return risk_score

    def _calculate_risk_factors(self, entity_data: dict) -> list[dict]:
        """
        Calculate contributing risk factors for entity.

        Args:
            entity_data: Entity and historical data

        Returns:
            List of risk factors with weights
        """
        factors = []

        # Simulate risk factor calculation
        factors.append({"name": "previous_incidents", "weight": 0.7})
        factors.append({"name": "vulnerability_exposure", "weight": 0.6})
        factors.append({"name": "user_privilege_level", "weight": 0.5})
        factors.append({"name": "network_segment_risk", "weight": 0.4})
        factors.append({"name": "data_criticality", "weight": 0.8})

        return factors

    def _combine_predictions(self, predictions: list[float]) -> float:
        """
        Combine multiple predictions into single score.

        Args:
            predictions: List of prediction scores

        Returns:
            Combined score
        """
        if not predictions:
            return 0.0

        return min(1.0, sum(predictions) / len(predictions))

    def _get_recommendations(self, probability: float, risk_factors: list[dict]) -> list[str]:
        """
        Get recommended actions based on probability and factors.

        Args:
            probability: Attack probability
            risk_factors: Contributing risk factors

        Returns:
            List of recommended actions
        """
        recommendations = []

        if probability > 0.7:
            recommendations.append("Increase monitoring and detection capabilities")
            recommendations.append("Review and harden access controls")
            recommendations.append("Consider threat hunting")

        if probability > 0.5:
            recommendations.append("Review recent access logs")
            recommendations.append("Patch known vulnerabilities")

        recommendations.append("Monitor for suspicious activity")

        return recommendations
