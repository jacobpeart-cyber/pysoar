"""
AI/ML Security Engine Module for PySOAR.

Provides intelligent security operations through machine learning and LLM capabilities:
- Anomaly Detection: Behavioral, statistical, temporal, and volumetric anomaly detection
- Threat Intelligence: Automated threat assessment and risk scoring
- Alert Triage: AI-powered alert prioritization and false positive reduction
- Incident Analysis: Root cause analysis and impact assessment
- Natural Language Queries: Conversational security intelligence
- Playbook Generation: Automated incident response playbook creation
- Threat Prediction: Proactive attack probability and lateral movement prediction

Core Components:
- MLModel: Manages trained ML models and their lifecycle
- AnomalyDetector: Detects suspicious patterns in security data
- AIAnalyzer: LLM-powered analysis and recommendations
- NaturalLanguageQueryEngine: Conversational query processing
- ThreatPredictor: Predictive threat intelligence

This module is the differentiating feature of PySOAR, enabling proactive
and intelligent security operations through AI/ML.
"""

__version__ = "1.0.0"
__all__ = [
    "AnomalyDetector",
    "AIAnalyzer",
    "NaturalLanguageQueryEngine",
    "ThreatPredictor",
]
