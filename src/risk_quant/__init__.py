"""Risk Quantification (FAIR Model) module for PySOAR

Implements the Factor Analysis of Information Risk framework for financial risk scoring
and Monte Carlo simulation-based risk analysis.
"""

from src.risk_quant.engine import (
    BIAEngine,
    ControlEffectivenessAnalyzer,
    FAIREngine,
    RiskAggregator,
)

__all__ = [
    "FAIREngine",
    "RiskAggregator",
    "ControlEffectivenessAnalyzer",
    "BIAEngine",
]
