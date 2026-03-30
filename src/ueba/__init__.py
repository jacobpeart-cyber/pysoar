"""
UEBA (User & Entity Behavior Analytics) Module
Analyzes user and entity behavior to detect anomalies and security threats.
"""

from src.ueba.models import (
    EntityProfile,
    BehaviorBaseline,
    BehaviorEvent,
    UEBARiskAlert,
    PeerGroup,
)
from src.ueba.engine import (
    BehaviorAnalyzer,
    RiskScorer,
    ImpossibleTravelDetector,
    PeerGroupAnalyzer,
    BaselineManager,
)

__all__ = [
    "EntityProfile",
    "BehaviorBaseline",
    "BehaviorEvent",
    "UEBARiskAlert",
    "PeerGroup",
    "BehaviorAnalyzer",
    "RiskScorer",
    "ImpossibleTravelDetector",
    "PeerGroupAnalyzer",
    "BaselineManager",
]
