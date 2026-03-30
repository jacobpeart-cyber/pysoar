"""
PySOAR Deception Technology Module.

Deploys honeypots, honeytokens, and decoy assets to detect attackers with near-zero false positives.
"""

from src.deception.engine import (
    DecoyManager,
    DeceptionOrchestrator,
    HoneyTokenGenerator,
    InteractionAnalyzer,
)
from src.deception.models import (
    Decoy,
    DecoyInteraction,
    DeceptionCampaign,
    HoneyToken,
)

__all__ = [
    "Decoy",
    "DecoyInteraction",
    "DeceptionCampaign",
    "HoneyToken",
    "DecoyManager",
    "HoneyTokenGenerator",
    "InteractionAnalyzer",
    "DeceptionOrchestrator",
]
