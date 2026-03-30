"""
Threat Modeling Engine for PySOAR

Supports STRIDE, PASTA, Attack Trees, LINDDUN, VAST, OCTAVE, and custom methodologies.
Provides automated threat identification, risk assessment, and mitigation planning.
"""

from src.threat_modeling.models import (
    ThreatModel,
    ThreatModelComponent,
    IdentifiedThreat,
    ThreatMitigation,
    AttackTree,
    ThreatModelStatus,
    ThreatModelMethodology,
    ComponentType,
    STRIDECategory,
    ThreatStatus,
    LikelihoodLevel,
    ImpactLevel,
    MitigationType,
    ImplementationStatus,
)
from src.threat_modeling.engine import (
    STRIDEAnalyzer,
    PASTAEngine,
    AttackTreeGenerator,
    MitigationRecommender,
    ThreatModelValidator,
)

__all__ = [
    "ThreatModel",
    "ThreatModelComponent",
    "IdentifiedThreat",
    "ThreatMitigation",
    "AttackTree",
    "ThreatModelStatus",
    "ThreatModelMethodology",
    "ComponentType",
    "STRIDECategory",
    "ThreatStatus",
    "LikelihoodLevel",
    "ImpactLevel",
    "MitigationType",
    "ImplementationStatus",
    "STRIDEAnalyzer",
    "PASTAEngine",
    "AttackTreeGenerator",
    "MitigationRecommender",
    "ThreatModelValidator",
]
