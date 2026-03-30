"""
Breach & Attack Simulation (BAS) Engine Module

Provides comprehensive attack simulation, adversary emulation, and security
posture assessment capabilities for PySOAR.
"""

from src.simulation.engine import (
    SimulationOrchestrator,
    AtomicTestLibrary,
    AdversaryEmulator,
    PostureScorer,
)
from src.simulation.models import (
    AttackSimulation,
    AttackTechnique,
    SimulationTest,
    AdversaryProfile,
    SecurityPostureScore,
)

__all__ = [
    "SimulationOrchestrator",
    "AtomicTestLibrary",
    "AdversaryEmulator",
    "PostureScorer",
    "AttackSimulation",
    "AttackTechnique",
    "SimulationTest",
    "AdversaryProfile",
    "SecurityPostureScore",
]
