"""DFIR (Digital Forensics & Incident Response) Module

Provides comprehensive forensic case management, evidence collection and verification,
timeline reconstruction, artifact analysis, and legal hold management for incident
investigation workflows.
"""

from src.dfir.models import (
    ForensicCase,
    ForensicEvidence,
    ForensicTimeline,
    ForensicArtifact,
    LegalHold,
    CaseStatus,
    CaseType,
    EvidenceType,
    AcquisitionMethod,
    ArtifactType,
    HoldType,
)
from src.dfir.engine import (
    ForensicEngine,
    EvidenceManager,
    TimelineReconstructor,
    ArtifactAnalyzer,
    LegalHoldManager,
)

__all__ = [
    # Models
    "ForensicCase",
    "ForensicEvidence",
    "ForensicTimeline",
    "ForensicArtifact",
    "LegalHold",
    # Enums
    "CaseStatus",
    "CaseType",
    "EvidenceType",
    "AcquisitionMethod",
    "ArtifactType",
    "HoldType",
    # Engine classes
    "ForensicEngine",
    "EvidenceManager",
    "TimelineReconstructor",
    "ArtifactAnalyzer",
    "LegalHoldManager",
]
