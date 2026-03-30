"""
Data Loss Prevention (DLP) Module

Comprehensive data loss prevention system for detecting, preventing, and responding
to unauthorized data exfiltration, PII exposure, and regulatory violations.

Includes policy management, violation detection, data discovery, classification,
breach assessment, and incident response capabilities.
"""

from src.dlp.engine import (
    DLPEngine,
    DataClassifier,
    ExfiltrationDetector,
    DiscoveryScanner,
    BreachAssessor,
)
from src.dlp.models import (
    DLPPolicy,
    DLPViolation,
    DataClassification,
    SensitiveDataDiscovery,
    DLPIncident,
)

__all__ = [
    "DLPEngine",
    "DataClassifier",
    "ExfiltrationDetector",
    "DiscoveryScanner",
    "BreachAssessor",
    "DLPPolicy",
    "DLPViolation",
    "DataClassification",
    "SensitiveDataDiscovery",
    "DLPIncident",
]
