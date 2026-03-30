"""Vulnerability Management module for PySOAR

This module provides comprehensive vulnerability management capabilities including:
- Vulnerability database and tracking
- Scan profile management
- Patch orchestration and deployment
- Risk prioritization and SLA management
- CISA KEV (Known Exploited Vulnerabilities) monitoring
- Vulnerability lifecycle tracking
"""

from src.vulnmgmt.engine import (
    KEVMonitor,
    PatchOrchestrator,
    RiskPrioritizer,
    VulnerabilityLifecycle,
    VulnerabilityScanner,
)

__all__ = [
    "VulnerabilityScanner",
    "RiskPrioritizer",
    "PatchOrchestrator",
    "VulnerabilityLifecycle",
    "KEVMonitor",
]
