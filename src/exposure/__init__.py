"""
Continuous Threat Exposure Management (CTEM) Module

This module provides comprehensive exposure management capabilities for PySOAR:

- Asset Discovery: Automatically discover and inventory assets across your infrastructure
- Vulnerability Management: Track, prioritize, and manage vulnerabilities with contextual risk
- Exposure Scoring: Calculate real-time risk scores based on CVSS, EPSS, and asset criticality
- Attack Surface Management: Monitor and assess your organization's external and internal attack surface
- Remediation Tracking: Manage remediation efforts with SLA tracking and verification

The CTEM module integrates with multiple vulnerability scanners, SIEM systems, and external threat
intelligence sources to provide a unified view of your organization's security exposure.
"""

from src.exposure.models import (
    AttackSurface,
    AssetVulnerability,
    ExposureAsset,
    ExposureScan,
    RemediationTicket,
    ExposureVulnerability,
)

Vulnerability = ExposureVulnerability  # Backwards compatibility alias

__all__ = [
    "ExposureAsset",
    "ExposureVulnerability",
    "Vulnerability",
    "AssetVulnerability",
    "ExposureScan",
    "RemediationTicket",
    "AttackSurface",
]
