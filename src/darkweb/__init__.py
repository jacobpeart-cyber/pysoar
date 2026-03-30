"""Dark Web Monitoring Module

Provides comprehensive dark web and deep web monitoring capabilities including:
- Credential leak detection and alerting
- Brand impersonation and domain spoofing detection
- Data sale monitoring on illicit marketplaces
- Executive targeting and PII exposure detection
- Code/source code leak detection
- Infrastructure exposure monitoring
- Ransomware victim list monitoring
- Automated threat intelligence correlation
- Credential remediation workflows
- Brand protection and takedown management
"""

from src.darkweb.models import (
    DarkWebMonitor,
    DarkWebFinding,
    DarkWebMonitorType,
    FindingType,
    SourcePlatform,
    CredentialLeak,
    PasswordType,
    RemediationAction,
    BrandThreat,
    BrandThreatType,
    TakedownStatus,
)

__all__ = [
    "DarkWebMonitor",
    "DarkWebFinding",
    "DarkWebMonitorType",
    "FindingType",
    "SourcePlatform",
    "CredentialLeak",
    "PasswordType",
    "RemediationAction",
    "BrandThreat",
    "BrandThreatType",
    "TakedownStatus",
]
