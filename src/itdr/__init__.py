"""
ITDR (Identity Threat Detection & Response) Module

Comprehensive identity security platform including:
- Identity profiling and baseline establishment
- Threat detection (credential attacks, privilege escalation, lateral movement)
- Credential exposure monitoring
- Access behavior anomaly detection
- Privileged access management (PAM)
- Risk scoring and response orchestration
"""

from src.itdr.engine import (
    IdentityThreatDetector,
    CredentialMonitor,
    AccessBehaviorAnalyzer,
    PrivilegedAccessManager,
)
from src.itdr.models import (
    IdentityProfile,
    IdentityThreat,
    CredentialExposure,
    AccessAnomaly,
    PrivilegedAccessEvent,
)

__all__ = [
    "IdentityThreatDetector",
    "CredentialMonitor",
    "AccessBehaviorAnalyzer",
    "PrivilegedAccessManager",
    "IdentityProfile",
    "IdentityThreat",
    "CredentialExposure",
    "AccessAnomaly",
    "PrivilegedAccessEvent",
]
