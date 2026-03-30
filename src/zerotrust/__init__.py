"""Zero Trust Architecture module for PySOAR (NIST 800-207)

This module implements Zero Trust principles for comprehensive security:
- Never trust by default, always verify
- Continuous authentication and authorization
- Device trust assessment and posture management
- Micro-segmentation of networks and applications
- Continuous monitoring and risk assessment
"""

from src.zerotrust.engine import (
    ContinuousAuthEngine,
    DeviceTrustAssessor,
    MicroSegmentationEngine,
    PolicyDecisionPoint,
    ZeroTrustScorer,
)
from src.zerotrust.models import (
    AccessDecision,
    DeviceTrustProfile,
    IdentityVerification,
    MicroSegment,
    ZeroTrustPolicy,
)

__all__ = [
    "ZeroTrustPolicy",
    "DeviceTrustProfile",
    "AccessDecision",
    "MicroSegment",
    "IdentityVerification",
    "PolicyDecisionPoint",
    "DeviceTrustAssessor",
    "MicroSegmentationEngine",
    "ContinuousAuthEngine",
    "ZeroTrustScorer",
]
