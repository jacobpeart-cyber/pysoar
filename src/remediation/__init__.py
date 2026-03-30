"""
PySOAR Remediation Engine Module

Automated remediation execution from detection to fix:
- Policy-driven remediation with human-in-the-loop controls
- Multiple action types: firewall blocks, isolation, account actions, patching, etc.
- Integration connectors for orchestration across security infrastructure
- Approval workflows with timeout handling
- Rollback capabilities for safe automation
- Real-time execution monitoring and effectiveness verification
"""

from src.remediation.models import (
    RemediationPolicy,
    RemediationAction,
    RemediationExecution,
    RemediationPlaybook,
    RemediationIntegration,
)
from src.remediation.engine import RemediationEngine

__all__ = [
    "RemediationPolicy",
    "RemediationAction",
    "RemediationExecution",
    "RemediationPlaybook",
    "RemediationIntegration",
    "RemediationEngine",
]
