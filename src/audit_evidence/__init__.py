"""
Audit & Evidence Collection Module

Implements comprehensive audit logging, automated evidence collection,
evidence packaging, and continuous monitoring for federal compliance frameworks.
Supports FedRAMP, CMMC, SOC2, HIPAA, and PCI audit requirements.
"""

from src.audit_evidence.models import (
    AuditTrail,
    EvidencePackage,
    AutomatedEvidenceRule,
)
from src.audit_evidence.engine import (
    AuditLogger,
    EvidenceCollector,
    ContinuousMonitor,
    AuditReadinessChecker,
)

__all__ = [
    "AuditTrail",
    "EvidencePackage",
    "AutomatedEvidenceRule",
    "AuditLogger",
    "EvidenceCollector",
    "ContinuousMonitor",
    "AuditReadinessChecker",
]
