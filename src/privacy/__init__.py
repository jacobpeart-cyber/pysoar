"""
Privacy Engineering Automation Module

Handles GDPR, CCPA, LGPD, PIPA, PDPA, and HIPAA privacy compliance automation.
Manages Data Subject Requests (DSRs), Privacy Impact Assessments (PIAs),
consent records, data processing activities, and privacy incidents.

This module fills a critical gap in SOAR platforms by providing comprehensive
privacy engineering automation with regulatory compliance tracking.
"""

from src.privacy.models import (
    DataSubjectRequest,
    PrivacyImpactAssessment,
    ConsentRecord,
    DataProcessingRecord,
    PrivacyIncident,
)
from src.privacy.engine import (
    DSRProcessor,
    PIAEngine,
    ConsentManager,
    DataGovernance,
    PrivacyIncidentManager,
)

__all__ = [
    "DataSubjectRequest",
    "PrivacyImpactAssessment",
    "ConsentRecord",
    "DataProcessingRecord",
    "PrivacyIncident",
    "DSRProcessor",
    "PIAEngine",
    "ConsentManager",
    "DataGovernance",
    "PrivacyIncidentManager",
]
