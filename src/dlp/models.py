"""
Data Loss Prevention Models

Defines database models for DLP policies, violations, data classifications,
discovery scans, and breach incidents.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel


class PolicyType(str, Enum):
    """DLP policy types"""

    DATA_CLASSIFICATION = "data_classification"
    EXFILTRATION_PREVENTION = "exfiltration_prevention"
    PII_DETECTION = "pii_detection"
    PHI_DETECTION = "phi_detection"
    PCI_DETECTION = "pci_detection"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    CUSTOM_PATTERN = "custom_pattern"
    REGULATORY = "regulatory"


class Severity(str, Enum):
    """Severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ViolationType(str, Enum):
    """DLP violation types"""

    PII_EXPOSURE = "pii_exposure"
    PHI_EXPOSURE = "phi_exposure"
    PCI_DATA_LEAK = "pci_data_leak"
    IP_THEFT = "ip_theft"
    UNAUTHORIZED_TRANSFER = "unauthorized_transfer"
    CLASSIFICATION_VIOLATION = "classification_violation"
    ENCRYPTION_MISSING = "encryption_missing"
    RETENTION_VIOLATION = "retention_violation"
    CROSS_BORDER_TRANSFER = "cross_border_transfer"
    BULK_DOWNLOAD = "bulk_download"


class ActionType(str, Enum):
    """Response actions for violations"""

    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    ENCRYPTED = "encrypted"
    LOGGED = "logged"
    ALERTED = "alerted"
    REDACTED = "redacted"
    ALLOWED_WITH_JUSTIFICATION = "allowed_with_justification"


class ViolationStatus(str, Enum):
    """Violation investigation status"""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class ClassificationLevel(str, Enum):
    """Data classification levels"""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"
    CUI = "cui"  # Controlled Unclassified Information
    PII = "pii"  # Personally Identifiable Information
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Industry


class ScanType(str, Enum):
    """Data discovery scan types"""

    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD_STORAGE = "cloud_storage"
    DATABASE = "database"
    EMAIL = "email"
    CODE_REPOSITORY = "code_repository"
    FILE_SHARE = "file_share"


class ScanStatus(str, Enum):
    """Scan execution status"""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class IncidentStatus(str, Enum):
    """Incident lifecycle status"""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class DLPPolicy(BaseModel):
    """DLP Policy model for defining detection and prevention rules"""

    __tablename__ = "dlp_policies"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    policy_type: Mapped[str] = mapped_column(
        String(50),
        default=PolicyType.CUSTOM_PATTERN.value,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        default=Severity.MEDIUM.value,
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    data_patterns: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    file_types_monitored: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    channels_monitored: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    response_actions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    exceptions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    last_triggered: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    trigger_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    def __repr__(self) -> str:
        return f"<DLPPolicy {self.name}>"


class DLPViolation(BaseModel):
    """DLP Violation model for tracking detected violations"""

    __tablename__ = "dlp_violations"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    policy_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    violation_type: Mapped[str] = mapped_column(
        String(50),
        default=ViolationType.UNAUTHORIZED_TRANSFER.value,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        default=Severity.MEDIUM.value,
        nullable=False,
    )
    source_user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    source_device: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_application: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    destination: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_classification: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    sensitive_data_types: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    file_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    data_volume_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action_taken: Mapped[str] = mapped_column(
        String(50),
        default=ActionType.LOGGED.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=ViolationStatus.NEW.value,
        nullable=False,
        index=True,
    )
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    def __repr__(self) -> str:
        return f"<DLPViolation {self.id}>"


class DataClassification(BaseModel):
    """Data Classification model for categorizing sensitive data"""

    __tablename__ = "data_classifications"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    classification_level: Mapped[str] = mapped_column(
        String(50),
        default=ClassificationLevel.INTERNAL.value,
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    handling_rules: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    retention_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    encryption_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dlp_policies: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    auto_classification_rules: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    color_code: Mapped[Optional[str]] = mapped_column(String(7), nullable=True)

    def __repr__(self) -> str:
        return f"<DataClassification {self.name}>"


class SensitiveDataDiscovery(BaseModel):
    """Sensitive Data Discovery model for scanning and cataloging sensitive data"""

    __tablename__ = "sensitive_data_discoveries"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(
        String(50),
        default=ScanType.ENDPOINT.value,
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        default=ScanStatus.PENDING.value,
        nullable=False,
    )
    total_files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sensitive_files_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    classification_breakdown: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_scheduled_scan: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<SensitiveDataDiscovery {self.scan_id}>"


class DLPIncident(BaseModel):
    """DLP Incident model for managing breach incidents and responses"""

    __tablename__ = "dlp_incidents"

    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    violation_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    incident_title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(20),
        default=Severity.HIGH.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=IncidentStatus.OPEN.value,
        nullable=False,
        index=True,
    )
    affected_data_subjects_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    data_types_involved: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    regulatory_implications: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    breach_notification_required: Mapped[bool] = mapped_column(Boolean, default=False)
    notification_deadline: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notification_sent: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    incident_commander: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    remediation_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<DLPIncident {self.incident_title}>"
