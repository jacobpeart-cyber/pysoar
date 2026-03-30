"""SIEM data models for log storage, detection rules, and correlation"""

from enum import Enum
from typing import Optional

from sqlalchemy import (, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel, UUIDMixin, TimestampMixin


class SourceType(str, Enum):
    """Log source types"""

    SYSLOG = "syslog"
    JSON_API = "json_api"
    CEF = "cef"
    LEEF = "leef"
    WINDOWS_EVENT = "windows_event"
    CLOUD_TRAIL = "cloud_trail"
    CUSTOM = "custom"


class LogType(str, Enum):
    """Log types"""

    AUTHENTICATION = "authentication"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    CLOUD = "cloud"
    SECURITY = "security"
    SYSTEM = "system"


class Severity(str, Enum):
    """Severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RuleStatus(str, Enum):
    """Detection rule status"""

    ACTIVE = "active"
    DISABLED = "disabled"
    TESTING = "testing"
    DEPRECATED = "deprecated"


class CorrelationStatus(str, Enum):
    """Correlation event status"""

    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class LogEntry(BaseModel):
    """Core log storage model for ingested events"""

    __tablename__ = "log_entries"

    # Event metadata
    timestamp: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # When the event occurred
    received_at: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # When PySOAR received it

    # Source information
    source_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    source_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )  # e.g., "firewall-01"
    source_ip: Mapped[str] = mapped_column(
        String(45), nullable=False, index=True
    )  # Source system IP

    # Log classification
    log_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(50), default=Severity.INFORMATIONAL.value, nullable=False, index=True
    )

    # Raw and parsed data
    raw_log: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_fields: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - extracted key-value pairs
    normalized_fields: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - common schema fields
    message: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # Human-readable summary

    # Network information
    source_address: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True, index=True
    )  # From log content
    destination_address: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True, index=True
    )
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Process and user information
    username: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )
    hostname: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )
    process_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Action and outcome
    action: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # e.g., "allowed", "blocked", "login_success"
    outcome: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # "success", "failure", "unknown"

    # Detection and tagging
    rule_matches: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - list of rule IDs
    tags: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - list of string tags

    # Organization and partitioning
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )
    partition_key: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True
    )  # YYYY-MM-DD format for table partitioning

    def __repr__(self) -> str:
        return f"<LogEntry {self.id}: {self.log_type}@{self.source_name}>"


class DetectionRule(BaseModel):
    """Sigma-inspired detection rules for security event detection"""

    __tablename__ = "detection_rules"

    # Core rule information
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    author: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Status and severity
    status: Mapped[str] = mapped_column(
        String(50), default=RuleStatus.ACTIVE.value, nullable=False, index=True
    )
    severity: Mapped[str] = mapped_column(
        String(50), default=Severity.MEDIUM.value, nullable=False, index=True
    )

    # Log type targeting
    log_types: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - list of log types this rule applies to

    # Detection logic
    detection_logic: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - detection conditions: field matches, boolean operators
    condition: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )  # e.g., "selection1 AND NOT filter1"

    # Aggregation rules
    timewindow: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # seconds
    threshold: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # for count-based rules
    group_by: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - fields to group by

    # MITRE ATT&CK
    mitre_tactics: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - list of tactic IDs
    mitre_techniques: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - list of technique IDs

    # Metadata
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    false_positive_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - list of URLs

    # Original definition
    rule_yaml: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # Original YAML definition

    # Rule state
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_matched_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    match_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    # Organization
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<DetectionRule {self.id}: {self.name}>"


class CorrelationEvent(BaseModel):
    """Correlated events from multiple logs to detect attack patterns"""

    __tablename__ = "correlation_events"

    # Correlation identification
    correlation_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True, unique=True
    )  # Groups related logs
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(50), default=Severity.MEDIUM.value, nullable=False, index=True
    )

    # Associated rule
    rule_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("detection_rules.id"), nullable=True
    )

    # Related entities
    log_entry_ids: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - list of log entry IDs
    source_addresses: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - unique IPs
    usernames: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - unique users
    hostnames: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - unique hosts

    # Timeline
    timespan_start: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    timespan_end: Mapped[str] = mapped_column(String(50), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # MITRE ATT&CK
    mitre_tactics: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON
    mitre_techniques: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON

    # Alert linkage
    alert_generated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    alert_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Status
    status: Mapped[str] = mapped_column(
        String(50), default=CorrelationStatus.NEW.value, nullable=False, index=True
    )

    # Organization
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<CorrelationEvent {self.id}: {self.correlation_id}>"


class SIEMDataSource(BaseModel):
    """Configured log sources for SIEM data collection"""

    __tablename__ = "siem_data_sources"

    # Source identification
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Configuration
    connection_config: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - host, port, protocol, auth
    parser_config: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON - parsing rules, field mappings

    # Status
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_event_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    events_today: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    # Error tracking
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Organization
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<SIEMDataSource {self.id}: {self.name}>"
