"""Log normalizer for converting parsed logs to common schema"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from src.core.logging import get_logger

logger = get_logger(__name__)


class SeverityLevel(Enum):
    """Normalized severity levels"""

    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogType(Enum):
    """Log type classifications"""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    APPLICATION = "application"
    SYSTEM = "system"
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_LOSS = "data_loss"
    COMPLIANCE = "compliance"
    UNKNOWN = "unknown"


@dataclass
class NormalizedLog:
    """Normalized log entry with common schema"""

    timestamp: Optional[datetime] = None
    source_type: str = "unknown"
    log_type: LogType = LogType.UNKNOWN
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    source_address: Optional[str] = None
    destination_address: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    message: str = ""
    raw_fields: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_type": self.source_type,
            "log_type": self.log_type.value,
            "severity": self.severity.value,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "hostname": self.hostname,
            "process_name": self.process_name,
            "action": self.action,
            "outcome": self.outcome,
            "message": self.message,
            "raw_fields": self.raw_fields,
        }


class LogNormalizer:
    """Normalizer for converting parsed logs to common schema"""

    # Field name mappings for different sources
    FIELD_MAPPINGS = {
        "syslog": {
            "username": ["user", "username", "uid", "ruser", "data_UserName"],
            "hostname": ["hostname", "computer", "host"],
            "process_name": ["app_name", "program", "process"],
            "source_address": ["src", "src_ip", "source_ip", "saddr", "src_host"],
            "destination_address": ["dst", "dst_ip", "dest_ip", "daddr", "dst_host"],
            "source_port": ["src_port", "sport", "source_port"],
            "destination_port": ["dst_port", "dport", "destination_port"],
            "protocol": ["protocol", "proto"],
        },
        "json": {
            "username": ["user", "username", "uid", "user_id", "userId"],
            "hostname": ["hostname", "host", "server", "computer"],
            "process_name": ["process", "process_name", "app", "application"],
            "source_address": ["src", "src_ip", "source_ip", "source_address", "sourceIP"],
            "destination_address": ["dst", "dst_ip", "dest_ip", "destination_ip", "destIP"],
            "source_port": ["src_port", "sport", "source_port"],
            "destination_port": ["dst_port", "dport", "destination_port"],
            "protocol": ["protocol", "proto"],
        },
        "cef": {
            "username": ["duser", "suser", "cs1", "cs2"],
            "hostname": ["shost", "dhost", "host"],
            "process_name": ["sproc", "dproc"],
            "source_address": ["src", "sip"],
            "destination_address": ["dst", "dip"],
            "source_port": ["spt", "sport"],
            "destination_port": ["dpt", "dport"],
            "protocol": ["proto", "protocol"],
        },
        "leef": {
            "username": ["usrName", "dstUser", "srcUser"],
            "hostname": ["srcHost", "destHost", "host"],
            "process_name": ["process", "proc"],
            "source_address": ["srcIP", "src", "source"],
            "destination_address": ["destIP", "dst", "destination"],
            "source_port": ["srcPort", "srcport"],
            "destination_port": ["destPort", "dstport"],
            "protocol": ["protocol", "proto"],
        },
        "windows": {
            "username": ["user_id", "SubjectUserName", "TargetUserName"],
            "hostname": ["hostname", "Computer"],
            "process_name": ["Image", "ParentImage", "data_Image"],
            "source_address": ["IpAddress", "SourceIp", "data_IpAddress"],
            "destination_address": ["DestinationIp", "data_DestinationIp"],
            "source_port": ["SourcePort", "data_SourcePort"],
            "destination_port": ["DestinationPort", "data_DestinationPort"],
            "protocol": ["Protocol", "data_Protocol"],
        },
    }

    # Severity mappings from vendor-specific values
    SEVERITY_MAPPINGS = {
        "syslog": {
            "0": SeverityLevel.CRITICAL,
            "1": SeverityLevel.CRITICAL,
            "2": SeverityLevel.CRITICAL,
            "3": SeverityLevel.HIGH,
            "4": SeverityLevel.MEDIUM,
            "5": SeverityLevel.MEDIUM,
            "6": SeverityLevel.LOW,
            "7": SeverityLevel.INFORMATIONAL,
        },
        "cef": {
            "-2": SeverityLevel.UNKNOWN,
            "-1": SeverityLevel.UNKNOWN,
            "0": SeverityLevel.INFORMATIONAL,
            "1": SeverityLevel.LOW,
            "2": SeverityLevel.LOW,
            "3": SeverityLevel.MEDIUM,
            "4": SeverityLevel.MEDIUM,
            "5": SeverityLevel.HIGH,
            "6": SeverityLevel.HIGH,
            "7": SeverityLevel.CRITICAL,
            "8": SeverityLevel.CRITICAL,
            "9": SeverityLevel.CRITICAL,
            "10": SeverityLevel.CRITICAL,
        },
        "leef": {
            "unknown": SeverityLevel.UNKNOWN,
            "informational": SeverityLevel.INFORMATIONAL,
            "low": SeverityLevel.LOW,
            "medium": SeverityLevel.MEDIUM,
            "high": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL,
        },
        "windows": {
            "0": SeverityLevel.INFORMATIONAL,
            "1": SeverityLevel.INFORMATIONAL,
            "2": SeverityLevel.MEDIUM,
            "3": SeverityLevel.HIGH,
            "4": SeverityLevel.CRITICAL,
        },
        "json": {
            "debug": SeverityLevel.INFORMATIONAL,
            "info": SeverityLevel.INFORMATIONAL,
            "notice": SeverityLevel.LOW,
            "warning": SeverityLevel.MEDIUM,
            "error": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL,
            "alert": SeverityLevel.CRITICAL,
            "emergency": SeverityLevel.CRITICAL,
        },
    }

    # Keywords for log type classification
    LOG_TYPE_KEYWORDS = {
        LogType.AUTHENTICATION: [
            "login", "authentication", "auth", "ssh", "rlogin", "su", "sudo",
            "password", "grant", "denied", "failed", "success",
        ],
        LogType.AUTHORIZATION: [
            "permission", "access", "denied", "allowed", "acl", "privilege",
        ],
        LogType.NETWORK: [
            "network", "connection", "established", "closed", "packet", "flow",
            "firewall", "proxy", "http", "https", "port", "tcp", "udp",
        ],
        LogType.MALWARE: [
            "malware", "virus", "trojan", "ransomware", "worm", "spyware",
            "signature", "detected", "threat", "infection",
        ],
        LogType.INTRUSION: [
            "intrusion", "dos", "ddos", "exploit", "scan", "probe", "attack",
            "xss", "sql", "injection", "buffer overflow",
        ],
        LogType.DATA_LOSS: [
            "data", "loss", "leak", "exfiltration", "breach", "unauthorized access",
        ],
        LogType.COMPLIANCE: [
            "compliance", "audit", "policy", "violation", "soc", "hipaa",
            "pci", "gdpr", "regulation",
        ],
    }

    def __init__(self):
        self.parser = None

    def normalize(self, parsed_fields: Dict, source_type: str) -> NormalizedLog:
        """
        Normalize parsed log fields to common schema.

        Args:
            parsed_fields: Dictionary of parsed log fields
            source_type: Type of log source (syslog, json, cef, leef, windows)

        Returns:
            NormalizedLog instance
        """
        normalized = NormalizedLog(
            source_type=source_type,
            raw_fields=parsed_fields,
        )

        # Normalize timestamp
        normalized.timestamp = self._normalize_timestamp(parsed_fields)

        # Extract and map fields based on source type
        field_mapping = self.FIELD_MAPPINGS.get(source_type, {})
        for target_field, source_fields in field_mapping.items():
            value = self._extract_field(parsed_fields, source_fields)
            if value:
                setattr(normalized, target_field, value)

        # Parse ports as integers
        if normalized.source_port and isinstance(normalized.source_port, str):
            try:
                normalized.source_port = int(normalized.source_port)
            except ValueError:
                normalized.source_port = None

        if normalized.destination_port and isinstance(normalized.destination_port, str):
            try:
                normalized.destination_port = int(normalized.destination_port)
            except ValueError:
                normalized.destination_port = None

        # Normalize severity
        normalized.severity = self._normalize_severity(parsed_fields, source_type)

        # Classify log type
        normalized.log_type = self._classify_log_type(parsed_fields)

        # Extract message
        normalized.message = self._extract_message(parsed_fields)

        # Extract action and outcome
        normalized.action = self._extract_action(parsed_fields)
        normalized.outcome = self._extract_outcome(parsed_fields)

        return normalized

    def _extract_field(self, fields: Dict, possible_names: list) -> Optional[str]:
        """Extract a field by trying multiple possible field names"""
        for name in possible_names:
            # Direct match
            if name in fields:
                value = fields[name]
                if value and not isinstance(value, dict):
                    return str(value).strip()

            # Case-insensitive match
            for key, value in fields.items():
                if key.lower() == name.lower() and value and not isinstance(value, dict):
                    return str(value).strip()

        return None

    def _normalize_timestamp(self, fields: Dict) -> Optional[datetime]:
        """Parse and normalize timestamp to UTC datetime"""
        timestamp_str = self._extract_field(
            fields,
            ["timestamp", "TimeCreated", "time", "eventTime", "date"],
        )

        if not timestamp_str:
            return None

        # Try common ISO formats
        iso_formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d %H:%M:%S",  # RFC 3164 format
        ]

        for fmt in iso_formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        logger.debug(f"Could not parse timestamp: {timestamp_str}")
        return None

    def _normalize_severity(self, fields: Dict, source_type: str) -> SeverityLevel:
        """Map vendor-specific severity to normalized level"""
        severity_mapping = self.SEVERITY_MAPPINGS.get(source_type, {})

        # Try severity field
        severity_keys = ["severity", "level", "Level", "urgency", "priority"]
        for key in severity_keys:
            if key in fields:
                severity_value = str(fields[key]).lower()
                # Direct mapping
                if severity_value in severity_mapping:
                    return severity_mapping[severity_value]
                # Text mapping
                if "critical" in severity_value or "fatal" in severity_value:
                    return SeverityLevel.CRITICAL
                if "error" in severity_value or "high" in severity_value:
                    return SeverityLevel.HIGH
                if "warn" in severity_value or "medium" in severity_value:
                    return SeverityLevel.MEDIUM
                if "info" in severity_value or "notice" in severity_value:
                    return SeverityLevel.LOW
                if "debug" in severity_value or "trace" in severity_value:
                    return SeverityLevel.INFORMATIONAL

        return SeverityLevel.UNKNOWN

    def _classify_log_type(self, fields: Dict) -> LogType:
        """Classify log type based on content analysis"""
        all_text = " ".join(str(v) for v in fields.values() if v).lower()

        # Count keyword matches for each log type
        matches = {}
        for log_type, keywords in self.LOG_TYPE_KEYWORDS.items():
            count = sum(1 for kw in keywords if kw in all_text)
            if count > 0:
                matches[log_type] = count

        if matches:
            # Return log type with most keyword matches
            return max(matches.items(), key=lambda x: x[1])[0]

        return LogType.UNKNOWN

    def _extract_message(self, fields: Dict) -> str:
        """Extract main message from log"""
        message_keys = ["message", "msg", "Message", "text", "description", "data_Description"]

        for key in message_keys:
            if key in fields and fields[key]:
                return str(fields[key])[:500]  # Limit length

        # Try to build message from other fields
        if "name" in fields:
            return str(fields["name"])[:500]

        return ""

    def _extract_action(self, fields: Dict) -> Optional[str]:
        """Extract action from log"""
        action_keys = ["action", "act", "Activity", "data_Activity", "cs3"]

        return self._extract_field(fields, action_keys)

    def _extract_outcome(self, fields: Dict) -> Optional[str]:
        """Extract outcome (success/failure) from log"""
        outcome_keys = ["outcome", "result", "Result", "status", "Status", "rt"]

        outcome = self._extract_field(fields, outcome_keys)

        if outcome:
            outcome_lower = outcome.lower()
            # Normalize to standard values
            if "success" in outcome_lower or "succeeded" in outcome_lower or "allowed" in outcome_lower:
                return "success"
            elif "fail" in outcome_lower or "denied" in outcome_lower or "error" in outcome_lower:
                return "failure"
            else:
                return outcome

        return None
