"""
Legacy IOC module — now a thin alias over ThreatIndicator.

PySOAR used to have two separate indicator tables:
  - `iocs` (legacy, manual entry only, no feed connectivity)
  - `threat_indicators` (modern, populated by feeds, richer schema)

They were not synced, so alerts never matched indicators coming from threat
feeds. This module is now an alias pointing at `ThreatIndicator` so all
callers — manual IOC CRUD, agent tools, automation pipeline, scheduled
sweeps — read and write the same unified table.

Back-compat enums are kept so existing imports do not break.
"""

from enum import Enum

from src.intel.models import ThreatIndicator as IOC  # noqa: F401


class IOCStatus(str, Enum):
    """Legacy IOC status enum (maps to ThreatIndicator.is_active)."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"


class IOCType(str, Enum):
    """Legacy IOC type enum (maps to ThreatIndicator.indicator_type)."""

    IP = "ipv4"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    FILE_NAME = "filename"
    REGISTRY_KEY = "registry_key"
    CVE = "cve"
    USER_AGENT = "user_agent"
    CIDR = "cidr"
    ASN = "asn"


class ThreatLevel(str, Enum):
    """Legacy threat-level enum (maps to ThreatIndicator.severity)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "informational"


__all__ = ["IOC", "IOCStatus", "IOCType", "ThreatLevel"]
