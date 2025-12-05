"""Indicator of Compromise (IOC) model"""

from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel


class IOCType(str, Enum):
    """Types of indicators"""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    FILE_NAME = "filename"
    REGISTRY_KEY = "registry"
    CVE = "cve"
    USER_AGENT = "user_agent"
    CIDR = "cidr"
    ASN = "asn"


class IOCStatus(str, Enum):
    """IOC status"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"


class ThreatLevel(str, Enum):
    """Threat level classification"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IOC(BaseModel):
    """Indicator of Compromise model"""

    __tablename__ = "iocs"

    # Core fields
    value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=IOCStatus.ACTIVE.value,
        nullable=False,
    )

    # Classification
    threat_level: Mapped[str] = mapped_column(
        String(50),
        default=ThreatLevel.UNKNOWN.value,
        nullable=False,
    )
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    # Metadata
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Source information
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Threat intelligence
    malware_family: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    campaign: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # MITRE ATT&CK
    mitre_tactics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Enrichment data
    enrichment_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    last_enriched: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Validity period
    first_seen: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_seen: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    expires_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Sightings
    sighting_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_sighting: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Flags
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_internal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<IOC {self.ioc_type}:{self.value[:50]}>"
