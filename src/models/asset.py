"""Asset model for asset inventory management"""

from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel


class AssetType(str, Enum):
    """Types of assets"""

    SERVER = "server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    NETWORK_DEVICE = "network_device"
    FIREWALL = "firewall"
    DATABASE = "database"
    APPLICATION = "application"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    IOT_DEVICE = "iot_device"
    MOBILE = "mobile"
    OTHER = "other"


class AssetCriticality(str, Enum):
    """Asset criticality levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetStatus(str, Enum):
    """Asset status"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    MAINTENANCE = "maintenance"


class Asset(BaseModel):
    """Asset model for inventory management"""

    __tablename__ = "assets"

    # Core identification
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    asset_type: Mapped[str] = mapped_column(
        String(50),
        default=AssetType.OTHER.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=AssetStatus.ACTIVE.value,
        nullable=False,
    )

    # Network information
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    fqdn: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Classification
    criticality: Mapped[str] = mapped_column(
        String(50),
        default=AssetCriticality.MEDIUM.value,
        nullable=False,
    )
    business_unit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Technical details
    operating_system: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    installed_software: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    open_ports: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    services: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Cloud information
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    cloud_region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cloud_instance_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Security information
    security_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    vulnerabilities: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    compliance_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    last_scan: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Additional metadata
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    custom_fields: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Monitoring
    is_monitored: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    agent_installed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_seen: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    def __repr__(self) -> str:
        return f"<Asset {self.name} ({self.asset_type})>"
