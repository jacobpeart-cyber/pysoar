"""Asset schemas for request/response validation"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


class AssetBase(BaseModel):
    """Base asset schema"""
    name: str = Field(..., min_length=1, max_length=255)
    hostname: Optional[str] = Field(None, max_length=255)
    asset_type: str = Field(default="other", max_length=50)
    status: str = Field(default="active", max_length=50)
    ip_address: Optional[str] = Field(None, max_length=45)
    mac_address: Optional[str] = Field(None, max_length=17)
    fqdn: Optional[str] = Field(None, max_length=255)
    criticality: str = Field(default="medium", max_length=50)
    business_unit: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=255)
    owner: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field(None, max_length=255)
    operating_system: Optional[str] = Field(None, max_length=255)
    os_version: Optional[str] = Field(None, max_length=100)
    cloud_provider: Optional[str] = Field(None, max_length=50)
    cloud_region: Optional[str] = Field(None, max_length=100)
    cloud_instance_id: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    is_monitored: bool = True
    agent_installed: bool = False


class AssetCreate(AssetBase):
    """Schema for creating an asset"""
    pass


class AssetUpdate(BaseModel):
    """Schema for updating an asset"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    hostname: Optional[str] = Field(None, max_length=255)
    asset_type: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = Field(None, max_length=45)
    mac_address: Optional[str] = Field(None, max_length=17)
    fqdn: Optional[str] = Field(None, max_length=255)
    criticality: Optional[str] = Field(None, max_length=50)
    business_unit: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=255)
    owner: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field(None, max_length=255)
    operating_system: Optional[str] = Field(None, max_length=255)
    os_version: Optional[str] = Field(None, max_length=100)
    cloud_provider: Optional[str] = Field(None, max_length=50)
    cloud_region: Optional[str] = Field(None, max_length=100)
    cloud_instance_id: Optional[str] = Field(None, max_length=255)
    security_score: Optional[int] = Field(None, ge=0, le=100)
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    is_monitored: Optional[bool] = None
    agent_installed: Optional[bool] = None


class AssetResponse(AssetBase, DBModel):
    """Schema for asset response"""
    id: str = ""
    name: str = ""
    hostname: Optional[str] = None
    asset_type: str = ""
    status: str = ""
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    fqdn: Optional[str] = None
    criticality: str = ""
    business_unit: Optional[str] = None
    department: Optional[str] = None
    owner: Optional[str] = None
    location: Optional[str] = None
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_instance_id: Optional[str] = None
    security_score: Optional[int] = None
    last_scan: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    is_monitored: bool = False
    agent_installed: bool = False
    last_seen: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AssetListResponse(BaseModel):
    """Schema for paginated asset list"""
    items: list[AssetResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0
