"""Asset schemas for request/response validation"""

from datetime import datetime
from typing import Any, Optional

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


class AssetResponse(BaseModel):
    """Schema for asset response"""
    id: str
    name: str
    hostname: Optional[str]
    asset_type: str
    status: str
    ip_address: Optional[str]
    mac_address: Optional[str]
    fqdn: Optional[str]
    criticality: str
    business_unit: Optional[str]
    department: Optional[str]
    owner: Optional[str]
    location: Optional[str]
    operating_system: Optional[str]
    os_version: Optional[str]
    cloud_provider: Optional[str]
    cloud_region: Optional[str]
    cloud_instance_id: Optional[str]
    security_score: Optional[int]
    last_scan: Optional[str]
    description: Optional[str]
    tags: Optional[list[str]]
    is_monitored: bool
    agent_installed: bool
    last_seen: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetListResponse(BaseModel):
    """Schema for paginated asset list"""
    items: list[AssetResponse]
    total: int
    page: int
    size: int
    pages: int
