"""IOC schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class IOCBase(BaseModel):
    """Base IOC schema"""

    value: str = Field(..., min_length=1, max_length=2048)
    ioc_type: str
    threat_level: str = "unknown"
    confidence: int = Field(default=50, ge=0, le=100)
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    category: Optional[str] = None


class IOCCreate(IOCBase):
    """Schema for creating an IOC"""

    source: Optional[str] = None
    source_url: Optional[str] = None
    source_reference: Optional[str] = None
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    expires_at: Optional[str] = None


class IOCUpdate(BaseModel):
    """Schema for updating an IOC"""

    status: Optional[str] = None
    threat_level: Optional[str] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    category: Optional[str] = None
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    is_whitelisted: Optional[bool] = None
    expires_at: Optional[str] = None


class IOCResponse(IOCBase):
    """Schema for IOC response"""

    id: str
    status: str
    source: Optional[str] = None
    source_url: Optional[str] = None
    source_reference: Optional[str] = None
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    enrichment_data: Optional[dict[str, Any]] = None
    last_enriched: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    expires_at: Optional[str] = None
    sighting_count: int
    last_sighting: Optional[str] = None
    is_whitelisted: bool
    is_internal: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class IOCListResponse(BaseModel):
    """Schema for paginated IOC list"""

    items: list[IOCResponse]
    total: int
    page: int
    size: int
    pages: int


class IOCBulkCreate(BaseModel):
    """Schema for bulk IOC creation"""

    iocs: list[IOCCreate]


class IOCSearchRequest(BaseModel):
    """Schema for IOC search"""

    value: str
    ioc_type: Optional[str] = None


class IOCEnrichRequest(BaseModel):
    """Schema for IOC enrichment request"""

    ioc_id: str
    providers: Optional[list[str]] = None  # Specific providers to use
