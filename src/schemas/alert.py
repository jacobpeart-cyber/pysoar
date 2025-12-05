"""Alert schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertBase(BaseModel):
    """Base alert schema"""

    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: str = "medium"
    source: str = "manual"
    alert_type: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[list[str]] = None
    priority: int = Field(default=3, ge=1, le=5)
    confidence: int = Field(default=50, ge=0, le=100)


class AlertCreate(AlertBase):
    """Schema for creating an alert"""

    source_id: Optional[str] = None
    source_url: Optional[str] = None
    raw_data: Optional[dict[str, Any]] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    file_hash: Optional[str] = None
    url: Optional[str] = None
    domain: Optional[str] = None


class AlertUpdate(BaseModel):
    """Schema for updating an alert"""

    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=5)
    assigned_to: Optional[str] = None
    incident_id: Optional[str] = None
    resolution_notes: Optional[str] = None
    tags: Optional[list[str]] = None


class AlertResponse(AlertBase):
    """Schema for alert response"""

    id: str
    status: str
    source_id: Optional[str] = None
    source_url: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    file_hash: Optional[str] = None
    url: Optional[str] = None
    domain: Optional[str] = None
    assigned_to: Optional[str] = None
    incident_id: Optional[str] = None
    resolution_notes: Optional[str] = None
    resolved_at: Optional[str] = None
    enrichment_data: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    """Schema for paginated alert list"""

    items: list[AlertResponse]
    total: int
    page: int
    size: int
    pages: int


class AlertBulkAction(BaseModel):
    """Schema for bulk alert actions"""

    alert_ids: list[str]
    action: str  # acknowledge, close, assign, etc.
    value: Optional[str] = None  # For assign action: user_id


class AlertStats(BaseModel):
    """Schema for alert statistics"""

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_source: dict[str, int]
    new_today: int
    new_this_week: int
