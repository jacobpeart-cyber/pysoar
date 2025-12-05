"""Incident schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class IncidentBase(BaseModel):
    """Base incident schema"""

    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: str = "medium"
    incident_type: str = "other"
    priority: int = Field(default=3, ge=1, le=5)


class IncidentCreate(IncidentBase):
    """Schema for creating an incident"""

    alert_ids: Optional[list[str]] = None
    impact: Optional[str] = None
    affected_systems: Optional[list[str]] = None
    affected_users: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None


class IncidentUpdate(BaseModel):
    """Schema for updating an incident"""

    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    incident_type: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=5)
    assigned_to: Optional[str] = None
    impact: Optional[str] = None
    affected_systems: Optional[list[str]] = None
    affected_users: Optional[list[str]] = None
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    lessons_learned: Optional[str] = None
    recommendations: Optional[str] = None
    tags: Optional[list[str]] = None


class IncidentResponse(IncidentBase):
    """Schema for incident response"""

    id: str
    status: str
    assigned_to: Optional[str] = None
    impact: Optional[str] = None
    affected_systems: Optional[list[str]] = None
    affected_users: Optional[list[str]] = None
    detected_at: Optional[str] = None
    contained_at: Optional[str] = None
    resolved_at: Optional[str] = None
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    lessons_learned: Optional[str] = None
    recommendations: Optional[str] = None
    indicators: Optional[dict[str, Any]] = None
    evidence: Optional[dict[str, Any]] = None
    tags: Optional[list[str]] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    alert_count: int = 0
    external_id: Optional[str] = None
    ticket_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class IncidentListResponse(BaseModel):
    """Schema for paginated incident list"""

    items: list[IncidentResponse]
    total: int
    page: int
    size: int
    pages: int


class IncidentTimeline(BaseModel):
    """Schema for incident timeline entry"""

    timestamp: datetime
    action: str
    user: Optional[str] = None
    details: Optional[str] = None


class IncidentStats(BaseModel):
    """Schema for incident statistics"""

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_type: dict[str, int]
    open_count: int
    mttr_hours: Optional[float] = None  # Mean time to resolve
