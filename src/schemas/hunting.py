"""Hunting module schemas for API request/response validation"""

import json as json_mod
from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field, field_validator


def _parse_json_list(v):
    """Parse JSON string to list, or return as-is if already a list"""
    if v is None:
        return None
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            parsed = json_mod.loads(v)
            return parsed if isinstance(parsed, list) else [str(parsed)]
        except (json_mod.JSONDecodeError, TypeError):
            return [v] if v else None
    return v


class HuntHypothesisBase(BaseModel):
    """Base schema for hunt hypotheses"""

    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1)
    priority: Any = Field(default=3)
    hunt_type: str = "behavioral"
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    data_sources: Optional[list[str]] = None
    expected_evidence: Optional[list[str]] = None
    tags: Optional[list[str]] = None

    @field_validator("priority", mode="before")
    @classmethod
    def parse_priority(cls, v):
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            mapping = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
            if v.upper() in mapping:
                return mapping[v.upper()]
            try:
                return int(v)
            except ValueError:
                return 3
        return 3

    @field_validator("mitre_tactics", "mitre_techniques", "data_sources", "expected_evidence", "tags", mode="before")
    @classmethod
    def parse_json_lists(cls, v):
        return _parse_json_list(v)


class HuntHypothesisCreate(HuntHypothesisBase):
    """Schema for creating a hunt hypothesis"""

    pass


class HuntHypothesisUpdate(BaseModel):
    """Schema for updating a hunt hypothesis"""

    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=5)
    hunt_type: Optional[str] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    data_sources: Optional[list[str]] = None
    expected_evidence: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class HuntHypothesisResponse(DBModel):
    """Schema for hunt hypothesis response"""

    id: str
    status: str  # DRAFT, ACTIVE, COMPLETED, ARCHIVED
    created_by: str
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    sessions_count: int = 0

    class Config:
        from_attributes = True


class HuntHypothesisListResponse(BaseModel):
    """Schema for paginated hunt hypothesis list"""

    items: list[HuntHypothesisResponse]
    total: int
    page: int
    size: int
    pages: int


class HuntSessionCreate(BaseModel):
    """Schema for creating a hunt session"""

    hypothesis_id: str
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Hunt parameters (time_start, time_end, target_hosts, scope, etc.)",
    )


class HuntSessionResponse(DBModel):
    """Schema for hunt session response"""

    id: str
    hypothesis_id: str
    status: str  # PENDING, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    query_count: int = 0
    events_analyzed: int = 0
    findings_count: int = 0
    queries_executed: Optional[int] = 0
    error_message: Optional[str] = None
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


class HuntSessionListResponse(BaseModel):
    """Schema for paginated hunt session list"""

    items: list[HuntSessionResponse]
    total: int
    page: int
    size: int
    pages: int


class HuntFindingCreate(BaseModel):
    """Schema for creating a hunt finding"""

    session_id: str
    title: str = Field(..., min_length=1, max_length=500)
    description: str
    severity: str  # critical, high, medium, low, info
    evidence: Optional[list[Any]] = None
    affected_assets: Optional[list[str]] = None
    iocs_found: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    analyst_notes: Optional[str] = None

    @field_validator("evidence", "affected_assets", "iocs_found", "mitre_techniques", mode="before")
    @classmethod
    def parse_json_lists(cls, v):
        return _parse_json_list(v)


class HuntFindingUpdate(BaseModel):
    """Schema for updating a hunt finding"""

    classification: Optional[str] = None  # true_positive, false_positive, testing, etc.
    analyst_notes: Optional[str] = None
    escalated_to_case: Optional[bool] = None
    case_id: Optional[str] = None


class HuntFindingResponse(DBModel):
    """Schema for hunt finding response"""

    id: str
    classification: Optional[str] = None
    escalated_to_case: bool = False
    case_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class HuntFindingListResponse(BaseModel):
    """Schema for paginated hunt finding list"""

    items: list[HuntFindingResponse]
    total: int
    page: int
    size: int
    pages: int


class HuntTemplateResponse(DBModel):
    """Schema for hunt template response"""

    id: str
    name: str
    description: str
    category: str  # investigation_report, ioc_sweep, behavioral_hunt, etc.
    hunt_type: str
    hypothesis_template: str
    default_queries: Optional[list[dict[str, str]]] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    difficulty: str  # beginner, intermediate, advanced
    estimated_duration_minutes: int
    tags: Optional[list[str]] = None
    is_builtin: bool = True
    enabled: bool = True

    class Config:
        from_attributes = True


class HuntNotebookCell(BaseModel):
    """Schema for a notebook cell"""

    cell_type: str  # markdown, query, result, visualization, code
    content: str
    output: Optional[str] = None
    executed_at: Optional[datetime] = None
    execution_time_ms: Optional[float] = None
    metadata: Optional[dict[str, Any]] = None


class HuntNotebookCreate(BaseModel):
    """Schema for creating a hunt notebook"""

    session_id: str
    title: str = Field(..., min_length=1, max_length=500)


class HuntNotebookUpdate(BaseModel):
    """Schema for updating a hunt notebook"""

    title: Optional[str] = Field(None, min_length=1, max_length=500)
    content: Optional[list[HuntNotebookCell]] = None


class HuntNotebookResponse(DBModel):
    """Schema for hunt notebook response"""

    id: str
    session_id: str
    title: str
    content: list[HuntNotebookCell]
    version: int = 1
    is_published: bool = False
    published_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class HuntNotebookListResponse(BaseModel):
    """Schema for paginated hunt notebook list"""

    items: list[HuntNotebookResponse]
    total: int
    page: int
    size: int
    pages: int


class HuntNotebookCellExecute(BaseModel):
    """Schema for executing a notebook cell"""

    cell_index: int = Field(..., ge=0)
    query: Optional[str] = None


class HuntStatsResponse(BaseModel):
    """Schema for hunt statistics"""

    total_hypotheses: int
    active_hunts: int
    completed_hunts: int
    total_findings: int
    findings_by_classification: dict[str, int]
    findings_by_severity: dict[str, int]
    avg_hunt_duration_minutes: float
    top_mitre_techniques: list[str]
