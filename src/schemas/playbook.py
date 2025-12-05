"""Playbook schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class PlaybookStep(BaseModel):
    """Schema for a single playbook step"""

    id: str
    name: str
    action: str  # e.g., "enrich_ip", "send_notification", "block_ip"
    parameters: dict[str, Any] = {}
    on_success: Optional[str] = None  # Next step ID on success
    on_failure: Optional[str] = None  # Next step ID on failure
    timeout_seconds: int = 300
    continue_on_error: bool = False


class PlaybookBase(BaseModel):
    """Base playbook schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    trigger_type: str = "manual"
    category: Optional[str] = None
    tags: Optional[list[str]] = None


class PlaybookCreate(PlaybookBase):
    """Schema for creating a playbook"""

    steps: list[PlaybookStep]
    trigger_conditions: Optional[dict[str, Any]] = None
    variables: Optional[dict[str, Any]] = None
    timeout_seconds: int = 3600
    max_retries: int = 3


class PlaybookUpdate(BaseModel):
    """Schema for updating a playbook"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_conditions: Optional[dict[str, Any]] = None
    steps: Optional[list[PlaybookStep]] = None
    variables: Optional[dict[str, Any]] = None
    category: Optional[str] = None
    tags: Optional[list[str]] = None
    is_enabled: Optional[bool] = None
    timeout_seconds: Optional[int] = None
    max_retries: Optional[int] = None


class PlaybookResponse(PlaybookBase):
    """Schema for playbook response"""

    id: str
    status: str
    steps: list[PlaybookStep]
    trigger_conditions: Optional[dict[str, Any]] = None
    variables: Optional[dict[str, Any]] = None
    version: int
    is_enabled: bool
    timeout_seconds: int
    max_retries: int
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PlaybookListResponse(BaseModel):
    """Schema for paginated playbook list"""

    items: list[PlaybookResponse]
    total: int
    page: int
    size: int
    pages: int


class PlaybookExecuteRequest(BaseModel):
    """Schema for executing a playbook"""

    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    input_data: Optional[dict[str, Any]] = None


class PlaybookExecutionResponse(BaseModel):
    """Schema for playbook execution response"""

    id: str
    playbook_id: str
    incident_id: Optional[str] = None
    status: str
    current_step: int
    total_steps: int
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    input_data: Optional[dict[str, Any]] = None
    output_data: Optional[dict[str, Any]] = None
    step_results: Optional[list[dict[str, Any]]] = None
    error_message: Optional[str] = None
    error_step: Optional[int] = None
    triggered_by: Optional[str] = None
    trigger_source: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PlaybookExecutionListResponse(BaseModel):
    """Schema for paginated execution list"""

    items: list[PlaybookExecutionResponse]
    total: int
    page: int
    size: int
    pages: int
