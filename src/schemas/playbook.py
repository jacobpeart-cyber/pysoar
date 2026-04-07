"""Playbook schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


class PlaybookStep(BaseModel):
    """Schema for a single playbook step"""

    id: Optional[str] = None
    name: str = ""
    action: str = "manual"
    parameters: dict[str, Any] = {}
    on_success: Optional[str] = None
    on_failure: Optional[str] = None
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


class PlaybookResponse(PlaybookBase, DBModel):
    """Schema for playbook response"""

    id: str = ""
    status: str = ""
    steps: list[PlaybookStep]
    trigger_conditions: Optional[dict[str, Any]] = None
    variables: Optional[dict[str, Any]] = None
    version: int = 0
    is_enabled: bool = False
    timeout_seconds: int = 0
    max_retries: int = 0
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookListResponse(BaseModel):
    """Schema for paginated playbook list"""

    items: list[PlaybookResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class PlaybookExecuteRequest(BaseModel):
    """Schema for executing a playbook"""

    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    input_data: Optional[dict[str, Any]] = None


class PlaybookExecutionResponse(DBModel):
    """Schema for playbook execution response"""

    id: str = ""
    playbook_id: str = ""
    incident_id: Optional[str] = None
    status: str = ""
    current_step: int = 0
    total_steps: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    input_data: Optional[dict[str, Any]] = None
    output_data: Optional[dict[str, Any]] = None
    step_results: Optional[list[dict[str, Any]]] = None
    error_message: Optional[str] = None
    error_step: Optional[int] = None
    triggered_by: Optional[str] = None
    trigger_source: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookExecutionListResponse(BaseModel):
    """Schema for paginated execution list"""

    items: list[PlaybookExecutionResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0
