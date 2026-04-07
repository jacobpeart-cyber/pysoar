"""Schemas for Visual Playbook Builder API"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Node-related schemas
class PlaybookNodeConfigBase(BaseModel):
    """Base configuration for a node"""

    display_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    config: Optional[dict[str, Any]] = None
    timeout_seconds: int = Field(300, ge=1, le=3600)
    retry_count: int = Field(0, ge=0, le=10)
    on_error: str = Field("stop", pattern="^(stop|continue|goto|retry)$")


class PlaybookNodeCreate(PlaybookNodeConfigBase):
    """Schema for creating a node"""

    node_type: str = Field(..., pattern="^(trigger|action|condition|loop|parallel|delay|human_approval|transform|subplaybook|error_handler|variable_set|api_call|notification|enrichment)$")
    position_x: float
    position_y: float
    input_schema: Optional[dict[str, Any]] = None
    output_schema: Optional[dict[str, Any]] = None


class PlaybookNodeUpdate(BaseModel):
    """Schema for updating a node"""

    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    position_x: Optional[float] = None
    position_y: Optional[float] = None
    config: Optional[dict[str, Any]] = None
    timeout_seconds: Optional[int] = Field(None, ge=1, le=3600)
    retry_count: Optional[int] = Field(None, ge=0, le=10)
    on_error: Optional[str] = None


class PlaybookNodeResponse(DBModel):
    """Schema for node response"""

    id: str
    node_id: str
    node_type: str
    position_x: float
    position_y: float
    input_schema: Optional[dict[str, Any]] = None
    output_schema: Optional[dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Edge-related schemas
class PlaybookEdgeBase(BaseModel):
    """Base edge schema"""

    source_node_id: str
    target_node_id: str
    edge_type: str = Field("success", pattern="^(success|failure|conditional|always|timeout|error)$")
    condition_expression: Optional[str] = None
    label: Optional[str] = Field(None, max_length=255)
    priority: int = Field(0, ge=0, le=100)


class PlaybookEdgeCreate(PlaybookEdgeBase):
    """Schema for creating an edge"""

    pass


class PlaybookEdgeUpdate(BaseModel):
    """Schema for updating an edge"""

    edge_type: Optional[str] = None
    condition_expression: Optional[str] = None
    label: Optional[str] = None
    priority: Optional[int] = None


class PlaybookEdgeResponse(PlaybookEdgeBase, DBModel):
    """Schema for edge response"""

    id: str
    playbook_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Playbook-related schemas
class PlaybookBase(BaseModel):
    """Base playbook schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    category: str = Field("custom", pattern="^(incident_response|threat_hunting|compliance|remediation|enrichment|notification|custom)$")
    trigger_type: str = Field("manual", pattern="^(alert|schedule|webhook|manual|event|threshold|api_call)$")
    trigger_config: Optional[dict[str, Any]] = None


class PlaybookCreate(PlaybookBase):
    """Schema for creating a playbook"""

    version: int = Field(1, ge=1)


class PlaybookUpdate(BaseModel):
    """Schema for updating a playbook"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_config: Optional[dict[str, Any]] = None
    status: Optional[str] = Field(None, pattern="^(draft|testing|active|disabled|archived)$")
    canvas_data: Optional[dict[str, Any]] = None


class PlaybookValidateRequest(BaseModel):
    """Schema for playbook validation request"""

    nodes: list[PlaybookNodeCreate] = []
    edges: list[PlaybookEdgeCreate] = []


class PlaybookValidateResponse(BaseModel):
    """Schema for validation response"""

    is_valid: bool
    errors: list[str] = []
    warnings: list[str] = []


class PlaybookResponse(PlaybookBase, DBModel):
    """Schema for playbook response"""

    id: str
    organization_id: str
    version: int
    status: str
    execution_count: int
    avg_execution_time_ms: float
    success_rate: float
    last_executed: Optional[str] = None
    is_template: bool
    template_category: Optional[str] = None
    created_by: Optional[str] = None
    nodes: list[PlaybookNodeResponse] = []
    edges: list[PlaybookEdgeResponse] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookListResponse(BaseModel):
    """Schema for paginated playbook list"""

    items: list[PlaybookResponse]
    total: int
    page: int
    size: int
    pages: int


class PlaybookCloneRequest(BaseModel):
    """Schema for cloning a playbook"""

    new_name: str = Field(..., min_length=1, max_length=255)
    organization_id: Optional[str] = None


class PlaybookImportRequest(BaseModel):
    """Schema for importing a playbook"""

    playbook_data: dict[str, Any]
    organization_id: Optional[str] = None


class PlaybookExportResponse(BaseModel):
    """Schema for exported playbook"""

    id: str
    name: str
    description: Optional[str] = None
    version: int
    category: str
    trigger_type: str
    trigger_config: Optional[dict[str, Any]] = None
    canvas_data: Optional[dict[str, Any]] = None
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


# Execution-related schemas
class PlaybookExecutionTrigger(BaseModel):
    """Schema for triggering execution"""

    trigger_event: Optional[dict[str, Any]] = None
    variables: Optional[dict[str, Any]] = None


class PlaybookExecutionResponse(DBModel):
    """Schema for execution response"""

    id: str
    playbook_id: str
    organization_id: str
    trigger_event: Optional[dict[str, Any]] = None
    status: str
    current_node_id: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    execution_path: list[str] = []
    variables: Optional[dict[str, Any]] = None
    error_message: Optional[str] = None
    triggered_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookNodeExecutionResponse(DBModel):
    """Schema for node execution response"""

    id: str
    execution_id: str
    node_id: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    input_data: Optional[dict[str, Any]] = None
    output_data: Optional[dict[str, Any]] = None
    error_message: Optional[str] = None
    retry_attempt: int
    approved_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookExecutionListResponse(BaseModel):
    """Schema for paginated execution list"""

    items: list[PlaybookExecutionResponse]
    total: int
    page: int
    size: int
    pages: int


class PlaybookExecutionStatusResponse(BaseModel):
    """Schema for execution status"""

    execution_id: str
    playbook_id: str
    status: str
    current_node_id: Optional[str] = None
    progress_percent: float
    node_executions: list[PlaybookNodeExecutionResponse] = []
    error_message: Optional[str] = None


# Template-related schemas
class PlaybookTemplateBase(BaseModel):
    """Base template schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    category: str


class PlaybookTemplateResponse(PlaybookTemplateBase, DBModel):
    """Schema for template response"""

    id: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookTemplateListResponse(BaseModel):
    """Schema for paginated template list"""

    items: list[PlaybookTemplateResponse]
    total: int
    page: int
    size: int
    pages: int


class CreateFromTemplateRequest(BaseModel):
    """Schema for creating playbook from template"""

    template_id: str
    playbook_name: str = Field(..., min_length=1, max_length=255)
    organization_id: Optional[str] = None


# Dashboard schemas
class PlaybookExecutionStats(BaseModel):
    """Schema for execution statistics"""

    total_executions: int
    successful_executions: int
    failed_executions: int
    avg_execution_time_ms: float
    success_rate: float


class PlaybookDashboardResponse(BaseModel):
    """Schema for playbook dashboard"""

    total_playbooks: int
    active_playbooks: int
    draft_playbooks: int
    total_templates: int
    execution_stats: PlaybookExecutionStats
    top_playbooks: list[PlaybookResponse] = []
    failure_rates: dict[str, float] = {}
    avg_execution_times: dict[str, float] = {}


# Error responses
class ErrorResponse(BaseModel):
    """Schema for error response"""

    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ValidationErrorResponse(BaseModel):
    """Schema for validation error"""

    detail: str
    errors: list[dict[str, str]]
