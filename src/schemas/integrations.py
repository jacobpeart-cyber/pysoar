"""Schemas for integration marketplace and connector API"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Connector schemas
class ConnectorBase(BaseModel):
    """Base connector schema"""

    name: str = Field(..., min_length=1, max_length=255)
    display_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    vendor: Optional[str] = None
    category: str = ""
    version: str = "1.0.0"
    auth_type: str = ""
    supported_actions: list[str] = []
    supported_triggers: list[str] = []


class ConnectorResponse(ConnectorBase, DBModel):
    """Connector response schema"""

    id: str = ""
    icon_url: Optional[str] = None
    documentation_url: Optional[str] = None
    config_schema: dict[str, Any]
    is_builtin: bool = False
    is_community: bool = False
    rating: Optional[float] = None
    install_count: int = 0
    last_updated: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ConnectorListResponse(BaseModel):
    """Paginated connector list response"""

    items: list[ConnectorResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Installation schemas
class IntegrationConfigField(BaseModel):
    """Configuration field definition"""

    name: str = ""
    type: str  # string, integer, boolean, password, etc.
    display_name: str = ""
    description: Optional[str] = None
    required: bool = False
    default: Optional[Any] = None


class IntegrationInstallRequest(BaseModel):
    """Request to install a connector"""

    connector_id: str = ""
    display_name: str = Field(..., min_length=1, max_length=255)
    config: dict[str, Any] = {}
    credentials: dict[str, Any] = {}


class InstalledIntegrationBase(BaseModel):
    """Base installed integration schema"""

    display_name: str = Field(..., min_length=1, max_length=255)
    config: dict[str, Any] = {}


class InstalledIntegrationCreate(IntegrationInstallRequest):
    """Schema for creating installed integration"""

    pass


class InstalledIntegrationUpdate(BaseModel):
    """Schema for updating installed integration"""

    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[dict[str, Any]] = None
    credentials: Optional[dict[str, Any]] = None


class InstalledIntegrationResponse(InstalledIntegrationBase, DBModel):
    """Response for installed integration"""

    id: str = ""
    connector_id: str = ""
    status: str = ""
    health_status: str = ""
    last_health_check: Optional[str] = None
    last_successful_action: Optional[str] = None
    error_message: Optional[str] = None
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class InstalledIntegrationListResponse(BaseModel):
    """Paginated installed integration list"""

    items: list[InstalledIntegrationResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class IntegrationTestRequest(BaseModel):
    """Request to test integration connection"""

    pass


class IntegrationTestResponse(BaseModel):
    """Response from integration test"""

    status: str  # success, failed, partial
    message: Optional[str] = None
    details: dict[str, Any] = {}
    timestamp: str = ""


class IntegrationStatusResponse(BaseModel):
    """Integration status response"""

    id: str = ""
    status: str = ""
    health_status: str = ""
    last_health_check: Optional[str] = None
    connected: bool = False
    rate_limit_info: Optional[dict[str, Any]] = None
    last_action: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: str = ""


# Action schemas
class ActionInputField(BaseModel):
    """Input field for action"""

    name: str = ""
    type: str = ""
    required: bool = False
    description: Optional[str] = None


class ActionOutputField(BaseModel):
    """Output field from action"""

    name: str = ""
    type: str = ""
    description: Optional[str] = None


class IntegrationActionResponse(DBModel):
    """Response for integration action"""

    id: str = ""
    connector_id: str = ""
    action_name: str = ""
    display_name: str = ""
    description: Optional[str] = None
    action_type: str = ""
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    requires_approval: bool = False
    timeout_seconds: int = 0
    is_idempotent: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IntegrationActionListResponse(BaseModel):
    """Paginated action list"""

    items: list[IntegrationActionResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Execution schemas
class ActionExecutionRequest(BaseModel):
    """Request to execute action"""

    input_data: dict[str, Any] = {}
    playbook_run_id: Optional[str] = None


class ExecutionLogEntry(BaseModel):
    """Single execution log entry"""

    timestamp: str = ""
    level: str  # info, warning, error
    message: str = ""


class IntegrationExecutionResponse(DBModel):
    """Response for action execution"""

    id: str = ""
    installation_id: str = ""
    action_id: str = ""
    triggered_by: str = ""
    status: str = ""
    input_data: dict[str, Any]
    output_data: Optional[dict[str, Any]] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ExecutionHistoryListResponse(BaseModel):
    """Paginated execution history"""

    items: list[IntegrationExecutionResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Webhook schemas
class WebhookEventType(BaseModel):
    """Webhook event type definition"""

    name: str = ""
    description: Optional[str] = None
    payload_schema: dict[str, Any]


class WebhookRegisterRequest(BaseModel):
    """Request to register webhook"""

    endpoint_path: str = ""
    http_method: str = "POST"
    event_types: list[str] = []
    secret: Optional[str] = None
    transform_template: Optional[str] = None


class WebhookResponse(DBModel):
    """Webhook endpoint response"""

    id: str = ""
    installation_id: str = ""
    endpoint_path: str = ""
    http_method: str = ""
    event_types: list[str]
    is_active: bool = False
    last_received: Optional[str] = None
    received_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WebhookListResponse(BaseModel):
    """Paginated webhook list"""

    items: list[WebhookResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class WebhookTestRequest(BaseModel):
    """Request to test webhook"""

    event_type: str = ""
    payload: dict[str, Any]


class WebhookTestResponse(BaseModel):
    """Response from webhook test"""

    webhook_id: str = ""
    event_type: str = ""
    status: str  # success, failed
    message: Optional[str] = None
    timestamp: str = ""


# Dashboard schemas
class IntegrationHealthMetric(BaseModel):
    """Health metric for integration"""

    integration_id: str = ""
    connector_name: str = ""
    status: str = ""
    health_status: str = ""
    uptime_percent: Optional[float] = None
    error_rate: Optional[float] = None
    avg_response_time_ms: Optional[float] = None


class ExecutionStatistics(BaseModel):
    """Statistics for action executions"""

    period: str  # hour, day, week, month
    total_executions: int = 0
    successful: int = 0
    failed: int = 0
    timeout: int = 0
    cancelled: int = 0
    success_rate: float = 0.0
    avg_duration_ms: Optional[float] = None


class DashboardIntegrationHealthResponse(BaseModel):
    """Dashboard view of integration health"""

    total_installed: int = 0
    healthy: int = 0
    degraded: int = 0
    unhealthy: int = 0
    unknown: int = 0
    integrations: list[IntegrationHealthMetric]
    last_updated: str = ""


class DashboardExecutionStatsResponse(BaseModel):
    """Dashboard view of execution statistics"""

    period: str = ""
    total_executions: int = 0
    successful: int = 0
    failed: int = 0
    by_connector: dict[str, ExecutionStatistics]
    by_action_type: dict[str, ExecutionStatistics]
    last_updated: str = ""


class TopConnectorUsage(BaseModel):
    """Top used connectors"""

    connector_name: str = ""
    installations: int = 0
    executions_last_30_days: int = 0
    success_rate: float = 0.0


class ErrorRateMetric(BaseModel):
    """Error rate metrics"""

    connector_name: str = ""
    error_rate: float = 0.0
    error_count: int = 0
    sample_errors: list[str]


class DashboardSummaryResponse(BaseModel):
    """Complete dashboard summary"""

    total_installed: int = 0
    total_executions: int = 0
    success_rate: float = 0.0
    avg_execution_time_ms: Optional[float] = None
    health_overview: DashboardIntegrationHealthResponse
    top_connectors: list[TopConnectorUsage]
    high_error_rate: list[ErrorRateMetric]
    period_stats: DashboardExecutionStatsResponse
    last_updated: str = ""
