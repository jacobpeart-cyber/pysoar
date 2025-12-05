"""Common schemas used across the API"""

from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class HealthResponse(BaseModel):
    """Health check response"""

    status: str
    version: str
    environment: str
    database: str
    redis: str


class ErrorResponse(BaseModel):
    """Standard error response"""

    error: str
    message: str
    details: Optional[dict[str, Any]] = None
    request_id: Optional[str] = None


class SuccessResponse(BaseModel):
    """Standard success response"""

    success: bool = True
    message: str


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response"""

    items: list[T]
    total: int
    page: int
    size: int
    pages: int


class FilterParams(BaseModel):
    """Common filter parameters"""

    search: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    sort_by: str = "created_at"
    sort_order: str = "desc"


class BulkActionResponse(BaseModel):
    """Response for bulk actions"""

    success_count: int
    failure_count: int
    failures: list[dict[str, str]] = []


class DashboardStats(BaseModel):
    """Dashboard statistics"""

    alerts: dict[str, Any]
    incidents: dict[str, Any]
    iocs: dict[str, Any]
    playbook_executions: dict[str, Any]
    recent_activity: list[dict[str, Any]]
