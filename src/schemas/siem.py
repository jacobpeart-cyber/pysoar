"""SIEM schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


class LogEntryBase(BaseModel):
    """Base log entry schema"""

    timestamp: Optional[str] = None
    source_type: str = "unknown"
    source_name: str = "unknown"
    message: Optional[str] = None
    severity: str = "informational"


class LogIngestRequest(BaseModel):
    """Schema for ingesting a single log"""

    raw_log: str = Field(..., min_length=1)
    source_type: str = "auto"
    source_name: Optional[str] = None
    source_ip: Optional[str] = None
    tags: Optional[list[str]] = None


class LogBatchIngestRequest(BaseModel):
    """Schema for batch log ingestion"""

    logs: list[LogIngestRequest]
    organization_id: Optional[str] = None


class LogEntryResponse(LogEntryBase, DBModel):
    """Schema for log entry response"""

    id: str
    timestamp: str
    received_at: str
    source_type: str
    source_name: str
    log_type: str
    severity: str
    message: Optional[str] = None
    source_address: Optional[str] = None
    destination_address: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    parsed_fields: Optional[dict[str, Any]] = None
    normalized_fields: Optional[dict[str, Any]] = None
    rule_matches: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class LogListResponse(BaseModel):
    """Schema for paginated log list"""

    items: list[LogEntryResponse]
    total: int
    page: int
    size: int
    pages: int


class LogSearchRequest(BaseModel):
    """Schema for searching logs"""

    query: Optional[str] = None
    field_filters: Optional[dict[str, Any]] = None
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    source_types: Optional[list[str]] = None
    log_types: Optional[list[str]] = None
    severities: Optional[list[str]] = None
    source_addresses: Optional[list[str]] = None
    destination_addresses: Optional[list[str]] = None
    usernames: Optional[list[str]] = None
    hostnames: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    page: int = Field(default=1, ge=1)
    size: int = Field(default=50, ge=1, le=500)
    sort_by: str = "timestamp"
    sort_order: str = "desc"


class LogSearchResponse(BaseModel):
    """Schema for log search results"""

    items: list[LogEntryResponse]
    total: int
    page: int
    size: int
    pages: int
    query_time_ms: int
    aggregations: Optional[dict[str, Any]] = None


class AggregationRequest(BaseModel):
    """Schema for aggregation queries"""

    field: str
    agg_type: str
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    interval: Optional[str] = None
    top_n: int = Field(default=10, ge=1, le=100)


class DetectionRuleBase(BaseModel):
    """Base detection rule schema"""

    name: str = Field(..., min_length=1, max_length=255)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: str = "medium"
    log_types: Optional[list[str]] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class DetectionRuleCreate(DetectionRuleBase):
    """Schema for creating a detection rule"""

    detection_logic: Optional[dict[str, Any]] = None
    condition: Optional[str] = None
    timewindow: Optional[int] = None
    threshold: Optional[int] = None
    group_by: Optional[list[str]] = None
    false_positive_notes: Optional[str] = None
    references: Optional[list[str]] = None
    rule_yaml: Optional[str] = None


class DetectionRuleUpdate(BaseModel):
    """Schema for updating a detection rule"""

    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    log_types: Optional[list[str]] = None
    detection_logic: Optional[dict[str, Any]] = None
    condition: Optional[str] = None
    timewindow: Optional[int] = None
    threshold: Optional[int] = None
    group_by: Optional[list[str]] = None
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    false_positive_notes: Optional[str] = None
    references: Optional[list[str]] = None
    rule_yaml: Optional[str] = None
    enabled: Optional[bool] = None


class DetectionRuleResponse(DetectionRuleBase, DBModel):
    """Schema for detection rule response"""

    id: str
    status: str
    enabled: bool
    match_count: int
    last_matched_at: Optional[str] = None
    detection_logic: Optional[dict[str, Any]] = None
    condition: Optional[str] = None
    timewindow: Optional[int] = None
    threshold: Optional[int] = None
    group_by: Optional[list[str]] = None
    false_positive_notes: Optional[str] = None
    references: Optional[list[str]] = None
    rule_yaml: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DetectionRuleListResponse(BaseModel):
    """Schema for paginated detection rule list"""

    items: list[DetectionRuleResponse]
    total: int
    page: int
    size: int
    pages: int


class CorrelationEventResponse(DBModel):
    """Schema for correlation event response"""

    id: str
    correlation_id: str
    name: str
    description: Optional[str] = None
    severity: str
    rule_id: Optional[str] = None
    log_entry_ids: Optional[list[str]] = None
    source_addresses: Optional[list[str]] = None
    usernames: Optional[list[str]] = None
    hostnames: Optional[list[str]] = None
    timespan_start: str
    timespan_end: str
    event_count: int
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    alert_generated: bool
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class SIEMStatsResponse(BaseModel):
    """Schema for SIEM statistics"""

    total_logs: int
    logs_today: int
    events_per_second: float = 0.0
    active_rules: int
    alerts_triggered_24h: int = 0
    active_data_sources: int = 0
    logs_by_type: list[dict[str, Any]]
    logs_by_severity: list[dict[str, Any]]
    logs_by_source: list[dict[str, Any]]
    recent_detections: list[dict[str, Any]] = []
    rule_matches_today: int
    active_correlations: int
    ingestion_rate_per_hour: float
    storage_stats: Optional[dict[str, Any]] = None


class DataSourceCreate(BaseModel):
    """Schema for creating a data source"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    source_type: str
    connection_config: dict[str, Any] = {}
    parser_config: Optional[dict[str, Any]] = None
    enabled: bool = True


class DataSourceResponse(DBModel):
    """Schema for data source response"""

    id: str
    name: str
    description: Optional[str] = None
    source_type: str
    enabled: bool
    last_event_at: Optional[str] = None
    events_today: int
    error_count: int
    last_error: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
