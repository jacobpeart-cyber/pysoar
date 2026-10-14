"""SIEM schemas for API request/response validation"""

import json as _json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field, field_validator, model_validator


def _parse_json_list(v):
    if v is None:
        return None
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, str):
        try:
            parsed = _json.loads(v)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except (_json.JSONDecodeError, TypeError):
            pass
    return None


def _parse_json_dict(v):
    if v is None:
        return None
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            parsed = _json.loads(v)
            if isinstance(parsed, dict):
                return parsed
        except (_json.JSONDecodeError, TypeError):
            pass
    return None


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
    # Honoured only for platform superusers (explicit tenant choice); for
    # anyone else it must equal their own organisation (403 otherwise).
    organization_id: Optional[str] = None


class LogEntryResponse(LogEntryBase, DBModel):
    """Schema for log entry response"""

    id: str = ""
    timestamp: str = ""
    received_at: str = ""
    source_type: str = ""
    source_name: str = ""
    log_type: str = ""
    severity: str = ""
    message: Optional[str] = None
    # address the log was received from / the stored raw line (wave 3: the
    # log table's Source IP column and the detail modal's raw section)
    source_ip: Optional[str] = None
    raw_log: Optional[str] = None
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
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @field_validator("parsed_fields", "normalized_fields", mode="before")
    @classmethod
    def _parse_json_dict_fields(cls, v):
        return _parse_json_dict(v)

    @field_validator("rule_matches", "tags", mode="before")
    @classmethod
    def _parse_json_list_fields(cls, v):
        return _parse_json_list(v)

    class Config:
        from_attributes = True


class LogListResponse(BaseModel):
    """Schema for paginated log list"""

    items: list[LogEntryResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


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
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0
    query_time_ms: int = 0
    aggregations: Optional[dict[str, Any]] = None
    # The ingest-time window the search ran over (bounded; see
    # src/api/v1/endpoints/siem.py MAX_LOG_WINDOW).
    window_start: Optional[str] = None
    window_end: Optional[str] = None


class AggregationRequest(BaseModel):
    """Schema for aggregation queries"""

    field: str = ""
    agg_type: str = ""
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

    id: str = ""
    status: str = ""
    enabled: bool = False
    match_count: int = 0
    last_matched_at: Optional[str] = None
    detection_logic: Optional[dict[str, Any]] = None
    condition: Optional[str] = None
    timewindow: Optional[int] = None
    threshold: Optional[int] = None
    group_by: Optional[list[str]] = None
    false_positive_notes: Optional[str] = None
    references: Optional[list[str]] = None
    rule_yaml: Optional[str] = None
    # None = platform (built-in) rule: visible to every organisation,
    # read-only for organisation users.
    organization_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Set on create / update responses only: whether the engine of the
    # process that answered now evaluates this rule, and validator warnings.
    engine_loaded: Optional[bool] = None
    validation_warnings: list[str] = []

    @field_validator("detection_logic", mode="before")
    @classmethod
    def _parse_detection_logic(cls, v):
        return _parse_json_dict(v)

    @field_validator(
        "log_types", "mitre_tactics", "mitre_techniques",
        "tags", "group_by", "references",
        mode="before",
    )
    @classmethod
    def _parse_list_fields(cls, v):
        return _parse_json_list(v)

    class Config:
        from_attributes = True


class DetectionRuleListResponse(BaseModel):
    """Schema for paginated detection rule list"""

    items: list[DetectionRuleResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class CorrelationEventResponse(DBModel):
    """Schema for correlation event response"""

    id: str = ""
    correlation_id: str = ""
    name: str = ""
    description: Optional[str] = None
    severity: str = ""
    rule_id: Optional[str] = None
    log_entry_ids: Optional[list[str]] = None
    source_addresses: Optional[list[str]] = None
    usernames: Optional[list[str]] = None
    hostnames: Optional[list[str]] = None
    timespan_start: str = ""
    timespan_end: str = ""
    event_count: int = 0
    mitre_tactics: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    alert_generated: bool = False
    status: str = ""
    created_at: Optional[datetime] = None

    @field_validator(
        "log_entry_ids", "source_addresses", "usernames", "hostnames",
        "mitre_tactics", "mitre_techniques",
        mode="before",
    )
    @classmethod
    def _parse_list_fields(cls, v):
        return _parse_json_list(v)

    class Config:
        from_attributes = True


class SIEMStatsResponse(BaseModel):
    """Schema for SIEM statistics"""

    total_logs: int = 0
    logs_today: int = 0
    events_per_second: float = 0.0
    active_rules: int = 0
    alerts_triggered_24h: int = 0
    active_data_sources: int = 0
    logs_by_type: list[dict[str, Any]]
    logs_by_severity: list[dict[str, Any]]
    logs_by_source: list[dict[str, Any]]
    recent_detections: list[dict[str, Any]] = []
    rule_matches_today: int = 0
    active_correlations: int = 0
    ingestion_rate_per_hour: float = 0.0
    storage_stats: Optional[dict[str, Any]] = None
    # Wave 3: everything below is computed from stored rows and live
    # collector / queue state for the caller's organisation.
    window_hours: int = 24
    logs_24h: int = 0
    # enabled data sources whose last event arrived in the last hour
    receiving_data_sources: int = 0
    events_per_second_window_seconds: int = 300
    ingestion_timeline: list[dict[str, Any]] = []
    logs_by_source_type: list[dict[str, Any]] = []
    top_rules: list[dict[str, Any]] = []
    correlations_24h: int = 0
    last_ingest_at: Optional[str] = None
    pipeline_status: Optional[dict[str, Any]] = None


class DataSourceCreate(BaseModel):
    """Schema for creating a data source"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    source_type: str = ""
    connection_config: dict[str, Any] = {}
    parser_config: Optional[dict[str, Any]] = None
    enabled: bool = True


class DataSourceUpdate(BaseModel):
    """Schema for partially updating a data source (only sent fields change)"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    source_type: Optional[str] = None
    connection_config: Optional[dict[str, Any]] = None
    parser_config: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None


class DataSourceResponse(DBModel):
    """Schema for data source response"""

    id: str = ""
    name: str = ""
    description: Optional[str] = None
    source_type: str = ""
    enabled: bool = False
    last_event_at: Optional[str] = None
    events_today: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    created_at: Optional[datetime] = None
    # Lifetime count of ingested logs whose source_name equals ``name``.
    events_received: int = 0
    # disabled | no_events | receiving (event in the last hour) | idle
    ingest_status: str = ""
    # How ingested logs are attributed to this data source.
    match_field: str = "source_name"

    class Config:
        from_attributes = True

    @model_validator(mode="after")
    def _derive_ingest_state(self) -> "DataSourceResponse":
        now = datetime.now(timezone.utc)
        last = None
        if self.last_event_at:
            try:
                last = datetime.fromisoformat(self.last_event_at.replace("Z", "+00:00"))
            except ValueError:
                last = None
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
        # events_today is reset by the first event of a new UTC day, so a
        # source that has been quiet since an earlier day has 0 today.
        if last is None or last.date() != now.date():
            self.events_today = 0
        self.events_received = self.events_received or 0
        if not self.enabled:
            self.ingest_status = "disabled"
        elif last is None:
            self.ingest_status = "no_events"
        elif now - last <= timedelta(hours=1):
            self.ingest_status = "receiving"
        else:
            self.ingest_status = "idle"
        return self
