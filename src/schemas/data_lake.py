"""Schemas for Data Lake API request/response validation"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Data Source Schemas


class DataSourceBase(BaseModel):
    """Base schema for data sources"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    source_type: str = Field(..., description="Type of data source (siem_events, edr_telemetry, etc.)")
    ingestion_type: str = Field(..., description="Ingestion method (push, pull, streaming, batch)")
    format: str = Field(..., description="Data format (json, csv, syslog, cef, parquet, etc.)")
    retention_days: int = Field(default=90, ge=1, le=2555)
    schema_definition: dict[str, Any] = Field(default_factory=dict)
    normalization_mapping: dict[str, Any] = Field(default_factory=dict)
    connection_config_encrypted: dict[str, Any] = Field(default_factory=dict)


class DataSourceCreate(DataSourceBase):
    """Schema for creating a data source"""

    pass


class DataSourceUpdate(BaseModel):
    """Schema for updating a data source"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    ingestion_type: Optional[str] = None
    format: Optional[str] = None
    retention_days: Optional[int] = Field(None, ge=1, le=2555)
    schema_definition: Optional[dict[str, Any]] = None
    normalization_mapping: Optional[dict[str, Any]] = None
    status: Optional[str] = None
    is_enabled: Optional[bool] = None


class DataSourceResponse(DataSourceBase, DBModel):
    """Schema for data source response"""

    id: str
    status: str
    ingestion_rate_eps: Optional[int] = None
    total_events_ingested: int
    storage_size_bytes: int
    last_event_received: Optional[str] = None
    last_error: Optional[str] = None
    is_enabled: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataSourceListResponse(BaseModel):
    """Schema for paginated data source list"""

    items: list[DataSourceResponse]
    total: int
    page: int
    size: int
    pages: int


# Data Partition Schemas


class DataPartitionBase(BaseModel):
    """Base schema for data partitions"""

    partition_key: str
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    format: str = "parquet"
    compression: str = "snappy"
    storage_tier: str = "hot"


class DataPartitionCreate(DataPartitionBase):
    """Schema for creating a data partition"""

    source_id: str
    location: str


class DataPartitionUpdate(BaseModel):
    """Schema for updating a data partition"""

    storage_tier: Optional[str] = None
    is_indexed: Optional[bool] = None
    index_columns: Optional[list[str]] = None


class DataPartitionResponse(DataPartitionBase, DBModel):
    """Schema for data partition response"""

    id: str
    source_id: str
    record_count: int
    size_bytes: int
    location: str
    is_indexed: bool
    index_columns: Optional[list[str]] = None
    query_count_30d: int
    last_accessed: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataPartitionListResponse(BaseModel):
    """Schema for paginated partition list"""

    items: list[DataPartitionResponse]
    total: int
    page: int
    size: int
    pages: int


# Data Pipeline Schemas


class TransformRule(BaseModel):
    """Schema for transform rule definition"""

    type: str
    name: str
    config: dict[str, Any] = Field(default_factory=dict)


class DataPipelineBase(BaseModel):
    """Base schema for data pipelines"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    pipeline_type: str = Field(..., description="Type of pipeline (ingestion, transformation, etc.)")
    destination: str
    transform_rules: list[TransformRule] = Field(default_factory=list)
    schedule_cron: Optional[str] = None


class DataPipelineCreate(DataPipelineBase):
    """Schema for creating a data pipeline"""

    source_id: Optional[str] = None


class DataPipelineUpdate(BaseModel):
    """Schema for updating a data pipeline"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    destination: Optional[str] = None
    transform_rules: Optional[list[TransformRule]] = None
    schedule_cron: Optional[str] = None
    status: Optional[str] = None


class DataPipelineResponse(DataPipelineBase, DBModel):
    """Schema for data pipeline response"""

    id: str
    source_id: Optional[str] = None
    status: str
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    avg_processing_time_ms: int
    records_processed_total: int
    error_count: int
    last_error: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataPipelineListResponse(BaseModel):
    """Schema for paginated pipeline list"""

    items: list[DataPipelineResponse]
    total: int
    page: int
    size: int
    pages: int


# Unified Data Model Schemas


class FieldDefinition(BaseModel):
    """Field definition for unified data model"""

    name: str
    type: str
    description: Optional[str] = None
    required: bool = False
    source_mapping: Optional[dict[str, Any]] = None


class UnifiedDataModelBase(BaseModel):
    """Base schema for unified data models"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    entity_type: str = Field(..., description="Entity type (event, alert, asset, etc.)")
    field_definitions: list[FieldDefinition] = Field(default_factory=list)
    normalization_rules: list[dict[str, Any]] = Field(default_factory=list)
    enrichment_rules: list[dict[str, Any]] = Field(default_factory=list)


class UnifiedDataModelCreate(UnifiedDataModelBase):
    """Schema for creating a unified data model"""

    sample_data: Optional[dict[str, Any]] = None


class UnifiedDataModelUpdate(BaseModel):
    """Schema for updating a unified data model"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    field_definitions: Optional[list[FieldDefinition]] = None
    normalization_rules: Optional[list[dict[str, Any]]] = None
    enrichment_rules: Optional[list[dict[str, Any]]] = None
    sample_data: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None


class UnifiedDataModelResponse(UnifiedDataModelBase, DBModel):
    """Schema for unified data model response"""

    id: str
    schema_version: str
    sample_data: Optional[dict[str, Any]] = None
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UnifiedDataModelListResponse(BaseModel):
    """Schema for paginated unified data model list"""

    items: list[UnifiedDataModelResponse]
    total: int
    page: int
    size: int
    pages: int


# Query Job Schemas


class QueryJobBase(BaseModel):
    """Base schema for query jobs"""

    query_text: str = Field(...)
    query_language: str = Field(..., description="Language (sql, kql, spl, lucene, custom_dsl)")
    data_sources_queried: list[str] = Field(default_factory=list)
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None


class QueryJobCreate(QueryJobBase):
    """Schema for creating a query job"""

    pass


class QueryJobResponse(QueryJobBase, DBModel):
    """Schema for query job response"""

    id: str
    status: str
    records_scanned: int = 0
    records_returned: int = 0
    execution_time_ms: int = 0
    result_location: Optional[str] = None
    cost_estimate: Optional[float] = None
    submitted_by: str
    cached: bool
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class QueryJobListResponse(BaseModel):
    """Schema for paginated query job list"""

    items: list[QueryJobResponse]
    total: int
    page: int
    size: int
    pages: int


# Engine Operation Schemas


class SourceConfigurationResult(BaseModel):
    """Result of source configuration"""

    source_id: str
    status: str
    validation: dict[str, Any]


class IngestionMetrics(BaseModel):
    """Ingestion performance metrics"""

    source_id: str
    status: str
    events_per_second: int
    total_events: int
    daily_ingestion_gb: float
    success_rate: float
    error_rate: float
    avg_latency_ms: int
    time_window_seconds: int


class QueryExecutionResult(BaseModel):
    """Result of query execution"""

    query_id: str
    status: str
    cached: bool
    records_scanned: int
    records_returned: int
    execution_time_ms: int
    data_sources_queried: list[str]
    result_location: Optional[str] = None
    cost_estimate: Optional[float] = None


class CostEstimate(BaseModel):
    """Query cost estimate"""

    data_scanned_gb: int
    query_complexity: str
    base_cost_usd: float
    estimated_cost_usd: float
    pricing_per_tb_usd: float


class StorageCost(BaseModel):
    """Storage cost calculation"""

    storage_gb: int
    tier: str
    monthly_cost_usd: float
    annual_cost_usd: float
    cost_per_gb_month: float


class DataQualityReport(BaseModel):
    """Data quality validation report"""

    dataset_id: str
    total_records: int
    quality_issues: int
    quality_score: float
    status: str


class LineageInfo(BaseModel):
    """Data lineage information"""

    dataset_id: str
    upstream_sources: list[str]
    downstream_consumers: list[str] = Field(default_factory=list)


# Dashboard Schemas


class DashboardMetrics(BaseModel):
    """Unified dashboard metrics"""

    ingestion_metrics: Optional[IngestionMetrics] = None
    storage_usage: dict[str, Any] = Field(default_factory=dict)
    query_performance: dict[str, Any] = Field(default_factory=dict)
    pipeline_health: dict[str, Any] = Field(default_factory=dict)
    data_quality: list[DataQualityReport] = Field(default_factory=list)
    timestamp: datetime


class StorageUsage(BaseModel):
    """Storage usage breakdown"""

    total_bytes: int
    by_tier: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    hot_percentage: float
    warm_percentage: float
    cold_percentage: float


class QueryPerformance(BaseModel):
    """Query performance metrics"""

    avg_execution_time_ms: int
    p50_execution_time_ms: int
    p95_execution_time_ms: int
    p99_execution_time_ms: int
    cached_queries_percentage: float
    total_queries_24h: int
    failed_queries_24h: int


class PipelineHealth(BaseModel):
    """Pipeline health metrics"""

    total_pipelines: int
    active_pipelines: int
    failed_pipelines: int
    avg_success_rate: float
    total_records_processed_24h: int
    avg_processing_time_ms: int
