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

    id: str = ""
    status: str = ""
    ingestion_rate_eps: Optional[int] = None
    total_events_ingested: int = 0
    storage_size_bytes: int = 0
    last_event_received: Optional[str] = None
    last_error: Optional[str] = None
    is_enabled: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataSourceListResponse(BaseModel):
    """Schema for paginated data source list"""

    items: list[DataSourceResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Data Partition Schemas


class DataPartitionBase(BaseModel):
    """Base schema for data partitions"""

    partition_key: str = ""
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    format: str = "parquet"
    compression: str = "snappy"
    storage_tier: str = "hot"


class DataPartitionCreate(DataPartitionBase):
    """Schema for creating a data partition"""

    source_id: str = ""
    location: str = ""


class DataPartitionUpdate(BaseModel):
    """Schema for updating a data partition"""

    storage_tier: Optional[str] = None
    is_indexed: Optional[bool] = None
    index_columns: Optional[list[str]] = None


class DataPartitionResponse(DataPartitionBase, DBModel):
    """Schema for data partition response"""

    id: str = ""
    source_id: str = ""
    record_count: int = 0
    size_bytes: int = 0
    location: str = ""
    is_indexed: bool = False
    index_columns: Optional[list[str]] = None
    query_count_30d: int = 0
    last_accessed: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataPartitionListResponse(BaseModel):
    """Schema for paginated partition list"""

    items: list[DataPartitionResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Data Pipeline Schemas


class TransformRule(BaseModel):
    """Schema for transform rule definition"""

    type: str = ""
    name: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


class DataPipelineBase(BaseModel):
    """Base schema for data pipelines"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    pipeline_type: str = Field(..., description="Type of pipeline (ingestion, transformation, etc.)")
    destination: str = ""
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

    id: str = ""
    source_id: Optional[str] = None
    status: str = ""
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    avg_processing_time_ms: int = 0
    records_processed_total: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataPipelineListResponse(BaseModel):
    """Schema for paginated pipeline list"""

    items: list[DataPipelineResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Unified Data Model Schemas


class FieldDefinition(BaseModel):
    """Field definition for unified data model"""

    name: str = ""
    type: str = ""
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

    id: str = ""
    schema_version: str = ""
    sample_data: Optional[dict[str, Any]] = None
    is_active: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UnifiedDataModelListResponse(BaseModel):
    """Schema for paginated unified data model list"""

    items: list[UnifiedDataModelResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


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

    id: str = ""
    status: str = ""
    records_scanned: int = 0
    records_returned: int = 0
    execution_time_ms: int = 0
    result_location: Optional[str] = None
    cost_estimate: Optional[float] = None
    submitted_by: str = ""
    cached: bool = False
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class QueryJobListResponse(BaseModel):
    """Schema for paginated query job list"""

    items: list[QueryJobResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Engine Operation Schemas


class SourceConfigurationResult(BaseModel):
    """Result of source configuration"""

    source_id: str = ""
    status: str = ""
    validation: dict[str, Any]


class IngestionMetrics(BaseModel):
    """Ingestion performance metrics"""

    source_id: str = ""
    status: str = ""
    events_per_second: int = 0
    total_events: int = 0
    daily_ingestion_gb: float = 0.0
    success_rate: float = 0.0
    error_rate: float = 0.0
    avg_latency_ms: int = 0
    time_window_seconds: int = 0


class QueryExecutionResult(BaseModel):
    """Result of query execution"""

    query_id: str = ""
    status: str = ""
    cached: bool = False
    records_scanned: int = 0
    records_returned: int = 0
    execution_time_ms: int = 0
    data_sources_queried: list[str]
    result_location: Optional[str] = None
    cost_estimate: Optional[float] = None


class CostEstimate(BaseModel):
    """Query cost estimate"""

    data_scanned_gb: int = 0
    query_complexity: str = ""
    base_cost_usd: float = 0.0
    estimated_cost_usd: float = 0.0
    pricing_per_tb_usd: float = 0.0


class StorageCost(BaseModel):
    """Storage cost calculation"""

    storage_gb: int = 0
    tier: str = ""
    monthly_cost_usd: float = 0.0
    annual_cost_usd: float = 0.0
    cost_per_gb_month: float = 0.0


class DataQualityReport(BaseModel):
    """Data quality validation report"""

    dataset_id: str = ""
    total_records: int = 0
    quality_issues: int = 0
    quality_score: float = 0.0
    status: str = ""


class LineageInfo(BaseModel):
    """Data lineage information"""

    dataset_id: str = ""
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

    total_bytes: int = 0
    by_tier: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    hot_percentage: float = 0.0
    warm_percentage: float = 0.0
    cold_percentage: float = 0.0


class QueryPerformance(BaseModel):
    """Query performance metrics"""

    avg_execution_time_ms: int = 0
    p50_execution_time_ms: int = 0
    p95_execution_time_ms: int = 0
    p99_execution_time_ms: int = 0
    cached_queries_percentage: float = 0.0
    total_queries_24h: int = 0
    failed_queries_24h: int = 0


class PipelineHealth(BaseModel):
    """Pipeline health metrics"""

    total_pipelines: int = 0
    active_pipelines: int = 0
    failed_pipelines: int = 0
    avg_success_rate: float = 0.0
    total_records_processed_24h: int = 0
    avg_processing_time_ms: int = 0
