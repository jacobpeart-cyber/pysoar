"""Data Lake models for security data sources, pipelines, and queries"""

from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import ForeignKey, Integer, String, Text, Float, Boolean
from sqlalchemy.dialects.postgresql import JSON, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.organization import Organization


class SourceType(str, Enum):
    """Data source types"""

    SIEM_EVENTS = "siem_events"
    EDR_TELEMETRY = "edr_telemetry"
    NETWORK_FLOW = "network_flow"
    CLOUD_AUDIT = "cloud_audit"
    IDENTITY_LOGS = "identity_logs"
    EMAIL_LOGS = "email_logs"
    DNS_LOGS = "dns_logs"
    FIREWALL_LOGS = "firewall_logs"
    VULNERABILITY_SCANS = "vulnerability_scans"
    THREAT_INTEL = "threat_intel"
    APPLICATION_LOGS = "application_logs"
    CONTAINER_LOGS = "container_logs"
    OT_EVENTS = "ot_events"
    CUSTOM = "custom"


class IngestionType(str, Enum):
    """Data ingestion methods"""

    PUSH = "push"
    PULL = "pull"
    STREAMING = "streaming"
    BATCH = "batch"


class DataFormat(str, Enum):
    """Data format types"""

    JSON = "json"
    CSV = "csv"
    SYSLOG = "syslog"
    CEF = "cef"
    LEEF = "leef"
    PARQUET = "parquet"
    AVRO = "avro"
    ORC = "orc"
    CUSTOM = "custom"


class SourceStatus(str, Enum):
    """Data source status"""

    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    INITIALIZING = "initializing"
    DISABLED = "disabled"


class StorageTier(str, Enum):
    """Storage tiers for data partition optimization"""

    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    FROZEN = "frozen"
    ARCHIVED = "archived"


class CompressionType(str, Enum):
    """Compression algorithms"""

    NONE = "none"
    GZIP = "gzip"
    SNAPPY = "snappy"
    LZ4 = "lz4"
    ZSTD = "zstd"


class PipelineType(str, Enum):
    """Data pipeline types"""

    INGESTION = "ingestion"
    TRANSFORMATION = "transformation"
    ENRICHMENT = "enrichment"
    AGGREGATION = "aggregation"
    EXPORT = "export"
    RETENTION_MANAGEMENT = "retention_management"


class PipelineStatus(str, Enum):
    """Pipeline execution status"""

    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    BUILDING = "building"
    FAILED = "failed"


class QueryLanguage(str, Enum):
    """Query language types"""

    SQL = "sql"
    KQL = "kql"
    SPLUNK_SPL = "splunk_spl"
    LUCENE = "lucene"
    CUSTOM_DSL = "custom_dsl"


class QueryStatus(str, Enum):
    """Query job status"""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EntityType(str, Enum):
    """Unified data model entity types"""

    EVENT = "event"
    ALERT = "alert"
    ASSET = "asset"
    IDENTITY = "identity"
    NETWORK_FLOW = "network_flow"
    VULNERABILITY = "vulnerability"
    THREAT_INDICATOR = "threat_indicator"
    INCIDENT = "incident"
    AUDIT_LOG = "audit_log"


class DataSource(BaseModel):
    """Security data source with connection and ingestion configuration"""

    __tablename__ = "data_sources"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    connection_config_encrypted: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment="Encrypted connection details (API keys, credentials, endpoints)",
    )
    ingestion_type: Mapped[str] = mapped_column(String(50), nullable=False)
    format: Mapped[str] = mapped_column(String(50), nullable=False)
    schema_definition: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment="Field definitions and data types",
    )
    normalization_mapping: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment="Mapping to unified data model fields",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=SourceStatus.INITIALIZING.value,
        nullable=False,
        index=True,
    )
    ingestion_rate_eps: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Events per second ingestion rate",
    )
    total_events_ingested: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    storage_size_bytes: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    retention_days: Mapped[int] = mapped_column(
        Integer,
        default=90,
        nullable=False,
    )
    last_event_received: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp of last event",
    )
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    partitions: Mapped[list["DataPartition"]] = relationship(
        back_populates="source",
        cascade="all, delete-orphan",
    )
    pipelines: Mapped[list["DataPipeline"]] = relationship(
        back_populates="source",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<DataSource {self.id}: {self.name} ({self.source_type})>"


class DataPartition(BaseModel):
    """Partitioned data segment with storage and optimization metadata"""

    __tablename__ = "data_partitions"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("data_sources.id"),
        nullable=False,
        index=True,
    )
    partition_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Partition identifier (e.g., source_siem_2024_03_21)",
    )
    time_range_start: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp start of data range",
    )
    time_range_end: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp end of data range",
    )
    record_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    storage_tier: Mapped[str] = mapped_column(
        String(50),
        default=StorageTier.HOT.value,
        nullable=False,
    )
    format: Mapped[str] = mapped_column(String(50), nullable=False)
    compression: Mapped[str] = mapped_column(
        String(50),
        default=CompressionType.SNAPPY.value,
        nullable=False,
    )
    location: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        comment="Storage path (S3, GCS, local path, etc.)",
    )
    is_indexed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    index_columns: Mapped[Optional[list[str]]] = mapped_column(
        JSON,
        nullable=True,
        comment="Columns with indexes for query optimization",
    )
    query_count_30d: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Queries against this partition in last 30 days",
    )
    last_accessed: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp of last query",
    )

    # Relationships
    source: Mapped["DataSource"] = relationship(back_populates="partitions")

    def __repr__(self) -> str:
        return f"<DataPartition {self.id}: {self.partition_key} ({self.storage_tier})>"


class DataPipeline(BaseModel):
    """Data transformation and processing pipeline"""

    __tablename__ = "data_pipelines"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pipeline_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("data_sources.id"),
        nullable=True,
    )
    destination: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Target system/data lake path",
    )
    transform_rules: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        comment="List of transformation operations with configs",
    )
    schedule_cron: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Cron expression for scheduled execution",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=PipelineStatus.BUILDING.value,
        nullable=False,
        index=True,
    )
    last_run: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp of last execution",
    )
    next_run: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp of next scheduled execution",
    )
    avg_processing_time_ms: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    records_processed_total: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    source: Mapped[Optional["DataSource"]] = relationship(back_populates="pipelines")

    def __repr__(self) -> str:
        return f"<DataPipeline {self.id}: {self.name} ({self.pipeline_type})>"


class UnifiedDataModel(BaseModel):
    """Unified data model schema for normalized security data"""

    __tablename__ = "unified_data_models"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(20), default="1.0.0", nullable=False)
    field_definitions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        comment="Array of {name, type, description, source_mapping, required}",
    )
    normalization_rules: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        comment="Rules for normalizing raw data to unified model",
    )
    enrichment_rules: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        comment="Rules for enriching data with context (geo, threat intel, assets)",
    )
    sample_data: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        comment="Example normalized event for validation",
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<UnifiedDataModel {self.id}: {self.name} ({self.entity_type})>"


class QueryJob(BaseModel):
    """Data query execution job"""

    __tablename__ = "query_jobs"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    query_text: Mapped[str] = mapped_column(Text, nullable=False)
    query_language: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        default=QueryStatus.QUEUED.value,
        nullable=False,
        index=True,
    )
    data_sources_queried: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        comment="IDs of data sources included in query",
    )
    time_range_start: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp query start",
    )
    time_range_end: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="ISO timestamp query end",
    )
    records_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_returned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    execution_time_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_location: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        comment="Path to query results (S3, GCS, etc.)",
    )
    cost_estimate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Estimated query cost in USD",
    )
    submitted_by: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        comment="User ID who submitted the query",
    )
    cached: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether result was served from cache",
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<QueryJob {self.id}: {self.status}>"
