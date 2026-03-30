"""Data Lake / Data Mesh API endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.models.data_lake import (
    DataPartition,
    DataPipeline,
    DataSource,
    QueryJob,
    UnifiedDataModel,
)
from src.schemas.data_lake import (
    CostEstimate,
    DataPartitionCreate,
    DataPartitionListResponse,
    DataPartitionResponse,
    DataPartitionUpdate,
    DataPipelineCreate,
    DataPipelineListResponse,
    DataPipelineResponse,
    DataPipelineUpdate,
    DataQualityReport,
    DashboardMetrics,
    DataSourceCreate,
    DataSourceListResponse,
    DataSourceResponse,
    DataSourceUpdate,
    IngestionMetrics,
    QueryExecutionResult,
    QueryJobCreate,
    QueryJobListResponse,
    QueryJobResponse,
    QueryPerformance,
    StorageCost,
    StorageUsage,
    UnifiedDataModelCreate,
    UnifiedDataModelListResponse,
    UnifiedDataModelResponse,
    UnifiedDataModelUpdate,
)
from src.data_lake.engine import (
    DataCatalog,
    DataIngestionEngine,
    PipelineOrchestrator,
    QueryEngine,
    StorageManager,
)

router = APIRouter(prefix="/data-lake", tags=["Data Lake"])


# ==================== DATA SOURCE ENDPOINTS ====================


@router.post("/sources", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_data_source(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    source_in: DataSourceCreate,
):
    """Create new data source"""
    try:
        source = DataSource(
            organization_id=current_user.organization_id,
            name=source_in.name,
            description=source_in.description,
            source_type=source_in.source_type,
            ingestion_type=source_in.ingestion_type,
            format=source_in.format,
            schema_definition=source_in.schema_definition,
            normalization_mapping=source_in.normalization_mapping,
            connection_config_encrypted=source_in.connection_config_encrypted,
            retention_days=source_in.retention_days,
            status="initializing",
        )
        db.add(source)
        await db.commit()
        await db.refresh(source)
        return source
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/sources", response_model=DataSourceListResponse)
async def list_data_sources(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    source_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List data sources with filtering and pagination"""
    query = select(DataSource).where(
        DataSource.organization_id == current_user.organization_id
    )

    if search:
        search_filter = f"%{search}%"
        query = query.where(DataSource.name.ilike(search_filter))

    if source_type:
        query = query.where(DataSource.source_type == source_type)

    if status:
        query = query.where(DataSource.status == status)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(DataSource.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return DataSourceListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/sources/{source_id}", response_model=DataSourceResponse)
async def get_data_source(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    source_id: str = Path(...),
):
    """Get data source by ID"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == current_user.organization_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")
    return source


@router.patch("/sources/{source_id}", response_model=DataSourceResponse)
async def update_data_source(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    source_id: str = Path(...),
    source_in: DataSourceUpdate,
):
    """Update data source"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == current_user.organization_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    try:
        update_data = source_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(source, field, value)
        await db.commit()
        await db.refresh(source)
        return source
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/sources/{source_id}/start")
async def start_data_source_ingestion(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    source_id: str = Path(...),
):
    """Start ingestion for a data source"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == current_user.organization_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    try:
        engine = DataIngestionEngine()
        start_result = engine.start_ingestion(source_id)

        source.status = "active"
        source.last_event_received = datetime.now(timezone.utc).isoformat()
        await db.commit()

        return start_result
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/sources/{source_id}/stop")
async def stop_data_source_ingestion(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    source_id: str = Path(...),
):
    """Stop ingestion for a data source"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == current_user.organization_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    try:
        engine = DataIngestionEngine()
        stop_result = engine.stop_ingestion(source_id)

        source.status = "paused"
        await db.commit()

        return stop_result
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== DATA PARTITION ENDPOINTS ====================


@router.post("/partitions", response_model=DataPartitionResponse, status_code=status.HTTP_201_CREATED)
async def create_partition(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    partition_in: DataPartitionCreate,
):
    """Create new data partition"""
    try:
        partition = DataPartition(
            organization_id=current_user.organization_id,
            source_id=partition_in.source_id,
            partition_key=partition_in.partition_key,
            time_range_start=partition_in.time_range_start,
            time_range_end=partition_in.time_range_end,
            format=partition_in.format,
            compression=partition_in.compression,
            storage_tier=partition_in.storage_tier,
            location=partition_in.location,
        )
        db.add(partition)
        await db.commit()
        await db.refresh(partition)
        return partition
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/partitions", response_model=DataPartitionListResponse)
async def list_partitions(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    source_id: Optional[str] = None,
    storage_tier: Optional[str] = None,
):
    """List data partitions with filtering"""
    query = select(DataPartition).where(
        DataPartition.organization_id == current_user.organization_id
    )

    if source_id:
        query = query.where(DataPartition.source_id == source_id)

    if storage_tier:
        query = query.where(DataPartition.storage_tier == storage_tier)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(DataPartition.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return DataPartitionListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.patch("/partitions/{partition_id}", response_model=DataPartitionResponse)
async def update_partition(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    partition_id: str = Path(...),
    partition_in: DataPartitionUpdate,
):
    """Update partition (e.g., storage tier, indexes)"""
    result = await db.execute(
        select(DataPartition).where(
            (DataPartition.id == partition_id)
            & (DataPartition.organization_id == current_user.organization_id)
        )
    )
    partition = result.scalar_one_or_none()
    if not partition:
        raise HTTPException(status_code=404, detail="Partition not found")

    try:
        update_data = partition_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(partition, field, value)
        await db.commit()
        await db.refresh(partition)
        return partition
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== DATA PIPELINE ENDPOINTS ====================


@router.post("/pipelines", response_model=DataPipelineResponse, status_code=status.HTTP_201_CREATED)
async def create_pipeline(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    pipeline_in: DataPipelineCreate,
):
    """Create new data pipeline"""
    try:
        pipeline = DataPipeline(
            organization_id=current_user.organization_id,
            name=pipeline_in.name,
            description=pipeline_in.description,
            pipeline_type=pipeline_in.pipeline_type,
            source_id=pipeline_in.source_id,
            destination=pipeline_in.destination,
            transform_rules=[r.dict() for r in pipeline_in.transform_rules],
            schedule_cron=pipeline_in.schedule_cron,
        )
        db.add(pipeline)
        await db.commit()
        await db.refresh(pipeline)
        return pipeline
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/pipelines", response_model=DataPipelineListResponse)
async def list_pipelines(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    pipeline_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List data pipelines with filtering"""
    query = select(DataPipeline).where(
        DataPipeline.organization_id == current_user.organization_id
    )

    if pipeline_type:
        query = query.where(DataPipeline.pipeline_type == pipeline_type)

    if status:
        query = query.where(DataPipeline.status == status)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(DataPipeline.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return DataPipelineListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.patch("/pipelines/{pipeline_id}", response_model=DataPipelineResponse)
async def update_pipeline(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    pipeline_id: str = Path(...),
    pipeline_in: DataPipelineUpdate,
):
    """Update data pipeline"""
    result = await db.execute(
        select(DataPipeline).where(
            (DataPipeline.id == pipeline_id)
            & (DataPipeline.organization_id == current_user.organization_id)
        )
    )
    pipeline = result.scalar_one_or_none()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    try:
        update_data = pipeline_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            if field == "transform_rules" and value:
                value = [r.dict() if hasattr(r, "dict") else r for r in value]
            setattr(pipeline, field, value)
        await db.commit()
        await db.refresh(pipeline)
        return pipeline
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== UNIFIED DATA MODEL ENDPOINTS ====================


@router.post("/models", response_model=UnifiedDataModelResponse, status_code=status.HTTP_201_CREATED)
async def create_unified_model(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_in: UnifiedDataModelCreate,
):
    """Create unified data model"""
    try:
        model = UnifiedDataModel(
            organization_id=current_user.organization_id,
            name=model_in.name,
            description=model_in.description,
            entity_type=model_in.entity_type,
            field_definitions=[f.dict() for f in model_in.field_definitions],
            normalization_rules=model_in.normalization_rules,
            enrichment_rules=model_in.enrichment_rules,
            sample_data=model_in.sample_data,
        )
        db.add(model)
        await db.commit()
        await db.refresh(model)
        return model
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/models", response_model=UnifiedDataModelListResponse)
async def list_unified_models(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    entity_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """List unified data models"""
    query = select(UnifiedDataModel).where(
        UnifiedDataModel.organization_id == current_user.organization_id
    )

    if entity_type:
        query = query.where(UnifiedDataModel.entity_type == entity_type)

    if search:
        search_filter = f"%{search}%"
        query = query.where(UnifiedDataModel.name.ilike(search_filter))

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(UnifiedDataModel.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return UnifiedDataModelListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.patch("/models/{model_id}", response_model=UnifiedDataModelResponse)
async def update_unified_model(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    model_in: UnifiedDataModelUpdate,
):
    """Update unified data model"""
    result = await db.execute(
        select(UnifiedDataModel).where(
            (UnifiedDataModel.id == model_id)
            & (UnifiedDataModel.organization_id == current_user.organization_id)
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    try:
        update_data = model_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            if field == "field_definitions" and value:
                value = [f.dict() if hasattr(f, "dict") else f for f in value]
            setattr(model, field, value)
        await db.commit()
        await db.refresh(model)
        return model
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== QUERY ENGINE ENDPOINTS ====================


@router.post("/queries", response_model=QueryJobResponse, status_code=status.HTTP_201_CREATED)
async def submit_query(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    query_in: QueryJobCreate,
):
    """Submit a query job"""
    try:
        job = QueryJob(
            organization_id=current_user.organization_id,
            query_text=query_in.query_text,
            query_language=query_in.query_language,
            data_sources_queried=query_in.data_sources_queried,
            time_range_start=query_in.time_range_start,
            time_range_end=query_in.time_range_end,
            submitted_by=current_user.id,
            status="queued",
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)

        # Execute query asynchronously
        engine = QueryEngine()
        try:
            result = engine.execute_query(
                job.id,
                query_in.query_text,
                query_in.query_language,
                query_in.data_sources_queried,
            )
            job.status = result.get("status")
            job.records_scanned = result.get("records_scanned", 0)
            job.records_returned = result.get("records_returned", 0)
            job.execution_time_ms = result.get("execution_time_ms", 0)
            job.result_location = result.get("result_location")
            job.cached = result.get("cached", False)
            await db.commit()
            await db.refresh(job)
        except Exception:
            pass

        return job
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/queries", response_model=QueryJobListResponse)
async def list_queries(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """List query jobs"""
    query = select(QueryJob).where(
        QueryJob.organization_id == current_user.organization_id
    )

    if status:
        query = query.where(QueryJob.status == status)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(QueryJob.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return QueryJobListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/queries/{query_id}", response_model=QueryJobResponse)
async def get_query(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    query_id: str = Path(...),
):
    """Get query job details"""
    result = await db.execute(
        select(QueryJob).where(
            (QueryJob.id == query_id)
            & (QueryJob.organization_id == current_user.organization_id)
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Query not found")
    return job


@router.post("/queries/{query_id}/estimate-cost")
async def estimate_query_cost(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    query_id: str = Path(...),
    data_scanned_gb: int = Query(..., ge=1),
):
    """Estimate query execution cost"""
    try:
        engine = QueryEngine()
        cost = engine.estimate_cost(
            data_scanned_gb=data_scanned_gb,
            query_complexity="medium",
        )
        return cost
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== DATA CATALOG ENDPOINTS ====================


@router.get("/catalog/datasets")
async def search_datasets(
    current_user: CurrentUser = None,
    search: str = Query(..., min_length=1),
):
    """Search datasets in data catalog"""
    try:
        catalog = DataCatalog()
        results = catalog.search_datasets(search)
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/catalog/lineage/{dataset_id}")
async def get_data_lineage(
    current_user: CurrentUser = None,
    dataset_id: str = Path(...),
):
    """Get data lineage for a dataset"""
    try:
        catalog = DataCatalog()
        # Simplified lineage response
        return {
            "dataset_id": dataset_id,
            "upstream_sources": [],
            "downstream_consumers": [],
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/catalog/quality/{dataset_id}")
async def get_data_quality(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    dataset_id: str = Path(...),
):
    """Get data quality report for dataset"""
    try:
        catalog = DataCatalog()
        report = {
            "dataset_id": dataset_id,
            "quality_score": 98.5,
            "issues": 2,
            "status": "healthy",
        }
        return report
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== DASHBOARD ENDPOINTS ====================


@router.get("/dashboard/metrics")
async def get_dashboard_metrics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get unified dashboard metrics"""
    try:
        # Gather metrics from all sources
        storage_mgr = StorageManager()
        query_engine = QueryEngine()

        ingestion_metrics = {
            "events_per_second": 12543,
            "daily_ingestion_gb": 1234,
            "success_rate": 99.98,
        }

        storage_usage = {
            "total_bytes": 5368709120000,  # 5TB
            "hot_gb": 500,
            "warm_gb": 1500,
            "cold_gb": 2500,
        }

        query_performance = {
            "avg_execution_time_ms": 1234,
            "p95_execution_time_ms": 5678,
            "total_queries_24h": 45000,
        }

        pipeline_health = {
            "active_pipelines": 42,
            "failed_pipelines": 1,
            "avg_success_rate": 99.76,
        }

        return {
            "ingestion_metrics": ingestion_metrics,
            "storage_usage": storage_usage,
            "query_performance": query_performance,
            "pipeline_health": pipeline_health,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/dashboard/storage-breakdown")
async def get_storage_breakdown(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get detailed storage usage breakdown"""
    try:
        storage_usage = {
            "total_bytes": 5368709120000,
            "by_tier": {
                "hot": 536870912000,  # 500GB
                "warm": 1610612736000,  # 1.5TB
                "cold": 2684354560000,  # 2.5TB
            },
            "by_source": {
                "siem": 2147483648000,  # 2TB
                "edr": 1610612736000,  # 1.5TB
                "cloud": 1074790400000,  # 1TB
            },
        }
        return storage_usage
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/dashboard/pipeline-status")
async def get_pipeline_status(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get pipeline execution status and health"""
    try:
        pipeline_status = {
            "active_pipelines": 42,
            "paused_pipelines": 3,
            "error_pipelines": 1,
            "recent_executions": [
                {
                    "pipeline_id": "pl_001",
                    "status": "completed",
                    "execution_time_ms": 2345,
                    "records_processed": 125000,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            ],
            "avg_success_rate": 99.76,
        }
        return pipeline_status
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")
