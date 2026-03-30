"""SIEM management endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from sqlalchemy import asc, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.schemas.siem import (
    AggregationRequest,
    CorrelationEventResponse,
    DataSourceCreate,
    DataSourceResponse,
    DetectionRuleCreate,
    DetectionRuleListResponse,
    DetectionRuleResponse,
    DetectionRuleUpdate,
    LogBatchIngestRequest,
    LogEntryResponse,
    LogIngestRequest,
    LogListResponse,
    LogSearchRequest,
    LogSearchResponse,
    SIEMStatsResponse,
)
from src.siem.models import (
    CorrelationEvent,
    DetectionRule,
    LogEntry,
    SIEMDataSource,
)

router = APIRouter(prefix="/siem", tags=["SIEM"])


async def get_log_or_404(db: AsyncSession, log_id: str) -> LogEntry:
    """Get log entry by ID or raise 404"""
    result = await db.execute(select(LogEntry).where(LogEntry.id == log_id))
    log_entry = result.scalar_one_or_none()
    if not log_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log entry not found",
        )
    return log_entry


async def get_rule_or_404(db: AsyncSession, rule_id: str) -> DetectionRule:
    """Get detection rule by ID or raise 404"""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found",
        )
    return rule


async def get_correlation_or_404(db: AsyncSession, correlation_id: str) -> CorrelationEvent:
    """Get correlation event by ID or raise 404"""
    result = await db.execute(select(CorrelationEvent).where(CorrelationEvent.id == correlation_id))
    correlation = result.scalar_one_or_none()
    if not correlation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Correlation event not found",
        )
    return correlation


async def get_source_or_404(db: AsyncSession, source_id: str) -> SIEMDataSource:
    """Get data source by ID or raise 404"""
    result = await db.execute(select(SIEMDataSource).where(SIEMDataSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Data source not found",
        )
    return source


# ============================================================================
# LOG INGESTION ENDPOINTS
# ============================================================================


@router.post("/logs/ingest", response_model=LogEntryResponse, status_code=status.HTTP_201_CREATED)
async def ingest_log(
    log_data: LogIngestRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Ingest a single log entry"""
    log_entry = LogEntry(
        raw_log=log_data.raw_log,
        source_type=log_data.source_type,
        source_name=log_data.source_name or "unknown",
        source_ip=log_data.source_ip or "0.0.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        received_at=datetime.now(timezone.utc).isoformat(),
        log_type="unknown",
        severity="informational",
        tags=json.dumps(log_data.tags) if log_data.tags else None,
    )

    db.add(log_entry)
    await db.flush()
    await db.refresh(log_entry)

    return LogEntryResponse.model_validate(log_entry)


@router.post("/logs/batch", response_model=None)
async def batch_ingest_logs(
    batch_data: LogBatchIngestRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Batch ingest multiple log entries"""
    logs = []
    errors = []

    for log_data in batch_data.logs:
        try:
            log_entry = LogEntry(
                raw_log=log_data.raw_log,
                source_type=log_data.source_type,
                source_name=log_data.source_name or "unknown",
                source_ip=log_data.source_ip or "0.0.0.0",
                timestamp=datetime.now(timezone.utc).isoformat(),
                received_at=datetime.now(timezone.utc).isoformat(),
                log_type="unknown",
                severity="informational",
                tags=json.dumps(log_data.tags) if log_data.tags else None,
                organization_id=batch_data.organization_id,
            )
            logs.append(log_entry)
        except Exception as e:
            errors.append({"raw_log": log_data.raw_log[:50], "error": str(e)})

    db.add_all(logs)
    await db.flush()

    return {
        "success_count": len(logs),
        "error_count": len(errors),
        "errors": errors,
    }


@router.post("/logs/search", response_model=LogSearchResponse)
async def search_logs(
    search_data: LogSearchRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Search logs with complex filtering"""
    query = select(LogEntry)

    # Apply filters
    if search_data.query:
        search_filter = f"%{search_data.query}%"
        query = query.where(
            (LogEntry.message.ilike(search_filter))
            | (LogEntry.raw_log.ilike(search_filter))
            | (LogEntry.hostname.ilike(search_filter))
        )

    if search_data.source_types:
        query = query.where(LogEntry.source_type.in_(search_data.source_types))

    if search_data.log_types:
        query = query.where(LogEntry.log_type.in_(search_data.log_types))

    if search_data.severities:
        query = query.where(LogEntry.severity.in_(search_data.severities))

    if search_data.source_addresses:
        query = query.where(LogEntry.source_address.in_(search_data.source_addresses))

    if search_data.destination_addresses:
        query = query.where(LogEntry.destination_address.in_(search_data.destination_addresses))

    if search_data.usernames:
        query = query.where(LogEntry.username.in_(search_data.usernames))

    if search_data.hostnames:
        query = query.where(LogEntry.hostname.in_(search_data.hostnames))

    if search_data.time_start:
        query = query.where(LogEntry.timestamp >= search_data.time_start.isoformat())

    if search_data.time_end:
        query = query.where(LogEntry.timestamp <= search_data.time_end.isoformat())

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(LogEntry, search_data.sort_by, LogEntry.timestamp)
    if search_data.sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((search_data.page - 1) * search_data.size).limit(search_data.size)

    result = await db.execute(query)
    log_entries = list(result.scalars().all())

    return LogSearchResponse(
        items=[LogEntryResponse.model_validate(le) for le in log_entries],
        total=total,
        page=search_data.page,
        size=search_data.size,
        pages=math.ceil(total / search_data.size) if total > 0 else 0,
        query_time_ms=0,
    )


@router.post("/logs/aggregate", response_model=None)
async def aggregate_logs(
    agg_data: AggregationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Run aggregation query on logs"""
    query = select(getattr(LogEntry, agg_data.field), func.count(LogEntry.id))

    if agg_data.time_start:
        query = query.where(LogEntry.timestamp >= agg_data.time_start.isoformat())

    if agg_data.time_end:
        query = query.where(LogEntry.timestamp <= agg_data.time_end.isoformat())

    query = query.group_by(getattr(LogEntry, agg_data.field)).order_by(
        func.count(LogEntry.id).desc()
    )

    if agg_data.top_n:
        query = query.limit(agg_data.top_n)

    result = await db.execute(query)
    rows = result.all()

    aggregations = {str(row[0]): row[1] for row in rows if row[0] is not None}

    return {
        "field": agg_data.field,
        "agg_type": agg_data.agg_type,
        "aggregations": aggregations,
    }


@router.get("/logs/{log_id}", response_model=LogEntryResponse)
async def get_log(
    log_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a log entry by ID"""
    log_entry = await get_log_or_404(db, log_id)
    return LogEntryResponse.model_validate(log_entry)


@router.get("/logs/stats", response_model=SIEMStatsResponse)
async def get_siem_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get SIEM statistics"""
    # Total logs
    total_result = await db.execute(select(func.count(LogEntry.id)))
    total_logs = total_result.scalar() or 0

    # Logs today (simplified)
    logs_today_result = await db.execute(select(func.count(LogEntry.id)))
    logs_today = logs_today_result.scalar() or 0

    # By type
    type_result = await db.execute(
        select(LogEntry.log_type, func.count(LogEntry.id))
        .group_by(LogEntry.log_type)
    )
    logs_by_type = dict(type_result.all())

    # By severity
    severity_result = await db.execute(
        select(LogEntry.severity, func.count(LogEntry.id))
        .group_by(LogEntry.severity)
    )
    logs_by_severity = dict(severity_result.all())

    # By source
    source_result = await db.execute(
        select(LogEntry.source_name, func.count(LogEntry.id))
        .group_by(LogEntry.source_name)
    )
    logs_by_source = dict(source_result.all())

    # Active rules
    rules_result = await db.execute(
        select(func.count(DetectionRule.id)).where(DetectionRule.enabled == True)
    )
    active_rules = rules_result.scalar() or 0

    # Rule matches today
    matches_result = await db.execute(select(func.sum(DetectionRule.match_count)))
    rule_matches_today = matches_result.scalar() or 0

    # Active correlations
    corr_result = await db.execute(select(func.count(CorrelationEvent.id)))
    active_correlations = corr_result.scalar() or 0

    return SIEMStatsResponse(
        total_logs=total_logs,
        logs_today=logs_today,
        logs_by_type=logs_by_type,
        logs_by_severity=logs_by_severity,
        logs_by_source=logs_by_source,
        active_rules=active_rules,
        rule_matches_today=int(rule_matches_today) if rule_matches_today else 0,
        active_correlations=active_correlations,
        ingestion_rate_per_hour=0.0,
    )


# ============================================================================
# DETECTION RULE ENDPOINTS
# ============================================================================


@router.get("/rules", response_model=DetectionRuleListResponse)
async def list_rules(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    enabled: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List detection rules with filtering and pagination"""
    query = select(DetectionRule)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (DetectionRule.title.ilike(search_filter))
            | (DetectionRule.description.ilike(search_filter))
            | (DetectionRule.name.ilike(search_filter))
        )

    if severity:
        query = query.where(DetectionRule.severity == severity)

    if enabled is not None:
        query = query.where(DetectionRule.enabled == enabled)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(DetectionRule, sort_by, DetectionRule.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    rules = list(result.scalars().all())

    return DetectionRuleListResponse(
        items=[DetectionRuleResponse.model_validate(r) for r in rules],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/rules", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule_data: DetectionRuleCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new detection rule"""
    rule = DetectionRule(
        name=rule_data.name,
        title=rule_data.title,
        description=rule_data.description,
        severity=rule_data.severity,
        log_types=json.dumps(rule_data.log_types) if rule_data.log_types else None,
        detection_logic=json.dumps(rule_data.detection_logic) if rule_data.detection_logic else None,
        condition=rule_data.condition,
        timewindow=rule_data.timewindow,
        threshold=rule_data.threshold,
        group_by=json.dumps(rule_data.group_by) if rule_data.group_by else None,
        mitre_tactics=json.dumps(rule_data.mitre_tactics) if rule_data.mitre_tactics else None,
        mitre_techniques=json.dumps(rule_data.mitre_techniques) if rule_data.mitre_techniques else None,
        tags=json.dumps(rule_data.tags) if rule_data.tags else None,
        false_positive_notes=rule_data.false_positive_notes,
        references=json.dumps(rule_data.references) if rule_data.references else None,
        rule_yaml=rule_data.rule_yaml,
    )

    db.add(rule)
    await db.flush()
    await db.refresh(rule)

    return DetectionRuleResponse.model_validate(rule)


@router.get("/rules/{rule_id}", response_model=DetectionRuleResponse)
async def get_rule(
    rule_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a detection rule by ID"""
    rule = await get_rule_or_404(db, rule_id)
    return DetectionRuleResponse.model_validate(rule)


@router.put("/rules/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(
    rule_id: str,
    rule_data: DetectionRuleUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a detection rule"""
    rule = await get_rule_or_404(db, rule_id)

    update_data = rule_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle JSON serialization for list fields
    json_fields = ["log_types", "mitre_tactics", "mitre_techniques", "tags", "references", "group_by", "detection_logic"]
    for field in json_fields:
        if field in update_data and isinstance(update_data[field], (list, dict)):
            update_data[field] = json.dumps(update_data[field])

    for key, value in update_data.items():
        setattr(rule, key, value)

    await db.flush()
    await db.refresh(rule)

    return DetectionRuleResponse.model_validate(rule)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a detection rule"""
    rule = await get_rule_or_404(db, rule_id)
    await db.delete(rule)
    await db.flush()


@router.post("/rules/{rule_id}/test", response_model=None)
async def test_rule(
    rule_id: str,
    sample_logs: list[str],
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Test a detection rule against sample logs"""
    rule = await get_rule_or_404(db, rule_id)

    # Simplified test: count how many logs would match
    matches = 0
    for log in sample_logs:
        if rule.name.lower() in log.lower():
            matches += 1

    return {
        "rule_id": rule_id,
        "sample_count": len(sample_logs),
        "match_count": matches,
        "match_rate": matches / len(sample_logs) if sample_logs else 0,
    }


@router.post("/rules/validate", response_model=None)
async def validate_rule(
    rule_data: DetectionRuleCreate,
    current_user: CurrentUser = None,
):
    """Validate rule YAML without saving"""
    errors = []

    if not rule_data.name or len(rule_data.name) == 0:
        errors.append("Rule name is required")

    if not rule_data.title or len(rule_data.title) == 0:
        errors.append("Rule title is required")

    if rule_data.severity and rule_data.severity not in ["critical", "high", "medium", "low", "informational"]:
        errors.append("Invalid severity level")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
    }


# ============================================================================
# CORRELATION EVENT ENDPOINTS
# ============================================================================


@router.get("/correlations", response_model=list[CorrelationEventResponse])
async def list_correlations(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
):
    """List correlation events"""
    query = select(CorrelationEvent)

    if severity:
        query = query.where(CorrelationEvent.severity == severity)

    if status:
        query = query.where(CorrelationEvent.status == status)

    # Apply pagination
    query = query.order_by(CorrelationEvent.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    correlations = list(result.scalars().all())

    return [CorrelationEventResponse.model_validate(c) for c in correlations]


@router.get("/correlations/{correlation_id}", response_model=CorrelationEventResponse)
async def get_correlation(
    correlation_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a correlation event by ID"""
    correlation = await get_correlation_or_404(db, correlation_id)
    return CorrelationEventResponse.model_validate(correlation)


@router.put("/correlations/{correlation_id}/status", response_model=CorrelationEventResponse)
async def update_correlation_status(
    correlation_id: str,
    status_update: dict,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update correlation event status"""
    correlation = await get_correlation_or_404(db, correlation_id)

    if "status" in status_update:
        correlation.status = status_update["status"]

    await db.flush()
    await db.refresh(correlation)

    return CorrelationEventResponse.model_validate(correlation)


# ============================================================================
# DATA SOURCE ENDPOINTS
# ============================================================================


@router.get("/sources", response_model=list[DataSourceResponse])
async def list_sources(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List data sources"""
    query = select(SIEMDataSource).order_by(SIEMDataSource.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    sources = list(result.scalars().all())

    return [DataSourceResponse.model_validate(s) for s in sources]


@router.post("/sources", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    source_data: DataSourceCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new data source"""
    source = SIEMDataSource(
        name=source_data.name,
        description=source_data.description,
        source_type=source_data.source_type,
        connection_config=json.dumps(source_data.connection_config),
        parser_config=json.dumps(source_data.parser_config) if source_data.parser_config else None,
        enabled=source_data.enabled,
    )

    db.add(source)
    await db.flush()
    await db.refresh(source)

    return DataSourceResponse.model_validate(source)


@router.put("/sources/{source_id}", response_model=DataSourceResponse)
async def update_source(
    source_id: str,
    source_data: DataSourceCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a data source"""
    source = await get_source_or_404(db, source_id)

    source.name = source_data.name
    source.description = source_data.description
    source.source_type = source_data.source_type
    source.connection_config = json.dumps(source_data.connection_config)
    source.parser_config = json.dumps(source_data.parser_config) if source_data.parser_config else None
    source.enabled = source_data.enabled

    await db.flush()
    await db.refresh(source)

    return DataSourceResponse.model_validate(source)


@router.delete("/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a data source"""
    source = await get_source_or_404(db, source_id)
    await db.delete(source)
    await db.flush()
