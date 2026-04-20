"""SIEM management endpoints"""

import json
import logging
import math
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Query, status
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
from src.services.automation import AutomationService
from src.core.utils import safe_json_loads

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


@router.post("/logs/ingest", response_model=None, status_code=status.HTTP_201_CREATED)
async def ingest_log(
    log_data: LogIngestRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Ingest a single log entry through the full SIEM pipeline.

    The log is automatically:
    1. Parsed (syslog, CEF, LEEF, JSON, Windows Event auto-detected)
    2. Normalized (severity, log type, network fields extracted)
    3. Evaluated against all enabled detection rules
    4. Correlated with related events
    5. Alerts created for rule matches
    """
    from src.siem.pipeline import process_log

    org_id = getattr(current_user, "organization_id", None)

    log_entry, alerts, correlations = await process_log(
        raw_log=log_data.raw_log,
        source_type=log_data.source_type,
        source_name=log_data.source_name or "unknown",
        source_ip=log_data.source_ip or "0.0.0.0",
        db=db,
        organization_id=org_id,
        tags=log_data.tags,
    )

    # Fire automation for any correlations created during ingestion
    if correlations:
        try:
            automation = AutomationService(db)
            for corr in correlations:
                corr_name = corr.get("name", "unknown") if isinstance(corr, dict) else getattr(corr, "name", "unknown")
                corr_severity = corr.get("severity", "medium") if isinstance(corr, dict) else getattr(corr, "severity", "medium")
                await automation.on_siem_rule_match(
                    rule_name=corr_name,
                    rule_severity=corr_severity,
                    matched_events=[],
                    organization_id=org_id,
                )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Automation failed for SIEM correlation: {e}")

    return {
        "id": log_entry.id,
        "log_type": log_entry.log_type,
        "severity": log_entry.severity,
        "source_type": log_entry.source_type,
        "message": log_entry.message,
        "parsed": log_entry.parsed_fields is not None,
        "normalized": log_entry.normalized_fields is not None,
        "alerts_generated": len(alerts),
        "correlations_triggered": len(correlations),
        "alerts": alerts,
        "correlations": correlations,
    }


@router.post("/logs/batch", response_model=None)
async def batch_ingest_logs(
    batch_data: LogBatchIngestRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Batch ingest multiple log entries through the full SIEM pipeline.

    Each log is parsed, normalized, and evaluated against detection rules.
    """
    from src.siem.pipeline import process_log

    org_id = getattr(current_user, "organization_id", None) or batch_data.organization_id

    processed = 0
    total_alerts = 0
    total_correlations = 0
    errors = []

    for log_data in batch_data.logs:
        try:
            log_entry, alerts, correlations = await process_log(
                raw_log=log_data.raw_log,
                source_type=log_data.source_type,
                source_name=log_data.source_name or "unknown",
                source_ip=log_data.source_ip or "0.0.0.0",
                db=db,
                organization_id=org_id,
                tags=log_data.tags if hasattr(log_data, "tags") else None,
            )
            processed += 1
            total_alerts += len(alerts)
            total_correlations += len(correlations)
        except Exception as e:
            errors.append({"raw_log": log_data.raw_log[:50], "error": str(e)})

    return {
        "success_count": processed,
        "error_count": len(errors),
        "alerts_generated": total_alerts,
        "correlations_triggered": total_correlations,
        "errors": errors,
    }


# Whitelist of LogEntry columns clients can sort or aggregate by. Anything
# outside this set is rejected so the search/aggregate endpoints can't be
# used to enumerate or order by arbitrary (potentially sensitive) columns.
_LOG_SEARCHABLE_FIELDS = {
    "timestamp", "received_at", "source_type", "source_name", "source_ip",
    "log_type", "severity", "source_address", "destination_address",
    "source_port", "destination_port", "protocol", "username", "hostname",
    "process_name", "action", "outcome", "created_at",
}


@router.post("/logs/search", response_model=LogSearchResponse)
async def search_logs(
    search_data: LogSearchRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Search logs with complex filtering."""
    import time as _time
    started = _time.monotonic()

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

    # Apply sorting — whitelist sortable columns to prevent arbitrary
    # ORDER BY injection via the request body.
    sort_by = search_data.sort_by if search_data.sort_by in _LOG_SEARCHABLE_FIELDS else "timestamp"
    sort_column = getattr(LogEntry, sort_by, LogEntry.timestamp)
    if search_data.sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((search_data.page - 1) * search_data.size).limit(search_data.size)

    result = await db.execute(query)
    log_entries = list(result.scalars().all())

    query_time_ms = int((_time.monotonic() - started) * 1000)

    return LogSearchResponse(
        items=[LogEntryResponse.model_validate(le) for le in log_entries],
        total=total,
        page=search_data.page,
        size=search_data.size,
        pages=math.ceil(total / search_data.size) if total > 0 else 0,
        query_time_ms=query_time_ms,
    )


@router.post("/logs/aggregate", response_model=None)
async def aggregate_logs(
    agg_data: AggregationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Run aggregation query on logs.

    The `field` parameter is whitelisted against
    `_LOG_SEARCHABLE_FIELDS` so clients can't GROUP BY arbitrary
    columns (would otherwise allow leaking JSON blob columns or hashes).
    """
    if agg_data.field not in _LOG_SEARCHABLE_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid aggregation field. Allowed fields: "
                + ", ".join(sorted(_LOG_SEARCHABLE_FIELDS))
            ),
        )

    field_column = getattr(LogEntry, agg_data.field)
    query = select(field_column, func.count(LogEntry.id))

    if agg_data.time_start:
        query = query.where(LogEntry.timestamp >= agg_data.time_start.isoformat())

    if agg_data.time_end:
        query = query.where(LogEntry.timestamp <= agg_data.time_end.isoformat())

    query = query.group_by(field_column).order_by(func.count(LogEntry.id).desc())

    if agg_data.top_n:
        query = query.limit(min(agg_data.top_n, 1000))

    result = await db.execute(query)
    rows = result.all()

    aggregations = {str(row[0]): row[1] for row in rows if row[0] is not None}

    return {
        "field": agg_data.field,
        "agg_type": agg_data.agg_type,
        "aggregations": aggregations,
    }


@router.get("/logs/stats", response_model=SIEMStatsResponse)
async def get_siem_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get SIEM statistics"""
    total_result = await db.execute(select(func.count(LogEntry.id)))
    total_logs = total_result.scalar() or 0

    # Filter logs_today by today's date
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    logs_today_result = await db.execute(
        select(func.count(LogEntry.id)).where(LogEntry.timestamp >= today_start.isoformat())
    )
    logs_today = logs_today_result.scalar() or 0

    # Events per second based on total logs over 24 hours
    events_per_second = total_logs / (24 * 3600) if total_logs > 0 else 0.0

    type_result = await db.execute(
        select(LogEntry.log_type, func.count(LogEntry.id))
        .group_by(LogEntry.log_type)
    )
    logs_by_type = [{"name": row[0] or "unknown", "value": row[1]} for row in type_result.all()]

    severity_result = await db.execute(
        select(LogEntry.severity, func.count(LogEntry.id))
        .group_by(LogEntry.severity)
    )
    logs_by_severity = [{"name": row[0] or "unknown", "value": row[1]} for row in severity_result.all()]

    source_result = await db.execute(
        select(LogEntry.source_name, func.count(LogEntry.id))
        .group_by(LogEntry.source_name)
    )
    logs_by_source = [{"name": row[0] or "unknown", "value": row[1]} for row in source_result.all()]

    rules_result = await db.execute(
        select(func.count(DetectionRule.id)).where(DetectionRule.enabled == True)
    )
    active_rules = rules_result.scalar() or 0

    matches_result = await db.execute(select(func.sum(DetectionRule.match_count)))
    rule_matches_today = matches_result.scalar() or 0

    # Alerts triggered in last 24 hours (correlation events with alert_generated=True)
    twenty_four_hours_ago = datetime.now(timezone.utc).replace(microsecond=0)
    twenty_four_hours_ago = twenty_four_hours_ago.replace(
        hour=twenty_four_hours_ago.hour,
    )
    alerts_result = await db.execute(
        select(func.count(CorrelationEvent.id)).where(
            CorrelationEvent.alert_generated == True
        )
    )
    alerts_triggered_24h = alerts_result.scalar() or 0

    # Active data sources count
    sources_result = await db.execute(
        select(func.count(SIEMDataSource.id)).where(SIEMDataSource.enabled == True)
    )
    active_data_sources = sources_result.scalar() or 0

    corr_result = await db.execute(select(func.count(CorrelationEvent.id)))
    active_correlations = corr_result.scalar() or 0

    # Recent detections - last 5 correlation events
    recent_corr_result = await db.execute(
        select(CorrelationEvent)
        .order_by(CorrelationEvent.created_at.desc())
        .limit(5)
    )
    recent_corr = list(recent_corr_result.scalars().all())
    recent_detections = [
        {
            "rule_name": c.name,
            "severity": c.severity,
            "timestamp": c.created_at.isoformat() if c.created_at else "",
            "status": c.status,
        }
        for c in recent_corr
    ]

    # Ingestion rate per hour
    ingestion_rate = logs_today / max(datetime.now(timezone.utc).hour, 1)

    return SIEMStatsResponse(
        total_logs=total_logs,
        logs_today=logs_today,
        events_per_second=round(events_per_second, 2),
        active_rules=active_rules,
        alerts_triggered_24h=alerts_triggered_24h,
        active_data_sources=active_data_sources,
        logs_by_type=logs_by_type,
        logs_by_severity=logs_by_severity,
        logs_by_source=logs_by_source,
        recent_detections=recent_detections,
        rule_matches_today=int(rule_matches_today) if rule_matches_today else 0,
        active_correlations=active_correlations,
        ingestion_rate_per_hour=round(ingestion_rate, 2),
    )


@router.get("/logs/{log_id}", response_model=LogEntryResponse)
async def get_log(
    log_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a log entry by ID"""
    log_entry = await get_log_or_404(db, log_id)
    return LogEntryResponse.model_validate(log_entry)


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

    # Reload rules in the engine
    from src.siem.engine_manager import reload_rules
    await reload_rules(db)

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

    from src.siem.engine_manager import reload_rules
    await reload_rules(db)

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

    from src.siem.engine_manager import reload_rules
    await reload_rules(db)


@router.post("/rules/{rule_id}/test", response_model=None)
async def test_rule(
    rule_id: str,
    test_data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Dry-run a detection rule against sample logs.

    Uses the real Sigma-style rule engine — same one that runs in prod
    on every ingested log — so the test result is identical to what
    would happen at runtime. Does NOT fire AutomationService (this is a
    dry-run; firing real alerts on synthetic test data was the previous
    behaviour and would create phantom incidents).

    Sample logs may be passed as either:
      * a list of strings (free-form text — wrapped as { "raw_log": str })
      * a list of dicts with parsed fields (recommended for testing
        field-aware Sigma rules)
    """
    from src.siem.rules.engine import RuleEngine
    from src.siem.engine_manager import _build_yaml_from_logic
    from src.core.utils import safe_json_loads

    rule = await get_rule_or_404(db, rule_id)
    sample_logs = test_data.get("sample_logs", []) or []

    # Build a one-rule engine instance loaded with this specific rule.
    # Prefer rule_yaml; fall back to detection_logic JSON (same path
    # used by load_rules_from_db at runtime).
    yaml_content = getattr(rule, "rule_yaml", None)
    if not yaml_content:
        detection_logic = getattr(rule, "detection_logic", None)
        if detection_logic:
            try:
                logic = (
                    json.loads(detection_logic)
                    if isinstance(detection_logic, str)
                    else detection_logic
                )
                yaml_content = _build_yaml_from_logic(rule, logic)
            except Exception:
                yaml_content = None

    if not yaml_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rule has no YAML or detection_logic to evaluate",
        )

    test_engine = RuleEngine()
    rule_instance = test_engine.load_rule_from_yaml(yaml_content)
    if not rule_instance:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rule YAML is invalid or unparseable",
        )
    test_engine.add_rule(rule_instance)

    matches: list[dict] = []
    for sample in sample_logs:
        # Normalize the sample into a log_fields dict
        if isinstance(sample, dict):
            log_fields = sample
        elif isinstance(sample, str):
            # Try to parse as JSON; otherwise treat as raw_log/message
            parsed = safe_json_loads(sample, None)
            log_fields = parsed if isinstance(parsed, dict) else {
                "raw_log": sample,
                "message": sample,
            }
        else:
            continue

        rule_matches = test_engine.evaluate_log(log_fields)
        if rule_matches:
            matches.append({
                "log": log_fields,
                "matched_rules": [
                    {"rule_id": m.rule_id, "title": m.rule_title, "severity": m.severity}
                    for m in rule_matches
                ],
            })

    return {
        "rule_id": rule_id,
        "rule_name": rule.name,
        "sample_count": len(sample_logs),
        "match_count": len(matches),
        "match_rate": len(matches) / len(sample_logs) if sample_logs else 0,
        "matches": matches[:50],  # Cap detail output to first 50 matches
        "dry_run": True,
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
    status_update: dict = Body(...),
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


# ============================================================================
# SAVED SEARCH ENDPOINTS
# ============================================================================


@router.get("/saved-searches", response_model=None)
async def list_saved_searches(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """List saved searches"""
    from src.siem.models import SavedSearch
    org_id = getattr(current_user, "organization_id", None)
    query = select(SavedSearch)
    if org_id:
        query = query.where(SavedSearch.organization_id == org_id)
    query = query.order_by(SavedSearch.created_at.desc())
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/saved-searches", response_model=None, status_code=status.HTTP_201_CREATED)
async def create_saved_search(
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a saved search"""
    import uuid
    from src.siem.models import SavedSearch
    search = SavedSearch(
        id=str(uuid.uuid4()),
        name=data.get("name", "Untitled Search"),
        description=data.get("description"),
        query=data.get("query", ""),
        filters=json.dumps(data.get("filters", {})),
        time_range=data.get("time_range"),
        is_alert=data.get("is_alert", False),
        alert_threshold=data.get("alert_threshold"),
        schedule_cron=data.get("schedule_cron"),
        organization_id=getattr(current_user, "organization_id", None),
        created_by=str(current_user.id),
    )
    db.add(search)
    await db.flush()
    await db.refresh(search)
    return search


@router.delete("/saved-searches/{search_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_search(
    search_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a saved search"""
    from src.siem.models import SavedSearch
    result = await db.execute(select(SavedSearch).where(SavedSearch.id == search_id))
    search = result.scalar_one_or_none()
    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")
    await db.delete(search)
    await db.flush()


@router.post("/saved-searches/{search_id}/run", response_model=None)
async def run_saved_search(
    search_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Execute a saved search and return results"""
    from src.siem.models import SavedSearch
    result = await db.execute(select(SavedSearch).where(SavedSearch.id == search_id))
    search = result.scalar_one_or_none()
    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Execute the search query
    query = select(LogEntry)
    if search.query:
        search_filter = f"%{search.query}%"
        query = query.where(
            (LogEntry.message.ilike(search_filter))
            | (LogEntry.raw_log.ilike(search_filter))
        )
    query = query.order_by(LogEntry.created_at.desc()).limit(100)
    result = await db.execute(query)
    logs = list(result.scalars().all())

    # Update last run
    search.last_run_at = datetime.now(timezone.utc).isoformat()
    search.last_result_count = len(logs)
    await db.flush()

    return {
        "search_id": search_id,
        "search_name": search.name,
        "result_count": len(logs),
        "results": [LogEntryResponse.model_validate(l) for l in logs],
    }


# ============================================================================
# RULE IMPORT/EXPORT ENDPOINTS
# ============================================================================


@router.post("/rules/import", response_model=None, status_code=status.HTTP_201_CREATED)
async def import_rule_yaml(
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Import a detection rule from Sigma YAML.

    Per the Sigma spec (https://github.com/SigmaHQ/sigma-specification):
      * ``title:`` is the human-readable rule name and is what we persist
        to ``detection_rules.name``.
      * ``id:`` is a stable UUID identifier for the rule across Sigma
        repos — we preserve it as a ``sigma_id:<uuid>`` tag so it's
        queryable without a schema change.

    Previously this handler wrote the Sigma ``id`` (a UUID) into
    ``name`` and used the title only for ``title``. That meant the UI
    rule list showed raw UUIDs as names.
    """
    import uuid
    import yaml
    from sqlalchemy.exc import IntegrityError

    yaml_content = data.get("yaml", "")
    if not yaml_content:
        raise HTTPException(status_code=400, detail="YAML content required")

    try:
        parsed = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=400,
            detail="Sigma YAML must be a mapping (object) at the top level",
        )

    # Required Sigma fields
    title = parsed.get("title")
    if not title or not isinstance(title, str) or not title.strip():
        raise HTTPException(
            status_code=400,
            detail="Sigma rule is missing required 'title' field",
        )
    title = title.strip()

    sigma_id = parsed.get("id")  # UUID identifier — NOT the name
    if sigma_id is not None and not isinstance(sigma_id, str):
        sigma_id = str(sigma_id)

    detection = parsed.get("detection", {}) or {}
    if not isinstance(detection, dict):
        detection = {}

    # Build tags: preserve author-supplied tags and add a stable sigma_id
    # tag so the original UUID is queryable even though it's not the
    # primary `name`.
    sigma_tags = parsed.get("tags") or []
    if not isinstance(sigma_tags, list):
        sigma_tags = [str(sigma_tags)]
    if sigma_id:
        sigma_tags = list(sigma_tags) + [f"sigma_id:{sigma_id}"]

    # Extract MITRE tactics/techniques from Sigma `tags` (attack.* prefixed)
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    for tag in sigma_tags:
        if not isinstance(tag, str):
            continue
        if tag.startswith("attack.t"):
            mitre_techniques.append(tag.replace("attack.", ""))
        elif tag.startswith("attack."):
            mitre_tactics.append(tag.replace("attack.", ""))

    logsource = parsed.get("logsource", {}) or {}
    log_types = []
    if isinstance(logsource, dict):
        for key in ("product", "service", "category"):
            v = logsource.get(key)
            if v:
                log_types.append(str(v))

    # If `name` collides (unique constraint) we append a short suffix
    # derived from the sigma id so the import still succeeds but the
    # user-facing title remains intact.
    primary_name = title
    if sigma_id:
        # leave primary_name == title; fall back only on conflict below
        pass

    rule = DetectionRule(
        id=str(uuid.uuid4()),
        name=primary_name,
        title=title,
        description=parsed.get("description", "") or "",
        author=parsed.get("author") or None,
        severity=parsed.get("level", "medium") or "medium",
        status="active" if parsed.get("status", "stable") != "deprecated" else "disabled",
        log_types=json.dumps(log_types) if log_types else None,
        detection_logic=json.dumps(detection),
        condition=detection.get("condition", "selection") if isinstance(detection, dict) else "selection",
        tags=json.dumps(sigma_tags) if sigma_tags else None,
        mitre_tactics=json.dumps(mitre_tactics) if mitre_tactics else None,
        mitre_techniques=json.dumps(mitre_techniques) if mitre_techniques else None,
        references=json.dumps(parsed.get("references", []) or []) if parsed.get("references") else None,
        rule_yaml=yaml_content,
        enabled=True,
    )
    db.add(rule)
    try:
        await db.flush()
    except IntegrityError:
        # Name collision on the unique index — fall back to title + short
        # sigma-id suffix (still title-based, never a bare UUID).
        await db.rollback()
        suffix = (sigma_id[:8] if sigma_id else uuid.uuid4().hex[:8])
        rule.name = f"{title} ({suffix})"
        db.add(rule)
        await db.flush()
    await db.refresh(rule)

    from src.siem.engine_manager import reload_rules
    await reload_rules(db)

    return {
        "id": rule.id,
        "name": rule.name,
        "title": rule.title,
        "sigma_id": sigma_id,
        "status": "imported",
    }


@router.get("/rules/{rule_id}/export", response_model=None)
async def export_rule_yaml(
    rule_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Export a detection rule as YAML"""
    rule = await get_rule_or_404(db, rule_id)

    if rule.rule_yaml:
        return {"yaml": rule.rule_yaml, "title": rule.title}

    # Build YAML from fields
    import yaml
    rule_dict = {
        "title": rule.title,
        "id": rule.name,
        "description": rule.description or "",
        "level": rule.severity,
        "status": "active" if rule.enabled else "disabled",
        "detection": safe_json_loads(rule.detection_logic, {}) if rule.detection_logic else {},
    }
    return {"yaml": yaml.dump(rule_dict, default_flow_style=False), "title": rule.title}


# ============================================================================
# MIRROR / BACKFILL ENDPOINT
# ============================================================================


@router.post("/logs/backfill", response_model=None)
async def backfill_log_entries(
    limit_per_source: int = Query(5000, ge=1, le=50000),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Copy existing Alert + AuditLog rows into ``log_entries``.

    Run once after deploy to populate the SIEM search surface with the
    platform's historical security events. Idempotent — rows already
    mirrored (tracked by source id in parsed_fields) are skipped. New
    Alert/AuditLog inserts after this point are mirrored automatically
    by the SQLAlchemy ``after_insert`` listeners registered at startup.
    """
    from src.siem.mirror import backfill_from_history

    result = await backfill_from_history(db, limit_per_source=limit_per_source)
    await db.commit()

    # Recompute current totals so the response confirms what the user sees
    total_result = await db.execute(select(func.count(LogEntry.id)))
    total_after = total_result.scalar() or 0

    return {
        "status": "ok",
        "alerts_mirrored": result["alerts_mirrored"],
        "audits_mirrored": result["audits_mirrored"],
        "log_entries_total_after": total_after,
    }


# ============================================================================
# SYSLOG COLLECTOR CONTROL ENDPOINTS
# ============================================================================

_collector_instance = None
_collector_task = None


async def _syslog_batch_handler(messages: list):
    """Process a batch of syslog messages through the SIEM pipeline."""
    from src.siem.pipeline import process_log
    from src.core.database import async_session_factory

    async with async_session_factory() as db:
        for msg in messages:
            try:
                raw_log = msg.get("raw", "") if isinstance(msg, dict) else str(msg)
                source_ip = msg.get("source_ip", "0.0.0.0") if isinstance(msg, dict) else "0.0.0.0"
                await process_log(
                    raw_log=raw_log,
                    source_type="syslog",
                    source_name="syslog-collector",
                    source_ip=source_ip,
                    db=db,
                )
            except Exception as e:
                logger.error(f"Syslog pipeline error: {e}")
        await db.commit()


@router.get("/collector/status", response_model=None)
async def get_collector_status(current_user: CurrentUser = None):
    """Get syslog collector status"""
    global _collector_instance
    if _collector_instance:
        health = _collector_instance.get_health()
        return {
            "running": _collector_instance._running,
            "listen_port": _collector_instance.udp_port,
            "protocol": "udp+tcp",
            "messages_received": health.get("messages_received", 0),
            "messages_processed": health.get("messages_processed", 0),
            "errors": health.get("errors", 0),
            "uptime_seconds": health.get("uptime_seconds", 0),
            "messages_per_second": health.get("messages_per_second", 0),
        }
    return {
        "running": False,
        "listen_port": 5514,
        "protocol": "udp+tcp",
        "messages_received": 0,
        "messages_processed": 0,
        "errors": 0,
        "uptime_seconds": 0,
        "messages_per_second": 0,
    }


@router.post("/collector/start", response_model=None)
async def start_collector(
    current_user: CurrentUser = None,
    port: int = 5514,
):
    """Start the syslog collector on specified port."""
    import asyncio
    global _collector_instance, _collector_task

    if _collector_instance and _collector_instance._running:
        return {"status": "already_running", "message": f"Collector already running on port {_collector_instance.udp_port}"}

    try:
        from src.siem.syslog_receiver import SyslogReceiver

        _collector_instance = SyslogReceiver(
            host="0.0.0.0",
            udp_port=port,
            tcp_port=port,
            batch_size=50,
            flush_interval=3,
            message_handler=_syslog_batch_handler,
        )

        _collector_task = asyncio.create_task(_collector_instance.start())

        return {
            "status": "started",
            "message": f"Syslog collector started on UDP+TCP port {port}",
            "port": port,
        }
    except Exception as e:
        logger.error(f"Failed to start collector: {e}")
        return {
            "status": "error",
            "message": f"Failed to start: {str(e)}",
        }


@router.post("/collector/stop", response_model=None)
async def stop_collector(current_user: CurrentUser = None):
    """Stop the syslog collector"""
    global _collector_instance, _collector_task

    if not _collector_instance or not _collector_instance._running:
        return {"status": "not_running", "message": "Collector is not running"}

    try:
        await _collector_instance.stop()
        if _collector_task:
            _collector_task.cancel()
            _collector_task = None

        stats = _collector_instance.stats.copy()
        _collector_instance = None

        return {
            "status": "stopped",
            "message": "Syslog collector stopped",
            "final_stats": {
                "messages_received": stats.get("messages_received", 0),
                "messages_processed": stats.get("messages_processed", 0),
                "errors": stats.get("errors", 0),
            },
        }
    except Exception as e:
        logger.error(f"Failed to stop collector: {e}")
        return {"status": "error", "message": f"Failed to stop: {str(e)}"}
