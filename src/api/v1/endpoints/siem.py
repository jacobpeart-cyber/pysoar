"""SIEM management endpoints.

Tenancy and roles (wave 1, docs/audit/2026-10-08/PLAN.md):

* Every tenant route takes ``OrganizationId``: queries filter on it, created
  rows (logs, rules, imports, data sources, saved searches) are stamped with
  it, and ids from another organisation answer 404.
* Detection rules with ``organization_id IS NULL`` are platform (built-in)
  rules (see ``src.siem.rule_seeder``): every organisation can read and
  export them and the engine evaluates them on every organisation's logs,
  but only a platform superuser may update or delete them (organisation
  users get 403 ``platform_rule_read_only``).
* Roles: viewers read (searches, aggregations, dry-run tests and saved
  search runs are reads even though they are POSTs); analysts perform
  operational writes (log ingestion, correlation triage, saved searches);
  admins change configuration (rules, imports, data sources, cloud poll of
  their organisation's integrations); platform superusers run host-level or
  every-tenant actions (syslog listener start/stop, history backfill, ingest
  queue status).
"""

import json
import math
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    PlatformSuperUser,
    require_role,
    resolve_organization_scope,
)
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.models.user import User, UserRole
from src.schemas.siem import (
    AggregationRequest,
    CorrelationEventResponse,
    DataSourceCreate,
    DataSourceUpdate,
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
    CorrelationStatus,
    DetectionRule,
    LogEntry,
    SIEMDataSource,
)
from src.models.alert import Alert
from src.services.automation import AutomationService
from src.core.utils import safe_json_loads
from src.siem.rule_validation import engine_yaml_for_rule
from src.siem.rule_validation import validate_rule as validate_rule_definition

logger = get_logger(__name__)

router = APIRouter(prefix="/siem", tags=["SIEM"])

#: Operational writes (ingest, correlation triage, saved searches).
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
#: Configuration writes (rules, imports, data sources, cloud polling).
SIEMAdminUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


def _error(status_code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": error, "detail": detail})


@router.get("/ingest/status")
async def ingest_status(
    current_user: PlatformSuperUser = None,
):
    """Return ingest queue status (host-wide queue; platform superusers only)."""
    from src.siem.ingest_queue import get_status

    try:
        return await get_status()
    except Exception as exc:  # noqa: BLE001 - any backend failure is reported, not hidden
        logger.warning("ingest status check failed", error=str(exc))
        raise _error(
            status.HTTP_503_SERVICE_UNAVAILABLE, "ingest_status_unavailable", str(exc)
        ) from exc


async def get_log_or_404(db: AsyncSession, log_id: str, org_id: str) -> LogEntry:
    """Get log entry by ID within the organisation or raise 404"""
    stmt = select(LogEntry).where(LogEntry.id == log_id, LogEntry.organization_id == org_id)
    result = await db.execute(stmt)
    log_entry = result.scalar_one_or_none()
    if not log_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log entry not found",
        )
    return log_entry


def _visible_rules(org_id: str):
    """Rules an organisation can see: its own plus platform (NULL-org) rules."""
    return or_(DetectionRule.organization_id == org_id, DetectionRule.organization_id.is_(None))


async def get_rule_or_404(db: AsyncSession, rule_id: str, org_id: str) -> DetectionRule:
    """Get a detection rule visible to the organisation (own or platform) or raise 404"""
    stmt = select(DetectionRule).where(DetectionRule.id == rule_id, _visible_rules(org_id))
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found",
        )
    return rule


def _invalid_rule(check) -> HTTPException:
    """422 carrying the validator's per-field errors."""
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={
            "error": "invalid_rule",
            "detail": "; ".join(check.messages()),
            "field_errors": list(check.field_errors),
            "warnings": list(check.warnings),
        },
    )


def _engine_loaded(rule: DetectionRule, organization_id: Optional[str]) -> bool:
    """Whether the organisation's engine (this process) now evaluates ``rule``."""
    from src.siem.engine_manager import get_rule_engine

    return get_rule_engine(organization_id).get_rule(str(rule.id)) is not None


def _ensure_rule_writable(rule: DetectionRule, current_user: User) -> None:
    """Platform (NULL-org) rules are read-only for organisation users."""
    if rule.organization_id is None and not current_user.is_superuser:
        raise _error(
            status.HTTP_403_FORBIDDEN,
            "platform_rule_read_only",
            "built-in platform rules apply to every organisation and cannot be changed by one",
        )


async def get_correlation_or_404(db: AsyncSession, correlation_id: str, org_id: str) -> CorrelationEvent:
    """Get correlation event by ID within the organisation or raise 404"""
    stmt = select(CorrelationEvent).where(
        CorrelationEvent.id == correlation_id, CorrelationEvent.organization_id == org_id
    )
    result = await db.execute(stmt)
    correlation = result.scalar_one_or_none()
    if not correlation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Correlation event not found",
        )
    return correlation


async def get_source_or_404(db: AsyncSession, source_id: str, org_id: str) -> SIEMDataSource:
    """Get data source by ID within the organisation or raise 404"""
    stmt = select(SIEMDataSource).where(
        SIEMDataSource.id == source_id, SIEMDataSource.organization_id == org_id
    )
    result = await db.execute(stmt)
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


async def _resolve_api_key(api_key: str, db: AsyncSession) -> Optional[str]:
    """Verify a ``pysoar_<token>`` API key header and return the owner_id.

    Looks up by the 8-char prefix, then bcrypt-verifies the rest against
    stored key_hash. Also checks is_active + not expired + permissions
    include a log-ingest scope. Returns ``None`` on any mismatch.
    """
    from src.core.security import verify_password
    from src.models.api_key import APIKey

    if not api_key or not api_key.startswith("pysoar_"):
        return None
    stripped = api_key[len("pysoar_"):]
    if len(stripped) < 9:
        return None
    prefix = stripped[:8]
    result = await db.execute(
        select(APIKey).where(APIKey.key_prefix == prefix, APIKey.is_active == True)
    )
    for candidate in result.scalars().all():
        try:
            if verify_password(stripped, candidate.key_hash):
                if candidate.is_expired:
                    return None
                # Permissions check: allow if the key carries
                # "siem:write" / "logs:write" / "*" / empty (full).
                perms: list[str] = []
                if candidate.permissions:
                    try:
                        perms = json.loads(candidate.permissions) or []
                    except (json.JSONDecodeError, TypeError):
                        perms = []
                if perms and not any(
                    p in ("*", "siem:write", "logs:write", "siem:*") for p in perms
                ):
                    return None
                # Bump usage_count + last_used_at so the APIKeys page
                # shows real traffic.
                candidate.usage_count = (candidate.usage_count or 0) + 1
                candidate.last_used_at = datetime.now(timezone.utc).isoformat()
                await db.flush()
                return candidate.owner_id
        except Exception:  # noqa: BLE001
            continue
    return None


@router.post("/logs/ingest/bulk", response_model=None, status_code=status.HTTP_202_ACCEPTED)
async def bulk_ingest_logs_apikey(
    request: "Request" = None,  # type: ignore[name-defined]
    db: DatabaseSession = None,
):
    """Authenticated bulk log ingestion for external forwarders.

    This is the endpoint Filebeat, Fluentd, Logstash, Vector, Syslog-NG,
    NXLog, or a custom shipper POSTs to. Authentication is via an API
    key in the ``X-API-Key`` header (created under Admin > API Keys,
    needs ``siem:write`` or ``logs:write`` permission).

    Body can be either:
      * ``application/x-ndjson`` — one JSON object per line
      * ``application/json`` — a JSON array of log objects
      * ``text/plain`` — raw lines, each treated as ``raw_log``

    Each record is dispatched through the full SIEM pipeline (parse +
    normalize + rule match + correlation + alert creation), so an
    external SIEM source immediately contributes to detection.

    Response is an aggregate summary so shippers can detect bad
    batches without parsing per-line responses.
    """
    from fastapi import Request
    from src.siem.pipeline import process_log

    if request is None:
        raise HTTPException(status_code=400, detail="missing request context")

    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header required",
        )
    owner_id = await _resolve_api_key(api_key, db)
    if owner_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key (or missing siem:write permission)",
        )

    # The key owner's organisation scopes every ingested row. A key whose
    # owner has no organisation cannot ingest (rows would be tenant-less).
    owner_res = await db.execute(select(User).where(User.id == owner_id))
    owner = owner_res.scalar_one_or_none()
    org_id = getattr(owner, "organization_id", None) if owner else None
    if not org_id:
        raise _error(
            status.HTTP_403_FORBIDDEN,
            "organization_required",
            "the API key's owner belongs to no organisation; ingested logs must belong to one",
        )

    raw_body = await request.body()
    if not raw_body:
        return {"success_count": 0, "error_count": 0, "alerts_generated": 0}

    content_type = (request.headers.get("content-type") or "").lower()
    records: list[dict] = []

    try:
        if "ndjson" in content_type or "jsonlines" in content_type or "x-json-lines" in content_type:
            for line in raw_body.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append(obj)
                except json.JSONDecodeError:
                    records.append({"raw_log": line})
        elif "json" in content_type:
            parsed = json.loads(raw_body.decode("utf-8", errors="replace") or "[]")
            if isinstance(parsed, list):
                for obj in parsed:
                    if isinstance(obj, dict):
                        records.append(obj)
            elif isinstance(parsed, dict):
                records.append(parsed)
        else:
            # text/plain — one raw syslog-style line per record
            for line in raw_body.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line:
                    records.append({"raw_log": line})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse body: {exc}",
        )

    # Cap batch size so a bad shipper can't DoS the pipeline. 1000 is
    # high enough for normal batching (most forwarders use 50-200).
    if len(records) > 1000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch too large ({len(records)} > 1000) — split the request",
        )

    source_ip = request.client.host if request.client else "0.0.0.0"

    processed = 0
    errors: list[dict] = []
    total_alerts = 0
    total_correlations = 0

    for rec in records:
        raw_log = rec.get("raw_log") or rec.get("message") or json.dumps(rec)
        src_type = rec.get("source_type") or "auto"
        src_name = rec.get("source_name") or rec.get("host") or "external-forwarder"
        src_ip = rec.get("source_ip") or source_ip
        tags = rec.get("tags") if isinstance(rec.get("tags"), list) else None
        rec_severity = rec.get("severity")  # authoritative for structured shippers
        try:
            _log_entry, alerts, correlations = await process_log(
                raw_log=raw_log,
                source_type=src_type,
                source_name=src_name,
                source_ip=src_ip,
                db=db,
                organization_id=org_id,
                tags=tags,
                severity=rec_severity,
            )
            processed += 1
            total_alerts += len(alerts)
            total_correlations += len(correlations)
        except Exception as exc:  # noqa: BLE001
            errors.append({"raw_log": str(raw_log)[:200], "error": str(exc)[:200]})

    return {
        "success_count": processed,
        "error_count": len(errors),
        "alerts_generated": total_alerts,
        "correlations_triggered": total_correlations,
        "errors": errors[:20],
    }


@router.post("/logs/ingest", response_model=None, status_code=status.HTTP_201_CREATED)
async def ingest_log(
    log_data: LogIngestRequest,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
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
        except Exception as e:  # noqa: BLE001 - the log is stored; automation failure is logged
            logger.error("Automation failed for SIEM correlation", error=str(e), organization_id=org_id)

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
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """
    Batch ingest multiple log entries through the full SIEM pipeline.

    Each log is parsed, normalized, and evaluated against detection rules.
    The body's ``organization_id`` selects the tenant only for platform
    superusers; anyone else must leave it empty or name their own
    organisation. Each log is written in its own SAVEPOINT, so one failing
    log is reported in ``errors`` without losing the others.
    """
    from src.siem.pipeline import process_log

    org_id = resolve_organization_scope(current_user, batch_data.organization_id)

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

#: Widest time window a log search / aggregation may cover. Without an
#: explicit ``time_start`` the query is bounded to logs ingested within it.
MAX_LOG_WINDOW = timedelta(days=90)
#: Deepest result a paginated search may reach (page * size).
MAX_LOG_RESULT_OFFSET = 10_000


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _log_window(
    time_start: Optional[datetime], time_end: Optional[datetime],
) -> tuple[datetime, datetime, bool]:
    """Effective (start, end, explicit) window of a log query; 422 when unbounded.

    ``explicit`` is True when the caller gave ``time_start`` (the event
    ``timestamp`` is filtered); otherwise the query is bounded to logs
    ingested (``created_at``) within ``MAX_LOG_WINDOW`` before ``end``.
    """
    end = _as_utc(time_end) or datetime.now(timezone.utc)
    start = _as_utc(time_start)
    if start is None:
        return end - MAX_LOG_WINDOW, end, False
    if start > end:
        raise _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid_window", "time_start is after time_end")
    if end - start > MAX_LOG_WINDOW:
        raise _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "window_too_large",
            f"a log query may cover at most {MAX_LOG_WINDOW.days} days",
        )
    return start, end, True


def _apply_log_filters(query, search_data: LogSearchRequest):
    """Apply the LogSearchRequest filters (except the time window) to ``query``."""
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
    for field_name, value in (search_data.field_filters or {}).items():
        if field_name not in _LOG_SEARCHABLE_FIELDS or field_name in ("timestamp", "created_at", "received_at"):
            raise _error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "invalid_field_filter",
                f"cannot filter on '{field_name}'; allowed: "
                + ", ".join(sorted(_LOG_SEARCHABLE_FIELDS - {"timestamp", "created_at", "received_at"})),
            )
        column = getattr(LogEntry, field_name)
        if isinstance(value, list):
            query = query.where(column.in_(value))
        elif value is None:
            query = query.where(column.is_(None))
        else:
            query = query.where(column == value)
    for tag in search_data.tags or []:
        # tags are stored as a JSON list of strings
        query = query.where(LogEntry.tags.like(f"%{json.dumps(str(tag))}%"))
    return query


@router.post("/logs/search", response_model=LogSearchResponse)
async def search_logs(
    search_data: LogSearchRequest,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Search the organisation's logs with complex filtering (a read; viewers allowed).

    The window is bounded (at most ``MAX_LOG_WINDOW``; without ``time_start``
    only logs ingested within it are searched) and pagination stops at
    ``MAX_LOG_RESULT_OFFSET`` results. ``field_filters`` (whitelisted
    columns, value or list of values) and ``tags`` are applied.
    """
    import time as _time
    started = _time.monotonic()

    if search_data.page * search_data.size > MAX_LOG_RESULT_OFFSET:
        raise _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "page_out_of_range",
            f"results beyond {MAX_LOG_RESULT_OFFSET} are not paginated; narrow the search",
        )
    window_start, window_end, explicit = _log_window(search_data.time_start, search_data.time_end)

    query = select(LogEntry).where(LogEntry.organization_id == org_id)
    if not explicit:
        query = query.where(LogEntry.created_at >= window_start)
    query = _apply_log_filters(query, search_data)

    if explicit:
        query = query.where(LogEntry.timestamp >= window_start.isoformat())
    if search_data.time_end:
        query = query.where(LogEntry.timestamp <= window_end.isoformat())

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
        window_start=window_start.isoformat(),
        window_end=window_end.isoformat(),
    )


@router.post("/logs/aggregate", response_model=None)
async def aggregate_logs(
    agg_data: AggregationRequest,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Run an aggregation over the organisation's logs (a read; viewers allowed).

    The `field` parameter is whitelisted against
    `_LOG_SEARCHABLE_FIELDS` so clients can't GROUP BY arbitrary
    columns (would otherwise allow leaking JSON blob columns or hashes).
    The window is bounded like ``/logs/search`` (at most ``MAX_LOG_WINDOW``;
    without ``time_start`` only logs ingested within it are counted) and at
    most ``top_n`` (<= 100) buckets are returned.
    """
    if agg_data.field not in _LOG_SEARCHABLE_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid aggregation field. Allowed fields: "
                + ", ".join(sorted(_LOG_SEARCHABLE_FIELDS))
            ),
        )

    window_start, window_end, explicit = _log_window(agg_data.time_start, agg_data.time_end)
    field_column = getattr(LogEntry, agg_data.field)
    query = select(field_column, func.count(LogEntry.id)).where(LogEntry.organization_id == org_id)

    if explicit:
        query = query.where(LogEntry.timestamp >= window_start.isoformat())
    else:
        query = query.where(LogEntry.created_at >= window_start)
    if agg_data.time_end:
        query = query.where(LogEntry.timestamp <= window_end.isoformat())

    total_in_window = (
        await db.execute(select(func.count()).select_from(query.group_by(field_column).subquery()))
    ).scalar() or 0

    query = query.group_by(field_column).order_by(func.count(LogEntry.id).desc())
    query = query.limit(agg_data.top_n)

    result = await db.execute(query)
    rows = result.all()

    aggregations = {str(row[0]): row[1] for row in rows if row[0] is not None}

    return {
        "field": agg_data.field,
        "agg_type": agg_data.agg_type,
        "aggregations": aggregations,
        "null_count": next((row[1] for row in rows if row[0] is None), 0),
        "buckets_total": total_in_window,
        "truncated": total_in_window > len(rows),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
    }


#: Window of the overview breakdowns, timeline and alert counts.
STATS_WINDOW = timedelta(hours=24)
#: Window over which events per second is measured.
EPS_WINDOW = timedelta(minutes=5)
#: A stage that saw data within this long is "receiving"; otherwise "idle".
INGEST_FRESH_WINDOW = timedelta(minutes=15)
#: Queue depth above which the queue stage reports "backlogged".
QUEUE_BACKLOG_THRESHOLD = 1000


def _queue_consumers() -> tuple[bool, int]:
    """(initialised, running consumer tasks) of this process's ingest queue."""
    from src.siem import ingest_queue

    tasks = getattr(ingest_queue, "_worker_tasks", None) or []
    return ingest_queue.is_initialized(), sum(1 for t in tasks if not t.done())


async def _pipeline_status(
    *,
    now: datetime,
    last_ingest_at: Optional[datetime],
    events_last_window: int,
    active_rules: int,
    rule_alerts_24h: int,
    correlations_24h: int,
) -> dict[str, Any]:
    """Per-stage pipeline state from stored rows and live collector / queue state.

    Nothing here is a constant: ``ingestion`` is derived from the
    organisation's newest stored log, ``collector`` from the syslog listener
    of the API process that answered, ``queue`` from the host ingest queue
    (depth is host-wide, not per organisation), ``detection`` from the
    enabled rules and the rule alerts they raised, ``correlation`` from
    stored correlation rows.
    """
    from src.siem.ingest_queue import get_status as queue_status

    if last_ingest_at is None:
        ingestion_state = "no_data"
    elif now - last_ingest_at <= INGEST_FRESH_WINDOW:
        ingestion_state = "receiving"
    else:
        ingestion_state = "idle"

    collector = _collector_instance
    collector_running = bool(collector is not None and getattr(collector, "_running", False))
    collector_stats = collector.get_stats() if collector is not None else {}

    initialised, consumers = _queue_consumers()
    try:
        q = await queue_status()
    except Exception as exc:  # noqa: BLE001 - reported as the queue's state, not hidden
        q = {"mode": "unknown", "queue_length": -1, "redis_connected": False, "error": str(exc)}
    depth = q.get("queue_length", 0)
    if q.get("mode") == "none" or not initialised:
        queue_state = "not_started"
    elif depth < 0 or (q.get("mode") == "redis" and not q.get("redis_connected")):
        queue_state = "unavailable"
    elif consumers == 0:
        queue_state = "no_consumers"
    elif depth > QUEUE_BACKLOG_THRESHOLD:
        queue_state = "backlogged"
    else:
        queue_state = "running"

    stages = {
        "ingestion": {
            "state": ingestion_state,
            "last_ingest_at": last_ingest_at.isoformat() if last_ingest_at else None,
            "events_last_5m": events_last_window,
        },
        "collector": {
            "state": "running" if collector_running else "stopped",
            "scope": "syslog listener of the API process that answered",
            "port": getattr(collector, "udp_port", None) if collector_running else None,
            "messages_received": int(collector_stats.get("messages_received", 0) or 0),
        },
        "queue": {
            "state": queue_state,
            "mode": q.get("mode"),
            "depth": depth,
            "consumers_running": consumers,
            "scope": "host-wide endpoint-event queue",
        },
        "detection": {
            "state": "active" if active_rules else "no_rules",
            "rules_enabled": active_rules,
            "rule_alerts_24h": rule_alerts_24h,
        },
        "correlation": {
            "state": "active" if ingestion_state == "receiving" else "idle",
            "correlations_24h": correlations_24h,
        },
    }
    if ingestion_state == "no_data":
        overall = "no_data"
    elif queue_state in ("unavailable", "backlogged", "no_consumers"):
        overall = "degraded"
    else:
        overall = ingestion_state
    return {"overall": overall, "checked_at": now.isoformat(), "stages": stages}


def _hour_buckets(now: datetime) -> list[tuple[datetime, datetime]]:
    """Hourly [start, end) buckets covering ``STATS_WINDOW``, oldest first."""
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    hours = int(STATS_WINDOW.total_seconds() // 3600)
    return [(end - timedelta(hours=h + 1), end - timedelta(hours=h)) for h in range(hours - 1, -1, -1)]


@router.get("/logs/stats", response_model=SIEMStatsResponse)
async def get_siem_stats(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """The organisation's SIEM overview, computed from stored rows.

    ``total_logs`` is all time; the breakdowns (``logs_by_*``), the hourly
    ``ingestion_timeline`` and the alert / correlation counts cover the last
    ``window_hours`` (24) by ingest time; ``events_per_second`` is measured
    over the last ``events_per_second_window_seconds`` (300).
    ``pipeline_status`` reports each stage from stored data and the live
    collector / queue state.
    """
    now = datetime.now(timezone.utc)
    since = now - STATS_WINDOW
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    own_logs = LogEntry.organization_id == org_id
    recent_logs = (own_logs, LogEntry.created_at >= since)

    total_logs = int((await db.execute(select(func.count(LogEntry.id)).where(own_logs))).scalar() or 0)
    logs_today = int(
        (await db.execute(select(func.count(LogEntry.id)).where(own_logs, LogEntry.created_at >= today_start))).scalar()
        or 0,
    )
    logs_24h = int((await db.execute(select(func.count(LogEntry.id)).where(*recent_logs))).scalar() or 0)
    events_last_window = int(
        (
            await db.execute(
                select(func.count(LogEntry.id)).where(own_logs, LogEntry.created_at >= now - EPS_WINDOW),
            )
        ).scalar()
        or 0,
    )
    events_per_second = events_last_window / EPS_WINDOW.total_seconds()
    last_ingest_at = _as_utc(
        (await db.execute(select(func.max(LogEntry.created_at)).where(own_logs))).scalar(),
    )

    async def _breakdown(column) -> list[dict[str, Any]]:
        rows = (
            await db.execute(
                select(column, func.count(LogEntry.id))
                .where(*recent_logs)
                .group_by(column)
                .order_by(func.count(LogEntry.id).desc())
                .limit(20),
            )
        ).all()
        return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]

    logs_by_type = await _breakdown(LogEntry.log_type)
    logs_by_severity = await _breakdown(LogEntry.severity)
    logs_by_source = await _breakdown(LogEntry.source_name)
    logs_by_source_type = await _breakdown(LogEntry.source_type)

    # Hourly ingest counts over the window: one scan, portable SUM(CASE).
    buckets = _hour_buckets(now)
    sums = (
        await db.execute(
            select(
                *[
                    func.sum(case((and_(LogEntry.created_at >= b0, LogEntry.created_at < b1), 1), else_=0))
                    for b0, b1 in buckets
                ],
            ).where(own_logs, LogEntry.created_at >= buckets[0][0]),
        )
    ).one()
    ingestion_timeline = [
        {"hour": b0.isoformat(), "count": int(sums[i] or 0)} for i, (b0, _b1) in enumerate(buckets)
    ]

    # Enabled rules that apply to this organisation (its own + platform).
    active_rules = int(
        (
            await db.execute(
                select(func.count(DetectionRule.id)).where(
                    DetectionRule.enabled == True,  # noqa: E712
                    _visible_rules(org_id),
                ),
            )
        ).scalar()
        or 0,
    )

    # Rule matches today and SIEM alerts in the last 24 hours, both counted
    # from this organisation's SIEM alerts. Rule match_count columns are not
    # used: platform rules are shared, so their counters are not per tenant.
    siem_alerts = (Alert.organization_id == org_id, Alert.source == "siem")
    rule_alerts = (*siem_alerts, Alert.alert_type == "detection_rule")
    rule_matches_today = int(
        (await db.execute(select(func.count(Alert.id)).where(*rule_alerts, Alert.created_at >= today_start))).scalar()
        or 0,
    )
    alerts_triggered_24h = int(
        (await db.execute(select(func.count(Alert.id)).where(*siem_alerts, Alert.created_at >= since))).scalar() or 0,
    )
    rule_alerts_24h = int(
        (await db.execute(select(func.count(Alert.id)).where(*rule_alerts, Alert.created_at >= since))).scalar() or 0,
    )

    # Top alerting rules: this organisation's rule alerts in the window,
    # grouped by the rule title the pipeline wrote ("Detection: <title>").
    top_rows = (
        await db.execute(
            select(Alert.title, func.count(Alert.id), func.max(Alert.severity))
            .where(*rule_alerts, Alert.created_at >= since)
            .group_by(Alert.title)
            .order_by(func.count(Alert.id).desc())
            .limit(10),
        )
    ).all()
    top_rules = [
        {
            "name": (row[0] or "").removeprefix("Detection: ") or "unknown",
            "count": row[1],
            "severity": row[2],
        }
        for row in top_rows
    ]

    own_sources = SIEMDataSource.organization_id == org_id
    active_data_sources = int(
        (
            await db.execute(
                select(func.count(SIEMDataSource.id)).where(
                    own_sources, SIEMDataSource.enabled == True,  # noqa: E712
                ),
            )
        ).scalar()
        or 0,
    )
    receiving_data_sources = int(
        (
            await db.execute(
                select(func.count(SIEMDataSource.id)).where(
                    own_sources,
                    SIEMDataSource.enabled == True,  # noqa: E712
                    SIEMDataSource.last_event_at >= (now - timedelta(hours=1)).isoformat(),
                ),
            )
        ).scalar()
        or 0,
    )

    own_correlations = CorrelationEvent.organization_id == org_id
    active_correlations = int(
        (
            await db.execute(
                select(func.count(CorrelationEvent.id)).where(
                    own_correlations,
                    CorrelationEvent.status.in_(
                        [CorrelationStatus.NEW.value, CorrelationStatus.INVESTIGATING.value],
                    ),
                ),
            )
        ).scalar()
        or 0,
    )
    correlations_24h = int(
        (
            await db.execute(
                select(func.count(CorrelationEvent.id)).where(
                    own_correlations, CorrelationEvent.created_at >= since,
                ),
            )
        ).scalar()
        or 0,
    )

    # Recent detections: the newest correlations and rule alerts, merged.
    recent_corr = (
        await db.execute(
            select(CorrelationEvent)
            .where(own_correlations)
            .order_by(CorrelationEvent.created_at.desc())
            .limit(5),
        )
    ).scalars().all()
    recent_alerts = (
        await db.execute(select(Alert).where(*rule_alerts).order_by(Alert.created_at.desc()).limit(5))
    ).scalars().all()
    recent = [
        {
            "id": c.id,
            "kind": "correlation",
            "rule_name": c.name,
            "severity": c.severity,
            "timestamp": _as_utc(c.created_at).isoformat() if c.created_at else "",
            "status": c.status,
        }
        for c in recent_corr
    ] + [
        {
            "id": a.id,
            "kind": "rule_alert",
            "rule_name": (a.title or "").removeprefix("Detection: "),
            "severity": a.severity,
            "timestamp": _as_utc(a.created_at).isoformat() if a.created_at else "",
            "status": a.status,
        }
        for a in recent_alerts
    ]
    recent_detections = sorted(recent, key=lambda d: d["timestamp"], reverse=True)[:5]

    pipeline_status = await _pipeline_status(
        now=now,
        last_ingest_at=last_ingest_at,
        events_last_window=events_last_window,
        active_rules=active_rules,
        rule_alerts_24h=rule_alerts_24h,
        correlations_24h=correlations_24h,
    )

    return SIEMStatsResponse(
        total_logs=total_logs,
        logs_today=logs_today,
        events_per_second=round(events_per_second, 3),
        active_rules=active_rules,
        alerts_triggered_24h=alerts_triggered_24h,
        active_data_sources=active_data_sources,
        receiving_data_sources=receiving_data_sources,
        logs_by_type=logs_by_type,
        logs_by_severity=logs_by_severity,
        logs_by_source=logs_by_source,
        logs_by_source_type=logs_by_source_type,
        recent_detections=recent_detections,
        rule_matches_today=rule_matches_today,
        active_correlations=active_correlations,
        ingestion_rate_per_hour=round(logs_24h / (STATS_WINDOW.total_seconds() / 3600), 2),
        window_hours=int(STATS_WINDOW.total_seconds() // 3600),
        logs_24h=logs_24h,
        events_per_second_window_seconds=int(EPS_WINDOW.total_seconds()),
        ingestion_timeline=ingestion_timeline,
        top_rules=top_rules,
        correlations_24h=correlations_24h,
        last_ingest_at=last_ingest_at.isoformat() if last_ingest_at else None,
        pipeline_status=pipeline_status,
    )


@router.get("/logs/{log_id}", response_model=LogEntryResponse)
async def get_log(
    log_id: str,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get a log entry by ID"""
    log_entry = await get_log_or_404(db, log_id, org_id)
    return LogEntryResponse.model_validate(log_entry)


# ============================================================================
# DETECTION RULE ENDPOINTS
# ============================================================================


@router.get("/rules", response_model=DetectionRuleListResponse)
async def list_rules(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    enabled: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List the organisation's detection rules plus the platform (built-in) rules"""
    query = select(DetectionRule).where(_visible_rules(org_id))

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
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create a detection rule owned by the organisation.

    The definition is validated the way the engine loads it
    (``src.siem.rule_validation``): ``rule_yaml`` (Sigma-like) or
    ``detection_logic`` (field -> value conditions, optionally named
    selections combined by ``condition``) is required, and any problem is a
    422 ``invalid_rule`` with ``field_errors``. The stored logic is what the
    engine evaluates; the response's ``engine_loaded`` says whether this
    process's engine picked it up.
    """
    check = validate_rule_definition(
        name=rule_data.name,
        title=rule_data.title,
        severity=rule_data.severity,
        rule_yaml=rule_data.rule_yaml,
        detection_logic=rule_data.detection_logic,
        condition=rule_data.condition,
    )
    if not check.valid:
        raise _invalid_rule(check)

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
        organization_id=org_id,
    )

    try:
        async with db.begin_nested():
            db.add(rule)
            await db.flush()
    except IntegrityError as exc:
        # detection_rules.name is unique per organisation (migration 035).
        raise _error(
            status.HTTP_409_CONFLICT, "rule_name_conflict", "a detection rule with this name already exists"
        ) from exc
    await db.refresh(rule)

    # Reload this organisation's rules in the engine
    from src.siem.engine_manager import reload_rules
    await reload_rules(db, org_id)

    response = DetectionRuleResponse.model_validate(rule)
    response.engine_loaded = _engine_loaded(rule, org_id)
    response.validation_warnings = list(check.warnings)
    return response


@router.get("/rules/{rule_id}", response_model=DetectionRuleResponse)
async def get_rule(
    rule_id: str,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get a detection rule by ID"""
    rule = await get_rule_or_404(db, rule_id, org_id)
    return DetectionRuleResponse.model_validate(rule)


@router.put("/rules/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(
    rule_id: str,
    rule_data: DetectionRuleUpdate,
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update a detection rule (platform rules: platform superusers only)"""
    rule = await get_rule_or_404(db, rule_id, org_id)
    _ensure_rule_writable(rule, current_user)

    update_data = rule_data.model_dump(exclude_unset=True, exclude_none=True)

    # A change to the definition is validated against the merged rule the
    # engine will load (422 invalid_rule with field_errors otherwise).
    warnings: list[str] = []
    definition_keys = {"rule_yaml", "detection_logic", "condition", "severity"}
    if definition_keys & update_data.keys():
        detection_changed = bool({"rule_yaml", "detection_logic", "condition"} & update_data.keys())
        if detection_changed:
            stored_logic = safe_json_loads(rule.detection_logic, None) if rule.detection_logic else None
            check = validate_rule_definition(
                title=update_data.get("title", rule.title),
                severity=update_data.get("severity"),
                rule_yaml=update_data.get("rule_yaml", rule.rule_yaml),
                detection_logic=update_data.get("detection_logic", stored_logic),
                condition=update_data.get("condition", rule.condition),
                require_identity=False,
            )
        else:
            # severity only: the stored detection is not re-judged
            check = validate_rule_definition(
                severity=update_data.get("severity"), require_identity=False, require_detection=False,
            )
        if not check.valid:
            raise _invalid_rule(check)
        warnings = list(check.warnings)

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
    await reload_rules(db, rule.organization_id)

    response = DetectionRuleResponse.model_validate(rule)
    response.engine_loaded = _engine_loaded(rule, rule.organization_id) if rule.enabled else False
    response.validation_warnings = warnings
    return response


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Delete a detection rule (platform rules: platform superusers only)"""
    rule = await get_rule_or_404(db, rule_id, org_id)
    _ensure_rule_writable(rule, current_user)
    rule_org = rule.organization_id
    await db.delete(rule)
    await db.flush()

    from src.siem.engine_manager import reload_rules
    await reload_rules(db, rule_org)


@router.post("/rules/{rule_id}/test", response_model=None)
async def test_rule(
    rule_id: str,
    test_data: dict = Body(...),
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Dry-run a detection rule against sample logs (a read; viewers allowed).

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
    import yaml

    from src.siem.rules.engine import RuleEngine

    rule = await get_rule_or_404(db, rule_id, org_id)
    sample_logs = test_data.get("sample_logs", []) or []

    # Build a one-rule engine loaded with exactly the YAML the runtime
    # engine loads for this row (src.siem.rule_validation.engine_yaml_for_rule).
    try:
        yaml_content = engine_yaml_for_rule(rule)
    except (ValueError, TypeError, yaml.YAMLError) as exc:
        logger.warning("Stored rule definition could not be read", rule_id=rule.id, error=str(exc))
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
    """Validate a rule definition without saving (a read; viewers allowed).

    Parses ``rule_yaml`` (Sigma-like YAML) or ``detection_logic`` with the
    same checks Create Rule applies and the engine relies on. Returns
    ``valid``, ``errors`` (``"<field>: <message>"`` strings),
    ``field_errors`` (``[{field, message}]``), ``warnings`` and, when valid,
    ``detection`` (the block the engine will evaluate).
    """
    check = validate_rule_definition(
        name=rule_data.name,
        title=rule_data.title,
        severity=rule_data.severity,
        rule_yaml=rule_data.rule_yaml,
        detection_logic=rule_data.detection_logic,
        condition=rule_data.condition,
    )
    return check.to_dict()


# ============================================================================
# CORRELATION EVENT ENDPOINTS
# ============================================================================


@router.get("/correlations", response_model=list[CorrelationEventResponse])
async def list_correlations(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
):
    """List the organisation's correlation events"""
    query = select(CorrelationEvent).where(CorrelationEvent.organization_id == org_id)

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get a correlation event by ID"""
    correlation = await get_correlation_or_404(db, correlation_id, org_id)
    return CorrelationEventResponse.model_validate(correlation)


@router.put("/correlations/{correlation_id}/status", response_model=CorrelationEventResponse)
async def update_correlation_status(
    correlation_id: str,
    status_update: dict = Body(...),
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update correlation event status (triage; analysts and admins)"""
    correlation = await get_correlation_or_404(db, correlation_id, org_id)

    if "status" in status_update:
        allowed = {s.value for s in CorrelationStatus}
        new_status = status_update["status"]
        if new_status not in allowed:
            raise _error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "invalid_status",
                f"status must be one of {sorted(allowed)}",
            )
        correlation.status = new_status

    await db.flush()
    await db.refresh(correlation)

    return CorrelationEventResponse.model_validate(correlation)


# ============================================================================
# DATA SOURCE ENDPOINTS
# ============================================================================


@router.get("/sources", response_model=list[DataSourceResponse])
async def list_sources(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List the organisation's data sources"""
    query = (
        select(SIEMDataSource)
        .where(SIEMDataSource.organization_id == org_id)
        .order_by(SIEMDataSource.created_at.desc())
    )
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    sources = list(result.scalars().all())

    return [DataSourceResponse.model_validate(s) for s in sources]


@router.post("/sources", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    source_data: DataSourceCreate,
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create a new data source owned by the organisation"""
    source = SIEMDataSource(
        name=source_data.name,
        description=source_data.description,
        source_type=source_data.source_type,
        connection_config=json.dumps(source_data.connection_config),
        parser_config=json.dumps(source_data.parser_config) if source_data.parser_config else None,
        enabled=source_data.enabled,
        organization_id=org_id,
    )

    try:
        async with db.begin_nested():
            db.add(source)
            await db.flush()
    except IntegrityError as exc:
        # siem_data_sources.name is unique per organisation (migration 035).
        raise _error(
            status.HTTP_409_CONFLICT, "source_name_conflict", "a data source with this name already exists"
        ) from exc
    await db.refresh(source)

    return DataSourceResponse.model_validate(source)


@router.put("/sources/{source_id}", response_model=DataSourceResponse)
async def update_source(
    source_id: str,
    source_data: DataSourceUpdate,
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update a data source.

    Partial update: only fields present in the body change. The old full
    replace required ``name`` (so the enable toggle 422'd) and reset
    ``connection_config`` to {} whenever a client omitted it.
    """
    source = await get_source_or_404(db, source_id, org_id)

    changes = source_data.model_dump(exclude_unset=True)
    if changes.get("name"):
        source.name = changes["name"]
    if "description" in changes:
        source.description = changes["description"]
    if "source_type" in changes:
        source.source_type = changes["source_type"]
    if "connection_config" in changes:
        source.connection_config = json.dumps(changes["connection_config"] or {})
    if "parser_config" in changes:
        source.parser_config = json.dumps(changes["parser_config"]) if changes["parser_config"] else None
    if "enabled" in changes and changes["enabled"] is not None:
        source.enabled = changes["enabled"]

    await db.flush()
    await db.refresh(source)

    return DataSourceResponse.model_validate(source)


@router.delete("/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: str,
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Delete a data source"""
    source = await get_source_or_404(db, source_id, org_id)
    await db.delete(source)
    await db.flush()


# ============================================================================
# SAVED SEARCH ENDPOINTS
# ============================================================================


@router.get("/saved-searches", response_model=None)
async def list_saved_searches(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """List the organisation's saved searches"""
    from src.siem.models import SavedSearch
    query = select(SavedSearch).where(SavedSearch.organization_id == org_id)
    query = query.order_by(SavedSearch.created_at.desc())
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/saved-searches", response_model=None, status_code=status.HTTP_201_CREATED)
async def create_saved_search(
    data: dict = Body(...),
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
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
        organization_id=org_id,
        created_by=str(current_user.id),
    )
    db.add(search)
    await db.flush()
    await db.refresh(search)
    return search


@router.delete("/saved-searches/{search_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_search(
    search_id: str,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Delete a saved search"""
    from src.siem.models import SavedSearch
    stmt = select(SavedSearch).where(
        SavedSearch.id == search_id, SavedSearch.organization_id == org_id
    )
    result = await db.execute(stmt)
    search = result.scalar_one_or_none()
    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")
    await db.delete(search)
    await db.flush()


@router.post("/saved-searches/{search_id}/run", response_model=None)
async def run_saved_search(
    search_id: str,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Execute a saved search and return results (a read; viewers allowed)"""
    from src.siem.models import SavedSearch
    stmt = select(SavedSearch).where(
        SavedSearch.id == search_id, SavedSearch.organization_id == org_id
    )
    result = await db.execute(stmt)
    search = result.scalar_one_or_none()
    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Execute the search query
    query = select(LogEntry).where(LogEntry.organization_id == org_id)
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
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
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

    # The engine must be able to evaluate what is imported: unsupported
    # Sigma constructs (aggregation pipes, "1 of" quantifiers, unknown
    # modifiers) are field errors, not an inert rule shown as enabled.
    check = validate_rule_definition(title=title, rule_yaml=yaml_content, require_identity=False)
    if not check.valid:
        raise _invalid_rule(check)

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
        organization_id=org_id,
    )
    try:
        async with db.begin_nested():
            db.add(rule)
            await db.flush()
    except IntegrityError:
        # Name collision on the unique index: fall back to title + short
        # sigma-id suffix (still title-based, never a bare UUID). Only the
        # SAVEPOINT is rolled back; the old full rollback discarded the
        # request's whole transaction.
        suffix = (sigma_id[:8] if sigma_id else uuid.uuid4().hex[:8])
        rule.name = f"{title} ({suffix})"
        try:
            async with db.begin_nested():
                db.add(rule)
                await db.flush()
        except IntegrityError as exc:
            raise _error(
                status.HTTP_409_CONFLICT, "rule_name_conflict", "a detection rule with this name already exists"
            ) from exc
    await db.refresh(rule)

    from src.siem.engine_manager import reload_rules
    await reload_rules(db, org_id)

    return {
        "id": rule.id,
        "name": rule.name,
        "title": rule.title,
        "sigma_id": sigma_id,
        "status": "imported",
        "engine_loaded": _engine_loaded(rule, org_id),
        "warnings": list(check.warnings),
    }


@router.get("/rules/{rule_id}/export", response_model=None)
async def export_rule_yaml(
    rule_id: str,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Export a detection rule (own or platform) as YAML"""
    rule = await get_rule_or_404(db, rule_id, org_id)

    if rule.rule_yaml:
        return {"yaml": rule.rule_yaml, "title": rule.title}

    # No stored YAML: export exactly what the engine evaluates for this row.
    import yaml

    try:
        engine_yaml = engine_yaml_for_rule(rule)
    except (ValueError, TypeError, yaml.YAMLError) as exc:
        raise _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "unreadable_rule", f"stored detection logic is unreadable: {exc}",
        ) from exc
    if engine_yaml is None:
        raise _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "no_detection_logic",
            "this rule has no rule_yaml or detection_logic to export",
        )
    return {"yaml": engine_yaml, "title": rule.title}


# ============================================================================
# CLOUD POLLER (manual trigger — Celery beat runs this on schedule)
# ============================================================================


@router.post("/cloud/poll-all", response_model=None)
async def trigger_cloud_poll(
    current_user: SIEMAdminUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """Manually poll the organisation's installed cloud-log integrations.

    Iterates the caller's organisation's AWS CloudTrail / Azure Activity /
    GCP Cloud Logging (and Splunk / Elastic / QRadar) integrations, fetches
    new events since each one's last poll, and dispatches them through the
    SIEM pipeline. Celery beat polls every tenant's integrations on a
    5-minute schedule; this endpoint is the on-demand 'fetch latest now'
    for one organisation and never touches another tenant's integrations.
    """
    from src.siem.cloud_poller import poll_all_cloud_integrations
    results = await poll_all_cloud_integrations(db, organization_id=org_id)
    return {
        "polled": len(results),
        "results": results,
    }


# ============================================================================
# MIRROR / BACKFILL ENDPOINT
# ============================================================================


@router.post("/logs/backfill", response_model=None)
async def backfill_log_entries(
    limit_per_source: int = Query(5000, ge=1, le=50000),
    current_user: PlatformSuperUser = None,
    db: DatabaseSession = None,
):
    """Copy existing Alert + AuditLog rows into ``log_entries``.

    Platform superusers only: the backfill reads every tenant's alerts and
    audit logs, so it is a platform-wide operation.

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


async def _resolve_default_siem_org() -> Optional[str]:
    """Resolve the org to stamp on syslog-received logs/alerts.

    The syslog receiver has no per-message authentication (a firewall
    shipping RFC 3164 can't present an API key), so logs would otherwise
    land NULL-org and the per-org autonomous investigator would never
    triage them. Resolution order:

      1. ``SIEM_DEFAULT_ORG_ID`` env (explicit operator choice).
      2. The sole superuser's organization (single-owner deployments —
         the common case for a self-hosted PySOAR).

    Returns None if neither resolves (multi-superuser with no env set);
    the operator must then set SIEM_DEFAULT_ORG_ID explicitly.
    """
    import os

    env_org = os.getenv("SIEM_DEFAULT_ORG_ID")
    if env_org:
        return env_org

    from src.models.user import User

    try:
        async with async_session_factory() as db:
            supers = (
                await db.execute(select(User).where(User.is_superuser == True))  # noqa: E712
            ).scalars().all()
            orgs = {u.organization_id for u in supers if u.organization_id}
            if len(orgs) == 1:
                return orgs.pop()
    except SQLAlchemyError as exc:
        logger.warning("Default SIEM org resolution failed", error=str(exc))
    return None


async def _syslog_batch_handler(messages: list):
    """Process a batch of syslog messages through the SIEM pipeline.

    SyslogReceiver._process_message hands batches of dicts shaped as
    ``{"raw_message", "source_ip", "hostname", "app_name", "message",
    "facility", "severity", "parsed_fields", ...}``. The previous
    handler read ``msg.get("raw", "")`` (wrong key) so every row
    landed with raw_log='' and message=''. Now reads the right keys
    and prefers the parsed hostname for source_name so IDs from
    routers/firewalls are usable.
    """
    from src.siem.pipeline import process_log

    org_id = await _resolve_default_siem_org()

    async with async_session_factory() as db:
        for msg in messages:
            try:
                if isinstance(msg, dict):
                    raw_log = (
                        msg.get("raw_message")
                        or msg.get("raw")
                        or msg.get("message")
                        or ""
                    )
                    source_ip = msg.get("source_ip") or "0.0.0.0"
                    hostname = msg.get("hostname") or msg.get("app_name") or source_ip
                    source_name = f"syslog/{hostname}"
                else:
                    raw_log = str(msg)
                    source_ip = "0.0.0.0"
                    source_name = "syslog-collector"
                if not raw_log:
                    continue
                await process_log(
                    raw_log=raw_log,
                    source_type="syslog",
                    source_name=source_name,
                    source_ip=source_ip,
                    db=db,
                    organization_id=org_id,
                )
            except Exception as e:  # noqa: BLE001 - one bad message must not drop the batch
                # process_log wraps each message in a SAVEPOINT, so the
                # failure is rolled back alone and the session stays usable.
                logger.error("Syslog pipeline error", error=str(e), organization_id=org_id)
        await db.commit()


@router.get("/collector/status", response_model=None)
async def get_collector_status(current_user: CurrentUser = None):
    """Syslog collector status of the API process that answered.

    ``status`` ("running" / "stopped") and ``port`` mirror ``running`` and
    ``listen_port`` (the dashboard reads the former). The listener lives in
    one API process; ``scope`` says so.
    """
    global _collector_instance
    if _collector_instance:
        # get_stats() carries the processed/errors/uptime/rate counters;
        # get_health() does not, so those always read 0 before.
        stats = _collector_instance.get_stats()
        running = bool(_collector_instance._running)
        return {
            "status": "running" if running else "stopped",
            "port": _collector_instance.udp_port,
            "scope": "api_process",
            "running": running,
            "listen_port": _collector_instance.udp_port,
            "protocol": "udp+tcp",
            "messages_received": stats.get("messages_received", 0),
            "messages_processed": stats.get("messages_processed", 0),
            "errors": stats.get("errors", 0),
            "uptime_seconds": stats.get("uptime_seconds", 0),
            "messages_per_second": stats.get("messages_per_second", 0),
        }
    return {
        "status": "stopped",
        "port": None,
        "scope": "api_process",
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
    current_user: PlatformSuperUser = None,
    port: int = 5514,
):
    """Start the syslog collector on specified port.

    The listener is host-global (one socket for the whole deployment, logs
    stamped with ``SIEM_DEFAULT_ORG_ID``), so only platform superusers may
    start or stop it.
    """
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
    except (OSError, RuntimeError, ValueError) as e:
        logger.error("Failed to start collector", error=str(e))
        raise _error(status.HTTP_500_INTERNAL_SERVER_ERROR, "collector_start_failed", str(e)) from e


@router.post("/collector/stop", response_model=None)
async def stop_collector(current_user: PlatformSuperUser = None):
    """Stop the syslog collector (host-global; platform superusers only)"""
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
    except (OSError, RuntimeError) as e:
        logger.error("Failed to stop collector", error=str(e))
        raise _error(status.HTTP_500_INTERNAL_SERVER_ERROR, "collector_stop_failed", str(e)) from e
