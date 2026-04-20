"""Log search service for querying the PostgreSQL log store."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import time

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.siem.models import LogEntry


@dataclass
class SearchQuery:
    """Query parameters for log search."""

    query_text: Optional[str] = None
    field_filters: dict[str, Any] = field(default_factory=dict)
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
    page: int = 1
    size: int = 50
    sort_by: str = "timestamp"
    sort_order: str = "desc"


@dataclass
class SearchResult:
    """Result of a log search query."""

    items: list[dict]
    total: int
    page: int
    size: int
    pages: int
    query_time_ms: float
    aggregations: Optional[dict] = None


@dataclass
class AggregationQuery:
    """Query parameters for log aggregation."""

    field: str
    agg_type: str  # "count", "terms", "date_histogram", "stats"
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    interval: Optional[str] = None  # "hour", "day", "week" for date_histogram
    top_n: int = 10


def _apply_filters(stmt, query: "SearchQuery"):
    """Apply all filter predicates from a SearchQuery onto a SQLAlchemy statement."""
    if query.query_text:
        text_filter = or_(
            LogEntry.message.ilike(f"%{query.query_text}%"),
            LogEntry.raw_log.ilike(f"%{query.query_text}%"),
            LogEntry.hostname.ilike(f"%{query.query_text}%"),
        )
        stmt = stmt.where(text_filter)

    # Standard column field_filters — skip unknown/JSON fields to avoid
    # AttributeError from earlier bug that referenced a non-existent
    # `parsed_data` mapped column (the model stores parsed fields as a
    # JSON string in `parsed_fields`, not as a JSON-queryable column).
    for field_name, field_value in query.field_filters.items():
        if field_name in ("parsed_data", "parsed_fields", "normalized_fields"):
            # Substring match on the JSON blob — pragmatic and correct
            # for our Text-backed JSON storage.
            if isinstance(field_value, dict):
                for key, val in field_value.items():
                    stmt = stmt.where(
                        LogEntry.parsed_fields.ilike(f"%\"{key}\":%{val}%")
                    )
            elif field_value is not None:
                stmt = stmt.where(LogEntry.parsed_fields.ilike(f"%{field_value}%"))
            continue
        if hasattr(LogEntry, field_name):
            stmt = stmt.where(getattr(LogEntry, field_name) == field_value)

    # timestamp is stored as ISO-8601 String(50). Coerce datetimes to
    # isoformat so the lexicographic comparison matches our own writes.
    if query.time_start:
        ts = query.time_start.isoformat() if isinstance(query.time_start, datetime) else str(query.time_start)
        stmt = stmt.where(LogEntry.timestamp >= ts)
    if query.time_end:
        te = query.time_end.isoformat() if isinstance(query.time_end, datetime) else str(query.time_end)
        stmt = stmt.where(LogEntry.timestamp <= te)

    if query.source_types:
        stmt = stmt.where(LogEntry.source_type.in_(query.source_types))
    if query.log_types:
        stmt = stmt.where(LogEntry.log_type.in_(query.log_types))
    if query.severities:
        stmt = stmt.where(LogEntry.severity.in_(query.severities))
    if query.source_addresses:
        stmt = stmt.where(LogEntry.source_address.in_(query.source_addresses))
    # Column is `destination_address` (String), not `destination_ip` —
    # the earlier reference crashed on any request carrying this filter.
    if query.destination_addresses:
        stmt = stmt.where(LogEntry.destination_address.in_(query.destination_addresses))
    if query.usernames:
        stmt = stmt.where(LogEntry.username.in_(query.usernames))
    if query.hostnames:
        stmt = stmt.where(LogEntry.hostname.in_(query.hostnames))

    # tags is a JSON-serialized list stored in a Text column, not a
    # Postgres ARRAY. Use substring match as a pragmatic equivalent.
    if query.tags:
        stmt = stmt.where(
            or_(*[LogEntry.tags.ilike(f"%{tag}%") for tag in query.tags])
        )

    return stmt


def _row_to_dict(log: LogEntry) -> dict:
    """Serialize a LogEntry row to a dict for API responses."""
    parsed = None
    if log.parsed_fields:
        try:
            parsed = json.loads(log.parsed_fields)
        except (json.JSONDecodeError, TypeError):
            parsed = None

    tags = None
    if log.tags:
        try:
            tags = json.loads(log.tags)
            if not isinstance(tags, list):
                tags = None
        except (json.JSONDecodeError, TypeError):
            tags = None

    return {
        "id": log.id,
        "timestamp": log.timestamp,  # stored as ISO-8601 string
        "received_at": log.received_at,
        "source_type": log.source_type,
        "source_name": log.source_name,
        "source_ip": log.source_ip,
        "source_address": log.source_address,
        "destination_address": log.destination_address,
        "source_port": log.source_port,
        "destination_port": log.destination_port,
        "protocol": log.protocol,
        "log_type": log.log_type,
        "severity": log.severity,
        "message": log.message,
        "username": log.username,
        "hostname": log.hostname,
        "process_name": log.process_name,
        "action": log.action,
        "outcome": log.outcome,
        "tags": tags,
        "parsed_fields": parsed,
        "raw_log": log.raw_log,
        "organization_id": log.organization_id,
    }


class LogSearchService:
    """Service for searching and aggregating logs."""

    async def search(
        self, db: AsyncSession, query: SearchQuery
    ) -> SearchResult:
        """Search logs based on query parameters."""
        start_time = time.time()

        stmt = _apply_filters(select(LogEntry), query)
        count_stmt = _apply_filters(select(func.count()).select_from(LogEntry), query)

        total_result = await db.execute(count_stmt)
        total = total_result.scalar_one()

        sort_col = getattr(LogEntry, query.sort_by, None) or LogEntry.timestamp
        if query.sort_order.lower() == "desc":
            stmt = stmt.order_by(sort_col.desc())
        else:
            stmt = stmt.order_by(sort_col.asc())

        offset = (query.page - 1) * query.size
        stmt = stmt.offset(offset).limit(query.size)

        result = await db.execute(stmt)
        logs = result.scalars().all()

        items = [_row_to_dict(log) for log in logs]

        pages = (total + query.size - 1) // query.size
        query_time_ms = (time.time() - start_time) * 1000

        return SearchResult(
            items=items,
            total=total,
            page=query.page,
            size=query.size,
            pages=pages,
            query_time_ms=query_time_ms,
        )

    async def aggregate(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Aggregate logs by field with various aggregation types."""
        if query.agg_type == "terms":
            return await self._aggregate_terms(db, query)
        elif query.agg_type == "date_histogram":
            return await self._aggregate_date_histogram(db, query)
        elif query.agg_type == "stats":
            return await self._aggregate_stats(db, query)
        elif query.agg_type == "count":
            return await self._aggregate_count(db, query)
        else:
            raise ValueError(f"Unsupported aggregation type: {query.agg_type}")

    def _time_bounds(self, query: AggregationQuery):
        ts = query.time_start.isoformat() if isinstance(query.time_start, datetime) else query.time_start
        te = query.time_end.isoformat() if isinstance(query.time_end, datetime) else query.time_end
        return ts, te

    async def _aggregate_terms(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Group by field values and count occurrences."""
        col = getattr(LogEntry, query.field, None)
        if col is None:
            return {"field": query.field, "agg_type": "terms", "buckets": [], "total_buckets": 0}

        stmt = select(col, func.count().label("count"))
        ts, te = self._time_bounds(query)
        if ts:
            stmt = stmt.where(LogEntry.timestamp >= ts)
        if te:
            stmt = stmt.where(LogEntry.timestamp <= te)

        stmt = stmt.group_by(col).order_by(func.count().desc()).limit(query.top_n)

        result = await db.execute(stmt)
        rows = result.all()

        buckets = [{"key": row[0], "count": row[1]} for row in rows if row[0] is not None]
        return {
            "field": query.field,
            "agg_type": "terms",
            "buckets": buckets,
            "total_buckets": len(buckets),
        }

    async def _aggregate_date_histogram(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Group by time interval and count occurrences.

        `timestamp` is a String(50) ISO-8601 column, so we cast it to
        timestamptz before date_trunc to produce a real bucketed series.
        """
        interval_map = {"hour": "hour", "day": "day", "week": "week", "month": "month"}
        pg_interval = interval_map.get(query.interval, "day")

        # timestamp is stored as ISO-8601 string — parse it to timestamp
        # with the Postgres format pattern before date_trunc can bucket.
        ts_col = func.date_trunc(
            pg_interval,
            func.to_timestamp(LogEntry.timestamp, "YYYY-MM-DD\"T\"HH24:MI:SS"),
        )

        stmt = select(ts_col.label("bucket"), func.count().label("count"))
        ts, te = self._time_bounds(query)
        if ts:
            stmt = stmt.where(LogEntry.timestamp >= ts)
        if te:
            stmt = stmt.where(LogEntry.timestamp <= te)

        stmt = stmt.group_by(ts_col).order_by(ts_col.asc())
        result = await db.execute(stmt)
        rows = result.all()

        buckets = [
            {"bucket": row[0].isoformat() if row[0] else None, "count": row[1]}
            for row in rows
        ]
        return {
            "field": query.field,
            "agg_type": "date_histogram",
            "interval": query.interval,
            "buckets": buckets,
            "total_buckets": len(buckets),
        }

    async def _aggregate_stats(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Calculate stats (count, min, max, avg) for a numeric field."""
        col = getattr(LogEntry, query.field, None)
        if col is None:
            return {"field": query.field, "agg_type": "stats", "count": 0, "min": None, "max": None, "avg": None}

        stmt = select(
            func.count().label("count"),
            func.min(col).label("min"),
            func.max(col).label("max"),
            func.avg(col).label("avg"),
        )
        ts, te = self._time_bounds(query)
        if ts:
            stmt = stmt.where(LogEntry.timestamp >= ts)
        if te:
            stmt = stmt.where(LogEntry.timestamp <= te)

        result = await db.execute(stmt)
        row = result.one()
        return {
            "field": query.field,
            "agg_type": "stats",
            "count": row[0],
            "min": row[1],
            "max": row[2],
            "avg": float(row[3]) if row[3] is not None else None,
        }

    async def _aggregate_count(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Count total logs matching criteria."""
        stmt = select(func.count()).select_from(LogEntry)
        ts, te = self._time_bounds(query)
        if ts:
            stmt = stmt.where(LogEntry.timestamp >= ts)
        if te:
            stmt = stmt.where(LogEntry.timestamp <= te)

        result = await db.execute(stmt)
        count = result.scalar_one()
        return {"field": query.field, "agg_type": "count", "count": count}

    async def get_field_values(
        self,
        db: AsyncSession,
        field: str,
        prefix: str = "",
        limit: int = 20,
    ) -> list[str]:
        """Get autocomplete suggestions for field values."""
        col = getattr(LogEntry, field, None)
        if col is None:
            return []

        stmt = select(col).distinct()
        if prefix:
            stmt = stmt.where(col.ilike(f"{prefix}%"))
        stmt = stmt.order_by(col.asc()).limit(limit)

        result = await db.execute(stmt)
        values = result.scalars().all()
        return [v for v in values if v is not None]
