"""Log search service for querying the PostgreSQL log store."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import time

from sqlalchemy import and_, func, or_, select, text
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


class LogSearchService:
    """Service for searching and aggregating logs."""

    async def search(
        self, db: AsyncSession, query: SearchQuery
    ) -> SearchResult:
        """
        Search logs based on query parameters.

        Args:
            db: Async database session
            query: SearchQuery object with filter criteria

        Returns:
            SearchResult with matching logs and pagination info
        """
        start_time = time.time()

        # Build base select statement
        stmt = select(LogEntry)

        # Apply text search
        if query.query_text:
            text_filter = or_(
                LogEntry.message.ilike(f"%{query.query_text}%"),
                LogEntry.raw_log.ilike(f"%{query.query_text}%"),
            )
            stmt = stmt.where(text_filter)

        # Apply field filters
        for field_name, field_value in query.field_filters.items():
            if field_name == "parsed_data":
                # JSON field filtering
                for key, val in field_value.items():
                    stmt = stmt.where(
                        LogEntry.parsed_data[key].astext == str(val)
                    )
            else:
                # Standard field filtering
                if hasattr(LogEntry, field_name):
                    stmt = stmt.where(getattr(LogEntry, field_name) == field_value)

        # Apply time range filtering
        if query.time_start:
            stmt = stmt.where(LogEntry.timestamp >= query.time_start)
        if query.time_end:
            stmt = stmt.where(LogEntry.timestamp <= query.time_end)

        # Apply source types filter
        if query.source_types:
            stmt = stmt.where(LogEntry.source_type.in_(query.source_types))

        # Apply log types filter
        if query.log_types:
            stmt = stmt.where(LogEntry.log_type.in_(query.log_types))

        # Apply severities filter
        if query.severities:
            stmt = stmt.where(LogEntry.severity.in_(query.severities))

        # Apply source addresses filter
        if query.source_addresses:
            stmt = stmt.where(LogEntry.source_ip.in_(query.source_addresses))

        # Apply destination addresses filter
        if query.destination_addresses:
            stmt = stmt.where(
                LogEntry.destination_ip.in_(query.destination_addresses)
            )

        # Apply usernames filter
        if query.usernames:
            stmt = stmt.where(LogEntry.username.in_(query.usernames))

        # Apply hostnames filter
        if query.hostnames:
            stmt = stmt.where(LogEntry.hostname.in_(query.hostnames))

        # Apply tags filter
        if query.tags:
            tag_filter = or_(
                *[LogEntry.tags.contains([tag]) for tag in query.tags]
            )
            stmt = stmt.where(tag_filter)

        # Get total count
        count_stmt = select(func.count()).select_from(LogEntry)
        # Apply same filters to count statement
        if query.query_text:
            text_filter = or_(
                LogEntry.message.ilike(f"%{query.query_text}%"),
                LogEntry.raw_log.ilike(f"%{query.query_text}%"),
            )
            count_stmt = count_stmt.where(text_filter)

        for field_name, field_value in query.field_filters.items():
            if field_name == "parsed_data":
                for key, val in field_value.items():
                    count_stmt = count_stmt.where(
                        LogEntry.parsed_data[key].astext == str(val)
                    )
            else:
                if hasattr(LogEntry, field_name):
                    count_stmt = count_stmt.where(
                        getattr(LogEntry, field_name) == field_value
                    )

        if query.time_start:
            count_stmt = count_stmt.where(LogEntry.timestamp >= query.time_start)
        if query.time_end:
            count_stmt = count_stmt.where(LogEntry.timestamp <= query.time_end)

        if query.source_types:
            count_stmt = count_stmt.where(LogEntry.source_type.in_(query.source_types))
        if query.log_types:
            count_stmt = count_stmt.where(LogEntry.log_type.in_(query.log_types))
        if query.severities:
            count_stmt = count_stmt.where(LogEntry.severity.in_(query.severities))
        if query.source_addresses:
            count_stmt = count_stmt.where(LogEntry.source_ip.in_(query.source_addresses))
        if query.destination_addresses:
            count_stmt = count_stmt.where(
                LogEntry.destination_ip.in_(query.destination_addresses)
            )
        if query.usernames:
            count_stmt = count_stmt.where(LogEntry.username.in_(query.usernames))
        if query.hostnames:
            count_stmt = count_stmt.where(LogEntry.hostname.in_(query.hostnames))
        if query.tags:
            tag_filter = or_(
                *[LogEntry.tags.contains([tag]) for tag in query.tags]
            )
            count_stmt = count_stmt.where(tag_filter)

        total_result = await db.execute(count_stmt)
        total = total_result.scalar_one()

        # Apply sorting
        sort_col = getattr(LogEntry, query.sort_by, LogEntry.timestamp)
        if query.sort_order.lower() == "desc":
            stmt = stmt.order_by(sort_col.desc())
        else:
            stmt = stmt.order_by(sort_col.asc())

        # Apply pagination
        offset = (query.page - 1) * query.size
        stmt = stmt.offset(offset).limit(query.size)

        # Execute query
        result = await db.execute(stmt)
        logs = result.scalars().all()

        # Convert logs to dictionaries
        items = [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "source_type": log.source_type,
                "source_name": log.source_name,
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "log_type": log.log_type,
                "severity": log.severity,
                "message": log.message,
                "username": log.username,
                "hostname": log.hostname,
                "tags": log.tags,
                "parsed_data": log.parsed_data,
                "raw_log": log.raw_log,
                "organization_id": log.organization_id,
            }
            for log in logs
        ]

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
        """
        Aggregate logs by field with various aggregation types.

        Args:
            db: Async database session
            query: AggregationQuery object with aggregation parameters

        Returns:
            Dictionary with aggregation results
        """
        stmt = select(LogEntry)

        # Apply time range filtering
        if query.time_start:
            stmt = stmt.where(LogEntry.timestamp >= query.time_start)
        if query.time_end:
            stmt = stmt.where(LogEntry.timestamp <= query.time_end)

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

    async def _aggregate_terms(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Group by field values and count occurrences."""
        stmt = select(
            getattr(LogEntry, query.field), func.count().label("count")
        )

        if query.time_start:
            stmt = stmt.where(LogEntry.timestamp >= query.time_start)
        if query.time_end:
            stmt = stmt.where(LogEntry.timestamp <= query.time_end)

        stmt = stmt.group_by(getattr(LogEntry, query.field))
        stmt = stmt.order_by(func.count().desc())
        stmt = stmt.limit(query.top_n)

        result = await db.execute(stmt)
        rows = result.all()

        buckets = [
            {"key": row[0], "count": row[1]} for row in rows if row[0] is not None
        ]

        return {
            "field": query.field,
            "agg_type": "terms",
            "buckets": buckets,
            "total_buckets": len(buckets),
        }

    async def _aggregate_date_histogram(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Group by time interval and count occurrences."""
        interval_map = {
            "hour": "hour",
            "day": "day",
            "week": "week",
            "month": "month",
        }
        pg_interval = interval_map.get(query.interval, "day")

        stmt = select(
            func.date_trunc(pg_interval, LogEntry.timestamp).label("bucket"),
            func.count().label("count"),
        )

        if query.time_start:
            stmt = stmt.where(LogEntry.timestamp >= query.time_start)
        if query.time_end:
            stmt = stmt.where(LogEntry.timestamp <= query.time_end)

        stmt = stmt.group_by(func.date_trunc(pg_interval, LogEntry.timestamp))
        stmt = stmt.order_by(func.date_trunc(pg_interval, LogEntry.timestamp).asc())

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
        stmt = select(
            func.count().label("count"),
            func.min(getattr(LogEntry, query.field)).label("min"),
            func.max(getattr(LogEntry, query.field)).label("max"),
            func.avg(getattr(LogEntry, query.field)).label("avg"),
        )

        if query.time_start:
            stmt = stmt.where(LogEntry.timestamp >= query.time_start)
        if query.time_end:
            stmt = stmt.where(LogEntry.timestamp <= query.time_end)

        result = await db.execute(stmt)
        row = result.one()

        return {
            "field": query.field,
            "agg_type": "stats",
            "count": row[0],
            "min": row[1],
            "max": row[2],
            "avg": row[3],
        }

    async def _aggregate_count(
        self, db: AsyncSession, query: AggregationQuery
    ) -> dict:
        """Count total logs matching criteria."""
        stmt = select(func.count()).select_from(LogEntry)

        if query.time_start:
            stmt = stmt.where(LogEntry.timestamp >= query.time_start)
        if query.time_end:
            stmt = stmt.where(LogEntry.timestamp <= query.time_end)

        result = await db.execute(stmt)
        count = result.scalar_one()

        return {
            "field": query.field,
            "agg_type": "count",
            "count": count,
        }

    async def get_field_values(
        self,
        db: AsyncSession,
        field: str,
        prefix: str = "",
        limit: int = 20,
    ) -> list[str]:
        """
        Get autocomplete suggestions for field values.

        Args:
            db: Async database session
            field: Field name to get values for
            prefix: Optional prefix to filter values
            limit: Maximum number of values to return

        Returns:
            List of field values matching prefix
        """
        if not hasattr(LogEntry, field):
            return []

        stmt = select(getattr(LogEntry, field)).distinct()

        if prefix:
            stmt = stmt.where(
                getattr(LogEntry, field).ilike(f"{prefix}%")
            )

        stmt = stmt.order_by(getattr(LogEntry, field).asc())
        stmt = stmt.limit(limit)

        result = await db.execute(stmt)
        values = result.scalars().all()

        return [v for v in values if v is not None]
