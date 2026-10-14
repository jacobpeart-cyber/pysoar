"""Per-organisation run state of the ITDR background jobs.

The rows live in ``log_ingest_cursors`` (``src.ueba.models.LogIngestCursor``):
the auth-event analysis uses its cursor columns (consumer ``itdr_auth``);
the identity scan (``itdr_scan``) and each directory sync
(``itdr_sync:<integration id>``) only use the run columns (last run time,
status, error, summary), so the dashboard can show when each job last ran
instead of a made-up timestamp.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.ueba.models import LogIngestCursor
from src.ueba.siem_bridge import _cursor

SCAN = "itdr_scan"
AUTH = "itdr_auth"
SYNC_PREFIX = "itdr_sync:"


def sync_consumer(integration_id: str) -> str:
    return f"{SYNC_PREFIX}{integration_id}"


async def record_run(
    db: AsyncSession,
    org_id: str,
    consumer: str,
    *,
    status: str,
    summary: Optional[dict[str, Any]] = None,
    error: Optional[str] = None,
    rows: int = 0,
) -> None:
    """Upsert the run columns of ``consumer``'s row (flushes, does not commit)."""
    row = await _cursor(db, org_id, consumer)
    row.last_run_at = datetime.now(timezone.utc)
    row.last_run_status = status
    row.last_run_rows = rows
    row.rows_processed_total = int(row.rows_processed_total or 0) + rows
    row.last_error = error[:2000] if error else None
    row.last_run_summary = dict(summary or {})
    await db.flush()


async def run_statuses(db: AsyncSession, org_id: str) -> list[dict[str, Any]]:
    """Every ITDR job row of ``org_id`` (read-only)."""
    rows = (await db.execute(
        select(LogIngestCursor).where(
            LogIngestCursor.organization_id == org_id,
            LogIngestCursor.consumer.like("itdr%"),
        ).order_by(LogIngestCursor.consumer),
    )).scalars().all()
    return [
        {
            "job": r.consumer,
            "status": r.last_run_status or "never_run",
            "last_run_at": r.last_run_at,
            "last_run_rows": int(r.last_run_rows or 0),
            "rows_processed_total": int(r.rows_processed_total or 0),
            "last_error": r.last_error,
            "last_run_summary": dict(r.last_run_summary or {}),
        }
        for r in rows
    ]
