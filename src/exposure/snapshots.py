"""Daily exposure posture snapshots (the stored time series behind the charts).

``capture_daily_snapshot`` aggregates the stored rows of one organisation with
COUNT / AVG queries (no row is loaded into Python) and upserts the row for the
current UTC day, so re-running it the same day refreshes that day's point.
``read_trend`` returns the stored points; a day without a snapshot is simply
absent from the series.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.exposure.models import (
    AssetVulnerability,
    ExposureAsset,
    ExposureDailySnapshot,
    ExposureVulnerability,
    RemediationTicket,
)
from src.exposure.scoring import OPEN_LINK_STATUSES, organization_risk

TREND_DAYS_MAX = 365


async def _count(db: AsyncSession, stmt: Any) -> int:
    return int((await db.execute(stmt)).scalar() or 0)


async def _compliance_score(db: AsyncSession, organization_id: str) -> Optional[float]:
    """Mean stored compliance score of the org's enabled frameworks, or None."""
    from src.compliance.models import ComplianceFramework

    avg = (
        await db.execute(
            select(func.avg(ComplianceFramework.compliance_score)).where(
                ComplianceFramework.organization_id == organization_id,
                ComplianceFramework.is_enabled == True,  # noqa: E712
                ComplianceFramework.compliance_score.is_not(None),
            ),
        )
    ).scalar()
    return round(float(avg), 1) if avg is not None else None


async def capture_daily_snapshot(
    db: AsyncSession, organization_id: str, now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Aggregate the org's exposure posture and upsert today's snapshot row."""
    now = now or datetime.now(timezone.utc)
    day = now.date().isoformat()
    day_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

    active = and_(ExposureAsset.organization_id == organization_id, ExposureAsset.is_active == True)  # noqa: E712
    total_assets = await _count(db, select(func.count(ExposureAsset.id)).where(active))
    internet = await _count(
        db, select(func.count(ExposureAsset.id)).where(active, ExposureAsset.is_internet_facing == True),  # noqa: E712
    )
    open_links = and_(
        AssetVulnerability.organization_id == organization_id,
        AssetVulnerability.status.in_(OPEN_LINK_STATUSES),
    )
    open_exposures = await _count(db, select(func.count(AssetVulnerability.id)).where(open_links))
    assets_with_open = await _count(
        db, select(func.count(func.distinct(AssetVulnerability.asset_id))).where(open_links),
    )
    by_severity = {
        (sev or "unknown"): int(n)
        for sev, n in (
            await db.execute(
                select(ExposureVulnerability.severity, func.count(AssetVulnerability.id))
                .join(ExposureVulnerability, AssetVulnerability.vulnerability_id == ExposureVulnerability.id)
                .where(open_links)
                .group_by(ExposureVulnerability.severity),
            )
        ).all()
    }
    new_exposures = await _count(
        db,
        select(func.count(AssetVulnerability.id)).where(
            AssetVulnerability.organization_id == organization_id, AssetVulnerability.created_at >= day_start,
        ),
    )
    remediated = await _count(
        db,
        select(func.count(AssetVulnerability.id)).where(
            AssetVulnerability.organization_id == organization_id,
            AssetVulnerability.remediated_at.is_not(None),
            AssetVulnerability.remediated_at >= day_start,
        ),
    )
    overdue = await _count(
        db,
        select(func.count(RemediationTicket.id)).where(
            RemediationTicket.organization_id == organization_id,
            RemediationTicket.due_date < now,
            RemediationTicket.status.notin_(["closed", "verification"]),
        ),
    )
    values = {
        "total_assets": total_assets,
        "internet_facing_assets": internet,
        "assets_with_open_exposures": assets_with_open,
        "open_exposures": open_exposures,
        "critical_open": by_severity.get("critical", 0),
        "high_open": by_severity.get("high", 0),
        "medium_open": by_severity.get("medium", 0),
        "low_open": by_severity.get("low", 0),
        "informational_open": by_severity.get("informational", 0),
        "new_exposures": new_exposures,
        "remediated_exposures": remediated,
        "overdue_tickets": overdue,
        "overall_risk_score": await organization_risk(db, organization_id),
        "compliance_score": await _compliance_score(db, organization_id),
        "captured_at": now,
    }
    row = (
        await db.execute(
            select(ExposureDailySnapshot).where(
                ExposureDailySnapshot.organization_id == organization_id,
                ExposureDailySnapshot.snapshot_date == day,
            ),
        )
    ).scalars().first()
    if row is None:
        row = ExposureDailySnapshot(organization_id=organization_id, snapshot_date=day, **values)
        db.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
    await db.flush()
    return {"organization_id": organization_id, "snapshot_date": day, **{k: v for k, v in values.items() if k != "captured_at"}}


def _point(row: ExposureDailySnapshot) -> dict[str, Any]:
    day = datetime.fromisoformat(row.snapshot_date)
    return {
        "date": day.strftime("%b %d"),
        "snapshot_date": row.snapshot_date,
        # ``exposures`` is the series the dashboard chart already plots:
        # open asset exposures on that day.
        "exposures": row.open_exposures,
        "open_exposures": row.open_exposures,
        "critical": row.critical_open,
        "high": row.high_open,
        "medium": row.medium_open,
        "low": row.low_open,
        "informational": row.informational_open,
        "new_exposures": row.new_exposures,
        "remediated_exposures": row.remediated_exposures,
        "total_assets": row.total_assets,
        "internet_facing_assets": row.internet_facing_assets,
        "overdue_tickets": row.overdue_tickets,
        "risk_score": row.overall_risk_score,
        "compliance": row.compliance_score,
    }


async def read_trend(db: AsyncSession, organization_id: str, days: int = 30) -> list[dict[str, Any]]:
    """Stored snapshot points for the last ``days`` days, oldest first."""
    days = max(1, min(int(days), TREND_DAYS_MAX))
    since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat()
    rows = (
        await db.execute(
            select(ExposureDailySnapshot)
            .where(
                ExposureDailySnapshot.organization_id == organization_id,
                ExposureDailySnapshot.snapshot_date >= since,
            )
            .order_by(ExposureDailySnapshot.snapshot_date.asc())
            .limit(TREND_DAYS_MAX),
        )
    ).scalars().all()
    return [_point(r) for r in rows]
