"""Metrics and Analytics API endpoints"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.models.alert import Alert
from src.models.incident import Incident
from src.models.ioc import IOC
from src.models.playbook import PlaybookExecution

router = APIRouter()


@router.get("/overview")
async def get_metrics_overview(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get overview metrics for the dashboard"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    # Total counts
    alerts_total = await db.scalar(select(func.count(Alert.id)))
    incidents_total = await db.scalar(select(func.count(Incident.id)))
    iocs_total = await db.scalar(select(func.count(IOC.id)))

    # Active counts
    alerts_active = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.status.in_(["new", "acknowledged", "in_progress"])
        )
    )
    incidents_active = await db.scalar(
        select(func.count(Incident.id)).where(
            Incident.status.in_(["open", "investigating", "containment"])
        )
    )

    # Period counts
    alerts_period = await db.scalar(
        select(func.count(Alert.id)).where(Alert.created_at >= start_date)
    )
    incidents_period = await db.scalar(
        select(func.count(Incident.id)).where(Incident.created_at >= start_date)
    )

    # Resolved counts
    alerts_resolved = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.status.in_(["resolved", "closed"]),
            Alert.created_at >= start_date,
        )
    )
    incidents_resolved = await db.scalar(
        select(func.count(Incident.id)).where(
            Incident.status == "closed",
            Incident.created_at >= start_date,
        )
    )

    return {
        "totals": {
            "alerts": alerts_total or 0,
            "incidents": incidents_total or 0,
            "iocs": iocs_total or 0,
        },
        "active": {
            "alerts": alerts_active or 0,
            "incidents": incidents_active or 0,
        },
        "period": {
            "days": days,
            "alerts_created": alerts_period or 0,
            "alerts_resolved": alerts_resolved or 0,
            "incidents_created": incidents_period or 0,
            "incidents_resolved": incidents_resolved or 0,
        },
    }


@router.get("/alerts/by-severity")
async def get_alerts_by_severity(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get alert counts grouped by severity"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.created_at >= start_date)
        .group_by(Alert.severity)
    )

    severity_counts = {row[0]: row[1] for row in result.all()}

    return {
        "period_days": days,
        "by_severity": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
    }


@router.get("/alerts/by-source")
async def get_alerts_by_source(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get alert counts grouped by source"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    result = await db.execute(
        select(Alert.source, func.count(Alert.id))
        .where(Alert.created_at >= start_date)
        .group_by(Alert.source)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )

    return {
        "period_days": days,
        "by_source": [{"source": row[0], "count": row[1]} for row in result.all()],
    }


@router.get("/alerts/by-status")
async def get_alerts_by_status(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get alert counts grouped by status"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    result = await db.execute(
        select(Alert.status, func.count(Alert.id))
        .where(Alert.created_at >= start_date)
        .group_by(Alert.status)
    )

    return {
        "period_days": days,
        "by_status": {row[0]: row[1] for row in result.all()},
    }


@router.get("/alerts/trend")
async def get_alerts_trend(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get daily alert trend"""
    start_date = datetime.utcnow() - timedelta(days=days)

    # Generate date range
    date_range = [
        (start_date + timedelta(days=i)).strftime("%Y-%m-%d")
        for i in range(days + 1)
    ]

    # Get alerts per day
    result = await db.execute(
        select(
            func.date(Alert.created_at).label("date"),
            func.count(Alert.id).label("count"),
        )
        .where(Alert.created_at >= start_date.isoformat())
        .group_by(func.date(Alert.created_at))
        .order_by(func.date(Alert.created_at))
    )

    daily_counts = {str(row[0]): row[1] for row in result.all()}

    trend = [
        {"date": date, "count": daily_counts.get(date, 0)}
        for date in date_range
    ]

    return {
        "period_days": days,
        "trend": trend,
    }


@router.get("/incidents/by-type")
async def get_incidents_by_type(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get incident counts grouped by type"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    result = await db.execute(
        select(Incident.incident_type, func.count(Incident.id))
        .where(Incident.created_at >= start_date)
        .group_by(Incident.incident_type)
        .order_by(func.count(Incident.id).desc())
    )

    return {
        "period_days": days,
        "by_type": [{"type": row[0], "count": row[1]} for row in result.all()],
    }


@router.get("/incidents/mttr")
async def get_mean_time_to_resolve(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get Mean Time To Resolve (MTTR) for incidents"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    # Get closed incidents with resolution time
    result = await db.execute(
        select(Incident)
        .where(
            Incident.status == "closed",
            Incident.created_at >= start_date,
            Incident.resolved_at.isnot(None),
        )
    )

    incidents = result.scalars().all()

    if not incidents:
        return {
            "period_days": days,
            "mttr_hours": None,
            "mttr_days": None,
            "incidents_analyzed": 0,
        }

    total_hours = 0
    count = 0

    for incident in incidents:
        try:
            created = datetime.fromisoformat(incident.created_at)
            resolved = datetime.fromisoformat(incident.resolved_at)
            duration = (resolved - created).total_seconds() / 3600
            total_hours += duration
            count += 1
        except (ValueError, TypeError):
            continue

    if count == 0:
        return {
            "period_days": days,
            "mttr_hours": None,
            "mttr_days": None,
            "incidents_analyzed": 0,
        }

    mttr_hours = total_hours / count

    return {
        "period_days": days,
        "mttr_hours": round(mttr_hours, 2),
        "mttr_days": round(mttr_hours / 24, 2),
        "incidents_analyzed": count,
    }


@router.get("/playbooks/executions")
async def get_playbook_execution_stats(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
):
    """Get playbook execution statistics"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    # Total executions
    total = await db.scalar(
        select(func.count(PlaybookExecution.id)).where(
            PlaybookExecution.created_at >= start_date
        )
    )

    # By status
    status_result = await db.execute(
        select(PlaybookExecution.status, func.count(PlaybookExecution.id))
        .where(PlaybookExecution.created_at >= start_date)
        .group_by(PlaybookExecution.status)
    )

    status_counts = {row[0]: row[1] for row in status_result.all()}

    # Success rate
    completed = status_counts.get("completed", 0)
    failed = status_counts.get("failed", 0)
    success_rate = (completed / (completed + failed) * 100) if (completed + failed) > 0 else 0

    return {
        "period_days": days,
        "total_executions": total or 0,
        "by_status": status_counts,
        "success_rate": round(success_rate, 2),
    }


@router.get("/iocs/by-type")
async def get_iocs_by_type(
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get IOC counts grouped by type"""
    result = await db.execute(
        select(IOC.ioc_type, func.count(IOC.id))
        .where(IOC.is_active == True)
        .group_by(IOC.ioc_type)
        .order_by(func.count(IOC.id).desc())
    )

    return {
        "by_type": [{"type": row[0], "count": row[1]} for row in result.all()],
    }


@router.get("/iocs/by-threat-level")
async def get_iocs_by_threat_level(
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get IOC counts grouped by threat level"""
    result = await db.execute(
        select(IOC.threat_level, func.count(IOC.id))
        .where(IOC.is_active == True)
        .group_by(IOC.threat_level)
    )

    return {
        "by_threat_level": {row[0]: row[1] for row in result.all()},
    }


@router.get("/top-attackers")
async def get_top_attackers(
    db: DatabaseSession,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=10, ge=1, le=100),
):
    """Get top attacking source IPs"""
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    result = await db.execute(
        select(Alert.source_ip, func.count(Alert.id))
        .where(
            Alert.created_at >= start_date,
            Alert.source_ip.isnot(None),
        )
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
    )

    return {
        "period_days": days,
        "top_attackers": [{"ip": row[0], "alert_count": row[1]} for row in result.all()],
    }
