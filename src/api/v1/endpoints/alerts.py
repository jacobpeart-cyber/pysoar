"""Alert management endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.models.alert import Alert, AlertSeverity, AlertStatus
from src.schemas.alert import (
    AlertBulkAction,
    AlertCreate,
    AlertListResponse,
    AlertResponse,
    AlertStats,
    AlertUpdate,
)
from src.services.alert_correlation import process_new_alert
from src.services.websocket_manager import notify_new_alert, create_notification_callback

router = APIRouter(prefix="/alerts", tags=["Alerts"])


async def process_alert_correlation(alert_id: str):
    """Background task to process alert through correlation rules"""
    async with async_session_factory() as db:
        try:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                notify_callback = create_notification_callback("incidents")
                await process_new_alert(db, alert, notify_callback)
                await db.commit()
        except Exception:
            await db.rollback()


async def get_alert_or_404(db: AsyncSession, alert_id: str) -> Alert:
    """Get alert by ID or raise 404"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return alert


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    alert_status: Optional[str] = Query(None, alias="status"),
    source: Optional[str] = None,
    assigned_to: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List alerts with filtering and pagination"""
    query = select(Alert)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (Alert.title.ilike(search_filter))
            | (Alert.description.ilike(search_filter))
            | (Alert.source_ip.ilike(search_filter))
            | (Alert.hostname.ilike(search_filter))
        )

    if severity:
        query = query.where(Alert.severity == severity)

    if alert_status:
        query = query.where(Alert.status == alert_status)

    if source:
        query = query.where(Alert.source == source)

    if assigned_to:
        query = query.where(Alert.assigned_to == assigned_to)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(Alert, sort_by, Alert.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    alerts = list(result.scalars().all())

    return AlertListResponse(
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert_data: AlertCreate,
    current_user: CurrentUser,
    db: DatabaseSession,
    background_tasks: BackgroundTasks,
):
    """Create a new alert"""
    alert = Alert(
        title=alert_data.title,
        description=alert_data.description,
        severity=alert_data.severity,
        source=alert_data.source,
        alert_type=alert_data.alert_type,
        category=alert_data.category,
        tags=json.dumps(alert_data.tags) if alert_data.tags else None,
        priority=alert_data.priority,
        confidence=alert_data.confidence,
        source_id=alert_data.source_id,
        source_url=alert_data.source_url,
        raw_data=json.dumps(alert_data.raw_data) if alert_data.raw_data else None,
        source_ip=alert_data.source_ip,
        destination_ip=alert_data.destination_ip,
        hostname=alert_data.hostname,
        username=alert_data.username,
        file_hash=alert_data.file_hash,
        url=alert_data.url,
        domain=alert_data.domain,
        status=AlertStatus.NEW.value,
    )

    db.add(alert)
    await db.flush()
    await db.refresh(alert)

    response = AlertResponse.model_validate(alert)

    # Send WebSocket notification
    background_tasks.add_task(notify_new_alert, response.model_dump())

    # Process through correlation rules (may create incident)
    background_tasks.add_task(process_alert_correlation, alert.id)

    return response


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get alert statistics"""
    # Total count
    total_result = await db.execute(select(func.count(Alert.id)))
    total = total_result.scalar() or 0

    # By severity
    severity_result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )
    by_severity = dict(severity_result.all())

    # By status
    status_result = await db.execute(
        select(Alert.status, func.count(Alert.id))
        .group_by(Alert.status)
    )
    by_status = dict(status_result.all())

    # By source
    source_result = await db.execute(
        select(Alert.source, func.count(Alert.id))
        .group_by(Alert.source)
    )
    by_source = dict(source_result.all())

    # New today (simplified - in production use proper date filtering)
    new_today = by_status.get(AlertStatus.NEW.value, 0)

    return AlertStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_source=by_source,
        new_today=new_today,
        new_this_week=total,  # Simplified
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get an alert by ID"""
    alert = await get_alert_or_404(db, alert_id)
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    alert_data: AlertUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Update an alert"""
    alert = await get_alert_or_404(db, alert_id)

    update_data = alert_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle tags serialization
    if "tags" in update_data:
        update_data["tags"] = json.dumps(update_data["tags"])

    # Handle status change to resolved
    if update_data.get("status") == AlertStatus.RESOLVED.value:
        update_data["resolved_at"] = datetime.now(timezone.utc).isoformat()

    for key, value in update_data.items():
        setattr(alert, key, value)

    await db.flush()
    await db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Delete an alert"""
    alert = await get_alert_or_404(db, alert_id)
    await db.delete(alert)
    await db.flush()


@router.post("/bulk", response_model=dict)
async def bulk_action(
    action_data: AlertBulkAction,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Perform bulk action on alerts"""
    success_count = 0
    failures = []

    for alert_id in action_data.alert_ids:
        try:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()

            if not alert:
                failures.append({"id": alert_id, "error": "Not found"})
                continue

            if action_data.action == "acknowledge":
                alert.status = AlertStatus.ACKNOWLEDGED.value
            elif action_data.action == "close":
                alert.status = AlertStatus.CLOSED.value
            elif action_data.action == "assign":
                alert.assigned_to = action_data.value
            elif action_data.action == "resolve":
                alert.status = AlertStatus.RESOLVED.value
                alert.resolved_at = datetime.now(timezone.utc).isoformat()

            success_count += 1

        except Exception as e:
            failures.append({"id": alert_id, "error": str(e)})

    await db.flush()

    return {
        "success_count": success_count,
        "failure_count": len(failures),
        "failures": failures,
    }
