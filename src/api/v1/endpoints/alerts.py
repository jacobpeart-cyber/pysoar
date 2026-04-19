"""Alert management endpoints"""

import json
import math
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.models.alert import Alert, AlertSeverity, AlertStatus
from src.models.audit import AuditLog
from src.schemas.alert import (
    AlertBulkAction,
    AlertCreate,
    AlertListResponse,
    AlertResponse,
    AlertStats,
    AlertUpdate,
)
from src.services.alert_correlation import process_new_alert
from src.services.automation import AutomationService
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


async def get_alert_or_404(db: AsyncSession, alert_id: str, org_id: Optional[str] = None) -> Alert:
    """Get alert by ID or raise 404 (tenant-scoped)"""
    stmt = select(Alert).where(Alert.id == alert_id)
    if org_id is not None:
        stmt = stmt.where(Alert.organization_id == org_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return alert


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
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
    org_id = getattr(current_user, "organization_id", None)
    query = select(Alert).where(Alert.organization_id == org_id)

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

    # Apply sorting — whitelist sortable columns to prevent clients from
    # ordering by arbitrary (potentially sensitive) attributes via the query
    # string. Anything outside this set falls back to created_at DESC.
    _ALLOWED_ALERT_SORTS = {
        "created_at", "updated_at", "severity", "status", "source",
        "title", "assigned_to",
    }
    if sort_by not in _ALLOWED_ALERT_SORTS:
        sort_by = "created_at"
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
    request: Request = None,
):
    """Create a new alert"""
    alert = Alert(
        organization_id=getattr(current_user, "organization_id", None) if current_user else None,
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

    # Audit: one row per alert create
    try:
        db.add(AuditLog(
            user_id=str(current_user.id) if current_user else None,
            action="alert_create",
            resource_type="alert",
            resource_id=str(alert.id),
            description=f"Created alert: {alert.title}",
            ip_address=(request.client.host if request and request.client else None),
            user_agent=(request.headers.get("user-agent") if request else None),
            success=True,
        ))
        await db.flush()
    except Exception as _e:
        import logging as _logging
        _logging.getLogger(__name__).warning(f"Failed to write audit_log for alert_create {alert.id}: {_e}")

    response = AlertResponse.model_validate(alert)

    # Send WebSocket notification
    background_tasks.add_task(notify_new_alert, response.model_dump())

    # Run central automation service (includes correlation, incident creation, playbooks)
    try:
        org_id = getattr(current_user, "organization_id", None) if current_user else None
        automation = AutomationService(db)
        await automation.on_alert_created(
            alert,
            organization_id=org_id,
            created_by=str(current_user.id) if current_user else None,
        )
    except Exception as e:
        # Fall back to legacy correlation if automation service fails
        import logging
        logging.getLogger(__name__).error(f"AutomationService on_alert_created failed: {e}", exc_info=True)
        background_tasks.add_task(process_alert_correlation, alert.id)

    return response


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get alert statistics with real date-filtered counts (tenant-scoped)."""
    org_id = getattr(current_user, "organization_id", None)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)

    org_filter = Alert.organization_id == org_id

    # Total count
    total_result = await db.execute(
        select(func.count(Alert.id)).where(org_filter)
    )
    total = total_result.scalar() or 0

    # By severity
    severity_result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(org_filter)
        .group_by(Alert.severity)
    )
    by_severity = {k: v for k, v in severity_result.all() if k is not None}

    # By status
    status_result = await db.execute(
        select(Alert.status, func.count(Alert.id))
        .where(org_filter)
        .group_by(Alert.status)
    )
    by_status = {k: v for k, v in status_result.all() if k is not None}

    # By source
    source_result = await db.execute(
        select(Alert.source, func.count(Alert.id))
        .where(org_filter)
        .group_by(Alert.source)
    )
    by_source = {k: v for k, v in source_result.all() if k is not None}

    # Real "new today" and "new this week" counts
    today_result = await db.execute(
        select(func.count(Alert.id)).where(
            and_(org_filter, Alert.created_at >= today_start)
        )
    )
    new_today = today_result.scalar() or 0

    week_result = await db.execute(
        select(func.count(Alert.id)).where(
            and_(org_filter, Alert.created_at >= week_start)
        )
    )
    new_this_week = week_result.scalar() or 0

    today_iso_prefix = today_start.isoformat()
    resolved_result = await db.execute(
        select(func.count(Alert.id)).where(
            and_(
                org_filter,
                Alert.resolved_at.is_not(None),
                Alert.resolved_at >= today_iso_prefix,
            )
        )
    )
    resolved_today = resolved_result.scalar() or 0

    return AlertStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_source=by_source,
        new_today=new_today,
        new_this_week=new_this_week,
        resolved_today=resolved_today,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get an alert by ID"""
    alert = await get_alert_or_404(db, alert_id, getattr(current_user, "organization_id", None))
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    alert_data: AlertUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    request: Request = None,
):
    """Update an alert"""
    alert = await get_alert_or_404(db, alert_id, getattr(current_user, "organization_id", None))

    update_data = alert_data.model_dump(exclude_unset=True, exclude_none=True)

    # Capture a shallow snapshot of the fields we're about to change so the
    # audit row can record the before/after for forensic purposes. We don't
    # snapshot every column because alert rows can carry large raw_data JSON
    # and the audit log is supposed to be lightweight.
    pre_state = {k: getattr(alert, k, None) for k in update_data.keys()}

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

    # Audit: one row per alert update
    try:
        db.add(AuditLog(
            user_id=str(current_user.id) if current_user else None,
            action="alert_update",
            resource_type="alert",
            resource_id=str(alert.id),
            description=f"Updated alert fields: {sorted(list(update_data.keys()))}",
            old_value=json.dumps({k: (str(v) if v is not None else None) for k, v in pre_state.items()}, default=str),
            new_value=json.dumps({k: (str(v) if v is not None else None) for k, v in update_data.items()}, default=str),
            ip_address=(request.client.host if request and request.client else None),
            user_agent=(request.headers.get("user-agent") if request else None),
            success=True,
        ))
        await db.flush()
    except Exception as _e:
        import logging as _logging
        _logging.getLogger(__name__).warning(f"Failed to write audit_log for alert_update {alert.id}: {_e}")

    return AlertResponse.model_validate(alert)


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete an alert"""
    alert = await get_alert_or_404(db, alert_id, getattr(current_user, "organization_id", None))
    await db.delete(alert)
    await db.flush()


_VALID_BULK_ACTIONS = {"acknowledge", "close", "assign", "resolve", "delete", "in_progress"}


@router.post("/bulk", response_model=None)
async def bulk_action(
    action_data: AlertBulkAction,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    request: Request = None,
):
    """Perform bulk action on alerts.

    Supported actions: acknowledge, in_progress, resolve, close, assign, delete.
    `assign` requires `value` to be set to a user ID.
    """
    if action_data.action not in _VALID_BULK_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action. Supported: {sorted(_VALID_BULK_ACTIONS)}",
        )
    if action_data.action == "assign" and not action_data.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'assign' action requires a non-empty value (user ID).",
        )
    if not action_data.alert_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="alert_ids must contain at least one alert ID.",
        )
    if len(action_data.alert_ids) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A single bulk request may target at most 500 alerts.",
        )

    success_count = 0
    failures: list[dict] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    org_id = getattr(current_user, "organization_id", None)
    for alert_id in action_data.alert_ids:
        try:
            result = await db.execute(
                select(Alert).where(
                    and_(Alert.id == alert_id, Alert.organization_id == org_id)
                )
            )
            alert = result.scalar_one_or_none()

            if not alert:
                failures.append({"id": alert_id, "error": "Not found"})
                continue

            if action_data.action == "acknowledge":
                alert.status = AlertStatus.ACKNOWLEDGED.value
            elif action_data.action == "in_progress":
                alert.status = AlertStatus.IN_PROGRESS.value
            elif action_data.action == "close":
                alert.status = AlertStatus.CLOSED.value
                if not alert.resolved_at:
                    alert.resolved_at = now_iso
            elif action_data.action == "assign":
                alert.assigned_to = action_data.value
            elif action_data.action == "resolve":
                alert.status = AlertStatus.RESOLVED.value
                alert.resolved_at = now_iso
            elif action_data.action == "delete":
                await db.delete(alert)

            success_count += 1

        except Exception as e:
            failures.append({"id": alert_id, "error": str(e)})

    await db.flush()

    # Audit: one summary row per bulk action. Recording one row per
    # touched alert would blow up the audit_logs table on big bulk
    # ops (N up to 500), so we keep the fan-out small by writing one
    # row describing the action and the full ID list.
    try:
        db.add(AuditLog(
            user_id=str(current_user.id) if current_user else None,
            action=f"alert_bulk_{action_data.action}",
            resource_type="alert",
            resource_id=None,
            description=(
                f"Bulk {action_data.action} on {success_count}/{len(action_data.alert_ids)} alerts"
                + (f" (value={action_data.value})" if action_data.value else "")
            ),
            new_value=json.dumps({
                "action": action_data.action,
                "value": action_data.value,
                "alert_ids": action_data.alert_ids,
                "success_count": success_count,
                "failure_count": len(failures),
                "failures": failures,
            }, default=str),
            ip_address=(request.client.host if request and request.client else None),
            user_agent=(request.headers.get("user-agent") if request else None),
            success=(len(failures) == 0),
        ))
        await db.flush()
    except Exception as _e:
        import logging as _logging
        _logging.getLogger(__name__).warning(f"Failed to write audit_log for alert_bulk: {_e}")

    return {
        "success_count": success_count,
        "failure_count": len(failures),
        "failures": failures,
    }
