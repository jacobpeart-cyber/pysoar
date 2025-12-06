"""Incident management endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession
from src.models.alert import Alert
from src.models.incident import Incident, IncidentStatus
from src.schemas.incident import (
    IncidentCreate,
    IncidentListResponse,
    IncidentResponse,
    IncidentStats,
    IncidentUpdate,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])


async def get_incident_or_404(db: AsyncSession, incident_id: str) -> Incident:
    """Get incident by ID or raise 404"""
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.alerts))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return incident


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    incident_status: Optional[str] = Query(None, alias="status"),
    incident_type: Optional[str] = None,
    assigned_to: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List incidents with filtering and pagination"""
    query = select(Incident).options(selectinload(Incident.alerts))

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (Incident.title.ilike(search_filter))
            | (Incident.description.ilike(search_filter))
        )

    if severity:
        query = query.where(Incident.severity == severity)

    if incident_status:
        query = query.where(Incident.status == incident_status)

    if incident_type:
        query = query.where(Incident.incident_type == incident_type)

    if assigned_to:
        query = query.where(Incident.assigned_to == assigned_to)

    # Get total count
    count_query = select(func.count()).select_from(
        select(Incident.id)
        .where(query.whereclause) if query.whereclause is not None else select(Incident.id)
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(Incident, sort_by, Incident.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    incidents = list(result.scalars().all())

    # Build response with alert count
    items = []
    for incident in incidents:
        response = IncidentResponse.model_validate(incident)
        response.alert_count = len(incident.alerts)
        items.append(response)

    return IncidentListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: IncidentCreate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Create a new incident"""
    incident = Incident(
        title=incident_data.title,
        description=incident_data.description,
        severity=incident_data.severity,
        incident_type=incident_data.incident_type,
        priority=incident_data.priority,
        impact=incident_data.impact,
        affected_systems=json.dumps(incident_data.affected_systems) if incident_data.affected_systems else None,
        affected_users=json.dumps(incident_data.affected_users) if incident_data.affected_users else None,
        tags=json.dumps(incident_data.tags) if incident_data.tags else None,
        mitre_tactics=json.dumps(incident_data.mitre_tactics) if incident_data.mitre_tactics else None,
        mitre_techniques=json.dumps(incident_data.mitre_techniques) if incident_data.mitre_techniques else None,
        status=IncidentStatus.OPEN.value,
        detected_at=datetime.now(timezone.utc).isoformat(),
    )

    db.add(incident)
    await db.flush()

    # Link alerts if provided
    if incident_data.alert_ids:
        for alert_id in incident_data.alert_ids:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                alert.incident_id = incident.id

    await db.flush()
    await db.refresh(incident)

    response = IncidentResponse.model_validate(incident)
    response.alert_count = len(incident_data.alert_ids) if incident_data.alert_ids else 0
    return response


@router.get("/stats", response_model=IncidentStats)
async def get_incident_stats(
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get incident statistics"""
    # Total count
    total_result = await db.execute(select(func.count(Incident.id)))
    total = total_result.scalar() or 0

    # By severity
    severity_result = await db.execute(
        select(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
    )
    by_severity = dict(severity_result.all())

    # By status
    status_result = await db.execute(
        select(Incident.status, func.count(Incident.id))
        .group_by(Incident.status)
    )
    by_status = dict(status_result.all())

    # By type
    type_result = await db.execute(
        select(Incident.incident_type, func.count(Incident.id))
        .group_by(Incident.incident_type)
    )
    by_type = dict(type_result.all())

    # Open count
    open_count = by_status.get(IncidentStatus.OPEN.value, 0)

    return IncidentStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_type=by_type,
        open_count=open_count,
        mttr_hours=None,  # Would require more complex calculation
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get an incident by ID"""
    incident = await get_incident_or_404(db, incident_id)
    response = IncidentResponse.model_validate(incident)
    response.alert_count = len(incident.alerts)
    return response


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    incident_data: IncidentUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Update an incident"""
    incident = await get_incident_or_404(db, incident_id)

    update_data = incident_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle JSON fields
    json_fields = ["affected_systems", "affected_users", "tags"]
    for field in json_fields:
        if field in update_data:
            update_data[field] = json.dumps(update_data[field])

    # Handle status transitions
    if update_data.get("status") == IncidentStatus.CONTAINMENT.value:
        update_data["contained_at"] = datetime.now(timezone.utc).isoformat()
    elif update_data.get("status") == IncidentStatus.CLOSED.value:
        update_data["resolved_at"] = datetime.now(timezone.utc).isoformat()

    for key, value in update_data.items():
        setattr(incident, key, value)

    await db.flush()
    await db.refresh(incident)

    response = IncidentResponse.model_validate(incident)
    response.alert_count = len(incident.alerts)
    return response


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Delete an incident"""
    incident = await get_incident_or_404(db, incident_id)

    # Unlink alerts
    for alert in incident.alerts:
        alert.incident_id = None

    await db.delete(incident)
    await db.flush()


@router.post("/{incident_id}/alerts/{alert_id}")
async def link_alert_to_incident(
    incident_id: str,
    alert_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Link an alert to an incident"""
    incident = await get_incident_or_404(db, incident_id)

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    alert.incident_id = incident.id
    await db.flush()

    return {"message": "Alert linked to incident"}


@router.delete("/{incident_id}/alerts/{alert_id}")
async def unlink_alert_from_incident(
    incident_id: str,
    alert_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Unlink an alert from an incident"""
    await get_incident_or_404(db, incident_id)

    result = await db.execute(
        select(Alert).where(
            (Alert.id == alert_id) & (Alert.incident_id == incident_id)
        )
    )
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found or not linked to this incident",
        )

    alert.incident_id = None
    await db.flush()

    return {"message": "Alert unlinked from incident"}
