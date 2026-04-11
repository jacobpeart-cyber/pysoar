"""Incident management endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import and_, func, select
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


async def get_incident_or_404(db: AsyncSession, incident_id: str, org_id: Optional[str] = None) -> Incident:
    """Get incident by ID or raise 404 (tenant-scoped)"""
    stmt = (
        select(Incident)
        .options(selectinload(Incident.alerts))
        .where(Incident.id == incident_id)
    )
    if org_id is not None:
        stmt = stmt.where(Incident.organization_id == org_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return incident


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
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
    org_id = getattr(current_user, "organization_id", None)
    query = (
        select(Incident)
        .options(selectinload(Incident.alerts))
        .where(Incident.organization_id == org_id)
    )

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
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply sorting — whitelist sortable columns so clients can't order by
    # arbitrary attributes via the query string.
    _ALLOWED_INCIDENT_SORTS = {
        "created_at", "updated_at", "severity", "status", "incident_type",
        "title", "priority", "assigned_to",
    }
    if sort_by not in _ALLOWED_INCIDENT_SORTS:
        sort_by = "created_at"
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new incident and fire cross-module automation.

    Automation fires on every incident create (manual, agentic, or
    alert-correlation-driven): for critical/high severity it auto-creates
    a War Room and seeds it with 4 standard response action items
    (triage, containment, evidence, comms).
    """
    from src.services.automation import AutomationService

    incident = Incident(
        organization_id=getattr(current_user, "organization_id", None) if current_user else None,
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

    # Link alerts if provided (tenant-scoped so a tenant can't pull alerts
    # from another tenant into their own incident).
    linked_alerts = 0
    _org = getattr(current_user, "organization_id", None) if current_user else None
    if incident_data.alert_ids:
        for alert_id in incident_data.alert_ids:
            result = await db.execute(
                select(Alert).where(
                    and_(Alert.id == alert_id, Alert.organization_id == _org)
                )
            )
            alert = result.scalar_one_or_none()
            if alert:
                alert.incident_id = incident.id
                linked_alerts += 1

    await db.flush()
    await db.refresh(incident)

    # Fire cross-module automation (best-effort — never fail the request
    # if the war-room creation hits a snag)
    try:
        automation = AutomationService(db)
        await automation.on_incident_created(
            incident,
            organization_id=getattr(current_user, "organization_id", None) if current_user else None,
            created_by=str(current_user.id) if current_user else None,
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            f"AutomationService.on_incident_created failed for {incident.id}: {e}",
            exc_info=True,
        )

    response = IncidentResponse.model_validate(incident)
    response.alert_count = linked_alerts
    return response


@router.get("/stats", response_model=IncidentStats)
async def get_incident_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get incident statistics including a real MTTR calculation (tenant-scoped).

    MTTR = average(resolved_at - created_at) over all closed incidents
    that have a resolved_at timestamp.
    """
    org_id = getattr(current_user, "organization_id", None)
    org_filter = Incident.organization_id == org_id

    # Total count
    total_result = await db.execute(
        select(func.count(Incident.id)).where(org_filter)
    )
    total = total_result.scalar() or 0

    # By severity / status / type
    severity_result = await db.execute(
        select(Incident.severity, func.count(Incident.id))
        .where(org_filter)
        .group_by(Incident.severity)
    )
    by_severity = {k: v for k, v in severity_result.all() if k is not None}

    status_result = await db.execute(
        select(Incident.status, func.count(Incident.id))
        .where(org_filter)
        .group_by(Incident.status)
    )
    by_status = {k: v for k, v in status_result.all() if k is not None}

    type_result = await db.execute(
        select(Incident.incident_type, func.count(Incident.id))
        .where(org_filter)
        .group_by(Incident.incident_type)
    )
    by_type = {k: v for k, v in type_result.all() if k is not None}

    # Every non-closed status counts as "open" for dashboard purposes.
    _ACTIVE_STATUSES = {
        IncidentStatus.OPEN.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINMENT.value,
        IncidentStatus.ERADICATION.value,
        IncidentStatus.RECOVERY.value,
    }
    open_count = sum(v for k, v in by_status.items() if k in _ACTIVE_STATUSES)

    # Real MTTR: average resolution time across closed incidents (tenant-scoped)
    closed_result = await db.execute(
        select(Incident.created_at, Incident.resolved_at)
        .where(org_filter)
        .where(Incident.status == IncidentStatus.CLOSED.value)
        .where(Incident.resolved_at.is_not(None))
    )
    durations_seconds: list[float] = []
    for created_at, resolved_at_str in closed_result.all():
        if not created_at or not resolved_at_str:
            continue
        try:
            resolved_at = datetime.fromisoformat(str(resolved_at_str).replace("Z", "+00:00"))
            if resolved_at.tzinfo is None:
                resolved_at = resolved_at.replace(tzinfo=timezone.utc)
            created_utc = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
            delta_s = (resolved_at - created_utc).total_seconds()
            if delta_s > 0:
                durations_seconds.append(delta_s)
        except (ValueError, TypeError):
            continue

    mttr_hours = round(sum(durations_seconds) / len(durations_seconds) / 3600.0, 2) if durations_seconds else None

    return IncidentStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_type=by_type,
        open_count=open_count,
        mttr_hours=mttr_hours,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get an incident by ID"""
    incident = await get_incident_or_404(db, incident_id, getattr(current_user, "organization_id", None))
    response = IncidentResponse.model_validate(incident)
    response.alert_count = len(incident.alerts)
    return response


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    incident_data: IncidentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an incident"""
    incident = await get_incident_or_404(db, incident_id, getattr(current_user, "organization_id", None))

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete an incident and detach all FK references.

    Cleans up everything that points at this incident so the DELETE
    doesn't hit a foreign-key violation:
      - alerts.incident_id -> NULL
      - war_rooms.incident_id -> NULL (war rooms are NOT deleted — they
        retain their action items and chat history as standalone records
        operators can still review after incident closure)
      - case_notes, case_tasks, case_attachments, case_timeline cascade
        on the incident_id FK (already defined as CASCADE in the models)
    """
    from src.collaboration.models import WarRoom

    incident = await get_incident_or_404(db, incident_id, getattr(current_user, "organization_id", None))

    # Unlink alerts
    for alert in incident.alerts:
        alert.incident_id = None

    # Detach any war rooms pointing at this incident
    wr_result = await db.execute(select(WarRoom).where(WarRoom.incident_id == incident_id))
    for war_room in wr_result.scalars().all():
        war_room.incident_id = None

    await db.flush()
    await db.delete(incident)
    await db.flush()


@router.post("/{incident_id}/alerts/{alert_id}")
async def link_alert_to_incident(
    incident_id: str,
    alert_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Link an alert to an incident (both must belong to the same tenant)"""
    _org = getattr(current_user, "organization_id", None)
    incident = await get_incident_or_404(db, incident_id, _org)

    result = await db.execute(
        select(Alert).where(
            and_(Alert.id == alert_id, Alert.organization_id == _org)
        )
    )
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Unlink an alert from an incident (tenant-scoped)"""
    _org = getattr(current_user, "organization_id", None)
    await get_incident_or_404(db, incident_id, _org)

    result = await db.execute(
        select(Alert).where(
            and_(
                Alert.id == alert_id,
                Alert.incident_id == incident_id,
                Alert.organization_id == _org,
            )
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
