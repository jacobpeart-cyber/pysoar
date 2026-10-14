"""
UEBA REST API Endpoints
FastAPI router for User & Entity Behavior Analytics operations.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.core.config import settings

from src.services.automation import AutomationService
from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    get_current_active_user,
    get_db,
    require_role,
)
from src.models.user import User, UserRole
from src.ueba.engine import PeerGroupAnalyzer, RiskScorer
from src.ueba import siem_bridge
from src.ueba.models import (
    EntityProfile,
    BehaviorBaseline,
    BehaviorEvent,
    UEBARiskAlert,
    PeerGroup,
)
from src.schemas.ueba import (
    EntityProfileResponse,
    EntityProfileCreate,
    EntityProfileUpdate,
    EntityRiskResponse,
    BehaviorTimelineResponse,
    PeerComparisonResponse,
    UEBARiskAlertResponse,
    UEBARiskAlertUpdate,
    BehaviorEventResponse,
    BehaviorEventCreate,
    BehaviorEventBatch,
    PeerGroupResponse,
    PeerGroupCreate,
    UEBADashboardStats,
    RiskHeatmapResponse,
    BatchIngestionResponse,
    BehaviorBaselineResponse,
    SiemBridgeStatus,
    EntityListFilter,
    AlertListFilter,
    EventListFilter,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/ueba", tags=["ueba"])

#: Operational writes (alert triage, escalation, watchlist, event ingest).
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
#: Configuration and whole-org recomputation (peer groups, baselines).
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


# ============================================================================
# Helper Functions
# ============================================================================


async def get_entity_or_404(db: AsyncSession, entity_id: str, organization_id: str) -> EntityProfile:
    """Get entity profile by ID or raise 404"""
    result = await db.execute(
        select(EntityProfile).where(
            and_(
                EntityProfile.id == entity_id,
                EntityProfile.organization_id == organization_id,
            )
        )
    )
    entity = result.scalar_one_or_none()
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found")
    return entity


async def get_alert_or_404(db: AsyncSession, alert_id: str, organization_id: str) -> UEBARiskAlert:
    """Get UEBA risk alert by ID or raise 404"""
    result = await db.execute(
        select(UEBARiskAlert).where(
            and_(
                UEBARiskAlert.id == alert_id,
                UEBARiskAlert.organization_id == organization_id,
            )
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


def _timeline_event(event: BehaviorEvent) -> dict:
    """One BehaviorEvent row in the BehaviorTimelineEvent shape."""
    data = event.event_data if isinstance(event.event_data, dict) else {}
    reasons = list(event.anomaly_reasons or [])
    description = data.get("description")
    if not description:
        description = ", ".join(str(r) for r in reasons) if reasons else event.event_type
    return {
        "id": event.id,
        "event_type": event.event_type,
        "timestamp": event.created_at,
        "created_at": event.created_at,
        "description": str(description or ""),
        "is_anomalous": bool(event.is_anomalous),
        "anomaly_reasons": reasons,
        "risk_contribution": event.risk_contribution or 0.0,
        "source_ip": event.source_ip,
        "destination": event.destination,
        "event_data": data,
    }


#: Preference when an entity belongs to several groups.
_PEER_GROUP_TYPE_ORDER = ("custom", "auto_clustered", "role", "department")


def _pick_peer_group(entity: EntityProfile, groups: list[PeerGroup]) -> Optional[PeerGroup]:
    """The peer group ``entity`` is a member of (its labelled group first)."""
    containing = [g for g in groups if entity.id in (g.members or [])]
    if not containing:
        return None
    if entity.peer_group:
        for g in containing:
            if entity.peer_group in (g.name, g.id):
                return g

    def _rank(g: PeerGroup) -> tuple[int, int]:
        try:
            type_rank = _PEER_GROUP_TYPE_ORDER.index(g.group_type)
        except ValueError:
            type_rank = len(_PEER_GROUP_TYPE_ORDER)
        return (type_rank, -(g.member_count or 0))

    return sorted(containing, key=_rank)[0]


# Event scoring + persist logic lives in src.ueba.ingest so the REST
# ingest endpoints and the `ueba.process_behavior_events` Celery task
# share one implementation and cannot drift.
from src.ueba.ingest import (  # noqa: E402
    ingest_behavior_event,
    score_event_anomaly as _score_event_anomaly,  # noqa: F401  (re-export for compat)
)


async def get_peer_group_or_404(db: AsyncSession, group_id: str, organization_id: str) -> PeerGroup:
    """Get peer group by ID or raise 404"""
    result = await db.execute(
        select(PeerGroup).where(
            and_(
                PeerGroup.id == group_id,
                PeerGroup.organization_id == organization_id,
            )
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail=f"Peer group {group_id} not found")
    return group


# ============================================================================
# Entity Profile Endpoints
# ============================================================================

@router.get(
    "/entities",
    response_model=list[EntityProfileResponse],
    summary="List entities",
    description="List user and entity profiles with filtering"
)
async def list_entities(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    entity_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    is_watched: Optional[bool] = Query(None),
    department: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list:
    """
    Retrieve list of entities with optional filtering.

    Query Parameters:
    - entity_type: Filter by type (user, host, service_account, application)
    - risk_level: Filter by risk level (critical, high, medium, low)
    - is_watched: Filter by watchlist status
    - department: Filter by department
    - search: Search by entity_id or display_name
    - limit: Number of results (default 100, max 1000)
    - offset: Pagination offset
    """
    logger.info(
        f"Listing entities: type={entity_type}, risk={risk_level}, "
        f"watched={is_watched}, limit={limit}, offset={offset}"
    )

    query = select(EntityProfile).where(
        EntityProfile.organization_id == org_id
    )

    if entity_type:
        query = query.where(EntityProfile.entity_type == entity_type)

    if risk_level:
        query = query.where(EntityProfile.risk_level == risk_level)

    if is_watched is not None:
        query = query.where(EntityProfile.is_watched == is_watched)

    if department:
        query = query.where(EntityProfile.department == department)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                EntityProfile.entity_id.ilike(search_filter),
                EntityProfile.display_name.ilike(search_filter),
            )
        )

    query = query.order_by(desc(EntityProfile.risk_score))
    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    entities = list(result.scalars().all())

    return entities


@router.get(
    "/entities/{entity_id}",
    response_model=EntityProfileResponse,
    summary="Get entity detail",
    description="Retrieve detailed profile for a specific entity"
)
async def get_entity(
    entity_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> EntityProfile:
    """
    Get detailed entity profile with risk information.

    Path Parameters:
    - entity_id: Unique entity identifier
    """
    logger.info(f"Getting entity profile: {entity_id}")

    entity = await get_entity_or_404(db, entity_id, org_id)
    return entity


@router.put(
    "/entities/{entity_id}/watch",
    response_model=EntityProfileResponse,
    summary="Add/remove from watchlist",
    description="Add entity to or remove from watchlist"
)
async def update_watchlist(
    entity_id: str,
    is_watched: bool,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    reason: Optional[str] = None,
) -> EntityProfile:
    """
    Update watchlist status for an entity.

    Path Parameters:
    - entity_id: Unique entity identifier

    Query Parameters:
    - is_watched: True to add to watchlist, False to remove
    - reason: Reason for watchlist status
    """
    logger.info(f"Updating watchlist for {entity_id}: watched={is_watched}")

    entity = await get_entity_or_404(db, entity_id, org_id)

    entity.is_watched = is_watched
    entity.watch_reason = reason if is_watched else None

    await db.flush()
    await db.refresh(entity)

    return entity


@router.get(
    "/entities/{entity_id}/timeline",
    response_model=BehaviorTimelineResponse,
    summary="Get behavior timeline",
    description="Retrieve behavior event timeline for entity"
)
async def get_entity_timeline(
    entity_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    days: int = Query(7, ge=1, le=365),
    anomalies_only: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
) -> dict:
    """
    Get behavior timeline for an entity.

    Path Parameters:
    - entity_id: Unique entity identifier

    Query Parameters:
    - days: Number of days to include (default 7)
    - anomalies_only: Only show anomalous events
    - limit: Maximum events to return
    """
    logger.info(f"Getting timeline for {entity_id}: days={days}, anomalies_only={anomalies_only}")

    entity = await get_entity_or_404(db, entity_id, org_id)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    query = select(BehaviorEvent).where(
        and_(
            BehaviorEvent.entity_profile_id == entity.id,
            BehaviorEvent.organization_id == org_id,
            BehaviorEvent.created_at >= cutoff,
        )
    )

    if anomalies_only:
        query = query.where(BehaviorEvent.is_anomalous == True)

    query = query.order_by(desc(BehaviorEvent.created_at)).limit(limit)

    result = await db.execute(query)
    events = list(result.scalars().all())

    # BehaviorEvent has no ``timestamp`` / ``description`` columns; returning
    # the ORM rows straight into BehaviorTimelineEvent was a 500 whenever the
    # entity had an event. Map them explicitly.
    timeline_events = [_timeline_event(ev) for ev in events]

    return {
        "entity_id": entity_id,
        "event_count": len(timeline_events),
        "anomaly_count": sum(1 for ev in events if ev.is_anomalous),
        "events": timeline_events,
        "total_events": len(timeline_events),
        "period_days": days,
        "anomalies_only": anomalies_only,
    }


@router.get(
    "/entities/{entity_id}/risk",
    response_model=EntityRiskResponse,
    summary="Get risk detail and trend",
    description="Retrieve risk score breakdown and trend for entity"
)
async def get_entity_risk(
    entity_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    days: int = Query(30, ge=1, le=365),
) -> dict:
    """
    Get detailed risk information for an entity.

    Path Parameters:
    - entity_id: Unique entity identifier

    Query Parameters:
    - days: Days of trend data to include
    """
    logger.info(f"Getting risk for {entity_id}: days={days}")

    entity = await get_entity_or_404(db, entity_id, org_id)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Alerts in period (severity + time feed the factor breakdown and trend)
    alert_rows = (
        await db.execute(
            select(UEBARiskAlert.severity, UEBARiskAlert.created_at).where(
                and_(
                    UEBARiskAlert.entity_profile_id == entity.id,
                    UEBARiskAlert.organization_id == org_id,
                    UEBARiskAlert.created_at >= cutoff,
                )
            )
        )
    ).all()
    alerts = [{"severity": sev, "created_at": created} for sev, created in alert_rows]

    # Anomalous events in period, with their summed risk contribution
    anomaly_count, anomaly_contribution = (
        await db.execute(
            select(
                func.count(BehaviorEvent.id),
                func.coalesce(func.sum(BehaviorEvent.risk_contribution), 0.0),
            ).where(
                and_(
                    BehaviorEvent.entity_profile_id == entity.id,
                    BehaviorEvent.organization_id == org_id,
                    BehaviorEvent.is_anomalous == True,
                    BehaviorEvent.created_at >= cutoff,
                )
            )
        )
    ).one()

    # The response previously handed ``current_behavior`` (a dict) to a list
    # field and omitted the required ``risk_trend``: always a 500.
    scorer = RiskScorer()
    risk_factors = scorer.get_risk_factors(entity.id, alerts)
    if anomaly_count:
        risk_factors.append({
            "factor": "anomalous_events",
            "count": int(anomaly_count),
            "contribution": round(float(anomaly_contribution or 0.0), 2),
        })

    return {
        "entity_id": entity_id,
        "risk_score": entity.risk_score,
        "risk_level": entity.risk_level,
        "risk_factors": risk_factors,
        "risk_trend": scorer.get_risk_trend(entity.id, alerts, days=days),
        "alert_count": len(alerts),
        "anomaly_count": int(anomaly_count or 0),
        "period_days": days,
        "updated_at": entity.updated_at,
    }


@router.get(
    "/entities/{entity_id}/peers",
    response_model=PeerComparisonResponse,
    summary="Get peer comparison",
    description="Compare entity behavior to peer group"
)
async def get_peer_comparison(
    entity_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Compare entity behavior to peer group members.

    Path Parameters:
    - entity_id: Unique entity identifier
    """
    logger.info(f"Getting peer comparison for {entity_id}")

    entity = await get_entity_or_404(db, entity_id, org_id)

    # Peer groups record their members by EntityProfile id (auto-cluster
    # and the update_peer_groups task); ``EntityProfile.peer_group`` is only
    # a label, so membership is resolved from the groups themselves. The old
    # response omitted the required comparisons/deviations: always a 500.
    groups = list(
        (
            await db.execute(
                select(PeerGroup).where(PeerGroup.organization_id == org_id)
            )
        ).scalars().all()
    )
    group = _pick_peer_group(entity, groups)

    if group is None:
        return {
            "entity_id": entity_id,
            "peer_group_id": "",
            "peer_group_name": "",
            "member_count": 0,
            "comparisons": [],
            "deviations": [],
        }

    peer_ids = [m for m in (group.members or []) if m != entity.id][:500]
    peer_entities: list[EntityProfile] = []
    if peer_ids:
        peer_entities = list(
            (
                await db.execute(
                    select(EntityProfile).where(
                        and_(
                            EntityProfile.organization_id == org_id,
                            EntityProfile.id.in_(peer_ids),
                        )
                    )
                )
            ).scalars().all()
        )

    entity_data = {
        "risk_score": entity.risk_score or 0.0,
        "activity_count": entity.anomaly_count_30d or 0,
    }
    peer_data = [
        {"risk_score": p.risk_score or 0.0, "activity_count": p.anomaly_count_30d or 0}
        for p in peer_entities
    ]

    comparisons = []
    for metric, key in (("risk_score", "risk_score"), ("anomaly_count_30d", "activity_count")):
        values = [float(d[key]) for d in peer_data]
        if not values:
            continue
        own = float(entity_data[key])
        comparisons.append({
            "metric": metric,
            "entity_value": own,
            "peer_average": round(sum(values) / len(values), 2),
            "percentile": round(sum(1 for v in values if v < own) / len(values) * 100.0, 1),
        })

    deviations = PeerGroupAnalyzer().detect_peer_deviation(entity.id, entity_data, peer_data)

    return {
        "entity_id": entity_id,
        "peer_group_id": group.id,
        "peer_group_name": group.name,
        "member_count": len(peer_entities) + 1,
        "comparisons": comparisons,
        "deviations": deviations,
    }


# ============================================================================
# Risk Alert Endpoints
# ============================================================================

@router.get(
    "/alerts",
    response_model=list[UEBARiskAlertResponse],
    summary="List UEBA alerts",
    description="List risk alerts with filtering"
)
async def list_alerts(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    alert_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    entity_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list:
    """
    List UEBA risk alerts with optional filtering.

    Query Parameters:
    - alert_type: Filter by alert type
    - severity: Filter by severity (critical, high, medium, low)
    - status: Filter by status (new, investigating, confirmed, dismissed)
    - entity_id: Filter by entity
    - search: Search in description
    - limit: Number of results
    - offset: Pagination offset
    """
    logger.info(
        f"Listing alerts: type={alert_type}, severity={severity}, "
        f"status={status}, limit={limit}, offset={offset}"
    )

    query = select(UEBARiskAlert).where(
        UEBARiskAlert.organization_id == org_id
    )

    if alert_type:
        query = query.where(UEBARiskAlert.alert_type == alert_type)

    if severity:
        query = query.where(UEBARiskAlert.severity == severity)

    if status:
        query = query.where(UEBARiskAlert.status == status)

    if entity_id:
        query = query.where(UEBARiskAlert.entity_profile_id == entity_id)

    if search:
        search_filter = f"%{search}%"
        query = query.where(UEBARiskAlert.description.ilike(search_filter))

    query = query.order_by(desc(UEBARiskAlert.created_at))
    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    alerts = list(result.scalars().all())

    return alerts


@router.get(
    "/alerts/{alert_id}",
    response_model=UEBARiskAlertResponse,
    summary="Get alert detail",
    description="Retrieve detailed alert information with evidence"
)
async def get_alert(
    alert_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> UEBARiskAlert:
    """
    Get detailed alert information.

    Path Parameters:
    - alert_id: Unique alert identifier
    """
    logger.info(f"Getting alert: {alert_id}")

    alert = await get_alert_or_404(db, alert_id, org_id)
    return alert


@router.put(
    "/alerts/{alert_id}/status",
    response_model=UEBARiskAlertResponse,
    summary="Update alert status",
    description="Change alert status and add analyst notes"
)
async def update_alert_status(
    alert_id: str,
    update: UEBARiskAlertUpdate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> UEBARiskAlert:
    """
    Update alert status and metadata.

    Path Parameters:
    - alert_id: Unique alert identifier

    Request Body:
    - status: New status (investigating, confirmed, dismissed)
    - analyst_notes: Notes from analyst
    - escalated_to_incident: Incident ID if escalated
    """
    logger.info(f"Updating alert {alert_id}: status={update.status}")

    alert = await get_alert_or_404(db, alert_id, org_id)

    update_data = update.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in update_data.items():
        setattr(alert, key, value)

    await db.flush()
    await db.refresh(alert)

    return alert


@router.post(
    "/alerts/{alert_id}/escalate",
    response_model=UEBARiskAlertResponse,
    summary="Escalate to incident",
    description="Escalate alert to security incident"
)
async def escalate_alert(
    alert_id: str,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    incident_id: Optional[str] = Query(None),
    notes: Optional[str] = Query(None),
) -> UEBARiskAlert:
    """
    Escalate a UEBA risk alert to a security Incident.

    If ``incident_id`` is provided, link this alert to that existing
    incident (verified to belong to the same org). Otherwise, create a
    brand-new Incident from the alert metadata and fire the standard
    incident-created automation pipeline (which spins up a war room and
    action items for high/critical severity).

    Query Parameters:
    - incident_id: optional existing incident to link to
    - notes: escalation notes (stored on the alert)
    """
    from src.models.incident import Incident, IncidentStatus

    logger.info(f"Escalating alert {alert_id} (target incident={incident_id})")

    alert = await get_alert_or_404(db, alert_id, org_id)

    # Idempotent: if already escalated, return as-is
    if alert.escalated_to_incident and alert.status == "confirmed":
        if notes:
            alert.analyst_notes = notes
            await db.flush()
            await db.refresh(alert)
        return alert

    # Load the entity so we can populate the incident w/ meaningful context
    entity_result = await db.execute(
        select(EntityProfile).where(
            EntityProfile.id == alert.entity_profile_id,
            EntityProfile.organization_id == org_id,
        )
    )
    entity = entity_result.scalar_one_or_none()

    target_incident: Optional[Incident] = None
    created_new = False

    if incident_id:
        # Link to an existing incident — verify it exists and belongs
        # to the caller's organization (cross-tenant IDOR guard).
        inc_stmt = select(Incident).where(
            Incident.id == incident_id,
            Incident.organization_id == org_id,
        )
        inc_result = await db.execute(inc_stmt)
        target_incident = inc_result.scalar_one_or_none()
        if not target_incident:
            raise HTTPException(
                status_code=404,
                detail=f"Incident {incident_id} not found",
            )
    else:
        # Create a real incident from this alert
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        incident_severity = sev_map.get((alert.severity or "").lower(), "medium")

        entity_label = (
            f"{entity.entity_type}:{entity.entity_id}" if entity else "unknown entity"
        )

        target_incident = Incident(
            title=f"UEBA escalation: {alert.alert_type} on {entity_label}",
            description=(
                (alert.description or "")
                + "\n\n---\n"
                + f"Escalated from UEBA alert {alert.id}.\n"
                + f"Entity: {entity_label}\n"
                + f"Risk score delta: {alert.risk_score_delta}\n"
                + (f"Analyst notes: {notes}\n" if notes else "")
            ),
            severity=incident_severity,
            status=IncidentStatus.OPEN.value,
            incident_type="ueba_anomaly",
            detected_at=datetime.now(timezone.utc).isoformat(),
            organization_id=org_id,
        )
        db.add(target_incident)
        await db.flush()
        created_new = True

    alert.status = "confirmed"
    alert.escalated_to_incident = target_incident.id
    if notes:
        alert.analyst_notes = notes

    if created_new:
        try:
            automation = AutomationService(db)
            await automation.on_incident_created(
                target_incident,
                organization_id=org_id,
                created_by=str(current_user.id) if current_user else None,
            )
        except Exception as automation_exc:  # noqa: BLE001
            # The incident and the alert link are real and committed with the
            # request; the war-room/action-item fanout is best effort.
            logger.warning(
                "ueba_escalation_automation_failed",
                incident_id=target_incident.id,
                organization_id=org_id,
                error=str(automation_exc),
            )

    await db.flush()
    await db.refresh(alert)

    return alert


# ============================================================================
# Behavior Event Endpoints
# ============================================================================

@router.post(
    "/events",
    response_model=BehaviorEventResponse,
    summary="Ingest behavior event",
    description="Submit a single behavior event for analysis"
)
async def ingest_event(
    event: BehaviorEventCreate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> BehaviorEvent:
    """
    Ingest and analyze a single behavior event.

    Request Body:
    - entity_id: Entity identifier
    - event_type: Type of event
    - event_data: Event-specific data
    - source_ip: Source IP if applicable
    - destination: Destination if applicable
    - geo_location: Geolocation data if available
    - device_info: Device information if available
    """
    logger.info(f"Ingesting event for entity {event.entity_id}: type={event.event_type}")

    # Shared with the batch endpoint and the process_behavior_events
    # Celery task: entity lookup, anomaly scoring against the baseline,
    # risk-counter bump, and on_ueba_anomaly automation fanout.
    behavior_event, _alert_created = await ingest_behavior_event(
        db, org_id, event.model_dump()
    )
    if behavior_event is None:
        raise HTTPException(status_code=404, detail=f"Entity {event.entity_id} not found")

    await db.flush()
    await db.refresh(behavior_event)

    return behavior_event


@router.post(
    "/events/batch",
    response_model=BatchIngestionResponse,
    summary="Batch ingest events",
    description="Submit multiple behavior events in batch"
)
async def ingest_batch(
    batch: BehaviorEventBatch,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Ingest and analyze multiple behavior events.

    Request Body:
    - events: List of behavior events (1-1000 per request)
    """
    logger.info(f"Ingesting batch of {len(batch.events)} events")

    import time as _t
    _started = _t.monotonic()

    processed = 0
    failed = 0
    anomalies = 0
    alerts_created = 0

    for event in batch.events:
        # Shared per-event ingest: entity lookup, baseline scoring,
        # risk bump, and on_ueba_anomaly fanout — identical logic to
        # single-event ingest and the process_behavior_events task.
        # An unknown entity counts as failed; any other error (database,
        # scoring) fails the request instead of being folded into the count.
        behavior_event, alert_created = await ingest_behavior_event(
            db, org_id, event.model_dump()
        )
        if behavior_event is None:
            failed += 1
            continue

        processed += 1
        if behavior_event.is_anomalous:
            anomalies += 1
        if alert_created:
            alerts_created += 1

    if processed > 0:
        await db.flush()

    elapsed_ms = (_t.monotonic() - _started) * 1000.0

    return {
        "total_events": len(batch.events),
        "processed_events": processed,
        "failed_events": failed,
        "anomalies_detected": anomalies,
        "alerts_created": alerts_created,
        "processing_time_ms": round(elapsed_ms, 2),
    }


@router.get(
    "/events",
    response_model=list[BehaviorEventResponse],
    summary="Search behavior events",
    description="Search and filter behavior events"
)
async def search_events(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    entity_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    is_anomalous: Optional[bool] = Query(None),
    source_ip: Optional[str] = Query(None),
    destination: Optional[str] = Query(None),
    days: int = Query(7, ge=1, le=365),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list:
    """
    Search behavior events with filtering.

    Query Parameters:
    - entity_id: Filter by entity
    - event_type: Filter by event type
    - is_anomalous: Filter by anomaly status
    - source_ip: Filter by source IP
    - destination: Filter by destination
    - days: Number of days to search
    - limit: Number of results
    - offset: Pagination offset
    """
    logger.info(f"Searching events: entity={entity_id}, type={event_type}, days={days}")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    query = select(BehaviorEvent).where(
        and_(
            BehaviorEvent.organization_id == org_id,
            BehaviorEvent.created_at >= cutoff,
        )
    )

    if entity_id:
        query = query.where(BehaviorEvent.entity_profile_id == entity_id)

    if event_type:
        query = query.where(BehaviorEvent.event_type == event_type)

    if is_anomalous is not None:
        query = query.where(BehaviorEvent.is_anomalous == is_anomalous)

    if source_ip:
        query = query.where(BehaviorEvent.source_ip == source_ip)

    if destination:
        query = query.where(BehaviorEvent.destination == destination)

    query = query.order_by(desc(BehaviorEvent.created_at))
    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    events = list(result.scalars().all())

    return events


# ============================================================================
# Peer Group Endpoints
# ============================================================================

@router.get(
    "/peer-groups",
    response_model=list[PeerGroupResponse],
    summary="List peer groups",
    description="List all peer groups"
)
async def list_peer_groups(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    group_type: Optional[str] = Query(None),
) -> list:
    """
    List peer groups.

    Query Parameters:
    - group_type: Filter by type (department, role, custom, auto_clustered)
    """
    logger.info(f"Listing peer groups: type={group_type}")

    query = select(PeerGroup).where(
        PeerGroup.organization_id == org_id
    )

    if group_type:
        query = query.where(PeerGroup.group_type == group_type)

    query = query.order_by(PeerGroup.name)

    result = await db.execute(query)
    groups = list(result.scalars().all())

    return groups


@router.post(
    "/peer-groups",
    response_model=PeerGroupResponse,
    summary="Create peer group",
    description="Create a custom peer group"
)
async def create_peer_group(
    group: PeerGroupCreate,
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> PeerGroup:
    """
    Create a custom peer group.

    Request Body:
    - name: Group name
    - description: Group description
    - group_type: Type (usually 'custom')
    - risk_threshold: Risk threshold for members
    """
    logger.info(f"Creating peer group: {group.name}")

    peer_group = PeerGroup(
        id=str(uuid.uuid4()),
        name=group.name,
        description=group.description if hasattr(group, "description") else None,
        group_type=group.group_type if hasattr(group, "group_type") else "custom",
        risk_threshold=group.risk_threshold if hasattr(group, "risk_threshold") else 70.0,
        organization_id=org_id,
    )

    db.add(peer_group)
    await db.flush()
    await db.refresh(peer_group)

    return peer_group


@router.get(
    "/peer-groups/{group_id}",
    response_model=PeerGroupResponse,
    summary="Get group detail",
    description="Retrieve peer group with member risk info"
)
async def get_peer_group(
    group_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> PeerGroup:
    """
    Get peer group details with member information.

    Path Parameters:
    - group_id: Unique group identifier
    """
    logger.info(f"Getting peer group: {group_id}")

    group = await get_peer_group_or_404(db, group_id, org_id)
    return group


@router.post(
    "/peer-groups/auto-cluster",
    response_model=list[PeerGroupResponse],
    summary="Auto-cluster peers",
    description="Trigger automatic peer clustering"
)
async def trigger_auto_cluster(
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> list:
    """
    Trigger automatic peer clustering.

    Groups entities by (entity_type, department, role) — this is the
    canonical dimension along which UEBA compares peer behavior. Entities
    without a department/role are bucketed by (entity_type, risk_level)
    so they still get a comparable group. Existing auto_clustered groups
    are deleted first so repeated calls are idempotent.
    """
    from sqlalchemy import delete as sql_delete

    logger.info("Triggering auto-cluster for peer groups")


    # Load all entities for this org
    entity_result = await db.execute(
        select(EntityProfile).where(EntityProfile.organization_id == org_id)
    )
    entities = list(entity_result.scalars().all())

    if not entities:
        return []

    # Bucket entities
    buckets: dict[tuple, list[EntityProfile]] = {}
    for e in entities:
        if e.department and e.role:
            key = (e.entity_type, e.department, e.role)
            label = f"{e.entity_type}:{e.department}/{e.role}"
        elif e.department:
            key = (e.entity_type, e.department, None)
            label = f"{e.entity_type}:{e.department}"
        else:
            key = (e.entity_type, None, e.risk_level or "low")
            label = f"{e.entity_type}:{e.risk_level or 'low'}-risk"
        buckets.setdefault(key, []).append(e)

    # Wipe prior auto-clustered groups for this org
    await db.execute(
        sql_delete(PeerGroup).where(
            and_(
                PeerGroup.organization_id == org_id,
                PeerGroup.group_type == "auto_clustered",
            )
        )
    )
    await db.flush()

    created_groups: list[PeerGroup] = []
    for key, members in buckets.items():
        if len(members) < 2:
            # A peer group of one isn't useful
            continue
        etype, dept_or_none, role_or_risk = key
        if dept_or_none and role_or_risk:
            name = f"{etype}-{dept_or_none}-{role_or_risk}"
        elif dept_or_none:
            name = f"{etype}-{dept_or_none}"
        else:
            name = f"{etype}-{role_or_risk}"

        # Aggregate baseline: mean risk_score, risk_level distribution
        scores = [m.risk_score or 0.0 for m in members]
        mean_risk = sum(scores) / len(scores) if scores else 0.0
        baseline_data = {
            "mean_risk_score": round(mean_risk, 2),
            "member_count": len(members),
            "entity_type": etype,
        }

        group = PeerGroup(
            id=str(uuid.uuid4()),
            name=name,
            description=f"Auto-clustered on {datetime.now(timezone.utc).date().isoformat()}",
            group_type="auto_clustered",
            member_count=len(members),
            baseline_data=baseline_data,
            risk_threshold=max(70.0, mean_risk + 20.0),
            members=[m.id for m in members],
            organization_id=org_id,
        )
        db.add(group)
        created_groups.append(group)

    await db.flush()
    for g in created_groups:
        await db.refresh(g)

    logger.info(f"Auto-cluster created {len(created_groups)} peer groups from {len(entities)} entities")
    return created_groups


# ============================================================================
# Baseline Endpoints
# ============================================================================

@router.get(
    "/baselines/{entity_id}",
    response_model=list[BehaviorBaselineResponse],
    summary="Get entity baselines",
    description="Retrieve behavior baselines for entity"
)
async def get_baselines(
    entity_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    behavior_type: Optional[str] = Query(None),
) -> list:
    """
    Get behavior baselines for an entity.

    Path Parameters:
    - entity_id: Entity identifier

    Query Parameters:
    - behavior_type: Filter by specific behavior type
    """
    logger.info(f"Getting baselines for {entity_id}: type={behavior_type}")

    # Verify entity exists and belongs to org
    await get_entity_or_404(db, entity_id, org_id)

    # BehaviorBaseline has no organization_id column (filtering on one was a
    # 500 for every caller); the tenant boundary is the owning entity.
    query = (
        select(BehaviorBaseline)
        .join(EntityProfile, EntityProfile.id == BehaviorBaseline.entity_profile_id)
        .where(
            and_(
                BehaviorBaseline.entity_profile_id == entity_id,
                EntityProfile.organization_id == org_id,
            )
        )
    )

    if behavior_type:
        query = query.where(BehaviorBaseline.behavior_type == behavior_type)

    result = await db.execute(query)
    baselines = list(result.scalars().all())

    return baselines


@router.post(
    "/baselines/rebuild",
    summary="Rebuild baselines",
    description="Trigger baseline recalculation"
)
async def rebuild_baselines(
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    entity_ids: Optional[list[str]] = Query(None),
    baseline_days: int = Query(30, ge=1, le=365),
) -> dict:
    """
    Rebuild behavior baselines for entities synchronously.

    For each target entity:
    - Load BehaviorEvents from the last ``baseline_days`` days
    - Group by event_type
    - For each (entity, event_type), compute typical source_ips, typical
      destinations, common hours, and sample count
    - Upsert a BehaviorBaseline row per (entity, event_type)

    Query Parameters:
    - entity_ids: specific entities to rebuild (None = all entities in org)
    - baseline_days: rolling window for baseline calculation (default 30)
    """
    from sqlalchemy import delete as sql_delete


    # Load target entities
    if entity_ids:
        ent_query = select(EntityProfile).where(
            and_(
                EntityProfile.id.in_(entity_ids),
                EntityProfile.organization_id == org_id,
            )
        )
    else:
        ent_query = select(EntityProfile).where(EntityProfile.organization_id == org_id)

    ent_result = await db.execute(ent_query)
    entities = list(ent_result.scalars().all())

    logger.info(f"Rebuilding baselines for {len(entities)} entities (window={baseline_days}d)")

    cutoff = datetime.now(timezone.utc) - timedelta(days=baseline_days)
    baselines_built = 0
    events_analyzed = 0

    for entity in entities:
        # Fetch recent events for this entity
        ev_result = await db.execute(
            select(BehaviorEvent).where(
                and_(
                    BehaviorEvent.entity_profile_id == entity.id,
                    BehaviorEvent.organization_id == org_id,
                    BehaviorEvent.created_at >= cutoff,
                    # SIEM-bridge hourly buckets keep their own baseline.
                    BehaviorEvent.event_type != siem_bridge.EVENT_TYPE,
                )
            )
        )
        events = list(ev_result.scalars().all())
        events_analyzed += len(events)

        if not events:
            continue

        # Group by event_type
        by_type: dict[str, list[BehaviorEvent]] = {}
        for ev in events:
            by_type.setdefault(ev.event_type, []).append(ev)

        # Wipe this entity's existing baselines so the rebuild is clean
        await db.execute(
            sql_delete(BehaviorBaseline).where(
                BehaviorBaseline.entity_profile_id == entity.id,
                BehaviorBaseline.behavior_type != siem_bridge.EVENT_TYPE,
            )
        )

        for event_type, type_events in by_type.items():
            ips: dict[str, int] = {}
            dests: dict[str, int] = {}
            hours: dict[int, int] = {}
            for ev in type_events:
                if ev.source_ip:
                    ips[ev.source_ip] = ips.get(ev.source_ip, 0) + 1
                if ev.destination:
                    dests[ev.destination] = dests.get(ev.destination, 0) + 1
                if ev.created_at:
                    h = ev.created_at.hour
                    hours[h] = hours.get(h, 0) + 1

            typical_ips = sorted(ips.keys(), key=lambda k: -ips[k])[:20]
            typical_dests = sorted(dests.keys(), key=lambda k: -dests[k])[:20]
            top_hours = sorted(hours.keys(), key=lambda k: -hours[k])[:8]

            sample_count = len(type_events)
            # Confidence grows with sample size, saturates at 100 samples
            confidence = min(1.0, sample_count / 100.0)

            baseline = BehaviorBaseline(
                id=str(uuid.uuid4()),
                entity_profile_id=entity.id,
                behavior_type=event_type,
                baseline_period_days=baseline_days,
                statistical_model={
                    "unique_source_ips": len(ips),
                    "unique_destinations": len(dests),
                    "sample_count": sample_count,
                },
                typical_values=typical_ips,
                time_patterns={
                    "hours": top_hours,
                    "hour_counts": hours,
                    "destinations": typical_dests,
                },
                peer_comparison={},
                confidence=round(confidence, 3),
                sample_count=sample_count,
                last_updated_at=datetime.now(timezone.utc),
            )
            db.add(baseline)
            baselines_built += 1

        # Update entity baseline_data summary
        entity.baseline_data = {
            "baseline_days": baseline_days,
            "event_types": list(by_type.keys()),
            "total_events": len(events),
            "last_rebuild": datetime.now(timezone.utc).isoformat(),
        }

    await db.flush()

    return {
        "status": "completed",
        "entities_targeted": len(entities),
        "baselines_built": baselines_built,
        "events_analyzed": events_analyzed,
        "baseline_days": baseline_days,
    }


# ============================================================================
# Dashboard Endpoints
# ============================================================================

@router.get(
    "/dashboard",
    response_model=UEBADashboardStats,
    summary="Get UEBA statistics",
    description="Retrieve UEBA dashboard statistics"
)
async def get_dashboard_stats(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Get UEBA dashboard statistics including risk distribution and alerts.
    """
    logger.info("Getting UEBA dashboard statistics")

    # Total entities
    total_result = await db.execute(
        select(func.count(EntityProfile.id)).where(EntityProfile.organization_id == org_id)
    )
    total_entities = total_result.scalar() or 0

    # Watched entities
    watched_result = await db.execute(
        select(func.count(EntityProfile.id)).where(
            and_(EntityProfile.organization_id == org_id, EntityProfile.is_watched == True)
        )
    )
    watched_entities = watched_result.scalar() or 0

    # High risk entities (score >= 70)
    high_risk_result = await db.execute(
        select(EntityProfile).where(
            and_(
                EntityProfile.organization_id == org_id,
                EntityProfile.risk_score >= 70.0,
            )
        ).order_by(desc(EntityProfile.risk_score)).limit(10)
    )
    high_risk_entities = list(high_risk_result.scalars().all())
    high_risk_count = (await db.execute(
        select(func.count(EntityProfile.id)).where(
            EntityProfile.organization_id == org_id,
            EntityProfile.risk_score >= 70.0,
        )
    )).scalar() or 0

    # Risk distribution
    risk_dist_result = await db.execute(
        select(EntityProfile.risk_level, func.count(EntityProfile.id))
        .where(EntityProfile.organization_id == org_id)
        .group_by(EntityProfile.risk_level)
    )
    risk_distribution = [{"level": level, "count": count} for level, count in risk_dist_result.all()]

    # Alert distribution by severity
    alert_dist_result = await db.execute(
        select(UEBARiskAlert.severity, func.count(UEBARiskAlert.id))
        .where(UEBARiskAlert.organization_id == org_id)
        .group_by(UEBARiskAlert.severity)
    )
    alert_distribution = [
        {"severity": sev, "alert_type": sev, "count": count} for sev, count in alert_dist_result.all()
    ]

    # Alerts in last 7 and 30 days
    now = datetime.now(timezone.utc)
    alerts_7d_result = await db.execute(
        select(func.count(UEBARiskAlert.id)).where(
            and_(
                UEBARiskAlert.organization_id == org_id,
                UEBARiskAlert.created_at >= now - timedelta(days=7),
            )
        )
    )
    alerts_7d = alerts_7d_result.scalar() or 0

    alerts_30d_result = await db.execute(
        select(func.count(UEBARiskAlert.id)).where(
            and_(
                UEBARiskAlert.organization_id == org_id,
                UEBARiskAlert.created_at >= now - timedelta(days=30),
            )
        )
    )
    alerts_30d = alerts_30d_result.scalar() or 0

    # Anomalies in last 7 and 30 days
    anomalies_7d_result = await db.execute(
        select(func.count(BehaviorEvent.id)).where(
            and_(
                BehaviorEvent.organization_id == org_id,
                BehaviorEvent.is_anomalous == True,
                BehaviorEvent.created_at >= now - timedelta(days=7),
            )
        )
    )
    anomalies_7d = anomalies_7d_result.scalar() or 0

    anomalies_30d_result = await db.execute(
        select(func.count(BehaviorEvent.id)).where(
            and_(
                BehaviorEvent.organization_id == org_id,
                BehaviorEvent.is_anomalous == True,
                BehaviorEvent.created_at >= now - timedelta(days=30),
            )
        )
    )
    anomalies_30d = anomalies_30d_result.scalar() or 0

    return {
        "total_entities": total_entities,
        "watched_entities": watched_entities,
        "high_risk_entities": high_risk_entities,
        "risk_distribution": risk_distribution,
        "alert_distribution": alert_distribution,
        "alerts_last_7d": alerts_7d,
        "alerts_last_30d": alerts_30d,
        "anomalies_last_7d": anomalies_7d,
        "anomalies_last_30d": anomalies_30d,
        "updated_at": now,
        "high_risk_entity_count": high_risk_count,
        "siem_bridge": await siem_bridge.cursor_status(db, org_id),
    }


# ============================================================================
# SIEM bridge (stored log entries -> entities, baselines, anomaly alerts)
# ============================================================================

#: Log rows one on-demand run may fold in (the 5-minute beat run allows more).
ON_DEMAND_BRIDGE_ROWS = 10_000


@router.get(
    "/siem-bridge/status",
    response_model=SiemBridgeStatus,
    summary="UEBA SIEM bridge status",
    description="Last run of the job that builds UEBA entities and anomaly alerts from stored SIEM logs",
)
async def get_siem_bridge_status(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    return await siem_bridge.cursor_status(db, org_id)


@router.post(
    "/siem-bridge/run",
    summary="Run the UEBA SIEM bridge now",
    description=(
        "Fold this organisation's new stored SIEM log entries into UEBA entities, "
        "hourly baselines and anomaly alerts now (admin). At most "
        f"{ON_DEMAND_BRIDGE_ROWS} log rows per call; the rest is read by the next run."
    ),
)
async def run_siem_bridge(
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    result = await siem_bridge.run_bridge_for_org(db, org_id, max_rows=ON_DEMAND_BRIDGE_ROWS)
    logger.info("ueba_siem_bridge_on_demand", organization_id=org_id, rows=result["log_rows"])
    return result


@router.get(
    "/risk-heatmap",
    response_model=RiskHeatmapResponse,
    summary="Get risk heatmap data",
    description="Retrieve risk heatmap data by entity type and risk level"
)
async def get_risk_heatmap(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Get risk heatmap data for visualization.
    """
    logger.info("Getting risk heatmap data")

    # Aggregate by entity_type and risk_level
    heatmap_result = await db.execute(
        select(
            EntityProfile.entity_type,
            EntityProfile.risk_level,
            func.count(EntityProfile.id),
        )
        .where(EntityProfile.organization_id == org_id)
        .group_by(EntityProfile.entity_type, EntityProfile.risk_level)
    )
    heatmap_data = [
        {"entity_type": etype, "risk_level": rlevel, "count": count}
        for etype, rlevel, count in heatmap_result.all()
    ]

    total_result = await db.execute(
        select(func.count(EntityProfile.id)).where(EntityProfile.organization_id == org_id)
    )
    total_entities = total_result.scalar() or 0

    return {
        "heatmap_data": heatmap_data,
        "total_entities": total_entities,
        "generated_at": datetime.now(timezone.utc),
    }
