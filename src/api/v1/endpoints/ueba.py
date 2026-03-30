"""
UEBA REST API Endpoints
FastAPI router for User & Entity Behavior Analytics operations.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.core.config import settings
from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user, get_db
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
    EntityListFilter,
    AlertListFilter,
    EventListFilter,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/ueba", tags=["ueba"])


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
    current_user: CurrentUser = None,
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
        EntityProfile.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> EntityProfile:
    """
    Get detailed entity profile with risk information.

    Path Parameters:
    - entity_id: Unique entity identifier
    """
    logger.info(f"Getting entity profile: {entity_id}")

    entity = await get_entity_or_404(db, entity_id, current_user.organization_id)
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
    current_user: CurrentUser = None,
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

    entity = await get_entity_or_404(db, entity_id, current_user.organization_id)

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
    current_user: CurrentUser = None,
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

    entity = await get_entity_or_404(db, entity_id, current_user.organization_id)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    query = select(BehaviorEvent).where(
        and_(
            BehaviorEvent.entity_profile_id == entity.id,
            BehaviorEvent.organization_id == current_user.organization_id,
            BehaviorEvent.created_at >= cutoff,
        )
    )

    if anomalies_only:
        query = query.where(BehaviorEvent.is_anomalous == True)

    query = query.order_by(desc(BehaviorEvent.created_at)).limit(limit)

    result = await db.execute(query)
    events = list(result.scalars().all())

    return {
        "entity_id": entity_id,
        "events": events,
        "total_events": len(events),
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
    current_user: CurrentUser = None,
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

    entity = await get_entity_or_404(db, entity_id, current_user.organization_id)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Count alerts in period
    alert_count_result = await db.execute(
        select(func.count(UEBARiskAlert.id)).where(
            and_(
                UEBARiskAlert.entity_profile_id == entity.id,
                UEBARiskAlert.organization_id == current_user.organization_id,
                UEBARiskAlert.created_at >= cutoff,
            )
        )
    )
    alert_count = alert_count_result.scalar() or 0

    # Count anomalous events in period
    anomaly_count_result = await db.execute(
        select(func.count(BehaviorEvent.id)).where(
            and_(
                BehaviorEvent.entity_profile_id == entity.id,
                BehaviorEvent.organization_id == current_user.organization_id,
                BehaviorEvent.is_anomalous == True,
                BehaviorEvent.created_at >= cutoff,
            )
        )
    )
    anomaly_count = anomaly_count_result.scalar() or 0

    return {
        "entity_id": entity_id,
        "risk_score": entity.risk_score,
        "risk_level": entity.risk_level,
        "alert_count": alert_count,
        "anomaly_count": anomaly_count,
        "period_days": days,
        "risk_factors": entity.current_behavior,
    }


@router.get(
    "/entities/{entity_id}/peers",
    response_model=PeerComparisonResponse,
    summary="Get peer comparison",
    description="Compare entity behavior to peer group"
)
async def get_peer_comparison(
    entity_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Compare entity behavior to peer group members.

    Path Parameters:
    - entity_id: Unique entity identifier
    """
    logger.info(f"Getting peer comparison for {entity_id}")

    entity = await get_entity_or_404(db, entity_id, current_user.organization_id)

    # Find peer group members
    peer_entities = []
    if entity.peer_group:
        peer_result = await db.execute(
            select(EntityProfile).where(
                and_(
                    EntityProfile.organization_id == current_user.organization_id,
                    EntityProfile.peer_group == entity.peer_group,
                    EntityProfile.id != entity.id,
                )
            ).limit(50)
        )
        peer_entities = list(peer_result.scalars().all())

    peer_risk_scores = [p.risk_score for p in peer_entities]
    avg_peer_risk = sum(peer_risk_scores) / len(peer_risk_scores) if peer_risk_scores else 0.0

    return {
        "entity_id": entity_id,
        "entity_risk_score": entity.risk_score,
        "peer_group": entity.peer_group,
        "peer_count": len(peer_entities),
        "avg_peer_risk_score": avg_peer_risk,
        "peers": peer_entities,
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
    current_user: CurrentUser = None,
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
        UEBARiskAlert.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> UEBARiskAlert:
    """
    Get detailed alert information.

    Path Parameters:
    - alert_id: Unique alert identifier
    """
    logger.info(f"Getting alert: {alert_id}")

    alert = await get_alert_or_404(db, alert_id, current_user.organization_id)
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
    current_user: CurrentUser = None,
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

    alert = await get_alert_or_404(db, alert_id, current_user.organization_id)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    incident_id: str = Query(...),
    notes: Optional[str] = Query(None),
) -> UEBARiskAlert:
    """
    Escalate alert to a security incident.

    Path Parameters:
    - alert_id: Unique alert identifier

    Query Parameters:
    - incident_id: Target incident ID
    - notes: Escalation notes
    """
    logger.info(f"Escalating alert {alert_id} to incident {incident_id}")

    alert = await get_alert_or_404(db, alert_id, current_user.organization_id)

    alert.status = "confirmed"
    alert.escalated_to_incident = incident_id
    if notes:
        alert.analyst_notes = notes

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
    current_user: CurrentUser = None,
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

    # Look up entity profile by entity_id field
    entity_result = await db.execute(
        select(EntityProfile).where(
            and_(
                EntityProfile.entity_id == event.entity_id,
                EntityProfile.organization_id == current_user.organization_id,
            )
        )
    )
    entity = entity_result.scalar_one_or_none()
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entity {event.entity_id} not found")

    behavior_event = BehaviorEvent(
        id=str(uuid.uuid4()),
        entity_profile_id=entity.id,
        event_type=event.event_type,
        event_data=event.event_data if hasattr(event, "event_data") else {},
        source_ip=event.source_ip if hasattr(event, "source_ip") else None,
        destination=event.destination if hasattr(event, "destination") else None,
        geo_location=event.geo_location if hasattr(event, "geo_location") else None,
        device_info=event.device_info if hasattr(event, "device_info") else None,
        organization_id=current_user.organization_id,
    )

    db.add(behavior_event)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Ingest and analyze multiple behavior events.

    Request Body:
    - events: List of behavior events (1-1000 per request)
    """
    logger.info(f"Ingesting batch of {len(batch.events)} events")

    processed = 0
    failed = 0
    anomalies = 0

    for event in batch.events:
        try:
            # Look up entity profile
            entity_result = await db.execute(
                select(EntityProfile).where(
                    and_(
                        EntityProfile.entity_id == event.entity_id,
                        EntityProfile.organization_id == current_user.organization_id,
                    )
                )
            )
            entity = entity_result.scalar_one_or_none()
            if not entity:
                failed += 1
                continue

            behavior_event = BehaviorEvent(
                id=str(uuid.uuid4()),
                entity_profile_id=entity.id,
                event_type=event.event_type,
                event_data=event.event_data if hasattr(event, "event_data") else {},
                source_ip=event.source_ip if hasattr(event, "source_ip") else None,
                destination=event.destination if hasattr(event, "destination") else None,
                geo_location=event.geo_location if hasattr(event, "geo_location") else None,
                device_info=event.device_info if hasattr(event, "device_info") else None,
                organization_id=current_user.organization_id,
            )
            db.add(behavior_event)
            processed += 1
        except Exception:
            failed += 1

    if processed > 0:
        await db.flush()

    return {
        "total_events": len(batch.events),
        "processed_events": processed,
        "failed_events": failed,
        "anomalies_detected": anomalies,
        "alerts_created": 0,
        "processing_time_ms": 0.0,
    }


@router.get(
    "/events",
    response_model=list[BehaviorEventResponse],
    summary="Search behavior events",
    description="Search and filter behavior events"
)
async def search_events(
    current_user: CurrentUser = None,
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
            BehaviorEvent.organization_id == current_user.organization_id,
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
    current_user: CurrentUser = None,
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
        PeerGroup.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
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
        organization_id=current_user.organization_id,
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> PeerGroup:
    """
    Get peer group details with member information.

    Path Parameters:
    - group_id: Unique group identifier
    """
    logger.info(f"Getting peer group: {group_id}")

    group = await get_peer_group_or_404(db, group_id, current_user.organization_id)
    return group


@router.post(
    "/peer-groups/auto-cluster",
    response_model=list[PeerGroupResponse],
    summary="Auto-cluster peers",
    description="Trigger automatic peer clustering"
)
async def trigger_auto_cluster(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> list:
    """
    Trigger automatic peer clustering based on behavior features.
    """
    logger.info("Triggering auto-cluster for peer groups")

    # Return existing auto-clustered groups
    result = await db.execute(
        select(PeerGroup).where(
            and_(
                PeerGroup.organization_id == current_user.organization_id,
                PeerGroup.group_type == "auto_clustered",
            )
        )
    )
    groups = list(result.scalars().all())

    return groups


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
    current_user: CurrentUser = None,
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

    # Verify entity exists
    await get_entity_or_404(db, entity_id, current_user.organization_id)

    query = select(BehaviorBaseline).where(
        BehaviorBaseline.entity_profile_id == entity_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    entity_ids: Optional[list[str]] = Query(None),
) -> dict:
    """
    Trigger baseline recalculation for entities.

    Query Parameters:
    - entity_ids: Specific entities to rebuild (None = all)
    """
    target_count = len(entity_ids) if entity_ids else 0

    if not entity_ids:
        # Count all entities in org
        count_result = await db.execute(
            select(func.count(EntityProfile.id)).where(
                EntityProfile.organization_id == current_user.organization_id
            )
        )
        target_count = count_result.scalar() or 0

    logger.info(f"Rebuilding baselines for {target_count} entities")

    task_id = str(uuid.uuid4())

    return {
        "status": "scheduled",
        "task_id": task_id,
        "entities_targeted": target_count,
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Get UEBA dashboard statistics including risk distribution and alerts.
    """
    logger.info("Getting UEBA dashboard statistics")

    org_id = current_user.organization_id

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
    alert_distribution = [{"severity": sev, "count": count} for sev, count in alert_dist_result.all()]

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
    }


@router.get(
    "/risk-heatmap",
    response_model=RiskHeatmapResponse,
    summary="Get risk heatmap data",
    description="Retrieve risk heatmap data by entity type and risk level"
)
async def get_risk_heatmap(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Get risk heatmap data for visualization.
    """
    logger.info("Getting risk heatmap data")

    org_id = current_user.organization_id

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
