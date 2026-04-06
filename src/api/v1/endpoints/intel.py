"""Threat Intelligence Platform API endpoints"""

import math
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Path, HTTPException, Query, status
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_admin_user
from src.intel.models import (
    IndicatorSighting,
    IntelReport,
    ThreatActor,
    ThreatCampaign,
    ThreatFeed,
    ThreatIndicator,
)
from src.schemas.intel import (
    BulkIndicatorImport,
    IntelDashboardStats,
    IntelReportCreate,
    IntelReportListResponse,
    IntelReportResponse,
    IntelReportUpdate,
    IntelSearchRequest,
    IndicatorSightingCreate,
    IndicatorSightingResponse,
    ThreatActorCreate,
    ThreatActorListResponse,
    ThreatActorResponse,
    ThreatActorUpdate,
    ThreatCampaignCreate,
    ThreatCampaignListResponse,
    ThreatCampaignResponse,
    ThreatCampaignUpdate,
    ThreatFeedCreate,
    ThreatFeedListResponse,
    ThreatFeedResponse,
    ThreatFeedUpdate,
    ThreatIndicatorCreate,
    ThreatIndicatorListResponse,
    ThreatIndicatorResponse,
    ThreatIndicatorUpdate,
)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


# ============================================================================
# STATS AND LOOKUP ENDPOINTS (consumed by frontend ThreatIntel.tsx)
# ============================================================================


@router.get("/stats", response_model=None, operation_id="get_threat_intel_stats")
async def get_threat_intel_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Get threat intelligence stats for the frontend dashboard cards.
    """
    org_id = getattr(current_user, "organization_id", None)

    # Build org filter - if no org_id, query all
    def org_filter(model):
        if org_id:
            return model.organization_id == org_id
        return True

    total_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(org_filter(ThreatIndicator))
        )
    ).scalar() or 0

    malicious_severities = ("critical", "high")

    malicious_ips = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                and_(
                    org_filter(ThreatIndicator),
                    ThreatIndicator.indicator_type.in_(["ipv4", "ipv6", "ip"]),
                    ThreatIndicator.severity.in_(malicious_severities),
                )
            )
        )
    ).scalar() or 0

    malicious_domains = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                and_(
                    org_filter(ThreatIndicator),
                    ThreatIndicator.indicator_type == "domain",
                    ThreatIndicator.severity.in_(malicious_severities),
                )
            )
        )
    ).scalar() or 0

    malicious_hashes = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                and_(
                    org_filter(ThreatIndicator),
                    ThreatIndicator.indicator_type.in_(["md5", "sha1", "sha256", "hash"]),
                    ThreatIndicator.severity.in_(malicious_severities),
                )
            )
        )
    ).scalar() or 0

    feeds_active = (
        await db.execute(
            select(func.count(ThreatFeed.id)).where(
                and_(
                    org_filter(ThreatFeed),
                    ThreatFeed.is_enabled == True,
                )
            )
        )
    ).scalar() or 0

    last_update_result = (
        await db.execute(
            select(func.max(ThreatIndicator.last_seen)).where(org_filter(ThreatIndicator))
        )
    ).scalar()

    return {
        "total_indicators": total_indicators,
        "malicious_ips": malicious_ips,
        "malicious_domains": malicious_domains,
        "malicious_hashes": malicious_hashes,
        "feeds_active": feeds_active,
        "last_update": last_update_result.isoformat() if last_update_result else None,
    }


@router.post("/lookup", response_model=None, operation_id="lookup_ioc")
async def lookup_ioc(
    payload: dict,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Look up an IOC indicator and return reputation information.
    Frontend POSTs { indicator: string, type: string }.
    """
    indicator_value = payload.get("indicator", "")
    indicator_type = payload.get("type", "auto")

    if not indicator_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="indicator is required",
        )

    org_id = getattr(current_user, "organization_id", None)

    # Query matching indicators
    org_clause = ThreatIndicator.organization_id == org_id if org_id else True
    query = select(ThreatIndicator).where(
        and_(
            org_clause,
            ThreatIndicator.value == indicator_value,
        )
    )
    if indicator_type and indicator_type != "auto":
        query = query.where(ThreatIndicator.indicator_type == indicator_type)

    result = await db.execute(query.order_by(desc(ThreatIndicator.last_seen)))
    indicators = result.scalars().all()

    if not indicators:
        return {
            "indicator": indicator_value,
            "type": indicator_type,
            "reputation": "unknown",
            "confidence": 0,
            "sources": [],
            "tags": [],
            "first_seen": None,
            "last_seen": None,
        }

    # Determine overall reputation from severity of matching indicators
    severity_to_reputation = {
        "critical": "malicious",
        "high": "malicious",
        "medium": "suspicious",
        "low": "clean",
        "informational": "clean",
    }

    best = indicators[0]
    reputation = severity_to_reputation.get(best.severity or "", "unknown")
    confidence = best.confidence or 0
    resolved_type = best.indicator_type or indicator_type

    # Build sources list
    sources = []
    for ind in indicators:
        sources.append({
            "name": ind.source or "Internal",
            "verdict": severity_to_reputation.get(ind.severity or "", "unknown"),
            "last_seen": ind.last_seen.isoformat() if ind.last_seen else datetime.now(timezone.utc).isoformat(),
        })

    # Aggregate tags
    all_tags = []
    for ind in indicators:
        all_tags.extend(ind.tags or [])
    unique_tags = list(dict.fromkeys(all_tags))

    # Earliest first_seen and latest last_seen
    first_seens = [ind.first_seen for ind in indicators if ind.first_seen]
    last_seens = [ind.last_seen for ind in indicators if ind.last_seen]

    return {
        "indicator": indicator_value,
        "type": resolved_type,
        "reputation": reputation,
        "confidence": confidence,
        "sources": sources,
        "tags": unique_tags,
        "first_seen": min(first_seens).isoformat() if first_seens else None,
        "last_seen": max(last_seens).isoformat() if last_seens else None,
    }


# ============================================================================
# THREAT FEED ENDPOINTS
# ============================================================================


@router.post("/feeds", response_model=ThreatFeedResponse, status_code=status.HTTP_201_CREATED)
async def create_threat_feed(
    feed_data: ThreatFeedCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> ThreatFeedResponse:
    """
    Create a new threat feed.

    Requires admin privileges.
    """
    user = await get_current_admin_user(current_user, db) if hasattr(current_user, "is_admin") else current_user

    feed = ThreatFeed(
        id=str(uuid.uuid4()),
        **feed_data.model_dump(),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(feed)
    await db.flush()
    await db.refresh(feed)
    return feed


@router.get("/feeds", response_model=ThreatFeedListResponse, operation_id="list_threat_feeds")
async def list_threat_feeds(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    is_enabled: Optional[bool] = None,
    provider: Optional[str] = None,
    search: Optional[str] = None,
) -> ThreatFeedListResponse:
    """
    List threat feeds with filtering and pagination.
    """
    query = select(ThreatFeed).where(ThreatFeed.organization_id == getattr(current_user, "organization_id", None))

    if is_enabled is not None:
        query = query.where(ThreatFeed.is_enabled == is_enabled)
    if provider:
        query = query.where(ThreatFeed.provider == provider)
    if search:
        query = query.where(
            or_(
                ThreatFeed.name.ilike(f"%{search}%"),
                ThreatFeed.description.ilike(f"%{search}%"),
            )
        )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    pages = math.ceil(total / size) if total > 0 else 0

    query = query.offset((page - 1) * size).limit(size).order_by(desc(ThreatFeed.created_at))
    result = await db.execute(query)
    items = result.scalars().all()

    return ThreatFeedListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/feeds/{feed_id}", response_model=ThreatFeedResponse, operation_id="get_threat_feed")
async def get_threat_feed(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> ThreatFeedResponse:
    """
    Get threat feed details.
    """
    result = await db.execute(
        select(ThreatFeed).where(
            and_(ThreatFeed.id == feed_id, ThreatFeed.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    return feed


@router.put("/feeds/{feed_id}", response_model=ThreatFeedResponse, operation_id="update_threat_feed")
async def update_threat_feed(
    feed_update: ThreatFeedUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> ThreatFeedResponse:
    """
    Update a threat feed.

    Requires admin privileges.
    """
    user = await get_current_admin_user(current_user, db) if hasattr(current_user, "is_admin") else current_user

    result = await db.execute(
        select(ThreatFeed).where(
            and_(ThreatFeed.id == feed_id, ThreatFeed.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    for field, value in feed_update.model_dump(exclude_unset=True).items():
        setattr(feed, field, value)

    await db.flush()
    await db.refresh(feed)
    return feed


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_threat_feed")
async def delete_threat_feed(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> None:
    """
    Delete a threat feed.

    Requires admin privileges.
    """
    user = await get_current_admin_user(current_user, db) if hasattr(current_user, "is_admin") else current_user

    result = await db.execute(
        select(ThreatFeed).where(
            and_(ThreatFeed.id == feed_id, ThreatFeed.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    await db.delete(feed)
    await db.flush()


@router.post("/feeds/{feed_id}/poll", response_model=None, operation_id="poll_threat_feed")
async def poll_threat_feed(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """
    Trigger a manual poll of a threat feed.

    Requires admin privileges.
    """
    user = await get_current_admin_user(current_user, db) if hasattr(current_user, "is_admin") else current_user

    result = await db.execute(
        select(ThreatFeed).where(
            and_(ThreatFeed.id == feed_id, ThreatFeed.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    feed.last_poll_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(feed)

    return {"status": "poll_scheduled", "feed_id": feed_id}


@router.post("/feeds/{feed_id}/sync", response_model=None, operation_id="sync_threat_feed")
async def sync_threat_feed(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """
    Trigger a sync (alias for poll) of a threat feed.
    The frontend calls /feeds/{feed_id}/sync.
    """
    return await poll_threat_feed(current_user=current_user, db=db, feed_id=feed_id)


@router.post("/feeds/register-builtins", response_model=None, operation_id="register_builtin_feeds")
async def register_builtin_feeds(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Register built-in threat feeds.

    Requires admin privileges.
    """
    user = await get_current_admin_user(current_user, db) if hasattr(current_user, "is_admin") else current_user

    builtin_feeds = [
        {
            "name": "AlienVault OTX",
            "feed_type": "json",
            "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "provider": "AlienVault",
            "description": "Open Threat Exchange community threat intelligence",
            "is_builtin": True,
            "poll_interval_minutes": 60,
        },
        {
            "name": "Abuse.ch URLhaus",
            "feed_type": "csv",
            "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "provider": "abuse.ch",
            "description": "URLhaus malicious URL feed",
            "is_builtin": True,
            "poll_interval_minutes": 30,
        },
        {
            "name": "Abuse.ch ThreatFox",
            "feed_type": "json",
            "url": "https://threatfox-api.abuse.ch/api/v1/",
            "provider": "abuse.ch",
            "description": "ThreatFox IOC feed",
            "is_builtin": True,
            "poll_interval_minutes": 60,
        },
    ]

    registered_count = 0
    for feed_def in builtin_feeds:
        # Check if already registered
        existing = await db.execute(
            select(ThreatFeed).where(
                and_(
                    ThreatFeed.name == feed_def["name"],
                    ThreatFeed.organization_id == getattr(current_user, "organization_id", None),
                )
            )
        )
        if existing.scalars().first():
            continue

        feed = ThreatFeed(
            id=str(uuid.uuid4()),
            organization_id=getattr(current_user, "organization_id", None),
            **feed_def,
        )
        db.add(feed)
        registered_count += 1

    await db.flush()
    return {"status": "feeds_registered", "count": registered_count}


@router.get("/feeds/{feed_id}/stats", response_model=None, operation_id="get_feed_stats")
async def get_feed_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """
    Get statistics for a threat feed.
    """
    result = await db.execute(
        select(ThreatFeed).where(
            and_(ThreatFeed.id == feed_id, ThreatFeed.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    total_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(ThreatIndicator.feed_id == feed_id)
        )
    ).scalar() or 0

    active_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                and_(ThreatIndicator.feed_id == feed_id, ThreatIndicator.is_active == True)
            )
        )
    ).scalar() or 0

    return {
        "feed_id": feed_id,
        "total_indicators": total_indicators,
        "active_indicators": active_indicators,
        "last_poll_at": feed.last_poll_at.isoformat() if feed.last_poll_at else None,
        "last_success_at": feed.last_success_at.isoformat() if feed.last_success_at else None,
    }


# ============================================================================
# THREAT INDICATOR ENDPOINTS
# ============================================================================


@router.post("/indicators", response_model=ThreatIndicatorResponse, status_code=status.HTTP_201_CREATED)
async def create_indicator(
    indicator_data: ThreatIndicatorCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> ThreatIndicatorResponse:
    """
    Create a new threat indicator.
    """
    indicator = ThreatIndicator(
        id=str(uuid.uuid4()),
        **indicator_data.model_dump(),
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(indicator)
    await db.flush()
    await db.refresh(indicator)
    return indicator


@router.post("/indicators/bulk", response_model=None, status_code=status.HTTP_201_CREATED, operation_id="bulk_import_indicators")
async def bulk_import_indicators(
    import_data: BulkIndicatorImport,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Bulk import threat indicators.
    """
    now = datetime.now(timezone.utc)
    created_count = 0
    errors = []

    for idx, ind_data in enumerate(import_data.indicators):
        try:
            indicator = ThreatIndicator(
                id=str(uuid.uuid4()),
                **ind_data.model_dump(),
                feed_id=import_data.feed_id,
                first_seen=now,
                last_seen=now,
                organization_id=getattr(current_user, "organization_id", None),
            )
            # Override source with the bulk import source if not set on individual indicator
            if not indicator.source:
                indicator.source = import_data.source
            db.add(indicator)
            created_count += 1
        except Exception as e:
            errors.append({"index": idx, "error": str(e)})

    await db.flush()

    return {
        "status": "imported",
        "count": created_count,
        "errors": errors,
        "source": import_data.source,
    }


@router.get("/indicators", response_model=ThreatIndicatorListResponse, operation_id="list_indicators")
async def list_indicators(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    indicator_type: Optional[str] = None,
    severity: Optional[str] = None,
    tlp: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_whitelisted: Optional[bool] = None,
    search: Optional[str] = None,
    tags: Optional[list[str]] = Query(None),
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> ThreatIndicatorListResponse:
    """
    List threat indicators with advanced filtering and pagination.
    """
    query = select(ThreatIndicator).where(ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))

    if indicator_type:
        query = query.where(ThreatIndicator.indicator_type == indicator_type)
    if severity:
        query = query.where(ThreatIndicator.severity == severity)
    if tlp:
        query = query.where(ThreatIndicator.tlp == tlp)
    if is_active is not None:
        query = query.where(ThreatIndicator.is_active == is_active)
    if is_whitelisted is not None:
        query = query.where(ThreatIndicator.is_whitelisted == is_whitelisted)
    if search:
        query = query.where(
            or_(
                ThreatIndicator.value.ilike(f"%{search}%"),
                ThreatIndicator.source.ilike(f"%{search}%"),
            )
        )
    if min_confidence is not None:
        query = query.where(ThreatIndicator.confidence >= min_confidence)
    if date_from:
        query = query.where(ThreatIndicator.created_at >= date_from)
    if date_to:
        query = query.where(ThreatIndicator.created_at <= date_to)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    pages = math.ceil(total / size) if total > 0 else 0

    # Apply sorting
    sort_column = getattr(ThreatIndicator, sort_by, ThreatIndicator.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    query = query.offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    items = result.scalars().all()

    return ThreatIndicatorListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/indicators/{indicator_id}", response_model=ThreatIndicatorResponse, operation_id="get_indicator")
async def get_indicator(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> ThreatIndicatorResponse:
    """
    Get a specific threat indicator.
    """
    result = await db.execute(
        select(ThreatIndicator).where(
            and_(ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    return indicator


@router.put("/indicators/{indicator_id}", response_model=ThreatIndicatorResponse, operation_id="update_indicator")
async def update_indicator(
    indicator_update: ThreatIndicatorUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> ThreatIndicatorResponse:
    """
    Update a threat indicator.
    """
    result = await db.execute(
        select(ThreatIndicator).where(
            and_(ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    for field, value in indicator_update.model_dump(exclude_unset=True).items():
        setattr(indicator, field, value)

    await db.flush()
    await db.refresh(indicator)
    return indicator


@router.delete("/indicators/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_indicator")
async def delete_indicator(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> None:
    """
    Delete a threat indicator.
    """
    result = await db.execute(
        select(ThreatIndicator).where(
            and_(ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    await db.delete(indicator)
    await db.flush()


@router.post("/indicators/{indicator_id}/enrich", response_model=None, operation_id="enrich_indicator")
async def enrich_indicator(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> dict:
    """
    Trigger enrichment for a threat indicator.
    """
    result = await db.execute(
        select(ThreatIndicator).where(
            and_(ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    # Mark as enrichment pending in context
    enrichment_data = indicator.context or {}
    enrichment_data["enrichment_status"] = "scheduled"
    enrichment_data["enrichment_requested_at"] = datetime.now(timezone.utc).isoformat()
    indicator.context = enrichment_data

    await db.flush()
    await db.refresh(indicator)

    return {
        "status": "enrichment_scheduled",
        "indicator_id": indicator_id,
    }


@router.post("/indicators/{indicator_id}/whitelist", response_model=ThreatIndicatorResponse, operation_id="whitelist_indicator")
async def whitelist_indicator(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> ThreatIndicatorResponse:
    """
    Whitelist a threat indicator.
    """
    result = await db.execute(
        select(ThreatIndicator).where(
            and_(ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    indicator.is_whitelisted = True
    indicator.is_active = False

    await db.flush()
    await db.refresh(indicator)
    return indicator


@router.get("/indicators/{indicator_id}/timeline", response_model=None, operation_id="get_indicator_timeline")
async def get_indicator_timeline(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> list:
    """
    Get the timeline/history for a threat indicator.
    """
    # Verify indicator exists and belongs to user's org
    result = await db.execute(
        select(ThreatIndicator).where(
            and_(ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    # Get sightings as timeline events
    sightings_result = await db.execute(
        select(IndicatorSighting)
        .where(IndicatorSighting.indicator_id == indicator_id)
        .order_by(desc(IndicatorSighting.created_at))
    )
    sightings = sightings_result.scalars().all()

    timeline = []
    # Add creation event
    timeline.append({
        "event_type": "created",
        "timestamp": indicator.created_at.isoformat() if indicator.created_at else None,
        "details": {"source": indicator.source, "indicator_type": indicator.indicator_type},
    })

    # Add sighting events
    for sighting in sightings:
        timeline.append({
            "event_type": "sighting",
            "timestamp": sighting.created_at.isoformat() if sighting.created_at else None,
            "details": {
                "source": sighting.source,
                "sighting_type": sighting.sighting_type,
                "context": sighting.context,
            },
        })

    # Sort by timestamp descending
    timeline.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return timeline


@router.post("/indicators/search", response_model=ThreatIndicatorListResponse, operation_id="advanced_search_indicators")
async def advanced_search_indicators(
    search_request: IntelSearchRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> ThreatIndicatorListResponse:
    """
    Perform advanced search on threat indicators.
    """
    query = select(ThreatIndicator).where(ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))

    if search_request.query:
        query = query.where(
            or_(
                ThreatIndicator.value.ilike(f"%{search_request.query}%"),
                ThreatIndicator.source.ilike(f"%{search_request.query}%"),
            )
        )
    if search_request.indicator_types:
        query = query.where(ThreatIndicator.indicator_type.in_(search_request.indicator_types))
    if search_request.severity:
        query = query.where(ThreatIndicator.severity.in_(search_request.severity))
    if search_request.tlp:
        query = query.where(ThreatIndicator.tlp.in_(search_request.tlp))
    if search_request.is_active is not None:
        query = query.where(ThreatIndicator.is_active == search_request.is_active)
    if search_request.min_confidence is not None:
        query = query.where(ThreatIndicator.confidence >= search_request.min_confidence)
    if search_request.date_from:
        query = query.where(ThreatIndicator.created_at >= search_request.date_from)
    if search_request.date_to:
        query = query.where(ThreatIndicator.created_at <= search_request.date_to)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    pages = math.ceil(total / size) if total > 0 else 0

    query = query.offset((page - 1) * size).limit(size).order_by(desc(ThreatIndicator.created_at))
    result = await db.execute(query)
    items = result.scalars().all()

    return ThreatIndicatorListResponse(items=items, total=total, page=page, size=size, pages=pages)


# ============================================================================
# SIGHTING ENDPOINTS
# ============================================================================


@router.post("/sightings", response_model=IndicatorSightingResponse, status_code=status.HTTP_201_CREATED, operation_id="record_sighting")
async def record_sighting(
    sighting_data: IndicatorSightingCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> IndicatorSightingResponse:
    """
    Record a new sighting for a threat indicator.
    """
    # Verify the indicator exists
    result = await db.execute(
        select(ThreatIndicator).where(
            and_(
                ThreatIndicator.id == sighting_data.indicator_id,
                ThreatIndicator.organization_id == getattr(current_user, "organization_id", None),
            )
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    sighting = IndicatorSighting(
        id=str(uuid.uuid4()),
        **sighting_data.model_dump(),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(sighting)

    # Update indicator sighting tracking
    indicator.sighting_count = (indicator.sighting_count or 0) + 1
    indicator.last_sighting_at = datetime.now(timezone.utc)
    indicator.last_seen = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(sighting)
    return sighting


@router.get("/indicators/{indicator_id}/sightings", response_model=list[IndicatorSightingResponse], operation_id="get_indicator_sightings")
async def get_indicator_sightings(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> list[IndicatorSightingResponse]:
    """
    Get sightings for a specific threat indicator.
    """
    # Verify the indicator exists and belongs to user's org
    ind_result = await db.execute(
        select(ThreatIndicator).where(
            and_(ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    if not ind_result.scalars().first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    query = (
        select(IndicatorSighting)
        .where(IndicatorSighting.indicator_id == indicator_id)
        .order_by(desc(IndicatorSighting.created_at))
        .offset((page - 1) * size)
        .limit(size)
    )
    result = await db.execute(query)
    sightings = result.scalars().all()
    return sightings


# ============================================================================
# THREAT ACTOR ENDPOINTS
# ============================================================================


@router.post("/actors", response_model=ThreatActorResponse, status_code=status.HTTP_201_CREATED, operation_id="create_actor")
async def create_actor(
    actor_data: ThreatActorCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> ThreatActorResponse:
    """
    Create a new threat actor.
    """
    actor = ThreatActor(
        id=str(uuid.uuid4()),
        **actor_data.model_dump(),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(actor)
    await db.flush()
    await db.refresh(actor)
    return actor


@router.get("/actors", response_model=ThreatActorListResponse, operation_id="list_actors")
async def list_actors(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    country: Optional[str] = None,
    actor_type: Optional[str] = None,
    tags: Optional[list[str]] = Query(None),
) -> ThreatActorListResponse:
    """
    List threat actors with filtering and pagination.
    """
    query = select(ThreatActor).where(ThreatActor.organization_id == getattr(current_user, "organization_id", None))

    if search:
        query = query.where(
            or_(
                ThreatActor.name.ilike(f"%{search}%"),
                ThreatActor.description.ilike(f"%{search}%"),
            )
        )
    if country:
        query = query.where(ThreatActor.country_of_origin == country)
    if actor_type:
        query = query.where(ThreatActor.actor_type == actor_type)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    pages = math.ceil(total / size) if total > 0 else 0

    query = query.offset((page - 1) * size).limit(size).order_by(desc(ThreatActor.created_at))
    result = await db.execute(query)
    items = result.scalars().all()

    return ThreatActorListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/actors/{actor_id}", response_model=ThreatActorResponse, operation_id="get_actor")
async def get_actor(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    actor_id: str = Path(...),
) -> ThreatActorResponse:
    """
    Get threat actor details with associated campaigns and indicators.
    """
    result = await db.execute(
        select(ThreatActor).where(
            and_(ThreatActor.id == actor_id, ThreatActor.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    actor = result.scalars().first()
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")
    return actor


@router.put("/actors/{actor_id}", response_model=ThreatActorResponse, operation_id="update_actor")
async def update_actor(
    actor_update: ThreatActorUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    actor_id: str = Path(...),
) -> ThreatActorResponse:
    """
    Update a threat actor.
    """
    result = await db.execute(
        select(ThreatActor).where(
            and_(ThreatActor.id == actor_id, ThreatActor.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    actor = result.scalars().first()
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")

    for field, value in actor_update.model_dump(exclude_unset=True).items():
        setattr(actor, field, value)

    await db.flush()
    await db.refresh(actor)
    return actor


@router.delete("/actors/{actor_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_actor")
async def delete_actor(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    actor_id: str = Path(...),
) -> None:
    """
    Delete a threat actor.
    """
    result = await db.execute(
        select(ThreatActor).where(
            and_(ThreatActor.id == actor_id, ThreatActor.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    actor = result.scalars().first()
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")

    await db.delete(actor)
    await db.flush()


# ============================================================================
# THREAT CAMPAIGN ENDPOINTS
# ============================================================================


@router.post("/campaigns", response_model=ThreatCampaignResponse, status_code=status.HTTP_201_CREATED, operation_id="create_campaign")
async def create_campaign(
    campaign_data: ThreatCampaignCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> ThreatCampaignResponse:
    """
    Create a new threat campaign.
    """
    campaign = ThreatCampaign(
        id=str(uuid.uuid4()),
        **campaign_data.model_dump(),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(campaign)
    await db.flush()
    await db.refresh(campaign)
    return campaign


@router.get("/campaigns", response_model=ThreatCampaignListResponse, operation_id="list_campaigns")
async def list_campaigns(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    search: Optional[str] = None,
    tags: Optional[list[str]] = Query(None),
) -> ThreatCampaignListResponse:
    """
    List threat campaigns with filtering and pagination.
    """
    query = select(ThreatCampaign).where(ThreatCampaign.organization_id == getattr(current_user, "organization_id", None))

    if status:
        query = query.where(ThreatCampaign.status == status)
    if search:
        query = query.where(
            or_(
                ThreatCampaign.name.ilike(f"%{search}%"),
                ThreatCampaign.description.ilike(f"%{search}%"),
            )
        )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    pages = math.ceil(total / size) if total > 0 else 0

    query = query.offset((page - 1) * size).limit(size).order_by(desc(ThreatCampaign.created_at))
    result = await db.execute(query)
    items = result.scalars().all()

    return ThreatCampaignListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/campaigns/{campaign_id}", response_model=ThreatCampaignResponse, operation_id="get_campaign")
async def get_campaign(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    campaign_id: str = Path(...),
) -> ThreatCampaignResponse:
    """
    Get threat campaign details.
    """
    result = await db.execute(
        select(ThreatCampaign).where(
            and_(ThreatCampaign.id == campaign_id, ThreatCampaign.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    return campaign


@router.put("/campaigns/{campaign_id}", response_model=ThreatCampaignResponse, operation_id="update_campaign")
async def update_campaign(
    campaign_update: ThreatCampaignUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    campaign_id: str = Path(...),
) -> ThreatCampaignResponse:
    """
    Update a threat campaign.
    """
    result = await db.execute(
        select(ThreatCampaign).where(
            and_(ThreatCampaign.id == campaign_id, ThreatCampaign.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    for field, value in campaign_update.model_dump(exclude_unset=True).items():
        setattr(campaign, field, value)

    await db.flush()
    await db.refresh(campaign)
    return campaign


@router.delete("/campaigns/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_campaign")
async def delete_campaign(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    campaign_id: str = Path(...),
) -> None:
    """
    Delete a threat campaign.
    """
    result = await db.execute(
        select(ThreatCampaign).where(
            and_(ThreatCampaign.id == campaign_id, ThreatCampaign.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    await db.delete(campaign)
    await db.flush()


# ============================================================================
# INTEL REPORT ENDPOINTS
# ============================================================================


@router.post("/reports", response_model=IntelReportResponse, status_code=status.HTTP_201_CREATED, operation_id="create_report")
async def create_report(
    report_data: IntelReportCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> IntelReportResponse:
    """
    Create a new intel report.
    """
    report = IntelReport(
        id=str(uuid.uuid4()),
        **report_data.model_dump(),
        author_id=current_user.id,
        status="draft",
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return report


@router.get("/reports", response_model=IntelReportListResponse, operation_id="list_reports")
async def list_reports(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    report_type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    tags: Optional[list[str]] = Query(None),
) -> IntelReportListResponse:
    """
    List intel reports with filtering and pagination.
    """
    query = select(IntelReport).where(IntelReport.organization_id == getattr(current_user, "organization_id", None))

    if report_type:
        query = query.where(IntelReport.report_type == report_type)
    if status:
        query = query.where(IntelReport.status == status)
    if search:
        query = query.where(
            or_(
                IntelReport.title.ilike(f"%{search}%"),
                IntelReport.executive_summary.ilike(f"%{search}%"),
            )
        )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    pages = math.ceil(total / size) if total > 0 else 0

    query = query.offset((page - 1) * size).limit(size).order_by(desc(IntelReport.created_at))
    result = await db.execute(query)
    items = result.scalars().all()

    return IntelReportListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/reports/{report_id}", response_model=IntelReportResponse, operation_id="get_report")
async def get_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> IntelReportResponse:
    """
    Get a specific intel report.
    """
    result = await db.execute(
        select(IntelReport).where(
            and_(IntelReport.id == report_id, IntelReport.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.put("/reports/{report_id}", response_model=IntelReportResponse, operation_id="update_report")
async def update_report(
    report_update: IntelReportUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> IntelReportResponse:
    """
    Update an intel report.
    """
    result = await db.execute(
        select(IntelReport).where(
            and_(IntelReport.id == report_id, IntelReport.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    for field, value in report_update.model_dump(exclude_unset=True).items():
        setattr(report, field, value)

    await db.flush()
    await db.refresh(report)
    return report


@router.post("/reports/{report_id}/publish", response_model=IntelReportResponse, operation_id="publish_report")
async def publish_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> IntelReportResponse:
    """
    Publish an intel report.
    """
    result = await db.execute(
        select(IntelReport).where(
            and_(IntelReport.id == report_id, IntelReport.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    report.status = "published"
    report.published_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(report)
    return report


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_report")
async def delete_report(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> None:
    """
    Delete an intel report.
    """
    result = await db.execute(
        select(IntelReport).where(
            and_(IntelReport.id == report_id, IntelReport.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    await db.delete(report)
    await db.flush()


# ============================================================================
# DASHBOARD AND EXPORT ENDPOINTS
# ============================================================================


@router.get("/dashboard", response_model=IntelDashboardStats, operation_id="get_dashboard_stats")
async def get_dashboard_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> IntelDashboardStats:
    """
    Get threat intelligence dashboard statistics.
    """
    org_id = getattr(current_user, "organization_id", None)

    # Total indicators
    total_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(ThreatIndicator.organization_id == org_id)
        )
    ).scalar() or 0

    # Active indicators
    active_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                and_(ThreatIndicator.organization_id == org_id, ThreatIndicator.is_active == True)
            )
        )
    ).scalar() or 0

    # Feeds
    feeds_total = (
        await db.execute(
            select(func.count(ThreatFeed.id)).where(ThreatFeed.organization_id == org_id)
        )
    ).scalar() or 0

    feeds_enabled = (
        await db.execute(
            select(func.count(ThreatFeed.id)).where(
                and_(ThreatFeed.organization_id == org_id, ThreatFeed.is_enabled == True)
            )
        )
    ).scalar() or 0

    # Indicators by type
    type_result = await db.execute(
        select(ThreatIndicator.indicator_type, func.count(ThreatIndicator.id))
        .where(ThreatIndicator.organization_id == org_id)
        .group_by(ThreatIndicator.indicator_type)
    )
    indicators_by_type = dict(type_result.all())

    # Indicators by severity
    severity_result = await db.execute(
        select(ThreatIndicator.severity, func.count(ThreatIndicator.id))
        .where(ThreatIndicator.organization_id == org_id)
        .group_by(ThreatIndicator.severity)
    )
    indicators_by_severity = dict(severity_result.all())

    # Recent sightings (last 7 days)
    from datetime import timedelta
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_sightings = (
        await db.execute(
            select(func.count(IndicatorSighting.id)).where(
                and_(
                    IndicatorSighting.organization_id == org_id,
                    IndicatorSighting.created_at >= seven_days_ago,
                )
            )
        )
    ).scalar() or 0

    # Actors tracked
    actors_tracked = (
        await db.execute(
            select(func.count(ThreatActor.id)).where(ThreatActor.organization_id == org_id)
        )
    ).scalar() or 0

    # Active campaigns
    active_campaigns = (
        await db.execute(
            select(func.count(ThreatCampaign.id)).where(
                and_(ThreatCampaign.organization_id == org_id, ThreatCampaign.status == "active")
            )
        )
    ).scalar() or 0

    # Coverage score: simple heuristic based on feed count and indicator count
    coverage_score = min(100.0, (feeds_enabled * 10.0) + (min(total_indicators, 1000) / 10.0))

    return IntelDashboardStats(
        total_indicators=total_indicators,
        active_indicators=active_indicators,
        feeds_enabled=feeds_enabled,
        feeds_total=feeds_total,
        indicators_by_type=indicators_by_type,
        indicators_by_severity=indicators_by_severity,
        recent_sightings=recent_sightings,
        actors_tracked=actors_tracked,
        active_campaigns=active_campaigns,
        top_tags=[],  # Would require JSON array aggregation which is DB-specific
        coverage_score=coverage_score,
    )


@router.get("/export", response_model=None, operation_id="export_indicators")
async def export_indicators(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    format: str = Query("json", description="json, csv, stix"),
    indicator_types: Optional[list[str]] = Query(None),
    severity: Optional[list[str]] = Query(None),
    tags: Optional[list[str]] = Query(None),
) -> dict:
    """
    Export threat indicators in various formats (JSON, CSV, STIX).
    """
    if format not in ["json", "csv", "stix"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid export format. Must be json, csv, or stix",
        )

    query = select(ThreatIndicator).where(ThreatIndicator.organization_id == getattr(current_user, "organization_id", None))

    if indicator_types:
        query = query.where(ThreatIndicator.indicator_type.in_(indicator_types))
    if severity:
        query = query.where(ThreatIndicator.severity.in_(severity))

    query = query.where(ThreatIndicator.is_active == True).order_by(desc(ThreatIndicator.created_at))
    result = await db.execute(query)
    indicators = result.scalars().all()

    export_data = []
    for ind in indicators:
        export_data.append({
            "id": ind.id,
            "indicator_type": ind.indicator_type,
            "value": ind.value,
            "source": ind.source,
            "confidence": ind.confidence,
            "severity": ind.severity,
            "tlp": ind.tlp,
            "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
            "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
            "tags": ind.tags,
            "mitre_tactics": ind.mitre_tactics,
            "mitre_techniques": ind.mitre_techniques,
        })

    return {
        "format": format,
        "count": len(export_data),
        "indicators": export_data,
    }
