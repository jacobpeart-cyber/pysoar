"""Threat Intelligence Platform API endpoints

Tenancy (wave 1, docs/audit/2026-10-08/PLAN.md):

* Feeds, indicators, sightings, actors, campaigns and reports are owned by an
  organisation: every query filters on the caller's ``OrganizationId`` and
  every created row is stamped with it. Lookups by id outside the tenant 404.
* NULL-organisation convention: ``organization_id IS NULL`` marks PLATFORM
  intel, i.e. the built-in feeds registered at startup and the indicators the
  system-wide feed poll ingests for them (see ``src/intel/feeds.py``). Reads
  of feeds and indicators (list / get / search / lookup / export / stats)
  return the caller's rows PLUS platform rows. Platform rows are read-only to
  tenants: update / delete / enrich / whitelist / poll answer 403
  ``platform_intel_read_only``. Only a platform superuser manages them
  (``POST /feeds/register-builtins``, ``POST /feeds/poll-all``).
* Roles: feed configuration and polling require ``admin``; indicator,
  sighting, actor, campaign and report writes require ``analyst`` or
  ``admin``; viewers are read-only.
"""

import csv
import io
import logging
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Path, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import String, and_, cast, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    PlatformSuperUser,
    require_role,
)
from src.intel import providers as intel_providers
from src.intel.models import (
    IndicatorSighting,
    IntelReport,
    ThreatActor,
    ThreatCampaign,
    ThreatFeed,
    ThreatIndicator,
)
from src.models.user import User, UserRole

logger = logging.getLogger(__name__)

# Role gates (viewers are read-only on every route below).
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

#: Row cap for GET /export.
EXPORT_MAX_ROWS = 50_000
#: Indicators counted for the dashboard's top tags.
TOP_TAGS_SAMPLE = 5_000

# ---------------------------------------------------------------------------
# External enrichment (VirusTotal / AbuseIPDB / AlienVault OTX)
# ---------------------------------------------------------------------------
# Keys, caching, the outbound guard and provider error reporting live in
# ``src/intel/providers.py`` (shared with indicator enrichment and the IOC
# router). Results are cached per organisation for an hour.


def _external_sources(outcomes: list[intel_providers.ProviderOutcome]) -> list[dict[str, Any]]:
    """``external_sources`` entries: one per provider that answered or failed."""
    sources: list[dict[str, Any]] = []
    for outcome in outcomes:
        if outcome.status == "ok" and outcome.result is not None:
            entry = dict(outcome.result)
            entry["cached"] = outcome.cached
            entry["key_source"] = outcome.key_source
            # The UI reads ``details``; ``raw`` is kept for existing clients.
            entry.setdefault("details", entry.get("raw"))
            sources.append(entry)
        elif outcome.status == "error":
            sources.append({
                "name": outcome.provider,
                "verdict": "error",
                "confidence": 0,
                "error": outcome.error,
                "key_source": outcome.key_source,
            })
    return sources


def _external_errors(outcomes: list[intel_providers.ProviderOutcome]) -> list[str]:
    errors: list[str] = []
    for outcome in outcomes:
        if outcome.status == "error":
            errors.append(f"{outcome.provider}: {outcome.error}")
        elif outcome.status == "credentials_unreadable":
            errors.append(f"{outcome.provider}: credentials_unreadable")
    return errors


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
# TENANCY HELPERS
# ============================================================================
# NULL-organisation convention: a feed or indicator with organization_id NULL
# is platform intel (built-in feeds and what the system-wide poll ingests for
# them). Tenants read it alongside their own rows but can never modify it.


def _visible_to(model: Any, org_id: str) -> Any:
    """Rows of ``model`` the tenant may read: its own plus platform (NULL) rows."""
    return or_(model.organization_id == org_id, model.organization_id.is_(None))


def _platform_read_only(kind: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "platform_intel_read_only",
            "detail": f"this {kind} is platform-wide threat intel and is read-only to tenants",
        },
    )


async def _get_visible_feed_or_404(db: AsyncSession, feed_id: str, org_id: str) -> ThreatFeed:
    result = await db.execute(
        select(ThreatFeed).where(ThreatFeed.id == feed_id, _visible_to(ThreatFeed, org_id))
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    return feed


async def _get_owned_feed(db: AsyncSession, feed_id: str, org_id: str) -> ThreatFeed:
    """The caller's own feed: 404 outside the tenant, 403 for a platform feed."""
    feed = await _get_visible_feed_or_404(db, feed_id, org_id)
    if feed.organization_id is None:
        raise _platform_read_only("feed")
    return feed


async def _get_visible_indicator_or_404(
    db: AsyncSession, indicator_id: str, org_id: str
) -> ThreatIndicator:
    result = await db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.id == indicator_id, _visible_to(ThreatIndicator, org_id)
        )
    )
    indicator = result.scalars().first()
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    return indicator


async def _get_owned_indicator(
    db: AsyncSession, indicator_id: str, org_id: str
) -> ThreatIndicator:
    """The caller's own indicator: 404 outside the tenant, 403 for platform intel."""
    indicator = await _get_visible_indicator_or_404(db, indicator_id, org_id)
    if indicator.organization_id is None:
        raise _platform_read_only("indicator")
    return indicator


# ============================================================================
# STATS AND LOOKUP ENDPOINTS (consumed by frontend ThreatIntel.tsx)
# ============================================================================


@router.get("/stats", response_model=None, operation_id="get_threat_intel_stats")
async def get_threat_intel_stats(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Get threat intelligence stats for the frontend dashboard cards.

    Counts the caller's own feeds/indicators plus platform (NULL-org) intel.
    """

    def org_filter(model):
        return _visible_to(model, org_id)

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
                    ThreatIndicator.indicator_type.in_(["ipv4", "ipv6", "ip", "cidr"]),
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """Look up an IOC locally and enrich it with external providers.

    1. Local match in ``threat_indicators`` (own plus platform intel). A UI
       type such as ``ip`` or ``hash`` matches every stored variant
       (``ipv4``/``ipv6``/``cidr``, ``md5``/``sha1``/``sha256``).
    2. External enrichment through ``src/intel/providers.py``: VirusTotal
       (ip, domain, url, hash), AbuseIPDB (ip) and AlienVault OTX (ip,
       domain, url, hash), with the organisation's keys or the platform's.
       ``providers`` reports each provider's state (``ok``,
       ``not_configured``, ``credentials_unreadable``, ``error``,
       ``unsupported_type``); ``not_configured`` lists the providers that
       apply but have no key. Errors are listed, never dropped.

    Frontend POSTs ``{ indicator: string, type: string }``.
    """
    indicator_value = (payload.get("indicator") or "").strip()
    indicator_type = (payload.get("type") or "auto").strip() or "auto"

    if not indicator_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="indicator is required",
        )

    # Query matching indicators in the local DB: own plus platform intel.
    query = select(ThreatIndicator).where(
        and_(
            _visible_to(ThreatIndicator, org_id),
            ThreatIndicator.value == indicator_value,
        )
    )
    if indicator_type != "auto":
        query = query.where(
            ThreatIndicator.indicator_type.in_(intel_providers.type_variants(indicator_type))
        )

    result = await db.execute(query.order_by(desc(ThreatIndicator.last_seen)).limit(100))
    indicators = result.scalars().all()

    severity_to_reputation = {
        "critical": "malicious",
        "high": "malicious",
        "medium": "suspicious",
        "low": "clean",
        "informational": "clean",
    }

    # --- Local result -------------------------------------------------------
    if indicators:
        best = indicators[0]
        local_reputation = severity_to_reputation.get(best.severity or "", "unknown")
        local_confidence = best.confidence or 0
        resolved_type = best.indicator_type or indicator_type
        local_sources = [
            {
                "name": ind.source or "Internal",
                "verdict": severity_to_reputation.get(ind.severity or "", "unknown"),
                "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
                "platform_intel": ind.organization_id is None,
            }
            for ind in indicators
        ]
        all_tags: list[str] = []
        for ind in indicators:
            all_tags.extend(ind.tags or [])
        unique_tags = list(dict.fromkeys(all_tags))
        first_seens = [ind.first_seen for ind in indicators if ind.first_seen]
        last_seens = [ind.last_seen for ind in indicators if ind.last_seen]
        first_seen_iso = min(first_seens).isoformat() if first_seens else None
        last_seen_iso = max(last_seens).isoformat() if last_seens else None
    else:
        local_reputation = "unknown"
        local_confidence = 0
        resolved_type = indicator_type
        local_sources = []
        unique_tags = []
        first_seen_iso = None
        last_seen_iso = None

    # --- External enrichment -----------------------------------------------
    if resolved_type in ("", "auto"):
        resolved_type = intel_providers.detect_type(indicator_value)
    dispatch_type = intel_providers.dispatch_bucket(resolved_type)

    outcomes = await intel_providers.enrich_value(db, org_id, dispatch_type, indicator_value)
    external_sources = _external_sources(outcomes)
    external_errors = _external_errors(outcomes)
    external_status = intel_providers.overall_status(outcomes)

    # --- Merge: prefer local reputation; escalate if external is worse -----
    verdict_rank = {
        "malicious": 4,
        "suspicious": 3,
        "low_risk": 2,
        "clean": 1,
        "unknown": 0,
        "unsupported": 0,
        "error": 0,
    }
    merged_reputation = local_reputation
    merged_confidence = local_confidence
    for src in external_sources:
        v = src.get("verdict", "unknown")
        if verdict_rank.get(v, 0) > verdict_rank.get(merged_reputation, 0):
            merged_reputation = v
            merged_confidence = max(merged_confidence, int(src.get("confidence") or 0))

    return {
        "indicator": indicator_value,
        "type": resolved_type if resolved_type not in (None, "", "auto", "unknown") else dispatch_type,
        "reputation": merged_reputation,
        "confidence": merged_confidence,
        "sources": local_sources,
        "external_sources": external_sources,
        "external_enrichment": external_status,
        "external_errors": external_errors,
        "providers": [o.summary() for o in outcomes],
        "not_configured": [o.provider for o in outcomes if o.status == "not_configured"],
        "tags": unique_tags,
        "first_seen": first_seen_iso,
        "last_seen": last_seen_iso,
    }


# ============================================================================
# THREAT FEED ENDPOINTS
# ============================================================================


@router.post("/feeds", response_model=ThreatFeedResponse, status_code=status.HTTP_201_CREATED)
async def create_threat_feed(
    feed_data: ThreatFeedCreate,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> ThreatFeedResponse:
    """
    Create a new threat feed owned by the caller's organisation (admin only).
    """
    await _ensure_feed_name_free(db, feed_data.name)

    feed = ThreatFeed(
        id=str(uuid.uuid4()),
        **feed_data.model_dump(),
        organization_id=org_id,
    )
    db.add(feed)
    await db.flush()
    await db.refresh(feed)
    return feed


async def _ensure_feed_name_free(db: AsyncSession, name: str) -> None:
    """``threat_feeds.name`` is globally unique in the schema; answer 409
    instead of letting the insert fail with an IntegrityError (500)."""
    existing = await db.execute(select(ThreatFeed.id).where(ThreatFeed.name == name))
    if existing.first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "feed_name_taken", "detail": "a threat feed with this name already exists"},
        )


@router.get("/feeds", response_model=ThreatFeedListResponse, operation_id="list_threat_feeds")
async def list_threat_feeds(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    is_enabled: Optional[bool] = None,
    provider: Optional[str] = None,
    search: Optional[str] = None,
) -> ThreatFeedListResponse:
    """
    List the caller's threat feeds plus the platform (NULL-org) built-in feeds.
    """
    query = select(ThreatFeed).where(_visible_to(ThreatFeed, org_id))

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
    items = list(result.scalars().all())

    # Overlay the live indicator count from the join table so the Feeds
    # tab shows real numbers even when the counter column drifted (it
    # only gets incremented inside FeedManager.poll_feed — if rows were
    # bulk-imported by a different path the counter was stale). We
    # expunge first so the override doesn't flush back on commit.
    if items:
        feed_ids = [f.id for f in items]
        live_counts_res = await db.execute(
            select(ThreatIndicator.feed_id, func.count(ThreatIndicator.id))
            .where(
                ThreatIndicator.feed_id.in_(feed_ids),
                _visible_to(ThreatIndicator, org_id),
            )
            .group_by(ThreatIndicator.feed_id)
        )
        live_counts = {row[0]: row[1] for row in live_counts_res.all()}
        for feed in items:
            live = live_counts.get(feed.id, 0)
            if live != (feed.total_indicators or 0):
                db.expunge(feed)
                feed.total_indicators = live

    return ThreatFeedListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/feeds/{feed_id}", response_model=ThreatFeedResponse, operation_id="get_threat_feed")
async def get_threat_feed(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> ThreatFeedResponse:
    """
    Get threat feed details (own or platform feed).
    """
    return await _get_visible_feed_or_404(db, feed_id, org_id)


@router.put("/feeds/{feed_id}", response_model=ThreatFeedResponse, operation_id="update_threat_feed")
async def update_threat_feed(
    feed_update: ThreatFeedUpdate,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> ThreatFeedResponse:
    """
    Update one of the caller's threat feeds (admin only; platform feeds 403).
    """
    feed = await _get_owned_feed(db, feed_id, org_id)

    changes = feed_update.model_dump(exclude_unset=True)
    if changes.get("name") and changes["name"] != feed.name:
        await _ensure_feed_name_free(db, changes["name"])
    for field, value in changes.items():
        setattr(feed, field, value)

    await db.flush()
    await db.refresh(feed)
    return feed


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_threat_feed")
async def delete_threat_feed(
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> None:
    """
    Delete one of the caller's threat feeds (admin only; platform feeds 403).
    """
    feed = await _get_owned_feed(db, feed_id, org_id)

    await db.delete(feed)
    await db.flush()


@router.post("/feeds/{feed_id}/poll", response_model=None, operation_id="poll_threat_feed")
async def poll_threat_feed(
    background_tasks: BackgroundTasks,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """Trigger a real poll of a threat feed.

    Previously this only stamped ``last_poll_at`` without actually
    fetching. The frontend Sync button was a no-op; ``total_indicators``
    never grew. This now dispatches ``FeedManager.poll_feed(feed_id)``
    as a background task so the HTTP response returns immediately while
    the ingestion runs against its own session and writes real rows
    into ``threat_indicators``, stamped with the feed's organisation.

    Admin only. Platform (NULL-org) feeds answer 403: polling them affects
    every tenant, so only a platform superuser may (``POST /feeds/poll-all``).
    """
    feed = await _get_owned_feed(db, feed_id, org_id)
    if not feed.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Feed is disabled — enable before polling",
        )

    # Snapshot trigger timestamp on the request's session so the UI
    # reflects the click even before the background job finishes.
    feed.last_poll_at = datetime.now(timezone.utc)
    await db.flush()

    background_tasks.add_task(_run_feed_poll, feed_id)

    return {
        "status": "poll_started",
        "feed_id": feed_id,
        "feed_name": feed.name,
        "message": (
            "Feed ingestion dispatched. Indicators will appear within "
            "seconds for small feeds, minutes for large ones. Re-check "
            "total_indicators or the IOC DB tab after the job finishes."
        ),
    }


async def _run_feed_poll(feed_id: str) -> None:
    """Background poll of one feed. ``FeedManager.poll_feed`` records
    fetch/parse problems on ``feed.last_error`` (shown on the Feeds tab); an
    unexpected crash is logged with its traceback and re-raised."""
    from src.intel.feeds import FeedManager

    try:
        count = await FeedManager().poll_feed(feed_id)
    except Exception:
        logger.exception("Threat feed poll failed", extra={"feed_id": feed_id})
        raise
    logger.info(
        "Threat feed poll completed", extra={"feed_id": feed_id, "new_indicators": count}
    )


@router.post("/feeds/{feed_id}/sync", response_model=None, operation_id="sync_threat_feed")
async def sync_threat_feed(
    background_tasks: BackgroundTasks,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """Sync is an alias of poll. Wired through the same real ingestion path."""
    return await poll_threat_feed(
        background_tasks=background_tasks,
        current_user=current_user,
        org_id=org_id,
        db=db,
        feed_id=feed_id,
    )


@router.post("/feeds/register-builtins", response_model=None, operation_id="register_builtin_feeds")
async def register_builtin_feeds(
    current_user: PlatformSuperUser = None,
) -> dict:
    """
    (Re-)register the platform built-in feeds (platform superuser only).

    Built-in feeds are platform intel (organization_id NULL) that every
    tenant reads, so registering them is a platform action. This runs the
    same idempotent registration as application startup
    (``FeedManager.register_builtin_feeds``). Previously any user could call
    it, and it inserted per-tenant copies of three feeds whose names collide
    with the global ``threat_feeds.name`` unique constraint (500).
    """
    from src.intel.feeds import FeedManager

    created = await FeedManager().register_builtin_feeds()
    return {"status": "feeds_registered", "count": created}


@router.post("/feeds/poll-all", response_model=None, operation_id="poll_all_threat_feeds")
async def poll_all_threat_feeds(
    background_tasks: BackgroundTasks,
    current_user: PlatformSuperUser = None,
) -> dict:
    """Poll every enabled feed of every tenant plus the platform feeds now
    (platform superuser only). Same work as the scheduled
    ``intel.poll_threat_feeds`` task; each feed's indicators are stamped with
    that feed's organisation (NULL for platform feeds)."""
    background_tasks.add_task(_run_all_feed_polls)
    return {"status": "poll_started", "scope": "all_feeds"}


async def _run_all_feed_polls() -> None:
    from src.intel.feeds import FeedManager

    results = await FeedManager().poll_all_feeds(only_due=False)
    logger.info("Platform-wide feed poll completed", extra={"feeds": len(results)})


@router.get("/feeds/{feed_id}/stats", response_model=None, operation_id="get_feed_stats")
async def get_feed_stats(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """
    Get statistics for a threat feed (own or platform feed).
    """
    feed = await _get_visible_feed_or_404(db, feed_id, org_id)

    total_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                ThreatIndicator.feed_id == feed_id,
                _visible_to(ThreatIndicator, org_id),
            )
        )
    ).scalar() or 0

    active_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                and_(
                    ThreatIndicator.feed_id == feed_id,
                    _visible_to(ThreatIndicator, org_id),
                    ThreatIndicator.is_active == True,
                )
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
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
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
        organization_id=org_id,
    )
    db.add(indicator)
    await db.flush()
    await db.refresh(indicator)
    return indicator


@router.post("/indicators/bulk", response_model=None, status_code=status.HTTP_201_CREATED, operation_id="bulk_import_indicators")
async def bulk_import_indicators(
    import_data: BulkIndicatorImport,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Bulk import threat indicators into the caller's organisation.

    ``feed_id``, when given, must be one of the caller's own feeds.
    """
    if import_data.feed_id:
        await _get_owned_feed(db, import_data.feed_id, org_id)
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
                organization_id=org_id,
            )
            # Override source with the bulk import source if not set on individual indicator
            if not indicator.source:
                indicator.source = import_data.source
            db.add(indicator)
            created_count += 1
        except (TypeError, ValueError) as e:
            errors.append({"index": idx, "error": str(e)})

    await db.flush()

    return {
        "status": "imported",
        "count": created_count,
        "errors": errors,
        "source": import_data.source,
    }


def _with_tags(query: Any, tags: Optional[list[str]]) -> Any:
    """Indicators carrying every tag in ``tags``.

    ``tags`` is a JSON array column; matching its text form against the
    quoted tag works on PostgreSQL and SQLite alike.
    """
    for tag in tags or []:
        tag = (tag or "").strip()
        if not tag:
            continue
        escaped = tag.replace("\\", "\\\\").replace('"', '\\"')
        query = query.where(cast(ThreatIndicator.tags, String).like(f'%"{escaped}"%'))
    return query


@router.get("/indicators", response_model=ThreatIndicatorListResponse, operation_id="list_indicators")
async def list_indicators(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
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
    """List threat indicators with advanced filtering and pagination.

    ``indicator_type`` and ``severity`` accept a CSV of values so one
    UI filter can cover IP family variations (``ip,ipv4,ipv6``) and
    severity bands (``high,critical`` for "malicious"). Previously
    these were strict equality, which left ipv6 + critical rows
    unreachable from the Reputation filter.
    """
    query = select(ThreatIndicator)

    query = query.where(_visible_to(ThreatIndicator, org_id))

    if indicator_type:
        type_values = [t.strip() for t in indicator_type.split(",") if t.strip()]
        if len(type_values) == 1:
            query = query.where(ThreatIndicator.indicator_type == type_values[0])
        elif type_values:
            query = query.where(ThreatIndicator.indicator_type.in_(type_values))
    if severity:
        sev_values = [s.strip() for s in severity.split(",") if s.strip()]
        if len(sev_values) == 1:
            query = query.where(ThreatIndicator.severity == sev_values[0])
        elif sev_values:
            query = query.where(ThreatIndicator.severity.in_(sev_values))
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
    query = _with_tags(query, tags)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    pages = math.ceil(total / size) if total > 0 else 0

    # Apply sorting — whitelist sortable columns (prevent clients ordering
    # by arbitrary model attributes via the query string).
    _ALLOWED_SORTS = {
        "created_at", "updated_at", "last_seen", "first_seen",
        "severity", "confidence", "sighting_count", "indicator_type", "source",
    }
    if sort_by not in _ALLOWED_SORTS:
        sort_by = "created_at"
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> ThreatIndicatorResponse:
    """
    Get a specific threat indicator.
    """
    indicator = await _get_visible_indicator_or_404(db, indicator_id, org_id)
    return indicator


@router.put("/indicators/{indicator_id}", response_model=ThreatIndicatorResponse, operation_id="update_indicator")
async def update_indicator(
    indicator_update: ThreatIndicatorUpdate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> ThreatIndicatorResponse:
    """
    Update a threat indicator.
    """
    indicator = await _get_owned_indicator(db, indicator_id, org_id)

    for field, value in indicator_update.model_dump(exclude_unset=True).items():
        setattr(indicator, field, value)

    await db.flush()
    await db.refresh(indicator)
    return indicator


@router.delete("/indicators/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_indicator")
async def delete_indicator(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> None:
    """
    Delete a threat indicator.
    """
    indicator = await _get_owned_indicator(db, indicator_id, org_id)

    await db.delete(indicator)
    await db.flush()


@router.post("/indicators/{indicator_id}/enrich", response_model=None, operation_id="enrich_indicator")
async def enrich_indicator(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> dict:
    """Enrich one of the caller's indicators through VirusTotal / AbuseIPDB / OTX now.

    Runs the same providers as ``POST /lookup`` with the organisation's keys
    (or the platform's) and stores the outcome on the indicator under
    ``context.external_enrichment``. ``status`` is ``enriched`` when at least
    one provider answered, otherwise the reason (``not_configured``,
    ``enrichment_failed``, ``integration_credentials_unreadable``,
    ``unsupported_indicator_type``). Platform intel answers 403.
    """
    indicator = await _get_owned_indicator(db, indicator_id, org_id)

    bucket = intel_providers.dispatch_bucket(indicator.indicator_type)
    outcomes = await intel_providers.enrich_value(db, org_id, bucket, indicator.value, use_cache=False)
    overall = intel_providers.overall_status(outcomes)
    checked_at = datetime.now(timezone.utc).isoformat()

    context = dict(indicator.context or {})
    context["external_enrichment"] = {
        "status": overall,
        "checked_at": checked_at,
        "providers": [o.summary() for o in outcomes],
        "sources": _external_sources(outcomes),
    }
    context.pop("enrichment_status", None)
    context.pop("enrichment_requested_at", None)
    indicator.context = context

    await db.flush()
    await db.refresh(indicator)

    return {
        "status": "enriched" if overall == "ok" else overall,
        "indicator_id": indicator_id,
        "checked_at": checked_at,
        "providers": [o.summary() for o in outcomes],
        "external_sources": _external_sources(outcomes),
        "external_errors": _external_errors(outcomes),
        "not_configured": [o.provider for o in outcomes if o.status == "not_configured"],
    }


@router.post("/indicators/{indicator_id}/whitelist", response_model=ThreatIndicatorResponse, operation_id="whitelist_indicator")
async def whitelist_indicator(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> ThreatIndicatorResponse:
    """
    Whitelist a threat indicator.
    """
    indicator = await _get_owned_indicator(db, indicator_id, org_id)

    indicator.is_whitelisted = True
    indicator.is_active = False

    await db.flush()
    await db.refresh(indicator)
    return indicator


@router.get("/indicators/{indicator_id}/timeline", response_model=None, operation_id="get_indicator_timeline")
async def get_indicator_timeline(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> list:
    """
    Get the timeline/history for a threat indicator.
    """
    # The indicator must be the caller's own or platform intel.
    indicator = await _get_visible_indicator_or_404(db, indicator_id, org_id)

    # Get this tenant's sightings as timeline events
    sightings_query = (
        select(IndicatorSighting)
        .where(
            IndicatorSighting.indicator_id == indicator_id,
            IndicatorSighting.organization_id == org_id,
        )
        .order_by(desc(IndicatorSighting.created_at))
    )
    sightings_result = await db.execute(sightings_query)
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> ThreatIndicatorListResponse:
    """
    Perform advanced search on threat indicators.
    """
    query = select(ThreatIndicator)

    query = query.where(_visible_to(ThreatIndicator, org_id))

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
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> IndicatorSightingResponse:
    """
    Record a sighting (stamped with the caller's organisation) of one of the
    caller's indicators or of a platform indicator.
    """
    indicator = await _get_visible_indicator_or_404(db, sighting_data.indicator_id, org_id)

    sighting = IndicatorSighting(
        id=str(uuid.uuid4()),
        **sighting_data.model_dump(),
        organization_id=org_id,
    )
    db.add(sighting)

    # Sighting counters live on the indicator row. Platform (NULL-org)
    # indicators are shared by every tenant and read-only to them, so only
    # the caller's own indicators are bumped; the sighting row itself always
    # records the event for this tenant.
    if indicator.organization_id is not None:
        indicator.sighting_count = (indicator.sighting_count or 0) + 1
        indicator.last_sighting_at = datetime.now(timezone.utc)
        indicator.last_seen = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(sighting)
    return sighting


@router.get("/indicators/{indicator_id}/sightings", response_model=list[IndicatorSightingResponse], operation_id="get_indicator_sightings")
async def get_indicator_sightings(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> list[IndicatorSightingResponse]:
    """
    Get sightings for a specific threat indicator.
    """
    # The indicator must be the caller's own or platform intel.
    await _get_visible_indicator_or_404(db, indicator_id, org_id)

    query = (
        select(IndicatorSighting)
        .where(IndicatorSighting.indicator_id == indicator_id)
        .order_by(desc(IndicatorSighting.created_at))
        .offset((page - 1) * size)
        .limit(size)
    )
    query = query.where(IndicatorSighting.organization_id == org_id)
    result = await db.execute(query)
    sightings = result.scalars().all()
    return sightings


# ============================================================================
# THREAT ACTOR ENDPOINTS
# ============================================================================


@router.post("/actors", response_model=ThreatActorResponse, status_code=status.HTTP_201_CREATED, operation_id="create_actor")
async def create_actor(
    actor_data: ThreatActorCreate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> ThreatActorResponse:
    """
    Create a new threat actor in the caller's organisation.
    """
    await _ensure_actor_name_free(db, actor_data.name)
    actor = ThreatActor(
        id=str(uuid.uuid4()),
        **actor_data.model_dump(),
        organization_id=org_id,
    )
    db.add(actor)
    await db.flush()
    await db.refresh(actor)
    return actor


async def _ensure_actor_name_free(db: AsyncSession, name: str) -> None:
    """``threat_actors.name`` is globally unique in the schema; answer 409
    instead of letting the insert fail with an IntegrityError (500)."""
    existing = await db.execute(select(ThreatActor.id).where(ThreatActor.name == name))
    if existing.first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "actor_name_taken", "detail": "a threat actor with this name already exists"},
        )


@router.get("/actors", response_model=ThreatActorListResponse, operation_id="list_actors")
async def list_actors(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
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
    query = select(ThreatActor)

    query = query.where(ThreatActor.organization_id == org_id)

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    actor_id: str = Path(...),
) -> ThreatActorResponse:
    """
    Get threat actor details with associated campaigns and indicators.
    """
    stmt = select(ThreatActor).where(ThreatActor.id == actor_id)
    stmt = stmt.where(ThreatActor.organization_id == org_id)
    result = await db.execute(stmt)
    actor = result.scalars().first()
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")
    return actor


@router.put("/actors/{actor_id}", response_model=ThreatActorResponse, operation_id="update_actor")
async def update_actor(
    actor_update: ThreatActorUpdate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    actor_id: str = Path(...),
) -> ThreatActorResponse:
    """
    Update a threat actor.
    """
    stmt = select(ThreatActor).where(ThreatActor.id == actor_id)
    stmt = stmt.where(ThreatActor.organization_id == org_id)
    result = await db.execute(stmt)
    actor = result.scalars().first()
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")

    changes = actor_update.model_dump(exclude_unset=True)
    if changes.get("name") and changes["name"] != actor.name:
        await _ensure_actor_name_free(db, changes["name"])
    for field, value in changes.items():
        setattr(actor, field, value)

    await db.flush()
    await db.refresh(actor)
    return actor


@router.delete("/actors/{actor_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_actor")
async def delete_actor(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    actor_id: str = Path(...),
) -> None:
    """
    Delete a threat actor.
    """
    stmt = select(ThreatActor).where(ThreatActor.id == actor_id)
    stmt = stmt.where(ThreatActor.organization_id == org_id)
    result = await db.execute(stmt)
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
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> ThreatCampaignResponse:
    """
    Create a new threat campaign in the caller's organisation. ``actor_id``,
    when given, must be one of the caller's actors.
    """
    if campaign_data.actor_id:
        await _ensure_own_actor(db, campaign_data.actor_id, org_id)
    campaign = ThreatCampaign(
        id=str(uuid.uuid4()),
        **campaign_data.model_dump(),
        organization_id=org_id,
    )
    db.add(campaign)
    await db.flush()
    await db.refresh(campaign)
    return campaign


async def _ensure_own_actor(db: AsyncSession, actor_id: str, org_id: str) -> None:
    """A campaign may only link to an actor of the same organisation (404 otherwise)."""
    result = await db.execute(
        select(ThreatActor.id).where(
            ThreatActor.id == actor_id, ThreatActor.organization_id == org_id
        )
    )
    if result.first() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")


@router.get("/campaigns", response_model=ThreatCampaignListResponse, operation_id="list_campaigns")
async def list_campaigns(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
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
    query = select(ThreatCampaign)

    query = query.where(ThreatCampaign.organization_id == org_id)

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    campaign_id: str = Path(...),
) -> ThreatCampaignResponse:
    """
    Get threat campaign details.
    """
    stmt = select(ThreatCampaign).where(ThreatCampaign.id == campaign_id)
    stmt = stmt.where(ThreatCampaign.organization_id == org_id)
    result = await db.execute(stmt)
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    return campaign


@router.put("/campaigns/{campaign_id}", response_model=ThreatCampaignResponse, operation_id="update_campaign")
async def update_campaign(
    campaign_update: ThreatCampaignUpdate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    campaign_id: str = Path(...),
) -> ThreatCampaignResponse:
    """
    Update a threat campaign.
    """
    stmt = select(ThreatCampaign).where(ThreatCampaign.id == campaign_id)
    stmt = stmt.where(ThreatCampaign.organization_id == org_id)
    result = await db.execute(stmt)
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    changes = campaign_update.model_dump(exclude_unset=True)
    if changes.get("actor_id"):
        await _ensure_own_actor(db, changes["actor_id"], org_id)
    for field, value in changes.items():
        setattr(campaign, field, value)

    await db.flush()
    await db.refresh(campaign)
    return campaign


@router.delete("/campaigns/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT, operation_id="delete_campaign")
async def delete_campaign(
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    campaign_id: str = Path(...),
) -> None:
    """
    Delete a threat campaign.
    """
    stmt = select(ThreatCampaign).where(ThreatCampaign.id == campaign_id)
    stmt = stmt.where(ThreatCampaign.organization_id == org_id)
    result = await db.execute(stmt)
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
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
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
        organization_id=org_id,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return report


@router.get("/reports", response_model=IntelReportListResponse, operation_id="list_reports")
async def list_reports(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
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
    query = select(IntelReport)

    query = query.where(IntelReport.organization_id == org_id)

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> IntelReportResponse:
    """
    Get a specific intel report.
    """
    stmt = select(IntelReport).where(IntelReport.id == report_id)
    stmt = stmt.where(IntelReport.organization_id == org_id)
    result = await db.execute(stmt)
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.put("/reports/{report_id}", response_model=IntelReportResponse, operation_id="update_report")
async def update_report(
    report_update: IntelReportUpdate,
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> IntelReportResponse:
    """
    Update an intel report.
    """
    stmt = select(IntelReport).where(IntelReport.id == report_id)
    stmt = stmt.where(IntelReport.organization_id == org_id)
    result = await db.execute(stmt)
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
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> IntelReportResponse:
    """
    Publish an intel report.
    """
    stmt = select(IntelReport).where(IntelReport.id == report_id)
    stmt = stmt.where(IntelReport.organization_id == org_id)
    result = await db.execute(stmt)
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
    current_user: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    report_id: str = Path(...),
) -> None:
    """
    Delete an intel report.
    """
    stmt = select(IntelReport).where(IntelReport.id == report_id)
    stmt = stmt.where(IntelReport.organization_id == org_id)
    result = await db.execute(stmt)
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
) -> IntelDashboardStats:
    """
    Get threat intelligence dashboard statistics.

    Scoped to the caller's organization so each tenant only sees its own
    intel posture; feed and indicator counts also include platform
    (NULL-org) intel, which every tenant reads.
    """

    def _scope(stmt, model):
        if model in (ThreatIndicator, ThreatFeed):
            return stmt.where(_visible_to(model, org_id))
        return stmt.where(model.organization_id == org_id)

    total_indicators = (
        await db.execute(_scope(select(func.count(ThreatIndicator.id)), ThreatIndicator))
    ).scalar() or 0

    active_indicators = (
        await db.execute(
            _scope(
                select(func.count(ThreatIndicator.id)).where(
                    ThreatIndicator.is_active == True
                ),
                ThreatIndicator,
            )
        )
    ).scalar() or 0

    feeds_total = (
        await db.execute(_scope(select(func.count(ThreatFeed.id)), ThreatFeed))
    ).scalar() or 0

    feeds_enabled = (
        await db.execute(
            _scope(
                select(func.count(ThreatFeed.id)).where(ThreatFeed.is_enabled == True),
                ThreatFeed,
            )
        )
    ).scalar() or 0

    # Indicators by type
    type_result = await db.execute(
        _scope(
            select(ThreatIndicator.indicator_type, func.count(ThreatIndicator.id)),
            ThreatIndicator,
        ).group_by(ThreatIndicator.indicator_type)
    )
    indicators_by_type = dict(type_result.all())

    # Indicators by severity
    severity_result = await db.execute(
        _scope(
            select(ThreatIndicator.severity, func.count(ThreatIndicator.id)),
            ThreatIndicator,
        ).group_by(ThreatIndicator.severity)
    )
    indicators_by_severity = dict(severity_result.all())

    # Recent sightings (last 7 days)
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_sightings = (
        await db.execute(
            _scope(
                select(func.count(IndicatorSighting.id)).where(
                    IndicatorSighting.created_at >= seven_days_ago
                ),
                IndicatorSighting,
            )
        )
    ).scalar() or 0

    # Actors tracked
    actors_tracked = (
        await db.execute(_scope(select(func.count(ThreatActor.id)), ThreatActor))
    ).scalar() or 0

    # Active campaigns
    active_campaigns = (
        await db.execute(
            _scope(
                select(func.count(ThreatCampaign.id)).where(
                    ThreatCampaign.status == "active"
                ),
                ThreatCampaign,
            )
        )
    ).scalar() or 0

    # Coverage score: the share of enabled feeds (own plus platform) whose
    # last successful poll is within the last 24 hours, as a percentage.
    day_ago = datetime.now(timezone.utc) - timedelta(days=1)
    feeds_fresh = (
        await db.execute(
            _scope(
                select(func.count(ThreatFeed.id)).where(
                    ThreatFeed.is_enabled == True,
                    ThreatFeed.last_success_at >= day_ago,
                ),
                ThreatFeed,
            )
        )
    ).scalar() or 0
    coverage_score = round(100.0 * feeds_fresh / feeds_enabled, 1) if feeds_enabled else 0.0

    # Top tags over the most recent TOP_TAGS_SAMPLE indicators (own plus
    # platform). JSON array aggregation is dialect-specific, so the tags are
    # counted here over a bounded sample; ``top_tags_sample_size`` says how
    # many indicators were counted.
    tag_rows = (
        await db.execute(
            _scope(select(ThreatIndicator.tags), ThreatIndicator)
            .order_by(desc(ThreatIndicator.created_at))
            .limit(TOP_TAGS_SAMPLE)
        )
    ).all()
    tag_counts: dict[str, int] = {}
    for (row_tags,) in tag_rows:
        if isinstance(row_tags, list):
            for tag in row_tags:
                if isinstance(tag, str) and tag:
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
    top_tags = [tag for tag, _ in sorted(tag_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]]

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
        top_tags=top_tags,
        coverage_score=coverage_score,
        coverage_basis="enabled feeds with a successful poll in the last 24 hours",
        feeds_polled_24h=feeds_fresh,
        top_tags_sample_size=len(tag_rows),
    )



_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection: prefix a leading = + - @ tab or
    CR with a single quote so the cell is read as text."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value

@router.get("/export", response_model=None, operation_id="export_indicators")
async def export_indicators(
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    format: str = Query("json", description="json, csv, stix"),
    indicator_types: Optional[list[str]] = Query(None),
    severity: Optional[list[str]] = Query(None),
    tags: Optional[list[str]] = Query(None),
) -> Any:
    """Export active threat indicators (own plus platform intel).

    ``json`` returns ``{format, count, truncated, indicators}``; ``csv``
    returns a ``text/csv`` attachment; ``stix`` returns a STIX 2.1 bundle of
    ``indicator`` objects. At most ``EXPORT_MAX_ROWS`` rows are exported,
    newest first; ``truncated`` (JSON), ``x_pysoar_truncated`` (STIX) and the
    ``X-PySOAR-Truncated`` header (CSV) say whether the cap cut the set.
    """
    if format not in ["json", "csv", "stix"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid export format. Must be json, csv, or stix",
        )

    query = select(ThreatIndicator).where(_visible_to(ThreatIndicator, org_id))
    if indicator_types:
        expanded: list[str] = []
        for itype in indicator_types:
            expanded.extend(intel_providers.type_variants(itype))
        query = query.where(ThreatIndicator.indicator_type.in_(expanded))
    if severity:
        query = query.where(ThreatIndicator.severity.in_(severity))
    query = _with_tags(query, tags)

    query = (
        query.where(ThreatIndicator.is_active == True)
        .order_by(desc(ThreatIndicator.created_at))
        .limit(EXPORT_MAX_ROWS + 1)
    )
    indicators = list((await db.execute(query)).scalars().all())
    truncated = len(indicators) > EXPORT_MAX_ROWS
    indicators = indicators[:EXPORT_MAX_ROWS]

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
            "platform_intel": ind.organization_id is None,
        })

    if format == "csv":
        buffer = io.StringIO()
        columns = [
            "id", "indicator_type", "value", "source", "confidence", "severity", "tlp",
            "first_seen", "last_seen", "tags", "mitre_techniques", "platform_intel",
        ]
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in export_data:
            flat = dict(row)
            flat["tags"] = ";".join(str(x) for x in (row.get("tags") or []))
            flat["mitre_techniques"] = ";".join(str(x) for x in (row.get("mitre_techniques") or []))
            # Indicator values and tags are attacker-influenced text; a cell
            # starting with = + - @ or a tab/CR would execute as a formula when
            # the file is opened in a spreadsheet.
            writer.writerow({key: _csv_safe(value) for key, value in flat.items()})
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="threat-indicators.csv"',
                "X-PySOAR-Truncated": "true" if truncated else "false",
            },
        )

    if format == "stix":
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects = []
        for row in export_data:
            pattern = _stix_pattern(row["indicator_type"], row["value"])
            if pattern is None:
                continue
            created = row["first_seen"] or now_iso
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, 'pysoar:' + row['id'])}",
                "created": created,
                "modified": row["last_seen"] or created,
                "name": row["value"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created,
                "confidence": row["confidence"],
                "labels": [x for x in (row.get("tags") or []) if isinstance(x, str)],
                "x_pysoar_severity": row["severity"],
                "x_pysoar_source": row["source"],
            })
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
            "x_pysoar_truncated": truncated,
            "x_pysoar_skipped_untyped": len(export_data) - len(objects),
        }

    return {
        "format": format,
        "count": len(export_data),
        "truncated": truncated,
        "indicators": export_data,
    }


def _stix_pattern(indicator_type: Optional[str], value: str) -> Optional[str]:
    """A STIX 2.1 pattern for one indicator, or None for a type STIX cannot express."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    itype = (indicator_type or "").lower()
    if itype in ("ipv4", "ip") and ":" not in value:
        return f"[ipv4-addr:value = '{escaped}']"
    if itype in ("ipv6", "ip"):
        return f"[ipv6-addr:value = '{escaped}']"
    if itype == "cidr":
        kind = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{kind}:value = '{escaped}']"
    if itype in ("domain", "hostname"):
        return f"[domain-name:value = '{escaped}']"
    if itype == "url":
        return f"[url:value = '{escaped}']"
    if itype == "email":
        return f"[email-addr:value = '{escaped}']"
    if itype in ("md5", "sha1", "sha256", "sha512"):
        name = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}[itype]
        return f"[file:hashes.'{name}' = '{escaped}']"
    return None
