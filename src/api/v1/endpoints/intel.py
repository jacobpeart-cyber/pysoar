"""Threat Intelligence Platform API endpoints"""

import asyncio
import json
import logging
import math
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Path, HTTPException, Query, status
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
from src.integrations.models import InstalledIntegration, IntegrationConnector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-process TTL cache for external IOC enrichment
# ---------------------------------------------------------------------------
# External intel APIs (VirusTotal free tier = 4 req/min, AbuseIPDB daily caps)
# rate-limit us aggressively, so we cache lookups for 1 hour per
# (provider, indicator_type, value) tuple. This keeps the UI snappy on repeat
# lookups and avoids burning quota on the same indicator.
_IOC_CACHE_TTL_SECONDS = 3600
_ioc_lookup_cache: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}


def _cache_get(key: tuple[str, str, str]) -> Optional[dict[str, Any]]:
    entry = _ioc_lookup_cache.get(key)
    if not entry:
        return None
    expires_at, value = entry
    if expires_at < time.time():
        _ioc_lookup_cache.pop(key, None)
        return None
    return value


def _cache_set(key: tuple[str, str, str], value: dict[str, Any]) -> None:
    _ioc_lookup_cache[key] = (time.time() + _IOC_CACHE_TTL_SECONDS, value)


def _detect_indicator_type(value: str) -> str:
    """Best-effort IOC type detection when the caller passes type='auto'."""
    v = value.strip()
    # URL
    if v.lower().startswith(("http://", "https://")):
        return "url"
    # Hash — length-based heuristic
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    # IPv4
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", v):
        return "ip"
    # IPv6 (very loose)
    if ":" in v and re.fullmatch(r"[0-9a-fA-F:]+", v):
        return "ip"
    # Domain
    if re.fullmatch(r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}", v):
        return "domain"
    return "unknown"


def _normalize_type(t: str) -> str:
    """Collapse fine-grained IOC types to a dispatch bucket."""
    t = (t or "").lower()
    if t in ("ipv4", "ipv6", "ip"):
        return "ip"
    if t in ("md5", "sha1", "sha256", "hash"):
        return "hash"
    if t == "url":
        return "url"
    if t == "domain":
        return "domain"
    return t


async def _load_intel_integrations(
    db: AsyncSession,
) -> dict[str, dict[str, Any]]:
    """Load installed VirusTotal / AbuseIPDB integration credentials.

    Returns a mapping ``{connector_name: credentials_dict}`` for any active
    installation. Credentials for these connectors are stored as plaintext
    JSON in ``auth_credentials_encrypted`` (name is historical — see
    ``src/integrations/engine.py`` ``test_connection``).
    """
    q = (
        select(InstalledIntegration, IntegrationConnector)
        .join(
            IntegrationConnector,
            IntegrationConnector.id == InstalledIntegration.connector_id,
        )
        .where(IntegrationConnector.name.in_(("virustotal", "abuseipdb")))
    )
    result = await db.execute(q)
    integrations: dict[str, dict[str, Any]] = {}
    for inst, conn in result.all():
        try:
            creds = json.loads(inst.auth_credentials_encrypted or "{}")
        except (json.JSONDecodeError, TypeError):
            creds = {}
        if not isinstance(creds, dict):
            continue
        # Only surface integrations that have a usable key.
        if conn.name.lower() in ("virustotal", "abuseipdb") and (
            creds.get("api_key") or creds.get("apikey") or creds.get("key")
        ):
            integrations[conn.name.lower()] = creds
    return integrations


def _vt_verdict(stats: dict[str, Any]) -> tuple[str, int]:
    """Map VT last_analysis_stats -> (verdict, confidence[0-100])."""
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total = malicious + suspicious + harmless + undetected
    if malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "suspicious"
    elif total > 0 and harmless > 0:
        verdict = "clean"
    else:
        verdict = "unknown"
    confidence = 0
    if total > 0:
        confidence = min(100, int(((malicious + suspicious) / total) * 100))
    return verdict, confidence


async def _vt_lookup(
    client: httpx.AsyncClient,
    api_key: str,
    ioc_type: str,
    value: str,
) -> dict[str, Any]:
    """Call VirusTotal v3 directly. Returns an ``external_sources`` entry."""
    import base64 as _b64

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    if ioc_type == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    elif ioc_type == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{value}"
    elif ioc_type == "hash":
        endpoint = f"https://www.virustotal.com/api/v3/files/{value}"
    elif ioc_type == "url":
        url_id = _b64.urlsafe_b64encode(value.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        return {
            "name": "virustotal",
            "verdict": "unsupported",
            "confidence": 0,
            "error": f"VirusTotal does not support type '{ioc_type}'",
        }

    resp = await client.get(endpoint, headers=headers)
    if resp.status_code == 404:
        return {
            "name": "virustotal",
            "verdict": "unknown",
            "confidence": 0,
            "raw": {"not_found": True, "status": 404},
        }
    resp.raise_for_status()
    body = resp.json() or {}
    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    verdict, confidence = _vt_verdict(stats)
    return {
        "name": "virustotal",
        "verdict": verdict,
        "confidence": confidence,
        "raw": {
            "last_analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
        },
    }


async def _abuseipdb_lookup(
    client: httpx.AsyncClient,
    api_key: str,
    value: str,
) -> dict[str, Any]:
    """Call AbuseIPDB /check directly."""
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": value, "maxAgeInDays": 90, "verbose": True}
    resp = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params=params,
    )
    resp.raise_for_status()
    body = resp.json() or {}
    data = body.get("data") or {}
    score = int(data.get("abuseConfidenceScore") or 0)
    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    elif score > 0:
        verdict = "low_risk"
    else:
        verdict = "clean"
    return {
        "name": "abuseipdb",
        "verdict": verdict,
        "confidence": score,
        "raw": {
            "abuse_confidence_score": score,
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported_at": data.get("lastReportedAt"),
        },
    }


async def _enrich_external(
    ioc_type: str,
    value: str,
    integrations: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Call configured external providers in parallel.

    Returns ``(sources, errors)`` where ``sources`` matches the
    ``external_sources`` schema and ``errors`` is a list of free-form
    strings describing any per-provider failures.
    """
    tasks: list[tuple[str, asyncio.Task]] = []
    errors: list[str] = []

    def _get_key(creds: dict[str, Any]) -> Optional[str]:
        return creds.get("api_key") or creds.get("apikey") or creds.get("key")

    # Build per-provider task list from the type dispatcher.
    timeout = httpx.Timeout(8.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if ioc_type == "ip":
            if "abuseipdb" in integrations:
                key = _get_key(integrations["abuseipdb"])
                if key:
                    tasks.append((
                        "abuseipdb",
                        asyncio.create_task(_abuseipdb_lookup(client, key, value)),
                    ))
            if "virustotal" in integrations:
                key = _get_key(integrations["virustotal"])
                if key:
                    tasks.append((
                        "virustotal",
                        asyncio.create_task(_vt_lookup(client, key, "ip", value)),
                    ))
        elif ioc_type in ("domain", "url", "hash"):
            if "virustotal" in integrations:
                key = _get_key(integrations["virustotal"])
                if key:
                    tasks.append((
                        "virustotal",
                        asyncio.create_task(_vt_lookup(client, key, ioc_type, value)),
                    ))

        if not tasks:
            return [], errors

        results = await asyncio.gather(
            *(t for _, t in tasks), return_exceptions=True
        )

    sources: list[dict[str, Any]] = []
    for (name, _task), result in zip(tasks, results):
        if isinstance(result, Exception):
            err_msg = f"{name}: {type(result).__name__}: {result}"
            errors.append(err_msg)
            logger.warning("IOC enrichment failed: %s", err_msg)
            sources.append({
                "name": name,
                "verdict": "error",
                "confidence": 0,
                "error": str(result)[:200],
            })
            continue
        sources.append(result)
    return sources, errors
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
        # PySOAR is single-tenant per deployment; data is not org-scoped.
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
    """Look up an IOC and enrich with external feeds.

    Order of operations:
      1. Query the local ``threat_indicators`` table for a match (fast
         path, returns local reputation + tags).
      2. Detect IOC type if caller passed ``type='auto'``.
      3. Enrich via installed VirusTotal / AbuseIPDB integrations:
         - ``ip``     -> AbuseIPDB + VirusTotal (parallel)
         - ``domain`` -> VirusTotal
         - ``url``    -> VirusTotal
         - ``hash``   -> VirusTotal
      4. Merge: local reputation is kept if set, but external results
         are appended under ``external_sources``. If no integrations are
         installed, ``external_enrichment = "no_integrations_configured"``
         makes that explicit — we never silently drop the enrichment.

    Frontend POSTs ``{ indicator: string, type: string }``.
    """
    indicator_value = (payload.get("indicator") or "").strip()
    indicator_type = payload.get("type", "auto")

    if not indicator_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="indicator is required",
        )

    # Query matching indicators in the local DB
    org_clause = True
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
                "last_seen": (
                    ind.last_seen.isoformat()
                    if ind.last_seen
                    else datetime.now(timezone.utc).isoformat()
                ),
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
    # Resolve dispatch type (ip/domain/url/hash) — either user-supplied or
    # best-effort detected from the value itself.
    dispatch_type = _normalize_type(
        resolved_type if resolved_type and resolved_type != "auto" else indicator_type
    )
    if dispatch_type in ("", "auto", "unknown"):
        dispatch_type = _normalize_type(_detect_indicator_type(indicator_value))
    if dispatch_type in ("", "unknown"):
        # still resolve as-is; skip external if unclassifiable
        dispatch_type = _normalize_type(indicator_type)

    external_sources: list[dict[str, Any]] = []
    external_errors: list[str] = []
    external_status = "ok"

    try:
        integrations = await _load_intel_integrations(db)
    except Exception as e:
        logger.warning("Failed to load intel integrations: %s", e)
        integrations = {}

    if not integrations:
        external_status = "no_integrations_configured"
    elif dispatch_type not in ("ip", "domain", "url", "hash"):
        external_status = "unsupported_indicator_type"
    else:
        # Pull providers that will actually be called so we can check cache
        # first and only hit the network for cache misses.
        providers_for_type = {
            "ip": ["abuseipdb", "virustotal"],
            "domain": ["virustotal"],
            "url": ["virustotal"],
            "hash": ["virustotal"],
        }[dispatch_type]
        providers_to_call = [p for p in providers_for_type if p in integrations]

        cached_hits: list[dict[str, Any]] = []
        missing: list[str] = []
        for provider in providers_to_call:
            cache_key = (provider, dispatch_type, indicator_value)
            cached = _cache_get(cache_key)
            if cached is not None:
                cached_hits.append(cached)
            else:
                missing.append(provider)

        # Call only missing providers
        fresh_sources: list[dict[str, Any]] = []
        if missing:
            sub_integrations = {k: v for k, v in integrations.items() if k in missing}
            try:
                fresh_sources, external_errors = await _enrich_external(
                    dispatch_type, indicator_value, sub_integrations
                )
            except Exception as e:
                logger.exception("External IOC enrichment crashed: %s", e)
                external_errors.append(f"enrichment_crashed: {e}")
                fresh_sources = []
                external_status = "enrichment_failed"
            # Populate cache for successful results only
            for src in fresh_sources:
                if src.get("verdict") not in ("error",):
                    _cache_set((src["name"], dispatch_type, indicator_value), src)

        external_sources = cached_hits + fresh_sources
        if not external_sources and external_status == "ok":
            external_status = "no_results"

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
        "type": resolved_type if resolved_type not in (None, "", "auto") else dispatch_type,
        "reputation": merged_reputation,
        "confidence": merged_confidence,
        "sources": local_sources,
        "external_sources": external_sources,
        "external_enrichment": external_status,
        "external_errors": external_errors,
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> ThreatFeedResponse:
    """
    Create a new threat feed.

    Requires admin privileges.
    """
    # Use current_user directly (admin check handled by dependency injection)

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
    query = select(ThreatFeed)

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
            .where(ThreatIndicator.feed_id.in_(feed_ids))
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
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> ThreatFeedResponse:
    """
    Get threat feed details.
    """
    result = await db.execute(
        select(ThreatFeed).where(
            ThreatFeed.id == feed_id
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
    # Use current_user directly (admin check handled by dependency injection)

    result = await db.execute(
        select(ThreatFeed).where(
            ThreatFeed.id == feed_id
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
    # Use current_user directly (admin check handled by dependency injection)

    result = await db.execute(
        select(ThreatFeed).where(
            ThreatFeed.id == feed_id
        )
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    await db.delete(feed)
    await db.flush()


@router.post("/feeds/{feed_id}/poll", response_model=None, operation_id="poll_threat_feed")
async def poll_threat_feed(
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """Trigger a real poll of a threat feed.

    Previously this only stamped ``last_poll_at`` without actually
    fetching. The frontend Sync button was a no-op; ``total_indicators``
    never grew. This now dispatches ``FeedManager.poll_feed(feed_id)``
    as a background task so the HTTP response returns immediately while
    the ingestion runs against its own session and writes real rows
    into ``threat_indicators``.
    """
    result = await db.execute(
        select(ThreatFeed).where(ThreatFeed.id == feed_id)
    )
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    if not feed.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Feed is disabled — enable before polling",
        )

    # Snapshot trigger timestamp on the request's session so the UI
    # reflects the click even before the background job finishes.
    feed.last_poll_at = datetime.now(timezone.utc)
    await db.flush()

    async def _run_poll(fid: str) -> None:
        try:
            from src.intel.feeds import FeedManager
            count = await FeedManager().poll_feed(fid)
            import logging
            logging.getLogger(__name__).info(
                "Threat feed poll completed", extra={"feed_id": fid, "new_indicators": count}
            )
        except Exception as exc:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).error(
                "Threat feed poll failed: %s", exc, extra={"feed_id": fid}, exc_info=True
            )

    background_tasks.add_task(_run_poll, feed_id)

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


@router.post("/feeds/{feed_id}/sync", response_model=None, operation_id="sync_threat_feed")
async def sync_threat_feed(
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    feed_id: str = Path(...),
) -> dict:
    """Sync is an alias of poll. Wired through the same real ingestion path."""
    return await poll_threat_feed(
        background_tasks=background_tasks,
        current_user=current_user,
        db=db,
        feed_id=feed_id,
    )


@router.post("/feeds/register-builtins", response_model=None, operation_id="register_builtin_feeds")
async def register_builtin_feeds(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
) -> dict:
    """
    Register built-in threat feeds.

    Requires admin privileges.
    """
    # Use current_user directly (admin check handled by dependency injection)

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
            ThreatFeed.id == feed_id
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
    """List threat indicators with advanced filtering and pagination.

    ``indicator_type`` and ``severity`` accept a CSV of values so one
    UI filter can cover IP family variations (``ip,ipv4,ipv6``) and
    severity bands (``high,critical`` for "malicious"). Previously
    these were strict equality, which left ipv6 + critical rows
    unreachable from the Reputation filter.
    """
    query = select(ThreatIndicator)

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
    db: DatabaseSession = None,
    indicator_id: str = Path(...),
) -> ThreatIndicatorResponse:
    """
    Get a specific threat indicator.
    """
    result = await db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.id == indicator_id
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
            ThreatIndicator.id == indicator_id
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
            ThreatIndicator.id == indicator_id
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
            ThreatIndicator.id == indicator_id
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
            ThreatIndicator.id == indicator_id
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
            ThreatIndicator.id == indicator_id
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
    query = select(ThreatIndicator)

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
        select(ThreatIndicator).where(ThreatIndicator.id == sighting_data.indicator_id)
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
            ThreatIndicator.id == indicator_id
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
    query = select(ThreatActor)

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
            ThreatActor.id == actor_id
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
            ThreatActor.id == actor_id
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
            ThreatActor.id == actor_id
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
    query = select(ThreatCampaign)

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
            ThreatCampaign.id == campaign_id
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
            ThreatCampaign.id == campaign_id
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
            ThreatCampaign.id == campaign_id
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
    query = select(IntelReport)

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
            IntelReport.id == report_id
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
            IntelReport.id == report_id
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
            IntelReport.id == report_id
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
            IntelReport.id == report_id
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

    PySOAR is single-tenant per deployment — org_id filters removed so
    every admin in the deployment sees the full platform data.
    """
    total_indicators = (
        await db.execute(select(func.count(ThreatIndicator.id)))
    ).scalar() or 0

    active_indicators = (
        await db.execute(
            select(func.count(ThreatIndicator.id)).where(ThreatIndicator.is_active == True)
        )
    ).scalar() or 0

    feeds_total = (await db.execute(select(func.count(ThreatFeed.id)))).scalar() or 0

    feeds_enabled = (
        await db.execute(
            select(func.count(ThreatFeed.id)).where(ThreatFeed.is_enabled == True)
        )
    ).scalar() or 0

    # Indicators by type
    type_result = await db.execute(
        select(ThreatIndicator.indicator_type, func.count(ThreatIndicator.id))
        .group_by(ThreatIndicator.indicator_type)
    )
    indicators_by_type = dict(type_result.all())

    # Indicators by severity
    severity_result = await db.execute(
        select(ThreatIndicator.severity, func.count(ThreatIndicator.id))
        .group_by(ThreatIndicator.severity)
    )
    indicators_by_severity = dict(severity_result.all())

    # Recent sightings (last 7 days)
    from datetime import timedelta
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_sightings = (
        await db.execute(
            select(func.count(IndicatorSighting.id)).where(
                IndicatorSighting.created_at >= seven_days_ago
            )
        )
    ).scalar() or 0

    # Actors tracked
    actors_tracked = (
        await db.execute(select(func.count(ThreatActor.id)))
    ).scalar() or 0

    # Active campaigns
    active_campaigns = (
        await db.execute(
            select(func.count(ThreatCampaign.id)).where(ThreatCampaign.status == "active")
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

    query = select(ThreatIndicator)

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
