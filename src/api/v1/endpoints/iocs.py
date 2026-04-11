"""IOC (Indicator of Compromise) management endpoints.

Backed by the unified `threat_indicators` table. Legacy IOC-specific fields
(description, category, malware_family, threat_actor, campaign, source_url,
source_reference, enrichment_data, is_internal) are stored inside the
ThreatIndicator.context JSON dict to preserve the wire contract for the
existing frontend IOCs page.
"""

import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.intel.models import ThreatIndicator
from src.schemas.ioc import (
    IOCBulkCreate,
    IOCCreate,
    IOCEnrichRequest,  # noqa: F401 - exported for compat
    IOCListResponse,
    IOCResponse,
    IOCSearchRequest,
    IOCUpdate,
)

router = APIRouter(prefix="/iocs", tags=["IOCs"])


# --------------------------------------------------------------------------- #
# Field mapping helpers
# --------------------------------------------------------------------------- #

def _parse_dt(value) -> Optional[datetime]:
    """Accept str or datetime and return aware datetime or None."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _dt_iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def ioc_to_response(ioc: ThreatIndicator) -> IOCResponse:
    """Convert a unified ThreatIndicator row into the legacy IOCResponse shape."""
    ctx = ioc.context if isinstance(ioc.context, dict) else {}

    return IOCResponse(
        id=ioc.id,
        value=ioc.value,
        ioc_type=ioc.indicator_type,
        status="active" if ioc.is_active else "inactive",
        threat_level=ioc.severity or "unknown",
        confidence=ioc.confidence if ioc.confidence is not None else 50,
        description=ctx.get("description"),
        tags=ioc.tags or [],
        category=ctx.get("category"),
        source=ioc.source,
        source_url=ctx.get("source_url"),
        source_reference=ctx.get("source_reference"),
        malware_family=ctx.get("malware_family"),
        threat_actor=ctx.get("threat_actor"),
        campaign=ctx.get("campaign"),
        mitre_tactics=ioc.mitre_tactics or [],
        mitre_techniques=ioc.mitre_techniques or [],
        enrichment_data=ctx.get("enrichment_data"),
        last_enriched=ctx.get("last_enriched"),
        first_seen=_dt_iso(ioc.first_seen),
        last_seen=_dt_iso(ioc.last_seen),
        expires_at=_dt_iso(ioc.expires_at),
        sighting_count=ioc.sighting_count or 0,
        last_sighting=_dt_iso(ioc.last_sighting_at),
        is_whitelisted=bool(ioc.is_whitelisted),
        is_internal=bool(ctx.get("is_internal", False)),
        created_at=ioc.created_at,
        updated_at=ioc.updated_at,
    )


async def get_ioc_or_404(db: AsyncSession, ioc_id: str) -> ThreatIndicator:
    """Get IOC by ID or raise 404."""
    result = await db.execute(select(ThreatIndicator).where(ThreatIndicator.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found",
        )
    return ioc


def _build_context_from_create(ioc_data: IOCCreate) -> dict:
    """Stash legacy-only fields into the ThreatIndicator.context JSON."""
    ctx: dict = {}
    if ioc_data.description:
        ctx["description"] = ioc_data.description
    if ioc_data.category:
        ctx["category"] = ioc_data.category
    if ioc_data.source_url:
        ctx["source_url"] = ioc_data.source_url
    if ioc_data.source_reference:
        ctx["source_reference"] = ioc_data.source_reference
    if ioc_data.malware_family:
        ctx["malware_family"] = ioc_data.malware_family
    if ioc_data.threat_actor:
        ctx["threat_actor"] = ioc_data.threat_actor
    if ioc_data.campaign:
        ctx["campaign"] = ioc_data.campaign
    return ctx


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

@router.get("", response_model=IOCListResponse)
async def list_iocs(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    ioc_type: Optional[str] = None,
    ioc_status: Optional[str] = Query(None, alias="status"),
    threat_level: Optional[str] = None,
    is_whitelisted: Optional[bool] = None,
):
    """List IOCs (unified threat indicators) with filtering and pagination."""
    query = select(ThreatIndicator)

    if search:
        search_filter = f"%{search}%"
        query = query.where(ThreatIndicator.value.ilike(search_filter))

    if ioc_type:
        query = query.where(ThreatIndicator.indicator_type == ioc_type)

    if ioc_status:
        if ioc_status == "active":
            query = query.where(ThreatIndicator.is_active == True)  # noqa: E712
        else:
            query = query.where(ThreatIndicator.is_active == False)  # noqa: E712

    if threat_level:
        query = query.where(ThreatIndicator.severity == threat_level)

    if is_whitelisted is not None:
        query = query.where(ThreatIndicator.is_whitelisted == is_whitelisted)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.order_by(ThreatIndicator.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    iocs = list(result.scalars().all())

    return IOCListResponse(
        items=[ioc_to_response(ioc) for ioc in iocs],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("", response_model=IOCResponse, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    ioc_data: IOCCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new IOC in the unified threat_indicators table."""
    now = datetime.now(timezone.utc)

    # Check for duplicate (same value + type)
    result = await db.execute(
        select(ThreatIndicator).where(
            (ThreatIndicator.value == ioc_data.value)
            & (ThreatIndicator.indicator_type == ioc_data.ioc_type)
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.sighting_count = (existing.sighting_count or 0) + 1
        existing.last_sighting_at = now
        existing.last_seen = now
        await db.flush()
        await db.refresh(existing)
        return ioc_to_response(existing)

    ctx = _build_context_from_create(ioc_data)
    org_id = getattr(current_user, "organization_id", None)

    ioc = ThreatIndicator(
        value=ioc_data.value,
        indicator_type=ioc_data.ioc_type,
        is_active=True,
        is_whitelisted=False,
        severity=ioc_data.threat_level or "informational",
        confidence=ioc_data.confidence,
        source=ioc_data.source,
        tags=ioc_data.tags or [],
        mitre_tactics=ioc_data.mitre_tactics or [],
        mitre_techniques=ioc_data.mitre_techniques or [],
        context=ctx,
        first_seen=now,
        last_seen=now,
        expires_at=_parse_dt(ioc_data.expires_at),
        sighting_count=1,
        organization_id=org_id,
    )

    db.add(ioc)
    await db.flush()
    await db.refresh(ioc)

    return ioc_to_response(ioc)


@router.post("/bulk", response_model=None)
async def bulk_create_iocs(
    bulk_data: IOCBulkCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Bulk create IOCs."""
    created_count = 0
    updated_count = 0
    failures: list[dict] = []
    now = datetime.now(timezone.utc)
    org_id = getattr(current_user, "organization_id", None)

    for ioc_data in bulk_data.iocs:
        try:
            result = await db.execute(
                select(ThreatIndicator).where(
                    (ThreatIndicator.value == ioc_data.value)
                    & (ThreatIndicator.indicator_type == ioc_data.ioc_type)
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.sighting_count = (existing.sighting_count or 0) + 1
                existing.last_sighting_at = now
                existing.last_seen = now
                updated_count += 1
            else:
                ioc = ThreatIndicator(
                    value=ioc_data.value,
                    indicator_type=ioc_data.ioc_type,
                    is_active=True,
                    is_whitelisted=False,
                    severity=ioc_data.threat_level or "informational",
                    confidence=ioc_data.confidence,
                    source=ioc_data.source,
                    tags=ioc_data.tags or [],
                    context=_build_context_from_create(ioc_data),
                    first_seen=now,
                    last_seen=now,
                    sighting_count=1,
                    organization_id=org_id,
                )
                db.add(ioc)
                created_count += 1

        except Exception as e:
            failures.append({"value": ioc_data.value, "error": str(e)})

    await db.flush()

    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "failure_count": len(failures),
        "failures": failures,
    }


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(
    ioc_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get an IOC by ID."""
    ioc = await get_ioc_or_404(db, ioc_id)
    return ioc_to_response(ioc)


@router.patch("/{ioc_id}", response_model=IOCResponse)
async def update_ioc(
    ioc_id: str,
    ioc_data: IOCUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an IOC."""
    ioc = await get_ioc_or_404(db, ioc_id)

    update_data = ioc_data.model_dump(exclude_unset=True, exclude_none=True)
    ctx = dict(ioc.context) if isinstance(ioc.context, dict) else {}

    # Handle legacy fields that map into ThreatIndicator columns
    if "status" in update_data:
        ioc.is_active = update_data.pop("status") == "active"
    if "threat_level" in update_data:
        ioc.severity = update_data.pop("threat_level")
    if "confidence" in update_data:
        ioc.confidence = update_data.pop("confidence")
    if "tags" in update_data:
        ioc.tags = update_data.pop("tags") or []
    if "is_whitelisted" in update_data:
        ioc.is_whitelisted = update_data.pop("is_whitelisted")
    if "expires_at" in update_data:
        ioc.expires_at = _parse_dt(update_data.pop("expires_at"))

    # Everything else goes into context
    for legacy_key in (
        "description", "category", "malware_family", "threat_actor", "campaign",
    ):
        if legacy_key in update_data:
            ctx[legacy_key] = update_data.pop(legacy_key)

    if ctx != ioc.context:
        ioc.context = ctx

    await db.flush()
    await db.refresh(ioc)

    return ioc_to_response(ioc)


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(
    ioc_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete an IOC."""
    ioc = await get_ioc_or_404(db, ioc_id)
    await db.delete(ioc)
    await db.flush()


@router.post("/search", response_model=list[IOCResponse])
async def search_ioc(
    search_data: IOCSearchRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Search for an IOC by value."""
    query = select(ThreatIndicator).where(ThreatIndicator.value == search_data.value)
    if search_data.ioc_type:
        query = query.where(ThreatIndicator.indicator_type == search_data.ioc_type)

    result = await db.execute(query)
    iocs = list(result.scalars().all())

    now = datetime.now(timezone.utc)
    for ioc in iocs:
        ioc.last_seen = now
        ioc.sighting_count = (ioc.sighting_count or 0) + 1

    await db.flush()

    return [ioc_to_response(ioc) for ioc in iocs]


@router.post("/{ioc_id}/enrich", response_model=IOCResponse)
async def enrich_ioc(
    ioc_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Enrich an IOC by aggregating all matching threat indicators by value.

    Because ioc and threat_indicators are now the same table, enrichment
    means "look for other rows with the same value across different feeds
    and fold their context together."
    """
    ioc = await get_ioc_or_404(db, ioc_id)

    sibling_result = await db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.value == ioc.value,
            ThreatIndicator.id != ioc.id,
            ThreatIndicator.is_active == True,  # noqa: E712
        )
    )
    siblings = list(sibling_result.scalars().all())

    ctx = dict(ioc.context) if isinstance(ioc.context, dict) else {}
    enrichment = dict(ctx.get("enrichment_data") or {})

    for sib in siblings:
        key = f"feed_{sib.feed_id}" if sib.feed_id else f"local_{sib.id[:8]}"
        enrichment[key] = {
            "confidence": sib.confidence,
            "severity": sib.severity,
            "tags": sib.tags,
            "context": sib.context,
            "first_seen": _dt_iso(sib.first_seen),
            "last_seen": _dt_iso(sib.last_seen),
            "sighting_count": sib.sighting_count,
            "mitre_tactics": sib.mitre_tactics,
            "mitre_techniques": sib.mitre_techniques,
            "source": sib.source,
        }

    if siblings:
        scores = [s.confidence for s in siblings if s.confidence is not None]
        if scores:
            enrichment["composite_confidence"] = int(sum(scores) / len(scores))
            enrichment["source_count"] = len(siblings) + 1

    ctx["enrichment_data"] = enrichment
    ctx["last_enriched"] = datetime.now(timezone.utc).isoformat()
    ioc.context = ctx

    await db.flush()
    await db.refresh(ioc)

    return ioc_to_response(ioc)
