"""IOC (Indicator of Compromise) management endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.models.ioc import IOC, IOCStatus
from src.schemas.ioc import (
    IOCBulkCreate,
    IOCCreate,
    IOCEnrichRequest,
    IOCListResponse,
    IOCResponse,
    IOCSearchRequest,
    IOCUpdate,
)

router = APIRouter(prefix="/iocs", tags=["IOCs"])


async def get_ioc_or_404(db: AsyncSession, ioc_id: str) -> IOC:
    """Get IOC by ID or raise 404"""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found",
        )
    return ioc


def ioc_to_response(ioc: IOC) -> IOCResponse:
    """Convert IOC model to response schema"""
    tags = json.loads(ioc.tags) if ioc.tags else None
    mitre_tactics = json.loads(ioc.mitre_tactics) if ioc.mitre_tactics else None
    mitre_techniques = json.loads(ioc.mitre_techniques) if ioc.mitre_techniques else None
    enrichment_data = json.loads(ioc.enrichment_data) if ioc.enrichment_data else None

    return IOCResponse(
        id=ioc.id,
        value=ioc.value,
        ioc_type=ioc.ioc_type,
        status=ioc.status,
        threat_level=ioc.threat_level,
        confidence=ioc.confidence,
        description=ioc.description,
        tags=tags,
        category=ioc.category,
        source=ioc.source,
        source_url=ioc.source_url,
        source_reference=ioc.source_reference,
        malware_family=ioc.malware_family,
        threat_actor=ioc.threat_actor,
        campaign=ioc.campaign,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        enrichment_data=enrichment_data,
        last_enriched=ioc.last_enriched,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        expires_at=ioc.expires_at,
        sighting_count=ioc.sighting_count,
        last_sighting=ioc.last_sighting,
        is_whitelisted=ioc.is_whitelisted,
        is_internal=ioc.is_internal,
        created_at=ioc.created_at,
        updated_at=ioc.updated_at,
    )


@router.get("", response_model=IOCListResponse)
async def list_iocs(
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    ioc_type: Optional[str] = None,
    ioc_status: Optional[str] = Query(None, alias="status"),
    threat_level: Optional[str] = None,
    is_whitelisted: Optional[bool] = None,
):
    """List IOCs with filtering and pagination"""
    query = select(IOC)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (IOC.value.ilike(search_filter))
            | (IOC.description.ilike(search_filter))
            | (IOC.malware_family.ilike(search_filter))
            | (IOC.threat_actor.ilike(search_filter))
        )

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)

    if ioc_status:
        query = query.where(IOC.status == ioc_status)

    if threat_level:
        query = query.where(IOC.threat_level == threat_level)

    if is_whitelisted is not None:
        query = query.where(IOC.is_whitelisted == is_whitelisted)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(IOC.created_at.desc())
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
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Create a new IOC"""
    # Check for duplicate
    result = await db.execute(
        select(IOC).where(
            (IOC.value == ioc_data.value) & (IOC.ioc_type == ioc_data.ioc_type)
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update sighting count and return existing
        existing.sighting_count += 1
        existing.last_sighting = datetime.now(timezone.utc).isoformat()
        await db.flush()
        await db.refresh(existing)
        return ioc_to_response(existing)

    ioc = IOC(
        value=ioc_data.value,
        ioc_type=ioc_data.ioc_type,
        status=IOCStatus.ACTIVE.value,
        threat_level=ioc_data.threat_level,
        confidence=ioc_data.confidence,
        description=ioc_data.description,
        tags=json.dumps(ioc_data.tags) if ioc_data.tags else None,
        category=ioc_data.category,
        source=ioc_data.source,
        source_url=ioc_data.source_url,
        source_reference=ioc_data.source_reference,
        malware_family=ioc_data.malware_family,
        threat_actor=ioc_data.threat_actor,
        campaign=ioc_data.campaign,
        mitre_tactics=json.dumps(ioc_data.mitre_tactics) if ioc_data.mitre_tactics else None,
        mitre_techniques=json.dumps(ioc_data.mitre_techniques) if ioc_data.mitre_techniques else None,
        expires_at=ioc_data.expires_at,
        first_seen=datetime.now(timezone.utc).isoformat(),
        sighting_count=1,
    )

    db.add(ioc)
    await db.flush()
    await db.refresh(ioc)

    return ioc_to_response(ioc)


@router.post("/bulk", response_model=dict)
async def bulk_create_iocs(
    bulk_data: IOCBulkCreate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Bulk create IOCs"""
    created_count = 0
    updated_count = 0
    failures = []

    for ioc_data in bulk_data.iocs:
        try:
            # Check for duplicate
            result = await db.execute(
                select(IOC).where(
                    (IOC.value == ioc_data.value) & (IOC.ioc_type == ioc_data.ioc_type)
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.sighting_count += 1
                existing.last_sighting = datetime.now(timezone.utc).isoformat()
                updated_count += 1
            else:
                ioc = IOC(
                    value=ioc_data.value,
                    ioc_type=ioc_data.ioc_type,
                    status=IOCStatus.ACTIVE.value,
                    threat_level=ioc_data.threat_level,
                    confidence=ioc_data.confidence,
                    description=ioc_data.description,
                    tags=json.dumps(ioc_data.tags) if ioc_data.tags else None,
                    category=ioc_data.category,
                    source=ioc_data.source,
                    first_seen=datetime.now(timezone.utc).isoformat(),
                    sighting_count=1,
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
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get an IOC by ID"""
    ioc = await get_ioc_or_404(db, ioc_id)
    return ioc_to_response(ioc)


@router.patch("/{ioc_id}", response_model=IOCResponse)
async def update_ioc(
    ioc_id: str,
    ioc_data: IOCUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Update an IOC"""
    ioc = await get_ioc_or_404(db, ioc_id)

    update_data = ioc_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle JSON fields
    if "tags" in update_data:
        update_data["tags"] = json.dumps(update_data["tags"])

    for key, value in update_data.items():
        setattr(ioc, key, value)

    await db.flush()
    await db.refresh(ioc)

    return ioc_to_response(ioc)


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(
    ioc_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Delete an IOC"""
    ioc = await get_ioc_or_404(db, ioc_id)
    await db.delete(ioc)
    await db.flush()


@router.post("/search", response_model=list[IOCResponse])
async def search_ioc(
    search_data: IOCSearchRequest,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Search for an IOC by value"""
    query = select(IOC).where(IOC.value == search_data.value)

    if search_data.ioc_type:
        query = query.where(IOC.ioc_type == search_data.ioc_type)

    result = await db.execute(query)
    iocs = list(result.scalars().all())

    # Update last_seen for found IOCs
    now = datetime.now(timezone.utc).isoformat()
    for ioc in iocs:
        ioc.last_seen = now
        ioc.sighting_count += 1

    await db.flush()

    return [ioc_to_response(ioc) for ioc in iocs]


@router.post("/{ioc_id}/enrich", response_model=IOCResponse)
async def enrich_ioc(
    ioc_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Enrich an IOC with threat intelligence"""
    ioc = await get_ioc_or_404(db, ioc_id)

    # In production, this would call threat intelligence integrations
    # For now, we just mark it as enriched
    ioc.last_enriched = datetime.now(timezone.utc).isoformat()
    await db.flush()
    await db.refresh(ioc)

    return ioc_to_response(ioc)
