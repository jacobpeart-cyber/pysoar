"""Asset management endpoints"""

import json
import math
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.models.asset import Asset, AssetStatus
from src.schemas.asset import (
    AssetCreate,
    AssetListResponse,
    AssetResponse,
    AssetUpdate,
)

router = APIRouter(prefix="/assets", tags=["Assets"])


async def get_asset_or_404(db: AsyncSession, asset_id: str) -> Asset:
    """Get Asset by ID or raise 404"""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )
    return asset


def asset_to_response(asset: Asset) -> AssetResponse:
    """Convert Asset model to response schema"""
    tags = json.loads(asset.tags) if asset.tags else None

    return AssetResponse(
        id=asset.id,
        name=asset.name,
        hostname=asset.hostname,
        asset_type=asset.asset_type,
        status=asset.status,
        ip_address=asset.ip_address,
        mac_address=asset.mac_address,
        fqdn=asset.fqdn,
        criticality=asset.criticality,
        business_unit=asset.business_unit,
        department=asset.department,
        owner=asset.owner,
        location=asset.location,
        operating_system=asset.operating_system,
        os_version=asset.os_version,
        cloud_provider=asset.cloud_provider,
        cloud_region=asset.cloud_region,
        cloud_instance_id=asset.cloud_instance_id,
        security_score=asset.security_score,
        last_scan=asset.last_scan,
        description=asset.description,
        tags=tags,
        is_monitored=asset.is_monitored,
        agent_installed=asset.agent_installed,
        last_seen=asset.last_seen,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


@router.get("", response_model=AssetListResponse)
async def list_assets(
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    asset_type: Optional[str] = None,
    asset_status: Optional[str] = Query(None, alias="status"),
    criticality: Optional[str] = None,
):
    """List assets with filtering and pagination"""
    query = select(Asset)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (Asset.name.ilike(search_filter))
            | (Asset.hostname.ilike(search_filter))
            | (Asset.ip_address.ilike(search_filter))
            | (Asset.description.ilike(search_filter))
        )

    if asset_type:
        query = query.where(Asset.asset_type == asset_type)

    if asset_status:
        query = query.where(Asset.status == asset_status)

    if criticality:
        query = query.where(Asset.criticality == criticality)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(Asset.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    assets = list(result.scalars().all())

    return AssetListResponse(
        items=[asset_to_response(asset) for asset in assets],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_data: AssetCreate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Create a new asset"""
    asset = Asset(
        name=asset_data.name,
        hostname=asset_data.hostname,
        asset_type=asset_data.asset_type,
        status=asset_data.status,
        ip_address=asset_data.ip_address,
        mac_address=asset_data.mac_address,
        fqdn=asset_data.fqdn,
        criticality=asset_data.criticality,
        business_unit=asset_data.business_unit,
        department=asset_data.department,
        owner=asset_data.owner,
        location=asset_data.location,
        operating_system=asset_data.operating_system,
        os_version=asset_data.os_version,
        cloud_provider=asset_data.cloud_provider,
        cloud_region=asset_data.cloud_region,
        cloud_instance_id=asset_data.cloud_instance_id,
        description=asset_data.description,
        tags=json.dumps(asset_data.tags) if asset_data.tags else None,
        is_monitored=asset_data.is_monitored,
        agent_installed=asset_data.agent_installed,
    )

    db.add(asset)
    await db.flush()
    await db.refresh(asset)

    return asset_to_response(asset)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get an asset by ID"""
    asset = await get_asset_or_404(db, asset_id)
    return asset_to_response(asset)


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: str,
    asset_data: AssetUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Update an asset"""
    asset = await get_asset_or_404(db, asset_id)

    update_data = asset_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle JSON fields
    if "tags" in update_data:
        update_data["tags"] = json.dumps(update_data["tags"])

    for key, value in update_data.items():
        setattr(asset, key, value)

    await db.flush()
    await db.refresh(asset)

    return asset_to_response(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Delete an asset"""
    asset = await get_asset_or_404(db, asset_id)
    await db.delete(asset)
    await db.flush()
