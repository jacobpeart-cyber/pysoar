"""API Key management endpoints"""

import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_admin_user
from src.core.security import get_password_hash, verify_password
from src.models.api_key import APIKey, APIKeyPermission
from src.models.user import User

router = APIRouter()


class APIKeyCreate(BaseModel):
    """Schema for creating an API key"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    allowed_ips: Optional[list[str]] = None
    rate_limit: int = Field(default=1000, ge=1, le=100000)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    """Schema for API key response"""

    id: str
    name: str
    description: Optional[str]
    key_prefix: str
    permissions: list[str]
    allowed_ips: Optional[list[str]]
    rate_limit: int
    is_active: bool
    expires_at: Optional[str]
    last_used_at: Optional[str]
    usage_count: int
    created_at: str

    class Config:
        from_attributes = True


class APIKeyCreatedResponse(APIKeyResponse):
    """Response when creating a new API key (includes the full key)"""

    api_key: str  # Only shown once at creation


class APIKeyUpdate(BaseModel):
    """Schema for updating an API key"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    permissions: Optional[list[str]] = None
    allowed_ips: Optional[list[str]] = None
    rate_limit: Optional[int] = Field(None, ge=1, le=100000)
    is_active: Optional[bool] = None


@router.get("", response_model=list[APIKeyResponse])
async def list_api_keys(
    db: DatabaseSession,
    current_user: CurrentUser,
    include_inactive: bool = Query(default=False),
):
    """List all API keys for the current user"""
    query = select(APIKey).where(APIKey.owner_id == current_user.id)

    if not include_inactive:
        query = query.where(APIKey.is_active == True)

    query = query.order_by(APIKey.created_at.desc())

    result = await db.execute(query)
    keys = result.scalars().all()

    return [_format_api_key(key) for key in keys]


@router.post("", response_model=APIKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: APIKeyCreate,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Create a new API key"""
    # Validate permissions
    available_perms = APIKeyPermission.all_permissions() + ["*"]
    for perm in data.permissions:
        if perm not in available_perms and not perm.endswith(":*"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid permission: {perm}",
            )

    # Non-admins can only create keys with limited permissions
    if not current_user.is_admin:
        admin_perms = ["users:read", "users:write", "settings:read", "settings:write", "*"]
        if any(perm in admin_perms for perm in data.permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can create keys with admin permissions",
            )

    # Generate the key
    full_key, key_prefix, key_to_hash = APIKey.generate_key()

    # Calculate expiration
    expires_at = None
    if data.expires_in_days:
        expires_at = (datetime.utcnow() + timedelta(days=data.expires_in_days)).isoformat()

    # Create the API key
    api_key = APIKey(
        name=data.name,
        description=data.description,
        key_prefix=key_prefix,
        key_hash=get_password_hash(key_to_hash),
        permissions=json.dumps(data.permissions) if data.permissions else None,
        allowed_ips=json.dumps(data.allowed_ips) if data.allowed_ips else None,
        rate_limit=data.rate_limit,
        expires_at=expires_at,
        owner_id=current_user.id,
    )

    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    response = _format_api_key(api_key)
    response["api_key"] = full_key  # Include the full key in creation response

    return response


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get an API key by ID"""
    api_key = await _get_user_api_key(db, key_id, current_user)
    return _format_api_key(api_key)


@router.patch("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: str,
    data: APIKeyUpdate,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Update an API key"""
    api_key = await _get_user_api_key(db, key_id, current_user)

    if data.name is not None:
        api_key.name = data.name
    if data.description is not None:
        api_key.description = data.description
    if data.permissions is not None:
        api_key.permissions = json.dumps(data.permissions)
    if data.allowed_ips is not None:
        api_key.allowed_ips = json.dumps(data.allowed_ips)
    if data.rate_limit is not None:
        api_key.rate_limit = data.rate_limit
    if data.is_active is not None:
        api_key.is_active = data.is_active

    await db.commit()
    await db.refresh(api_key)

    return _format_api_key(api_key)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    key_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Delete an API key"""
    api_key = await _get_user_api_key(db, key_id, current_user)
    await db.delete(api_key)
    await db.commit()


@router.post("/{key_id}/regenerate", response_model=APIKeyCreatedResponse)
async def regenerate_api_key(
    key_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Regenerate an API key (creates a new key value)"""
    api_key = await _get_user_api_key(db, key_id, current_user)

    # Generate new key
    full_key, key_prefix, key_to_hash = APIKey.generate_key()

    api_key.key_prefix = key_prefix
    api_key.key_hash = get_password_hash(key_to_hash)
    api_key.usage_count = 0
    api_key.last_used_at = None
    api_key.last_used_ip = None

    await db.commit()
    await db.refresh(api_key)

    response = _format_api_key(api_key)
    response["api_key"] = full_key

    return response


@router.get("/permissions/available", response_model=list[str])
async def list_available_permissions(
    current_user: CurrentUser,
):
    """List all available permissions"""
    return APIKeyPermission.all_permissions()


# Admin endpoints
@router.get("/admin/all", response_model=list[APIKeyResponse])
async def list_all_api_keys(
    db: DatabaseSession,
    admin_user: User = Depends(get_current_admin_user),
):
    """List all API keys (admin only)"""
    result = await db.execute(
        select(APIKey).order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [_format_api_key(key) for key in keys]


async def _get_user_api_key(
    db: AsyncSession,
    key_id: str,
    user: User,
) -> APIKey:
    """Get an API key, ensuring it belongs to the user (or user is admin)"""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    if api_key.owner_id != user.id and not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this API key",
        )

    return api_key


def _format_api_key(api_key: APIKey) -> dict:
    """Format an API key for response"""
    return {
        "id": api_key.id,
        "name": api_key.name,
        "description": api_key.description,
        "key_prefix": api_key.key_prefix,
        "permissions": json.loads(api_key.permissions) if api_key.permissions else [],
        "allowed_ips": json.loads(api_key.allowed_ips) if api_key.allowed_ips else None,
        "rate_limit": api_key.rate_limit,
        "is_active": api_key.is_active,
        "expires_at": api_key.expires_at,
        "last_used_at": api_key.last_used_at,
        "usage_count": api_key.usage_count,
        "created_at": api_key.created_at,
    }
