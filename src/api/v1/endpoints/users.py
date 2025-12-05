"""User management endpoints"""

import math

from fastapi import APIRouter, HTTPException, Query, status

from src.api.deps import AdminUser, CurrentUser, DatabaseSession
from src.core.exceptions import NotFoundError, ValidationError
from src.schemas.user import (
    UserCreate,
    UserListResponse,
    UserResponse,
    UserUpdate,
)
from src.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=UserListResponse)
async def list_users(
    current_user: AdminUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
):
    """List all users (admin only)"""
    user_service = UserService(db)
    users, total = await user_service.list_users(
        page=page,
        size=size,
        search=search,
        role=role,
        is_active=is_active,
    )

    return UserListResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: AdminUser,
    db: DatabaseSession,
):
    """Create a new user (admin only)"""
    user_service = UserService(db)

    try:
        user = await user_service.create(
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            role=user_data.role,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return UserResponse.model_validate(user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get a user by ID"""
    # Users can view their own profile, admins can view any profile
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    user_service = UserService(db)
    user = await user_service.get_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return UserResponse.model_validate(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Update a user"""
    # Users can update their own profile (limited fields), admins can update any profile
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Non-admins cannot change role or active status
    if not current_user.is_admin:
        user_data.role = None
        user_data.is_active = None

    user_service = UserService(db)

    try:
        update_data = user_data.model_dump(exclude_unset=True, exclude_none=True)
        user = await user_service.update(user_id, **update_data)
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return UserResponse.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: AdminUser,
    db: DatabaseSession,
):
    """Delete a user (admin only)"""
    # Prevent self-deletion
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    user_service = UserService(db)

    try:
        await user_service.delete(user_id)
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
