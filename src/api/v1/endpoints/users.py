"""User management endpoints.

Tenancy and RBAC (wave 1):

* Listing users and every write on another user (create, update, role or
  active-status change, delete) is ``admin`` only and confined to the caller's
  organisation (``OrganizationId``): a user of another organisation is
  reported as missing (404). An org-less platform superuser gets 403
  ``organization_required`` here; cross-tenant user administration is not
  offered by this router.
* A tenant admin can never touch a platform superuser account, and no route
  here can set ``is_superuser`` (it is not part of any request schema).
* ``role`` must be one of ``admin`` / ``analyst`` / ``viewer``.
* Self-service stays ``CurrentUser``: anyone can read their own record and edit
  their own profile fields. Password changes go through
  ``/auth/change-password`` (which verifies the current password and revokes
  tokens), and the email address cannot be changed through this router.
"""

import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    require_role,
    resolve_organization_scope,
)
from src.core.exceptions import NotFoundError, ValidationError
from src.core.logging import get_logger
from src.models.user import User, UserRole
from src.schemas.user import (
    UserCreate,
    UserListResponse,
    UserResponse,
    UserUpdate,
)
from src.services.user_service import UserService

logger = get_logger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])

_VALID_ROLES: frozenset[str] = frozenset(r.value for r in UserRole)


def _user_not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")


def _validate_role(role: Optional[str]) -> None:
    if role is not None and role not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"role must be one of {sorted(_VALID_ROLES)}",
        )


async def _get_tenant_user(
    user_service: UserService, user_id: str, org_id: str, caller: User
) -> User:
    """The target user inside ``org_id``; 404 outside it.

    A platform superuser account is never manageable by a tenant admin, even
    when it carries the same organisation id: it is reported as missing.
    """
    target = await user_service.get_by_id(user_id)
    if target is None or str(target.organization_id or "") != org_id:
        raise _user_not_found()
    if target.is_superuser and not caller.is_superuser:
        raise _user_not_found()
    return target


@router.get("", response_model=UserListResponse)
async def list_users(
    org_id: OrganizationId,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
):
    """List the users of the caller's organisation (admin only)."""
    user_service = UserService(db)
    users, total = await user_service.list_users(
        page=page,
        size=size,
        search=search,
        role=role,
        is_active=is_active,
        organization_id=org_id,
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
    org_id: OrganizationId,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    db: DatabaseSession = None,
):
    """Create a user in the caller's organisation (admin only, never a superuser)."""
    _validate_role(user_data.role)
    user_service = UserService(db)

    try:
        user = await user_service.create(
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            role=user_data.role,
            is_superuser=False,
            organization_id=org_id,
        )
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )

    logger.info("user_created", user_id=user.id, organization_id=org_id, actor_id=current_user.id)
    return UserResponse.model_validate(user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a user by ID: yourself, or (admin only) a user of your organisation."""
    if user_id == current_user.id:
        return UserResponse.model_validate(current_user)

    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    org_id = resolve_organization_scope(current_user, None)

    user_service = UserService(db)
    user = await _get_tenant_user(user_service, user_id, org_id, current_user)
    return UserResponse.model_validate(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    organization_id: Optional[str] = Query(
        None, description="platform superuser only: the tenant whose user is edited"
    ),
):
    """Update a user: your own profile, or (admin only) a user of your organisation.

    * Self-service: profile fields only. ``role`` / ``is_active`` may be sent
      unchanged (the admin UI posts the whole row) but never changed on your
      own account (403 ``privileged_field``), so nobody self-promotes and an
      admin cannot lock themselves out.
    * Another user: tenant ``admin`` of that user's organisation, or a platform
      superuser naming the tenant with ``organization_id``. A user of another
      organisation is reported as missing (404).
    """
    user_service = UserService(db)
    update_data = user_data.model_dump(exclude_unset=True, exclude_none=True)

    if user_id == current_user.id:
        # Self-service profile edit. Role and active status are never
        # self-assigned; password and email changes are not taken here
        # (/auth/change-password verifies the current password).
        changed_privileged = sorted(
            field
            for field in ("role", "is_active")
            if field in update_data and update_data[field] != getattr(current_user, field)
        )
        if changed_privileged:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "privileged_field",
                    "detail": f"{', '.join(changed_privileged)} cannot be changed on your own account",
                },
            )
        update_data.pop("role", None)
        update_data.pop("is_active", None)
        if "password" in update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Use /auth/change-password to change your own password",
            )
        new_email = str(update_data.pop("email", "") or "").lower()
        if new_email and new_email != (current_user.email or "").lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The email address cannot be changed here",
            )
    else:
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
            )
        org_id = resolve_organization_scope(current_user, organization_id)
        _validate_role(update_data.get("role"))
        await _get_tenant_user(user_service, user_id, org_id, current_user)

    try:
        user = await user_service.update(user_id, **update_data)
    except NotFoundError:
        raise _user_not_found()
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )

    if user_id != current_user.id:
        logger.info(
            "user_updated",
            user_id=user_id,
            fields=sorted(update_data.keys()),
            actor_id=current_user.id,
        )
    return UserResponse.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    org_id: OrganizationId,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    db: DatabaseSession = None,
):
    """Delete a user of the caller's organisation (admin only)."""
    # Prevent self-deletion
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    user_service = UserService(db)
    await _get_tenant_user(user_service, user_id, org_id, current_user)

    try:
        await user_service.delete(user_id)
    except NotFoundError:
        raise _user_not_found()

    logger.info("user_deleted", user_id=user_id, organization_id=org_id, actor_id=current_user.id)
