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
* ``custom_role_id`` (create / patch, admin only) assigns a custom role of the
  caller's organisation (422 ``role_not_found`` otherwise; never to a platform
  superuser, 422 ``superuser_custom_role``; never broader than the caller's own
  tiers, 403 ``tier_exceeds_caller``); ``null`` clears it. Assigning stores
  ``role`` as ``viewer`` (src/identity/roles.py, built-in role floor). Every
  assignment change is audited (``user_custom_role_changed``). Nobody changes
  their own custom role (403 ``privileged_field``).
* "admin" here means tier admin in the ``users`` area: the built-in admin role,
  or a custom role granting it.
* Self-service stays ``CurrentUser``: anyone can read their own record and edit
  their own profile fields. Password changes go through
  ``/auth/change-password`` (which verifies the current password and revokes
  tokens), and the email address cannot be changed through this router.
"""

import json
import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from src.api.deps import (
    RedisClient,
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    require_role,
    resolve_organization_scope,
)
from src.core.exceptions import NotFoundError, ValidationError
from src.core.logging import get_logger
from src.core.password_policy import PasswordValidator
from src.core.token_blacklist import TokenBlacklist
from src.identity import roles as identity_roles
from src.identity.models import Role
from src.models.audit import AuditLog
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


def _is_user_admin(user: User) -> bool:
    """Tier admin in the ``users`` area (``is_admin`` for users without a custom role)."""
    return identity_roles.has_tier(user, "users", "admin")


async def _resolve_custom_role(
    db, role_id: str, org_id: str, target: Optional[User], caller: User, areas: set[str],
) -> Role:
    """The custom role ``role_id`` of ``org_id``, checked for assignment to
    ``target`` (``None`` while creating) by ``caller``."""
    role = await db.get(Role, role_id)
    if role is None or str(role.organization_id) != org_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "role_not_found", "detail": "custom role not found in this organisation"},
        )
    if target is not None:
        problem = identity_roles.assignment_error(target, role, org_id)
        if problem:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=problem)
    over = identity_roles.escalation_areas(
        caller, role.default_tier, dict(role.area_tiers or {}), set(role.area_tiers or {}) | areas,
    )
    if over:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "tier_exceeds_caller",
                "areas": over,
                "detail": "you cannot assign a role that grants more than you hold yourself",
            },
        )
    return role


def _check_builtin_role_grant(caller: User, role: Optional[str], areas: set[str]) -> None:
    """A custom-role holder cannot hand out a built-in role broader than the
    tiers they hold themselves (403 ``tier_exceeds_caller``). Built-in admins
    and superusers always pass."""
    if not role or not identity_roles.has_custom_role(caller):
        return
    over = identity_roles.escalation_areas(caller, identity_roles.BUILTIN_ROLE_TIERS.get(role, "admin"), {}, areas)
    if over:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "tier_exceeds_caller",
                "areas": over,
                "detail": f"you cannot grant the built-in {role} role: it exceeds your own access",
            },
        )


def _audit_custom_role(db, caller: User, org_id: str, target_id: str, old: Optional[str], new: Optional[Role]) -> None:
    db.add(AuditLog(
        user_id=str(caller.id),
        organization_id=org_id,
        action="user_custom_role_changed",
        resource_type="user",
        resource_id=target_id,
        description=(f"Custom role {new.name!r} assigned" if new is not None else "Custom role cleared"),
        old_value=json.dumps({"custom_role_id": old}),
        new_value=json.dumps({"custom_role_id": str(new.id) if new is not None else None,
                              "role": "viewer" if new is not None else None}),
        success=True,
    ))


async def _target_escalation_areas(db, caller: User, target: User, areas) -> list[str]:
    """Areas where ``target`` holds more than ``caller`` does.

    A caller may not change the credentials, status, role or existence of an
    account that outranks them anywhere (a custom-role holder with admin over
    ``users`` must not be able to take over a built-in administrator). Empty
    for superusers and built-in admins; a target whose custom role cannot be
    loaded holds nothing.
    """
    if getattr(caller, "is_superuser", False):
        return []
    if target.custom_role_id:
        role = await db.get(Role, str(target.custom_role_id))
        if role is None or str(role.organization_id) != str(target.organization_id or ""):
            return []
        return identity_roles.escalation_areas(caller, role.default_tier, dict(role.area_tiers or {}), areas)
    builtin = identity_roles.BUILTIN_ROLE_TIERS.get(target.role or "", "none")
    return identity_roles.escalation_areas(caller, builtin, {}, areas)


def _target_outranks_caller(areas: list[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "tier_exceeds_caller",
            "areas": areas,
            "detail": "that account holds more than you do in these areas; a full administrator must make this change",
        },
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
    request: Request,
    org_id: OrganizationId,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    db: DatabaseSession = None,
):
    """Create a user in the caller's organisation (admin only, never a superuser)."""
    _validate_role(user_data.role)
    user_service = UserService(db)
    custom_role = (
        await _resolve_custom_role(
            db, user_data.custom_role_id, org_id, None, current_user, identity_roles.known_areas(request.app),
        )
        if user_data.custom_role_id else None
    )
    if custom_role is None:
        _check_builtin_role_grant(current_user, user_data.role, identity_roles.known_areas(request.app))

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

    if custom_role is not None:
        identity_roles.apply_custom_role(user, custom_role)
        _audit_custom_role(db, current_user, org_id, str(user.id), None, custom_role)
        await db.flush()
        await db.refresh(user)

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

    if not _is_user_admin(current_user):
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
    request: Request,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
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
    # ``custom_role_id: null`` means "clear", so it is read from the unset-only dump.
    custom_role_sent = "custom_role_id" in user_data.model_fields_set
    new_custom_role_id = user_data.custom_role_id
    update_data.pop("custom_role_id", None)
    custom_role: Optional[Role] = None
    target: Optional[User] = None
    org_id: Optional[str] = None

    if user_id == current_user.id:
        # Self-service profile edit. Role and active status are never
        # self-assigned; password and email changes are not taken here
        # (/auth/change-password verifies the current password).
        changed_privileged = sorted(
            field
            for field in ("role", "is_active")
            if field in update_data and update_data[field] != getattr(current_user, field)
        )
        if custom_role_sent and (new_custom_role_id or None) != (current_user.custom_role_id or None):
            changed_privileged = sorted([*changed_privileged, "custom_role_id"])
        custom_role_sent = False
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
        if not _is_user_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
            )
        org_id = resolve_organization_scope(current_user, organization_id)
        _validate_role(update_data.get("role"))
        target = await _get_tenant_user(user_service, user_id, org_id, current_user)
        outranks = await _target_escalation_areas(db, current_user, target, identity_roles.known_areas(request.app))
        if outranks:
            raise _target_outranks_caller(outranks)
        provider_managed = (target.identity_source or "local") != "local"
        if provider_managed and (
            "password" in update_data or ("email" in update_data and update_data["email"].lower() != target.email.lower())
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "sso_managed",
                    "detail": "this account signs in through the organisation's identity provider; "
                    "its password and email are managed there",
                },
            )
        if "password" in update_data:
            is_valid, errors = PasswordValidator.validate(update_data["password"], settings={"email": target.email})
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "password_policy",
                        "detail": "Password does not meet requirements: " + "; ".join(errors),
                        "errors": list(errors),
                    },
                )
            # An administrator-set password is temporary: the user chooses their
            # own at the next sign-in, and every existing session is revoked.
            update_data["force_password_change"] = True
        if custom_role_sent and new_custom_role_id:
            custom_role = await _resolve_custom_role(
                db, new_custom_role_id, org_id, target, current_user, identity_roles.known_areas(request.app),
            )
        if custom_role_sent and (new_custom_role_id or None) == (target.custom_role_id or None):
            custom_role_sent = False  # unchanged (the admin UI posts the whole row)
        keeps_custom_role = bool(new_custom_role_id) if custom_role_sent else bool(target.custom_role_id)
        if "role" in update_data and update_data["role"] != target.role and not keeps_custom_role:
            _check_builtin_role_grant(current_user, update_data["role"], identity_roles.known_areas(request.app))

    try:
        user = await user_service.update(user_id, **update_data)
    except NotFoundError:
        raise _user_not_found()
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )

    if "password" in update_data and user_id != current_user.id and redis is not None:
        await TokenBlacklist(redis).revoke_all_user_tokens(str(user.id))
        db.add(AuditLog(
            user_id=str(current_user.id),
            organization_id=org_id,
            action="user_password_set_by_admin",
            resource_type="user",
            resource_id=str(user.id),
            description="administrator set a temporary password; sessions revoked; change required at next sign-in",
            success=True,
        ))
        await db.flush()
    if custom_role_sent and org_id is not None:
        old_custom_role_id = user.custom_role_id
        identity_roles.apply_custom_role(user, custom_role)
        _audit_custom_role(db, current_user, org_id, str(user.id), old_custom_role_id, custom_role)
        await db.flush()
        await db.refresh(user)
    if user.custom_role_id and user.role != UserRole.VIEWER.value:
        # Built-in role floor: a custom-role holder's ``role`` stays viewer
        # whatever the request sent (src/identity/roles.py).
        user.role = UserRole.VIEWER.value
        await db.flush()
        await db.refresh(user)

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
    request: Request,
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
    target = await _get_tenant_user(user_service, user_id, org_id, current_user)
    outranks = await _target_escalation_areas(db, current_user, target, identity_roles.known_areas(request.app))
    if outranks:
        raise _target_outranks_caller(outranks)

    try:
        await user_service.delete(user_id)
    except NotFoundError:
        raise _user_not_found()

    logger.info("user_deleted", user_id=user_id, organization_id=org_id, actor_id=current_user.id)
