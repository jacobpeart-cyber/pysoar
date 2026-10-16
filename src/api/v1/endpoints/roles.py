"""Custom roles: per-area access tiers for an organisation (admin only).

A custom role has a ``default_tier`` and per-area overrides (``area_tiers``);
a user holding one (``User.custom_role_id``, assigned through ``/users``) is
judged by it in every area instead of the built-in ``role``. Enforcement is in
``src.api.deps`` and ``src.identity.roles`` (see that module's docstring for
the tier model, exempt areas and the built-in role floor).

Every route is ``admin`` (tier admin in the ``roles`` area) and confined to the
caller's organisation (``OrganizationId``: an org-less caller, including the
platform superuser, gets 403 ``organization_required``). A role of another
organisation is reported as missing (404 ``role_not_found``). Create, update
and delete are audited. Role changes take effect on the holders' next request
(the role is loaded per request); no token revocation is needed.
"""

import json
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.core.logging import get_logger
from src.identity import roles as identity_roles
from src.identity.models import BUILTIN_ROLE_TIERS, TIER_ORDER, Role
from src.models.audit import AuditLog
from src.models.user import User, UserRole
from src.schemas.identity import (
    AreaCatalogueResponse,
    AreaEntry,
    BuiltinRoleResponse,
    RoleCreate,
    RoleListResponse,
    RoleMember,
    RoleMembersResponse,
    RoleResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/roles", tags=["Roles"])

RolesAdmin = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

_BUILTIN_DESCRIPTIONS: dict[str, str] = {
    "viewer": "Read access in every area.",
    "analyst": "Read and operational write access in every area (no configuration).",
    "admin": "Full access in every area, including configuration and user management.",
}


def _role_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": "role_not_found", "detail": "custom role not found in this organisation"},
    )


async def _get_org_role(db: AsyncSession, role_id: str, org_id: str) -> Role:
    role = await db.get(Role, role_id)
    if role is None or str(role.organization_id) != org_id:
        raise _role_not_found()
    return role


async def _member_counts(db: AsyncSession, org_id: str) -> dict[str, int]:
    rows = await db.execute(
        select(User.custom_role_id, func.count(User.id))
        .where(User.organization_id == org_id, User.custom_role_id.is_not(None))
        .group_by(User.custom_role_id)
    )
    return {str(rid): int(n) for rid, n in rows.all()}


async def _member_count(db: AsyncSession, org_id: str, role_id: str) -> int:
    n = await db.scalar(
        select(func.count(User.id)).where(User.organization_id == org_id, User.custom_role_id == role_id)
    )
    return int(n or 0)


def _to_response(role: Role, members: int) -> RoleResponse:
    return RoleResponse(
        id=str(role.id),
        organization_id=str(role.organization_id),
        name=role.name,
        description=role.description,
        default_tier=role.default_tier,
        area_tiers=dict(role.area_tiers or {}),
        member_count=members,
        created_by=role.created_by,
        created_at=role.created_at,
        updated_at=role.updated_at,
    )


def _snapshot(role: Role) -> dict[str, Any]:
    return {
        "name": role.name,
        "description": role.description,
        "default_tier": role.default_tier,
        "area_tiers": dict(role.area_tiers or {}),
    }


async def _validate_body(
    request: Request,
    db: AsyncSession,
    body: RoleCreate,
    org_id: str,
    caller: User,
    role_id: Optional[str] = None,
) -> tuple[str, dict[str, str]]:
    """Checks shared by create and update; returns the cleaned name and area tiers."""
    name = body.name.strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_role_name", "detail": "name must not be blank"},
        )
    if name.lower() in BUILTIN_ROLE_TIERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "reserved_role_name",
                "detail": f"{name!r} is a built-in role name; SSO group mappings use these names",
            },
        )
    area_tiers = {str(k).strip(): v for k, v in body.area_tiers.items()}
    known = identity_roles.known_areas(request.app)
    unknown = sorted(a for a in area_tiers if a not in known)
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "unknown_area",
                "areas": unknown,
                "detail": "area_tiers keys must be areas listed by GET /roles/areas",
            },
        )
    if body.default_tier not in TIER_ORDER or any(v not in TIER_ORDER for v in area_tiers.values()):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_tier", "detail": f"tiers must be one of {list(TIER_ORDER)}"},
        )
    over = identity_roles.escalation_areas(caller, body.default_tier, area_tiers, known)
    if over:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "tier_exceeds_caller",
                "areas": over,
                "detail": "a role cannot grant more than you hold yourself",
            },
        )
    same_name = [Role.organization_id == org_id, func.lower(Role.name) == name.lower()]
    if role_id:
        same_name.append(Role.id != role_id)
    clash = await db.scalar(select(Role.id).where(*same_name))
    if clash is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "role_name_taken", "detail": f"a role named {name!r} already exists"},
        )
    return name, area_tiers


def _audit(
    db: AsyncSession,
    caller: User,
    org_id: str,
    action: str,
    role_id: str,
    description: str,
    old: Optional[dict[str, Any]] = None,
    new: Optional[dict[str, Any]] = None,
) -> None:
    db.add(AuditLog(
        user_id=str(caller.id),
        organization_id=org_id,
        action=action,
        resource_type="role",
        resource_id=role_id,
        description=description,
        old_value=json.dumps(old) if old is not None else None,
        new_value=json.dumps(new) if new is not None else None,
        success=True,
    ))


@router.get("", response_model=RoleListResponse)
async def list_roles(org_id: OrganizationId, current_user: RolesAdmin, db: DatabaseSession) -> RoleListResponse:
    """The built-in roles (one tier everywhere) and the organisation's custom roles."""
    builtin_rows = await db.execute(
        select(User.role, func.count(User.id))
        .where(User.organization_id == org_id, User.custom_role_id.is_(None), User.is_superuser.is_(False))
        .group_by(User.role)
    )
    builtin_counts = {str(r): int(n) for r, n in builtin_rows.all()}
    roles = (
        await db.execute(select(Role).where(Role.organization_id == org_id).order_by(Role.name))
    ).scalars().all()
    counts = await _member_counts(db, org_id)
    return RoleListResponse(
        builtin=[
            BuiltinRoleResponse(
                name=name, tier=tier, description=_BUILTIN_DESCRIPTIONS[name], member_count=builtin_counts.get(name, 0),
            )
            for name, tier in BUILTIN_ROLE_TIERS.items()
        ],
        custom=[_to_response(r, counts.get(str(r.id), 0)) for r in roles],
    )


@router.get("/areas", response_model=AreaCatalogueResponse)
async def list_areas(request: Request, org_id: OrganizationId, current_user: RolesAdmin) -> AreaCatalogueResponse:
    """The areas a role can set tiers for, derived from the routes the app serves."""
    return AreaCatalogueResponse(
        tiers=list(TIER_ORDER),
        areas=[AreaEntry(**entry) for entry in identity_roles.area_catalogue(request.app)],
    )


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleCreate,
    request: Request,
    org_id: OrganizationId,
    current_user: RolesAdmin,
    db: DatabaseSession,
) -> RoleResponse:
    """Create a custom role in the caller's organisation."""
    name, area_tiers = await _validate_body(request, db, body, org_id, current_user)
    role = Role(
        organization_id=org_id,
        name=name,
        description=body.description,
        default_tier=body.default_tier,
        area_tiers=area_tiers,
        created_by=str(current_user.id),
    )
    db.add(role)
    await db.flush()
    _audit(db, current_user, org_id, "role_created", str(role.id), f"Custom role {name!r} created", new=_snapshot(role))
    await db.commit()
    await db.refresh(role)
    logger.info("role_created", role_id=str(role.id), organization_id=org_id, actor_id=str(current_user.id))
    return _to_response(role, 0)


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(role_id: str, org_id: OrganizationId, current_user: RolesAdmin, db: DatabaseSession) -> RoleResponse:
    role = await _get_org_role(db, role_id, org_id)
    return _to_response(role, await _member_count(db, org_id, str(role.id)))


@router.put("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    body: RoleCreate,
    request: Request,
    org_id: OrganizationId,
    current_user: RolesAdmin,
    db: DatabaseSession,
) -> RoleResponse:
    """Replace a custom role's name, description and tiers. Holders are judged
    by the new tiers from their next request."""
    role = await _get_org_role(db, role_id, org_id)
    name, area_tiers = await _validate_body(request, db, body, org_id, current_user, role_id=str(role.id))
    old = _snapshot(role)
    role.name = name
    role.description = body.description
    role.default_tier = body.default_tier
    role.area_tiers = area_tiers
    await db.flush()
    _audit(db, current_user, org_id, "role_updated", str(role.id), f"Custom role {name!r} updated", old=old, new=_snapshot(role))
    await db.commit()
    await db.refresh(role)
    logger.info("role_updated", role_id=str(role.id), organization_id=org_id, actor_id=str(current_user.id))
    return _to_response(role, await _member_count(db, org_id, str(role.id)))


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_id: str, org_id: OrganizationId, current_user: RolesAdmin, db: DatabaseSession) -> None:
    """Delete a custom role nobody holds (409 ``role_in_use`` with the holder count otherwise)."""
    role = await _get_org_role(db, role_id, org_id)
    holders = await _member_count(db, org_id, str(role.id))
    if holders:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "role_in_use",
                "members": holders,
                "detail": f"{holders} user(s) hold this role; assign them another role first",
            },
        )
    old = _snapshot(role)
    rid = str(role.id)
    await db.delete(role)
    _audit(db, current_user, org_id, "role_deleted", rid, f"Custom role {old['name']!r} deleted", old=old)
    await db.commit()
    logger.info("role_deleted", role_id=rid, organization_id=org_id, actor_id=str(current_user.id))


@router.get("/{role_id}/members", response_model=RoleMembersResponse)
async def list_role_members(
    role_id: str, org_id: OrganizationId, current_user: RolesAdmin, db: DatabaseSession,
) -> RoleMembersResponse:
    """Users of the organisation holding this custom role."""
    role = await _get_org_role(db, role_id, org_id)
    users = (
        await db.execute(
            select(User)
            .where(User.organization_id == org_id, User.custom_role_id == str(role.id))
            .order_by(User.email)
        )
    ).scalars().all()
    return RoleMembersResponse(
        role_id=str(role.id),
        total=len(users),
        items=[
            RoleMember(
                id=str(u.id), email=u.email, full_name=u.full_name, is_active=u.is_active,
                identity_source=u.identity_source or "local",
            )
            for u in users
        ],
    )
