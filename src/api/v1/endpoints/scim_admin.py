"""SCIM administration (Settings > Identity): provisioning tokens, the role
each SCIM group grants, and linking local accounts to the identity provider.

Every route is admin (tier admin in the ``settings`` area) and confined to the
caller's organisation (``OrganizationId``: an org-less caller, including the
platform superuser, gets 403 ``organization_required``). Issuing a token and
changing a group's role mapping need a *full* admin (built-in ``admin``
without a custom role): a SCIM token can provision users into any mapped
role, administrators included, so a custom-role holder with admin over
``settings`` must not be able to mint one (403 ``full_admin_required``).
Every change is audited.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.core.config import settings
from src.core.logging import get_logger
from src.identity import scim
from src.identity.models import BUILTIN_ROLE_TIERS, IdentitySource, SCIMToken
from src.models.audit import AuditLog
from src.models.user import User, UserRole
from src.schemas.identity import (
    SCIMGroupListResponse,
    SCIMGroupMappingUpdate,
    SCIMGroupSummary,
    SCIMTokenCreate,
    SCIMTokenCreated,
    SCIMTokenListResponse,
    SCIMTokenResponse,
    SCIMUserLink,
    SCIMUserLinkResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/settings/scim", tags=["SCIM administration"])

SCIMAdmin = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


def _error(code: int, error: str, detail: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=code, detail={"error": error, "detail": detail, **extra})


def _require_full_admin(user: User) -> None:
    if user.is_superuser or (user.role == UserRole.ADMIN.value and not user.custom_role_id):
        return
    raise _error(
        status.HTTP_403_FORBIDDEN, "full_admin_required",
        "issuing SCIM tokens and mapping SCIM groups to roles needs the built-in admin role "
        "(a SCIM token can provision administrators)",
    )


def _scim_base_url(request: Request) -> str:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host.split(',')[0].strip()}{settings.api_v1_prefix}/scim/v2"


def _audit(
    db: AsyncSession, request: Request, caller: User, org_id: str, action: str, resource_type: str,
    resource_id: Optional[str], description: str, old: Optional[dict[str, Any]] = None,
    new: Optional[dict[str, Any]] = None,
) -> None:
    db.add(AuditLog(
        user_id=str(caller.id),
        organization_id=org_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        old_value=json.dumps(old, default=str) if old is not None else None,
        new_value=json.dumps(new, default=str) if new is not None else None,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    ))


def _token_out(token: SCIMToken) -> SCIMTokenResponse:
    return SCIMTokenResponse(
        id=str(token.id),
        name=token.name,
        token_prefix=token.token_prefix,
        status=scim.token_status(token),
        created_by=token.created_by,
        created_at=scim.aware(token.created_at),
        last_used_at=scim.aware(token.last_used_at),
        expires_at=scim.aware(token.expires_at),
        revoked_at=scim.aware(token.revoked_at),
        revoked_by=token.revoked_by,
    )


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@router.get("/tokens", response_model=SCIMTokenListResponse)
async def list_tokens(
    request: Request, org_id: OrganizationId, current_user: SCIMAdmin, db: DatabaseSession,
) -> SCIMTokenListResponse:
    """The organisation's SCIM tokens (never the token values)."""
    rows = (
        await db.execute(
            select(SCIMToken).where(SCIMToken.organization_id == org_id).order_by(SCIMToken.created_at.desc())
        )
    ).scalars().all()
    return SCIMTokenListResponse(scim_base_url=_scim_base_url(request), items=[_token_out(t) for t in rows])


@router.post("/tokens", response_model=SCIMTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    body: SCIMTokenCreate, request: Request, org_id: OrganizationId, current_user: SCIMAdmin, db: DatabaseSession,
) -> SCIMTokenCreated:
    """Issue a SCIM token. The token is in this answer only; PySOAR keeps its SHA-256."""
    _require_full_admin(current_user)
    name = body.name.strip()
    if not name:
        raise _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid_token_name", "name must not be blank")
    value = scim.new_token()
    expires_at = scim.utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    token = SCIMToken(
        organization_id=org_id,
        name=name,
        token_hash=scim.hash_token(value),
        token_prefix=scim.display_prefix(value),
        created_by=str(current_user.id),
        expires_at=expires_at,
    )
    db.add(token)
    await db.flush()
    _audit(db, request, current_user, org_id, "scim_token_created", "scim_token", str(token.id),
           f"SCIM token {name!r} issued", new={"name": name, "token_prefix": token.token_prefix,
                                               "expires_at": expires_at})
    await db.commit()
    await db.refresh(token)
    logger.info("scim_token_created", organization_id=org_id, token_id=str(token.id), actor_id=str(current_user.id))
    return SCIMTokenCreated(**_token_out(token).model_dump(), token=value, scim_base_url=_scim_base_url(request))


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    token_id: str, request: Request, org_id: OrganizationId, current_user: SCIMAdmin, db: DatabaseSession,
) -> None:
    """Revoke a token (it stops working on the identity provider's next call).
    Revoking an already revoked token changes nothing."""
    token = await db.get(SCIMToken, token_id)
    if token is None or str(token.organization_id) != org_id:
        raise _error(status.HTTP_404_NOT_FOUND, "scim_token_not_found", "SCIM token not found in this organisation")
    if token.revoked_at is not None:
        return
    token.revoked_at = scim.utcnow()
    token.revoked_by = str(current_user.id)
    _audit(db, request, current_user, org_id, "scim_token_revoked", "scim_token", str(token.id),
           f"SCIM token {token.name!r} revoked", new={"token_prefix": token.token_prefix})
    await db.commit()
    logger.info("scim_token_revoked", organization_id=org_id, token_id=str(token.id), actor_id=str(current_user.id))


# ---------------------------------------------------------------------------
# Group role mappings
# ---------------------------------------------------------------------------


async def _summary(db: AsyncSession, org_id: str, gid: str, group: dict[str, Any], config: Any) -> SCIMGroupSummary:
    value, source = scim.mapping_of(group, config)
    error = None
    if value is not None and await scim.resolve_role(db, org_id, value) is None:
        error = "role_not_found"
    members = await db.execute(
        select(User.id).where(
            User.organization_id == org_id, User.is_superuser.is_(False),
            User.id.in_(list(group.get("members") or []) or [""]),
        )
    )
    return SCIMGroupSummary(
        id=gid,
        display_name=str(group.get("displayName") or ""),
        external_id=group.get("externalId"),
        member_count=len(members.all()),
        role=value,
        mapping_source=source,
        mapping_error=error,
        created=group.get("created"),
        last_modified=group.get("lastModified"),
    )


def _store_error(exc: scim.SCIMError) -> HTTPException:
    return _error(exc.status, "scim_group_store_unreadable", exc.detail)


@router.get("/groups", response_model=SCIMGroupListResponse)
async def list_groups(org_id: OrganizationId, current_user: SCIMAdmin, db: DatabaseSession) -> SCIMGroupListResponse:
    """Groups the identity provider pushed, with the role each grants."""
    try:
        store = await scim.load_group_store(db, org_id)
    except scim.SCIMError as exc:
        raise _store_error(exc) from exc
    config = await scim.sso_configuration(db, org_id)
    items = [
        await _summary(db, org_id, gid, g, config)
        for gid, g in sorted(store.groups.items(), key=lambda kv: str(kv[1].get("displayName", "")).lower())
    ]
    return SCIMGroupListResponse(items=items)


@router.put("/groups/{group_id}", response_model=SCIMGroupSummary)
async def set_group_role(
    group_id: str, body: SCIMGroupMappingUpdate, request: Request, org_id: OrganizationId,
    current_user: SCIMAdmin, db: DatabaseSession,
) -> SCIMGroupSummary:
    """Map a SCIM group to a role (or ``null`` to unmap). The mapping is
    written to the SSO configuration's ``group_role_map`` (keyed by the group's
    displayName) when the organisation has one, else to the group record.
    Current members' roles are recomputed at once."""
    _require_full_admin(current_user)
    try:
        store = await scim.load_group_store(db, org_id, for_update=True)
    except scim.SCIMError as exc:
        raise _store_error(exc) from exc
    group = store.groups.get(group_id)
    if group is None:
        raise _error(status.HTTP_404_NOT_FOUND, "scim_group_not_found", "SCIM group not found in this organisation")
    value = (body.role or "").strip() or None
    if value is not None:
        target = await scim.resolve_role(db, org_id, value)
        if target is None:
            raise _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown_role",
                         f"{value!r} is neither a built-in role ({', '.join(BUILTIN_ROLE_TIERS)}) "
                         "nor a custom role of this organisation", value=value)
        builtin, role = target
        if role is not None:
            value = str(role.id)  # store the id: renaming the role keeps the mapping
        else:
            value = builtin
    config = await scim.sso_configuration(db, org_id)
    old_value, old_source = scim.mapping_of(group, config)
    name = str(group.get("displayName") or "")
    if config is not None:
        role_map = dict(config.group_role_map or {})
        if value is None:
            role_map.pop(name, None)
        else:
            role_map[name] = value
        config.group_role_map = role_map
        group["role"] = None
    else:
        group["role"] = value
    store.touch(group_id)
    store.save()
    await db.flush()
    changes = 0
    for user in (await db.execute(
        select(User).where(
            User.organization_id == org_id, User.is_superuser.is_(False),
            User.id.in_(list(group.get("members") or []) or [""]),
        )
    )).scalars().all():
        change = await scim.recompute_role(db, org_id, user, store, config)
        if change:
            changes += 1
            _audit(db, request, current_user, org_id, "scim_role_assigned", "user", str(user.id),
                   f"Role of {user.email} recomputed after SCIM group {name!r} was remapped",
                   old=change["from"], new={**change["to"], "group_id": group_id})
    _audit(db, request, current_user, org_id, "scim_group_mapping_updated", "scim_group", group_id,
           f"SCIM group {name!r} mapped to {value or 'nothing'}",
           old={"role": old_value, "source": old_source},
           new={"role": value, "source": ("sso_group_role_map" if config is not None else "scim_groups") if value else None,
                "role_changes": changes})
    summary = await _summary(db, org_id, group_id, group, config)
    await db.commit()
    logger.info("scim_group_mapping_updated", organization_id=org_id, group_id=group_id, role=value,
                actor_id=str(current_user.id))
    return summary


# ---------------------------------------------------------------------------
# Linking local accounts to the identity provider
# ---------------------------------------------------------------------------


async def _org_user(db: AsyncSession, org_id: str, user_id: str) -> User:
    """A user of the organisation; the platform superuser is reported missing."""
    user = (await db.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id, User.is_superuser.is_(False))
    )).scalar_one_or_none()
    if user is None:
        raise _error(status.HTTP_404_NOT_FOUND, "user_not_found", "user not found in this organisation")
    return user


def _link_out(user: User) -> SCIMUserLinkResponse:
    return SCIMUserLinkResponse(
        id=str(user.id), email=user.email, identity_source=user.identity_source,
        external_id=user.external_id, is_active=user.is_active,
    )


@router.post("/users/{user_id}/link", response_model=SCIMUserLinkResponse)
async def link_user(
    user_id: str, body: SCIMUserLink, request: Request, org_id: OrganizationId,
    current_user: SCIMAdmin, db: DatabaseSession,
) -> SCIMUserLinkResponse:
    """Hand a local account to the identity provider (``identity_source``
    becomes ``scim``). From then on SCIM manages it in full: sign-in email,
    activation and role through mapped groups. This is the only way a local
    account becomes SCIM-managed; ``POST /scim/v2/Users`` never adopts one."""
    _require_full_admin(current_user)
    user = await _org_user(db, org_id, user_id)
    if not user.is_active:
        raise _error(status.HTTP_409_CONFLICT, "user_inactive", "reactivate the account in PySOAR before linking it")
    if (user.identity_source or IdentitySource.LOCAL.value) != IdentitySource.LOCAL.value:
        raise _error(status.HTTP_409_CONFLICT, "not_local_account",
                     f"the account is already managed by the identity provider ({user.identity_source})")
    external_id = (body.external_id or "").strip() or None
    before = {"identity_source": user.identity_source, "external_id": user.external_id}
    user.identity_source = IdentitySource.SCIM.value
    if external_id is not None:
        user.external_id = external_id
    _audit(db, request, current_user, org_id, "scim_user_linked", "user", str(user.id),
           f"Local account {user.email} handed to the identity provider (SCIM-managed)",
           old=before, new={"identity_source": user.identity_source, "external_id": user.external_id})
    out = _link_out(user)
    await db.commit()
    logger.info("scim_user_linked", organization_id=org_id, user_id=str(user.id), actor_id=str(current_user.id))
    return out


@router.delete("/users/{user_id}/link", response_model=SCIMUserLinkResponse)
async def unlink_user(
    user_id: str, request: Request, org_id: OrganizationId, current_user: SCIMAdmin, db: DatabaseSession,
) -> SCIMUserLinkResponse:
    """Return a SCIM-managed account to local management. It keeps its email,
    activity and role; SCIM can no longer change its email, lifecycle or role.
    An account SCIM created has no usable password: the user sets one through
    password reset, which local accounts may use."""
    _require_full_admin(current_user)
    user = await _org_user(db, org_id, user_id)
    if str(user.id) == str(current_user.id):
        raise _error(status.HTTP_409_CONFLICT, "self_unlink",
                     "you cannot take your own account out of identity-provider management; ask another admin")
    if user.identity_source != IdentitySource.SCIM.value:
        raise _error(status.HTTP_409_CONFLICT, "not_scim_managed", "the account is not SCIM-managed")
    before = {"identity_source": user.identity_source}
    user.identity_source = IdentitySource.LOCAL.value
    _audit(db, request, current_user, org_id, "scim_user_unlinked", "user", str(user.id),
           f"Account {user.email} returned to local management", old=before,
           new={"identity_source": user.identity_source})
    out = _link_out(user)
    await db.commit()
    logger.info("scim_user_unlinked", organization_id=org_id, user_id=str(user.id), actor_id=str(current_user.id))
    return out
