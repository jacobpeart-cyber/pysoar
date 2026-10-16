"""SCIM 2.0 service provider (``/api/v1/scim/v2``), called by identity providers.

Authentication is a SCIM bearer token (``Authorization: Bearer scim_...``)
issued under ``/settings/scim/tokens``; JWTs are not accepted here and these
routes never use ``get_current_user``. The token selects the organisation;
every lookup is confined to it, the platform superuser is never visible, and
an id of another organisation answers 404. Every answer, errors included, is a
SCIM document (``application/scim+json``; errors use the
``urn:ietf:params:scim:api:messages:2.0:Error`` schema).

What is implemented and how it maps onto PySOAR is described in
``src.identity.scim``. Every change is audited (``scim_*`` actions, actor
``scim_token:<prefix>``).
"""

from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Annotated, Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, RedisClient
from src.core.config import settings
from src.core.logging import get_logger
from src.core.security import get_password_hash
from src.core.token_blacklist import TokenBlacklist
from src.identity import scim
from src.identity.models import IdentitySource, SCIMToken
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.models.user import User

logger = get_logger(__name__)


class SCIMRoute(APIRoute):
    """Turns ``SCIMError``, request validation errors and HTTP errors raised
    anywhere in the route (dependencies included) into SCIM error documents."""

    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except scim.SCIMError as exc:
                return _error_response(exc)
            except RequestValidationError as exc:
                first = exc.errors()[0] if exc.errors() else {}
                where = ".".join(str(p) for p in first.get("loc", []) if p not in ("query", "path", "body"))
                return _error_response(scim.SCIMError(400, f"invalid {where or 'request'}: {first.get('msg', '')}",
                                                      "invalidValue"))
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail)
                return _error_response(scim.SCIMError(exc.status_code, detail))

        return handler


router = APIRouter(prefix="/scim/v2", tags=["SCIM 2.0"], route_class=SCIMRoute)


def _error_response(exc: scim.SCIMError) -> JSONResponse:
    headers = {"WWW-Authenticate": 'Bearer realm="scim"'} if exc.status == 401 else None
    return JSONResponse(exc.body(), status_code=exc.status, media_type=scim.MEDIA_TYPE, headers=headers)


def _json(content: Any, status_code: int = 200, location: Optional[str] = None) -> JSONResponse:
    headers = {"Location": location} if location else None
    return JSONResponse(content, status_code=status_code, media_type=scim.MEDIA_TYPE, headers=headers)


def _base_url(request: Request) -> str:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host.split(',')[0].strip()}{settings.api_v1_prefix}/scim/v2"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SCIMCaller:
    token_id: str
    token_prefix: str
    organization_id: str

    @property
    def actor(self) -> str:
        return f"scim_token:{self.token_prefix}"


async def get_scim_caller(request: Request, db: DatabaseSession) -> SCIMCaller:
    """Resolve the bearer SCIM token to its organisation (401 otherwise)."""
    scheme, _, value = (request.headers.get("authorization") or "").partition(" ")
    token = value.strip()
    if scheme.lower() != "bearer" or not token:
        raise scim.SCIMError(401, "a SCIM bearer token is required")
    digest = scim.hash_token(token)
    row = (await db.execute(select(SCIMToken).where(SCIMToken.token_hash == digest))).scalar_one_or_none()
    if row is None or not hmac.compare_digest(str(row.token_hash), digest):
        logger.warning("scim_auth_failed", reason="unknown_token", path=request.url.path)
        raise scim.SCIMError(401, "invalid SCIM token")
    now = scim.utcnow()
    state = scim.token_status(row, now)
    if state != "active":
        logger.warning("scim_auth_failed", reason=f"token_{state}", token_prefix=row.token_prefix,
                       organization_id=row.organization_id)
        raise scim.SCIMError(401, f"SCIM token {state}")
    org_active = await db.scalar(select(Organization.is_active).where(Organization.id == row.organization_id))
    if not org_active:
        raise scim.SCIMError(403, "the token's organisation is inactive")
    last = scim.aware(row.last_used_at)
    if last is None or now - last >= scim.LAST_USED_RESOLUTION:
        row.last_used_at = now
        await db.commit()
    return SCIMCaller(token_id=str(row.id), token_prefix=row.token_prefix, organization_id=str(row.organization_id))


SCIMAuth = Annotated[SCIMCaller, Depends(get_scim_caller)]


def _audit(
    db: AsyncSession,
    request: Request,
    caller: SCIMCaller,
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    description: str,
    old: Optional[dict[str, Any]] = None,
    new: Optional[dict[str, Any]] = None,
) -> None:
    db.add(AuditLog(
        user_id=None,
        organization_id=caller.organization_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=f"{description} (via {caller.actor})",
        old_value=json.dumps(old, default=str) if old is not None else None,
        new_value=json.dumps({**(new or {}), "actor": caller.actor}, default=str),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    ))


async def _body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        raise scim.SCIMError(400, "request body is required", "invalidSyntax")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise scim.SCIMError(400, "request body is not valid JSON", "invalidSyntax") from exc


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


@router.get("/ServiceProviderConfig")
async def service_provider_config(request: Request, caller: SCIMAuth) -> JSONResponse:
    return _json(scim.service_provider_config(_base_url(request)))


@router.get("/ResourceTypes")
async def resource_types(request: Request, caller: SCIMAuth) -> JSONResponse:
    docs = scim.resource_type_documents(_base_url(request))
    return _json(scim.list_response(docs, len(docs), 1))


@router.get("/ResourceTypes/{name}")
async def resource_type(name: str, request: Request, caller: SCIMAuth) -> JSONResponse:
    for doc in scim.resource_type_documents(_base_url(request)):
        if doc["id"] == name:
            return _json(doc)
    raise scim.not_found("resource type")


@router.get("/Schemas")
async def schemas(request: Request, caller: SCIMAuth) -> JSONResponse:
    docs = scim.schema_documents(_base_url(request))
    return _json(scim.list_response(docs, len(docs), 1))


@router.get("/Schemas/{schema_id}")
async def schema(schema_id: str, request: Request, caller: SCIMAuth) -> JSONResponse:
    for doc in scim.schema_documents(_base_url(request)):
        if doc["id"] == schema_id:
            return _json(doc)
    raise scim.not_found("schema")


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def _org_users(org_id: str):
    return select(User).where(User.organization_id == org_id, User.is_superuser.is_(False))


async def _get_user(db: AsyncSession, org_id: str, user_id: str) -> User:
    user = (await db.execute(_org_users(org_id).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise scim.not_found("user")
    return user


async def _email_taken(db: AsyncSession, email: str, exclude_id: Optional[str] = None) -> bool:
    stmt = select(User.id).where(func.lower(User.email) == email.lower())
    if exclude_id:
        stmt = stmt.where(User.id != exclude_id)
    return (await db.execute(stmt.limit(1))).scalar_one_or_none() is not None


def _uniqueness() -> scim.SCIMError:
    # Emails are unique across PySOAR; the answer is the same whichever
    # organisation holds the address.
    return scim.SCIMError(409, "a user with this userName already exists", "uniqueness")


def _user_snapshot(user: User) -> dict[str, Any]:
    return {
        "email": user.email, "full_name": user.full_name, "external_id": user.external_id,
        "active": user.is_active, "phone": user.phone, "department": user.department,
        "role": user.role, "custom_role_id": user.custom_role_id,
    }


async def _revoke_sessions(redis: Any, user: User) -> bool:
    revoked = await TokenBlacklist(redis).revoke_all_user_tokens(str(user.id))
    if not revoked:
        # is_active = false already refuses every token in get_current_user;
        # the generation bump is the second line, so say it failed.
        logger.warning("scim_token_revocation_failed", user_id=str(user.id))
    return revoked


async def _write_user(
    db: AsyncSession, redis: Any, user: User, state: scim.UserState,
) -> dict[str, Any]:
    """Write a UserState onto ``user``; returns what happened to activity."""
    changes = state.changes()
    outcome: dict[str, Any] = {}
    email_change = "email" in changes and changes["email"] != (user.email or "").lower()
    active_change = "active" in changes and bool(changes["active"]) != bool(user.is_active)
    # Checked before anything is written. A SCIM token must never redirect the
    # sign-in of a PySOAR-managed account (account takeover) nor lock one out.
    if email_change and not _idp_managed(user):
        raise _local_account("their userName (sign-in email) cannot be changed through SCIM")
    if active_change and not _idp_managed(user):
        raise _local_account("they cannot be deactivated or reactivated through SCIM")
    if email_change:
        if await _email_taken(db, changes["email"], exclude_id=str(user.id)):
            raise _uniqueness()
        outcome["email_domain"] = await _check_email_domain(db, str(user.organization_id), changes["email"])
        outcome["email_changed"] = {"from": user.email, "to": changes["email"]}
        user.email = changes["email"]
        # The old address's bindings must not follow the account to the new one.
        user.sso_subject = None
        user.password_reset_token = None
        user.password_reset_token_expires_at = None
        outcome["tokens_revoked"] = await _revoke_sessions(redis, user)
    if "full_name" in changes:
        user.full_name = changes["full_name"][:255] if changes["full_name"] else None
    if "external_id" in changes:
        user.external_id = changes["external_id"]
    if "phone" in changes:
        user.phone = changes["phone"]
    if "department" in changes:
        user.department = changes["department"]
    if active_change:
        user.is_active = bool(changes["active"])
        if user.is_active:
            outcome["activity"] = "reactivated"
        else:
            outcome["activity"] = "deactivated"
            if "tokens_revoked" not in outcome:
                outcome["tokens_revoked"] = await _revoke_sessions(redis, user)
    return outcome


#: Identity sources whose sign-in email and lifecycle the identity provider owns.
_IDP_MANAGED_SOURCES = frozenset({IdentitySource.SCIM.value, IdentitySource.OIDC.value})


def _idp_managed(user: User) -> bool:
    return (user.identity_source or IdentitySource.LOCAL.value) in _IDP_MANAGED_SOURCES


def _local_account(what: str) -> scim.SCIMError:
    return scim.SCIMError(403, f"local accounts are managed in PySOAR: {what}", "mutability")


async def _check_email_domain(db: AsyncSession, org_id: str, email: str) -> str:
    """A new or changed email must be in the SSO configuration's
    ``allowed_email_domains`` when it lists any (400 ``invalidValue``).
    Returns ``allowed`` or ``unrestricted`` (no list to check: audited)."""
    config = await scim.sso_configuration(db, org_id)
    domains = {str(d).strip().lower() for d in (config.allowed_email_domains or [])} if config is not None else set()
    if not domains:
        return "unrestricted"
    domain = email.rsplit("@", 1)[-1].lower()
    if domain not in domains:
        raise scim.SCIMError(
            400, f"email domain {domain} is not in this organisation's allowed SSO email domains", "invalidValue",
        )
    return "allowed"


def _extras(state: scim.UserState) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if state.ignored:
        out["ignored_attributes"] = sorted(set(state.ignored))
    if state.email_mismatch:
        out["emails_not_stored"] = state.email_mismatch
    return out


async def _user_out(db: AsyncSession, request: Request, org_id: str, user: User, status_code: int = 200) -> JSONResponse:
    store = await scim.load_group_store(db, org_id)
    base = _base_url(request)
    resource = scim.user_resource(user, base, store.groups_of(str(user.id)))
    return _json(resource, status_code, location=resource["meta"]["location"] if status_code == 201 else None)


def _finish_user_change(
    db: AsyncSession, request: Request, caller: SCIMCaller, user: User,
    before: dict[str, Any], outcome: dict[str, Any], state: scim.UserState, verb: str,
) -> None:
    after = _user_snapshot(user)
    activity = outcome.get("activity")
    if after != before or state.ignored or state.email_mismatch:
        _audit(db, request, caller, "scim_user_updated", "user", str(user.id),
               f"SCIM {verb} of {user.email}", old=before, new={**after, **_extras(state)})
    if "email_changed" in outcome:
        _audit(db, request, caller, "scim_user_email_changed", "user", str(user.id),
               f"Sign-in email changed through SCIM to {user.email}",
               old={"email": outcome["email_changed"]["from"]},
               new={"email": outcome["email_changed"]["to"], "email_domain_check": outcome["email_domain"],
                    "sso_subject_cleared": True, "password_reset_cleared": True,
                    "tokens_revoked": outcome.get("tokens_revoked")})
    if activity:
        _audit(db, request, caller, f"scim_user_{activity}", "user", str(user.id),
               f"User {user.email} {activity} through SCIM",
               new={"active": user.is_active, **({"tokens_revoked": outcome["tokens_revoked"]}
                                                  if "tokens_revoked" in outcome else {})})


@router.get("/Users")
async def list_users(
    request: Request,
    caller: SCIMAuth,
    db: DatabaseSession,
    filter_: Annotated[Optional[str], Query(alias="filter", max_length=1000)] = None,
    start_index: Annotated[Optional[int], Query(alias="startIndex")] = None,
    count: Annotated[Optional[int], Query()] = None,
    attributes: Annotated[Optional[str], Query(max_length=1000)] = None,
    excluded: Annotated[Optional[str], Query(alias="excludedAttributes", max_length=1000)] = None,
) -> JSONResponse:
    org_id = caller.organization_id
    parsed = scim.parse_filter(filter_, scim.USER_FILTERS)
    stmt = _org_users(org_id)
    if parsed is not None:
        key, value = parsed
        if key == "email":
            stmt = stmt.where(func.lower(User.email) == value.strip().lower())
        elif key == "external_id":
            stmt = stmt.where(User.external_id == value)
        else:
            stmt = stmt.where(User.id == value)
    start, size = scim.page_bounds(start_index, count)
    total = int(await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    users: list[User] = []
    if size:
        users = list((await db.execute(
            stmt.order_by(User.created_at, User.id).offset(start - 1).limit(size)
        )).scalars().all())
    store = await scim.load_group_store(db, org_id)
    base = _base_url(request)
    resources = [
        scim.project(scim.user_resource(u, base, store.groups_of(str(u.id))), attributes, excluded) for u in users
    ]
    return _json(scim.list_response(resources, total, start))


@router.post("/Users")
async def create_user(request: Request, caller: SCIMAuth, db: DatabaseSession) -> JSONResponse:
    org_id = caller.organization_id
    body = await _body(request)
    if not isinstance(body, dict):
        raise scim.SCIMError(400, "a User resource object is required", "invalidSyntax")
    state = scim.UserState()
    state.load_resource(body)
    values = state.values
    # Any existing account answers 409, local ones included: a SCIM token never
    # takes over an account. An administrator links a local account explicitly
    # (POST /settings/scim/users/{id}/link); the IdP then finds it by filter.
    if await _email_taken(db, values["email"]):
        raise _uniqueness()
    domain_check = await _check_email_domain(db, org_id, values["email"])
    config = await scim.sso_configuration(db, org_id)
    user = User(
        email=values["email"],
        # No usable password: a hash of a random secret nobody holds. SCIM users
        # sign in through the organisation's SSO (password reset refuses them).
        hashed_password=get_password_hash(secrets.token_urlsafe(48)),
        full_name=(state.full_name() or None),
        role="viewer",
        is_active=bool(values["active"]),
        is_superuser=False,
        organization_id=org_id,
        identity_source=IdentitySource.SCIM.value,
        external_id=values["external_id"],
        phone=values["phone"],
        department=values["department"],
        force_password_change=False,
    )
    err = scim.assign_role(user, await scim.default_role(db, org_id, config), org_id)
    if err is not None:  # a custom default role of another organisation cannot happen; keep viewer
        logger.warning("scim_default_role_refused", organization_id=org_id, **err)
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise _uniqueness() from exc
    _audit(db, request, caller, "scim_user_created", "user", str(user.id),
           f"User {user.email} provisioned through SCIM",
           new={**_user_snapshot(user), "email_domain_check": domain_check, **_extras(state)})
    await db.commit()
    await db.refresh(user)
    logger.info("scim_user_created", organization_id=org_id, user_id=str(user.id), token_prefix=caller.token_prefix)
    return await _user_out(db, request, org_id, user, 201)


@router.get("/Users/{user_id}")
async def get_user(
    user_id: str,
    request: Request,
    caller: SCIMAuth,
    db: DatabaseSession,
    attributes: Annotated[Optional[str], Query(max_length=1000)] = None,
    excluded: Annotated[Optional[str], Query(alias="excludedAttributes", max_length=1000)] = None,
) -> JSONResponse:
    org_id = caller.organization_id
    user = await _get_user(db, org_id, user_id)
    store = await scim.load_group_store(db, org_id)
    resource = scim.user_resource(user, _base_url(request), store.groups_of(str(user.id)))
    return _json(scim.project(resource, attributes, excluded))


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: str, request: Request, caller: SCIMAuth, db: DatabaseSession, redis: RedisClient,
) -> JSONResponse:
    org_id = caller.organization_id
    user = await _get_user(db, org_id, user_id)
    body = await _body(request)
    if not isinstance(body, dict):
        raise scim.SCIMError(400, "a User resource object is required", "invalidSyntax")
    before = _user_snapshot(user)
    state = scim.UserState(user)
    state.load_resource(body)
    outcome = await _write_user(db, redis, user, state)
    await db.flush()
    _finish_user_change(db, request, caller, user, before, outcome, state, "replace")
    await db.commit()
    await db.refresh(user)
    return await _user_out(db, request, org_id, user)


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str, request: Request, caller: SCIMAuth, db: DatabaseSession, redis: RedisClient,
) -> JSONResponse:
    org_id = caller.organization_id
    user = await _get_user(db, org_id, user_id)
    body = await _body(request)
    before = _user_snapshot(user)
    state = scim.UserState(user)
    scim.apply_patch(state, body)
    outcome = await _write_user(db, redis, user, state)
    await db.flush()
    _finish_user_change(db, request, caller, user, before, outcome, state, "patch")
    await db.commit()
    await db.refresh(user)
    return await _user_out(db, request, org_id, user)


@router.delete("/Users/{user_id}", status_code=204)
async def delete_user(
    user_id: str, request: Request, caller: SCIMAuth, db: DatabaseSession, redis: RedisClient,
) -> Response:
    """Deactivate (never a hard delete): the account, its audit trail and its
    authored records stay; every token of the user is revoked."""
    org_id = caller.organization_id
    user = await _get_user(db, org_id, user_id)
    if not _idp_managed(user):
        raise _local_account("they cannot be deleted or deactivated through SCIM")
    if user.is_active:
        user.is_active = False
        revoked = await _revoke_sessions(redis, user)
        _audit(db, request, caller, "scim_user_deactivated", "user", str(user.id),
               f"User {user.email} deactivated through SCIM DELETE", new={"active": False, "tokens_revoked": revoked})
        await db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Groups (role mappings)
# ---------------------------------------------------------------------------


async def _members_of(db: AsyncSession, org_id: str, member_ids: list[str]) -> list[User]:
    if not member_ids:
        return []
    rows = (await db.execute(_org_users(org_id).where(User.id.in_(member_ids)).order_by(User.email))).scalars().all()
    return list(rows)


async def _group_out(
    db: AsyncSession, request: Request, org_id: str, store: scim.GroupStore, gid: str,
    status_code: int = 200, attributes: Optional[str] = None, excluded: Optional[str] = None,
) -> JSONResponse:
    group = store.groups[gid]
    members = await _members_of(db, org_id, list(group.get("members") or []))
    resource = scim.project(scim.group_resource(gid, group, _base_url(request), members), attributes, excluded)
    return _json(resource, status_code, location=resource["meta"]["location"] if status_code == 201 else None)


def _member_ids(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise scim.SCIMError(400, "members must be a list of {value: <user id>}", "invalidValue")
    out: list[str] = []
    for item in value:
        member = item.get("value") if isinstance(item, dict) else item
        if not isinstance(member, str) or not member.strip():
            raise scim.SCIMError(400, "every member needs a value (the user id)", "invalidValue")
        out.append(member.strip())
    return out


async def _validate_members(db: AsyncSession, org_id: str, ids: list[str]) -> list[str]:
    """Only users of the organisation (never the superuser) can be members."""
    unique = list(dict.fromkeys(ids))
    if not unique:
        return []
    found = {str(u.id) for u in await _members_of(db, org_id, unique)}
    missing = [i for i in unique if i not in found]
    if missing:
        raise scim.SCIMError(400, f"unknown member id(s): {', '.join(missing[:10])}", "invalidValue")
    return unique


def _group_name(value: Any) -> str:
    name = value.strip() if isinstance(value, str) else ""
    if not name or len(name) > 255:
        raise scim.SCIMError(400, "displayName is required (at most 255 characters)", "invalidValue")
    return name


async def _get_group(db: AsyncSession, org_id: str, gid: str, *, for_update: bool) -> scim.GroupStore:
    store = await scim.load_group_store(db, org_id, for_update=for_update)
    if gid not in store.groups:
        raise scim.not_found("group")
    return store


async def _apply_membership(
    db: AsyncSession, request: Request, caller: SCIMCaller, store: scim.GroupStore, gid: str,
    affected: set[str], *, mapping_changed: bool = False, was_mapped: bool = False,
) -> list[dict[str, Any]]:
    """Recompute the role of ``affected`` users when the group maps to a role
    (or did before this change); audit each change."""
    org_id = caller.organization_id
    config = await scim.sso_configuration(db, org_id)
    mapped_now = gid in store.groups and await scim.mapped_target(db, org_id, store.groups[gid], config) is not None
    if not (mapped_now or was_mapped or mapping_changed) or not affected:
        return []
    changes: list[dict[str, Any]] = []
    for user in await _members_of(db, org_id, sorted(affected)):
        change = await scim.recompute_role(db, org_id, user, store, config)
        if change:
            changes.append({"user_id": str(user.id), **change})
            _audit(db, request, caller, "scim_role_assigned", "user", str(user.id),
                   f"Role of {user.email} set from SCIM group membership", old=change["from"],
                   new={**change["to"], "group_id": gid})
    return changes


async def _was_mapped(db: AsyncSession, org_id: str, group: dict[str, Any]) -> bool:
    config = await scim.sso_configuration(db, org_id)
    return await scim.mapped_target(db, org_id, group, config) is not None


def _group_snapshot(group: dict[str, Any]) -> dict[str, Any]:
    return {"displayName": group.get("displayName"), "externalId": group.get("externalId"),
            "members": len(group.get("members") or [])}


@router.get("/Groups")
async def list_groups(
    request: Request,
    caller: SCIMAuth,
    db: DatabaseSession,
    filter_: Annotated[Optional[str], Query(alias="filter", max_length=1000)] = None,
    start_index: Annotated[Optional[int], Query(alias="startIndex")] = None,
    count: Annotated[Optional[int], Query()] = None,
    attributes: Annotated[Optional[str], Query(max_length=1000)] = None,
    excluded: Annotated[Optional[str], Query(alias="excludedAttributes", max_length=1000)] = None,
) -> JSONResponse:
    org_id = caller.organization_id
    parsed = scim.parse_filter(filter_, scim.GROUP_FILTERS)
    store = await scim.load_group_store(db, org_id)
    items = sorted(store.groups.items(), key=lambda kv: (str(kv[1].get("created") or ""), kv[0]))
    if parsed is not None:
        key, value = parsed
        if key == "id":
            items = [(g, d) for g, d in items if g == value]
        elif key == "displayName":
            items = [(g, d) for g, d in items if str(d.get("displayName", "")).lower() == value.lower()]
        else:
            items = [(g, d) for g, d in items if d.get("externalId") == value]
    start, size = scim.page_bounds(start_index, count)
    page = items[start - 1:start - 1 + size] if size else []
    base = _base_url(request)
    resources = []
    for gid, group in page:
        members = await _members_of(db, org_id, list(group.get("members") or []))
        resources.append(scim.project(scim.group_resource(gid, group, base, members), attributes, excluded))
    return _json(scim.list_response(resources, len(items), start))


@router.post("/Groups")
async def create_group(request: Request, caller: SCIMAuth, db: DatabaseSession) -> JSONResponse:
    org_id = caller.organization_id
    body = await _body(request)
    if not isinstance(body, dict):
        raise scim.SCIMError(400, "a Group resource object is required", "invalidSyntax")
    name = _group_name(body.get("displayName"))
    store = await scim.load_group_store(db, org_id, for_update=True)
    if store.by_name(name):
        raise scim.SCIMError(409, "a group with this displayName already exists", "uniqueness")
    members = await _validate_members(db, org_id, _member_ids(body.get("members")))
    gid = store.new_group(name, scim.normalise_external_id(body.get("externalId")))
    store.groups[gid]["members"] = members
    store.save()
    changes = await _apply_membership(db, request, caller, store, gid, set(members))
    _audit(db, request, caller, "scim_group_created", "scim_group", gid, f"SCIM group {name!r} created",
           new={**_group_snapshot(store.groups[gid]), "role_changes": len(changes)})
    await db.commit()
    return await _group_out(db, request, org_id, store, gid, 201)


@router.get("/Groups/{group_id}")
async def get_group(
    group_id: str,
    request: Request,
    caller: SCIMAuth,
    db: DatabaseSession,
    attributes: Annotated[Optional[str], Query(max_length=1000)] = None,
    excluded: Annotated[Optional[str], Query(alias="excludedAttributes", max_length=1000)] = None,
) -> JSONResponse:
    store = await _get_group(db, caller.organization_id, group_id, for_update=False)
    return await _group_out(db, request, caller.organization_id, store, group_id,
                            attributes=attributes, excluded=excluded)


async def _rename(
    db: AsyncSession, caller: SCIMCaller, store: scim.GroupStore, gid: str, new_name: str,
) -> Optional[dict[str, str]]:
    """Rename a group; an SSO ``group_role_map`` key follows the rename (when
    the new name is not already a key) so the mapping stays attached."""
    group = store.groups[gid]
    old_name = str(group.get("displayName") or "")
    if new_name == old_name:
        return None
    if store.by_name(new_name, exclude=gid):
        raise scim.SCIMError(409, "a group with this displayName already exists", "uniqueness")
    group["displayName"] = new_name
    config = await scim.sso_configuration(db, caller.organization_id)
    if config is not None:
        role_map = dict(config.group_role_map or {})
        if old_name in role_map and new_name not in role_map:
            role_map[new_name] = role_map.pop(old_name)
            config.group_role_map = role_map
    return {"from": old_name, "to": new_name}


@router.put("/Groups/{group_id}")
async def replace_group(group_id: str, request: Request, caller: SCIMAuth, db: DatabaseSession) -> JSONResponse:
    org_id = caller.organization_id
    store = await _get_group(db, org_id, group_id, for_update=True)
    body = await _body(request)
    if not isinstance(body, dict):
        raise scim.SCIMError(400, "a Group resource object is required", "invalidSyntax")
    group = store.groups[group_id]
    before = _group_snapshot(group)
    was_mapped = await _was_mapped(db, org_id, group)
    old_members = set(group.get("members") or [])
    rename = await _rename(db, caller, store, group_id, _group_name(body.get("displayName")))
    group["externalId"] = scim.normalise_external_id(body.get("externalId"))
    members = await _validate_members(db, org_id, _member_ids(body.get("members")))
    group["members"] = members
    store.touch(group_id)
    store.save()
    affected = old_members ^ set(members) if not rename else old_members | set(members)
    changes = await _apply_membership(db, request, caller, store, group_id, affected,
                                      was_mapped=was_mapped, mapping_changed=bool(rename))
    _audit(db, request, caller, "scim_group_updated", "scim_group", group_id,
           f"SCIM group {group['displayName']!r} replaced", old=before,
           new={**_group_snapshot(group), "rename": rename, "role_changes": len(changes)})
    await db.commit()
    return await _group_out(db, request, org_id, store, group_id)


@router.patch("/Groups/{group_id}")
async def patch_group(group_id: str, request: Request, caller: SCIMAuth, db: DatabaseSession) -> JSONResponse:
    org_id = caller.organization_id
    store = await _get_group(db, org_id, group_id, for_update=True)
    ops = scim.operations(await _body(request))
    group = store.groups[group_id]
    before = _group_snapshot(group)
    was_mapped = await _was_mapped(db, org_id, group)
    old_members = set(group.get("members") or [])
    members: list[str] = list(group.get("members") or [])
    rename: Optional[dict[str, str]] = None
    ignored: list[str] = []

    async def set_attr(attr: str, value: Any, op: str) -> None:
        nonlocal members, rename
        low = attr.strip().lower()
        if low.startswith(scim.SCHEMA_GROUP.lower() + ":"):
            low = low[len(scim.SCHEMA_GROUP) + 1:]
        if low == "displayname":
            if op == "remove":
                raise scim.SCIMError(400, "displayName cannot be removed", "mutability")
            rename = await _rename(db, caller, store, group_id, _group_name(value)) or rename
        elif low == "externalid":
            group["externalId"] = None if op == "remove" else scim.normalise_external_id(value)
        elif low == "members":
            if op == "remove":
                drop = set(_member_ids(value)) if value is not None else set(members)
                members = [m for m in members if m not in drop]
            else:
                ids = await _validate_members(db, org_id, _member_ids(value))
                members = ids if op == "replace" else list(dict.fromkeys(members + ids))
        else:
            vf = scim.member_value_path(attr)
            if vf is None:
                ignored.append(attr)
                return
            if op != "remove":
                raise scim.SCIMError(400, "a members[value eq ...] path only supports remove", "invalidPath")
            members = [m for m in members if m != vf]

    for op, path, value in ops:
        if path:
            await set_attr(path, value, op)
        elif op == "remove":
            raise scim.SCIMError(400, "remove needs a path", "noTarget")
        elif isinstance(value, dict):
            for key, sub in value.items():
                await set_attr(key, sub, op)
        else:
            raise scim.SCIMError(400, "an operation without a path needs an object value", "invalidValue")

    group["members"] = members
    store.touch(group_id)
    store.save()
    affected = old_members ^ set(members) if not rename else old_members | set(members)
    changes = await _apply_membership(db, request, caller, store, group_id, affected,
                                      was_mapped=was_mapped, mapping_changed=bool(rename))
    _audit(db, request, caller, "scim_group_updated", "scim_group", group_id,
           f"SCIM group {group['displayName']!r} patched", old=before,
           new={**_group_snapshot(group), "added": sorted(set(members) - old_members),
                "removed": sorted(old_members - set(members)), "rename": rename,
                "role_changes": len(changes), **({"ignored_attributes": ignored} if ignored else {})})
    await db.commit()
    return await _group_out(db, request, org_id, store, group_id,
                            attributes=request.query_params.get("attributes"),
                            excluded=request.query_params.get("excludedAttributes"))


@router.delete("/Groups/{group_id}", status_code=204)
async def delete_group(group_id: str, request: Request, caller: SCIMAuth, db: DatabaseSession) -> Response:
    """Delete the group record. Its members' roles are recomputed from their
    remaining groups when the group mapped to a role. An SSO
    ``group_role_map`` entry for the name is left in place (it is the SSO
    configuration's, edited under Settings > Identity > SSO)."""
    org_id = caller.organization_id
    store = await _get_group(db, org_id, group_id, for_update=True)
    group = store.groups[group_id]
    was_mapped = await _was_mapped(db, org_id, group)
    members = set(group.get("members") or [])
    snapshot = _group_snapshot(group)
    del store.groups[group_id]
    store.save()
    changes = await _apply_membership(db, request, caller, store, group_id, members, was_mapped=was_mapped)
    _audit(db, request, caller, "scim_group_deleted", "scim_group", group_id,
           f"SCIM group {snapshot['displayName']!r} deleted", old=snapshot, new={"role_changes": len(changes)})
    await db.commit()
    return Response(status_code=204)
