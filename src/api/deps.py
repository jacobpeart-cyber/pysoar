"""API dependencies for authentication, authorization and tenancy.

Which dependency to use:

* ``CurrentUser``: any authenticated, active user.
* ``require_role([...])``: role gate (``viewer`` / ``analyst`` / ``admin``);
  platform superusers always pass.
* ``AdminUser`` / ``get_current_superuser``: NOTE ``get_current_superuser``
  admits tenant admins (``is_admin`` is true for every tenant's admin role).
  Never use it for platform-wide or cross-tenant actions.
* ``PlatformSuperUser``: platform operator only (``is_superuser``). Use this for
  anything that touches every tenant or the host (backups, raw SQL, ...).

Custom roles (identity package, ``src.identity.roles``): for a user holding a
custom role (``User.custom_role_id``) the gates above are judged per *area*
(first path segment under ``/api/v1``) by the role's tiers instead of
``User.role``: ``get_current_user`` refuses tier ``none`` (403 ``area_denied``,
outside the exempt areas), ``require_role([ADMIN])`` / ``AdminUser`` /
``get_current_superuser`` need tier ``admin`` and ``require_role([ADMIN,
ANALYST])`` needs ``write`` (403 ``insufficient_tier``). Users without a custom
role take exactly the code paths they always did.

Tenancy (wave 1, see docs/audit/2026-10-08/PLAN.md):

* ``OrganizationId``: the caller's organisation id, or 403
  ``organization_required`` when the user has none. Superusers are NOT exempt:
  an org-less superuser must name a tenant explicitly through
  ``resolve_organization_scope``. Every tenant-owned query filters on it and
  every created row is stamped with it; never write ``if org_id:`` guards.
* ``resolve_organization_scope(user, organization_id)``: for routes that take
  an optional ``organization_id`` query/body value. A platform superuser's
  explicit value selects the tenant; for anyone else the explicit value must
  equal their own organisation (403 ``organization_mismatch``). With no
  explicit value it falls back to ``get_current_organization_id`` rules.
"""

from typing import Annotated, Optional

from redis import asyncio as aioredis
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from src.core.config import settings
from src.core.database import get_db
from src.core.security import decode_token_full
from src.identity import roles as identity_roles
from src.models.user import User, UserRole
from src.services.user_service import UserService

# HTTP Bearer security scheme
security = HTTPBearer(auto_error=False)


async def get_redis_client():
    """Get Redis client with proper connection management"""
    redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        yield redis
    finally:
        await redis.close()


async def get_tenant_db(
    current_user: Annotated[User, Depends(lambda: None)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AsyncSession:
    """Get tenant-scoped database session"""
    return db


def _not_authenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
    connection: HTTPConnection = None,  # type: ignore[assignment]
) -> User:
    """Get the current authenticated user from JWT token with enhanced security"""
    if not credentials:
        raise _not_authenticated()
    user = await _user_from_token(credentials.credentials, db, redis, allowed=frozenset({"access"}))
    if identity_roles.has_custom_role(user):
        await _enforce_custom_role_area(user, db, connection)
    return user


async def _enforce_custom_role_area(user: User, db: AsyncSession, connection: Optional[HTTPConnection]) -> None:
    """Custom-role holders only: load the role for this request (cached on the
    user instance for the role gates below) and refuse tier ``none`` in the
    request's area with 403 ``area_denied``. Exempt areas and the caller's own
    ``/users/<id>`` are never denied; a role that cannot be loaded or belongs
    to another organisation grants nothing."""
    from src.identity.models import Role

    role = await db.get(Role, str(user.custom_role_id))
    if role is not None and str(role.organization_id) != str(user.organization_id or ""):
        role = None
    setattr(user, identity_roles.CUSTOM_ROLE_ATTR, role)
    path = connection.url.path if connection is not None else ""
    area = identity_roles.area_of_path(path)
    if area is None or area in identity_roles.EXEMPT_AREAS or identity_roles.is_self_route(path, str(user.id)):
        return
    if identity_roles.effective_tier(user, area, role) == "none":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=identity_roles.area_denied_detail(area))


def _custom_role_gate(user: User, connection: Optional[HTTPConnection], required: str) -> None:
    """403 ``insufficient_tier`` unless the custom-role holder ``user`` holds
    ``required`` in the request's area."""
    area = identity_roles.area_of_path(connection.url.path) if connection is not None else None
    held = identity_roles.effective_tier(user, area)
    if not identity_roles.tier_at_least(held, required):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=identity_roles.insufficient_tier_detail(area, required, held),
        )


async def get_password_change_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
) -> User:
    """The caller of ``POST /auth/change-password``: a normal access token, or
    the five-minute *limited* token login issues (``X-Limited-Token``) when a
    password change is forced (type ``limited``, scope ``password_change``).
    Every other route refuses the limited token, so a forced change cannot
    be used to do anything but change the password."""
    if not credentials:
        raise _not_authenticated()
    return await _user_from_token(
        credentials.credentials, db, redis, allowed=frozenset({"access", "limited"}), scope="password_change",
    )


async def _user_from_token(
    token: str,
    db: AsyncSession,
    redis: aioredis.Redis,
    *,
    allowed: frozenset[str],
    scope: Optional[str] = None,
) -> User:
    """Resolve ``token`` to its active user: decode, check the token type
    (and scope for a limited token), the jti blacklist and user-level
    revocation (fail closed when Redis is unavailable), then load the user."""
    try:
        # Decode full token payload
        token_payload = decode_token_full(token)
        if not token_payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Token type: access tokens everywhere; a limited token only where the
        # caller allows it and only with the scope it was issued for.
        token_type = token_payload.get("type")
        if token_type not in allowed or (
            token_type == "limited" and (scope is None or token_payload.get("scope") != scope)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = token_payload.get("sub")
        jti = token_payload.get("jti")
        iat = token_payload.get("iat")

        if not user_id or not jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token structure",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            # Check token blacklist (jti)
            blacklisted = await redis.get(f"blacklist:{jti}")
            if blacklisted:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # User-level revocation: the token's generation must be current.
            # (Tokens from before this scheme carry no ``gen`` and count as 0, so
            # the first revocation kills them too.)
            current_generation = await redis.get(f"revoke_gen:{user_id}")
            if int(token_payload.get("gen") or 0) < int(current_generation or 0):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User tokens have been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except Exception as e:
            if isinstance(e, HTTPException):
                raise
            # FAIL CLOSED on Redis error
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )

        user_service = UserService(db)
        user = await user_service.get_by_id(user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled",
            )

        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Get the current active user"""
    return current_user


async def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_user)],
    connection: HTTPConnection = None,  # type: ignore[assignment]
) -> User:
    """Get the current user if they are an admin"""
    if identity_roles.has_custom_role(current_user):
        _custom_role_gate(current_user, connection, "admin")
        return current_user
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def get_current_superuser(
    current_user: Annotated[User, Depends(get_current_user)],
    connection: HTTPConnection = None,  # type: ignore[assignment]
) -> User:
    """Get the current user if they are a superuser"""
    if identity_roles.has_custom_role(current_user):
        _custom_role_gate(current_user, connection, "admin")
        return current_user
    if not current_user.is_superuser and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )
    return current_user


setattr(get_current_admin_user, identity_roles.REQUIRED_TIER_ATTR, "admin")
setattr(get_current_superuser, identity_roles.REQUIRED_TIER_ATTR, "admin")


async def get_platform_superuser(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Platform operator only: ``is_superuser`` is required, the tenant admin
    role is NOT enough.

    ``get_current_superuser`` above also admits ``is_admin`` (any tenant's
    admin role), so it cannot gate operations that touch every tenant, such
    as whole-database backups or raw SQL. Use this dependency for those.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "platform_superuser_required",
                "detail": "this operation affects every tenant and is limited to platform superusers",
            },
        )
    return current_user


def _organization_required() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "organization_required",
            "detail": "this operation is tenant-scoped and the account belongs to no organisation; "
            "platform superusers must pass an explicit organization_id",
        },
    )


async def get_current_organization_id(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> str:
    """The caller's organisation id; 403 ``organization_required`` if none.

    Superusers get no implicit platform-wide scope here: an org-less superuser
    is refused and must use a route that accepts an explicit
    ``organization_id`` (see ``resolve_organization_scope``).
    """
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        raise _organization_required()
    return str(org_id)


def resolve_organization_scope(current_user: User, organization_id: Optional[str]) -> str:
    """Effective tenant for a route with an optional explicit ``organization_id``.

    * platform superuser + explicit value: that organisation;
    * anyone else + explicit value: must equal their own organisation, else
      403 ``organization_mismatch``;
    * no explicit value: the caller's own organisation, else 403
      ``organization_required``.
    """
    own = getattr(current_user, "organization_id", None)
    if organization_id:
        if current_user.is_superuser:
            return str(organization_id)
        if own and str(own) == str(organization_id):
            return str(own)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "organization_mismatch",
                "detail": "organization_id does not match the caller's organisation",
            },
        )
    if not own:
        raise _organization_required()
    return str(own)


async def get_optional_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Optional[User]:
    """Get the current user if authenticated, otherwise None"""
    if not credentials:
        return None

    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


def require_role(allowed_roles: list[UserRole]):
    """Dependency factory for role-based access control.

    A custom-role holder is judged by tier in the request's area instead: the
    gate needs the lowest built-in tier among ``allowed_roles`` (``[ADMIN]`` ->
    admin, ``[ADMIN, ANALYST]`` -> write)."""
    required_tier = identity_roles.required_tier_for_roles(allowed_roles)

    async def check_role(
        current_user: Annotated[User, Depends(get_current_user)],
        connection: HTTPConnection = None,  # type: ignore[assignment]
    ) -> User:
        if current_user.is_superuser:
            return current_user

        if identity_roles.has_custom_role(current_user):
            _custom_role_gate(current_user, connection, required_tier)
            return current_user

        if current_user.role not in [role.value for role in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in allowed_roles]}",
            )
        return current_user

    setattr(check_role, identity_roles.REQUIRED_TIER_ATTR, required_tier)
    return check_role


# Common dependency types
CurrentUser = Annotated[User, Depends(get_current_active_user)]
AdminUser = Annotated[User, Depends(get_current_admin_user)]
PlatformSuperUser = Annotated[User, Depends(get_platform_superuser)]
OrganizationId = Annotated[str, Depends(get_current_organization_id)]
OptionalUser = Annotated[Optional[User], Depends(get_optional_user)]
DatabaseSession = Annotated[AsyncSession, Depends(get_db)]
RedisClient = Annotated[aioredis.Redis, Depends(get_redis_client)]
TenantSession = Annotated[AsyncSession, Depends(get_tenant_db)]
