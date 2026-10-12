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

from src.core.config import settings
from src.core.database import get_db
from src.core.security import decode_token_full, verify_token
from src.core.token_blacklist import TokenBlacklist
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


async def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis_client)],
) -> User:
    """Get the current authenticated user from JWT token with enhanced security"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        # Decode full token payload
        token_payload = decode_token_full(token)
        if not token_payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify token type is "access"
        if not verify_token(token, token_type="access"):
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

            # Check user-level revocation (user_id, iat)
            user_revocation = await redis.get(f"revoke:{user_id}")
            if user_revocation and int(user_revocation) >= iat:
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
) -> User:
    """Get the current user if they are an admin"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def get_current_superuser(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Get the current user if they are a superuser"""
    if not current_user.is_superuser and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )
    return current_user


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
    """Dependency factory for role-based access control"""

    async def check_role(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        if current_user.is_superuser:
            return current_user

        if current_user.role not in [role.value for role in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in allowed_roles]}",
            )
        return current_user

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
