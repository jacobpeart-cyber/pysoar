"""OIDC single sign-on: per-organisation configuration and the login flow.

Configuration (admin of the organisation; org-scoped through ``OrganizationId``):

* ``GET    /settings/sso``       the configuration (404 ``sso_not_configured``); the
  client secret is never returned, only ``client_secret_set``.
* ``PUT    /settings/sso``       upsert (``oidc`` only; ``saml`` answers 501).
* ``DELETE /settings/sso``       remove it.
* ``POST   /settings/sso/test``  fetch discovery + JWKS through netguard and store
  the result; a failure is 502 ``sso_test_failed``, never a pass.

Login (public; the browser and the login page call these):

* ``POST /auth/sso/discover``        ``{email}`` -> whether that domain signs in through SSO.
* ``GET  /auth/sso/{org_slug}/start`` 302 to the identity provider (code + PKCE S256).
* ``GET  /auth/sso/callback``        the provider's redirect target; 302 to
  ``/login?sso=<one-time code>`` or ``/login?sso_error=<reason>``.
* ``POST /auth/sso/exchange``        ``{code}`` -> the password-login token response
  (or the MFA challenge when the organisation does not trust the IdP's MFA).

Every configuration change, test, login and refusal writes an ``AuditLog`` row.
"""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional
from urllib.parse import quote, urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from src.api.deps import DatabaseSession, OrganizationId, RedisClient, require_role
from src.core.config import settings
from src.core.logging import get_logger
from src.core.security import create_access_token, create_refresh_token, get_password_hash
from src.core.token_blacklist import TokenBlacklist
from src.identity import oidc
from src.identity import roles as identity_roles
from src.identity.models import BUILTIN_ROLE_TIERS, IdentitySource, Role, SSOConfiguration, SSOProtocol
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.models.user import User, UserRole
from src.schemas.auth import MFARequiredResponse, TokenResponse
from src.schemas.identity import (
    SSOConfigResponse,
    SSOConfigUpdate,
    SSODiscoverRequest,
    SSODiscoverResponse,
    SSOExchangeRequest,
    SSOTestResponse,
    sso_config_to_dict,
)
from src.services.tenant_settings import session_timeout_minutes_for

logger = get_logger(__name__)

router = APIRouter(tags=["SSO"])

AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

BUILTIN_ROLES = frozenset(r.value for r in UserRole)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

#: Reasons the callback may put in ``/login?sso_error=``. Anything else is
#: reported as ``sso_failed`` so a provider's text never reaches the URL.
LOGIN_ERROR_REASONS = frozenset({
    "invalid_state", "idp_error", "missing_code", "sso_unavailable", "provider_unreachable",
    "discovery_failed", "jwks_failed", "token_exchange_failed", "invalid_id_token",
    "email_missing", "email_not_verified", "email_domain_not_allowed", "user_not_provisioned",
    "account_conflict", "subject_mismatch", "role_unresolved", "user_inactive",
    "superuser_not_allowed", "sso_failed",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error(status_code: int, error: str, detail: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": error, "detail": detail, **extra})


def _audit(
    db: Any,
    *,
    action: str,
    organization_id: Optional[str],
    user_id: Optional[str],
    description: str,
    resource_id: Optional[str] = None,
    resource_type: str = "sso_configuration",
    old_value: Optional[dict[str, Any]] = None,
    new_value: Optional[dict[str, Any]] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    request: Optional[Request] = None,
) -> None:
    db.add(AuditLog(
        user_id=user_id,
        organization_id=organization_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        old_value=json.dumps(old_value, default=str) if old_value is not None else None,
        new_value=json.dumps(new_value, default=str) if new_value is not None else None,
        success=success,
        error_message=error_message,
        ip_address=(request.client.host if request is not None and request.client else None),
        user_agent=(request.headers.get("user-agent") if request is not None else None),
    ))


def _public_origin(request: Request) -> str:
    """Scheme and host the browser used (nginx sets X-Forwarded-Proto)."""
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc)
    return f"{proto}://{host.split(',')[0].strip()}"


def _cookie_path() -> str:
    return f"{settings.api_v1_prefix}/auth/sso"


def _set_browser_cookie(response: Response, request: Request, value: str) -> None:
    """``pysoar_sso``: HttpOnly, SameSite=Lax (sent on the IdP's top-level redirect
    back), Secure on https, scoped to the SSO routes, 10 minutes like the state."""
    response.set_cookie(
        oidc.BROWSER_COOKIE, value, max_age=oidc.STATE_TTL_SECONDS, path=_cookie_path(),
        httponly=True, samesite="lax", secure=_public_origin(request).startswith("https://"),
    )


def _clear_browser_cookie(response: Response, request: Request) -> None:
    response.set_cookie(
        oidc.BROWSER_COOKIE, "", max_age=0, path=_cookie_path(),
        httponly=True, samesite="lax", secure=_public_origin(request).startswith("https://"),
    )


def _redirect_uri(request: Request) -> str:
    return _public_origin(request) + f"{settings.api_v1_prefix}/auth/sso/callback"


def _login_path(org_slug: str) -> str:
    return f"{settings.api_v1_prefix}/auth/sso/{quote(org_slug, safe='')}/start"


def _login_redirect(**params: str) -> RedirectResponse:
    return RedirectResponse("/login?" + urlencode(params), status_code=status.HTTP_302_FOUND)


def _fail_redirect(reason: str) -> RedirectResponse:
    return _login_redirect(sso_error=reason if reason in LOGIN_ERROR_REASONS else "sso_failed")


def _is_https_url(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme == "https" and bool(parts.hostname)


async def _config_for(db: Any, org_id: str) -> Optional[SSOConfiguration]:
    return (await db.execute(
        select(SSOConfiguration).where(SSOConfiguration.organization_id == org_id)
    )).scalar_one_or_none()


async def _role_target(db: Any, org_id: str, value: str) -> Optional[tuple[str, Optional[Role]]]:
    """``(built-in role name, None)`` or ``("viewer", custom Role)`` for a role value, or None."""
    value = (value or "").strip()
    if value in BUILTIN_ROLES:
        return value, None
    if not value:
        return None
    role = (await db.execute(
        select(Role).where(Role.organization_id == org_id, (Role.id == value) | (Role.name == value))
    )).scalars().first()
    return (UserRole.VIEWER.value, role) if role is not None else None


async def resolve_role_value(db: Any, org_id: str, value: str) -> Optional[tuple[str, Optional[str]]]:
    """``(User.role, custom_role_id)`` for a mapped role value, or None.

    A value is a built-in role name, or a custom role of ``org_id`` named by id
    or by name. A custom-role holder's built-in ``role`` is ``viewer``: the
    custom role decides every area (``src.identity.roles``).
    """
    target = await _role_target(db, org_id, value)
    if target is None:
        return None
    builtin, role = target
    return builtin, (role.id if role is not None else None)


def is_full_admin(user: User) -> bool:
    """A built-in admin without a custom role, or the platform superuser."""
    return bool(user.is_superuser) or (user.role == UserRole.ADMIN.value and not user.custom_role_id)


#: Settings only a full admin may change: whoever controls them controls which
#: identities (administrators' included) the provider can sign in.
#: ``email_claim`` / ``groups_claim`` decide which assertion becomes the account
#: email and the role mapping, so they are trust settings too.
_TRUST_FIELDS = ("issuer", "discovery_url", "client_id", "client_secret", "allowed_email_domains",
                 "require_email_verified", "trust_idp_mfa", "jit_provisioning", "enabled",
                 "email_claim", "groups_claim")


def _full_admin_required(fields: list[str]) -> HTTPException:
    return _error(status.HTTP_403_FORBIDDEN, "full_admin_required",
                  "changing the identity provider, its trust settings or enabling SSO needs a built-in "
                  "admin without a custom role: " + ", ".join(fields), fields=fields)


def _to_response(config: SSOConfiguration, org: Organization, request: Request) -> SSOConfigResponse:
    return SSOConfigResponse(
        id=config.id,
        organization_id=config.organization_id,
        organization_slug=org.slug,
        protocol=config.protocol,
        display_name=config.display_name,
        issuer=config.issuer,
        client_id=config.client_id,
        client_secret_set=bool(config.client_secret),
        scopes=config.scopes,
        discovery_url=config.discovery_url,
        effective_discovery_url=oidc.discovery_url_for(config.issuer, config.discovery_url),
        redirect_uri=_redirect_uri(request),
        login_url=_login_path(org.slug),
        email_claim=config.email_claim,
        name_claim=config.name_claim,
        groups_claim=config.groups_claim,
        group_role_map=dict(config.group_role_map or {}),
        jit_provisioning=config.jit_provisioning,
        default_role=config.default_role,
        allowed_email_domains=list(config.allowed_email_domains or []),
        require_email_verified=config.require_email_verified,
        trust_idp_mfa=config.trust_idp_mfa,
        enabled=config.enabled,
        last_tested_at=config.last_tested_at,
        last_test_status=config.last_test_status,
        last_test_detail=config.last_test_detail,
        updated_by=config.updated_by,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


async def _organization(db: Any, org_id: str) -> Organization:
    org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
    if org is None:
        raise _error(status.HTTP_404_NOT_FOUND, "organization_not_found", "the caller's organisation no longer exists")
    return org


# ---------------------------------------------------------------------------
# Configuration (admin)
# ---------------------------------------------------------------------------


@router.get("/settings/sso", response_model=SSOConfigResponse)
async def get_sso_configuration(
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    request: Request,
    db: DatabaseSession = None,
) -> SSOConfigResponse:
    """The organisation's SSO configuration (admin). 404 ``sso_not_configured`` when none."""
    config = await _config_for(db, org_id)
    if config is None:
        raise _error(status.HTTP_404_NOT_FOUND, "sso_not_configured", "this organisation has no single sign-on configuration")
    return _to_response(config, await _organization(db, org_id), request)


@router.put("/settings/sso", response_model=SSOConfigResponse)
async def put_sso_configuration(
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    payload: SSOConfigUpdate,
    request: Request,
    db: DatabaseSession = None,
) -> SSOConfigResponse:
    """Create or replace the organisation's SSO configuration (admin, audited).

    Enabling requires at least one allowed email domain and a passing
    ``POST /settings/sso/test`` for the current issuer / discovery URL.
    """
    protocol = (payload.protocol or "").strip().lower()
    if protocol == SSOProtocol.SAML.value:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={
                "error": "not_implemented",
                "reason": "saml_requires_xmlsec",
                "detail": "SAML 2.0 needs xmlsec (libxmlsec1) in the API image to verify signed assertions; "
                "it ships with the identity SAML follow-up package. Configure OpenID Connect (protocol 'oidc'), "
                "which every major identity provider (Okta, Entra ID, Google, Auth0, Keycloak, Ping) supports.",
            },
        )
    if protocol != SSOProtocol.OIDC.value:
        raise _error(422, "unsupported_protocol", f"protocol must be 'oidc' (got {payload.protocol!r})")

    issuer = (payload.issuer or "").strip()
    client_id = (payload.client_id or "").strip()
    if not issuer or not client_id:
        raise _error(422, "missing_field", "issuer and client_id are required for OIDC",
                     fields=[f for f, v in (("issuer", issuer), ("client_id", client_id)) if not v])
    if not _is_https_url(issuer):
        raise _error(422, "invalid_issuer", "issuer must be an https URL (OpenID Connect requires TLS)")
    discovery_url = (payload.discovery_url or "").strip() or None
    if discovery_url and not _is_https_url(discovery_url):
        raise _error(422, "invalid_discovery_url", "discovery_url must be an https URL")
    if discovery_url and (urlsplit(discovery_url).hostname or "").lower() != (urlsplit(issuer).hostname or "").lower():
        raise _error(422, "discovery_host_mismatch",
                     "discovery_url must be on the issuer's host (the provider publishes its own configuration)")
    scopes = " ".join(payload.scopes.split())
    if "openid" not in scopes.split(" "):
        raise _error(422, "invalid_scopes", "scopes must include 'openid'")

    domains: list[str] = []
    for raw in payload.allowed_email_domains:
        domain = raw.strip().lower().lstrip("@")
        if not _DOMAIN_RE.match(domain):
            raise _error(422, "invalid_email_domain", f"{raw!r} is not an email domain", domain=raw)
        if domain not in domains:
            domains.append(domain)

    existing = await _config_for(db, org_id)
    if not is_full_admin(current_user):
        if existing is None:
            changed = list(_TRUST_FIELDS)
        else:
            changed = [f for f, before, after in (
                ("issuer", existing.issuer, issuer),
                ("discovery_url", existing.discovery_url or None, discovery_url),
                ("client_id", existing.client_id, client_id),
                ("client_secret", existing.client_secret or None,
                 existing.client_secret or None if payload.client_secret is None else (payload.client_secret or None)),
                ("allowed_email_domains", sorted(existing.allowed_email_domains or []), sorted(domains)),
                # Turning verification on only narrows who can sign in.
                ("require_email_verified", existing.require_email_verified,
                 existing.require_email_verified if payload.require_email_verified else False),
                ("trust_idp_mfa", existing.trust_idp_mfa, payload.trust_idp_mfa),
                ("jit_provisioning", existing.jit_provisioning, payload.jit_provisioning),
                ("enabled", existing.enabled, payload.enabled),
                ("email_claim", existing.email_claim, payload.email_claim.strip()),
                ("groups_claim", existing.groups_claim or None, (payload.groups_claim or "").strip() or None),
            ) if before != after]
        if changed:
            raise _full_admin_required(changed)

    # The provider's email_verified describes its "email" claim only; another
    # claim carries no verification, so it cannot be used while verification is required.
    if payload.email_claim.strip() != "email" and payload.require_email_verified:
        raise _error(422, "email_claim_requires_unverified",
                     f"email_verified only covers the provider's 'email' claim; to take the address from "
                     f"{payload.email_claim.strip()!r}, set require_email_verified to false (and trust that the "
                     f"provider controls that claim), or keep email_claim 'email'")

    # Every role the configuration can hand out stays within the caller's own tiers.
    known = identity_roles.known_areas(request.app)
    over: set[str] = set()
    for value in [payload.default_role, *payload.group_role_map.values()]:
        target = await _role_target(db, org_id, value)
        if target is None:
            raise _error(422, "unknown_role",
                         f"{value!r} is neither a built-in role (admin, analyst, viewer) nor a custom role of this organisation",
                         value=value)
        builtin, role = target
        if role is None:
            over.update(identity_roles.escalation_areas(current_user, BUILTIN_ROLE_TIERS[builtin], {}, known))
        else:
            over.update(identity_roles.escalation_areas(current_user, role.default_tier, dict(role.area_tiers or {}), known))
    if over:
        raise _error(status.HTTP_403_FORBIDDEN, "tier_exceeds_caller",
                     "the SSO configuration cannot assign a role that grants more than you hold yourself",
                     areas=sorted(over))

    # One organisation per email domain: discovery routes a domain to exactly one IdP.
    if domains:
        others = (await db.execute(
            select(SSOConfiguration).where(SSOConfiguration.organization_id != org_id)
        )).scalars().all()
        for other in others:
            clash = sorted(set(domains) & {str(d).lower() for d in (other.allowed_email_domains or [])})
            if clash:
                raise _error(409, "email_domain_claimed",
                             f"email domain {clash[0]} is already claimed by another organisation's SSO configuration",
                             domain=clash[0])

    config = existing
    old = sso_config_to_dict(config) if config is not None else None
    created = config is None
    if config is None:
        config = SSOConfiguration(organization_id=org_id, issuer=issuer, client_id=client_id)
        db.add(config)
    elif config.issuer != issuer or (config.discovery_url or None) != discovery_url:
        # The stored test result was for another provider.
        config.last_tested_at = None
        config.last_test_status = None
        config.last_test_detail = None

    if payload.enabled:
        if not domains:
            raise _error(422, "allowed_email_domains_required",
                         "list at least one email domain before enabling SSO: discovery and provisioning are limited to them")
        if config.last_test_status != "ok":
            raise _error(409, "sso_test_required",
                         "save the configuration, run POST /settings/sso/test successfully, then enable it")

    config.protocol = protocol
    config.display_name = (payload.display_name or "").strip() or None
    config.issuer = issuer
    config.client_id = client_id
    if payload.client_secret is not None:
        config.client_secret = payload.client_secret or None
    config.scopes = scopes
    config.discovery_url = discovery_url
    config.email_claim = payload.email_claim.strip()
    config.name_claim = payload.name_claim.strip()
    config.groups_claim = (payload.groups_claim or "").strip() or None
    config.group_role_map = {str(k): str(v).strip() for k, v in payload.group_role_map.items()}
    config.jit_provisioning = payload.jit_provisioning
    config.default_role = payload.default_role.strip()
    config.allowed_email_domains = domains
    config.require_email_verified = payload.require_email_verified
    config.trust_idp_mfa = payload.trust_idp_mfa
    config.enabled = payload.enabled
    config.updated_by = str(current_user.id)
    await db.flush()

    new = sso_config_to_dict(config)
    _audit(db, action="sso_config_create" if created else "sso_config_update", organization_id=org_id,
           user_id=str(current_user.id), resource_id=config.id, old_value=old, new_value=new, request=request,
           description=f"SSO configuration {'created' if created else 'updated'} (issuer {issuer}, "
           f"{'enabled' if config.enabled else 'disabled'})")
    await db.commit()
    await db.refresh(config)
    logger.info("sso_config_saved", organization_id=org_id, enabled=config.enabled, created=created)
    return _to_response(config, await _organization(db, org_id), request)


@router.delete("/settings/sso", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sso_configuration(
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    request: Request,
    db: DatabaseSession = None,
) -> None:
    """Remove the organisation's SSO configuration (admin, audited).

    Users provisioned through SSO stay (deactivate them under Users); they can
    no longer sign in until SSO is configured again.
    """
    config = await _config_for(db, org_id)
    if config is None:
        raise _error(status.HTTP_404_NOT_FOUND, "sso_not_configured", "this organisation has no single sign-on configuration")
    if not is_full_admin(current_user):
        raise _full_admin_required(["delete"])
    old = sso_config_to_dict(config)
    config_id = config.id
    await db.delete(config)
    _audit(db, action="sso_config_delete", organization_id=org_id, user_id=str(current_user.id),
           resource_id=config_id, old_value=old, request=request,
           description=f"SSO configuration deleted (issuer {old['issuer']})")
    await db.commit()
    logger.info("sso_config_deleted", organization_id=org_id)


@router.post("/settings/sso/test", response_model=SSOTestResponse)
async def test_sso_configuration(
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    request: Request,
    db: DatabaseSession = None,
    redis: RedisClient = None,
) -> SSOTestResponse:
    """Fetch the provider's discovery document and JWKS and record the result (admin, audited).

    Checks: discovery reachable through netguard, ``issuer`` equals the
    configured issuer, the three endpoints present, JWKS reachable with at least
    one key. Failure: 502 ``sso_test_failed`` with ``reason`` and ``detail``.
    It does not exercise the client secret (only a real login does).
    """
    config = await _config_for(db, org_id)
    if config is None:
        raise _error(status.HTTP_404_NOT_FOUND, "sso_not_configured", "save a configuration before testing it")
    now = datetime.now(timezone.utc)
    try:
        metadata = await oidc.fetch_metadata(config.issuer, config.discovery_url)
        jwks = await oidc.fetch_jwks(metadata.jwks_uri)
    except oidc.OIDCError as exc:
        config.last_tested_at = now
        config.last_test_status = "failed"
        config.last_test_detail = exc.detail[:2000]
        _audit(db, action="sso_config_test", organization_id=org_id, user_id=str(current_user.id),
               resource_id=config.id, success=False, error_message=exc.detail[:2000], request=request,
               new_value={"status": "failed", "reason": exc.reason},
               description=f"SSO connection test failed: {exc.reason}")
        await db.commit()
        logger.warning("sso_test_failed", organization_id=org_id, reason=exc.reason)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "sso_test_failed", "reason": exc.reason, "detail": exc.detail},
        ) from exc

    await redis.setex(oidc.jwks_cache_key(config.id, metadata.jwks_uri), oidc.JWKS_TTL_SECONDS, json.dumps(jwks))
    keys = jwks["keys"]
    warnings: list[str] = []
    if metadata.code_challenge_methods_supported and "S256" not in metadata.code_challenge_methods_supported:
        warnings.append("provider does not advertise PKCE S256; logins send it anyway and may be refused")
    requested = config.scopes.split()
    if metadata.scopes_supported:
        unsupported = [s for s in requested if s not in metadata.scopes_supported]
        if unsupported:
            warnings.append("provider does not advertise scopes: " + ", ".join(unsupported))
    if not any(k.get("kty") in ("RSA", "EC", "OKP") for k in keys):
        warnings.append("JWKS holds no RSA, EC or OKP signing key; ID tokens cannot be verified")
    if not config.client_secret:
        warnings.append("no client secret stored: the token exchange runs as a public client (PKCE only)")

    detail = f"{len(keys)} signing key(s); endpoints discovered"
    if warnings:
        detail += "; warnings: " + "; ".join(warnings)
    config.last_tested_at = now
    config.last_test_status = "ok"
    config.last_test_detail = detail[:2000]
    _audit(db, action="sso_config_test", organization_id=org_id, user_id=str(current_user.id),
           resource_id=config.id, request=request,
           new_value={"status": "ok", "key_count": len(keys), "warnings": warnings},
           description="SSO connection test passed")
    await db.commit()
    return SSOTestResponse(
        status="ok",
        tested_at=now,
        issuer=metadata.issuer,
        authorization_endpoint=metadata.authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        jwks_uri=metadata.jwks_uri,
        userinfo_endpoint=metadata.userinfo_endpoint,
        key_count=len(keys),
        key_ids=[str(k["kid"]) for k in keys if k.get("kid")],
        scopes_supported=metadata.scopes_supported,
        token_endpoint_auth_methods_supported=metadata.token_endpoint_auth_methods_supported,
        code_challenge_methods_supported=metadata.code_challenge_methods_supported,
        id_token_signing_alg_values_supported=metadata.id_token_signing_alg_values_supported,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Login flow (public)
# ---------------------------------------------------------------------------


@router.post("/auth/sso/discover", response_model=SSODiscoverResponse)
async def discover_sso(
    payload: SSODiscoverRequest,
    request: Request,
    db: DatabaseSession = None,
) -> SSODiscoverResponse:
    """Whether ``email``'s domain signs in through an enabled SSO configuration.

    Answers ``{available: false}`` with nothing else otherwise (no hint about
    accounts or organisations).
    """
    domain = oidc.email_domain(payload.email)
    if not domain:
        return SSODiscoverResponse(available=False)
    rows = (await db.execute(
        select(SSOConfiguration, Organization)
        .join(Organization, Organization.id == SSOConfiguration.organization_id)
        .where(SSOConfiguration.enabled.is_(True), SSOConfiguration.protocol == SSOProtocol.OIDC.value,
               Organization.is_active.is_(True))
    )).all()
    for config, org in rows:
        if domain in {str(d).lower() for d in (config.allowed_email_domains or [])}:
            return SSODiscoverResponse(
                available=True,
                organization_slug=org.slug,
                display_name=config.display_name or org.name,
                login_url=_login_path(org.slug),
            )
    return SSODiscoverResponse(available=False)


@router.get("/auth/sso/{org_slug}/start", name="sso_start", status_code=status.HTTP_302_FOUND)
async def start_sso(
    org_slug: str,
    request: Request,
    login_hint: Annotated[Optional[str], Query(max_length=255)] = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
) -> RedirectResponse:
    """Redirect the browser to the organisation's identity provider.

    Stores ``{organization_id, nonce, code_verifier, redirect_uri, browser, created}``
    under ``sso:state:<state>`` for 10 minutes and sets the ``pysoar_sso``
    cookie whose SHA-256 is ``browser``: only this browser can finish the login. An unknown organisation or a
    disabled configuration redirects to ``/login?sso_error=sso_unavailable``.
    """
    org = (await db.execute(
        select(Organization).where(Organization.slug == org_slug, Organization.is_active.is_(True))
    )).scalar_one_or_none()
    config = await _config_for(db, org.id) if org is not None else None
    if org is None or config is None or not config.enabled or config.protocol != SSOProtocol.OIDC.value:
        return _fail_redirect("sso_unavailable")
    try:
        metadata = await oidc.get_metadata(redis, config.issuer, config.discovery_url, scope=config.id)
    except oidc.OIDCError as exc:
        _audit(db, action="sso_login_failed", organization_id=org.id, user_id=None, resource_id=config.id,
               success=False, error_message=exc.detail[:2000], request=request,
               description=f"SSO login could not start: {exc.reason}")
        await db.commit()
        logger.warning("sso_start_failed", organization_id=org.id, reason=exc.reason)
        return _fail_redirect(exc.reason)

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = oidc.new_pkce_pair()
    redirect_uri = _redirect_uri(request)
    browser_secret = oidc.new_browser_secret()
    await oidc.put_json(redis, oidc.STATE_KEY.format(state), oidc.STATE_TTL_SECONDS, {
        "browser": oidc.browser_binding(browser_secret),
        "organization_id": org.id,
        "nonce": nonce,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "created": datetime.now(timezone.utc).isoformat(),
    })
    url = oidc.authorization_url(
        metadata, client_id=config.client_id, redirect_uri=redirect_uri, scopes=config.scopes,
        state=state, nonce=nonce, code_challenge=challenge, login_hint=login_hint,
    )
    response = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    _set_browser_cookie(response, request, browser_secret)
    return response


class _LoginRefused(Exception):  # noqa: N818 (control flow inside the callback)
    def __init__(self, reason: str, detail: str, user_id: Optional[str] = None) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.user_id = user_id


def _email_verified(claims: dict[str, Any]) -> bool:
    value = claims.get("email_verified")
    # Some providers (Cognito, older ADFS) send the boolean as a string.
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _groups(claims: dict[str, Any], groups_claim: Optional[str]) -> list[str]:
    value = oidc.claim(claims, groups_claim)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


async def _role_for_new_user(db: Any, config: SSOConfiguration, claims: dict[str, Any]) -> tuple[str, Optional[str]]:
    """Role from ``group_role_map`` (first mapped group, in map order) else ``default_role``."""
    groups = set(_groups(claims, config.groups_claim))
    for group, value in (config.group_role_map or {}).items():
        if group in groups:
            resolved = await resolve_role_value(db, config.organization_id, value)
            if resolved is None:
                raise _LoginRefused("role_unresolved", f"group {group!r} maps to {value!r}, which no longer exists")
            return resolved
    resolved = await resolve_role_value(db, config.organization_id, config.default_role)
    if resolved is None:
        raise _LoginRefused("role_unresolved", f"default role {config.default_role!r} no longer exists")
    return resolved


async def _user_for_claims(db: Any, config: SSOConfiguration, claims: dict[str, Any]) -> tuple[User, str]:
    """Match, bind or provision the user for verified ID token claims; returns (user, how)."""
    org_id = config.organization_id
    email = oidc.claim(claims, config.email_claim)
    if not isinstance(email, str) or "@" not in email:
        raise _LoginRefused("email_missing", f"ID token has no usable {config.email_claim!r} claim")
    email = email.strip().lower()
    if config.require_email_verified and (config.email_claim != "email" or not _email_verified(claims)):
        raise _LoginRefused("email_not_verified", f"the provider does not assert that {email} is verified")
    domain = oidc.email_domain(email)
    if domain not in {str(d).lower() for d in (config.allowed_email_domains or [])}:
        raise _LoginRefused("email_domain_not_allowed", f"email domain {domain} is not allowed for this organisation")
    subject = str(claims["sub"])

    user = (await db.execute(
        select(User).where(User.organization_id == org_id, User.sso_subject == subject)
    )).scalar_one_or_none()
    how = "subject"
    if user is None:
        user = (await db.execute(
            select(User).where(User.organization_id == org_id, User.email == email)
        )).scalar_one_or_none()
        how = "email"
        if user is not None:
            if user.is_superuser:
                # Never bind a provider identity to the platform operator's account.
                raise _LoginRefused("superuser_not_allowed",
                                    f"{email} is a platform superuser account; it cannot be bound to SSO", user.id)
            if user.sso_subject and user.sso_subject != subject:
                raise _LoginRefused("subject_mismatch",
                                    f"{email} is bound to another identity provider subject", user.id)
            user.sso_subject = subject
            how = "bound"
    if user is None:
        if not config.jit_provisioning:
            raise _LoginRefused("user_not_provisioned", f"no account for {email} and just-in-time provisioning is off")
        taken = (await db.execute(select(User.id).where(User.email == email))).scalar_one_or_none()
        if taken is not None:
            raise _LoginRefused("account_conflict", f"{email} already has an account outside this organisation")
        role, custom_role_id = await _role_for_new_user(db, config, claims)
        name = oidc.claim(claims, config.name_claim)
        user = User(
            email=email,
            # No usable password: a hash of a random secret nobody holds, so a
            # password login answers 401 like any wrong password.
            hashed_password=get_password_hash(secrets.token_urlsafe(48)),
            full_name=str(name)[:255] if isinstance(name, str) and name.strip() else None,
            role=role,
            custom_role_id=custom_role_id,
            is_active=True,
            is_superuser=False,
            organization_id=org_id,
            identity_source=IdentitySource.OIDC.value,
            sso_subject=subject,
            force_password_change=False,
        )
        db.add(user)
        await db.flush()
        how = "provisioned"
    if user.is_superuser:
        raise _LoginRefused("superuser_not_allowed", "platform superusers sign in with their password, not SSO", user.id)
    if not user.is_active:
        raise _LoginRefused("user_inactive", f"{email} is deactivated", user.id)
    return user, how


@router.get("/auth/sso/callback", name="sso_callback", status_code=status.HTTP_302_FOUND)
async def sso_callback(
    request: Request,
    code: Annotated[Optional[str], Query(max_length=4096)] = None,
    state: Annotated[Optional[str], Query(max_length=256)] = None,
    error: Annotated[Optional[str], Query(max_length=256)] = None,
    error_description: Annotated[Optional[str], Query(max_length=2048)] = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
) -> RedirectResponse:
    """The identity provider's redirect target.

    Consumes the state (single use), exchanges the code, verifies the ID token,
    then matches the user by ``sso_subject``, else by email (binding the
    subject), else provisions one when just-in-time provisioning is on. Success:
    302 ``/login?sso=<one-time code, 60 s>``; failure: 302
    ``/login?sso_error=<reason>`` with the cause in the audit row.
    """
    pending = await oidc.take_json(redis, oidc.STATE_KEY.format(state)) if state else None
    cookie = request.cookies.get(oidc.BROWSER_COOKIE)
    if pending is not None and not oidc.binding_matches(cookie, pending.get("browser")):
        # Someone else's login handed to this browser (login CSRF): refuse it.
        _audit(db, action="sso_login_failed", organization_id=str(pending.get("organization_id") or "") or None,
               user_id=None, success=False, request=request,
               error_message="state is not bound to this browser (pysoar_sso cookie missing or different)",
               description="SSO callback refused: invalid_state")
        await db.commit()
        logger.warning("sso_callback_browser_mismatch", organization_id=pending.get("organization_id"))
        return _fail_redirect("invalid_state")
    if pending is None:
        _audit(db, action="sso_login_failed", organization_id=None, user_id=None, success=False,
               request=request, error_message="unknown, expired or replayed state",
               description="SSO callback refused: invalid_state")
        await db.commit()
        return _fail_redirect("invalid_state")

    org_id = str(pending.get("organization_id") or "")
    config = await _config_for(db, org_id) if org_id else None
    # Read before any rollback expires the instance.
    config_id = config.id if config is not None else None

    async def refuse(reason: str, detail: str, user_id: Optional[str] = None) -> RedirectResponse:
        _audit(db, action="sso_login_failed", organization_id=org_id or None, user_id=user_id,
               resource_id=config_id, success=False,
               error_message=detail[:2000], request=request,
               description=f"SSO login refused: {reason}")
        await db.commit()
        logger.warning("sso_login_refused", organization_id=org_id, reason=reason)
        return _fail_redirect(reason)

    if error:
        return await refuse("idp_error", f"provider returned error={error}: {(error_description or '')[:500]}")
    if not code:
        return await refuse("missing_code", "callback carried no authorization code")
    if config is None or not config.enabled or config.protocol != SSOProtocol.OIDC.value:
        return await refuse("sso_unavailable", "SSO was disabled or removed during the login")

    try:
        metadata = await oidc.get_metadata(redis, config.issuer, config.discovery_url, scope=config.id)
        tokens = await oidc.exchange_code(
            metadata, client_id=config.client_id, client_secret=config.client_secret, code=code,
            redirect_uri=str(pending.get("redirect_uri") or _redirect_uri(request)),
            code_verifier=str(pending.get("code_verifier") or ""),
        )
        claims = await oidc.verify_id_token(
            redis, metadata, str(tokens["id_token"]), issuer=metadata.issuer,
            client_id=config.client_id, nonce=str(pending.get("nonce") or ""), scope=config.id,
        )
    except oidc.OIDCError as exc:
        await db.rollback()
        return await refuse(exc.reason, exc.detail)

    try:
        user, how = await _user_for_claims(db, config, claims)
    except _LoginRefused as exc:
        await db.rollback()
        return await refuse(exc.reason, exc.detail, exc.user_id)

    if how == "provisioned":
        _audit(db, action="sso_user_provisioned", organization_id=org_id, user_id=user.id,
               resource_type="user", resource_id=user.id, request=request,
               new_value={"email": user.email, "role": user.role, "custom_role_id": user.custom_role_id,
                          "identity_source": user.identity_source},
               description=f"User {user.email} provisioned just in time through SSO")
    elif how == "bound":
        _audit(db, action="sso_subject_bound", organization_id=org_id, user_id=user.id,
               resource_type="user", resource_id=user.id, request=request,
               description=f"SSO subject bound to existing user {user.email} on first SSO login")

    login_code = secrets.token_urlsafe(32)
    await oidc.put_json(redis, oidc.LOGIN_KEY.format(login_code), oidc.LOGIN_CODE_TTL_SECONDS,
                        {"user_id": user.id, "organization_id": org_id, "browser": pending.get("browser")})
    _audit(db, action="sso_callback", organization_id=org_id, user_id=user.id, resource_type="user",
           resource_id=user.id, request=request,
           description=f"SSO identity verified for {user.email} ({how}); one-time login code issued")
    await db.commit()
    return _login_redirect(sso=login_code)


@router.post("/auth/sso/exchange", response_model=None)
async def sso_exchange(
    payload: SSOExchangeRequest,
    request: Request,
    response: Response,
    db: DatabaseSession = None,
    redis: RedisClient = None,
) -> TokenResponse | MFARequiredResponse:
    """Trade the one-time code from ``/login?sso=`` for tokens (single use, 60 s).

    Same response as password login: ``TokenResponse`` (``gen`` claim,
    organisation session timeout), or ``MFARequiredResponse`` when the
    organisation does not trust the IdP's MFA and the user has MFA enabled
    (finish with ``POST /mfa/verify``). 401 ``invalid_sso_code`` otherwise,
    including when the request lacks the ``pysoar_sso`` cookie the login was
    started with. The cookie is cleared once the code is redeemed.
    """
    entry = await oidc.take_json(redis, oidc.LOGIN_KEY.format(payload.code))
    invalid = _error(status.HTTP_401_UNAUTHORIZED, "invalid_sso_code", "unknown, expired or already used SSO login code")
    if entry is None or not oidc.binding_matches(request.cookies.get(oidc.BROWSER_COOKIE), entry.get("browser")):
        raise invalid
    user = (await db.execute(
        select(User).where(User.id == str(entry.get("user_id")), User.organization_id == str(entry.get("organization_id")))
    )).scalar_one_or_none()
    if user is None or not user.is_active or user.is_superuser:
        raise invalid
    org_id = str(user.organization_id)
    config = await _config_for(db, org_id)
    if config is None or not config.enabled:
        raise _error(status.HTTP_401_UNAUTHORIZED, "sso_unavailable", "SSO was disabled for this organisation")

    generation = await TokenBlacklist(redis).current_generation(user.id)

    if not config.trust_idp_mfa and user.mfa_enabled:
        _audit(db, action="sso_login_mfa_challenge", organization_id=org_id, user_id=user.id,
               resource_type="user", resource_id=user.id, request=request,
               description=f"SSO login for {user.email} needs PySOAR MFA (IdP MFA not trusted)")
        await db.commit()
        mfa_token = create_access_token(
            subject=user.id, expires_delta=timedelta(minutes=5), extra_claims={"type": "mfa", "gen": generation},
        )
        _clear_browser_cookie(response, request)
        return MFARequiredResponse(mfa_required=True, mfa_token=mfa_token, expires_in=300)

    if user.identity_source == IdentitySource.LOCAL.value and user.force_password_change:
        from src.api.v1.endpoints.auth import forced_password_change

        raise forced_password_change(user.id, generation)

    user.last_login = datetime.now(timezone.utc).isoformat()
    session_minutes = await session_timeout_minutes_for(db, user.organization_id)
    access_token = create_access_token(
        subject=user.id, expires_delta=timedelta(minutes=session_minutes),
        extra_claims={"role": user.role, "gen": generation},
    )
    refresh_token = create_refresh_token(subject=user.id, extra_claims={"gen": generation})
    _audit(db, action="sso_login", organization_id=org_id, user_id=user.id, resource_type="user",
           resource_id=user.id, request=request, description=f"User {user.email} signed in through SSO")
    await db.commit()
    _clear_browser_cookie(response, request)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, expires_in=session_minutes * 60)
