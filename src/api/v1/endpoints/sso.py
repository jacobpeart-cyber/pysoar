"""Single sign-on (OIDC and SAML 2.0): per-organisation configuration and the login flow.

Configuration (admin of the organisation; org-scoped through ``OrganizationId``):

* ``GET    /settings/sso``       the configuration (404 ``sso_not_configured``); the
  client secret is never returned, only ``client_secret_set``. For SAML it carries
  what to register at the IdP (SP entity id, ACS URL, SP metadata URL).
* ``PUT    /settings/sso``       upsert (``oidc`` or ``saml``).
* ``DELETE /settings/sso``       remove it.
* ``POST   /settings/sso/test``  OIDC: fetch discovery + JWKS through netguard. SAML:
  fetch the IdP metadata through netguard (storing its SSO URL and certificates),
  or check the stored certificates locally. A failure is 502 ``sso_test_failed``,
  never a pass.

Login (public; the browser and the login page call these):

* ``POST /auth/sso/discover``        ``{email}`` -> whether that domain signs in through SSO.
* ``GET  /auth/sso/{org_slug}/start`` 302 to the identity provider (code + PKCE S256).
* ``GET  /auth/sso/callback``        the provider's redirect target; 302 to
  ``/login?sso=<one-time code>`` or ``/login?sso_error=<reason>``.
* ``POST /auth/sso/exchange``        ``{code}`` -> the password-login token response
  (or the MFA challenge when the organisation does not trust the IdP's MFA).

SAML 2.0 (``src.identity.saml``; ``start`` above sends the AuthnRequest):

* ``GET  /auth/sso/{org_slug}/saml/metadata`` our SP EntityDescriptor (public XML).
* ``POST /auth/sso/{org_slug}/saml/acs``      the IdP's HTTP-POST of the Response; verified,
  then 303 to ``complete`` (the browser cookie is SameSite=Lax, so it is not sent on
  the IdP's cross-site POST; the binding is checked on the same-browser GET that follows).
* ``GET  /auth/sso/saml/complete``            checks the ``pysoar_sso`` browser binding, resolves
  the user like OIDC and 302s to ``/login?sso=<one-time code>``.

Every configuration change, test, login and refusal writes an ``AuditLog`` row.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional, Union
from urllib.parse import quote, urlencode, urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from src.api.deps import DatabaseSession, OrganizationId, RedisClient, require_role
from src.core.config import settings
from src.core.logging import get_logger
from src.core.security import create_access_token, create_refresh_token, get_password_hash
from src.core.token_blacklist import TokenBlacklist
from src.identity import oidc
from src.identity import roles as identity_roles
from src.identity import saml as saml_sp
from src.identity.models import BUILTIN_ROLE_TIERS, IdentitySource, Role, SSOConfiguration, SSOProtocol
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.models.user import User, UserRole
from src.schemas.auth import MFARequiredResponse, TokenResponse
from src.schemas.identity import (
    SAMLCertificateSummary,
    SAMLConfigResponse,
    SAMLSettingsUpdate,
    SAMLTestResponse,
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
    # SAML (src.identity.saml)
    "saml_response_invalid", "saml_signature_invalid", "saml_conditions_failed", "saml_unsolicited",
    "saml_replay", "saml_encrypted_unsupported", "saml_status_failure",
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


# -- SAML helpers -------------------------------------------------------------


def _saml_base(request: Request, org_slug: str) -> str:
    return _public_origin(request) + f"{settings.api_v1_prefix}/auth/sso/{quote(org_slug, safe='')}/saml"


def _acs_url(request: Request, org_slug: str) -> str:
    """Our Assertion Consumer Service (HTTP-POST) for the organisation."""
    return _saml_base(request, org_slug) + "/acs"


def _sp_metadata_url(request: Request, org_slug: str) -> str:
    """Our SP metadata; also the default SP entity id."""
    return _saml_base(request, org_slug) + "/metadata"


def _stored_saml(config: Optional[SSOConfiguration]) -> Optional[saml_sp.SAMLSettings]:
    if config is None or config.protocol != SSOProtocol.SAML.value:
        return None
    return saml_sp.SAMLSettings.from_config(config.saml_settings)


def _saml_settings_from(update: Optional[SAMLSettingsUpdate], existing: Optional[SSOConfiguration]) -> saml_sp.SAMLSettings:
    """Validate the SAML part of a PUT. ``idp_certificates`` null keeps the stored ones."""
    update = update or SAMLSettingsUpdate()
    if not update.want_assertions_signed:
        raise _error(422, "saml_assertion_signature_required",
                     "want_assertions_signed cannot be turned off: an unsigned assertion is never accepted")
    if update.name_id_format not in saml_sp.NAME_ID_FORMATS:
        raise _error(422, "invalid_name_id_format",
                     "name_id_format must be emailAddress, persistent or unspecified (transient cannot identify an account)",
                     allowed=list(saml_sp.NAME_ID_FORMATS))
    if not 0 <= update.clock_skew_seconds <= saml_sp.MAX_CLOCK_SKEW_SECONDS:
        raise _error(422, "invalid_clock_skew",
                     f"clock_skew_seconds must be between 0 and {saml_sp.MAX_CLOCK_SKEW_SECONDS}")
    sso_url = (update.idp_sso_url or "").strip() or None
    if sso_url and not _is_https_url(sso_url):
        raise _error(422, "invalid_idp_sso_url", "the IdP single sign-on URL must be an https URL")
    stored = _stored_saml(existing)
    if update.idp_certificates is None:
        certificates = stored.idp_certificates if stored is not None else ()
    else:
        normalised: list[str] = []
        for index, text in enumerate(update.idp_certificates):
            try:
                pem = saml_sp.normalise_certificate(text)
            except saml_sp.SAMLError as exc:
                raise _error(422, "invalid_certificate", f"IdP certificate {index + 1}: {exc.detail}", index=index) from exc
            if pem not in normalised:
                normalised.append(pem)
        certificates = tuple(normalised)
    return saml_sp.SAMLSettings(
        idp_sso_url=sso_url,
        idp_certificates=certificates,
        name_id_format=update.name_id_format,
        want_response_signed=update.want_response_signed,
        clock_skew_seconds=update.clock_skew_seconds,
    )


def _certificate_summaries(certificates: tuple[str, ...]) -> list[SAMLCertificateSummary]:
    out: list[SAMLCertificateSummary] = []
    for pem in certificates:
        try:
            out.append(SAMLCertificateSummary(**saml_sp.certificate_summary(pem)))
        except ValueError:
            logger.warning("sso_saml_certificate_unreadable")
    return out


def _saml_config_response(config: SSOConfiguration, org: Organization, request: Request) -> SAMLConfigResponse:
    stored = saml_sp.SAMLSettings.from_config(config.saml_settings)
    return SAMLConfigResponse(
        sp_entity_id=config.client_id,
        acs_url=_acs_url(request, org.slug),
        sp_metadata_url=_sp_metadata_url(request, org.slug),
        metadata_url=config.discovery_url,
        idp_entity_id=config.issuer,
        idp_sso_url=stored.idp_sso_url,
        idp_certificates=_certificate_summaries(stored.idp_certificates),
        name_id_format=stored.name_id_format,
        name_id_formats_supported=list(saml_sp.NAME_ID_FORMATS),
        want_assertions_signed=True,
        want_response_signed=stored.want_response_signed,
        clock_skew_seconds=stored.clock_skew_seconds,
    )


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
#: For SAML the IdP certificates, SSO URL and NameID format are trust settings
#: too, and so are loosening ``want_response_signed`` or widening the clock skew.
_TRUST_FIELDS = ("protocol", "issuer", "discovery_url", "client_id", "client_secret", "allowed_email_domains",
                 "require_email_verified", "trust_idp_mfa", "jit_provisioning", "enabled",
                 "email_claim", "groups_claim", "saml.idp_sso_url", "saml.idp_certificates",
                 "saml.name_id_format", "saml.want_response_signed", "saml.clock_skew_seconds")


def _full_admin_required(fields: list[str]) -> HTTPException:
    return _error(status.HTTP_403_FORBIDDEN, "full_admin_required",
                  "changing the identity provider, its trust settings or enabling SSO needs a built-in "
                  "admin without a custom role: " + ", ".join(fields), fields=fields)


def _to_response(config: SSOConfiguration, org: Organization, request: Request) -> SSOConfigResponse:
    is_saml = config.protocol == SSOProtocol.SAML.value
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
        effective_discovery_url=(config.discovery_url or "") if is_saml
        else oidc.discovery_url_for(config.issuer, config.discovery_url),
        # SAML: the ACS URL is what the IdP posts to.
        redirect_uri=_acs_url(request, org.slug) if is_saml else _redirect_uri(request),
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
        saml=_saml_config_response(config, org, request) if is_saml else None,
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

    ``oidc``: issuer, client id / secret, scopes, discovery URL. ``saml``:
    ``issuer`` = IdP entity id, ``client_id`` = our SP entity id (default: the
    SP metadata URL), ``discovery_url`` = IdP metadata URL, and ``saml`` = the
    IdP SSO URL, signing certificates, NameID format, ``want_response_signed``
    and clock skew; the claim fields name SAML attributes (groups default
    ``groups``), and ``require_email_verified`` is stored false (SAML has no
    verified-email flag: the signed attribute is trusted).

    Enabling requires at least one allowed email domain and a passing
    ``POST /settings/sso/test`` for the current provider settings.
    """
    protocol = (payload.protocol or "").strip().lower()
    if protocol not in (SSOProtocol.OIDC.value, SSOProtocol.SAML.value):
        raise _error(422, "unsupported_protocol", f"protocol must be 'oidc' or 'saml' (got {payload.protocol!r})")
    org = await _organization(db, org_id)
    existing = await _config_for(db, org_id)

    issuer = (payload.issuer or "").strip()
    discovery_url = (payload.discovery_url or "").strip() or None
    saml_settings: Optional[saml_sp.SAMLSettings] = None
    if protocol == SSOProtocol.OIDC.value:
        client_id = (payload.client_id or "").strip()
        if not issuer or not client_id:
            raise _error(422, "missing_field", "issuer and client_id are required for OIDC",
                         fields=[f for f, v in (("issuer", issuer), ("client_id", client_id)) if not v])
        if not _is_https_url(issuer):
            raise _error(422, "invalid_issuer", "issuer must be an https URL (OpenID Connect requires TLS)")
        if discovery_url and not _is_https_url(discovery_url):
            raise _error(422, "invalid_discovery_url", "discovery_url must be an https URL")
        if discovery_url and (urlsplit(discovery_url).hostname or "").lower() != (urlsplit(issuer).hostname or "").lower():
            raise _error(422, "discovery_host_mismatch",
                         "discovery_url must be on the issuer's host (the provider publishes its own configuration)")
        scopes = " ".join(payload.scopes.split())
        if "openid" not in scopes.split(" "):
            raise _error(422, "invalid_scopes", "scopes must include 'openid'")
        stored_secret = (existing.client_secret or None) if existing is not None else None
        client_secret = stored_secret if payload.client_secret is None else (payload.client_secret or None)
        require_email_verified = payload.require_email_verified
        groups_claim = (payload.groups_claim or "").strip() or None
    else:
        client_id = (payload.client_id or "").strip() or _sp_metadata_url(request, org.slug)
        if not issuer:
            raise _error(422, "missing_field", "issuer (the IdP entity id) is required for SAML", fields=["issuer"])
        if len(client_id) > 255:
            raise _error(422, "invalid_sp_entity_id", "the SP entity id (client_id) must be at most 255 characters")
        if discovery_url and not _is_https_url(discovery_url):
            raise _error(422, "invalid_metadata_url", "the IdP metadata URL (discovery_url) must be an https URL")
        saml_settings = _saml_settings_from(payload.saml, existing)
        scopes = " ".join(payload.scopes.split()) or "openid email profile"
        client_secret = None
        require_email_verified = False
        groups_claim = (payload.groups_claim or "").strip() or "groups"

    domains: list[str] = []
    for raw in payload.allowed_email_domains:
        domain = raw.strip().lower().lstrip("@")
        if not _DOMAIN_RE.match(domain):
            raise _error(422, "invalid_email_domain", f"{raw!r} is not an email domain", domain=raw)
        if domain not in domains:
            domains.append(domain)

    stored_saml = _stored_saml(existing)
    if not is_full_admin(current_user):
        if existing is None:
            changed = list(_TRUST_FIELDS)
        else:
            diffs: list[tuple[str, Any, Any]] = [
                ("protocol", existing.protocol, protocol),
                ("issuer", existing.issuer, issuer),
                ("discovery_url", existing.discovery_url or None, discovery_url),
                ("client_id", existing.client_id, client_id),
                ("client_secret", existing.client_secret or None, client_secret),
                ("allowed_email_domains", sorted(existing.allowed_email_domains or []), sorted(domains)),
                # Turning verification on only narrows who can sign in.
                ("require_email_verified", existing.require_email_verified,
                 existing.require_email_verified if require_email_verified else False),
                ("trust_idp_mfa", existing.trust_idp_mfa, payload.trust_idp_mfa),
                ("jit_provisioning", existing.jit_provisioning, payload.jit_provisioning),
                ("enabled", existing.enabled, payload.enabled),
                ("email_claim", existing.email_claim, payload.email_claim.strip()),
                ("groups_claim", existing.groups_claim or None, groups_claim),
            ]
            if groups_claim or existing.groups_claim:
                # With a groups claim / attribute configured, every login re-syncs
                # the role from group_role_map (_resync_role): editing the map (or
                # the default role new accounts get) can re-role existing accounts,
                # built-in admins included, so it is a trust setting.
                diffs += [
                    ("group_role_map", dict(existing.group_role_map or {}),
                     {str(k): str(v).strip() for k, v in payload.group_role_map.items()}),
                    ("default_role", existing.default_role, payload.default_role.strip()),
                ]
            if saml_settings is not None:
                before = stored_saml or saml_sp.SAMLSettings()
                diffs += [
                    ("saml.idp_sso_url", before.idp_sso_url, saml_settings.idp_sso_url),
                    ("saml.idp_certificates", before.idp_certificates, saml_settings.idp_certificates),
                    ("saml.name_id_format", before.name_id_format, saml_settings.name_id_format),
                    # Requiring a signed response, or a smaller skew, only narrows what is accepted.
                    ("saml.want_response_signed", before.want_response_signed,
                     before.want_response_signed if saml_settings.want_response_signed else False),
                    ("saml.clock_skew_seconds", before.clock_skew_seconds,
                     max(before.clock_skew_seconds, saml_settings.clock_skew_seconds)),
                ]
            changed = [f for f, before_value, after_value in diffs if before_value != after_value]
        if changed:
            raise _full_admin_required(changed)

    # The provider's email_verified describes its "email" claim only; another
    # claim carries no verification, so it cannot be used while verification is required.
    if protocol == SSOProtocol.OIDC.value and payload.email_claim.strip() != "email" and payload.require_email_verified:
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
    before_saml = stored_saml or saml_sp.SAMLSettings()
    if config is None:
        config = SSOConfiguration(organization_id=org_id, issuer=issuer, client_id=client_id)
        db.add(config)
    elif (config.protocol != protocol or config.issuer != issuer or (config.discovery_url or None) != discovery_url
          or (saml_settings is not None and (
              config.client_id != client_id
              or before_saml.idp_sso_url != saml_settings.idp_sso_url
              or before_saml.idp_certificates != saml_settings.idp_certificates))):
        # The stored test result was for another provider (or other SAML trust material).
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
    config.client_secret = client_secret
    config.scopes = scopes
    config.discovery_url = discovery_url
    config.email_claim = payload.email_claim.strip()
    config.name_claim = payload.name_claim.strip()
    config.groups_claim = groups_claim
    config.group_role_map = {str(k): str(v).strip() for k, v in payload.group_role_map.items()}
    config.jit_provisioning = payload.jit_provisioning
    config.default_role = payload.default_role.strip()
    config.allowed_email_domains = domains
    config.require_email_verified = require_email_verified
    config.trust_idp_mfa = payload.trust_idp_mfa
    config.enabled = payload.enabled
    config.saml_settings = saml_settings.as_dict() if saml_settings is not None else None
    config.updated_by = str(current_user.id)
    await db.flush()

    new = sso_config_to_dict(config)
    _audit(db, action="sso_config_create" if created else "sso_config_update", organization_id=org_id,
           user_id=str(current_user.id), resource_id=config.id, old_value=old, new_value=new, request=request,
           description=f"SSO configuration {'created' if created else 'updated'} ({protocol}, issuer {issuer}, "
           f"{'enabled' if config.enabled else 'disabled'})")
    await db.commit()
    await db.refresh(config)
    logger.info("sso_config_saved", organization_id=org_id, enabled=config.enabled, created=created, protocol=protocol)
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


@router.post("/settings/sso/test", response_model=Union[SSOTestResponse, SAMLTestResponse])
async def test_sso_configuration(
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    request: Request,
    db: DatabaseSession = None,
    redis: RedisClient = None,
) -> SSOTestResponse | SAMLTestResponse:
    """Fetch the provider's discovery document and JWKS and record the result (admin, audited).

    Checks: discovery reachable through netguard, ``issuer`` equals the
    configured issuer, the three endpoints present, JWKS reachable with at least
    one key. Failure: 502 ``sso_test_failed`` with ``reason`` and ``detail``.
    It does not exercise the client secret (only a real login does).
    """
    config = await _config_for(db, org_id)
    if config is None:
        raise _error(status.HTTP_404_NOT_FOUND, "sso_not_configured", "save a configuration before testing it")
    if config.protocol == SSOProtocol.SAML.value:
        return await _test_saml_configuration(db, config, org_id, current_user, request)
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
        .where(SSOConfiguration.enabled.is_(True),
               SSOConfiguration.protocol.in_((SSOProtocol.OIDC.value, SSOProtocol.SAML.value)),
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
    if org is None or config is None or not config.enabled or config.protocol not in (
            SSOProtocol.OIDC.value, SSOProtocol.SAML.value):
        return _fail_redirect("sso_unavailable")
    if config.protocol == SSOProtocol.SAML.value:
        return await _start_saml(db, redis, request, org, config)
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


async def _mapped_role(db: Any, config: SSOConfiguration, claims: dict[str, Any]) -> Optional[tuple[str, Optional[str]]]:
    """``(User.role, custom_role_id)`` from ``group_role_map`` (first mapped
    group, in map order), ``None`` when no group of the user is mapped; a
    mapping to a role that no longer exists refuses the login."""
    mapped = oidc.first_mapped_group(config.group_role_map, _groups(claims, config.groups_claim))
    if mapped is None:
        return None
    group, value = mapped
    resolved = await resolve_role_value(db, config.organization_id, value)
    if resolved is None:
        raise _LoginRefused("role_unresolved", f"group {group!r} maps to {value!r}, which no longer exists")
    return resolved


async def _role_for_new_user(db: Any, config: SSOConfiguration, claims: dict[str, Any]) -> tuple[str, Optional[str]]:
    """Role from ``group_role_map`` (first mapped group, in map order) else ``default_role``."""
    resolved = await _mapped_role(db, config, claims)
    if resolved is not None:
        return resolved
    resolved = await resolve_role_value(db, config.organization_id, config.default_role)
    if resolved is None:
        raise _LoginRefused("role_unresolved", f"default role {config.default_role!r} no longer exists")
    return resolved


async def _resync_role(
    db: Any, config: SSOConfiguration, claims: dict[str, Any], user: User, request: Optional[Request],
) -> None:
    """Group re-sync on login: re-apply the role the user's groups map to.

    Only when the configuration names a groups claim and has a non-empty
    ``group_role_map``. No mapped group: the role is left as it is (never
    demoted on an empty mapping). SCIM-managed users are never changed here
    (the provisioning feed owns their role). Custom roles go through
    ``assignment_error`` / ``apply_custom_role``; a change is audited as
    ``sso_role_synced`` with the old and new role.
    """
    if not config.groups_claim or not config.group_role_map:
        return
    if (user.identity_source or IdentitySource.LOCAL.value) == IdentitySource.SCIM.value or user.is_superuser:
        return
    resolved = await _mapped_role(db, config, claims)
    if resolved is None:
        return
    builtin, custom_role_id = resolved
    old = {"role": user.role, "custom_role_id": user.custom_role_id}
    if custom_role_id:
        role = await db.get(Role, str(custom_role_id))
        problem = identity_roles.assignment_error(user, role, config.organization_id) if role is not None else {
            "error": "role_not_found", "detail": "custom role not found in this organisation",
        }
        if problem is not None:
            raise _LoginRefused("role_unresolved", f"mapped role {custom_role_id!r}: {problem['detail']}", user.id)
        identity_roles.apply_custom_role(user, role)
    else:
        identity_roles.apply_custom_role(user, None)
        user.role = builtin
    new = {"role": user.role, "custom_role_id": user.custom_role_id}
    if new == old:
        return
    _audit(db, action="sso_role_synced", organization_id=config.organization_id, user_id=user.id,
           resource_type="user", resource_id=user.id, request=request, old_value=old, new_value=new,
           description=f"Role of {user.email} re-synced from identity provider groups on SSO login")
    logger.info("sso_role_synced", organization_id=config.organization_id, user_id=user.id,
                old_role=old["role"], new_role=new["role"], new_custom_role_id=new["custom_role_id"])


async def _user_for_claims(
    db: Any, config: SSOConfiguration, claims: dict[str, Any], *, request: Optional[Request] = None,
) -> tuple[User, str]:
    """Match, bind or provision the user for verified ID token claims; returns (user, how).

    A matched or bound user's role is then re-synced from the groups claim
    (``_resync_role``); pass ``request`` so that audit row carries the client."""
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
    if how != "provisioned":
        await _resync_role(db, config, claims, user, request)
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
        user, how = await _user_for_claims(db, config, claims, request=request)
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


# ---------------------------------------------------------------------------
# SAML 2.0 (src.identity.saml)
# ---------------------------------------------------------------------------


async def _test_saml_configuration(
    db: Any, config: SSOConfiguration, org_id: str, current_user: User, request: Request,
) -> SAMLTestResponse:
    """``POST /settings/sso/test`` for SAML.

    With an IdP metadata URL: fetch it through netguard, find the
    EntityDescriptor whose entityID is the configured IdP entity id, and store
    its HTTP-Redirect SSO URL and signing certificates. Without one: check the
    stored SSO URL and certificates locally (the IdP is not contacted; the
    result says so). Failure: 502 ``sso_test_failed`` with the reason.
    """
    now = datetime.now(timezone.utc)
    stored = saml_sp.SAMLSettings.from_config(config.saml_settings)
    warnings: list[str] = []
    formats: list[str] = []
    try:
        if config.discovery_url:
            metadata = await saml_sp.fetch_idp_metadata(config.discovery_url, config.issuer)
            source = "metadata"
            formats = metadata.name_id_formats
            if stored.idp_sso_url and stored.idp_sso_url != metadata.sso_url:
                warnings.append(f"the IdP SSO URL was updated from the metadata (was {stored.idp_sso_url})")
            if stored.idp_certificates and set(stored.idp_certificates) != set(metadata.certificates):
                warnings.append("the IdP signing certificates were replaced by the ones the metadata lists")
            tested = replace(stored, idp_sso_url=metadata.sso_url, idp_certificates=tuple(metadata.certificates))
            if formats and tested.name_id_format not in formats and saml_sp.NAMEID_UNSPECIFIED not in formats:
                warnings.append(f"the IdP does not advertise the NameID format {tested.name_id_format}; "
                                "it may refuse the request or send another format")
        else:
            source = "configuration"
            if not stored.idp_sso_url:
                raise saml_sp.SAMLError("configuration_incomplete",
                                        "no IdP single sign-on URL: enter it, or an IdP metadata URL to read it from")
            if not stored.idp_certificates:
                raise saml_sp.SAMLError("configuration_incomplete",
                                        "no IdP signing certificate: paste it, or enter an IdP metadata URL to read it from")
            tested = stored
            warnings.append("no IdP metadata URL: the certificate(s) and SSO URL were checked locally and the IdP was "
                            "not contacted; a real sign-in exercises them")
        summaries = [saml_sp.certificate_summary(pem, now=now) for pem in tested.idp_certificates]
        if all(s["expired"] for s in summaries):
            raise saml_sp.SAMLError("certificate_invalid",
                                    "every IdP signing certificate has expired; signatures made with them are refused")
        for s in summaries:
            if s["expired"]:
                warnings.append(f"certificate {s['sha256_fingerprint']} expired at {s['not_after']} and will not verify")
    except saml_sp.SAMLError as exc:
        config.last_tested_at = now
        config.last_test_status = "failed"
        config.last_test_detail = exc.detail[:2000]
        _audit(db, action="sso_config_test", organization_id=org_id, user_id=str(current_user.id),
               resource_id=config.id, success=False, error_message=exc.detail[:2000], request=request,
               new_value={"status": "failed", "protocol": "saml", "reason": exc.reason},
               description=f"SSO connection test failed: {exc.reason}")
        await db.commit()
        logger.warning("sso_test_failed", organization_id=org_id, reason=exc.reason, protocol="saml")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "sso_test_failed", "reason": exc.reason, "detail": exc.detail},
        ) from exc

    old_settings = stored.audit_dict()
    config.saml_settings = tested.as_dict()
    detail = f"{len(summaries)} signing certificate(s); SSO URL {tested.idp_sso_url} ({source})"
    if warnings:
        detail += "; warnings: " + "; ".join(warnings)
    config.last_tested_at = now
    config.last_test_status = "ok"
    config.last_test_detail = detail[:2000]
    _audit(db, action="sso_config_test", organization_id=org_id, user_id=str(current_user.id),
           resource_id=config.id, request=request, old_value={"saml_settings": old_settings},
           new_value={"status": "ok", "protocol": "saml", "source": source, "saml_settings": tested.audit_dict(),
                      "warnings": warnings},
           description=f"SSO connection test passed (SAML, {source})")
    await db.commit()
    return SAMLTestResponse(
        tested_at=now,
        source=source,
        idp_entity_id=config.issuer,
        idp_sso_url=str(tested.idp_sso_url),
        certificate_count=len(summaries),
        certificates=[SAMLCertificateSummary(**s) for s in summaries],
        name_id_formats=formats,
        warnings=warnings,
    )


async def _start_saml(db: Any, redis: Any, request: Request, org: Organization, config: SSOConfiguration) -> RedirectResponse:
    """Send the browser to the IdP with an unsigned AuthnRequest (HTTP-Redirect binding).

    Stores ``{organization_id, browser, relay_state, acs_url, sp_entity_id,
    created}`` under ``sso:saml:request:<request id>`` for 10 minutes (single
    use) and sets the same ``pysoar_sso`` browser cookie as OIDC.
    """
    stored = saml_sp.SAMLSettings.from_config(config.saml_settings)
    if not stored.idp_sso_url or not stored.idp_certificates:
        _audit(db, action="sso_login_failed", organization_id=org.id, user_id=None, resource_id=config.id,
               success=False, request=request, error_message="SAML configuration lacks the IdP SSO URL or certificates",
               description="SSO login could not start: sso_unavailable")
        await db.commit()
        return _fail_redirect("sso_unavailable")
    request_id = saml_sp.new_request_id()
    relay_state = secrets.token_urlsafe(32)
    acs_url = _acs_url(request, org.slug)
    browser_secret = oidc.new_browser_secret()
    now = datetime.now(timezone.utc)
    await oidc.put_json(redis, saml_sp.REQUEST_KEY.format(request_id), saml_sp.REQUEST_TTL_SECONDS, {
        "browser": oidc.browser_binding(browser_secret),
        "organization_id": org.id,
        "relay_state": relay_state,
        "acs_url": acs_url,
        "sp_entity_id": config.client_id,
        "created": now.isoformat(),
    })
    xml = saml_sp.authn_request_xml(
        request_id=request_id, issue_instant=now, destination=stored.idp_sso_url, sp_entity_id=config.client_id,
        acs_url=acs_url, name_id_format=stored.name_id_format,
    )
    response = RedirectResponse(saml_sp.redirect_url(stored.idp_sso_url, xml, relay_state), status_code=status.HTTP_302_FOUND)
    _set_browser_cookie(response, request, browser_secret)
    return response


async def _saml_org_config(db: Any, org_slug: str) -> tuple[Optional[Organization], Optional[SSOConfiguration]]:
    org = (await db.execute(
        select(Organization).where(Organization.slug == org_slug, Organization.is_active.is_(True)),
    )).scalar_one_or_none()
    config = await _config_for(db, org.id) if org is not None else None
    if config is not None and config.protocol != SSOProtocol.SAML.value:
        config = None
    return org, config


@router.get("/auth/sso/{org_slug}/saml/metadata", name="sso_saml_metadata")
async def saml_sp_metadata(
    org_slug: str,
    request: Request,
    db: DatabaseSession = None,
) -> Response:
    """Our SAML SP metadata for the organisation (public XML): entity id, ACS URL
    (HTTP-POST), NameID format, ``AuthnRequestsSigned=false``,
    ``WantAssertionsSigned=true``. No signing or encryption certificate: PySOAR
    does not sign requests and does not accept encrypted assertions. Served
    while SSO is disabled too, so the administrator can register it first.
    404 ``saml_not_configured`` unless the organisation has a SAML configuration."""
    org, config = await _saml_org_config(db, org_slug)
    if org is None or config is None:
        raise _error(status.HTTP_404_NOT_FOUND, "saml_not_configured",
                     "this organisation has no SAML single sign-on configuration")
    stored = saml_sp.SAMLSettings.from_config(config.saml_settings)
    body = saml_sp.sp_metadata_xml(entity_id=config.client_id, acs_url=_acs_url(request, org.slug),
                                   name_id_format=stored.name_id_format)
    return Response(content=body, media_type="application/samlmetadata+xml",
                    headers={"Content-Disposition": f'inline; filename="pysoar-{org.slug}-saml-metadata.xml"'})


def _see_other(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/auth/sso/{org_slug}/saml/acs", name="sso_saml_acs", status_code=status.HTTP_303_SEE_OTHER)
async def saml_acs(
    org_slug: str,
    request: Request,
    saml_response: Annotated[Optional[str], Form(alias="SAMLResponse", max_length=400_000)] = None,
    relay_state: Annotated[Optional[str], Form(alias="RelayState", max_length=1024)] = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
) -> RedirectResponse:
    """The IdP's HTTP-POST of the SAML Response (public).

    Verifies the response (``src.identity.saml.validate_response``: signature
    against the stored certificates, status, issuer, time window, audience,
    recipient), then that ``InResponseTo`` names a pending request of this
    organisation (consumed; unsolicited responses refused), that ``RelayState``
    matches it, and that the assertion id is new (replay cache until the
    assertion expires). Success: 303 to ``/auth/sso/saml/complete?ticket=``,
    where the browser binding is checked; failure: 303
    ``/login?sso_error=<reason>`` with the cause in the audit row.
    """
    org, config = await _saml_org_config(db, org_slug)
    org_id = org.id if org is not None else None
    config_id = config.id if config is not None else None

    async def refuse(reason: str, detail: str) -> RedirectResponse:
        _audit(db, action="sso_login_failed", organization_id=org_id, user_id=None, resource_id=config_id,
               success=False, error_message=detail[:2000], request=request,
               description=f"SSO login refused: {reason}")
        await db.commit()
        logger.warning("sso_login_refused", organization_id=org_id, reason=reason, protocol="saml")
        return _see_other("/login?" + urlencode({"sso_error": reason if reason in LOGIN_ERROR_REASONS else "sso_failed"}))

    if org is None or config is None or not config.enabled:
        return await refuse("sso_unavailable", f"no enabled SAML configuration for organisation slug {org_slug!r}")
    stored = saml_sp.SAMLSettings.from_config(config.saml_settings)
    acs_url = _acs_url(request, org.slug)
    try:
        identity = saml_sp.validate_response(
            saml_sp.decode_post_response(saml_response or ""), settings=stored, idp_entity_id=config.issuer,
            sp_entity_id=config.client_id, acs_url=acs_url,
        )
    except saml_sp.SAMLError as exc:
        return await refuse(exc.reason, exc.detail)

    if not identity.in_response_to:
        return await refuse("saml_unsolicited", "the response answers no AuthnRequest (InResponseTo missing); "
                            "IdP-initiated sign-in is not supported: start the sign-in from PySOAR")
    now = datetime.now(timezone.utc)
    ttl = max(1, int((identity.valid_until - now).total_seconds()) + 1)
    fresh = await redis.set(saml_sp.replay_key(config.id, identity.assertion_id), "1", ex=ttl, nx=True)
    if not fresh:
        return await refuse("saml_replay", f"assertion {identity.assertion_id} was already used")
    pending = await oidc.take_json(redis, saml_sp.REQUEST_KEY.format(identity.in_response_to))
    if pending is None or pending.get("organization_id") != org.id:
        return await refuse("saml_unsolicited", f"InResponseTo {identity.in_response_to!r} names no pending request "
                            "of this organisation (unknown, expired or already used)")
    expected_relay = str(pending.get("relay_state") or "")
    if relay_state is not None and not hmac.compare_digest(relay_state, expected_relay):
        return await refuse("invalid_state", "RelayState does not match the AuthnRequest")
    if pending.get("acs_url") and pending.get("acs_url") != acs_url:
        return await refuse("saml_conditions_failed", "the response reached another ACS URL than the request named")

    claims = identity.claims(email_attribute=config.email_claim, name_attribute=config.name_claim,
                             groups_attribute=config.groups_claim)
    ticket = secrets.token_urlsafe(32)
    await oidc.put_json(redis, saml_sp.TICKET_KEY.format(ticket), saml_sp.TICKET_TTL_SECONDS, {
        "organization_id": org.id, "config_id": config.id, "browser": pending.get("browser"), "claims": claims,
    })
    _audit(db, action="sso_saml_assertion", organization_id=org.id, user_id=None, resource_id=config.id,
           request=request, new_value={"assertion_id": identity.assertion_id, "name_id": identity.name_id,
                                       "name_id_format": identity.name_id_format,
                                       "in_response_to": identity.in_response_to},
           description="SAML assertion verified; browser binding check pending")
    await db.commit()
    return _see_other(f"{settings.api_v1_prefix}/auth/sso/saml/complete?" + urlencode({"ticket": ticket}))


@router.get("/auth/sso/saml/complete", name="sso_saml_complete", status_code=status.HTTP_302_FOUND)
async def saml_complete(
    request: Request,
    ticket: Annotated[Optional[str], Query(max_length=256)] = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
) -> RedirectResponse:
    """Second leg of the SAML login, in the browser that started it.

    The ACS hands over a single-use ticket (60 s); this same-site GET carries
    the ``pysoar_sso`` cookie, which must match the request's binding (login
    CSRF). Then the user is matched by NameID (``sso_subject``), else by email
    (binding the NameID), else provisioned when just-in-time provisioning is
    on, exactly as for OIDC. Success: 302 ``/login?sso=<one-time code>``.
    """
    entry = await oidc.take_json(redis, saml_sp.TICKET_KEY.format(ticket)) if ticket else None
    cookie = request.cookies.get(oidc.BROWSER_COOKIE)
    if entry is not None and not oidc.binding_matches(cookie, entry.get("browser")):
        _audit(db, action="sso_login_failed", organization_id=str(entry.get("organization_id") or "") or None,
               user_id=None, success=False, request=request,
               error_message="SAML login is not bound to this browser (pysoar_sso cookie missing or different)",
               description="SSO callback refused: invalid_state")
        await db.commit()
        logger.warning("sso_saml_browser_mismatch", organization_id=entry.get("organization_id"))
        return _fail_redirect("invalid_state")
    if entry is None:
        _audit(db, action="sso_login_failed", organization_id=None, user_id=None, success=False,
               request=request, error_message="unknown, expired or replayed SAML ticket",
               description="SSO callback refused: invalid_state")
        await db.commit()
        return _fail_redirect("invalid_state")

    org_id = str(entry.get("organization_id") or "")
    config = await _config_for(db, org_id) if org_id else None
    config_id = config.id if config is not None else None

    async def refuse(reason: str, detail: str, user_id: Optional[str] = None) -> RedirectResponse:
        _audit(db, action="sso_login_failed", organization_id=org_id or None, user_id=user_id,
               resource_id=config_id, success=False, error_message=detail[:2000], request=request,
               description=f"SSO login refused: {reason}")
        await db.commit()
        logger.warning("sso_login_refused", organization_id=org_id, reason=reason, protocol="saml")
        return _fail_redirect(reason)

    if (config is None or not config.enabled or config.protocol != SSOProtocol.SAML.value
            or config.id != entry.get("config_id")):
        return await refuse("sso_unavailable", "SSO was disabled, removed or replaced during the login")
    claims = entry.get("claims")
    if not isinstance(claims, dict) or not claims.get("sub"):
        return await refuse("sso_failed", "the SAML ticket carries no identity")

    try:
        user, how = await _user_for_claims(db, config, claims, request=request)
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
                        {"user_id": user.id, "organization_id": org_id, "browser": entry.get("browser")})
    _audit(db, action="sso_callback", organization_id=org_id, user_id=user.id, resource_type="user",
           resource_id=user.id, request=request,
           description=f"SSO identity verified for {user.email} (SAML, {how}); one-time login code issued")
    await db.commit()
    return _login_redirect(sso=login_code)
