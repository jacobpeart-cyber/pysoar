"""Identity package schemas: SSO configuration and login, SCIM token management,
custom roles. Shared by the identity routers; each package appends its own
section."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ============================================================================
# SSO (OIDC) — src/api/v1/endpoints/sso.py
# ============================================================================


class SSOConfigUpdate(BaseModel):
    """``PUT /settings/sso`` body (full replace; ``client_secret`` omitted or
    null keeps the stored secret, an empty string clears it).

    ``issuer`` and ``client_id`` are required for ``oidc``; they are optional in
    the schema only so a ``saml`` request reaches the handler's 501."""

    protocol: str = Field(default="oidc", max_length=10)
    display_name: Optional[str] = Field(default=None, max_length=100)
    issuer: Optional[str] = Field(default=None, max_length=500)
    client_id: Optional[str] = Field(default=None, max_length=255)
    client_secret: Optional[str] = Field(default=None, max_length=1024)
    scopes: str = Field(default="openid email profile", max_length=255)
    discovery_url: Optional[str] = Field(default=None, max_length=500)
    email_claim: str = Field(default="email", min_length=1, max_length=100)
    name_claim: str = Field(default="name", min_length=1, max_length=100)
    groups_claim: Optional[str] = Field(default=None, max_length=100)
    #: ``{"<IdP group>": "<admin|analyst|viewer, or a custom role id or name>"}``
    group_role_map: dict[str, str] = Field(default_factory=dict)
    jit_provisioning: bool = False
    default_role: str = Field(default="viewer", min_length=1, max_length=100)
    allowed_email_domains: list[str] = Field(default_factory=list, max_length=50)
    require_email_verified: bool = True
    trust_idp_mfa: bool = True
    enabled: bool = False


class SSOConfigResponse(BaseModel):
    """The organisation's SSO configuration. The client secret is never returned."""

    id: str
    organization_id: str
    organization_slug: str
    protocol: str
    display_name: Optional[str] = None
    issuer: str
    client_id: str
    client_secret_set: bool
    scopes: str
    discovery_url: Optional[str] = None
    effective_discovery_url: str
    #: The redirect URI to register at the identity provider.
    redirect_uri: str
    #: Where users start a login for this organisation (``GET``; redirects to the IdP).
    login_url: str
    email_claim: str
    name_claim: str
    groups_claim: Optional[str] = None
    group_role_map: dict[str, str] = Field(default_factory=dict)
    jit_provisioning: bool
    default_role: str
    allowed_email_domains: list[str] = Field(default_factory=list)
    require_email_verified: bool
    trust_idp_mfa: bool
    enabled: bool
    last_tested_at: Optional[datetime] = None
    last_test_status: Optional[str] = None
    last_test_detail: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SSOTestResponse(BaseModel):
    """``POST /settings/sso/test`` success: what the provider advertised."""

    status: str = "ok"
    tested_at: datetime
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: Optional[str] = None
    key_count: int
    key_ids: list[str] = Field(default_factory=list)
    scopes_supported: list[str] = Field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = Field(default_factory=list)
    code_challenge_methods_supported: list[str] = Field(default_factory=list)
    id_token_signing_alg_values_supported: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SSODiscoverRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)


class SSODiscoverResponse(BaseModel):
    available: bool
    organization_slug: Optional[str] = None
    display_name: Optional[str] = None
    #: Relative URL the browser navigates to (``GET``) to start the login.
    login_url: Optional[str] = None


class SSOExchangeRequest(BaseModel):
    code: str = Field(min_length=16, max_length=128)


def sso_config_to_dict(value: Any) -> dict[str, Any]:
    """Audit-safe snapshot of an SSO configuration (no secret)."""
    return {
        "protocol": value.protocol,
        "display_name": value.display_name,
        "issuer": value.issuer,
        "client_id": value.client_id,
        "client_secret_set": bool(value.client_secret),
        "scopes": value.scopes,
        "discovery_url": value.discovery_url,
        "email_claim": value.email_claim,
        "name_claim": value.name_claim,
        "groups_claim": value.groups_claim,
        "group_role_map": dict(value.group_role_map or {}),
        "jit_provisioning": value.jit_provisioning,
        "default_role": value.default_role,
        "allowed_email_domains": list(value.allowed_email_domains or []),
        "require_email_verified": value.require_email_verified,
        "trust_idp_mfa": value.trust_idp_mfa,
        "enabled": value.enabled,
    }


# ============================================================================
# Custom roles — src/api/v1/endpoints/roles.py (src/identity/roles.py)
# ============================================================================

from typing import Literal  # noqa: E402  (section appended to a shared module)

TierName = Literal["none", "read", "write", "admin"]


class RoleCreate(BaseModel):
    """``POST /roles`` and ``PUT /roles/{id}`` body (PUT replaces every field).

    ``area_tiers`` keys must be areas from ``GET /roles/areas``; an area not
    listed takes ``default_tier``."""

    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    default_tier: TierName = "read"
    area_tiers: dict[str, TierName] = Field(default_factory=dict, max_length=200)


class RoleResponse(BaseModel):
    """A custom role of the caller's organisation."""

    id: str
    organization_id: str
    name: str
    description: Optional[str] = None
    default_tier: str
    area_tiers: dict[str, str] = Field(default_factory=dict)
    member_count: int = 0
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class BuiltinRoleResponse(BaseModel):
    """A built-in role: one tier in every area."""

    name: str
    tier: str
    description: str
    #: Users of the organisation holding this built-in role and no custom role.
    member_count: int = 0


class RoleListResponse(BaseModel):
    builtin: list[BuiltinRoleResponse] = Field(default_factory=list)
    custom: list[RoleResponse] = Field(default_factory=list)


class AreaEntry(BaseModel):
    """One area of the catalogue (first path segment under ``/api/v1``)."""

    area: str
    label: str
    routes: int
    #: Routes in the area gated at write (analyst) and admin tier; the rest
    #: need read (any member).
    write_routes: int
    admin_routes: int
    #: Exempt areas are never denied by tier (``area_denied``).
    exempt: bool
    exempt_reason: Optional[str] = None
    #: The tier each built-in role holds here (``viewer`` / ``analyst`` / ``admin``).
    builtin_tiers: dict[str, str] = Field(default_factory=dict)


class AreaCatalogueResponse(BaseModel):
    tiers: list[str]
    areas: list[AreaEntry]


class RoleMember(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    identity_source: str = "local"


class RoleMembersResponse(BaseModel):
    role_id: str
    total: int
    items: list[RoleMember] = Field(default_factory=list)


# ============================================================================
# SCIM token management — src/api/v1/endpoints/scim_admin.py (src/identity/scim.py)
# ============================================================================


class SCIMTokenCreate(BaseModel):
    """``POST /settings/scim/tokens`` body. Without ``expires_in_days`` the token
    never expires (revoke it with ``DELETE``)."""

    name: str = Field(min_length=1, max_length=100)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=730)


class SCIMTokenResponse(BaseModel):
    """A SCIM token of the caller's organisation (never the token itself)."""

    id: str
    name: str
    token_prefix: str
    #: ``active`` | ``expired`` | ``revoked``
    status: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None


class SCIMTokenCreated(SCIMTokenResponse):
    """``POST /settings/scim/tokens`` answer: the only time ``token`` is returned."""

    token: str
    #: The SCIM base URL to configure at the identity provider.
    scim_base_url: str


class SCIMTokenListResponse(BaseModel):
    scim_base_url: str
    items: list[SCIMTokenResponse] = Field(default_factory=list)


class SCIMGroupMappingUpdate(BaseModel):
    """``PUT /settings/scim/groups/{group_id}`` body: the role the group's
    members receive (``admin`` / ``analyst`` / ``viewer``, or a custom role of
    the organisation by id or name); ``null`` removes the mapping."""

    role: Optional[str] = Field(default=None, max_length=100)


class SCIMGroupSummary(BaseModel):
    """A group the identity provider pushed through SCIM, with its role mapping."""

    id: str
    display_name: str
    external_id: Optional[str] = None
    member_count: int
    #: The mapped role value (``None`` when the group maps to nothing).
    role: Optional[str] = None
    #: Where the mapping is kept: ``sso_group_role_map`` (the organisation's SSO
    #: configuration) or ``scim_groups`` (organisation settings), ``None`` if unmapped.
    mapping_source: Optional[str] = None
    #: ``None`` when the mapping resolves; otherwise why it does not (``role_not_found``).
    mapping_error: Optional[str] = None
    created: Optional[str] = None
    last_modified: Optional[str] = None


class SCIMGroupListResponse(BaseModel):
    items: list[SCIMGroupSummary] = Field(default_factory=list)


class SCIMUserLink(BaseModel):
    """``POST /settings/scim/users/{user_id}/link`` body: hand a local account
    to the identity provider, optionally with its IdP ``externalId``."""

    external_id: Optional[str] = Field(default=None, max_length=255)


class SCIMUserLinkResponse(BaseModel):
    id: str
    email: str
    identity_source: str
    external_id: Optional[str] = None
    is_active: bool
