"""Identity models: SSO configuration, SCIM provisioning tokens and custom roles.

Shared by the identity packages (OIDC single sign-on, SCIM 2.0 provisioning,
per-area custom roles). One row of each kind is scoped to an organisation;
nothing here is platform-wide.

Roles. Access is decided per *area* (the first path segment under ``/api/v1``,
e.g. ``alerts``, ``siem``, ``settings``) at one of four tiers::

    none < read < write < admin

The built-in roles map to a single tier everywhere (``viewer`` = read,
``analyst`` = write, ``admin`` = admin). A custom role (``Role``) carries a
default tier plus per-area overrides; a user holding one (``User.custom_role_id``)
is judged by it instead of the built-in mapping. The platform superuser bypasses
tiers. Enforcement lives in ``src.identity.roles`` and ``src.api.deps``.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.core.encryption import EncryptedType
from src.models.base import BaseModel


class Tier(str, Enum):
    """Access tier for one area."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


#: Ordering used when comparing tiers.
TIER_ORDER: dict[str, int] = {Tier.NONE.value: 0, Tier.READ.value: 1, Tier.WRITE.value: 2, Tier.ADMIN.value: 3}

#: The tier each built-in ``User.role`` holds in every area.
BUILTIN_ROLE_TIERS: dict[str, str] = {"viewer": Tier.READ.value, "analyst": Tier.WRITE.value, "admin": Tier.ADMIN.value}


class IdentitySource(str, Enum):
    """Where a user account is managed."""

    LOCAL = "local"
    OIDC = "oidc"
    SCIM = "scim"


class SSOProtocol(str, Enum):
    """Supported single sign-on protocols. ``saml`` is declared so configuration
    can name it, but it answers 501 until the SAML package (xmlsec in the image)
    lands."""

    OIDC = "oidc"
    SAML = "saml"


class SSOConfiguration(BaseModel):
    """An organisation's single sign-on identity provider (one per organisation)."""

    __tablename__ = "sso_configurations"

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True, index=True,
    )
    protocol: Mapped[str] = mapped_column(String(10), default=SSOProtocol.OIDC.value, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    #: OIDC issuer URL (the ``iss`` claim); discovery is ``<issuer>/.well-known/openid-configuration``
    #: unless ``discovery_url`` overrides it.
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret: Mapped[Optional[str]] = mapped_column(EncryptedType(length=2048), nullable=True)
    scopes: Mapped[str] = mapped_column(String(255), default="openid email profile", nullable=False)
    discovery_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    email_claim: Mapped[str] = mapped_column(String(100), default="email", nullable=False)
    name_claim: Mapped[str] = mapped_column(String(100), default="name", nullable=False)
    groups_claim: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    #: ``{"<IdP group name>": "<built-in role name or custom role id>"}``
    group_role_map: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_role: Mapped[str] = mapped_column(String(50), default="viewer", nullable=False)
    #: Email domains whose users may sign in (and be provisioned) through this IdP.
    allowed_email_domains: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    require_email_verified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: When true a successful IdP login satisfies MFA; when false PySOAR's own MFA step still runs.
    trust_idp_mfa: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_tested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    last_test_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    def __repr__(self) -> str:
        return f"<SSOConfiguration org={self.organization_id} {self.protocol} enabled={self.enabled}>"


class SCIMToken(BaseModel):
    """A bearer token an identity provider uses to call ``/scim/v2`` for one
    organisation. Only the SHA-256 of the token is stored; the token itself is
    shown once at creation."""

    __tablename__ = "scim_tokens"

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    #: First characters of the token, for display only.
    token_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    def __repr__(self) -> str:
        return f"<SCIMToken org={self.organization_id} {self.token_prefix}... revoked={self.revoked_at is not None}>"


class Role(BaseModel):
    """A custom role: a default tier plus per-area overrides, owned by one organisation."""

    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_roles_org_name"),)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    default_tier: Mapped[str] = mapped_column(String(10), default=Tier.READ.value, nullable=False)
    #: ``{"<area>": "<tier>"}`` overrides of ``default_tier``.
    area_tiers: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    def tier_for(self, area: str) -> str:
        """The tier this role grants in ``area``."""
        tier = (self.area_tiers or {}).get(area, self.default_tier)
        return tier if tier in TIER_ORDER else Tier.NONE.value

    def __repr__(self) -> str:
        return f"<Role org={self.organization_id} {self.name} default={self.default_tier}>"
