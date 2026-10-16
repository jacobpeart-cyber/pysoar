"""User model for authentication and authorization"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.encryption import EncryptedType, EncryptedJSON
from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.alert import Alert
    from src.models.incident import Incident
    from src.models.audit import AuditLog


class UserRole(str, Enum):
    """User roles for authorization"""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(BaseModel):
    """User model for authentication"""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "sso_subject", name="uq_users_org_sso_subject"),
        Index("ix_users_org_external_id", "organization_id", "external_id"),
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(
        String(50),
        default=UserRole.ANALYST.value,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    force_password_change: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    password_reset_token: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, index=True, unique=True
    )
    password_reset_token_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Identity package (migration 037). A user holding a custom role is judged by
    # that role's per-area tiers instead of the built-in mapping of ``role``;
    # ``identity_source`` says who manages the account (local password, the
    # organisation's OIDC provider, or SCIM provisioning); ``external_id`` is the
    # SCIM externalId and ``sso_subject`` the OIDC ``sub`` bound at first login.
    custom_role_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    identity_source: Mapped[str] = mapped_column(String(20), default="local", server_default="local", nullable=False)
    sso_subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Organization
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True, index=True
    )

    # Optional fields
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # MFA fields
    mfa_secret: Mapped[Optional[str]] = mapped_column(EncryptedType(), nullable=True)
    mfa_backup_codes: Mapped[Optional[dict]] = mapped_column(EncryptedJSON(), nullable=True)

    # Last login tracking
    last_login: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Relationships
    assigned_alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="assignee",
        foreign_keys="Alert.assigned_to",
    )
    assigned_incidents: Mapped[list["Incident"]] = relationship(
        "Incident",
        back_populates="assignee",
        foreign_keys="Incident.assigned_to",
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN.value or self.is_superuser


# users.custom_role_id references the roles table, so the identity models must
# be in the metadata whenever User is (tests and tools import this module on
# its own). Imported last to avoid a cycle: src.identity.models only needs
# src.models.base and src.core.encryption.
from src.identity import models as _identity_models  # noqa: E402,F401
