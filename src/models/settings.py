"""AppSetting model for persisting runtime-editable application settings.

Sections (e.g. 'general', 'smtp', 'notifications', 'security',
'integration:splunk') are stored as JSON blobs scoped to an organization.
A NULL ``organization_id`` is treated as a global default. The
``(organization_id, section)`` uniqueness constraint is what lets the
PATCH endpoints do ``INSERT ... ON CONFLICT DO UPDATE`` upserts.
"""

from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.organization import Organization
    from src.models.user import User


# Portable JSON column: JSONB on Postgres, plain JSON on SQLite (tests)
_JSONVariant = JSON().with_variant(JSONB(), "postgresql")


class AppSetting(BaseModel):
    """A persisted application settings blob for one (org, section) pair."""

    __tablename__ = "app_settings"

    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    section: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    value: Mapped[Any] = mapped_column(_JSONVariant, nullable=False, default=dict)
    updated_by: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization", foreign_keys=[organization_id]
    )
    updater: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[updated_by]
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "section", name="uq_app_settings_org_section"
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AppSetting org={self.organization_id} section={self.section}>"
