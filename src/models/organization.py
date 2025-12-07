"""Organization and Team models for multi-tenancy"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class OrganizationPlan(str, Enum):
    """Organization subscription plans"""

    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class Organization(BaseModel):
    """Organization for multi-tenancy"""

    __tablename__ = "organizations"

    # Basic info
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Contact info
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Address
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Branding
    logo_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    primary_color: Mapped[Optional[str]] = mapped_column(String(7), nullable=True)

    # Plan and limits
    plan: Mapped[str] = mapped_column(
        String(50),
        default=OrganizationPlan.FREE.value,
        nullable=False,
    )
    max_users: Mapped[int] = mapped_column(default=5, nullable=False)
    max_alerts_per_month: Mapped[int] = mapped_column(default=1000, nullable=False)
    max_storage_gb: Mapped[int] = mapped_column(default=5, nullable=False)

    # Settings (JSON)
    settings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    teams: Mapped[list["Team"]] = relationship("Team", back_populates="organization")
    members: Mapped[list["OrganizationMember"]] = relationship(
        "OrganizationMember", back_populates="organization"
    )

    def __repr__(self) -> str:
        return f"<Organization {self.name}>"


class OrganizationRole(str, Enum):
    """Roles within an organization"""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class OrganizationMember(BaseModel):
    """Organization membership"""

    __tablename__ = "organization_members"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        String(50),
        default=OrganizationRole.MEMBER.value,
        nullable=False,
    )
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relations
    organization: Mapped["Organization"] = relationship("Organization", back_populates="members")
    user: Mapped["User"] = relationship("User")

    def __repr__(self) -> str:
        return f"<OrganizationMember org={self.organization_id} user={self.user_id}>"


class Team(BaseModel):
    """Teams within an organization"""

    __tablename__ = "teams"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Organization relationship
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    # Team settings
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relations
    organization: Mapped["Organization"] = relationship("Organization", back_populates="teams")
    members: Mapped[list["TeamMember"]] = relationship("TeamMember", back_populates="team")

    def __repr__(self) -> str:
        return f"<Team {self.name}>"


class TeamRole(str, Enum):
    """Roles within a team"""

    LEAD = "lead"
    MEMBER = "member"


class TeamMember(BaseModel):
    """Team membership"""

    __tablename__ = "team_members"

    team_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("teams.id"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        String(50),
        default=TeamRole.MEMBER.value,
        nullable=False,
    )

    # Relations
    team: Mapped["Team"] = relationship("Team", back_populates="members")
    user: Mapped["User"] = relationship("User")

    def __repr__(self) -> str:
        return f"<TeamMember team={self.team_id} user={self.user_id}>"
