"""User model for authentication and authorization"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

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

    # Optional fields
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

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
