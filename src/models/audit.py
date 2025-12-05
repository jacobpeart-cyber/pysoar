"""Audit log model for tracking user actions"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class AuditAction(str, Enum):
    """Types of auditable actions"""

    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGE = "password_change"

    # CRUD operations
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"

    # Alert actions
    ALERT_ACKNOWLEDGE = "alert_acknowledge"
    ALERT_ASSIGN = "alert_assign"
    ALERT_CLOSE = "alert_close"
    ALERT_ESCALATE = "alert_escalate"

    # Incident actions
    INCIDENT_CREATE = "incident_create"
    INCIDENT_UPDATE = "incident_update"
    INCIDENT_CLOSE = "incident_close"
    INCIDENT_ASSIGN = "incident_assign"

    # Playbook actions
    PLAYBOOK_EXECUTE = "playbook_execute"
    PLAYBOOK_CREATE = "playbook_create"
    PLAYBOOK_UPDATE = "playbook_update"

    # System actions
    EXPORT = "export"
    IMPORT = "import"
    CONFIG_CHANGE = "config_change"
    API_ACCESS = "api_access"


class AuditLog(BaseModel):
    """Audit log model for tracking all user actions"""

    __tablename__ = "audit_logs"

    # User who performed the action
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )

    # Action details
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    # Change details
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    new_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Request context
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Status
    success: Mapped[bool] = mapped_column(default=True, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="audit_logs",
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} on {self.resource_type}>"
