"""API Key model for service account authentication"""

import secrets
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class APIKey(BaseModel):
    """API Key for service account authentication"""

    __tablename__ = "api_keys"

    # Key identification
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # The key itself (hashed, only shown once on creation)
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Permissions (JSON array of permission strings)
    permissions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # E.g., ["alerts:read", "alerts:write", "incidents:read", "iocs:read", "iocs:write"]

    # Scope restrictions
    allowed_ips: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    rate_limit: Mapped[int] = mapped_column(default=1000, nullable=False)  # requests per hour

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Expiration
    expires_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Usage tracking
    last_used_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_used_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    usage_count: Mapped[int] = mapped_column(default=0, nullable=False)

    # Ownership
    owner_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    # Relations
    owner: Mapped["User"] = relationship("User")

    def __repr__(self) -> str:
        return f"<APIKey {self.name} ({self.key_prefix}...)>"

    @staticmethod
    def generate_key() -> tuple[str, str, str]:
        """
        Generate a new API key.
        Returns: (full_key, key_prefix, key_to_hash)
        The full_key is shown to the user once, key_prefix for identification,
        and key_to_hash should be hashed and stored.
        """
        # Generate a secure random key
        key = secrets.token_urlsafe(32)
        prefix = key[:8]
        return f"pysoar_{key}", prefix, key

    @property
    def is_expired(self) -> bool:
        """Check if the key has expired"""
        if not self.expires_at:
            return False
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.utcnow() > expires
        except ValueError:
            return False

    def has_permission(self, permission: str) -> bool:
        """Check if the key has a specific permission"""
        import json

        if not self.permissions:
            return False

        try:
            perms = json.loads(self.permissions)
            # Check for wildcard permission
            if "*" in perms or "admin" in perms:
                return True
            # Check for exact match
            if permission in perms:
                return True
            # Check for category wildcard (e.g., "alerts:*")
            category = permission.split(":")[0]
            if f"{category}:*" in perms:
                return True
            return False
        except json.JSONDecodeError:
            return False

    def record_usage(self, ip_address: Optional[str] = None):
        """Record API key usage"""
        self.last_used_at = datetime.utcnow().isoformat()
        self.last_used_ip = ip_address
        self.usage_count += 1


class APIKeyPermission:
    """Available API key permissions"""

    # Alert permissions
    ALERTS_READ = "alerts:read"
    ALERTS_WRITE = "alerts:write"
    ALERTS_DELETE = "alerts:delete"

    # Incident permissions
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_WRITE = "incidents:write"
    INCIDENTS_DELETE = "incidents:delete"

    # IOC permissions
    IOCS_READ = "iocs:read"
    IOCS_WRITE = "iocs:write"
    IOCS_DELETE = "iocs:delete"

    # Asset permissions
    ASSETS_READ = "assets:read"
    ASSETS_WRITE = "assets:write"
    ASSETS_DELETE = "assets:delete"

    # Playbook permissions
    PLAYBOOKS_READ = "playbooks:read"
    PLAYBOOKS_WRITE = "playbooks:write"
    PLAYBOOKS_EXECUTE = "playbooks:execute"

    # User permissions (admin only)
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"

    # Settings permissions (admin only)
    SETTINGS_READ = "settings:read"
    SETTINGS_WRITE = "settings:write"

    # Audit permissions
    AUDIT_READ = "audit:read"

    # Wildcard
    ALL = "*"

    @classmethod
    def all_permissions(cls) -> list[str]:
        """Get all available permissions"""
        return [
            cls.ALERTS_READ, cls.ALERTS_WRITE, cls.ALERTS_DELETE,
            cls.INCIDENTS_READ, cls.INCIDENTS_WRITE, cls.INCIDENTS_DELETE,
            cls.IOCS_READ, cls.IOCS_WRITE, cls.IOCS_DELETE,
            cls.ASSETS_READ, cls.ASSETS_WRITE, cls.ASSETS_DELETE,
            cls.PLAYBOOKS_READ, cls.PLAYBOOKS_WRITE, cls.PLAYBOOKS_EXECUTE,
            cls.USERS_READ, cls.USERS_WRITE,
            cls.SETTINGS_READ, cls.SETTINGS_WRITE,
            cls.AUDIT_READ,
        ]

    @classmethod
    def read_only_permissions(cls) -> list[str]:
        """Get read-only permissions"""
        return [
            cls.ALERTS_READ,
            cls.INCIDENTS_READ,
            cls.IOCS_READ,
            cls.ASSETS_READ,
            cls.PLAYBOOKS_READ,
        ]

    @classmethod
    def analyst_permissions(cls) -> list[str]:
        """Get analyst-level permissions"""
        return [
            cls.ALERTS_READ, cls.ALERTS_WRITE,
            cls.INCIDENTS_READ, cls.INCIDENTS_WRITE,
            cls.IOCS_READ, cls.IOCS_WRITE,
            cls.ASSETS_READ,
            cls.PLAYBOOKS_READ, cls.PLAYBOOKS_EXECUTE,
        ]
