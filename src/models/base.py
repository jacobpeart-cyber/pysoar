"""Base model with common fields and utilities"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def generate_uuid() -> str:
    """Generate a UUID string"""
    return str(uuid4())


def utc_now() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base class for all database models"""

    pass


class TimestampMixin:
    """Mixin for created_at and updated_at timestamps"""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
        nullable=False,
    )


class UUIDMixin:
    """Mixin for UUID primary key"""

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
        nullable=False,
    )


class BaseModel(Base, UUIDMixin, TimestampMixin):
    """Abstract base model with UUID and timestamps"""

    __abstract__ = True

    def to_dict(self) -> dict[str, Any]:
        """Convert model to dictionary"""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
