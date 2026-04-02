"""Ticket Hub models for unified ticketing across all PySOAR modules."""

from typing import Optional
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel


class TicketComment(BaseModel):
    """Generic threaded comment attachable to any ticket type."""

    __tablename__ = "ticket_comments"

    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    parent_comment_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    mentioned_users: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    is_edited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    edited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)


class TicketActivity(BaseModel):
    """Activity log for any ticket across any module."""

    __tablename__ = "ticket_activities"

    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    activity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    old_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extra_metadata: Mapped[Optional[str]] = mapped_column("metadata", JSON, nullable=True)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)


class AutomationRule(BaseModel):
    """Workflow automation rules for ticket creation and management."""

    __tablename__ = "automation_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    trigger_conditions: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    actions: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)


class TicketLink(BaseModel):
    """Links between tickets across different modules."""

    __tablename__ = "ticket_links"

    source_type_a: Mapped[str] = mapped_column(String(50), nullable=False)
    source_id_a: Mapped[str] = mapped_column(String(36), nullable=False)
    source_type_b: Mapped[str] = mapped_column(String(50), nullable=False)
    source_id_b: Mapped[str] = mapped_column(String(36), nullable=False)
    link_type: Mapped[str] = mapped_column(String(50), nullable=False, default="related")
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
