"""Ticket Hub models for unified ticketing across all PySOAR modules."""

from typing import Any, Optional
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

    # Prompt-injection scan of the human/untrusted text on this row
    # (design v2 §11; populated by ingest-time scanning in phase 2).
    injection_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    injection_hits: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)


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

    # Evaluator state (wave 2, migration 024). ``evaluation_status`` is
    # ``active`` while the beat evaluator (src/tickethub/tasks.py) can run the
    # rule, ``unsupported`` when its trigger / conditions / actions cannot be
    # evaluated (``unsupported_reason`` says why; the rule never fires).
    # ``last_evaluated_at`` is the per-rule cursor: each run looks at targets
    # created after it.
    evaluation_status: Mapped[str] = mapped_column(
        String(20), default="active", server_default="active", nullable=False,
    )
    unsupported_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_evaluated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AutomationRuleFiring(BaseModel):
    """One action an automation rule executed against one target.

    Written by the evaluator for every (rule, target, action) it fires, with
    the honest outcome: ``success``, ``failed``, ``awaiting_integration``
    (nothing configured to carry it out) or ``detection_only`` (containment
    with no endpoint agent covering the target).
    """

    __tablename__ = "automation_rule_firings"

    rule_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("automation_rules.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    # The triggering event: the alert / incident id, or the TicketActivity id
    # of a status change. The evaluator never fires a rule twice per event.
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    result: Mapped[str] = mapped_column(String(30), nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detail: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


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
