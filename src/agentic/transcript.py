"""Per-run agent transcript persisted for autonomous and approval runs.

Design v2 §7 ("Transcript"): a compact record of every step an
``AgentRunner`` took — tool, redacted-args hash, result hash, policy
decision and the audit row ids of the pre/post pair — so an assessor can
reconstruct what the agent did without the LLM bodies. The step list is
encrypted at rest (``EncryptedJSON``) and expires per organization
(``retention_until``, default 90 days) so the nightly retention task can
delete it without inspecting the content.

Only the runtime (WP3) writes rows; this module owns the shape.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from src.core.encryption import EncryptedJSON
from src.models.base import BaseModel, utc_now

__all__ = ["AgentRunTranscript", "DEFAULT_TRANSCRIPT_RETENTION_DAYS", "default_retention_until"]

DEFAULT_TRANSCRIPT_RETENTION_DAYS = 90


def default_retention_until(days: int = DEFAULT_TRANSCRIPT_RETENTION_DAYS) -> datetime:
    """UTC timestamp after which a transcript may be deleted."""
    return utc_now() + timedelta(days=days)


class AgentRunTranscript(BaseModel):
    """Compact, encrypted per-run step record (one row per ``run_id``)."""

    __tablename__ = "agent_run_transcripts"

    run_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Principal: exactly one of the two is set (autonomous runs carry the
    # SOC agent, interactive/approval runs carry the user).
    mode: Mapped[str] = mapped_column(String(20), nullable=False)  # interactive | autonomous | approval
    actor_user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    soc_agent_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("soc_agents.id"), nullable=True
    )
    session_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    investigation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    # Encrypted at rest. A list of step dicts:
    # {step, tool, args_sha256, result_sha256, decision, reason_code,
    #  audit_pre_id, audit_post_id, duration_ms, redactions_applied}
    steps: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(EncryptedJSON, nullable=True)
    step_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Outcome summary (mirrors Investigation.outcome for autonomous runs)
    outcome: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    injection_tier: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    provider: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_class: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    retention_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=default_retention_until, nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_agent_run_transcripts_org_started", "organization_id", "started_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AgentRunTranscript run={self.run_id} steps={self.step_count}>"
