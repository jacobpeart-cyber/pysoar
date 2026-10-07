"""LLM call log and daily usage rollup tables (design sections 6/7/11).

``llm_call_logs`` gets one row per provider call -- also when the call raised
(``stop_reason='error'``, ``usage_estimated=true``). Prompt/response bodies
are stored only when ``settings.llm_log_bodies`` is on, already redacted, and
raw rows are purged after the organization's ``llm_call_log_retention_days``
(``agentic_policy`` settings, 30..1095 days, default 365) once they have been
rolled up into ``llm_usage_daily`` (``src.agentic.retention``).

Column names match ``alembic/versions/020_agentic_guardrails.py`` (owned by
work package 4) exactly; change both together.
"""
from __future__ import annotations

from datetime import date
from typing import Any, Optional

from sqlalchemy import Boolean, Date, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from src.models.base import BaseModel


class LLMCallLog(BaseModel):
    """One provider call (successful or failed) attributed to an organization and run."""

    __tablename__ = "llm_call_logs"

    run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    actor_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    soc_agent_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("soc_agents.id"), nullable=True)
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)  # chat, triage, investigation, summary...
    mode: Mapped[str] = mapped_column(String(20), nullable=False)  # interactive, autonomous, approval
    role: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    propose_actions: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    session_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    investigation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    credential_source: Mapped[str] = mapped_column(String(20), nullable=False)  # org | platform
    prompt_version: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    system_prompt_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    tools_offered: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)  # [{name, schema_sha256}]
    messages_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Usage (normalized per provider; see base.Usage)
    input_uncached_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    thinking_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_billable_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    usage_estimated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    stop_reason: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    injection_tier: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_sent_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    redactions_applied: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_class: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)

    # Only populated when settings.llm_log_bodies is true (redacted).
    request_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # NULL when settings.llm_prices has no entry for the model (never guessed).
    cost_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("ix_llm_call_logs_run_id", "run_id"),
        Index("ix_llm_call_logs_org_created", "organization_id", "created_at"),
        Index("ix_llm_call_logs_investigation_id", "investigation_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<LLMCallLog org={self.organization_id} run={self.run_id} {self.provider}/{self.model} {self.stop_reason}>"


class LLMUsageDaily(BaseModel):
    """Nightly rollup of ``llm_call_logs`` per (org, day, provider, model, purpose, mode, credential_source, actor)."""

    __tablename__ = "llm_usage_daily"

    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    day: Mapped[date] = mapped_column(Date, nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    credential_source: Mapped[str] = mapped_column(String(20), nullable=False)
    # "user:<id>" | "agent:<id>" | "-" so the bucket key is NOT NULL
    actor_key: Mapped[str] = mapped_column(String(64), nullable=False, default="-")

    calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    input_uncached_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    thinking_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_billable_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Sum of priced rows only; NULL when no row of the group had a price.
    cost_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "day", "provider", "model", "purpose", "mode", "credential_source", "actor_key",
            name="uq_llm_usage_daily_bucket",
        ),
        Index("ix_llm_usage_daily_org_day", "organization_id", "day"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<LLMUsageDaily org={self.organization_id} day={self.day} {self.provider}/{self.model}>"


def actor_key_for(actor_user_id: Optional[str], soc_agent_id: Optional[str]) -> str:
    """The ``llm_usage_daily.actor_key`` value for a call-log row."""
    if actor_user_id:
        return f"user:{actor_user_id}"
    if soc_agent_id:
        return f"agent:{soc_agent_id}"
    return "-"


__all__ = ["LLMCallLog", "LLMUsageDaily", "actor_key_for"]
