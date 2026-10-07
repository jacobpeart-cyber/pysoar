"""Per-run agent transcript persisted for autonomous and approval runs.

Design v2 §7 ("Transcript"): a compact record of every step an
``AgentRunner`` took — tool, redacted-args hash, result hash, policy
decision and the audit row ids of the pre/post pair — so an assessor can
reconstruct what the agent did without the LLM bodies. The step list is
encrypted at rest (``EncryptedJSON``) and expires per organization: a
writer stamps ``retention_until`` from the organization's
``agent_transcript_retention_days`` (30..1095, default 365) through
:func:`transcript_retention_until`, and the nightly retention task
(``src.agentic.retention``) deletes rows whose stamp has passed without
inspecting the content. A later change of the setting applies to rows
written after it; existing rows keep the expiry they were stamped with.

Every agent run writes exactly one row through :func:`persist_run_transcript`
(chat turns in ``POST /agentic/chat``, autonomous investigations in
``AutonomousInvestigator``). The writer re-applies ``src.core.redact`` to
every argument, preview and the final answer, caps each preview and the
whole step payload, records what it cut, and never lets a write failure
fail the run (savepoint + structured log + ``agent_transcripts_total``).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Optional, Union

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from src.core.encryption import EncryptedJSON
from src.core.logging import get_logger
from src.core.metrics import AGENT_TRANSCRIPTS_TOTAL
from src.core.metrics import increment as metric_increment
from src.core.redact import REDACTED, redact, redact_text
from src.models.base import BaseModel, utc_now

if TYPE_CHECKING:  # pragma: no cover - typing only (avoids an import cycle)
    from src.agentic.context import AgentContext, Mode
    from src.agentic.runtime import RunResult

__all__ = [
    "DEFAULT_TRANSCRIPT_RETENTION_DAYS",
    "TRANSCRIPT_FINAL_TEXT_MAX_CHARS",
    "TRANSCRIPT_MAX_STEPS",
    "TRANSCRIPT_PREVIEW_MAX_CHARS",
    "TRANSCRIPT_STEPS_MAX_BYTES",
    "AgentRunTranscript",
    "build_transcript_payload",
    "default_retention_until",
    "persist_run_transcript",
    "transcript_retention_until",
]

logger = get_logger(__name__)

#: Most tool steps (and LLM turns / policy events / proposals) kept per transcript.
TRANSCRIPT_MAX_STEPS = 200
#: Ceiling on the serialized ``steps`` payload (before encryption).
TRANSCRIPT_STEPS_MAX_BYTES = 256 * 1024
#: Ceiling on each argument / result / turn preview.
TRANSCRIPT_PREVIEW_MAX_CHARS = 1024
#: Ceiling on the stored final answer.
TRANSCRIPT_FINAL_TEXT_MAX_CHARS = 8000

#: Platform default when the organization has no setting (decision 2026-10-06).
DEFAULT_TRANSCRIPT_RETENTION_DAYS = 365


def default_retention_until(days: int = DEFAULT_TRANSCRIPT_RETENTION_DAYS) -> datetime:
    """UTC timestamp after which a transcript may be deleted (platform default).

    The column default only covers a writer that bypasses
    :func:`transcript_retention_until`; every runtime writer must stamp the
    organization's own value.
    """
    return utc_now() + timedelta(days=days)


async def transcript_retention_until(
    session: AsyncSession, organization_id: str, *, now: Optional[datetime] = None,
) -> datetime:
    """``retention_until`` for a transcript written now by ``organization_id``.

    Reads the organization's ``agentic_policy`` section (organization-scoped);
    an unset or invalid value means the 365-day platform default.
    """
    from src.agentic.policy import load_org_policy_settings

    policy = await load_org_policy_settings(session, organization_id)
    return (now or utc_now()) + timedelta(days=policy.agent_transcript_retention_days)


class AgentRunTranscript(BaseModel):
    """Compact, encrypted per-run step record (one row per ``run_id``)."""

    __tablename__ = "agent_run_transcripts"

    run_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
    )

    # Principal: exactly one of the two is set (autonomous runs carry the
    # SOC agent, interactive/approval runs carry the user).
    mode: Mapped[str] = mapped_column(String(20), nullable=False)  # interactive | autonomous | approval
    actor_user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True,
    )
    soc_agent_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("soc_agents.id"), nullable=True,
    )
    session_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    investigation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    # Encrypted at rest. A list of step dicts:
    # {step, tool, args_sha256, result_sha256, decision, reason_code,
    #  audit_pre_id, audit_post_id, duration_ms, redactions_applied}
    steps: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(EncryptedJSON, nullable=True)
    step_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Encrypted at rest (revision 022). Run-level summary: prompt version,
    # stop reason, usage totals, trust summary, proposal ids/hashes, policy
    # events, LLM turn records, the redacted+capped final answer and a
    # ``truncation`` record of everything the writer cut.
    summary: Mapped[Optional[dict[str, Any]]] = mapped_column(EncryptedJSON, nullable=True)

    # Outcome summary (mirrors Investigation.outcome for autonomous runs)
    outcome: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    injection_tier: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    provider: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_class: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False,
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    retention_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=default_retention_until, nullable=False, index=True,
    )

    __table_args__ = (
        Index("ix_agent_run_transcripts_org_started", "organization_id", "started_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AgentRunTranscript run={self.run_id} steps={self.step_count}>"


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

# ``"api_key": "value"`` / ``password=value`` inside free text (a truncated
# JSON preview no longer parses, so key redaction cannot reach it).
_INLINE_SECRET_RE = re.compile(
    r"(?i)(\"?[a-z0-9_\-]*(?:api[_-]?key|token|secret|passw(?:or)?d|private[_-]?key|authorization|cookie|credential)s?\"?"
    r"\s*[:=]\s*)(\"(?:[^\"\\]|\\.)*\"?|'[^']*'?|[^\s,;}\]]+)",
)
_NUMERIC_RE = re.compile(r"^\d+(?:\.\d+)?$")


def _redact_inline(text: str) -> tuple[str, int]:
    count = 0

    def _sub(match: re.Match[str]) -> str:
        nonlocal count
        value = match.group(2)
        if _NUMERIC_RE.match(value) or value in ("true", "false", "null") or REDACTED in value:
            return match.group(0)  # counters (max_tokens=4096) and already-redacted values stay
        count += 1
        return f'{match.group(1)}"{REDACTED}"'

    return _INLINE_SECRET_RE.sub(_sub, text), count


def _preview(value: Any, cap: int = TRANSCRIPT_PREVIEW_MAX_CHARS) -> tuple[Optional[str], int, bool]:
    """Redacted, capped text form of ``value``: ``(text, redactions, truncated)``."""
    if value is None:
        return None, 0, False
    count = 0
    if isinstance(value, str):
        try:
            parsed: Any = json.loads(value)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            parsed, n = redact(parsed)
            count += n
            text = json.dumps(parsed, default=str, sort_keys=True)
        else:
            text = value
    else:
        redacted, n = redact(value)
        count += n
        text = json.dumps(redacted, default=str, sort_keys=True)
    text, n = redact_text(text)
    count += n
    text, n = _redact_inline(text)
    count += n
    truncated = len(text) > cap
    if truncated:
        text = text[:cap]
    return text, count, truncated


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, default=str, sort_keys=True).encode("utf-8")).hexdigest()


def _mode_value(mode: Union[str, "Mode"]) -> str:
    return str(getattr(mode, "value", mode))


def _enum_text(value: Any) -> Optional[str]:
    return None if value is None else str(getattr(value, "value", value))


def _clip(value: Optional[str], limit: int) -> Optional[str]:
    return str(value)[:limit] if value else None


def build_transcript_payload(result: "RunResult") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Redacted, capped ``(steps, summary)`` for one run result.

    Pure: no I/O. ``steps`` holds one dict per tool call, in order, up to
    :data:`TRANSCRIPT_MAX_STEPS` entries and :data:`TRANSCRIPT_STEPS_MAX_BYTES`
    serialized bytes; whatever is cut is counted in ``summary["truncation"]``.
    """
    previews_truncated = 0
    redactions = 0
    steps: list[dict[str, Any]] = []
    used_bytes = 2  # "[]"
    dropped_for_count = max(0, len(result.tool_log) - TRANSCRIPT_MAX_STEPS)
    dropped_for_size = 0

    for entry in result.tool_log[:TRANSCRIPT_MAX_STEPS]:
        redacted_args, n_args = redact(entry.args or {})
        args_text, n_prev, args_cut = _preview(redacted_args)
        result_text, n_res, result_cut = _preview(entry.result_preview)
        redactions += n_args + n_prev + n_res
        previews_truncated += int(args_cut) + int(result_cut)
        step: dict[str, Any] = {
            "step": entry.step,
            "tool": entry.tool,
            "tool_use_id": entry.tool_use_id,
            "tier": entry.tier,
            "decision": entry.decision,
            "reason_code": entry.reason_code,
            "allowed": entry.allowed,
            "success": entry.success,
            "is_error": entry.is_error,
            "duration_ms": entry.duration_ms,
            "args_sha256": _sha256_json(redacted_args),
            "args_preview": args_text,
            "result_sha256": entry.result_sha256,
            "result_preview": result_text,
            "audit_pre_id": entry.audit_pre_id,
            "audit_post_id": entry.audit_post_id,
            "proposal_id": entry.proposal_id,
            "error_class": entry.error_class,
            "redactions_applied": entry.redactions_applied,
        }
        size = len(json.dumps(step, default=str)) + 1
        if used_bytes + size > TRANSCRIPT_STEPS_MAX_BYTES:
            dropped_for_size += 1
            continue
        used_bytes += size
        steps.append(step)

    turns: list[dict[str, Any]] = []
    for record in result.steps[:TRANSCRIPT_MAX_STEPS]:
        text, n, cut = _preview(record.text_preview or "")
        redactions += n
        previews_truncated += int(cut)
        turns.append({
            "step": record.step,
            "stop_reason": record.stop_reason,
            "tool_calls": list(record.tool_calls)[:50],
            "usage_total": record.usage_total,
            "text_preview": text,
        })

    policy_events = [
        {
            "step": event.step,
            "tool": event.tool,
            "decision": _enum_text(event.decision),
            "reason_code": _enum_text(event.reason_code),
            "tier": _enum_text(event.tier),
            "audit_id": event.audit_id,
            "proposal_id": event.proposal_id,
        }
        for event in result.policy_events[:TRANSCRIPT_MAX_STEPS]
    ]

    proposals = [
        {
            "id": proposal.id,
            "tool": proposal.tool,
            "step": proposal.step,
            "params_sha256": proposal.params_sha256,
            "evidence_sha256": proposal.evidence_sha256,
            "suspect": proposal.suspect,
            "persisted": proposal.persisted,
        }
        for proposal in result.proposals[:TRANSCRIPT_MAX_STEPS]
    ]

    final_text, n_final = redact_text(result.final_text or "")
    final_text, n_inline = _redact_inline(final_text)
    redactions += n_final + n_inline
    final_cut = len(final_text) > TRANSCRIPT_FINAL_TEXT_MAX_CHARS
    if final_cut:
        final_text = final_text[:TRANSCRIPT_FINAL_TEXT_MAX_CHARS]

    lists_cut = any(
        len(items) > TRANSCRIPT_MAX_STEPS
        for items in (result.steps, result.policy_events, result.proposals)
    )
    trust = result.trust
    usage = result.usage
    truncation = {
        "truncated": bool(dropped_for_count or dropped_for_size or previews_truncated or final_cut or lists_cut),
        "tool_steps_total": len(result.tool_log),
        "tool_steps_kept": len(steps),
        "tool_steps_dropped_over_count": dropped_for_count,
        "tool_steps_dropped_over_size": dropped_for_size,
        "turns_total": len(result.steps),
        "policy_events_total": len(result.policy_events),
        "proposals_total": len(result.proposals),
        "previews_truncated": previews_truncated,
        "final_text_truncated": final_cut,
        "max_steps": TRANSCRIPT_MAX_STEPS,
        "max_steps_bytes": TRANSCRIPT_STEPS_MAX_BYTES,
        "preview_max_chars": TRANSCRIPT_PREVIEW_MAX_CHARS,
    }
    summary: dict[str, Any] = {
        "stop_reason": result.stop_reason,
        "stop_detail": _clip(redact_text(result.stop_detail)[0], 500) if result.stop_detail else None,
        "error_code": result.error_code,
        "request_id": result.request_id,
        "credential_source": result.credential_source,
        "honesty_note_applied": bool(result.honesty_note_applied),
        "verdict_submitted": result.verdict is not None,
        "usage": {
            "input_uncached": usage.input_uncached,
            "cache_read": usage.cache_read,
            "cache_write": usage.cache_write,
            "output": usage.output,
            "thinking": usage.thinking,
            "total_billable": usage.total_billable,
            "estimated": bool(usage.estimated),
        },
        "trust": {
            "tier": trust.tier.value,
            "score": trust.score,
            "hit_count": len(trust.hits),
            "families": sorted({hit.family for hit in trust.hits}),
            "contaminated_label_count": len(trust.contaminated_labels),
        },
        "proposals": proposals,
        "policy_events": policy_events,
        "turns": turns,
        "final_text": final_text,
        "redactions_applied": redactions,
        "truncation": truncation,
    }
    return steps, summary


async def persist_run_transcript(
    session: AsyncSession,
    ctx: "AgentContext",
    result: "RunResult",
    *,
    mode: Union[str, "Mode"],
    now: Optional[datetime] = None,
    started_at: Optional[datetime] = None,
    outcome: Optional[str] = None,
) -> Optional[AgentRunTranscript]:
    """Add one :class:`AgentRunTranscript` for ``result`` and flush it in a savepoint.

    The caller commits with its own unit of work. Never raises: any failure
    (retention lookup, serialization, encryption, a constraint on flush) is
    rolled back to the savepoint, logged as ``agent_transcript_persist_failed``
    and counted in ``agent_transcripts_total{outcome="failed"}``; the run's
    result is unaffected and ``None`` is returned.
    """
    from src.agentic.prompts import PROMPT_VERSION

    mode_text = _mode_value(mode)
    try:
        finished = now or utc_now()
        steps, summary = build_transcript_payload(result)
        summary["prompt_version"] = PROMPT_VERSION
        retention = await transcript_retention_until(session, ctx.org_id, now=finished)
        row = AgentRunTranscript(
            run_id=result.run_id,
            organization_id=ctx.org_id,
            mode=mode_text,
            actor_user_id=ctx.actor_user_id,
            soc_agent_id=ctx.soc_agent_id,
            session_id=ctx.session_id,
            investigation_id=ctx.investigation_id,
            steps=steps,
            step_count=len(result.tool_log),
            summary=summary,
            outcome=_clip(outcome or result.stop_reason, 40),
            injection_tier=result.trust.tier.value,
            provider=_clip(result.provider, 40),
            model=_clip(result.model, 120),
            tokens_used=result.usage.total_billable,
            error_class=_clip(result.error_code, 120),
            started_at=started_at or finished,
            finished_at=finished,
            retention_until=retention,
        )
        async with session.begin_nested():
            session.add(row)
            await session.flush()
    except Exception as exc:  # the evidence write must never fail the run
        logger.error(
            "agent_transcript_persist_failed",
            run_id=getattr(result, "run_id", None),
            organization_id=ctx.org_id,
            mode=mode_text,
            error_class=exc.__class__.__name__,
            error=redact_text(str(exc))[0][:300],
        )
        metric_increment(AGENT_TRANSCRIPTS_TOTAL, mode=mode_text, outcome="failed")
        return None

    metric_increment(AGENT_TRANSCRIPTS_TOTAL, mode=mode_text, outcome="written")
    logger.info(
        "agent_transcript_persisted",
        run_id=result.run_id,
        organization_id=ctx.org_id,
        mode=mode_text,
        step_count=row.step_count,
        truncated=summary["truncation"]["truncated"],
    )
    return row
