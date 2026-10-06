"""LLM call log writer, daily rollup and retention purge (design sections 6/7).

``LLMCallLogWriter.record`` wraps exactly one ``provider.complete`` call:

    async with writer.record(ctx, provider, system=..., messages=..., tools=...) as rec:
        rec.turn = await provider.complete(...)

A row is written in **every** exit path:

* success: measured usage, ``stop_reason`` from the turn;
* provider exception: ``stop_reason='error'``, ``usage_estimated=true`` with
  the provider's input-token *estimate* and ``error_class`` (the redacted,
  capped message goes to the structured log), then the exception is re-raised;
* the block exits without setting ``rec.turn``: written as an error row with
  ``error_class='turn_not_recorded'`` so a runtime bug is visible.

Each row is committed in its own short session (``session_factory``) so a
rollback of the run's transaction never loses call evidence. Bodies are
redacted with :func:`src.core.redact.redact` and only persisted when
``settings.llm_log_bodies`` is true.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, AsyncIterator, Callable, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import Settings, settings as app_settings
from src.core.logging import get_logger
from src.core.metrics import LLM_CALLS_TOTAL, increment as metric_increment
from src.core.redact import redact
from src.llm._common import encode_json
from src.llm.base import LLMError, LLMTurn, Message, ToolSpecForLLM, Usage
from src.llm.models import LLMCallLog, LLMUsageDaily, actor_key_for

logger = get_logger(__name__)

ERROR_MESSAGE_CAP = 1000
ERROR_CLASS_CAP = 120


class CallLogWriteError(RuntimeError):
    """The call-log row could not be persisted (fail-closed evidence path)."""


@dataclass
class CallLogContext:
    """Attribution for one call; mirrors the AgentContext fields the log stores."""

    org_id: str
    run_id: str
    purpose: str
    mode: str
    actor_user_id: Optional[str] = None
    soc_agent_id: Optional[str] = None
    role: Optional[str] = None
    propose_actions: bool = False
    session_id: Optional[str] = None
    investigation_id: Optional[str] = None
    prompt_version: Optional[str] = None
    injection_tier: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.org_id:
            raise ValueError("CallLogContext.org_id is required")
        if not self.run_id:
            raise ValueError("CallLogContext.run_id is required")


@dataclass
class CallRecord:
    """Mutable handle yielded by :meth:`LLMCallLogWriter.record`."""

    turn: Optional[LLMTurn] = None
    row: Optional[LLMCallLog] = None


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _message_to_json(message: Message) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    for block in message.content:
        blocks.append({k: v for k, v in vars(block).items()})
    out: dict[str, Any] = {"role": message.role, "content": blocks}
    if message.provider_native is not None:
        out["provider_native"] = message.provider_native
    return out


def tools_offered(tools: list[ToolSpecForLLM] | None) -> list[dict[str, Any]]:
    return [{"name": t.name, "schema_sha256": sha256_hex(encode_json(t.input_schema))} for t in tools or ()]


def price_call(model: str, usage: Usage, cfg: Optional[Settings] = None) -> Optional[float]:
    """USD cost from ``settings.llm_prices`` (per 1M tokens); ``None`` when the model is unpriced."""
    cfg = cfg or app_settings
    table = cfg.llm_prices.get(model) if isinstance(cfg.llm_prices, dict) else None
    if not isinstance(table, dict):
        return None
    try:
        input_price = float(table["input"])
        output_price = float(table["output"])
    except (KeyError, TypeError, ValueError):
        return None
    cache_read_price = float(table.get("cache_read", input_price))
    cache_write_price = float(table.get("cache_write", input_price))
    thinking_price = float(table.get("thinking", output_price))
    cost = (
        usage.input_uncached * input_price
        + usage.cache_read * cache_read_price
        + usage.cache_write * cache_write_price
        + usage.output * output_price
        + usage.thinking * thinking_price
    ) / 1_000_000
    return round(cost, 6)


class LLMCallLogWriter:
    def __init__(
        self,
        session_factory: Optional[Callable[[], AsyncSession]] = None,
        *,
        cfg: Optional[Settings] = None,
        clock: Optional[Callable[[], float]] = None,
        fail_closed: bool = True,
    ) -> None:
        self.cfg = cfg or app_settings
        self._session_factory = session_factory
        self._clock = clock or time.monotonic
        self.fail_closed = fail_closed

    def _sessions(self) -> Callable[[], AsyncSession]:
        if self._session_factory is not None:
            return self._session_factory
        from src.core.database import async_session_factory

        return async_session_factory

    # -- row construction ---------------------------------------------------

    def build_row(
        self,
        ctx: CallLogContext,
        provider: Any,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpecForLLM] | None,
        latency_ms: int,
        turn: Optional[LLMTurn],
        error: Optional[BaseException],
    ) -> LLMCallLog:
        redacted_messages, redactions = redact([_message_to_json(m) for m in messages])
        redacted_system, n = redact(system)
        redactions += n
        messages_digest = sha256_hex(encode_json(redacted_messages))

        if turn is not None:
            usage = turn.usage
            stop_reason = turn.stop_reason
            request_id = turn.request_id
            model = turn.model or getattr(provider, "model", "")
            error_class: Optional[str] = None
        else:
            estimate = provider.estimate_input_tokens(system, messages, tools)
            usage = Usage(input_uncached=int(estimate), estimated=True)
            stop_reason = "error"
            request_id = getattr(error, "request_id", None) or getattr(provider, "last_request_id", None)
            model = getattr(provider, "model", "")
            if error is None:
                error_class = "turn_not_recorded"
            else:
                code = getattr(error, "code", None) if isinstance(error, LLMError) else None
                error_class = str(code or error.__class__.__name__)[:ERROR_CLASS_CAP]
                redacted_error, _ = redact(str(error))
                logger.warning(
                    "llm_call_failed",
                    organization_id=ctx.org_id,
                    run_id=ctx.run_id,
                    provider=getattr(provider, "name", "unknown"),
                    error_class=error_class,
                    error=str(redacted_error)[:ERROR_MESSAGE_CAP],
                )

        request_body: Optional[str] = None
        response_body: Optional[str] = None
        if self.cfg.llm_log_bodies:
            request_body = json.dumps(
                {"system": redacted_system, "messages": redacted_messages}, ensure_ascii=False, separators=(",", ":")
            )
            if turn is not None:
                redacted_turn, n = redact(
                    {"text": turn.text, "tool_calls": [vars(c) for c in turn.tool_calls], "provider_native": turn.provider_native}
                )
                redactions += n
                response_body = json.dumps(redacted_turn, ensure_ascii=False, separators=(",", ":"))

        return LLMCallLog(
            organization_id=ctx.org_id,
            run_id=ctx.run_id,
            actor_user_id=ctx.actor_user_id,
            soc_agent_id=ctx.soc_agent_id,
            purpose=ctx.purpose,
            mode=ctx.mode,
            role=ctx.role,
            propose_actions=bool(ctx.propose_actions),
            session_id=ctx.session_id,
            investigation_id=ctx.investigation_id,
            provider=getattr(provider, "name", "unknown"),
            model=model,
            credential_source=getattr(provider, "credential_source", "platform"),
            prompt_version=ctx.prompt_version,
            system_prompt_sha256=sha256_hex(system),
            tools_offered=tools_offered(tools),
            messages_sha256=messages_digest,
            input_uncached_tokens=usage.input_uncached,
            cache_read_tokens=usage.cache_read,
            cache_write_tokens=usage.cache_write,
            output_tokens=usage.output,
            thinking_tokens=usage.thinking,
            total_billable_tokens=usage.total_billable,
            usage_estimated=bool(usage.estimated),
            cost_usd=None if usage.estimated else price_call(model, usage, self.cfg),
            latency_ms=int(latency_ms),
            stop_reason=stop_reason,
            injection_tier=ctx.injection_tier,
            request_id=request_id,
            error_class=error_class,
            data_sent_bytes=getattr(provider, "last_request_bytes", None),
            redactions_applied=redactions,
            request_body=request_body,
            response_body=response_body,
        )

    async def write(self, row: LLMCallLog) -> LLMCallLog:
        """Persist ``row`` in its own committed session."""
        try:
            async with self._sessions()() as session:
                session.add(row)
                await session.commit()
        except Exception as exc:  # noqa: BLE001 - re-typed for the caller
            logger.error(
                "llm_call_log_write_failed",
                organization_id=row.organization_id,
                run_id=row.run_id,
                provider=row.provider,
                error=str(exc),
            )
            raise CallLogWriteError(str(exc)) from exc
        # One counter tick per persisted provider call (errors carry
        # ``stop_reason='error'``); see src/core/metrics.py.
        metric_increment(LLM_CALLS_TOTAL, provider=row.provider, stop_reason=row.stop_reason)
        return row

    @contextlib.asynccontextmanager
    async def record(
        self,
        ctx: CallLogContext,
        provider: Any,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpecForLLM] | None,
    ) -> AsyncIterator[CallRecord]:
        record = CallRecord()
        started = self._clock()
        error: Optional[BaseException] = None
        try:
            yield record
        except BaseException as exc:
            error = exc
            raise
        finally:
            latency_ms = int((self._clock() - started) * 1000)
            row = self.build_row(
                ctx,
                provider,
                system=system,
                messages=messages,
                tools=tools,
                latency_ms=latency_ms,
                turn=record.turn if error is None else None,
                error=error,
            )
            try:
                record.row = await self.write(row)
            except CallLogWriteError:
                # A provider error is already propagating: keep it as the
                # primary failure, the write failure is logged above.
                if error is None and self.fail_closed:
                    raise


# -- rollup + retention -----------------------------------------------------


async def rollup_usage_daily(db: AsyncSession, day: date, *, organization_id: Optional[str] = None) -> int:
    """Aggregate ``llm_call_logs`` for ``day`` (UTC) into ``llm_usage_daily``.

    Idempotent: existing groups are overwritten. ``organization_id`` limits
    the rollup to one tenant; the nightly maintenance task passes ``None``
    to roll up every tenant (a platform job, not a caller-scoped query).
    Returns the number of groups written. Caller commits.
    """
    start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    stmt = select(LLMCallLog).where(LLMCallLog.created_at >= start, LLMCallLog.created_at < end)
    if organization_id is not None:
        stmt = stmt.where(LLMCallLog.organization_id == organization_id)
    rows = (await db.execute(stmt)).scalars().all()

    groups: dict[tuple[str, str, str, str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.organization_id,
            row.provider,
            row.model,
            row.purpose,
            row.mode,
            row.credential_source,
            actor_key_for(row.actor_user_id, row.soc_agent_id),
        )
        agg = groups.setdefault(
            key,
            {
                "calls": 0,
                "errors": 0,
                "input_uncached_tokens": 0,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "output_tokens": 0,
                "thinking_tokens": 0,
                "total_billable_tokens": 0,
                "cost_usd": None,
            },
        )
        agg["calls"] += 1
        agg["errors"] += 1 if row.stop_reason == "error" else 0
        for col in (
            "input_uncached_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "output_tokens",
            "thinking_tokens",
            "total_billable_tokens",
        ):
            agg[col] += int(getattr(row, col) or 0)
        if row.cost_usd is not None:
            agg["cost_usd"] = round((agg["cost_usd"] or 0.0) + float(row.cost_usd), 6)

    written = 0
    for key, agg in groups.items():
        org, provider, model, purpose, mode, credential_source, actor_key = key
        existing = (
            await db.execute(
                select(LLMUsageDaily).where(
                    LLMUsageDaily.organization_id == org,
                    LLMUsageDaily.day == day,
                    LLMUsageDaily.provider == provider,
                    LLMUsageDaily.model == model,
                    LLMUsageDaily.purpose == purpose,
                    LLMUsageDaily.mode == mode,
                    LLMUsageDaily.credential_source == credential_source,
                    LLMUsageDaily.actor_key == actor_key,
                )
            )
        ).scalar_one_or_none()
        target = existing or LLMUsageDaily(
            organization_id=org,
            day=day,
            provider=provider,
            model=model,
            purpose=purpose,
            mode=mode,
            credential_source=credential_source,
            actor_key=actor_key,
        )
        for col, value in agg.items():
            setattr(target, col, value)
        if existing is None:
            db.add(target)
        written += 1
    await db.flush()
    return written


async def purge_call_logs(
    db: AsyncSession,
    *,
    retention_days: Optional[int] = None,
    now: Optional[datetime] = None,
    organization_id: Optional[str] = None,
) -> int:
    """Delete raw ``llm_call_logs`` older than the retention window. Caller commits."""
    days = int(retention_days if retention_days is not None else app_settings.llm_log_retention_days)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    stmt = delete(LLMCallLog).where(LLMCallLog.created_at < cutoff)
    if organization_id is not None:
        stmt = stmt.where(LLMCallLog.organization_id == organization_id)
    result = await db.execute(stmt)
    return int(result.rowcount or 0)


__all__ = [
    "CallLogContext",
    "CallLogWriteError",
    "CallRecord",
    "LLMCallLogWriter",
    "price_call",
    "purge_call_logs",
    "rollup_usage_daily",
    "sha256_hex",
    "tools_offered",
]
