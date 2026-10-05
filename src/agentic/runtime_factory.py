"""Shared construction of the guarded agent runtime (design v2 sections 1, 5, 6).

``src/api/v1/endpoints/agentic.py`` wires the interactive surfaces (chat,
direct tool execute, approve, rollback) in its own ``_build_runtime``. The
Celery investigator cannot import that module -- the endpoint imports
``src.agentic.tasks``, so the dependency only runs one way -- and a task must
not pull FastAPI into a worker. This module therefore owns the same wiring in
a dependency-free form:

    registry (org-bound)  ->  PolicyEngine (role / mode / tier / refs / audit)
        -> AgentRunner (provider turns, trust scan, proposals)

Nothing here is FastAPI-aware and nothing is created at import time: every
Redis client comes from a per-loop factory, so a Celery prefork worker that
calls ``asyncio.run`` once per task never reuses a client across loops.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.context import AgentContext
from src.agentic.policy import OrgPolicySettings, PolicyEngine, audit_rows_fallback_counter
from src.agentic.runtime import AgentRunner, LLMCallRecord
from src.audit_evidence.engine import AuditLogger
from src.core.logging import get_logger
from src.llm import factory as llm_factory
from src.llm.base import LLMProvider, Usage
from src.llm.calllog import LLMCallLogWriter, price_call
from src.llm.models import LLMCallLog
from src.llm.quota import CircuitOpen, TokenQuota
from src.services.agent_tools import AgentToolRegistry

logger = get_logger(__name__)

__all__ = [
    "AgentRuntime",
    "QuotaAdmission",
    "QuotaBreaker",
    "RedisToolRateLimiter",
    "build_policy",
    "build_runtime",
    "call_log_writer",
]


class RedisToolRateLimiter:
    """Per-(org, tool) minute bucket. Any backend failure propagates so the
    policy engine falls back to the audit-row counter and, failing that,
    denies write+ tools (fail closed)."""

    def __init__(self, redis: Any, *, limit_per_minute: int) -> None:
        self._redis = redis
        self._limit = max(int(limit_per_minute), 1)

    async def try_acquire(self, org_id: str, tool: str) -> bool:
        if self._redis is None:
            raise RuntimeError("no redis client available for tool rate limiting")
        minute = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        key = f"agent:toolrate:{org_id}:{tool}:{minute}"
        count = int(await self._redis.incr(key))
        if count == 1:
            await self._redis.expire(key, 120)
        return count <= self._limit


class QuotaAdmission:
    """``Admission`` adapter over ``TokenQuota.admit``."""

    def __init__(self, quota: Any, bucket: str = "autonomous") -> None:
        self._quota = quota
        self._bucket = bucket

    def admit(self, ctx: AgentContext) -> Any:
        actor_key = ctx.soc_agent_id and f"agent:{ctx.soc_agent_id}" or ctx.actor_user_id or "unknown"
        return self._quota.admit(ctx.org_id, actor_key, self._bucket)


class QuotaBreaker:
    """``CircuitBreaker`` adapter over ``TokenQuota``'s provider breaker."""

    def __init__(self, quota: Any) -> None:
        self._quota = quota

    async def is_open(self, provider: str, credential_source: str, org_id: str) -> bool:
        try:
            await self._quota.breaker_check(provider, credential_source, org_id)
        except CircuitOpen:
            return True
        return False

    async def record_failure(self, provider: str, credential_source: str, org_id: str, error_class: str) -> None:
        await self._quota.breaker_record_failure(provider, credential_source, org_id)

    async def record_success(self, provider: str, credential_source: str, org_id: str) -> None:
        await self._quota.breaker_record_success(provider, credential_source, org_id)


def call_log_writer() -> Callable[[LLMCallRecord], Any]:
    """Runtime ``CallLogWriter``: one committed ``llm_call_logs`` row per turn."""
    writer = LLMCallLogWriter()

    async def _write(record: LLMCallRecord) -> None:
        usage = Usage(
            input_uncached=record.input_uncached,
            cache_read=record.cache_read,
            cache_write=record.cache_write,
            output=record.output,
            thinking=record.thinking,
            estimated=record.usage_estimated,
        )
        row = LLMCallLog(
            run_id=record.run_id,
            organization_id=record.organization_id,
            actor_user_id=record.actor_user_id,
            soc_agent_id=record.soc_agent_id,
            purpose=record.purpose,
            mode=record.mode,
            role=record.role,
            propose_actions=record.propose_actions,
            session_id=record.session_id,
            investigation_id=record.investigation_id,
            provider=record.provider,
            model=record.model,
            credential_source=record.credential_source,
            prompt_version=record.prompt_version,
            system_prompt_sha256=record.system_prompt_sha256,
            tools_offered=record.tools_offered,
            messages_sha256=record.messages_sha256,
            input_uncached_tokens=record.input_uncached,
            cache_read_tokens=record.cache_read,
            cache_write_tokens=record.cache_write,
            output_tokens=record.output,
            thinking_tokens=record.thinking,
            total_billable_tokens=record.total_billable,
            usage_estimated=record.usage_estimated,
            latency_ms=record.latency_ms,
            stop_reason=record.stop_reason,
            injection_tier=record.injection_tier,
            request_id=record.request_id,
            data_sent_bytes=record.data_sent_bytes,
            redactions_applied=record.redactions_applied,
            error_class=record.error_class,
            cost_usd=price_call(record.model, usage),
        )
        await writer.write(row)

    return _write


#: ``settings`` may be a ready ``OrgPolicySettings`` or a callable that derives
#: one from the registry's specs (the autonomous allow-list needs the specs to
#: filter out anything that is no longer read-only).
PolicySettingsSource = OrgPolicySettings | Callable[[dict[str, Any]], OrgPolicySettings] | None


def build_policy(
    db: AsyncSession,
    ctx: AgentContext,
    *,
    redis: Any = None,
    settings: PolicySettingsSource = None,
) -> tuple[AgentToolRegistry, PolicyEngine, AuditLogger]:
    """An org-bound registry with its policy engine and audit sink.

    ``redis`` is optional: without it the policy engine counts rate usage from
    audit rows instead, which is slower but never silently unlimited.
    """
    registry = AgentToolRegistry(db, ctx)
    if settings is None:
        policy_settings = OrgPolicySettings()
    elif isinstance(settings, OrgPolicySettings):
        policy_settings = settings
    else:
        policy_settings = settings(registry.specs)
    audit = AuditLogger(db, ctx.org_id)
    policy = PolicyEngine(
        registry,
        audit,
        limiter=(
            RedisToolRateLimiter(redis, limit_per_minute=policy_settings.tool_rate_limit_per_minute)
            if redis is not None
            else None
        ),
        rate_fallback_counter=audit_rows_fallback_counter(db),
        settings=policy_settings,
    )
    registry.bind_policy(policy)
    return registry, policy, audit


@dataclass
class AgentRuntime:
    """The wired collaborators one agent run needs."""

    provider: Optional[LLMProvider]
    registry: AgentToolRegistry
    policy: PolicyEngine
    runner: AgentRunner
    audit: AuditLogger
    quota: Any
    credential_source: str


async def build_runtime(
    db: AsyncSession,
    ctx: AgentContext,
    *,
    redis: Any = None,
    quota: Any = None,
    purpose: str = "investigation",
    settings: PolicySettingsSource = None,
    step_callback: Any = None,
    with_provider: bool = True,
) -> AgentRuntime:
    """Resolve the org's provider and wire registry + policy + runner.

    ``LLMNotConfigured`` from the factory propagates: the caller decides how to
    record it (the investigator persists ``outcome='llm_not_configured'``).
    """
    registry, policy, audit = build_policy(db, ctx, redis=redis, settings=settings)
    quota = quota if quota is not None else TokenQuota(redis_factory=(lambda: redis) if redis is not None else None)

    provider: Optional[LLMProvider] = None
    credential_source = ""
    if with_provider:
        config, api_key = await llm_factory.resolve_llm_config(db, ctx.org_id)
        provider = llm_factory.build_provider(
            config.provider,
            model=config.model,
            api_key=api_key,
            credential_source=config.credential_source,
        )
        credential_source = config.credential_source

    runner = AgentRunner(
        provider=provider,
        registry=registry,
        policy=policy,
        audit=audit,
        session=db,
        admission=QuotaAdmission(quota) if with_provider else None,
        breaker=QuotaBreaker(quota) if with_provider else None,
        call_log_writer=call_log_writer() if with_provider else None,
        step_callback=step_callback,
        purpose=purpose,
    )
    return AgentRuntime(
        provider=provider,
        registry=registry,
        policy=policy,
        runner=runner,
        audit=audit,
        quota=quota,
        credential_source=credential_source,
    )
