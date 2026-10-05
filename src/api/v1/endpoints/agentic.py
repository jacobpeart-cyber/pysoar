"""API endpoints for the Agentic AI SOC analyst.

Every agent surface in this module (chat, direct tool execute, approve,
rollback) goes through the same guarded runtime (design v2 sections 1, 7-9):

    AgentContext (from the JWT)  ->  AgentToolRegistry (org-bound)
         -> PolicyEngine (role / mode / tier / refs / rate / audit)
             -> AgentRunner (provider turns, trust scan, proposals)

There is no Gemini loop, no heuristic fallback and no canned reply left in
here: when the LLM is not configured, out of budget or failing, the caller
gets a typed 4xx/5xx and the user's message is persisted as ``failed`` so
the UI can retry it.
"""

import hashlib
import json
import math
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Body, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.agentic.context import ROLE_RANK, AgentContext, Mode, UserRole
from src.agentic.decisions import TrustState, TrustTier
from src.agentic.engine import AgenticSOCEngine, NaturalLanguageInterface
from src.agentic.models import (
    ActionExecutionStatus,
    AgentAction,
    AgentChatMessage,
    AgentChatSession,
    AgentMemory,
    Investigation,
    InvestigationFeedback as InvestigationFeedbackRow,
    InvestigationStatus,
    SOCAgent,
)
from src.agentic.policy import (
    AUDIT_EVENT_POLICY,
    OrgPolicySettings,
    PolicyEngine,
    audit_rows_fallback_counter,
    canonical_json,
)
from src.agentic.runtime import (
    AdmissionDenied,
    AgentRunner,
    LLMCallRecord,
    RunRejected,
    RunResult,
    _RunState,
)
from src.agentic.tasks import run_investigation
from src.agentic.toolspec import Tier
from src.agentic.trust import TrustScanner, trust_state_from_dict
from src.api.deps import CurrentUser, DatabaseSession, RedisClient
from src.audit_evidence.engine import AuditLogger
from src.core.utils import safe_json_loads
from src.llm.base import (
    LLMNotConfigured,
    LLMQuotaExceeded,
    Message,
    TextBlock,
    Usage,
)
from src.llm.calllog import LLMCallLogWriter, price_call
from src.llm import factory as llm_factory
from src.llm.models import LLMCallLog
from src.llm.quota import CircuitOpen, QuotaBackendUnavailable, TokenQuota
from src.schemas.agentic import (
    AccuracyStats,
    ActionPendingApproval,
    AgentActionApproval,
    AgentMemoryListResponse,
    AgentMemoryResponse,
    AgentProposal,
    AlertExplanation,
    ChatMessageListResponse,
    ChatMessageResponse,
    ChatSessionCreate,
    ChatSessionListResponse,
    ChatSessionResponse,
    DashboardMetrics,
    InvestigationCorrection,
    InvestigationCreate,
    InvestigationExplanation,
    InvestigationFeedback,
    InvestigationListResponse,
    InvestigationMetrics,
    InvestigationResponse,
    InvestigationUpdate,
    MemoryStats,
    NaturalLanguageQuery,
    NaturalLanguageResponse,
    SOCAgentCreate,
    SOCAgentListResponse,
    SOCAgentPerformance,
    SOCAgentResponse,
    SOCAgentUpdate,
    ThreatHuntRequest,
    ThreatHuntResult,
)
from src.services.agent_tools import AgentToolRegistry, render_json_schema

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/agentic", tags=["Agentic"])

#: Turns of prior conversation replayed into a chat run (runtime elides further).
CHAT_HISTORY_TURNS = 12
#: Persisted assistant/user message payload cap.
MESSAGE_RESULT_CAP = 8_000


# ============================================================================
# Agent context + runtime wiring (design v2 sections 1 and 9)
# ============================================================================


def _org_id(current_user: Any) -> str:
    """The caller's organization; every agent query is scoped to it."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "no_organization",
                "detail": "the account is not attached to an organization; agent tools are org-scoped",
            },
        )
    return str(org_id)


def _agent_role(current_user: Any) -> UserRole:
    """Map the JWT user's role onto the agent role ladder (superuser -> admin)."""
    if bool(getattr(current_user, "is_superuser", False)):
        return UserRole.ADMIN
    raw = str(getattr(current_user, "role", "") or "").lower()
    if raw == UserRole.ADMIN.value:
        return UserRole.ADMIN
    if raw == UserRole.ANALYST.value:
        return UserRole.ANALYST
    return UserRole.VIEWER


def _client_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    client = getattr(request, "client", None)
    return getattr(client, "host", None)


def _agent_context(
    current_user: Any,
    mode: Mode,
    *,
    propose_actions: bool = False,
    session_id: Optional[str] = None,
    investigation_id: Optional[str] = None,
    request: Optional[Request] = None,
    origin_trust_tier: Optional[TrustTier] = None,
    approving_action_id: Optional[str] = None,
) -> AgentContext:
    """Build the run context from the JWT user. 403 when the user has no org."""
    return AgentContext(
        org_id=_org_id(current_user),
        role=_agent_role(current_user),
        mode=mode,
        actor_user_id=str(getattr(current_user, "id", "") or ""),
        propose_actions=propose_actions,
        session_id=session_id,
        investigation_id=investigation_id,
        origin_trust_tier=origin_trust_tier,
        approving_action_id=approving_action_id,
        is_superuser=bool(getattr(current_user, "is_superuser", False)),
        actor_ip=_client_ip(request),
    )


def _require_analyst(ctx: AgentContext) -> None:
    if ROLE_RANK[ctx.role] < ROLE_RANK[UserRole.ANALYST]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "role_not_permitted", "detail": "this operation requires the analyst role"},
        )


class _RedisToolRateLimiter:
    """Per-(org, tool) token bucket on the request's Redis client.

    Implements ``ToolRateLimiter`` (src/agentic/policy.py). Any backend
    failure propagates so the policy engine falls back to the audit-row
    counter and, failing that, denies write+ tools (fail closed).
    """

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


def _agent_quota(redis: Any) -> TokenQuota:
    """The LLM budget/admission/breaker backend for one request.

    Factory indirection so tests can substitute a permissive implementation
    without reaching into Redis; production always gets the real quota.
    """
    return TokenQuota(redis_factory=lambda: redis)


class _QuotaAdmission:
    """``Admission`` adapter: TokenQuota.admit(org, actor_key, bucket)."""

    def __init__(self, quota: Any, bucket: str = "interactive") -> None:
        self._quota = quota
        self._bucket = bucket

    def admit(self, ctx: AgentContext) -> Any:
        actor_key = ctx.actor_user_id or ctx.soc_agent_id or "unknown"
        return self._quota.admit(ctx.org_id, actor_key, self._bucket)


class _QuotaBreaker:
    """``CircuitBreaker`` adapter over TokenQuota's provider breaker."""

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


def _call_log_writer() -> Any:
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


class _AgentRuntime:
    """The wired collaborators one agent request needs."""

    def __init__(
        self,
        *,
        provider: Any,
        registry: AgentToolRegistry,
        policy: PolicyEngine,
        runner: AgentRunner,
        audit: AuditLogger,
        quota: Any,
        credential_source: str,
    ) -> None:
        self.provider = provider
        self.registry = registry
        self.policy = policy
        self.runner = runner
        self.audit = audit
        self.quota = quota
        self.credential_source = credential_source


async def _build_runtime(
    db: AsyncSession,
    ctx: AgentContext,
    redis: Any,
    *,
    purpose: str = "chat",
    with_provider: bool = True,
) -> _AgentRuntime:
    """Resolve the org's provider and wire registry + policy + runner.

    ``with_provider=False`` skips provider construction for the surfaces that
    never call an LLM (direct tool execute, approve, rollback) so a tenant
    without AI settings can still run tools.
    """
    registry = AgentToolRegistry(db, ctx)
    audit = AuditLogger(db, ctx.org_id)
    settings = OrgPolicySettings()
    policy = PolicyEngine(
        registry,
        audit,
        limiter=_RedisToolRateLimiter(redis, limit_per_minute=settings.tool_rate_limit_per_minute),
        rate_fallback_counter=audit_rows_fallback_counter(db),
        settings=settings,
    )
    registry.bind_policy(policy)

    quota = _agent_quota(redis)
    provider = None
    credential_source = ""
    if with_provider:
        # Called through the module so the provider factory stays patchable
        # (and so the org's settings remain the authoritative source).
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
        admission=_QuotaAdmission(quota) if with_provider else None,
        breaker=_QuotaBreaker(quota) if with_provider else None,
        call_log_writer=_call_log_writer() if with_provider else None,
        purpose=purpose,
    )
    return _AgentRuntime(
        provider=provider, registry=registry, policy=policy, runner=runner,
        audit=audit, quota=quota, credential_source=credential_source,
    )


def _not_configured_error(exc: LLMNotConfigured) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "llm_not_configured",
            "detail": str(exc),
            "source": getattr(exc, "source", None),
            "reason": getattr(exc, "reason", None),
        },
    )


def _quota_error(exc: LLMQuotaExceeded) -> HTTPException:
    retry_after = getattr(exc, "retry_after", None)
    headers = {"Retry-After": str(int(retry_after))} if retry_after else None
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "error": "quota_backend_unavailable" if isinstance(exc, QuotaBackendUnavailable) else "llm_quota_exceeded",
            "detail": str(exc),
            "bucket": getattr(exc, "bucket", None),
        },
        headers=headers,
    )


def _run_result_error(result: RunResult) -> HTTPException:
    """A run that ended in ``stop_reason=error`` is reported, never papered over."""
    if result.error_code == CircuitOpen.code:
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "llm_unavailable",
                "detail": "the provider circuit breaker is open for this organization; no call was attempted",
                "run_id": result.run_id,
            },
        )
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "llm_provider_error",
            "detail": result.stop_detail or result.error_code or "the provider call failed",
            "error_code": result.error_code,
            "request_id": result.request_id,
            "run_id": result.run_id,
        },
    )


def _rejected_error(exc: RunRejected) -> HTTPException:
    if isinstance(exc, AdmissionDenied):
        headers = {"Retry-After": str(int(exc.retry_after))} if exc.retry_after else None
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": exc.code, "detail": str(exc)},
            headers=headers,
        )
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error": exc.code, "detail": str(exc)},
    )


def _tool_log_entry(entry: Any) -> dict[str, Any]:
    """One renderable row for ``interpretation.tools_invoked``."""
    out: dict[str, Any] = {
        "step": entry.step,
        "tool": entry.tool,
        "args": entry.args,
        "tier": entry.tier,
        "decision": entry.decision,
        "reason_code": entry.reason_code,
        "blocked": not entry.allowed,
        "duration_ms": entry.duration_ms,
    }
    if entry.proposal_id:
        out["proposal_id"] = entry.proposal_id
    if entry.allowed and entry.result_preview is not None:
        out["result"] = entry.result_preview
    if entry.error_class:
        out["error"] = entry.error_class
    return out


def _proposal_payload(proposal: Any) -> dict[str, Any]:
    return {
        "id": proposal.id,
        "tool": proposal.tool,
        "args": proposal.args,
        "effective_targets": proposal.effective_targets,
        "params_sha256": proposal.params_sha256,
        "evidence_sha256": proposal.evidence_sha256,
        "suspect": proposal.suspect,
        "expires_at": proposal.expires_at,
    }


def _policy_event_payload(event: Any) -> dict[str, Any]:
    return {
        "step": event.step,
        "tool": event.tool,
        "decision": event.decision,
        "reason_code": event.reason_code,
        "tier": event.tier.value if hasattr(event.tier, "value") else str(event.tier),
        "audit_id": event.audit_id,
        "proposal_id": event.proposal_id,
    }


def _usage_payload(usage: Usage) -> dict[str, Any]:
    return {
        "input_uncached": usage.input_uncached,
        "cache_read": usage.cache_read,
        "cache_write": usage.cache_write,
        "output": usage.output,
        "thinking": usage.thinking,
        "total_billable": usage.total_billable,
        "estimated": usage.estimated,
    }


def _proposal_state(ctx: AgentContext, trust: TrustState) -> _RunState:
    """A minimal run state so the runtime's own materializer/auditor can be reused.

    The direct-execute and approval surfaces must produce byte-identical
    proposal hashes and audit payloads to the chat runtime, so they call the
    runtime's methods rather than re-implementing them.
    """
    state = _RunState(ctx=ctx, started=time.monotonic())
    state.trust = TrustScanner(trust)
    return state


def _result_dict(raw: Any) -> dict[str, Any]:
    """``AgentAction.result`` normalized: it may be a JSON string or a dict."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        parsed = safe_json_loads(raw, {})
        return parsed if isinstance(parsed, dict) else {"execution_result": parsed}
    return {}


def _rollback_capable(result: dict[str, Any]) -> bool:
    """True when the execution recorded forward-effect ids we can reverse by id."""
    return bool(result.get("ioc_id") or result.get("agent_commands") or result.get("user_id"))



# ============================================================================
# Structured Threat Hunt (PY-HUNT-001)
# ============================================================================


class StructuredHuntRequest(BaseModel):
    hypothesis: str = Field(..., min_length=4, description="The hunt hypothesis / question")
    timeframe_hours: int = Field(24, ge=1, le=720)


@router.post("/hunts")
async def run_structured_hunt_endpoint(
    req: StructuredHuntRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Run a structured PY-HUNT-001 threat hunt by hypothesis.

    Validates the hypothesis against the MITRE ATT&CK KB, runs the real
    multi-source scan, maps findings to ATT&CK, scores a verdict, and
    returns a structured report. Recommendations are advisory and always
    flagged for human approval — the hunt never remediates.
    """
    from src.agentic.structured_hunt import run_structured_hunt
    org_id = getattr(current_user, "organization_id", None)
    return await run_structured_hunt(
        db, hypothesis=req.hypothesis, organization_id=org_id,
        timeframe_hours=req.timeframe_hours,
    )


# ============================================================================
# Agent Management Endpoints
# ============================================================================


@router.get("/agents", response_model=SOCAgentListResponse)
async def list_agents(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List SOC agents with filtering and pagination"""
    query = select(SOCAgent).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None)
    )

    if agent_type:
        query = query.where(SOCAgent.agent_type == agent_type)

    if status:
        query = query.where(SOCAgent.status == status)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(SOCAgent.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    agents = list(result.scalars().all())

    return SOCAgentListResponse(
        items=[SOCAgentResponse.model_validate(a) for a in agents],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/agents/{agent_id}", response_model=SOCAgentResponse)
async def get_agent(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Get specific agent details"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    return SOCAgentResponse.model_validate(agent)


@router.post("/agents", response_model=SOCAgentResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    agent_data: SOCAgentCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create new SOC agent"""
    agent = SOCAgent(
        organization_id=getattr(current_user, "organization_id", None),
        name=agent_data.name,
        agent_type=agent_data.agent_type,
        capabilities=json.dumps(agent_data.capabilities or []),
        llm_model=agent_data.llm_model,
        temperature=agent_data.temperature,
        max_reasoning_steps=agent_data.max_reasoning_steps,
        autonomy_level=agent_data.autonomy_level,
    )

    db.add(agent)
    await db.commit()
    await db.refresh(agent)

    return SOCAgentResponse.model_validate(agent)


@router.put("/agents/{agent_id}", response_model=SOCAgentResponse)
async def update_agent(
    agent_data: SOCAgentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Update agent configuration"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    # Update fields
    if agent_data.name:
        agent.name = agent_data.name
    if agent_data.status:
        agent.status = agent_data.status
    if agent_data.temperature is not None:
        agent.temperature = agent_data.temperature
    if agent_data.max_reasoning_steps:
        agent.max_reasoning_steps = agent_data.max_reasoning_steps
    if agent_data.autonomy_level:
        agent.autonomy_level = agent_data.autonomy_level

    await db.commit()
    await db.refresh(agent)

    return SOCAgentResponse.model_validate(agent)


@router.post("/agents/{agent_id}/start")
async def start_agent(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Start agent operation"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    agent.status = "idle"
    await db.commit()

    return {"status": "started", "agent_id": agent_id}


@router.post("/agents/{agent_id}/stop")
async def stop_agent(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Stop agent operation"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    agent.status = "paused"
    await db.commit()

    return {"status": "stopped", "agent_id": agent_id}


@router.get("/agents/{agent_id}/performance", response_model=SOCAgentPerformance)
async def get_agent_performance(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Get agent performance metrics"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    return SOCAgentPerformance(
        agent_id=agent.id,
        name=agent.name,
        total_investigations=agent.total_investigations,
        avg_resolution_time_minutes=agent.avg_resolution_time_minutes,
        accuracy_score=agent.accuracy_score,
        false_positive_rate=agent.false_positive_rate,
        status=agent.status,
    )


# ============================================================================
# Investigation Endpoints
# ============================================================================


@router.get("/investigations", response_model=InvestigationListResponse)
async def list_investigations(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[int] = None,
):
    """List investigations with filtering and pagination"""
    query = select(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None)
    )

    if agent_id:
        query = query.where(Investigation.agent_id == agent_id)

    if status:
        query = query.where(Investigation.status == status)

    if priority:
        query = query.where(Investigation.priority == priority)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(Investigation.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    investigations = list(result.scalars().all())

    return InvestigationListResponse(
        items=[InvestigationResponse.model_validate(i) for i in investigations],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get investigation details"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    # Parse JSON fields
    inv_data = InvestigationResponse.model_validate(investigation)

    if investigation.reasoning_chain:
        try:
            inv_data.reasoning_chain = safe_json_loads(investigation.reasoning_chain, {})
        except (ValueError, TypeError):  # malformed legacy JSON column
            pass

    if investigation.evidence_collected:
        try:
            inv_data.evidence_collected = safe_json_loads(investigation.evidence_collected, {})
        except (ValueError, TypeError):  # malformed legacy JSON column
            pass

    if investigation.actions_taken:
        try:
            inv_data.actions_taken = safe_json_loads(investigation.actions_taken, {})
        except (ValueError, TypeError):  # malformed legacy JSON column
            pass

    if investigation.recommendations:
        try:
            inv_data.recommendations = safe_json_loads(investigation.recommendations, {})
        except (ValueError, TypeError):  # malformed legacy JSON column
            pass

    return inv_data


@router.post("/investigations", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def start_investigation(
    inv_data: InvestigationCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Start manual investigation"""
    # Verify agent exists
    agent = await db.get(SOCAgent, inv_data.agent_id)
    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    investigation = Investigation(
        organization_id=getattr(current_user, "organization_id", None),
        agent_id=inv_data.agent_id,
        trigger_type=inv_data.trigger_type,
        trigger_source_id=inv_data.trigger_source_id,
        title=inv_data.title,
        hypothesis=inv_data.hypothesis,
        status=InvestigationStatus.INITIATED.value,
        priority=inv_data.priority,
        evidence_collected=json.dumps(inv_data.initial_context or {}),
    )

    db.add(investigation)
    await db.commit()

    # Start async investigation
    run_investigation.delay(
        agent_id=inv_data.agent_id,
        organization_id=getattr(current_user, "organization_id", None),
        trigger_type=inv_data.trigger_type,
        trigger_source_id=inv_data.trigger_source_id,
        title=inv_data.title,
        initial_context=inv_data.initial_context,
    )

    await db.refresh(investigation)
    return InvestigationResponse.model_validate(investigation)


@router.put("/investigations/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    inv_data: InvestigationUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Update investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    if inv_data.title:
        investigation.title = inv_data.title
    if inv_data.hypothesis:
        investigation.hypothesis = inv_data.hypothesis
    if inv_data.priority:
        investigation.priority = inv_data.priority
    if inv_data.status:
        investigation.status = inv_data.status
    if inv_data.human_feedback:
        investigation.human_feedback = inv_data.human_feedback
    if inv_data.feedback_rating:
        investigation.feedback_rating = inv_data.feedback_rating

    await db.commit()
    await db.refresh(investigation)

    return InvestigationResponse.model_validate(investigation)


@router.get("/investigations/{investigation_id}/reasoning-chain")
async def get_reasoning_chain(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get detailed reasoning chain for investigation"""
    result = await db.execute(
        select(Investigation)
        .options(selectinload(Investigation.reasoning_steps))
        .where(Investigation.id == investigation_id)
    )
    investigation = result.scalar_one_or_none()

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    steps = []
    for step in investigation.reasoning_steps:
        steps.append({
            "step_number": step.step_number,
            "step_type": step.step_type,
            "thought_process": step.thought_process,
            "observation": safe_json_loads(step.observation, {}) if step.observation else None,
            "confidence_delta": step.confidence_delta,
            "duration_ms": step.duration_ms,
        })

    return {
        "investigation_id": investigation_id,
        "total_steps": len(steps),
        "steps": steps,
    }


@router.get("/investigations/{investigation_id}/timeline")
async def get_investigation_timeline(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get timeline view of investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    return {
        "investigation_id": investigation_id,
        "title": investigation.title,
        "status": investigation.status,
        "confidence_score": investigation.confidence_score,
        "start_time": investigation.created_at,
        "steps_count": len(investigation.reasoning_steps),
        "actions_count": len(investigation.actions),
        "findings": investigation.findings_summary,
    }


@router.post("/investigations/{investigation_id}/feedback")
async def submit_investigation_feedback(
    feedback: InvestigationFeedback,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Submit quality-rating feedback on an investigation."""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    investigation.feedback_rating = feedback.rating
    investigation.human_feedback = feedback.feedback

    await db.commit()

    return {
        "status": "feedback_recorded",
        "investigation_id": investigation_id,
        "rating": feedback.rating,
    }


@router.post("/investigations/{investigation_id}/correct")
async def correct_investigation_verdict(
    correction: InvestigationCorrection,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Mark an investigation's verdict wrong.

    Writes a structured InvestigationFeedback row that future
    investigations read into their prompt context — so the agent
    adjusts its hypothesis-generation when similar alerts arrive.
    A reviewer explanation in `correction_note` is the most valuable
    learning signal; the agent quotes it verbatim in the prompt so
    the next investigation understands WHY the prior call was wrong.
    """
    investigation = await db.get(Investigation, investigation_id)
    org_id = getattr(current_user, "organization_id", None)
    if not investigation or investigation.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Investigation not found")

    row = InvestigationFeedbackRow(
        investigation_id=investigation_id,
        organization_id=org_id,
        reviewer_user_id=current_user.id,
        corrected_verdict=correction.corrected_verdict,
        agent_verdict=investigation.resolution_type,
        agent_confidence=investigation.confidence_score,
        correction_note=correction.correction_note,
    )
    db.add(row)

    # Update the investigation itself so the Investigations UI shows
    # the corrected verdict with a visible "human-corrected" marker.
    investigation.resolution_type = correction.corrected_verdict
    if not investigation.human_feedback and correction.correction_note:
        investigation.human_feedback = correction.correction_note

    # AU-2 audit — record the correction so a 3PAO can see who
    # overrode which agent call.
    try:
        from src.tickethub.models import TicketActivity
        db.add(TicketActivity(
            source_type="investigation",
            source_id=investigation_id,
            activity_type="verdict_corrected",
            description=(
                f"user={current_user.email} "
                f"agent_verdict={row.agent_verdict}@{row.agent_confidence or 0:.0f}% "
                f"→ corrected={correction.corrected_verdict} "
                f"note={(correction.correction_note or '')[:300]}"
            ),
            organization_id=org_id,
        ))
    except Exception:
        pass

    await db.commit()
    await db.refresh(row)
    return {
        "status": "correction_recorded",
        "investigation_id": investigation_id,
        "corrected_verdict": row.corrected_verdict,
        "feedback_id": row.id,
    }


@router.get("/investigations/{investigation_id}/feedback")
async def list_investigation_feedback(
    investigation_id: str = Path(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Return corrections recorded for this investigation."""
    investigation = await db.get(Investigation, investigation_id)
    org_id = getattr(current_user, "organization_id", None)
    if not investigation or investigation.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Investigation not found")
    rows = list(await db.scalars(
        select(InvestigationFeedbackRow)
        .where(InvestigationFeedbackRow.investigation_id == investigation_id)
        .order_by(InvestigationFeedbackRow.created_at.desc())
    ))
    return {
        "items": [
            {
                "id": r.id,
                "reviewer_user_id": r.reviewer_user_id,
                "agent_verdict": r.agent_verdict,
                "agent_confidence": r.agent_confidence,
                "corrected_verdict": r.corrected_verdict,
                "correction_note": r.correction_note,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "total": len(rows),
    }


# ============================================================================
# Action Approval Endpoints
# ============================================================================


@router.get("/actions/pending-approval")
async def list_pending_approvals(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List actions pending approval"""
    org_id = getattr(current_user, "organization_id", None)
    filters = [AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value]
    if org_id:
        filters.append(AgentAction.organization_id == org_id)
    query = select(AgentAction).where(*filters)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(AgentAction.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    actions = list(result.scalars().all())

    items = []
    for action in actions:
        inv = await db.get(Investigation, action.investigation_id)
        if not inv:
            continue
        if org_id and getattr(inv, "organization_id", None) and inv.organization_id != org_id:
            continue
        agent = await db.get(SOCAgent, inv.agent_id) if inv.agent_id else None
        items.append(ActionPendingApproval(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            investigation_id=action.investigation_id,
            investigation_title=inv.title,
            agent_id=agent.id if agent else "",
            agent_name=agent.name if agent else "Unknown",
            confidence_score=inv.confidence_score or 0,
            created_at=action.created_at,
        ))

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }

def _params_dict(raw: Any) -> dict[str, Any]:
    """``AgentAction.parameters`` normalized (dict rows and legacy JSON strings)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        parsed = safe_json_loads(raw, {})
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _conflict(error: str, detail: str, **extra: Any) -> HTTPException:
    payload: dict[str, Any] = {"error": error, "detail": detail}
    payload.update(extra)
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=payload)


def _expired(action: AgentAction) -> bool:
    expires_at = getattr(action, "expires_at", None)
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


@router.post("/actions/{action_id}/approve")
async def approve_action(
    approval: AgentActionApproval,
    request: Request,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
    action_id: str = Path(...),
):
    """Approve (or deny) an agent-proposed action and execute it.

    Design v2 section 8. The approval is bound by hash to the exact
    arguments and evidence the proposal was created with, re-evaluated by
    the policy engine in ``approval`` mode with the originating run's trust
    tier, and executed through ``AgentToolRegistry.call`` with the approver
    as the actor. Both audit events (pre-decision + post-execution) are
    written by the same code the chat runtime uses.
    """
    ctx_probe = _agent_context(current_user, Mode.APPROVAL, request=request)
    _require_analyst(ctx_probe)
    org_id = ctx_probe.org_id

    action = (await db.execute(
        select(AgentAction).where(AgentAction.id == action_id, AgentAction.organization_id == org_id)
    )).scalar_one_or_none()
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "action_not_found", "detail": "Action not found"},
        )

    approver_ip = _client_ip(request)
    approver_role = ctx_probe.role.value
    now = datetime.now(timezone.utc)

    if not approval.approved:
        action.execution_status = ActionExecutionStatus.DENIED.value
        action.approved_by = ctx_probe.actor_user_id
        action.approval_timestamp = now.isoformat()
        if hasattr(action, "approver_role"):
            action.approver_role = approver_role
            action.approver_ip = approver_ip
            action.approval_reason = approval.reason or approval.approval_notes
        audit = AuditLogger(db, org_id)
        await audit.log_event(
            event_type=AUDIT_EVENT_POLICY,
            action="action.denied",
            actor_type="user",
            actor_id=ctx_probe.actor_user_id or "unknown",
            resource_type="agent_action",
            resource_id=action.id,
            description=f"proposal denied: {action.tool_name or action.action_type}",
            new_value={
                "tool": action.tool_name,
                "reason": (approval.reason or approval.approval_notes or "")[:500],
                "approver_role": approver_role,
            },
            result="denied",
            risk_level="medium",
            actor_ip=approver_ip,
            request_id=action.run_id,
            run_id=action.run_id,
        )
        await db.commit()
        return {"status": "denied", "action_id": action_id, "execution_status": action.execution_status}

    if action.execution_status != ActionExecutionStatus.PENDING_APPROVAL.value:
        raise _conflict(
            "not_pending_approval",
            f"action is in status '{action.execution_status}'; only pending proposals can be approved",
        )

    tool_name = getattr(action, "tool_name", None)
    params = _params_dict(action.parameters)

    # -- hash binding (AC-3 / SI-10): approve exactly what was proposed ----
    stored_params_sha = getattr(action, "params_sha256", None)
    stored_evidence_sha = getattr(action, "evidence_sha256", None)
    if not stored_params_sha or not stored_evidence_sha:
        raise _conflict(
            "approval_stale",
            "this proposal carries no argument/evidence binding; it cannot be approved for execution",
        )
    if approval.params_sha256 != stored_params_sha or approval.evidence_sha256 != stored_evidence_sha:
        raise _conflict("approval_stale", "the approval does not match the proposal's bound arguments or evidence")
    if tool_name:
        recomputed = hashlib.sha256(
            canonical_json({"tool": tool_name, "args": params}).encode("utf-8")
        ).hexdigest()
        if recomputed != stored_params_sha:
            raise _conflict("approval_stale", "the stored arguments no longer hash to the proposal binding")

    if _expired(action):
        raise _conflict("approval_expired", "the proposal expired before it was approved")

    # -- suspect proposals (prompt-injection contaminated evidence) --------
    if bool(getattr(action, "suspect", False)):
        if ctx_probe.role is not UserRole.ADMIN or not approval.acknowledge_suspect or not (approval.reason or "").strip():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "suspect_action_requires_reinvestigation",
                    "detail": (
                        "this proposal was raised from evidence flagged for prompt injection; an admin must "
                        "acknowledge_suspect with a written reason, or the alert must be re-investigated"
                    ),
                    "injection_tier": getattr(action, "injection_tier", None),
                },
            )
        audit = AuditLogger(db, org_id)
        await audit.log_event(
            event_type=AUDIT_EVENT_POLICY,
            action="suspect.approved",
            actor_type="user",
            actor_id=ctx_probe.actor_user_id or "unknown",
            resource_type="agent_action",
            resource_id=action.id,
            description=f"admin acknowledged a suspect proposal: {tool_name or action.action_type}",
            new_value={
                "tool": tool_name,
                "injection_tier": getattr(action, "injection_tier", None),
                "reason": approval.reason[:500],
                "approver_role": approver_role,
            },
            result="success",
            risk_level="high",
            actor_ip=approver_ip,
            request_id=action.run_id,
            run_id=action.run_id,
        )

    # -- proposals with no executable tool stay human work ------------------
    if not tool_name:
        action.execution_status = ActionExecutionStatus.APPROVED.value
        action.approved_by = ctx_probe.actor_user_id
        action.approval_timestamp = now.isoformat()
        if hasattr(action, "approver_role"):
            action.approver_role = approver_role
            action.approver_ip = approver_ip
            action.approval_reason = approval.reason or approval.approval_notes
        action.rollback_available = False
        action.result = json.dumps(
            {
                "executed": False,
                "note": "approved as human work: this proposal carries no executable tool",
                "target": action.target,
            }
        )
        await db.commit()
        return {
            "status": "approved",
            "action_id": action_id,
            "executed": False,
            "execution_status": action.execution_status,
            "detail": "no executable tool is bound to this proposal; it is recorded as human work",
        }

    origin_tier: Optional[TrustTier] = None
    raw_tier = getattr(action, "injection_tier", None)
    if raw_tier:
        try:
            origin_tier = TrustTier(str(raw_tier))
        except ValueError:
            origin_tier = TrustTier.LOCKDOWN  # an unreadable tier is treated as the worst case

    ctx = _agent_context(
        current_user,
        Mode.APPROVAL,
        propose_actions=True,
        investigation_id=action.investigation_id,
        request=request,
        origin_trust_tier=origin_tier,
        approving_action_id=action.id,
    )
    runtime = await _build_runtime(db, ctx, redis, purpose="approval", with_provider=False)

    spec = runtime.registry.specs.get(tool_name)
    if spec is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "unknown_tool", "detail": f"{tool_name} is not a registered tool"},
        )
    if spec.tier is Tier.PRIVILEGED and ctx.role is not UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "role_not_permitted", "detail": "privileged actions require an admin approver"},
        )

    action.approved_by = ctx.actor_user_id
    action.approval_timestamp = now.isoformat()
    if hasattr(action, "approver_role"):
        action.approver_role = approver_role
        action.approver_ip = approver_ip
        action.approval_reason = approval.reason or approval.approval_notes
    await db.flush()

    decision = await runtime.policy.evaluate(ctx, spec, params, TrustState(), step=0)
    if decision.kind != "allow":
        # The proposal stays pending: the approval was recorded and audited,
        # but the policy refused the execution.
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "policy_denied",
                "reason_code": decision.reason_code,
                "detail": decision.detail or f"policy returned {decision.kind} for {tool_name}",
                "decision": decision.kind,
            },
        )

    state = _proposal_state(ctx, TrustState(tier=origin_tier or TrustTier.CLEAN))
    started = time.monotonic()
    action.execution_status = ActionExecutionStatus.APPROVED.value
    await db.flush()
    action.execution_status = ActionExecutionStatus.EXECUTING.value
    await db.flush()
    try:
        result = await runtime.registry.call(ctx, tool_name, params, decision=decision, policy=runtime.policy)
    except PermissionError as exc:
        await runtime.runner._audit_post(state, tool_name, "blocked", started, error_class=str(exc))
        action.execution_status = ActionExecutionStatus.PENDING_APPROVAL.value
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "policy_denied", "reason_code": str(exc), "detail": "the tool refused the approved call"},
        ) from exc
    except Exception as exc:  # noqa: BLE001 - the failure class is recorded, never the secrets
        error_class = exc.__class__.__name__
        logger.error("approved_action_failed", action_id=action.id, tool=tool_name, error_class=error_class)
        await runtime.runner._audit_post(state, tool_name, "failed", started, error_class=error_class)
        action.execution_status = ActionExecutionStatus.FAILED.value
        action.result = json.dumps({"executed": False, "error_class": error_class})
        action.rollback_available = False
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "tool_failed", "detail": f"{error_class}: the approved tool did not complete"},
        ) from exc

    payload = result if isinstance(result, dict) else {"result": result}
    result_json = json.dumps(payload, default=str)[:MESSAGE_RESULT_CAP]
    action.result = result_json
    action.execution_status = (
        ActionExecutionStatus.FAILED.value if isinstance(payload, dict) and payload.get("error")
        else ActionExecutionStatus.COMPLETED.value
    )
    action.rollback_available = _rollback_capable(payload) and action.execution_status == ActionExecutionStatus.COMPLETED.value
    await runtime.runner._audit_post(
        state,
        tool_name,
        "executed" if action.execution_status == ActionExecutionStatus.COMPLETED.value else "failed",
        started,
        extra={
            "action_id": action.id,
            "approver_role": approver_role,
            "params_sha256": stored_params_sha,
            "result_sha256": hashlib.sha256(result_json.encode("utf-8")).hexdigest(),
            "rollback_available": action.rollback_available,
        },
    )
    await db.commit()

    return {
        "status": "approved",
        "action_id": action_id,
        "executed": True,
        "tool": tool_name,
        "execution_status": action.execution_status,
        "rollback_available": action.rollback_available,
        "result": payload,
        "run_id": action.run_id,
    }


@router.post("/actions/{action_id}/rollback")
async def rollback_action(
    request: Request,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    action_id: str = Path(...),
):
    """Reverse an executed action by its recorded forward-effect ids only.

    Design v2 section 3/8: the rollback never re-derives its targets from
    values in the proposal (an attacker-influenced value must not steer the
    reversal). It reads the ids the forward execution recorded in
    ``AgentAction.result`` -- the ThreatIndicator id, the endpoint-agent
    command ids, the User id -- and reverses exactly those. Where the
    forward effect was an endpoint-agent command, the inverse command
    (``unblock_ip`` / ``release_host``) is queued through the same agent
    service, issued by the approver.
    """
    from src.agents.capabilities import capability_allows
    from src.agents.models import EndpointAgent
    from src.agents.service import AgentService, AgentServiceError
    from src.intel.models import ThreatIndicator
    from src.models.user import User

    ctx = _agent_context(current_user, Mode.APPROVAL, request=request)
    _require_analyst(ctx)
    org_id = ctx.org_id

    action = (await db.execute(
        select(AgentAction).where(AgentAction.id == action_id, AgentAction.organization_id == org_id)
    )).scalar_one_or_none()
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "action_not_found", "detail": "Action not found"},
        )
    if action.rollback_executed or action.execution_status == ActionExecutionStatus.ROLLED_BACK.value:
        raise _conflict("already_rolled_back", "this action has already been rolled back")
    if action.execution_status != ActionExecutionStatus.COMPLETED.value:
        raise _conflict(
            "not_completed",
            f"action is in status '{action.execution_status}'; only completed actions have effects to reverse",
        )

    recorded = _result_dict(action.result)
    if not _rollback_capable(recorded):
        action.rollback_available = False
        await db.commit()
        raise _conflict(
            "not_reversible",
            "the execution recorded no reversible effect ids; manual remediation is required",
            tool=getattr(action, "tool_name", None),
        )

    audit = AuditLogger(db, org_id)
    await audit.log_event(
        event_type=AUDIT_EVENT_POLICY,
        action="action.rollback",
        actor_type="user",
        actor_id=ctx.actor_user_id or "unknown",
        resource_type="agent_action",
        resource_id=action.id,
        description=f"rollback requested for {getattr(action, 'tool_name', None) or action.action_type}",
        new_value={"tool": getattr(action, "tool_name", None), "effects": sorted(recorded.keys())[:20]},
        result="success",
        risk_level="medium",
        actor_ip=ctx.actor_ip,
        request_id=ctx.run_id,
        run_id=ctx.run_id,
    )

    reversed_effects: dict[str, Any] = {}
    problems: list[str] = []

    ioc_id = recorded.get("ioc_id")
    if ioc_id:
        ioc = (await db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.id == str(ioc_id), ThreatIndicator.organization_id == org_id
            )
        )).scalar_one_or_none()
        if ioc is None:
            problems.append(f"threat indicator {ioc_id} is no longer present in this organization")
        else:
            ioc.is_active = False
            reversed_effects["indicator_deactivated"] = ioc.id

    user_id = recorded.get("user_id")
    if user_id:
        user = (await db.execute(
            select(User).where(User.id == str(user_id), User.organization_id == org_id)
        )).scalar_one_or_none()
        if user is None:
            problems.append(f"user {user_id} is no longer present in this organization")
        else:
            user.is_active = True
            reversed_effects["user_reenabled"] = user.id

    commands = recorded.get("agent_commands")
    if isinstance(commands, list) and commands:
        inverse = {"block_ip": "unblock_ip", "isolate_host": "release_host"}.get(
            str(getattr(action, "tool_name", "") or action.action_type or "")
        )
        if inverse is None:
            problems.append(
                f"no inverse endpoint command is defined for {getattr(action, 'tool_name', None) or action.action_type}"
            )
        else:
            svc = AgentService(db)
            issued: list[dict[str, Any]] = []
            for entry in commands:
                if not isinstance(entry, dict) or not entry.get("agent_id"):
                    continue
                agent = (await db.execute(
                    select(EndpointAgent).where(
                        EndpointAgent.id == str(entry["agent_id"]),
                        EndpointAgent.organization_id == org_id,
                    )
                )).scalar_one_or_none()
                if agent is None:
                    problems.append(f"endpoint agent {entry.get('agent_id')} not found; cannot queue {inverse}")
                    continue
                if not capability_allows(list(agent.capabilities or []), inverse):
                    problems.append(f"agent {agent.id} is not enrolled for {inverse}")
                    continue
                payload = (
                    {"ip": recorded.get("ip")} if inverse == "unblock_ip"
                    else {"hostname": recorded.get("hostname")}
                )
                try:
                    cmd = await svc.issue_command(
                        agent=agent,
                        action=inverse,
                        payload=payload,
                        issued_by=ctx.actor_user_id,
                        approval_override=True,
                    )
                except AgentServiceError as exc:
                    problems.append(f"agent {agent.id}: {exc}")
                    continue
                issued.append({
                    "agent_id": agent.id,
                    "reverses_command_id": entry.get("command_id"),
                    "command_id": cmd.id,
                    "action": inverse,
                })
            if issued:
                reversed_effects["inverse_commands"] = issued

    if not reversed_effects:
        await db.commit()
        raise _conflict(
            "rollback_failed",
            "none of the recorded effects could be reversed",
            problems=problems[:10],
        )

    detail = {"reversed": reversed_effects, "problems": problems[:10]}
    action.rollback_executed = True
    action.execution_status = ActionExecutionStatus.ROLLED_BACK.value
    stored = _result_dict(action.result)
    stored["rollback"] = detail
    action.result = json.dumps(stored, default=str)[:MESSAGE_RESULT_CAP]

    await audit.log_event(
        event_type=AUDIT_EVENT_POLICY,
        action="action.rolled_back",
        actor_type="user",
        actor_id=ctx.actor_user_id or "unknown",
        resource_type="agent_action",
        resource_id=action.id,
        description=f"rollback executed for {getattr(action, 'tool_name', None) or action.action_type}",
        new_value=detail,
        result="success" if not problems else "partial",
        risk_level="medium",
        actor_ip=ctx.actor_ip,
        request_id=ctx.run_id,
        run_id=ctx.run_id,
    )
    await db.commit()

    return {"status": "rolled_back", "action_id": action_id, "detail": detail}




# ============================================================================
# Natural Language Interface
# ============================================================================

@router.get("/tools")
async def list_agent_tools(
    request: Request,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """The tools the caller's role may invoke (ToolSpec-driven, org-bound)."""
    ctx = _agent_context(current_user, Mode.INTERACTIVE, request=request)
    registry = AgentToolRegistry(db, ctx)
    tools = [
        {
            "name": spec.name,
            "description": spec.description,
            "parameters": render_json_schema(spec),
            "tier": spec.tier.value,
            "min_role": spec.min_role.value,
        }
        for spec in registry.visible_specs(ctx.role)
    ]
    return {"tools": tools, "total": len(tools)}


@router.post("/tools/{tool_name}/execute")
async def execute_agent_tool(
    tool_name: str,
    request: Request,
    body: dict[str, Any] = Body(default_factory=dict),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
):
    """Execute one tool directly, through the same policy gate as the agent.

    F14 (direct execute bypass) is closed: the call goes through
    ``PolicyEngine.evaluate`` + ``AgentToolRegistry.call``, so role, tier,
    reference scoping, rate limits and the audit pair all apply. A
    destructive/privileged tier therefore yields a *proposal* here too -- it
    is never executed inline.

    Body: the tool arguments, optionally wrapped as
    ``{"params": {...}, "propose_actions": true}``.
    """
    propose_actions = bool(body.pop("propose_actions", False)) if isinstance(body, dict) else False
    params = body.get("params") if isinstance(body.get("params"), dict) else body
    if not isinstance(params, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_arguments", "detail": "tool arguments must be a JSON object"},
        )

    ctx = _agent_context(
        current_user, Mode.INTERACTIVE, propose_actions=propose_actions, request=request
    )
    runtime = await _build_runtime(db, ctx, redis, purpose="chat", with_provider=False)
    spec = runtime.registry.specs.get(tool_name)
    if spec is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "unknown_tool", "detail": f"{tool_name} is not a registered tool"},
        )

    decision = await runtime.policy.evaluate(ctx, spec, params, TrustState(), step=0)
    state = _proposal_state(ctx, TrustState())
    started = time.monotonic()

    if decision.kind == "propose":
        investigation = await _proposal_investigation(
            db, ctx.org_id,
            trigger_type="direct_tool",
            source_id=ctx.actor_user_id or "unknown",
            title=f"Direct tool proposals: {getattr(current_user, 'email', ctx.actor_user_id)}",
            hypothesis="Destructive tools invoked directly are proposed for approval, never executed inline.",
        )
        if investigation is None:
            raise _proposals_unavailable()
        ctx.investigation_id = investigation.id
        proposal = await runtime.runner._materialize_proposal(state, decision)
        await runtime.runner._audit_post(
            state, tool_name, "proposed" if proposal.persisted else "failed", started,
            extra={"proposal_id": proposal.id, "params_sha256": proposal.params_sha256},
            error_class=None if proposal.persisted else "proposal_not_persisted",
        )
        await db.commit()
        if not proposal.persisted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "proposal_unavailable",
                    "detail": (
                        "the proposal could not be recorded, so nothing was executed; "
                        "destructive tools are only executed from an approved proposal"
                    ),
                },
            )
        return {"proposed": True, "executed": False, "proposal": _proposal_payload(proposal)}

    if decision.kind != "allow":
        await runtime.runner._audit_post(
            state, tool_name, "blocked", started, error_class=decision.reason_code, detail=decision.detail,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "policy_denied",
                "reason_code": decision.reason_code,
                "detail": decision.detail or f"{tool_name} was denied",
            },
        )

    try:
        result = await runtime.registry.call(ctx, tool_name, params, decision=decision, policy=runtime.policy)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "unknown_tool", "detail": f"{tool_name} is not a registered tool"},
        ) from exc
    except PermissionError as exc:
        await runtime.runner._audit_post(state, tool_name, "blocked", started, error_class=str(exc))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "policy_denied", "reason_code": str(exc), "detail": f"{tool_name} was denied"},
        ) from exc
    except Exception as exc:  # noqa: BLE001 - the failure class is recorded, never its secrets
        error_class = exc.__class__.__name__
        logger.error("direct_tool_failed", tool=tool_name, error_class=error_class, organization_id=ctx.org_id)
        await runtime.runner._audit_post(state, tool_name, "failed", started, error_class=error_class)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "tool_failed", "detail": f"{error_class}: the tool did not complete"},
        ) from exc

    payload = result if isinstance(result, dict) else {"result": result}
    await runtime.runner._audit_post(
        state, tool_name, "executed", started,
        extra={"result_sha256": hashlib.sha256(
            json.dumps(payload, default=str, sort_keys=True).encode("utf-8")
        ).hexdigest()},
    )
    await db.commit()
    return {"proposed": False, "executed": True, "tool": tool_name, "result": payload}


# ----------------------------------------------------------------------------
# Chat
# ----------------------------------------------------------------------------


def _jsonable(value: Any) -> Any:
    """JSON-safe copy for the ``tool_calls`` JSON column (datetimes -> str)."""
    return json.loads(json.dumps(value, default=str))


async def _chat_history(db: AsyncSession, session_id: str) -> list[Message]:
    """The last ``CHAT_HISTORY_TURNS`` persisted turns, oldest first."""
    rows = (await db.execute(
        select(AgentChatMessage)
        .where(AgentChatMessage.session_id == session_id)
        .order_by(AgentChatMessage.created_at.desc(), AgentChatMessage.id.desc())
        .limit(CHAT_HISTORY_TURNS)
    )).scalars().all()
    history: list[Message] = []
    for row in reversed(list(rows)):
        text = (row.content or "").strip()
        if not text:
            continue
        role = "assistant" if (row.role or "user") == "assistant" else "user"
        history.append(Message(role=role, content=[TextBlock(text=text)]))
    return history


async def _proposal_investigation(
    db: AsyncSession,
    org_id: str,
    *,
    trigger_type: str,
    source_id: str,
    title: str,
    hypothesis: str,
    agent: Optional[SOCAgent] = None,
) -> Optional[Investigation]:
    """The investigation interactive proposals are recorded against.

    ``agent_actions.investigation_id`` is NOT NULL, so an interactive run
    that may propose actions needs an investigation row of its own. One row
    per source (a chat session, or a user's direct tool executions), created
    on first use and reused afterwards, attributed to the caller's chosen SOC
    agent or the organization's oldest one. Returns ``None`` when the
    organization has no SOC agent -- the caller is told rather than silently
    losing the proposal.
    """
    existing = (await db.execute(
        select(Investigation)
        .where(
            Investigation.organization_id == org_id,
            Investigation.trigger_type == trigger_type,
            Investigation.trigger_source_id == source_id,
        )
        .limit(1)
    )).scalars().first()
    if existing is not None:
        return existing

    host = agent
    if host is None:
        host = (await db.execute(
            select(SOCAgent)
            .where(SOCAgent.organization_id == org_id)
            .order_by(SOCAgent.created_at.asc())
            .limit(1)
        )).scalars().first()
    if host is None:
        return None

    investigation = Investigation(
        organization_id=org_id,
        agent_id=host.id,
        trigger_type=trigger_type,
        trigger_source_id=source_id,
        title=title[:500],
        hypothesis=hypothesis,
        status=InvestigationStatus.INITIATED.value,
        priority=3,
    )
    db.add(investigation)
    await db.flush()
    return investigation


def _proposals_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "proposals_unavailable",
            "detail": (
                "proposals are recorded against a SOC agent's investigation and this organization "
                "has no SOC agent; create one before proposing destructive actions"
            ),
        },
    )


async def _mark_message_failed(
    db: AsyncSession, message: AgentChatMessage, run_id: str, error: str, detail: str
) -> None:
    """Record the failure on the user's turn so the UI can offer a retry."""
    message.tool_calls = {
        "status": "failed",
        "error": error,
        "detail": detail[:500],
        "run_id": run_id,
    }
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001 - the original failure is the one the caller sees
        logger.error("chat_failure_persist_failed", run_id=run_id, error=str(exc)[:300])
        await db.rollback()


async def _settle_reservation(quota: Any, reservation: Any, tokens: int) -> None:
    if reservation is None:
        return
    try:
        await quota.settle(reservation, tokens)
    except Exception as exc:  # noqa: BLE001 - accounting must never fail the request
        logger.warning("llm_quota_settle_failed", error=str(exc)[:200])


@router.post("/chat", response_model=NaturalLanguageResponse)
async def chat_with_agent(
    query_data: NaturalLanguageQuery,
    request: Request,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
):
    """One guarded agent turn (design v2 sections 1 and 9).

    The JWT builds the ``AgentContext``; the org's configured provider runs
    the turn through ``AgentRunner``; destructive tools become approval-gated
    proposals instead of executing inline; the session's injection trust
    state is loaded and persisted back. Nothing here fabricates an answer:
    a provider or budget failure is a 503/429 and the user's message is
    persisted as ``failed``.
    """
    org_id = _org_id(current_user)
    role = _agent_role(current_user)
    user_id = str(getattr(current_user, "id", "") or "")
    propose_actions = bool(query_data.propose_actions)

    if propose_actions and ROLE_RANK[role] < ROLE_RANK[UserRole.ANALYST]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "role_not_permitted",
                "detail": "viewers may not enable propose_actions; the agent stays read-only for this role",
            },
        )

    # -- session: must belong to this organization AND this user -----------
    if query_data.session_id:
        session = (await db.execute(
            select(AgentChatSession).where(
                AgentChatSession.id == query_data.session_id,
                AgentChatSession.organization_id == org_id,
                AgentChatSession.user_id == user_id,
            )
        )).scalar_one_or_none()
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "session_not_found", "detail": "Session not found"},
            )
    else:
        session = AgentChatSession(
            user_id=user_id,
            organization_id=org_id,
            title=(query_data.query[:60] + ("…" if len(query_data.query) > 60 else "")) or "New chat",
        )
        db.add(session)
        await db.flush()

    # -- the client-supplied agent id is validated, never trusted ----------
    agent: Optional[SOCAgent] = None
    if query_data.agent_id:
        agent = (await db.execute(
            select(SOCAgent).where(
                SOCAgent.id == query_data.agent_id, SOCAgent.organization_id == org_id
            )
        )).scalar_one_or_none()
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "unknown_agent", "detail": "agent_id is not a SOC agent in this organization"},
            )

    investigation_id: Optional[str] = None
    if propose_actions:
        investigation = await _proposal_investigation(
            db, org_id,
            trigger_type="chat",
            source_id=session.id,
            title=f"Chat session: {session.title}",
            hypothesis="Interactive analyst session; actions proposed here require approval.",
            agent=agent,
        )
        if investigation is None:
            raise _proposals_unavailable()
        investigation_id = investigation.id

    # History is loaded BEFORE the current turn is persisted.
    history = await _chat_history(db, session.id)
    user_message = AgentChatMessage(
        session_id=session.id, role="user", content=query_data.query, tool_calls=None,
    )
    db.add(user_message)
    await db.flush()

    ctx = _agent_context(
        current_user,
        Mode.INTERACTIVE,
        propose_actions=propose_actions,
        session_id=session.id,
        investigation_id=investigation_id,
        request=request,
    )

    try:
        runtime = await _build_runtime(db, ctx, redis, purpose="chat")
    except LLMNotConfigured as exc:
        await _mark_message_failed(db, user_message, ctx.run_id, "llm_not_configured", str(exc))
        raise _not_configured_error(exc) from exc

    trust_state = trust_state_from_dict(session.trust_state)
    reservation = None
    try:
        reservation = await runtime.quota.reserve(
            org_id, "interactive", ctx.max_tokens,
            credential_source=runtime.credential_source or "org",
        )
    except LLMQuotaExceeded as exc:
        await _mark_message_failed(db, user_message, ctx.run_id, getattr(exc, "code", "llm_quota_exceeded"), str(exc))
        raise _quota_error(exc) from exc

    try:
        async with runtime.provider:
            result = await runtime.runner.run(
                ctx, query_data.query, history=history, trust_state=trust_state,
            )
    except RunRejected as exc:
        await _settle_reservation(runtime.quota, reservation, 0)
        await _mark_message_failed(db, user_message, ctx.run_id, exc.code, str(exc))
        raise _rejected_error(exc) from exc
    except LLMQuotaExceeded as exc:
        await _settle_reservation(runtime.quota, reservation, 0)
        await _mark_message_failed(db, user_message, ctx.run_id, getattr(exc, "code", "llm_quota_exceeded"), str(exc))
        raise _quota_error(exc) from exc
    except CircuitOpen as exc:
        await _settle_reservation(runtime.quota, reservation, 0)
        await _mark_message_failed(db, user_message, ctx.run_id, CircuitOpen.code, str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "llm_unavailable", "detail": str(exc), "run_id": ctx.run_id},
        ) from exc

    await _settle_reservation(runtime.quota, reservation, result.usage.total_billable)
    session.trust_state = result.trust_state_dict

    if result.stop_reason == "error":
        await _mark_message_failed(
            db, user_message, result.run_id,
            result.error_code or "llm_provider_error",
            result.stop_detail or "the provider call failed",
        )
        raise _run_result_error(result)

    tools_invoked = [_tool_log_entry(entry) for entry in result.tool_log]
    proposals = [_proposal_payload(p) for p in result.proposals]
    policy_events = [_policy_event_payload(e) for e in result.policy_events]

    db.add(AgentChatMessage(
        session_id=session.id,
        role="assistant",
        content=result.final_text or "",
        tool_calls=_jsonable({
            "run_id": result.run_id,
            "status": "ok",
            "stop_reason": result.stop_reason,
            "tools_invoked": tools_invoked,
            "proposals": proposals,
            "policy_events": policy_events,
            "provider": result.provider,
            "model": result.model,
            "injection_tier": result.trust.tier.value,
        }),
    ))
    await db.commit()

    return NaturalLanguageResponse(
        response=result.final_text or "",
        agent_id=agent.id if agent is not None else "",
        agent_name=agent.name if agent is not None else "SOC Agent",
        interpretation={
            "tools_invoked": tools_invoked,
            "run_id": result.run_id,
            "stop_reason": result.stop_reason,
            "stop_detail": result.stop_detail,
            "steps": len(result.steps),
            "honesty_note_applied": result.honesty_note_applied,
        },
        session_id=session.id,
        run_id=result.run_id,
        proposals=[AgentProposal(**p) for p in proposals],
        policy_events=policy_events,
        trust={
            "tier": result.trust.tier.value,
            "hits": [
                {"family": h.family, "label": h.label, "preview": h.preview, "snippet_sha256": h.snippet_sha256}
                for h in result.trust.hits
            ],
        },
        provider=result.provider,
        model=result.model,
        credential_source=result.credential_source,
        usage=_usage_payload(result.usage),
    )




# ============================================================================
# Chat Session endpoints (persistence)
# ============================================================================


@router.get("/chat/sessions", response_model=ChatSessionListResponse)
async def list_chat_sessions(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    limit: int = Query(50, ge=1, le=200),
    include_archived: bool = Query(False),
):
    """List the current user's chat sessions, newest first."""
    user_id = getattr(current_user, "id", None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    q = select(AgentChatSession).where(AgentChatSession.user_id == user_id)
    if not include_archived:
        q = q.where(AgentChatSession.is_archived == False)  # noqa: E712
    q = q.order_by(AgentChatSession.updated_at.desc()).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return ChatSessionListResponse(
        items=[
            ChatSessionResponse(
                id=s.id, title=s.title, created_at=s.created_at,
                updated_at=s.updated_at, is_archived=s.is_archived,
            ) for s in rows
        ],
        total=len(rows),
    )


@router.post("/chat/sessions", response_model=ChatSessionResponse)
async def create_chat_session(
    body: ChatSessionCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new chat session."""
    user_id = getattr(current_user, "id", None)
    org_id = getattr(current_user, "organization_id", None)
    if not user_id or not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    s = AgentChatSession(
        user_id=user_id, organization_id=org_id, title=body.title or "New chat",
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return ChatSessionResponse(
        id=s.id, title=s.title, created_at=s.created_at,
        updated_at=s.updated_at, is_archived=s.is_archived,
    )


@router.get("/chat/sessions/{session_id}/messages", response_model=ChatMessageListResponse)
async def list_chat_messages(
    session_id: str = Path(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    limit: int = Query(200, ge=1, le=1000),
):
    """List messages in a chat session (oldest first so rendering is straight-forward)."""
    user_id = getattr(current_user, "id", None)
    session = (await db.execute(
        select(AgentChatSession).where(AgentChatSession.id == session_id)
    )).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not your session")
    rows = (await db.execute(
        select(AgentChatMessage)
        .where(AgentChatMessage.session_id == session_id)
        .order_by(AgentChatMessage.created_at.asc())
        .limit(limit)
    )).scalars().all()
    items = []
    for m in rows:
        tc = m.tool_calls
        if tc is not None and not isinstance(tc, list):
            # Stored shape is always a list; defensive unwrap in case legacy rows
            # wrote a dict {"tools_invoked": [...]}
            tc = tc.get("tools_invoked") if isinstance(tc, dict) else None
        items.append(ChatMessageResponse(
            id=m.id, role=m.role, content=m.content, tool_calls=tc,
            created_at=m.created_at,
        ))
    return ChatMessageListResponse(items=items, total=len(items))


@router.delete("/chat/sessions/{session_id}", status_code=204)
async def delete_chat_session(
    session_id: str = Path(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a chat session and all its messages."""
    user_id = getattr(current_user, "id", None)
    session = (await db.execute(
        select(AgentChatSession).where(AgentChatSession.id == session_id)
    )).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not your session")
    await db.delete(session)
    await db.commit()


@router.get("/alerts/{alert_id}/explain", response_model=AlertExplanation)
async def explain_alert(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    alert_id: str = Path(...),
):
    """Get natural language explanation of alert"""
    nl_interface = NaturalLanguageInterface(db)
    explanation = await nl_interface.explain_alert(alert_id)

    return AlertExplanation(
        alert_id=alert_id,
        explanation=explanation,
        risk_assessment="High",
        recommended_actions=[
            "Review login details",
            "Check for lateral movement",
            "Verify account status",
        ],
    )


@router.get("/investigations/{investigation_id}/explain", response_model=InvestigationExplanation)
async def explain_investigation(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get natural language explanation of investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    engine = AgenticSOCEngine(db)
    narrative = await engine.explain_reasoning(investigation_id)
    suggestions = await NaturalLanguageInterface(db).suggest_next_steps(investigation_id)

    return InvestigationExplanation(
        investigation_id=investigation_id,
        title=investigation.title,
        narrative=narrative,
        key_findings=[investigation.findings_summary or ""],
        confidence_score=investigation.confidence_score,
        recommendations=suggestions,
    )


# ============================================================================
# Dashboard Endpoints
# ============================================================================


@router.get("/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get SOC dashboard metrics"""
    # Count agents
    agent_query = select(func.count()).select_from(SOCAgent).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None)
    )
    agent_result = await db.execute(agent_query)
    total_agents = agent_result.scalar() or 0

    # Count investigations
    inv_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None)
    )
    inv_result = await db.execute(inv_query)
    total_investigations = inv_result.scalar() or 0

    # Count by status
    in_progress_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None),
        Investigation.status == InvestigationStatus.REASONING.value,
    )
    in_progress_result = await db.execute(in_progress_query)
    investigations_in_progress = in_progress_result.scalar() or 0

    # Count pending approvals
    approval_query = select(func.count()).select_from(AgentAction).where(
        AgentAction.organization_id == getattr(current_user, "organization_id", None),
        AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value,
    )
    approval_result = await db.execute(approval_query)
    pending_approvals = approval_result.scalar() or 0

    # Count active agents (status != 'paused')
    active_agent_query = select(func.count()).select_from(SOCAgent).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.status != "paused",
    )
    active_agent_result = await db.execute(active_agent_query)
    agents_active = active_agent_result.scalar() or 0

    # Investigations completed in last 24h
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    completed_24h_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None),
        Investigation.status == InvestigationStatus.COMPLETED.value,
        Investigation.updated_at >= cutoff_24h.isoformat(),
    )
    completed_24h_result = await db.execute(completed_24h_query)
    investigations_completed_24h = completed_24h_result.scalar() or 0

    # Average resolution time from agent stats
    avg_time_query = select(func.avg(SOCAgent.avg_resolution_time_minutes)).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.total_investigations > 0,
    )
    avg_time_result = await db.execute(avg_time_query)
    avg_investigation_time = avg_time_result.scalar() or 0.0

    # Overall accuracy from agent stats
    accuracy_query = select(func.avg(SOCAgent.accuracy_score)).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.total_investigations > 0,
    )
    accuracy_result = await db.execute(accuracy_query)
    overall_accuracy = accuracy_result.scalar() or 0.0

    # Overall false positive rate from agent stats
    fpr_query = select(func.avg(SOCAgent.false_positive_rate)).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.total_investigations > 0,
    )
    fpr_result = await db.execute(fpr_query)
    overall_fpr = fpr_result.scalar() or 0.0

    return DashboardMetrics(
        total_agents=total_agents,
        agents_active=agents_active,
        total_investigations=total_investigations,
        investigations_in_progress=investigations_in_progress,
        investigations_completed_24h=investigations_completed_24h,
        avg_investigation_time_minutes=round(float(avg_investigation_time), 1),
        overall_accuracy=round(float(overall_accuracy), 1),
        overall_false_positive_rate=round(float(overall_fpr), 1),
        pending_approvals=pending_approvals,
    )


@router.get("/dashboard/investigation-metrics", response_model=InvestigationMetrics)
async def get_investigation_metrics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get investigation statistics from real database data"""
    org_id = getattr(current_user, "organization_id", None)
    base_filter = Investigation.organization_id == org_id

    # Total investigations
    total_result = await db.execute(
        select(func.count()).select_from(Investigation).where(base_filter)
    )
    total = total_result.scalar() or 0

    # Count by status
    status_result = await db.execute(
        select(Investigation.status, func.count())
        .where(base_filter)
        .group_by(Investigation.status)
    )
    by_status = {row[0]: row[1] for row in status_result.all()}

    # Count by resolution type
    resolution_result = await db.execute(
        select(Investigation.resolution_type, func.count())
        .where(base_filter, Investigation.resolution_type.isnot(None))
        .group_by(Investigation.resolution_type)
    )
    by_resolution = {row[0]: row[1] for row in resolution_result.all()}

    # Count by priority
    priority_result = await db.execute(
        select(Investigation.priority, func.count())
        .where(base_filter)
        .group_by(Investigation.priority)
    )
    by_priority = {row[0]: row[1] for row in priority_result.all()}

    # Average confidence score
    avg_conf_result = await db.execute(
        select(func.avg(Investigation.confidence_score)).where(
            base_filter, Investigation.confidence_score.isnot(None)
        )
    )
    avg_confidence = avg_conf_result.scalar() or 0.0

    # Average resolution time from agents
    avg_time_result = await db.execute(
        select(func.avg(SOCAgent.avg_resolution_time_minutes)).where(
            SOCAgent.organization_id == org_id,
            SOCAgent.total_investigations > 0,
        )
    )
    avg_resolution_time = avg_time_result.scalar() or 0.0

    return InvestigationMetrics(
        total=total,
        by_status=by_status,
        by_resolution=by_resolution,
        by_priority=by_priority,
        avg_confidence_score=round(float(avg_confidence), 1),
        avg_resolution_time_minutes=round(float(avg_resolution_time), 1),
    )


@router.get("/dashboard/accuracy-stats", response_model=AccuracyStats)
async def get_accuracy_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get accuracy and false positive statistics from real database data"""
    org_id = getattr(current_user, "organization_id", None)
    base_filter = Investigation.organization_id == org_id

    # Total investigations
    total_result = await db.execute(
        select(func.count()).select_from(Investigation).where(base_filter)
    )
    total = total_result.scalar() or 0

    # Count by resolution type
    resolution_result = await db.execute(
        select(Investigation.resolution_type, func.count())
        .where(base_filter, Investigation.resolution_type.isnot(None))
        .group_by(Investigation.resolution_type)
    )
    resolution_counts = {row[0]: row[1] for row in resolution_result.all()}

    true_positives = resolution_counts.get("true_positive", 0)
    false_positives = resolution_counts.get("false_positive", 0)
    inconclusive = resolution_counts.get("inconclusive", 0)
    escalated = resolution_counts.get("escalated", 0)

    # Calculate rates
    resolved_total = true_positives + false_positives + inconclusive + escalated
    accuracy_score = (
        round((true_positives / resolved_total) * 100, 1) if resolved_total > 0 else 0.0
    )
    false_positive_rate = (
        round((false_positives / resolved_total) * 100, 1) if resolved_total > 0 else 0.0
    )

    return AccuracyStats(
        total_investigations=total,
        true_positives=true_positives,
        false_positives=false_positives,
        inconclusive=inconclusive,
        escalated=escalated,
        accuracy_score=accuracy_score,
        false_positive_rate=false_positive_rate,
    )


# ============================================================================
# Threat Hunting Endpoints
# ============================================================================


@router.post("/threat-hunts", response_model=ThreatHuntResult)
async def start_threat_hunt(
    hunt_request: ThreatHuntRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Run a threat hunt against real platform data.

    Previously returned a fake ``hunt_id=hunt_<timestamp>`` with every
    count set to 0 and ``status=initiated`` — the button claimed a
    hunt started, nothing ran, no Investigation rows were created,
    and the dashboard stayed empty forever.

    Now performs a real, synchronous multi-source hunt:
      1. Resolve the agent (specified or first in org)
      2. Query Alerts (status != resolved, severity high/critical)
      3. Query open IdentityThreats
      4. Query open CredentialLeaks
      5. Query unresolved HuntFindings from the SIEM module
      6. Create a real Investigation row that consolidates the count
         with a reasoning_chain entry per source, confidence scored
         from the cross-source overlap
      7. Return real counts from the aggregation

    Hunt profiles ("credential_theft", "lateral_movement", "exfil",
    "apt", "ransomware", "default") filter which sources are queried.
    """
    import time
    from src.models.alert import Alert
    from src.itdr.models import IdentityThreat
    from src.darkweb.models import CredentialLeak
    try:
        from src.hunting.models import HuntFinding
    except Exception:  # noqa: BLE001
        HuntFinding = None

    org_id = getattr(current_user, "organization_id", None)
    start_t = time.time()

    # Resolve the agent
    agent_id = hunt_request.agent_id
    if not agent_id:
        result = await db.execute(
            select(SOCAgent).where(SOCAgent.organization_id == org_id)
        )
        agent = result.scalars().first()
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No agents available",
            )
        agent_id = agent.id

    profile = (hunt_request.hunt_profile or "default").lower()

    # Source filters by profile
    want_alerts = True
    want_identity = profile in ("credential_theft", "apt", "default")
    want_credentials = profile in ("credential_theft", "exfil", "default")
    want_hunt_findings = profile in ("lateral_movement", "apt", "ransomware", "default")

    reasoning_chain: list[dict] = []
    affected_assets: list[str] = []
    indicators_found = 0
    high_confidence_findings = 0

    # 1. Alerts (tenant-scoped)
    if want_alerts:
        alert_query = select(Alert).where(
            and_(
                Alert.organization_id == org_id,
                Alert.severity.in_(["critical", "high"]),
                Alert.status.in_(["new", "investigating"]),
            )
        )
        alerts = list((await db.execute(alert_query)).scalars().all())
        reasoning_chain.append({
            "source": "alerts",
            "query": "severity in (critical, high), status unresolved",
            "count": len(alerts),
        })
        indicators_found += len(alerts)
        high_confidence_findings += sum(1 for a in alerts if a.severity == "critical")
        for a in alerts[:10]:
            if a.source_ip:
                affected_assets.append(f"ip:{a.source_ip}")
            if getattr(a, "hostname", None):
                affected_assets.append(f"host:{a.hostname}")

    # 2. IdentityThreats
    if want_identity:
        id_query = select(IdentityThreat).where(
            and_(
                IdentityThreat.organization_id == org_id,
                IdentityThreat.status.in_(["detected", "investigating"]),
            )
        )
        threats = list((await db.execute(id_query)).scalars().all())
        reasoning_chain.append({
            "source": "identity_threats",
            "query": "status in (detected, investigating)",
            "count": len(threats),
        })
        indicators_found += len(threats)
        high_confidence_findings += sum(1 for t in threats if t.severity == "critical")

    # 3. CredentialLeaks
    if want_credentials:
        cred_query = select(CredentialLeak).where(
            and_(
                CredentialLeak.organization_id == org_id,
                CredentialLeak.is_remediated == False,  # noqa: E712
            )
        )
        creds = list((await db.execute(cred_query)).scalars().all())
        reasoning_chain.append({
            "source": "credential_leaks",
            "query": "is_remediated=false",
            "count": len(creds),
        })
        indicators_found += len(creds)

    # 4. Hunt findings (SIEM hunting module)
    # NOTE: HuntFinding/HuntSession/HuntHypothesis don't carry organization_id
    # directly — they're scoped via the users.created_by chain. To keep this
    # tenant-safe we scope HuntFindings via HuntSession.created_by being a
    # member of the caller's org.
    if want_hunt_findings and HuntFinding is not None:
        try:
            from src.hunting.models import HuntSession
            from src.models.user import User as _User

            org_user_subq = select(_User.id).where(_User.organization_id == org_id)
            hf_query = (
                select(HuntFinding)
                .join(HuntSession, HuntSession.id == HuntFinding.session_id)
                .where(
                    and_(
                        HuntFinding.severity.in_(["critical", "high"]),
                        HuntSession.created_by.in_(org_user_subq),
                    )
                )
            )
            hfs = list((await db.execute(hf_query)).scalars().all())
            reasoning_chain.append({
                "source": "hunt_findings",
                "query": "severity in (critical, high), tenant-scoped via session.created_by",
                "count": len(hfs),
            })
            indicators_found += len(hfs)
            high_confidence_findings += sum(1 for h in hfs if h.severity == "critical")
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"HuntFinding scan failed: {exc}")

    # Confidence: scale by how many sources returned hits
    sources_with_hits = sum(1 for r in reasoning_chain if r["count"] > 0)
    confidence = min(100.0, sources_with_hits * 25.0 + min(indicators_found * 2, 20))

    # Create a real Investigation row documenting the hunt
    from src.agentic.models import InvestigationStatus
    investigation = Investigation(
        agent_id=agent_id,
        organization_id=org_id or "",
        trigger_type="threat_hunt",
        trigger_source_id=None,
        title=f"Threat hunt: {profile}",
        hypothesis=(
            f"Hunt profile '{profile}' looking for active indicators "
            f"across alerts, identity threats, credential leaks, "
            f"and hunt findings."
        ),
        status=(
            InvestigationStatus.COMPLETED.value
            if indicators_found > 0
            else InvestigationStatus.INITIATED.value
        ),
        priority=1 if high_confidence_findings > 0 else 3,
        confidence_score=confidence,
        reasoning_chain=reasoning_chain,
        evidence_collected={
            "sources_scanned": [r["source"] for r in reasoning_chain],
            "total_indicators": indicators_found,
        },
        affected_assets=affected_assets[:20] if affected_assets else None,
        findings_summary=(
            f"Hunt '{profile}' found {indicators_found} indicator(s) "
            f"across {sources_with_hits} source(s), "
            f"{high_confidence_findings} of which are high-confidence."
        ),
    )
    db.add(investigation)
    await db.flush()
    await db.refresh(investigation)

    hunt_id = investigation.id
    elapsed = (time.time() - start_t) / 60.0

    logger.info(
        f"Threat hunt completed: profile={profile} agent={agent_id} "
        f"indicators={indicators_found} high_conf={high_confidence_findings} "
        f"elapsed_min={elapsed:.2f}"
    )

    return ThreatHuntResult(
        hunt_id=hunt_id,
        agent_id=agent_id,
        profile=profile,
        status="completed",
        indicators_found=indicators_found,
        investigations_created=1,
        high_confidence_findings=high_confidence_findings,
        execution_time_minutes=round(elapsed, 2),
        timestamp=datetime.now(timezone.utc),
    )


# ============================================================================
# Memory Management Endpoints
# ============================================================================


@router.get("/agents/{agent_id}/memory", response_model=AgentMemoryListResponse)
async def list_agent_memory(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    memory_type: Optional[str] = None,
):
    """List agent memory entries"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    query = select(AgentMemory).where(AgentMemory.agent_id == agent_id)

    if memory_type:
        query = query.where(AgentMemory.memory_type == memory_type)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(AgentMemory.access_count.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    memories = list(result.scalars().all())

    return AgentMemoryListResponse(
        items=[AgentMemoryResponse.model_validate(m) for m in memories],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/agents/{agent_id}/memory/stats", response_model=MemoryStats)
async def get_memory_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Get agent memory statistics"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    query = select(AgentMemory).where(AgentMemory.agent_id == agent_id)
    result = await db.execute(query)
    memories = list(result.scalars().all())

    by_type = {}
    for memory in memories:
        by_type[memory.memory_type] = by_type.get(memory.memory_type, 0) + 1

    avg_confidence = sum(m.confidence for m in memories) / len(memories) if memories else 0
    high_confidence = len([m for m in memories if m.confidence > 0.7])
    decaying = len([m for m in memories if m.confidence < 0.5])

    return MemoryStats(
        agent_id=agent_id,
        total_memories=len(memories),
        by_type=by_type,
        avg_confidence=avg_confidence,
        memories_decaying=decaying,
        memories_high_confidence=high_confidence,
    )


@router.delete("/agents/{agent_id}/memory")
async def clear_agent_memory(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
    memory_type: Optional[str] = None,
):
    """Clear agent memory (optional filter by type)"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    query = select(AgentMemory).where(AgentMemory.agent_id == agent_id)

    if memory_type:
        query = query.where(AgentMemory.memory_type == memory_type)

    result = await db.execute(query)
    memories = result.scalars().all()

    for memory in memories:
        await db.delete(memory)

    await db.commit()

    return {
        "status": "cleared",
        "memories_deleted": len(memories),
    }
