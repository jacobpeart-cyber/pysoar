"""Shared contracts for the Agentic SOC rebuild.

These dataclasses/protocols are the interfaces the parallel work packages code
against. They are placed verbatim into the repository as:

    src/llm/base.py            (LLMProvider, Message, ContentBlock, ToolCall, ToolSpecForLLM, Usage, LLMTurn, errors)
    src/agentic/context.py     (AgentContext, Mode, Role)
    src/agentic/toolspec.py    (ToolSpec, ParamSpec, Effects, Tier, Target)
    src/agentic/decisions.py   (Decision, PolicyEvent, TrustTier, TrustHit, TrustState)

Nothing here performs I/O. Keep it importable from Celery, tests, and endpoints
without pulling FastAPI or SQLAlchemy sessions in.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Literal, Optional, Protocol

# ---------------------------------------------------------------------------
# src/llm/base.py
# ---------------------------------------------------------------------------

Role = Literal["user", "assistant"]
StopReason = Literal["end_turn", "tool_use", "max_tokens", "refusal", "timeout", "error"]


@dataclass
class TextBlock:
    text: str
    type: Literal["text"] = "text"


@dataclass
class ToolUseBlock:
    id: str            # provider id, or synthesized "name#seq" for Gemini/Ollama
    name: str
    input: dict[str, Any]
    type: Literal["tool_use"] = "tool_use"


@dataclass
class ToolResultBlock:
    tool_use_id: str
    content: str       # already redacted + wrapped by the runtime
    is_error: bool = False
    type: Literal["tool_result"] = "tool_result"


ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock


@dataclass
class Message:
    role: Role
    content: list[ContentBlock]
    # Opaque provider payload for an assistant turn (Anthropic content array incl.
    # thinking blocks; Gemini parts incl. thoughtSignature; OpenAI message incl.
    # tool_calls/reasoning). When present, providers MUST replay it verbatim and
    # never rebuild the assistant turn from `content`.
    provider_native: Any = None


@dataclass
class ToolSpecForLLM:
    name: str
    description: str
    input_schema: dict[str, Any]   # JSON Schema, additionalProperties=false, all required listed
    strict: bool = True


@dataclass
class Usage:
    input_uncached: int = 0
    cache_read: int = 0
    cache_write: int = 0
    output: int = 0
    thinking: int = 0
    estimated: bool = False

    @property
    def total_billable(self) -> int:
        return self.input_uncached + self.cache_read + self.cache_write + self.output + self.thinking


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMTurn:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: StopReason
    usage: Usage
    provider: str
    model: str
    request_id: Optional[str]
    provider_native: Any          # the assistant turn to replay (see Message.provider_native)
    stop_details: Optional[dict[str, Any]] = None   # e.g. refusal category / gemini blockReason


class LLMError(Exception):
    retryable: bool = False
    code: str = "llm_error"

    def __init__(self, message: str, *, request_id: Optional[str] = None, retry_after: Optional[float] = None):
        super().__init__(message)
        self.request_id = request_id
        self.retry_after = retry_after


class LLMAuthError(LLMError):
    code = "llm_auth"


class LLMRateLimitError(LLMError):
    code = "llm_rate_limited"
    retryable = False   # runtime decides: single retry after retry_after in autonomous mode only


class LLMTransientError(LLMError):
    code = "llm_transient"
    retryable = True


class LLMInvalidResponse(LLMError):
    code = "llm_invalid_response"


class LLMNotConfigured(LLMError):
    code = "llm_not_configured"


class LLMQuotaExceeded(LLMError):
    code = "llm_quota_exceeded"


class LLMProvider(Protocol):
    name: str                 # "anthropic" | "gemini" | "openai" | "ollama"
    model: str
    credential_source: Literal["org", "platform"]

    async def __aenter__(self) -> "LLMProvider": ...
    async def __aexit__(self, *exc: Any) -> None: ...

    async def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpecForLLM] | None,
        max_tokens: int,
        response_schema: dict[str, Any] | None = None,   # rejected (ValueError) when tools is non-empty
    ) -> LLMTurn: ...

    async def list_models(self) -> list[str]: ...

    def estimate_input_tokens(self, system: str, messages: list[Message], tools: list[ToolSpecForLLM] | None) -> int: ...


# ---------------------------------------------------------------------------
# src/agentic/context.py
# ---------------------------------------------------------------------------

class Mode(str, Enum):
    INTERACTIVE = "interactive"   # chat / direct tool execute
    AUTONOMOUS = "autonomous"     # Celery investigator: read-only allow-list
    APPROVAL = "approval"         # /actions/{id}/approve executing a proposal


class UserRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


ROLE_RANK = {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}


@dataclass
class AgentContext:
    org_id: str
    role: UserRole
    mode: Mode
    actor_user_id: Optional[str] = None       # set for interactive/approval
    soc_agent_id: Optional[str] = None        # set for autonomous (validated in-org)
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    propose_actions: bool = False             # analyst+: agent may propose destructive actions
    session_id: Optional[str] = None
    investigation_id: Optional[str] = None
    # Approval mode only: the originating run's trust tier + the AgentAction being executed
    origin_trust_tier: Optional["TrustTier"] = None
    approving_action_id: Optional[str] = None
    is_superuser: bool = False
    actor_ip: Optional[str] = None
    deadline_seconds: float = 90.0
    max_steps: int = 6
    max_tokens: int = 8192
    run_token_ceiling: int = 150_000

    def __post_init__(self) -> None:
        if not self.org_id:
            raise ValueError("AgentContext.org_id is required")
        if self.mode is Mode.AUTONOMOUS and not self.soc_agent_id:
            raise ValueError("autonomous mode requires soc_agent_id")
        if self.mode is not Mode.AUTONOMOUS and not self.actor_user_id:
            raise ValueError("interactive/approval mode requires actor_user_id")


# ---------------------------------------------------------------------------
# src/agentic/toolspec.py
# ---------------------------------------------------------------------------

class Tier(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    PRIVILEGED = "privileged"


@dataclass(frozen=True)
class Effects:
    reads_org: bool = True
    writes_org: bool = False
    external: bool = False
    executes_code: bool = False

    @property
    def is_read_only(self) -> bool:
        return not (self.writes_org or self.external or self.executes_code)


@dataclass
class ParamSpec:
    type: Literal["string", "integer", "number", "boolean", "array", "object"]
    description: str
    required: bool = False
    enum: Optional[list[str]] = None
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    max_length: Optional[int] = None
    items: Optional["ParamSpec"] = None            # for arrays
    schema: Optional[dict[str, Any]] = None         # nested object schema (additionalProperties=false)
    ref: Optional[str] = None                       # model name, e.g. "Incident": resolved with _scoped_get
    ref_by_value: Optional[tuple[str, str]] = None  # (model name, column), e.g. ("User", "email")
    ref_list: bool = False                          # array of refs


@dataclass
class Target:
    kind: Literal["host", "ip", "user", "incident", "alert", "asset", "integration", "playbook", "endpoint_agent", "other"]
    value: str
    resolved_id: Optional[str] = None
    provenance: Literal["structured", "untrusted_text", "unknown"] = "unknown"


@dataclass
class ToolSpec:
    name: str
    description: str
    params: dict[str, ParamSpec]
    effects: Effects
    tier: Tier
    min_role: UserRole
    models: tuple[str, ...]                         # every model the handler touches; all must carry organization_id
    handler: Callable[..., Awaitable[Any]]
    category: str = "query"                         # human-facing only; never used for gating
    returns_sensitive: bool = False
    effective_targets: Optional[Callable[[dict[str, Any], Any], Awaitable[list[Target]]]] = None  # required for DESTRUCTIVE/PRIVILEGED

    def to_llm(self) -> ToolSpecForLLM: ...          # implemented in the registry module
    def json_schema(self) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# src/agentic/decisions.py
# ---------------------------------------------------------------------------

class TrustTier(str, Enum):
    CLEAN = "clean"
    FLAGGED = "flagged"
    LOCKDOWN = "lockdown"


@dataclass
class TrustHit:
    family: str
    start: int
    length: int
    snippet_sha256: str
    preview: str          # <= 40 chars, value-redacted
    label: str            # which DATA block, e.g. "alert:1a2b"


@dataclass
class TrustState:
    tier: TrustTier = TrustTier.CLEAN
    hits: list[TrustHit] = field(default_factory=list)
    score: float = 0.0
    contaminated_labels: set[str] = field(default_factory=set)
    first_seen_message_id: Optional[str] = None

    @property
    def lockdown(self) -> bool:
        return self.tier is TrustTier.LOCKDOWN

    @property
    def flagged(self) -> bool:
        return self.tier is not TrustTier.CLEAN


DecisionKind = Literal["allow", "deny", "propose"]

ReasonCode = Literal[
    "ok",
    "invalid_arguments",
    "unknown_tool",
    "role_not_permitted",
    "autonomous_mode_readonly",
    "proposal_disabled",
    "injection_lockdown",
    "cross_tenant_reference",
    "ambiguous_target",
    "value_not_in_org",
    "invalid_target",
    "too_many_targets",
    "rate_limited",
    "audit_unavailable",
]


@dataclass
class Decision:
    kind: DecisionKind
    reason_code: ReasonCode
    tool: str
    tier: Tier
    risk: Literal["info", "low", "medium", "high", "critical"]
    resolved_args: dict[str, Any]            # by-value refs rewritten to in-org ids
    effective_targets: list[Target]
    audit_id: Optional[str] = None           # AuditTrail row id of the pre-decision event
    detail: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.kind == "allow"


@dataclass
class PolicyEvent:
    step: int
    tool: str
    decision: DecisionKind
    reason_code: ReasonCode
    tier: Tier
    audit_id: Optional[str]
    proposal_id: Optional[str] = None       # AgentAction id when kind == "propose"
