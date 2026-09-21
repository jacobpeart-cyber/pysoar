"""LLM provider contracts (verbatim from src/agentic/contracts_reference.py).

Nothing here performs I/O. Keep it importable from Celery, tests, and endpoints
without pulling FastAPI or SQLAlchemy sessions in.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Optional, Protocol

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
