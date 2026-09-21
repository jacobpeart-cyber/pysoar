"""Provider-agnostic LLM layer (see docs/agentic-soc-rebuild-design.md section 6).

Public surface:

* :mod:`src.llm.base` -- contracts (``LLMProvider``, ``Message``, ``LLMTurn``,
  ``Usage``, typed errors). Import these; never a provider's private types.
* :func:`src.llm.factory.resolve_llm` -- org-authoritative provider resolution.
* :class:`src.llm.quota.TokenQuota` -- reserve/settle budgets, admission, breaker.
* :class:`src.llm.calllog.LLMCallLogWriter` -- one ``llm_call_logs`` row per call.

Provider modules are imported lazily by the factory so importing this package
never pulls the Anthropic SDK or opens a client.
"""
from src.llm.base import (
    ContentBlock,
    LLMAuthError,
    LLMError,
    LLMInvalidResponse,
    LLMNotConfigured,
    LLMProvider,
    LLMQuotaExceeded,
    LLMRateLimitError,
    LLMTransientError,
    LLMTurn,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolResultBlock,
    ToolSpecForLLM,
    ToolUseBlock,
    Usage,
)

__all__ = [
    "ContentBlock",
    "LLMAuthError",
    "LLMError",
    "LLMInvalidResponse",
    "LLMNotConfigured",
    "LLMProvider",
    "LLMQuotaExceeded",
    "LLMRateLimitError",
    "LLMTransientError",
    "LLMTurn",
    "Message",
    "StopReason",
    "TextBlock",
    "ToolCall",
    "ToolResultBlock",
    "ToolSpecForLLM",
    "ToolUseBlock",
    "Usage",
]
