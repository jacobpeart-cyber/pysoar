"""Robust LLM-output JSON parsing.

Provider-agnostic extraction (extract_json) and structured-output orchestration
(request_structured). Pure functions + retry loop. Never returns fake-success
payloads — failures return ParseResult(ok=False, error=...) or raise typed
exceptions (LLMParseError, LLMUnavailableError, LLMTransportError).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


class LLMParseError(Exception):
    """Raised when LLM output cannot be parsed into the expected schema."""

    def __init__(self, message: str, raw: str = ""):
        super().__init__(message)
        self.raw = raw


class LLMUnavailableError(Exception):
    """Raised when an LLM call could not produce a valid structured response
    after all retries — distinct from transport failure."""


class LLMTransportError(Exception):
    """Raised on HTTP/network failure to the LLM provider. Outage, not parse failure."""


@dataclass
class ParseResult:
    ok: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    attempt_log: list[str] = field(default_factory=list)
