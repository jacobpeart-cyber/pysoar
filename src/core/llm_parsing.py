"""Robust LLM-output JSON parsing.

Provider-agnostic extraction (extract_json) and structured-output orchestration
(request_structured). Pure functions + retry loop. Never returns fake-success
payloads — failures return ParseResult(ok=False, error=...) or raise typed
exceptions (LLMParseError, LLMUnavailableError, LLMTransportError).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from src.core.exceptions import PySOARException


class LLMParseError(PySOARException):
    """Raised when LLM output cannot be parsed into the expected schema.

    The raw LLM text is stored in details["raw"] for debugging."""

    def __init__(self, message: str, raw: str = ""):
        super().__init__(message=message, details={"raw": raw})

    @property
    def raw(self) -> str:
        return self.details.get("raw", "")


class LLMUnavailableError(PySOARException):
    """Raised when an LLM call could not produce a valid structured response
    after all retries — distinct from transport failure."""


class LLMTransportError(PySOARException):
    """Raised on HTTP/network failure to the LLM provider. Outage, not parse failure."""


@dataclass
class ParseResult:
    """Outcome of an LLM-output parse attempt.

    Fields:
        ok: True iff a valid parsed value is in `data`. Callers MUST verify
            `data is not None` when consuming `ok=True` results — constructing
            `ParseResult(ok=True)` with no data is a programming error, not a
            valid success state.
        data: The parsed and (optionally) schema-validated payload. None when ok=False.
        error: Human-readable failure description; suitable for feeding back to the
            LLM on retry. None when ok=True.
        attempt_log: Diagnostic trail of which extraction strategies were tried.
    """
    ok: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    attempt_log: list[str] = field(default_factory=list)
