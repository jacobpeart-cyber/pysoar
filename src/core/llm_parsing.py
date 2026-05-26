"""Robust LLM-output JSON parsing.

Provider-agnostic extraction (extract_json) and structured-output orchestration
(request_structured). Pure functions + retry loop. Never returns fake-success
payloads — failures return ParseResult(ok=False, error=...) or raise typed
exceptions (LLMParseError, LLMUnavailableError, LLMTransportError).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

import json_repair
from pydantic import BaseModel, ValidationError

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


def _balanced_brace_extract(text: str, start: int) -> Optional[str]:
    """Given text[start] == '{', return the substring through the matching '}'.

    Returns None if start is past end, start char isn't '{', or braces never
    balance. Handles strings: braces inside double-quoted strings (with
    backslash escapes) do not affect nesting depth.
    """
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


_BARE_OBJ_START_RE = re.compile(r'\{\s*"\w+"\s*:')


def _try_bare_object(text: str) -> Optional[str]:
    """Find first {"key": ...} object in the text, brace-balanced. Returns the
    JSON substring or None if no object-shaped pattern found."""
    match = _BARE_OBJ_START_RE.search(text)
    if not match:
        return None
    return _balanced_brace_extract(text, match.start())


_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)


def _try_fenced_block(text: str) -> Optional[str]:
    """Extract the JSON object body from a ```json ... ``` (or bare ```) fenced
    block. Uses balanced-brace scan inside the fence — NOT lazy regex (which
    truncates on nested objects). Returns the first parseable candidate
    across all fences, or None if no fence yields one."""
    for match in _FENCE_RE.finditer(text):
        body = match.group(1).strip()
        first_brace = body.find("{")
        if first_brace < 0:
            continue
        candidate = _balanced_brace_extract(body, first_brace)
        if candidate is None:
            continue
        # Quick parseability check so we skip fences that look JSON-ish but aren't
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            continue
    return None


def extract_json(text: str, schema: Optional[type[BaseModel]] = None) -> ParseResult:
    """Extract a JSON object from raw LLM text. Optionally validate against a
    Pydantic schema.

    Strategy ladder: fenced block (added in Task 5) -> bare object -> json.loads
    -> json_repair.loads (added in Task 6) -> schema validate (added in Task 7).
    First strategy yielding a parsed dict wins.

    Returns ParseResult(ok=False, error=...) on any failure — never raises,
    never returns a hardcoded success-shaped payload.
    """
    log: list[str] = []
    if not text:
        return ParseResult(ok=False, error="empty input", attempt_log=["empty"])

    # Check if input starts with array (reject top-level arrays)
    stripped = text.lstrip()
    if stripped.startswith("["):
        return ParseResult(
            ok=False,
            error="no JSON object found in text",
            attempt_log=["no_object"],
        )

    candidate: Optional[str] = None

    fenced = _try_fenced_block(text)
    if fenced is not None:
        candidate = fenced
        log.append("fenced_block")
    else:
        bare = _try_bare_object(text)
        if bare is not None:
            candidate = bare
            log.append("bare_object")

    if candidate is None:
        # Last-resort: try the very first '{' in the text, even without the
        # key-shape signature. json_repair downstream will tell us if it's
        # garbage. Avoids missing smart-quoted or otherwise non-standard
        # objects that the key regex won't match.
        first_brace = text.find("{")
        if first_brace >= 0:
            last_resort = _balanced_brace_extract(text, first_brace)
            if last_resort is not None:
                candidate = last_resort
                log.append("first_brace_fallback")

    if candidate is None:
        return ParseResult(
            ok=False,
            error="no JSON object found in text",
            attempt_log=log + ["no_object"],
        )

    parsed: Optional[Any] = None
    try:
        parsed = json.loads(candidate)
        log.append("json.loads")
    except json.JSONDecodeError:
        try:
            parsed = json_repair.loads(candidate)
            log.append("json_repair")
        except Exception as exc:  # noqa: BLE001
            return ParseResult(
                ok=False,
                error=f"JSON parse failed even with json_repair: {exc}",
                attempt_log=log + ["json_repair_fail"],
            )

    if not isinstance(parsed, dict):
        return ParseResult(
            ok=False,
            error=f"parsed value is {type(parsed).__name__}, expected object",
            attempt_log=log + ["not_object"],
        )

    if schema is not None:
        try:
            validated = schema.model_validate(parsed)
            return ParseResult(ok=True, data=validated, attempt_log=log + ["schema_ok"])
        except ValidationError as exc:
            return ParseResult(
                ok=False,
                error=str(exc),
                attempt_log=log + ["schema_fail"],
            )

    return ParseResult(ok=True, data=parsed, attempt_log=log)


class StructuredProvider(Protocol):
    """Interface request_structured uses to call the underlying LLM.

    Implementations are responsible for using their native structured-output
    mode where available (Gemini response_mime_type, Anthropic tool_use shim,
    OpenAI response_format) and for falling back to prompt-enforced JSON where
    not. They MUST raise LLMTransportError on HTTP/network failure, not
    return a fake response.
    """

    async def acomplete_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
        tools: Optional[list[dict]] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        """Return the raw LLM text. The caller will extract JSON from it."""
        ...


async def request_structured(
    provider: StructuredProvider,
    *,
    system_prompt: str,
    user_prompt: str,
    schema: type[BaseModel],
    retries: int = 2,
    tools: Optional[list[dict]] = None,
    history: Optional[list[dict]] = None,
) -> ParseResult:
    """LLM-call orchestrator. Calls provider.acomplete_structured, runs the
    response through extract_json(schema=...), returns the ParseResult.

    Retry loop is added in Task 9; this initial version is single-attempt.

    Transport failures (LLMTransportError) propagate — they are outages, not
    parse failures. NEVER returns a hardcoded success-shaped payload.
    """
    raw = await provider.acomplete_structured(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        schema=schema,
        tools=tools,
        history=history,
    )
    return extract_json(raw, schema)
