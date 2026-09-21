"""Helpers shared by the provider implementations.

Nothing here talks to a network on import. The HTTP client factory is the one
place the fixed transport policy lives: TLS verification on, no environment
proxies/CA overrides (``trust_env=False``), no redirects, bounded timeouts and
zero library-level retries (the runtime owns retry policy).
"""
from __future__ import annotations

import copy
import json
import math
from typing import Any, Final, Optional

import httpx

from src.llm.base import (
    LLMAuthError,
    LLMError,
    LLMInvalidResponse,
    LLMRateLimitError,
    LLMTransientError,
    Message,
    ToolResultBlock,
    ToolSpecForLLM,
    ToolUseBlock,
    TextBlock,
)

# connect / read / write / pool -- identical for every provider (design section 6).
HTTP_TIMEOUT: Final[httpx.Timeout] = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)

# Status codes the runtime may retry once. 408/425/429 handled separately.
_TRANSIENT_STATUS: Final[frozenset[int]] = frozenset({500, 502, 503, 504, 529})

# A conservative characters-per-token ratio used ONLY for reservations and
# for the ``usage_estimated=true`` call-log row written when a provider call
# raises before returning usage. Never presented as measured usage.
CHARS_PER_TOKEN_ESTIMATE: Final[float] = 3.5


def new_http_client(base_url: str, *, headers: Optional[dict[str, str]] = None) -> httpx.AsyncClient:
    """Build the fixed-policy async HTTP client used by the httpx providers."""
    return httpx.AsyncClient(
        base_url=base_url,
        headers=headers or {},
        timeout=HTTP_TIMEOUT,
        verify=True,
        trust_env=False,
        follow_redirects=False,
    )


def encode_json(payload: Any) -> bytes:
    """Canonical UTF-8 JSON bytes; used for ``data_sent_bytes`` and hashing."""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode("utf-8")


def estimate_tokens(system: str, messages: list[Message], tools: list[ToolSpecForLLM] | None) -> int:
    """Character-based token *estimate* for quota reservation.

    Counts the system prompt, every content block (text, tool inputs and
    tool results), any provider-native replay payload and the tool schemas.
    """
    chars = len(system or "")
    for message in messages:
        if message.provider_native is not None:
            chars += len(encode_json(message.provider_native))
            continue
        for block in message.content:
            if isinstance(block, TextBlock):
                chars += len(block.text)
            elif isinstance(block, ToolUseBlock):
                chars += len(block.name) + len(encode_json(block.input))
            elif isinstance(block, ToolResultBlock):
                chars += len(block.content) + len(block.tool_use_id)
    for tool in tools or ():
        chars += len(tool.name) + len(tool.description) + len(encode_json(tool.input_schema))
    return int(math.ceil(chars / CHARS_PER_TOKEN_ESTIMATE))


def retry_after_seconds(headers: httpx.Headers | dict[str, str] | None) -> Optional[float]:
    """Parse a numeric ``Retry-After`` header (seconds); ``None`` when absent/unparseable."""
    if not headers:
        return None
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _error_detail(response: httpx.Response) -> str:
    """Short, non-secret error detail from a provider error body."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or err.get("type") or ""
            return str(msg)[:300]
        if isinstance(err, str):
            return err[:300]
        if isinstance(body.get("message"), str):
            return body["message"][:300]
    return response.text[:200]


def map_http_status(response: httpx.Response, *, provider: str) -> LLMError:
    """Translate a non-2xx provider response into the typed error hierarchy."""
    status = response.status_code
    request_id = (
        response.headers.get("request-id")
        or response.headers.get("x-request-id")
        or response.headers.get("x-goog-request-id")
    )
    detail = _error_detail(response)
    message = f"{provider} HTTP {status}: {detail}"
    if status in (401, 403):
        return LLMAuthError(message, request_id=request_id)
    if status == 429:
        return LLMRateLimitError(message, request_id=request_id, retry_after=retry_after_seconds(response.headers))
    if status in (408, 425) or status in _TRANSIENT_STATUS:
        return LLMTransientError(message, request_id=request_id, retry_after=retry_after_seconds(response.headers))
    return LLMError(message, request_id=request_id)


def map_transport_error(exc: Exception, *, provider: str) -> LLMError:
    """Translate httpx transport failures (timeouts, DNS, TLS, resets) into typed errors."""
    if isinstance(exc, httpx.TimeoutException):
        return LLMTransientError(f"{provider} request timed out: {exc.__class__.__name__}")
    if isinstance(exc, httpx.TransportError):
        return LLMTransientError(f"{provider} transport failure: {exc.__class__.__name__}: {exc}")
    return LLMError(f"{provider} request failed: {exc.__class__.__name__}: {exc}")


def parse_json_response(response: httpx.Response, *, provider: str) -> dict[str, Any]:
    """Decode a 2xx body as a JSON object; anything else is ``LLMInvalidResponse``."""
    try:
        body = response.json()
    except ValueError as exc:
        raise LLMInvalidResponse(f"{provider} returned non-JSON body") from exc
    if not isinstance(body, dict):
        raise LLMInvalidResponse(f"{provider} returned a JSON {type(body).__name__}, expected object")
    return body


def parse_tool_arguments(raw: Any, *, provider: str, name: str) -> dict[str, Any]:
    """Coerce a tool-call argument payload (JSON string or object) into a dict."""
    if raw is None or raw == "":
        return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMInvalidResponse(f"{provider} tool call {name!r} has non-JSON arguments") from exc
    else:
        parsed = raw
    if not isinstance(parsed, dict):
        raise LLMInvalidResponse(f"{provider} tool call {name!r} arguments are not an object")
    return parsed


def strict_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy where every object has ``additionalProperties: false``
    and lists **all** of its properties as required.

    Properties the source schema did not require become nullable (``type``
    gains ``"null"``) so the strict form accepts the same inputs. Applies
    recursively through ``properties``, ``items``, ``anyOf``/``oneOf``/``allOf``
    and ``$defs``.
    """

    def _walk(node: Any) -> Any:
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if not isinstance(node, dict):
            return node
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in ("properties", "$defs", "definitions") and isinstance(value, dict):
                out[key] = {k: _walk(v) for k, v in value.items()}
            elif key in ("items", "additionalProperties") and isinstance(value, dict):
                out[key] = _walk(value)
            elif key in ("anyOf", "oneOf", "allOf") and isinstance(value, list):
                out[key] = [_walk(item) for item in value]
            else:
                out[key] = copy.deepcopy(value)
        node_type = out.get("type")
        is_object = node_type == "object" or (isinstance(node_type, list) and "object" in node_type) or "properties" in out
        if is_object:
            props = out.get("properties")
            if not isinstance(props, dict):
                props = {}
                out["properties"] = props
            previously_required = set(out.get("required") or [])
            for prop_name, prop_schema in props.items():
                if prop_name not in previously_required and isinstance(prop_schema, dict):
                    _make_nullable(prop_schema)
            out["required"] = list(props.keys())
            out["additionalProperties"] = False
        return out

    return _walk(schema)


def _make_nullable(prop: dict[str, Any]) -> None:
    node_type = prop.get("type")
    if isinstance(node_type, str):
        if node_type != "null":
            prop["type"] = [node_type, "null"]
    elif isinstance(node_type, list):
        if "null" not in node_type:
            prop["type"] = [*node_type, "null"]
    elif "anyOf" in prop and isinstance(prop["anyOf"], list):
        if not any(isinstance(alt, dict) and alt.get("type") == "null" for alt in prop["anyOf"]):
            prop["anyOf"] = [*prop["anyOf"], {"type": "null"}]


__all__ = [
    "CHARS_PER_TOKEN_ESTIMATE",
    "HTTP_TIMEOUT",
    "encode_json",
    "estimate_tokens",
    "map_http_status",
    "map_transport_error",
    "new_http_client",
    "parse_json_response",
    "parse_tool_arguments",
    "retry_after_seconds",
    "strict_json_schema",
]
