"""Anthropic Messages API provider (official ``anthropic`` SDK 1.7.x).

Design section 6:

* ``AsyncAnthropic(api_key=<explicit>, max_retries=0, timeout=Timeout(...))``;
  the key must be supplied (never ambient ``ANTHROPIC_API_KEY``).
* ``thinking`` is omitted entirely; ``tool_choice`` is never forced.
* Tools are sent with ``strict: true``; content blocks are parsed by ``type``.
* ``stop_reason`` map: ``end_turn``, ``tool_use``, ``max_tokens``, ``refusal``
  (+ ``stop_details``), ``pause_turn`` / ``model_context_window_exceeded`` /
  unknown -> ``error``.
* ``provider_native`` is the response ``content`` array (JSON form, fields
  exactly as the API set them) and is replayed verbatim on later turns so
  ``thinking`` / ``redacted_thinking`` blocks survive.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

import anthropic

from src.core.logging import get_logger
from src.llm._common import encode_json, estimate_tokens, retry_after_seconds
from src.llm.base import (
    LLMAuthError,
    LLMError,
    LLMInvalidResponse,
    LLMNotConfigured,
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

logger = get_logger(__name__)

# Fixed host: tenants supply keys only (design section 6). The SDK default is
# https://api.anthropic.com; we pass it explicitly so an ambient
# ANTHROPIC_BASE_URL can never redirect traffic.
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_TIMEOUT = anthropic.Timeout(connect=5, read=60, write=10, pool=5)

_STOP_REASON_MAP: dict[str, StopReason] = {
    "end_turn": "end_turn",
    "stop_sequence": "end_turn",
    "tool_use": "tool_use",
    "max_tokens": "max_tokens",
    "refusal": "refusal",
    # No server tools are ever attached, so a paused turn cannot be continued
    # meaningfully; both of these are surfaced as an honest error turn.
    "pause_turn": "error",
    "model_context_window_exceeded": "error",
}


class AnthropicProvider:
    """``LLMProvider`` implementation over ``anthropic.AsyncAnthropic``."""

    name: str = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        credential_source: Literal["org", "platform"],
    ) -> None:
        if not api_key:
            raise LLMNotConfigured("anthropic api_key is empty")
        if not model:
            raise LLMNotConfigured("anthropic model is not set")
        self._api_key = api_key
        self.model = model
        self.credential_source = credential_source
        self._client: Optional[anthropic.AsyncAnthropic] = None
        self.last_request_bytes: Optional[int] = None
        self.last_request_id: Optional[str] = None

    # -- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> "AnthropicProvider":
        # The SDK client is created inside the running loop so two providers
        # across two asyncio.run() calls never share a connection pool.
        self._client = anthropic.AsyncAnthropic(
            api_key=self._api_key,
            base_url=ANTHROPIC_BASE_URL,
            max_retries=0,
            timeout=ANTHROPIC_TIMEOUT,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.close()

    @property
    def client(self) -> anthropic.AsyncAnthropic:
        if self._client is None:
            raise RuntimeError("AnthropicProvider must be used as an async context manager")
        return self._client

    # -- request building --------------------------------------------------

    @staticmethod
    def _tool_param(tool: ToolSpecForLLM) -> dict[str, Any]:
        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "strict": bool(tool.strict),
        }

    @staticmethod
    def _user_content(message: Message) -> list[dict[str, Any]]:
        parts: list[dict[str, Any]] = []
        for block in message.content:
            if isinstance(block, TextBlock):
                parts.append({"type": "text", "text": block.text})
            elif isinstance(block, ToolResultBlock):
                parts.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.tool_use_id,
                        "content": block.content,
                        "is_error": bool(block.is_error),
                    }
                )
            elif isinstance(block, ToolUseBlock):
                raise ValueError("tool_use blocks are only valid in assistant messages")
        return parts

    @staticmethod
    def _assistant_content(message: Message) -> Any:
        if message.provider_native is not None:
            # Verbatim replay: never rebuilt from `content`.
            return message.provider_native
        parts: list[dict[str, Any]] = []
        for block in message.content:
            if isinstance(block, TextBlock):
                parts.append({"type": "text", "text": block.text})
            elif isinstance(block, ToolUseBlock):
                parts.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
            elif isinstance(block, ToolResultBlock):
                raise ValueError("tool_result blocks are only valid in user messages")
        return parts

    def build_request(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpecForLLM] | None,
        max_tokens: int,
        response_schema: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if tools and response_schema is not None:
            raise ValueError("response_schema cannot be combined with tools")
        native_messages: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "user":
                native_messages.append({"role": "user", "content": self._user_content(message)})
            elif message.role == "assistant":
                native_messages.append({"role": "assistant", "content": self._assistant_content(message)})
            else:
                raise ValueError(f"unsupported message role {message.role!r}")
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": int(max_tokens),
            "system": system,
            "messages": native_messages,
        }
        if tools:
            params["tools"] = [self._tool_param(t) for t in tools]
        if response_schema is not None:
            params["output_config"] = {"format": {"type": "json_schema", "schema": response_schema}}
        return params

    # -- response parsing --------------------------------------------------

    @staticmethod
    def _usage(raw: Any) -> Usage:
        input_tokens = int(getattr(raw, "input_tokens", 0) or 0)
        output_tokens = int(getattr(raw, "output_tokens", 0) or 0)
        cache_read = int(getattr(raw, "cache_read_input_tokens", 0) or 0)
        cache_write = int(getattr(raw, "cache_creation_input_tokens", 0) or 0)
        details = getattr(raw, "output_tokens_details", None)
        thinking = int(getattr(details, "thinking_tokens", 0) or 0) if details is not None else 0
        thinking = min(thinking, output_tokens)
        return Usage(
            input_uncached=input_tokens,
            cache_read=cache_read,
            cache_write=cache_write,
            output=output_tokens - thinking,
            thinking=thinking,
        )

    @staticmethod
    def _native_block(block: Any) -> Any:
        dump = getattr(block, "model_dump", None)
        if callable(dump):
            return dump(mode="json", exclude_unset=True)
        if isinstance(block, dict):
            return block
        raise LLMInvalidResponse(f"anthropic content block of unexpected type {type(block).__name__}")

    def parse_response(self, response: Any) -> LLMTurn:
        content = getattr(response, "content", None)
        if not isinstance(content, list):
            raise LLMInvalidResponse("anthropic response has no content array")
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        native: list[Any] = []
        for block in content:
            block_type = getattr(block, "type", None) if not isinstance(block, dict) else block.get("type")
            native.append(self._native_block(block))
            if block_type == "text":
                text_parts.append(str(getattr(block, "text", "") if not isinstance(block, dict) else block.get("text", "")))
            elif block_type == "tool_use":
                if isinstance(block, dict):
                    tool_id, tool_name, tool_input = block.get("id"), block.get("name"), block.get("input")
                else:
                    tool_id, tool_name, tool_input = block.id, block.name, block.input
                if not tool_id or not tool_name:
                    raise LLMInvalidResponse("anthropic tool_use block missing id or name")
                if not isinstance(tool_input, dict):
                    raise LLMInvalidResponse(f"anthropic tool_use {tool_name!r} input is not an object")
                tool_calls.append(ToolCall(id=str(tool_id), name=str(tool_name), input=tool_input))
            # thinking / redacted_thinking / anything else: preserved in
            # `native` for replay, never interpreted.

        raw_stop = getattr(response, "stop_reason", None)
        stop_reason: StopReason = _STOP_REASON_MAP.get(str(raw_stop), "error")
        stop_details: Optional[dict[str, Any]] = None
        if stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            stop_details = {
                "category": getattr(details, "category", None) if details is not None else None,
                "explanation": getattr(details, "explanation", None) if details is not None else None,
            }
        elif stop_reason == "error":
            stop_details = {"provider_stop_reason": raw_stop}
        if stop_reason == "tool_use" and not tool_calls:
            raise LLMInvalidResponse("anthropic stop_reason=tool_use without any tool_use block")

        request_id = getattr(response, "_request_id", None)
        self.last_request_id = request_id
        return LLMTurn(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=self._usage(getattr(response, "usage", None)),
            provider=self.name,
            model=str(getattr(response, "model", self.model) or self.model),
            request_id=request_id,
            provider_native=native,
            stop_details=stop_details,
        )

    # -- errors ------------------------------------------------------------

    @staticmethod
    def _map_error(exc: Exception) -> LLMError:
        if isinstance(exc, anthropic.APIStatusError):
            request_id = getattr(exc, "request_id", None)
            headers = getattr(getattr(exc, "response", None), "headers", None)
            retry_after = retry_after_seconds(headers)
            status = exc.status_code
            detail = f"anthropic HTTP {status}: {exc.message}"
            if isinstance(exc, (anthropic.AuthenticationError, anthropic.PermissionDeniedError)):
                return LLMAuthError(detail, request_id=request_id)
            if isinstance(exc, anthropic.RateLimitError):
                return LLMRateLimitError(detail, request_id=request_id, retry_after=retry_after)
            if isinstance(exc, anthropic.NotFoundError):
                return LLMNotConfigured(detail, request_id=request_id)
            if status in (408, 425) or status >= 500:
                return LLMTransientError(detail, request_id=request_id, retry_after=retry_after)
            return LLMError(detail, request_id=request_id)
        if isinstance(exc, anthropic.APIConnectionError):
            return LLMTransientError(f"anthropic connection failure: {exc.__class__.__name__}")
        if isinstance(exc, anthropic.APIResponseValidationError):
            return LLMInvalidResponse(f"anthropic response failed SDK validation: {exc}")
        if isinstance(exc, anthropic.AnthropicError):
            return LLMError(f"anthropic SDK error: {exc.__class__.__name__}: {exc}")
        return LLMError(f"anthropic call failed: {exc.__class__.__name__}: {exc}")

    # -- LLMProvider -------------------------------------------------------

    async def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpecForLLM] | None,
        max_tokens: int,
        response_schema: dict[str, Any] | None = None,
    ) -> LLMTurn:
        params = self.build_request(
            system=system, messages=messages, tools=tools, max_tokens=max_tokens, response_schema=response_schema
        )
        self.last_request_bytes = len(encode_json(params))
        try:
            response = await self.client.messages.create(**params)
        except LLMError:
            raise
        except Exception as exc:  # noqa: BLE001 - every SDK failure is re-typed
            raise self._map_error(exc) from exc
        return self.parse_response(response)

    async def list_models(self) -> list[str]:
        ids: list[str] = []
        try:
            page = await self.client.models.list(limit=100)
            for info in getattr(page, "data", []) or []:
                model_id = getattr(info, "id", None)
                if model_id:
                    ids.append(str(model_id))
            while getattr(page, "has_more", False) and hasattr(page, "get_next_page"):
                page = await page.get_next_page()
                for info in getattr(page, "data", []) or []:
                    model_id = getattr(info, "id", None)
                    if model_id:
                        ids.append(str(model_id))
        except LLMError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise self._map_error(exc) from exc
        return ids

    async def capability_snapshot(self) -> dict[str, Any]:
        """``client.models.retrieve(model)`` as a plain dict (callers cache it)."""
        try:
            info = await self.client.models.retrieve(self.model)
        except LLMError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise self._map_error(exc) from exc
        dump = getattr(info, "model_dump", None)
        if callable(dump):
            return dump(mode="json")
        raise LLMInvalidResponse("anthropic models.retrieve returned an unexpected object")

    def estimate_input_tokens(self, system: str, messages: list[Message], tools: list[ToolSpecForLLM] | None) -> int:
        return estimate_tokens(system, messages, tools)


__all__ = ["ANTHROPIC_BASE_URL", "ANTHROPIC_TIMEOUT", "AnthropicProvider"]
