"""Ollama provider over ``/api/chat`` (async httpx).

Design section 6:

* ``stream: false``, ``keep_alive`` and ``options.num_ctx`` on every call.
* Tool-call ids do not exist in the Ollama wire format; they are synthesized
  as ``name#seq`` and mapped back to ``role: tool`` messages (``tool_name``)
  in call order.
* The response ``message`` object is the ``provider_native`` payload and is
  replayed verbatim.
* A model that "does not support tools" is surfaced as
  ``LLMNotConfigured`` with ``reason == "model_lacks_tools"`` (the settings
  probe shows it); an unknown model is ``LLMNotConfigured`` /
  ``model_not_found``.
* The base URL is platform env only (``settings.ollama_base_url``).
"""
from __future__ import annotations

from typing import Any, Literal, Optional

import httpx

from src.core.logging import get_logger
from src.llm._common import (
    encode_json,
    estimate_tokens,
    map_http_status,
    map_transport_error,
    new_http_client,
    parse_json_response,
    parse_tool_arguments,
)
from src.llm.base import (
    LLMError,
    LLMInvalidResponse,
    LLMNotConfigured,
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
from src.llm.gemini_provider import synthesize_tool_id, tool_name_from_id

logger = get_logger(__name__)

DEFAULT_KEEP_ALIVE = "5m"
DEFAULT_NUM_CTX = 32_768


def _not_configured(message: str, *, reason: str) -> LLMNotConfigured:
    err = LLMNotConfigured(message)
    err.reason = reason  # type: ignore[attr-defined]
    err.source = "platform"  # type: ignore[attr-defined]
    return err


class OllamaProvider:
    """``LLMProvider`` implementation over the Ollama chat API."""

    name: str = "ollama"

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        credential_source: Literal["org", "platform"] = "platform",
        keep_alive: str = DEFAULT_KEEP_ALIVE,
        num_ctx: int = DEFAULT_NUM_CTX,
    ) -> None:
        if not model:
            raise _not_configured("ollama model is not set", reason="model_not_set")
        if not base_url:
            raise _not_configured("ollama base_url is not set", reason="base_url_not_set")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.credential_source = credential_source
        self.keep_alive = keep_alive
        self.num_ctx = int(num_ctx)
        self._client: Optional[httpx.AsyncClient] = None
        self._tool_seq = 0
        self.last_request_bytes: Optional[int] = None
        self.last_request_id: Optional[str] = None

    async def __aenter__(self) -> "OllamaProvider":
        self._client = new_http_client(self.base_url)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("OllamaProvider must be used as an async context manager")
        return self._client

    # -- request building --------------------------------------------------

    @staticmethod
    def _expand_user(message: Message) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        text_parts: list[str] = []
        for block in message.content:
            if isinstance(block, ToolResultBlock):
                out.append({"role": "tool", "tool_name": tool_name_from_id(block.tool_use_id), "content": block.content})
            elif isinstance(block, TextBlock):
                text_parts.append(block.text)
            elif isinstance(block, ToolUseBlock):
                raise ValueError("tool_use blocks are only valid in assistant messages")
        if text_parts or not out:
            out.append({"role": "user", "content": "".join(text_parts)})
        return out

    @staticmethod
    def _assistant(message: Message) -> dict[str, Any]:
        if message.provider_native is not None:
            return message.provider_native
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in message.content:
            if isinstance(block, TextBlock):
                text_parts.append(block.text)
            elif isinstance(block, ToolUseBlock):
                tool_calls.append({"function": {"name": block.name, "arguments": block.input}})
            elif isinstance(block, ToolResultBlock):
                raise ValueError("tool_result blocks are only valid in user messages")
        msg: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts)}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        return msg

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
        native: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for message in messages:
            if message.role == "user":
                native.extend(self._expand_user(message))
            elif message.role == "assistant":
                native.append(self._assistant(message))
            else:
                raise ValueError(f"unsupported message role {message.role!r}")
        body: dict[str, Any] = {
            "model": self.model,
            "messages": native,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {"num_ctx": self.num_ctx, "num_predict": int(max_tokens)},
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {"name": t.name, "description": t.description, "parameters": t.input_schema},
                }
                for t in tools
            ]
        elif response_schema is not None:
            body["format"] = response_schema
        return body

    # -- response parsing --------------------------------------------------

    @staticmethod
    def _usage(body: dict[str, Any]) -> Usage:
        prompt = int(body.get("prompt_eval_count") or 0)
        output = int(body.get("eval_count") or 0)
        return Usage(input_uncached=prompt, output=output)

    def parse_response(self, body: dict[str, Any]) -> LLMTurn:
        message = body.get("message")
        if not isinstance(message, dict):
            raise LLMInvalidResponse("ollama response has no message")
        tool_calls: list[ToolCall] = []
        for raw_call in message.get("tool_calls") or []:
            if not isinstance(raw_call, dict):
                raise LLMInvalidResponse("ollama tool_call is not an object")
            fn = raw_call.get("function")
            if not isinstance(fn, dict) or not fn.get("name"):
                raise LLMInvalidResponse("ollama tool_call missing function name")
            name = str(fn["name"])
            self._tool_seq += 1
            tool_calls.append(
                ToolCall(
                    id=synthesize_tool_id(name, self._tool_seq),
                    name=name,
                    input=parse_tool_arguments(fn.get("arguments"), provider=self.name, name=name),
                )
            )
        content = message.get("content")
        text = content if isinstance(content, str) else ""
        done_reason = str(body.get("done_reason") or "")
        stop_details: Optional[dict[str, Any]] = None
        stop_reason: StopReason
        if done_reason == "stop" or (done_reason == "" and body.get("done") is True):
            stop_reason = "tool_use" if tool_calls else "end_turn"
        elif done_reason == "length":
            stop_reason = "max_tokens"
        else:
            stop_reason = "error"
            stop_details = {"done_reason": done_reason or "missing"}
            tool_calls = []
        return LLMTurn(
            text=text,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=self._usage(body),
            provider=self.name,
            model=str(body.get("model") or self.model),
            request_id=None,
            provider_native=message,
            stop_details=stop_details,
        )

    # -- LLMProvider -------------------------------------------------------

    def _map_error(self, response: httpx.Response) -> LLMError:
        detail = ""
        try:
            parsed = response.json()
            if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
                detail = parsed["error"]
        except ValueError:
            detail = response.text[:200]
        lowered = detail.lower()
        if "does not support tools" in lowered:
            return _not_configured(f"ollama model {self.model!r} does not support tools", reason="model_lacks_tools")
        if response.status_code == 404 or "not found" in lowered:
            return _not_configured(f"ollama model {self.model!r} not found: {detail}", reason="model_not_found")
        return map_http_status(response, provider=self.name)

    async def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpecForLLM] | None,
        max_tokens: int,
        response_schema: dict[str, Any] | None = None,
    ) -> LLMTurn:
        body = self.build_request(
            system=system, messages=messages, tools=tools, max_tokens=max_tokens, response_schema=response_schema
        )
        payload = encode_json(body)
        self.last_request_bytes = len(payload)
        try:
            response = await self.client.post("/api/chat", content=payload, headers={"content-type": "application/json"})
        except httpx.HTTPError as exc:
            raise map_transport_error(exc, provider=self.name) from exc
        if response.status_code >= 400:
            raise self._map_error(response)
        return self.parse_response(parse_json_response(response, provider=self.name))

    async def list_models(self) -> list[str]:
        try:
            response = await self.client.get("/api/tags")
        except httpx.HTTPError as exc:
            raise map_transport_error(exc, provider=self.name) from exc
        if response.status_code >= 400:
            raise self._map_error(response)
        body = parse_json_response(response, provider=self.name)
        models = body.get("models")
        if not isinstance(models, list):
            raise LLMInvalidResponse("ollama /api/tags response has no models list")
        return [str(m["name"]) for m in models if isinstance(m, dict) and m.get("name")]

    def estimate_input_tokens(self, system: str, messages: list[Message], tools: list[ToolSpecForLLM] | None) -> int:
        return estimate_tokens(system, messages, tools)


__all__ = ["DEFAULT_KEEP_ALIVE", "DEFAULT_NUM_CTX", "OllamaProvider"]
