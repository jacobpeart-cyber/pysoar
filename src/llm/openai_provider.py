"""OpenAI Chat Completions provider (async httpx, no SDK).

Design section 6:

* ``POST {base}/chat/completions`` with ``tools`` (``type: function``,
  ``strict: true``); schemas are made strict recursively (all properties
  required, ``additionalProperties: false``).
* One runtime ``user`` message holding several ``tool_result`` blocks is
  expanded into ordered ``role: tool`` messages keyed by ``tool_call_id``,
  followed by a ``user`` text message when the block also carries text.
* The response ``message`` object is the ``provider_native`` payload and is
  replayed verbatim (``tool_calls``, ``reasoning`` fields survive).
* ``finish_reason`` map: ``stop``/``tool_calls`` -> ``end_turn``/``tool_use``;
  ``length`` -> ``max_tokens``; ``content_filter`` or ``message.refusal`` ->
  ``refusal``; anything else -> ``error``.
* The model must be configured explicitly; ``list_models`` uses ``/models``.
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
    strict_json_schema,
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

logger = get_logger(__name__)

OPENAI_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider:
    """``LLMProvider`` implementation over the Chat Completions API."""

    name: str = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        credential_source: Literal["org", "platform"],
        base_url: Optional[str] = None,
    ) -> None:
        if not api_key:
            raise LLMNotConfigured("openai api_key is empty")
        if not model:
            raise LLMNotConfigured("openai model is not set")
        self._api_key = api_key
        self.model = model
        self.credential_source = credential_source
        # Platform env only (design section 6): the factory passes
        # settings.openai_base_url; tenants can never set this.
        self.base_url = (base_url or OPENAI_BASE_URL).rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None
        self.last_request_bytes: Optional[int] = None
        self.last_request_id: Optional[str] = None

    async def __aenter__(self) -> "OpenAIProvider":
        self._client = new_http_client(self.base_url, headers={"authorization": f"Bearer {self._api_key}"})
        return self

    async def __aexit__(self, *exc: Any) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("OpenAIProvider must be used as an async context manager")
        return self._client

    # -- request building --------------------------------------------------

    @staticmethod
    def _expand_user(message: Message) -> list[dict[str, Any]]:
        """tool_result blocks -> ordered ``tool`` messages; text -> one ``user`` message."""
        out: list[dict[str, Any]] = []
        text_parts: list[str] = []
        for block in message.content:
            if isinstance(block, ToolResultBlock):
                out.append({"role": "tool", "tool_call_id": block.tool_use_id, "content": block.content})
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
                tool_calls.append(
                    {
                        "id": block.id,
                        "type": "function",
                        "function": {"name": block.name, "arguments": encode_json(block.input).decode("utf-8")},
                    }
                )
            elif isinstance(block, ToolResultBlock):
                raise ValueError("tool_result blocks are only valid in user messages")
        msg: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts) or None}
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
        body: dict[str, Any] = {"model": self.model, "messages": native, "stream": False}
        # api.openai.com deprecated `max_tokens` in favour of
        # `max_completion_tokens`; OpenAI-compatible servers mostly only know
        # the older name.
        if self.base_url == OPENAI_BASE_URL:
            body["max_completion_tokens"] = int(max_tokens)
        else:
            body["max_tokens"] = int(max_tokens)
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": strict_json_schema(t.input_schema) if t.strict else t.input_schema,
                        "strict": bool(t.strict),
                    },
                }
                for t in tools
            ]
            body["parallel_tool_calls"] = True
        elif response_schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": strict_json_schema(response_schema), "strict": True},
            }
        return body

    # -- response parsing --------------------------------------------------

    @staticmethod
    def _usage(raw: Any) -> Usage:
        if not isinstance(raw, dict):
            return Usage()
        prompt = int(raw.get("prompt_tokens") or 0)
        completion = int(raw.get("completion_tokens") or 0)
        prompt_details = raw.get("prompt_tokens_details") or {}
        completion_details = raw.get("completion_tokens_details") or {}
        cached = int(prompt_details.get("cached_tokens") or 0) if isinstance(prompt_details, dict) else 0
        reasoning = int(completion_details.get("reasoning_tokens") or 0) if isinstance(completion_details, dict) else 0
        reasoning = min(reasoning, completion)
        return Usage(
            input_uncached=max(prompt - cached, 0),
            cache_read=cached,
            cache_write=0,
            output=completion - reasoning,
            thinking=reasoning,
        )

    def parse_response(self, body: dict[str, Any], *, request_id: Optional[str]) -> LLMTurn:
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMInvalidResponse("openai response has no choices")
        choice = choices[0]
        if not isinstance(choice, dict):
            raise LLMInvalidResponse("openai choice is not an object")
        message = choice.get("message")
        if not isinstance(message, dict):
            raise LLMInvalidResponse("openai choice has no message")

        tool_calls: list[ToolCall] = []
        for raw_call in message.get("tool_calls") or []:
            if not isinstance(raw_call, dict):
                raise LLMInvalidResponse("openai tool_call is not an object")
            fn = raw_call.get("function") or {}
            call_id = raw_call.get("id")
            name = fn.get("name") if isinstance(fn, dict) else None
            if not call_id or not name:
                raise LLMInvalidResponse("openai tool_call missing id or function name")
            tool_calls.append(
                ToolCall(
                    id=str(call_id),
                    name=str(name),
                    input=parse_tool_arguments(fn.get("arguments"), provider=self.name, name=str(name)),
                )
            )

        content = message.get("content")
        text = content if isinstance(content, str) else ""
        refusal = message.get("refusal")
        finish = str(choice.get("finish_reason") or "")
        stop_details: Optional[dict[str, Any]] = None
        stop_reason: StopReason
        if refusal:
            stop_reason = "refusal"
            stop_details = {"refusal": str(refusal)[:500], "finish_reason": finish}
            tool_calls = []
        elif finish == "content_filter":
            stop_reason = "refusal"
            stop_details = {"finish_reason": finish}
            tool_calls = []
        elif finish in ("stop", "tool_calls", "function_call"):
            stop_reason = "tool_use" if tool_calls else "end_turn"
        elif finish == "length":
            stop_reason = "max_tokens"
        else:
            stop_reason = "error"
            stop_details = {"finish_reason": finish or "missing"}
            tool_calls = []

        return LLMTurn(
            text=text,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=self._usage(body.get("usage")),
            provider=self.name,
            model=str(body.get("model") or self.model),
            request_id=request_id,
            provider_native=message,
            stop_details=stop_details,
        )

    # -- LLMProvider -------------------------------------------------------

    def _map_error(self, response: httpx.Response) -> LLMError:
        err = map_http_status(response, provider=self.name)
        if response.status_code == 404 and "model" in str(err).lower():
            return LLMNotConfigured(str(err), request_id=err.request_id)
        return err

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
            response = await self.client.post("/chat/completions", content=payload, headers={"content-type": "application/json"})
        except httpx.HTTPError as exc:
            raise map_transport_error(exc, provider=self.name) from exc
        request_id = response.headers.get("x-request-id")
        self.last_request_id = request_id
        if response.status_code >= 400:
            raise self._map_error(response)
        parsed = parse_json_response(response, provider=self.name)
        return self.parse_response(parsed, request_id=request_id)

    async def list_models(self) -> list[str]:
        try:
            response = await self.client.get("/models")
        except httpx.HTTPError as exc:
            raise map_transport_error(exc, provider=self.name) from exc
        if response.status_code >= 400:
            raise self._map_error(response)
        body = parse_json_response(response, provider=self.name)
        data = body.get("data")
        if not isinstance(data, list):
            raise LLMInvalidResponse("openai /models response has no data list")
        return [str(item["id"]) for item in data if isinstance(item, dict) and item.get("id")]

    def estimate_input_tokens(self, system: str, messages: list[Message], tools: list[ToolSpecForLLM] | None) -> int:
        return estimate_tokens(system, messages, tools)


__all__ = ["OPENAI_BASE_URL", "OpenAIProvider"]
