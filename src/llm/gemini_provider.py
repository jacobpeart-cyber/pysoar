"""Google Gemini provider over the REST ``generateContent`` API (async httpx).

Design section 6:

* ``systemInstruction`` carries the system prompt; the non-streaming
  ``:generateContent`` endpoint is used (never ``streamGenerateContent``).
* Tools become ``functionDeclarations``; tool-call ids do not exist in the
  Gemini wire format so they are synthesized as ``name#seq`` (``seq`` is
  monotonic per provider instance, i.e. per run) and mapped back to
  ``functionResponse`` parts by name in call order.
* ``responseSchema`` is NEVER sent together with tools.
* The candidate ``content`` (parts including ``thoughtSignature``) is the
  ``provider_native`` payload and is replayed verbatim.
* ``finishReason`` map: ``STOP`` -> ``end_turn``/``tool_use``; ``MAX_TOKENS``
  -> ``max_tokens``; ``SAFETY|RECITATION|BLOCKLIST|PROHIBITED_CONTENT|SPII|
  IMAGE_SAFETY`` -> ``refusal``; ``MALFORMED_FUNCTION_CALL|OTHER``/unknown ->
  ``error``; missing candidates / ``promptFeedback.blockReason`` -> ``refusal``.
"""
from __future__ import annotations

import copy
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
)
from src.llm.base import (
    LLMAuthError,
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

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"
GEMINI_API_VERSION = "v1beta"

_REFUSAL_FINISH = frozenset({"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY"})
_ERROR_FINISH = frozenset({"MALFORMED_FUNCTION_CALL", "OTHER", "LANGUAGE", "UNEXPECTED_TOOL_CALL"})

# JSON Schema keywords the Gemini OpenAPI subset rejects; everything else is
# passed through so enums/ranges/nesting survive.
_UNSUPPORTED_SCHEMA_KEYS = frozenset({"additionalProperties", "$schema", "$id", "examples", "const", "$defs", "definitions"})


def synthesize_tool_id(name: str, seq: int) -> str:
    return f"{name}#{seq}"


def tool_name_from_id(tool_use_id: str) -> str:
    """Inverse of :func:`synthesize_tool_id`; the name is everything before the last ``#``."""
    name, sep, _ = tool_use_id.rpartition("#")
    return name if sep else tool_use_id


def gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Deep copy of a JSON Schema with the keywords Gemini rejects removed."""

    def _walk(node: Any) -> Any:
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if not isinstance(node, dict):
            return node
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in _UNSUPPORTED_SCHEMA_KEYS:
                continue
            if key in ("properties",) and isinstance(value, dict):
                out[key] = {k: _walk(v) for k, v in value.items()}
            elif key == "items" and isinstance(value, dict):
                out[key] = _walk(value)
            elif key in ("anyOf", "oneOf", "allOf") and isinstance(value, list):
                out[key] = [_walk(item) for item in value]
            else:
                out[key] = copy.deepcopy(value)
        return out

    return _walk(schema)


class GeminiProvider:
    """``LLMProvider`` implementation over the Gemini REST API."""

    name: str = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        credential_source: Literal["org", "platform"],
    ) -> None:
        if not api_key:
            raise LLMNotConfigured("gemini api_key is empty")
        if not model:
            raise LLMNotConfigured("gemini model is not set")
        self._api_key = api_key
        self.model = model
        self.credential_source = credential_source
        self._client: Optional[httpx.AsyncClient] = None
        self._tool_seq = 0
        self.last_request_bytes: Optional[int] = None
        self.last_request_id: Optional[str] = None

    async def __aenter__(self) -> "GeminiProvider":
        self._client = new_http_client(GEMINI_BASE_URL, headers={"x-goog-api-key": self._api_key})
        return self

    async def __aexit__(self, *exc: Any) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("GeminiProvider must be used as an async context manager")
        return self._client

    # -- request building --------------------------------------------------

    @staticmethod
    def _user_parts(message: Message) -> list[dict[str, Any]]:
        parts: list[dict[str, Any]] = []
        for block in message.content:
            if isinstance(block, TextBlock):
                parts.append({"text": block.text})
            elif isinstance(block, ToolResultBlock):
                parts.append(
                    {
                        "functionResponse": {
                            "name": tool_name_from_id(block.tool_use_id),
                            "response": {"content": block.content, "is_error": bool(block.is_error)},
                        }
                    }
                )
            elif isinstance(block, ToolUseBlock):
                raise ValueError("tool_use blocks are only valid in assistant messages")
        return parts

    @staticmethod
    def _model_content(message: Message) -> dict[str, Any]:
        if message.provider_native is not None:
            return message.provider_native
        parts: list[dict[str, Any]] = []
        for block in message.content:
            if isinstance(block, TextBlock):
                parts.append({"text": block.text})
            elif isinstance(block, ToolUseBlock):
                parts.append({"functionCall": {"name": block.name, "args": block.input}})
            elif isinstance(block, ToolResultBlock):
                raise ValueError("tool_result blocks are only valid in user messages")
        return {"role": "model", "parts": parts}

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
        contents: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "user":
                contents.append({"role": "user", "parts": self._user_parts(message)})
            elif message.role == "assistant":
                contents.append(self._model_content(message))
            else:
                raise ValueError(f"unsupported message role {message.role!r}")
        generation_config: dict[str, Any] = {"maxOutputTokens": int(max_tokens)}
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": contents,
            "generationConfig": generation_config,
        }
        if tools:
            body["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "parameters": gemini_schema(t.input_schema),
                        }
                        for t in tools
                    ]
                }
            ]
        elif response_schema is not None:
            generation_config["responseMimeType"] = "application/json"
            generation_config["responseSchema"] = gemini_schema(response_schema)
        return body

    # -- response parsing --------------------------------------------------

    @staticmethod
    def _usage(meta: Any) -> Usage:
        if not isinstance(meta, dict):
            return Usage()
        prompt = int(meta.get("promptTokenCount") or 0)
        cached = int(meta.get("cachedContentTokenCount") or 0)
        output = int(meta.get("candidatesTokenCount") or 0)
        thinking = int(meta.get("thoughtsTokenCount") or 0)
        return Usage(
            input_uncached=max(prompt - cached, 0),
            cache_read=cached,
            cache_write=0,
            output=output,
            thinking=thinking,
        )

    def parse_response(self, body: dict[str, Any], *, request_id: Optional[str]) -> LLMTurn:
        usage = self._usage(body.get("usageMetadata"))
        candidates = body.get("candidates")
        prompt_feedback = body.get("promptFeedback")
        block_reason = prompt_feedback.get("blockReason") if isinstance(prompt_feedback, dict) else None
        if block_reason or not candidates:
            return LLMTurn(
                text="",
                tool_calls=[],
                stop_reason="refusal",
                usage=usage,
                provider=self.name,
                model=self.model,
                request_id=request_id,
                provider_native=None,
                stop_details={"block_reason": block_reason or "no_candidates"},
            )
        candidate = candidates[0]
        if not isinstance(candidate, dict):
            raise LLMInvalidResponse("gemini candidate is not an object")
        content = candidate.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        if parts is None:
            parts = []
        if not isinstance(parts, list):
            raise LLMInvalidResponse("gemini candidate parts is not a list")

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in parts:
            if not isinstance(part, dict):
                raise LLMInvalidResponse("gemini part is not an object")
            if part.get("thought") is True:
                continue  # thought summaries are never surfaced as answer text
            call = part.get("functionCall")
            if isinstance(call, dict):
                name = call.get("name")
                if not name:
                    raise LLMInvalidResponse("gemini functionCall without name")
                args = call.get("args")
                if args is None:
                    args = {}
                if not isinstance(args, dict):
                    raise LLMInvalidResponse(f"gemini functionCall {name!r} args are not an object")
                self._tool_seq += 1
                tool_calls.append(ToolCall(id=synthesize_tool_id(str(name), self._tool_seq), name=str(name), input=args))
            elif "text" in part:
                text_parts.append(str(part.get("text") or ""))

        finish = str(candidate.get("finishReason") or "")
        stop_details: Optional[dict[str, Any]] = None
        stop_reason: StopReason
        if finish == "STOP" or (finish == "" and parts):
            stop_reason = "tool_use" if tool_calls else "end_turn"
        elif finish == "MAX_TOKENS":
            stop_reason = "max_tokens"
        elif finish in _REFUSAL_FINISH:
            stop_reason = "refusal"
            stop_details = {"finish_reason": finish, "safety_ratings": candidate.get("safetyRatings")}
        else:
            stop_reason = "error"
            stop_details = {"finish_reason": finish or "missing", "finish_message": candidate.get("finishMessage")}
            tool_calls = []

        native = content if isinstance(content, dict) else {"role": "model", "parts": parts}
        return LLMTurn(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=usage,
            provider=self.name,
            model=str(body.get("modelVersion") or self.model),
            request_id=request_id,
            provider_native=native,
            stop_details=stop_details,
        )

    # -- LLMProvider -------------------------------------------------------

    def _map_error(self, response: httpx.Response) -> LLMError:
        err = map_http_status(response, provider=self.name)
        if response.status_code == 400 and "api key" in str(err).lower():
            return LLMAuthError(str(err), request_id=err.request_id)
        if response.status_code == 404:
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
        url = f"/{GEMINI_API_VERSION}/models/{self.model}:generateContent"
        try:
            response = await self.client.post(url, content=payload, headers={"content-type": "application/json"})
        except httpx.HTTPError as exc:
            raise map_transport_error(exc, provider=self.name) from exc
        request_id = response.headers.get("x-goog-request-id") or response.headers.get("x-request-id")
        self.last_request_id = request_id
        if response.status_code >= 400:
            raise self._map_error(response)
        parsed = parse_json_response(response, provider=self.name)
        if not request_id and isinstance(parsed.get("responseId"), str):
            request_id = parsed["responseId"]
            self.last_request_id = request_id
        return self.parse_response(parsed, request_id=request_id)

    async def list_models(self) -> list[str]:
        names: list[str] = []
        page_token: Optional[str] = None
        while True:
            params: dict[str, Any] = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            try:
                response = await self.client.get(f"/{GEMINI_API_VERSION}/models", params=params)
            except httpx.HTTPError as exc:
                raise map_transport_error(exc, provider=self.name) from exc
            if response.status_code >= 400:
                raise self._map_error(response)
            body = parse_json_response(response, provider=self.name)
            for model in body.get("models") or []:
                if not isinstance(model, dict):
                    continue
                methods = model.get("supportedGenerationMethods") or []
                if "generateContent" not in methods:
                    continue
                raw_name = str(model.get("name") or "")
                names.append(raw_name[len("models/"):] if raw_name.startswith("models/") else raw_name)
            page_token = body.get("nextPageToken")
            if not page_token:
                break
        return names

    def estimate_input_tokens(self, system: str, messages: list[Message], tools: list[ToolSpecForLLM] | None) -> int:
        return estimate_tokens(system, messages, tools)


__all__ = ["GEMINI_BASE_URL", "GeminiProvider", "gemini_schema", "synthesize_tool_id", "tool_name_from_id"]
