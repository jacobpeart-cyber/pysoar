"""GeminiProvider over a patched ``httpx.AsyncClient.post/get`` (no network)."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from src.llm.base import (
    LLMAuthError,
    LLMNotConfigured,
    LLMRateLimitError,
    LLMTransientError,
    Message,
    TextBlock,
    ToolResultBlock,
    ToolSpecForLLM,
)
from src.llm.gemini_provider import GeminiProvider, gemini_schema, synthesize_tool_id, tool_name_from_id

TOOL = ToolSpecForLLM(
    name="get_alert",
    description="Fetch an alert",
    input_schema={"type": "object", "properties": {"alert_id": {"type": "string"}}, "required": ["alert_id"], "additionalProperties": False},
)


class FakeTransport:
    """Records every request and answers from a queue of (status, body, headers)."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        transport = self

        async def _post(self: httpx.AsyncClient, url: str, *, content: bytes | None = None, headers: Any = None, **kw: Any) -> httpx.Response:
            transport.requests.append({"method": "POST", "url": url, "body": json.loads(content) if content else None, "client": self})
            return transport._next(url)

        async def _get(self: httpx.AsyncClient, url: str, *, params: Any = None, **kw: Any) -> httpx.Response:
            transport.requests.append({"method": "GET", "url": url, "params": params, "client": self})
            return transport._next(url)

        monkeypatch.setattr(httpx.AsyncClient, "post", _post)
        monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    def _next(self, url: str) -> httpx.Response:
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        status, body, headers = item
        return httpx.Response(status, json=body, headers=headers or {}, request=httpx.Request("POST", url))


def _candidate(parts: list[dict[str, Any]], finish: str = "STOP") -> dict[str, Any]:
    return {
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish}],
        "usageMetadata": {"promptTokenCount": 120, "cachedContentTokenCount": 20, "candidatesTokenCount": 30, "thoughtsTokenCount": 15},
        "modelVersion": "gemini-2.5-pro",
        "responseId": "resp_1",
    }


@pytest.fixture
def provider() -> GeminiProvider:
    return GeminiProvider(api_key="AIzaTest", model="gemini-2.5-pro", credential_source="org")


def test_ids_round_trip() -> None:
    assert synthesize_tool_id("get_alert", 3) == "get_alert#3"
    assert tool_name_from_id("get_alert#3") == "get_alert"
    assert tool_name_from_id("weird#name#7") == "weird#name"


def test_gemini_schema_strips_unsupported_keywords() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "$schema": "x",
        "properties": {"a": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {}}}},
        "required": ["a"],
    }
    out = gemini_schema(schema)
    assert "additionalProperties" not in out and "$schema" not in out
    assert "additionalProperties" not in out["properties"]["a"]["items"]
    assert out["required"] == ["a"]
    assert "additionalProperties" in schema  # input untouched


async def test_tool_round_trip_with_thought_signature(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    first = _candidate(
        [
            {"text": "Looking.", "thoughtSignature": "sigABC"},
            {"functionCall": {"name": "get_alert", "args": {"alert_id": "a1"}}, "thoughtSignature": "sigDEF"},
        ]
    )
    second = _candidate([{"text": "Benign."}])
    transport = FakeTransport([(200, first, {"x-goog-request-id": "g-1"}), (200, second, None)])
    transport.install(monkeypatch)

    async with provider as p:
        turn1 = await p.complete(system="sys", messages=[Message("user", [TextBlock("look")])], tools=[TOOL], max_tokens=256)
        assert turn1.stop_reason == "tool_use"
        assert turn1.text == "Looking."
        assert [(c.id, c.name, c.input) for c in turn1.tool_calls] == [("get_alert#1", "get_alert", {"alert_id": "a1"})]
        assert turn1.request_id == "g-1"
        assert turn1.usage.input_uncached == 100 and turn1.usage.cache_read == 20
        assert turn1.usage.output == 30 and turn1.usage.thinking == 15
        assert turn1.provider_native == first["candidates"][0]["content"]

        turn2 = await p.complete(
            system="sys",
            messages=[
                Message("user", [TextBlock("look")]),
                Message("assistant", [TextBlock("Looking.")], provider_native=turn1.provider_native),
                Message("user", [ToolResultBlock("get_alert#1", '{"severity":"low"}')]),
            ],
            tools=[TOOL],
            max_tokens=256,
        )
        assert turn2.stop_reason == "end_turn" and turn2.text == "Benign."
        assert p.client.headers["x-goog-api-key"] == "AIzaTest"

    req = transport.requests[1]
    assert req["url"] == "/v1beta/models/gemini-2.5-pro:generateContent"
    body = req["body"]
    assert body["systemInstruction"] == {"parts": [{"text": "sys"}]}
    assert body["tools"][0]["functionDeclarations"][0]["name"] == "get_alert"
    assert "additionalProperties" not in body["tools"][0]["functionDeclarations"][0]["parameters"]
    assert "responseSchema" not in body["generationConfig"]
    assert body["generationConfig"]["maxOutputTokens"] == 256
    # verbatim replay incl. thoughtSignature
    assert body["contents"][1] == first["candidates"][0]["content"]
    assert body["contents"][1]["parts"][1]["thoughtSignature"] == "sigDEF"
    assert body["contents"][2] == {
        "role": "user",
        "parts": [{"functionResponse": {"name": "get_alert", "response": {"content": '{"severity":"low"}', "is_error": False}}}],
    }


async def test_tool_ids_are_unique_across_turns(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    call = {"functionCall": {"name": "get_alert", "args": {"alert_id": "a"}}}
    transport = FakeTransport([(200, _candidate([call, call]), None), (200, _candidate([call]), None)])
    transport.install(monkeypatch)
    async with provider as p:
        t1 = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10)
        t2 = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10)
    assert [c.id for c in t1.tool_calls] == ["get_alert#1", "get_alert#2"]
    assert [c.id for c in t2.tool_calls] == ["get_alert#3"]


@pytest.mark.parametrize(
    "finish,expected",
    [
        ("STOP", "end_turn"),
        ("MAX_TOKENS", "max_tokens"),
        ("SAFETY", "refusal"),
        ("RECITATION", "refusal"),
        ("BLOCKLIST", "refusal"),
        ("PROHIBITED_CONTENT", "refusal"),
        ("MALFORMED_FUNCTION_CALL", "error"),
        ("OTHER", "error"),
        ("SOMETHING_NEW", "error"),
    ],
)
async def test_finish_reason_map(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch, finish: str, expected: str) -> None:
    transport = FakeTransport([(200, _candidate([{"text": "x"}], finish), None)])
    transport.install(monkeypatch)
    async with provider as p:
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    assert turn.stop_reason == expected
    if expected in ("refusal", "error"):
        assert turn.stop_details is not None and turn.stop_details["finish_reason"] == finish


async def test_prompt_block_and_no_candidates_are_refusals(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport(
        [
            (200, {"promptFeedback": {"blockReason": "SAFETY"}, "usageMetadata": {"promptTokenCount": 5}}, None),
            (200, {"candidates": [], "usageMetadata": {"promptTokenCount": 5}}, None),
        ]
    )
    transport.install(monkeypatch)
    async with provider as p:
        blocked = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
        empty = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    assert blocked.stop_reason == "refusal" and blocked.stop_details == {"block_reason": "SAFETY"}
    assert blocked.usage.input_uncached == 5
    assert empty.stop_reason == "refusal" and empty.stop_details == {"block_reason": "no_candidates"}


async def test_response_schema_only_without_tools(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    schema = {"type": "object", "properties": {"v": {"type": "string"}}, "required": ["v"], "additionalProperties": False}
    transport = FakeTransport([(200, _candidate([{"text": '{"v":"ok"}'}]), None)])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(ValueError):
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10, response_schema=schema)
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10, response_schema=schema)
    assert turn.text == '{"v":"ok"}'
    cfg = transport.requests[0]["body"]["generationConfig"]
    assert cfg["responseMimeType"] == "application/json"
    assert cfg["responseSchema"] == {"type": "object", "properties": {"v": {"type": "string"}}, "required": ["v"]}
    assert "tools" not in transport.requests[0]["body"]


@pytest.mark.parametrize(
    "status,body,headers,expected",
    [
        (400, {"error": {"message": "API key not valid. Please pass a valid API key."}}, None, LLMAuthError),
        (403, {"error": {"message": "forbidden"}}, None, LLMAuthError),
        (404, {"error": {"message": "model not found"}}, None, LLMNotConfigured),
        (429, {"error": {"message": "quota"}}, {"retry-after": "12"}, LLMRateLimitError),
        (503, {"error": {"message": "overloaded"}}, None, LLMTransientError),
    ],
)
async def test_http_error_mapping(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch, status: int, body: Any, headers: Any, expected: type) -> None:
    transport = FakeTransport([(status, body, headers)])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(expected) as info:
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    if expected is LLMRateLimitError:
        assert info.value.retry_after == 12.0


async def test_transport_errors_are_transient(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport([httpx.ConnectTimeout("slow"), httpx.ConnectError("refused")])
    transport.install(monkeypatch)
    async with provider as p:
        for _ in range(2):
            with pytest.raises(LLMTransientError) as info:
                await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
            assert info.value.retryable is True


async def test_list_models_filters_generate_content_and_pages(provider: GeminiProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport(
        [
            (200, {"models": [{"name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent"]}, {"name": "models/embed", "supportedGenerationMethods": ["embedContent"]}], "nextPageToken": "t2"}, None),
            (200, {"models": [{"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]}]}, None),
        ]
    )
    transport.install(monkeypatch)
    async with provider as p:
        assert await p.list_models() == ["gemini-2.5-pro", "gemini-2.5-flash"]
    assert transport.requests[1]["params"]["pageToken"] == "t2"


async def test_client_policy(provider: GeminiProvider) -> None:
    async with provider as p:
        client = p.client
        assert client.trust_env is False
        assert client.follow_redirects is False
        assert client.timeout.connect == 5.0 and client.timeout.read == 60.0
    assert provider._client is None
