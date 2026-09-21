"""OpenAIProvider over a patched ``httpx.AsyncClient.post/get`` (no network)."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from src.llm._common import strict_json_schema
from src.llm.base import (
    LLMAuthError,
    LLMInvalidResponse,
    LLMNotConfigured,
    LLMRateLimitError,
    LLMTransientError,
    Message,
    TextBlock,
    ToolResultBlock,
    ToolSpecForLLM,
)
from src.llm.openai_provider import OPENAI_BASE_URL, OpenAIProvider

TOOL = ToolSpecForLLM(
    name="get_alert",
    description="Fetch an alert",
    input_schema={
        "type": "object",
        "properties": {"alert_id": {"type": "string"}, "verbose": {"type": "boolean"}},
        "required": ["alert_id"],
    },
)


class FakeTransport:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        transport = self

        async def _post(self: httpx.AsyncClient, url: str, *, content: bytes | None = None, **kw: Any) -> httpx.Response:
            transport.requests.append({"method": "POST", "url": url, "body": json.loads(content) if content else None, "client": self})
            return transport._next(url)

        async def _get(self: httpx.AsyncClient, url: str, **kw: Any) -> httpx.Response:
            transport.requests.append({"method": "GET", "url": url, "client": self})
            return transport._next(url)

        monkeypatch.setattr(httpx.AsyncClient, "post", _post)
        monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    def _next(self, url: str) -> httpx.Response:
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        status, body, headers = item
        return httpx.Response(status, json=body, headers=headers or {}, request=httpx.Request("POST", url))


def _completion(message: dict[str, Any], finish: str = "stop") -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "model": "gpt-5",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": 150,
            "completion_tokens": 60,
            "prompt_tokens_details": {"cached_tokens": 50},
            "completion_tokens_details": {"reasoning_tokens": 25},
        },
    }


@pytest.fixture
def provider() -> OpenAIProvider:
    return OpenAIProvider(api_key="sk-test-key", model="gpt-5", credential_source="platform")


def test_strict_schema_requires_all_properties_and_nullable_optionals() -> None:
    out = strict_json_schema(TOOL.input_schema)
    assert out["additionalProperties"] is False
    assert out["required"] == ["alert_id", "verbose"]
    assert out["properties"]["verbose"]["type"] == ["boolean", "null"]
    assert out["properties"]["alert_id"]["type"] == "string"
    nested = strict_json_schema({"type": "object", "properties": {"a": {"type": "object", "properties": {"b": {"type": "integer"}}}}})
    assert nested["properties"]["a"]["additionalProperties"] is False
    assert nested["properties"]["a"]["required"] == ["b"]
    assert "additionalProperties" not in TOOL.input_schema  # untouched input


async def test_tool_message_expansion_and_native_replay(provider: OpenAIProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    assistant_msg = {
        "role": "assistant",
        "content": None,
        "reasoning": "hidden",
        "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "get_alert", "arguments": '{"alert_id": "a1"}'}},
            {"id": "call_2", "type": "function", "function": {"name": "get_alert", "arguments": '{"alert_id": "a2"}'}},
        ],
    }
    transport = FakeTransport(
        [
            (200, _completion(assistant_msg, "tool_calls"), {"x-request-id": "rq-1"}),
            (200, _completion({"role": "assistant", "content": "Both benign."}), None),
        ]
    )
    transport.install(monkeypatch)
    async with provider as p:
        turn1 = await p.complete(system="sys", messages=[Message("user", [TextBlock("check")])], tools=[TOOL], max_tokens=300)
        assert turn1.stop_reason == "tool_use" and turn1.text == ""
        assert [(c.id, c.input) for c in turn1.tool_calls] == [("call_1", {"alert_id": "a1"}), ("call_2", {"alert_id": "a2"})]
        assert turn1.request_id == "rq-1"
        assert turn1.usage.input_uncached == 100 and turn1.usage.cache_read == 50
        assert turn1.usage.output == 35 and turn1.usage.thinking == 25
        assert turn1.usage.total_billable == 210
        assert turn1.provider_native is assistant_msg or turn1.provider_native == assistant_msg

        turn2 = await p.complete(
            system="sys",
            messages=[
                Message("user", [TextBlock("check")]),
                Message("assistant", [], provider_native=turn1.provider_native),
                Message("user", [ToolResultBlock("call_1", "r1"), ToolResultBlock("call_2", "r2", is_error=True), TextBlock("continue")]),
            ],
            tools=[TOOL],
            max_tokens=300,
        )
        assert turn2.stop_reason == "end_turn" and turn2.text == "Both benign."
        assert p.client.headers["authorization"] == "Bearer sk-test-key"

    body = transport.requests[1]["body"]
    assert transport.requests[1]["url"] == "/chat/completions"
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["messages"][1] == {"role": "user", "content": "check"}
    assert body["messages"][2] == assistant_msg  # verbatim incl. reasoning
    assert body["messages"][3] == {"role": "tool", "tool_call_id": "call_1", "content": "r1"}
    assert body["messages"][4] == {"role": "tool", "tool_call_id": "call_2", "content": "r2"}
    assert body["messages"][5] == {"role": "user", "content": "continue"}
    assert body["max_completion_tokens"] == 300 and "max_tokens" not in body
    assert body["stream"] is False
    tool = body["tools"][0]["function"]
    assert tool["strict"] is True and tool["parameters"]["additionalProperties"] is False
    assert tool["parameters"]["required"] == ["alert_id", "verbose"]


async def test_openai_compatible_base_url_uses_max_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAIProvider(api_key="k", model="local", credential_source="platform", base_url="https://llm.internal/v1/")
    transport = FakeTransport([(200, _completion({"role": "assistant", "content": "ok"}), None)])
    transport.install(monkeypatch)
    async with provider as p:
        await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=12)
        assert str(p.client.base_url).startswith("https://llm.internal/v1")
    assert transport.requests[0]["body"]["max_tokens"] == 12
    assert provider.base_url == "https://llm.internal/v1"
    assert OpenAIProvider(api_key="k", model="m", credential_source="platform").base_url == OPENAI_BASE_URL


@pytest.mark.parametrize(
    "message,finish,expected",
    [
        ({"role": "assistant", "content": "x"}, "stop", "end_turn"),
        ({"role": "assistant", "content": "x"}, "length", "max_tokens"),
        ({"role": "assistant", "content": None}, "content_filter", "refusal"),
        ({"role": "assistant", "content": None, "refusal": "I cannot help with that."}, "stop", "refusal"),
        ({"role": "assistant", "content": "x"}, "weird", "error"),
    ],
)
async def test_finish_reason_map(provider: OpenAIProvider, monkeypatch: pytest.MonkeyPatch, message: dict[str, Any], finish: str, expected: str) -> None:
    transport = FakeTransport([(200, _completion(message, finish), None)])
    transport.install(monkeypatch)
    async with provider as p:
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    assert turn.stop_reason == expected
    if message.get("refusal"):
        assert turn.stop_details == {"refusal": "I cannot help with that.", "finish_reason": "stop"}


async def test_malformed_tool_arguments_are_invalid_response(provider: OpenAIProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "c", "type": "function", "function": {"name": "get_alert", "arguments": "{not json"}}]}
    transport = FakeTransport([(200, _completion(msg, "tool_calls"), None), (200, {"choices": []}, None)])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(LLMInvalidResponse):
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10)
        with pytest.raises(LLMInvalidResponse):
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10)


async def test_response_schema_uses_strict_json_schema_format(provider: OpenAIProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    schema = {"type": "object", "properties": {"v": {"type": "string"}}, "required": ["v"]}
    transport = FakeTransport([(200, _completion({"role": "assistant", "content": '{"v":"1"}'}), None)])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(ValueError):
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10, response_schema=schema)
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10, response_schema=schema)
    assert turn.text == '{"v":"1"}'
    fmt = transport.requests[0]["body"]["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["strict"] is True
    assert fmt["json_schema"]["schema"]["additionalProperties"] is False


@pytest.mark.parametrize(
    "status,body,headers,expected",
    [
        (401, {"error": {"message": "bad key"}}, None, LLMAuthError),
        (404, {"error": {"message": "The model `x` does not exist"}}, None, LLMNotConfigured),
        (429, {"error": {"message": "rate"}}, {"retry-after": "3"}, LLMRateLimitError),
        (500, {"error": {"message": "boom"}}, None, LLMTransientError),
        (502, {"error": {"message": "gateway"}}, None, LLMTransientError),
    ],
)
async def test_http_error_mapping(provider: OpenAIProvider, monkeypatch: pytest.MonkeyPatch, status: int, body: Any, headers: Any, expected: type) -> None:
    transport = FakeTransport([(status, body, headers)])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(expected) as info:
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    if expected is LLMRateLimitError:
        assert info.value.retry_after == 3.0


async def test_list_models(provider: OpenAIProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport([(200, {"data": [{"id": "gpt-5"}, {"id": "gpt-5-mini"}]}, None)])
    transport.install(monkeypatch)
    async with provider as p:
        assert await p.list_models() == ["gpt-5", "gpt-5-mini"]
    assert transport.requests[0]["url"] == "/models"
