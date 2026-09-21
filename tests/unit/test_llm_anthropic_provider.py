"""AnthropicProvider over a patched ``client.messages.create`` (no network)."""
from __future__ import annotations

import asyncio
from typing import Any

import anthropic
import httpx2
import pytest
from anthropic.types import Message as SDKMessage

from src.llm.anthropic_provider import ANTHROPIC_TIMEOUT, AnthropicProvider
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

TOOL = ToolSpecForLLM(
    name="get_alert",
    description="Fetch an alert",
    input_schema={"type": "object", "properties": {"alert_id": {"type": "string"}}, "required": ["alert_id"], "additionalProperties": False},
)


def _sdk_message(content: list[dict[str, Any]], *, stop_reason: str = "end_turn", **extra: Any) -> SDKMessage:
    payload: dict[str, Any] = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {
            "input_tokens": 100,
            "output_tokens": 40,
            "cache_read_input_tokens": 20,
            "cache_creation_input_tokens": 5,
            "output_tokens_details": {"thinking_tokens": 10},
        },
    }
    payload.update(extra)
    msg = SDKMessage.model_validate(payload)
    msg._request_id = "req_abc"
    return msg


class _Capture:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


@pytest.fixture
def provider() -> AnthropicProvider:
    return AnthropicProvider(api_key="sk-ant-test", model="claude-opus-5", credential_source="org")


def test_constructor_requires_explicit_key_and_model() -> None:
    with pytest.raises(LLMNotConfigured):
        AnthropicProvider(api_key="", model="m", credential_source="org")
    with pytest.raises(LLMNotConfigured):
        AnthropicProvider(api_key="k", model="", credential_source="org")


async def test_client_is_created_with_fixed_policy(provider: AnthropicProvider) -> None:
    with pytest.raises(RuntimeError):
        provider.client  # not entered yet
    async with provider as p:
        assert p.client.max_retries == 0
        assert p.client.timeout == ANTHROPIC_TIMEOUT
        assert str(p.client.base_url).startswith("https://api.anthropic.com")
    with pytest.raises(RuntimeError):
        provider.client


async def test_tool_round_trip_replays_native_content_verbatim(provider: AnthropicProvider) -> None:
    first = _sdk_message(
        [
            {"type": "thinking", "thinking": "let me look", "signature": "sig123"},
            {"type": "text", "text": "Checking."},
            {"type": "tool_use", "id": "toolu_1", "name": "get_alert", "input": {"alert_id": "a1"}},
        ],
        stop_reason="tool_use",
    )
    second = _sdk_message([{"type": "text", "text": "Alert a1 is benign."}])
    capture = _Capture([first, second])
    async with provider as p:
        p.client.messages.create = capture  # type: ignore[method-assign]
        turn1 = await p.complete(system="sys", messages=[Message("user", [TextBlock("look at a1")])], tools=[TOOL], max_tokens=512)
        assert turn1.stop_reason == "tool_use"
        assert turn1.text == "Checking."
        assert [(c.id, c.name, c.input) for c in turn1.tool_calls] == [("toolu_1", "get_alert", {"alert_id": "a1"})]
        assert turn1.request_id == "req_abc"
        assert turn1.usage.input_uncached == 100 and turn1.usage.cache_read == 20 and turn1.usage.cache_write == 5
        assert turn1.usage.output == 30 and turn1.usage.thinking == 10
        assert turn1.usage.total_billable == 165
        assert turn1.usage.estimated is False
        # thinking block survives in native payload (never in text)
        assert turn1.provider_native[0]["type"] == "thinking" and turn1.provider_native[0]["signature"] == "sig123"
        assert "let me look" not in turn1.text

        messages = [
            Message("user", [TextBlock("look at a1")]),
            Message("assistant", [TextBlock("Checking.")], provider_native=turn1.provider_native),
            Message("user", [ToolResultBlock("toolu_1", '{"severity": "low"}')]),
        ]
        turn2 = await p.complete(system="sys", messages=messages, tools=[TOOL], max_tokens=512)
        assert turn2.stop_reason == "end_turn" and turn2.text == "Alert a1 is benign."

    req = capture.calls[1]
    assert req["model"] == "claude-opus-5" and req["max_tokens"] == 512 and req["system"] == "sys"
    assert "thinking" not in req and "tool_choice" not in req
    assert req["tools"] == [
        {"name": "get_alert", "description": "Fetch an alert", "input_schema": TOOL.input_schema, "strict": True}
    ]
    # byte-for-byte replay of the first response's native content
    assert req["messages"][1] == {"role": "assistant", "content": turn1.provider_native}
    assert req["messages"][1]["content"] is turn1.provider_native
    assert req["messages"][2] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": '{"severity": "low"}', "is_error": False}],
    }
    assert p.last_request_bytes and p.last_request_bytes > 0


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("end_turn", "end_turn"),
        ("stop_sequence", "end_turn"),
        ("max_tokens", "max_tokens"),
        ("pause_turn", "error"),
        ("model_context_window_exceeded", "error"),
    ],
)
async def test_stop_reason_map(provider: AnthropicProvider, raw: str, expected: str) -> None:
    async with provider as p:
        p.client.messages.create = _Capture([_sdk_message([{"type": "text", "text": "x"}], stop_reason=raw)])  # type: ignore[method-assign]
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    assert turn.stop_reason == expected
    if expected == "error":
        assert turn.stop_details == {"provider_stop_reason": raw}


async def test_refusal_carries_stop_details(provider: AnthropicProvider) -> None:
    msg = _sdk_message([], stop_reason="refusal", stop_details={"type": "refusal", "category": "cyber", "explanation": "no"})
    async with provider as p:
        p.client.messages.create = _Capture([msg])  # type: ignore[method-assign]
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    assert turn.stop_reason == "refusal"
    assert turn.stop_details == {"category": "cyber", "explanation": "no"}
    assert turn.tool_calls == []


async def test_tool_use_without_block_is_invalid(provider: AnthropicProvider) -> None:
    async with provider as p:
        p.client.messages.create = _Capture([_sdk_message([{"type": "text", "text": "x"}], stop_reason="tool_use")])  # type: ignore[method-assign]
        with pytest.raises(LLMInvalidResponse):
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10)


def _status_error(cls: type, status: int, headers: dict[str, str] | None = None) -> anthropic.APIStatusError:
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx2.Response(status, request=request, headers=headers or {}, json={"error": {"type": "e", "message": "boom"}})
    return cls("boom", response=response, body={"error": {"type": "e", "message": "boom"}})


@pytest.mark.parametrize(
    "exc,expected",
    [
        (_status_error(anthropic.AuthenticationError, 401), LLMAuthError),
        (_status_error(anthropic.PermissionDeniedError, 403), LLMAuthError),
        (_status_error(anthropic.RateLimitError, 429, {"retry-after": "7"}), LLMRateLimitError),
        (_status_error(anthropic.InternalServerError, 500), LLMTransientError),
        (_status_error(anthropic.APIStatusError, 529), LLMTransientError),
        (_status_error(anthropic.NotFoundError, 404), LLMNotConfigured),
        (anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com")), LLMTransientError),
        (anthropic.APITimeoutError(request=httpx2.Request("POST", "https://api.anthropic.com")), LLMTransientError),
    ],
)
async def test_error_mapping(provider: AnthropicProvider, exc: Exception, expected: type) -> None:
    async with provider as p:
        p.client.messages.create = _Capture([exc])  # type: ignore[method-assign]
        with pytest.raises(expected) as info:
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    if expected is LLMRateLimitError:
        assert info.value.retry_after == 7.0
    assert info.value.retryable is (expected is LLMTransientError)


async def test_response_schema_rejected_with_tools_and_sent_without(provider: AnthropicProvider) -> None:
    schema = {"type": "object", "properties": {"verdict": {"type": "string"}}, "required": ["verdict"], "additionalProperties": False}
    async with provider as p:
        capture = _Capture([_sdk_message([{"type": "text", "text": '{"verdict": "benign"}'}])])
        p.client.messages.create = capture  # type: ignore[method-assign]
        with pytest.raises(ValueError):
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10, response_schema=schema)
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10, response_schema=schema)
    assert turn.text == '{"verdict": "benign"}'
    assert capture.calls[0]["output_config"] == {"format": {"type": "json_schema", "schema": schema}}


def test_two_event_loops_get_distinct_clients() -> None:
    provider = AnthropicProvider(api_key="sk-ant-test", model="m", credential_source="platform")
    seen: list[Any] = []  # strong refs so ids cannot be recycled

    async def _use() -> None:
        async with provider as p:
            seen.append(p.client)

    asyncio.run(_use())
    asyncio.run(_use())
    assert len(seen) == 2 and seen[0] is not seen[1]
    assert provider._client is None  # closed on exit


def test_estimate_input_tokens_is_positive_and_counts_tools() -> None:
    provider = AnthropicProvider(api_key="k", model="m", credential_source="org")
    without = provider.estimate_input_tokens("system", [Message("user", [TextBlock("hello world")])], None)
    with_tools = provider.estimate_input_tokens("system", [Message("user", [TextBlock("hello world")])], [TOOL])
    assert 0 < without < with_tools
