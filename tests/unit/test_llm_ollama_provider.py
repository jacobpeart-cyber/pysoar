"""OllamaProvider over a patched ``httpx.AsyncClient.post/get`` (no network)."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from src.llm.base import LLMNotConfigured, LLMTransientError, Message, TextBlock, ToolResultBlock, ToolSpecForLLM
from src.llm.ollama_provider import OllamaProvider

TOOL = ToolSpecForLLM(
    name="get_alert",
    description="Fetch an alert",
    input_schema={"type": "object", "properties": {"alert_id": {"type": "string"}}, "required": ["alert_id"], "additionalProperties": False},
)


class FakeTransport:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        transport = self

        async def _post(self: httpx.AsyncClient, url: str, *, content: bytes | None = None, **kw: Any) -> httpx.Response:
            transport.requests.append({"method": "POST", "url": url, "body": json.loads(content) if content else None})
            return transport._next(url)

        async def _get(self: httpx.AsyncClient, url: str, **kw: Any) -> httpx.Response:
            transport.requests.append({"method": "GET", "url": url})
            return transport._next(url)

        monkeypatch.setattr(httpx.AsyncClient, "post", _post)
        monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    def _next(self, url: str) -> httpx.Response:
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        status, body = item
        return httpx.Response(status, json=body, request=httpx.Request("POST", url))


def _chat(message: dict[str, Any], done_reason: str = "stop") -> dict[str, Any]:
    return {"model": "llama3.1", "message": message, "done": True, "done_reason": done_reason, "prompt_eval_count": 80, "eval_count": 20}


@pytest.fixture
def provider() -> OllamaProvider:
    return OllamaProvider(model="llama3.1", base_url="http://ollama.internal:11434/", num_ctx=8192, keep_alive="10m")


def test_constructor_validation() -> None:
    with pytest.raises(LLMNotConfigured):
        OllamaProvider(model="", base_url="http://x")
    with pytest.raises(LLMNotConfigured):
        OllamaProvider(model="m", base_url="")
    assert OllamaProvider(model="m", base_url="http://x/").base_url == "http://x"


async def test_tool_round_trip_synthesized_ids_and_replay(provider: OllamaProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    assistant = {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "get_alert", "arguments": {"alert_id": "a1"}}}]}
    transport = FakeTransport([(200, _chat(assistant)), (200, _chat({"role": "assistant", "content": "Benign."}))])
    transport.install(monkeypatch)
    async with provider as p:
        turn1 = await p.complete(system="sys", messages=[Message("user", [TextBlock("look")])], tools=[TOOL], max_tokens=64)
        assert turn1.stop_reason == "tool_use"
        assert [(c.id, c.name, c.input) for c in turn1.tool_calls] == [("get_alert#1", "get_alert", {"alert_id": "a1"})]
        assert turn1.usage.input_uncached == 80 and turn1.usage.output == 20 and turn1.usage.total_billable == 100
        assert turn1.provider_native == assistant
        assert turn1.request_id is None

        turn2 = await p.complete(
            system="sys",
            messages=[
                Message("user", [TextBlock("look")]),
                Message("assistant", [], provider_native=turn1.provider_native),
                Message("user", [ToolResultBlock("get_alert#1", "low")]),
            ],
            tools=[TOOL],
            max_tokens=64,
        )
        assert turn2.stop_reason == "end_turn" and turn2.text == "Benign."

    body = transport.requests[1]["body"]
    assert transport.requests[1]["url"] == "/api/chat"
    assert body["stream"] is False and body["keep_alive"] == "10m"
    assert body["options"] == {"num_ctx": 8192, "num_predict": 64}
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["messages"][2] == assistant
    assert body["messages"][3] == {"role": "tool", "tool_name": "get_alert", "content": "low"}
    assert body["tools"][0]["function"]["name"] == "get_alert"


@pytest.mark.parametrize("done_reason,expected", [("stop", "end_turn"), ("length", "max_tokens"), ("load", "error")])
async def test_done_reason_map(provider: OllamaProvider, monkeypatch: pytest.MonkeyPatch, done_reason: str, expected: str) -> None:
    transport = FakeTransport([(200, _chat({"role": "assistant", "content": "x"}, done_reason))])
    transport.install(monkeypatch)
    async with provider as p:
        turn = await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    assert turn.stop_reason == expected


async def test_model_without_tool_support_is_not_configured(provider: OllamaProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport([(400, {"error": "registry.ollama.ai/library/llama3.1:latest does not support tools"})])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(LLMNotConfigured) as info:
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10)
    assert info.value.reason == "model_lacks_tools"  # type: ignore[attr-defined]
    assert info.value.retryable is False


async def test_unknown_model_is_not_configured(provider: OllamaProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport([(404, {"error": "model 'llama3.1' not found"})])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(LLMNotConfigured) as info:
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)
    assert info.value.reason == "model_not_found"  # type: ignore[attr-defined]


async def test_server_errors_and_timeouts_are_transient(provider: OllamaProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport([(500, {"error": "boom"}), httpx.ReadTimeout("slow")])
    transport.install(monkeypatch)
    async with provider as p:
        for _ in range(2):
            with pytest.raises(LLMTransientError):
                await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10)


async def test_response_schema_becomes_format(provider: OllamaProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    schema = {"type": "object", "properties": {"v": {"type": "string"}}, "required": ["v"]}
    transport = FakeTransport([(200, _chat({"role": "assistant", "content": '{"v":"1"}'}))])
    transport.install(monkeypatch)
    async with provider as p:
        with pytest.raises(ValueError):
            await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=[TOOL], max_tokens=10, response_schema=schema)
        await p.complete(system="s", messages=[Message("user", [TextBlock("q")])], tools=None, max_tokens=10, response_schema=schema)
    assert transport.requests[0]["body"]["format"] == schema


async def test_list_models(provider: OllamaProvider, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport([(200, {"models": [{"name": "llama3.1:latest"}, {"name": "qwen2.5:7b"}]})])
    transport.install(monkeypatch)
    async with provider as p:
        assert await p.list_models() == ["llama3.1:latest", "qwen2.5:7b"]
    assert transport.requests[0]["url"] == "/api/tags"
