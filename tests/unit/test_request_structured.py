"""Tests for request_structured — provider-agnostic LLM call orchestrator."""

from typing import Literal, Optional

from pydantic import BaseModel, Field

from src.core.llm_parsing import (
    ParseResult,
    StructuredProvider,
    LLMTransportError,
    request_structured,
)


class VerdictFixture(BaseModel):
    verdict: Literal["true_positive", "false_positive", "benign", "inconclusive"]
    confidence: float = Field(ge=0, le=100)
    reasoning: str


class FakeProvider:
    """Test double for StructuredProvider. Returns canned responses in order."""

    def __init__(self, responses: list):
        self.responses = list(responses)
        self.calls: list[dict] = []

    async def acomplete_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
        tools: Optional[list[dict]] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        self.calls.append({
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "schema": schema,
            "tools": tools,
            "history": history,
        })
        if not self.responses:
            raise AssertionError("FakeProvider exhausted")
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


class TestRequestStructuredHappyPath:
    async def test_valid_first_attempt(self):
        valid = '{"verdict": "benign", "confidence": 90, "reasoning": "no IOCs"}'
        provider = FakeProvider([valid])
        result = await request_structured(
            provider,
            system_prompt="you are an analyst",
            user_prompt="classify alert 1",
            schema=VerdictFixture,
        )
        assert result.ok is True
        assert isinstance(result.data, VerdictFixture)
        assert result.data.verdict == "benign"
        assert len(provider.calls) == 1
        assert provider.calls[0]["schema"] is VerdictFixture
        assert provider.calls[0]["user_prompt"] == "classify alert 1"
