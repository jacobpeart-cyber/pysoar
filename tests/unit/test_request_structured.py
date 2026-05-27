"""Tests for request_structured — provider-agnostic LLM call orchestrator."""

from typing import Literal, Optional

import pytest
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


class TestRequestStructuredRetry:
    async def test_invalid_then_valid_retries_once(self):
        invalid = "the model wrote prose instead of JSON"
        valid = '{"verdict": "benign", "confidence": 70, "reasoning": "after retry"}'
        provider = FakeProvider([invalid, valid])
        result = await request_structured(
            provider,
            system_prompt="sys",
            user_prompt="orig user prompt",
            schema=VerdictFixture,
            retries=2,
        )
        assert result.ok is True
        assert result.data.reasoning == "after retry"
        assert len(provider.calls) == 2

    async def test_retry_prompt_carries_validation_error(self):
        invalid = '{"verdict": "WRONG_VALUE", "confidence": 90, "reasoning": "x"}'
        valid = '{"verdict": "benign", "confidence": 90, "reasoning": "fixed"}'
        provider = FakeProvider([invalid, valid])
        result = await request_structured(
            provider,
            system_prompt="sys",
            user_prompt="orig user prompt",
            schema=VerdictFixture,
            retries=2,
        )
        assert result.ok is True
        # Second call's user_prompt must include the validation error
        second_prompt = provider.calls[1]["user_prompt"]
        assert "orig user prompt" in second_prompt
        assert "previous response failed validation" in second_prompt
        assert "verdict" in second_prompt  # the failed field name

    async def test_all_attempts_fail_returns_ok_false(self):
        bad1 = "prose only"
        bad2 = '{"verdict": "WRONG", "confidence": 50, "reasoning": "x"}'
        bad3 = '{"verdict": "STILL_WRONG", "confidence": 50, "reasoning": "x"}'
        provider = FakeProvider([bad1, bad2, bad3])
        result = await request_structured(
            provider,
            system_prompt="sys",
            user_prompt="orig",
            schema=VerdictFixture,
            retries=2,  # 1 initial + 2 retries = 3 attempts
        )
        assert result.ok is False
        assert result.error
        assert len(provider.calls) == 3

    async def test_retries_zero_means_single_attempt(self):
        bad = "no JSON here"
        provider = FakeProvider([bad])
        result = await request_structured(
            provider,
            system_prompt="sys",
            user_prompt="orig",
            schema=VerdictFixture,
            retries=0,
        )
        assert result.ok is False
        assert len(provider.calls) == 1


class TestRequestStructuredTransport:
    async def test_transport_error_propagates_not_swallowed(self):
        """LLMTransportError from the provider must bubble up — never be
        caught and turned into a fake ParseResult."""
        provider = FakeProvider([LLMTransportError("connection reset")])
        with pytest.raises(LLMTransportError, match="connection reset"):
            await request_structured(
                provider,
                system_prompt="sys",
                user_prompt="orig",
                schema=VerdictFixture,
                retries=2,
            )
        assert len(provider.calls) == 1  # didn't retry on transport error

    async def test_transport_error_on_retry_propagates(self):
        """If the FIRST attempt parses badly and the SECOND attempt is a
        transport failure, the transport error still propagates and is not
        masked by the prior parse failure."""
        bad_parse = "no JSON"
        provider = FakeProvider([bad_parse, LLMTransportError("timeout")])
        with pytest.raises(LLMTransportError, match="timeout"):
            await request_structured(
                provider,
                system_prompt="sys",
                user_prompt="orig",
                schema=VerdictFixture,
                retries=2,
            )
        assert len(provider.calls) == 2
