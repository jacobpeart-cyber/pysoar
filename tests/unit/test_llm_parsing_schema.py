"""Tests for extract_json's Pydantic schema validation path."""

from typing import Literal

from pydantic import BaseModel, Field

from src.core.llm_parsing import extract_json


class VerdictFixture(BaseModel):
    verdict: Literal["true_positive", "false_positive", "benign", "inconclusive"]
    confidence: float = Field(ge=0, le=100)
    reasoning: str = Field(max_length=4000)
    recommendations: list[str] = Field(default_factory=list)


class TestExtractJsonWithSchema:
    def test_valid_passes_schema(self):
        text = '{"verdict": "benign", "confidence": 90, "reasoning": "no IOCs matched", "recommendations": ["close"]}'
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is True
        assert isinstance(r.data, VerdictFixture)
        assert r.data.verdict == "benign"
        assert r.data.confidence == 90
        assert "schema_ok" in r.attempt_log

    def test_missing_required_field(self):
        text = '{"verdict": "benign", "confidence": 90}'  # missing reasoning
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "reasoning" in r.error
        assert "schema_fail" in r.attempt_log

    def test_wrong_field_type(self):
        text = '{"verdict": "benign", "confidence": "high", "reasoning": "x"}'
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "confidence" in r.error

    def test_enum_violation(self):
        text = '{"verdict": "MAYBE", "confidence": 50, "reasoning": "x"}'
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "verdict" in r.error

    def test_out_of_range_numeric(self):
        text = '{"verdict": "benign", "confidence": 150, "reasoning": "x"}'
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "confidence" in r.error

    def test_error_string_is_feedable_to_llm(self):
        """The error string must contain enough detail that the model can
        correct on retry — field name + reason."""
        text = '{"verdict": "MAYBE", "confidence": 999, "reasoning": "x"}'
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "verdict" in r.error
        assert len(r.error) > 50

    def test_no_schema_returns_dict(self):
        r = extract_json('{"a": 1}')
        assert r.ok is True
        assert r.data == {"a": 1}
        assert "schema_ok" not in r.attempt_log
