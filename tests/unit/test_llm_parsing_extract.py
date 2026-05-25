"""Tests for src.core.llm_parsing — extract_json + ParseResult."""

from src.core.llm_parsing import (
    ParseResult,
    LLMParseError,
    LLMUnavailableError,
    LLMTransportError,
    _balanced_brace_extract,
)


class TestParseResultExists:
    def test_parse_result_constructs_ok(self):
        r = ParseResult(ok=True, data={"a": 1})
        assert r.ok is True
        assert r.data == {"a": 1}
        assert r.error is None
        assert r.attempt_log == []

    def test_parse_result_constructs_fail(self):
        r = ParseResult(ok=False, error="boom")
        assert r.ok is False
        assert r.data is None
        assert r.error == "boom"


class TestExceptionTypes:
    def test_parse_error_carries_raw(self):
        exc = LLMParseError("bad shape", raw="{broken")
        assert str(exc) == "bad shape"
        assert exc.raw == "{broken"

    def test_unavailable_error_is_exception(self):
        exc = LLMUnavailableError("no key")
        assert isinstance(exc, Exception)

    def test_transport_error_is_exception(self):
        exc = LLMTransportError("timeout")
        assert isinstance(exc, Exception)


class TestBalancedBraceExtract:
    def test_simple_object(self):
        assert _balanced_brace_extract('{"a": 1}', 0) == '{"a": 1}'

    def test_nested_object(self):
        text = '{"a": {"b": 2}, "c": 3}'
        assert _balanced_brace_extract(text, 0) == text

    def test_nested_array_with_objects(self):
        text = '{"items": [{"x": 1}, {"x": 2}]}'
        assert _balanced_brace_extract(text, 0) == text

    def test_start_offset(self):
        text = 'prose before {"a": 1} prose after'
        assert _balanced_brace_extract(text, 13) == '{"a": 1}'

    def test_brace_in_string_does_not_close(self):
        text = '{"msg": "value with } brace"}'
        assert _balanced_brace_extract(text, 0) == text

    def test_escaped_quote_in_string(self):
        text = r'{"msg": "has \"quoted\" word"}'
        assert _balanced_brace_extract(text, 0) == text

    def test_unbalanced_returns_none(self):
        assert _balanced_brace_extract('{"a": 1', 0) is None

    def test_no_brace_at_start_returns_none(self):
        assert _balanced_brace_extract('not an object', 0) is None

    def test_start_past_end_returns_none(self):
        assert _balanced_brace_extract('{}', 99) is None
