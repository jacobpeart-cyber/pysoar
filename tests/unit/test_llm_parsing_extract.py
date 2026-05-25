"""Tests for src.core.llm_parsing — extract_json + ParseResult."""

from src.core.llm_parsing import (
    ParseResult,
    LLMParseError,
    LLMUnavailableError,
    LLMTransportError,
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
