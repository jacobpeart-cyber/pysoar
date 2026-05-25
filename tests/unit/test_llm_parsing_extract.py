"""Tests for src.core.llm_parsing — extract_json + ParseResult."""

from src.core.llm_parsing import (
    ParseResult,
    LLMParseError,
    LLMUnavailableError,
    LLMTransportError,
    _balanced_brace_extract,
    extract_json,
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


class TestExtractJsonBare:
    def test_empty_string_returns_fail(self):
        r = extract_json("")
        assert r.ok is False
        assert "empty" in r.error.lower()
        assert "empty" in r.attempt_log

    def test_pure_prose_no_object(self):
        r = extract_json("the model said hello but emitted no JSON at all")
        assert r.ok is False
        assert "no JSON object" in r.error
        assert "no_object" in r.attempt_log

    def test_bare_object(self):
        r = extract_json('{"verdict": "true_positive", "confidence": 90}')
        assert r.ok is True
        assert r.data == {"verdict": "true_positive", "confidence": 90}
        assert "bare_object" in r.attempt_log
        assert "json.loads" in r.attempt_log

    def test_bare_object_surrounded_by_prose(self):
        r = extract_json('The model thought: {"verdict": "benign"} so we are done.')
        assert r.ok is True
        assert r.data == {"verdict": "benign"}

    def test_bare_object_nested(self):
        r = extract_json('{"a": {"b": [1, 2, {"c": 3}]}}')
        assert r.ok is True
        assert r.data == {"a": {"b": [1, 2, {"c": 3}]}}

    def test_array_only_is_not_object(self):
        r = extract_json('[1, 2, 3]')
        assert r.ok is False
        assert "no JSON object" in r.error

    def test_parsed_array_inside_object_rejected_top_level(self):
        # extract_json is for objects — a top-level array shouldn't sneak through
        r = extract_json('[{"verdict": "x"}]')
        # The bare-object regex requires {"<word>": pattern; this won't match.
        assert r.ok is False


class TestExtractJsonFenced:
    def test_fenced_block_with_json_tag(self):
        text = 'Here is my answer:\n```json\n{"verdict": "benign"}\n```\nDone.'
        r = extract_json(text)
        assert r.ok is True
        assert r.data == {"verdict": "benign"}
        assert "fenced_block" in r.attempt_log

    def test_fenced_block_without_tag(self):
        text = '```\n{"verdict": "benign"}\n```'
        r = extract_json(text)
        assert r.ok is True
        assert r.data == {"verdict": "benign"}

    def test_fenced_block_with_nested_object_REGRESSION(self):
        """Regression: the old lazy-regex extractor truncated at the first '}'.
        With nested objects, the inner '}' would close the match too early
        and the outer JSON would never parse."""
        text = '```json\n{"verdict": "true_positive", "evidence": {"alert_id": "abc", "host": "h1"}}\n```'
        r = extract_json(text)
        assert r.ok is True
        assert r.data == {
            "verdict": "true_positive",
            "evidence": {"alert_id": "abc", "host": "h1"},
        }

    def test_fenced_block_with_array_of_objects(self):
        text = '```json\n{"actions": [{"type": "block", "ip": "1.2.3.4"}, {"type": "isolate", "host": "h1"}]}\n```'
        r = extract_json(text)
        assert r.ok is True
        assert r.data["actions"][0]["type"] == "block"
        assert r.data["actions"][1]["host"] == "h1"

    def test_multiple_fenced_blocks_picks_first_parseable(self):
        text = (
            'Reasoning:\n'
            '```\nnot json at all\n```\n'
            'Verdict:\n'
            '```json\n{"verdict": "benign"}\n```\n'
        )
        r = extract_json(text)
        assert r.ok is True
        assert r.data == {"verdict": "benign"}

    def test_fenced_block_prefers_over_bare(self):
        """If both a fenced block and a bare object exist, fenced wins (more
        intentional from the model's perspective)."""
        text = '{"old": "value"} but the real answer is ```json\n{"new": "value"}\n```'
        r = extract_json(text)
        assert r.ok is True
        assert r.data == {"new": "value"}
        assert "fenced_block" in r.attempt_log


class TestExtractJsonRepair:
    def test_trailing_comma_in_object(self):
        r = extract_json('{"a": 1, "b": 2,}')
        assert r.ok is True
        assert r.data == {"a": 1, "b": 2}
        assert "json_repair" in r.attempt_log

    def test_trailing_comma_in_array(self):
        r = extract_json('{"items": [1, 2, 3,]}')
        assert r.ok is True
        assert r.data == {"items": [1, 2, 3]}

    def test_single_quotes_in_fenced_block(self):
        # bare-object regex requires double-quoted keys; single quotes
        # only flow through when wrapped in a fenced block
        r = extract_json("```json\n{'verdict': 'benign'}\n```")
        assert r.ok is True
        assert r.data == {"verdict": "benign"}

    def test_smart_quotes(self):
        # "smart" / curly quotes that json.loads chokes on
        # Using actual curly quotes (U+201C and U+201D)
        r = extract_json('{“verdict”: “benign”}')
        assert r.ok is True
        assert r.data == {"verdict": "benign"}

    def test_truncated_unrepairable(self):
        # Truncated mid-object with no recoverable structure. json_repair
        # MAY silently complete it (acceptable) or fail (acceptable).
        # The contract is: no crash, and if ok=False, error is populated.
        r = extract_json('{"verdict": "true_positive", "evidence":')
        if not r.ok:
            assert r.error
            assert len(r.error) > 0
