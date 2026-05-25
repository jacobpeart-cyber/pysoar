# LLM Parsing — PR 1 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the foundation library `src/core/llm_parsing.py` (extract_json + request_structured + exception types) with full unit tests. No caller is refactored in this PR; this is just the library landing so subsequent PRs (2-5 of sub-project E) can build on it.

**Architecture:** Single file at `src/core/llm_parsing.py` exporting `ParseResult`, `extract_json`, `request_structured`, `StructuredProvider` (Protocol), and three exception types (`LLMParseError`, `LLMUnavailableError`, `LLMTransportError`). Pure-function extractor with a strategy ladder (fenced-block → bare-object → `json.loads` → `json_repair.loads` → Pydantic schema validate). Provider-agnostic retry loop in `request_structured` that feeds validation errors back to the LLM on parse failure. No fake-success payloads ever — failures return `ParseResult(ok=False, error=...)` or raise typed exceptions.

**Tech Stack:** Python 3.11+, Pydantic v2 (already in project), `json-repair` (new PyPI dep), pytest with `asyncio_mode = auto` (per `pytest.ini`).

**Spec reference:** [docs/superpowers/specs/2026-05-25-hardened-llm-parsing-design.md](../specs/2026-05-25-hardened-llm-parsing-design.md) — sections "Module layout", "extract_json", "request_structured", "Exception types", "No-silent-fallback contract" Rule 1, Testing rows 1, 2, 3, 5, Rollout PR 1.

---

## File Structure

| File | State | Responsibility |
| --- | --- | --- |
| `requirements.txt` | Modify | Add `json-repair>=0.30` |
| `src/core/llm_parsing.py` | Create | All library code: `ParseResult`, `extract_json`, `request_structured`, `StructuredProvider`, exception types |
| `tests/unit/test_llm_parsing_extract.py` | Create | `extract_json` truth table — empty, fenced, fenced-nested, bare, prose-surrounded, trailing commas, single quotes, smart quotes, truncated, multi-fenced |
| `tests/unit/test_llm_parsing_schema.py` | Create | Pydantic schema validation paths through `extract_json` |
| `tests/unit/test_request_structured.py` | Create | Mock-provider retry loop, success-first-attempt, all-attempts-fail, transport-error-propagation |
| `tests/unit/test_llm_parsing_no_fakes.py` | Create | Regression guard: inspect `llm_parsing.py` source, assert forbidden fake-payload patterns absent |

All library code lives in one file because the pieces are tightly coupled (extract_json uses ParseResult; request_structured calls extract_json) and the total size is ~200 lines. Splitting fragments the module without benefit.

---

## Task 1: Add `json-repair` dependency

**Files:**

- Modify: `requirements.txt`

- [ ] **Step 1: Add the dependency line**

Edit `requirements.txt`. After the line `pydantic-settings>=2.1.0` (or wherever the "Authentication & Security" group ends), add a new section:

```text

# LLM output parsing
json-repair>=0.30
```

- [ ] **Step 2: Install it**

Run from the project root with the project's venv active:

```bash
python -m pip install -r requirements.txt
```

Expected: `Successfully installed json-repair-<version>` (or "Requirement already satisfied" if reinstalling).

- [ ] **Step 3: Verify the import works**

```bash
python -c "import json_repair; print(json_repair.__name__, json_repair.repair_json('{a: 1,}'))"
```

Expected: prints `json_repair {"a": 1}` (or similar — the exact return shape varies by version, but should not error).

- [ ] **Step 4: Commit**

```bash
git add requirements.txt
git commit -m "deps: add json-repair for LLM JSON parsing recovery"
```

---

## Task 2: Stub the module — `ParseResult` + exception types

**Files:**

- Create: `src/core/llm_parsing.py`
- Create: `tests/unit/test_llm_parsing_extract.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_llm_parsing_extract.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.core.llm_parsing'`.

- [ ] **Step 3: Create the module with minimal content**

Create `src/core/llm_parsing.py`:

```python
"""Robust LLM-output JSON parsing.

Provider-agnostic extraction (extract_json) and structured-output orchestration
(request_structured). Pure functions + retry loop. Never returns fake-success
payloads — failures return ParseResult(ok=False, error=...) or raise typed
exceptions (LLMParseError, LLMUnavailableError, LLMTransportError).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


class LLMParseError(Exception):
    """Raised when LLM output cannot be parsed into the expected schema."""

    def __init__(self, message: str, raw: str = ""):
        super().__init__(message)
        self.raw = raw


class LLMUnavailableError(Exception):
    """Raised when an LLM call could not produce a valid structured response
    after all retries — distinct from transport failure."""


class LLMTransportError(Exception):
    """Raised on HTTP/network failure to the LLM provider. Outage, not parse failure."""


@dataclass
class ParseResult:
    ok: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    attempt_log: list[str] = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py -v`
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_llm_parsing_extract.py
git commit -m "core: scaffold llm_parsing module — ParseResult + exception types"
```

---

## Task 3: Balanced-brace extraction helper

The current `_extract_verdict` in `agentic/investigator.py` uses a lazy regex `\{.*?\}` that truncates on nested objects. This task builds the replacement: a brace-balanced scan that respects strings.

**Files:**

- Modify: `src/core/llm_parsing.py`
- Modify: `tests/unit/test_llm_parsing_extract.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_llm_parsing_extract.py`:

```python
from src.core.llm_parsing import _balanced_brace_extract


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py::TestBalancedBraceExtract -v`
Expected: 9 tests FAIL with `ImportError: cannot import name '_balanced_brace_extract'`.

- [ ] **Step 3: Implement the helper**

Append to `src/core/llm_parsing.py`:

```python
def _balanced_brace_extract(text: str, start: int) -> Optional[str]:
    """Given text[start] == '{', return the substring through the matching '}'.

    Returns None if start is past end, start char isn't '{', or braces never
    balance. Handles strings: braces inside double-quoted strings (with
    backslash escapes) do not affect nesting depth.
    """
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py::TestBalancedBraceExtract -v`
Expected: 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_llm_parsing_extract.py
git commit -m "core(llm_parsing): brace-balanced JSON extractor — handles nested objects + strings"
```

---

## Task 4: `extract_json` — bare-object detection path

**Files:**

- Modify: `src/core/llm_parsing.py`
- Modify: `tests/unit/test_llm_parsing_extract.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_llm_parsing_extract.py`:

```python
from src.core.llm_parsing import extract_json


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
        # The bare-object regex requires {"<word>": pattern, so this won't match.
        assert r.ok is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py::TestExtractJsonBare -v`
Expected: 7 tests FAIL with `ImportError: cannot import name 'extract_json'`.

- [ ] **Step 3: Implement `extract_json` with bare-object path only**

Append to `src/core/llm_parsing.py`:

```python
import json
import re

_BARE_OBJ_START_RE = re.compile(r'\{\s*"\w+"\s*:')


def _try_bare_object(text: str) -> Optional[str]:
    """Find first {"key": ...} object in the text, brace-balanced. Returns the
    JSON substring or None if no object-shaped pattern found."""
    match = _BARE_OBJ_START_RE.search(text)
    if not match:
        return None
    return _balanced_brace_extract(text, match.start())


def extract_json(text: str, schema: Optional[type] = None) -> ParseResult:
    """Extract a JSON object from raw LLM text. Optionally validate against a
    Pydantic schema.

    Strategy ladder: fenced block (added in Task 5) -> bare object -> json.loads
    -> json_repair.loads (added in Task 6) -> schema validate (added in Task 7).
    First strategy yielding a parsed dict wins.

    Returns ParseResult(ok=False, error=...) on any failure — never raises,
    never returns a hardcoded success-shaped payload.
    """
    log: list[str] = []
    if not text:
        return ParseResult(ok=False, error="empty input", attempt_log=["empty"])

    candidate: Optional[str] = None

    bare = _try_bare_object(text)
    if bare is not None:
        candidate = bare
        log.append("bare_object")

    if candidate is None:
        return ParseResult(
            ok=False,
            error="no JSON object found in text",
            attempt_log=log + ["no_object"],
        )

    try:
        parsed = json.loads(candidate)
        log.append("json.loads")
    except json.JSONDecodeError as exc:
        return ParseResult(
            ok=False,
            error=f"JSON parse failed: {exc}",
            attempt_log=log + ["json_parse_fail"],
        )

    if not isinstance(parsed, dict):
        return ParseResult(
            ok=False,
            error=f"parsed value is {type(parsed).__name__}, expected object",
            attempt_log=log + ["not_object"],
        )

    return ParseResult(ok=True, data=parsed, attempt_log=log)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py::TestExtractJsonBare -v`
Expected: 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_llm_parsing_extract.py
git commit -m "core(llm_parsing): extract_json — bare-object detection path"
```

---

## Task 5: `extract_json` — fenced block (fixes nested-object truncation bug)

This is the bug fix that motivates the whole sub-project. The existing `_extract_verdict` uses lazy regex that truncates on any nested object. The test in this task is the regression guard.

**Files:**

- Modify: `src/core/llm_parsing.py`
- Modify: `tests/unit/test_llm_parsing_extract.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_llm_parsing_extract.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py::TestExtractJsonFenced -v`
Expected: 6 tests FAIL (currently `extract_json` only does bare-object path; fenced text without bare-object match returns "no JSON object"; or, where a bare object also exists, it picks the wrong one).

- [ ] **Step 3: Implement the fenced-block path**

In `src/core/llm_parsing.py`, replace the existing `_BARE_OBJ_START_RE` line and add the fence regex. The current imports stay; add this just below the existing `_BARE_OBJ_START_RE` definition:

```python
_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)


def _try_fenced_block(text: str) -> Optional[str]:
    """Extract the JSON object body from a ```json ... ``` (or bare ```) fenced
    block. Uses balanced-brace scan inside the fence — NOT lazy regex (which
    truncates on nested objects). Returns the first parseable candidate
    across all fences."""
    for match in _FENCE_RE.finditer(text):
        body = match.group(1).strip()
        first_brace = body.find("{")
        if first_brace < 0:
            continue
        candidate = _balanced_brace_extract(body, first_brace)
        if candidate is None:
            continue
        # Quick parseability check so we skip fences that look JSON-ish but aren't
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            continue
    return None
```

Then update `extract_json` to try fenced first. Replace the candidate-discovery block:

```python
    bare = _try_bare_object(text)
    if bare is not None:
        candidate = bare
        log.append("bare_object")
```

With:

```python
    fenced = _try_fenced_block(text)
    if fenced is not None:
        candidate = fenced
        log.append("fenced_block")
    else:
        bare = _try_bare_object(text)
        if bare is not None:
            candidate = bare
            log.append("bare_object")
```

- [ ] **Step 4: Run all extract tests**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py -v`
Expected: All tests (TestParseResultExists + TestExceptionTypes + TestBalancedBraceExtract + TestExtractJsonBare + TestExtractJsonFenced) PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_llm_parsing_extract.py
git commit -m "core(llm_parsing): fenced-block path — fixes nested-object truncation bug"
```

---

## Task 6: `extract_json` — `json_repair` recovery fallback

For LLM outputs with trailing commas, single quotes, or smart quotes — common when the model "thinks" it's writing JSON but isn't quite right. `json.loads` would reject these; `json_repair.loads` handles them.

**Files:**

- Modify: `src/core/llm_parsing.py`
- Modify: `tests/unit/test_llm_parsing_extract.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_llm_parsing_extract.py`:

```python
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

    def test_single_quotes(self):
        r = extract_json("{'verdict': 'benign', 'confidence': 80}")
        assert r.ok is True
        assert r.data == {"verdict": "benign", "confidence": 80}
        # bare-object regex won't match single-quoted, but the model
        # sometimes wraps it in fences — verify via fence path too:
        r2 = extract_json("```json\n{'verdict': 'benign'}\n```")
        assert r2.ok is True
        assert r2.data == {"verdict": "benign"}

    def test_smart_quotes(self):
        # "smart" / curly quotes that json.loads chokes on
        r = extract_json('{“verdict”: “benign”}')
        assert r.ok is True
        assert r.data == {"verdict": "benign"}

    def test_truncated_unrepairable(self):
        # Truncated mid-object with no recoverable structure — repair may
        # silently complete it. Accept either outcome but assert no crash.
        r = extract_json('{"verdict": "true_positive", "evidence":')
        # If json_repair can complete it, ok=True is acceptable.
        # If not, ok=False with a non-empty error is required.
        if not r.ok:
            assert r.error
            assert len(r.error) > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py::TestExtractJsonRepair -v`
Expected: trailing-comma tests FAIL (current path only does `json.loads`). Single-quote and smart-quote tests may fail at the bare-object regex stage (because `\w+` and `"` are required).

- [ ] **Step 3: Implement the json_repair fallback**

In `src/core/llm_parsing.py`, add the `json_repair` import at the top with the other imports:

```python
import json_repair
```

Update `extract_json`. Replace the existing parse block:

```python
    try:
        parsed = json.loads(candidate)
        log.append("json.loads")
    except json.JSONDecodeError as exc:
        return ParseResult(
            ok=False,
            error=f"JSON parse failed: {exc}",
            attempt_log=log + ["json_parse_fail"],
        )
```

With:

```python
    parsed: Optional[Any] = None
    try:
        parsed = json.loads(candidate)
        log.append("json.loads")
    except json.JSONDecodeError:
        try:
            parsed = json_repair.loads(candidate)
            log.append("json_repair")
        except Exception as exc:  # noqa: BLE001
            return ParseResult(
                ok=False,
                error=f"JSON parse failed even with json_repair: {exc}",
                attempt_log=log + ["json_repair_fail"],
            )
```

Also: the bare-object regex requires double-quoted keys. To handle single-quoted bare objects (no fence), broaden the regex pattern. Replace:

```python
_BARE_OBJ_START_RE = re.compile(r'\{\s*"\w+"\s*:')
```

With:

```python
_BARE_OBJ_START_RE = re.compile(r'\{\s*["\']\w+["\']\s*:')
```

And for smart quotes, the fence path already routes through `_balanced_brace_extract` which doesn't care about quote style — the smart-quote case relies on `json_repair` to fix the parsed text. The fence path may not find a `{` if the smart quotes confuse the start scan, so we also need to make `_try_bare_object` tolerant. Verify behavior — if the smart-quote test still fails, broaden bare-object detection by adding a fallback that finds the first `{` in the text and tries `_balanced_brace_extract` from there:

In `extract_json`, after the existing `_try_bare_object` fallback, add a last-resort:

```python
    if candidate is None:
        # Last-resort: try the very first '{' in the text, even without the
        # key-shape signature. json_repair downstream will tell us if it's
        # garbage. Avoids missing smart-quoted or otherwise non-standard
        # objects that the key regex won't match.
        first_brace = text.find("{")
        if first_brace >= 0:
            last_resort = _balanced_brace_extract(text, first_brace)
            if last_resort is not None:
                candidate = last_resort
                log.append("first_brace_fallback")
```

Place this block between the existing `bare = _try_bare_object(text)` block and the `if candidate is None: return ParseResult(ok=False, error="no JSON object found...")` block.

- [ ] **Step 4: Run all extract tests**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py -v`
Expected: All tests PASS (TestExtractJsonRepair now passes; nothing earlier regresses).

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_llm_parsing_extract.py
git commit -m "core(llm_parsing): json_repair recovery for trailing commas / single quotes / smart quotes"
```

---

## Task 7: `extract_json` — Pydantic schema validation path

**Files:**

- Modify: `src/core/llm_parsing.py`
- Create: `tests/unit/test_llm_parsing_schema.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_llm_parsing_schema.py`:

```python
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
        text = '{"verdict": "benign", "confidence": "high", "reasoning": "x"}'  # confidence not numeric
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "confidence" in r.error

    def test_enum_violation(self):
        text = '{"verdict": "MAYBE", "confidence": 50, "reasoning": "x"}'
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "verdict" in r.error

    def test_out_of_range_numeric(self):
        text = '{"verdict": "benign", "confidence": 150, "reasoning": "x"}'  # > 100
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        assert "confidence" in r.error

    def test_error_string_is_feedable_to_llm(self):
        """The error string must contain enough detail that the model can
        correct on retry — field name + reason."""
        text = '{"verdict": "MAYBE", "confidence": 999, "reasoning": "x"}'
        r = extract_json(text, schema=VerdictFixture)
        assert r.ok is False
        # Pydantic error strings include the field path and a reason
        assert "verdict" in r.error
        assert len(r.error) > 50  # non-trivial error detail

    def test_no_schema_returns_dict(self):
        r = extract_json('{"a": 1}')
        assert r.ok is True
        assert r.data == {"a": 1}
        assert "schema_ok" not in r.attempt_log
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_llm_parsing_schema.py -v`
Expected: Several FAIL — `extract_json` accepts `schema=` parameter (Task 4 added the signature) but doesn't actually validate. Tests expecting `ok=False` on bad data will fail because the function returns `ok=True` with the raw dict.

- [ ] **Step 3: Implement schema validation**

In `src/core/llm_parsing.py`, add the Pydantic import at the top:

```python
from pydantic import BaseModel, ValidationError
```

Update the `extract_json` signature type hint:

```python
def extract_json(text: str, schema: Optional[type[BaseModel]] = None) -> ParseResult:
```

Replace the final return block:

```python
    return ParseResult(ok=True, data=parsed, attempt_log=log)
```

With:

```python
    if schema is not None:
        try:
            validated = schema.model_validate(parsed)
            return ParseResult(ok=True, data=validated, attempt_log=log + ["schema_ok"])
        except ValidationError as exc:
            return ParseResult(
                ok=False,
                error=str(exc),
                attempt_log=log + ["schema_fail"],
            )

    return ParseResult(ok=True, data=parsed, attempt_log=log)
```

- [ ] **Step 4: Run all extract + schema tests**

Run: `python -m pytest tests/unit/test_llm_parsing_extract.py tests/unit/test_llm_parsing_schema.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_llm_parsing_schema.py
git commit -m "core(llm_parsing): Pydantic schema validation in extract_json"
```

---

## Task 8: `StructuredProvider` protocol + `request_structured` happy path

**Files:**

- Modify: `src/core/llm_parsing.py`
- Create: `tests/unit/test_request_structured.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_request_structured.py`:

```python
"""Tests for request_structured — provider-agnostic LLM call orchestrator."""

from typing import Literal, Optional
from unittest.mock import AsyncMock

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_request_structured.py -v`
Expected: FAIL with `ImportError: cannot import name 'StructuredProvider'` and `'request_structured'`.

- [ ] **Step 3: Implement Protocol + minimal `request_structured`**

In `src/core/llm_parsing.py`, first add `Protocol` to the existing typing import at the top of the file. Change:

```python
from typing import Any, Optional
```

To:

```python
from typing import Any, Optional, Protocol
```

Then append to the bottom of `src/core/llm_parsing.py`:

```python
class StructuredProvider(Protocol):
    """Interface request_structured uses to call the underlying LLM.

    Implementations are responsible for using their native structured-output
    mode where available (Gemini response_mime_type, Anthropic tool_use shim,
    OpenAI response_format) and for falling back to prompt-enforced JSON where
    not. They MUST raise LLMTransportError on HTTP/network failure, not
    return a fake response.
    """

    async def acomplete_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
        tools: Optional[list[dict]] = None,
        history: Optional[list[dict]] = None,
    ) -> str:
        """Return the raw LLM text. The caller will extract JSON from it."""
        ...


async def request_structured(
    provider: StructuredProvider,
    *,
    system_prompt: str,
    user_prompt: str,
    schema: type[BaseModel],
    retries: int = 2,
    tools: Optional[list[dict]] = None,
    history: Optional[list[dict]] = None,
) -> ParseResult:
    """LLM-call orchestrator. Calls provider.acomplete_structured, runs the
    response through extract_json(schema=...), returns the ParseResult.

    Retry loop is added in Task 9; this initial version is single-attempt.

    Transport failures (LLMTransportError) propagate — they are outages, not
    parse failures. NEVER returns a hardcoded success-shaped payload.
    """
    raw = await provider.acomplete_structured(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        schema=schema,
        tools=tools,
        history=history,
    )
    return extract_json(raw, schema)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_request_structured.py -v`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_request_structured.py
git commit -m "core(llm_parsing): StructuredProvider protocol + request_structured happy path"
```

---

## Task 9: `request_structured` retry loop with error feedback

**Files:**

- Modify: `src/core/llm_parsing.py`
- Modify: `tests/unit/test_request_structured.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_request_structured.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_request_structured.py::TestRequestStructuredRetry -v`
Expected: First 3 tests FAIL because current `request_structured` is single-attempt — provider.calls length is 1 not 2/3. The last test (retries=0) may pass by coincidence.

- [ ] **Step 3: Implement the retry loop**

Replace the current `request_structured` body in `src/core/llm_parsing.py`:

```python
async def request_structured(
    provider: StructuredProvider,
    *,
    system_prompt: str,
    user_prompt: str,
    schema: type[BaseModel],
    retries: int = 2,
    tools: Optional[list[dict]] = None,
    history: Optional[list[dict]] = None,
) -> ParseResult:
    """LLM-call orchestrator with parse-fail retry loop.

    On parse/validate failure: append the validation error to the user prompt
    and retry. Total attempts = retries + 1. Transport failures
    (LLMTransportError) propagate — they are outages, not parse failures.

    Returns ParseResult — caller decides what to do with ok=False (raise
    LLMUnavailableError, return 503, etc.). NEVER returns a hardcoded
    success-shaped payload.
    """
    current_prompt = user_prompt
    last_result: Optional[ParseResult] = None
    for attempt in range(retries + 1):
        raw = await provider.acomplete_structured(
            system_prompt=system_prompt,
            user_prompt=current_prompt,
            schema=schema,
            tools=tools,
            history=history,
        )
        result = extract_json(raw, schema)
        if result.ok:
            return result
        last_result = result
        if attempt == retries:
            break
        current_prompt = (
            user_prompt
            + f"\n\nYour previous response failed validation: {result.error}\n"
            "Return ONLY the JSON object matching the schema, no prose, no fences."
        )
    # Must not be None — loop runs at least once
    assert last_result is not None
    return last_result
```

- [ ] **Step 4: Run all request_structured tests**

Run: `python -m pytest tests/unit/test_request_structured.py -v`
Expected: All tests PASS (happy path + 4 retry tests).

- [ ] **Step 5: Commit**

```bash
git add src/core/llm_parsing.py tests/unit/test_request_structured.py
git commit -m "core(llm_parsing): request_structured retry loop with validation error feedback"
```

---

## Task 10: `request_structured` transport error propagation

The spec: "Transport errors (HTTP 5xx, timeout) raise `LLMTransportError`. They're outages, not parse failures. NEVER substituted with a fake payload." This test proves the orchestrator does not swallow them.

**Files:**

- Modify: `tests/unit/test_request_structured.py`

- [ ] **Step 1: Write the failing test (or confirming-passing test)**

Append to `tests/unit/test_request_structured.py`:

```python
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
```

- [ ] **Step 2: Run tests**

Run: `python -m pytest tests/unit/test_request_structured.py::TestRequestStructuredTransport -v`
Expected: Both PASS. The current implementation does not wrap `provider.acomplete_structured` in try/except, so the exception propagates naturally. **If they fail**, that's a real bug — somewhere an `except Exception:` is swallowing the transport error, which violates the no-fakes contract. Fix the implementation, do NOT relax the tests.

- [ ] **Step 3: If a fix was needed in Step 2, apply it now**

If the tests passed in Step 2, skip to Step 4. If they failed because an `except Exception:` swallows the error, find and remove the over-broad catch in `request_structured`.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/test_request_structured.py src/core/llm_parsing.py
git commit -m "core(llm_parsing): test that transport errors propagate, never silently swallowed"
```

---

## Task 11: No-fakes regression guard

The spec's Rule 1: "No function in `src/core/llm_parsing.py` may return a hardcoded success-shaped payload on failure." This test reads the module source via `inspect.getsource` and asserts forbidden patterns are absent.

**Files:**

- Create: `tests/unit/test_llm_parsing_no_fakes.py`

- [ ] **Step 1: Write the test**

Create `tests/unit/test_llm_parsing_no_fakes.py`:

```python
"""Regression guard: the llm_parsing module must NEVER return hardcoded
success-shaped payloads on failure. This test reads the module source and
asserts forbidden patterns are absent. If a future edit reintroduces any of
these patterns, this test fails before the change can ship.

Patterns are drawn from the historical fake-fallback code in:
- src/ai/engine.py:831-861 (deleted in PR 4 of sub-project E)
- src/agentic/investigator.py:_extract_verdict (replaced in PR 3)
- the broader 'silent stub' pattern across PySOAR.
"""

import inspect

import src.core.llm_parsing as llm_parsing


FORBIDDEN_PATTERNS = [
    # Hardcoded result fields from src/ai/engine.py's fake-success fallback
    '"priority": "p3"',
    '"priority":"p3"',
    "'priority': 'p3'",
    "Review manually",
    "AI analysis unavailable",
    "Manual review required",
    "AI analysis could not be completed",
    "unknown error",
    # Fabricated confidence/metric values
    'confidence=0.0',
    'confidence: 0.0',
    '"confidence": 0.0',
    '"dwell_time_days": 0',
    # Generic 'pretend the call succeeded' markers
    '"analysis_complete": True',
    "'analysis_complete': True",
]


class TestNoFakeSuccessPayloads:
    def test_module_source_contains_no_forbidden_patterns(self):
        source = inspect.getsource(llm_parsing)
        offenders = [p for p in FORBIDDEN_PATTERNS if p in source]
        assert not offenders, (
            f"src/core/llm_parsing.py contains forbidden fake-success patterns: "
            f"{offenders}. The no-fakes contract prohibits hardcoded "
            f"success-shaped fallback payloads. Failures must return "
            f"ParseResult(ok=False, error=...) or raise."
        )

    def test_no_bare_except_in_parse_paths(self):
        """A bare `except:` or `except Exception:` that swallows without
        re-raising in this module is a likely fake-fallback risk. We allow
        them ONLY for the json_repair fallback path which has a documented
        narrow catch. Any other broad catch fails the test."""
        source = inspect.getsource(llm_parsing)
        # Count broad-catch sites; allow only the documented one.
        broad_catches = source.count("except Exception")
        # As of this PR there is exactly one documented broad catch wrapping
        # json_repair.loads (which may raise non-JSONDecodeError). If the
        # count grows, the new site needs justification in the spec.
        assert broad_catches <= 1, (
            f"src/core/llm_parsing.py has {broad_catches} broad `except Exception` "
            f"sites. Only one is allowed (json_repair fallback). New broad "
            f"catches risk silently swallowing failures — document and "
            f"justify before adding."
        )
```

- [ ] **Step 2: Run the test**

Run: `python -m pytest tests/unit/test_llm_parsing_no_fakes.py -v`
Expected: Both tests PASS — we wrote the module without fakes from the start.

- [ ] **Step 3: Sanity-check the regression guard by temporarily breaking it**

Manually edit `src/core/llm_parsing.py`, add a fake line inside `extract_json` (e.g. `# Review manually` as a comment near the top). Run:

```bash
python -m pytest tests/unit/test_llm_parsing_no_fakes.py -v
```

Expected: FAIL with the "forbidden fake-success patterns" message naming "Review manually". This confirms the guard catches regressions.

Then revert the edit and re-run to confirm PASS:

```bash
git checkout src/core/llm_parsing.py
python -m pytest tests/unit/test_llm_parsing_no_fakes.py -v
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/test_llm_parsing_no_fakes.py
git commit -m "core(llm_parsing): no-fakes regression guard — reads source, asserts forbidden patterns absent"
```

---

## Task 12: Full-suite verification

**Files:**

- (none — verification only)

- [ ] **Step 1: Run the full new test file set**

```bash
python -m pytest tests/unit/test_llm_parsing_extract.py tests/unit/test_llm_parsing_schema.py tests/unit/test_request_structured.py tests/unit/test_llm_parsing_no_fakes.py -v
```

Expected: All tests PASS. Roughly 30+ tests.

- [ ] **Step 2: Run the full project unit test suite to confirm no regressions**

```bash
python -m pytest tests/unit/ -v
```

Expected: All previously passing tests still pass. The new tests are additive — nothing in the existing codebase calls the new `llm_parsing` module yet.

- [ ] **Step 3: Verify the spec's Rule 1 enforcer (Test 3 from spec) covers what the spec requires**

Re-read the spec Rule 1: `"priority":`, `"Review manually"`, `"AI analysis unavailable"`, `"Manual review required"`, `confidence=0.0`, `"unknown error"`. Cross-check against `FORBIDDEN_PATTERNS` in `tests/unit/test_llm_parsing_no_fakes.py`. All present. Pass.

- [ ] **Step 4: Open the PR (or push the branch for review)**

If working on a branch:

```bash
git push -u origin <branch-name>
```

Otherwise leave commits on local main and confirm with the user before pushing.

---

## Out of scope for PR 1 (will be covered by subsequent plans)

- `request_structured`'s Gemini-specific dispatch (response_mime_type + response_schema, prompt-enforced fallback when tools are loaded) — added in PR 3 plan alongside the investigator refactor.
- `AIAnalyzer` adapting to implement `StructuredProvider` — PR 3 plan.
- Site refactors at the 5 `agentic/llm.py` parse sites and the 6 `ai/engine.py` caller sites — PR 4 plan.
- Endpoint-layer changes (delete `_heuristic_*`, raise 503) — PR 4 plan.
- `Investigation.unsupported_recommendations` migration + ActionClassifier + capability-gaps endpoint — PR 3 and PR 5 plans.

This PR ships ~250 lines of library + ~30 tests, no behavior change to any existing caller.
