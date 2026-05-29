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
        assert broad_catches == 1, (
            f"src/core/llm_parsing.py has {broad_catches} broad `except Exception` "
            f"sites. EXACTLY ONE is required (json_repair fallback). If you "
            f"removed it, update this guard. If you added one, document and "
            f"justify before adding."
        )
