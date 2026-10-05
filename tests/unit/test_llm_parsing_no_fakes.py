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

import pytest

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


class TestNoFakeSuccessPayloadsInTheLLMCallers:
    """The same contract for the two modules that used to break it.

    ``src/ai/engine.py``'s ``_call_llm`` fabricated a whole analysis on
    failure and ``src/agentic/investigator.py`` fabricated a 40% confidence
    when the model never produced a verdict. Both are rewritten on
    ``src/llm``; these patterns must not come back.
    """

    @pytest.mark.parametrize("module_name", ["src.ai.engine", "src.agentic.investigator"])
    def test_module_source_contains_no_forbidden_patterns(self, module_name):
        import importlib

        module = importlib.import_module(module_name)
        source = inspect.getsource(module)
        offenders = [p for p in FORBIDDEN_PATTERNS if p in source]
        assert not offenders, (
            f"{module_name} contains forbidden fake-success patterns: {offenders}. "
            f"A failed or absent LLM call must be reported, never answered with a "
            f"hardcoded success-shaped payload."
        )

    def test_investigator_does_not_fabricate_a_confidence(self):
        from src.agentic import investigator

        source = inspect.getsource(investigator)
        assert "or 40" not in source
        assert "confidence_score or" not in source

    def test_ai_engine_has_no_hardcoded_provider_endpoint(self):
        from src.ai import engine

        source = inspect.getsource(engine)
        assert "generativelanguage.googleapis.com" not in source
        assert "GEMINI_API_KEY" not in source
