# Hardened LLM-Output Parsing — Design

**Date:** 2026-05-25
**Sub-project:** E of the PySOAR audit-gap roadmap
**Status:** Draft, awaiting user approval before plan generation

---

## Problem

Eight sites across the codebase parse LLM output as JSON (the verdict extractor, the action-classification regex pile, `_call_llm(structured_output=True)`, and five sites in `agentic/llm.py`). They fail in three ways:

1. **Brittle extraction.** `_extract_verdict` in [src/agentic/investigator.py:152](../../../src/agentic/investigator.py#L152) uses a lazy-match regex `\{.*?\}` that silently truncates on any nested object or array. It works today only because the verdict schema happens to be all primitives plus flat string arrays — a schema change would break it.
2. **Silent fake-success fallback.** `_call_llm(structured_output=True)` in [src/ai/engine.py:781](../../../src/ai/engine.py#L781) returns a hardcoded `{"priority": "p3", "reasoning": "AI analysis unavailable", "recommended_actions": ["Review manually"], ...}` payload when the LLM call fails or the response fails to parse. Callers receive a result indistinguishable from a real one. This is the worst pattern in the codebase — it fabricates a working AI verdict from nothing.
3. **Regex-pile for English-to-action translation.** [src/agentic/investigator.py:751+](../../../src/agentic/investigator.py#L751) `_ACTION_RULES` is ~15 hand-tuned regex patterns trying to turn LLM-generated English recommendations ("block IP 1.2.3.4 at the firewall") into structured action calls. Brittle, expand-as-Gemini-rewords, no test coverage for the patterns it misses.

Plus five naked `json.loads(response.content)` sites in [src/agentic/llm.py](../../../src/agentic/llm.py) (lines 604, 635, 661, 689, 739) with zero fence-stripping.

## Goals

1. One robust JSON-extraction helper used across all LLM-output sites.
2. Use Gemini's structured-output mode (`response_mime_type: "application/json"` + `response_schema`) wherever function-calling isn't in play, so the model is constrained at generation time, not filtered afterward.
3. Delete every fake-success fallback **and every heuristic substitution**. AI endpoints that fail report `503` honestly; they never serve a substitute product labeled as the requested one.
4. Replace the action-classification regex pile with a structured LLM call against a closed enum of action types that have been verified to map end-to-end to real handlers.
5. Make the system's capability gaps visible: any recommendation the system cannot mechanically execute is recorded on the investigation and aggregated into a `/capability-gaps` endpoint, not buried in a ticket queue.

## Non-Goals

- Adding new action handlers (block_ip, isolate_host, etc.) — this sub-project only uses what's already verified to exist.
- Replacing the LLM provider (Gemini stays).
- Touching the older heuristic `agentic/engine.py` path that the LLM-driven investigator already replaced.

## Architecture

### New module: `src/core/llm_parsing.py`

Two public surfaces.

**`extract_json(text, schema=None) -> ParseResult`** — provider-agnostic, pure function. Takes raw LLM text, returns a `ParseResult`.

```python
@dataclass
class ParseResult:
    ok: bool
    data: dict | BaseModel | None
    error: str | None         # populated iff ok=False; feedable to LLM on retry
    attempt_log: list[str]    # diagnostic only: ["fenced_block", "json_repair", "schema_fail"]
```

Extraction strategy ladder. First strategy that yields ok=True wins.

1. **Fenced block** — match ```` ```json ... ``` ```` or ```` ``` ... ``` ```` using a brace-balanced scan (not lazy regex). Fixes the existing truncation bug on nested objects.
2. **Bare object** — scan for first `{` followed by `"<word>"\s*:`, brace-balance to the matching `}`.
3. **`json.loads`** on the candidate substring.
4. **`json_repair.loads`** — handles trailing commas, unquoted keys, single quotes, smart quotes. Cheap, deterministic, no LLM call.
5. **Schema validate** (if `schema` provided) — `schema.model_validate(parsed)`. ValidationError formatted into `error` string suitable for retry-prompt feedback.

Contract:

- Pure function. No logging, no I/O, no global state.
- `ok=False` always carries an `error` string. **Never returns a hardcoded success-shaped payload.**

**`async request_structured(provider, *, system_prompt, user_prompt, schema, retries=2, tools=None, history=None) -> ParseResult`** — LLM-call orchestrator. Per-provider dispatch:

| Provider | Mechanism |
| --- | --- |
| Gemini (`AIAnalyzer`) | `generationConfig.response_mime_type: "application/json"` + `generationConfig.response_schema: pydantic_to_gemini_schema(schema)`. When `tools` is non-empty (function-calling active), Gemini disallows JSON mode, so fall back to prompt-enforced: append "Respond ONLY with JSON matching: {schema_text}". Investigator's verdict emission takes the prompt-enforced path because tools are always loaded; the action classifier (Group D) calls with `tools=None`, so JSON mode is fully available. |
| Anthropic (`AnthropicProvider`) | Force `tool_use` with a single synthetic tool whose `input_schema` is the Pydantic schema. Model is structurally required to call it. |
| OpenAI (`OpenAIProvider`) | `response_format={"type": "json_schema", "json_schema": ...}`. |
| Ollama / vLLM | Prompt-enforced; relies on `extract_json` for recovery. |

Retry loop:

```python
for attempt in range(retries + 1):
    raw = await provider_call(...)
    result = extract_json(raw, schema)
    if result.ok:
        return result
    if attempt == retries:
        return result   # ok=False, error populated; caller decides
    user_prompt += (
        f"\n\nYour previous response failed validation: {result.error}\n"
        f"Return ONLY the JSON object matching the schema, no prose."
    )
```

Transport errors (HTTP 5xx, timeout, connection reset) raise `LLMTransportError`. They're outages, not parse failures. **Never substituted with a fake payload.**

### Exception types (in `src/core/llm_parsing.py`)

- `LLMParseError` — raised by Group A callers when `extract_json` returns `ok=False` and retry isn't applicable.
- `LLMUnavailableError` — raised by `_call_llm` when `request_structured` returns `ok=False` after all retries.
- `LLMTransportError` — raised on HTTP/network failure. Distinct from parse failure because the remediation differs (outage = retry later; parse failure = prompt fix).

## Site refactors

### Group A — `src/agentic/llm.py` (5 sites)

Lines 604, 635, 661, 689, 739. Each is `return json.loads(response.content)` with no fence-stripping and no failure handling. Each becomes:

```python
result = extract_json(response.content, ThisCallSchema)
if not result.ok:
    raise LLMParseError(f"{caller_name}: {result.error}", raw=response.content)
return result.data
```

Each call site defines its own Pydantic schema next to it (`SimilarityScoreSchema`, `HypothesisSchema`, etc. — exact names chosen by reading what each site expects to receive). Schemas are co-located with consumers, not centralized.

### Group B — `_call_llm(structured_output=True)` in [src/ai/engine.py:781](../../../src/ai/engine.py#L781)

The current implementation is the worst offender. On parse failure it returns a hardcoded 10-field dict that looks like a real AI verdict. Replacement signature:

```python
def _call_llm(self, system_prompt, user_prompt, structured_output=False, schema=None) -> str | BaseModel:
    if structured_output:
        if schema is None:
            raise ValueError("structured_output=True requires schema=...")
        result = asyncio.run(request_structured(self, system_prompt=..., user_prompt=..., schema=schema))
        if not result.ok:
            raise LLMUnavailableError(result.error)
        return result.data
    # else: existing text path stays as-is
```

**Endpoint-layer architecture — no heuristic substitution.** The endpoints in [src/api/v1/endpoints/ai.py](../../../src/api/v1/endpoints/ai.py) currently have `_heuristic_*` fallbacks that produce rule-based output labeled `derivation="rule_based"` when the LLM is unavailable or fails. That labeling does not make the substitution honest — a caller invoking `/ai/analyze/incident/{id}` requested AI analysis, and serving them a different product (with a label) is still a substitution. **The labels go and so do the fallbacks.**

Replacement behavior: each AI endpoint always attempts the LLM call. On `LLMUnavailableError` (LLM not configured, transport failure, or all retries exhausted), the endpoint raises `HTTPException(status_code=503, detail={"error": "llm_unavailable", "message": "AI analysis requires Gemini API key. Configure GEMINI_API_KEY in /opt/pysoar/.env.", "method": "<method_name>"})`. No fallback path. No degraded-mode label. Either AI analysis was produced or the endpoint reports `503 Service Unavailable` and the caller decides.

**Deleted from `ai.py` in this sub-project:**

- `_llm_available()` (line 98) — removed from AI endpoints; if a diagnostics endpoint elsewhere needs LLM-configured status, that's a separate concern.
- `_heuristic_incident_analysis` (line 239) — substitution helper, no honest caller after fallback removal.
- `_heuristic_root_cause` (line 345) — same.
- `_heuristic_response_recommendations` (line 404) — same.
- `_derive_playbook_from_history` (used at lines 1612, 1620) — same.
- All `if _llm_available(): try: ... except: heuristic` blocks in the 4 endpoints.
- `derivation` field from all response payloads (always-LLM now, field is dead).
- `model_used = "heuristic-v1"` constant and its assignments (no heuristic mode exists).
- `confidence = 0.6` heuristic-mode literal in `generate_playbook` (line 1571).

Persistence: `AIAnalysis` DB rows are still written, but **only when the LLM call validates successfully**. No "heuristic AIAnalysis row" gets persisted. If the endpoint 503s, no row is created.

**Per-caller table.** Each of the 6 analyzer methods needs (a) a Pydantic schema, (b) its `.get("field", "<default>")` defensive defaults deleted (Pydantic guarantees the shape, so the defaults are dead code that hide partial-response stubs).

| Method (`ai/engine.py`) | Line | LLM produces | Pydantic schema | Silent defaults to delete | Endpoint |
| --- | --- | --- | --- | --- | --- |
| `analyze_alert` | 575 | priority/reasoning/confidence/fp_prob/recommended_actions | `AlertTriageSchema` | `.get("priority","p3")`, `.get("reasoning","Analysis incomplete")`, `.get("confidence",0.5)`, `.get("false_positive_probability",0.3)`, `.get("recommended_actions",[])` | `POST /ai/analyze/alert/{id}` |
| `summarize_incident` | 608 | executive_summary/technical_details/impact_assessment/recommendations | `IncidentSummarySchema` | `.get(...)` defaults + **`"analysis_complete": True` hardcoded** (fabricated claim that AI succeeded — worst offender, delete) | `POST /ai/analyze/incident/{id}` |
| `assess_threat` | 649 | threat_level/analysis/historical_context/predicted_impact | `ThreatAssessmentSchema` | `.get("threat_level","medium")` (fabricated medium-severity floor), `.get("analysis","")`, etc. | `POST /ai/assess/threat` |
| `recommend_response` | 679 | immediate_actions/containment/investigation/recovery/timeline_hours | `ResponseRecommendationSchema` | `.get(...)` defaults + **`.get("timeline_estimate_hours", 4)`** (fabricated number from nowhere) | `POST /ai/recommend/response/{id}` |
| `generate_playbook` | 712 | playbook_name/steps/conditions/automations/success_criteria | `PlaybookGenerationSchema` | **`.get("playbook_name", f"Response to {pattern}")`** (fabricated name), `.get("steps",[])`, etc. | `POST /ai/generate/playbook` |
| `analyze_root_cause` | 742 | root_cause/attack_chain/entry_point/dwell_time_days/confidence | `RootCauseAnalysisSchema` | `.get(...)` defaults + **`.get("dwell_time_days", 0)`** and **`.get("confidence", 0.5)`** (fabricated metrics) | `POST /ai/analyze/root-cause/{id}` |

Refactor pattern per method:

```python
def analyze_alert(self, alert_data: dict) -> AlertTriageSchema:
    # ... build prompts ...
    result = self._call_llm(system_prompt, user_prompt, structured_output=True, schema=AlertTriageSchema)
    return result   # already validated by Pydantic; no .get() defaults; raises LLMUnavailableError on failure
```

**Endpoint behavior tests.** For each of the 6 AI endpoints, write a test that asserts: (1) when `_call_llm` raises `LLMUnavailableError`, the endpoint returns `503` with body `{"error": "llm_unavailable", "message": ..., "method": ...}` and **does not** persist an `AIAnalysis` row, (2) when the LLM call succeeds, the endpoint returns 200 with the validated Pydantic payload and persists the row. No 200-with-degraded-payload path exists.

**Deleted code in PR 4 — comprehensive list:**

In `ai/engine.py`:

- Lines 831-841 — parse-failure fake 10-field "Review manually" return.
- Lines 849-861 — exception-handler fake payload.
- All `response.get("field", "<default>")` patterns in the 6 methods above (lines 599-606, 641-647, 672-677, 704-710, 735-740, 773-779) — replaced by direct attribute access on the validated Pydantic model.
- `"analysis_complete": True` hardcoded in `summarize_incident:646`.
- `"timeline_estimate_hours": 4` hardcoded in `recommend_response:709`.
- `f"Response to {incident_pattern}"` hardcoded fallback name in `generate_playbook:736`.
- `"dwell_time_days": 0` and `"confidence": 0.5` hardcoded in `analyze_root_cause:777-778`.

In `api/v1/endpoints/ai.py`:

- `_llm_available()` (line 98) and all 4 call sites in the AI endpoints.
- `_heuristic_incident_analysis` (line 239).
- `_heuristic_root_cause` (line 345).
- `_heuristic_response_recommendations` (line 404).
- `_derive_playbook_from_history` (referenced lines 1612, 1620).
- Every `if _llm_available(): try: ... except: heuristic` block in the 4 endpoints (around lines 1215, 1340, 1437, 1574).
- `derivation` field from response payloads and from response model schemas.
- `model_used = "heuristic-v1"` literal and assignments.
- `confidence = 0.6` heuristic-mode literal (line 1571).
- Any `_or_` defaults that mix LLM output with heuristic output (e.g. line 1228 `llm_out.get("executive_summary") or heuristic["executive_summary"]`).

### Group C — `_extract_verdict` in [src/agentic/investigator.py:152](../../../src/agentic/investigator.py#L152)

`VerdictSchema`:

```python
class VerdictSchema(BaseModel):
    verdict: Literal["true_positive", "false_positive", "benign", "inconclusive"]
    confidence: float = Field(ge=0, le=100)
    reasoning: str = Field(max_length=4000)
    hypothesis: str = Field(max_length=2000)
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
```

`_extract_verdict` + `_validate_and_normalize_verdict` (~80 lines combined) collapse to:

```python
def _extract_verdict(text: str) -> ParseResult:
    return extract_json(text, VerdictSchema)
```

The existing "persist a malformed_verdict step + soft transcript note" becomes a real retry inside `request_structured` (the next iteration's user prompt carries the validation error verbatim).

### Group D — action classifier replaces `_ACTION_RULES`

Current state: ~15 regex patterns in [investigator.py:751+](../../../src/agentic/investigator.py#L751) that try to turn English recommendations into structured action calls.

Replacement: one batched `request_structured` call after the verdict is finalized.

**Closed action enum** — every value maps end-to-end to a verified handler (see Phase 2 capability gate below):

```python
class ActionType(str, Enum):
    BLOCK_IP = "block_ip"                    # → remediation.engine.block_ip
    ISOLATE_HOST = "isolate_host"            # → agent command, capability=ir
    DISABLE_USER = "disable_user"            # → remediation.engine.disable_user
    RESET_CREDENTIALS = "reset_credentials"  # → remediation.engine.reset_credentials
    QUARANTINE_FILE = "quarantine_file"      # → agent command, capability=ir
    KILL_PROCESS = "kill_process"            # → agent command, capability=ir
    COLLECT_FORENSICS = "collect_forensics"  # → agent command, capability=ir

class ClassifiedAction(BaseModel):
    recommendation_text: str
    action_type: ActionType
    args: dict[str, Any]

class ActionClassification(BaseModel):
    actions: list[ClassifiedAction]
    unsupported: list[str]  # recommendations the model could not map to the enum
```

The classifier prompt enumerates exactly these action types and instructs Gemini: *if a recommendation does not map to one of these, place its text in `unsupported`, do not invent an action_type.* Gemini's structured-output mode constrains generation to the schema.

**`Investigation.unsupported_recommendations: list[str]`** (new column, real Alembic migration) captures the `unsupported` list. **`Investigation.status` enum extension** adds `partially_actionable`. If `unsupported_recommendations` is non-empty at finalization, the investigation enters `partially_actionable` instead of auto-resolving.

**`GET /api/v1/agentic/capability-gaps`** aggregates `unsupported_recommendations` across investigations. The system reports its own holes — countable, queryable, prioritizable.

No confidence floor. No "default to ticket" fallback. If Gemini emits something outside the enum, that lands in `unsupported` and stays visible.

## No-silent-fallback contract

Three rules enforced at the code-test level, not as principles.

**Rule 1: `src/core/llm_parsing.py` may not return hardcoded success-shaped payloads.** Test `tests/unit/test_llm_parsing_no_fakes.py` reads the module source via `inspect.getsource` and asserts absence of forbidden patterns: `"priority":`, `"Review manually"`, `"AI analysis unavailable"`, `"Manual review required"`, `confidence=0.0`, `"unknown error"`. If a future edit reintroduces the pattern, the test fails on import.

**Rule 2: Every refactored site loses its fake fallback in the same diff.** Spec lists exact lines:

- [ai/engine.py:831-841](../../../src/ai/engine.py#L831-L841) — "Failed to parse Gemini JSON" → 10-field "Review manually" return. **Delete.**
- [ai/engine.py:849-861](../../../src/ai/engine.py#L849-L861) — bare-except → "AI analysis unavailable" return with confidence 0.0. **Delete.**
- Each Group A site — naked `json.loads`. **Replace, do not wrap.**
- `_extract_verdict` + `_validate_and_normalize_verdict`. **Delete, replaced by `extract_json(text, VerdictSchema)`.**

**Rule 3: Capability verification gate before the classifier enum is final.** Phase 2 ships `tests/integration/test_action_handlers_are_real.py` first. It invokes each candidate handler with a minimal real payload against a fixture DB and asserts observable state change. Handlers that fail the gate do not enter the `ActionType` enum and become their own follow-up sub-project. The classifier ships only with the verified subset.

## Testing

| # | File | Proves |
| --- | --- | --- |
| 1 | `tests/unit/test_llm_parsing_extract.py` | `extract_json` truth table: well-formed, fenced, fenced-with-nested-objects (bug fix), bare-surrounded-by-prose, trailing commas, single quotes, smart quotes, truncated, empty, prose-only. Pure-function tests. |
| 2 | `tests/unit/test_llm_parsing_schema.py` | Pydantic validation paths: valid, missing required, wrong type, enum violation, out-of-range. Error string contains field name + reason (feedable to LLM). |
| 3 | `tests/unit/test_llm_parsing_no_fakes.py` | **Rule 1 enforcer.** |
| 4 | `tests/unit/test_ai_engine_no_fake_fallback.py` | **Rule 2 enforcer for `_call_llm`.** Forces parse failure, asserts `LLMUnavailableError`, asserts no dict returned. |
| 5 | `tests/unit/test_request_structured_retry.py` | Mock provider returns invalid JSON attempt 1, valid attempt 2. Asserts retry happens, error appears in attempt-2 prompt. |
| 6 | `tests/integration/test_action_handlers_are_real.py` | **Rule 3 enforcer.** Every handler in the classifier enum tested end-to-end against fixture DB. |
| 7 | `tests/unit/test_verdict_schema.py` | Regression: every valid `_validate_and_normalize_verdict` output validates against `VerdictSchema`; every invalid one rejects. |
| 8 | `tests/integration/test_unsupported_recommendation_surfaces.py` | Forces classifier to return unmapped recommendation. Asserts `Investigation.unsupported_recommendations` populated, status `partially_actionable`, `GET /agentic/capability-gaps` reports it. |
| 9 | `tests/integration/test_ai_endpoints_503_on_llm_unavailable.py` | For each of the 6 endpoints in `api/v1/endpoints/ai.py`: monkeypatch `_call_llm` to raise `LLMUnavailableError`, assert `503` response with body `{"error": "llm_unavailable", "message": ..., "method": ...}`, and assert no `AIAnalysis` DB row is persisted. Then test the success path: LLM returns valid data, endpoint returns 200 with the validated Pydantic payload, `AIAnalysis` row exists. No 200-with-degraded-payload path exists. |
| 10 | `tests/unit/test_ai_endpoints_no_heuristic_helpers.py` | Reads `src/api/v1/endpoints/ai.py` source via `inspect.getsource` and asserts the deleted heuristic helpers (`_heuristic_incident_analysis`, `_heuristic_root_cause`, `_heuristic_response_recommendations`, `_derive_playbook_from_history`, `_llm_available`) are absent. Regression guard against the pattern coming back. |

All tests added to the existing pytest suite gated by `pytest.ini`. No new framework.

## Rollout — 5 PRs

**PR 1 — Foundation.** `requirements.txt` adds `json-repair`. Create `src/core/llm_parsing.py` with `extract_json`, `ParseResult`, exception types. Ship tests 1, 2, 3, 5. No caller refactored yet.

**PR 2 — Capability gate.** Ship test 6. Run it. Whatever passes becomes the enum in a new `src/agentic/action_classifier.py` (schemas + enum only, no caller yet). Failed handlers filed as follow-up tickets.

**PR 3 — Investigator refactor.** `VerdictSchema`. Replace `_extract_verdict` + `_validate_and_normalize_verdict`. Add `request_structured` (Gemini path). Alembic migration for `unsupported_recommendations` + status enum. Implement and wire `ActionClassifier`. Ship tests 4, 7, 8.

**PR 4 — Sweep remaining sites + delete fakes + delete heuristic substitution.** Group A (5 sites). Group B: `_call_llm` signature change, per-method Pydantic schemas, delete `.get("field", "<default>")` defaults across all 6 methods, delete `ai/engine.py:831-861`. **Endpoint-layer changes:** delete `_llm_available`, the 4 `_heuristic_*` helpers, `_derive_playbook_from_history`, and every `if _llm_available(): try: ... except: heuristic` block in the 4 endpoints. Each endpoint now raises `HTTPException(503, ...)` on `LLMUnavailableError`. Remove `derivation` and `model_used="heuristic-v1"` from response payloads and schemas. Ship tests 9 and 10.

**PR 5 — Surface the gaps.** `GET /api/v1/agentic/capability-gaps` endpoint. Agent Console UI for `partially_actionable` investigations + capability-gaps panel. System reports its own holes.

Each PR is independently shippable and revertible. None silently regresses the previous one — Rule 1's enforcer test guards.

## Dependencies

- `json-repair` (PyPI, MIT) — added to `requirements.txt`.
- Pydantic v2 — already in stack.
- Alembic — already in stack.

No new runtime services. No new infra. No new test framework.

## Out of scope (named, so it doesn't smuggle back in)

- Adding new action handlers. The enum reflects only verified existing capabilities.
- Replacing the LLM provider.
- Touching `agentic/engine.py` heuristic path (already superseded).
- Routing for "IAM team" / "security awareness team" / etc. recommendations — those land in `unsupported_recommendations` and stay visible. If a routing module is built later, it's a separate sub-project.
- **Heuristic-substitution sweep in non-AI endpoints** — the same "fall back to a labeled rule-based product when the real thing isn't available" pattern exists in `darkweb.py`, `simulation.py`, `agentic.py`, `settings.py`, `integrations.py`, `backup.py`. Killing it everywhere is **sub-project H** (added to parent roadmap), to be done after sub-project E lands. Each module is a sub-PR with the same shape: identify the substitution helper, identify the gate, raise 503 honestly, delete the helper.
