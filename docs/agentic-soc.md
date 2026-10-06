# Agentic SOC — architecture, controls and operations

This document describes the Agentic SOC **as implemented** in this repository
(commits `793656b` through `293eec2`, October 2026). Every claim below names
the code that implements it and the test that proves it. Where something is
not implemented, it says so. The design rationale and the red-team findings
that shaped it are in `agentic-soc-rebuild-design.md`.

## 1. What it is

A guarded LLM agent that SOC analysts use through chat and that the platform
runs autonomously against new high-severity alerts. It can read platform data
through 66 typed tools and can *propose* containment actions; it cannot execute
a destructive action by itself. Every tool call passes a policy engine, every
decision is written to a hash-chained audit trail, and every LLM turn is
recorded with provider, model, tokens and cost.

| Surface | Entry point | Mode |
|---|---|---|
| Chat | `POST /api/v1/agentic/chat` (`src/api/v1/endpoints/agentic.py:chat_with_agent`) | interactive |
| Direct tool call | `POST /api/v1/agentic/tools/{name}/execute` | interactive |
| Approval of a proposal | `POST /api/v1/agentic/actions/{id}/approve` | approval |
| Rollback of an executed action | `POST /api/v1/agentic/actions/{id}/rollback` | approval |
| Structured threat hunt | `POST /api/v1/agentic/hunts` | interactive |
| ITDR response | `POST /api/v1/itdr/threats/{id}/respond` | interactive |
| Autonomous investigation | Celery `src.agentic.tasks.run_investigation` (`src/agentic/investigator.py:AutonomousInvestigator`) | autonomous |

## 2. Components

```
request/task ──► AgentContext (src/agentic/context.py)
                 org_id, role, mode, actor_user_id | soc_agent_id, run_id, propose_actions
       │
       ▼
 AgentRunner (src/agentic/runtime.py)
   admission ─► LLM turn ─► for each tool call: PolicyEngine ─► AgentToolRegistry.call
       │                                        │                     │
       ▼                                        ▼                     ▼
 src/llm/* providers                   src/agentic/policy.py    src/services/agent_tools.py
 (anthropic, gemini, openai, ollama)   8-step gate + audit      66 ToolSpecs, every query
 factory, quota, calllog, redact       src/agentic/trust.py     org-scoped (_scoped)
                                       scan + tiers + lockdown
```

* **Provider layer** (`src/llm/`): one `LLMProvider` protocol (`src/llm/base.py`)
  with adapters for Anthropic (official SDK, `src/llm/anthropic_provider.py`),
  Gemini, OpenAI and Ollama. Assistant turns are replayed from the provider's
  native content (`Message.provider_native`), so thinking blocks and Gemini
  thought signatures survive multi-step tool loops. `src/llm/factory.py`
  resolves the provider per organization: an org's own `ai` settings and
  credentials are authoritative; the platform key is used only when the org has
  opted in (`use_platform_default`). Hosts are fixed in code; tenants supply
  keys, never URLs.
* **Quota and breaker** (`src/llm/quota.py`): reserve-then-settle token budgets
  per org and day, split between interactive and autonomous buckets; run
  admission (per-user runs/minute, per-user and per-org concurrency); a circuit
  breaker per provider/credential/org.
* **Call log** (`src/llm/calllog.py`, table `llm_call_logs`): one row per LLM
  turn, including failures, with provider, model, credential source, prompt
  version, tools offered, message hash, normalized usage and cost.
* **Redaction** (`src/core/redact.py`): one function applied to outbound
  provider payloads, persisted tool results, audit rows and error responses.
* **Tool registry** (`src/services/agent_tools.py`): `ToolSpec` per tool with
  typed parameters, declared effects, tier (`read`/`write`/`destructive`/
  `privileged`), minimum role, the models it touches, and for destructive
  tools an `effective_targets` expansion. `AgentToolRegistry.call` is the only
  execution path; composite tools dispatch sub-actions through `_sub_call` so
  each gets its own decision and audit pair.
* **Policy engine** (`src/agentic/policy.py`): the gate in §3.
* **Trust layer** (`src/agentic/trust.py`): untrusted-content boundary and
  injection scanner in §4.
* **Runtime** (`src/agentic/runtime.py`): the loop in §5.
* **Investigator** (`src/agentic/investigator.py`): autonomous mode in §6.
* **Settings** (`src/api/v1/endpoints/settings.py`): `GET/PUT /settings/ai`,
  live model discovery, encrypted secrets at rest (§7).

## 3. Policy order (every tool call)

`PolicyEngine.evaluate` runs these checks in order and stops at the first
denial. Reason codes are the strings returned to the model and recorded in the
audit row. Tests: `tests/unit/test_policy_matrix.py`.

1. **Schema** — arguments validated against the tool's JSON schema
   (`additionalProperties: false`, ranges, enums, 16 KB cap) → `invalid_arguments`.
2. **Role** — caller role ≥ the tool's `min_role`; viewers may only call read
   tools → `role_not_permitted`.
3. **Mode** — autonomous runs may call only the read-only evidence allow-list
   plus the terminal `submit_verdict` tool → `autonomous_mode_readonly`.
   Interactive runs turn destructive/privileged tools into **proposals**
   (decision `propose`), never executions; `proposal_disabled` when the user
   did not enable proposals. Approval mode executes after the remaining checks;
   privileged tools require an admin approver.
4. **Trust** — in lockdown every write tool is denied except the two
   documentation tools (`add_incident_note`, `update_incident_findings`) →
   `injection_lockdown`. Approval mode inherits the originating run's tier.
5. **Tenant references** — every `*_id` argument, recursively through nested
   objects and lists, must resolve to a row in the caller's organization
   (`cross_tenant_reference`, reported like not-found); by-value targets
   (email, hostname, indicator value) are resolved in-org and rewritten to ids
   (`value_not_in_org`, `ambiguous_target`); semantic validators cover IP
   targets and `disable_user` (never the actor, never a superuser; targeting an
   admin escalates the tool to privileged).
6. **Effective targets** — destructive tools must expand their concrete
   targets; each must resolve in-org; more than 25 → `too_many_targets`.
7. **Rate** — Redis token bucket per org and tool for write tools; when Redis is
   unavailable the engine counts recent audit rows and fails closed.
8. **Audit** — the pre-decision row is written (`agent_policy/tool.allow|deny|
   propose`); after execution a second row records the outcome
   (`agent_tool/tool.executed|failed|blocked`). Audit failure aborts execution.

## 4. Untrusted content and prompt injection

Tests: `tests/unit/test_trust_scanner.py` (52-payload attack corpus, benign SOC
corpus with a 5 % false-positive ceiling), `tests/unit/test_agent_runtime.py`.

* The system prompt (`src/agentic/prompts.py`, `PROMPT_VERSION`) states the
  hierarchy: operator instructions > tool schemas > data. Every alert, log,
  ticket, tool result and replayed history item is wrapped in a labelled data
  block with a per-turn nonce; content inside a block is evidence, never an
  instruction. Seed context for investigations is delivered as a synthetic
  tool result, not free text.
* `scan_for_injection` runs over the **raw** payload (recursively, after
  decoding nested JSON and normalising encodings) before truncation and scores
  families: instruction override, role hijack, tool coercion, exfiltration,
  marker spoofing, boundary forging and obfuscation. Scores accumulate across
  the run and across records in a list result.
* Two tiers: `flagged` (banner, proposals marked suspect) and `lockdown`
  (write tools denied). The tier is persisted on the chat session and on the
  investigation and is **sticky** until an analyst acknowledges it
  (`POST /agentic/trust/acknowledge`, audited). Stored hits carry a hash and a
  40-character redacted preview, never the raw payload.
* Mechanical honesty: the "Actions taken" panel is built only from the tool
  ledger; if the model attempted a write and nothing executed, the reply is
  prefixed with "No actions were executed this turn."

## 5. Runtime behaviour

* Tool calls are dispatched only when the provider reports
  `stop_reason == tool_use`; a turn cut off by `max_tokens` is retried once
  with a doubled budget and its tool calls are dropped (`dropped_truncated`),
  never executed with truncated arguments. Refusals produce no fabrication.
* All results of a turn return in one user message; parallel calls are capped
  at 8; cumulative tool-result context is elided beyond 64 KB; history replay is
  bounded (12 turns / 24 KB).
* Limits: interactive 6 steps / 8 192 tokens per turn / 150 k tokens per run /
  90 s; autonomous 15 steps / 4 096 / 120 k / 600 s. One retry on transient
  provider errors; a circuit breaker short-circuits an unhealthy provider.
* Failure is honest: provider errors surface as HTTP 503
  (`llm_not_configured`, `llm_unavailable`, `llm_provider_error`), quota as
  429 with `Retry-After`; the user's message is persisted with a failed status
  so the UI can retry. There is no heuristic fallback of any kind.

## 6. Autonomous investigations

`AutonomousInvestigator.run` (`src/agentic/investigator.py`), tests in
`tests/unit/test_autonomous_investigator.py`.

* Runs in autonomous mode: only read-only evidence tools plus `submit_verdict`
  are offered; a destructive call is denied, never proposed.
* `Investigation.outcome` is one of `verdict`, `inconclusive_budget`,
  `refused`, `provider_error`, `injection_suspected`, `queued_budget_exceeded`,
  `llm_not_configured`, `setup_error`. `confidence_score` is NULL unless a real
  verdict was produced. Lockdown outranks a verdict.
* Recommended actions become `AgentAction` proposals (≤ 5 per investigation,
  ≤ 50 pending per org per hour) only when each target has provenance in a
  structured field reachable from the trigger; a target that exists only in
  untrusted text becomes a human task (`tool_name` NULL).
* Celery (`src/agentic/tasks.py`): dedicated `investigations` queue with time
  limits; auth/not-configured/quota/invalid-response errors do not retry and set
  `llm:disabled:{org}` for an hour; kickoff is admission-gated by the autonomous
  budget and per-org concurrency (3) and hourly (20) caps.

## 7. Configuration and secrets

* `GET/PUT /api/v1/settings/ai` (admin): provider, model (validated live against
  the provider's model list before anything is persisted), `use_platform_default`,
  key fingerprint and rotation time. Keys are stored enveloped (`enc:v1`) in the
  organization's `InstalledIntegration` row; settings sections envelope every
  secret value at rest (`src/core/secrets.py`). Audit events `ai.provider.set`
  and `ai.key.rotated` carry only the fingerprint.
* Environment (`.env.example`): `LLM_PROVIDER` (default `gemini`), `LLM_MODEL`,
  `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OLLAMA_BASE_URL`,
  `LLM_DAILY_TOKEN_BUDGET`, `LLM_AUTONOMOUS_DAILY_TOKEN_BUDGET`,
  `LLM_USER_RUNS_PER_MINUTE`, `LLM_USER_CONCURRENCY`, `LLM_ORG_CONCURRENCY`,
  `LLM_LOG_RETENTION_DAYS`. `ENCRYPTION_MASTER_KEY` is **required**: migration
  020 refuses to run without it and the API refuses to start the ephemeral-key
  path outside development.
* Egress: `deploy/kubernetes/base/networkpolicy-llm-egress.yaml` restricts the
  api/worker/scheduler pods to DNS, in-cluster dependencies and TCP/443 to
  public address space (metadata and private ranges blocked); the Cilium
  variant pins the three provider hostnames.

## 8. Threat model (STRIDE)

| Threat | Mitigation | Test |
|---|---|---|
| Prompt injection via alert/log text steers a tool call | Data blocks + scanner + lockdown; destructive tools are proposals only | `test_obedient_model_with_injected_alert_only_proposes_never_executes` |
| Cross-tenant read or write through the agent | Every registry query org-scoped; recursive tenant refs; by-value resolution in-org | `tests/unit/test_agent_tools_isolation.py` (every tool) |
| Privilege escalation via the chat toggle | Server-derived role; viewers read-only; `propose_actions` is a proposal switch, not authorization | `test_viewer_cannot_propose`, policy matrix |
| Approval of tampered or stale proposals | Approve must echo `params_sha256` + `evidence_sha256`; expiry; suspect proposals need admin acknowledgement | `tests/unit/test_agentic_approval_endpoints.py` |
| Rollback reversing the wrong rows | Reversal only by recorded effect ids, never by matching values | `tests/test_remediation_rollback.py` |
| Secret exfiltration via tool results or audit | Redaction at every sink; hits stored as hashes + short previews | `tests/unit/test_redact.py`, `test_sensitive_tool_results_are_redacted_before_provider_and_persistence` |
| Budget exhaustion / noisy neighbour | Reserve-then-settle budgets, split buckets, admission, breaker, fail-closed autonomous kickoff | `tests/unit/test_llm_quota.py`, investigator kickoff tests |
| Tenant-supplied provider URL → SSRF / IMDS | Fixed hosts; URLs rejected at the API; egress NetworkPolicy | `tests/unit/test_settings_ai.py` |
| Audit tampering or silent gaps | Hash-chained `audit_trails`; audit failure aborts execution | `tests/unit/test_audit_chain.py`, `test_post_audit_failure_fails_closed` |
| Fabricated analysis presented as real | No defaulted verdicts anywhere; honest `unavailable`/outcome states | `tests/unit/test_ai_engine_honest.py`, `test_llm_parsing_no_fakes.py` |

## 9. Operator runbook

* **"Blocked: injection_lockdown"** — the session or investigation touched
  content that scored as an injection. The banner names the family, preview and
  source record. Documentation tools still work. An analyst or admin can
  acknowledge the specific content hash via `POST /agentic/trust/acknowledge`
  with a reason; the acknowledgement is audited.
* **503 `llm_not_configured`** — the organization has no AI configuration and
  has not opted into the platform default. An admin sets it under Settings →
  AI Provider (`PUT /settings/ai`). `GET /health/llm` shows configured/source.
* **503 `llm_unavailable`** — the circuit breaker is open after repeated
  provider failures; it half-opens after 60 s. Check `GET /health/llm`.
* **429** — the per-user run rate, concurrency, or the org's daily token
  budget is exhausted; `Retry-After` is set. Budgets are per day and split
  between analysts and autonomous triage so one cannot starve the other.
* **Proposal cannot be approved** — the row has no integrity binding (created
  before this release) or has expired (72 h); re-run the investigation.
* **Autonomous triage paused** — a non-retryable LLM error set
  `llm:disabled:{org}` for an hour; fix the credentials under Settings → AI
  Provider and the flag expires.
* **Where to look** (all org-scoped; analyst role or above unless noted):
  `GET /agentic/runs/{run_id}` is the per-run timeline (audit rows, LLM calls,
  proposals joined); `GET /agentic/usage` totals tokens and cost from
  `llm_call_logs` (superusers may span organizations); `GET
  /agentic/policy-events` pages and filters every allow/deny decision;
  `GET /agentic/evidence/export` (admin only) returns the same as JSON or CSV
  for an auditor; `GET /agentic/actions/pending-approval` lists proposals with
  their hash binding; `GET /metrics/agentic` (admin only) is the in-process
  counter snapshot.

## 10. Control-to-code map

| Control | Implementation | Evidence |
|---|---|---|
| AC-3, AC-6(1) | `PolicyEngine` role and tier gates; admin-only settings; approval endpoint | `test_policy_matrix.py`, `test_agentic_approval_endpoints.py`, `test_settings_ai.py` |
| AC-4 | `AgentToolRegistry._scoped`, recursive tenant refs | `test_agent_tools_isolation.py` |
| AC-5 | Suspect proposals require admin acknowledgement with a reason (second-approver setting: not implemented, see §11) | approval tests |
| AU-2, AU-3, AU-12 | Pre/post audit rows per tool, `llm_call_logs` per turn | `test_audit_chain.py`, `test_call_log_records_are_complete_per_turn` |
| AU-9, AU-10 | `audit_trails.prev_hash/row_hash` chain; fail-closed audit | `test_audit_chain.py`, `test_post_audit_failure_fails_closed` |
| AU-6, AU-7 | Run timeline, policy-event review, usage totals and admin-only evidence export (JSON/CSV); ITDR respond routed through the same `guarded_tool_call` path | `test_agentic_read_surfaces.py`, `test_itdr_respond.py` |
| CM-7 | Autonomous read-only allow-list; effects-based tiers | `test_autonomous_offers_only_allowlisted_read_tools_and_ends_on_verdict` |
| SI-10 | Schema validation, injection scanner, semantic validators | `test_trust_scanner.py`, policy matrix |
| SC-5 | Admission, budgets, breaker | `test_llm_quota.py` |
| SC-7, SC-7(5) | Egress NetworkPolicy, fixed provider hosts | manifest; `test_settings_ai.py` |
| SC-8, SC-13 | TLS verification on every provider and probe call | `test_no_verify_false_in_settings` |
| SC-28 | Enveloped secrets at rest | `test_settings_section_encryption.py`, `test_llm_secrets_envelope.py` |

## 11. Not implemented / decisions pending

* **Second approver** (`require_second_approver`): no org setting exists yet;
  separation of duties is enforced only for suspect proposals (admin + reason).
* **Ingest-time scanning** of alerts and logs: the columns exist
  (`injection_score`, `injection_hits`) but scanning happens when content
  reaches the agent, not at ingestion.
* **Platform-key grandfathering**: existing tenants default to
  `use_platform_default=false`; autonomous triage for them records
  `llm_not_configured` until an admin configures a provider or opts in.
* **Metrics**: `GET /metrics/agentic` is an in-process registry (no
  `prometheus_client`); counters reset on restart.
* **Ingest-time memory bounds outside the agent**: the beat tasks that caused
  the September 2026 worker OOM (IOC sweep, feed polling, UEBA baselines,
  ITDR and exposure sweeps) are now windowed and capped, with per-child
  recycling at 300 MB. The dark-web, STIG, integrations, supply-chain and
  on-demand exposure tasks still load whole tables and are a follow-up.

## 12. Deploying this release

1. Prod requires `ENCRYPTION_MASTER_KEY` in `/opt/pysoar/.env` before
   `alembic upgrade head` (migration 020 backfills settings secrets and refuses
   to run without the key).
2. New Python dependency (`anthropic`): rebuild the image
   (`docker compose build api` then `docker builder prune -af` on the
   disk-constrained host).
3. `alembic upgrade head` (one revision, 020), then restart api/worker/scheduler.
4. Frontend bundle changed: swap `dist` and restart frontend + nginx.
5. Verify: `GET /health`, `GET /health/llm` (admin token), one chat turn with
   `propose_actions=false`.
