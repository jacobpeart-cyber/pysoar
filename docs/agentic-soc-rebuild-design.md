# PySOAR Agentic SOC rebuild — design v2 (post red-team)

v1.1 was red-teamed by six adversarial lenses (58 attacks). v2 incorporates every attack that survives a code check, plus the two findings the scout added (F2: `require_role` unused platform-wide; F14: direct tool execute bypass). Findings F1–F14 from v1.1 still apply and are not repeated here.

Guiding rule (unchanged): real or honest. Nothing fabricated, nothing silently allowed, every decision auditable.

---

## 1. Architecture (revised)

```
 /agentic/chat ─┐                                  ┌─ Celery: autonomous_triage / run_investigation
 /tools/execute ┤   AgentRunner  (src/agentic/runtime.py)  ◄──┘   (AutonomousInvestigator)
 /actions/approve┤   ctx = {run_id, org, actor_user_id|soc_agent_id, role, mode, propose_actions, origin}
 /actions/rollback┤   loop: admit → LLM turn → (drop tool calls unless stop_reason==tool_use)
 /itdr respond  ─┘         → per call: policy → registry.call() → redact → wrap → results
        │                        │                      │                 │
   src/llm/*                policy.py              agent_tools.py      trust.py
   providers (native replay)  effects/role/refs/    ToolSpec-driven      ingest+result scan,
   factory (org authoritative) by-value/compose     org-scoped `_scoped` two tiers, sticky per
   quota (reserve→settle)     rate/audit(2 events)  registry.call()      session/investigation
   calllog (+hashes)          run admission         composite sub-calls   acknowledge endpoint
   redact (all sinks)         circuit breaker
```

Invariant: **no code path executes a tool handler except `AgentToolRegistry.call(ctx, tool, args)`**, which always runs `PolicyEngine.evaluate` first and writes the pre/post audit pair. Handlers are private (`_`-prefixed) and a test asserts no external module references them.

**Destructive tools never execute inline from chat.** In interactive mode they are *proposed*: the runner materializes an `AgentAction(requires_approval=True)` bound by hash to the exact args and evidence, returns `pending_approval` to the model, and the UI renders an approve card. Execution only via `/actions/{id}/approve`. `authorize_actions` is renamed `propose_actions` (analyst+: "the agent may propose actions for my approval" vs read-only assist).

---

## 2. Tool specification (`src/services/agent_tools.py`)

Every registered tool carries a typed `ToolSpec` (registry construction raises if any field is missing):

| field | meaning |
|---|---|
| `name`, `description` | as today |
| `params: dict[str, ParamSpec]` | `ParamSpec{type, description, required, enum?, minimum?, maximum?, max_length?, ref?: Model, ref_by_value?: (Model, column), schema?: nested JSON schema}` — no opaque dicts: nested payloads carry a sub-schema (`queue_endpoint_command.action` is an enum from the agent command contract with per-action payload schemas; `execute_integration_action.input_data` validated against the connector's declared action schema; `execute_playbook.input_data` validated against `Playbook.variables`-derived schema). `limit` params get `maximum: 100`. Args JSON ≤ 16 KB. |
| `effects: {reads_org, writes_org, external, executes_code}` | gating is by effects, never by the human-facing `category`. `simulate_attack`, `run_threat_hunt`, `scope_hunt`, `create_forensic_case`, `execute_playbook`, `execute_integration_action`, `queue_endpoint_command`, `remediate_incident` are `writes_org` and/or `external`. |
| `tier: read | write | destructive | privileged` | destructive = today's DESTRUCTIVE_TOOLS plus the re-tagged externals; privileged = `queue_endpoint_command` with `run_script`/`kill_process`, `disable_user` targeting an admin. |
| `min_role: viewer | analyst | admin` | viewers: `read` only (and not compliance evidence, darkweb, integrations, logs, endpoint agents — those are `analyst`); analysts: `write` + propose `destructive`; admins: all incl. `privileged`. |
| `models: [Model]` | every table the handler touches; registration raises if any model lacks `organization_id`. |
| `returns_sensitive: bool` | drives output redaction strength. |
| `effective_targets(args, db) -> list[Target]` | required for destructive/privileged tools; expands composite intent (e.g. `remediate_incident` → hosts + IPs) so policy checks and the approval card show every concrete target. Cap 25 targets. |

`tool_schema(name)` renders `params` to JSON Schema (`additionalProperties: false`, all required marked) for Anthropic `input_schema` (`strict: true`), Gemini `function_declarations`, OpenAI `function.parameters`, and policy validation. `gemini_function_declarations()` is derived from it; the description-string type sniffing is deleted.

Registry:
- `AgentToolRegistry(db, ctx: AgentContext)`; `ctx.org_id` required (raise). No `_get_or_create_default_org` / `_get_or_create_system_user` — deleted. Writes set `organization_id=ctx.org_id`, `created_by_user_id=ctx.actor_user_id` or `created_by_agent_id=ctx.soc_agent_id` (proper FK columns; the literal string "agent" is gone).
- `_scoped(select(Model))` appends `Model.organization_id == ctx.org_id`; a grep-based test fails on any `select(` in the module not wrapped by `_scoped`. `_scoped_get(Model, id)` for by-id loads.
- `call(ctx, tool, args)` is the only entry point (policy → execute → audit). Composite handlers (`remediate_incident`, ITDR respond, quarantine) invoke sub-actions through `call()` so each sub-action gets its own policy decision, rate-bucket charge, audit pair, and target validation; a denied sub-call aborts the composite.
- `execute_playbook`: reserved keys in `input_data` (`organization_id`, `actor_user_id`, `playbook_execution_id`) are hard-overwritten from ctx; `PlaybookExecution.organization_id = ctx.org_id`; the playbook engine derives org from the execution row and ignores `context["organization_id"]`.
- By-value args (`user_email`, `assignee`, `hostname`, `ip`, `asset_ref`, `cve_or_id`) are resolved by policy to an in-org primary key before the handler runs; `"me"` binds to `ctx.actor_user_id`; zero or >1 matches → deny.
- `search_logs` / `list_siem_rules` stay (LogEntry and DetectionRule have `organization_id`); NULL-org legacy rows are excluded by `_scoped`.
- `list_configured_integrations` returns connector ids + health only for non-admins (never key presence/channel).
- `GET /agentic/tools` returns only the tools the caller's role may invoke; the model's tool list is generated from the caller's role too.

---

## 3. Policy engine (`src/agentic/policy.py`)

`PolicyEngine.evaluate(ctx, spec, args, trust) -> Decision{allowed, reason_code, tier, risk, effective_targets, resolved_args}`:

1. **Schema**: validate args against `tool_schema` (types, enums, ranges, nested sub-schemas, size ≤ 16 KB) → `invalid_arguments`.
2. **Role**: `ctx.role` ≥ `spec.min_role` → else `role_not_permitted`. Viewers can never write (UNGATED_ACTION_TOOLS is no longer a role exemption; it only means "no proposal card needed for analysts").
3. **Mode**: `autonomous` → explicit allow-list of `read` tools only (not "registry minus"); anything else `autonomous_mode_readonly`. `interactive` → `destructive`/`privileged` tools are never executed inline: decision `propose` (materialize AgentAction) when `ctx.propose_actions` else `proposal_disabled`. `approval` mode (from `/actions/{id}/approve`) → allowed after checks 4–7 with `ctx.origin` carrying the originating run's trust state.
4. **Trust**: `trust.lockdown` → deny `write`/`destructive`/`privileged` except documentation-only tools (`add_incident_note`, `update_incident_findings`) → `injection_lockdown`. `trust.flagged` → allowed, but proposals carry `suspect=true`.
5. **Refs**: for every `ParamSpec.ref` (recursively through nested dicts/lists) load with `_scoped_get`; missing → `cross_tenant_reference` (reported like not-found, constant time). For `ref_by_value` resolve in-org; ambiguous → `ambiguous_target`. Semantic validators: `ip` must parse and must not be loopback/link-local/CIDR unless org setting allows; `disable_user` cannot target the actor, a superuser, or an admin unless `ctx.role == admin`; playbook ref uses `Playbook.organization_id` (new column) with fallback to `created_by ∈ org users` for legacy NULL rows.
6. **Effective targets**: call `spec.effective_targets`; each target must resolve in-org; > 25 → `too_many_targets`.
7. **Rate**: Redis token bucket per (org, tool) for `write+`; Redis down → count post-execution audit rows in the last 60 s (fail closed for `write+`).
8. **Audit** (see §7): pre-decision row written with `flush()`; the caller commits once per step after execution + post row; audit failure aborts execution (`audit_unavailable`).

Single sources of truth: tool tiers and role matrix live in the specs; `tests/unit/test_destructive_tool_gate.py` becomes `test_tool_spec_invariants.py`: every tool declares `effects`, `tier`, `min_role`, `models`; every `*_id` param has a `ref`; every by-value param has `ref_by_value`; a static scan flags any handler body referencing `db.add(`/`.commit(`/`.delay(`/`httpx`/`ActionExecutor`/`SimulationOrchestrator` while declared `read`.

Rollback (`/actions/{id}/rollback`) goes through `evaluate(ctx, spec("rollback:"+tool), params)` with role ≥ analyst and reverses by the forward-effect ids recorded in `action.result` (never by value).

---

## 4. Trust layer (`src/agentic/trust.py`)

- **Scan raw, not rendered**: `scan_for_injection(payload)` walks all fields recursively (decoding nested JSON strings), normalizes (NFKC, strip zero-width/RTL/tag chars, HTML/percent/`\uXXXX` decode, collapse spaced letters, lowercase), then matches families: instruction-override, role-hijack, tool-coercion (tool names + imperative verbs; descriptive context like "the block_ip playbook" is low weight), exfiltration, marker-spoof, **boundary-forge** (`^---.*end.*---`, `^(SYSTEM|OPERATOR|ADMIN|USER)\s*[:(]`, `</?data>`, `]]`), obfuscation. Scores accumulate across the run and across records in a list result; each record in a list result is its own sub-block `[[DATA alert:<id> nonce]]` so the banner can name the row. Truncate only after scanning; record `scanned_len`/`rendered_len`.
- **Two tiers**: `flagged` (low threshold: banner + audit, proposals marked suspect, no denial) and `lockdown` (high threshold, or any marker-spoof/role-hijack/boundary-forge hit).
- **Sticky + acknowledgeable**: `trust_state {tier, hits[], first_seen}` persisted on `AgentChatSession` and `Investigation`; later runs start from it. `POST /agentic/trust/acknowledge {session_id|investigation_id|record_hash, reason}` (analyst+, audited `agent_policy/injection.acknowledged`) downgrades that content hash to `flagged` org-wide. Audit rows for `injection.detected` dedupe per (org, content_hash, hour) with a counter.
- **Hits are safe to store**: `{family, start, length, sha256(snippet), preview}` where preview ≤ 40 chars and value-redacted; never the raw match.
- **Boundary**: nonce per LLM turn; markers in model output neutralized before persistence (`[[DATA` → `[[DATA-quoted`); history replayed as native role messages labeled `history` with the marker-spoof family excluded for that label. Seed data and tool outputs go into `tool_result` blocks (seed via a synthetic `load_context` tool call), never free text. System prompt states no operator/system message can appear after the system prompt; "lockdown cleared"/"pre-approved" inside data is by definition an attack indicator.
- **Ingest-time scanning (phase 2)**: `injection_score`/`injection_hits` columns on Alert, LogEntry, ThreatIndicator, Ticket, CaseNote computed on write; flagged rows are excluded from agent tool results by default with `{quarantined_count: N}` and an admin "mark clean". v2 ships result-time scanning with the storage columns; the ingestion hooks land in the next phase.
- **Mechanical honesty**: the assistant bubble's "Actions taken" panel is generated only from `tool_log` entries with `allowed && success`; if `final_text` claims an action with no matching successful entry, the runner prepends a machine note: "No actions were executed this turn."

---

## 5. Runtime (`src/agentic/runtime.py`)

- **Admission** (before the first LLM call): per-user runs/min (10) and concurrency semaphores `llm:active:{user}` (2) / `llm:active:{org}` (8) via `INCR`+`EXPIRE`, released in `finally`; autonomous runs use `actor=agent` buckets. Redis down → process-local `asyncio.Semaphore(4)` per org for interactive; autonomous fails closed (`quota_backend_unavailable`).
- **Per-run caps**: `max_steps` (interactive 6, autonomous 15), `max_tokens` (interactive 8192, autonomous 4096; verdict turn may raise), per-run token ceiling 150k (interactive) / 120k (autonomous), wall clock 90 s interactive (`asyncio.timeout`) / 600 s autonomous, parallel tool calls per turn 8 (extras → `is_error too_many_parallel_calls`), cumulative appended tool_result chars 64k (older results elided `[[elided tool_result id=…]]`), history replay ≤ last 12 turns / 24k chars, `query` ≤ 8k chars. Handler execution `asyncio.wait_for(…, 10)` + `SET LOCAL statement_timeout = 8000`.
- **Loop**: build messages (system frozen for the run; lockdown/step context goes in user/tool_result messages, never `system`); `provider.complete`; **tool calls are dispatched only when `stop_reason == tool_use`** — on `max_tokens`/`refusal`/other they are logged as `dropped_truncated` and, for `max_tokens`, retried once with doubled `max_tokens` else the run fails; each tool → `registry.call`; results redacted (§7) then wrapped; all results for a turn returned in **one** user message; assistant turns replayed from `provider_native` verbatim.
- **Retries**: SDK/httpx `max_retries=0`; the runtime retries once on `LLMTransientError` if wall clock permits; never on `LLMRateLimitError` interactively (return 429 + `Retry-After`).
- **Circuit breaker** in Redis per (provider, credential_source, org): open after 5 transient/auth failures in 60 s, 60 s hold, half-open probe; open → 503 `llm_unavailable` without a provider call (one `breaker_open` event/min).
- **Deadline expiry** → `stop_reason=timeout` with partial `final_text` + executed steps (never a proxy error). Step events streamed over the existing WebSocket manager keyed by `run_id`; JSON response remains the fallback.
- **Result**: `{run_id, final_text, stop_reason, steps[], tool_log[], proposals[], policy_events[], usage, provider, model, credential_source, trust}`. Provider error → `stop_reason=error`, endpoint 503 `{error: llm_provider_error, request_id}` (exception text only in server logs, redacted). No heuristics anywhere.
- **Lifecycle**: `resolve_llm` returns an async-context-manager provider; runner used as `async with provider, registry:` inside the caller's loop; Redis clients from a per-loop factory; no module-level async clients (unit test creates two providers across two `asyncio.run` calls). `raw_content` dropped after parsing; `RunResult.steps` bounded.

---

## 6. Provider layer (`src/llm/`)

- `Message.provider_native` (opaque, per assistant turn) replayed verbatim within a run — thinking/redacted_thinking blocks (Anthropic) and `thoughtSignature` parts (Gemini) survive. Providers own a per-run id map: Anthropic ids pass through; Gemini/Ollama ids synthesized `name#seq` and mapped back to `functionResponse`/`role: tool` by name in call order. OpenAI expands the single tool_result user message into ordered `tool` messages keyed by `tool_call_id` then a `user` text message.
- `Usage = {input_uncached, cache_read, cache_write, output, thinking, total_billable}` normalized per provider (Anthropic: `input_tokens + cache_read_input_tokens + cache_creation_input_tokens`; Gemini: `promptTokenCount`, `thoughtsTokenCount`; OpenAI: `prompt_tokens`, `completion_tokens` incl. reasoning). On exception an `LLMCallLog` row is still written (`stop_reason=error`, `usage_estimated=true`) and the reservation is settled.
- **Anthropic**: `AsyncAnthropic(api_key=<explicit>, max_retries=0, timeout=anthropic.Timeout(connect=5, read=60, write=10, pool=5))`; never rely on ambient credentials (fail if key falsy); **omit `thinking`** (Opus 5 runs adaptive by default; Haiku/older would 400 on adaptive) — optional capability snapshot from `client.models.retrieve(model)` cached per (org, model) 24 h; never `tool_choice any/tool`; `strict: true` tools; content parsed by `block.type`; `stop_reason` map: `end_turn`, `tool_use`, `max_tokens`, `refusal` (+`stop_details`), `pause_turn` → error (no server tools), `model_context_window_exceeded` → error; unknown → error.
- **Gemini**: `systemInstruction`; `stream:false`; **never** `responseSchema` together with tools; `finishReason` map: `STOP`→`end_turn`/`tool_use`, `MAX_TOKENS`→`max_tokens`, `SAFETY|RECITATION|BLOCKLIST|PROHIBITED_CONTENT`→`refusal`, `MALFORMED_FUNCTION_CALL|OTHER`→error; missing candidates / `promptFeedback.blockReason` → `refusal`.
- **OpenAI**: chat completions with `tools`; `finish_reason` map (`length`→`max_tokens`, `content_filter`/`message.refusal`→`refusal`); schemas generated with all properties required + `additionalProperties:false` recursively (strict). Model must be configured (discovery via `/v1/models`).
- **Ollama**: `/api/chat` with `stream:false`, `keep_alive`, `options.num_ctx`; "does not support tools" → `LLMNotConfigured(model_lacks_tools)` (surfaced by the settings probe).
- **Verdicts are a tool**: `submit_verdict` (strict schema: verdict enum, confidence 0–100, reasoning, `recommended_actions:[{tool, args}]`, `mitre_techniques[]`) ends an autonomous run when called; `_extract_verdict` and the `_ACTION_RULES` regex materializer are deleted. `response_schema` is used only for tool-less single-shot calls (triage/summaries) and rejected when tools are attached.
- **Errors** carry `retryable`: Auth/NotConfigured/Quota/InvalidResponse → not retryable; Transient → retryable; RateLimit → single retry after `Retry-After` only in autonomous mode.
- **Factory** (`resolve_llm(db, org)`): if the org `ai` section exists it is **authoritative** — credentials only from that org's `InstalledIntegration`; missing → `LLMNotConfigured(source=org, reason=missing_credential)`, never env fallback. Platform env fallback only when `ai.use_platform_default == true` (default **false**; superuser can set a global default). Hosted providers use fixed hosts (tenants supply keys only). `ollama`/OpenAI-compatible base URLs are platform env only; if ever per-tenant: https/allowlist, deny loopback/link-local/RFC1918/metadata, resolve-and-pin, no redirects, `trust_env=False`. All clients `verify=True`; the `verify=False` probes in `settings.py` are removed. `credential_source ∈ {org, platform}` on every call log row and chat response.
- **Quota** (`quota.py`): reserve-then-settle via Lua (`INCRBY` only if `current + reserve ≤ budget`, `EXPIRE` in the same script; settle `DECRBY reserve − actual`), checked **every turn**. Separate buckets `llm:budget:{org}:{day}:interactive` and `:autonomous` (`llm_autonomous_daily_token_budget` default 1M; interactive reserve 40 % autonomous cannot consume). Autonomous admission at enqueue time in `_kickoff`: autonomous budget + `llm:auto:running:{org}` ≤ 3 + `llm:auto:started:{org}:{hour}` ≤ 20; over cap → Investigation `queued_budget_exceeded` with no LLM calls. Shared platform key gets a platform-wide bucket with per-tenant weighted fair share; BYO tenants charge only their own bucket. Budget exhaustion emits an AuditTrail security event (`SC-5`). Notifications at 80 %/100 % via the existing channel.
- **Call log** (`LLMCallLog`, migration 020): `run_id, org, actor_user_id|soc_agent_id, purpose, mode, role, propose_actions, session_id, investigation_id, provider, model, credential_source, prompt_version, system_prompt_sha256, tools_offered (names + schema hash), messages_sha256, usage (all fields), latency_ms, stop_reason, injection_tier, request_id, data_sent_bytes, redactions_applied, usage_estimated`. Bodies not stored unless `llm_log_bodies=true` with retention. Nightly rollup to `llm_usage_daily`; raw rows deleted after 90 days.

---

## 7. Audit and evidence

- **Two events per tool** via `AuditLogger.log_event`: `agent_policy/tool.allow|deny|propose` (pre) and `agent_tool/tool.executed|failed|blocked` (post: `duration_ms`, `result_sha256`, error class). `session.flush()` in the logger, one commit per step by the runner after audit + execution; audit-write failure aborts execution (fail closed). The `try/except: pass` around `TicketActivity` writes is deleted; the TicketActivity feed row is written once per run summary, not per decision.
- **Run id everywhere**: `AuditTrail.request_id = run_id`; `LLMCallLog.run_id`; `AgentAction.run_id`; `Investigation.run_ids`; `AgentCommand.initiated_by_user_id/run_id`; `PlaybookExecution.triggered_by_user_id`; `ActionExecutor.triggered_by` gets the principal.
- **Tamper evidence**: `audit_trails.prev_hash/row_hash` (sha256 over canonical row + prev, chained per org) in migration 020; verified by the existing compliance attester; app DB role INSERT-only on the table (deployment note).
- **Args in audit**: value-redacted (§ redact), capped 2 KB with `[truncated]` + `args_sha256`.
- **Redaction** (`src/core/redact.py`, one implementation applied at every sink: outbound provider messages, persisted `AgentChatMessage.tool_calls`, AuditTrail/TicketActivity, LLMCallLog, client error responses): key regex `(?i)(api[_-]?key|token|secret|passw(or)?d|private[_-]?key|authorization|cookie|credential)` recursively + value patterns (`sk-ant-*`, `sk-*`, `AIza*`, `ghp_*`, `AKIA[0-9A-Z]{16}`, JWT, `Basic|Bearer …`, PEM); tool results persisted truncated to 4 KB with `redactions_applied`; `returns_sensitive` tools get the strongest profile.
- **Transcript**: `AgentRunTranscript` (migration 020) persists a compact per-run record (steps: tool, redacted args hash, result hash, decision, audit ids) for autonomous and approval runs; encrypted at rest; per-org retention (default 90 days).
- **Read surfaces**: `GET /agentic/runs/{run_id}` (joined timeline, analyst+), `GET /agentic/usage` (org-scoped tokens/cost by day/user/purpose/provider, budget remaining; superuser cross-org variant), `GET /agentic/policy-events` (filters, pagination), `GET /agentic/evidence/export?format=csv|json&from&to` (admin; joins AuditTrail + LLMCallLog + AgentAction; columns: timestamp, run_id, organization, actor, role, mode, tool, redacted_args, decision, reason_code, provider, model, tokens, approver, approval_timestamp, execution_status, result_hash, injection_tier), registered as an `AutomatedEvidenceRule` for AC-3, AC-6(1), AU-2, AU-3, SI-10. Prices live in settings (per-model table), not code.

---

## 8. Proposals, approvals, autonomous outcomes

`AgentAction` gains first-class columns (migration 020): `run_id, tool_name, proposed_by_user_id|proposed_by_agent_id, source ∈ {chat, autonomous, skill, itdr}, params_sha256, evidence_sha256, effective_targets (json), suspect, injection_tier, expires_at (72 h default, org-configurable), approver_role, approver_ip, approval_reason`. `parameters['_tool']` is gone; approve executes `tool_name`.

`/actions/{id}/approve`:
- role ≥ analyst; org match; `params_sha256` and `evidence_sha256` must be echoed by the client (`approval_stale` on mismatch); expired → 409.
- `suspect=true` → 403 `suspect_action_requires_reinvestigation` unless the approver is admin and passes `acknowledge_suspect: true` + a reason (audited `agent_policy/suspect.approved`, risk high).
- Separation of duties (AC-5): approver ≠ `proposed_by_user_id` for `destructive`/`privileged` when the org setting `require_second_approver` is on (default off — open question for JP); privileged always requires admin. Bulk approve excludes destructive/privileged and suspect rows.
- Re-runs `PolicyEngine.evaluate` in `approval` mode with `ctx.origin` = originating run trust state; re-scans the stored evidence at a stricter threshold and shows the delta; executes with the approver as actor; audit pair written.

Autonomous investigator:
- `AgentRunner(mode=autonomous)` with the explicit read-only allow-list; `submit_verdict` tool; `Investigation.outcome ∈ {verdict, inconclusive_budget, refused, provider_error, injection_suspected, queued_budget_exceeded, llm_not_configured}` + `failure_reason`; when `outcome != verdict`, `confidence_score` is NULL (the `or 40` fabrication is deleted) and no AgentAction rows are created.
- Recommendations: ≤ 5 per investigation, ≤ 50 pending per org per hour (excess kept as text); `injection_tier == lockdown` → recommendations persisted as text only (no AgentAction rows); each proposed target must have **provenance** in a structured, human-written field reachable from the trigger (`Alert.hostname/source_ip/username`, `Asset`, `User`, `Incident.affected_systems`); a target that appears only inside DATA text is materialized as a human task (no `tool_name`), never executable.
- Celery: `run_investigation` on its own `investigations` queue (`soft_time_limit=900, time_limit=960`); non-retryable LLM errors → exactly one `escalated`/`llm_not_configured` investigation and a per-org `llm:disabled:{org}` flag (TTL 1 h) checked by `_kickoff`; transient → `max_retries=2` resuming from persisted steps; `worker_max_memory_per_child=400000` for that worker.

---

## 9. Endpoints (delta vs v1.1)

- `/chat`: `AgentContext` from JWT (`role`, `actor_user_id`; `soc_agent_id` validated against `SOCAgent.organization_id == org` else 400 — the client value is never written to audit); session must match org **and** user; viewers with `propose_actions=true` → 403; admission + caps; response adds `run_id, proposals[], policy_events, trust, provider, model, credential_source, usage`; 503/429 persist the user message with `status=failed` so the UI can retry.
- `/tools/{name}/execute`: `registry.call` (full policy incl. role, tier → destructive returns a proposal, not an execution).
- `/actions/{id}/approve|rollback`: §8 / §3.
- `/itdr/threats/{id}/respond`: routed through `registry.call` with JWT ctx.
- `/hunts` (structured hunt) and skills: through `registry.call` with ctx.
- `GET/PUT /settings/ai` (admin): provider, model, `use_platform_default`; validates model via `list_models()` on **fixed hosts**; persists capability snapshot; returns `source, key_fingerprint (sha256 prefix + last4), rotated_at, last_successful_call_at`; audit events `ai.provider.set / ai.key.rotated / ai.key.deleted` (risk medium; never the key). `GET /settings/ai/models?provider=`. Superuser `GET /admin/ai/tenants`.
- `POST /agentic/trust/acknowledge`, `GET /agentic/runs/{run_id}`, `GET /agentic/usage`, `GET /agentic/policy-events`, `GET /agentic/evidence/export`, `GET /health/llm` (per-org provider reachability, cached 60 s). Prometheus: `llm_calls_total{provider,stop_reason}`, `agent_policy_decisions_total{decision,reason}`, `agent_injection_events_total{tier}`.

---

## 10. Secrets (F12) — safe migration

- Versioned envelope `enc:v1:<b64>` written by `encrypt_secret_json`; `decrypt_secret_json` requires it and **raises** `SecretUnreadable` for `ai` and `integration:*` sections (surfaced as 503 `llm_not_configured / secret_unreadable`), instead of returning `{}`.
- `EncryptionService()` with no master key **raises** in production/migration contexts (the `os.urandom` throwaway-key path is dev-only and logged loudly).
- Migration 020: hard-fails if `settings.encryption_master_key` is unset; verifies a stored canary (`app_settings` section `_crypto_canary`, written at first boot) decrypts under the current key before touching rows; copies `value` to `value_pre020` in the same transaction; encrypts only secret keys in non-enveloped values (idempotent); asserts round-trip equality before commit.

---

## 11. Data model changes (migration 020, single revision)

- `llm_call_logs`, `llm_usage_daily`, `agent_run_transcripts` (new tables).
- `audit_trails`: `prev_hash`, `row_hash`, `run_id` index; composite index `(organization_id, event_type, action, created_at)`.
- `agent_actions`: columns in §8; `agent_chat_sessions.trust_state`; `investigations`: `outcome, failure_reason, llm_provider, llm_model, tokens_used, injection_tier, run_ids`; `alerts/log_entries/threat_indicators/tickets/case_notes`: `injection_score, injection_hits` (nullable; populated in phase 2); `playbooks.organization_id` (backfilled from `created_by`); `playbook_executions.triggered_by_user_id`; `agent_commands.initiated_by_user_id, run_id`; `app_settings.value_pre020`; created-by FK pairs where the literal "agent" was stored.

---

## 12. Deletions

`src/agentic/llm.py`; `src/agentic/guardrails.py`; `src/agentic/tools.py` (`SecurityTools`, `ToolExecutor`, the 10 shadow tools); `AgenticSOCEngine.investigate_with_llm` + `llm_orchestrator` + `run_skill` (skills re-pointed at `registry.call`); `AIAnalyzer._heuristic_tool_pick`, `model_map`, pricing constants, `_call_llm` fabricated defaults, `call_llm_with_tools*` (replaced by `src/llm`); `investigator._extract_verdict`, `_ACTION_RULES` materializer, the `or 40` confidence; `_get_or_create_default_org`, `_get_or_create_system_user`; `verify=False` in settings probes; `NaturalLanguageInterface._extract_*` regex intent parsing (its `explain_alert`/`suggest_next_steps` stay, routed through `src/llm`).

---

## 13. Frontend

- ChatWorkbench: `propose_actions` toggle (disabled with tooltip for viewer); **inline approve cards** (tool, every arg, expanded targets, evidence excerpt + source, injection tier, provider/model; Approve/Deny with reason; hashes echoed); trust banner with family + 40-char preview + source record + Acknowledge (analyst+); "Actions taken" panel from `tool_log` only; provider/model/tokens per bubble; honest error card with Retry; streamed step progress.
- Approvals page: suspect badge + disabled approve with reason; expiry; no bulk for destructive; evidence panel.
- Settings → AI provider: provider select, live model list, key status + fingerprint + rotated_at, test, `use_platform_default`, save (admin). No URL fields.
- Agentic dashboard: Agent Ops cards (tokens today vs budget, blocked actions, injection events, provider health).

---

## 14. Tests (additions to v1.1 §12)

- Runtime: second request contains the first response's native content byte-for-byte; `stop_reason=max_tokens` + tool_use → zero executions; deadline → `timeout` with partial text; parallel cap; context elision; obedient FakeProvider + injected alert → destructive becomes a *proposal*, never executed; turn-2 after lockdown still locked (sticky).
- Policy matrix: mode × role × tier × trust × refs (incl. nested dict/list refs, by-value ambiguity, `"me"`, superuser/admin targets, playbook legacy rows, installation_id, composite sub-calls).
- Registry: grep test for `_scoped`; write-detecting `before_flush` listener over every `read` tool; parametrized isolation over every tool incl. list/search (no org-B identifier in serialized output); `execute_playbook` with `input_data.organization_id=orgB` → zero rows in org B.
- Providers: mocked transports for all four; Gemini finishReason map; OpenAI tool-message expansion; Ollama no-tools → `LLMNotConfigured`.
- Quota: reserve/settle, split buckets, Redis-down semantics (interactive vs autonomous).
- Audit: fail-closed on audit failure; hash chain verification; redaction at every sink (secret in tool result never reaches provider payload, DB, or response).
- Approval: hash mismatch → `approval_stale`; expired → 409; suspect → 403 unless admin acknowledge; SoD when enabled; rollback by recorded ids only.
- Migration 020: canary/envelope/idempotency/round-trip on a fixture DB; no master key → hard fail.
- Investigation outcomes: refusal → `confidence_score IS NULL`, zero AgentActions; revoked key → exactly one escalated investigation, zero retries.
- Trust corpus: ≥ 40 attack payloads (incl. non-English, JSON-key, boundary-forge, encodings, split) **and** a benign SOC corpus (playbook text, EDR command lines, phishing bodies) with an FP-rate ceiling.

---

## 15. Open questions for JP

1. `require_second_approver` for destructive actions: default off (solo SOCs) or on (defense customers)?
2. `use_platform_default`: should existing tenants be grandfathered to `true` on migration so autonomous triage keeps running, or flipped to `false` (safer; triage pauses until an admin confirms)?
3. Ingest-time scanning/quarantine of alerts and logs (phase 2) touches SIEM ingestion throughput — approve as the next phase?
4. Retention defaults: 90 days for call logs and transcripts acceptable for FedRAMP customers, or make it a per-org setting from day one?

## 16. Compliance mapping (delta)

Adds AC-4, AC-5, AU-5, AU-9, AU-10, AU-11, SC-5, SC-5(2), SC-7, SC-7(5), SC-8, SC-13, SC-28, SI-7, SI-12, SA-9(5) to v1.1's list; `docs/agentic-soc.md` carries the control-to-code map (file, function, test, export column) and a STRIDE table; `deploy/kubernetes/base/networkpolicy-llm-egress.yaml` + OPA constraint restricts api/worker egress to provider hosts.
