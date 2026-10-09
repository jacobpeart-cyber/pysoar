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
* **Run transcripts** (`src/agentic/transcript.py`, table
  `agent_run_transcripts`): one row per agent run, written by
  `persist_run_transcript` at the end of every chat turn and autonomous
  investigation. Per tool call: tool, tier, decision/reason, duration, error
  flag, audit pair ids, hashes and redacted previews (≤ 1 KB each); per run:
  prompt version, usage totals, trust summary, proposal ids and hashes,
  policy events, honesty-note flag and the redacted final answer (≤ 8 000
  chars). `steps` and `summary` (migration 022) are encrypted at rest; the
  step list is capped at 200 entries / 256 KB with the cut recorded in
  `summary.truncation`; `retention_until` is stamped from the org's
  `agent_transcript_retention_days`. A failed write is logged
  (`agent_transcript_persist_failed`), counted
  (`agent_transcripts_total{outcome="failed"}`) and never fails the run.
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
   privileged tools require an admin approver. **Separation of duties**: when
   the organization enables `require_second_approver`, a destructive or
   privileged proposal needs two distinct approvers before the approval-mode
   evaluation runs; the proposer never counts (`proposer_cannot_approve`,
   403) and the first approver cannot also give the second
   (`second_approver_required`, 409). See section 5.
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
* Every completed run (including one that ends in a provider error) writes
  one redacted, capped transcript row (§2, *Run transcripts*), readable with
  `GET /agentic/runs/{run_id}`; a run rejected before it starts (admission,
  quota, open breaker) has no transcript, only its call-log and audit rows.
* Approvals (`POST /agentic/actions/{id}/approve`) are hash-bound
  (`params_sha256`/`evidence_sha256`), expire after 72 h and, for suspect
  proposals, need an admin with `acknowledge_suspect` and a written reason.
  With the org setting `require_second_approver` on (off by default; an org
  admin sets it with `PUT /settings/agentic-policy` or Settings → AI Provider →
  Agent approval policy, audited as `agentic_policy.set`), a destructive or
  privileged proposal takes two approvals from two different users, neither of
  them the proposer. The first approval is recorded on the action
  (`first_approved_by`/`first_approved_at`, migration 021), audited as
  `action.first_approval`, and leaves the action pending
  (`{"status": "awaiting_second_approval"}`). The second approval, which must
  echo the same hashes and pass the suspect rule again, is audited as
  `action.second_approval` and executes exactly as a single approval does.
  Refused attempts are audited as `action.approval_refused`. Expiry and
  rollback are unchanged. `GET /agentic/actions/pending-approval` rows carry
  `requires_second_approver`, `first_approved_by` and `first_approved_at`.
  Proposals with no executable tool (recorded as human work) and denials are
  not subject to the rule; the proposer may still deny (withdraw) a proposal.

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
  `LLM_LOG_RETENTION_DAYS` (platform default for call logs, 365).
  `ENCRYPTION_MASTER_KEY` is **required**: migration
  020 refuses to run without it and the API refuses to start the ephemeral-key
  path outside development.
* Retention (`GET/PUT /api/v1/settings/agentic-policy`, org admin, same
  `agentic_policy` section as `require_second_approver`):
  `llm_call_log_retention_days` and `agent_transcript_retention_days`, whole
  days from 30 to 1095. Values outside that range, non-integers and unknown
  keys get a 422. With no setting the default is 365 days; for call logs that
  default is `LLM_LOG_RETENTION_DAYS`, clamped to 30..1095. A PUT is partial,
  and every change writes one `agentic_policy.set` audit row with the old and
  new effective values. Shortening a window is logged at medium risk.
  Settings > AI Provider has the two inputs. The Celery task
  `src.agentic.tasks.purge_agentic_retention` runs daily at 05:15 UTC with
  15/16-minute limits (`src/agentic/retention.py`). For each organization it:
  (1) rolls up into `llm_usage_daily` each whole UTC day about to leave the
  call-log window that has no rollup yet, so `/agentic/usage` keeps the
  totals; (2) deletes `llm_call_logs` older than UTC midnight of
  `now - retention`; (3) deletes transcripts whose `retention_until` has
  passed. Writers stamp `retention_until` from the organization's setting
  (`transcript_retention_until`), so a change applies to new transcripts and
  existing rows keep their stamp. Deletes run in committed windows of 10,000
  rows. A run stops after 100 windows (and rolls up at most 400 days per
  organization), reporting `truncated: true`, and the next night continues.
  The result carries `call_logs_deleted`, `transcripts_deleted`,
  `days_rolled_up`, `batches`, `failed_organizations` and per-organization
  counts.
* Egress: `deploy/kubernetes/base/networkpolicy-llm-egress.yaml` restricts the
  api/worker/scheduler pods to DNS, in-cluster dependencies and TCP/443 to
  public address space (metadata and private ranges blocked); the Cilium
  variant pins the three provider hostnames.

### Rotating `ENCRYPTION_MASTER_KEY`

`scripts/rotate_master_key.py` re-encrypts every value the master key protects
in one database transaction: `enc:v1` envelopes in `app_settings.value`
(including the `_crypto_canary` row), `installed_integrations.auth_credentials_encrypted`
(envelopes and legacy raw ciphertext; `__plaintext__:` rows are counted and left
alone), `users.mfa_secret` / `users.mfa_backup_codes`, and
`agent_run_transcripts.steps`. It refuses to start unless the canary opens under
the old key (or, on a re-run, the new key), re-reads every rewritten value under
the new key before committing, rolls everything back on any failure, and skips
values already under the new key, so it is safe to re-run. Keys come only from
the `ENCRYPTION_MASTER_KEY` (old/current) and `ENCRYPTION_MASTER_KEY_NEW`
environment variables and are never logged. Exit codes: 0 success, 1 failed and
rolled back, 2 refused before writing. Production procedure (from `/opt/pysoar`;
`scripts/` is not mounted into the api container, hence the `-v`):

1. Generate the new key: `docker compose run --rm --no-deps -v "$PWD/scripts:/app/scripts:ro" api python scripts/rotate_master_key.py --generate`.
2. `read -rs ENCRYPTION_MASTER_KEY_NEW && export ENCRYPTION_MASTER_KEY_NEW`
   (keeps the key out of shell history), then `docker compose stop api worker scheduler`
   so nothing writes under the old key mid-rotation.
3. Dry run: `docker compose run --rm -e ENCRYPTION_MASTER_KEY_NEW -v "$PWD/scripts:/app/scripts:ro" api python scripts/rotate_master_key.py --dry-run`.
4. The same command without `--dry-run` rotates for real. Do not continue unless it exits 0.
5. Set `ENCRYPTION_MASTER_KEY` to the new value in `/opt/pysoar/.env`, then
   `docker compose up -d api worker scheduler`.
6. `docker compose run --rm -v "$PWD/scripts:/app/scripts:ro" api python scripts/rotate_master_key.py --verify-only`
   checks that every encrypted value opens under the now-current key; then `unset ENCRYPTION_MASTER_KEY_NEW`.
7. Store the new key in the password manager and retire the old key.

`app_settings.value_pre020` still holds the plaintext copy of settings that
migration 020 took before enveloping them. Rotation does not touch it, so a
leaked key alone does not expose those values, but a leaked database dump does.

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
| AC-5 | Separation of duties: org setting `require_second_approver` (two distinct approvers for destructive/privileged actions, proposer excluded, `evaluate_approval_quorum`); suspect proposals additionally require admin acknowledgement with a reason | `test_agentic_second_approver.py`, `test_agentic_approval_endpoints.py`, `test_migration_021.py` |
| AU-2, AU-3, AU-12 | Pre/post audit rows per tool, `llm_call_logs` per turn, one encrypted `agent_run_transcripts` row per run (redacted steps + run summary) | `test_audit_chain.py`, `test_call_log_records_are_complete_per_turn`, `test_agent_run_transcripts.py` |
| AU-9, AU-10 | `audit_trails.prev_hash/row_hash` chain; fail-closed audit | `test_audit_chain.py`, `test_post_audit_failure_fails_closed` |
| AU-6, AU-7 | Run timeline, policy-event review, usage totals and admin-only evidence export (JSON/CSV); ITDR respond routed through the same `guarded_tool_call` path | `test_agentic_read_surfaces.py`, `test_itdr_respond.py` |
| CM-7 | Autonomous read-only allow-list; effects-based tiers | `test_autonomous_offers_only_allowlisted_read_tools_and_ends_on_verdict` |
| SI-10 | Schema validation, injection scanner, semantic validators | `test_trust_scanner.py`, policy matrix |
| SC-5 | Admission, budgets, breaker | `test_llm_quota.py` |
| SC-7, SC-7(5) | Egress NetworkPolicy, fixed provider hosts | manifest; `test_settings_ai.py` |
| SC-8, SC-13 | TLS verification on every provider and probe call | `test_no_verify_false_in_settings` |
| SC-28 | Enveloped secrets at rest | `test_settings_section_encryption.py`, `test_llm_secrets_envelope.py` |

## 11. Not implemented / decisions pending

* **Second approver scope**: `require_second_approver` is per organization and
  off by default. When it is off, the proposer may approve their own proposal
  (a single-analyst SOC must be able to act); the proposer exclusion applies
  only while the setting is on.
* **Ingest-time scanning** of alerts and logs: the columns exist
  (`injection_score`, `injection_hits`) but scanning happens when content
  reaches the agent, not at ingestion. Decided 2026-10-06: approved as the
  next phase, scored asynchronously after the row is written (ingest
  throughput unaffected; the agent still re-scans at use time; lockdown-tier
  hits raise an alert). Not yet implemented.
* **Platform-key grandfathering**: decided 2026-10-06, existing tenants stay
  at `use_platform_default=false`; autonomous triage for them records
  `llm_not_configured` until an admin configures a provider or opts in.
* **Retention**: decided 2026-10-06 and implemented: LLM call logs and agent
  run transcripts default to 365 days with a per-organization setting
  (`llm_call_log_retention_days`, `agent_transcript_retention_days`, 30 to
  1095 days, audited) honoured by the nightly `purge_agentic_retention` task.
  See section 7. Transcript expiry is stamped when the row is written.
* **Metrics**: `GET /metrics/agentic` is an in-process registry (no
  `prometheus_client`); counters reset on restart.
* **Memory bounds outside the agent**: every Celery task that read whole
  tables is now windowed (keyset pages of 1000), capped per run with a
  `truncated` flag, committed per window and time-limited, with per-child
  worker recycling at 300 MB. Round one (2026-10-05) covered the beat tasks
  behind the September 2026 OOM; round two (2026-10-06) covered dark-web,
  STIG, integrations, supply-chain, deception, scheduled playbooks and the
  on-demand exposure tasks. Regression tests:
  `test_task_memory_bounds.py`, `test_task_memory_bounds_round2.py`.
* **Data-lake raw SQL tenant guard is unsafe**: `_build_tenant_scoped_sql`
  in `src/api/v1/endpoints/data_lake.py` is regex based (first FROM table
  only; comma joins, JOIN targets and subqueries unscoped; column whitelist
  not enforced), so since 2026-10-08 the raw SQL path of
  `POST /data-lake/query` is platform-superuser only (403
  `raw_sql_requires_superuser` for everyone else, tenant admins included).
  Pending: rewrite the guard on a real SQL parser before reopening it to
  tenant users. Regression test: `test_data_lake_raw_sql_gate.py`.

## 12. Deploying this release

0. TLS on the production host. The origin certificate expired on
   2026-07-05 because certbot was configured with the `standalone`
   authenticator (needs port 80) while the frontend container held port 80,
   so every renewal failed and Cloudflare returned 526. Port 80 now belongs to
   the `nginx` service, whose port-80 server serves the ACME webroot
   (`./nginx/certbot`). One-time switch on the host, as root:

   ```
   certbot certonly --webroot -w /opt/pysoar/nginx/certbot -d pysoar.it.com \
       --deploy-hook /opt/pysoar/deploy/certbot-deploy-hook.sh \
       --non-interactive --agree-tos --force-renewal
   ```

   Done on 2026-10-06: certbot created the lineage `pysoar.it.com-0001`
   (webroot + `renew_hook`), the old standalone lineage was removed with
   `certbot delete --cert-name pysoar.it.com`, and `certbot renew --dry-run
   --no-random-sleep-on-renew` succeeded. The existing `certbot.timer` renews
   unattended; the hook copies the lineage into `nginx/ssl/` and restarts the
   proxy. When checking renewal by hand, pass `--no-random-sleep-on-renew`:
   non-interactive certbot otherwise sleeps up to eight minutes first, which
   looks like a hang.
1. Prod requires `ENCRYPTION_MASTER_KEY` in `/opt/pysoar/.env` before
   `alembic upgrade head` (migration 020 backfills settings secrets and refuses
   to run without the key).
2. New Python dependency (`anthropic`): rebuild the image
   (`docker compose build api` then `docker builder prune -af` on the
   disk-constrained host).
3. `alembic upgrade head` (020 through 022; 022 adds `agent_run_transcripts.summary`, which every run writes and `GET /agentic/runs/{run_id}` reads; without it transcript writes fail (runs still complete) and the run endpoint errors), then restart api/worker/scheduler.
4. Frontend bundle changed: swap `dist` and restart frontend + nginx.
5. Verify: `GET /health`, `GET /health/llm` (admin token), one chat turn with
   `propose_actions=false`, then `GET /agentic/runs/{run_id}` for that turn
   shows a non-null `transcript`.
