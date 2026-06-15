# Agent-Hosted Honeypots — Design

**Date:** 2026-06-11
**Status:** Approved (architecture choice: endpoint agent hosts listeners)

## Problem

Audit gap #9: `deploy_honeypot` creates a `Decoy` DB row and nothing
else — no listener ever runs anywhere, yet the UI presents decoys as
"deployed". Honeytokens are real; honeypots are theater.

## Design

### Agent side (`agent/pysoar_agent.py`)

- New `HoneypotManager`: thread-per-listener TCP accept loops.
  On connection: record peer ip/port, read up to 1 KB of client bytes
  (2s timeout), send the configured banner, close. Interactions are
  queued in memory and flushed to the server.
- New handlers, registered like existing ones:
  - `deploy_honeypot` — payload `{decoy_id, port, banner, service}`.
    Binds the port (>1024 only, refuses in-use ports), starts the
    listener thread, returns `{listening: true, port}`.
  - `stop_honeypot` — payload `{decoy_id}`. Stops the listener.
- Interaction flush: piggybacks on the existing poll cycle — after
  polling for commands, the agent POSTs any queued interactions to
  `POST /_agent/honeypot-interactions` (same agent-token auth as
  heartbeat/results).
- Listeners do NOT survive agent restart (documented; the server marks
  the decoy `degraded` if the agent re-enrolls/heartbeats without it).
  Re-deploy from the UI restores them. (Deliberate: no agent-side
  persistence to keep the agent stateless.)

### Capability gating (`src/agents/capabilities.py`)

- New `AgentCapability.DECEPTION = "deception"`.
- New `AgentAction.DEPLOY_HONEYPOT` / `STOP_HONEYPOT` mapped to it.
- NOT high-blast (passive listening, reversible) — single-analyst
  deploy, but only on agents enrolled with the `deception` capability.

### Server side

- `DeceptionEngine.deploy_honeypot` (src/deception/engine.py): after
  creating the `Decoy` row, look for an active deception-capable agent
  in the org (optionally matching `deployment_target` hostname). If
  found: issue `deploy_honeypot` via `AgentService.issue_command`,
  store `{agent_id, command_id, listener: "dispatched"}` in the decoy's
  existing `configuration` JSON (no migration), set status `deploying`.
  If none: status stays `record_only` — honest label, like the
  coverage-only pattern in BAS.
- New endpoint `POST /_agent/honeypot-interactions` (agents.py, uses
  `_require_agent`): accepts a batch of interactions, creates
  `DecoyInteraction` rows (tenant from the agent's org, decoy validated
  to belong to that org). The existing agentic broad sweep
  (`auto_triage_broad_sweep`) already watches DecoyInteraction rows —
  honeypot hits flow into the autonomous investigator with no new
  plumbing.

## Error handling

- Port in use / bind failure → agent returns error result; server marks
  decoy `failed` with the reason in configuration JSON.
- Unknown decoy_id on interaction post → row skipped, logged, rest of
  batch processed.

## Testing

- Capability mapping tests (deploy/stop allowed only with `deception`).
- HoneypotManager unit tests: real socket on an ephemeral port —
  connect, receive banner, interaction recorded; stop closes the port.
- Engine dispatch test: deception-capable agent seeded → command issued
  + configuration updated; no agent → `record_only`.
- Interaction endpoint test: agent-authed batch post creates
  DecoyInteraction rows; cross-tenant decoy rejected.

## Out of scope

UDP/ICMP decoys, TLS banners, listener persistence across agent
restarts, automatic re-deploy on agent reconnect.
