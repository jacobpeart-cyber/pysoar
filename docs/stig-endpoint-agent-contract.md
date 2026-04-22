# STIG scan contract for PySOAR endpoint agents

This document defines the protocol the PySOAR endpoint agent binary must
implement so that `src.stig.tasks.run_stig_scan` produces real, 3PAO-auditable
scan results.

## Why this document exists

Server-side, PySOAR:

1. Loads XCCDF benchmarks (DISA STIG Viewer content) via
   `POST /api/v1/stig/scap/upload` → parses `<Rule>` elements into
   `stig_rules` rows.
2. Dispatches a scan via `src.stig.tasks.run_stig_scan(host, benchmark_id, org_id)`
   which queues one `AgentCommand(action="run_stig_check", ...)` per rule and
   polls `AgentResult` for the matching response.
3. Alternatively, accepts a one-shot oscap ARF report via
   `POST /api/v1/stig/scans/{scan_id}/arf` (multipart upload).

The server does **not** touch remote hosts. The endpoint agent running on
the target is the only component that can produce honest results.

## Required endpoint-agent behavior

The agent polls the server for queued commands (via the normal command-
polling endpoint used by the live-response system). When it receives a
command with `action == "run_stig_check"`, it MUST:

### Option A — per-rule execution (preferred for low-latency)

Payload:

```json
{
  "rule_id": "V-230221",
  "stig_id": "SV-230221r627750_rule",
  "severity": "medium",
  "check": {
    "kind": "oval" | "script",
    "href": "RHEL_8_STIG-oval.xml",   // when kind=oval
    "name": "oval:mil.disa.stig.rhel8:def:1",  // when kind=oval
    "script": "...",                   // when kind=script
    "interpreter": "bash" | "powershell"
  },
  "timeout_seconds": 60
}
```

Response (`AgentResult.output_json`):

```json
{
  "rule_id": "V-230221",
  "status": "pass" | "fail" | "notapplicable" | "error",
  "evidence": "Observed value X; expected Y",
  "collected_at": "2026-04-22T03:00:00Z",
  "duration_ms": 42
}
```

Rules without `check.kind` are manual; the agent MUST NOT guess — return
`status: "notchecked"`.

### Option B — full-benchmark ARF upload (preferred for periodic sweeps)

When the command payload contains `{"mode": "full_arf", "xccdf_url": "..."}`
the agent downloads the XCCDF and runs `oscap` natively:

```bash
oscap xccdf eval \
  --profile xccdf_mil.disa.stig_profile_MAC-3_Public \
  --results-arf /var/pysoar/arf-<scan_id>.xml \
  /var/pysoar/xccdf/<benchmark>.xml
```

Then POSTs the ARF file back:

```
POST /api/v1/stig/scans/{scan_id}/arf
Authorization: Bearer <agent-token>
Content-Type: multipart/form-data; boundary=...

file=<arf xml>
```

The server parses `<rule-result>` elements, maps oscap codes to STIG
finding statuses, and writes compliance metrics.

## Result code mapping

Server-side, `src.stig.engine.STIGScanner._ARF_RESULT_MAP` translates
oscap / XCCDF 1.2 rule-result values to STIG finding statuses:

| oscap code       | STIG finding status |
|------------------|---------------------|
| `pass`           | `not_a_finding`     |
| `fail`           | `open`              |
| `notapplicable`  | `not_applicable`    |
| `notchecked`     | `not_reviewed`      |
| `notselected`    | `not_reviewed`      |
| `informational`  | `not_reviewed`      |
| `error`          | `not_reviewed`      |
| `unknown`        | `not_reviewed`      |
| `fixed`          | `not_a_finding`     |

Reference: NIST SP 800-126 Rev 3 §5.5.

## Integrity requirements

1. The agent MUST NOT fabricate results. A rule with no check content
   MUST be reported as `notchecked`.
2. The agent MUST include the real `collected_at` timestamp from the host
   clock (not the server clock).
3. `AgentCommand` entries are hash-chained (`prev_hash` → `chain_hash`).
   The agent MUST reject commands whose chain breaks.
4. `AgentResult` output is persisted as-is; auditors can replay any
   scan by joining `agent_commands` → `agent_results`.

## Scheduled runs

`scheduled_fleet_stig_sweep` fires via Celery beat every Sunday at
06:00 UTC (`src/workers/celery_app.py`). It enumerates every active
`EndpointAgent` × every `STIGBenchmark` in the same org and delegates to
`run_stig_scan`. Ad-hoc scans can be triggered any time via
`POST /api/v1/stig/scans/launch` (which calls `run_stig_scan.delay`).

## Open issues (not blockers for first audit)

- Agent-side XCCDF caching: agents re-download XCCDF each scan; should
  cache by content hash.
- Delta scans: only re-check rules whose `check` content changed since
  last successful `pass`.
- Signed result envelopes: wrap `AgentResult.output_json` in a detached
  JWS signed by the agent's enrollment key for non-repudiation.
