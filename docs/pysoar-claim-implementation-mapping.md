# PySOAR Claim vs Implementation Mapping

Refreshed 2026-06-11 by a six-track code audit (workers/automation,
integrations/remediation, detection, IR/forensics, GRC/infra, data/AI/
simulation). Supersedes the 2026-05-19 version. Purpose: make gap
remediation concrete, working from the top down.

Status legend: REAL (computes from actual data) · FAKE (fabricates or
no-ops while reporting success) · OVERSTATED (real core, claim stretches
it) · HONEST-EMPTY (returns nothing + says why, acceptable).

## 1. Tier 1 gaps — advertised features that silently no-op or fabricate

| # | Claim | Reality | Where |
| --- | --- | --- | --- |
| 1 | Alert processing pipeline (dedupe, enrich, trigger playbooks) | **FIXED 2026-06-11**: zero-caller stub deleted (honest absence beats fake success); real processing lives in the SIEM pipeline + automation service | `src/workers/tasks.py` |
| 2 | IOC enrichment refresh (beat-scheduled daily) | **FIXED 2026-06-11**: re-enriches active non-whitelisted indicators stale 7+ days (100/run) via IndicatorEnricher, which persists results | `src/workers/tasks.py` |
| 3 | Alert ingestion from external sources | **FIXED 2026-06-11**: zero-caller stub deleted; real ingestion is the SIEM collectors + cloud pollers | `src/workers/tasks.py` |
| 4 | Report generation (CSV/JSON/PDF) | **FIXED 2026-06-11**: real tenant-scoped CSV+PDF via `src/services/report_generator.py` + `GET /reports/{type}/export`; frontend downloads server files | `src/api/v1/endpoints/reports.py` |
| 5 | Network remediation (sinkhole, block URL, DNS block) | **FIXED 2026-06-11**: now registers target as active IOC (detective control) and honestly reports `mode: detection_only`; enforcement still needs a firewall integration | `src/remediation/engine.py` |
| 6 | STIG findings enter automation (alerts → incidents → playbooks) | **FIXED 2026-06-11**: `on_stig_finding` now calls `on_alert_created` like every other source | `src/services/automation.py` |
| 7 | Data lake ingestion/pipeline metrics | **FIXED 2026-06-11**: fabricating dead methods deleted (zero callers); API serves real rows | `src/data_lake/engine.py` |
| 8 | Data lake event enrichment (geo, intel, asset) | **FIXED 2026-06-11**: fabricating dead method deleted (zero callers) | `src/data_lake/engine.py` |
| 9 | Honeypots/decoys "deployed" with automated alerting | `deploy_honeypot` creates a DB record; no listener is ever started. Orchestrator effectiveness/coverage return zeros/fixed maps | `src/deception/engine.py:104,700` |

## 2. Tier 2 — overstated or degraded

| # | Claim | Reality | Where |
| --- | --- | --- | --- |
| 10 | "20+ pre-built integrations" | 46 declared, 10 real adapters (slack, crowdstrike, servicenow, jira, pagerduty, virustotal, shodan, abuseipdb, aws_security_hub, microsoft_sentinel); other 36 fall back to a generic HTTP guesser | `src/integrations/engine.py`, `src/integrations/connectors/` |
| 11 | Tenant-scoped real-time KPIs | **FIXED 2026-06-11** (re-read: /metrics is a Prometheus exposition endpoint, platform totals are correct semantics; the dashboard IS tenant-scoped) — public access now 403s via X-Forwarded-For gate | `src/api/v1/endpoints/monitoring.py` |
| 12 | Purple team "correlate the SIEM/EDR response timeline" | **FIXED 2026-06-11**: real executions now require fired evidence (log rule-match or correlation event) inside the execution window, with measured latency; "rule claims coverage but didn't fire" surfaced as `coverage_only_not_fired` | `src/simulation/engine.py` `_check_detection` |
| 13 | Hunt finding scoring | **FIXED 2026-06-11**: type priors now scale with evidence magnitude (count vs analyzer threshold, host spread, rarity inversion) + corroboration bumps; analyzers stamp their thresholds into evidence | `src/hunting/engine.py` `score_finding` |
| 14 | Dark web actor attribution / campaign mapping | **FIXED 2026-06-11**: zero-caller fabricators deleted (`enrich_findings`, `_map_campaign`, `_get_historical_context` returned canned data); real path is correlate_with_iocs/incidents | `src/darkweb/engine.py` |
| 15 | Enrichment via VT/AbuseIPDB/Shodan/GreyNoise | **FIXED 2026-06-11**: skipped providers now reported with reasons (no key / not implemented / query failed) in results and persisted context — 'no data' is distinguishable from 'checked and clean' | `src/intel/enrichment.py` |
| 16 | ITDR credential exposure check | **FIXED 2026-06-11**: skipped lookups now log explicit warnings instead of silently returning clean results | `src/itdr/engine.py` |
| 17 | Patch deployment | Marks vulnerability rows PATCHED; never talks to a patch system | `src/remediation/engine.py:1182` |
| 18 | `IntegrationManager.install_connector` | **FIXED 2026-06-11**: dead fake-success method deleted; API endpoint owns persistence | `src/integrations/engine.py` |

## 3. Verified real (sampled, no action needed)

SIEM collectors + correlation (z-scores, attack chains), rule engine,
threat-intel feeds + composite scoring, UEBA (baselines, impossible
travel, peer groups), ITDR detections, dark-web feed scanning
(URLhaus/HIBP/ThreatFox/OTX), exposure scoring + CISA KEV + EPSS,
FAIR Monte Carlo (scipy PERT), STRIDE/PASTA generation, STIG/SCAP
parse+remediation scripts, compliance attester (live-state queries),
zero trust PDP + session gate, DFIR chain of custody + IOC extraction,
phishing send (gated on SMTP config, no fake success), war room +
post-mortems, DSR workflows, endpoint agent (hash chain, two-person
approval, real iptables/netsh isolation), BAS agent dispatch (21
techniques, honest coverage-only fallback), Gemini LLM integration,
playbook execution loop (fixed 2026-06-11).

## 4. Remediation order

1. **Quick wins (bugs + honesty):** #6 STIG pipeline, #11 tenant-scope
   /metrics, #2 implement enrichment refresh, #1/#3 delete-or-implement
   stub tasks, #16 surface ITDR failure, #18 delete dead code.
2. **Stop fabricating:** #7/#8 data-lake metrics + enrichment from real
   tables (or honest nulls), #5 NetworkActionExecutor → dispatch via
   agent/integration or return `recorded_only`.
3. **Deliver claimed outputs:** #4 real CSV + PDF report export.
4. **Close the loop:** #12 purple-team temporal correlation.
5. **Bigger builds:** #9 deception listeners via endpoint agent, #10
   connector adapter expansion, #13/#14 statistical scoring.
