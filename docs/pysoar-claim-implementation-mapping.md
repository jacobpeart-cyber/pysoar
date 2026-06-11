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
| 1 | Alert processing pipeline (dedupe, enrich, trigger playbooks) | `process_alert_task` logs and returns `{"processed": true}` — body is a "This would…" comment | `src/workers/tasks.py` |
| 2 | IOC enrichment refresh (beat-scheduled daily) | `refresh_ioc_enrichments` returns `{"refreshed": 0}` forever | `src/workers/tasks.py` + beat entry |
| 3 | Alert ingestion from external sources | `ingest_alerts_from_source` stub returns `{"imported": 0}` | `src/workers/tasks.py` |
| 4 | Report generation (CSV/JSON/PDF) | `generate_report` returns `{"generated": true, "url": null}`; PDF/CSV handlers don't exist anywhere | `src/workers/tasks.py`, compliance export only does JSON/Markdown |
| 5 | Network remediation (sinkhole, block URL, DNS block) | `NetworkActionExecutor.execute` writes an activity row and returns success — configures nothing, dispatches nothing | `src/remediation/engine.py:1148` |
| 6 | STIG findings enter automation (alerts → incidents → playbooks) | `on_stig_finding` creates the Alert but never calls `on_alert_created`, so the automation pipeline is skipped | `src/services/automation.py:873` |
| 7 | Data lake ingestion/pipeline metrics | Hardcoded: 125,000,000 events, 5,432 eps, 456 GB/day, 52,083 throughput — no DB reads | `src/data_lake/engine.py:331,1286` |
| 8 | Data lake event enrichment (geo, intel, asset) | Hardcoded geo (US/CA/Mountain View) and reputation_score 85 | `src/data_lake/engine.py:209` |
| 9 | Honeypots/decoys "deployed" with automated alerting | `deploy_honeypot` creates a DB record; no listener is ever started. Orchestrator effectiveness/coverage return zeros/fixed maps | `src/deception/engine.py:104,700` |

## 2. Tier 2 — overstated or degraded

| # | Claim | Reality | Where |
| --- | --- | --- | --- |
| 10 | "20+ pre-built integrations" | 46 declared, 10 real adapters (slack, crowdstrike, servicenow, jira, pagerduty, virustotal, shodan, abuseipdb, aws_security_hub, microsoft_sentinel); other 36 fall back to a generic HTTP guesser | `src/integrations/engine.py`, `src/integrations/connectors/` |
| 11 | Tenant-scoped real-time KPIs | `/metrics` queries real counts but has NO organization_id filter — cross-tenant aggregates | `src/api/v1/endpoints/monitoring.py:95` |
| 12 | Purple team "correlate the SIEM/EDR response timeline" | Detection score = does any active rule list the technique ID. No temporal correlation with actually-fired alerts | `src/simulation/engine.py:513` |
| 13 | Hunt finding scoring | Fixed constants by type (lateral_movement=0.85 …), thresholds map score→severity | `src/hunting/engine.py:525,748` |
| 14 | Dark web actor attribution / campaign mapping | 8 hardcoded keyword signatures; `_map_campaign` and `_get_historical_context` return null/zeros | `src/darkweb/engine.py:926-1071` |
| 15 | Enrichment via VT/AbuseIPDB/Shodan/GreyNoise | Real API calls when keys exist; silent `[]` when missing (UI shows nothing instead of "no key configured") | `src/intel/enrichment.py:63-83` |
| 16 | ITDR credential exposure check | Silently returns `[]` if CredentialLeak import fails | `src/itdr/engine.py:449` |
| 17 | Patch deployment | Marks vulnerability rows PATCHED; never talks to a patch system | `src/remediation/engine.py:1182` |
| 18 | `IntegrationManager.install_connector` | Dead code — returns success without persisting; the API endpoint does the real work | `src/integrations/engine.py:722` |

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
