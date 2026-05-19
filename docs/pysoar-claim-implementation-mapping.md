# PySOAR Claim vs Implementation Mapping

This document maps high-level PySOAR product claims to code and architecture evidence in the repository. It is intended to make gap remediation concrete and prioritize work from the top of the gap list.

## 1. Verified implementation

| Claim | Evidence / Code | Status |
|---|---|---|
| Native SIEM log ingestion | `src/siem/storage.py`, `src/siem/pipeline.py`, `src/api/v1/endpoints/siem.py`, `src/main.py` | Implemented |
| Playbook engine core | `src/playbooks/engine.py` | Implemented |
| Playbook action primitives | `src/playbooks/actions.py` | Implemented |
| Visual playbook builder schema/API | `src/playbook_builder/models.py`, `src/api/v1/endpoints/playbook_builder.py` | Implemented |
| Endpoint agent platform | `agent/pysoar_agent.py`, `src/agents/models.py`, `src/api/v1/endpoints/agents.py` | Implemented |
| Capability-gated commands | `agent/pysoar_agent.py` allowlist, `src/agents/models.py` | Implemented |
| Tamper-evident command chain | `src/agents/models.py` `AgentCommand`, hash chain semantics in agent code | Implemented |
| Agentic autonomous investigator | `src/agentic/investigator.py`, `src/agentic/tasks.py`, `src/agentic/tools.py` | Implemented (prototype) |
| Threat intel platform (IOC storage/enrichment) | `src/intel/models.py`, `src/playbooks/actions.py`, `connectors/virustotal.py`, `src/services/agent_tools.py` | Partially implemented |
| Dark web monitoring module | `src/darkweb/models.py`, `src/darkweb/tasks.py`, `src/api/v1/endpoints/darkweb.py`, agentic darkweb tools | Implemented |
| Zero Trust engine / NIST 800-207 module | `src/zerotrust/engine.py`, `src/zerotrust/models.py`, `src/api/v1/endpoints/zerotrust.py` | Implemented |
| Compliance / FedRAMP modules | `src/fedramp/`, `src/compliance/`, `src/api/v1/endpoints/audit_evidence.py` | Implemented |
| Privacy / DSR workflow | `src/privacy/`, `src/api/v1/endpoints/aliases.py` | Implemented |
| Attack simulation API | `src/api/v1/endpoints/simulation.py` | Implemented (partial) |
| Threat hunting task stub | `src/agentic/tasks.py`, `src/agentic/llm.py` | Implemented (prototype) |

## 2. Partial support / prototype-level

| Claim | Evidence / Code | Gap |
|---|---|---|
| Threat hunting / MITRE attack simulation | `src/agentic/tasks.py` threat hunt returns mock summary; `src/api/v1/endpoints/simulation.py` attack simulation endpoints | Needs real hunting engine, adversary emulation execution, and correlation outputs |
| Deep integration connector library | `src/integrations/engine.py` connector registry, generic HTTP fallback, some connector wrapper classes | Needs actual adapter implementations for most high-value connectors |
| EDR telemetry | endpoint agent exists, but no native sensor data model or streaming ingestion of processes/network/file artifacts | Missing endpoint event ingestion and EDR visibility |
| Live response / host containment | `agent/pysoar_agent.py` has kill/isolate handlers, but server/API-driven dispatch flow is not fully validated | Needs end-to-end approval/test coverage |
| Playbook action schema validation | `src/playbooks/engine.py` executes actions dynamically, but action parameter typing and validation are minimal | Needs stronger typed action contracts |
| Unified Ticket Hub | `frontend/src/pages/TicketHub.tsx`, `src/api/v1/endpoints/tickethub.py`, `src/tickethub/engine.py`, `src/tickethub/models.py` | Implemented |
| Notebook support | README claims notebooks; codebase includes no explicit notebook backend or integration tooling | Missing Jupyter/notebook support |

## 3. Claims not verified or missing

| Claim | Notes | Gap severity |
|---|---|---|
| Dark Web scanning for marketplaces and paste sites | module exists, but no connector or scraper implementation was confirmed in code review | Medium |
| 1000+ prebuilt integrations / automation packs | registry is declarative; only a small set of connectors/adapters are actually implemented | High |
| Full incident lifecycle with SLA/workflow | incident/case models exist, but advanced workflow and analyst assignment are not clearly visible | Medium |
| Real-time analytic dashboards | frontend/back-end visualization not fully validated from backend code | Medium |
| Full EDR sensor model | absent; only endpoint agent command execution is present | High |
| Parallel playbook execution / rollback / approval workflow | engine supports sequential steps and continue_on_error, but not parallelism/rollback | High |
| Metrics/operational resilience | some Redis/celery/worker tasks exist, but explicit HA metrics and recovery are not fully implemented | High |

## 4. Top-priority gaps to fix first

1. **Connector execution**
   - Make at least one real connector end-to-end: VirusTotal + Slack, or EDR + ITSM.
   - Ensure `src/integrations/engine.py` uses real adapters, not only generic HTTP fallback.

2. **EDR / endpoint visibility**
   - Add endpoint telemetry ingestion beyond heartbeat.
   - Model process/network/file artifacts and store them for correlation.

3. **Playbook hardening**
   - Add action schema validation, retry, approval, and safe execution semantics.

4. **Agentic robustness**
   - Harden JSON extraction, evidence boundaries, and error recovery in `src/agentic/investigator.py`.
   - Treat the LLM investigator as advisory until action flows are safe.

5. **Threat hunting / simulation**
   - Turn the current mock threat hunt into a real query/search-based hunt.
   - Tie simulation endpoints to actual telemetry/correlation evidence.

## 5. Recommended next step

Start by adding a concrete mapping table from README product claims to code support, then immediately close the highest-confidence gap:
- implement a real connector workflow through the integration runtime and playbook/agent tool layer.

This doc is the first deliverable for the gap list; the next step is a focused code fix for the highest-priority gap: real connector execution and EDR telemetry.
