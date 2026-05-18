# PySOAR Engineering Backlog

## Goal

Turn the current prototype into a hardened enterprise platform by focusing on the most critical implementation gaps in:
- `src/integrations` (real connector action plumbing)
- `src/playbooks` (robust execution, retry/rollback, approval, structured actions)
- `src/agentic` (safe, explainable agentic SOC behavior and toolkit integration)

---

## Core Epics

### Epic 1: Real Connector Execution

Why: The connector registry is declarative, but production parity depends on real API adapters and end-to-end action execution.

Deliverables:
- Implement connector installer persistence and health checks in `src/integrations/engine.py`
- Create actual action execution flow for high-value connectors in `src/integrations/*` and `src/integrations/manager.py`
- Build integration-specific request builders and response parsers for:
  - EDR: `crowdstrike`, `sentinelone`, `carbon_black`, `microsoft_defender`, `cortex_xdr`
  - ITSM: `servicenow`, `jira`, `pagerduty`
  - Threat intel: `virustotal`, `shodan`, `abuseipdb`
  - Notification: `slack`, `microsoft_teams`, `smtp_email`

Tasks:
1. Add connector config schema validation in `ConnectorRegistry.validate_connector_schema`
2. Implement `IntegrationManager.install_connector` persistence path to `InstalledIntegration`
3. Add action dispatch mapping from `IntegrationManager.execute_action` to connector-specific endpoint templates
4. Add `IntegrationManager.test_connection` coverage for missing connector types and remove false `unknown` behavior by implementing probes for all supported connectors
5. Add integration health and status APIs to the frontend and audit pipeline

### Epic 2: Playbook Engine Hardening

Why: The playbook engine currently only supports sequential action steps and basic conditional branching.

Deliverables:
- Add typed action schemas and parameter validation
- Add retry/failure handling and rollback semantics
- Add approval gating for dangerous actions
- Add parallel child playbooks / subflow support

Tasks:
1. Replace `PlaybookAction.validate_parameters` with per-action schema validation and enforce before execution in `PlaybookEngine._execute_step`
2. Add `continue_on_error` semantics to support safe failure handling
3. Implement `timeout_seconds` and global `execution_timeout` enforcement
4. Add `approval_required` metadata to actions such as `run_script`, `send_notification`, `create_incident`, `create_forensic_case`
5. Add a `playbook_execution_logs` timeline object for each action result, with structured `inputs`, `outputs`, and `status`
6. Build a small sandbox for `run_script` or remove it until safe endpoint-specific actions exist

### Epic 3: Agentic SOC Safety and Explainability

Why: The autonomous investigator is a strong foundation, but it must be constrained and instrumented so it can be trusted in enterprise SOC workflows.

Deliverables:
- Harden tool guardrails and enforce action allowlists by mode
- Add evidence quality and step monitoring
- Improve verdict extraction and fallback handling
- Treat the investigator as advisory at first, not automatic remediation

Tasks:
1. Extend `src/agentic/investigator.py` to enforce `INVESTIGATOR_READONLY_TOOLS` plus explicit `recommended_actions` instead of blocked actions being silently logged
2. Add UI/state for agent recommendations vs executed actions
3. Add prompt + tool schema alignment tests for the LLM pipeline
4. Add explicit `human_review_required` return values for any dangerous remediation suggestion
5. Improve `_extract_verdict` error handling and prompt recovery for partial/malformed JSON
6. Add step-by-step audit entries for all tool calls in investigations and make them queryable by org

### Epic 4: Endpoint/EDR Strategy and Telemetry

Why: Replacing Cortex or Sentinel requires endpoint visibility; currently PySOAR only has external EDR connector concepts.

Deliverables:
- Choose whether to integrate vendor EDR telemetry or build a native light agent
- Create endpoint asset objects and ingestion models
- Add containment controls or integrate with endpoint action APIs

Tasks:
1. Add endpoint agent models in `src/models/endpoint_agent.py` and API registration endpoints
2. Add `list_endpoint_agents` / `queue_endpoint_command` actual agent queueing behavior in `src/services/agent_tools.py`
3. Add host telemetry ingestion support to SIEM in `src/siem/pipeline.py`
4. Add `contain`, `kill_process`, `network_isolate` action support via connector or local agent bridge

---

## Specific Code-Level Work Items

### `src/integrations/engine.py`

- Remove the stubbed `install_connector` path that only logs and return success without DB state.
- Add real integration persistence using `InstalledIntegration` and `IntegrationExecution`
- Add `get_connector_details`/`check_compatibility` to support runtime validation before action execution
- Implement actual health probes for all built-in connectors, not just a handful

### `src/services/agent_tools.py`

- Replace placeholder remediation actions (`_block_ip`, `_isolate_host`) with real workflow events or connector action dispatch
- Implement `execute_playbook` to actually queue or start the playbook engine instead of only creating a `PlaybookExecution` row
- Add authorization checks for dangerous tools in AI mode vs analyst mode
- Add `queue_endpoint_command` handler integration with endpoint command processor

### `src/playbooks/actions.py`

- Add `validate_parameters` for each action and integrate with `PlaybookEngine`
- Add action metadata fields such as `approval_required`, `continue_on_error`, `timeout_seconds`, and `required_parameters`
- Replace the generic `send_notification/run_script` pattern with typed playbook actions that match installed connector capabilities
- Remove or sandbox `run_script` until safe execution semantics are defined

### `src/agentic/investigator.py`

- Enforce explicit allowable tool lists based on investigation mode and do not permit state-changing actions without review
- Wire `list_configured_integrations` output into tool recommendation filtering consistently
- Add investigation progress logging and front-end event model for every tool call
- Turn `recommendations` into structured objects so the UI can distinguish advisory output from executed actions
- Add a safe fallback when the LLM returns malformed verdict JSON

### Immediate Proof-of-Concept Work

1. Implement a full end-to-end playbook for one real integration:
   - `virustotal` lookup -> create IOC -> notify Slack -> create incident
2. Add a real connector health check path in `src/integrations/engine.py` for Slack and VirusTotal
3. Add a small incident lifecycle improvement: assign alert, update status, close incident
4. Add one agentic investigation test for `triage_alert` + `search_logs` + `recommendations`

---

## Suggested Sprint Plan

Sprint 1:
- Stabilize `AgentToolRegistry` and `IntegrationManager`
- Add integration persistence and health probe coverage
- Add `PlaybookEngine` parameter validation and better failure handling

Sprint 2:
- Implement one full connector workflow end-to-end
- Harden agentic investigator mode and review behaviors
- Add endpoint/EDR asset + queue action support

Sprint 3:
- Add operational telemetry, status APIs, and workflow visibility
- Expand the connector library for cloud security and ITSM
- Build analyst review/approval gating in the UI

---

## What this gives PySOAR

Focused execution on these code areas will move the product from prototype toward an enterprise-class SOAR platform by making:
- connector metadata real and actionable
- playbooks robust and safe
- agentic automation explainable rather than speculative
- endpoint/EDR response feasible rather than conceptual
 