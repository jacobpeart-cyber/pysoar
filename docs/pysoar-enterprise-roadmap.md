# PySOAR Enterprise Roadmap

## Goal

Make PySOAR a viable replacement for Cortex XSOAR / Phantom / Microsoft Sentinel by moving it from prototype/SIEM proof-of-concept to a hardened enterprise SOAR/SIEM/Agentic SOC platform.

---

## Current Capability Inventory

### 1) Native SIEM
- Built-in log ingestion via:
  - `src/main.py` / `src/siem/syslog_receiver.py` for UDP/TCP 5514 syslog
  - HTTP bulk ingestion endpoint in `src/api/v1/endpoints/siem.py`
  - Single log ingestion and batch ingestion API endpoints
- Processing pipeline in `src/siem/pipeline.py` includes parse, normalize, rule evaluation, alert creation, and correlation.
- `src/siem/models.py` and `src/siem/storage.py` support log storage and query.
- Detection rule seeding and rule engine priming are present in `src/main.py`.

### 2) Playbooks / Automation
- `src/playbooks/engine.py` executes playbook steps sequentially with conditional flow and error handling.
- `src/playbooks/actions.py` implements action primitives including:
  - `enrich_ip`, `enrich_domain`, `enrich_hash`
  - `send_notification`
  - `update_alert`
  - `create_incident`
  - `run_script`
  - `conditional`
  - `wait`
- Frontend has playbook builder and execution APIs.
- Integration marketplace in frontend exists for connectors.

### 3) Agentic SOC
- `src/agentic/investigator.py` contains an actual LLM-driven autonomous investigator with OODA loop semantics.
- Guardrails and tool allowlists are implemented to keep state-changing actions blocked during autonomous runs.
- `src/agentic/tasks.py` supports background Celery runs, periodic threat hunts, and agent memory maintenance.
- `src/agentic/tools.py` and `src/agentic/skills.py` provide a tool/skill registry and execution abstractions.

### 4) Integration / Connector Framework
- `src/integrations/engine.py` defines a registry of built-in connectors across:
  - SIEM interop (Splunk, QRadar, Elastic, etc.)
  - EDR vendors (CrowdStrike, SentinelOne, Carbon Black, Defender, Cortex XDR)
  - Firewalls (Palo Alto, Fortinet, Cisco ASA)
  - Cloud providers (AWS Security Hub, Azure Sentinel, GCP SCC)
  - Cloud log sources (CloudTrail, Azure Activity Log, GCP Cloud Logging)
  - Identity providers (Okta, Azure AD, CyberArk)
  - Ticketing / ITSM (ServiceNow, Jira, PagerDuty)
  - Messaging / comms (Slack, Teams, SMTP)
  - Threat Intel (VirusTotal, Shodan, AlienVault OTX, GreyNoise, AbuseIPDB, Recorded Future)
  - Vulnerability scanners (Nessus, Qualys, OpenVAS, Trivy)
  - CI/CD platforms (GitHub Actions, GitLab CI, Jenkins)
- The registry is largely declarative; actual action wiring requires implementation behind the connector engine and marketplace.

### 5) Supplementary modules
- Compliance, ITDR, vulnerability management, attack surface, and Zero Trust scoring modules are present.
- These provide domain-specific data sources but are not the core SOAR automation engine.

---

## Gap Matrix: PySOAR vs. Enterprise SOAR, EDR, and Agentic SOC

| Capability | Enterprise SOAR | PySOAR today | Gap severity |
|---|---|---|---|
| Log ingestion reliability | High-scale authenticated, buffered, transform-capable ingestion | Native syslog + HTTP bulk exists | Low-medium (needs hardening, TLS, scaling)
| Rule engine & detection | Mature rule library with tuning and performance | Prototype rule engine present | Medium
| Alert/case workflow | Full incident lifecycle, analyst queues, SLA, assignments | Basic alert/incidents, limited workflow | High
| Connector action library | Deep API adapters for EDR, cloud, identity, ITSM, network | Declarative connector registry + some adapter stubs | High
| Playbook engine | Full branching, retries, approval, parallelism, typed actions | Step engine with basic conditional + wait | High
| EDR telemetry | Endpoint sensor ingest + process/network/file artifacts | No native endpoint sensor model; only external EDR connectors declared | High
| EDR response | Contain/isolate/kill/quarantine on endpoints | Conceptual actions via connectors / script, no native endpoint control | High
| Agentic automation | Safe evidence-driven tool orchestration + recommendations | Yes, prototype investigator with tool guardrails | Medium (useful but not proven production)
| Human-in-the-loop controls | Explicit approvals, review before change | Some blocked state actions in autonomous mode | Medium
| Integration automation | Installed connectors, test/config APIs, actions | Marketplace APIs exist, but implementation coverage unclear | Medium
| Operational resilience | HA, backpressure, queueing, metrics, security | Basic service startup; no explicit HA/scale architecture | High
| Compliance / audit | Full audit trail, approvals, evidence | Some audit persistence in agentic steps and actions | Low-medium


## Key technical gaps to fix before enterprise parity

### A) Automation and playbook capability
- Expand from generic `run_script`/alert updates to real connector-driven adapters.
- Add strong action schemas, parameter validation, and sandboxed execution.
- Support retry/rollback, parallel execution, child playbooks, and approvals.
- Make action state observable and auditable inside the UI.

### B) Real connector implementation
- Most connectors are declared in `src/integrations/engine.py` but likely only partially implemented.
- Need real API adapters and end-to-end workflows for high-value systems (EDR, identity, ITSM, cloud security).
- Avoid relying on stubbed capability names alone.

### C) Endpoint / EDR capability
- Either build endpoint agents and ingest host telemetry, or integrate deeply with existing EDR vendors.
- True EDR replacement requires endpoint process/network/file context plus containment.
- Current code only supports external EDR action conceptually.

### D) Agentic robustness
- The autonomous investigator is architected sensibly but needs production hardening:
  - prompt/tool alignment
  - robust JSON extraction and error recovery
  - step monitoring and investigator retries
  - evidence overflow protection
- Treat this as augmentation first, not fully autonomous response yet.

### E) Ingestion hardening
- Secure the syslog/HTTP ingestion path with TLS and auth.
- Add buffering, batching, retries, and validation at the ingest layer.
- Monitor ingestion health and rule engine performance.

### F) UI/workflow completeness
- Existing frontend has dashboards and playbook builder, but real SOC users need incident triage, evidence viewers, analyst assignment, case comments, and remediation status.

---

## Prioritized Roadmap

### Phase 1 — Enterprise SOAR foundation

1. Harden ingestion and detection
   - Validate syslog + HTTP bulk ingest in production-like flow
   - Add TLS/auth for HTTP ingest and protect syslog from abuse
   - Add ingestion metrics, backpressure, and batch retry controls
   - Expand detection coverage and rule engine testing

2. Build strong case/incident workflow
   - Add incident lifecycle states, assignment, comments, owner, and SLA markers
   - Create alert triage and escalation automation
   - Ensure all actions are auditable and linked to cases

3. Stabilize connector execution
   - Implement actual action adapters for at least one real EDR, one cloud provider, one identity provider, one ITSM tool, and one alert notification channel
   - Test end-to-end playbook flows through these connectors

4. Harden playbooks
   - Add approval steps and `execute_playbook` safe handling
   - Add structured action schemas and validation
   - Add failure handling and retries

### Phase 2 — Operational maturity

1. Add resilience and observability
   - Metrics for ingest, worker health, rule eval latency, connector success
   - Support persistent queues or durable task processing
   - Add health endpoints and service recovery

2. Expand connectors and integrations
   - Focus on real EDR vendors, cloud-native security, threat intel, and ITSM
   - Add integration tests for each connector
   - Add webhook/event-driven inbound connectors where relevant

3. Improve UI/UX for SOC operations
   - Analyst dashboards, case views, evidence timeline, contextual search
   - Integration marketplace visibility and connector status
   - Investigator / agent console real-time progress

### Phase 3 — Secure autonomous SOC

1. Harden the Agentic layer
   - Make LLM-driven investigation a trusted advisor module, not first-line automation
   - Add explicit human review points before any remediation recommendation runs
   - Track error recovery and explainability

2. Add memory and learning
   - Improve agent memory, feedback loop, false positive corrections
   - Use analyst-behavior data to tune the investigator

3. Tighten governance
   - API key scopes, RBAC, multi-tenant isolation, audit logging
   - Formal guardrails for dangerous actions and approval workflows

### Phase 4 — EDR and full response parity

1. Choose EDR strategy
   - Build sensor-based endpoint telemetry, or
   - Integrate with vendor EDRs as the primary endpoint response layer

2. Add host investigation objects
   - process trees, network connections, file hashes, user sessions
   - endpoint containment / quarantine actions
   - live response workflows

3. Align detection and response
   - Map EDR/endpoint alerts into cases
   - Automate containment recommendations based on endpoint evidence

---

## Recommended immediate next steps

1. Keep the native SIEM ingestion path, but use HTTP bulk + regional aggregator for production.
2. Pick 2-3 high-value connectors and implement them end-to-end rather than defining more connector metadata.
3. Improve the playbook engine with robust action schemas and failure handling.
4. Ship the Agentic investigator as a query/recommendation assistant first, then incrementally widen its action scope.
5. Establish a clear product boundary: `PySOAR = SIEM + SOAR + Agentic augmentation`; EDR can be delivered via integration or agent extension.

---

## Conclusion

PySOAR has many of the right pieces, but it must fill the gaps in connector execution, workflow robustness, operational resilience, and endpoint response before it can truly replace Cortex/Phantom/Sentinel.

The fastest path is not to build every connector at once; it is to make a small but strong set of real workflows that prove the platform end-to-end.
