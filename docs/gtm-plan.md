# Go-To-Market Plan (GTM) — PySOAR

## Objective
Position PySOAR as an enterprise SOAR alternative to Cortex XSOAR (Cortex), Splunk Phantom, and Microsoft Sentinel playbooks by closing functional gaps, hardening reliability, and packaging for enterprise deployment.

## High-Level Pillars
- Product parity: playbooks, connectors, automation, case/incident management
- Reliability & scalability: CI/CD, tests, deployment artifacts (Docker/Helm)
- Security & compliance: secrets management, RBAC, audit logging
- Observability & support: metrics, SLOs, documentation
- Commercial readiness: licensing, onboarding docs, feature matrix

## Feature Matrix (candidate)
- Playbook engine: actions, branching, retries, idempotence — Present
- Integrations/connectors: Slack, VirusTotal, ServiceNow, CrowdStrike — Partial; wrapper plumbing present
- Case/incident management: create/update/assign — Present
- Tickets & workflows: bi-directional ticket sync — Partial
- Threat intel: IOC ingestion, enrichment, persistence — Partial (VirusTotal POC)
- Automation tools: agent tools, AI toolchain — Partial

## Prioritized Gaps (actionable)
1. Testability: decouple test collection from app imports (fixed) and ensure CI installs test deps selectively.
2. Integration runtime verification: add integration tests validating connector wrapper dispatch and persistence (in progress).
3. Connector coverage: implement and verify wrappers for top enterprise connectors (Slack, VirusTotal, ServiceNow, CrowdStrike).
4. Packaging: create Docker images and Helm chart for enterprise deploy.
5. Security: secrets encryption, managed identities, RBAC enforcement, audit trails.
6. Documentation: admin guide, operator runbook, onboarding checklist.
7. Performance: load test playbook engine and connectors, set SLOs.

## Next 30-day Plan (example)
- Week 1: Stabilize tests and CI; add integration/unit coverage for ActionExecutor and playbooks (done/in progress)
- Week 2: Harden connector wrappers and add mocks/recorded HTTP tests
- Week 3: Create Docker images, Helm skeleton, and deployment docs
- Week 4: Security review, packaging, and internal demo playbook

## Immediate next steps (I can implement now)
- Add integration test for `ActionExecutor` covering DB persistence (requires test DB provisioning)
- Expand connector wrapper unit tests with VCR-style HTTP recording
- Scaffold `docs/gtm-plan.md` (this file)
- Create CI job snippet to install test deps and run focused test suites


## How I can proceed next (pick or I'll start one)
- Implement CI test job and dependency management
- Create Docker + Helm skeleton and build script
- Start writing connector wrapper tests (Slack/VirusTotal)

