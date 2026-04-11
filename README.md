# PySOAR

**Enterprise Security Orchestration, Automation & Response Platform**

PySOAR is a full-stack, multi-tenant SOAR platform that unifies security operations into a single pane of glass. Built for modern SOC teams and MSSPs, it combines alert triage, incident response, threat intelligence, compliance management, Breach & Attack Simulation, Live Response through a deployable endpoint agent, and cross-module automation workflows — all in one platform.

47 integrated modules. Cross-module automation. Tenant-isolated by construction. Production-hardened.

---

## Platform Overview

### Core SOC Operations
- **Alert Management** — Ingest, triage, and correlate alerts from SIEM, EDR, IDS, firewall, cloud, and email gateways. Real-time WebSocket notifications, bulk actions, and whitelisted sort fields.
- **Incident Response** — Full incident lifecycle with severity tracking, real MTTR calculation, automatic War Room creation on critical/high incidents, and cross-module automation fan-out.
- **Case Management** — Collaborative case investigation with notes, attachments, tasks, timeline, and audit trails.
- **Threat Hunting** — Hypothesis-driven hunts with MITRE ATT&CK mapping, multi-source query aggregation, and notebook support.
- **SIEM Integration** — Real-time log ingestion, correlation rules, and event streaming to multiple backends.

### Threat Intelligence
- **Intel Platform** — IOC management with automated enrichment via VirusTotal, AbuseIPDB, Shodan, GreyNoise, and MISP.
- **Dark Web Monitoring** — Real scanners for credential leaks and brand exposure on dark web marketplaces and paste sites.
- **Adversary Profiles** — 5 built-in APT profiles (APT29, APT28, FIN7, Lazarus, Generic Ransomware) plus tenant-authored profiles.

### Breach & Attack Simulation + Purple Team
- **Attack Simulation** — 20+ MITRE ATT&CK techniques, adversary emulation, and safety-gated execution against real endpoints via the PySOAR Agent.
- **Purple Team** — Run an attack technique against a target, then correlate the SIEM/EDR response timeline to verify whether the blue team detected it. Includes detection scoring and gap analysis.
- **Deception Technology** — Honeypots, honeytokens, and decoy asset management with automated alerting.

### Endpoint Agent Platform
- **PySOAR Agent** (`agent/pysoar_agent.py`) — Standalone enrollment-token-based agent that connects back to the API, polls for commands, and executes IR/BAS/purple-team actions.
- **Capability-Gated Commands** — Every command is checked against a per-agent capability allowlist (`bas`, `ir`, `purple`) before dispatch. Agents can only run what they're enrolled for.
- **SHA-256 Hash-Chained Audit Trail** — Every command the agent receives, executes, or rejects is recorded in a tamper-evident hash chain. The `/agents/{id}/verify-chain` endpoint lets an analyst re-verify the chain integrity on demand.
- **Two-Person Approval for High-Blast Actions** — Live Response commands like "isolate host" or "kill process" require a second analyst to approve before the agent will execute. Rejecter must be a different user than the issuer; both the approval and rejection are signed rows in the chain.
- **Live Response Page** — Single-pane UI for issuing commands, monitoring command status (queued → dispatched → running → completed), and clearing the approval queue.

### Digital Forensics & Incident Response (DFIR)
- **Forensic Case Management** — Evidence chain of custody, timeline reconstruction, and artifact management.
- **Real IOC Extraction** — Regex-based extraction of IPs, domains, hashes, URLs, and emails from uploaded forensic artifacts (no mocks).
- **Chain-of-Custody Tracking** — Every artifact's acquisition, transfer, and review is logged.

### Identity & Access
- **ITDR** — Identity Threat Detection & Response with real credential stuffing detection, impossible-travel analysis, and privilege escalation monitoring.
- **UEBA** — User and entity behavior analytics with anomaly detection and risk scoring.
- **Zero Trust Engine** — Real CIDR-based policy evaluation across all 7 NIST 800-207 pillars (identity, device, network, application, data, visibility/analytics, automation/orchestration).

### Compliance, Risk & Governance
- **Compliance Hub** — Framework mapping for NIST 800-53, NIST CSF, ISO 27001, SOC 2, PCI DSS, HIPAA, and custom frameworks. Auto-evaluation against live evidence.
- **FedRAMP Moderate** — All 191 NIST 800-53 Rev 5 controls in the FedRAMP Moderate baseline. SSP generation, POA&M tracking, readiness scoring, and evidence status per control family.
- **STIG/SCAP** — Automated STIG scanning, remediation script generation from real fix_text, and compliance trend dashboards.
- **Audit & Evidence Collection** — Automated evidence collection, approval workflows, and audit readiness assessment with real aggregates.
- **Risk Quantification (FAIR)** — Monte Carlo simulations with PERT-distribution vulnerability/loss sampling, loss exceedance curves, portfolio VaR (95/99th percentile), and 5×5 risk heatmap.
- **Threat Modeling** — STRIDE and PASTA engines with auto-threat generation, mitigation recommendations, and model validation.

### Infrastructure & Cloud Security
- **OT/ICS Security** — ICS asset inventory, Purdue model segmentation mapping (levels 0–5), real NERC-CIP / IEC 62443 / NIST 800-82 compliance checks, and safety-first containment workflows.
- **Container Security** — Image vulnerability scanning, Kubernetes security findings, runtime alerts, NSA/CISA + DoD STIG + SOC 2 compliance matrices.
- **API Security** — Endpoint inventory, vulnerability tracking, shadow/zombie API detection, anomaly detection, and OWASP API Top 10 policy enforcement.
- **Supply Chain Security** — SBOM management, dependency risk scoring, license conflict detection, real CVE severity lookup.
- **Vulnerability Management** — Asset correlation, real risk matrix, patch plan creation, and cross-module automation on scan import.

### Data & Analytics
- **Data Lake / Data Mesh** — DataSource ingestion pipelines, partitioned storage with tier breakdown, unified data model registry, query catalog, and real storage usage aggregation.
- **Analytics Dashboard** — Real-time KPIs (alert volume, MTTR, severity distribution, source breakdowns) — all tenant-scoped.
- **Reports** — Exportable alert, incident, and executive reports in CSV/JSON/PDF.

### Automation & Workflow
- **Agentic SOC** — AI-powered autonomous investigation with OODA loop reasoning, natural-language query summarization via Gemini 2.5 Flash, and real threat-hunt aggregation across 4 data sources.
- **Playbook Builder** — Visual drag-and-drop playbook authoring with template library, schedule triggers, and execution history.
- **Playbook Engine** — 8-step action library (alert, enrich, block, isolate, notify, ticket, query, custom) with conditional branching.
- **Unified Ticket Hub** — Cross-module ticket aggregation layer that surfaces incidents, case tasks, remediation tickets, remediation executions, war room actions, POA&Ms, compliance control work, and evidence requests in one list + Kanban view. Includes threaded comments, activity log, ticket linking, and automation rules.

### Privacy & Data Protection
- **Privacy Engineering** — GDPR/CCPA Data Subject Request (DSR) workflow with deadline tracking, Privacy Impact Assessments (PIA), Records of Processing Activities (ROPA), consent management with withdrawal tracking, and privacy incident reporting.
- **DLP** — Data loss prevention policy management with real violation detection and incident tracking.
- **Phishing Simulation** — Campaign authoring, target group management, awareness score tracking, and per-user security posture metrics.

### Collaboration & Communication
- **War Room** — Real-time incident coordination with WebSocket-powered chat, shared artifacts, action items, incident timeline, and post-mortem generation.
- **Integrations Marketplace** — 20+ pre-built integrations with SIEM, EDR, ITSM, cloud, and email platforms.

---

## Security Posture

PySOAR is designed for MSSPs and multi-tenant SaaS deployments. Every endpoint that returns tenant data enforces strict organization boundaries.

### Multi-Tenant Isolation (hardened through comprehensive audit)
- **Every read path is tenant-scoped.** Alerts, incidents, assets, playbook executions, vulnerabilities, policies, anomalies, compliance checks, container images, findings, runtime alerts, OT assets/alerts/zones/incidents/policies, API endpoints, data lake sources/pipelines/partitions, privacy records, threat models, ticket hub comments/activity/links, war rooms/messages/artifacts/actions, FedRAMP POA&Ms, endpoint agents, agent commands — all filter on `organization_id == current_user.organization_id`.
- **Every `get_*_or_404` helper enforces tenant.** A tenant can't fetch another tenant's record by guessing the UUID (IDOR prevention).
- **Every dashboard aggregate is tenant-scoped.** No cross-tenant counts.
- **Role isolation:** per-tenant `admin` role only grants access within the caller's organization. Platform `superuser` is the only role that can see across tenants (used for platform-level operations like the Organizations and Settings pages).
- **Audit log isolation:** platform-level audit log access is locked to `is_superuser` so per-tenant admins can't see another tenant's audit trail.
- **Endpoint Agent isolation:** an agent belongs to exactly one organization. Commands are tenant-scoped, so a user in tenant A can't issue a Live Response command against an endpoint in tenant B.

### Schema-Level Isolation
- `alerts`, `incidents`, `assets`, and `playbook_executions` all have `organization_id` foreign keys (added in migrations 014 and 015) with backfill from `users.organization_id` where possible.
- Every other tenant-scoped table already had `organization_id` from day one.
- All cross-tenant references (e.g., linking an alert to an incident) verify both objects belong to the same tenant before proceeding.

### Cross-Module Automation Loop
Every module fires events into a central `AutomationService` pipeline so action in one module triggers reactions in others:

- **Alert created → Correlation → Incident → War Room → Action Items** — automatic
- **Incident created → Playbook execution, remediation tickets, stakeholder notifications** — configurable
- **Vulnerability found → Asset correlation → Remediation ticket → Agent-dispatched patch** — configurable
- **Compliance check failed → POA&M entry → Ticket Hub → Automation rule** — automatic
- **API security threat → Alert → Incident** — automatic
- **FedRAMP evidence gap → Ticket Hub** — automatic
- **Remediation policy evaluation → Agent dispatch on high-severity** — configurable

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend   │────▶│    Nginx     │────▶│   FastAPI    │
│   React 19   │     │   Reverse    │     │   Backend    │
│   TypeScript │     │   Proxy      │     │   (Async)    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                         ┌─────────────────────┼─────────────────────┐
                         │                     │                     │
                    ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
                    │PostgreSQL│          │  Redis   │          │ Celery   │
                    │   15     │          │  7       │          │ Workers  │
                    │ Database │          │ Cache/MQ │          │ + Beat   │
                    └─────────┘          └─────────┘          └─────────┘
                                               │
                                         ┌─────▼─────┐
                                         │  PySOAR   │
                                         │  Agents   │
                                         │ (remote)  │
                                         └───────────┘
```

**Stack**
- **Frontend:** React 19 + TypeScript + Vite + TanStack Query + Tailwind CSS
- **Backend:** FastAPI + SQLAlchemy 2.0 async (asyncpg) + Pydantic v2
- **Database:** PostgreSQL 15 with 15 alembic migrations
- **Cache/MQ:** Redis 7
- **Workers:** Celery 5 with Beat scheduler
- **Real-time:** WebSocket manager with per-org scoping
- **AI:** Gemini 2.5 Flash (configurable) for Agentic SOC reasoning and NL query summarization
- **Observability:** Prometheus metrics + Grafana dashboards
- **Deployment:** Docker Compose with bind-mount frontend for zero-rebuild hot deploys

---

## Compliance Baselines Shipped

| Framework | Controls | Coverage |
|-----------|----------|----------|
| **FedRAMP Moderate** | 191 | NIST 800-53 Rev 5 control catalog, SSP generation, POA&M, readiness scoring |
| **NIST 800-53** | Full | Control family evaluation with real evidence queries |
| **NIST 800-207 Zero Trust** | 7 pillars | Identity, Device, Network, Application, Data, Visibility, Automation |
| **NIST 800-82 (OT)** | Full | Real compliance checks on ICS asset inventory |
| **NERC-CIP** | Full | OT/ICS compliance |
| **IEC 62443** | Full | Industrial control system security |
| **ISO 27001** | Annex A | Control mapping and evidence tracking |
| **SOC 2** | Trust Services | TSC mapping with evidence collection |
| **PCI DSS** | v4.0 | Payment card industry compliance |
| **HIPAA** | Full | Healthcare security and privacy |
| **GDPR / CCPA** | DSR workflow | Subject rights, consent, ROPA, PIA |
| **DoD STIG** | SCAP-based | STIG scanning and remediation |
| **CISA / NSA K8s** | Container | Kubernetes hardening compliance |

---

## Quick Start

```bash
# Clone and start
git clone https://github.com/jacobpeart-cyber/pysoar.git
cd pysoar
cp .env.example .env

# Start all services
docker compose up -d

# Apply database migrations
docker exec pysoar-api alembic upgrade head

# Seed demo data (optional)
docker exec pysoar-api python scripts/seed_demo.py

# Access the platform
open http://localhost
```

**Default login:** `admin@pysoar.local` / `changeme123`

---

## Deploying the Endpoint Agent

```bash
# From an admin account, generate an enrollment token (via the UI or API)
# POST /api/v1/agents/enroll -> returns {agent_id, enrollment_token}

# On the target host:
python agent/pysoar_agent.py \
    --server https://your-pysoar-instance \
    --enrollment-token <token> \
    --capabilities bas,ir,purple
```

The agent will exchange its enrollment token for a long-lived agent token, send heartbeats, and poll for commands. Commands it cannot execute (capability not enrolled, command rejected, server unreachable) are logged locally and in the hash-chained audit record on the server.

---

## Production Deployment

```bash
# Configure production environment
cp .env.production .env
# Edit .env with real secrets, database URL, domain

# Deploy with production config
docker compose -f docker-compose.prod.yml up -d

# Verify health
curl https://your-domain/api/v1/health
```

All 47 sidebar pages are backed by real endpoints with tenant-scoped data. No placeholder or theater data. No hardcoded stats. No silent 500s.

See `.env.example` for all configuration options.

---

## API Documentation

- **Swagger UI:** `/api/v1/docs`
- **ReDoc:** `/api/v1/redoc`
- **OpenAPI JSON:** `/api/v1/openapi.json`

All endpoints are versioned under `/api/v1`. Authentication is JWT bearer or API key (`X-API-Key` header) with per-key rate limiting, IP allowlists, and per-permission scoping.

---

## Recent Platform Updates

**Migration 015 — Complete multi-tenant isolation of the SOC core**
The two most-used tables in the platform — `alerts` and `incidents` — are now tenant-scoped at the schema level. Every dashboard aggregate, list query, and cross-module lookup is now strictly isolated per organization.

**Migration 014 — Asset inventory and playbook execution history**
`assets` and `playbook_executions` both gained `organization_id` columns with backfill from `users.organization_id`. Asset inventory is now fully tenant-isolated.

**Migration 013 — Timezone-aware remediation timestamps**
All remediation timestamps now store tz-aware datetimes to fix timezone drift on cross-timezone deployments.

**Migration 012 — Endpoint Agent Platform tables**
Added `endpoint_agents` and `agent_commands` tables with hash-chained audit columns.

**Migration 011 — Simulation timestamps tz-aware**
**Migration 010 — Adversary profiles org-nullable** (to support global built-in APT profiles)
**Migration 009 — Compliance framework unique-per-org**
**Migrations 001-008 — Foundation schemas**

**Comprehensive audit sweep (47 pages)**
Every sidebar page was audited for P0 bugs, cross-tenant leaks, fake/theater data, broken endpoints, route collisions, and schema mismatches. 40+ commits resolving findings across the entire platform. All fixes deployed and E2E verified in production.

---

## License

Proprietary. All rights reserved.
