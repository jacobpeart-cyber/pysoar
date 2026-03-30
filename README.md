# PySOAR

**Enterprise Security Orchestration, Automation & Response Platform**

PySOAR is a full-stack SOAR platform that unifies security operations into a single pane of glass. Built for modern SOC teams, it combines alert triage, incident response, threat intelligence, compliance monitoring, and automated playbook execution in one platform.

## Key Features

### Core SOC Operations
- **Alert Management** — Ingest, triage, and correlate alerts from SIEM, EDR, IDS, firewall, cloud, and email gateways
- **Incident Response** — Full incident lifecycle management with severity tracking, MTTR metrics, and timeline reconstruction
- **Case Management** — Collaborative case investigation with notes, attachments, tasks, and audit trails
- **Playbook Automation** — Visual playbook builder with drag-and-drop orchestration and scheduled execution

### Threat Intelligence & Hunting
- **Threat Intelligence** — IOC management with automated enrichment via VirusTotal, AbuseIPDB, Shodan, and MISP
- **Threat Hunting** — Hypothesis-driven hunting with MITRE ATT&CK mapping and notebook support
- **Dark Web Monitoring** — Credential leak detection and dark web intelligence feeds
- **SIEM Integration** — Real-time log ingestion, correlation rules, and event streaming

### Advanced Security Modules
- **UEBA** — User and entity behavior analytics with anomaly detection and risk scoring
- **Attack Simulation** — Breach & attack simulation with 20+ MITRE techniques and adversary emulation
- **Deception Technology** — Honeypots, honeytokens, and decoy asset management
- **Digital Forensics (DFIR)** — Forensic case management, evidence chain of custody, and timeline analysis

### Compliance & Risk
- **Compliance Dashboard** — Framework mapping (NIST, ISO 27001, SOC 2, PCI DSS, HIPAA)
- **STIG Compliance** — Automated STIG/SCAP scanning and remediation tracking
- **Audit & Evidence** — Automated evidence collection and audit readiness assessment
- **Risk Quantification** — FAIR-based risk analysis with loss exceedance modeling

### Infrastructure Security
- **Zero Trust Architecture** — Zero trust posture assessment and policy enforcement
- **Container Security** — Container image scanning and Kubernetes policy management
- **OT/ICS Security** — Operational technology asset monitoring and Purdue model mapping
- **API Security** — API endpoint inventory, vulnerability tracking, and anomaly detection
- **Supply Chain Security** — SBOM management, dependency risk scoring, and supply chain monitoring

### Platform Capabilities
- **Agentic SOC** — AI-powered autonomous investigation with OODA loop reasoning
- **DLP** — Data loss prevention policy management and incident tracking
- **Privacy Engineering** — Privacy compliance monitoring and data subject request management
- **Integration Marketplace** — 20+ pre-built integrations with SIEM, EDR, ITSM, and cloud platforms
- **Real-time Collaboration** — War room for live incident coordination with WebSocket updates

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend   │────▶│    Nginx     │────▶│   FastAPI    │
│   React/TS   │     │   Reverse    │     │   Backend    │
│   Vite/TW    │     │   Proxy      │     │   (Async)    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                         ┌─────────────────────┼─────────────────────┐
                         │                     │                     │
                    ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
                    │PostgreSQL│          │  Redis   │          │ Celery   │
                    │   15     │          │  7       │          │ Workers  │
                    │ Database │          │ Cache/MQ │          │ + Beat   │
                    └─────────┘          └─────────┘          └─────────┘
```

**Stack:** React 19 + TypeScript + Tailwind CSS | FastAPI + SQLAlchemy (async) + Pydantic v2 | PostgreSQL 15 | Redis 7 | Celery 5

## Quick Start

```bash
# Clone and start
git clone https://github.com/jacobpeart-cyber/pysoar.git
cd pysoar
cp .env.example .env

# Start all services
docker compose up -d

# Seed demo data
docker exec pysoar-api python scripts/seed_demo.py

# Access the platform
open http://localhost
```

**Default login:** `admin@pysoar.local` / `changeme123`

## Production Deployment

```bash
# Configure production environment
cp .env.production .env
# Edit .env with real secrets, database URL, and domain

# Deploy with production config
docker compose -f docker-compose.prod.yml up -d
```

See `.env.example` for all configuration options.

## API Documentation

Interactive API documentation is available at `/api/v1/docs` (Swagger UI) and `/api/v1/redoc` (ReDoc).

## License

Proprietary. All rights reserved.
