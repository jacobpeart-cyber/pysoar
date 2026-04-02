# Configuration Management Plan — PySOAR

**Document Version:** 1.0
**Effective Date:** 2026-03-30
**Review Cycle:** Annual (next review: 2027-03-30)
**Classification:** For Official Use Only (FOUO)
**Owner:** Director of Engineering

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Configuration Items](#2-configuration-items)
3. [Baseline Configurations](#3-baseline-configurations)
4. [Change Control Process](#4-change-control-process)
5. [Configuration Monitoring](#5-configuration-monitoring)
6. [Impact Analysis](#6-impact-analysis)
7. [Version Control](#7-version-control)
8. [Tools and Automation](#8-tools-and-automation)
9. [Roles and Responsibilities](#9-roles-and-responsibilities)
10. [Compliance Mapping](#10-compliance-mapping)

---

## 1. Introduction

### 1.1 Purpose

This Configuration Management Plan (CMP) establishes the policies, procedures, and practices for managing the configuration of the PySOAR platform throughout its lifecycle. The plan ensures that all system components are identified, documented, controlled, and auditable in accordance with FedRAMP Moderate requirements and NIST SP 800-53 Rev 5 CM controls.

### 1.2 Scope

This plan covers all hardware, software, firmware, documentation, and infrastructure components within the PySOAR authorization boundary, including:

- Application source code and container images
- Infrastructure as Code (Terraform) configurations
- Database schemas and configurations
- Web server and reverse proxy configurations
- Cache and message broker configurations
- Network configurations (VPC, Security Groups, NACLs)
- Encryption key configurations
- CI/CD pipeline configurations
- Monitoring and alerting configurations

### 1.3 Objectives

- Maintain an accurate, current inventory of all configuration items
- Establish and enforce approved baseline configurations
- Control changes through a formal, documented process
- Detect and remediate unauthorized configuration changes
- Support audit and compliance requirements with complete change history

---

## 2. Configuration Items

### 2.1 CI Inventory

The following table identifies all configuration items (CIs) within the PySOAR system, their owners, and classification.

| CI Category | Configuration Item | Owner | Criticality | Location |
|---|---|---|---|---|
| **Application** | PySOAR API source code | Engineering | Critical | GitHub (private repo) |
| **Application** | Celery worker source code | Engineering | Critical | GitHub (private repo) |
| **Application** | Detection rule definitions | Detection Engineering | High | Database + Git |
| **Application** | Playbook definitions | Security Engineering | High | Database + Git |
| **Container** | PySOAR API Docker image | DevOps | Critical | Amazon ECR |
| **Container** | Celery Worker Docker image | DevOps | Critical | Amazon ECR |
| **Container** | Nginx Docker image | DevOps | Critical | Amazon ECR |
| **Container** | Base image (Python 3.12-slim) | DevOps | Critical | Amazon ECR (mirrored) |
| **Infrastructure** | Terraform state files | DevOps | Critical | S3 (encrypted, versioned) |
| **Infrastructure** | Terraform module definitions | DevOps | Critical | GitHub (private repo) |
| **Infrastructure** | VPC configuration | DevOps | Critical | Terraform / AWS Console |
| **Infrastructure** | Security Group rules | DevOps | Critical | Terraform / AWS Console |
| **Infrastructure** | NACL rules | DevOps | High | Terraform / AWS Console |
| **Infrastructure** | IAM roles and policies | DevOps | Critical | Terraform / AWS Console |
| **Database** | PostgreSQL configuration (postgresql.conf) | DBA | Critical | RDS Parameter Group |
| **Database** | PostgreSQL pg_hba.conf | DBA | Critical | RDS Parameter Group |
| **Database** | Database schema (Alembic migrations) | Engineering | Critical | GitHub (private repo) |
| **Cache** | Redis configuration | DevOps | High | ElastiCache Parameter Group |
| **Web Server** | Nginx configuration (nginx.conf) | DevOps | Critical | Docker image + Git |
| **Web Server** | TLS certificate configuration | DevOps | Critical | AWS ACM / Secrets Manager |
| **Monitoring** | CloudWatch alarm definitions | DevOps | High | Terraform |
| **Monitoring** | SIEM correlation rules | Detection Engineering | High | Database + Git |
| **Monitoring** | UEBA model configurations | Data Science | High | S3 + Git |
| **Security** | WAF rule sets | Security Engineering | Critical | Terraform / AWS Console |
| **Security** | KMS key policies | Security Engineering | Critical | Terraform |
| **CI/CD** | GitHub Actions workflows | DevOps | Critical | GitHub (private repo) |
| **CI/CD** | Build and deploy scripts | DevOps | Critical | GitHub (private repo) |
| **Documentation** | SSP and security documentation | Compliance | High | Git + Compliance Module |

### 2.2 CI Identification Scheme

Each configuration item is assigned a unique identifier:

```
PYSOAR-{CATEGORY}-{SEQ}-{VERSION}

Examples:
  PYSOAR-APP-001-v2.4.1    (PySOAR API application)
  PYSOAR-IMG-003-sha256abc  (Nginx container image)
  PYSOAR-IaC-007-v1.12     (VPC Terraform module)
  PYSOAR-DB-002-mig0142    (Database migration 142)
```

### 2.3 Component Inventory Management

The Asset Management Module maintains a real-time inventory of all CIs. The inventory is updated automatically through:

- Container registry webhooks (new image versions)
- Terraform state change notifications
- Git commit hooks (code and configuration changes)
- AWS Config rules (infrastructure drift detection)
- SBOM generation on each build (software dependencies)

The inventory is reconciled monthly to verify accuracy.

---

## 3. Baseline Configurations

### 3.1 Definition

A baseline configuration is the approved, documented, and version-controlled set of specifications for a system component at a specific point in time. Baselines serve as the reference point for detecting unauthorized changes and for system recovery.

### 3.2 Baseline Catalog

#### 3.2.1 Docker Container Baselines

| Component | Base Image | Hardening Standard | Key Settings |
|---|---|---|---|
| **PySOAR API** | python:3.12-slim-bookworm | CIS Docker Benchmark | Non-root user, read-only rootfs, no new privileges, dropped capabilities |
| **Celery Worker** | python:3.12-slim-bookworm | CIS Docker Benchmark | Non-root user, resource limits, no network (task queue only) |
| **Nginx** | nginx:1.25-alpine | CIS Nginx Benchmark | TLS 1.2+ only, HSTS, security headers, rate limiting |

Container hardening checklist:
- No root processes inside containers
- Read-only root filesystem where possible
- Minimal installed packages (no shell in production where feasible)
- No SUID/SGID binaries
- Resource limits (CPU, memory) enforced
- Network policies restrict inter-container traffic
- Image signing and verification before deployment

#### 3.2.2 PostgreSQL Baseline

| Parameter | Baseline Value | Rationale |
|---|---|---|
| `ssl` | `on` | Encrypt all client connections |
| `ssl_min_protocol_version` | `TLSv1.2` | FIPS-compliant minimum |
| `password_encryption` | `scram-sha-256` | Strong authentication |
| `log_connections` | `on` | Audit all connections |
| `log_disconnections` | `on` | Audit session duration |
| `log_statement` | `ddl` | Audit schema changes |
| `log_min_duration_statement` | `1000` | Log slow queries (> 1s) |
| `shared_preload_libraries` | `pgaudit` | Detailed audit logging |
| `pgaudit.log` | `write, ddl, role` | Audit write ops, schema changes, role changes |
| `max_connections` | `200` | Limit connection pool |
| `idle_in_transaction_session_timeout` | `60000` | Kill idle transactions after 60s |

#### 3.2.3 Redis Baseline

| Parameter | Baseline Value | Rationale |
|---|---|---|
| `requirepass` | `<from Secrets Manager>` | Mandatory authentication |
| `rename-command FLUSHALL` | `""` | Disable destructive commands |
| `rename-command FLUSHDB` | `""` | Disable destructive commands |
| `rename-command CONFIG` | `<random>` | Restrict config changes |
| `maxmemory-policy` | `allkeys-lru` | Prevent OOM |
| `timeout` | `300` | Close idle connections |
| `tcp-keepalive` | `60` | Detect dead connections |
| `bind` | `127.0.0.1` | Listen on internal only |
| Transit encryption | Enabled (TLS) | Encrypt client traffic |
| At-rest encryption | Enabled (KMS) | Encrypt data on disk |

#### 3.2.4 Nginx Baseline

| Directive | Baseline Value | Rationale |
|---|---|---|
| `ssl_protocols` | `TLSv1.2 TLSv1.3` | FIPS-compliant protocols only |
| `ssl_ciphers` | FIPS-approved cipher suites | NIST SP 800-52 Rev 2 compliance |
| `ssl_prefer_server_ciphers` | `on` | Server controls cipher selection |
| `add_header Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | HSTS enforcement |
| `add_header X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `add_header X-Frame-Options` | `DENY` | Prevent clickjacking |
| `add_header Content-Security-Policy` | Restrictive CSP | XSS prevention |
| `server_tokens` | `off` | Hide version information |
| `client_max_body_size` | `10m` | Limit upload size |
| Rate limiting | 100 req/s per IP, burst 200 | DoS protection |

#### 3.2.5 AWS Infrastructure Baseline

| Resource | Baseline Configuration |
|---|---|
| **VPC** | Dedicated VPC, DNS support/hostnames enabled, flow logs to CloudWatch |
| **Subnets** | Public (ALB/NAT only), Private-App, Private-Data, Private-Mgmt |
| **Security Groups** | Least-privilege ingress/egress per tier, no 0.0.0.0/0 ingress (except ALB 443) |
| **NACLs** | Explicit deny-all default, allow-list per subnet |
| **S3 Buckets** | SSE-KMS, versioning, public access blocked, access logging |
| **RDS** | Multi-AZ, encryption at rest, automated backups (7 days), deletion protection |
| **KMS** | Customer-managed CMKs, automatic annual rotation, key policy with least privilege |
| **IAM** | MFA required for console, no inline policies, role-based access |

### 3.3 Baseline Approval and Update

- Baselines are reviewed and approved by the Change Advisory Board (CAB) upon initial creation
- Baseline updates require a formal change request (see Section 4)
- All baseline changes are version-controlled in Git with approval records
- Current baselines are accessible through the Compliance Module

---

## 4. Change Control Process

### 4.1 Change Categories

| Category | Description | Approval | Examples |
|---|---|---|---|
| **Standard** | Pre-approved, low-risk, routine changes | Pre-approved by CAB | Dependency version bumps (patch), detection rule updates |
| **Normal** | Planned changes requiring review | CAB approval required | Feature deployments, infrastructure changes, database migrations |
| **Emergency** | Urgent changes to address active incidents or critical vulnerabilities | IR Manager + 1 CAB member | Security patches for actively exploited CVEs, incident containment |

### 4.2 Change Request Process

#### Step 1: Request Submission

The change requestor submits a change request (CR) including:

- Description of the proposed change
- Affected configuration items
- Justification and business need
- Risk assessment (see Section 6)
- Rollback plan
- Testing plan
- Proposed implementation window

#### Step 2: Security Review

The security team reviews all Normal and Emergency CRs for:

- Security impact analysis
- Compliance impact (does the change affect any FedRAMP controls?)
- Privacy impact assessment (if PII handling is affected)
- Threat model implications

#### Step 3: CAB Review and Approval

The Change Advisory Board reviews the CR, security assessment, and test results:

- **Standard changes:** Auto-approved if they match pre-approved patterns
- **Normal changes:** Require majority CAB approval with security team concurrence
- **Emergency changes:** Require IR Manager + 1 CAB member approval; full CAB review within 5 business days post-implementation

#### Step 4: Implementation

- Changes are deployed through the CI/CD pipeline (see Section 7)
- Implementation follows the approved plan and schedule
- Real-time monitoring during deployment via SIEM and CloudWatch

#### Step 5: Verification

- Automated tests validate the change (unit, integration, security)
- STIG compliance scan verifies baseline conformance
- Post-deployment monitoring confirms no adverse effects
- Change record is updated with implementation results

#### Step 6: Closure

- Change record is closed with final status (successful, rolled back, failed)
- Updated baselines are documented (if applicable)
- Audit trail is complete

### 4.3 Change Advisory Board (CAB)

| Role | Participant |
|---|---|
| CAB Chair | Director of Engineering |
| Security Representative | Security Engineering Lead |
| Operations Representative | SRE/DevOps Lead |
| Compliance Representative | Compliance Officer |
| Business Representative | Product Manager |
| DBA Representative | Database Administrator (as needed) |

CAB meetings: Weekly (scheduled) + ad hoc for emergency changes.

---

## 5. Configuration Monitoring

### 5.1 Continuous Configuration Monitoring

PySOAR implements continuous configuration monitoring through multiple mechanisms:

| Mechanism | Scope | Frequency | Tool |
|---|---|---|---|
| **AWS Config Rules** | Infrastructure resources (VPC, SG, S3, RDS, IAM) | Continuous (event-driven) | AWS Config |
| **Container Image Scanning** | Docker images in ECR | On push + daily scheduled | Trivy / ECR native scanning |
| **STIG Compliance Scanning** | OS and application configurations | Daily | PySOAR STIG Module |
| **Infrastructure Drift Detection** | Terraform-managed resources | Hourly (terraform plan) | CI/CD Pipeline |
| **File Integrity Monitoring** | Critical system files, configuration files | Continuous | AIDE / OSSEC agent |
| **Database Configuration Audit** | PostgreSQL parameter groups | Daily | Custom audit script |
| **Secret Rotation Monitoring** | Certificates, API keys, passwords | Continuous | AWS Secrets Manager + CloudWatch |
| **SBOM Drift Detection** | Software dependencies | On each build | Syft / Grype |

### 5.2 Unauthorized Change Detection

When an unauthorized or unexpected configuration change is detected:

1. **Alert Generated:** SIEM correlation rule triggers an alert categorized as "Unauthorized Configuration Change"
2. **Automated Response:** Depending on the change type, automated remediation may revert the change (e.g., Security Group drift is auto-corrected by Terraform)
3. **Investigation:** A Tier 2 analyst investigates the change origin, intent, and impact
4. **Incident Declaration:** If the change is confirmed unauthorized, an incident is declared per the Incident Response Plan
5. **Remediation:** The configuration is restored to the approved baseline
6. **Documentation:** The event is documented in the audit trail and, if appropriate, a POA&M item is created

### 5.3 Configuration Audit

Quarterly configuration audits verify:

- All CIs in the inventory are accounted for and correctly documented
- Running configurations match approved baselines
- Change records are complete and accurate
- Unauthorized changes are identified and remediated
- SBOM is current and free of known critical/high vulnerabilities

Audit results are documented in the Compliance Module and reported to the ISSO.

---

## 6. Impact Analysis

### 6.1 Security Impact Analysis Process

Every proposed change undergoes a security impact analysis before approval. The analysis evaluates:

| Factor | Assessment Criteria |
|---|---|
| **Confidentiality Impact** | Does the change affect data protection, encryption, or access controls? |
| **Integrity Impact** | Does the change affect data validation, audit logging, or integrity verification? |
| **Availability Impact** | Does the change affect system uptime, failover, or recovery capabilities? |
| **Compliance Impact** | Does the change affect FedRAMP control implementation or SSP accuracy? |
| **Attack Surface** | Does the change expose new interfaces, ports, protocols, or services? |
| **Dependency Risk** | Does the change introduce new third-party dependencies or update existing ones? |
| **Rollback Complexity** | How difficult is it to revert the change if issues are discovered? |

### 6.2 Risk Scoring

Changes are scored using the Risk Quantification Module:

| Risk Level | Score | Approval Required | Additional Requirements |
|---|---|---|---|
| **Low** | 1-3 | Standard (pre-approved) | Automated testing |
| **Medium** | 4-6 | CAB approval | Security review + automated testing |
| **High** | 7-8 | CAB + ISSO approval | Full security impact analysis + pen test |
| **Critical** | 9-10 | CAB + ISSO + AO approval | Full security impact analysis + pen test + 3PAO review |

### 6.3 SSP Impact

Any change that modifies the system's security posture, architecture, data flows, or control implementations requires an SSP update. The Compliance Module tracks SSP-impacting changes and generates SSP update reminders. Significant changes require FedRAMP PMO notification per the Significant Change Policy.

---

## 7. Version Control

### 7.1 Git Repository Structure

All configuration items that can be expressed as code or text are maintained in Git repositories:

```
pysoar/
  src/                    # Application source code
  terraform/              # Infrastructure as Code
  docker/                 # Dockerfiles and compose files
  config/                 # Application configuration templates
  migrations/             # Database schema migrations (Alembic)
  detection-rules/        # SIEM correlation rules
  playbooks/              # Incident response playbooks
  docs/                   # Security documentation (SSP, plans)
  tests/                  # Automated test suites
  .github/workflows/      # CI/CD pipeline definitions
```

### 7.2 Branching Strategy

| Branch | Purpose | Protection Rules |
|---|---|---|
| `main` | Production-ready code | Requires 2 approvals, passing CI, CODEOWNERS review, no force push |
| `staging` | Pre-production validation | Requires 1 approval, passing CI |
| `feature/*` | Feature development | No direct push to main/staging |
| `hotfix/*` | Emergency production fixes | Requires 1 approval (expedited), post-merge CAB review |
| `release/*` | Release candidates | Tagged releases, requires security sign-off |

### 7.3 Commit and Merge Requirements

- All commits must be signed (GPG or SSH key signature)
- All changes must go through pull request review
- CI pipeline must pass (lint, test, security scan) before merge
- Merge commits must reference the change request ID
- Squash merges are used for feature branches to maintain clean history

### 7.4 Versioning Scheme

PySOAR follows Semantic Versioning (SemVer):

```
MAJOR.MINOR.PATCH

MAJOR: Breaking API changes or significant architectural changes
MINOR: New features, non-breaking enhancements
PATCH: Bug fixes, security patches, dependency updates
```

Every release is tagged in Git and associated with:
- Release notes documenting all changes
- SBOM for the release
- Security scan results
- Approval record from the CAB

---

## 8. Tools and Automation

| Tool | Purpose | Integration |
|---|---|---|
| **Git / GitHub** | Source code and configuration version control | Central repository for all CIs |
| **Terraform** | Infrastructure as Code, drift detection | AWS resource management |
| **Docker** | Container image building and management | Application packaging |
| **GitHub Actions** | CI/CD pipeline automation | Build, test, scan, deploy |
| **AWS Config** | Infrastructure configuration monitoring | Drift detection and compliance |
| **PySOAR STIG Module** | Configuration compliance scanning | Baseline verification |
| **Trivy** | Container vulnerability scanning | Image security |
| **Syft / Grype** | SBOM generation and vulnerability matching | Dependency management |
| **Alembic** | Database schema migration management | Schema version control |
| **AWS Secrets Manager** | Secret and credential management | Automatic rotation |
| **CloudWatch** | Monitoring and alerting | Configuration change alerts |

---

## 9. Roles and Responsibilities

| Role | CM Responsibilities |
|---|---|
| **Configuration Manager (Dir. of Engineering)** | Overall CM plan ownership, CAB chair, baseline approval |
| **DevOps/SRE Team** | Infrastructure CI management, deployment execution, drift remediation |
| **Development Team** | Application code management, migration authoring, code reviews |
| **Security Engineering** | Security baseline definition, security impact analysis, WAF/SG rules |
| **DBA** | Database configuration management, parameter group maintenance |
| **Detection Engineering** | Detection rule lifecycle, SIEM configuration |
| **Compliance Officer** | CM audit, FedRAMP control mapping, SSP updates |
| **ISSO** | CM oversight, compliance verification, AO reporting |

---

## 10. Compliance Mapping

This Configuration Management Plan satisfies the following FedRAMP Moderate controls:

| Control | Title | How This Plan Addresses It |
|---|---|---|
| CM-1 | Policy and Procedures | This document establishes CM policy and procedures |
| CM-2 | Baseline Configuration | Section 3 defines and maintains baseline configurations |
| CM-3 | Configuration Change Control | Section 4 defines the formal change control process |
| CM-4 | Impact Analyses | Section 6 defines security impact analysis procedures |
| CM-5 | Access Restrictions for Change | Section 7.2 defines branch protection and approval requirements |
| CM-6 | Configuration Settings | Section 3.2 documents mandatory configuration settings |
| CM-7 | Least Functionality | Section 3.2.1 documents container minimization and hardening |
| CM-8 | System Component Inventory | Section 2 defines the CI inventory and management process |
| CM-9 | Configuration Management Plan | This document is the CM plan |
| CM-10 | Software Usage Restrictions | SBOM tracking and license compliance in CI/CD pipeline |
| CM-11 | User-Installed Software | Container image allow-listing prevents unauthorized software |
