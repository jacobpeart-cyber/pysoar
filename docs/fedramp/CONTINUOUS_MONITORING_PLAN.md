# Continuous Monitoring Plan — PySOAR

**Document Version:** 1.0
**Effective Date:** 2026-03-30
**Review Cycle:** Annual (next review: 2027-03-30)
**Classification:** For Official Use Only (FOUO)
**Owner:** Information System Security Officer (ISSO)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Monitoring Strategy](#2-monitoring-strategy)
3. [Automated Monitoring Tools](#3-automated-monitoring-tools)
4. [Assessment Frequency](#4-assessment-frequency)
5. [Reporting Requirements](#5-reporting-requirements)
6. [POA&M Management](#6-poam-management)
7. [Risk Assessment Updates](#7-risk-assessment-updates)
8. [Roles and Responsibilities](#8-roles-and-responsibilities)
9. [Compliance Mapping](#9-compliance-mapping)

---

## 1. Introduction

### 1.1 Purpose

This Continuous Monitoring (ConMon) Plan defines the strategy, tools, processes, and reporting requirements for maintaining ongoing awareness of the security posture of the PySOAR platform. Continuous monitoring ensures that the security controls documented in the System Security Plan (SSP) remain effective over time and that emerging threats and vulnerabilities are identified and addressed promptly.

This plan satisfies FedRAMP continuous monitoring requirements as defined in the FedRAMP Continuous Monitoring Strategy Guide and NIST SP 800-137 (Information Security Continuous Monitoring for Federal Information Systems and Organizations).

### 1.2 Scope

This plan covers all components within the PySOAR authorization boundary as defined in the SSP, including application infrastructure, data stores, network components, and management systems deployed in AWS GovCloud.

### 1.3 ConMon Goals

- Maintain an accurate, real-time understanding of the system's security posture
- Detect and respond to security threats, vulnerabilities, and configuration drift in near-real-time
- Verify ongoing effectiveness of implemented security controls
- Support risk-based decision-making for the Authorizing Official
- Satisfy FedRAMP monthly, quarterly, and annual reporting obligations
- Reduce the time between vulnerability introduction and remediation

---

## 2. Monitoring Strategy

### 2.1 Defense-in-Depth Monitoring Approach

PySOAR implements a layered continuous monitoring strategy aligned with NIST SP 800-137:

```
Layer 1: Infrastructure Monitoring
  └─ AWS Config, CloudWatch, VPC Flow Logs, GuardDuty

Layer 2: Application Monitoring
  └─ SIEM correlation rules, API access logging, error rate monitoring

Layer 3: Data Monitoring
  └─ DLP module, database audit logging, encryption verification

Layer 4: Identity Monitoring
  └─ UEBA behavioral analysis, ITDR anomaly detection, MFA compliance

Layer 5: Threat Monitoring
  └─ Threat intel IOC matching, dark web monitoring, vulnerability scanning

Layer 6: Compliance Monitoring
  └─ Control assessment automation, evidence collection, STIG scanning
```

### 2.2 Monitoring Domains

| Domain | What Is Monitored | Objective |
|---|---|---|
| **Vulnerability Management** | Known vulnerabilities in OS, application, containers, dependencies | Identify and remediate vulnerabilities within defined SLAs |
| **Configuration Compliance** | System configurations against approved baselines and STIGs | Detect and remediate configuration drift |
| **Security Events** | Authentication, authorization, data access, administrative actions | Detect and respond to security incidents |
| **User Behavior** | User and entity activity patterns | Detect insider threats and compromised accounts |
| **Threat Intelligence** | External threat landscape, IOCs, TTPs | Proactively identify emerging threats |
| **Network Traffic** | Ingress/egress flows, DNS queries, lateral movement | Detect unauthorized communications |
| **Availability** | System uptime, response times, error rates | Maintain operational availability |
| **Encryption** | Certificate validity, key rotation status, protocol compliance | Ensure cryptographic protections remain effective |

### 2.3 Key Performance Indicators (KPIs)

| KPI | Target | Measurement Method |
|---|---|---|
| **Vulnerability Remediation — Critical** | 100% within 15 calendar days | Vulnerability Management Module |
| **Vulnerability Remediation — High** | 100% within 30 calendar days | Vulnerability Management Module |
| **Vulnerability Remediation — Medium** | 100% within 90 calendar days | Vulnerability Management Module |
| **Configuration Compliance Rate** | > 98% of CIs in compliance | STIG Module / AWS Config |
| **Mean Time to Detect (MTTD)** | < 15 minutes for critical events | SIEM Module metrics |
| **Mean Time to Respond (MTTR)** | < 1 hour for critical incidents | Incident Response Module metrics |
| **False Positive Rate** | < 10% of triaged alerts | SIEM analytics |
| **Patch Currency** | > 95% of systems within patch cycle | Vulnerability Management Module |
| **MFA Compliance** | 100% of interactive users | Auth Module metrics |
| **Certificate Expiry** | 0 expired certificates | Certificate monitoring |
| **POA&M Overdue Items** | 0 overdue items | Compliance Module |

---

## 3. Automated Monitoring Tools

### 3.1 SIEM (Security Information and Event Management)

**Module:** PySOAR SIEM Module

**Capabilities:**
- Real-time log ingestion from all system components (application logs, database audit logs, authentication logs, network flow logs, CloudTrail, GuardDuty findings)
- Over 500 correlation rules mapped to MITRE ATT&CK framework
- Custom Sigma-compatible rule authoring
- Alert prioritization based on risk scoring and contextual enrichment
- Dashboard and visualization for security operations

**Data Sources:**
| Source | Log Type | Ingestion Method | Retention |
|---|---|---|---|
| PySOAR Application | API access, errors, audit events | Direct (structured JSON) | 1 year hot, 7 years cold |
| PostgreSQL | Connection, query, DDL audit logs | CloudWatch Logs agent | 1 year hot, 7 years cold |
| Redis | Connection, command audit | CloudWatch Logs agent | 90 days hot, 1 year cold |
| Nginx | Access, error logs | Sidecar container | 1 year hot, 7 years cold |
| AWS CloudTrail | API activity | S3 + EventBridge | 7 years |
| VPC Flow Logs | Network flows | CloudWatch Logs | 90 days hot, 1 year cold |
| AWS GuardDuty | Threat findings | EventBridge | 90 days (GuardDuty) + archived |
| AWS Config | Configuration changes | EventBridge | 7 years |

### 3.2 UEBA (User and Entity Behavior Analytics)

**Module:** PySOAR UEBA Module

**Capabilities:**
- Behavioral baseline establishment for all users and service accounts
- Machine-learning anomaly detection (login times, access patterns, data volumes, geographic locations)
- Risk scoring with automatic alert generation when thresholds are exceeded
- Peer-group analysis to identify outlier behavior
- Integration with ITDR for identity-specific threat detection

**Monitored Behaviors:**
- Login time and frequency deviations
- Unusual data access volume or patterns
- Privilege escalation attempts
- Geographic impossibility (login from impossible travel distances)
- Service account behavior anomalies
- Dormant account reactivation

### 3.3 Vulnerability Scanning

**Module:** PySOAR Vulnerability Management Module

**Scanning Coverage:**

| Scan Type | Target | Frequency | Tool |
|---|---|---|---|
| **Infrastructure Vulnerability Scan** | All EC2 instances, containers | Daily (automated) | Integrated scanner + AWS Inspector |
| **Container Image Scan** | All ECR images | On push + daily | Trivy |
| **Dependency Scan (SCA)** | Python packages, npm, system libs | On build + daily | Safety, Grype |
| **Web Application Scan (DAST)** | PySOAR API endpoints | Weekly | OWASP ZAP (automated) |
| **Static Analysis (SAST)** | Source code | On every PR + daily | Bandit, Semgrep |
| **Database Vulnerability Scan** | PostgreSQL, Redis | Monthly | dbsat / custom scripts |
| **Cloud Configuration Scan** | AWS resources | Continuous | AWS Config + Prowler |

**Vulnerability Handling:**
1. Vulnerabilities are automatically ingested and deduplicated
2. Each vulnerability is risk-scored (CVSS + environmental context + threat intel enrichment)
3. Vulnerabilities are assigned remediation deadlines per severity (see KPIs)
4. Remediation is tracked through to closure with verification scan
5. Vulnerabilities that cannot be remediated within SLA are escalated to POA&M

### 3.4 Configuration Compliance Scanning

**Module:** PySOAR STIG Module

**Capabilities:**
- Automated STIG and CIS Benchmark compliance scanning
- Baseline drift detection with automatic alerting
- Remediation guidance and automated remediation scripts
- Compliance scoring and trending dashboards

**Scan Schedule:**
| Target | Benchmark | Frequency |
|---|---|---|
| Container host OS | DISA STIG for RHEL/Amazon Linux | Daily |
| Docker configuration | CIS Docker Benchmark | Daily |
| PostgreSQL | CIS PostgreSQL Benchmark + DISA STIG | Daily |
| Nginx | CIS Nginx Benchmark | Daily |
| AWS Account | CIS AWS Foundations Benchmark | Continuous (AWS Config) |
| Application settings | Custom PySOAR security baseline | On change + daily |

### 3.5 Additional Monitoring Tools

| Tool | Purpose | Frequency |
|---|---|---|
| **AWS GuardDuty** | Threat detection for AWS environment | Continuous |
| **AWS CloudTrail** | API activity audit logging | Continuous |
| **AWS Config** | Resource configuration compliance | Continuous (event-driven) |
| **CloudWatch Alarms** | Infrastructure health and performance | Continuous |
| **Certificate Monitor** | TLS certificate expiry tracking | Daily check |
| **Dark Web Monitoring** | Credential exposure detection | Continuous (Threat Intel Module) |

---

## 4. Assessment Frequency

### 4.1 Ongoing Assessments

| Assessment Type | Frequency | Assessor | Deliverable |
|---|---|---|---|
| **Automated Vulnerability Scanning** | Daily | Automated (Vuln Mgmt Module) | Scan results in dashboard |
| **Configuration Compliance Scanning** | Daily | Automated (STIG Module) | Compliance scores |
| **SIEM Alert Review** | Continuous (automated) + Daily (manual) | SOC Analysts | Reviewed alerts, incident cases |
| **UEBA Anomaly Review** | Continuous (automated) + Weekly (manual) | Tier 2 Analysts | Anomaly investigations |
| **Threat Intel IOC Matching** | Continuous | Automated (Threat Intel Module) | IOC match alerts |

### 4.2 Periodic Assessments

| Assessment Type | Frequency | Assessor | Deliverable |
|---|---|---|---|
| **Control Subset Assessment** | Monthly (1/12 of controls) | ISSO + Security Team | Control assessment results |
| **Access Review / Recertification** | Quarterly | System Admin + Managers | Access review report |
| **Penetration Testing (Internal)** | Quarterly | Security Engineering | Pen test report |
| **POA&M Review** | Monthly | ISSO + Compliance Officer | Updated POA&M |
| **Risk Assessment Update** | Quarterly + event-driven | Risk Quantification Module | Updated risk register |
| **Contingency Plan Test** | Annual | DevOps + Security | Test results and AAR |
| **Penetration Testing (3PAO)** | Annual | Third Party Assessment Org | Independent pen test report |
| **Full Control Assessment** | Annual | 3PAO | SAR (Security Assessment Report) |
| **SSP Review and Update** | Annual + on significant change | ISSO + Compliance | Updated SSP |

### 4.3 Monthly Control Assessment Rotation

Each month, a subset of control families is assessed. Over 12 months, all control families are covered:

| Month | Control Families Assessed |
|---|---|
| January | AC (Access Control), IA (Identification and Authentication) |
| February | AU (Audit and Accountability), SI (System and Information Integrity) |
| March | CM (Configuration Management), SA (System and Services Acquisition) |
| April | SC (System and Communications Protection) |
| May | IR (Incident Response), CP (Contingency Planning) |
| June | CA (Security Assessment), RA (Risk Assessment) |
| July | PE (Physical and Environmental), MA (Maintenance) |
| August | AT (Awareness and Training), PS (Personnel Security) |
| September | PL (Planning), PM (Program Management) |
| October | MP (Media Protection) |
| November | Catch-up / re-assess any controls with findings |
| December | Annual summary and next-year planning |

---

## 5. Reporting Requirements

### 5.1 FedRAMP Reporting Deliverables

| Deliverable | Frequency | Recipient | Content |
|---|---|---|---|
| **ConMon Monthly Report** | Monthly (by 15th of following month) | FedRAMP PMO / AO | Vulnerability scan results, POA&M updates, significant changes, incident summary |
| **Vulnerability Scan Results** | Monthly (included in ConMon report) | FedRAMP PMO / AO | Full scan output, remediation status, false positive justifications |
| **POA&M Update** | Monthly | FedRAMP PMO / AO | Updated POA&M with status, milestones, new items |
| **Significant Change Request** | As needed | FedRAMP PMO | Description, security impact, updated SSP sections |
| **Incident Report** | As required (see IR Plan) | US-CERT, FedRAMP PMO, AO | Incident details, impact, remediation |
| **Annual Assessment Report** | Annual | FedRAMP PMO / AO | SAR from 3PAO, updated SSP, updated POA&M |

### 5.2 Internal Reporting

| Report | Frequency | Audience | Generated By |
|---|---|---|---|
| **Security Posture Dashboard** | Real-time | SOC, Security Leadership | SIEM Module |
| **Vulnerability Summary** | Weekly | Security Engineering, DevOps | Vulnerability Management Module |
| **Compliance Scorecard** | Weekly | ISSO, Compliance Officer | Compliance Module |
| **UEBA Risk Report** | Weekly | Tier 2 Analysts, SOC Manager | UEBA Module |
| **Executive Security Briefing** | Monthly | CISO, CIO, AO | Compiled from all modules |
| **Trend Analysis Report** | Quarterly | Security Leadership | Risk Quantification Module |

### 5.3 Report Generation

All reports are generated through the PySOAR platform:

- **Automated Generation:** ConMon monthly reports, vulnerability summaries, and compliance scorecards are generated automatically by the Compliance Module on schedule.
- **FedRAMP API Endpoint:** `GET /api/v1/fedramp/readiness` provides real-time readiness scoring. `GET /api/v1/fedramp/poam/report` provides current POA&M status. `GET /api/v1/fedramp/evidence/status` provides evidence collection status per control family.
- **Export Capability:** `GET /api/v1/fedramp/ssp/export` generates the SSP document for submission.

---

## 6. POA&M Management

### 6.1 POA&M Process

The Plan of Action and Milestones (POA&M) is the central tracking mechanism for all identified weaknesses, vulnerabilities, and non-compliant controls.

#### 6.1.1 POA&M Item Creation

POA&M items are created when:

- A vulnerability scan identifies a finding that cannot be remediated within the defined SLA
- A control assessment identifies a gap or partial implementation
- A penetration test reveals an exploitable weakness
- An incident investigation identifies a systemic weakness
- A configuration audit identifies persistent drift

#### 6.1.2 POA&M Item Fields

Each POA&M item includes:

| Field | Description |
|---|---|
| POA&M ID | Unique identifier (POAM-YYYY-NNNN) |
| Weakness Description | Detailed description of the finding |
| Associated Control(s) | NIST 800-53 control IDs affected |
| Source | How the weakness was identified (scan, assessment, incident, audit) |
| Severity | Critical, High, Moderate, Low |
| Risk Rating | Quantified risk score from Risk Quantification Module |
| Status | Open, In Progress, Completed, Risk Accepted |
| Responsible Party | Individual or team responsible for remediation |
| Milestones | Specific remediation steps with target dates |
| Scheduled Completion Date | Expected full remediation date |
| Resources Required | Budget, personnel, tools needed |
| Vendor Dependency | Whether remediation depends on a third-party vendor |
| Actual Completion Date | Date remediation was verified complete |
| Verification Method | How completion was verified (re-scan, assessment, test) |
| Comments | Additional context, status updates, justifications |

#### 6.1.3 POA&M Remediation Timelines

| Severity | Maximum Remediation Timeline | Escalation if Overdue |
|---|---|---|
| **Critical** | 15 calendar days | CISO + AO notification immediately |
| **High** | 30 calendar days | ISSO + CISO notification at day 25 |
| **Moderate** | 90 calendar days | ISSO notification at day 75 |
| **Low** | 180 calendar days | Reviewed at next quarterly assessment |

#### 6.1.4 Risk Acceptance

If a POA&M item cannot be remediated within the defined timeline, a formal risk acceptance request must be submitted to the Authorizing Official including:

- Justification for why remediation is not feasible
- Compensating controls in place
- Residual risk assessment
- Planned review date

Risk acceptances are reviewed quarterly and documented in the POA&M.

### 6.2 POA&M Monitoring

- The Compliance Module tracks all POA&M items with automated status updates
- Weekly automated notifications are sent to responsible parties for open items
- Monthly POA&M review meetings are held with the ISSO and Compliance Officer
- Overdue items trigger escalation per the timelines above
- POA&M metrics (total open, overdue, average age, closure rate) are included in the monthly ConMon report

---

## 7. Risk Assessment Updates

### 7.1 Ongoing Risk Assessment

The Risk Quantification Module maintains a continuously updated risk register based on:

- Vulnerability scan results (new vulnerabilities increase risk scores)
- Threat intelligence (emerging threats targeting the technology stack)
- UEBA anomalies (increased insider threat risk)
- Configuration drift (non-compliant configurations increase risk)
- Incident data (post-incident risk re-evaluation)

### 7.2 Quarterly Risk Review

Each quarter, the ISSO and security team conduct a formal risk review:

1. **Review risk register** for accuracy and completeness
2. **Re-evaluate risk scores** based on current threat landscape
3. **Assess compensating controls** for accepted risks
4. **Update risk treatment plans** as needed
5. **Brief the Authorizing Official** on material risk changes

### 7.3 Event-Driven Risk Assessment

A risk assessment update is triggered by:

- Significant security incident
- New critical or high vulnerability in a core component
- Major system architecture change
- New threat intelligence indicating targeted risk
- Change in operational environment or mission
- Regulatory or compliance requirement change

### 7.4 Risk Communication

Risk assessment results are communicated through:

| Audience | Content | Frequency |
|---|---|---|
| **Authorizing Official** | Risk executive summary, material changes, risk acceptance requests | Quarterly + event-driven |
| **CISO** | Full risk register, trending, recommendations | Monthly |
| **Security Team** | Detailed risk data, vulnerability priorities | Weekly |
| **Development Team** | Vulnerability-specific risk context for prioritization | Per vulnerability |

---

## 8. Roles and Responsibilities

| Role | ConMon Responsibilities |
|---|---|
| **ISSO** | ConMon plan ownership, monthly reporting to AO, POA&M oversight, compliance verification, annual assessment coordination |
| **Compliance Officer** | Report generation, evidence collection, control assessment scheduling, SSP maintenance |
| **SOC Manager** | SIEM operations oversight, alert quality management, detection rule governance |
| **SOC Analysts (Tier 1)** | Alert triage, initial investigation, escalation |
| **Senior Analysts (Tier 2)** | Deep investigation, threat hunting, UEBA review, vulnerability analysis |
| **Security Engineering** | Detection rule development, vulnerability remediation, pen testing |
| **DevOps/SRE** | Infrastructure monitoring, patch management, configuration remediation |
| **Risk Manager** | Risk register maintenance, risk scoring, AO risk briefings |
| **3PAO** | Annual independent assessment, penetration testing |
| **Authorizing Official** | Risk acceptance decisions, authorization continuity |

---

## 9. Compliance Mapping

This Continuous Monitoring Plan satisfies the following FedRAMP Moderate controls:

| Control | Title | How This Plan Addresses It |
|---|---|---|
| CA-2 | Control Assessments | Section 4 defines assessment frequency and methodology |
| CA-5 | Plan of Action and Milestones | Section 6 defines full POA&M lifecycle management |
| CA-7 | Continuous Monitoring | This document establishes the continuous monitoring program |
| PM-6 | Measures of Performance | Section 2.3 defines security KPIs and targets |
| PM-14 | Testing, Training, and Monitoring | Sections 3-4 define monitoring tools and assessment schedules |
| RA-3 | Risk Assessment | Section 7 defines ongoing and periodic risk assessment |
| RA-5 | Vulnerability Monitoring and Scanning | Section 3.3 defines comprehensive vulnerability scanning |
| SI-2 | Flaw Remediation | Section 6.1.3 defines remediation timelines by severity |
| SI-4 | System Monitoring | Section 3 defines automated monitoring tools and capabilities |
| SI-5 | Security Alerts and Advisories | Section 3.5 includes threat intelligence and advisory monitoring |
