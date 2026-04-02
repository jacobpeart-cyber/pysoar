# Incident Response Plan — PySOAR

**Document Version:** 1.0
**Effective Date:** 2026-03-30
**Review Cycle:** Annual (next review: 2027-03-30)
**Classification:** For Official Use Only (FOUO)
**Owner:** Director of Security Operations

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Authority and References](#2-authority-and-references)
3. [Incident Response Organization](#3-incident-response-organization)
4. [Incident Categories and Severity Levels](#4-incident-categories-and-severity-levels)
5. [Phase 1 — Preparation](#5-phase-1--preparation)
6. [Phase 2 — Detection and Identification](#6-phase-2--detection-and-identification)
7. [Phase 3 — Analysis](#7-phase-3--analysis)
8. [Phase 4 — Containment](#8-phase-4--containment)
9. [Phase 5 — Eradication and Recovery](#9-phase-5--eradication-and-recovery)
10. [Phase 6 — Post-Incident Activity](#10-phase-6--post-incident-activity)
11. [Communication Procedures](#11-communication-procedures)
12. [Testing and Training](#12-testing-and-training)
13. [Plan Maintenance](#13-plan-maintenance)
14. [Appendices](#14-appendices)

---

## 1. Purpose and Scope

### 1.1 Purpose

This Incident Response Plan (IRP) establishes the framework, procedures, and responsibilities for detecting, analyzing, containing, eradicating, and recovering from security incidents affecting the PySOAR platform and its hosted data. The plan ensures compliance with FedRAMP incident response requirements, NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide), and US-CERT reporting obligations.

### 1.2 Scope

This plan applies to all security incidents affecting:

- The PySOAR production environment (AWS GovCloud infrastructure)
- All data processed, stored, or transmitted by PySOAR (security events, audit logs, threat intelligence, incident records, vulnerability data, user credentials)
- All personnel with access to PySOAR systems (employees, contractors, third-party service providers)
- All interconnected systems and data feeds

### 1.3 Objectives

- Detect security incidents as rapidly as possible through automated and manual means
- Minimize the impact and scope of incidents through timely containment
- Preserve evidence for forensic investigation and potential legal proceedings
- Restore normal operations within defined recovery time objectives
- Satisfy federal incident reporting requirements (US-CERT, FedRAMP PMO)
- Improve defensive posture through lessons learned

---

## 2. Authority and References

| Reference | Description |
|---|---|
| NIST SP 800-61 Rev 2 | Computer Security Incident Handling Guide |
| NIST SP 800-53 Rev 5, IR Family | Incident Response controls |
| FedRAMP Incident Communications Procedures | FedRAMP PMO reporting requirements |
| US-CERT Federal Incident Notification Guidelines | Mandatory reporting timelines |
| CISA Binding Operational Directive 22-01 | Known Exploited Vulnerabilities |
| OMB M-20-04 | Fiscal Year 2019-2020 Guidance on Federal Information Security and Privacy Management Requirements |

---

## 3. Incident Response Organization

### 3.1 Roles and Responsibilities

| Role | Personnel | Responsibilities |
|---|---|---|
| **Incident Response Manager (IRM)** | Director of Security Operations | Overall IR authority, escalation decisions, external communications |
| **Incident Commander (IC)** | Senior Security Analyst (rotating) | Tactical incident coordination, status tracking, team assignment |
| **Tier 1 Analysts** | SOC Analysts | Alert triage, initial classification, documented escalation |
| **Tier 2 Analysts** | Senior Security Analysts | Deep investigation, threat hunting, containment execution |
| **DFIR Specialists** | Forensics Team | Evidence collection, forensic analysis, timeline reconstruction |
| **Threat Intelligence Analyst** | Intel Team | Indicator enrichment, attribution research, threat context |
| **System Administrators** | DevOps/SRE Team | System isolation, patching, recovery actions |
| **ISSO** | Information System Security Officer | Compliance oversight, reporting to authorizing official |
| **Legal Counsel** | General Counsel | Legal review, breach notification, law enforcement coordination |
| **Communications Lead** | VP of Communications | Customer notification, public communications |
| **Executive Sponsor** | CISO / CIO | Executive authority, resource allocation, AO notification |

### 3.2 Contact Information

The IR team contact roster (names, phone numbers, secure email, Signal handles) is maintained separately in a restricted-access document and distributed to all IR team members. The roster is updated within 24 hours of any personnel change.

### 3.3 Escalation Path

```
Tier 1 Analyst → Tier 2 Analyst → Incident Commander → IR Manager → CISO → CIO / AO
```

Critical and High severity incidents are immediately escalated to the Incident Commander. Incidents involving data breach or suspected APT activity are immediately escalated to the IR Manager.

---

## 4. Incident Categories and Severity Levels

### 4.1 Incident Categories

| Category | Code | Description | Examples |
|---|---|---|---|
| **Unauthorized Access** | CAT-1 | Unauthorized logical access to systems or data | Credential compromise, privilege escalation, unauthorized API access |
| **Denial of Service** | CAT-2 | Disruption of system availability | DDoS, resource exhaustion, application-layer DoS |
| **Malicious Code** | CAT-3 | Introduction of malware or malicious software | Ransomware, trojan, cryptominer, webshell |
| **Improper Usage** | CAT-4 | Violation of acceptable use policies | Insider misuse, policy violation, unauthorized configuration change |
| **Reconnaissance** | CAT-5 | Scanning, probing, or social engineering attempts | Port scanning, vulnerability scanning, phishing attempts |
| **Data Breach** | CAT-6 | Confirmed or suspected unauthorized data exfiltration | Data theft, accidental exposure, insider exfiltration |
| **Supply Chain Compromise** | CAT-7 | Compromise via third-party component or vendor | Dependency poisoning, compromised vendor integration |

### 4.2 Severity Levels

| Severity | Level | Impact Criteria | Initial Response Time | Reporting Deadline |
|---|---|---|---|---|
| **Critical (SEV-1)** | Emergency | Active data breach, APT intrusion, ransomware, multi-system compromise | 15 minutes | US-CERT: 1 hour; FedRAMP PMO: 1 hour |
| **High (SEV-2)** | Urgent | Confirmed unauthorized access, active exploitation, single-system compromise | 30 minutes | US-CERT: 1 hour; FedRAMP PMO: same day |
| **Medium (SEV-3)** | Priority | Successful reconnaissance, policy violation, suspicious activity confirmed | 4 hours | As applicable per investigation findings |
| **Low (SEV-4)** | Standard | Failed attack attempts, anomalous but benign activity, minor policy deviation | 24 hours | Logged internally, no external reporting |

---

## 5. Phase 1 — Preparation

### 5.1 Detection Infrastructure

PySOAR employs layered detection capabilities:

- **SIEM Module:** Over 500 correlation rules covering MITRE ATT&CK techniques, real-time log ingestion from all system components, custom Sigma-compatible detection rules.
- **UEBA Module:** Machine-learning behavioral baselines for all user and service accounts, anomaly scoring with automatic alert generation.
- **Threat Intelligence Module:** Automated IOC matching against all log sources, TAXII/STIX feed ingestion, dark web monitoring for credential exposure.
- **Agentic SOC:** AI-assisted alert triage that pre-analyzes alerts, enriches indicators, and provides analyst recommendations.
- **Network Monitoring:** VPC Flow Logs analysis, DNS query monitoring, AWS GuardDuty integration.
- **Endpoint Detection:** Container runtime monitoring, file integrity monitoring, process execution logging.

### 5.2 Playbooks and Runbooks

Pre-built incident response playbooks are maintained in the Playbook Builder Module for each incident category:

- PB-001: Compromised Credentials Response
- PB-002: Malware/Ransomware Response
- PB-003: Data Breach Response
- PB-004: DDoS Mitigation
- PB-005: Insider Threat Response
- PB-006: Phishing Response
- PB-007: Supply Chain Compromise Response
- PB-008: Unauthorized Configuration Change
- PB-009: Cryptomining Detection and Response
- PB-010: API Abuse Response

Each playbook includes automated actions (containment, evidence collection) and manual decision points requiring analyst approval.

### 5.3 Tools and Resources

| Tool | Purpose |
|---|---|
| PySOAR Case Management | Incident tracking, evidence attachment, timeline |
| PySOAR SIEM | Log analysis, correlation, alerting |
| PySOAR War Room | Real-time collaboration during incidents |
| PySOAR DFIR Module | Forensic evidence collection, chain of custody |
| AWS CloudTrail | API activity logging |
| AWS GuardDuty | Threat detection |
| Volatility / memory forensics | Memory analysis for compromised containers |

### 5.4 Evidence Preservation

Evidence handling procedures:

1. All evidence is collected using the DFIR Module with automatic chain-of-custody documentation
2. Evidence items receive SHA-256 hash values at time of collection
3. Evidence is stored in a write-once S3 bucket with versioning, Object Lock, and access logging
4. Access to evidence requires Tier 2 Analyst or above authorization
5. Evidence retention: minimum 3 years or as required by legal hold

---

## 6. Phase 2 — Detection and Identification

### 6.1 Detection Sources

| Source | Module | Alert Volume (typical) |
|---|---|---|
| SIEM Correlation Rules | SIEM Module | 200-500 alerts/day |
| UEBA Anomaly Detection | UEBA Module | 20-50 anomalies/day |
| Threat Intel IOC Matches | Threat Intel Module | 50-100 matches/day |
| Agentic SOC Auto-Triage | Agentic Module | Processes all alerts; escalates 5-15/day |
| User Reports | Ticketing Integration | 1-5 reports/day |
| External Notifications | US-CERT, vendors, 3PAO | As received |

### 6.2 Initial Triage Process

1. **Automated Triage (Agentic SOC):** All alerts are initially processed by the Agentic SOC, which performs indicator enrichment, historical correlation, and false-positive scoring. Alerts scoring above the confidence threshold are escalated to Tier 1.

2. **Tier 1 Triage (15-minute SLA):** Analysts review escalated alerts, validate the alert is a true positive, determine the incident category (Section 4.1), assign initial severity (Section 4.2), and create a case in the Case Management system.

3. **Incident Declaration:** If the event is confirmed as a security incident, the Tier 1 analyst formally declares an incident, assigns a unique incident ID (INC-YYYY-NNNN), and escalates per the severity escalation path.

### 6.3 Initial Documentation

Upon incident declaration, the following is documented in the case record:

- Incident ID and timestamp of detection
- Detection source and triggering alert(s)
- Affected systems and data types
- Initial severity and category
- Initial scope assessment
- Assigned responder(s)

---

## 7. Phase 3 — Analysis

### 7.1 Investigation Procedures

Tier 2 analysts and DFIR specialists conduct the investigation using the following techniques:

**Threat Hunting:**
- Hypothesis-driven hunts based on observed indicators using the Threat Hunting Module
- MITRE ATT&CK-mapped technique searches across all log sources
- Historical indicator searches (retroactive IOC matching)

**UEBA Correlation:**
- Review behavioral anomaly timeline for affected user/entity accounts
- Peer-group deviation analysis
- Risk score trending to identify gradual compromise patterns

**Agentic SOC Assistance:**
- AI-generated investigation summaries with recommended next steps
- Automated indicator enrichment (VirusTotal, AbuseIPDB, Shodan, internal threat intel)
- Related alert clustering to identify multi-stage attacks

**Forensic Analysis:**
- Container image forensics (comparing running image against known-good baseline)
- Database query log analysis for data exfiltration indicators
- Network flow analysis (VPC Flow Logs, DNS queries)
- Memory analysis for in-memory malware (if applicable)

### 7.2 Scope Determination

The analysis phase determines:

- Full list of affected systems, accounts, and data
- Attack timeline (initial access, lateral movement, actions on objectives)
- Root cause and attack vector
- Threat actor attribution (if possible) using Threat Intelligence Module
- Data impact assessment (what data was accessed, modified, or exfiltrated)

### 7.3 Severity Re-assessment

After analysis, the incident severity is re-assessed based on confirmed impact. Escalation or de-escalation is documented in the case record with justification.

---

## 8. Phase 4 — Containment

### 8.1 Containment Strategy

Containment actions are executed based on the incident category and severity. The goal is to limit the blast radius while preserving evidence.

### 8.2 Short-Term Containment (Immediate)

| Action | Trigger | Execution |
|---|---|---|
| **Account Disable/Lockout** | Compromised credentials confirmed | Automated via Remediation Playbook (< 1 min) |
| **API Key Revocation** | Compromised API key detected | Automated via Remediation Playbook (< 1 min) |
| **Network Isolation** | Active lateral movement | Security Group update via playbook (< 5 min) |
| **WAF Rule Deployment** | Active exploitation of web vulnerability | WAF rule push via playbook (< 5 min) |
| **Container Quarantine** | Malware/webshell detected in container | Container isolation + snapshot for forensics (< 10 min) |
| **IP Block** | Active attack from known IP | WAF/SG/NACL update via playbook (< 5 min) |
| **Session Termination** | Unauthorized active session | Force session invalidation (< 1 min) |

### 8.3 Long-Term Containment

- Deploy patched/hardened container images to replace compromised instances
- Implement additional monitoring rules for attacker TTPs
- Rotate all potentially compromised credentials
- Enable enhanced logging on affected systems
- Implement temporary compensating controls as needed

### 8.4 Automated Response Playbooks

The Remediation Module provides automated containment actions with approval gates:

- **Fully Automated (no approval required):** Brute-force IP blocking, known-malicious IOC blocking, session termination for locked accounts
- **Semi-Automated (analyst approval):** Account disabling, network isolation, WAF rule deployment
- **Manual (IC approval required):** System shutdown, data preservation hold, service degradation

---

## 9. Phase 5 — Eradication and Recovery

### 9.1 Eradication

Eradication activities ensure the threat is completely removed:

1. **Root Cause Elimination:** Address the vulnerability or misconfiguration that enabled the incident
2. **Malware Removal:** Destroy compromised containers and redeploy from verified-clean images
3. **Credential Reset:** Rotate all credentials associated with compromised accounts, services, and systems
4. **Persistence Removal:** Verify no backdoors, unauthorized accounts, or scheduled tasks remain
5. **IOC Sweep:** Scan all systems for residual indicators of compromise

### 9.2 Recovery

Recovery procedures follow this sequence:

1. **Restore from Verified Backups:** Restore affected data from backups verified to pre-date the compromise (Backup Module)
2. **System Validation:** Validate all system components against known-good baselines (STIG Module)
3. **Security Verification:** Run full security scan, verify detection rules, confirm logging is operational
4. **Controlled Return to Service:** Bring systems back online in a controlled manner with enhanced monitoring
5. **Monitoring Period:** Maintain elevated monitoring for 30 days post-recovery

### 9.3 Recovery Verification Checklist

- [ ] All compromised systems rebuilt from clean images
- [ ] All compromised credentials rotated
- [ ] Backup integrity verified
- [ ] Data integrity validated
- [ ] STIG compliance scan passed
- [ ] Vulnerability scan clean
- [ ] Detection rules updated for incident TTPs
- [ ] Enhanced monitoring active
- [ ] Authorizing official informed of recovery status

---

## 10. Phase 6 — Post-Incident Activity

### 10.1 DFIR Report

The DFIR Module generates a comprehensive forensic report including:

- Executive summary
- Detailed incident timeline (from initial access to containment)
- Attack vector and root cause analysis
- IOCs extracted (IP addresses, domains, file hashes, YARA rules)
- MITRE ATT&CK mapping of adversary techniques
- Evidence inventory with chain-of-custody records
- Impact assessment (data, systems, operations)

### 10.2 Lessons Learned (War Room Debrief)

A post-incident review is conducted within 5 business days of incident closure using the War Room collaboration feature:

**Participants:** All incident responders, system administrators, management

**Agenda:**
1. Incident recap and timeline review
2. What worked well in the response
3. What could be improved
4. Detection gaps identified
5. New detection rules / playbook updates needed
6. Training needs identified
7. Policy or architecture changes recommended

### 10.3 Corrective Actions

All corrective actions from the lessons-learned review are:

- Documented as POA&M items in the Compliance Module
- Assigned owners and due dates
- Tracked to completion
- Verified by the ISSO

### 10.4 Metrics

Post-incident metrics tracked:

| Metric | Target |
|---|---|
| Mean Time to Detect (MTTD) | < 15 minutes for SEV-1/2 |
| Mean Time to Contain (MTTC) | < 1 hour for SEV-1, < 4 hours for SEV-2 |
| Mean Time to Recover (MTTR) | < 4 hours for SEV-1, < 24 hours for SEV-2 |
| Evidence collection completeness | 100% of identified artifacts |
| Reporting compliance | 100% of required notifications within deadline |

---

## 11. Communication Procedures

### 11.1 Internal Communications

| Severity | Notification Audience | Method | Timeline |
|---|---|---|---|
| SEV-1 (Critical) | CISO, CIO, Legal, AO, full IR team | Phone + Secure Messaging + War Room | Immediate |
| SEV-2 (High) | CISO, IR Manager, IC, affected team leads | Secure Messaging + War Room | Within 30 minutes |
| SEV-3 (Medium) | IR Manager, IC, assigned analysts | Case Management + Secure Messaging | Within 4 hours |
| SEV-4 (Low) | IC, assigned analysts | Case Management | Within 24 hours |

### 11.2 External Communications

| Recipient | Trigger | Timeline | Method | Content |
|---|---|---|---|---|
| **US-CERT** | All confirmed SEV-1 and SEV-2 incidents | Within 1 hour of determination | US-CERT portal / email | Category, impact, affected systems, IOCs |
| **FedRAMP PMO** | All incidents affecting FedRAMP-authorized system | Within 1 hour of determination (SEV-1/2) | FedRAMP PMO notification | Incident summary, customer impact, remediation status |
| **Authorizing Official** | All confirmed incidents | Same business day | Email + phone for SEV-1/2 | Impact assessment, containment status, recovery ETA |
| **Affected Customers** | Data breach or service impact | As determined by Legal/Comms | Secure email / portal notification | Nature of incident, data impacted, remediation steps |
| **Law Enforcement** | Criminal activity, national security threat | As directed by Legal Counsel | Through Legal Counsel | As appropriate |

### 11.3 Communication Templates

Pre-drafted communication templates are maintained in the Playbook Builder Module:

- TMPL-001: US-CERT Initial Notification
- TMPL-002: FedRAMP PMO Notification
- TMPL-003: Authorizing Official Briefing
- TMPL-004: Customer Breach Notification
- TMPL-005: Internal All-Hands Update
- TMPL-006: Public Statement (if required)

All external communications must be reviewed by Legal Counsel before transmission.

---

## 12. Testing and Training

### 12.1 Testing Schedule

| Exercise Type | Frequency | Participants | Module |
|---|---|---|---|
| **Tabletop Exercise** | Quarterly | Full IR team + management | Simulation Module |
| **Functional Exercise** | Semi-annually | IR team, DevOps, selected management | Simulation Module |
| **Full-Scale Exercise** | Annually | All IR personnel, external partners | Simulation Module |
| **Playbook Validation** | After each real incident + quarterly | Tier 1/2 analysts | Playbook Builder |
| **Communication Drill** | Semi-annually | IR Manager, Comms, Legal | Simulation Module |
| **Purple Team Exercise** | Annually | Red team + Blue team + IR | Simulation Module |

### 12.2 Training Requirements

| Role | Training Requirements | Frequency |
|---|---|---|
| All IR Personnel | NIST 800-61 incident handling, PySOAR platform training | Annual |
| Tier 1 Analysts | Alert triage, initial response, evidence preservation | Annual + when onboarded |
| Tier 2 Analysts | Advanced investigation, threat hunting, containment procedures | Annual |
| DFIR Specialists | Forensic analysis, evidence handling, legal requirements | Annual + specialty certifications |
| IR Manager | Incident command, crisis communication, FedRAMP reporting | Annual |
| Executives | Security awareness, executive decision-making during incidents | Annual |

### 12.3 Exercise Documentation

All exercises are documented with:

- Exercise plan and objectives
- Scenario description and injects
- Participant attendance
- Observations and findings
- After-action report with improvement recommendations
- Corrective action tracking (POA&M items)

Exercise records are stored in the Audit Evidence Module and retained for a minimum of 3 years.

---

## 13. Plan Maintenance

This Incident Response Plan is:

- **Reviewed** annually by the IR Manager and ISSO
- **Updated** within 30 days of significant system changes, organizational changes, or lessons learned from incidents and exercises
- **Tested** through the exercise program described in Section 12
- **Distributed** to all IR team members within 5 business days of any update
- **Approved** by the CISO and Authorizing Official

Version history is maintained in the Compliance Module with full change tracking.

---

## 14. Appendices

### Appendix A: Incident Severity Decision Tree

```
Is there confirmed data exfiltration or active APT?
  YES → SEV-1 (Critical)
  NO  → Is there confirmed unauthorized access or active exploitation?
         YES → SEV-2 (High)
         NO  → Is there confirmed suspicious activity or policy violation?
                YES → SEV-3 (Medium)
                NO  → SEV-4 (Low)
```

### Appendix B: Evidence Collection Checklist

- [ ] System logs (application, authentication, audit)
- [ ] Network logs (VPC Flow Logs, DNS queries, proxy logs)
- [ ] CloudTrail API activity logs
- [ ] Container images (running and baseline for comparison)
- [ ] Database query logs
- [ ] Memory snapshots (if applicable)
- [ ] Configuration snapshots (pre/post incident)
- [ ] User session data
- [ ] Screenshots of attacker activity
- [ ] Threat intelligence enrichment results

### Appendix C: Federal Reporting Requirements Summary

| Requirement | Timeline | Contact |
|---|---|---|
| US-CERT notification (CAT 1-3) | 1 hour | soc@us-cert.gov / US-CERT portal |
| FedRAMP PMO notification | 1 hour for SEV-1/2 | info@fedramp.gov |
| Authorizing Official notification | Same business day | Per agency POC roster |
| Privacy breach (PII involved) | 72 hours | Per applicable breach notification law |
| Annual incident summary | Within 30 days of fiscal year end | FedRAMP PMO |
