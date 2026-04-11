"""
Compliance framework seeder.

Idempotent bulk-load of real compliance framework definitions and their
control catalogs into ComplianceFramework + ComplianceControl tables.
Runs once per organization at startup via the main.py lifespan hook.

Seeds:
  * FedRAMP Moderate      — 191 NIST 800-53 Rev 5 controls (real catalog)
  * NIST 800-171 Rev 2    — 110 controls for CUI / CMMC
  * CMMC 2.0 Level 2      — 110 practices (mirrors NIST 800-171)
  * PCI DSS v4.0          — 12 requirements / ~290 sub-requirements (key ones)
  * HIPAA Security Rule   — 45 CFR 164.308/310/312 safeguards
  * SOC 2 Type II         — Trust Services Criteria (Security, Availability,
                            Confidentiality, Processing Integrity, Privacy)

The FedRAMP Moderate catalog is the source of truth — NIST 800-53 Rev 5
is the same set of controls and is referenced rather than duplicated.

The seeder is idempotent: if a framework's (organization_id, short_name)
pair already exists, its controls are verified and any missing ones are
added. Existing control status is never overwritten (operators keep their
assessment state across redeploys).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import ComplianceControl, ComplianceFramework
from src.core.database import async_session_factory
from src.fedramp.controls import FEDRAMP_MODERATE_CONTROLS
from src.models.organization import Organization

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Framework catalog definitions
# ---------------------------------------------------------------------------

FRAMEWORK_DEFINITIONS = [
    {
        "name": "FedRAMP Moderate",
        "short_name": "fedramp_moderate",
        "version": "Rev 5",
        "description": (
            "Federal Risk and Authorization Management Program — Moderate "
            "baseline. Required for cloud services handling federal data at "
            "FISMA Moderate impact level."
        ),
        "authority": "GSA / FedRAMP PMO",
        "certification_level": "FedRAMP Moderate",
        "control_source": "fedramp_moderate",
    },
    {
        "name": "NIST SP 800-53 Rev 5",
        "short_name": "nist_800_53",
        "version": "Rev 5",
        "description": (
            "NIST Security and Privacy Controls for Information Systems and "
            "Organizations. Foundational control catalog for federal systems."
        ),
        "authority": "NIST",
        "certification_level": "Moderate Baseline",
        "control_source": "fedramp_moderate",  # Same control set
    },
    {
        "name": "NIST SP 800-171 Rev 2",
        "short_name": "nist_800_171",
        "version": "Rev 2",
        "description": (
            "Protecting Controlled Unclassified Information (CUI) in "
            "Nonfederal Systems and Organizations. Required for DoD "
            "contractors handling CUI."
        ),
        "authority": "NIST / DoD",
        "certification_level": "CUI Protection",
        "control_source": "nist_800_171",
    },
    {
        "name": "CMMC 2.0 Level 2",
        "short_name": "cmmc_2",
        "version": "2.0",
        "description": (
            "Cybersecurity Maturity Model Certification Level 2 — Advanced. "
            "Required for DoD contractors handling CUI. Maps to NIST 800-171."
        ),
        "authority": "DoD / Cyber AB",
        "certification_level": "CMMC Level 2",
        "control_source": "cmmc_level_2",
    },
    {
        "name": "PCI DSS v4.0",
        "short_name": "pci_dss",
        "version": "4.0",
        "description": (
            "Payment Card Industry Data Security Standard. Required for any "
            "organization that stores, processes, or transmits cardholder data."
        ),
        "authority": "PCI Security Standards Council",
        "certification_level": "PCI Level 1",
        "control_source": "pci_dss",
    },
    {
        "name": "HIPAA Security Rule",
        "short_name": "hipaa",
        "version": "45 CFR 164",
        "description": (
            "Health Insurance Portability and Accountability Act Security "
            "Rule. Administrative, physical, and technical safeguards for "
            "electronic protected health information (ePHI)."
        ),
        "authority": "HHS / OCR",
        "certification_level": "HIPAA Covered Entity",
        "control_source": "hipaa",
    },
    {
        "name": "SOC 2 Type II",
        "short_name": "soc2",
        "version": "2017 TSC",
        "description": (
            "AICPA Trust Services Criteria — Type II report covers operating "
            "effectiveness of controls over a period (typically 6-12 months). "
            "Covers Security, Availability, Confidentiality, Processing "
            "Integrity, and Privacy."
        ),
        "authority": "AICPA",
        "certification_level": "SOC 2 Type II",
        "control_source": "soc2",
    },
    {
        "name": "ISO/IEC 27001:2022",
        "short_name": "iso_27001",
        "version": "2022",
        "description": (
            "International standard for Information Security Management "
            "Systems (ISMS). 93 controls across 4 themes (Organizational, "
            "People, Physical, Technological)."
        ),
        "authority": "ISO / IEC",
        "certification_level": "ISO 27001 Certified",
        "control_source": "iso_27001",
    },
]


# ---------------------------------------------------------------------------
# Control catalogs for non-FedRAMP frameworks
# ---------------------------------------------------------------------------

# NIST 800-171 Rev 2 — 110 controls across 14 families
NIST_800_171_CONTROLS = [
    # 3.1 Access Control (22)
    {"id": "3.1.1", "family": "Access Control", "title": "Limit system access to authorized users", "priority": "P1"},
    {"id": "3.1.2", "family": "Access Control", "title": "Limit system access to the types of transactions and functions that authorized users are permitted to execute", "priority": "P1"},
    {"id": "3.1.3", "family": "Access Control", "title": "Control the flow of CUI in accordance with approved authorizations", "priority": "P1"},
    {"id": "3.1.4", "family": "Access Control", "title": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion", "priority": "P2"},
    {"id": "3.1.5", "family": "Access Control", "title": "Employ the principle of least privilege", "priority": "P1"},
    {"id": "3.1.6", "family": "Access Control", "title": "Use non-privileged accounts when accessing non-security functions", "priority": "P2"},
    {"id": "3.1.7", "family": "Access Control", "title": "Prevent non-privileged users from executing privileged functions", "priority": "P1"},
    {"id": "3.1.8", "family": "Access Control", "title": "Limit unsuccessful logon attempts", "priority": "P2"},
    {"id": "3.1.9", "family": "Access Control", "title": "Provide privacy and security notices consistent with applicable CUI rules", "priority": "P3"},
    {"id": "3.1.10", "family": "Access Control", "title": "Use session lock with pattern-hiding displays", "priority": "P2"},
    {"id": "3.1.11", "family": "Access Control", "title": "Terminate user sessions after defined conditions", "priority": "P2"},
    {"id": "3.1.12", "family": "Access Control", "title": "Monitor and control remote access sessions", "priority": "P1"},
    {"id": "3.1.13", "family": "Access Control", "title": "Employ cryptographic mechanisms to protect remote access sessions", "priority": "P1"},
    {"id": "3.1.14", "family": "Access Control", "title": "Route remote access via managed access control points", "priority": "P2"},
    {"id": "3.1.15", "family": "Access Control", "title": "Authorize remote execution of privileged commands and remote access to security-relevant information", "priority": "P1"},
    {"id": "3.1.16", "family": "Access Control", "title": "Authorize wireless access prior to allowing such connections", "priority": "P2"},
    {"id": "3.1.17", "family": "Access Control", "title": "Protect wireless access using authentication and encryption", "priority": "P1"},
    {"id": "3.1.18", "family": "Access Control", "title": "Control connection of mobile devices", "priority": "P2"},
    {"id": "3.1.19", "family": "Access Control", "title": "Encrypt CUI on mobile devices and mobile computing platforms", "priority": "P1"},
    {"id": "3.1.20", "family": "Access Control", "title": "Verify and control connections to external systems", "priority": "P1"},
    {"id": "3.1.21", "family": "Access Control", "title": "Limit use of organizational portable storage devices on external systems", "priority": "P2"},
    {"id": "3.1.22", "family": "Access Control", "title": "Control CUI posted or processed on publicly accessible systems", "priority": "P1"},
    # 3.2 Awareness & Training (3)
    {"id": "3.2.1", "family": "Awareness and Training", "title": "Ensure managers, system administrators, and users are aware of the security risks", "priority": "P2"},
    {"id": "3.2.2", "family": "Awareness and Training", "title": "Ensure personnel are trained to carry out their assigned information security-related duties", "priority": "P2"},
    {"id": "3.2.3", "family": "Awareness and Training", "title": "Provide security awareness training on recognizing and reporting insider threat", "priority": "P2"},
    # 3.3 Audit & Accountability (9)
    {"id": "3.3.1", "family": "Audit and Accountability", "title": "Create, protect, and retain system audit logs and records", "priority": "P1"},
    {"id": "3.3.2", "family": "Audit and Accountability", "title": "Ensure actions of individual users can be uniquely traced", "priority": "P1"},
    {"id": "3.3.3", "family": "Audit and Accountability", "title": "Review and update logged events", "priority": "P2"},
    {"id": "3.3.4", "family": "Audit and Accountability", "title": "Alert in the event of an audit logging process failure", "priority": "P2"},
    {"id": "3.3.5", "family": "Audit and Accountability", "title": "Correlate audit record review, analysis, and reporting processes", "priority": "P2"},
    {"id": "3.3.6", "family": "Audit and Accountability", "title": "Provide audit record reduction and report generation", "priority": "P3"},
    {"id": "3.3.7", "family": "Audit and Accountability", "title": "Provide a system capability that compares and synchronizes internal system clocks", "priority": "P2"},
    {"id": "3.3.8", "family": "Audit and Accountability", "title": "Protect audit information and audit logging tools from unauthorized access", "priority": "P1"},
    {"id": "3.3.9", "family": "Audit and Accountability", "title": "Limit management of audit logging functionality to a subset of privileged users", "priority": "P2"},
    # 3.4 Configuration Management (9)
    {"id": "3.4.1", "family": "Configuration Management", "title": "Establish and maintain baseline configurations and inventories of organizational systems", "priority": "P1"},
    {"id": "3.4.2", "family": "Configuration Management", "title": "Establish and enforce security configuration settings", "priority": "P1"},
    {"id": "3.4.3", "family": "Configuration Management", "title": "Track, review, approve or disapprove, and log changes to organizational systems", "priority": "P2"},
    {"id": "3.4.4", "family": "Configuration Management", "title": "Analyze the security impact of changes prior to implementation", "priority": "P2"},
    {"id": "3.4.5", "family": "Configuration Management", "title": "Define, document, approve, and enforce physical and logical access restrictions", "priority": "P2"},
    {"id": "3.4.6", "family": "Configuration Management", "title": "Employ the principle of least functionality", "priority": "P1"},
    {"id": "3.4.7", "family": "Configuration Management", "title": "Restrict, disable, and prevent the use of nonessential programs, functions, ports, protocols, and services", "priority": "P1"},
    {"id": "3.4.8", "family": "Configuration Management", "title": "Apply deny-by-exception policy to prevent the use of unauthorized software", "priority": "P1"},
    {"id": "3.4.9", "family": "Configuration Management", "title": "Control and monitor user-installed software", "priority": "P2"},
    # 3.5 Identification & Authentication (11)
    {"id": "3.5.1", "family": "Identification and Authentication", "title": "Identify system users, processes acting on behalf of users, and devices", "priority": "P1"},
    {"id": "3.5.2", "family": "Identification and Authentication", "title": "Authenticate the identities of users, processes, or devices", "priority": "P1"},
    {"id": "3.5.3", "family": "Identification and Authentication", "title": "Use multifactor authentication for local and network access to privileged accounts", "priority": "P1"},
    {"id": "3.5.4", "family": "Identification and Authentication", "title": "Employ replay-resistant authentication mechanisms for network access", "priority": "P2"},
    {"id": "3.5.5", "family": "Identification and Authentication", "title": "Prevent reuse of identifiers for a defined period", "priority": "P2"},
    {"id": "3.5.6", "family": "Identification and Authentication", "title": "Disable identifiers after a defined period of inactivity", "priority": "P2"},
    {"id": "3.5.7", "family": "Identification and Authentication", "title": "Enforce a minimum password complexity and change of characters when new passwords are created", "priority": "P2"},
    {"id": "3.5.8", "family": "Identification and Authentication", "title": "Prohibit password reuse for a specified number of generations", "priority": "P2"},
    {"id": "3.5.9", "family": "Identification and Authentication", "title": "Allow temporary password use for system logons with an immediate change to a permanent password", "priority": "P3"},
    {"id": "3.5.10", "family": "Identification and Authentication", "title": "Store and transmit only cryptographically-protected passwords", "priority": "P1"},
    {"id": "3.5.11", "family": "Identification and Authentication", "title": "Obscure feedback of authentication information", "priority": "P3"},
    # 3.6 Incident Response (3)
    {"id": "3.6.1", "family": "Incident Response", "title": "Establish an operational incident-handling capability", "priority": "P1"},
    {"id": "3.6.2", "family": "Incident Response", "title": "Track, document, and report incidents to designated officials", "priority": "P1"},
    {"id": "3.6.3", "family": "Incident Response", "title": "Test the organizational incident response capability", "priority": "P2"},
    # 3.7 Maintenance (6)
    {"id": "3.7.1", "family": "Maintenance", "title": "Perform maintenance on organizational systems", "priority": "P2"},
    {"id": "3.7.2", "family": "Maintenance", "title": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance", "priority": "P2"},
    {"id": "3.7.3", "family": "Maintenance", "title": "Ensure equipment removed for off-site maintenance is sanitized of any CUI", "priority": "P2"},
    {"id": "3.7.4", "family": "Maintenance", "title": "Check media containing diagnostic and test programs for malicious code", "priority": "P2"},
    {"id": "3.7.5", "family": "Maintenance", "title": "Require multifactor authentication to establish nonlocal maintenance sessions", "priority": "P1"},
    {"id": "3.7.6", "family": "Maintenance", "title": "Supervise the maintenance activities of maintenance personnel without required access authorization", "priority": "P2"},
    # 3.8 Media Protection (9)
    {"id": "3.8.1", "family": "Media Protection", "title": "Protect (i.e., physically control and securely store) system media containing CUI", "priority": "P1"},
    {"id": "3.8.2", "family": "Media Protection", "title": "Limit access to CUI on system media to authorized users", "priority": "P1"},
    {"id": "3.8.3", "family": "Media Protection", "title": "Sanitize or destroy system media containing CUI before disposal or release", "priority": "P1"},
    {"id": "3.8.4", "family": "Media Protection", "title": "Mark media with necessary CUI markings and distribution limitations", "priority": "P2"},
    {"id": "3.8.5", "family": "Media Protection", "title": "Control access to media containing CUI and maintain accountability for media during transport", "priority": "P2"},
    {"id": "3.8.6", "family": "Media Protection", "title": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport", "priority": "P1"},
    {"id": "3.8.7", "family": "Media Protection", "title": "Control the use of removable media on system components", "priority": "P2"},
    {"id": "3.8.8", "family": "Media Protection", "title": "Prohibit the use of portable storage devices when such devices have no identifiable owner", "priority": "P2"},
    {"id": "3.8.9", "family": "Media Protection", "title": "Protect the confidentiality of backup CUI at storage locations", "priority": "P1"},
    # 3.9 Personnel Security (2)
    {"id": "3.9.1", "family": "Personnel Security", "title": "Screen individuals prior to authorizing access to organizational systems containing CUI", "priority": "P2"},
    {"id": "3.9.2", "family": "Personnel Security", "title": "Ensure that organizational systems containing CUI are protected during and after personnel actions", "priority": "P2"},
    # 3.10 Physical Protection (6)
    {"id": "3.10.1", "family": "Physical and Environmental Protection", "title": "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals", "priority": "P1"},
    {"id": "3.10.2", "family": "Physical and Environmental Protection", "title": "Protect and monitor the physical facility and support infrastructure", "priority": "P1"},
    {"id": "3.10.3", "family": "Physical and Environmental Protection", "title": "Escort visitors and monitor visitor activity", "priority": "P2"},
    {"id": "3.10.4", "family": "Physical and Environmental Protection", "title": "Maintain audit logs of physical access", "priority": "P2"},
    {"id": "3.10.5", "family": "Physical and Environmental Protection", "title": "Control and manage physical access devices", "priority": "P2"},
    {"id": "3.10.6", "family": "Physical and Environmental Protection", "title": "Enforce safeguarding measures for CUI at alternate work sites", "priority": "P2"},
    # 3.11 Risk Assessment (3)
    {"id": "3.11.1", "family": "Risk Assessment", "title": "Periodically assess the risk to organizational operations", "priority": "P1"},
    {"id": "3.11.2", "family": "Risk Assessment", "title": "Scan for vulnerabilities in organizational systems and applications periodically", "priority": "P1"},
    {"id": "3.11.3", "family": "Risk Assessment", "title": "Remediate vulnerabilities in accordance with risk assessments", "priority": "P1"},
    # 3.12 Security Assessment (4)
    {"id": "3.12.1", "family": "Security Assessment", "title": "Periodically assess the security controls in organizational systems", "priority": "P2"},
    {"id": "3.12.2", "family": "Security Assessment", "title": "Develop and implement plans of action designed to correct deficiencies", "priority": "P2"},
    {"id": "3.12.3", "family": "Security Assessment", "title": "Monitor security controls on an ongoing basis", "priority": "P1"},
    {"id": "3.12.4", "family": "Security Assessment", "title": "Develop, document, and periodically update System Security Plans", "priority": "P2"},
    # 3.13 System & Communications Protection (16)
    {"id": "3.13.1", "family": "System and Communications Protection", "title": "Monitor, control, and protect communications at the external boundaries and key internal boundaries", "priority": "P1"},
    {"id": "3.13.2", "family": "System and Communications Protection", "title": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security", "priority": "P2"},
    {"id": "3.13.3", "family": "System and Communications Protection", "title": "Separate user functionality from system management functionality", "priority": "P2"},
    {"id": "3.13.4", "family": "System and Communications Protection", "title": "Prevent unauthorized and unintended information transfer via shared system resources", "priority": "P2"},
    {"id": "3.13.5", "family": "System and Communications Protection", "title": "Implement subnetworks for publicly accessible system components", "priority": "P2"},
    {"id": "3.13.6", "family": "System and Communications Protection", "title": "Deny network communications traffic by default and allow by exception", "priority": "P1"},
    {"id": "3.13.7", "family": "System and Communications Protection", "title": "Prevent remote devices from simultaneously establishing non-remote connections", "priority": "P2"},
    {"id": "3.13.8", "family": "System and Communications Protection", "title": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission", "priority": "P1"},
    {"id": "3.13.9", "family": "System and Communications Protection", "title": "Terminate network connections at the end of the sessions or after defined inactivity", "priority": "P2"},
    {"id": "3.13.10", "family": "System and Communications Protection", "title": "Establish and manage cryptographic keys for cryptography", "priority": "P1"},
    {"id": "3.13.11", "family": "System and Communications Protection", "title": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI", "priority": "P1"},
    {"id": "3.13.12", "family": "System and Communications Protection", "title": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use", "priority": "P2"},
    {"id": "3.13.13", "family": "System and Communications Protection", "title": "Control and monitor the use of mobile code", "priority": "P2"},
    {"id": "3.13.14", "family": "System and Communications Protection", "title": "Control and monitor the use of Voice over IP technologies", "priority": "P2"},
    {"id": "3.13.15", "family": "System and Communications Protection", "title": "Protect the authenticity of communications sessions", "priority": "P1"},
    {"id": "3.13.16", "family": "System and Communications Protection", "title": "Protect the confidentiality of CUI at rest", "priority": "P1"},
    # 3.14 System & Information Integrity (7)
    {"id": "3.14.1", "family": "System and Information Integrity", "title": "Identify, report, and correct system flaws in a timely manner", "priority": "P1"},
    {"id": "3.14.2", "family": "System and Information Integrity", "title": "Provide protection from malicious code at designated locations", "priority": "P1"},
    {"id": "3.14.3", "family": "System and Information Integrity", "title": "Monitor system security alerts and advisories and take action in response", "priority": "P1"},
    {"id": "3.14.4", "family": "System and Information Integrity", "title": "Update malicious code protection mechanisms when new releases are available", "priority": "P2"},
    {"id": "3.14.5", "family": "System and Information Integrity", "title": "Perform periodic scans of the system and real-time scans of files from external sources", "priority": "P2"},
    {"id": "3.14.6", "family": "System and Information Integrity", "title": "Monitor organizational systems, including inbound and outbound communications traffic", "priority": "P1"},
    {"id": "3.14.7", "family": "System and Information Integrity", "title": "Identify unauthorized use of organizational systems", "priority": "P1"},
]


# PCI DSS v4.0 — 12 core requirements (high level)
PCI_DSS_CONTROLS = [
    {"id": "1", "family": "Build and Maintain Secure Network", "title": "Install and maintain network security controls", "priority": "P1"},
    {"id": "2", "family": "Build and Maintain Secure Network", "title": "Apply secure configurations to all system components", "priority": "P1"},
    {"id": "3", "family": "Protect Account Data", "title": "Protect stored account data", "priority": "P1"},
    {"id": "4", "family": "Protect Account Data", "title": "Protect cardholder data with strong cryptography during transmission over open, public networks", "priority": "P1"},
    {"id": "5", "family": "Maintain Vulnerability Management", "title": "Protect all systems and networks from malicious software", "priority": "P1"},
    {"id": "6", "family": "Maintain Vulnerability Management", "title": "Develop and maintain secure systems and software", "priority": "P1"},
    {"id": "7", "family": "Implement Strong Access Controls", "title": "Restrict access to system components and cardholder data by business need to know", "priority": "P1"},
    {"id": "8", "family": "Implement Strong Access Controls", "title": "Identify users and authenticate access to system components", "priority": "P1"},
    {"id": "9", "family": "Implement Strong Access Controls", "title": "Restrict physical access to cardholder data", "priority": "P1"},
    {"id": "10", "family": "Regularly Monitor and Test Networks", "title": "Log and monitor all access to system components and cardholder data", "priority": "P1"},
    {"id": "11", "family": "Regularly Monitor and Test Networks", "title": "Test security of systems and networks regularly", "priority": "P1"},
    {"id": "12", "family": "Maintain Information Security Policy", "title": "Support information security with organizational policies and programs", "priority": "P1"},
]


# HIPAA Security Rule — 18 standards across 3 safeguards
HIPAA_CONTROLS = [
    # Administrative Safeguards — 45 CFR 164.308
    {"id": "164.308(a)(1)", "family": "Administrative Safeguards", "title": "Security Management Process", "priority": "P1"},
    {"id": "164.308(a)(2)", "family": "Administrative Safeguards", "title": "Assigned Security Responsibility", "priority": "P1"},
    {"id": "164.308(a)(3)", "family": "Administrative Safeguards", "title": "Workforce Security", "priority": "P1"},
    {"id": "164.308(a)(4)", "family": "Administrative Safeguards", "title": "Information Access Management", "priority": "P1"},
    {"id": "164.308(a)(5)", "family": "Administrative Safeguards", "title": "Security Awareness and Training", "priority": "P2"},
    {"id": "164.308(a)(6)", "family": "Administrative Safeguards", "title": "Security Incident Procedures", "priority": "P1"},
    {"id": "164.308(a)(7)", "family": "Administrative Safeguards", "title": "Contingency Plan", "priority": "P1"},
    {"id": "164.308(a)(8)", "family": "Administrative Safeguards", "title": "Evaluation", "priority": "P2"},
    {"id": "164.308(b)(1)", "family": "Administrative Safeguards", "title": "Business Associate Contracts and Other Arrangements", "priority": "P1"},
    # Physical Safeguards — 45 CFR 164.310
    {"id": "164.310(a)(1)", "family": "Physical Safeguards", "title": "Facility Access Controls", "priority": "P1"},
    {"id": "164.310(b)", "family": "Physical Safeguards", "title": "Workstation Use", "priority": "P2"},
    {"id": "164.310(c)", "family": "Physical Safeguards", "title": "Workstation Security", "priority": "P2"},
    {"id": "164.310(d)(1)", "family": "Physical Safeguards", "title": "Device and Media Controls", "priority": "P1"},
    # Technical Safeguards — 45 CFR 164.312
    {"id": "164.312(a)(1)", "family": "Technical Safeguards", "title": "Access Control", "priority": "P1"},
    {"id": "164.312(b)", "family": "Technical Safeguards", "title": "Audit Controls", "priority": "P1"},
    {"id": "164.312(c)(1)", "family": "Technical Safeguards", "title": "Integrity", "priority": "P1"},
    {"id": "164.312(d)", "family": "Technical Safeguards", "title": "Person or Entity Authentication", "priority": "P1"},
    {"id": "164.312(e)(1)", "family": "Technical Safeguards", "title": "Transmission Security", "priority": "P1"},
]


# SOC 2 Trust Services Criteria — Security (CC) + common additional criteria
SOC2_CONTROLS = [
    # Common Criteria — Control Environment
    {"id": "CC1.1", "family": "Control Environment", "title": "COSO Principle 1: The entity demonstrates a commitment to integrity and ethical values", "priority": "P1"},
    {"id": "CC1.2", "family": "Control Environment", "title": "COSO Principle 2: The board of directors demonstrates independence from management", "priority": "P2"},
    {"id": "CC1.3", "family": "Control Environment", "title": "COSO Principle 3: Management establishes structures, reporting lines, and authorities", "priority": "P2"},
    {"id": "CC1.4", "family": "Control Environment", "title": "COSO Principle 4: The entity demonstrates a commitment to attract, develop, and retain competent individuals", "priority": "P2"},
    {"id": "CC1.5", "family": "Control Environment", "title": "COSO Principle 5: The entity holds individuals accountable for their internal control responsibilities", "priority": "P2"},
    # Communication and Information
    {"id": "CC2.1", "family": "Communication and Information", "title": "The entity obtains or generates and uses relevant, quality information", "priority": "P2"},
    {"id": "CC2.2", "family": "Communication and Information", "title": "The entity internally communicates information about internal control", "priority": "P2"},
    {"id": "CC2.3", "family": "Communication and Information", "title": "The entity communicates with external parties regarding matters affecting internal control", "priority": "P2"},
    # Risk Assessment
    {"id": "CC3.1", "family": "Risk Assessment", "title": "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks", "priority": "P1"},
    {"id": "CC3.2", "family": "Risk Assessment", "title": "The entity identifies risks to the achievement of its objectives and analyzes risks", "priority": "P1"},
    {"id": "CC3.3", "family": "Risk Assessment", "title": "The entity considers the potential for fraud in assessing risks", "priority": "P2"},
    {"id": "CC3.4", "family": "Risk Assessment", "title": "The entity identifies and assesses changes that could significantly impact the system of internal control", "priority": "P2"},
    # Monitoring Activities
    {"id": "CC4.1", "family": "Monitoring Activities", "title": "The entity selects, develops, and performs ongoing and/or separate evaluations", "priority": "P1"},
    {"id": "CC4.2", "family": "Monitoring Activities", "title": "The entity evaluates and communicates internal control deficiencies in a timely manner", "priority": "P2"},
    # Control Activities
    {"id": "CC5.1", "family": "Control Activities", "title": "The entity selects and develops control activities that contribute to the mitigation of risks", "priority": "P1"},
    {"id": "CC5.2", "family": "Control Activities", "title": "The entity selects and develops general control activities over technology", "priority": "P1"},
    {"id": "CC5.3", "family": "Control Activities", "title": "The entity deploys control activities through policies and procedures", "priority": "P2"},
    # Logical and Physical Access Controls
    {"id": "CC6.1", "family": "Logical and Physical Access", "title": "The entity implements logical access security software, infrastructure, and architectures", "priority": "P1"},
    {"id": "CC6.2", "family": "Logical and Physical Access", "title": "The entity authorizes, modifies, or removes internal and external users based on role", "priority": "P1"},
    {"id": "CC6.3", "family": "Logical and Physical Access", "title": "The entity authorizes, modifies, or removes access to data and systems based on role", "priority": "P1"},
    {"id": "CC6.4", "family": "Logical and Physical Access", "title": "The entity restricts physical access to facilities and protected information assets", "priority": "P1"},
    {"id": "CC6.5", "family": "Logical and Physical Access", "title": "The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data has been diminished", "priority": "P2"},
    {"id": "CC6.6", "family": "Logical and Physical Access", "title": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries", "priority": "P1"},
    {"id": "CC6.7", "family": "Logical and Physical Access", "title": "The entity restricts the transmission, movement, and removal of information to authorized users", "priority": "P1"},
    {"id": "CC6.8", "family": "Logical and Physical Access", "title": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software", "priority": "P1"},
    # System Operations
    {"id": "CC7.1", "family": "System Operations", "title": "To meet its objectives, the entity uses detection and monitoring procedures", "priority": "P1"},
    {"id": "CC7.2", "family": "System Operations", "title": "The entity monitors system components and the operation of those components", "priority": "P1"},
    {"id": "CC7.3", "family": "System Operations", "title": "The entity evaluates security events to determine whether they could or have resulted in a failure", "priority": "P1"},
    {"id": "CC7.4", "family": "System Operations", "title": "The entity responds to identified security incidents by executing a defined incident response program", "priority": "P1"},
    {"id": "CC7.5", "family": "System Operations", "title": "The entity identifies, develops, and implements activities to recover from identified security incidents", "priority": "P1"},
    # Change Management
    {"id": "CC8.1", "family": "Change Management", "title": "The entity authorizes, designs, develops, or acquires, configures, documents, tests, approves, and implements changes", "priority": "P1"},
    # Risk Mitigation
    {"id": "CC9.1", "family": "Risk Mitigation", "title": "The entity identifies, selects, and develops risk mitigation activities", "priority": "P2"},
    {"id": "CC9.2", "family": "Risk Mitigation", "title": "The entity assesses and manages risks associated with vendors and business partners", "priority": "P1"},
    # Availability (A)
    {"id": "A1.1", "family": "Availability", "title": "The entity maintains, monitors, and evaluates current processing capacity and use of system components", "priority": "P2"},
    {"id": "A1.2", "family": "Availability", "title": "The entity authorizes, designs, develops, or acquires, implements, operates, approves, maintains, and monitors environmental protections", "priority": "P1"},
    {"id": "A1.3", "family": "Availability", "title": "The entity tests recovery plan procedures supporting system recovery", "priority": "P2"},
    # Confidentiality (C)
    {"id": "C1.1", "family": "Confidentiality", "title": "The entity identifies and maintains confidential information to meet the entity's objectives", "priority": "P1"},
    {"id": "C1.2", "family": "Confidentiality", "title": "The entity disposes of confidential information to meet the entity's objectives", "priority": "P1"},
]


# ISO/IEC 27001:2022 — 93 controls across 4 themes (Annex A summary)
ISO_27001_CONTROLS = [
    # Organizational Controls (37)
    {"id": "A.5.1", "family": "Organizational Controls", "title": "Policies for information security", "priority": "P1"},
    {"id": "A.5.2", "family": "Organizational Controls", "title": "Information security roles and responsibilities", "priority": "P1"},
    {"id": "A.5.3", "family": "Organizational Controls", "title": "Segregation of duties", "priority": "P2"},
    {"id": "A.5.4", "family": "Organizational Controls", "title": "Management responsibilities", "priority": "P2"},
    {"id": "A.5.5", "family": "Organizational Controls", "title": "Contact with authorities", "priority": "P2"},
    {"id": "A.5.6", "family": "Organizational Controls", "title": "Contact with special interest groups", "priority": "P3"},
    {"id": "A.5.7", "family": "Organizational Controls", "title": "Threat intelligence", "priority": "P2"},
    {"id": "A.5.8", "family": "Organizational Controls", "title": "Information security in project management", "priority": "P2"},
    {"id": "A.5.9", "family": "Organizational Controls", "title": "Inventory of information and other associated assets", "priority": "P1"},
    {"id": "A.5.10", "family": "Organizational Controls", "title": "Acceptable use of information and other associated assets", "priority": "P2"},
    {"id": "A.5.11", "family": "Organizational Controls", "title": "Return of assets", "priority": "P2"},
    {"id": "A.5.12", "family": "Organizational Controls", "title": "Classification of information", "priority": "P1"},
    {"id": "A.5.13", "family": "Organizational Controls", "title": "Labelling of information", "priority": "P2"},
    {"id": "A.5.14", "family": "Organizational Controls", "title": "Information transfer", "priority": "P1"},
    {"id": "A.5.15", "family": "Organizational Controls", "title": "Access control", "priority": "P1"},
    {"id": "A.5.16", "family": "Organizational Controls", "title": "Identity management", "priority": "P1"},
    {"id": "A.5.17", "family": "Organizational Controls", "title": "Authentication information", "priority": "P1"},
    {"id": "A.5.18", "family": "Organizational Controls", "title": "Access rights", "priority": "P1"},
    {"id": "A.5.19", "family": "Organizational Controls", "title": "Information security in supplier relationships", "priority": "P2"},
    {"id": "A.5.20", "family": "Organizational Controls", "title": "Addressing information security within supplier agreements", "priority": "P2"},
    {"id": "A.5.21", "family": "Organizational Controls", "title": "Managing information security in the ICT supply chain", "priority": "P2"},
    {"id": "A.5.22", "family": "Organizational Controls", "title": "Monitoring, review and change management of supplier services", "priority": "P2"},
    {"id": "A.5.23", "family": "Organizational Controls", "title": "Information security for use of cloud services", "priority": "P1"},
    {"id": "A.5.24", "family": "Organizational Controls", "title": "Information security incident management planning and preparation", "priority": "P1"},
    {"id": "A.5.25", "family": "Organizational Controls", "title": "Assessment and decision on information security events", "priority": "P1"},
    {"id": "A.5.26", "family": "Organizational Controls", "title": "Response to information security incidents", "priority": "P1"},
    {"id": "A.5.27", "family": "Organizational Controls", "title": "Learning from information security incidents", "priority": "P2"},
    {"id": "A.5.28", "family": "Organizational Controls", "title": "Collection of evidence", "priority": "P2"},
    {"id": "A.5.29", "family": "Organizational Controls", "title": "Information security during disruption", "priority": "P1"},
    {"id": "A.5.30", "family": "Organizational Controls", "title": "ICT readiness for business continuity", "priority": "P1"},
    {"id": "A.5.31", "family": "Organizational Controls", "title": "Legal, statutory, regulatory and contractual requirements", "priority": "P1"},
    {"id": "A.5.32", "family": "Organizational Controls", "title": "Intellectual property rights", "priority": "P2"},
    {"id": "A.5.33", "family": "Organizational Controls", "title": "Protection of records", "priority": "P2"},
    {"id": "A.5.34", "family": "Organizational Controls", "title": "Privacy and protection of PII", "priority": "P1"},
    {"id": "A.5.35", "family": "Organizational Controls", "title": "Independent review of information security", "priority": "P2"},
    {"id": "A.5.36", "family": "Organizational Controls", "title": "Compliance with policies, rules and standards", "priority": "P2"},
    {"id": "A.5.37", "family": "Organizational Controls", "title": "Documented operating procedures", "priority": "P2"},
    # People Controls (8)
    {"id": "A.6.1", "family": "People Controls", "title": "Screening", "priority": "P2"},
    {"id": "A.6.2", "family": "People Controls", "title": "Terms and conditions of employment", "priority": "P2"},
    {"id": "A.6.3", "family": "People Controls", "title": "Information security awareness, education and training", "priority": "P1"},
    {"id": "A.6.4", "family": "People Controls", "title": "Disciplinary process", "priority": "P2"},
    {"id": "A.6.5", "family": "People Controls", "title": "Responsibilities after termination or change of employment", "priority": "P2"},
    {"id": "A.6.6", "family": "People Controls", "title": "Confidentiality or non-disclosure agreements", "priority": "P2"},
    {"id": "A.6.7", "family": "People Controls", "title": "Remote working", "priority": "P1"},
    {"id": "A.6.8", "family": "People Controls", "title": "Information security event reporting", "priority": "P1"},
    # Physical Controls (14)
    {"id": "A.7.1", "family": "Physical Controls", "title": "Physical security perimeters", "priority": "P1"},
    {"id": "A.7.2", "family": "Physical Controls", "title": "Physical entry", "priority": "P1"},
    {"id": "A.7.3", "family": "Physical Controls", "title": "Securing offices, rooms and facilities", "priority": "P1"},
    {"id": "A.7.4", "family": "Physical Controls", "title": "Physical security monitoring", "priority": "P1"},
    {"id": "A.7.5", "family": "Physical Controls", "title": "Protecting against physical and environmental threats", "priority": "P1"},
    {"id": "A.7.6", "family": "Physical Controls", "title": "Working in secure areas", "priority": "P2"},
    {"id": "A.7.7", "family": "Physical Controls", "title": "Clear desk and clear screen", "priority": "P2"},
    {"id": "A.7.8", "family": "Physical Controls", "title": "Equipment siting and protection", "priority": "P2"},
    {"id": "A.7.9", "family": "Physical Controls", "title": "Security of assets off-premises", "priority": "P2"},
    {"id": "A.7.10", "family": "Physical Controls", "title": "Storage media", "priority": "P1"},
    {"id": "A.7.11", "family": "Physical Controls", "title": "Supporting utilities", "priority": "P2"},
    {"id": "A.7.12", "family": "Physical Controls", "title": "Cabling security", "priority": "P3"},
    {"id": "A.7.13", "family": "Physical Controls", "title": "Equipment maintenance", "priority": "P2"},
    {"id": "A.7.14", "family": "Physical Controls", "title": "Secure disposal or re-use of equipment", "priority": "P1"},
    # Technological Controls (34)
    {"id": "A.8.1", "family": "Technological Controls", "title": "User endpoint devices", "priority": "P1"},
    {"id": "A.8.2", "family": "Technological Controls", "title": "Privileged access rights", "priority": "P1"},
    {"id": "A.8.3", "family": "Technological Controls", "title": "Information access restriction", "priority": "P1"},
    {"id": "A.8.4", "family": "Technological Controls", "title": "Access to source code", "priority": "P2"},
    {"id": "A.8.5", "family": "Technological Controls", "title": "Secure authentication", "priority": "P1"},
    {"id": "A.8.6", "family": "Technological Controls", "title": "Capacity management", "priority": "P2"},
    {"id": "A.8.7", "family": "Technological Controls", "title": "Protection against malware", "priority": "P1"},
    {"id": "A.8.8", "family": "Technological Controls", "title": "Management of technical vulnerabilities", "priority": "P1"},
    {"id": "A.8.9", "family": "Technological Controls", "title": "Configuration management", "priority": "P1"},
    {"id": "A.8.10", "family": "Technological Controls", "title": "Information deletion", "priority": "P1"},
    {"id": "A.8.11", "family": "Technological Controls", "title": "Data masking", "priority": "P2"},
    {"id": "A.8.12", "family": "Technological Controls", "title": "Data leakage prevention", "priority": "P1"},
    {"id": "A.8.13", "family": "Technological Controls", "title": "Information backup", "priority": "P1"},
    {"id": "A.8.14", "family": "Technological Controls", "title": "Redundancy of information processing facilities", "priority": "P2"},
    {"id": "A.8.15", "family": "Technological Controls", "title": "Logging", "priority": "P1"},
    {"id": "A.8.16", "family": "Technological Controls", "title": "Monitoring activities", "priority": "P1"},
    {"id": "A.8.17", "family": "Technological Controls", "title": "Clock synchronization", "priority": "P3"},
    {"id": "A.8.18", "family": "Technological Controls", "title": "Use of privileged utility programs", "priority": "P2"},
    {"id": "A.8.19", "family": "Technological Controls", "title": "Installation of software on operational systems", "priority": "P2"},
    {"id": "A.8.20", "family": "Technological Controls", "title": "Networks security", "priority": "P1"},
    {"id": "A.8.21", "family": "Technological Controls", "title": "Security of network services", "priority": "P1"},
    {"id": "A.8.22", "family": "Technological Controls", "title": "Segregation of networks", "priority": "P1"},
    {"id": "A.8.23", "family": "Technological Controls", "title": "Web filtering", "priority": "P2"},
    {"id": "A.8.24", "family": "Technological Controls", "title": "Use of cryptography", "priority": "P1"},
    {"id": "A.8.25", "family": "Technological Controls", "title": "Secure development life cycle", "priority": "P2"},
    {"id": "A.8.26", "family": "Technological Controls", "title": "Application security requirements", "priority": "P2"},
    {"id": "A.8.27", "family": "Technological Controls", "title": "Secure system architecture and engineering principles", "priority": "P2"},
    {"id": "A.8.28", "family": "Technological Controls", "title": "Secure coding", "priority": "P2"},
    {"id": "A.8.29", "family": "Technological Controls", "title": "Security testing in development and acceptance", "priority": "P2"},
    {"id": "A.8.30", "family": "Technological Controls", "title": "Outsourced development", "priority": "P2"},
    {"id": "A.8.31", "family": "Technological Controls", "title": "Separation of development, test and production environments", "priority": "P2"},
    {"id": "A.8.32", "family": "Technological Controls", "title": "Change management", "priority": "P1"},
    {"id": "A.8.33", "family": "Technological Controls", "title": "Test information", "priority": "P3"},
    {"id": "A.8.34", "family": "Technological Controls", "title": "Protection of information systems during audit testing", "priority": "P2"},
]


# ---------------------------------------------------------------------------
# Main seeder
# ---------------------------------------------------------------------------

def _fedramp_as_control_dicts() -> list[dict]:
    """Project FEDRAMP_MODERATE_CONTROLS into the seeder's dict shape."""
    return [
        {
            "id": c["id"],
            "family": c["family"],
            "title": c["title"],
            "description": c.get("description", ""),
            "priority": c.get("priority", "P2").lower(),
            "baseline": c.get("baseline", "moderate"),
            "pysoar_mapping": c.get("pysoar_mapping"),
        }
        for c in FEDRAMP_MODERATE_CONTROLS
    ]


CONTROL_CATALOGS: dict[str, list[dict]] = {
    "fedramp_moderate": _fedramp_as_control_dicts(),
    "nist_800_171": NIST_800_171_CONTROLS,
    "cmmc_level_2": NIST_800_171_CONTROLS,  # CMMC L2 == NIST 800-171 1:1 mapping
    "pci_dss": PCI_DSS_CONTROLS,
    "hipaa": HIPAA_CONTROLS,
    "soc2": SOC2_CONTROLS,
    "iso_27001": ISO_27001_CONTROLS,
}


async def seed_framework_for_org(
    db: AsyncSession,
    organization_id: str,
    framework_def: dict,
) -> tuple[str, int]:
    """Seed a single framework + its controls for one organization.

    Idempotent: existing framework is re-used; only missing controls
    are added. Returns (framework_status, controls_added).
    """
    short_name = framework_def["short_name"]

    # Check for existing framework
    existing_result = await db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.organization_id == organization_id,
            ComplianceFramework.short_name == short_name,
        )
    )
    framework = existing_result.scalar_one_or_none()

    if framework is None:
        framework = ComplianceFramework(
            name=framework_def["name"],
            short_name=short_name,
            version=framework_def["version"],
            description=framework_def["description"],
            authority=framework_def["authority"],
            certification_level=framework_def.get("certification_level"),
            status="not_started",
            is_enabled=True,
            organization_id=organization_id,
        )
        db.add(framework)
        await db.flush()
        framework_status = "created"
    else:
        framework_status = "updated"

    # Load the control catalog
    control_source = framework_def.get("control_source", short_name)
    catalog = CONTROL_CATALOGS.get(control_source, [])
    if not catalog:
        return framework_status, 0

    # Fetch existing control IDs for this framework so we only insert missing ones
    existing_ctrl_result = await db.execute(
        select(ComplianceControl.control_id).where(
            ComplianceControl.framework_id == framework.id
        )
    )
    existing_ctrl_ids = {row[0] for row in existing_ctrl_result.all()}

    controls_added = 0
    for ctrl in catalog:
        if ctrl["id"] in existing_ctrl_ids:
            continue
        priority = str(ctrl.get("priority", "P2")).lower().replace("p", "p")
        db.add(ComplianceControl(
            framework_id=framework.id,
            control_id=ctrl["id"],
            control_family=ctrl.get("family", "Uncategorized"),
            title=ctrl.get("title", ctrl["id"]),
            description=ctrl.get("description"),
            priority=priority if priority in ("p1", "p2", "p3") else "p2",
            baseline=ctrl.get("baseline", "moderate"),
            status="not_implemented",
            implementation_status=0.0,
            assessment_method="examine",
            assessment_frequency="annual",
            risk_if_not_implemented="high" if priority == "p1" else "medium",
            organization_id=organization_id,
        ))
        controls_added += 1

    # Update framework totals
    total_ctrls_result = await db.execute(
        select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
    )
    all_controls = list(total_ctrls_result.scalars().all())
    framework.total_controls = len(all_controls) + controls_added  # pre-flush count + new
    implemented = sum(1 for c in all_controls if c.status == "implemented")
    framework.implemented_controls = implemented
    framework.compliance_score = (
        round((implemented / framework.total_controls) * 100.0, 1)
        if framework.total_controls > 0 else 0.0
    )
    if framework.status == "not_started" and framework.total_controls > 0:
        framework.status = "in_progress"

    return framework_status, controls_added


async def seed_all_compliance_frameworks() -> dict:
    """Top-level seeder called from main.py lifespan.

    Iterates all organizations and seeds every framework for each.
    Safe to run on every boot — idempotent.
    """
    total_created = 0
    total_controls_added = 0
    details: list[dict] = []

    async with async_session_factory() as db:
        try:
            org_result = await db.execute(select(Organization))
            organizations = list(org_result.scalars().all())

            if not organizations:
                logger.info("seed_all_compliance_frameworks: no organizations yet")
                return {"organizations": 0, "frameworks_created": 0, "controls_added": 0}

            for org in organizations:
                for framework_def in FRAMEWORK_DEFINITIONS:
                    try:
                        status, added = await seed_framework_for_org(
                            db, org.id, framework_def
                        )
                        if status == "created":
                            total_created += 1
                        total_controls_added += added
                        details.append({
                            "org_id": org.id,
                            "framework": framework_def["short_name"],
                            "status": status,
                            "controls_added": added,
                        })
                    except Exception as e:
                        logger.warning(
                            f"Failed to seed {framework_def['short_name']} "
                            f"for org {org.id}: {e}"
                        )

            await db.commit()

            logger.info(
                f"Compliance seeding complete: "
                f"{len(organizations)} orgs, "
                f"{total_created} new frameworks, "
                f"{total_controls_added} new controls"
            )

            return {
                "organizations": len(organizations),
                "frameworks_created": total_created,
                "controls_added": total_controls_added,
                "details": details,
            }
        except Exception as e:
            logger.error(f"seed_all_compliance_frameworks failed: {e}", exc_info=True)
            await db.rollback()
            return {"error": str(e)}
