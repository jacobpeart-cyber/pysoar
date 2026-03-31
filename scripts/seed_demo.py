"""
Seed demo data for PySOAR GTM demonstration.
Run: docker exec pysoar-api python scripts/seed_demo.py
"""

import asyncio
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from src.core.database import async_session_factory, engine
from src.models.alert import Alert
from src.models.incident import Incident
from src.models.ioc import IOC
from src.models.playbook import Playbook
from src.models.asset import Asset


def rand_date(days_back=30):
    """Random datetime within the past N days"""
    offset = random.randint(0, days_back * 24 * 3600)
    return datetime.now(timezone.utc) - timedelta(seconds=offset)


def rand_ip():
    return f"{random.randint(10, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


ALERT_DATA = [
    ("Brute force SSH login detected", "critical", "siem", "Multiple failed SSH login attempts from external IP", "ids"),
    ("Suspicious PowerShell execution", "high", "edr", "Encoded PowerShell command detected on workstation", "malware"),
    ("Outbound C2 communication detected", "critical", "firewall", "Beaconing traffic to known C2 infrastructure", "malware"),
    ("Phishing email with malicious attachment", "high", "email_gateway", "Employee received email with weaponized Excel macro", "phishing"),
    ("Unauthorized admin account created", "critical", "siem", "New domain admin account created outside change window", "unauthorized_access"),
    ("AWS S3 bucket made public", "high", "cloud", "Production S3 bucket ACL changed to public-read", "misconfiguration"),
    ("Lateral movement via RDP", "high", "edr", "Unusual RDP connections between workstations", "lateral_movement"),
    ("Data exfiltration to external storage", "critical", "firewall", "Large data transfer to cloud storage service", "data_exfiltration"),
    ("Ransomware encryption activity", "critical", "edr", "Mass file encryption detected on file server", "ransomware"),
    ("SQL injection attempt on web app", "medium", "ids", "SQL injection payload detected in HTTP POST request", "web_attack"),
    ("Expired SSL certificate detected", "low", "cloud", "SSL certificate expired on customer-facing API gateway", "misconfiguration"),
    ("Unusual login from foreign country", "medium", "siem", "Admin login from IP geolocated to unexpected region", "suspicious_login"),
    ("Firewall rule modification", "medium", "firewall", "Allow-all rule added to production firewall", "policy_violation"),
    ("Malware detected in email quarantine", "low", "email_gateway", "Known Emotet variant blocked by email gateway", "malware"),
    ("DNS tunneling attempt", "high", "ids", "Suspicious DNS queries with encoded data payloads", "data_exfiltration"),
    ("Privilege escalation on Linux server", "high", "edr", "User gained root access via kernel exploit", "privilege_escalation"),
    ("New scheduled task created", "medium", "siem", "Suspicious scheduled task created for persistence", "persistence"),
    ("Cloud IAM policy change", "medium", "cloud", "IAM role permissions expanded beyond least privilege", "policy_violation"),
    ("Web shell uploaded to server", "critical", "edr", "PHP web shell detected in web server uploads directory", "web_attack"),
    ("VPN connection from compromised IP", "low", "firewall", "VPN login from IP on threat intelligence blocklist", "suspicious_login"),
]

SEVERITIES = ["critical", "high", "medium", "low"]
STATUSES = ["new", "acknowledged", "in_progress", "resolved", "closed"]

INCIDENT_DATA = [
    ("Ransomware Attack on File Server", "critical", "investigating", "ransomware"),
    ("Executive Email Account Compromise", "high", "containment", "phishing"),
    ("Data Breach via SQL Injection", "critical", "eradication", "data_breach"),
    ("Insider Data Theft Investigation", "high", "investigating", "insider_threat"),
    ("Brute Force Attack on VPN Gateway", "medium", "open", "unauthorized_access"),
    ("Cloud Infrastructure Misconfiguration", "medium", "recovery", "other"),
    ("Malware Outbreak on Workstations", "high", "containment", "malware"),
    ("APT Activity Detected in Network", "critical", "investigating", "advanced_persistent_threat"),
]

IOC_DATA = [
    ("185.220.101.45", "ip", "high", "Known Cobalt Strike C2 server"),
    ("evil-update.com", "domain", "critical", "APT28 domain used in spear-phishing"),
    ("http://malware-delivery.net/stage2.exe", "url", "high", "Malware delivery URL"),
    ("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "sha256", "critical", "Ransomware payload hash"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5", "medium", "Suspicious file hash"),
    ("192.168.100.50", "ip", "medium", "Internal host exhibiting C2 beaconing"),
    ("phishing-portal.xyz", "domain", "high", "Credential harvesting domain"),
    ("https://cdn.attack-infra.com/loader.js", "url", "high", "JavaScript loader for exploit kit"),
    ("5d41402abc4b2a76b9719d911017c592", "md5", "low", "Adware hash"),
    ("103.45.67.89", "ip", "high", "Scanning IP from threat feed"),
    ("suspicious-vpn.ru", "domain", "medium", "Russian VPN service linked to APT activity"),
    ("44.33.22.11", "ip", "low", "Tor exit node"),
]

PLAYBOOK_DATA = [
    ("Malware Containment", "Automated malware containment and isolation procedure", [
        {"name": "Identify affected hosts", "action_type": "query", "description": "Query SIEM for all hosts communicating with the malware C2"},
        {"name": "Isolate endpoints", "action_type": "action", "description": "Network isolate affected endpoints via EDR"},
        {"name": "Block IOCs", "action_type": "action", "description": "Add malware IOCs to firewall blocklist"},
        {"name": "Collect forensic artifacts", "action_type": "query", "description": "Gather memory dumps and disk images"},
        {"name": "Notify SOC lead", "action_type": "notification", "description": "Send alert to SOC manager with summary"},
    ]),
    ("Phishing Response", "Automated phishing email investigation and response", [
        {"name": "Extract email indicators", "action_type": "query", "description": "Parse sender, URLs, and attachments from phishing email"},
        {"name": "Check URL reputation", "action_type": "enrichment", "description": "Query VirusTotal and URLScan for URL reputation"},
        {"name": "Search for similar emails", "action_type": "query", "description": "Search email gateway for related messages"},
        {"name": "Quarantine emails", "action_type": "action", "description": "Quarantine all matching emails across organization"},
        {"name": "Reset user credentials", "action_type": "action", "description": "Force password reset for affected users"},
    ]),
    ("Brute Force Mitigation", "Automated response to brute force attacks", [
        {"name": "Identify source IPs", "action_type": "query", "description": "Query authentication logs for failed attempts"},
        {"name": "Block source IPs", "action_type": "action", "description": "Add attacker IPs to firewall deny list"},
        {"name": "Check compromised accounts", "action_type": "query", "description": "Identify accounts with successful logins after failures"},
        {"name": "Lock compromised accounts", "action_type": "action", "description": "Disable any compromised accounts"},
    ]),
    ("Cloud Security Incident", "Automated cloud infrastructure investigation", [
        {"name": "Query CloudTrail events", "action_type": "query", "description": "Pull recent API activity for affected resources"},
        {"name": "Revoke exposed credentials", "action_type": "action", "description": "Rotate IAM keys and revoke sessions"},
        {"name": "Restore secure configuration", "action_type": "action", "description": "Revert security group and policy changes"},
    ]),
    ("Ransomware Response", "Full ransomware incident response playbook", [
        {"name": "Isolate infected systems", "action_type": "action", "description": "Network-isolate all identified infected hosts"},
        {"name": "Identify ransomware variant", "action_type": "query", "description": "Collect samples and identify the ransomware family"},
        {"name": "Assess encryption scope", "action_type": "query", "description": "Determine which files and systems are encrypted"},
        {"name": "Check backup integrity", "action_type": "query", "description": "Verify backup availability and integrity"},
        {"name": "Initiate recovery", "action_type": "action", "description": "Begin system restoration from verified backups"},
        {"name": "Executive notification", "action_type": "notification", "description": "Notify CISO and legal team of ransomware incident"},
    ]),
]

ASSET_DATA = [
    ("DC01", "server", "Active Directory Domain Controller", "10.0.1.10", "critical"),
    ("WEB-PROD-01", "server", "Production Web Application Server", "10.0.2.20", "high"),
    ("FW-EDGE-01", "network", "Perimeter Firewall - Palo Alto", "10.0.0.1", "critical"),
    ("LAPTOP-EXEC-042", "workstation", "CFO Laptop - Windows 11", "10.0.10.42", "high"),
    ("DB-PROD-01", "server", "Production PostgreSQL Database", "10.0.3.30", "critical"),
]


async def seed():
    print("Seeding PySOAR demo data...")

    async with async_session_factory() as db:
        # Check if data already exists
        result = await db.execute(select(Alert).limit(1))
        if result.scalars().first():
            print("Data already exists. Skipping seed.")
            return

        # Seed Alerts
        print("  Creating alerts...")
        for title, severity, source, desc, category in ALERT_DATA:
            status = random.choice(STATUSES)
            alert = Alert(
                id=str(uuid.uuid4()),
                title=title,
                description=desc,
                severity=severity,
                status=status,
                source=source,
                category=category,
                priority=random.randint(1, 5),
                confidence=random.randint(40, 99),
                source_ip=rand_ip(),
                destination_ip=rand_ip(),
                hostname=f"host-{random.randint(100, 999)}.corp.local",
                created_at=rand_date(30),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(alert)

        # Seed Incidents
        print("  Creating incidents...")
        for title, severity, status, inc_type in INCIDENT_DATA:
            incident = Incident(
                id=str(uuid.uuid4()),
                title=title,
                description=f"Investigation of {title.lower()} affecting production environment.",
                severity=severity,
                status=status,
                incident_type=inc_type,
                priority=random.randint(1, 4),
                created_at=rand_date(30),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(incident)

        # Seed IOCs
        print("  Creating IOCs...")
        for value, ioc_type, threat_level, desc in IOC_DATA:
            ioc = IOC(
                id=str(uuid.uuid4()),
                value=value,
                ioc_type=ioc_type,
                threat_level=threat_level,
                description=desc,
                source="threat_feed",
                status="active",
                created_at=rand_date(60),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(ioc)

        # Seed Playbooks
        print("  Creating playbooks...")
        for name, desc, steps in PLAYBOOK_DATA:
            playbook = Playbook(
                id=str(uuid.uuid4()),
                name=name,
                description=desc,
                steps=json.dumps(steps),
                is_enabled=True,
                status="active",
                trigger_type="manual",
                created_at=rand_date(90),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(playbook)

        # Seed Assets
        print("  Creating assets...")
        for name, asset_type, desc, ip, criticality in ASSET_DATA:
            asset = Asset(
                id=str(uuid.uuid4()),
                name=name,
                asset_type=asset_type,
                description=desc,
                ip_address=ip,
                status="active",
                criticality=criticality,
                created_at=rand_date(180),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(asset)

        # Seed SIEM Log Entries
        print("  Creating SIEM log entries...")
        from src.siem.models import LogEntry, DetectionRule, SIEMDataSource

        siem_logs = [
            ("Failed SSH login from 192.168.1.100", "syslog", "fw-edge-01", "10.0.0.1", "authentication", "high"),
            ("Successful RDP session from 10.0.5.20", "windows_event", "dc01.corp.local", "10.0.1.10", "authentication", "informational"),
            ("DNS query to known C2 domain evil.com", "syslog", "dns-resolver-01", "10.0.0.2", "network", "critical"),
            ("Firewall blocked inbound scan on port 445", "cef", "fw-edge-01", "10.0.0.1", "network", "medium"),
            ("User account locked after 5 failed attempts", "windows_event", "dc01.corp.local", "10.0.1.10", "security", "high"),
            ("AWS CloudTrail: S3 bucket policy changed", "cloud_trail", "aws-us-east-1", "172.16.0.1", "cloud", "high"),
            ("Antivirus quarantined file on WORKSTATION-42", "json_api", "edr-console", "10.0.10.5", "endpoint", "medium"),
            ("Apache access log: SQL injection attempt", "syslog", "web-prod-01", "10.0.2.20", "application", "critical"),
            ("VPN connection established from remote IP", "syslog", "vpn-gateway", "10.0.0.5", "network", "low"),
            ("Exchange: Suspicious mail forwarding rule created", "json_api", "exchange-01", "10.0.1.15", "application", "high"),
            ("Linux audit: sudo command by non-admin user", "syslog", "db-prod-01", "10.0.3.30", "system", "medium"),
            ("IDS alert: Port scan detected from external IP", "cef", "ids-sensor-01", "10.0.0.3", "security", "high"),
            ("Container runtime: Privilege escalation attempt", "json_api", "k8s-node-01", "10.0.4.10", "endpoint", "critical"),
            ("Azure AD: Impossible travel login detected", "cloud_trail", "azure-ad", "172.16.0.2", "authentication", "high"),
            ("Proxy: Connection to TOR exit node blocked", "syslog", "proxy-01", "10.0.0.4", "network", "medium"),
        ]

        for raw_log, source_type, source_name, source_ip, log_type, severity in siem_logs:
            log_entry = LogEntry(
                id=str(uuid.uuid4()),
                raw_log=raw_log,
                message=raw_log,
                source_type=source_type,
                source_name=source_name,
                source_ip=source_ip,
                log_type=log_type,
                severity=severity,
                timestamp=rand_date(7).isoformat(),
                received_at=datetime.now(timezone.utc).isoformat(),
                created_at=rand_date(7),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(log_entry)

        # Seed Detection Rules
        print("  Creating SIEM detection rules...")
        detection_rules = [
            ("Brute Force SSH", "brute-force-ssh", "Detect multiple failed SSH logins", "high", True),
            ("DNS to C2 Domain", "dns-c2-detection", "Alert on DNS queries to known C2 domains", "critical", True),
            ("Port Scan Detection", "port-scan-detect", "Detect horizontal port scanning", "medium", True),
            ("Privilege Escalation", "priv-esc-detect", "Detect privilege escalation attempts", "critical", True),
            ("Data Exfiltration", "data-exfil-detect", "Large outbound data transfers", "high", True),
            ("Suspicious Login Hours", "off-hours-login", "Login outside business hours", "low", False),
        ]

        for title, name, desc, severity, enabled in detection_rules:
            rule = DetectionRule(
                id=str(uuid.uuid4()),
                title=title,
                name=name,
                description=desc,
                severity=severity,
                enabled=enabled,
                match_count=random.randint(0, 50),
                created_at=rand_date(60),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(rule)

        # Seed Data Sources
        print("  Creating SIEM data sources...")
        data_sources = [
            ("Edge Firewall", "Palo Alto PA-5250 edge firewall", "syslog", "connected"),
            ("Domain Controller", "Windows Server 2022 AD DC", "windows_event", "connected"),
            ("AWS CloudTrail", "AWS account us-east-1 CloudTrail", "cloud_trail", "connected"),
            ("EDR Console", "CrowdStrike Falcon EDR", "json_api", "connected"),
            ("IDS Sensor", "Suricata IDS network sensor", "cef", "connected"),
        ]

        for name, desc, source_type, ds_status in data_sources:
            source = SIEMDataSource(
                id=str(uuid.uuid4()),
                name=name,
                description=desc,
                source_type=source_type,
                status=ds_status,
                created_at=rand_date(90),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(source)

        await db.commit()
        print("Demo data seeded successfully!")
        print(f"  - {len(ALERT_DATA)} alerts")
        print(f"  - {len(INCIDENT_DATA)} incidents")
        print(f"  - {len(IOC_DATA)} IOCs")
        print(f"  - {len(PLAYBOOK_DATA)} playbooks")
        print(f"  - {len(ASSET_DATA)} assets")
        print(f"  - {len(siem_logs)} SIEM log entries")
        print(f"  - {len(detection_rules)} detection rules")
        print(f"  - {len(data_sources)} data sources")


if __name__ == "__main__":
    asyncio.run(seed())
