"""Built-in detection rule seeder.

Previously ``detection_rules`` held seven rows where five had empty
``detection_logic`` and no ``rule_yaml`` — they were decorative names
with ``match_count`` values that had been poked in by seed scripts,
not by actual log evaluation. Rules with no body can't fire, so the
SIEM appeared to be "working" when it was never really evaluating.

This module ships a real detection-rule library that matches against
the field schema the SIEM log mirror produces (source_type=audit or
alert, plus action/severity/log_type/message). Every rule here carries
full Sigma-style ``detection_logic``, so when the pipeline evaluates a
mirrored log it can actually match.

``seed_builtin_detection_rules()`` is idempotent: it UPSERTs by name,
filling in empty detection_logic on existing rows so we don't lose
history, and adding any rule that's missing entirely.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.siem.models import DetectionRule

logger = logging.getLogger(__name__)


# Each rule's detection_logic uses FieldMatcher semantics (see
# src/siem/rules/engine.py): string = exact/wildcard, list = any-of,
# {"contains": "..."} = substring, {"regex": "..."} = regex, threshold+
# timewindow wrap the selection in an aggregation tracker.
BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "name": "auth-login-failed",
        "title": "Authentication Failure",
        "description": (
            "A user authentication attempt failed. Watch for patterns "
            "across the same user or source IP — correlated failures "
            "indicate brute-force or credential-stuffing activity."
        ),
        "severity": "medium",
        "log_types": ["authentication"],
        "mitre_tactics": ["TA0006"],  # Credential Access
        "mitre_techniques": ["T1110"],  # Brute Force
        "tags": ["authentication", "brute_force"],
        "detection_logic": {
            "source_type": "audit",
            "action": "login_failed",
        },
        "condition": "selection",
    },
    {
        "name": "auth-brute-force",
        "title": "Brute Force Login Attempts",
        "description": (
            "More than 5 failed login events within 5 minutes from "
            "the same source IP — strong indicator of automated "
            "credential brute-force activity."
        ),
        "severity": "high",
        "log_types": ["authentication"],
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1110.001", "T1110.003"],
        "tags": ["authentication", "brute_force", "password_spray"],
        "detection_logic": {
            "source_type": "audit",
            "action": "login_failed",
        },
        "condition": "selection",
        "timewindow": 300,
        "threshold": 5,
        "group_by": ["source_ip"],
    },
    {
        "name": "privileged-resource-deletion",
        "title": "Privileged Resource Deletion",
        "description": (
            "Sensitive resource deletion (users, roles, playbooks, "
            "detection rules, compliance evidence, or audit trails). "
            "Always worth a second look — this is how an attacker "
            "covers their tracks or degrades defenses."
        ),
        "severity": "high",
        "log_types": ["security", "system"],
        "mitre_tactics": ["TA0005"],  # Defense Evasion
        "mitre_techniques": ["T1485", "T1070"],  # Data Destruction, Indicator Removal
        "tags": ["defense_evasion", "destruction"],
        "detection_logic": {
            "source_type": "audit",
            "action": "delete",
            "resource_type": [
                "user",
                "users",
                "role",
                "roles",
                "playbook",
                "playbooks",
                "detection_rule",
                "detection_rules",
                "compliance_evidence",
                "audit_log",
                "audit_trail",
                "integration",
                "organization",
            ],
        },
        "condition": "selection",
    },
    {
        "name": "config-change",
        "title": "Configuration Change",
        "description": (
            "Platform or security configuration modified. Correlate "
            "with the acting user to catch unauthorized admin changes "
            "or misuse of elevated privileges."
        ),
        "severity": "medium",
        "log_types": ["system"],
        "mitre_tactics": ["TA0003"],  # Persistence
        "mitre_techniques": ["T1098"],  # Account Manipulation
        "tags": ["persistence", "config_change"],
        "detection_logic": {
            "source_type": "audit",
            "action": "config_change",
        },
        "condition": "selection",
    },
    {
        "name": "critical-security-alert",
        "title": "Critical Security Alert",
        "description": (
            "Any alert elevated to critical severity by a SOC module "
            "(EDR, IDS, cloud posture, etc.). Fires immediately — no "
            "aggregation — so the responder sees it without waiting "
            "for a correlation window."
        ),
        "severity": "critical",
        "log_types": ["security"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["alert_flood", "critical"],
        "detection_logic": {
            "source_type": "alert",
            "severity": "critical",
        },
        "condition": "selection",
    },
    {
        "name": "high-severity-alert-flood",
        "title": "High-Severity Alert Flood",
        "description": (
            "More than 10 high-or-critical alerts within 5 minutes — "
            "a meta-detection that fires when the platform itself is "
            "under attack or when a noisy integration is flooding the "
            "queue."
        ),
        "severity": "high",
        "log_types": ["security"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["alert_flood"],
        "detection_logic": {
            "source_type": "alert",
            "severity": ["high", "critical"],
        },
        "condition": "selection",
        "timewindow": 300,
        "threshold": 10,
        "group_by": ["source_type"],
    },
    {
        "name": "admin-account-created",
        "title": "New Admin or Privileged Account",
        "description": (
            "A user account was created and the description mentions "
            "admin / root / superuser privileges. Attackers commonly "
            "create sidecar admins for persistence (T1136.001)."
        ),
        "severity": "high",
        "log_types": ["security"],
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1136.001"],  # Local Account
        "tags": ["persistence", "account_creation"],
        "detection_logic": {
            "source_type": "audit",
            "action": "create",
            "resource_type": ["user", "users"],
            "message": {"regex": "(?i)admin|root|superuser|privileged"},
        },
        "condition": "selection",
    },
    {
        "name": "sensitive-export",
        "title": "Sensitive Data Export",
        "description": (
            "A user exported data from the platform. When the target "
            "is alerts, incidents, audit trails, compliance evidence, "
            "or threat intel, this is a staging step for data "
            "exfiltration (T1567 — Exfiltration Over Web Service)."
        ),
        "severity": "medium",
        "log_types": ["application"],
        "mitre_tactics": ["TA0010"],  # Exfiltration
        "mitre_techniques": ["T1567"],
        "tags": ["exfiltration"],
        "detection_logic": {
            "source_type": "audit",
            "action": "export",
        },
        "condition": "selection",
    },
    {
        "name": "playbook-execute-anomaly",
        "title": "Playbook Execution",
        "description": (
            "A playbook was executed. Not inherently malicious, but "
            "in combination with deletes or config changes in a short "
            "window, it's worth alerting on for change-control audit."
        ),
        "severity": "informational",
        "log_types": ["application"],
        "mitre_tactics": [],
        "mitre_techniques": ["T1203"],
        "tags": ["automation"],
        "detection_logic": {
            "source_type": "audit",
            "action": "playbook_execute",
        },
        "condition": "selection",
    },
    {
        "name": "incident-escalation-burst",
        "title": "Incident Escalation Burst",
        "description": (
            "More than 3 incidents created within 10 minutes — "
            "platform-wide incident burst suggesting a coordinated "
            "attack or widespread control failure."
        ),
        "severity": "high",
        "log_types": ["security"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["incident_storm"],
        "detection_logic": {
            "source_type": "audit",
            "action": "incident_create",
        },
        "condition": "selection",
        "timewindow": 600,
        "threshold": 3,
        "group_by": [],
    },
]


def _build_yaml_for(rule_spec: dict[str, Any]) -> str:
    """Build a Sigma-compatible YAML doc for storage."""
    import yaml
    detection = {
        "selection": rule_spec["detection_logic"],
        "condition": rule_spec.get("condition", "selection"),
    }
    if rule_spec.get("timewindow"):
        detection["timewindow"] = rule_spec["timewindow"]
    if rule_spec.get("threshold"):
        detection["threshold"] = rule_spec["threshold"]
    if rule_spec.get("group_by"):
        detection["group_by"] = rule_spec["group_by"]

    doc = {
        "title": rule_spec["title"],
        "id": rule_spec["name"],
        "description": rule_spec["description"],
        "status": "active",
        "level": rule_spec["severity"],
        "logsource": {"category": (rule_spec.get("log_types") or ["security"])[0]},
        "detection": detection,
        "tags": [
            *(f"attack.{t.lower()}" for t in rule_spec.get("mitre_tactics", [])),
            *(f"attack.{t.lower()}" for t in rule_spec.get("mitre_techniques", [])),
            *(rule_spec.get("tags") or []),
        ],
    }
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)


async def seed_builtin_detection_rules(db: AsyncSession) -> dict[str, int]:
    """Install or refresh the built-in detection rules.

    Idempotent: UPDATEs rows that exist but have empty detection_logic
    (the previous decorative state), INSERTs rows that are missing.
    Never downgrades a user-customized rule.
    """
    existing_res = await db.execute(select(DetectionRule))
    existing: dict[str, DetectionRule] = {r.name: r for r in existing_res.scalars().all()}

    inserted = 0
    updated = 0

    for spec in BUILTIN_RULES:
        logic_json = json.dumps(spec["detection_logic"])
        yaml_doc = _build_yaml_for(spec)

        row = existing.get(spec["name"])
        if row is None:
            new_rule = DetectionRule(
                id=str(uuid.uuid4()),
                name=spec["name"],
                title=spec["title"],
                description=spec["description"],
                author="pysoar-builtin",
                status="active",
                severity=spec["severity"],
                log_types=json.dumps(spec.get("log_types", [])) if spec.get("log_types") else None,
                detection_logic=logic_json,
                condition=spec.get("condition", "selection"),
                timewindow=spec.get("timewindow"),
                threshold=spec.get("threshold"),
                group_by=json.dumps(spec.get("group_by", [])) if spec.get("group_by") else None,
                mitre_tactics=json.dumps(spec.get("mitre_tactics", [])) if spec.get("mitre_tactics") else None,
                mitre_techniques=json.dumps(spec.get("mitre_techniques", [])) if spec.get("mitre_techniques") else None,
                tags=json.dumps(spec.get("tags", [])) if spec.get("tags") else None,
                rule_yaml=yaml_doc,
                enabled=True,
            )
            db.add(new_rule)
            inserted += 1
        else:
            # Refill only when empty — don't overwrite user customizations.
            if not row.detection_logic:
                row.detection_logic = logic_json
                row.condition = spec.get("condition", "selection")
                row.rule_yaml = yaml_doc
                row.title = row.title or spec["title"]
                row.description = row.description or spec["description"]
                if not row.severity or row.severity == "medium":
                    row.severity = spec["severity"]
                if spec.get("timewindow"):
                    row.timewindow = spec["timewindow"]
                if spec.get("threshold"):
                    row.threshold = spec["threshold"]
                if spec.get("group_by"):
                    row.group_by = json.dumps(spec["group_by"])
                if spec.get("log_types"):
                    row.log_types = json.dumps(spec["log_types"])
                if spec.get("mitre_tactics"):
                    row.mitre_tactics = json.dumps(spec["mitre_tactics"])
                if spec.get("mitre_techniques"):
                    row.mitre_techniques = json.dumps(spec["mitre_techniques"])
                if spec.get("tags"):
                    row.tags = json.dumps(spec["tags"])
                updated += 1

    await db.flush()
    logger.info(
        "SIEM rule seeder: %d inserted, %d refilled empty rules",
        inserted,
        updated,
    )
    return {"inserted": inserted, "refilled": updated}
