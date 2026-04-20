"""SIEM log-entry mirror.

The SIEM `log_entries` table is the canonical search/detection surface.
Historically it only saw logs that were POSTed to ``/siem/logs/ingest``
and sat empty in practice, which meant the SIEM dashboard, search, and
detection-rule engine all had nothing real to work against.

This module wires two paths into ``log_entries``:

1. SQLAlchemy ``after_insert`` mapper events on ``Alert`` and
   ``AuditLog`` that INSERT a mirror row into ``log_entries`` in the
   same transaction. Every alert or audit event the platform emits
   instantly becomes a searchable SIEM log.

2. An explicit backfill helper (``backfill_from_history``) that copies
   existing Alert/AuditLog rows into ``log_entries`` for historical
   coverage — used once at deploy time and exposed via an admin endpoint.

Running INSERTs inside the mapper event means the mirror is atomic
with the source write. If the originating transaction rolls back, so
does the mirror, so the two stores can never diverge.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import event, select, text

from src.models.alert import Alert
from src.models.audit import AuditLog
from src.siem.models import LogEntry

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Field mapping helpers
# --------------------------------------------------------------------------- #


# MITRE mapping for common audit actions so mirrored audit events carry
# real tactic/technique context rather than blank tags.
_AUDIT_MITRE_MAP: dict[str, list[str]] = {
    "login_failed": ["T1110", "T1078"],
    "login": ["T1078"],
    "logout": [],
    "password_change": ["T1098"],
    "alert_acknowledge": [],
    "alert_close": [],
    "alert_escalate": [],
    "incident_create": [],
    "playbook_execute": ["T1203"],
    "config_change": ["T1098"],
    "create": [],
    "update": [],
    "delete": ["T1485"],
    "export": ["T1567"],
    "import": ["T1105"],
}


def _severity_from_audit(audit: AuditLog) -> str:
    """Map audit action/success into a SIEM severity value."""
    action = (audit.action or "").lower()
    if not audit.success:
        # Failed auth attempts are high — real brute force indicators.
        if action in ("login_failed", "login"):
            return "high"
        return "medium"
    if action in ("delete", "config_change", "alert_close", "incident_close"):
        return "medium"
    if action in ("password_change", "playbook_execute", "alert_escalate"):
        return "medium"
    return "informational"


def _log_type_from_audit(action: str) -> str:
    """Classify audit action into SIEM log_type."""
    a = (action or "").lower()
    if a in ("login", "logout", "login_failed", "password_change"):
        return "authentication"
    if a.startswith("alert_") or a.startswith("incident_"):
        return "security"
    if a == "api_access":
        return "application"
    if a == "config_change":
        return "system"
    return "application"


def _alert_to_log_row(alert: Alert) -> dict[str, Any]:
    """Project an Alert row into a log_entries row dict."""
    now = datetime.now(timezone.utc).isoformat()
    created_at = alert.created_at.isoformat() if getattr(alert, "created_at", None) else now

    # Aggregate key discriminators into a human-readable message so
    # search `query` (ilike over message/raw_log/hostname) matches.
    bits = [f"[{alert.severity}]", alert.title or ""]
    if alert.source_ip:
        bits.append(f"src={alert.source_ip}")
    if alert.destination_ip:
        bits.append(f"dst={alert.destination_ip}")
    if alert.username:
        bits.append(f"user={alert.username}")
    if alert.hostname:
        bits.append(f"host={alert.hostname}")
    message = " ".join(b for b in bits if b)

    # raw_log reproduces the event as a JSON-CEF-style string so rule
    # engines can ilike-match against it if the parsed fields don't
    # match by name.
    raw_payload = {
        "type": "alert",
        "alert_id": alert.id,
        "source": alert.source,
        "title": alert.title,
        "severity": alert.severity,
        "category": alert.category,
        "alert_type": alert.alert_type,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "hostname": alert.hostname,
        "username": alert.username,
        "file_hash": alert.file_hash,
        "url": alert.url,
        "domain": alert.domain,
    }
    raw_log = json.dumps({k: v for k, v in raw_payload.items() if v is not None})

    parsed_fields = {
        "alert_id": alert.id,
        "alert_source": alert.source,
        "alert_type": alert.alert_type,
        "category": alert.category,
        "severity": alert.severity,
        "status": alert.status,
        "confidence": alert.confidence,
        "priority": alert.priority,
    }

    tags: list[str] = []
    # Preserve analyst-supplied tags from the alert (JSON string column).
    if alert.tags:
        try:
            raw_tags = json.loads(alert.tags)
            if isinstance(raw_tags, list):
                tags = [str(t) for t in raw_tags]
        except (json.JSONDecodeError, TypeError):
            tags = []

    return {
        "id": str(uuid.uuid4()),
        "timestamp": created_at,
        "received_at": now,
        "source_type": "alert",
        "source_name": (alert.source or "manual") + "-alert",
        "source_ip": alert.source_ip or "0.0.0.0",
        "log_type": "security",
        "severity": (alert.severity or "medium").lower(),
        "raw_log": raw_log,
        "parsed_fields": json.dumps(parsed_fields),
        "normalized_fields": None,
        "message": message,
        "source_address": alert.source_ip,
        "destination_address": alert.destination_ip,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "username": alert.username,
        "hostname": alert.hostname,
        "process_name": None,
        "action": alert.alert_type or "alert",
        "outcome": None,
        "rule_matches": None,
        "tags": json.dumps(tags) if tags else None,
        "organization_id": alert.organization_id,
        "partition_key": created_at[:10],
    }


def _audit_to_log_row(audit: AuditLog) -> dict[str, Any]:
    """Project an AuditLog row into a log_entries row dict."""
    now = datetime.now(timezone.utc).isoformat()
    created_at = audit.created_at.isoformat() if getattr(audit, "created_at", None) else now

    action = (audit.action or "unknown").lower()
    success = bool(getattr(audit, "success", True))

    bits = [
        f"audit.{action}",
        f"resource={audit.resource_type}",
    ]
    if audit.resource_id:
        bits.append(f"id={audit.resource_id}")
    if audit.user_id:
        bits.append(f"user_id={audit.user_id}")
    if audit.ip_address:
        bits.append(f"src_ip={audit.ip_address}")
    if not success:
        bits.append("outcome=failure")
    if audit.description:
        bits.append(f"desc={audit.description[:200]}")
    message = " ".join(bits)

    raw_payload = {
        "type": "audit",
        "audit_id": audit.id,
        "action": audit.action,
        "resource_type": audit.resource_type,
        "resource_id": audit.resource_id,
        "user_id": audit.user_id,
        "ip_address": audit.ip_address,
        "success": success,
        "description": audit.description,
        "error_message": audit.error_message,
    }
    raw_log = json.dumps({k: v for k, v in raw_payload.items() if v is not None})

    parsed_fields = {
        "audit_id": audit.id,
        "action": audit.action,
        "resource_type": audit.resource_type,
        "resource_id": audit.resource_id,
        "user_id": audit.user_id,
        "success": success,
    }

    mitre = _AUDIT_MITRE_MAP.get(action, [])
    tags = [f"audit:{action}"] + [f"mitre:{t}" for t in mitre]

    return {
        "id": str(uuid.uuid4()),
        "timestamp": created_at,
        "received_at": now,
        "source_type": "audit",
        "source_name": "pysoar-audit",
        "source_ip": audit.ip_address or "0.0.0.0",
        "log_type": _log_type_from_audit(action),
        "severity": _severity_from_audit(audit),
        "raw_log": raw_log,
        "parsed_fields": json.dumps(parsed_fields),
        "normalized_fields": None,
        "message": message,
        "source_address": audit.ip_address,
        "destination_address": None,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "username": None,  # audit stores user_id, not username
        "hostname": None,
        "process_name": None,
        "action": audit.action,
        "outcome": "success" if success else "failure",
        "rule_matches": None,
        "tags": json.dumps(tags) if tags else None,
        "organization_id": None,
        "partition_key": created_at[:10],
    }


# --------------------------------------------------------------------------- #
# Mapper event listeners
# --------------------------------------------------------------------------- #


def _insert_log_row(connection, row: dict[str, Any]) -> None:
    """INSERT a row into log_entries using a sync connection."""
    try:
        stmt = text(
            """
            INSERT INTO log_entries (
                id, timestamp, received_at, source_type, source_name, source_ip,
                log_type, severity, raw_log, parsed_fields, normalized_fields,
                message, source_address, destination_address, source_port,
                destination_port, protocol, username, hostname, process_name,
                action, outcome, rule_matches, tags, organization_id,
                partition_key, created_at, updated_at
            ) VALUES (
                :id, :timestamp, :received_at, :source_type, :source_name, :source_ip,
                :log_type, :severity, :raw_log, :parsed_fields, :normalized_fields,
                :message, :source_address, :destination_address, :source_port,
                :destination_port, :protocol, :username, :hostname, :process_name,
                :action, :outcome, :rule_matches, :tags, :organization_id,
                :partition_key, NOW(), NOW()
            )
            """
        )
        connection.execute(stmt, row)
    except Exception as exc:
        # Never let a mirror failure break the source transaction.
        logger.error("SIEM mirror insert failed: %s", exc, exc_info=True)


def _insert_derived_alert(connection, audit: AuditLog, match) -> Optional[str]:
    """Create an Alert derived from a rule match on a mirrored audit event.

    Runs inside the audit-log transaction so the derived alert is atomic
    with the audit write. Returns the new alert id, or None on error.
    """
    try:
        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        title = f"Detection: {match.rule_title}"
        description = (
            f"Rule '{match.rule_title}' matched an audit event: "
            f"action={audit.action} resource={audit.resource_type}"
            f" user_id={audit.user_id} src_ip={audit.ip_address or 'unknown'}"
        )
        raw_data = json.dumps({
            "rule_id": match.rule_id,
            "rule_title": match.rule_title,
            "audit_id": audit.id,
            "action": audit.action,
            "resource_type": audit.resource_type,
            "resource_id": audit.resource_id,
            "mitre_techniques": match.mitre_techniques or [],
        })
        tags = json.dumps(match.mitre_techniques) if match.mitre_techniques else None
        connection.execute(
            text(
                """
                INSERT INTO alerts (
                    id, title, description, severity, status, source,
                    source_id, alert_type, category, priority, confidence,
                    raw_data, source_ip, username, tags,
                    created_at, updated_at
                ) VALUES (
                    :id, :title, :description, :severity, 'new', 'siem',
                    :source_id, 'detection_rule', 'siem_detection', 3, 80,
                    :raw_data, :source_ip, :username, :tags,
                    NOW(), NOW()
                )
                """
            ),
            {
                "id": alert_id,
                "title": title,
                "description": description,
                "severity": match.severity or "medium",
                "source_id": audit.id,
                "raw_data": raw_data,
                "source_ip": audit.ip_address,
                "username": None,
                "tags": tags,
            },
        )
        # Raw-SQL insert bypasses the mapper event, so mirror this alert
        # into log_entries explicitly so it shows up in SIEM search.
        now_iso = now.isoformat()
        log_row = {
            "id": str(uuid.uuid4()),
            "timestamp": now_iso,
            "received_at": now_iso,
            "source_type": "alert",
            "source_name": "siem-alert",
            "source_ip": audit.ip_address or "0.0.0.0",
            "log_type": "security",
            "severity": (match.severity or "medium").lower(),
            "raw_log": raw_data,
            "parsed_fields": json.dumps({
                "alert_id": alert_id,
                "alert_source": "siem",
                "alert_type": "detection_rule",
                "rule_id": match.rule_id,
                "rule_title": match.rule_title,
            }),
            "normalized_fields": None,
            "message": f"[{match.severity or 'medium'}] {title}",
            "source_address": audit.ip_address,
            "destination_address": None,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "username": None,
            "hostname": None,
            "process_name": None,
            "action": "detection_rule",
            "outcome": None,
            "rule_matches": json.dumps([match.rule_id]),
            "tags": tags,
            "organization_id": None,
            "partition_key": now_iso[:10],
        }
        _insert_log_row(connection, log_row)
        # Bump the rule match_count so the Rules page reflects real hits.
        connection.execute(
            text(
                """
                UPDATE detection_rules
                SET match_count = COALESCE(match_count, 0) + 1,
                    last_matched_at = :ts
                WHERE name = :name
                """
            ),
            {"ts": now.isoformat(), "name": match.rule_id},
        )
        return alert_id
    except Exception as exc:
        logger.error("derived alert insert failed: %s", exc, exc_info=True)
        return None


def _eval_rules_on_mirrored_audit(connection, audit: AuditLog, row: dict[str, Any]) -> None:
    """Evaluate the SIEM RuleEngine against a mirrored audit event.

    Creates a derived Alert for every rule that matches so real-time
    detection works without requiring the AuditLog caller to opt in.
    Skipped silently if the engine has no rules loaded yet — rules
    stream in the first time a log is evaluated through the HTTP
    pipeline, and once the in-process RuleEngine is warm, subsequent
    audit events evaluate synchronously here.
    """
    try:
        from src.siem.engine_manager import get_rule_engine
        engine = get_rule_engine()
        if not engine.rules:
            return  # Cold engine — skip; pipeline will warm it on next ingest

        eval_fields = {
            "source_type": row["source_type"],
            "source_name": row["source_name"],
            "source_ip": row["source_ip"],
            "log_type": row["log_type"],
            "severity": row["severity"],
            "message": row["message"],
            "raw_log": row["raw_log"],
            "action": row["action"],
            "outcome": row["outcome"],
            "source_address": row["source_address"],
            "username": row["username"],
            "hostname": row["hostname"],
        }
        # Include parsed audit fields for field-based matching.
        if row.get("parsed_fields"):
            try:
                parsed = json.loads(row["parsed_fields"])
                if isinstance(parsed, dict):
                    # Don't clobber core fields above; only add what's new.
                    for k, v in parsed.items():
                        eval_fields.setdefault(k, v)
            except (json.JSONDecodeError, TypeError):
                pass

        matches = engine.evaluate_log(eval_fields)
        if not matches:
            return

        new_alert_ids: list[str] = []
        for m in matches:
            aid = _insert_derived_alert(connection, audit, m)
            if aid:
                new_alert_ids.append(aid)

        if new_alert_ids:
            # Record the matching rule IDs on the mirrored log entry so
            # the SIEM UI shows "rule_matches" was populated for this log.
            try:
                connection.execute(
                    text(
                        "UPDATE log_entries SET rule_matches = :m WHERE id = :id"
                    ),
                    {
                        "m": json.dumps([m.rule_id for m in matches]),
                        "id": row["id"],
                    },
                )
            except Exception as exc:
                logger.warning("log_entries.rule_matches update failed: %s", exc)
    except Exception as exc:
        logger.error("rule eval on mirrored audit failed: %s", exc, exc_info=True)


def _on_alert_after_insert(mapper, connection, target: Alert) -> None:
    row = _alert_to_log_row(target)
    _insert_log_row(connection, row)


def _on_audit_after_insert(mapper, connection, target: AuditLog) -> None:
    row = _audit_to_log_row(target)
    _insert_log_row(connection, row)
    _eval_rules_on_mirrored_audit(connection, target, row)


_REGISTERED = False


def register_mirror_listeners() -> None:
    """Attach mirror listeners to Alert + AuditLog mappers exactly once."""
    global _REGISTERED
    if _REGISTERED:
        return

    event.listen(Alert, "after_insert", _on_alert_after_insert)
    event.listen(AuditLog, "after_insert", _on_audit_after_insert)
    _REGISTERED = True
    logger.info("SIEM log mirror listeners registered for Alert and AuditLog")


# --------------------------------------------------------------------------- #
# Backfill
# --------------------------------------------------------------------------- #


async def backfill_from_history(db, limit_per_source: int = 5000) -> dict[str, int]:
    """Copy existing Alert and AuditLog rows into log_entries.

    Idempotent: skips rows that already have a log_entries mirror, keyed by
    the source id embedded in parsed_fields.

    Args:
        db: AsyncSession
        limit_per_source: max rows to copy from each of Alert / AuditLog.

    Returns:
        dict with per-source counts: ``{"alerts_mirrored": N, "audits_mirrored": N}``.
    """
    from sqlalchemy.ext.asyncio import AsyncSession
    assert isinstance(db, AsyncSession), "backfill_from_history requires AsyncSession"

    alerts_mirrored = 0
    audits_mirrored = 0

    # --- Alerts ---
    # Pull IDs we've already mirrored so we don't duplicate.
    existing_alert_ids_res = await db.execute(
        select(LogEntry.parsed_fields)
        .where(LogEntry.source_type == "alert")
    )
    existing_alert_ids: set[str] = set()
    for row in existing_alert_ids_res.scalars().all():
        if not row:
            continue
        try:
            pf = json.loads(row)
            aid = pf.get("alert_id") if isinstance(pf, dict) else None
            if aid:
                existing_alert_ids.add(aid)
        except (json.JSONDecodeError, TypeError):
            continue

    alerts_res = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(limit_per_source)
    )
    alerts = alerts_res.scalars().all()

    for alert in alerts:
        if alert.id in existing_alert_ids:
            continue
        row = _alert_to_log_row(alert)
        log_entry = LogEntry(
            id=row["id"],
            timestamp=row["timestamp"],
            received_at=row["received_at"],
            source_type=row["source_type"],
            source_name=row["source_name"],
            source_ip=row["source_ip"],
            log_type=row["log_type"],
            severity=row["severity"],
            raw_log=row["raw_log"],
            parsed_fields=row["parsed_fields"],
            normalized_fields=row["normalized_fields"],
            message=row["message"],
            source_address=row["source_address"],
            destination_address=row["destination_address"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            protocol=row["protocol"],
            username=row["username"],
            hostname=row["hostname"],
            process_name=row["process_name"],
            action=row["action"],
            outcome=row["outcome"],
            rule_matches=row["rule_matches"],
            tags=row["tags"],
            organization_id=row["organization_id"],
            partition_key=row["partition_key"],
        )
        db.add(log_entry)
        alerts_mirrored += 1

    # --- Audit logs ---
    existing_audit_ids_res = await db.execute(
        select(LogEntry.parsed_fields)
        .where(LogEntry.source_type == "audit")
    )
    existing_audit_ids: set[str] = set()
    for row in existing_audit_ids_res.scalars().all():
        if not row:
            continue
        try:
            pf = json.loads(row)
            aid = pf.get("audit_id") if isinstance(pf, dict) else None
            if aid:
                existing_audit_ids.add(aid)
        except (json.JSONDecodeError, TypeError):
            continue

    audits_res = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit_per_source)
    )
    audits = audits_res.scalars().all()

    for audit in audits:
        if audit.id in existing_audit_ids:
            continue
        row = _audit_to_log_row(audit)
        log_entry = LogEntry(
            id=row["id"],
            timestamp=row["timestamp"],
            received_at=row["received_at"],
            source_type=row["source_type"],
            source_name=row["source_name"],
            source_ip=row["source_ip"],
            log_type=row["log_type"],
            severity=row["severity"],
            raw_log=row["raw_log"],
            parsed_fields=row["parsed_fields"],
            normalized_fields=row["normalized_fields"],
            message=row["message"],
            source_address=row["source_address"],
            destination_address=row["destination_address"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            protocol=row["protocol"],
            username=row["username"],
            hostname=row["hostname"],
            process_name=row["process_name"],
            action=row["action"],
            outcome=row["outcome"],
            rule_matches=row["rule_matches"],
            tags=row["tags"],
            organization_id=row["organization_id"],
            partition_key=row["partition_key"],
        )
        db.add(log_entry)
        audits_mirrored += 1

    await db.flush()

    return {
        "alerts_mirrored": alerts_mirrored,
        "audits_mirrored": audits_mirrored,
    }
