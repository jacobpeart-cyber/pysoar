"""
Unified SIEM Log Processing Pipeline.

Chains together parsing, normalization, rule evaluation, correlation,
and alert generation into a single async function.
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from src.siem.parser import LogParserManager
from src.siem.normalizer import LogNormalizer
from src.siem.engine_manager import get_rule_engine, get_correlation_engine, ensure_rules_loaded
from src.siem.models import LogEntry, CorrelationEvent
from src.models.alert import Alert

logger = logging.getLogger(__name__)

# Module-level parser and normalizer (stateless, safe to reuse)
_parser = LogParserManager()
_normalizer = LogNormalizer()


async def process_log(
    raw_log: str,
    source_type: str,
    source_name: str,
    source_ip: str,
    db: AsyncSession,
    organization_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Tuple[LogEntry, List[Dict], List[Dict]]:
    """
    Process a single log through the full SIEM pipeline.

    Steps:
    1. Parse raw log (auto-detect format)
    2. Normalize extracted fields
    3. Create enriched LogEntry record
    4. Evaluate against all enabled detection rules
    5. Create Alert for each rule match
    6. Run correlation engine
    7. Create CorrelationEvent for results

    Returns:
        (log_entry, alerts_created, correlation_results)
    """
    alerts_created = []
    correlation_results = []

    # --- Step 1: Parse ---
    try:
        parsed = await _parser.parse(raw_log, source_type or "auto")
    except Exception as e:
        logger.warning(f"Parse failed, storing raw: {e}")
        parsed = {
            "parsed_fields": {},
            "source_type": source_type or "unknown",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": raw_log[:500],
        }

    parsed_fields = parsed.get("parsed_fields", {})
    detected_type = parsed.get("source_type", source_type or "unknown")
    message = parsed.get("message", raw_log[:500])
    # Some parsers explicitly set timestamp=None when the source line
    # had no parseable date (e.g. syslog header without a year). dict.get
    # only substitutes the default when the key is *missing*, so we need
    # an explicit None-check to avoid `None.isoformat()` later.
    timestamp = parsed.get("timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    # --- Step 2: Normalize ---
    try:
        normalized = _normalizer.normalize(parsed_fields, detected_type)
        norm_dict = normalized.to_dict() if hasattr(normalized, "to_dict") else {}
    except Exception as e:
        logger.warning(f"Normalize failed: {e}")
        norm_dict = {}
        normalized = None

    # Extract normalized fields
    severity = getattr(normalized, "severity", None)
    if severity and hasattr(severity, "value"):
        severity = severity.value
    severity = severity or "informational"

    log_type = getattr(normalized, "log_type", None)
    if log_type and hasattr(log_type, "value"):
        log_type = log_type.value
    log_type = log_type or "unknown"

    # --- Step 3: Create enriched LogEntry ---
    log_entry = LogEntry(
        id=str(uuid.uuid4()),
        raw_log=raw_log,
        source_type=detected_type,
        source_name=source_name or "unknown",
        source_ip=source_ip or "0.0.0.0",
        timestamp=(
            timestamp if isinstance(timestamp, str)
            else (timestamp.isoformat() if timestamp is not None else datetime.now(timezone.utc).isoformat())
        ),
        received_at=datetime.now(timezone.utc).isoformat(),
        log_type=log_type,
        severity=severity,
        message=message,
        parsed_fields=json.dumps(parsed_fields) if parsed_fields else None,
        normalized_fields=json.dumps(norm_dict) if norm_dict else None,
        source_address=norm_dict.get("source_address"),
        destination_address=norm_dict.get("destination_address"),
        source_port=norm_dict.get("source_port"),
        destination_port=norm_dict.get("destination_port"),
        protocol=norm_dict.get("protocol"),
        username=norm_dict.get("username"),
        hostname=norm_dict.get("hostname"),
        process_name=norm_dict.get("process_name"),
        action=norm_dict.get("action"),
        outcome=norm_dict.get("outcome"),
        tags=json.dumps(tags) if tags else None,
        organization_id=organization_id,
    )

    db.add(log_entry)
    await db.flush()

    # --- Step 4: Evaluate detection rules ---
    try:
        await ensure_rules_loaded(db)
        rule_engine = get_rule_engine()

        # Merge all fields for rule matching
        eval_fields = {}
        eval_fields.update(parsed_fields)
        eval_fields.update(norm_dict)
        eval_fields["raw_log"] = raw_log
        eval_fields["message"] = message
        eval_fields["source_type"] = detected_type
        eval_fields["source_name"] = source_name
        eval_fields["source_ip"] = source_ip

        matches = rule_engine.evaluate_log(eval_fields)

        if matches:
            logger.info(f"Log {log_entry.id} matched {len(matches)} rule(s)")

            # Update log entry with matches
            log_entry.rule_matches = json.dumps([m.rule_id for m in matches])

            # --- Step 5: Create alerts ---
            from sqlalchemy import select, update
            from src.siem.models import DetectionRule

            for match in matches:
                alert = Alert(
                    id=str(uuid.uuid4()),
                    title=f"Detection: {match.rule_title}",
                    description=f"Rule '{match.rule_title}' matched on log from {source_name} ({source_ip})",
                    severity=match.severity or "medium",
                    status="new",
                    source="siem",
                    source_id=log_entry.id,
                    alert_type="detection_rule",
                    source_ip=norm_dict.get("source_address") or source_ip,
                    hostname=norm_dict.get("hostname"),
                    raw_data=json.dumps(match.to_dict()),
                    tags=json.dumps(match.mitre_techniques) if match.mitre_techniques else None,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(alert)
                alerts_created.append({
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "rule_id": match.rule_id,
                    "rule_title": match.rule_title,
                })

                # Update rule match count
                try:
                    await db.execute(
                        update(DetectionRule)
                        .where(DetectionRule.name == match.rule_id)
                        .values(
                            match_count=DetectionRule.match_count + 1,
                            last_matched_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                except Exception:
                    pass  # Non-critical if rule update fails

                # Send email notification for critical/high alerts
                if match.severity in ("critical", "high"):
                    try:
                        from src.workers.tasks import send_notification_task
                        send_notification_task.delay(
                            channel="email",
                            recipients=[],  # Will use admin email from config
                            subject=f"[{match.severity.upper()}] SIEM Detection: {match.rule_title}",
                            message=f"Detection rule '{match.rule_title}' fired.\nSource: {source_name} ({source_ip})\nSeverity: {match.severity}\nLog: {raw_log[:200]}",
                        )
                    except Exception:
                        pass  # Non-critical

                # Purple Team correlation: broadcast a siem_match event
                # over the per-org agent WebSocket channel. The Purple
                # Team view listens for these and overlays them next to
                # the BAS fire events it already renders, so an analyst
                # watching a live technique execution sees detection
                # rule hits land on the same timeline in real time.
                try:
                    from src.agents.service import _agents_channel, _broadcast
                    await _broadcast(
                        _agents_channel(organization_id),
                        {
                            "type": "siem_match",
                            "rule_id": match.rule_id,
                            "rule_title": match.rule_title,
                            "severity": match.severity,
                            "mitre_techniques": match.mitre_techniques or [],
                            "source_name": source_name,
                            "source_ip": source_ip,
                            "alert_id": alert.id,
                            "log_id": log_entry.id,
                            "hostname": norm_dict.get("hostname"),
                        },
                    )
                except Exception as ws_exc:  # noqa: BLE001
                    logger.debug(f"purple team siem_match broadcast failed: {ws_exc}")

    except Exception as e:
        logger.error(f"Rule evaluation failed: {e}")

    # --- Step 6: Correlation ---
    try:
        corr_engine = get_correlation_engine()
        event_dict = {
            "event_id": log_entry.id,
            "timestamp": timestamp,
            "source_address": norm_dict.get("source_address", source_ip),
            "destination_address": norm_dict.get("destination_address"),
            "username": norm_dict.get("username"),
            "hostname": norm_dict.get("hostname"),
            "event_type": log_type,
            "action": norm_dict.get("action"),
            "outcome": norm_dict.get("outcome"),
            "severity": severity,
        }

        corr_results = corr_engine.process_event(event_dict)

        if corr_results:
            logger.info(f"Log {log_entry.id} triggered {len(corr_results)} correlation(s)")

            for corr in corr_results:
                corr_event = CorrelationEvent(
                    id=str(uuid.uuid4()),
                    name=corr.strategy_name if hasattr(corr, "strategy_name") else "correlation",
                    severity=corr.severity if hasattr(corr, "severity") else "medium",
                    status="new",
                    rule_id=corr.correlation_id if hasattr(corr, "correlation_id") else None,
                    event_count=len(corr.events) if hasattr(corr, "events") else 1,
                    source_addresses=json.dumps([source_ip]),
                    usernames=json.dumps([norm_dict.get("username", "")]),
                    hostnames=json.dumps([norm_dict.get("hostname", "")]),
                    description=corr.description if hasattr(corr, "description") else "",
                    alert_generated=corr.severity in ("high", "critical") if hasattr(corr, "severity") else False,
                    organization_id=organization_id,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(corr_event)
                correlation_results.append({
                    "id": corr_event.id,
                    "name": corr_event.name,
                    "severity": corr_event.severity,
                    "event_count": corr_event.event_count,
                })

    except Exception as e:
        logger.error(f"Correlation failed: {e}")

    await db.flush()

    return log_entry, alerts_created, correlation_results
