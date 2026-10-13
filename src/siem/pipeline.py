"""
Unified SIEM Log Processing Pipeline.

Chains together parsing, normalization, rule evaluation, correlation,
and alert generation into a single async function.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import or_, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.siem.correlation import CorrelationResult
from src.siem.parser import LogParserManager
from src.siem.normalizer import LogNormalizer
from src.siem.engine_manager import get_rule_engine, get_correlation_engine, ensure_rules_loaded
from src.siem.models import CorrelationEvent, CorrelationStatus, DetectionRule, LogEntry
from src.models.alert import Alert

logger = get_logger(__name__)

# Module-level parser and normalizer (stateless, safe to reuse)
_parser = LogParserManager()
_normalizer = LogNormalizer()


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational", "info"}


def _distinct_values(events: List[dict], field_name: str) -> List[str]:
    return sorted({str(e[field_name]) for e in events if e.get(field_name)})


def build_correlation_event(
    corr: CorrelationResult, organization_id: Optional[str]
) -> CorrelationEvent:
    """Map an in-memory ``CorrelationResult`` onto a valid ``CorrelationEvent`` row.

    Every NOT NULL column of the model is set (``correlation_id``, ``name``,
    ``severity``, ``timespan_start``, ``timespan_end``, ``event_count``,
    ``status``). ``rule_id`` stays NULL: it is a foreign key to
    ``detection_rules.id`` and strategy correlations are not rule-backed.
    ``alert_generated`` stays False because this path does not create an
    alert for the correlation. The row carries the log's organisation.
    """
    events = list(corr.events or [])
    severity = getattr(corr.severity, "value", corr.severity) or "medium"
    return CorrelationEvent(
        id=str(uuid.uuid4()),
        correlation_id=corr.correlation_id,
        name=corr.strategy_name or "correlation",
        description=corr.description or "",
        severity=str(severity),
        rule_id=None,
        log_entry_ids=json.dumps([e["event_id"] for e in events if e.get("event_id")]),
        source_addresses=json.dumps(_distinct_values(events, "source_address")),
        usernames=json.dumps(_distinct_values(events, "username")),
        hostnames=json.dumps(_distinct_values(events, "hostname")),
        timespan_start=corr.timespan_start.isoformat(),
        timespan_end=corr.timespan_end.isoformat(),
        event_count=len(events) or 1,
        mitre_tactics=json.dumps(list(corr.mitre_chain)) if corr.mitre_chain else None,
        alert_generated=False,
        status=CorrelationStatus.NEW.value,
        organization_id=organization_id,
    )


async def process_log(
    raw_log: str,
    source_type: str,
    source_name: str,
    source_ip: str,
    db: AsyncSession,
    organization_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    severity: Optional[str] = None,
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

    Tenancy: rules are evaluated with ``organization_id``'s engine (its own
    rules plus platform rules) and correlation uses that organisation's
    buffers only; every row written carries ``organization_id``.

    Failure isolation: all writes for this log run inside a SAVEPOINT, so a
    failure rolls back only this log and re-raises, leaving the caller's
    session usable for the rest of a batch. Each correlation insert has its
    own nested SAVEPOINT: a bad correlation row is logged and skipped
    without losing the log entry or its alerts.

    Returns:
        (log_entry, alerts_created, correlation_results)
    """
    alerts_created = []
    correlation_results = []

    # --- Step 1: Parse ---
    try:
        parsed = await _parser.parse(raw_log, source_type or "auto")
    except Exception as e:
        logger.warning("Parse failed, storing raw", error=str(e))
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
        logger.warning("Normalize failed", error=str(e))
        norm_dict = {}
        normalized = None

    # Caller-supplied severity wins for structured sources that already
    # know it (e.g. the Windows forwarder maps event Level -> severity).
    # Captured before the local `severity` is reassigned by derivation.
    severity_override = severity

    # Extract normalized fields
    severity = getattr(normalized, "severity", None)
    if severity and hasattr(severity, "value"):
        severity = severity.value
    severity = severity or "informational"

    if severity_override and str(severity_override).lower() in _VALID_SEVERITIES:
        sev = str(severity_override).lower()
        severity = "informational" if sev == "info" else sev

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

    async with db.begin_nested():
        await _persist_and_detect(
            db,
            log_entry,
            raw_log=raw_log,
            message=message,
            detected_type=detected_type,
            source_name=source_name,
            source_ip=source_ip,
            log_type=log_type,
            severity=severity,
            parsed_fields=parsed_fields,
            norm_dict=norm_dict,
            organization_id=organization_id,
            alerts_created=alerts_created,
            correlation_results=correlation_results,
        )

    return log_entry, alerts_created, correlation_results



async def _persist_and_detect(
    db: AsyncSession,
    log_entry: LogEntry,
    *,
    raw_log: str,
    message: Optional[str],
    detected_type: str,
    source_name: str,
    source_ip: str,
    log_type: str,
    severity: str,
    parsed_fields: Dict,
    norm_dict: Dict,
    organization_id: Optional[str],
    alerts_created: List[Dict],
    correlation_results: List[Dict],
) -> None:
    """Steps 3-7 of ``process_log``; runs inside the caller's SAVEPOINT."""
    db.add(log_entry)
    await db.flush()

    # --- Step 4: Evaluate detection rules (this organisation's engine) ---
    await ensure_rules_loaded(db, organization_id)
    try:
        rule_engine = get_rule_engine(organization_id)

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
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        logger.error(
            "Rule evaluation failed",
            log_id=log_entry.id,
            organization_id=organization_id,
            error=str(e),
        )
        matches = []

    if matches:
        logger.info(
            "Log matched detection rules",
            log_id=log_entry.id,
            matches=len(matches),
            organization_id=organization_id,
        )
        log_entry.rule_matches = json.dumps([m.rule_id for m in matches])

        # Only the counters of rules owned by the log's organisation are
        # bumped: never a same-named rule in another tenant, and not the
        # shared platform (NULL-org) rows either, whose counters every
        # tenant can read and would otherwise reveal other tenants'
        # activity. Per-tenant hits of platform rules are the alerts above.
        rule_owner = (
            DetectionRule.organization_id.is_(None)
            if organization_id is None
            else DetectionRule.organization_id == organization_id
        )

        # --- Step 5: Create alerts (carry the log's organisation) ---
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
                # Carry tenant scope from the log so the per-org
                # autonomous investigator (auto_triage) picks it up, also
                # when the matching rule is a platform (NULL-org) rule.
                organization_id=organization_id,
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

            try:
                async with db.begin_nested():
                    await db.execute(
                        update(DetectionRule)
                        .where(
                            or_(DetectionRule.name == match.rule_id, DetectionRule.id == match.rule_id),
                            rule_owner,
                        )
                        .values(
                            match_count=DetectionRule.match_count + 1,
                            last_matched_at=datetime.now(timezone.utc).isoformat(),
                        )
                        .execution_options(synchronize_session=False)
                    )
            except SQLAlchemyError as exc:
                logger.warning("Rule match count update failed", rule_id=match.rule_id, error=str(exc))

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
                except Exception as exc:  # noqa: BLE001 - a broker outage must not drop the log
                    logger.warning("SIEM detection notification not queued", error=str(exc))

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
                logger.debug("purple team siem_match broadcast failed", error=str(ws_exc))

        await db.flush()

    # --- Step 6: Correlation (this organisation's buffers only) ---
    event_dict = {
        "event_id": log_entry.id,
        "timestamp": log_entry.timestamp,
        "source_address": norm_dict.get("source_address", source_ip),
        "destination_address": norm_dict.get("destination_address"),
        "username": norm_dict.get("username"),
        "hostname": norm_dict.get("hostname"),
        "event_type": log_type,
        "action": norm_dict.get("action"),
        "outcome": norm_dict.get("outcome"),
        "severity": severity,
    }
    try:
        corr_results = get_correlation_engine(organization_id).process_event(event_dict)
    except (ValueError, TypeError, KeyError) as e:
        logger.error(
            "Correlation failed",
            log_id=log_entry.id,
            organization_id=organization_id,
            error=str(e),
        )
        corr_results = []

    # --- Step 7: Persist correlations, one SAVEPOINT per row ---
    for corr in corr_results:
        try:
            corr_event = build_correlation_event(corr, organization_id)
        except (AttributeError, TypeError, ValueError) as exc:
            logger.warning("Correlation result could not be mapped", error=str(exc))
            continue
        try:
            async with db.begin_nested():
                db.add(corr_event)
                await db.flush()
        except SQLAlchemyError as exc:
            logger.warning(
                "Correlation insert failed; skipped",
                correlation_id=corr_event.correlation_id,
                organization_id=organization_id,
                error=str(exc),
            )
            continue
        correlation_results.append({
            "id": corr_event.id,
            "correlation_id": corr_event.correlation_id,
            "name": corr_event.name,
            "severity": corr_event.severity,
            "event_count": corr_event.event_count,
        })
    if correlation_results:
        logger.info(
            "Log triggered correlations",
            log_id=log_entry.id,
            correlations=len(correlation_results),
            organization_id=organization_id,
        )

async def process_host_event(
    event: dict,
    db: AsyncSession,
    organization_id: Optional[str] = None,
) -> Tuple[Optional[LogEntry], List[Dict], List[Dict]]:
    """Process a structured host/EDR event dictionary.

    This accepts normalized host event types (process_start, net_conn,
    file_mod, etc.) and materializes them as a `LogEntry` so the
    existing detection and correlation pipeline can operate on them.
    Returns the created LogEntry plus any alerts/correlations produced.
    """
    try:
        raw = json.dumps(event)
    except Exception:
        raw = str(event)

    # Map common fields if present
    source_name = event.get("agent_id") or event.get("hostname") or "endpoint"
    source_ip = event.get("ip") or event.get("source_ip") or "0.0.0.0"
    event_type = event.get("event_type") or "endpoint"
    message = event.get("message") or json.dumps(event.get("meta", {}))

    # Reuse the main pipeline by delegating to process_log — this keeps
    # normalization and rule engines unified across log types.
    return await process_log(
        raw_log=raw,
        source_type="json_api",
        source_name=source_name,
        source_ip=source_ip,
        db=db,
        organization_id=organization_id,
        tags=["host_event", event_type],
    )
