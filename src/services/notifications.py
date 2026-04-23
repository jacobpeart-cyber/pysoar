"""Outbound notification dispatch for critical platform events.

Reads per-organization integration configuration from the app_settings
table (where the Settings page stores Slack/Teams/PagerDuty/OpsGenie
webhooks and keys) and pushes formatted messages on every enabled
channel.

Design principles:

1. **Best-effort**. A failed webhook never breaks the triggering
   request. We log and move on to the next channel.
2. **Per-org scoped**. Every fetch filters by the incident's
   `organization_id`; no cross-tenant spillover.
3. **Rich payloads**. Slack Block Kit + Teams MessageCard carry
   verdict, confidence, MITRE, top recommendations, and a direct link
   to the incident page. A 3 AM on-call analyst can tell what happened
   and where to go from the phone lock screen.
4. **Idempotent**. Each notification call is independent — no internal
   retries that could double-notify. Retry policy lives in the hosting
   Celery task if we ever need one.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger

logger = get_logger(__name__)

HTTP_TIMEOUT = 6.0  # seconds


async def _load_integration(
    db: AsyncSession, org_id: Optional[str], integration_id: str
) -> Optional[dict[str, Any]]:
    """Return the stored config dict for (org, integration), or None."""
    from src.models.settings import AppSetting
    section = f"integration:{integration_id}"
    stmt = select(AppSetting).where(AppSetting.section == section)
    if org_id is not None:
        stmt = stmt.where(AppSetting.organization_id == org_id)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row and isinstance(row.value, dict) and row.value:
        return row.value
    return None


def _severity_color(severity: str) -> str:
    sev = (severity or "").lower()
    return {
        "critical": "#d32f2f",
        "high": "#f57c00",
        "medium": "#fbc02d",
        "low": "#388e3c",
    }.get(sev, "#607d8b")


def _public_base_url() -> str:
    """Best-effort public URL for deep links. Overridable via env."""
    import os
    return os.environ.get("PYSOAR_PUBLIC_URL", "https://pysoar.it.com").rstrip("/")


def _format_slack_blocks(event: dict[str, Any]) -> dict[str, Any]:
    """Build a Slack Block Kit payload for an incident notification."""
    severity = event.get("severity") or "unknown"
    emoji = {"critical": ":rotating_light:", "high": ":warning:", "medium": ":bell:", "low": ":information_source:"}.get(
        severity.lower(), ":bell:"
    )
    incident_id = event.get("incident_id") or ""
    link = f"{_public_base_url()}/incidents/{incident_id}" if incident_id else _public_base_url()
    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
        {"type": "mrkdwn", "text": f"*Source*\n{event.get('trigger') or 'manual'}"},
    ]
    if event.get("verdict"):
        fields.append({"type": "mrkdwn", "text": f"*Verdict*\n{event['verdict']} ({int(event.get('confidence') or 0)}%)"})
    if event.get("mitre_techniques"):
        fields.append({"type": "mrkdwn", "text": f"*MITRE*\n{', '.join(event['mitre_techniques'][:5])}"})

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} Incident auto-opened: {event.get('title', '')[:140]}"},
        },
        {"type": "section", "fields": fields},
    ]
    if event.get("summary"):
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Summary*\n{str(event['summary'])[:2500]}"},
        })
    if event.get("recommendations"):
        rec_text = "\n".join(f"• {r}" for r in event["recommendations"][:5])
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Recommended actions* (gated on human approval)\n{rec_text}"},
        })
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Open in PySOAR"},
                "url": link,
                "style": "primary",
            }
        ],
    })
    return {"text": f"Incident: {event.get('title', '')[:200]}", "blocks": blocks}


def _format_teams_card(event: dict[str, Any]) -> dict[str, Any]:
    """Build a Teams legacy MessageCard payload (widely supported)."""
    severity = event.get("severity") or "unknown"
    incident_id = event.get("incident_id") or ""
    link = f"{_public_base_url()}/incidents/{incident_id}" if incident_id else _public_base_url()
    facts = [
        {"name": "Severity", "value": severity},
        {"name": "Source", "value": event.get("trigger") or "manual"},
    ]
    if event.get("verdict"):
        facts.append({"name": "Verdict", "value": f"{event['verdict']} ({int(event.get('confidence') or 0)}%)"})
    if event.get("mitre_techniques"):
        facts.append({"name": "MITRE", "value": ", ".join(event["mitre_techniques"][:5])})
    sections = [{"facts": facts, "markdown": True}]
    if event.get("summary"):
        sections.append({"title": "Summary", "text": str(event["summary"])[:2500], "markdown": True})
    if event.get("recommendations"):
        rec_text = "\n".join(f"- {r}" for r in event["recommendations"][:5])
        sections.append({"title": "Recommended actions (gated on human approval)", "text": rec_text, "markdown": True})

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": _severity_color(severity).lstrip("#"),
        "summary": f"Incident: {event.get('title', '')[:140]}",
        "title": f"Incident auto-opened: {event.get('title', '')[:140]}",
        "sections": sections,
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Open in PySOAR",
                "targets": [{"os": "default", "uri": link}],
            }
        ],
    }


def _format_pagerduty_event(event: dict[str, Any], integration_key: str) -> dict[str, Any]:
    """Build a PagerDuty Events API v2 trigger payload."""
    severity = (event.get("severity") or "info").lower()
    # Map PySOAR severity → PagerDuty severity
    pd_severity = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}.get(severity, "info")
    incident_id = event.get("incident_id") or event.get("investigation_id") or ""
    link = f"{_public_base_url()}/incidents/{incident_id}" if incident_id else _public_base_url()
    return {
        "routing_key": integration_key,
        "event_action": "trigger",
        # dedup_key ties repeat triggers to the same PagerDuty incident
        "dedup_key": f"pysoar:{incident_id}" if incident_id else None,
        "payload": {
            "summary": f"{event.get('title', 'Security incident')[:1024]}",
            "source": "pysoar",
            "severity": pd_severity,
            "custom_details": {
                "verdict": event.get("verdict"),
                "confidence": event.get("confidence"),
                "mitre_techniques": event.get("mitre_techniques"),
                "trigger": event.get("trigger"),
                "summary": (event.get("summary") or "")[:4000],
                "recommendations": event.get("recommendations") or [],
            },
        },
        "links": [{"href": link, "text": "Open in PySOAR"}],
        "client": "PySOAR",
        "client_url": _public_base_url(),
    }


async def _post_json(url: str, payload: dict[str, Any], *, headers: Optional[dict[str, str]] = None) -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.post(url, json=payload, headers=headers or {})
        if 200 <= r.status_code < 300:
            return True, f"{r.status_code}"
        return False, f"{r.status_code}: {r.text[:200]}"
    except httpx.HTTPError as exc:
        return False, f"http error: {exc}"


async def send_incident_notifications(
    db: AsyncSession,
    *,
    organization_id: Optional[str],
    event: dict[str, Any],
) -> dict[str, Any]:
    """Dispatch an incident notification to every enabled channel for the org.

    `event` keys used:
      title, severity, summary, trigger, incident_id,
      investigation_id, verdict, confidence, mitre_techniques,
      recommendations (list[str])

    Returns a dict summarizing per-channel send status.
    """
    results: dict[str, Any] = {"sent": [], "failed": [], "skipped": []}

    # Fire all enabled channels in parallel — a hung PagerDuty endpoint
    # shouldn't delay the Slack post.
    tasks: list[tuple[str, Any]] = []

    slack_cfg = await _load_integration(db, organization_id, "slack")
    if slack_cfg and slack_cfg.get("webhook_url"):
        tasks.append(("slack", _post_json(slack_cfg["webhook_url"], _format_slack_blocks(event))))
    elif slack_cfg is not None:
        results["skipped"].append("slack: no webhook_url")

    teams_cfg = await _load_integration(db, organization_id, "teams")
    if teams_cfg and teams_cfg.get("webhook_url"):
        tasks.append(("teams", _post_json(teams_cfg["webhook_url"], _format_teams_card(event))))
    elif teams_cfg is not None:
        results["skipped"].append("teams: no webhook_url")

    pd_cfg = await _load_integration(db, organization_id, "pagerduty")
    if pd_cfg and (pd_cfg.get("integration_key") or pd_cfg.get("api_key")):
        key = pd_cfg.get("integration_key") or pd_cfg.get("api_key")
        tasks.append((
            "pagerduty",
            _post_json(
                "https://events.pagerduty.com/v2/enqueue",
                _format_pagerduty_event(event, key),
            ),
        ))

    opsgenie_cfg = await _load_integration(db, organization_id, "opsgenie")
    if opsgenie_cfg and opsgenie_cfg.get("api_key"):
        og_payload = {
            "message": event.get("title", "Security incident")[:130],
            "description": (event.get("summary") or "")[:15000],
            "priority": {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}.get(
                (event.get("severity") or "").lower(), "P3"
            ),
            "tags": ["pysoar"] + list(event.get("mitre_techniques") or [])[:5],
            "source": "pysoar",
        }
        tasks.append((
            "opsgenie",
            _post_json(
                "https://api.opsgenie.com/v2/alerts",
                og_payload,
                headers={"Authorization": f"GenieKey {opsgenie_cfg['api_key']}"},
            ),
        ))

    if tasks:
        outcomes = await asyncio.gather(*(t[1] for t in tasks), return_exceptions=True)
        for (name, _), outcome in zip(tasks, outcomes):
            if isinstance(outcome, Exception):
                results["failed"].append(f"{name}: {outcome}")
                continue
            ok, detail = outcome
            (results["sent"] if ok else results["failed"]).append(f"{name}: {detail}")

    if not tasks:
        logger.debug("no notification channels configured for org=%s", organization_id)
    else:
        logger.info(
            "notifications dispatched org=%s sent=%s failed=%s",
            organization_id,
            len(results["sent"]),
            len(results["failed"]),
        )

    return results
