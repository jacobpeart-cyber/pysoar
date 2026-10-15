"""Wave 4 (W4-E): DLP policies evaluated over data the platform holds.

Policies resolve to ``active`` (evaluated by the content scanner) or
``inactive`` with the reason; the bounded scan walks stored log entries,
evidence, ticket comments and incident text from a per-org cursor and
writes one finding per (policy, record) with the location and a redacted
excerpt; re-scans never duplicate; tenants never see each other's content;
the scan route is admin-only and audited; the test route evaluates the
policy's own patterns and accepts ``sample_text``; the beat task is
registered with a wall clock.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.dlp.models import DLPPolicy, DLPScanCursor, DLPViolation
from src.dlp.scanner import plan_policy, redacted_excerpt, find_matches
from src.dlp.tasks import _content_scan_sweep
from src.models.audit import AuditLog
from src.models.incident import Incident
from src.siem.models import LogEntry
from src.workers.celery_app import celery_app

BASE = "/api/v1/dlp"
SSN = "123-45-6789"


def _log(org_id: str, text: str, username: str = "jdoe") -> LogEntry:
    now = datetime.now(timezone.utc).isoformat()
    return LogEntry(
        id=str(uuid.uuid4()), timestamp=now, received_at=now, source_type="syslog",
        source_name="app", source_ip="192.0.2.10", log_type="application", severity="low",
        raw_log=text, message=text, username=username, organization_id=org_id,
    )


async def _policy(client: AsyncClient, headers: dict[str, str], **body: Any) -> dict[str, Any]:
    payload = {"name": f"pol-{uuid.uuid4().hex[:6]}", "policy_type": "pii_detection", "severity": "high"}
    payload.update(body)
    resp = await client.post(f"{BASE}/policies", json=payload, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# planning: active / inactive with the reason
# ---------------------------------------------------------------------------

def test_plan_states() -> None:
    p = DLPPolicy(name="a", policy_type="pii_detection", enabled=True, data_patterns='["ssn"]',
                  channels_monitored='["logs"]', organization_id="o")
    plan = plan_policy(p)
    assert plan.status == "active" and plan.sources == ["log_entries"]

    email_only = DLPPolicy(name="b", policy_type="pii_detection", enabled=True,
                           channels_monitored='["email"]', organization_id="o")
    plan = plan_policy(email_only)
    assert plan.status == "inactive" and "email" in plan.reason

    exfil = DLPPolicy(name="c", policy_type="exfiltration_prevention", enabled=True, organization_id="o")
    plan = plan_policy(exfil)
    assert plan.status == "inactive" and "transfer events" in plan.reason

    disabled = DLPPolicy(name="d", policy_type="pii_detection", enabled=False, organization_id="o")
    assert plan_policy(disabled).reason == "policy is disabled"


def test_excerpt_redacts_every_match_and_other_secrets() -> None:
    p = DLPPolicy(name="a", policy_type="custom_pattern", enabled=True, data_patterns='["ssn"]',
                  organization_id="o")
    plan = plan_policy(p)
    text = f"user ssn {SSN} and key AKIAABCDEFGHIJKLMNOP and again 987-65-4321"
    hits = find_matches(plan, text)
    excerpt = redacted_excerpt(text, hits)
    assert SSN not in excerpt and "987-65-4321" not in excerpt
    assert "AKIAABCDEFGHIJKLMNOP" not in excerpt
    assert "[REDACTED:ssn]" in excerpt and "[REDACTED:aws_key]" in excerpt


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_reports_evaluation_status_and_rejects_bad_regex(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    active = await _policy(client, org_a_admin_headers, data_patterns=["ssn"], channels_monitored=["logs"])
    assert active["evaluation_status"] == "active"
    inactive = await _policy(client, org_a_admin_headers, policy_type="exfiltration_prevention")
    assert inactive["evaluation_status"] == "inactive" and inactive["evaluation_reason"]

    bad = await client.post(f"{BASE}/policies", json={"name": "bad", "data_patterns": ["(unclosed"]},
                            headers=org_a_admin_headers)
    assert bad.status_code == 422
    assert bad.json()["detail"]["error"] == "invalid_pattern"


@pytest.mark.asyncio
async def test_policy_test_uses_own_patterns_and_sample_text(
    client: AsyncClient, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str],
) -> None:
    pol = await _policy(client, org_a_admin_headers, policy_type="custom_pattern",
                        data_patterns=[r"PROJ-\d{4}"])
    resp = await client.post(f"{BASE}/policies/{pol['id']}/test",
                             json={"sample_text": f"leak PROJ-1234 and {SSN}"}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Only the policy's own pattern counts; the global SSN detector does not.
    assert body["matched_patterns"] == [r"custom:PROJ-\d{4}"]
    assert body["violations_detected"] == 1 and body["test_passed"] is False
    assert "PROJ-1234" not in body["redacted_excerpt"] and SSN not in body["redacted_excerpt"]


@pytest.mark.asyncio
async def test_content_scan_creates_redacted_findings_once_and_stays_in_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a,
    org_b,
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    pol = await _policy(client, org_a_admin_headers, data_patterns=["ssn"],
                        channels_monitored=["logs", "cases"])
    hit_log = _log(org_a_id, f"customer record ssn={SSN} exported")
    clean_log = _log(org_a_id, "nothing sensitive here")
    other_tenant = _log(org_b_id, f"tenant b ssn={SSN}")
    incident = Incident(id=str(uuid.uuid4()), title="Leak", description=f"pasted {SSN} in chat",
                        severity="high", status="open", organization_id=org_a_id)
    db_session.add_all([hit_log, clean_log, other_tenant, incident])
    hit_id, other_id, incident_id = hit_log.id, other_tenant.id, incident.id
    await db_session.commit()

    run = await client.post(f"{BASE}/scan/run", headers=org_a_admin_headers)
    assert run.status_code == 200, run.text
    summary = run.json()
    assert summary["policies_active"] == 1
    assert summary["sources"]["log_entries"]["rows_scanned"] == 2
    assert summary["findings_created"] == 2

    rows = (await db_session.execute(
        select(DLPViolation).where(DLPViolation.organization_id == org_a_id)
    )).scalars().all()
    by_source = {r.source_type: r for r in rows}
    assert set(by_source) == {"log_entries", "incidents"}
    log_finding = by_source["log_entries"]
    assert log_finding.policy_id == pol["id"] and log_finding.source_id == hit_id
    assert log_finding.detected_by == "content_scan" and log_finding.location.startswith("log_entries/")
    assert SSN not in log_finding.redacted_excerpt and "[REDACTED:ssn]" in log_finding.redacted_excerpt
    assert by_source["incidents"].source_id == incident_id
    assert other_id not in {r.source_id for r in rows}
    b_rows = (await db_session.execute(
        select(func.count(DLPViolation.id)).where(DLPViolation.organization_id == org_b_id)
    )).scalar()
    assert b_rows == 0

    # Re-scan from scratch: nothing duplicated.
    again = await client.post(f"{BASE}/scan/run", params={"rescan": "true"}, headers=org_a_admin_headers)
    assert again.status_code == 200 and again.json()["findings_created"] == 0
    total = (await db_session.execute(
        select(func.count(DLPViolation.id)).where(DLPViolation.organization_id == org_a_id)
    )).scalar()
    assert total == 2

    status = (await client.get(f"{BASE}/scan/status", headers=org_a_admin_headers)).json()
    logs = next(s for s in status["sources"] if s["source_type"] == "log_entries")
    assert logs["rows_scanned_total"] == 4 and logs["findings_total"] == 1
    assert status["policies"][0]["evaluation_status"] == "active"

    # Findings are listed with their location; org B cannot read them.
    listed = (await client.get(f"{BASE}/violations", params={"detected_by": "content_scan"},
                               headers=org_a_admin_headers)).json()
    assert listed["total"] == 2 and all(i["redacted_excerpt"] for i in listed["items"])
    other = await client.get(f"{BASE}/violations/{log_finding.id}", headers=org_b_headers)
    assert other.status_code in (403, 404)

    audits = (await db_session.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "dlp.content_scan")
    )).scalar()
    assert audits == 2


@pytest.mark.asyncio
async def test_scan_run_is_admin_only(
    client: AsyncClient, org_a_headers: dict[str, str], viewer_headers: dict[str, str],
) -> None:
    for headers in (org_a_headers, viewer_headers):
        assert (await client.post(f"{BASE}/scan/run", headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_sweep_task_scans_orgs_with_enabled_policies(
    db_session: AsyncSession, org_a,
) -> None:
    org_a_id = org_a.id
    db_session.add(DLPPolicy(name="p", policy_type="pii_detection", enabled=True,
                             data_patterns='["ssn"]', channels_monitored='["logs"]',
                             organization_id=org_a_id))
    db_session.add(_log(org_a_id, f"ssn {SSN}"))
    await db_session.commit()

    result = await _content_scan_sweep()
    assert result["organizations"] == 1 and result["findings_created"] == 1 and not result["failures"]
    cursor = (await db_session.execute(
        select(DLPScanCursor).where(DLPScanCursor.organization_id == org_a_id,
                                    DLPScanCursor.source_type == "log_entries")
    )).scalar_one()
    assert cursor.rows_scanned_total == 1 and cursor.last_id


def test_beat_entry_and_wall_clock() -> None:
    tasks = {cfg["task"] for cfg in celery_app.conf.beat_schedule.values()}
    assert "src.dlp.tasks.dlp_content_scan_sweep" in tasks
    limits = celery_app.conf.task_annotations["src.dlp.tasks.dlp_content_scan_sweep"]
    assert limits["soft_time_limit"] <= 900 and limits["time_limit"] > limits["soft_time_limit"]
