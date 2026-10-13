"""Backend contracts the Analytics / IncidentDetail / SIEM / Remediation pages read.

* ``/metrics/*`` is tenant-scoped and ``/metrics/incidents/mttr`` returns a
  real number (it used to call ``fromisoformat`` on a datetime and always
  return None).
* ``GET /incidents/{id}/alerts`` lists the linked alerts (IncidentResponse
  carries only ``alert_count``).
* ``PUT /siem/sources/{id}`` is a partial update, so the enable toggle that
  sends only ``{name, enabled}`` neither 422s nor wipes ``connection_config``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.models.alert import Alert
from src.models.incident import Incident


@pytest.mark.asyncio
async def test_metrics_are_tenant_scoped_and_mttr_is_real(
    client, db_session, org_a, org_b, org_a_headers, org_b_headers,
):
    now = datetime.now(timezone.utc)
    for _ in range(2):
        db_session.add(Alert(
            title="a", severity="high", source="edr", status="new",
            source_ip="10.0.0.5", organization_id=org_a.id,
        ))
    db_session.add(Alert(
        title="b", severity="low", source="edr", status="new",
        source_ip="10.9.9.9", organization_id=org_b.id,
    ))
    inc = Incident(
        title="closed", severity="high", status="closed",
        organization_id=org_a.id, resolved_at=(now + timedelta(hours=3)).isoformat(),
    )
    db_session.add(inc)
    await db_session.commit()
    await db_session.refresh(inc)
    # Pin created_at so resolution time is exactly 3h.
    inc.created_at = now
    await db_session.commit()

    resp = await client.get("/api/v1/metrics/overview", params={"days": 30}, headers=org_a_headers)
    assert resp.status_code == 200
    assert resp.json()["period"]["alerts_created"] == 2

    resp = await client.get("/api/v1/metrics/overview", params={"days": 30}, headers=org_b_headers)
    assert resp.json()["period"]["alerts_created"] == 1

    resp = await client.get("/api/v1/metrics/top-attackers", headers=org_b_headers)
    ips = [row["ip"] for row in resp.json()["top_attackers"]]
    assert ips == ["10.9.9.9"]
    assert resp.json()["top_attackers"][0]["alert_count"] == 1

    resp = await client.get("/api/v1/metrics/incidents/mttr", headers=org_a_headers)
    body = resp.json()
    assert body["incidents_analyzed"] == 1
    assert body["mttr_hours"] == pytest.approx(3.0, abs=0.05)

    resp = await client.get("/api/v1/metrics/incidents/mttr", headers=org_b_headers)
    assert resp.json()["mttr_hours"] is None


@pytest.mark.asyncio
async def test_incident_alerts_route_lists_linked_alerts_only_for_owner(
    client, db_session, org_a, org_a_headers, org_b_headers,
):
    inc = Incident(title="i", severity="high", status="open", organization_id=org_a.id)
    db_session.add(inc)
    await db_session.commit()
    await db_session.refresh(inc)
    linked = Alert(title="linked", severity="high", source="edr", status="new",
                   organization_id=org_a.id, incident_id=inc.id)
    other = Alert(title="other", severity="high", source="edr", status="new",
                  organization_id=org_a.id)
    db_session.add_all([linked, other])
    await db_session.commit()

    resp = await client.get(f"/api/v1/incidents/{inc.id}/alerts", headers=org_a_headers)
    assert resp.status_code == 200
    assert [a["title"] for a in resp.json()] == ["linked"]

    resp = await client.get(f"/api/v1/incidents/{inc.id}/alerts", headers=org_b_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_siem_source_toggle_is_partial_update(client, db_session, org_a, org_a_admin_headers):
    from src.siem.models import SIEMDataSource

    src = SIEMDataSource(
        name="fw", source_type="syslog", enabled=True,
        connection_config=json.dumps({"host": "10.0.0.1"}), organization_id=org_a.id,
    )
    db_session.add(src)
    await db_session.commit()
    await db_session.refresh(src)

    resp = await client.put(
        f"/api/v1/siem/sources/{src.id}", json={"name": "fw", "enabled": False}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False

    await db_session.refresh(src)
    assert json.loads(src.connection_config) == {"host": "10.0.0.1"}
    assert src.source_type == "syslog"


async def _execution(db_session, org_id: str, *, trigger_source: str, approval_status=None):
    from src.remediation.models import RemediationExecution

    ex = RemediationExecution(
        trigger_source=trigger_source, trigger_details={}, status="awaiting_approval",
        approval_status=approval_status, target_entity="10.1.1.1", target_type="ip",
        actions_planned=[], actions_completed=[], organization_id=org_id,
    )
    db_session.add(ex)
    await db_session.commit()
    await db_session.refresh(ex)
    return ex


@pytest.mark.asyncio
async def test_reject_binds_approver_to_caller_not_body(
    client, db_session, org_a, org_a_admin, org_a_admin_headers,
):
    # Approve/reject is admin-only (wave 1 role gates).
    admin_id = org_a_admin.id
    ex = await _execution(db_session, org_a.id, trigger_source="alert", approval_status="pending")
    resp = await client.post(
        f"/api/v1/remediation/executions/{ex.id}/reject",
        json={"approver_id": "someone-else", "reason": "false positive"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(ex)
    assert ex.approved_by == admin_id
    assert ex.approval_status == "rejected"


@pytest.mark.asyncio
async def test_quick_actions_list_includes_quick_action_rows(client, db_session, org_a, org_a_headers):
    await _execution(db_session, org_a.id, trigger_source="manual_quick_action")
    resp = await client.get("/api/v1/remediation/quick-actions", headers=org_a_headers)
    assert resp.status_code == 200
    assert [r["trigger_source"] for r in resp.json()] == ["manual_quick_action"]


@pytest.mark.asyncio
async def test_quarantine_requires_hostname(client, org_a_admin_headers):
    # Quick containment actions are admin-only (wave 1 role gates).
    resp = await client.post(
        "/api/v1/remediation/quarantine-file",
        json={"file_path": "C:/evil.exe", "host": "ws-01"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 400
