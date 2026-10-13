"""Wave 2 / W2-A: classic playbooks execute through real paths or say why not.

* containment steps go through src.services.containment (agent command queue,
  audit row) and never report a green success without an actuation;
* a failed step fails the run; awaiting_integration / queued_for_approval
  steps are recorded per step and the run is ``partial``, not ``completed``;
* run_script and unknown step types are rejected at authoring time and fail
  at run time;
* executions are pollable per playbook, tenant-scoped.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select

from src.agents.models import AgentCommand, EndpointAgent
from src.models.alert import Alert
from src.models.audit import AuditLog
from src.models.playbook import Playbook, PlaybookExecution
from src.services.playbook_engine import RUN_PARTIAL, PlaybookEngine
from tests.helpers.tenancy import assert_tenant_isolated


async def _playbook(db, org_id: str, steps: list[dict[str, Any]], *, status: str = "active") -> Playbook:
    pb = Playbook(name="W2 playbook", status=status, is_enabled=True, organization_id=org_id, steps=json.dumps(steps))
    db.add(pb)
    await db.flush()
    return pb


async def _run(db, pb: Playbook, org_id: str, user_id: str | None, input_data: dict | None = None) -> PlaybookExecution:
    ex = PlaybookExecution(
        playbook_id=pb.id, organization_id=org_id, status="pending", triggered_by=user_id,
        triggered_by_user_id=user_id, input_data=json.dumps(input_data or {}), trigger_source="manual",
    )
    db.add(ex)
    await db.commit()
    result = await PlaybookEngine(db).execute(ex.id)
    await db.commit()
    return result


def _steps(ex: PlaybookExecution) -> list[dict[str, Any]]:
    return json.loads(ex.step_results)


@pytest.mark.asyncio
async def test_isolate_host_step_queues_real_agent_command(db_session, org_a, org_a_admin):
    org_id, user_id = org_a.id, org_a_admin.id
    agent = EndpointAgent(hostname="web-01", display_name="web-01", os_type="linux", status="active",
                          capabilities=["ir"], organization_id=org_id)
    db_session.add(agent)
    pb = await _playbook(db_session, org_id, [{"name": "Isolate", "action": "isolate_host", "parameters": {"hostname": "web-01"}}])
    ex = await _run(db_session, pb, org_id, user_id)

    step = _steps(ex)[0]
    assert step["status"] == "queued_for_approval"
    assert step["started_at"] and step["finished_at"] and step["error"] is None
    cmd = await db_session.get(AgentCommand, step["result"]["details"]["command_id"])
    assert cmd.agent_id == agent.id and cmd.organization_id == org_id and cmd.status == "awaiting_approval"
    assert ex.status == RUN_PARTIAL and ex.status != "completed"
    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "containment_isolate_host", AuditLog.organization_id == org_id),
    )).scalars().one()
    assert audit.user_id == user_id
    assert json.loads(audit.new_value)["execution_ref"] == f"playbook_execution:{ex.id}"


@pytest.mark.asyncio
async def test_block_ip_without_agent_is_awaiting_integration_not_success(db_session, org_a, org_b):
    org_id = org_a.id
    db_session.add(EndpointAgent(hostname="b-01", display_name="b-01", os_type="linux", status="active",
                                 capabilities=["ir"], organization_id=org_b.id))
    pb = await _playbook(db_session, org_id, [
        {"name": "Block", "action": "block_ip", "parameters": {"ip": "{{source_ip}}"}},
        {"name": "Pause", "action": "wait", "parameters": {"seconds": 0}},
    ])
    ex = await _run(db_session, pb, org_id, None, {"source_ip": "203.0.113.5"})

    first, second = _steps(ex)
    assert first["status"] == "awaiting_integration" and first["missing_dependency"]
    assert first["result"]["details"]["target"] == "203.0.113.5"
    assert second["status"] == "completed"
    assert ex.status == RUN_PARTIAL
    assert json.loads(ex.output_data)["step_summary"] == {"awaiting_integration": 1, "completed": 1}
    assert (await db_session.execute(select(AgentCommand))).scalars().all() == []
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "containment_block_ip"))).scalars().one()
    assert audit.organization_id == org_id and json.loads(audit.new_value)["actor"] == f"system:playbook:{ex.id}"


@pytest.mark.asyncio
async def test_failed_step_fails_the_run_and_stops(db_session, org_a, org_b):
    foreign = Alert(title="B alert", severity="high", status="new", source="siem", organization_id=org_b.id)
    db_session.add(foreign)
    await db_session.flush()
    pb = await _playbook(db_session, org_a.id, [
        {"name": "Touch foreign alert", "action": "update_alert", "parameters": {"alert_id": foreign.id, "status": "resolved"}},
        {"name": "Never runs", "action": "wait", "parameters": {"seconds": 0}},
    ])
    ex = await _run(db_session, pb, org_a.id, None)
    steps = _steps(ex)
    assert ex.status == "failed" and len(steps) == 1 and steps[0]["status"] == "failed"
    assert "not found in this organisation" in steps[0]["error"] and ex.error_step == 1
    await db_session.refresh(foreign)
    assert foreign.status == "new"


@pytest.mark.asyncio
async def test_continue_on_error_runs_on_but_run_is_not_completed(db_session, org_a):
    pb = await _playbook(db_session, org_a.id, [
        {"name": "Bad", "action": "no_such_action", "continue_on_error": True},
        {"name": "Pause", "action": "wait", "parameters": {"seconds": 0}},
    ])
    ex = await _run(db_session, pb, org_a.id, None)
    assert [s["status"] for s in _steps(ex)] == ["failed", "completed"]
    assert ex.status == RUN_PARTIAL


@pytest.mark.asyncio
async def test_run_script_fails_at_runtime(db_session, org_a):
    pb = await _playbook(db_session, org_a.id, [{"name": "Shell", "action": "run_script", "parameters": {"script": "id"}}])
    ex = await _run(db_session, pb, org_a.id, None)
    assert ex.status == "failed" and "removed" in _steps(ex)[0]["error"]


@pytest.mark.asyncio
async def test_condition_skip_does_not_loop(db_session, org_a):
    pb = await _playbook(db_session, org_a.id, [
        {"name": "Check", "action": "condition", "parameters": {"field": "severity", "operator": "equals", "value": "high"},
         "on_success": "skip"},
        {"name": "Skipped", "action": "no_such_action"},
        {"name": "After", "action": "wait", "parameters": {"seconds": 0}},
    ])
    ex = await _run(db_session, pb, org_a.id, None, {"severity": "high"})
    assert [s["name"] for s in _steps(ex)] == ["Check", "After"]
    assert ex.status == "completed"


@pytest.mark.asyncio
async def test_unconfigured_notifications_tickets_and_enrichment_are_awaiting(db_session, org_a, monkeypatch):
    from src.integrations.manager import threat_intel_manager

    monkeypatch.setattr(threat_intel_manager, "get_configured_providers", lambda: [])
    pb = await _playbook(db_session, org_a.id, [
        {"name": "Slack", "action": "notify", "parameters": {"channel": "slack", "message": "hi"}},
        {"name": "Mail", "action": "send_email", "parameters": {"to": "soc@a.io", "subject": "s", "body": "b"}},
        {"name": "Ticket", "action": "create_ticket", "parameters": {"title": "t"}},
        {"name": "Enrich", "action": "enrich_ip", "parameters": {"ip": "198.51.100.3"}},
    ])
    ex = await _run(db_session, pb, org_a.id, None)
    steps = _steps(ex)
    assert [s["status"] for s in steps] == ["awaiting_integration"] * 4
    assert "webhook" in steps[0]["missing_dependency"] and "SMTP" in steps[1]["missing_dependency"]
    assert "Jira or ServiceNow" in steps[2]["missing_dependency"]
    assert steps[3]["result"]["details"].get("confidence") is None
    assert ex.status == RUN_PARTIAL


@pytest.mark.asyncio
async def test_http_request_requires_own_installed_integration(db_session, org_a):
    pb = await _playbook(db_session, org_a.id, [
        {"name": "Raw URL", "action": "http_request", "parameters": {"url": "http://169.254.169.254/latest"}},
    ])
    ex = await _run(db_session, pb, org_a.id, None)
    assert ex.status == "failed" and "installation_id" in _steps(ex)[0]["error"]

    pb2 = await _playbook(db_session, org_a.id, [
        {"name": "Other tenant", "action": "http_request", "parameters": {"installation_id": "nope", "url": "/x"}},
    ])
    ex2 = await _run(db_session, pb2, org_a.id, None)
    assert ex2.status == "failed" and "not found in this organisation" in _steps(ex2)[0]["error"]


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("action,detail", [("run_script", "removed"), ("format_disk", "unknown step type")])
async def test_create_rejects_removed_and_unknown_steps(client, org_a_admin_headers, action, detail):
    resp = await client.post("/api/v1/playbooks", headers=org_a_admin_headers, json={
        "name": "bad", "steps": [{"name": "x", "action": action, "parameters": {}}],
    })
    assert resp.status_code == 422
    body = resp.json()["detail"]
    assert body["error"] == "invalid_steps" and detail in body["steps"][0]["error"]


@pytest.mark.asyncio
async def test_update_rejects_run_script_and_schedule_trigger_is_stored_as_enum(client, org_a_admin_headers):
    resp = await client.post("/api/v1/playbooks", headers=org_a_admin_headers, json={
        "name": "sched", "trigger_type": "schedule", "steps": [{"name": "w", "action": "wait", "parameters": {}}],
    })
    assert resp.status_code == 201 and resp.json()["trigger_type"] == "scheduled"
    pb_id = resp.json()["id"]
    resp = await client.patch(f"/api/v1/playbooks/{pb_id}", headers=org_a_admin_headers, json={
        "steps": [{"name": "s", "action": "run_script", "parameters": {"script": "id"}}],
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_containment_playbook_execution_is_admin_only_and_pollable(
    client, db_session, org_a, org_a_headers, org_a_admin_headers, viewer_headers, org_b_headers,
):
    pb = await _playbook(db_session, org_a.id, [{"name": "Block", "action": "block_ip", "parameters": {"ip": "203.0.113.9"}}])
    await db_session.commit()
    pb_id = pb.id

    resp = await client.post(f"/api/v1/playbooks/{pb_id}/execute", headers=viewer_headers, json={})
    assert resp.status_code == 403
    resp = await client.post(f"/api/v1/playbooks/{pb_id}/execute", headers=org_a_headers, json={})
    assert resp.status_code == 403 and resp.json()["detail"]["error"] == "containment_requires_admin"

    resp = await client.post(f"/api/v1/playbooks/{pb_id}/execute", headers=org_a_admin_headers, json={})
    assert resp.status_code == 200, resp.text
    ex_id = resp.json()["id"]

    resp = await client.get(f"/api/v1/playbooks/{pb_id}/executions/{ex_id}", headers=org_a_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == RUN_PARTIAL
    assert body["step_summary"] == {"awaiting_integration": 1}
    step = body["step_results"][0]
    assert step["status"] == "awaiting_integration" and step["missing_dependency"]

    await assert_tenant_isolated(client, "GET", f"/api/v1/playbooks/{pb_id}/executions/{ex_id}", org_b_headers)
    listed = await client.get(f"/api/v1/playbooks/{pb_id}/executions", headers=org_a_headers)
    assert listed.json()["items"][0]["step_summary"] == {"awaiting_integration": 1}


@pytest.mark.asyncio
async def test_analyst_can_run_non_containment_playbook(client, db_session, org_a, org_a_headers):
    pb = await _playbook(db_session, org_a.id, [{"name": "w", "action": "wait", "parameters": {"seconds": 0}}])
    await db_session.commit()
    pb_id = pb.id
    resp = await client.post(f"/api/v1/playbooks/{pb_id}/execute", headers=org_a_headers, json={})
    assert resp.status_code == 200
    ex_id = resp.json()["id"]
    body = (await client.get(f"/api/v1/playbooks/{pb_id}/executions/{ex_id}", headers=org_a_headers)).json()
    assert body["status"] == "completed" and body["step_summary"] == {"completed": 1}


@pytest.mark.asyncio
async def test_analyst_cannot_run_integration_containment_step(client, db_session, org_a, org_a_headers):
    pb = await _playbook(db_session, org_a.id, [{
        "name": "Contain via EDR", "action": "integration_action",
        "parameters": {"installation_id": "inst", "action_name": "contain_host", "input_data": {"device_id": "d"}},
    }])
    lookup = await _playbook(db_session, org_a.id, [{
        "name": "Lookup", "action": "integration_action",
        "parameters": {"installation_id": "inst", "action_name": "search_hosts", "input_data": {}},
    }])
    await db_session.commit()
    pb_id, lookup_id = pb.id, lookup.id
    resp = await client.post(f"/api/v1/playbooks/{pb_id}/execute", headers=org_a_headers, json={})
    assert resp.status_code == 403 and resp.json()["detail"]["containment_steps"] == ["integration_action"]
    # Read-only lookups stay analyst-level (the step then fails: no such integration in the org).
    resp = await client.post(f"/api/v1/playbooks/{lookup_id}/execute", headers=org_a_headers, json={})
    assert resp.status_code == 200
