"""Wave 2 / W2-A: the visual playbook builder runs for real.

* the engine constructor accepts the session (tasks.py used to TypeError);
* node handlers act through the shared paths (containment, integrations,
  notifications) and record honest node statuses, persisted per node;
* nodes that cannot run are refused with 501 before a run starts;
* POST /playbook-builder/{id}/run creates a pending execution, dispatches it,
  and GET /executions/{id} reports node-by-node progress, tenant-scoped;
* no zero-node templates.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from src.agents.models import AgentCommand, EndpointAgent
from src.models.alert import Alert
from src.playbook_builder.engine import (
    PlaybookDesigner,
    PlaybookExecutionEngine,
    TemplateLibrary,
    run_visual_execution,
)
from src.playbook_builder.models import (
    PlaybookEdge,
    PlaybookNode,
    PlaybookNodeExecution,
    VisualPlaybook,
    VisualPlaybookExecution,
)
from tests.helpers.tenancy import assert_tenant_isolated

DISPATCH = "src.api.v1.endpoints.playbook_builder.async_playbook_execution"


async def _visual(
    db, org_id: str, nodes: list[tuple[str, str, dict | None]], edges: list[tuple[str, str, str]],
    *, on_error: dict[str, str] | None = None,
) -> VisualPlaybook:
    pb = VisualPlaybook(organization_id=org_id, name="W2 visual", category="custom", status="active", trigger_type="manual")
    db.add(pb)
    await db.flush()
    for i, (node_id, node_type, config) in enumerate(nodes):
        db.add(PlaybookNode(
            playbook_id=pb.id, organization_id=org_id, node_id=node_id, node_type=node_type, display_name=node_id,
            position_x=0.0, position_y=float(i), config=json.dumps(config) if config is not None else None,
            on_error=(on_error or {}).get(node_id, "stop"),
        ))
    for src, dst, kind in edges:
        db.add(PlaybookEdge(playbook_id=pb.id, organization_id=org_id, source_node_id=src, target_node_id=dst, edge_type=kind))
    await db.flush()
    return pb


async def _execute(
    db, pb: VisualPlaybook, user_id: str | None = None, trigger: dict | None = None, role: str | None = None,
) -> VisualPlaybookExecution:
    ex = VisualPlaybookExecution(
        playbook_id=pb.id, organization_id=pb.organization_id, status="pending", triggered_by=user_id,
        triggered_by_role=role,
        trigger_event=json.dumps(trigger) if trigger else None,
    )
    db.add(ex)
    await db.commit()
    result = await run_visual_execution(db, ex.id)
    await db.commit()
    return result


async def _node_rows(db, execution_id: str) -> dict[str, PlaybookNodeExecution]:
    rows = (await db.execute(
        select(PlaybookNodeExecution).where(PlaybookNodeExecution.execution_id == execution_id),
    )).scalars().all()
    return {r.node_id: r for r in rows}


def test_engine_constructor_accepts_session():
    engine = PlaybookExecutionEngine(object())  # tasks.py:69 used to raise TypeError here
    assert engine.db is not None


@pytest.mark.asyncio
async def test_containment_node_queues_agent_command_and_persists_nodes(db_session, org_a, org_a_admin):
    org_id = org_a.id
    agent = EndpointAgent(hostname="db-01", display_name="db-01", os_type="linux", status="active",
                          capabilities=["ir"], organization_id=org_id)
    db_session.add(agent)
    pb = await _visual(db_session, org_id, [
        ("t", "trigger", None),
        ("iso", "action", {"action_type": "isolate_host", "params": {"hostname": "$.host"}}),
        ("blk", "action", {"action_type": "block_ip", "params": {"ip": "203.0.113.4"}}),
    ], [("t", "iso", "success"), ("iso", "blk", "success")])
    ex = await _execute(db_session, pb, org_a_admin.id, trigger={"host": "db-01"}, role="admin")

    nodes = await _node_rows(db_session, ex.id)
    assert nodes["t"].status == "completed"
    assert nodes["iso"].status == "queued_for_approval"
    cmd_id = json.loads(nodes["iso"].output_data)["details"]["command_id"]
    cmd = await db_session.get(AgentCommand, cmd_id)
    assert cmd.agent_id == agent.id and cmd.organization_id == org_id and cmd.issued_by == org_a_admin.id
    # block_ip goes to every IR agent of the org: also queued for approval (high blast).
    assert nodes["blk"].status == "queued_for_approval"
    assert ex.status == "partial" and json.loads(ex.execution_path) == ["t", "iso", "blk"]
    assert ex.duration_ms is not None and ex.completed_at


@pytest.mark.asyncio
async def test_no_actuation_path_is_awaiting_integration(db_session, org_a, org_a_admin):
    pb = await _visual(db_session, org_a.id, [
        ("t", "trigger", None),
        ("blk", "action", {"action_type": "block_ip", "params": {"ip": "198.51.100.9"}}),
        ("n", "notification", {"channel": "slack", "message": "blocked {{ip}}"}),
    ], [("t", "blk", "success"), ("blk", "n", "success")])
    ex = await _execute(db_session, pb, org_a_admin.id, role="admin")
    nodes = await _node_rows(db_session, ex.id)
    assert nodes["blk"].status == "awaiting_integration" and nodes["blk"].error_message
    assert nodes["n"].status == "awaiting_integration" and "webhook" in nodes["n"].error_message
    assert ex.status == "partial"


@pytest.mark.asyncio
async def test_failed_node_fails_run_unless_continue(db_session, org_a, org_b):
    foreign = Alert(title="B", severity="low", status="new", source="siem", organization_id=org_b.id)
    db_session.add(foreign)
    await db_session.flush()
    nodes = [
        ("t", "trigger", None),
        ("upd", "action", {"action_type": "update_alert", "params": {"alert_id": foreign.id, "status": "resolved"}}),
        ("d", "delay", {"duration_seconds": 0}),
    ]
    edges = [("t", "upd", "success"), ("upd", "d", "always")]
    pb = await _visual(db_session, org_a.id, nodes, edges)
    ex = await _execute(db_session, pb)
    rows = await _node_rows(db_session, ex.id)
    assert ex.status == "failed" and "upd" in ex.error_message and set(rows) == {"t", "upd"}

    pb2 = await _visual(db_session, org_a.id, nodes, edges, on_error={"upd": "continue"})
    ex2 = await _execute(db_session, pb2)
    rows2 = await _node_rows(db_session, ex2.id)
    assert rows2["upd"].status == "failed" and rows2["d"].status == "completed"
    assert ex2.status == "partial"
    await db_session.refresh(foreign)
    assert foreign.status == "new"


@pytest.mark.asyncio
async def test_condition_branches_on_result(db_session, org_a):
    nodes = [
        ("t", "trigger", None),
        ("c", "condition", {"expression": "severity == 'high'"}),
        ("yes", "variable_set", {"variable_name": "path", "variable_value": "yes"}),
        ("no", "variable_set", {"variable_name": "path", "variable_value": "no"}),
    ]
    edges = [("t", "c", "success"), ("c", "yes", "success"), ("c", "no", "failure")]
    pb = await _visual(db_session, org_a.id, nodes, edges)
    ex = await _execute(db_session, pb, trigger={"severity": "high"})
    assert json.loads(ex.execution_path) == ["t", "c", "yes"] and ex.status == "completed"
    ex = await _execute(db_session, pb, trigger={"severity": "low"})
    assert json.loads(ex.execution_path) == ["t", "c", "no"] and ex.status == "completed"


def test_unsupported_nodes_reported():
    pb = PlaybookDesigner().import_playbook_json("org", {
        "name": "x",
        "nodes": [
            {"node_id": "t", "node_type": "trigger"},
            {"node_id": "a", "node_type": "action"},
            {"node_id": "h", "node_type": "human_approval"},
            {"node_id": "e", "node_type": "enrichment", "config": {"enrichment_type": "sandbox"}},
        ],
    })
    problems = {p["node_id"]: p["reason"] for p in PlaybookExecutionEngine().unsupported_nodes(pb)}
    assert set(problems) == {"a", "h", "e"}
    assert "action_type" in problems["a"] and "not implemented" in problems["h"]


def test_no_zero_node_templates_and_all_template_nodes_execute():
    templates = TemplateLibrary.get_templates()
    assert templates
    engine = PlaybookExecutionEngine()
    for tid, tpl in templates.items():
        assert tpl["nodes"], tid
        pb = PlaybookDesigner().import_playbook_json("org", tpl)
        assert engine.unsupported_nodes(pb) == [], tid


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_route_creates_pollable_execution(client, db_session, org_a, org_a_headers, org_b_headers):
    pb = await _visual(db_session, org_a.id, [
        ("t", "trigger", None),
        ("d", "delay", {"duration_seconds": 0}),
    ], [("t", "d", "success")])
    await db_session.commit()
    pb_id = pb.id

    with patch(DISPATCH) as task:
        resp = await client.post(f"/api/v1/playbook-builder/{pb_id}/run", headers=org_a_headers,
                                 json={"variables": {"k": "v"}})
    assert resp.status_code == 202, resp.text
    body = resp.json()
    ex_id = body["id"]
    assert body["status"] == "pending" and body["organization_id"] == org_a.id
    task.delay.assert_called_once_with(playbook_id=pb_id, execution_id=ex_id)

    # What the worker does:
    await run_visual_execution(db_session, ex_id)
    await db_session.commit()

    status = (await client.get(f"/api/v1/playbook-builder/executions/{ex_id}", headers=org_a_headers)).json()
    assert status["status"] == "completed" and status["progress_percent"] == 100.0
    assert status["node_summary"] == {"completed": 2} and status["execution_path"] == ["t", "d"]
    assert [n["node_id"] for n in status["node_executions"]] == ["t", "d"]

    listed = (await client.get("/api/v1/playbook-builder/executions", headers=org_a_headers)).json()
    assert [i["id"] for i in listed["items"]] == [ex_id] and listed["items"][0]["nodes_executed"] == 2

    await assert_tenant_isolated(client, "GET", f"/api/v1/playbook-builder/executions/{ex_id}", org_b_headers)
    with patch(DISPATCH):
        await assert_tenant_isolated(client, "POST", f"/api/v1/playbook-builder/{pb_id}/run", org_b_headers)

    dash = (await client.get("/api/v1/playbook-builder/dashboard", headers=org_a_headers)).json()
    assert dash["execution_stats"]["total_executions"] == 1 and dash["execution_stats"]["successful_executions"] == 1


@pytest.mark.asyncio
async def test_run_refuses_unexecutable_playbooks(client, db_session, org_a, org_a_headers, viewer_headers):
    unconfigured = await _visual(db_session, org_a.id, [("t", "trigger", None), ("a", "action", None)], [("t", "a", "success")])
    no_trigger = await _visual(db_session, org_a.id, [("d", "delay", {"duration_seconds": 0})], [])
    containment = await _visual(db_session, org_a.id, [
        ("t", "trigger", None), ("iso", "action", {"action_type": "isolate_host", "params": {"hostname": "h"}}),
    ], [("t", "iso", "success")])
    await db_session.commit()
    ids = (unconfigured.id, no_trigger.id, containment.id)

    with patch(DISPATCH) as task:
        resp = await client.post(f"/api/v1/playbook-builder/{ids[0]}/run", headers=org_a_headers)
        assert resp.status_code == 501
        detail = resp.json()["detail"]
        assert detail["error"] == "not_implemented" and detail["nodes"][0]["node_id"] == "a"
        assert (await client.post(f"/api/v1/playbook-builder/{ids[1]}/run", headers=org_a_headers)).status_code == 422
        resp = await client.post(f"/api/v1/playbook-builder/{ids[2]}/run", headers=org_a_headers)
        assert resp.status_code == 403 and resp.json()["detail"]["error"] == "containment_requires_admin"
        assert (await client.post(f"/api/v1/playbook-builder/{ids[2]}/run", headers=viewer_headers)).status_code == 403
        task.delay.assert_not_called()
    rows = (await db_session.execute(select(VisualPlaybookExecution))).scalars().all()
    assert rows == []

    validated = (await client.post(f"/api/v1/playbook-builder/{ids[0]}/validate", headers=org_a_headers, json={})).json()
    assert validated["is_valid"] is False and any("cannot execute" in e for e in validated["errors"])


@pytest.mark.asyncio
async def test_dispatch_failure_marks_execution_failed(client, db_session, org_a, org_a_headers):
    pb = await _visual(db_session, org_a.id, [("t", "trigger", None)], [])
    await db_session.commit()
    pb_id = pb.id
    with patch(DISPATCH) as task:
        task.delay.side_effect = ConnectionError("broker down")
        resp = await client.post(f"/api/v1/playbook-builder/{pb_id}/run", headers=org_a_headers, json={})
    assert resp.status_code == 503 and resp.json()["detail"]["error"] == "dispatch_failed"
    ex = (await db_session.execute(select(VisualPlaybookExecution))).scalars().one()
    await db_session.refresh(ex)
    assert ex.status == "failed" and "broker down" in ex.error_message


@pytest.mark.asyncio
async def test_template_list_has_node_counts(client, org_a_headers):
    items = (await client.get("/api/v1/playbook-builder/templates", headers=org_a_headers)).json()["items"]
    assert items and all(i["node_count"] == len(i["nodes"]) > 0 for i in items)


# ---------------------------------------------------------------------------
# Privileged nodes: classified by capability, checked at dispatch and run time
# ---------------------------------------------------------------------------


def test_privilege_classification_is_by_capability():
    from src.services.playbook_engine import is_privileged_step

    assert is_privileged_step("integration_action", {"action_name": "contain_host"})
    assert is_privileged_step("execute_integration_action", {"action_name": "lift_containment"})
    assert is_privileged_step("integration_action", {})
    assert is_privileged_step("http_request", {"installation_id": "x", "url": "/"})
    assert is_privileged_step("agent_command", {})
    assert not is_privileged_step("integration_action", {"action_name": "search_hosts"})
    assert not is_privileged_step("integration_action", {"action_name": "get_device"})
    for action in ("notify", "condition", "wait", "enrich", "create_ticket", "update_alert"):
        assert not is_privileged_step(action, {})
    pb = PlaybookDesigner().import_playbook_json("org", {"name": "x", "nodes": [
        {"node_id": "t", "node_type": "trigger"},
        {"node_id": "api", "node_type": "api_call", "config": {"installation_id": "i", "url": "/"}},
        {"node_id": "look", "node_type": "action",
         "config": {"action_type": "integration_action", "params": {"action_name": "search_hosts"}}},
        {"node_id": "n", "node_type": "notification", "config": {"channel": "slack", "message": "m"}},
    ]})
    assert PlaybookExecutionEngine().privileged_nodes(pb) == ["api"]


@pytest.mark.asyncio
async def test_analyst_cannot_dispatch_integration_containment_admin_can(
    client, db_session, org_a, org_a_headers, org_a_admin_headers,
):
    pb = await _visual(db_session, org_a.id, [
        ("t", "trigger", None),
        ("contain", "action", {"action_type": "integration_action",
                               "params": {"installation_id": "inst", "action_name": "contain_host",
                                          "input_data": {"device_id": "d"}}}),
    ], [("t", "contain", "success")])
    await db_session.commit()
    pb_id = pb.id
    with patch(DISPATCH) as task:
        resp = await client.post(f"/api/v1/playbook-builder/{pb_id}/run", headers=org_a_headers)
        assert resp.status_code == 403 and resp.json()["detail"]["nodes"] == ["contain"]
        task.delay.assert_not_called()
        resp = await client.post(f"/api/v1/playbook-builder/{pb_id}/run", headers=org_a_admin_headers)
        assert resp.status_code == 202
    ex = await db_session.get(VisualPlaybookExecution, resp.json()["id"])
    assert ex.triggered_by_role == "admin"


@pytest.mark.asyncio
async def test_runner_refuses_node_added_after_analyst_dispatch(
    client, db_session, org_a, org_a_user, org_a_admin, org_a_headers,
):
    pb = await _visual(db_session, org_a.id, [("t", "trigger", None), ("d", "delay", {"duration_seconds": 0})],
                       [("t", "d", "success")])
    await db_session.commit()
    pb_id, org_id, analyst_id, admin_id = pb.id, org_a.id, org_a_user.id, org_a_admin.id
    with patch(DISPATCH):
        resp = await client.post(f"/api/v1/playbook-builder/{pb_id}/run", headers=org_a_headers)
    assert resp.status_code == 202
    ex_id = resp.json()["id"]
    assert (await db_session.get(VisualPlaybookExecution, ex_id)).triggered_by_role == "analyst"

    # The playbook is edited after dispatch: an admin-only node appears.
    db_session.add(PlaybookNode(
        playbook_id=pb_id, organization_id=org_id, node_id="iso", node_type="action", display_name="iso",
        position_x=0.0, position_y=9.0, config=json.dumps({"action_type": "isolate_host", "params": {"hostname": "h"}}),
    ))
    db_session.add(PlaybookEdge(playbook_id=pb_id, organization_id=org_id, source_node_id="d", target_node_id="iso",
                                edge_type="success"))
    db_session.add(EndpointAgent(hostname="h", display_name="h", os_type="linux", status="active",
                                 capabilities=["ir"], organization_id=org_id))
    await db_session.commit()

    ex = await run_visual_execution(db_session, ex_id)
    await db_session.commit()
    assert ex.status == "failed" and "forbidden_privileged_node" in ex.error_message
    rows = await _node_rows(db_session, ex_id)
    assert set(rows) == {"iso"} and rows["iso"].status == "forbidden_privileged_node"
    assert (await db_session.execute(select(AgentCommand))).scalars().all() == []

    pb_obj = (await db_session.execute(
        select(VisualPlaybook).options(selectinload(VisualPlaybook.nodes)).where(VisualPlaybook.id == pb_id),
    )).scalar_one()
    # Scheduled / role-less runs are refused the same way.
    refused = await _execute(db_session, pb_obj, None)
    assert refused.status == "failed" and "forbidden_privileged_node" in refused.error_message
    # A recorded admin role is not enough when the user is not an admin.
    stale = await _execute(db_session, pb_obj, analyst_id, role="admin")
    assert stale.status == "failed" and "forbidden_privileged_node" in stale.error_message
    # An admin-dispatched run proceeds to the node.
    allowed = await _execute(db_session, pb_obj, admin_id, role="admin")
    assert allowed.status == "partial"
    assert (await _node_rows(db_session, allowed.id))["iso"].status == "queued_for_approval"

