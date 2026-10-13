"""Wave 2 / W2-B: remediation made real.

Covers the action registry (``GET /remediation/actions``) and policy
validation, quick actions through the shared containment service (audited,
honest status, reversible only with a revert handle), approve / manual
execute through the same runner, rollback 409 ``not_reversible``, the
installed-integration list / install / test, and the dashboard /
effectiveness figures computed from execution rows.

Only the boundaries are mocked (the integration probe); endpoint agents are
real rows and commands are real ``AgentCommand`` rows.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import AgentCommand, EndpointAgent
from src.integrations.models import InstalledIntegration, IntegrationConnector
from src.models.audit import AuditLog
from src.models.base import utc_now
from src.remediation.engine import RemediationEngine
from src.remediation.models import RemediationExecution, RemediationPlaybook, RemediationPolicy
from tests.helpers.tenancy import assert_tenant_isolated, bearer, make_user

API = "/api/v1/remediation"


async def _agent(db, org_id: str, hostname: str, capabilities=("ir",)) -> EndpointAgent:
    agent = EndpointAgent(
        hostname=hostname, os_type="linux", agent_version="1.0.0", capabilities=list(capabilities),
        status="active", organization_id=org_id,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return agent


async def _connector(db, name: str, category: str) -> IntegrationConnector:
    connector = IntegrationConnector(
        id=name, name=name, display_name=name.title(), category=category, vendor=name.title(),
        supported_actions=json.dumps(["contain_host"]), supported_triggers="[]", auth_type="api_key",
        config_schema="{}", is_builtin=True,
    )
    db.add(connector)
    await db.commit()
    return connector


async def _installed(db, org_id: str, connector: str, *, status: str = "active") -> InstalledIntegration:
    integ = InstalledIntegration(
        organization_id=org_id, connector_id=connector, display_name=f"{connector} prod",
        config_encrypted=json.dumps({}), auth_credentials_encrypted="", status=status,
    )
    db.add(integ)
    await db.commit()
    await db.refresh(integ)
    return integ


async def _commands(db, action: str) -> list[AgentCommand]:
    return list((await db.execute(select(AgentCommand).where(AgentCommand.action == action))).scalars().all())


# ---------------------------------------------------------------------------
# Registry + policy validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_actions_registry_lists_executable_keys(client, viewer_headers):
    resp = await client.get(f"{API}/actions", headers=viewer_headers)
    assert resp.status_code == 200, resp.text
    by_key = {a["key"]: a for a in resp.json()}
    assert {"firewall_block", "host_isolate", "account_disable", "file_quarantine"} <= set(by_key)
    # Fake executors are not offered.
    assert not {"script", "webhook", "patch_deploy", "dns_sinkhole"} & set(by_key)
    fq = by_key["file_quarantine"]
    assert fq["label"] and fq["reversible"] is True and isinstance(fq["requires_approval"], bool)
    assert {"name": "file_path", "type": "string", "required": True}.items() <= fq["parameters"][0].items()
    assert by_key["account_disable"]["reversible"] is False

    one = await client.get(f"{API}/actions", params={"action_type": "auto_block"}, headers=viewer_headers)
    assert [a["key"] for a in one.json()] == ["firewall_block"]


_POLICY = {
    "name": "Block bad IPs", "policy_type": "auto_block", "trigger_type": "threat_intel_match",
    "trigger_conditions": {}, "is_enabled": False,
}


@pytest.mark.asyncio
async def test_policy_with_unknown_action_is_rejected(client, org_a_admin_headers):
    resp = await client.post(
        f"{API}/policies", json={**_POLICY, "actions": [{"type": "launch_missiles"}]}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 400, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "unknown_action" and detail["unknown"] == ["launch_missiles"]
    assert "firewall_block" in detail["allowed"]


@pytest.mark.asyncio
async def test_policy_alias_stored_as_registry_key_and_update_validated(client, db_session, org_a_admin_headers):
    resp = await client.post(
        f"{API}/policies", json={**_POLICY, "actions": [{"type": "auto_block"}]}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    policy_id = resp.json()["id"]
    assert resp.json()["actions"][0]["type"] == "firewall_block"

    bad = await client.put(
        f"{API}/policies/{policy_id}", json={"actions": [{"type": "script"}]}, headers=org_a_admin_headers,
    )
    assert bad.status_code == 400 and bad.json()["detail"]["error"] == "unknown_action"

    # Disabled policies are listed by default; `enabled` / `type` filters work.
    listed = await client.get(f"{API}/policies", headers=org_a_admin_headers)
    assert [p["id"] for p in listed.json()] == [policy_id]
    assert (await client.get(f"{API}/policies", params={"enabled": "true"}, headers=org_a_admin_headers)).json() == []
    typed = await client.get(f"{API}/policies", params={"type": "auto_isolate"}, headers=org_a_admin_headers)
    assert typed.json() == []


# ---------------------------------------------------------------------------
# Quick actions through the containment service
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_ip_without_agent_is_detection_only_and_not_reversible(
    client, db_session, org_a, org_a_admin_headers,
):
    org_id = org_a.id
    resp = await client.post(f"{API}/block-ip", json={"ip": "203.0.113.5", "duration": 2}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["containment_status"] == "detection_only"
    assert body["status"] == "detection_only"
    assert body["duration_hours"] == 2 and body["ioc_id"]
    assert body["reversible"] is False and body["missing_dependency"]
    assert body["result"]["success"] is False

    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "containment_block_ip", AuditLog.organization_id == org_id),
    )).scalars().all()
    assert len(audit) == 1 and audit[0].success is False

    rollback = await client.post(f"{API}/executions/{body['execution_id']}/rollback", headers=org_a_admin_headers)
    assert rollback.status_code == 409
    assert rollback.json()["detail"]["error"] == "not_reversible"


@pytest.mark.asyncio
async def test_block_ip_with_agent_queues_command_and_rollback_reverses_it(
    client, db_session, org_a, org_a_admin_headers,
):
    org_id = org_a.id
    agent = await _agent(db_session, org_id, "ws-01")
    agent_id = agent.id
    resp = await client.post(f"{API}/block-ip", json={"ip": "198.51.100.7"}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # block_ip is high-blast: the real command waits in the agent approval queue.
    assert body["containment_status"] == "queued_for_approval"
    assert body["status"] == "awaiting_approval"
    assert body["reversible"] is True and body["agent_command_id"]
    [cmd] = await _commands(db_session, "block_ip")
    assert cmd.agent_id == agent_id and cmd.payload["ip"] == "198.51.100.7"

    rollback = await client.post(f"{API}/executions/{body['execution_id']}/rollback", headers=org_a_admin_headers)
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["rollback_status"] == "completed"
    [unblock] = await _commands(db_session, "unblock_ip")
    assert unblock.agent_id == agent_id and unblock.payload == {"ip": "198.51.100.7"}

    from src.intel.models import ThreatIndicator

    ioc = await db_session.get(ThreatIndicator, body["ioc_id"])
    await db_session.refresh(ioc)
    assert ioc.is_active is False
    rb_audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "containment_rollback_firewall_block"),
    )).scalars().all()
    assert len(rb_audit) == 1 and rb_audit[0].success is True

    again = await client.post(f"{API}/executions/{body['execution_id']}/rollback", headers=org_a_admin_headers)
    assert again.status_code == 409 and again.json()["detail"]["error"] == "already_rolled_back"


@pytest.mark.asyncio
async def test_isolate_and_quarantine_target_only_the_named_host(client, db_session, org_a, org_a_admin_headers):
    org_id = org_a.id
    target = await _agent(db_session, org_id, "srv-target")
    target_id = target.id
    await _agent(db_session, org_id, "srv-other")

    iso = await client.post(f"{API}/isolate-host", json={"hostname": "srv-target"}, headers=org_a_admin_headers)
    assert iso.status_code == 200, iso.text
    assert iso.json()["containment_status"] in ("executed", "queued_for_approval")
    assert iso.json()["reversible"] is True
    [cmd] = await _commands(db_session, "isolate_host")
    assert cmd.agent_id == target_id

    q = await client.post(
        f"{API}/quarantine-file", json={"hostname": "srv-target", "file_path": "/tmp/evil"},
        headers=org_a_admin_headers,
    )
    assert q.status_code == 200, q.text
    assert q.json()["agent_available"] is True and q.json()["target"] == "/tmp/evil"
    [qcmd] = await _commands(db_session, "quarantine_file")
    assert qcmd.agent_id == target_id and qcmd.payload["path"] == "/tmp/evil"

    missing = await client.post(
        f"{API}/quarantine-file", json={"hostname": "nowhere-01", "file_path": "/tmp/evil"},
        headers=org_a_admin_headers,
    )
    assert missing.json()["containment_status"] == "detection_only"
    assert len(await _commands(db_session, "quarantine_file")) == 1


@pytest.mark.asyncio
async def test_disable_account_is_honest_and_never_reversible(client, db_session, org_a, org_a_admin_headers):
    org_id = org_a.id
    no_host = await client.post(f"{API}/disable-account", json={"username": "jdoe"}, headers=org_a_admin_headers)
    assert no_host.status_code == 200, no_host.text
    assert no_host.json()["containment_status"] == "detection_only"

    await _agent(db_session, org_id, "ws-77")
    with_host = await client.post(
        f"{API}/disable-account", json={"username": "jdoe", "hostname": "ws-77"}, headers=org_a_admin_headers,
    )
    assert with_host.json()["containment_status"] in ("executed", "queued_for_approval")
    assert with_host.json()["reversible"] is False
    [cmd] = await _commands(db_session, "disable_account")
    assert cmd.payload["username"] == "jdoe"

    rollback = await client.post(
        f"{API}/executions/{with_host.json()['execution_id']}/rollback", headers=org_a_admin_headers,
    )
    assert rollback.status_code == 409 and rollback.json()["detail"]["error"] == "not_reversible"


@pytest.mark.asyncio
async def test_quick_actions_list_shows_the_new_rows(client, org_a_admin_headers, org_b_headers):
    await client.post(f"{API}/isolate-host", json={"hostname": "h1"}, headers=org_a_admin_headers)
    mine = await client.get(f"{API}/quick-actions", headers=org_a_admin_headers)
    assert [r["target_entity"] for r in mine.json()] == ["h1"]
    assert mine.json()[0]["actions_completed"][0]["status"] == "detection_only"
    theirs = await client.get(f"{API}/quick-actions", headers=org_b_headers)
    assert theirs.json() == []


# ---------------------------------------------------------------------------
# Manual execute + approval through the same runner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manual_execute_unknown_action_400(client, org_a_admin_headers):
    resp = await client.post(
        f"{API}/execute", json={"action_type": "script", "target_entity": "x"}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 400 and resp.json()["detail"]["error"] == "unknown_action"


@pytest.mark.asyncio
async def test_manual_execute_with_approval_runs_through_containment_on_approve(
    client, db_session, org_a, org_a_admin_headers,
):
    org_id = org_a.id
    await _agent(db_session, org_id, "db-01")
    second_admin = await make_user(db_session, role="admin", organization_id=org_id, label="admin-two")
    second_headers = bearer(second_admin)

    created = await client.post(
        f"{API}/execute",
        json={"action_type": "isolate_host", "target_entity": "db-01", "target_type": "host", "requires_approval": True},
        headers=org_a_admin_headers,
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["status"] == "awaiting_approval" and body["action_results"] == []
    assert await _commands(db_session, "isolate_host") == []

    # Separation of duties: the initiator cannot approve.
    self_ok = await client.post(
        f"{API}/executions/{body['execution_id']}/approve", json={}, headers=org_a_admin_headers,
    )
    assert self_ok.status_code == 403

    approved = await client.post(
        f"{API}/executions/{body['execution_id']}/approve", json={}, headers=second_headers,
    )
    assert approved.status_code == 200, approved.text
    result = approved.json()
    assert result["status"] == "completed" and result["overall_result"] == "success"
    [step] = result["action_results"]
    # The second admin's approval authorises the high-blast command: queued, not re-gated.
    assert step["status"] == "executed" and step["action_type"] == "host_isolate"
    assert step["reversible"] is True and step["started_at"] and step["finished_at"]
    [cmd] = await _commands(db_session, "isolate_host")
    assert cmd.status == "queued"


@pytest.mark.asyncio
async def test_manual_execute_without_agent_never_reports_success(client, org_a_admin_headers):
    resp = await client.post(
        f"{API}/execute", json={"action_type": "firewall_block", "target_entity": "192.0.2.10"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "detection_only"
    assert resp.json()["overall_result"] == "pending"
    assert resp.json()["action_results"][0]["missing_dependency"]


@pytest.mark.asyncio
async def test_engine_marks_unexecutable_legacy_actions_failed(db_session, org_a):
    execution = RemediationExecution(
        trigger_source="manual", trigger_details={}, status="approved", target_entity="srv-1",
        target_type="host", actions_planned=[{"type": "script", "parameters": {"script": "rm -rf /"}}],
        actions_completed=[], organization_id=org_a.id,
    )
    db_session.add(execution)
    await db_session.commit()
    run = await RemediationEngine(db_session)._run_actions(execution.id)
    assert run["results"][0]["success"] is False
    assert "not executable" in run["results"][0]["error"]
    await db_session.refresh(execution)
    assert execution.status == "failed" and execution.overall_result == "failure"


@pytest.mark.asyncio
async def test_playbook_execute_runs_registry_steps(client, db_session, org_a, org_a_admin_headers):
    org_id = org_a.id
    admin_id = (await make_user(db_session, role="admin", organization_id=org_id, label="pb-owner")).id
    pb = RemediationPlaybook(
        name="Contain", playbook_type="threat_containment",
        steps=[{"action_id": "firewall_block"}, {"action_id": "launch_missiles"}],
        created_by=admin_id, organization_id=org_id,
    )
    db_session.add(pb)
    await db_session.commit()
    resp = await client.post(
        f"{API}/playbooks/{pb.id}/execute", json={"target_entity": "203.0.113.50"}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    statuses = [r["status"] for r in body["action_results"]]
    assert statuses == ["detection_only", "failed"]
    assert body["status"] == "failed" and body["overall_result"] == "failure"
    assert body["actions_failed"] == 1 and body["actions_awaiting_integration"] == 1


# ---------------------------------------------------------------------------
# Executions list robustness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_executions_list_tolerates_legacy_string_details(client, db_session, org_a, org_a_headers):
    db_session.add(RemediationExecution(
        trigger_source="manual", trigger_details={}, status="completed", target_entity="x", target_type="host",
        actions_planned=[], actions_completed=[{"action": "notify", "details": "sent to soc"}],
        organization_id=org_a.id,
    ))
    await db_session.commit()
    resp = await client.get(f"{API}/executions", params={"trigger": "manual"}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    step = resp.json()[0]["actions_completed"][0]
    assert step["action_type"] == "notify" and step["details"] == {"message": "sent to soc"}


# ---------------------------------------------------------------------------
# Integrations: the installed-integration model with its real ids
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_integrations_list_reads_installed_integrations(client, db_session, org_a, org_a_headers, org_b_headers):
    await _connector(db_session, "crowdstrike", "edr")
    await _connector(db_session, "palo_alto", "firewall")
    cs = await _installed(db_session, org_a.id, "crowdstrike")
    fw = await _installed(db_session, org_a.id, "palo_alto")
    cs_id, fw_id = cs.id, fw.id

    resp = await client.get(f"{API}/integrations", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    by_id = {i["id"]: i for i in resp.json()}
    assert set(by_id) == {cs_id, fw_id}
    assert by_id[cs_id]["remediation_actions"] == ["host_isolate"]
    assert "file_quarantine" in by_id[cs_id]["awaiting_actions"]
    assert by_id[fw_id]["awaiting_actions"] == ["firewall_block"]
    assert all(i["auth_config"] == {} for i in by_id.values())
    assert (await client.get(f"{API}/integrations", headers=org_b_headers)).json() == []
    await assert_tenant_isolated(client, "GET", f"{API}/integrations/{cs_id}/health", org_b_headers)


@pytest.mark.asyncio
async def test_add_integration_writes_installed_integration(client, db_session, org_a, org_a_admin_headers):
    await _connector(db_session, "virustotal", "threat_intel")
    resp = await client.post(
        f"{API}/integrations",
        json={"connector_id": "virustotal", "name": "VT", "auth_config": {"api_key": "secret-key"}},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["connector_name"] == "virustotal" and body["auth_config"] == {}
    row = await db_session.get(InstalledIntegration, body["id"])
    assert row.organization_id == org_a.id
    assert "secret-key" not in (row.auth_credentials_encrypted or "")

    listed = await client.get(f"{API}/integrations", headers=org_a_admin_headers)
    assert [i["id"] for i in listed.json()] == [body["id"]]

    dup = await client.post(f"{API}/integrations", json={"connector_id": "virustotal"}, headers=org_a_admin_headers)
    assert dup.status_code == 409
    unknown = await client.post(f"{API}/integrations", json={"connector_id": "nope"}, headers=org_a_admin_headers)
    assert unknown.status_code == 400 and unknown.json()["detail"]["error"] == "unknown_connector"


@pytest.mark.asyncio
async def test_test_connection_probes_the_installed_integration(
    client, db_session, org_a, org_a_headers, org_b_headers, monkeypatch,
):
    from src.integrations.engine import IntegrationManager

    await _connector(db_session, "virustotal", "threat_intel")
    integ = await _installed(db_session, org_a.id, "virustotal")
    integ_id = integ.id
    probed: list[str] = []

    async def fake_probe(self, connector_type, config, credentials):
        probed.append(connector_type)
        return "unhealthy", "VirusTotal x-apikey not configured"

    monkeypatch.setattr(IntegrationManager, "_probe_connector", fake_probe)
    resp = await client.post(f"{API}/integrations/{integ_id}/test", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["success"] is False and resp.json()["status"] == "unhealthy"
    assert probed == ["virustotal"]
    health = await client.get(f"{API}/integrations/{integ_id}/health", headers=org_a_headers)
    assert health.json()["health_status"] == "unhealthy" and health.json()["last_health_check"]

    await assert_tenant_isolated(client, "POST", f"{API}/integrations/{integ_id}/test", org_b_headers)


# ---------------------------------------------------------------------------
# Dashboard + effectiveness from execution rows
# ---------------------------------------------------------------------------


async def _exec(db, org_id, *, overall, status, steps=None, created_delta=timedelta(0)):
    now = utc_now()
    row = RemediationExecution(
        trigger_source="manual", trigger_details={}, status=status, overall_result=overall,
        target_entity="10.0.0.1", target_type="ip", actions_planned=[], actions_completed=steps or [],
        organization_id=org_id, completed_at=now if overall else None,
    )
    db.add(row)
    await db.flush()
    row.created_at = now - created_delta
    await db.commit()
    return row


@pytest.mark.asyncio
async def test_dashboard_and_effectiveness_are_computed(client, db_session, org_a, org_a_headers):
    org_id = org_a.id
    admin_id = (await make_user(db_session, role="admin", organization_id=org_id, label="pol")).id
    db_session.add(RemediationPolicy(
        name="p", policy_type="auto_block", trigger_type="manual", trigger_conditions={}, actions=[],
        is_enabled=True, created_by=admin_id, organization_id=org_id,
    ))
    ok_step = {"action_type": "firewall_block", "success": True, "status": "executed"}
    await _exec(db_session, org_id, overall="success", status="completed", steps=[ok_step])
    await _exec(db_session, org_id, overall="failure", status="failed", steps=[{"action_type": "x", "success": False}])
    partial_step = {
        "action_type": "host_isolate", "path": "containment", "success": True, "status": "executed",
        "reversible": True, "revert": {"kind": "agent_commands", "reverse_action": "release_host", "commands": []},
    }
    await _exec(db_session, org_id, overall="partial_success", status="failed", steps=[partial_step])
    await _exec(db_session, org_id, overall="pending", status="awaiting_integration")

    dash = await client.get(f"{API}/dashboard", params={"days": 7}, headers=org_a_headers)
    assert dash.status_code == 200, dash.text
    d = dash.json()
    assert d["active_policies"] == 1
    assert d["actions_today"] == 3
    assert len(d["recent_executions"]) == 4
    assert len(d["execution_by_day"]) == 7 and d["execution_by_day"][-1]["total"] == 4

    eff = await client.get(f"{API}/effectiveness", headers=org_a_headers)
    assert eff.status_code == 200, eff.text
    e = eff.json()
    assert e["total_executions"] == 4 and e["executions_verified"] == 3 and e["pending_count"] == 1
    assert e["effective_count"] == 1 and e["ineffective_count"] == 2
    assert e["effectiveness_rate"] == pytest.approx(33.33, abs=0.01)
    assert e["rollbacks_recommended"] == 1 and e["verification_method"] == "execution_outcome"


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/block-ip", {"ip": "203.0.113.1"}),
        ("/isolate-host", {"hostname": "h"}),
        ("/disable-account", {"username": "u"}),
        ("/quarantine-file", {"hostname": "h", "file_path": "/x"}),
        ("/execute", {"action_type": "firewall_block", "target_entity": "203.0.113.1"}),
        ("/integrations", {"connector_id": "virustotal"}),
    ],
)
async def test_containment_and_configuration_are_admin_only(client, org_a_headers, viewer_headers, path, payload):
    for headers in (org_a_headers, viewer_headers):
        resp = await client.post(f"{API}{path}", json=payload, headers=headers)
        assert resp.status_code == 403, (path, resp.text)


@pytest.mark.asyncio
async def test_orgless_user_is_refused(client, orgless_headers):
    resp = await client.get(f"{API}/integrations", headers=orgless_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Unattended (policy-triggered) runs and the CrowdStrike revert path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_policy_triggered_run_is_unattended(db_session, org_a):
    org_id = org_a.id
    owner_id = (await make_user(db_session, role="admin", organization_id=org_id, label="owner")).id
    await _agent(db_session, org_id, "ws-auto")
    policy = RemediationPolicy(
        name="auto", policy_type="auto_isolate", trigger_type="alert_severity", trigger_conditions={},
        actions=[{"type": "host_isolate", "parameters": {}}], requires_approval=False,
        created_by=owner_id, organization_id=org_id,
    )
    db_session.add(policy)
    await db_session.commit()
    execution = await RemediationEngine(db_session).execute_remediation(
        policy.id, {"target_entity": "ws-auto", "target_type": "host"}, trigger_source="alert",
        organization_id=org_id,
    )
    await db_session.refresh(execution)
    step = execution.actions_completed[0]
    # No human in the loop: the agent command must wait for approval.
    assert step["status"] == "queued_for_approval"
    [cmd] = await _commands(db_session, "isolate_host")
    assert cmd.status == "awaiting_approval"


@pytest.mark.asyncio
async def test_crowdstrike_revert_refuses_invalid_hostname(db_session, org_a):
    from src.remediation.actions import revert_step

    step = {
        "action_type": "host_isolate", "path": "containment", "success": True, "status": "executed",
        "reversible": True, "target": "x",
        "revert": {"kind": "crowdstrike_lift_containment", "installation_id": "i-1", "hostname": "bad host'"},
    }
    outcome = await revert_step(db_session, org_a.id, step, actor="system:test", execution_ref=None)
    assert outcome["rolled_back"] is False
    assert "invalid_hostname" in outcome["reason"]


async def test_integration_base_url_cannot_point_at_internal_networks(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers: dict[str, str],
) -> None:
    """Stored base URLs go through the same outbound-target guard the engine applies
    before any call, so a tenant admin cannot aim the API host at metadata or loopback."""
    await _connector(db_session, "virustotal", "threat_intel")
    metadata = await client.post(
        f"{API}/integrations",
        json={"connector_id": "virustotal", "name": "VT", "config": {"base_url": "http://169.254.169.254/latest"}},
        headers=org_a_admin_headers,
    )
    assert metadata.status_code == 400, metadata.text
    assert metadata.json()["detail"]["error"] == "outbound_target_refused"

    ok = await client.post(
        f"{API}/integrations", json={"connector_id": "virustotal", "name": "VT"}, headers=org_a_admin_headers,
    )
    assert ok.status_code in (200, 201), ok.text
    integration_id = ok.json()["id"]

    loopback = await client.put(
        f"{API}/integrations/{integration_id}", json={"endpoint_url": "http://127.0.0.1:8500/v1"}, headers=org_a_admin_headers,
    )
    assert loopback.status_code == 400, loopback.text
    assert loopback.json()["detail"]["error"] == "outbound_target_refused"


async def test_every_outbound_config_value_is_guarded_not_only_base_url(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers: dict[str, str],
) -> None:
    """The validator checks by value (any http(s) URL, bare hosts under host-like
    keys), so it cannot drift from whichever key a connector or the probe reads."""
    await _connector(db_session, "slack", "notification")
    await _connector(db_session, "splunk", "siem")
    hook = await client.post(
        f"{API}/integrations",
        json={"connector_id": "slack", "name": "ops", "config": {"webhook_url": "http://169.254.169.254/hook"}},
        headers=org_a_admin_headers,
    )
    assert hook.status_code == 400, hook.text
    assert hook.json()["detail"] == {**hook.json()["detail"], "error": "outbound_target_refused", "field": "webhook_url"}

    host = await client.post(
        f"{API}/integrations",
        json={"connector_id": "splunk", "name": "splunk", "config": {"host": "127.0.0.1", "port": 8089}},
        headers=org_a_admin_headers,
    )
    assert host.status_code == 400, host.text
    assert host.json()["detail"]["field"] == "host"


async def test_connection_probe_refuses_internal_targets_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    """The probe itself applies the outbound guard, so a health check can never
    reach loopback, link-local or metadata addresses even for stored rows."""
    import httpx

    from src.integrations.engine import ConnectorRegistry, IntegrationManager

    class _NeverConnect:
        def __init__(self, *args, **kwargs):
            raise AssertionError("httpx must not be used for a refused target")

    monkeypatch.setattr(httpx, "AsyncClient", _NeverConnect)
    manager = IntegrationManager(ConnectorRegistry())
    health, message = await manager._probe_connector("webhook", {"webhook_url": "http://127.0.0.1:9/x"}, {})
    assert health == "unhealthy"
    assert message.startswith("outbound target refused")
    health2, message2 = await manager._probe_connector("splunk", {"base_url": "http://169.254.169.254"}, {})
    assert health2 == "unhealthy" and message2.startswith("outbound target refused")
