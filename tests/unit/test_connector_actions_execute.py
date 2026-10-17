"""Connector actions: seeded from the class on install, validated against
their ``params_schema``, executed through the class method, and recorded as
one honest execution row (a vendor 4xx is ``failed`` with its HTTP status,
never ``success`` with an error body). Planned connectors cannot execute and
the playbook / containment callers get a failed result, not an exception.
"""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import func, select

from src.integrations.engine import CONNECTOR_CLASS_MAP, ActionExecutor
from src.integrations.models import IntegrationAction, IntegrationExecution, InstalledIntegration
from tests.unit.connector_fakes import VALID_FIELDS, ensure_connector_rows, fake_vendor

BASE = "/api/v1/integrations"


async def _install(client, headers, name: str) -> str:
    config, credentials = VALID_FIELDS[name]
    resp = await client.post(
        f"{BASE}/install",
        json={"connector_id": name, "display_name": name, "config": config, "credentials": credentials},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _actions(client, headers, integration_id: str) -> dict[str, dict]:
    resp = await client.get(f"{BASE}/installed/{integration_id}/actions", params={"size": 100}, headers=headers)
    assert resp.status_code == 200, resp.text
    return {a["action_name"]: a for a in resp.json()["items"]}


async def _executions(db, integration_id: str) -> list[IntegrationExecution]:
    rows = (await db.execute(
        select(IntegrationExecution).where(IntegrationExecution.installed_id == integration_id)
    )).scalars().all()
    for r in rows:
        await db.refresh(r)
    return list(rows)


@pytest.mark.asyncio
async def test_install_seeds_action_rows_with_real_schemas(client, org_a_admin_headers, org_a_headers) -> None:
    vt = await _install(client, org_a_admin_headers, "virustotal")
    actions = await _actions(client, org_a_headers, vt)
    assert set(actions) == set(CONNECTOR_CLASS_MAP["virustotal"].ACTIONS)
    scan_ip = actions["scan_ip"]
    assert scan_ip["input_schema"]["required"] == ["ip"]
    assert scan_ip["input_schema"]["properties"]["ip"]["type"] == "string"
    assert scan_ip["requires_approval"] is False and scan_ip["is_idempotent"] is True
    assert scan_ip["description"].startswith("IP address report")

    slack = await _install(client, org_a_admin_headers, "slack")
    slack_actions = await _actions(client, org_a_headers, slack)
    assert slack_actions["send_message"]["requires_approval"] is True  # changes vendor state
    assert slack_actions["list_channels"]["requires_approval"] is False


@pytest.mark.asyncio
async def test_bad_params_are_422_and_nothing_runs(client, db_session, org_a_admin_headers, org_a_headers, monkeypatch) -> None:
    vt = await _install(client, org_a_admin_headers, "virustotal")
    action_id = (await _actions(client, org_a_headers, vt))["scan_ip"]["id"]

    def _never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no vendor call for invalid parameters")

    fake_vendor(monkeypatch, _never)
    for bad in ({}, {"ip": 42}, {"ip": "8.8.8.8", "url": "http://169.254.169.254/"}):
        resp = await client.post(f"{BASE}/installed/{vt}/actions/{action_id}/execute", json={"input_data": bad}, headers=org_a_headers)
        assert resp.status_code == 422, resp.text
        assert resp.json()["detail"]["error"] == "invalid_parameters"
    assert await _executions(db_session, vt) == []


@pytest.mark.asyncio
async def test_vendor_success_is_one_success_row(client, db_session, org_a_admin_headers, org_a_headers, monkeypatch) -> None:
    vt = await _install(client, org_a_admin_headers, "virustotal")
    action_id = (await _actions(client, org_a_headers, vt))["scan_ip"]["id"]
    body = {"data": {"id": "203.0.113.9", "attributes": {
        "reputation": -12, "country": "NL", "asn": 64500, "as_owner": "Example AS",
        "last_analysis_stats": {"malicious": 4, "suspicious": 1, "harmless": 60, "undetected": 20},
    }}}
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json=body))

    resp = await client.post(
        f"{BASE}/installed/{vt}/actions/{action_id}/execute", json={"input_data": {"ip": "203.0.113.9"}}, headers=org_a_headers,
    )
    assert resp.status_code == 202, resp.text
    out = resp.json()
    assert out["status"] == "success" and out["error_message"] is None
    assert out["output_data"]["malicious"] == 4 and out["output_data"]["country"] == "NL"
    assert [r.url.path for r in seen] == ["/api/v3/ip_addresses/203.0.113.9"]

    rows = await _executions(db_session, vt)
    assert len(rows) == 1 and rows[0].id == out["id"] and rows[0].status == "success"
    assert rows[0].action_id == action_id and rows[0].organization_id
    assert json.loads(rows[0].output_data)["malicious"] == 4


@pytest.mark.asyncio
async def test_vendor_4xx_is_a_failed_row_with_its_status(client, db_session, org_a_admin_headers, org_a_headers, monkeypatch) -> None:
    jira = await _install(client, org_a_admin_headers, "jira")
    action_id = (await _actions(client, org_a_headers, jira))["get_issue"]["id"]
    fake_vendor(monkeypatch, lambda request: httpx.Response(
        404, json={"errorMessages": ["Issue does not exist or you do not have permission to see it."], "errors": {}},
    ))

    resp = await client.post(
        f"{BASE}/installed/{jira}/actions/{action_id}/execute", json={"input_data": {"key": "SEC-404"}}, headers=org_a_headers,
    )
    assert resp.status_code == 202, resp.text
    out = resp.json()
    assert out["status"] == "failed" and out["http_status"] == 404
    assert "HTTP 404" in out["error_message"] and "Issue does not exist" in out["error_message"]
    assert "jira-fixture-token-0001" not in resp.text
    rows = await _executions(db_session, jira)
    assert [r.status for r in rows] == ["failed"]


@pytest.mark.asyncio
async def test_slack_ok_false_is_failed_not_success(client, db_session, org_a_admin_headers, org_a_headers, monkeypatch) -> None:
    slack = await _install(client, org_a_admin_headers, "slack")
    action_id = (await _actions(client, org_a_headers, slack))["send_message"]["id"]
    fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"ok": False, "error": "channel_not_found"}))
    resp = await client.post(
        f"{BASE}/installed/{slack}/actions/{action_id}/execute",
        json={"input_data": {"channel": "C0NOPE", "text": "hello"}}, headers=org_a_admin_headers,  # side effect: admin
    )
    assert resp.json()["status"] == "failed" and "channel_not_found" in resp.json()["error_message"]


@pytest.mark.asyncio
async def test_side_effect_actions_need_an_administrator(client, db_session, org_a_admin_headers, org_a_headers, monkeypatch) -> None:
    """An analyst can run read-only actions; one that changes the vendor's
    state is refused with 403 approval_required, nothing is sent, and the
    refusal is audited. An administrator runs it."""
    from src.models.audit import AuditLog

    slack = await _install(client, org_a_admin_headers, "slack")
    actions = await _actions(client, org_a_headers, slack)
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"ok": True, "channels": [], "ts": "1.2"}))

    refused = await client.post(
        f"{BASE}/installed/{slack}/actions/{actions['send_message']['id']}/execute",
        json={"input_data": {"channel": "C0GOOD", "text": "hello"}}, headers=org_a_headers,
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["error"] == "approval_required"
    assert seen == [] and await _executions(db_session, slack) == []
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "integration_action_execute", AuditLog.resource_id == slack)
    )).scalars().all()
    assert rows and any("approval_required" in (r.description or "") for r in rows)

    read_only = await client.post(
        f"{BASE}/installed/{slack}/actions/{actions['list_channels']['id']}/execute",
        json={"input_data": {}}, headers=org_a_headers,
    )
    assert read_only.status_code == 202, read_only.text

    allowed = await client.post(
        f"{BASE}/installed/{slack}/actions/{actions['send_message']['id']}/execute",
        json={"input_data": {"channel": "C0GOOD", "text": "hello"}}, headers=org_a_admin_headers,
    )
    assert allowed.status_code == 202, allowed.text


@pytest.mark.asyncio
async def test_planned_connector_execute_is_501(client, db_session, org_a, org_a_headers) -> None:
    await ensure_connector_rows(db_session, "palo_alto_ngfw")
    row = InstalledIntegration(
        organization_id=org_a.id, connector_id="palo_alto_ngfw", display_name="NGFW",
        config_encrypted="{}", auth_credentials_encrypted="", status="active",
    )
    db_session.add(row)
    await db_session.commit()
    resp = await client.post(f"{BASE}/installed/{row.id}/actions/any/execute", json={"input_data": {}}, headers=org_a_headers)
    assert resp.status_code == 501
    assert resp.json()["detail"]["error"] == "not_implemented"


@pytest.mark.asyncio
async def test_engine_callers_get_honest_failures(client, db_session, org_a, org_a_admin_headers) -> None:
    """What playbooks, containment, remediation and the agent tools see."""
    from src.playbooks.actions import ExecuteIntegrationAction

    await ensure_connector_rows(db_session, "okta")
    planned = InstalledIntegration(
        organization_id=org_a.id, connector_id="okta", display_name="Okta",
        config_encrypted="{}", auth_credentials_encrypted="", status="active",
    )
    db_session.add(planned)
    await db_session.commit()
    planned_id = planned.id
    cs = await _install(client, org_a_admin_headers, "crowdstrike")

    result = await ActionExecutor().execute_action(planned_id, "disable_user", {"username": "jdoe"})
    assert result["status"] == "failed" and result["error_code"] == "not_implemented"
    assert "Okta has no connector implementation" in result["error_message"]

    result = await ActionExecutor().execute_action(cs, "isolate", {"device_id": "d-1"})
    assert result["status"] == "failed" and result["error_code"] == "unknown_action"
    assert "available: [" in result["error_message"] and "contain_host" in result["error_message"]
    assert result["execution_id"] is None  # no action row is invented for an undeclared name

    playbook = await ExecuteIntegrationAction().execute(
        {"installation_id": cs, "action_name": "remediate", "input_data": {}}, {},
    )
    assert playbook["success"] is False and playbook["execution"]["status"] == "failed"

    count = (await db_session.execute(
        select(func.count(IntegrationAction.id)).where(IntegrationAction.action_name.in_(["isolate", "remediate", "disable_user"]))
    )).scalar()
    assert count == 0
