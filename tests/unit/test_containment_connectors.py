"""Containment through the Microsoft Defender, Okta and Entra ID adapters (src/services/containment.py).

Vendor HTTP is faked at the network boundary (tests/unit/connector_fakes.py:
DNS steered, the inner httpx transport replaced, PinnedTransport left in
front); the containment service, ActionExecutor and the connector classes run
for real, so every vendor call leaves an integration_executions row. The fake
bodies follow the response shapes in each vendor's API reference. No live
tenant was used.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

import httpx
import pytest
from sqlalchemy import func, select

from src.integrations.models import InstalledIntegration, IntegrationAction, IntegrationExecution
from src.models.audit import AuditLog
from src.remediation import actions as remediation_actions
from src.services import containment
from tests.unit.connector_fakes import VALID_FIELDS, ensure_connector_rows, fake_vendor, host_header

ORG = "cconn-org-a"
OTHER_ORG = "cconn-org-b"
MACHINE_ID = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07"
OTHER_MACHINE = "7f0a1c2d3e4b5a6978877665544332211ffeeddc"
ACTION_GUID = "2e9da30d-27f6-4208-81f2-9cd3d67893ba"
UNISOLATE_GUID = "3f8eb41e-38a7-4319-92a3-0de4e78904cb"
OKTA_USER = "00u1abcdEFGH2345ijkl"
ENTRA_USER = "6e7b768e-07e2-4810-8459-485f84f8f204"
MDE_TOKEN = "mde-access-token-0001"
GRAPH_TOKEN = "graph-access-token-0001"

Handler = Callable[[httpx.Request], httpx.Response]


async def _install(db, org: str, name: str, credentials: Optional[dict[str, Any]] = None) -> str:
    await ensure_connector_rows(db, name)
    config, creds = VALID_FIELDS[name]
    integ = InstalledIntegration(
        organization_id=org, connector_id=name, display_name=f"{name} ({org})",
        config_encrypted=json.dumps(config),
        auth_credentials_encrypted="__plaintext__:" + json.dumps(credentials or creds),
        status="active",
    )
    db.add(integ)
    await db.flush()
    return integ.id


async def _user(db, org: str, role: str) -> str:
    from src.core.security import get_password_hash
    from src.models.user import User

    user = User(
        email=f"{role}@{org}.example", hashed_password=get_password_hash("pw-fixture"), full_name=role,
        role=role, is_active=True, organization_id=org,
    )
    db.add(user)
    await db.flush()
    return user.id


def _json(request: httpx.Request) -> Any:
    return json.loads(request.content.decode()) if request.content else None


def _api(seen: list[httpx.Request], *hosts: str) -> list[tuple[str, str]]:
    return [(r.method, r.url.path) for r in seen if host_header(r) in hosts]


async def _executions(db, installation_id: str) -> list[IntegrationExecution]:
    return list((await db.execute(
        select(IntegrationExecution).where(IntegrationExecution.installed_id == installation_id),
    )).scalars().all())


async def _action_names(db, installation_id: str) -> list[str]:
    return sorted((await db.execute(
        select(IntegrationAction.action_name)
        .join(IntegrationExecution, IntegrationExecution.action_id == IntegrationAction.id)
        .where(IntegrationExecution.installed_id == installation_id),
    )).scalars().all())


def _refuse(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"no vendor request expected, got {request.method} {request.url}")


# --------------------------------------------------------------------------
# Microsoft Defender for Endpoint
# --------------------------------------------------------------------------


def _machine(machine_id: str, name: str) -> dict[str, Any]:
    return {
        "id": machine_id, "computerDnsName": name, "osPlatform": "Windows10", "healthStatus": "Active",
        "riskScore": "Medium", "lastIpAddress": "10.0.0.7",
    }


def _defender(machines: list[dict[str, Any]], *, get_name: Optional[str] = None, isolate_status: int = 201) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        host = host_header(request)
        if host == "login.microsoftonline.com":
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": MDE_TOKEN})
        assert host == "api.securitycenter.microsoft.com", host
        assert request.headers["authorization"] == f"Bearer {MDE_TOKEN}"
        path = request.url.path
        if request.method == "GET" and path == "/api/machines":
            return httpx.Response(200, json={"value": machines})
        if request.method == "GET" and path.startswith("/api/machines/"):
            mid = path.rsplit("/", 1)[-1]
            match = next(m for m in machines if m["id"] == mid)
            return httpx.Response(200, json={**match, "computerDnsName": get_name or match["computerDnsName"]})
        if request.method == "POST" and path == f"/api/machines/{MACHINE_ID}/isolate":
            if isolate_status >= 400:
                return httpx.Response(isolate_status, json={"error": {"code": "BadRequest", "message": "machine offline"}})
            return httpx.Response(201, json={
                "id": ACTION_GUID, "type": "Isolate", "status": "Pending", "machineId": MACHINE_ID,
                "requestor": "pysoar-app", "requestorComment": _json(request)["Comment"],
            })
        if request.method == "POST" and path == f"/api/machines/{MACHINE_ID}/unisolate":
            return httpx.Response(201, json={"id": UNISOLATE_GUID, "type": "Unisolate", "status": "Pending", "machineId": MACHINE_ID})
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": "unexpected"}})

    return handler


@pytest.mark.asyncio
async def test_defender_isolate_resolves_exact_name_then_isolates_full(db_session, monkeypatch):
    integ_id = await _install(db_session, ORG, "microsoft_defender")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, _defender([_machine(MACHINE_ID, "ws1.contoso.com")]))

    res = await containment.isolate_host(
        db_session, ORG, hostname="WS1.contoso.com", actor="system:playbook:ex-9", reason="ransomware",
        execution_ref="playbook_execution:ex-9",
    )
    assert res.status == containment.EXECUTED and not res.failed, res
    assert res.integration == "microsoft_defender" and res.integration_id == integ_id and res.reversible
    assert res.vendor_id == MACHINE_ID and res.vendor_action_id == ACTION_GUID
    assert ACTION_GUID in res.detail and "get_machine_action" in res.detail

    api = [r for r in seen if host_header(r) == "api.securitycenter.microsoft.com"]
    assert [(r.method, r.url.path) for r in api] == [
        ("GET", "/api/machines"), ("GET", f"/api/machines/{MACHINE_ID}"), ("POST", f"/api/machines/{MACHINE_ID}/isolate"),
    ]
    assert api[0].url.params["$filter"] == "computerDnsName eq 'ws1.contoso.com' or lastIpAddress eq 'ws1.contoso.com'"
    body = _json(api[2])
    assert body["IsolationType"] == "Full"
    assert "PySOAR" in body["Comment"] and "playbook_execution:ex-9" in body["Comment"]

    rows = await _executions(db_session, integ_id)
    assert sorted(r.status for r in rows) == ["success"] * 3
    assert sorted(res.integration_execution_ids) == sorted(r.id for r in rows)
    assert {r.playbook_run_id for r in rows} == {"playbook_execution:ex-9"}
    assert all(MDE_TOKEN not in (r.input_data or "") + (r.output_data or "") for r in rows)
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.id == res.audit_log_id))).scalar_one()
    assert audit.success is True and audit.organization_id == ORG
    assert json.loads(audit.new_value)["vendor_action_id"] == ACTION_GUID


@pytest.mark.asyncio
@pytest.mark.parametrize("machines,get_name,code", [
    ([], None, "host_not_found"),
    # search_machines also matches lastIpAddress / other names: only exact computerDnsName counts.
    ([_machine(OTHER_MACHINE, "ws1.contoso.com.evil.example")], None, "host_not_found"),
    ([_machine(MACHINE_ID, "ws1.contoso.com"), _machine(OTHER_MACHINE, "ws1.contoso.com")], None, "ambiguous_host"),
    # get_machine says the id belongs to another device.
    ([_machine(MACHINE_ID, "ws1.contoso.com")], "ws2.contoso.com", "host_not_found"),
])
async def test_defender_refuses_before_isolate(db_session, monkeypatch, machines, get_name, code):
    await _install(db_session, ORG, "microsoft_defender")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, _defender(machines, get_name=get_name))

    res = await containment.isolate_host(db_session, ORG, hostname="ws1.contoso.com", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.DETECTION_ONLY and res.failed and res.error.startswith(code), res
    assert not res.actuated and res.vendor_id is None
    assert not [r for r in seen if r.method == "POST" and r.url.path.endswith("/isolate")]


@pytest.mark.asyncio
async def test_defender_vendor_error_is_a_failed_result(db_session, monkeypatch):
    integ_id = await _install(db_session, ORG, "microsoft_defender")
    await db_session.commit()
    fake_vendor(monkeypatch, _defender([_machine(MACHINE_ID, "ws1.contoso.com")], isolate_status=400))

    res = await containment.isolate_host(db_session, ORG, hostname="ws1.contoso.com", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.DETECTION_ONLY and res.failed and not res.actuated
    assert res.error.startswith("isolate_machine:") and "400" in res.error
    assert MDE_TOKEN not in res.error and "mde-fixture-secret-0001" not in json.dumps(res.to_dict())
    rows = await _executions(db_session, integ_id)
    assert sorted(r.status for r in rows) == ["failed", "success", "success"]
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.id == res.audit_log_id))).scalar_one()
    assert audit.success is False


@pytest.mark.asyncio
async def test_unattended_defender_is_manual_required_without_vendor_calls(db_session, monkeypatch):
    await _install(db_session, ORG, "microsoft_defender")
    await db_session.commit()
    fake_vendor(monkeypatch, _refuse)
    res = await containment.isolate_host(
        db_session, ORG, hostname="ws1.contoso.com", actor="system:rule:r1", reason="rule", execution_ref="rule:r1",
        unattended=True,
    )
    assert res.status == containment.MANUAL_REQUIRED and not res.actuated
    assert res.integration == "microsoft_defender" and "isolate_machine" in res.detail


@pytest.mark.asyncio
async def test_crowdstrike_tried_first_then_defender_when_falcon_does_not_know_the_host(db_session, monkeypatch):
    # Rule: adapters run in ADAPTERS order (crowdstrike, then microsoft_defender);
    # host_not_found moves on to the next EDR, any other refusal stops.
    cs_id = await _install(db_session, ORG, "crowdstrike")
    mde_id = await _install(db_session, ORG, "microsoft_defender")
    await db_session.commit()
    falcon_devices: dict[str, str] = {}
    defender = _defender([_machine(MACHINE_ID, "ws1.contoso.com")])

    def handler(request: httpx.Request) -> httpx.Response:
        if host_header(request) == "api.crowdstrike.com":
            path = request.url.path
            if path == "/oauth2/token":
                return httpx.Response(201, json={"access_token": "cs-tok", "expires_in": 1800})
            if path == "/devices/queries/devices-scroll/v1":
                return httpx.Response(200, json={"resources": list(falcon_devices)})
            if path == "/devices/entities/devices/v2":
                dev = request.url.params["ids"]
                return httpx.Response(200, json={"resources": [{"device_id": dev, "hostname": falcon_devices[dev]}]})
            if path == "/devices/entities/devices-actions/v2":
                return httpx.Response(202, json={"resources": [{"id": "dev-1"}], "errors": []})
            return httpx.Response(404, json={})
        return defender(request)

    seen = fake_vendor(monkeypatch, handler)
    res = await containment.isolate_host(db_session, ORG, hostname="ws1.contoso.com", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.EXECUTED and res.integration == "microsoft_defender" and res.integration_id == mde_id
    assert ("POST", f"/api/machines/{MACHINE_ID}/isolate") in _api(seen, "api.securitycenter.microsoft.com")
    assert len(await _executions(db_session, cs_id)) == 1  # the Falcon lookup only

    # Falcon knows the host: CrowdStrike acts and Defender is never asked.
    falcon_devices["dev-1"] = "ws1.contoso.com"
    seen.clear()
    res = await containment.isolate_host(db_session, ORG, hostname="ws1.contoso.com", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.EXECUTED and res.integration == "crowdstrike" and res.vendor_id == "dev-1"
    assert _api(seen, "api.securitycenter.microsoft.com", "login.microsoftonline.com") == []

    # Ambiguous in Falcon: refused there, no fallthrough to Defender.
    falcon_devices["dev-2"] = "ws1.contoso.com"
    seen.clear()
    res = await containment.isolate_host(db_session, ORG, hostname="ws1.contoso.com", actor="system:t", reason="r", execution_ref=None)
    assert res.failed and res.error.startswith("ambiguous_host") and res.integration == "crowdstrike"
    assert _api(seen, "api.securitycenter.microsoft.com") == []


@pytest.mark.asyncio
async def test_other_tenants_defender_is_never_used(db_session, monkeypatch):
    await _install(db_session, OTHER_ORG, "microsoft_defender")
    await db_session.commit()
    fake_vendor(monkeypatch, _refuse)
    res = await containment.isolate_host(db_session, ORG, hostname="ws1.contoso.com", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.DETECTION_ONLY and res.integration is None


@pytest.mark.asyncio
async def test_defender_isolation_reverted_with_unisolate(db_session, monkeypatch):
    integ_id = await _install(db_session, ORG, "microsoft_defender")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, _defender([_machine(MACHINE_ID, "ws1.contoso.com")]))

    step = await remediation_actions.run_action(
        db_session, ORG, "host_isolate", "ws1.contoso.com", actor="system:remediation:x", reason="r",
        execution_ref="remediation:x",
    )
    assert step["success"] and step["reversible"], step
    assert step["revert"] == {
        "kind": "integration_revert", "action": "isolate_host", "connector": "microsoft_defender",
        "installation_id": integ_id, "vendor_id": MACHINE_ID, "target": "ws1.contoso.com",
    }
    seen.clear()
    outcome = await remediation_actions.revert_step(db_session, ORG, step, actor="system:remediation:x", execution_ref="remediation:x")
    assert outcome["rolled_back"] is True, outcome
    unisolate = [r for r in seen if r.url.path == f"/api/machines/{MACHINE_ID}/unisolate"]
    assert len(unisolate) == 1 and "PySOAR" in _json(unisolate[0])["Comment"]
    assert outcome["reverse_commands"][0]["vendor_action_id"] == UNISOLATE_GUID

    # Another organisation cannot replay the handle against this installation.
    seen.clear()
    other = await remediation_actions.revert_step(db_session, OTHER_ORG, step, actor="system:t", execution_ref=None)
    assert other["rolled_back"] is False and "no longer active" in other["reason"]
    assert seen == []


# --------------------------------------------------------------------------
# Okta and Microsoft Entra ID
# --------------------------------------------------------------------------


def _okta(*, status: str = "ACTIVE", login: str = "ada@corp.io", revoke_status: int = 204, missing: bool = False) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        assert host_header(request) == "acme.okta.com"
        assert request.headers["authorization"] == "SSWS okta-fixture-token-0001"
        path = request.url.path
        if request.method == "GET" and path.startswith("/api/v1/users/"):
            if missing:
                return httpx.Response(404, json={"errorCode": "E0000007", "errorSummary": "Not found: Resource not found"})
            return httpx.Response(200, json={
                "id": OKTA_USER, "status": status,
                "profile": {"login": login, "email": login, "firstName": "Ada", "lastName": "L"},
            })
        if request.method == "POST" and path in (
            f"/api/v1/users/{OKTA_USER}/lifecycle/suspend", f"/api/v1/users/{OKTA_USER}/lifecycle/unsuspend",
        ):
            return httpx.Response(200, json={})
        if request.method == "DELETE" and path == f"/api/v1/users/{OKTA_USER}/sessions":
            if revoke_status >= 400:
                return httpx.Response(revoke_status, json={"errorCode": "E0000006", "errorSummary": "forbidden"})
            return httpx.Response(204)
        return httpx.Response(404, json={"errorSummary": "unexpected"})

    return handler


def _entra(*, enabled: bool = True, upn: str = "ada@contoso.com") -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        host = host_header(request)
        if host == "login.microsoftonline.com":
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": GRAPH_TOKEN})
        assert host == "graph.microsoft.com"
        path = request.url.path
        if request.method == "GET" and path.startswith("/v1.0/users/"):
            return httpx.Response(200, json={"id": ENTRA_USER, "userPrincipalName": upn, "accountEnabled": enabled})
        if request.method == "PATCH" and path == f"/v1.0/users/{ENTRA_USER}":
            return httpx.Response(204)
        if request.method == "POST" and path == f"/v1.0/users/{ENTRA_USER}/revokeSignInSessions":
            return httpx.Response(200, json={"value": True})
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": "unexpected"}})

    return handler


@pytest.mark.asyncio
async def test_okta_disable_suspends_and_revokes_for_an_admin(db_session, monkeypatch):
    integ_id = await _install(db_session, ORG, "okta")
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, _okta())

    res = await containment.disable_user(
        db_session, ORG, username="Ada@corp.io", actor=admin, reason="token theft", execution_ref="playbook_execution:p1",
    )
    assert res.status == containment.EXECUTED and not res.failed and res.reversible, res
    assert res.integration == "okta" and res.vendor_id == OKTA_USER and "revoked" in res.detail
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/api/v1/users/Ada@corp.io"),
        ("POST", f"/api/v1/users/{OKTA_USER}/lifecycle/suspend"),
        ("DELETE", f"/api/v1/users/{OKTA_USER}/sessions"),
    ]
    rows = await _executions(db_session, integ_id)
    assert await _action_names(db_session, integ_id) == ["get_user", "revoke_sessions", "suspend_user"]
    assert sorted(res.integration_execution_ids) == sorted(r.id for r in rows)
    assert all("okta-fixture-token-0001" not in (r.input_data or "") for r in rows)
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.id == res.audit_log_id))).scalar_one()
    assert audit.user_id == admin and audit.success is True


@pytest.mark.asyncio
async def test_entra_disable_disables_and_revokes_for_an_admin(db_session, monkeypatch):
    integ_id = await _install(db_session, ORG, "azure_ad")
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, _entra())

    res = await containment.disable_user(db_session, ORG, username="ada@contoso.com", actor=admin, reason="r", execution_ref="x")
    assert res.status == containment.EXECUTED and res.integration == "azure_ad" and res.vendor_id == ENTRA_USER, res
    graph = [r for r in seen if host_header(r) == "graph.microsoft.com"]
    assert [(r.method, r.url.path) for r in graph] == [
        ("GET", "/v1.0/users/ada@contoso.com"),
        ("PATCH", f"/v1.0/users/{ENTRA_USER}"),
        ("POST", f"/v1.0/users/{ENTRA_USER}/revokeSignInSessions"),
    ]
    assert _json(graph[1]) == {"accountEnabled": False}
    assert await _action_names(db_session, integ_id) == ["disable_user", "get_user", "revoke_sign_in_sessions"]
    assert len(res.integration_execution_ids) == 3


@pytest.mark.asyncio
async def test_identity_disable_never_actuates_unattended_or_for_a_non_admin(db_session, monkeypatch):
    await _install(db_session, ORG, "okta")
    analyst = await _user(db_session, ORG, "analyst")
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    fake_vendor(monkeypatch, _refuse)

    for kwargs in (
        {"actor": admin, "unattended": True},             # automation rule / scheduled run
        {"actor": "system:playbook:ex-1"},                 # no human actor
        {"actor": analyst},                                # a human, but not an administrator
        {"actor": analyst, "approval_override": True},     # an override does not make an analyst an admin
    ):
        res = await containment.disable_user(db_session, ORG, username="ada@corp.io", reason="r", execution_ref=None, **kwargs)
        assert res.status == containment.MANUAL_REQUIRED and not res.actuated, (kwargs, res)
        assert res.integration == "okta" and "suspend_user" in res.detail
    assert (await db_session.execute(select(func.count(IntegrationExecution.id)))).scalar() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("username", ["jdoe", "ada @corp.io", "ada@corp.io/../x", "a@b@c.io", '"ada"@corp.io',
                                      "ada@corp.io?x=1", "x" * 320 + "@corp.io"])
async def test_invalid_login_refused_before_any_lookup(db_session, monkeypatch, username):
    await _install(db_session, ORG, "okta")
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    fake_vendor(monkeypatch, _refuse)
    res = await containment.disable_user(db_session, ORG, username=username, actor=admin, reason="r", execution_ref=None)
    assert res.status == containment.DETECTION_ONLY and res.failed and res.error == "invalid_login", res
    assert (await db_session.execute(select(func.count(IntegrationExecution.id)))).scalar() == 0


@pytest.mark.asyncio
async def test_okta_unknown_user_falls_through_to_entra_and_mismatch_refuses(db_session, monkeypatch):
    await _install(db_session, ORG, "okta")
    await _install(db_session, ORG, "azure_ad")
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    okta, entra = _okta(missing=True), _entra(upn="ada@corp.io")
    seen = fake_vendor(monkeypatch, lambda r: okta(r) if host_header(r) == "acme.okta.com" else entra(r))

    res = await containment.disable_user(db_session, ORG, username="ada@corp.io", actor=admin, reason="r", execution_ref=None)
    assert res.status == containment.EXECUTED and res.integration == "azure_ad", res
    assert not [r for r in seen if host_header(r) == "acme.okta.com" and r.method != "GET"]

    # Neither provider's answer is exactly this login: refused, nothing changed anywhere.
    okta = _okta(login="ada.lovelace@corp.io")
    entra = _entra(upn="ada.l@corp.io")
    seen.clear()
    res = await containment.disable_user(db_session, ORG, username="ada@corp.io", actor=admin, reason="r", execution_ref=None)
    assert res.failed and res.error.startswith("user_not_found")
    assert not [r for r in seen if r.method != "GET" and host_header(r) != "login.microsoftonline.com"]


@pytest.mark.asyncio
async def test_okta_partial_failure_is_reported_not_executed_cleanly(db_session, monkeypatch):
    await _install(db_session, ORG, "okta")
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    fake_vendor(monkeypatch, _okta(revoke_status=403))
    res = await containment.disable_user(db_session, ORG, username="ada@corp.io", actor=admin, reason="r", execution_ref=None)
    # The account WAS suspended; the revocation failed: actuated, failed, and said so.
    assert res.status == containment.EXECUTED and res.failed and res.error.startswith("revoke_sessions:")
    assert "suspended" in res.detail and "FAILED" in res.detail
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.id == res.audit_log_id))).scalar_one()
    assert audit.success is False


@pytest.mark.asyncio
async def test_already_suspended_okta_user_is_not_reversible(db_session, monkeypatch):
    await _install(db_session, ORG, "okta")
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, _okta(status="SUSPENDED"))
    res = await containment.disable_user(db_session, ORG, username="ada@corp.io", actor=admin, reason="r", execution_ref=None)
    assert res.status == containment.EXECUTED and res.reversible is False and "already SUSPENDED" in res.detail
    assert [r.method for r in seen] == ["GET", "DELETE"]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,handler,reverse", [
    ("okta", _okta(), ("POST", f"/api/v1/users/{OKTA_USER}/lifecycle/unsuspend")),
    ("azure_ad", _entra(upn="ada@corp.io"), ("PATCH", f"/v1.0/users/{ENTRA_USER}")),
])
async def test_identity_disable_reverted_by_rollback(db_session, monkeypatch, name, handler, reverse):
    await _install(db_session, ORG, name)
    admin = await _user(db_session, ORG, "admin")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, handler)

    step = await remediation_actions.run_action(
        db_session, ORG, "account_disable", "ada@corp.io", actor=admin, reason="r", execution_ref="remediation:y",
    )
    assert step["success"] and step["reversible"] and step["revert"]["kind"] == "integration_revert", step
    seen.clear()
    outcome = await remediation_actions.revert_step(db_session, ORG, step, actor=admin, execution_ref="remediation:y")
    assert outcome["rolled_back"] is True, outcome
    calls = [(r.method, r.url.path) for r in seen if host_header(r) != "login.microsoftonline.com"]
    assert calls == [reverse]
    if name == "azure_ad":
        assert _json(seen[-1]) == {"accountEnabled": True}
    assert "cannot be restored" in outcome["reverse_commands"][0]["detail"]


@pytest.mark.asyncio
async def test_long_execution_reference_still_leaves_execution_rows(db_session, monkeypatch):
    # integration_executions.playbook_run_id is VARCHAR(100) since migration 039:
    # the full playbook reference is stored; only a longer one is cut to its tail.
    integ_id = await _install(db_session, ORG, "microsoft_defender")
    await db_session.commit()
    fake_vendor(monkeypatch, _defender([_machine(MACHINE_ID, "ws1.contoso.com")]))
    run_id = "0f8fad5b-d9cb-469f-a165-70867728950e"
    res = await containment.isolate_host(
        db_session, ORG, hostname="ws1.contoso.com", actor="system:t", reason="r", execution_ref=f"playbook_execution:{run_id}",
    )
    assert res.status == containment.EXECUTED
    assert {r.playbook_run_id for r in await _executions(db_session, integ_id)} == {f"playbook_execution:{run_id}"}
    assert containment.engine_run_ref("x" * 150) == "x" * 100 and containment.engine_run_ref(None) is None


def test_adapter_table_and_executable_connectors():
    assert containment._EXECUTABLE_CONNECTORS == {
        "isolate_host": ("crowdstrike", "microsoft_defender"),
        "disable_user": ("okta", "azure_ad"),
    }
    assert containment.adapter_for("isolate_host", "microsoft_defender").operation == "isolate_machine"
    assert containment.adapter_for("quarantine_file", "crowdstrike") is None
    assert all(a.identity for a in containment.ADAPTERS["disable_user"])


@pytest.mark.parametrize("value", ["ada@corp.io", "first.last+ir@sub.corp.example", "svc_bot@localdomain"])
def test_validate_login_accepts(value):
    assert containment._validate_login(f"  {value} ") == value


@pytest.mark.asyncio
@pytest.mark.parametrize("name,handler", [("okta", _okta()), ("azure_ad", _entra(upn="ada@corp.io"))])
async def test_identity_rollback_refused_unless_attended_admin(db_session, monkeypatch, name, handler):
    await _install(db_session, ORG, name)
    admin = await _user(db_session, ORG, "admin")
    analyst = await _user(db_session, ORG, "analyst")
    await db_session.commit()
    seen = fake_vendor(monkeypatch, handler)
    step = await remediation_actions.run_action(
        db_session, ORG, "account_disable", "ada@corp.io", actor=admin, reason="r", execution_ref="remediation:z",
    )
    assert step["success"] and step["revert"]["kind"] == "integration_revert", step

    for kwargs in (
        {"actor": admin, "unattended": True},          # no human clicked rollback
        {"actor": analyst},                            # a human, not an itdr administrator
        {"actor": "system:remediation:z"},             # engine rollback without a user
    ):
        seen.clear()
        refused = await remediation_actions.revert_step(db_session, ORG, step, execution_ref="remediation:z", **kwargs)
        assert refused["rolled_back"] is False, (kwargs, refused)
        assert f"{name} re-enable requires an itdr administrator" in refused["reason"]
        assert seen == [], kwargs

    seen.clear()
    allowed = await remediation_actions.revert_step(db_session, ORG, step, actor=admin, execution_ref="remediation:z")
    assert allowed["rolled_back"] is True and [r for r in seen if host_header(r) != "login.microsoftonline.com"]
