"""src/services/containment.py: real actuation paths, honest states, audit, tenancy.

The agent transport is the AgentCommand queue (rows asserted directly); the
integration path is exercised end to end through ``ActionExecutor`` and the
CrowdStrike connector with HTTP mocked at the httpx transport.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

from src.agents.models import AgentCommand, EndpointAgent
from src.integrations.models import InstalledIntegration, IntegrationConnector
from src.models.asset import Asset
from src.models.audit import AuditLog
from src.services import containment

ORG_A = "cont-org-a"
ORG_B = "cont-org-b"
_REAL_CLIENT = httpx.AsyncClient


async def _agent(db, org: str, hostname: str, capabilities: list[str], status: str = "active") -> EndpointAgent:
    ag = EndpointAgent(
        hostname=hostname, display_name=hostname, os_type="linux", status=status,
        capabilities=capabilities, organization_id=org,
    )
    db.add(ag)
    await db.flush()
    return ag


async def _install(db, org: str, connector_name: str, category: str) -> InstalledIntegration:
    connector = (
        await db.execute(select(IntegrationConnector).where(IntegrationConnector.name == connector_name))
    ).scalar_one_or_none()
    if connector is None:
        connector = IntegrationConnector(
            name=connector_name, display_name=connector_name, category=category,
            supported_actions="[]", supported_triggers="[]", config_schema="{}",
        )
        db.add(connector)
        await db.flush()
    integ = InstalledIntegration(
        organization_id=org, connector_id=connector.id, display_name=f"{connector_name} ({org})",
        config_encrypted="{}",
        auth_credentials_encrypted="__plaintext__:" + json.dumps({"client_id": "cid", "client_secret": "sec"}),
        status="active",
    )
    db.add(integ)
    await db.flush()
    return integ


async def _audit_rows(db, org: str) -> list[AuditLog]:
    return list((await db.execute(select(AuditLog).where(AuditLog.organization_id == org))).scalars().all())


@pytest.mark.asyncio
async def test_isolate_host_agent_present_queues_command(db_session):
    db_session.add(Asset(name="web-01", hostname="web-01", asset_type="server", status="active", organization_id=ORG_A))
    ag = await _agent(db_session, ORG_A, "web-01", ["ir"])
    await db_session.commit()

    res = await containment.isolate_host(
        db_session, ORG_A, hostname="web-01", actor="system:playbook:ex-1", reason="ransomware", execution_ref="ex-1",
    )
    # isolate_host is high-blast: without an override it waits in the agent approval queue.
    assert res.status == containment.QUEUED_FOR_APPROVAL
    assert res.reversible is True and res.agent_id == ag.id
    cmd = await db_session.get(AgentCommand, res.command_id)
    assert cmd.agent_id == ag.id and cmd.action == "isolate_host" and cmd.status == "awaiting_approval"
    assert cmd.organization_id == ORG_A

    res2 = await containment.isolate_host(
        db_session, ORG_A, hostname="web-01", actor="system:playbook:ex-1", reason="r", execution_ref="ex-1",
        approval_override=True,
    )
    assert res2.status == containment.EXECUTED and res2.command_status == "queued"


@pytest.mark.asyncio
async def test_block_ip_agent_present_queues_command(db_session):
    a1 = await _agent(db_session, ORG_A, "ir-01", ["ir"])
    await _agent(db_session, ORG_A, "bas-01", ["bas"])
    await db_session.commit()

    res = await containment.block_ip(
        db_session, ORG_A, ip="203.0.113.9", actor="system:playbook:ex-2", reason="c2", execution_ref="ex-2",
        approval_override=True,
    )
    assert res.status == containment.EXECUTED and res.reversible
    assert [c["agent_id"] for c in res.commands] == [a1.id]
    cmd = await db_session.get(AgentCommand, res.command_id)
    assert cmd.payload["ip"] == "203.0.113.9" and cmd.status == "queued"


@pytest.mark.asyncio
async def test_no_agent_no_integration_is_detection_only(db_session):
    await db_session.commit()
    for res in (
        await containment.block_ip(db_session, ORG_A, ip="198.51.100.1", actor="system:t", reason="r", execution_ref=None),
        await containment.isolate_host(db_session, ORG_A, hostname="ghost", actor="system:t", reason="r", execution_ref=None),
        await containment.disable_user(db_session, ORG_A, username="jdoe", actor="system:t", reason="r", execution_ref=None),
        await containment.quarantine_file(
            db_session, ORG_A, hostname="ghost", file_path="/tmp/x", actor="system:t", reason="r", execution_ref=None,
        ),
    ):
        assert res.status == containment.DETECTION_ONLY, res
        assert not res.actuated and res.reversible is False and res.command_id is None
        assert res.missing_dependency
    assert (await db_session.execute(select(func.count(AgentCommand.id)))).scalar() == 0


@pytest.mark.asyncio
async def test_installed_but_unimplemented_integration_is_awaiting_integration(db_session):
    # Okta and Entra ID now have adapters (tests/unit/test_containment_connectors.py);
    # an identity-provider row without one still reports awaiting_integration.
    await _install(db_session, ORG_A, "onelogin", "identity_provider")
    await _install(db_session, ORG_A, "palo_alto_ngfw", "firewall")
    await _install(db_session, ORG_A, "sentinelone", "edr")
    await db_session.commit()

    res = await containment.disable_user(db_session, ORG_A, username="jdoe", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.AWAITING_INTEGRATION and "onelogin" in res.missing_dependency
    res = await containment.block_ip(db_session, ORG_A, ip="198.51.100.2", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.AWAITING_INTEGRATION and "palo_alto_ngfw" in res.missing_dependency
    res = await containment.isolate_host(db_session, ORG_A, hostname="ws-1", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.AWAITING_INTEGRATION and res.missing_dependency == "isolate_host connector implementation for sentinelone"


@pytest.mark.asyncio
async def test_integration_present_called_through_engine(db_session, monkeypatch):
    integ = await _install(db_session, ORG_A, "crowdstrike", "edr")
    await db_session.commit()
    integ_id = integ.id

    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "tok", "expires_in": 1800})
        if request.url.path == "/devices/queries/devices-scroll/v1":
            assert "hostname:'db-07'" in request.url.params["filter"]
            return httpx.Response(200, json={"resources": ["dev-123"]})
        if request.url.path == "/devices/entities/devices/v2":
            assert request.url.params["ids"] == "dev-123"
            return httpx.Response(200, json={"resources": [{"device_id": "dev-123", "hostname": "DB-07"}]})
        if request.url.path == "/devices/entities/devices-actions/v2":
            assert request.url.params["action_name"] == "contain"
            assert json.loads(request.content)["ids"] == ["dev-123"]
            return httpx.Response(202, json={"resources": [{"id": "dev-123"}], "errors": []})
        return httpx.Response(404, json={})

    real_client = httpx.AsyncClient

    def client_factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)

    res = await containment.isolate_host(
        db_session, ORG_A, hostname="db-07", actor="system:playbook:ex-3", reason="r", execution_ref="ex-3",
    )
    assert res.status == containment.EXECUTED, res
    assert res.integration == "crowdstrike" and res.integration_execution_id and res.reversible
    assert ("POST", "/devices/entities/devices-actions/v2") in seen
    from src.integrations.models import IntegrationExecution

    rows = (await db_session.execute(
        select(IntegrationExecution).where(IntegrationExecution.installed_id == integ_id),
    )).scalars().all()
    assert {r.status for r in rows} == {"success"} and len(rows) == 3


@pytest.mark.asyncio
async def test_integration_failure_is_not_executed(db_session, monkeypatch):
    await _install(db_session, ORG_A, "crowdstrike", "edr")
    await db_session.commit()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "tok", "expires_in": 1800})
        return httpx.Response(200, json={"resources": []})  # host unknown to Falcon

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(handler)}),
    )
    res = await containment.isolate_host(db_session, ORG_A, hostname="nohost", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.DETECTION_ONLY and res.failed and res.error.startswith("host_not_found")


@pytest.mark.asyncio
async def test_audit_row_written_per_call(db_session):
    from src.core.security import get_password_hash
    from src.models.user import User

    user = User(
        email="analyst@cont.io", hashed_password=get_password_hash("pw"), full_name="a",
        role="analyst", is_active=True, organization_id=ORG_A,
    )
    db_session.add(user)
    await _agent(db_session, ORG_A, "ir-09", ["ir"])
    await db_session.commit()

    res = await containment.block_ip(
        db_session, ORG_A, ip="203.0.113.50", actor=user.id, reason="beacon", execution_ref="playbook_execution:x",
    )
    await containment.isolate_host(db_session, ORG_A, hostname="none", actor="system:playbook:x", reason="r", execution_ref="x")
    rows = await _audit_rows(db_session, ORG_A)
    assert len(rows) == 2
    by_action = {r.action: r for r in rows}
    blk = by_action["containment_block_ip"]
    assert blk.user_id == user.id and blk.id == res.audit_log_id and blk.success is True
    payload = json.loads(blk.new_value)
    assert payload["status"] == res.status and payload["actor"] == user.id and payload["execution_ref"] == "playbook_execution:x"
    iso = by_action["containment_isolate_host"]
    assert iso.user_id is None and iso.success is False
    assert json.loads(iso.new_value)["actor"] == "system:playbook:x"
    # The audit command issuer is the real user.
    cmd = await db_session.get(AgentCommand, res.command_id)
    assert cmd.issued_by == user.id


@pytest.mark.asyncio
async def test_cross_tenant_agent_never_selected(db_session):
    await _agent(db_session, ORG_B, "shared-host", ["ir"])
    await _install(db_session, ORG_B, "crowdstrike", "edr")
    await db_session.commit()

    for res in (
        await containment.isolate_host(db_session, ORG_A, hostname="shared-host", actor="system:t", reason="r", execution_ref=None),
        await containment.block_ip(db_session, ORG_A, ip="203.0.113.77", actor="system:t", reason="r", execution_ref=None),
        await containment.quarantine_file(
            db_session, ORG_A, hostname="shared-host", file_path="C:/x.exe", actor="system:t", reason="r", execution_ref=None,
        ),
        await containment.disable_user(
            db_session, ORG_A, username="u", hostname="shared-host", actor="system:t", reason="r", execution_ref=None,
        ),
    ):
        assert res.status == containment.DETECTION_ONLY and res.agent_id is None and res.integration is None
    assert (await db_session.execute(select(func.count(AgentCommand.id)))).scalar() == 0
    assert await _audit_rows(db_session, ORG_B) == []


@pytest.mark.asyncio
async def test_quarantine_and_disable_user_via_host_agent(db_session):
    ag = await _agent(db_session, ORG_A, "ws-12", ["ir"])
    await db_session.commit()
    q = await containment.quarantine_file(
        db_session, ORG_A, hostname="ws-12", file_path="C:/Users/p/evil.exe", actor="system:t", reason="r",
        execution_ref=None, approval_override=True,
    )
    assert q.status == containment.EXECUTED and q.reversible
    assert (await db_session.get(AgentCommand, q.command_id)).payload["path"] == "C:/Users/p/evil.exe"
    d = await containment.disable_user(
        db_session, ORG_A, username="jdoe", hostname="ws-12", actor="system:t", reason="r", execution_ref=None,
    )
    assert d.status == containment.QUEUED_FOR_APPROVAL and d.reversible is False and d.agent_id == ag.id
    assert (await db_session.get(AgentCommand, d.command_id)).action == "disable_account"


def test_result_rejects_unknown_status():
    with pytest.raises(ValueError):
        containment.ContainmentResult(action="block_ip", target="x", status="success", detail="")


# ---------------------------------------------------------------------------
# unattended=True (automation rules, scheduled / auto-triggered runs)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unattended_integration_path_is_manual_required_and_not_called(db_session, monkeypatch):
    await _install(db_session, ORG_A, "crowdstrike", "edr")
    await db_session.commit()

    from src.integrations.engine import ActionExecutor

    async def must_not_run(*_args: Any, **_kwargs: Any) -> dict:
        raise AssertionError("integration engine must not be called for an unattended request")

    monkeypatch.setattr(ActionExecutor, "execute_action", must_not_run)

    def no_http(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected HTTP call {request.url}")

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(no_http)}),
    )
    res = await containment.isolate_host(
        db_session, ORG_A, hostname="db-07", actor="system:rule:r1", reason="rule", execution_ref="rule:r1",
        unattended=True,
    )
    assert res.status == containment.MANUAL_REQUIRED and not res.actuated and res.reversible is False
    assert res.integration == "crowdstrike" and "contain_host" in res.detail and "db-07" in res.detail
    audit = (await _audit_rows(db_session, ORG_A))[0]
    assert json.loads(audit.new_value)["status"] == "manual_required" and audit.success is False


@pytest.mark.asyncio
async def test_unattended_agent_path_always_awaits_approval(db_session):
    await _agent(db_session, ORG_A, "web-09", ["ir"])
    await db_session.commit()
    iso = await containment.isolate_host(
        db_session, ORG_A, hostname="web-09", actor="system:rule:r1", reason="r", execution_ref=None,
        unattended=True, approval_override=True,  # an override is ignored when unattended
    )
    blk = await containment.block_ip(
        db_session, ORG_A, ip="203.0.113.66", actor="system:rule:r1", reason="r", execution_ref=None,
        unattended=True, approval_override=True,
    )
    for res in (iso, blk):
        assert res.status == containment.QUEUED_FOR_APPROVAL
        assert (await db_session.get(AgentCommand, res.command_id)).status == "awaiting_approval"


@pytest.mark.asyncio
async def test_unattended_refuses_agent_action_that_would_skip_approval(db_session, monkeypatch):
    import src.agents.capabilities as caps

    ag = await _agent(db_session, ORG_A, "ws-77", ["ir"])
    await db_session.commit()
    monkeypatch.setattr(caps, "requires_approval", lambda _action: False)  # a future HIGH_BLAST change
    res = await containment.quarantine_file(
        db_session, ORG_A, hostname="ws-77", file_path="/tmp/x", actor="system:rule:r1", reason="r",
        execution_ref=None, unattended=True,
    )
    assert res.status == containment.MANUAL_REQUIRED and res.agent_id == ag.id and res.command_id is None
    assert (await db_session.execute(select(func.count(AgentCommand.id)))).scalar() == 0


# ---------------------------------------------------------------------------
# Target validation (hostnames and IPs come from alert fields / rules)
# ---------------------------------------------------------------------------


def _falcon(monkeypatch, devices: dict[str, str], calls: list[str]) -> None:
    """Mock Falcon at the httpx transport: ``devices`` maps device id -> hostname."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "tok", "expires_in": 1800})
        if request.url.path == "/devices/queries/devices-scroll/v1":
            return httpx.Response(200, json={"resources": list(devices)})
        if request.url.path == "/devices/entities/devices/v2":
            dev = request.url.params["ids"]
            return httpx.Response(200, json={"resources": [{"device_id": dev, "hostname": devices[dev]}]})
        if request.url.path == "/devices/entities/devices-actions/v2":
            return httpx.Response(202, json={"resources": [], "errors": []})
        return httpx.Response(404, json={})

    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **kw: _REAL_CLIENT(*a, **{**kw, "transport": httpx.MockTransport(handler)}),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("hostname", ["a' , hostname:'*", "web-01'", "host name", "*", "a\\b"])
async def test_injection_hostname_refused_before_any_lookup(db_session, monkeypatch, hostname):
    await _install(db_session, ORG_A, "crowdstrike", "edr")
    await _agent(db_session, ORG_A, "web-01", ["ir"])
    await db_session.commit()
    calls: list[str] = []
    _falcon(monkeypatch, {"dev-1": "web-01", "dev-2": "db-02"}, calls)

    for res in (
        await containment.isolate_host(db_session, ORG_A, hostname=hostname, actor="system:t", reason="r", execution_ref=None),
        await containment.quarantine_file(
            db_session, ORG_A, hostname=hostname, file_path="/x", actor="system:t", reason="r", execution_ref=None,
        ),
    ):
        assert res.status == containment.DETECTION_ONLY and res.failed and res.error == "invalid_hostname"
        assert not res.actuated and res.command_id is None
    assert calls == []
    assert (await db_session.execute(select(func.count(AgentCommand.id)))).scalar() == 0
    assert len(await _audit_rows(db_session, ORG_A)) == 2


def test_fql_quote_escapes_backslash_and_quote():
    assert containment.fql_quote("a'b\\c") == "a\\'b\\\\c"


@pytest.mark.asyncio
async def test_mismatched_device_hostname_is_not_contained(db_session, monkeypatch):
    await _install(db_session, ORG_A, "crowdstrike", "edr")
    await db_session.commit()
    calls: list[str] = []
    _falcon(monkeypatch, {"dev-9": "db-07.evil.example"}, calls)  # FQL prefix match on another host

    res = await containment.isolate_host(db_session, ORG_A, hostname="db-07", actor="system:t", reason="r", execution_ref=None)
    assert res.status == containment.DETECTION_ONLY and res.failed and res.error.startswith("host_not_found")
    assert "/devices/entities/devices-actions/v2" not in calls

    calls.clear()
    _falcon(monkeypatch, {"dev-1": "db-07", "dev-2": "db-07"}, calls)
    res = await containment.isolate_host(db_session, ORG_A, hostname="db-07", actor="system:t", reason="r", execution_ref=None)
    assert res.failed and res.error.startswith("ambiguous_host")
    assert "/devices/entities/devices-actions/v2" not in calls


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["not-an-ip", "127.0.0.1", "0.0.0.0", "224.0.0.5", "::1", "1.2.3.4; rm -rf /"])
async def test_invalid_ip_refused(db_session, ip):
    await _agent(db_session, ORG_A, "ir-01", ["ir"])
    await db_session.commit()
    res = await containment.block_ip(db_session, ORG_A, ip=ip, actor="system:t", reason="r", execution_ref=None,
                                     approval_override=True)
    assert res.status == containment.DETECTION_ONLY and res.failed and res.error == "invalid_ip"
    assert (await db_session.execute(select(func.count(AgentCommand.id)))).scalar() == 0


@pytest.mark.asyncio
async def test_private_ip_block_and_ip_host_isolation_allowed(db_session):
    await _agent(db_session, ORG_A, "10.0.0.5", ["ir"])
    await db_session.commit()
    blk = await containment.block_ip(db_session, ORG_A, ip="10.1.2.3", actor="system:t", reason="r",
                                     execution_ref=None, approval_override=True)
    assert blk.status == containment.EXECUTED
    iso = await containment.isolate_host(db_session, ORG_A, hostname="10.0.0.5", actor="system:t", reason="r",
                                         execution_ref=None, approval_override=True)
    assert iso.status == containment.EXECUTED
