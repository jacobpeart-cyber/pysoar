"""Wave 3 (W3-D): honeytokens and decoys made real.

Covers: honeytoken values are generated server-side, returned once and
stored only as a hash plus a preview; unsupported token types are refused
with the reason; the unauthenticated canary callback records the trigger
with source metadata, counts it from rows, matches a presented secret and
raises one alert for the owning organisation (repeat calls join it); decoys
are deployed through deception agents with ``deploy_decoy`` and reconciled
from the command result, or marked ``not_deployed`` with the reason;
disabling a dispatched decoy sends ``remove_decoy``; the status cannot be
set by the client; the capability catalogue carries the decoy actions.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from contextlib import asynccontextmanager
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.capabilities import CAPABILITY_ACTIONS, AgentAction, AgentCapability
from src.agents.models import AgentCommand, EndpointAgent
from src.agents.service import AgentService
from src.deception.models import Decoy, HoneyToken, HoneyTokenTrigger
from src.models.alert import Alert
from src.models.audit import AuditLog
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/deception"


def _error(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


async def _token(client: AsyncClient, headers: dict[str, str], token_type: str = "api_key", **extra: Any) -> dict[str, Any]:
    resp = await client.post(f"{BASE}/tokens", json={"token_type": token_type, **extra}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _agent(db: AsyncSession, org_id: str, hostname: str, caps: list[str]) -> str:
    agent = EndpointAgent(hostname=hostname, status="active", capabilities=caps, organization_id=org_id)
    db.add(agent)
    await db.commit()
    return agent.id


def test_capability_catalogue_has_the_decoy_actions() -> None:
    assert {AgentAction.DEPLOY_DECOY, AgentAction.REMOVE_DECOY} <= CAPABILITY_ACTIONS[AgentCapability.DECEPTION]
    assert AgentAction.DEPLOY_DECOY.value == "deploy_decoy" and AgentAction.REMOVE_DECOY.value == "remove_decoy"


# ---------------------------------------------------------------------------
# Honeytokens
# ---------------------------------------------------------------------------


async def test_token_value_is_returned_once_and_stored_hashed(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    created = await _token(client, org_a_headers, name="billing", deployment_location="repo/.env")
    value = created["token_value"]
    assert value.startswith("sk_live_") and len(value) == 40
    assert created["canary_url"].endswith(f"/api/v1/deception/canary/{created['id']}")
    assert created["canary_path"] == f"/api/v1/deception/canary/{created['id']}"
    assert value in created["planting"]["env_snippet"] and created["canary_url"] in created["planting"]["env_snippet"]
    assert created["deployment_location"] == "repo/.env"

    row = (await db_session.execute(select(HoneyToken).where(HoneyToken.id == created["id"]))).scalar_one()
    assert row.token_hash == hashlib.sha256(value.encode()).hexdigest()
    assert row.token_value != value and value not in row.token_value
    assert created["token_preview"] == row.token_value

    listed = await client.get(f"{BASE}/tokens", headers=org_a_headers)
    item = next(t for t in listed.json() if t["id"] == created["id"])
    assert "token_value" not in item and value not in str(listed.json())
    one = await client.get(f"{BASE}/tokens/{created['id']}", headers=org_a_headers)
    assert value not in one.text


async def test_unsupported_token_types_are_refused_with_the_reason(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    for token_type in ("ssh_key", "database_cred", "certificate", "nonsense"):
        resp = await client.post(f"{BASE}/tokens", json={"token_type": token_type}, headers=org_a_headers)
        assert resp.status_code == 400, resp.text
        assert _error(resp) == "unsupported_token_type"
    types = await client.get(f"{BASE}/tokens/types", headers=org_a_headers)
    by_type = {t["token_type"]: t for t in types.json()}
    assert by_type["aws_key"]["supported"] is True and by_type["ssh_key"]["supported"] is False
    assert by_type["ssh_key"]["reason"]


async def test_canary_records_trigger_counts_rows_and_raises_one_alert(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    created = await _token(client, org_a_headers, name="ci-key")
    token_id, value = created["id"], created["token_value"]

    # No credentials: recorded, value_presented unknown. No auth header needed.
    first = await client.post(
        f"{BASE}/canary/{token_id}", json={"note": "probe"},
        headers={"User-Agent": "curl/8.4", "X-Forwarded-For": "203.0.113.50"},
    )
    assert first.status_code == 200, first.text
    # The token's secret: value_presented True; joins the open alert.
    second = await client.post(f"{BASE}/canary/{token_id}", headers={"Authorization": f"Bearer {value}"})
    # A different credential: value_presented False.
    third = await client.post(f"{BASE}/canary/{token_id}", json={"token": "sk_live_wrong"})
    assert second.status_code == third.status_code == 200

    triggers = (await db_session.execute(
        select(HoneyTokenTrigger).where(HoneyTokenTrigger.token_id == token_id).order_by(HoneyTokenTrigger.created_at),
    )).scalars().all()
    assert len(triggers) == 3
    assert [t.value_presented for t in triggers] == [None, True, False]
    assert {t.organization_id for t in triggers} == {org_id}
    assert triggers[0].user_agent == "curl/8.4" and triggers[0].forwarded_for == "203.0.113.50"
    assert triggers[0].request_metadata["body_excerpt"] == '{"note":"probe"}'
    assert "authorization" not in str(triggers[1].request_metadata).lower().replace("authorization_scheme", "")
    assert value not in str(triggers[1].request_metadata)

    alerts = (await db_session.execute(select(Alert).where(Alert.alert_type == "honeytoken_trigger"))).scalars().all()
    assert len(alerts) == 1 and alerts[0].organization_id == org_id and alerts[0].severity == "critical"
    assert {t.alert_id for t in triggers} == {alerts[0].id}

    check = await client.post(f"{BASE}/tokens/{token_id}/check", headers=org_a_headers)
    assert check.json()["triggered_count"] == 3 and check.json()["has_been_used"] is True
    assert check.json()["triggers_with_value_presented"] == 1 and check.json()["status"] == "triggered"
    listed = await client.get(f"{BASE}/tokens/{token_id}/triggers", headers=org_a_headers)
    assert len(listed.json()) == 3
    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "deception_honeytoken_triggered", AuditLog.organization_id == org_id),
    )).scalars().all()
    assert len(audit) == 3


async def test_aws_and_url_canaries(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    aws = await _token(client, org_a_headers, token_type="aws_key")
    key_id = aws["planting"]["access_key_id"]
    assert key_id.startswith("AKIA") and key_id in aws["token_value"]
    assert aws["canary_url"] in aws["planting"]["config_snippet"]
    sig = f"AWS4-HMAC-SHA256 Credential={key_id}/20261013/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=ab"
    resp = await client.post(f"{BASE}/canary/{aws['id']}", headers={"Authorization": sig})
    assert resp.status_code == 200

    url = await _token(client, org_a_headers, token_type="url_canary")
    assert url["token_value"] == url["canary_url"]
    resp = await client.get(f"{BASE}/canary/{url['id']}")
    assert resp.status_code == 200

    rows = {
        t.token_id: t for t in (await db_session.execute(select(HoneyTokenTrigger))).scalars()
    }
    assert rows[aws["id"]].value_presented is True
    assert rows[url["id"]].http_method == "GET" and rows[url["id"]].value_presented is None

    basic = await _token(client, org_a_headers, token_type="jwt_token")
    auth = base64.b64encode(f"svc:{basic['token_value']}".encode()).decode()
    await client.post(f"{BASE}/canary/{basic['id']}", headers={"Authorization": f"Basic {auth}"})
    trig = (await db_session.execute(select(HoneyTokenTrigger).where(HoneyTokenTrigger.token_id == basic["id"]))).scalar_one()
    assert trig.value_presented is True


async def test_unknown_canary_is_404_and_triggers_are_tenant_scoped(
    client: AsyncClient, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    resp = await client.post(f"{BASE}/canary/{uuid.uuid4()}")
    assert resp.status_code == 404
    created = await _token(client, org_a_headers)
    await client.post(f"{BASE}/canary/{created['id']}")
    await assert_tenant_isolated(client, "GET", f"{BASE}/tokens/{created['id']}/triggers", org_b_headers)
    listed = await client.get(f"{BASE}/tokens", headers=org_b_headers)
    assert created["id"] not in {t["id"] for t in listed.json()}


# ---------------------------------------------------------------------------
# Decoys
# ---------------------------------------------------------------------------


async def test_decoys_without_an_agent_or_mechanism_are_not_deployed(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    for decoy_type, state in (("honeyfile", "no_deception_agent"), ("honeydns", "unsupported_decoy_type")):
        resp = await client.post(
            f"{BASE}/decoys", json={"name": f"d-{decoy_type}", "decoy_type": decoy_type, "category": "file",
                                    "status": "active"},
            headers=org_a_admin_headers,
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "not_deployed"
        assert body["configuration"]["deployment"]["state"] == state
        assert body["configuration"]["deployment"]["note"]


async def test_decoy_deploys_through_the_agent_and_follows_the_result(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.deception.tasks as deception_tasks

    org_id = org_a.id
    agent_id = await _agent(db_session, org_id, "fileserver-1", ["deception"])
    ok = await client.post(
        f"{BASE}/decoys",
        json={"name": "payroll.xlsx", "decoy_type": "honeyfile", "category": "file",
              "configuration": {"path": "/srv/share/payroll.xlsx", "deployment": {"state": "forged"}}},
        headers=org_a_admin_headers,
    )
    bad = await client.post(
        f"{BASE}/decoys",
        json={"name": "creds.txt", "decoy_type": "honeycred", "category": "credential",
              "deployment_target": "fileserver-1"},
        headers=org_a_admin_headers,
    )
    assert ok.status_code == bad.status_code == 201
    for resp in (ok, bad):
        assert resp.json()["status"] == "deploying"
        assert resp.json()["configuration"]["deployment"]["state"] == "dispatched"
        assert resp.json()["deployment_target"] == "fileserver-1"
    ok_cmd = ok.json()["configuration"]["deployment"]["command_id"]
    bad_cmd = bad.json()["configuration"]["deployment"]["command_id"]
    cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == ok_cmd))).scalar_one()
    assert cmd.action == "deploy_decoy" and cmd.payload["configuration"] == {"path": "/srv/share/payroll.xlsx"}

    agent = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    svc = AgentService(db_session)
    await svc.ingest_result(agent=agent, command_id=ok_cmd, status="success")
    await svc.ingest_result(agent=agent, command_id=bad_cmd, status="rejected", stderr="unknown action deploy_decoy")
    await db_session.commit()

    @asynccontextmanager
    async def _same_session():
        yield db_session

    monkeypatch.setattr(deception_tasks, "_AsyncSessionLocal", _same_session)
    out = await deception_tasks._reconcile_honeypot_dispatches()
    assert out["activated"] == 1 and out["failed"] == 1

    db_session.expire_all()
    rows = {d.id: d for d in (await db_session.execute(select(Decoy).where(Decoy.organization_id == org_id))).scalars()}
    assert rows[ok.json()["id"]].status == "active"
    assert rows[ok.json()["id"]].configuration["deployment"]["state"] == "deployed"
    assert rows[bad.json()["id"]].status == "failed"
    assert rows[bad.json()["id"]].configuration["deployment"]["error"] == "unknown action deploy_decoy"

    # The client cannot set the status or overwrite the dispatch record.
    upd = await client.put(
        f"{BASE}/decoys/{ok.json()['id']}",
        json={"name": "payroll-2026.xlsx", "decoy_type": "honeyfile", "category": "file", "status": "active",
              "configuration": {"path": "/srv/x", "deployment": {"state": "forged"}}},
        headers=org_a_admin_headers,
    )
    assert upd.status_code == 200
    assert upd.json()["configuration"]["deployment"]["state"] == "deployed"
    assert upd.json()["configuration"]["path"] == "/srv/x"

    # Disabling sends remove_decoy to the agent and is audited.
    dis = await client.post(f"{BASE}/decoys/{ok.json()['id']}/disable", headers=org_a_admin_headers)
    assert dis.status_code == 204
    removal = (await db_session.execute(
        select(AgentCommand).where(AgentCommand.action == "remove_decoy", AgentCommand.agent_id == agent_id),
    )).scalars().all()
    assert len(removal) == 1 and removal[0].payload["decoy_id"] == ok.json()["id"]
    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.organization_id == org_id, AuditLog.action.like("deception_%_decoy")),
    )).scalars().all()
    assert {a.action for a in audit} >= {"deception_deploy_decoy", "deception_disable_decoy"}


async def test_listed_decoys_count_interactions_from_rows(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    from src.deception.models import DecoyInteraction

    created = await client.post(
        f"{BASE}/decoys", json={"name": "ssh", "decoy_type": "honeyfile", "category": "file"},
        headers=org_a_admin_headers,
    )
    decoy_id = created.json()["id"]
    for ip in ("198.51.100.1", "198.51.100.2"):
        db_session.add(DecoyInteraction(decoy_id=decoy_id, interaction_type="connection", source_ip=ip,
                                        organization_id=org_a.id))
    await db_session.commit()
    listed = await client.get(f"{BASE}/decoys", headers=org_a_admin_headers)
    item = next(d for d in listed.json() if d["id"] == decoy_id)
    assert item["interaction_count"] == 2 and item["last_interaction_at"] is not None
