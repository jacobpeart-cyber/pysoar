"""Tenancy and RBAC for the integrations router (wave 1, docs/audit/2026-10-08/PLAN.md).

The connector catalogue is a global registry; installed integrations, their
actions, executions and webhooks are tenant-owned. Install / configure /
credential updates / enable / disable / uninstall and webhook registration
are admin-only, running actions and connection tests are analyst+, viewers
are read-only and an org-less platform superuser gets
``organization_required``. The webhook "test" route, which only inflated the
inbound counters, is an honest 501.

The fixtures install VirusTotal (an implemented connector, so install needs
its declared ``api_key`` credential); a planned connector such as Splunk is
refused with 501 (tests/unit/test_connector_catalog_truth.py).
"""

from __future__ import annotations

import json
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.integrations.models import IntegrationConnector, WebhookEndpoint
from tests.helpers.tenancy import assert_tenant_isolated, bearer, make_user

BASE = "/api/v1/integrations"
CONNECTOR = "virustotal"
CREDENTIALS = {"api_key": "vt-test-key-0001"}


async def _seed_connector(db: AsyncSession) -> None:
    """The installed_integrations FK needs the catalogue row (seeded at startup in prod)."""
    existing = (
        await db.execute(select(IntegrationConnector).where(IntegrationConnector.id == CONNECTOR))
    ).scalar_one_or_none()
    if existing is None:
        db.add(
            IntegrationConnector(
                id=CONNECTOR,
                name=CONNECTOR,
                display_name="VirusTotal",
                category="threat_intel",
                supported_actions=json.dumps([]),
                supported_triggers=json.dumps([]),
                auth_type="api_key",
                config_schema=json.dumps({"type": "object"}),
            ),
        )
        await db.commit()


async def _install(client: AsyncClient, db: AsyncSession, headers: dict[str, str]) -> str:
    await _seed_connector(db)
    resp = await client.post(
        f"{BASE}/install",
        json={"connector_id": CONNECTOR, "display_name": "VirusTotal A", "config": {}, "credentials": CREDENTIALS},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _webhook(client: AsyncClient, integration_id: str, headers: dict[str, str]) -> str:
    resp = await client.post(
        f"{BASE}/installed/{integration_id}/webhooks",
        json={"endpoint_path": "/hooks/a", "event_types": ["alert"]},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _error_key(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


async def test_installed_integrations_are_tenant_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
    org_b,
) -> None:
    org_b_admin = await make_user(db_session, role="admin", organization_id=org_b.id, label="admin-b")
    org_b_admin_headers = bearer(org_b_admin)

    integration_id = await _install(client, db_session, org_a_admin_headers)
    webhook_id = await _webhook(client, integration_id, org_a_admin_headers)
    inst = f"{BASE}/installed/{integration_id}"

    for method, path, body in [
        ("GET", inst, None),
        ("GET", f"{inst}/actions", None),
        ("GET", f"{inst}/executions", None),
        ("GET", f"{inst}/webhooks", None),
        ("POST", f"{inst}/test", None),
        ("POST", f"{inst}/actions/none/execute", {"input_data": {}}),
        ("POST", f"{inst}/webhooks/{webhook_id}/test", None),
    ]:
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    # Admin-only writes are refused for the other tenant's admin too.
    for method, path, body in [
        ("PATCH", inst, {"display_name": "pwned"}),
        ("POST", f"{inst}/enable", None),
        ("POST", f"{inst}/disable", None),
        ("POST", f"{inst}/webhooks", {"endpoint_path": "/x"}),
        ("DELETE", f"{inst}/webhooks/{webhook_id}", None),
        ("DELETE", inst, None),
    ]:
        await assert_tenant_isolated(client, method, path, org_b_admin_headers, json=body)

    listing = await client.get(f"{BASE}/installed", headers=org_b_headers)
    assert listing.status_code == 200
    assert integration_id not in {i["id"] for i in listing.json()["items"]}
    health = await client.get(f"{BASE}/dashboard/health", headers=org_b_headers)
    assert health.status_code == 200
    assert health.json()["total_installed"] == 0
    summary = await client.get(f"{BASE}/dashboard/summary", headers=org_b_headers)
    assert summary.status_code == 200
    assert summary.json()["total_installed"] == 0

    # Org B installing the same connector gets its own row (no 409 across tenants).
    other = await client.post(
        f"{BASE}/install",
        json={"connector_id": CONNECTOR, "display_name": "VirusTotal B", "credentials": CREDENTIALS},
        headers=org_b_admin_headers,
    )
    assert other.status_code == 201, other.text
    assert other.json()["id"] != integration_id

    # Org A still sees its untouched install and webhook.
    own = await client.get(inst, headers=org_a_admin_headers)
    assert own.status_code == 200 and own.json()["display_name"] == "VirusTotal A"
    hooks = await client.get(f"{inst}/webhooks", headers=org_a_admin_headers)
    assert webhook_id in {w["id"] for w in hooks.json()["items"]}


async def test_viewer_is_read_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    integration_id = await _install(client, db_session, org_a_admin_headers)
    webhook_id = await _webhook(client, integration_id, org_a_admin_headers)
    inst = f"{BASE}/installed/{integration_id}"

    for method, path, body in [
        ("POST", f"{BASE}/install", {"connector_id": CONNECTOR, "display_name": "v"}),
        ("PATCH", inst, {"display_name": "v"}),
        ("POST", f"{inst}/test", None),
        ("POST", f"{inst}/enable", None),
        ("POST", f"{inst}/disable", None),
        ("POST", f"{inst}/actions/none/execute", {"input_data": {}}),
        ("POST", f"{inst}/webhooks", {"endpoint_path": "/v"}),
        ("POST", f"{inst}/webhooks/{webhook_id}/test", None),
        ("DELETE", f"{inst}/webhooks/{webhook_id}", None),
        ("DELETE", inst, None),
    ]:
        resp = await client.request(method, path, json=body, headers=viewer_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text}"

    for path in [f"{BASE}/connectors", f"{BASE}/installed", inst, f"{inst}/webhooks", f"{BASE}/dashboard/stats"]:
        assert (await client.get(path, headers=viewer_headers)).status_code == 200, path


async def test_analyst_refused_on_admin_routes(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    monkeypatch,
) -> None:
    from src.integrations import netguard

    async def _internal_only(host: str, port: int):
        # The connection test must never leave the test process: every name
        # resolves to loopback, which the pinned transport refuses.
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(netguard, "_getaddrinfo", _internal_only)
    integration_id = await _install(client, db_session, org_a_admin_headers)
    webhook_id = await _webhook(client, integration_id, org_a_admin_headers)
    inst = f"{BASE}/installed/{integration_id}"

    for method, path, body in [
        ("POST", f"{BASE}/install", {"connector_id": CONNECTOR, "display_name": "a"}),
        ("PATCH", inst, {"credentials": {"token": "x"}}),
        ("POST", f"{inst}/enable", None),
        ("POST", f"{inst}/disable", None),
        ("POST", f"{inst}/webhooks", {"endpoint_path": "/a"}),
        ("DELETE", f"{inst}/webhooks/{webhook_id}", None),
        ("DELETE", inst, None),
    ]:
        resp = await client.request(method, path, json=body, headers=org_a_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text}"

    # Analysts pass the gate on operational routes (unknown action -> 404 lookup).
    resp = await client.post(f"{inst}/actions/none/execute", json={"input_data": {}}, headers=org_a_headers)
    assert resp.status_code == 404, resp.text
    resp = await client.post(f"{inst}/test", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "unhealthy"


async def test_admin_configuration_routes_work(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers: dict[str, str],
) -> None:
    integration_id = await _install(client, db_session, org_a_admin_headers)
    inst = f"{BASE}/installed/{integration_id}"
    resp = await client.patch(inst, json={"display_name": "Renamed"}, headers=org_a_admin_headers)
    assert resp.status_code == 200 and resp.json()["display_name"] == "Renamed"
    assert (await client.post(f"{inst}/disable", headers=org_a_admin_headers)).json()["status"] == "inactive"
    assert (await client.post(f"{inst}/enable", headers=org_a_admin_headers)).json()["status"] == "active"
    assert (await client.delete(inst, headers=org_a_admin_headers)).status_code == 204
    assert (await client.get(inst, headers=org_a_admin_headers)).status_code == 404


async def test_webhook_test_is_honest_501_and_does_not_touch_counters(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str],
) -> None:
    integration_id = await _install(client, db_session, org_a_admin_headers)
    webhook_id = await _webhook(client, integration_id, org_a_admin_headers)

    resp = await client.post(
        f"{BASE}/installed/{integration_id}/webhooks/{webhook_id}/test", headers=org_a_headers,
    )
    assert resp.status_code == 501, resp.text
    assert _error_key(resp) == "not_implemented"

    row = (
        await db_session.execute(select(WebhookEndpoint).where(WebhookEndpoint.id == webhook_id))
    ).scalar_one()
    await db_session.refresh(row)
    assert (row.received_count or 0) == 0
    assert row.last_received is None


async def test_orgless_superuser_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    for method, path, body in [
        ("GET", f"{BASE}/installed", None),
        ("GET", f"{BASE}/dashboard/summary", None),
        ("POST", f"{BASE}/install", {"connector_id": CONNECTOR, "display_name": "su"}),
    ]:
        resp = await client.request(method, path, json=body, headers=superuser_headers)
        assert resp.status_code == 403, f"{path}: {resp.text}"
        assert _error_key(resp) == "organization_required"
