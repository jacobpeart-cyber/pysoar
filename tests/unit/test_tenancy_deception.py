"""Tenancy and RBAC for the deception router (wave 1, docs/audit/2026-10-08/PLAN.md).

Covers: decoys, tokens, interactions and campaigns are scoped to the caller's
organisation; the interaction timeline and investigation only see the
caller's interactions; configuring a decoy cannot move it to another tenant;
recorded interactions are stamped with the caller's organisation; honeytoken
responses carry the real model columns; creating/configuring/deleting decoys
and deleting tokens are admin-only; viewers are read-only; an org-less
platform superuser is refused; decoy and token rotation are honest 501s.
"""

from __future__ import annotations

import uuid
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.deception.models import Decoy, DecoyInteraction
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/deception"


def _decoy_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": f"decoy-{uuid.uuid4().hex[:6]}",
        "decoy_type": "honeyfile",
        "category": "file",
    }
    body.update(overrides)
    return body


async def _decoy(client: AsyncClient, admin_headers: dict[str, str]) -> str:
    resp = await client.post(f"{BASE}/decoys", json=_decoy_body(), headers=admin_headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _interaction(client: AsyncClient, decoy_id: str, headers: dict[str, str], ip: str = "203.0.113.7") -> str:
    resp = await client.post(
        f"{BASE}/decoys/{decoy_id}/interactions",
        json={"source_ip": ip, "interaction_type": "connection", "alert_generated": False},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["interaction_id"]


def _error_key(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


async def test_deception_routes_are_tenant_isolated(
    client: AsyncClient,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    decoy_id = await _decoy(client, org_a_admin_headers)
    interaction_id = await _interaction(client, decoy_id, org_a_headers)
    token = await client.post(f"{BASE}/tokens", json={"token_type": "api_key"}, headers=org_a_headers)
    assert token.status_code == 201, token.text
    token_id = token.json()["id"]
    campaign = await client.post(
        f"{BASE}/campaigns", json={"name": "c-a", "objective": "general_detection"}, headers=org_a_headers
    )
    assert campaign.status_code == 201, campaign.text
    campaign_id = campaign.json()["id"]

    for method, path, body in [
        ("GET", f"{BASE}/decoys/{decoy_id}", None),
        ("PUT", f"{BASE}/decoys/{decoy_id}", _decoy_body()),
        ("POST", f"{BASE}/decoys/{decoy_id}/disable", None),
        ("POST", f"{BASE}/decoys/{decoy_id}/interactions", {"source_ip": "198.51.100.1"}),
        ("DELETE", f"{BASE}/decoys/{decoy_id}", None),
        ("GET", f"{BASE}/tokens/{token_id}", None),
        ("POST", f"{BASE}/tokens/{token_id}/check", None),
        ("DELETE", f"{BASE}/tokens/{token_id}", None),
        ("GET", f"{BASE}/interactions/{interaction_id}", None),
        ("POST", f"{BASE}/interactions/{interaction_id}/investigate", {}),
        ("GET", f"{BASE}/campaigns/{campaign_id}", None),
        ("PUT", f"{BASE}/campaigns/{campaign_id}/status", {"status": "paused"}),
        ("GET", f"{BASE}/campaigns/{campaign_id}/effectiveness", None),
    ]:
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    # The timeline used to read interactions by decoy_id with no org filter.
    await assert_tenant_isolated(
        client, "GET", f"{BASE}/interactions/timeline", org_b_headers, params={"decoy_id": decoy_id}
    )

    # Org B's lists and dashboard never include org A's rows.
    for path, ident in [
        (f"{BASE}/decoys", decoy_id),
        (f"{BASE}/tokens", token_id),
        (f"{BASE}/interactions", interaction_id),
        (f"{BASE}/campaigns", campaign_id),
    ]:
        resp = await client.get(path, headers=org_b_headers)
        assert resp.status_code == 200, resp.text
        assert ident not in {row["id"] for row in resp.json()}
    dash = await client.get(f"{BASE}/dashboard", headers=org_b_headers)
    assert dash.status_code == 200, dash.text
    assert interaction_id not in {i["id"] for i in dash.json()["recent_interactions"]}

    # Org A still sees its own timeline.
    own = await client.get(f"{BASE}/interactions/timeline", params={"decoy_id": decoy_id}, headers=org_a_headers)
    assert own.status_code == 200, own.text
    assert [e["interaction_id"] for e in own.json()["entries"]] == [interaction_id]


async def test_investigation_correlates_only_within_the_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    org_b_user: Any,
) -> None:
    org_b_id = org_b_user.organization_id
    ip = "192.0.2.55"
    decoy_a = await _decoy(client, org_a_admin_headers)
    first = await _interaction(client, decoy_a, org_a_headers, ip=ip)
    second = await _interaction(client, decoy_a, org_a_headers, ip=ip)

    # Org B saw the same attacker IP on its own decoy.
    decoy_b = Decoy(name="b-decoy", decoy_type="honeyfile", category="file", organization_id=org_b_id)
    db_session.add(decoy_b)
    await db_session.flush()
    other = DecoyInteraction(decoy_id=decoy_b.id, source_ip=ip, interaction_type="connection", organization_id=org_b_id)
    db_session.add(other)
    await db_session.commit()
    other_id = other.id

    resp = await client.post(f"{BASE}/interactions/{first}/investigate", json={}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    correlated = {c["id"] for c in body["correlated_interactions"]}
    assert correlated == {second}
    assert other_id not in correlated
    # No invented analysis values.
    assert body["analysis"]["confidence"] == 0.0
    assert body["analysis"]["skill_level"] == ""


async def test_recorded_interaction_is_stamped_with_the_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    decoy_id = await _decoy(client, org_a_admin_headers)
    resp = await client.post(
        f"{BASE}/decoys/{decoy_id}/interactions",
        json={"source_ip": "203.0.113.9", "alert_generated": True},
        headers=org_a_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["alert_generated"] is True
    row = (
        await db_session.execute(select(DecoyInteraction).where(DecoyInteraction.id == body["interaction_id"]))
    ).scalar_one()
    assert row.organization_id == org_a_id


async def test_configuring_a_decoy_cannot_change_its_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_admin: Any,
    org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id, admin_id = org_a.id, org_b.id, org_a_admin.id
    created = await client.post(
        f"{BASE}/decoys",
        json=_decoy_body(organization_id=org_b_id, deployed_by="someone-else"),
        headers=org_a_admin_headers,
    )
    assert created.status_code == 201, created.text
    decoy_id = created.json()["id"]
    assert created.json()["deployed_by"] == admin_id

    resp = await client.put(
        f"{BASE}/decoys/{decoy_id}",
        json=_decoy_body(name="renamed", fidelity_level="high", organization_id=org_b_id, deployed_by="x"),
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "renamed"

    # The UI sends organization_id="default"; that is ignored too.
    resp = await client.put(
        f"{BASE}/decoys/{decoy_id}",
        json=_decoy_body(name="renamed-2", organization_id="default"),
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text

    row = (await db_session.execute(select(Decoy).where(Decoy.id == decoy_id))).scalar_one()
    await db_session.refresh(row)
    assert row.organization_id == org_a_id
    assert row.deployed_by == admin_id


async def test_honeytoken_responses_carry_the_model_columns(
    client: AsyncClient, org_a_headers: dict[str, str]
) -> None:
    resp = await client.post(
        f"{BASE}/tokens", json={"token_type": "api_key", "name": "billing-key"}, headers=org_a_headers
    )
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["name"] == "billing-key"
    assert created["token_type"] == "api_key"
    assert created["status"] == "active"
    assert "deployment_location" in created

    listed = await client.get(f"{BASE}/tokens", headers=org_a_headers)
    assert listed.status_code == 200
    row = next(t for t in listed.json() if t["id"] == created["id"])
    assert (row["name"], row["token_type"], row["status"]) == ("billing-key", "api_key", "active")


async def test_viewers_cannot_write(
    client: AsyncClient, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str], viewer_headers: dict[str, str]
) -> None:
    decoy_id = await _decoy(client, org_a_admin_headers)
    interaction_id = await _interaction(client, decoy_id, org_a_headers)
    token = await client.post(f"{BASE}/tokens", json={"token_type": "api_key"}, headers=org_a_headers)
    token_id = token.json()["id"]
    campaign = await client.post(
        f"{BASE}/campaigns", json={"name": "c", "objective": "general_detection"}, headers=org_a_headers
    )
    campaign_id = campaign.json()["id"]

    for method, path, body in [
        ("POST", f"{BASE}/decoys", _decoy_body()),
        ("PUT", f"{BASE}/decoys/{decoy_id}", _decoy_body()),
        ("POST", f"{BASE}/decoys/{decoy_id}/disable", None),
        ("POST", f"{BASE}/decoys/{decoy_id}/rotate", None),
        ("POST", f"{BASE}/decoys/{decoy_id}/interactions", {"source_ip": "198.51.100.2"}),
        ("DELETE", f"{BASE}/decoys/{decoy_id}", None),
        ("POST", f"{BASE}/tokens", {"token_type": "api_key"}),
        ("POST", f"{BASE}/tokens/{token_id}/check", None),
        ("DELETE", f"{BASE}/tokens/{token_id}", None),
        ("POST", f"{BASE}/tokens/rotate?token_type=api_key", None),
        ("POST", f"{BASE}/interactions/{interaction_id}/investigate", {}),
        ("POST", f"{BASE}/campaigns", {"name": "v", "objective": "general_detection"}),
        ("PUT", f"{BASE}/campaigns/{campaign_id}/status", {"status": "paused"}),
    ]:
        resp = await client.request(method, path, json=body, headers=viewer_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text[:200]}"

    # Reads stay open to viewers.
    for path in (f"{BASE}/decoys", f"{BASE}/tokens", f"{BASE}/dashboard", f"{BASE}/decoys/{decoy_id}"):
        assert (await client.get(path, headers=viewer_headers)).status_code == 200, path


async def test_decoy_configuration_and_deletion_are_admin_only(
    client: AsyncClient, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str]
) -> None:
    decoy_id = await _decoy(client, org_a_admin_headers)
    token = await client.post(f"{BASE}/tokens", json={"token_type": "api_key"}, headers=org_a_headers)
    token_id = token.json()["id"]

    for method, path, body in [
        ("POST", f"{BASE}/decoys", _decoy_body()),
        ("PUT", f"{BASE}/decoys/{decoy_id}", _decoy_body()),
        ("POST", f"{BASE}/decoys/{decoy_id}/rotate", None),
        ("DELETE", f"{BASE}/decoys/{decoy_id}", None),
        ("DELETE", f"{BASE}/tokens/{token_id}", None),
        ("POST", f"{BASE}/tokens/rotate?token_type=api_key", None),
    ]:
        resp = await client.request(method, path, json=body, headers=org_a_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text[:200]}"

    # Analysts keep the operational writes.
    assert (await client.post(f"{BASE}/decoys/{decoy_id}/disable", headers=org_a_headers)).status_code == 204
    # Admins can delete.
    assert (await client.delete(f"{BASE}/tokens/{token_id}", headers=org_a_admin_headers)).status_code == 204
    assert (await client.delete(f"{BASE}/decoys/{decoy_id}", headers=org_a_admin_headers)).status_code == 204


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    for method, path, body in [
        ("GET", f"{BASE}/decoys", None),
        ("GET", f"{BASE}/dashboard", None),
        ("GET", f"{BASE}/tokens", None),
        ("POST", f"{BASE}/decoys", _decoy_body()),
        ("POST", f"{BASE}/tokens", {"token_type": "api_key"}),
    ]:
        resp = await client.request(method, path, json=body, headers=superuser_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code}"
        assert _error_key(resp) == "organization_required"


async def test_rotation_routes_are_honest_501s(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers: dict[str, str], org_b_headers: dict[str, str]
) -> None:
    decoy_id = await _decoy(client, org_a_admin_headers)

    resp = await client.post(f"{BASE}/decoys/{decoy_id}/rotate", headers=org_a_admin_headers)
    assert resp.status_code == 501, resp.text
    assert _error_key(resp) == "not_implemented"
    # Rotation no longer wipes evidence counters or touches the row.
    row = (await db_session.execute(select(Decoy).where(Decoy.id == decoy_id))).scalar_one()
    assert row.status == "active"

    resp = await client.post(f"{BASE}/tokens/rotate", params={"token_type": "api_key"}, headers=org_a_admin_headers)
    assert resp.status_code == 501, resp.text
    assert _error_key(resp) == "not_implemented"

    # Another tenant still gets 403/404 before the 501.
    await assert_tenant_isolated(client, "POST", f"{BASE}/decoys/{decoy_id}/rotate", org_b_headers)
