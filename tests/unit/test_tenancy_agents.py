"""Tenancy and RBAC for the endpoint-agent router (wave 1, docs/audit/2026-10-08/PLAN.md).

Covers: every operator route is scoped to the caller's organisation, enrol /
revoke / disable / enable are admin-only, issuing commands is analyst+,
approving or rejecting a high-blast command is admin-only and never the
issuer, the approver recorded is the session user, viewers are read-only and
an org-less platform superuser is refused with ``organization_required``.
"""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from src.models.user import User
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/agents"


async def _enroll(client: AsyncClient, headers: dict[str, str], hostname: str = "host-a") -> str:
    resp = await client.post(
        f"{BASE}/enroll", json={"hostname": hostname, "capabilities": ["ir"]}, headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["agent_id"]


async def _issue(client: AsyncClient, agent_id: str, headers: dict[str, str], action: str = "isolate_host") -> dict[str, Any]:
    resp = await client.post(
        f"{BASE}/{agent_id}/commands", json={"action": action, "payload": {}}, headers=headers,
    )
    assert resp.status_code == 202, resp.text
    return resp.json()


def _error_key(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


async def test_agent_routes_are_tenant_isolated(
    client: AsyncClient, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    agent_id = await _enroll(client, org_a_admin_headers)
    cmd = await _issue(client, agent_id, org_a_headers)
    cmd_id = cmd["id"]

    for method, path in [
        ("GET", f"{BASE}/{agent_id}"),
        ("GET", f"{BASE}/{agent_id}/verify-chain"),
        ("POST", f"{BASE}/{agent_id}/commands"),
    ]:
        body = {"action": "collect_process_list", "payload": {}} if method == "POST" else None
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    # Org B's lists never contain org A's rows.
    listing = await client.get(BASE, headers=org_b_headers)
    assert listing.status_code == 200
    assert agent_id not in {a["id"] for a in listing.json()["agents"]}
    cmds = await client.get(f"{BASE}/{agent_id}/commands", headers=org_b_headers)
    assert cmds.status_code == 200 and cmds.json() == []
    queue = await client.get(f"{BASE}/commands/pending-approval", headers=org_b_headers)
    assert queue.status_code == 200
    assert cmd_id not in {c["id"] for c in queue.json()}
    dash = await client.get(f"{BASE}/dashboard", headers=org_b_headers)
    assert dash.status_code == 200
    assert dash.json()["total_agents"] == 0
    assert cmd_id not in {c["id"] for c in dash.json()["recent_commands"]}

    # Org A sees its own.
    own = await client.get(BASE, headers=org_a_headers)
    assert agent_id in {a["id"] for a in own.json()["agents"]}
    own_queue = await client.get(f"{BASE}/commands/pending-approval", headers=org_a_headers)
    assert cmd_id in {c["id"] for c in own_queue.json()}


async def test_admin_routes_isolated_from_other_tenant_admin(
    client: AsyncClient, db_session, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str], org_b,
) -> None:
    from tests.helpers.tenancy import bearer, make_user

    org_b_admin = await make_user(db_session, role="admin", organization_id=org_b.id, label="admin-b")
    org_b_admin_headers = bearer(org_b_admin)

    agent_id = await _enroll(client, org_a_admin_headers)
    cmd_id = (await _issue(client, agent_id, org_a_headers))["id"]

    for path in [
        f"{BASE}/{agent_id}/disable",
        f"{BASE}/{agent_id}/enable",
        f"{BASE}/{agent_id}/revoke",
    ]:
        await assert_tenant_isolated(client, "POST", path, org_b_admin_headers)
    for path in [f"{BASE}/commands/{cmd_id}/approve", f"{BASE}/commands/{cmd_id}/reject"]:
        await assert_tenant_isolated(client, "POST", path, org_b_admin_headers, json={"reason": "x"})

    still = await client.get(f"{BASE}/{agent_id}", headers=org_a_headers)
    assert still.json()["status"] == "pending"


async def test_viewer_is_read_only(
    client: AsyncClient, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str], viewer_headers: dict[str, str],
) -> None:
    agent_id = await _enroll(client, org_a_admin_headers)
    cmd_id = (await _issue(client, agent_id, org_a_headers))["id"]

    writes = [
        (f"{BASE}/enroll", {"hostname": "v", "capabilities": ["ir"]}),
        (f"{BASE}/{agent_id}/commands", {"action": "collect_process_list", "payload": {}}),
        (f"{BASE}/{agent_id}/disable", None),
        (f"{BASE}/{agent_id}/enable", None),
        (f"{BASE}/{agent_id}/revoke", None),
        (f"{BASE}/commands/{cmd_id}/approve", {"reason": "ok"}),
        (f"{BASE}/commands/{cmd_id}/reject", {"reason": "no"}),
    ]
    for path, body in writes:
        resp = await client.post(path, json=body, headers=viewer_headers)
        assert resp.status_code == 403, f"{path}: {resp.status_code} {resp.text}"

    # Reads are allowed.
    assert (await client.get(BASE, headers=viewer_headers)).status_code == 200
    assert (await client.get(f"{BASE}/{agent_id}", headers=viewer_headers)).status_code == 200
    assert (await client.get(f"{BASE}/{agent_id}/commands", headers=viewer_headers)).status_code == 200


async def test_analyst_refused_on_admin_routes(
    client: AsyncClient, org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str],
) -> None:
    resp = await client.post(
        f"{BASE}/enroll", json={"hostname": "h", "capabilities": ["ir"]}, headers=org_a_headers,
    )
    assert resp.status_code == 403

    agent_id = await _enroll(client, org_a_admin_headers)
    for path in [f"{BASE}/{agent_id}/disable", f"{BASE}/{agent_id}/enable", f"{BASE}/{agent_id}/revoke"]:
        assert (await client.post(path, headers=org_a_headers)).status_code == 403, path

    # Analysts may issue commands, but not approve or reject them.
    cmd = await _issue(client, agent_id, org_a_headers)
    assert cmd["status"] == "awaiting_approval"
    for verb in ("approve", "reject"):
        resp = await client.post(
            f"{BASE}/commands/{cmd['id']}/{verb}", json={"reason": "x"}, headers=org_a_headers,
        )
        assert resp.status_code == 403, f"{verb}: {resp.text}"


async def test_approver_is_session_admin_and_never_the_issuer(
    client: AsyncClient,
    org_a_admin: User,
    org_a_admin_headers: dict[str, str],
    org_a_user: User,
    org_a_headers: dict[str, str],
) -> None:
    admin_id = str(org_a_admin.id)
    analyst_id = str(org_a_user.id)
    agent_id = await _enroll(client, org_a_admin_headers)

    # Admin issues a command: the same admin cannot approve or reject it.
    own = await _issue(client, agent_id, org_a_admin_headers)
    for verb in ("approve", "reject"):
        resp = await client.post(
            f"{BASE}/commands/{own['id']}/{verb}", json={"reason": "self"}, headers=org_a_admin_headers,
        )
        assert resp.status_code == 403, resp.text
        assert _error_key(resp) == "self_approval_forbidden"

    # Analyst issues; a body field cannot name a different approver.
    cmd = await _issue(client, agent_id, org_a_headers)
    resp = await client.post(
        f"{BASE}/commands/{cmd['id']}/approve",
        json={"reason": "change ticket 42", "approved_by": analyst_id, "approver_id": analyst_id},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "queued"
    assert body["approved_by"] == admin_id

    # Rejection records the session admin too.
    cmd2 = await _issue(client, agent_id, org_a_headers, action="kill_process")
    resp = await client.post(
        f"{BASE}/commands/{cmd2['id']}/reject", json={"reason": "no"}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "rejected"
    assert resp.json()["approved_by"] == admin_id


async def test_admin_lifecycle_routes_work_for_admin(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    agent_id = await _enroll(client, org_a_admin_headers)
    assert (await client.post(f"{BASE}/{agent_id}/disable", headers=org_a_admin_headers)).json()["status"] == "disabled"
    assert (await client.post(f"{BASE}/{agent_id}/enable", headers=org_a_admin_headers)).json()["status"] == "active"
    assert (await client.post(f"{BASE}/{agent_id}/revoke", headers=org_a_admin_headers)).json()["status"] == "revoked"


async def test_orgless_superuser_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    for method, path, body in [
        ("GET", BASE, None),
        ("GET", f"{BASE}/dashboard", None),
        ("GET", f"{BASE}/commands/pending-approval", None),
        ("POST", f"{BASE}/enroll", {"hostname": "su", "capabilities": ["ir"]}),
    ]:
        resp = await client.request(method, path, json=body, headers=superuser_headers)
        assert resp.status_code == 403, f"{path}: {resp.text}"
        assert _error_key(resp) == "organization_required"
