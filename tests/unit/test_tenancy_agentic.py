"""Wave 1 tenancy / RBAC for ``/agentic`` (src/api/v1/endpoints/agentic.py).

* every route takes the mandatory ``OrganizationId`` (the 36
  ``getattr(current_user, "organization_id", None)`` reads are gone); usage and
  evidence export keep the explicit superuser ``organization_id`` scope;
* lookups by id (agents, investigations, memory, chat sessions) 404 outside
  the tenant; a threat hunt cannot name another tenant's agent;
* viewers read only; chat, sessions, hunts, investigations, tool execution
  and trust acknowledgement need analyst+; agent configuration, memory wipes
  and approving / rolling back actions need admin;
* created rows are stamped with the caller's organisation.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.models import AgentChatSession, AgentMemory, Investigation, SOCAgent
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated, bearer, make_user

API = "/api/v1/agentic"
MISSING = "00000000-0000-0000-0000-000000000000"


async def _seed(db: AsyncSession, org_id: str, user_id: str) -> dict[str, str]:
    agent = SOCAgent(organization_id=org_id, name="triage", agent_type="triage_analyst", llm_model="fake-1")
    db.add(agent)
    await db.flush()
    investigation = Investigation(
        organization_id=org_id, agent_id=agent.id, trigger_type="manual", title="inv",
    )
    memory = AgentMemory(
        organization_id=org_id, agent_id=agent.id, memory_type="episodic", key="k", value={"v": 1},
    )
    session = AgentChatSession(user_id=user_id, organization_id=org_id, title="mine")
    db.add_all([investigation, memory, session])
    await db.commit()
    return {"agent": agent.id, "investigation": investigation.id, "session": session.id}


async def _org_b_admin_headers(db: AsyncSession, org_b: Organization) -> dict[str, str]:
    return bearer(await make_user(db, role="admin", organization_id=org_b.id, label="admin-b"))


# ---------------------------------------------------------------------------
# isolation
# ---------------------------------------------------------------------------


async def test_by_id_routes_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_user,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id, org_a_user.id)
    b_admin = await _org_b_admin_headers(db_session, org_b)
    agent, inv, sess = ids["agent"], ids["investigation"], ids["session"]

    # The owner sees them.
    assert (await client.get(f"{API}/agents/{agent}", headers=org_a_headers)).status_code == 200
    assert (await client.get(f"{API}/investigations/{inv}", headers=org_a_headers)).status_code == 200

    for method, path, json in (
        ("GET", f"{API}/agents/{agent}", None),
        ("GET", f"{API}/investigations/{inv}", None),
        ("GET", f"{API}/investigations/{inv}/reasoning-chain", None),
        ("GET", f"{API}/investigations/{inv}/feedback", None),
        ("GET", f"{API}/investigations/{inv}/explain", None),
        ("GET", f"{API}/chat/sessions/{sess}/messages", None),
        ("POST", f"{API}/investigations/{inv}/correct", {"corrected_verdict": "benign"}),
        ("DELETE", f"{API}/chat/sessions/{sess}", None),
        ("POST", f"{API}/investigations", {"title": "x", "trigger_type": "manual", "agent_id": agent}),
    ):
        resp = await assert_tenant_isolated(client, method, path, org_b_headers, json=json)
        assert resp.status_code == 404, (method, path, resp.text)

    # Admin-only routes, probed by the other tenant's admin (so the 404 is the
    # tenant check, not the role gate).
    for method, path, json in (
        ("PUT", f"{API}/agents/{agent}", {"name": "pwned"}),
    ):
        resp = await assert_tenant_isolated(client, method, path, b_admin, json=json)
        assert resp.status_code == 404, (method, path, resp.text)

    # Nothing of A's changed or vanished.
    db_session.expire_all()
    assert (await db_session.get(SOCAgent, agent)).name == "triage"
    assert (await db_session.get(Investigation, inv)).title == "inv"
    assert await db_session.get(AgentChatSession, sess) is not None
    remaining = (await db_session.execute(select(AgentMemory).where(AgentMemory.agent_id == agent))).scalars().all()
    assert len(remaining) == 1


async def test_lists_and_dashboards_do_not_leak(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_user,
    org_b_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id, org_a_user.id)

    agents = (await client.get(f"{API}/agents", headers=org_b_headers)).json()
    assert ids["agent"] not in {a["id"] for a in agents["items"]}
    investigations = (await client.get(f"{API}/investigations", headers=org_b_headers)).json()
    assert ids["investigation"] not in {i["id"] for i in investigations["items"]}
    sessions = (await client.get(f"{API}/chat/sessions", headers=org_b_headers)).json()
    assert ids["session"] not in {s["id"] for s in sessions["items"]}
    metrics = await client.get(f"{API}/dashboard/metrics", headers=org_b_headers)
    assert metrics.status_code == 200, metrics.text
    assert metrics.json()["total_agents"] == 0


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------

ANALYST_WRITES = [
    ("POST", "/chat", {"query": "hello"}),
    ("POST", "/chat/sessions", {"title": "t"}),
    ("DELETE", f"/chat/sessions/{MISSING}", None),
    ("POST", "/hunts", {"hypothesis": "lateral movement via smb"}),
    ("POST", "/investigations", {"title": "x", "trigger_type": "manual", "agent_id": MISSING}),
    ("POST", f"/investigations/{MISSING}/correct", {"corrected_verdict": "benign"}),
    ("POST", "/tools/list_alerts/execute", {"limit": 1}),
    ("POST", "/trust/acknowledge", {"session_id": MISSING, "reason": "reviewed"}),
]
ADMIN_WRITES = [
    ("POST", "/agents", {"name": "a", "agent_type": "triage_analyst"}),
    ("PUT", f"/agents/{MISSING}", {"name": "x"}),
    ("POST", f"/actions/{MISSING}/approve", {"approved": False}),
    ("POST", f"/actions/{MISSING}/rollback", None),
]


@pytest.mark.parametrize("method,path,json", ANALYST_WRITES + ADMIN_WRITES)
async def test_viewer_cannot_write(
    client: AsyncClient, viewer_headers: dict[str, str], method: str, path: str, json,
) -> None:
    resp = await client.request(method, f"{API}{path}", headers=viewer_headers, json=json)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "role_not_permitted"


@pytest.mark.parametrize("method,path,json", ADMIN_WRITES)
async def test_analyst_cannot_configure_or_approve(
    client: AsyncClient, org_a_headers: dict[str, str], method: str, path: str, json,
) -> None:
    resp = await client.request(method, f"{API}{path}", headers=org_a_headers, json=json)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "role_not_permitted"


@pytest.mark.parametrize("method,path,json", ADMIN_WRITES[1:])
async def test_admin_passes_the_role_gate(
    client: AsyncClient, org_a_admin_headers: dict[str, str], method: str, path: str, json,
) -> None:
    # Past the gate the missing id is a plain 404.
    resp = await client.request(method, f"{API}{path}", headers=org_a_admin_headers, json=json)
    assert resp.status_code == 404, resp.text


async def test_viewer_can_read(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_viewer,
    viewer_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id, org_a_viewer.id)
    for path in (
        "/agents", f"/agents/{ids['agent']}", "/investigations", f"/investigations/{ids['investigation']}",
        "/chat/sessions", f"/chat/sessions/{ids['session']}/messages", "/dashboard/metrics",
        "/dashboard/investigation-metrics",
    ):
        resp = await client.get(f"{API}{path}", headers=viewer_headers)
        assert resp.status_code == 200, (path, resp.text)


# ---------------------------------------------------------------------------
# stamping
# ---------------------------------------------------------------------------


async def test_creates_are_stamped_with_the_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
) -> None:
    a_id = org_a.id
    resp = await client.post(
        f"{API}/agents", headers=org_a_admin_headers, json={"name": "hunter", "agent_type": "threat_hunter"},
    )
    assert resp.status_code == 201, resp.text
    agent_id = resp.json()["id"]
    assert (await db_session.get(SOCAgent, agent_id)).organization_id == a_id

    resp = await client.post(f"{API}/chat/sessions", headers=org_a_headers, json={"title": "case 7"})
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["id"]
    assert (await db_session.get(AgentChatSession, session_id)).organization_id == a_id


# ---------------------------------------------------------------------------
# org-less callers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/agents", "/investigations", "/chat/sessions", "/dashboard/metrics", "/tools"])
async def test_orgless_callers_get_organization_required(
    client: AsyncClient, orgless_headers: dict[str, str], superuser_headers: dict[str, str], path: str,
) -> None:
    for headers in (orgless_headers, superuser_headers):
        resp = await client.get(f"{API}{path}", headers=headers)
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "organization_required"


async def test_usage_explicit_scope_for_orgless_superuser(
    client: AsyncClient, org_a: Organization, superuser_headers: dict[str, str], orgless_headers: dict[str, str],
) -> None:
    a_id = org_a.id
    resp = await client.get(f"{API}/usage", headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"

    resp = await client.get(f"{API}/usage", headers=superuser_headers, params={"organization_id": a_id})
    assert resp.status_code == 200, resp.text
    assert resp.json()["organization_id"] == a_id

    resp = await client.get(f"{API}/usage", headers=orgless_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"


# ---------------------------------------------------------------------------
# Adjacent wave-1 gate owned by the same change: POST /attack/sync (platform
# superuser only). POST /ai/query was deleted in wave 5 (agentic chat replaces it).
# ---------------------------------------------------------------------------


async def test_attack_sync_is_platform_superuser_only(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    resp = await client.post("/api/v1/attack/sync", headers=org_a_admin_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "platform_superuser_required"
