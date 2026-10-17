"""Identity residuals: GET /roles/me, custom roles in handler checks, and the
SSO group re-sync on login.

* ``GET /roles/me`` reports the caller's own effective tiers (the function the
  API gates use) and is never denied by tier.
* The admin-only branches that used to read ``User.role`` / ``is_admin``
  inline (bulk alert delete, note / attachment / comment deletion by
  non-authors, playbook containment, legal-hold release, team visibility,
  admin-permission API keys, the agent role ladder, the playbook engines'
  actor check) follow a custom role's tiers; built-in users keep their old
  behaviour (their suites stay green unchanged).
* Every successful SSO login re-applies the role the user's groups map to;
  no mapped group leaves the role alone; SCIM-managed users are never changed.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.identity import oidc
from src.identity import roles as identity_roles
from src.identity.models import Role
from src.models.audit import AuditLog
from src.models.user import User
from tests.helpers.tenancy import bearer, make_user
from tests.unit.sso_fakes import FakeIdP, configure, install, query, start, stateful_redis

DOMAIN = "acme-sso.io"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(role: str = "viewer", *, custom: Role | None = None, superuser: bool = False, org: str = "org-1") -> User:
    u = User(
        id=str(uuid.uuid4()), email="x@example.test", hashed_password="x", role=role,
        is_superuser=superuser, organization_id=org, custom_role_id=str(custom.id) if custom else None,
    )
    if custom is not None:
        setattr(u, identity_roles.CUSTOM_ROLE_ATTR, custom)
    return u


def _role(default: str = "read", tiers: dict | None = None, org: str = "org-1") -> Role:
    return Role(id=str(uuid.uuid4()), organization_id=org, name="r", default_tier=default, area_tiers=tiers or {})


async def _custom_holder(db, org_id: str, default: str, tiers: dict, label: str = "holder") -> tuple[User, dict, str]:
    """A user of ``org_id`` holding a fresh custom role; returns (user, headers, role id)."""
    role = Role(organization_id=org_id, name=f"r-{uuid.uuid4().hex[:6]}", default_tier=default, area_tiers=tiers)
    db.add(role)
    await db.commit()
    role_id = role.id
    user = await make_user(db, role="viewer", organization_id=org_id, label=label)
    user.custom_role_id = role_id
    await db.commit()
    await db.refresh(user)
    return user, bearer(user), role_id


def _error(resp) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_builtin_equivalent_and_full_admin() -> None:
    assert identity_roles.builtin_equivalent(_user("analyst"), "alerts") == "analyst"
    assert identity_roles.builtin_equivalent(_user("viewer", superuser=True), "alerts") == "admin"
    assert identity_roles.builtin_equivalent(_user("weird"), "alerts") == "viewer"
    holder = _user(custom=_role("read", {"agentic": "admin", "itdr": "write"}))
    assert identity_roles.builtin_equivalent(holder, "agentic") == "admin"
    assert identity_roles.builtin_equivalent(holder, "itdr") == "analyst"
    assert identity_roles.builtin_equivalent(holder, "alerts") == "viewer"

    assert identity_roles.is_full_admin(_user("admin"))
    assert identity_roles.is_full_admin(_user("viewer", superuser=True))
    assert not identity_roles.is_full_admin(_user("analyst"))
    admin_with_custom = _user("admin", custom=_role("admin"))
    assert not identity_roles.is_full_admin(admin_with_custom)


def test_has_tier_everywhere() -> None:
    assert identity_roles.has_tier_everywhere(_user("admin"), "admin")
    assert not identity_roles.has_tier_everywhere(_user("analyst"), "admin")
    assert identity_roles.has_tier_everywhere(_user(custom=_role("admin")), "admin")
    assert not identity_roles.has_tier_everywhere(_user(custom=_role("admin", {"siem": "write"})), "admin")
    assert not identity_roles.has_tier_everywhere(_user(custom=_role("admin", org="org-2")), "admin")
    unloaded = _user("admin")
    unloaded.custom_role_id = str(uuid.uuid4())
    assert not identity_roles.has_tier_everywhere(unloaded, "admin")


def test_roles_me_is_a_self_route() -> None:
    assert identity_roles.is_self_route("/api/v1/roles/me", "u1")
    assert not identity_roles.is_self_route("/api/v1/roles/me/x", "u1")
    assert not identity_roles.is_self_route("/api/v1/roles", "u1")
    assert identity_roles.is_self_route("/api/v1/users/u1", "u1")
    assert not identity_roles.is_self_route("/api/v1/users/u2", "u1")


def test_first_mapped_group_uses_map_order() -> None:
    mapping = {"admins": "admin", "analysts": "analyst"}
    assert oidc.first_mapped_group(mapping, ["analysts", "admins"]) == ("admins", "admin")
    assert oidc.first_mapped_group(mapping, ["analysts"]) == ("analysts", "analyst")
    assert oidc.first_mapped_group(mapping, ["everyone"]) is None
    assert oidc.first_mapped_group({}, ["admins"]) is None
    assert oidc.first_mapped_group(None, ["admins"]) is None


def test_agent_role_follows_the_request_area() -> None:
    from src.agentic.context import Mode, UserRole
    from src.api.v1.endpoints.agentic import _agent_context, _agent_role

    holder = _user(custom=_role("read", {"agentic": "write", "itdr": "admin"}))
    assert _agent_role(holder) is UserRole.ANALYST
    itdr_request = SimpleNamespace(url=SimpleNamespace(path="/api/v1/itdr/threats/t1/respond"), client=None)
    ctx = _agent_context(holder, Mode.INTERACTIVE, request=itdr_request, org_id="org-1")
    # Admin in the request's area alone is capped at ANALYST (bcaaed1): agent
    # tools act in other areas, so the ADMIN rung needs admin everywhere.
    assert ctx.role is UserRole.ANALYST
    everywhere = _user(custom=_role("admin", {}))
    ctx = _agent_context(everywhere, Mode.INTERACTIVE, request=itdr_request, org_id="org-1")
    assert ctx.role is UserRole.ADMIN
    ctx = _agent_context(holder, Mode.INTERACTIVE, org_id="org-1")
    assert ctx.role is UserRole.ANALYST
    # Built-in users keep their role whatever the area.
    assert _agent_role(_user("analyst"), "itdr") is UserRole.ANALYST
    assert _agent_role(_user("viewer", superuser=True)) is UserRole.ADMIN


async def test_agentic_admin_gate_uses_the_agentic_tier() -> None:
    from fastapi import HTTPException

    from src.api.v1.endpoints.agentic import _agentic_role_gate
    from src.models.user import UserRole

    gate = _agentic_role_gate(UserRole.ADMIN)
    assert getattr(gate, identity_roles.REQUIRED_TIER_ATTR) == "admin"
    ok = _user(custom=_role("read", {"agentic": "admin"}))
    assert await gate(ok) is ok
    with pytest.raises(HTTPException) as exc:
        await gate(_user(custom=_role("write")))
    assert exc.value.status_code == 403 and exc.value.detail["error"] == "role_not_permitted"
    with pytest.raises(HTTPException):
        await gate(_user("analyst"))
    assert await gate(_user("admin")) is not None


def test_playbook_builder_records_the_tier_role() -> None:
    from src.api.v1.endpoints.playbook_builder import _effective_role

    assert _effective_role(_user("analyst")) == "analyst"
    assert _effective_role(_user("viewer", superuser=True)) == "admin"
    assert _effective_role(_user(custom=_role("read", {"playbook-builder": "admin"}))) == "admin"
    assert _effective_role(_user(custom=_role("admin", {"playbook-builder": "write"}))) == "analyst"


async def test_user_has_tier_for_background_code(db_session, org_a, org_b) -> None:
    org_id = org_a.id
    admin = await make_user(db_session, role="admin", organization_id=org_id, label="bg-admin")
    analyst = await make_user(db_session, role="analyst", organization_id=org_id, label="bg-analyst")
    holder, _, _ = await _custom_holder(db_session, org_id, "read", {"playbooks": "admin"}, label="bg-holder")
    ids = (admin.id, analyst.id, holder.id)
    assert await identity_roles.user_has_tier(db_session, ids[0], org_id, "playbooks", "admin")
    assert not await identity_roles.user_has_tier(db_session, ids[1], org_id, "playbooks", "admin")
    assert await identity_roles.user_has_tier(db_session, ids[2], org_id, "playbooks", "admin")
    assert not await identity_roles.user_has_tier(db_session, ids[2], org_id, "alerts", "write")
    # Another organisation, unknown or inactive users hold nothing.
    assert not await identity_roles.user_has_tier(db_session, ids[0], org_b.id, "playbooks", "admin")
    assert not await identity_roles.user_has_tier(db_session, None, org_id, "playbooks", "admin")
    holder.is_active = False
    await db_session.commit()
    assert not await identity_roles.user_has_tier(db_session, ids[2], org_id, "playbooks", "admin")


# ---------------------------------------------------------------------------
# GET /roles/me
# ---------------------------------------------------------------------------


async def test_roles_me_for_builtin_users(
    client: AsyncClient, viewer_headers, org_a_headers, org_a_admin_headers,
) -> None:
    for headers, role, tier in (
        (viewer_headers, "viewer", "read"), (org_a_headers, "analyst", "write"), (org_a_admin_headers, "admin", "admin"),
    ):
        resp = await client.get("/api/v1/roles/me", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["role"] == role and body["custom_role"] is None and body["is_superuser"] is False
        assert body["is_full_admin"] is (role == "admin")
        assert body["tiers"] and set(body["tiers"].values()) == {tier}
        assert {"alerts", "roles", "siem", "users"} <= set(body["tiers"])
        assert {"auth", "mfa", "api-keys", "health"} <= set(body["exempt_areas"])


async def test_roles_me_for_a_custom_role_holder_matches_the_gates(client: AsyncClient, db_session, org_a) -> None:
    _, headers, role_id = await _custom_holder(db_session, org_a.id, "none", {"siem": "write", "alerts": "read"})
    resp = await client.get("/api/v1/roles/me", headers=headers)
    # Never denied by tier even though the role holds none over "roles".
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["role"] == "viewer" and body["custom_role"]["id"] == role_id and body["custom_role"]["name"]
    assert body["is_full_admin"] is False
    assert body["tiers"]["siem"] == "write" and body["tiers"]["alerts"] == "read"
    assert body["tiers"]["roles"] == "none" and body["tiers"]["incidents"] == "none"
    # The report matches enforcement: alerts readable, incidents denied, role admin denied.
    assert (await client.get("/api/v1/alerts", headers=headers)).status_code == 200
    denied = await client.get("/api/v1/incidents", headers=headers)
    assert denied.status_code == 403 and _error(denied) == "area_denied"
    assert (await client.get("/api/v1/roles", headers=headers)).status_code == 403


async def test_roles_me_for_superuser_and_anonymous(client: AsyncClient, superuser_headers) -> None:
    resp = await client.get("/api/v1/roles/me", headers=superuser_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_superuser"] and body["is_full_admin"] and set(body["tiers"].values()) == {"admin"}
    assert (await client.get("/api/v1/roles/me")).status_code == 401


async def test_role_by_id_route_still_resolves(client: AsyncClient, db_session, org_a, org_a_admin_headers) -> None:
    created = await client.post("/api/v1/roles", json={"name": "Readers", "default_tier": "read", "area_tiers": {}},
                                headers=org_a_admin_headers)
    assert created.status_code == 201, created.text
    role_id = created.json()["id"]
    assert (await client.get(f"/api/v1/roles/{role_id}", headers=org_a_admin_headers)).json()["id"] == role_id


# ---------------------------------------------------------------------------
# Handler checks on real routes
# ---------------------------------------------------------------------------


async def test_bulk_alert_delete_needs_admin_over_alerts(client: AsyncClient, db_session, org_a) -> None:
    from src.models.alert import Alert

    org_id = org_a.id
    alert = Alert(title="bulk", description="d", severity="high", status="new", source="siem", category="malware",
                  organization_id=org_id)
    db_session.add(alert)
    await db_session.commit()
    alert_id = alert.id
    _, writer, _ = await _custom_holder(db_session, org_id, "read", {"alerts": "write"}, label="alerts-writer")
    _, admin, _ = await _custom_holder(db_session, org_id, "read", {"alerts": "admin"}, label="alerts-admin")

    resp = await client.post("/api/v1/alerts/bulk", json={"alert_ids": [alert_id], "action": "delete"}, headers=writer)
    assert resp.status_code == 403 and _error(resp) == "admin_required"
    resp = await client.post("/api/v1/alerts/bulk", json={"alert_ids": [alert_id], "action": "acknowledge"}, headers=writer)
    assert resp.status_code == 200, resp.text
    resp = await client.post("/api/v1/alerts/bulk", json={"alert_ids": [alert_id], "action": "delete"}, headers=admin)
    assert resp.status_code == 200, resp.text
    assert resp.json()["results"][0]["status"] == "deleted"


async def test_note_deletion_by_non_author_needs_admin_over_incidents(client: AsyncClient, db_session, org_a) -> None:
    from src.models.case import CaseNote
    from src.models.incident import Incident

    org_id = org_a.id
    author = await make_user(db_session, role="analyst", organization_id=org_id, label="note-author")
    incident = Incident(title="case", severity="high", status="open", organization_id=org_id)
    db_session.add(incident)
    await db_session.commit()
    incident_id = incident.id
    notes = []
    for _ in range(2):
        note = CaseNote(content="n", incident_id=incident_id, author_id=author.id)
        db_session.add(note)
        await db_session.commit()
        notes.append(note.id)
    _, writer, _ = await _custom_holder(db_session, org_id, "read", {"incidents": "write"}, label="inc-writer")
    _, admin, _ = await _custom_holder(db_session, org_id, "read", {"incidents": "admin"}, label="inc-admin")

    resp = await client.delete(f"/api/v1/incidents/{incident_id}/notes/{notes[0]}", headers=writer)
    assert resp.status_code == 403, resp.text
    resp = await client.patch(f"/api/v1/incidents/{incident_id}/notes/{notes[0]}", json={"content": "x"}, headers=writer)
    assert resp.status_code == 403, resp.text
    resp = await client.delete(f"/api/v1/incidents/{incident_id}/notes/{notes[1]}", headers=admin)
    assert resp.status_code == 204, resp.text


async def test_comment_deletion_by_non_author_needs_admin_over_tickethub(client: AsyncClient, db_session, org_a) -> None:
    from src.tickethub.models import TicketComment

    org_id = org_a.id
    author = await make_user(db_session, role="analyst", organization_id=org_id, label="comment-author")
    ids = []
    for _ in range(2):
        comment = TicketComment(source_type="incident", source_id=str(uuid.uuid4()), content="c",
                                author_id=author.id, organization_id=org_id)
        db_session.add(comment)
        await db_session.commit()
        ids.append(comment.id)
    _, writer, _ = await _custom_holder(db_session, org_id, "read", {"tickethub": "write"}, label="th-writer")
    _, admin, _ = await _custom_holder(db_session, org_id, "read", {"tickethub": "admin"}, label="th-admin")

    resp = await client.delete(f"/api/v1/tickethub/comments/{ids[0]}", headers=writer)
    assert resp.status_code == 403 and _error(resp) == "not_comment_author"
    resp = await client.delete(f"/api/v1/tickethub/comments/{ids[1]}", headers=admin)
    assert resp.status_code == 204, resp.text


async def test_containment_playbook_needs_admin_over_playbooks(client: AsyncClient, db_session, org_a) -> None:
    from src.models.playbook import Playbook

    org_id = org_a.id
    author = await make_user(db_session, role="admin", organization_id=org_id, label="pb-author")
    pb = Playbook(name="contain", status="active", is_enabled=True, organization_id=org_id, created_by=author.id,
                  steps=json.dumps([{"name": "Block", "action": "block_ip", "parameters": {"ip": "203.0.113.9"}}]))
    db_session.add(pb)
    await db_session.commit()
    pb_id = pb.id
    _, writer, _ = await _custom_holder(db_session, org_id, "read", {"playbooks": "write"}, label="pb-writer")
    _, admin, _ = await _custom_holder(db_session, org_id, "read", {"playbooks": "admin"}, label="pb-admin")

    resp = await client.post(f"/api/v1/playbooks/{pb_id}/execute", headers=writer, json={})
    assert resp.status_code == 403 and _error(resp) == "containment_requires_admin"
    resp = await client.post(f"/api/v1/playbooks/{pb_id}/execute", headers=admin, json={})
    assert resp.status_code == 200, resp.text


async def test_legal_hold_release_needs_admin_over_dfir(client: AsyncClient, db_session, org_a, org_a_headers) -> None:
    org_id = org_a.id
    case = await client.post("/api/v1/dfir/cases", headers=org_a_headers,
                             json={"case_number": f"CASE-{uuid.uuid4().hex[:10]}", "title": "t", "severity": "medium"})
    assert case.status_code == 201, case.text
    hold = await client.post(f"/api/v1/dfir/cases/{case.json()['id']}/legal-holds", headers=org_a_headers,
                             json={"hold_type": "litigation", "custodians": ["alice"]})
    assert hold.status_code == 201, hold.text
    hold_id = hold.json()["id"]
    _, writer, _ = await _custom_holder(db_session, org_id, "read", {"dfir": "write"}, label="dfir-writer")
    _, admin, _ = await _custom_holder(db_session, org_id, "read", {"dfir": "admin"}, label="dfir-admin")

    resp = await client.put(f"/api/v1/dfir/legal-holds/{hold_id}", json={"status": "released"}, headers=writer)
    assert resp.status_code == 403 and _error(resp) == "admin_required"
    resp = await client.put(f"/api/v1/dfir/legal-holds/{hold_id}", json={"status": "released"}, headers=admin)
    assert resp.status_code == 200 and resp.json()["status"] == "released"


async def test_team_visibility_follows_admin_over_teams(client: AsyncClient, db_session, org_a) -> None:
    from src.models.organization import Team

    org_id = org_a.id
    team = Team(name=f"blue-{uuid.uuid4().hex[:6]}", organization_id=org_id)
    db_session.add(team)
    await db_session.commit()
    team_id = team.id
    _, reader, _ = await _custom_holder(db_session, org_id, "read", {}, label="teams-reader")
    _, admin, _ = await _custom_holder(db_session, org_id, "read", {"teams": "admin"}, label="teams-admin")

    listed = await client.get("/api/v1/teams", headers=reader)
    assert listed.status_code == 200 and team_id not in [t["id"] for t in listed.json()]
    assert (await client.get(f"/api/v1/teams/{team_id}", headers=reader)).status_code == 403
    listed = await client.get("/api/v1/teams", headers=admin)
    assert team_id in [t["id"] for t in listed.json()]
    assert (await client.get(f"/api/v1/teams/{team_id}", headers=admin)).status_code == 200


async def test_organization_admin_branch_follows_admin_over_organizations(client: AsyncClient, db_session, org_a) -> None:
    org_id = org_a.id
    member = await make_user(db_session, role="viewer", organization_id=org_id, label="org-member")
    member_id = member.id
    # The route gate and the in-handler branch (_get_organization's
    # require_admin) both need admin over organizations.
    _, writer, _ = await _custom_holder(db_session, org_id, "read", {"organizations": "write"}, label="org-writer")
    _, admin, _ = await _custom_holder(db_session, org_id, "read", {"organizations": "admin"}, label="org-admin")
    body = {"user_id": member_id, "role": "member"}
    resp = await client.post(f"/api/v1/organizations/{org_id}/members", json=body, headers=writer)
    assert resp.status_code == 403, resp.text
    resp = await client.post(f"/api/v1/organizations/{org_id}/members", json=body, headers=admin)
    assert resp.status_code in (200, 201), resp.text


async def test_admin_permission_api_keys_follow_tiers(client: AsyncClient, db_session, org_a, org_a_headers) -> None:
    org_id = org_a.id
    _, users_admin, _ = await _custom_holder(db_session, org_id, "read", {"users": "admin"}, label="key-users")
    _, all_admin, _ = await _custom_holder(db_session, org_id, "admin", {}, label="key-all")

    async def create(headers, perms):
        return await client.post("/api/v1/api-keys", json={"name": "k", "permissions": perms}, headers=headers)

    assert (await create(users_admin, ["users:read"])).status_code == 201
    assert (await create(users_admin, ["settings:write"])).status_code == 403
    assert (await create(users_admin, ["users:*"])).status_code == 201
    assert (await create(users_admin, ["*"])).status_code == 403
    assert (await create(users_admin, ["alerts:read"])).status_code == 201
    assert (await create(all_admin, ["*"])).status_code == 201
    # Built-in analyst: admin permissions refused, as before (now also users:*).
    assert (await create(org_a_headers, ["users:read"])).status_code == 403
    assert (await create(org_a_headers, ["users:*"])).status_code == 403
    assert (await create(org_a_headers, ["alerts:read"])).status_code == 201


async def test_agentic_analyst_gate_on_a_real_route(client: AsyncClient, db_session, org_a) -> None:
    org_id = org_a.id
    _, reader, _ = await _custom_holder(db_session, org_id, "read", {"agentic": "read"}, label="ag-reader")
    _, writer, _ = await _custom_holder(db_session, org_id, "read", {"agentic": "write"}, label="ag-writer")
    resp = await client.post("/api/v1/agentic/chat/sessions", json={"title": "t"}, headers=reader)
    assert resp.status_code == 403 and _error(resp) == "role_not_permitted"
    resp = await client.post("/api/v1/agentic/chat/sessions", json={"title": "t"}, headers=writer)
    assert resp.status_code == 200, resp.text


async def test_classic_engine_actor_check_reads_custom_roles(db_session, org_a) -> None:
    from src.services.playbook_engine import PlaybookEngine

    org_id = org_a.id
    holder, _, _ = await _custom_holder(db_session, org_id, "read", {"playbooks": "admin"}, label="eng-holder")
    writer, _, _ = await _custom_holder(db_session, org_id, "admin", {"playbooks": "write"}, label="eng-writer")
    analyst = await make_user(db_session, role="analyst", organization_id=org_id, label="eng-analyst")
    admin = await make_user(db_session, role="admin", organization_id=org_id, label="eng-admin")
    engine = PlaybookEngine(db_session)
    assert await engine._is_current_admin(holder.id, org_id)
    assert not await engine._is_current_admin(writer.id, org_id)
    assert not await engine._is_current_admin(analyst.id, org_id)
    assert await engine._is_current_admin(admin.id, org_id)


# ---------------------------------------------------------------------------
# SSO group re-sync
# ---------------------------------------------------------------------------


@pytest.fixture
def store(redis_mock):
    return stateful_redis(redis_mock)


@pytest.fixture
def idp(monkeypatch) -> FakeIdP:
    provider = FakeIdP()
    install(monkeypatch, provider)
    return provider


async def _login(client: AsyncClient, idp: FakeIdP, slug: str, **claims) -> dict[str, str]:
    resp = await start(client, slug)
    assert resp.status_code == 302, resp.text
    code, state = idp.authorize(resp.headers["location"], **claims)
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert cb.status_code == 302, cb.text
    return query(cb.headers["location"])


async def _synced_rows(db, user_id: str) -> list[AuditLog]:
    return list((await db.execute(
        select(AuditLog).where(AuditLog.action == "sso_role_synced", AuditLog.resource_id == user_id)
    )).scalars().all())


async def _reload(db, user_id: str) -> User:
    db.expire_all()
    return (await db.execute(select(User).where(User.id == user_id))).scalar_one()


async def test_login_resyncs_the_mapped_role_and_audits_it(client: AsyncClient, db_session, org_a, idp, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    hunters = Role(organization_id=org_id, name="Hunters", default_tier="read", area_tiers={"hunting": "write"})
    db_session.add(hunters)
    await db_session.commit()
    hunters_id = hunters.id
    await configure(db_session, org_id, idp, groups_claim="groups",
                    group_role_map={"soc-admins": "admin", "hunters": "Hunters", "soc": "analyst"})

    # First login provisions with the mapped role; no re-sync row for a new account.
    result = await _login(client, idp, slug, sub="s1", email=f"ann@{DOMAIN}", groups=["soc"])
    assert "sso" in result
    user = (await db_session.execute(select(User).where(User.sso_subject == "s1"))).scalar_one()
    user_id = user.id
    assert user.role == "analyst" and not await _synced_rows(db_session, user_id)

    # Promoted at the IdP: the next login applies it.
    assert "sso" in await _login(client, idp, slug, sub="s1", email=f"ann@{DOMAIN}", groups=["soc-admins", "soc"])
    user = await _reload(db_session, user_id)
    assert user.role == "admin" and user.custom_role_id is None
    rows = await _synced_rows(db_session, user_id)
    assert len(rows) == 1 and rows[0].organization_id == org_id and rows[0].success
    assert json.loads(rows[0].old_value) == {"role": "analyst", "custom_role_id": None}
    assert json.loads(rows[0].new_value) == {"role": "admin", "custom_role_id": None}

    # Moved to a group mapped to a custom role: assigned with the viewer floor.
    assert "sso" in await _login(client, idp, slug, sub="s1", email=f"ann@{DOMAIN}", groups=["hunters"])
    user = await _reload(db_session, user_id)
    assert user.custom_role_id == hunters_id and user.role == "viewer"

    # Back to a built-in mapping: the custom role is cleared.
    assert "sso" in await _login(client, idp, slug, sub="s1", email=f"ann@{DOMAIN}", groups=["soc"])
    user = await _reload(db_session, user_id)
    assert user.custom_role_id is None and user.role == "analyst"
    assert len(await _synced_rows(db_session, user_id)) == 3

    # Same mapping again: no change, no row.
    assert "sso" in await _login(client, idp, slug, sub="s1", email=f"ann@{DOMAIN}", groups=["soc"])
    assert len(await _synced_rows(db_session, user_id)) == 3


async def test_unmapped_groups_never_demote(client: AsyncClient, db_session, org_a, idp, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, idp, groups_claim="groups", group_role_map={"soc": "analyst"})
    user = await make_user(db_session, role="admin", organization_id=org_id, label="keeper")
    user_id = user.id
    user.email = f"keeper@{DOMAIN}"
    await db_session.commit()
    for groups in (["everyone"], []):
        assert "sso" in await _login(client, idp, slug, sub="keeper-sub", email=f"keeper@{DOMAIN}", groups=groups)
    assert (await _reload(db_session, user_id)).role == "admin"
    assert not await _synced_rows(db_session, user_id)


async def test_bound_local_account_is_resynced_on_its_first_sso_login(client: AsyncClient, db_session, org_a, idp, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, idp, groups_claim="groups", group_role_map={"soc-viewers": "viewer"},
                    jit_provisioning=False)
    user = await make_user(db_session, role="analyst", organization_id=org_id, label="bound")
    user_id = user.id
    user.email = f"bound@{DOMAIN}"
    await db_session.commit()
    assert "sso" in await _login(client, idp, slug, sub="bound-sub", email=f"bound@{DOMAIN}", groups=["soc-viewers"])
    user = await _reload(db_session, user_id)
    assert user.sso_subject == "bound-sub" and user.role == "viewer"
    assert len(await _synced_rows(db_session, user_id)) == 1


async def test_no_groups_claim_or_empty_map_leaves_roles_alone(client: AsyncClient, db_session, org_a, idp, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    config = await configure(db_session, org_id, idp, groups_claim=None, group_role_map={"soc": "admin"})
    user = await make_user(db_session, role="analyst", organization_id=org_id, label="nogroups")
    user_id = user.id
    user.email = f"nogroups@{DOMAIN}"
    await db_session.commit()
    assert "sso" in await _login(client, idp, slug, sub="ng", email=f"nogroups@{DOMAIN}", groups=["soc"])
    assert (await _reload(db_session, user_id)).role == "analyst"

    config.groups_claim = "groups"
    config.group_role_map = {}
    await db_session.commit()
    assert "sso" in await _login(client, idp, slug, sub="ng", email=f"nogroups@{DOMAIN}", groups=["soc"])
    assert (await _reload(db_session, user_id)).role == "analyst"
    assert not await _synced_rows(db_session, user_id)


async def test_scim_managed_users_are_never_changed_by_sso(client: AsyncClient, db_session, org_a, idp, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, idp, groups_claim="groups", group_role_map={"soc-admins": "admin"})
    user = await make_user(db_session, role="viewer", organization_id=org_id, label="scimmed")
    user_id = user.id
    user.email = f"scimmed@{DOMAIN}"
    user.identity_source = "scim"
    await db_session.commit()
    assert "sso" in await _login(client, idp, slug, sub="scim-sub", email=f"scimmed@{DOMAIN}", groups=["soc-admins"])
    assert (await _reload(db_session, user_id)).role == "viewer"
    assert not await _synced_rows(db_session, user_id)


async def test_mapping_to_a_missing_role_refuses_the_login(client: AsyncClient, db_session, org_a, idp, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, idp, groups_claim="groups", group_role_map={"ghosts": "Deleted Role"})
    user = await make_user(db_session, role="analyst", organization_id=org_id, label="ghost")
    user_id = user.id
    user.email = f"ghost@{DOMAIN}"
    await db_session.commit()
    result = await _login(client, idp, slug, sub="ghost-sub", email=f"ghost@{DOMAIN}", groups=["ghosts"])
    assert result == {"sso_error": "role_unresolved"}
    user = await _reload(db_session, user_id)
    assert user.role == "analyst" and user.sso_subject is None  # rolled back, nothing bound
