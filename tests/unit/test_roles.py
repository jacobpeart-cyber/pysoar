"""Custom roles: tier resolution, enforcement on real routes, role CRUD and assignment.

The enforcement tests use real routers: a custom role with ``siem: write`` and
``default: read`` must be able to do SIEM operational writes (saved searches,
``require_role([ADMIN, ANALYST])``) and nothing more (no SIEM rules, which are
admin; no alert writes). Users without a custom role must see exactly the old
behaviour (same status codes and detail strings).
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from src.identity import roles as identity_roles
from src.identity.models import Role
from src.models.audit import AuditLog
from src.models.user import User
from tests.helpers.tenancy import bearer, make_user


# ---------------------------------------------------------------------------
# Pure resolution
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


@pytest.mark.parametrize(
    ("make", "area", "expected"),
    [
        (lambda: _user("viewer"), "alerts", "read"),
        (lambda: _user("analyst"), "alerts", "write"),
        (lambda: _user("admin"), "siem", "admin"),
        (lambda: _user("unknown-role"), "alerts", "none"),
        (lambda: _user("viewer", superuser=True), "anything", "admin"),
        (lambda: _user(custom=_role("read", {"siem": "write"})), "siem", "write"),
        (lambda: _user(custom=_role("read", {"siem": "write"})), "alerts", "read"),
        (lambda: _user(custom=_role("none", {"alerts": "admin"})), "alerts", "admin"),
        (lambda: _user(custom=_role("none", {"alerts": "admin"})), "incidents", "none"),
        (lambda: _user(custom=_role("write", {"alerts": "bogus"})), "alerts", "none"),
        # A role of another organisation grants nothing.
        (lambda: _user(custom=_role("admin", org="org-2")), "alerts", "none"),
        # Superusers bypass even with a custom role id set.
        (lambda: _user(custom=_role("none"), superuser=True), "alerts", "admin"),
    ],
)
def test_effective_tier_resolution(make, area, expected) -> None:
    assert identity_roles.effective_tier(make(), area) == expected


def test_custom_role_holder_without_loaded_role_holds_nothing() -> None:
    u = _user("admin")
    u.custom_role_id = str(uuid.uuid4())
    assert identity_roles.effective_tier(u, "alerts") == "none"


def test_required_tier_for_builtin_gates() -> None:
    from src.models.user import UserRole

    assert identity_roles.required_tier_for_roles([UserRole.ADMIN]) == "admin"
    assert identity_roles.required_tier_for_roles([UserRole.ADMIN, UserRole.ANALYST]) == "write"
    assert identity_roles.required_tier_for_roles([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER]) == "read"


def test_area_of_path_and_self_routes() -> None:
    assert identity_roles.area_of_path("/api/v1/alerts/123") == "alerts"
    assert identity_roles.area_of_path("/api/v1/siem") == "siem"
    assert identity_roles.area_of_path("/api/v1") == ""
    assert identity_roles.area_of_path("/metrics") is None
    assert identity_roles.is_self_route("/api/v1/users/abc", "abc")
    assert not identity_roles.is_self_route("/api/v1/users/abc", "def")
    assert not identity_roles.is_self_route("/api/v1/users/abc/extra", "abc")
    assert not identity_roles.is_self_route("/api/v1/alerts/abc", "abc")


def test_escalation_areas() -> None:
    admin = _user("admin")
    assert identity_roles.escalation_areas(admin, "admin", {}, {"alerts", "siem"}) == []
    holder = _user(custom=_role("read", {"roles": "admin", "users": "admin"}))
    assert identity_roles.escalation_areas(holder, "read", {"roles": "admin"}, {"alerts", "roles"}) == []
    assert identity_roles.escalation_areas(holder, "write", {}, {"alerts", "roles"}) == ["alerts"]


def test_apply_custom_role_sets_viewer_floor() -> None:
    u = _user("admin")
    r = _role("write")
    identity_roles.apply_custom_role(u, r)
    assert u.custom_role_id == str(r.id) and u.role == "viewer"
    identity_roles.apply_custom_role(u, None)
    assert u.custom_role_id is None


def test_assignment_error() -> None:
    r = _role(org="org-1")
    assert identity_roles.assignment_error(_user("viewer", superuser=True), r, "org-1")["error"] == "superuser_custom_role"
    assert identity_roles.assignment_error(_user("viewer"), r, "org-2")["error"] == "role_not_found"
    assert identity_roles.assignment_error(_user("viewer"), r, "org-1") is None


# ---------------------------------------------------------------------------
# Through the API
# ---------------------------------------------------------------------------


async def _create_role(client, headers, **body) -> dict:
    payload = {"name": body.pop("name", f"role-{uuid.uuid4().hex[:6]}"), **body}
    r = await client.post("/api/v1/roles", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


async def _holder(client, db_session, org_id: str, admin_headers: dict, role_id: str, label: str = "holder") -> tuple[User, dict]:
    user = await make_user(db_session, role="analyst", organization_id=org_id, label=label)
    user_id = user.id
    r = await client.patch(f"/api/v1/users/{user_id}", json={"custom_role_id": role_id}, headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["custom_role_id"] == role_id
    assert r.json()["role"] == "viewer"  # built-in role floor
    return user, bearer(user)


@pytest.mark.asyncio
async def test_siem_write_role_can_write_siem_and_not_alerts(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = await _create_role(client, org_a_admin_headers, default_tier="read", area_tiers={"siem": "write"})
    _, h = await _holder(client, db_session, org_id, org_a_admin_headers, role["id"])

    # SIEM operational write (require_role([ADMIN, ANALYST])): allowed.
    r = await client.post("/api/v1/siem/saved-searches", json={"name": "s", "query": "x"}, headers=h)
    assert r.status_code == 201, r.text
    # SIEM configuration (admin): refused with the tier error.
    r = await client.post("/api/v1/siem/rules", json={}, headers=h)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "insufficient_tier"
    assert r.json()["detail"]["area"] == "siem" and r.json()["detail"]["required"] == "admin"
    # Alerts: read yes, write no.
    assert (await client.get("/api/v1/alerts", headers=h)).status_code == 200
    r = await client.post("/api/v1/alerts", json={"title": "t", "source": "manual"}, headers=h)
    assert r.status_code == 403
    assert r.json()["detail"] == {
        "error": "insufficient_tier", "area": "alerts", "required": "write", "tier": "read",
        "detail": r.json()["detail"]["detail"],
    }


@pytest.mark.asyncio
async def test_none_area_is_denied_on_reads_but_exempt_and_self_routes_work(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = await _create_role(client, org_a_admin_headers, default_tier="read", area_tiers={"alerts": "none"})
    user, h = await _holder(client, db_session, org_id, org_a_admin_headers, role["id"])
    user_id = user.id

    r = await client.get("/api/v1/alerts", headers=h)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "area_denied" and r.json()["detail"]["area"] == "alerts"
    assert (await client.get("/api/v1/incidents", headers=h)).status_code == 200
    # Exempt area and own profile.
    assert (await client.get("/api/v1/auth/me", headers=h)).status_code == 200
    assert (await client.get(f"/api/v1/users/{user_id}", headers=h)).status_code == 200


@pytest.mark.asyncio
async def test_default_none_role_denies_everything_but_exempt(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = await _create_role(client, org_a_admin_headers, default_tier="none", area_tiers={"incidents": "read"})
    _, h = await _holder(client, db_session, org_id, org_a_admin_headers, role["id"])
    for path in ("/api/v1/alerts", "/api/v1/siem/rules", "/api/v1/settings"):
        r = await client.get(path, headers=h)
        assert r.status_code == 403, path
        assert r.json()["detail"]["error"] == "area_denied", path
    assert (await client.get("/api/v1/incidents", headers=h)).status_code == 200
    assert (await client.get("/api/v1/health", headers=h)).status_code in (200, 503)


@pytest.mark.asyncio
async def test_admin_tier_passes_admin_gates_including_get_current_superuser(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = await _create_role(
        client, org_a_admin_headers, default_tier="read", area_tiers={"audit": "admin", "siem": "admin"},
    )
    _, h = await _holder(client, db_session, org_id, org_a_admin_headers, role["id"])
    # audit uses get_current_superuser (tenant admins pass) -> tier admin required.
    assert (await client.get("/api/v1/audit", headers=h)).status_code == 200
    # siem rules creation is require_role([ADMIN]); the body is incomplete so
    # anything but 403 proves the gate let the request through.
    assert (await client.post("/api/v1/siem/rules", json={}, headers=h)).status_code != 403
    # Without admin over audit the same holder is refused.
    role2 = await _create_role(client, org_a_admin_headers, default_tier="write")
    _, h2 = await _holder(client, db_session, org_id, org_a_admin_headers, role2["id"], label="holder2")
    r = await client.get("/api/v1/audit", headers=h2)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "insufficient_tier"


@pytest.mark.asyncio
async def test_role_update_takes_effect_on_next_request(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = await _create_role(client, org_a_admin_headers, name="flip", default_tier="read")
    _, h = await _holder(client, db_session, org_id, org_a_admin_headers, role["id"])
    assert (await client.get("/api/v1/alerts", headers=h)).status_code == 200
    r = await client.put(
        f"/api/v1/roles/{role['id']}",
        json={"name": "flip", "default_tier": "read", "area_tiers": {"alerts": "none"}},
        headers=org_a_admin_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["member_count"] == 1
    assert (await client.get("/api/v1/alerts", headers=h)).status_code == 403


@pytest.mark.parametrize(
    ("headers_fixture", "method", "path", "body", "expected", "detail"),
    [
        ("viewer_headers", "post", "/api/v1/alerts", {"title": "t", "source": "manual"}, 403,
         "Access denied. Required roles: ['admin', 'analyst']"),
        ("org_a_headers", "post", "/api/v1/siem/rules", {}, 403, "Access denied. Required roles: ['admin']"),
        ("org_a_headers", "get", "/api/v1/alerts", None, 200, None),
        ("viewer_headers", "get", "/api/v1/siem/rules", None, 200, None),
        ("org_a_headers", "get", "/api/v1/audit", None, 403, "Superuser access required"),
        ("org_a_admin_headers", "get", "/api/v1/audit", None, 200, None),
    ],
)
@pytest.mark.asyncio
async def test_builtin_users_unchanged(
    client, viewer_headers, org_a_headers, org_a_admin_headers, headers_fixture, method, path, body, expected, detail,
) -> None:
    headers = {
        "viewer_headers": viewer_headers, "org_a_headers": org_a_headers, "org_a_admin_headers": org_a_admin_headers,
    }[headers_fixture]
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    r = await getattr(client, method)(path, **kwargs)
    assert r.status_code == expected, r.text
    if detail is not None:
        assert r.json()["detail"] == detail


@pytest.mark.asyncio
async def test_role_crud_audited_and_validated(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = await _create_role(client, org_a_admin_headers, name="Tier 1", default_tier="read",
                              area_tiers={"alerts": "write"}, description="triage")
    rid = role["id"]
    assert role["organization_id"] == org_id and role["member_count"] == 0

    # Validation.
    r = await client.post("/api/v1/roles", json={"name": "tier 1"}, headers=org_a_admin_headers)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "role_name_taken"
    r = await client.post("/api/v1/roles", json={"name": "Admin"}, headers=org_a_admin_headers)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "reserved_role_name"
    r = await client.post("/api/v1/roles", json={"name": "x", "area_tiers": {"nope": "read"}}, headers=org_a_admin_headers)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "unknown_area"
    assert r.json()["detail"]["areas"] == ["nope"]
    r = await client.post("/api/v1/roles", json={"name": "x", "default_tier": "root"}, headers=org_a_admin_headers)
    assert r.status_code == 422  # tiers beyond admin do not exist

    r = await client.get(f"/api/v1/roles/{rid}", headers=org_a_admin_headers)
    assert r.status_code == 200 and r.json()["area_tiers"] == {"alerts": "write"}
    r = await client.put(f"/api/v1/roles/{rid}", json={"name": "Tier 1", "default_tier": "none"},
                         headers=org_a_admin_headers)
    assert r.status_code == 200 and r.json()["default_tier"] == "none" and r.json()["area_tiers"] == {}

    listing = (await client.get("/api/v1/roles", headers=org_a_admin_headers)).json()
    assert [b["name"] for b in listing["builtin"]] == ["viewer", "analyst", "admin"]
    assert [c["id"] for c in listing["custom"]] == [rid]

    assert (await client.delete(f"/api/v1/roles/{rid}", headers=org_a_admin_headers)).status_code == 204
    assert (await client.get(f"/api/v1/roles/{rid}", headers=org_a_admin_headers)).status_code == 404

    actions = (await db_session.execute(
        select(AuditLog.action).where(AuditLog.resource_id == rid, AuditLog.organization_id == org_id)
    )).scalars().all()
    assert sorted(actions) == ["role_created", "role_deleted", "role_updated"]


@pytest.mark.asyncio
async def test_delete_in_use_is_409_with_holder_count(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = await _create_role(client, org_a_admin_headers)
    rid = role["id"]
    user, _ = await _holder(client, db_session, org_id, org_a_admin_headers, rid)
    user_id = user.id
    r = await client.delete(f"/api/v1/roles/{rid}", headers=org_a_admin_headers)
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "role_in_use" and r.json()["detail"]["members"] == 1

    members = (await client.get(f"/api/v1/roles/{rid}/members", headers=org_a_admin_headers)).json()
    assert members["total"] == 1 and members["items"][0]["id"] == user_id

    r = await client.patch(f"/api/v1/users/{user_id}", json={"custom_role_id": None, "role": "analyst"},
                           headers=org_a_admin_headers)
    assert r.status_code == 200 and r.json()["custom_role_id"] is None and r.json()["role"] == "analyst"
    assert (await client.delete(f"/api/v1/roles/{rid}", headers=org_a_admin_headers)).status_code == 204

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.resource_id == user_id, AuditLog.action == "user_custom_role_changed")
        .order_by(AuditLog.created_at)
    )).scalars().all()
    assert [json.loads(a.new_value)["custom_role_id"] for a in rows] == [rid, None]


@pytest.mark.asyncio
async def test_create_user_with_custom_role_and_floor_kept_on_patch(client, org_a, org_a_admin_headers) -> None:
    role = await _create_role(client, org_a_admin_headers, default_tier="write")
    r = await client.post(
        "/api/v1/users",
        json={"email": f"new-{uuid.uuid4().hex[:6]}@pysoar-tests.io", "password": "longpassword1",
              "role": "admin", "custom_role_id": role["id"]},
        headers=org_a_admin_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["custom_role_id"] == role["id"] and body["role"] == "viewer"
    assert body["identity_source"] == "local"
    # The admin UI posts the whole row back with a built-in role: the floor holds.
    r = await client.patch(f"/api/v1/users/{body['id']}", json={"role": "admin", "custom_role_id": role["id"]},
                           headers=org_a_admin_headers)
    assert r.status_code == 200 and r.json()["role"] == "viewer"


@pytest.mark.asyncio
async def test_holder_cannot_escalate_or_self_assign(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    manager_role = await _create_role(
        client, org_a_admin_headers, default_tier="read", area_tiers={"roles": "admin", "users": "admin"},
    )
    broad = await _create_role(client, org_a_admin_headers, default_tier="admin")
    manager, h = await _holder(client, db_session, org_id, org_a_admin_headers, manager_role["id"], label="mgr")
    manager_id = manager.id

    # Can list roles (roles: admin) ...
    assert (await client.get("/api/v1/roles", headers=h)).status_code == 200
    # ... but not mint a role broader than itself,
    r = await client.post("/api/v1/roles", json={"name": "wide", "default_tier": "write"}, headers=h)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "tier_exceeds_caller"
    # nor assign one, nor hand out the built-in admin role,
    target = await make_user(db_session, role="viewer", organization_id=org_id, label="target")
    target_id = target.id
    r = await client.patch(f"/api/v1/users/{target_id}", json={"custom_role_id": broad["id"]}, headers=h)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "tier_exceeds_caller"
    r = await client.patch(f"/api/v1/users/{target_id}", json={"role": "admin"}, headers=h)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "tier_exceeds_caller"
    # but can manage users within its tiers (users: admin).
    r = await client.patch(f"/api/v1/users/{target_id}", json={"custom_role_id": manager_role["id"]}, headers=h)
    assert r.status_code == 200, r.text
    # Nobody changes their own custom role.
    r = await client.patch(f"/api/v1/users/{manager_id}", json={"custom_role_id": None}, headers=h)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "privileged_field"


@pytest.mark.asyncio
async def test_area_catalogue_as_served(client, org_a_admin_headers) -> None:
    r = await client.get("/api/v1/roles/areas", headers=org_a_admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["tiers"] == ["none", "read", "write", "admin"]
    by_area = {a["area"]: a for a in body["areas"]}
    for area in ("alerts", "incidents", "playbooks", "siem", "settings", "roles", "users"):
        assert area in by_area, area
        assert not by_area[area]["exempt"]
    assert by_area["siem"]["label"] == "SIEM"
    assert by_area["siem"]["admin_routes"] > 0 and by_area["siem"]["write_routes"] > 0
    assert by_area["roles"]["admin_routes"] == by_area["roles"]["routes"]
    assert by_area["auth"]["exempt"] and by_area["auth"]["exempt_reason"]
    assert by_area["alerts"]["builtin_tiers"] == {"viewer": "read", "analyst": "write", "admin": "admin"}
    assert "docs" not in by_area and "" not in by_area


@pytest.mark.asyncio
async def test_role_of_deleted_or_foreign_org_denies(client, db_session, org_a, org_b) -> None:
    """A user whose custom_role_id points at another organisation's role (only
    possible by direct database writes) is denied everywhere, not let through."""
    org_a_id, org_b_id = org_a.id, org_b.id
    foreign = Role(organization_id=org_b_id, name="foreign", default_tier="admin", area_tiers={})
    db_session.add(foreign)
    await db_session.commit()
    foreign_id = foreign.id
    user = await make_user(db_session, role="admin", organization_id=org_a_id, label="odd")
    user.custom_role_id = foreign_id
    await db_session.commit()
    h = bearer(user)
    r = await client.get("/api/v1/alerts", headers=h)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "area_denied"
