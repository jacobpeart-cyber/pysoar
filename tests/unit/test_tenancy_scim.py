"""Tenancy for SCIM: a token sees only its organisation; token and group
administration is confined to the caller's organisation."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from src.identity.scim import SCHEMA_GROUP, SCHEMA_PATCH, SCHEMA_USER
from src.models.user import User
from tests.helpers.tenancy import assert_tenant_isolated, bearer, make_user

BASE = "/api/v1/scim/v2"


async def _token(client, headers) -> str:
    r = await client.post("/api/v1/settings/scim/tokens", json={"name": "idp"}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["token"]


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_a_token_only_sees_its_organisation(client, db_session, org_a, org_b, org_a_admin_headers) -> None:
    org_b_id = org_b.id
    admin_b = await make_user(db_session, role="admin", organization_id=org_b_id, label="admin-b")
    user_b = await make_user(db_session, role="analyst", organization_id=org_b_id, label="user-b")
    user_b_id, user_b_email, user_b_role = user_b.id, user_b.email, user_b.role
    token_a = await _token(client, org_a_admin_headers)
    token_b = await _token(client, bearer(admin_b))

    # Org B's token provisions a group with org B's user.
    r = await client.post(f"{BASE}/Groups", json={"schemas": [SCHEMA_GROUP], "displayName": "B team",
                                                   "members": [{"value": user_b_id}]}, headers=_h(token_b))
    assert r.status_code == 201
    group_b = r.json()["id"]

    listing = (await client.get(f"{BASE}/Users", headers=_h(token_a))).json()
    assert user_b_id not in [u["id"] for u in listing["Resources"]]
    found = (await client.get(f"{BASE}/Users", params={"filter": f'userName eq "{user_b_email}"'},
                              headers=_h(token_a))).json()
    assert found["totalResults"] == 0
    assert (await client.get(f"{BASE}/Groups", headers=_h(token_a))).json()["totalResults"] == 0

    patch = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "value": {"active": False}}]}
    for method, path, body in (
        ("get", f"{BASE}/Users/{user_b_id}", None),
        ("put", f"{BASE}/Users/{user_b_id}", {"schemas": [SCHEMA_USER], "userName": "taken@over.io"}),
        ("patch", f"{BASE}/Users/{user_b_id}", patch),
        ("delete", f"{BASE}/Users/{user_b_id}", None),
        ("get", f"{BASE}/Groups/{group_b}", None),
        ("put", f"{BASE}/Groups/{group_b}", {"displayName": "stolen", "members": []}),
        ("patch", f"{BASE}/Groups/{group_b}", {"schemas": [SCHEMA_PATCH], "Operations": [
            {"op": "remove", "path": "members"}]}),
        ("delete", f"{BASE}/Groups/{group_b}", None),
    ):
        r = await assert_tenant_isolated(client, method, path, _h(token_a), json=body)
        assert r.status_code == 404, (method, path)

    # Org A's token cannot put org B's user into one of its own groups.
    r = await client.post(f"{BASE}/Groups", json={"displayName": "A team", "members": [{"value": user_b_id}]},
                          headers=_h(token_a))
    assert r.status_code == 400

    db_session.expire_all()
    user = (await db_session.execute(select(User).where(User.id == user_b_id))).scalar_one()
    assert user.is_active is True and user.email == user_b_email and user.role == user_b_role
    assert (await client.get(f"{BASE}/Groups/{group_b}", headers=_h(token_b))).json()["members"][0]["value"] == user_b_id


async def test_superuser_is_never_visible_or_editable(client, db_session, org_a, org_a_admin_headers) -> None:
    su = await make_user(db_session, role="admin", organization_id=org_a.id, is_superuser=True, label="su")
    su_id, su_email = su.id, su.email
    token = await _token(client, org_a_admin_headers)
    assert su_id not in [u["id"] for u in (await client.get(f"{BASE}/Users", headers=_h(token))).json()["Resources"]]
    for method in ("get", "put", "patch", "delete"):
        body = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]}
        r = await client.request(method.upper(), f"{BASE}/Users/{su_id}", headers=_h(token),
                                 json=body if method in ("put", "patch") else None)
        assert r.status_code == 404
    r = await client.post(f"{BASE}/Groups", json={"displayName": "Admins", "members": [{"value": su_id}]},
                          headers=_h(token))
    assert r.status_code == 400
    r = await client.post(f"{BASE}/Users", json={"userName": su_email}, headers=_h(token))
    assert r.status_code == 409
    db_session.expire_all()
    assert (await db_session.execute(select(User.is_active).where(User.id == su_id))).scalar_one() is True


async def test_token_and_group_admin_is_org_scoped(client, db_session, org_a, org_b, org_a_admin_headers) -> None:
    r = await client.post("/api/v1/settings/scim/tokens", json={"name": "a"}, headers=org_a_admin_headers)
    token_id = r.json()["id"]
    token = r.json()["token"]
    group = (await client.post(f"{BASE}/Groups", json={"displayName": "A only"}, headers=_h(token))).json()
    admin_b = await make_user(db_session, role="admin", organization_id=org_b.id, label="admin-b")
    hb = bearer(admin_b)

    assert (await client.get("/api/v1/settings/scim/tokens", headers=hb)).json()["items"] == []
    r = await assert_tenant_isolated(client, "delete", f"/api/v1/settings/scim/tokens/{token_id}", hb)
    assert r.json()["detail"]["error"] == "scim_token_not_found"
    assert (await client.get(f"{BASE}/Users", headers=_h(token))).status_code == 200  # still valid

    assert (await client.get("/api/v1/settings/scim/groups", headers=hb)).json()["items"] == []
    r = await assert_tenant_isolated(client, "put", f"/api/v1/settings/scim/groups/{group['id']}", hb,
                                     json={"role": "admin"})
    assert r.json()["detail"]["error"] == "scim_group_not_found"
    r = await client.put(f"/api/v1/settings/scim/groups/{uuid.uuid4()}", json={"role": "admin"},
                         headers=org_a_admin_headers)
    assert r.status_code == 404


async def test_custom_role_of_another_org_cannot_be_mapped(client, db_session, org_a, org_b, org_a_admin_headers) -> None:
    from src.identity.models import Role

    role_b = Role(organization_id=org_b.id, name="b-role", default_tier="admin", area_tiers={})
    db_session.add(role_b)
    await db_session.commit()
    role_b_id = role_b.id
    token = await _token(client, org_a_admin_headers)
    group = (await client.post(f"{BASE}/Groups", json={"displayName": "G"}, headers=_h(token))).json()
    for value in (role_b_id, "b-role"):
        r = await client.put(f"/api/v1/settings/scim/groups/{group['id']}", json={"role": value},
                             headers=org_a_admin_headers)
        assert r.status_code == 422 and r.json()["detail"]["error"] == "unknown_role"
