"""Tenancy and role gates for /roles and custom-role assignment."""

from __future__ import annotations

import uuid

import pytest

from tests.helpers.tenancy import assert_tenant_isolated, bearer, make_user


async def _role(client, headers, **body) -> dict:
    r = await client.post(
        "/api/v1/roles", json={"name": f"r-{uuid.uuid4().hex[:6]}", "default_tier": "read", **body}, headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_roles_are_tenant_isolated(client, db_session, org_a, org_b, org_a_admin_headers) -> None:
    org_b_id = org_b.id
    role = await _role(client, org_a_admin_headers)
    rid = role["id"]
    admin_b = await make_user(db_session, role="admin", organization_id=org_b_id, label="admin-b")
    hb = bearer(admin_b)

    for method, path, body in (
        ("get", f"/api/v1/roles/{rid}", None),
        ("put", f"/api/v1/roles/{rid}", {"name": "taken-over", "default_tier": "admin"}),
        ("delete", f"/api/v1/roles/{rid}", None),
        ("get", f"/api/v1/roles/{rid}/members", None),
    ):
        r = await assert_tenant_isolated(client, method, path, hb, json=body)
        assert r.status_code == 404 and r.json()["detail"]["error"] == "role_not_found"

    listing = (await client.get("/api/v1/roles", headers=hb)).json()
    assert rid not in [c["id"] for c in listing["custom"]]
    # Same name is free in another organisation.
    r = await client.post("/api/v1/roles", json={"name": role["name"]}, headers=hb)
    assert r.status_code == 201

    # A role of org A cannot be assigned to a user of org B.
    user_b = await make_user(db_session, role="analyst", organization_id=org_b_id, label="user-b")
    user_b_id = user_b.id
    r = await client.patch(f"/api/v1/users/{user_b_id}", json={"custom_role_id": rid}, headers=hb)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "role_not_found"
    r = await client.post(
        "/api/v1/users",
        json={"email": f"b-{uuid.uuid4().hex[:6]}@pysoar-tests.io", "password": "longpassword1", "custom_role_id": rid},
        headers=hb,
    )
    assert r.status_code == 422 and r.json()["detail"]["error"] == "role_not_found"
    # And org A's admin cannot reach org B's user at all.
    r = await client.patch(f"/api/v1/users/{user_b_id}", json={"custom_role_id": rid}, headers=org_a_admin_headers)
    assert r.status_code == 404


_ROLE_ROUTES = [
    ("get", "/api/v1/roles", None),
    ("get", "/api/v1/roles/areas", None),
    ("post", "/api/v1/roles", {"name": "x"}),
    ("get", "/api/v1/roles/{id}", None),
    ("put", "/api/v1/roles/{id}", {"name": "x"}),
    ("delete", "/api/v1/roles/{id}", None),
    ("get", "/api/v1/roles/{id}/members", None),
]


@pytest.mark.asyncio
async def test_viewer_and_analyst_refused_on_every_role_route(
    client, org_a_admin_headers, viewer_headers, org_a_headers,
) -> None:
    rid = (await _role(client, org_a_admin_headers))["id"]
    for headers in (viewer_headers, org_a_headers):
        for method, path, body in _ROLE_ROUTES:
            kwargs = {"headers": headers}
            if body is not None:
                kwargs["json"] = body
            r = await getattr(client, method)(path.replace("{id}", rid), **kwargs)
            assert r.status_code == 403, (method, path, r.status_code)


@pytest.mark.asyncio
async def test_orgless_superuser_gets_organization_required(client, superuser_headers) -> None:
    fake = str(uuid.uuid4())
    for method, path, body in _ROLE_ROUTES:
        kwargs = {"headers": superuser_headers}
        if body is not None:
            kwargs["json"] = body
        r = await getattr(client, method)(path.replace("{id}", fake), **kwargs)
        assert r.status_code == 403, (method, path, r.status_code)
        assert r.json()["detail"]["error"] == "organization_required", (method, path)


@pytest.mark.asyncio
async def test_superuser_cannot_hold_a_custom_role(client, db_session, org_a, org_a_admin_headers, superuser_headers) -> None:
    org_id = org_a.id
    rid = (await _role(client, org_a_admin_headers))["id"]
    su_in_org = await make_user(db_session, role="admin", organization_id=org_id, is_superuser=True, label="su-in-org")
    su_id = su_in_org.id
    # The tenant admin cannot see the superuser account at all.
    r = await client.patch(f"/api/v1/users/{su_id}", json={"custom_role_id": rid}, headers=org_a_admin_headers)
    assert r.status_code == 404
    # The platform superuser naming the tenant is refused with the reason.
    r = await client.patch(
        f"/api/v1/users/{su_id}", params={"organization_id": org_id}, json={"custom_role_id": rid},
        headers=superuser_headers,
    )
    assert r.status_code == 422 and r.json()["detail"]["error"] == "superuser_custom_role"
