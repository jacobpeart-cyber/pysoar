"""Wave 1 tenancy and RBAC for ``/users`` (users.py).

* list/create/update-other/delete: tenant ``admin`` only, confined to the
  caller's organisation; another tenant's user is 404;
* a tenant admin can neither grant ``is_superuser`` nor manage a platform
  superuser account; ``role`` is validated;
* self-service (``GET``/``PATCH /users/{me}``) stays open to every role, but
  cannot change role or active status (403 ``privileged_field``; unchanged
  values are tolerated), password or email;
* an org-less platform superuser gets 403 ``organization_required`` unless it
  names the tenant on ``PATCH /users/{id}?organization_id=...``.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.organization import Organization
from src.models.user import User
from tests.helpers.tenancy import assert_tenant_isolated, make_user

BASE = "/api/v1/users"


async def test_list_is_admin_only_and_tenant_scoped(
    client: AsyncClient,
    org_a_user: User,
    org_b_user: User,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    a_id, b_id = org_a_user.id, org_b_user.id
    resp = await client.get(BASE, headers=org_a_admin_headers, params={"size": 100})
    assert resp.status_code == 200, resp.text
    ids = {u["id"] for u in resp.json()["items"]}
    assert a_id in ids
    assert b_id not in ids

    for headers in (org_a_headers, viewer_headers):
        assert (await client.get(BASE, headers=headers)).status_code == 403


async def test_create_lands_in_callers_org_and_never_superuser(
    client: AsyncClient,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    a_id, b_id = org_a.id, org_b.id
    body = {
        "email": "new-hire@pysoar-tests.io",
        "password": "longenough123",
        "role": "analyst",
        # Neither field is honoured: the org is the caller's and is_superuser
        # is not part of the schema.
        "organization_id": b_id,
        "is_superuser": True,
    }
    for headers in (org_a_headers, viewer_headers):
        assert (await client.post(BASE, headers=headers, json=body)).status_code == 403

    resp = await client.post(BASE, headers=org_a_admin_headers, json=body)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["organization_id"] == a_id
    assert data["is_superuser"] is False

    bad = await client.post(
        BASE, headers=org_a_admin_headers,
        json={"email": "odd-role@pysoar-tests.io", "password": "longenough123", "role": "root"},
    )
    assert bad.status_code == 422, bad.text


async def test_admin_cannot_touch_other_tenant_users(
    client: AsyncClient,
    org_b_user: User,
    org_a_admin_headers: dict[str, str],
) -> None:
    b_id = org_b_user.id
    await assert_tenant_isolated(client, "GET", f"{BASE}/{b_id}", org_a_admin_headers)
    await assert_tenant_isolated(
        client, "PATCH", f"{BASE}/{b_id}", org_a_admin_headers, json={"role": "viewer"},
    )
    await assert_tenant_isolated(
        client, "PATCH", f"{BASE}/{b_id}", org_a_admin_headers, json={"password": "takeover-123"},
    )
    await assert_tenant_isolated(client, "DELETE", f"{BASE}/{b_id}", org_a_admin_headers)


async def test_admin_manages_own_org_users(
    client: AsyncClient,
    org_a_user: User,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
) -> None:
    target = org_a_user.id
    resp = await client.patch(f"{BASE}/{target}", headers=org_a_admin_headers, json={"role": "viewer"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "viewer"

    resp = await client.patch(f"{BASE}/{target}", headers=org_a_admin_headers, json={"role": "superuser"})
    assert resp.status_code == 422, resp.text

    resp = await client.patch(
        f"{BASE}/{target}", headers=org_a_admin_headers, json={"role": "admin", "is_superuser": True},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_superuser"] is False

    resp = await client.delete(f"{BASE}/{target}", headers=org_a_admin_headers)
    assert resp.status_code == 204, resp.text


async def test_analyst_cannot_modify_or_delete_colleagues(
    client: AsyncClient,
    org_a_admin: User,
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    admin_id = org_a_admin.id
    for headers in (org_a_headers, viewer_headers):
        assert (await client.get(f"{BASE}/{admin_id}", headers=headers)).status_code == 403
        resp = await client.patch(f"{BASE}/{admin_id}", headers=headers, json={"role": "viewer"})
        assert resp.status_code == 403, resp.text
        assert (await client.delete(f"{BASE}/{admin_id}", headers=headers)).status_code == 403


async def test_tenant_admin_cannot_manage_superuser_in_same_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    su = await make_user(db_session, role="admin", organization_id=org_a.id, is_superuser=True, label="su-in-a")
    su_id = su.id
    for method, json in (("GET", None), ("PATCH", {"password": "takeover-123"}), ("DELETE", None)):
        resp = await client.request(method, f"{BASE}/{su_id}", headers=org_a_admin_headers, json=json)
        assert resp.status_code == 404, (method, resp.text)


async def test_self_service_profile(
    client: AsyncClient,
    org_a_viewer: User,
    viewer_headers: dict[str, str],
) -> None:
    me, my_email = org_a_viewer.id, org_a_viewer.email
    assert (await client.get(f"{BASE}/{me}", headers=viewer_headers)).status_code == 200

    # Unchanged privileged values (the admin UI posts the whole row) are fine.
    resp = await client.patch(
        f"{BASE}/{me}", headers=viewer_headers,
        json={"full_name": "Renamed Viewer", "email": my_email, "role": "viewer", "is_active": True},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["full_name"] == "Renamed Viewer"
    assert resp.json()["role"] == "viewer"

    # Changing them on your own account is refused, not silently dropped.
    for body in ({"role": "admin"}, {"is_active": False}, {"full_name": "x", "role": "analyst"}):
        resp = await client.patch(f"{BASE}/{me}", headers=viewer_headers, json=body)
        assert resp.status_code == 403, (body, resp.text)
        assert resp.json()["detail"]["error"] == "privileged_field"

    resp = await client.patch(f"{BASE}/{me}", headers=viewer_headers, json={"password": "bypass-check-1"})
    assert resp.status_code == 400, resp.text
    resp = await client.patch(f"{BASE}/{me}", headers=viewer_headers, json={"email": "other@pysoar-tests.io"})
    assert resp.status_code == 400, resp.text


async def test_orgless_superuser_refused_on_tenant_scoped_routes(
    client: AsyncClient,
    platform_superuser: User,
    org_a_user: User,
    superuser_headers: dict[str, str],
) -> None:
    target, su_id = org_a_user.id, platform_superuser.id
    for method, path, json in (
        ("GET", BASE, None),
        ("POST", BASE, {"email": "x@pysoar-tests.io", "password": "longenough123"}),
        ("GET", f"{BASE}/{target}", None),
        ("PATCH", f"{BASE}/{target}", {"role": "viewer"}),
        ("DELETE", f"{BASE}/{target}", None),
    ):
        resp = await client.request(method, path, headers=superuser_headers, json=json)
        assert resp.status_code == 403, (method, path, resp.text)
        assert resp.json()["detail"]["error"] == "organization_required"

    # Self-service still works for the org-less superuser.
    assert (await client.get(f"{BASE}/{su_id}", headers=superuser_headers)).status_code == 200


async def test_admin_cannot_change_own_role_or_deactivate_self(
    client: AsyncClient, org_a_admin: User, org_a_admin_headers: dict[str, str],
) -> None:
    me = org_a_admin.id
    for body in ({"role": "viewer"}, {"is_active": False}):
        resp = await client.patch(f"{BASE}/{me}", headers=org_a_admin_headers, json=body)
        assert resp.status_code == 403, (body, resp.text)
        assert resp.json()["detail"]["error"] == "privileged_field"


async def test_platform_superuser_edits_a_tenant_user_with_explicit_scope(
    client: AsyncClient,
    org_a: Organization,
    org_b: Organization,
    org_a_user: User,
    superuser_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
) -> None:
    a_id, b_id, target = org_a.id, org_b.id, org_a_user.id

    resp = await client.patch(
        f"{BASE}/{target}", headers=superuser_headers, json={"role": "viewer"}, params={"organization_id": a_id},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "viewer"

    # Naming the wrong tenant does not reach the user.
    resp = await client.patch(
        f"{BASE}/{target}", headers=superuser_headers, json={"role": "admin"}, params={"organization_id": b_id},
    )
    assert resp.status_code == 404, resp.text

    # A tenant admin cannot use the explicit scope to reach another tenant.
    resp = await client.patch(
        f"{BASE}/{target}", headers=org_a_admin_headers, json={"role": "analyst"}, params={"organization_id": b_id},
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_mismatch"
