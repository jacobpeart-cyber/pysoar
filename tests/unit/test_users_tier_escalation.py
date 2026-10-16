"""An administrator may not change or delete an account that outranks them.

A custom-role holder with admin tier over ``users`` could otherwise reset a
built-in administrator's password or deactivate them (security review of
6a500ba). Built-in admins and superusers are unaffected.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.identity.models import Role
from src.identity.roles import apply_custom_role
from tests.helpers.tenancy import bearer, make_user

pytestmark = pytest.mark.asyncio

USERS = "/api/v1/users"


async def _users_admin_holder(db: AsyncSession, org_id: str):
    """A user whose custom role grants admin over ``users`` and read elsewhere."""
    role = Role(organization_id=org_id, name="User manager", default_tier="read", area_tiers={"users": "admin"})
    db.add(role)
    await db.flush()
    holder = await make_user(db, role="viewer", organization_id=org_id, label="user-manager")
    apply_custom_role(holder, role)
    await db.commit()
    return holder


async def test_custom_role_user_manager_cannot_touch_a_builtin_admin(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin, org_a_viewer,
) -> None:
    org_id, admin_id, viewer_id = org_a.id, org_a_admin.id, org_a_viewer.id
    holder = await _users_admin_holder(db_session, org_id)
    headers = bearer(holder)

    # The built-in admin outranks the holder outside ``users``: refused on every change.
    for body in ({"is_active": False}, {"password": "N3w-Str0ng-Passw0rd!2026"}, {"role": "viewer"}, {"full_name": "x"}):
        resp = await client.patch(f"{USERS}/{admin_id}", json=body, headers=headers)
        assert resp.status_code == 403, (body, resp.text)
        assert resp.json()["detail"]["error"] == "tier_exceeds_caller"
        assert "alerts" in resp.json()["detail"]["areas"]
    gone = await client.delete(f"{USERS}/{admin_id}", headers=headers)
    assert gone.status_code == 403 and gone.json()["detail"]["error"] == "tier_exceeds_caller"

    # A viewer holds no more than the holder anywhere: manageable.
    ok = await client.patch(f"{USERS}/{viewer_id}", json={"full_name": "Renamed viewer"}, headers=headers)
    assert ok.status_code == 200, ok.text
    assert ok.json()["full_name"] == "Renamed viewer"


async def test_builtin_admin_and_superuser_are_unaffected(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, superuser_headers,
) -> None:
    org_id = org_a.id
    other_admin = await make_user(db_session, role="admin", organization_id=org_id, label="second-admin")
    await db_session.commit()
    other_id = other_admin.id

    renamed = await client.patch(f"{USERS}/{other_id}", json={"full_name": "Second admin"}, headers=org_a_admin_headers)
    assert renamed.status_code == 200, renamed.text
    by_superuser = await client.patch(
        f"{USERS}/{other_id}", json={"department": "SOC"}, params={"organization_id": org_id}, headers=superuser_headers,
    )
    assert by_superuser.status_code == 200, by_superuser.text
    deleted = await client.delete(f"{USERS}/{other_id}", headers=org_a_admin_headers)
    assert deleted.status_code == 204, deleted.text
