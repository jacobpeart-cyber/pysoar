"""An administrator-set password follows the policy, is temporary, and is
refused for accounts the identity provider manages (as are their emails)."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.helpers.tenancy import bearer, make_user

pytestmark = pytest.mark.asyncio

USERS = "/api/v1/users"
LOGIN = "/api/v1/auth/login"
STRONG = "T3mp-Str0ng-Passw0rd!2026"


async def test_admin_set_password_is_policy_checked_temporary_and_revokes_sessions(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, redis_mock: AsyncMock,
) -> None:
    from tests.unit.test_token_revocation import _stateful

    _stateful(redis_mock)
    analyst = await make_user(db_session, role="analyst", organization_id=org_a.id, label="pw-target")
    await db_session.commit()
    target_id, email = analyst.id, analyst.email
    old_headers = bearer(analyst)
    assert (await client.get("/api/v1/auth/me", headers=old_headers)).status_code == 200

    weak = await client.patch(f"{USERS}/{target_id}", json={"password": "short1"}, headers=org_a_admin_headers)
    assert weak.status_code in (400, 422), weak.text  # 8-char schema floor or the policy
    if weak.status_code == 400:
        assert weak.json()["detail"]["error"] == "password_policy"

    ok = await client.patch(f"{USERS}/{target_id}", json={"password": STRONG}, headers=org_a_admin_headers)
    assert ok.status_code == 200, ok.text

    # The user's existing sessions are gone, and the next sign-in demands a new password.
    assert (await client.get("/api/v1/auth/me", headers=old_headers)).status_code == 401
    login = await client.post(LOGIN, json={"email": email, "password": STRONG})
    assert login.status_code == 403 and login.headers.get("X-Password-Change-Required") == "true", login.text


async def test_provider_managed_accounts_refuse_password_and_email_changes(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers,
) -> None:
    sso_user = await make_user(db_session, role="viewer", organization_id=org_a.id, label="oidc-user")
    sso_user.identity_source = "oidc"
    await db_session.commit()
    sso_id = sso_user.id

    for body in ({"password": STRONG}, {"email": "renamed@renamed-corp.com"}):
        resp = await client.patch(f"{USERS}/{sso_id}", json=body, headers=org_a_admin_headers)
        assert resp.status_code == 409, (body, resp.text)
        assert resp.json()["detail"]["error"] == "sso_managed"
    # Profile fields are still editable by the administrator.
    ok = await client.patch(f"{USERS}/{sso_id}", json={"department": "SOC"}, headers=org_a_admin_headers)
    assert ok.status_code == 200, ok.text
