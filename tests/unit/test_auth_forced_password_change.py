"""Forced password change: login issues a limited token that can only change
the password, and the change clears the flag."""
from __future__ import annotations

from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import create_access_token

pytestmark = pytest.mark.asyncio

LOGIN = "/api/v1/auth/login"
CHANGE = "/api/v1/auth/change-password"
ME = "/api/v1/auth/me"
OLD = "testpassword123"
NEW = "N3w-Str0ng-Passw0rd!2026"


async def test_limited_token_changes_the_password_and_nothing_else(
    client: AsyncClient, db_session: AsyncSession, test_user,
) -> None:
    email, user_id = test_user.email, test_user.id
    test_user.force_password_change = True
    await db_session.commit()

    refused = await client.post(LOGIN, json={"email": email, "password": OLD})
    assert refused.status_code == 403, refused.text
    assert refused.headers.get("X-Password-Change-Required") == "true"
    limited = refused.headers.get("X-Limited-Token")
    assert limited
    headers = {"Authorization": f"Bearer {limited}"}

    # The limited token is not an access token: every ordinary route refuses it.
    assert (await client.get(ME, headers=headers)).status_code == 401

    # ... except the password change, which still needs the current password.
    wrong = await client.post(CHANGE, json={"current_password": "not-it", "new_password": NEW}, headers=headers)
    assert wrong.status_code in (400, 401, 403), wrong.text
    # A new password that breaks the policy comes back with the broken rules listed.
    weak = await client.post(CHANGE, json={"current_password": OLD, "new_password": "short"}, headers=headers)
    assert weak.status_code == 400, weak.text
    assert weak.json()["detail"]["error"] == "password_policy" and weak.json()["detail"]["errors"]
    changed = await client.post(CHANGE, json={"current_password": OLD, "new_password": NEW}, headers=headers)
    assert changed.status_code == 200, changed.text

    # The flag is cleared: login works with the new password and the old one is gone.
    ok = await client.post(LOGIN, json={"email": email, "password": NEW})
    assert ok.status_code == 200, ok.text
    assert "access_token" in ok.json()
    assert (await client.post(LOGIN, json={"email": email, "password": OLD})).status_code == 401

    # A limited token minted for another scope is refused even on the change route.
    other = create_access_token(
        subject=user_id, expires_delta=timedelta(minutes=5),
        extra_claims={"type": "limited", "scope": "something_else"},
    )
    refused_scope = await client.post(
        CHANGE, json={"current_password": NEW, "new_password": OLD + "x"},
        headers={"Authorization": f"Bearer {other}"},
    )
    assert refused_scope.status_code == 401, refused_scope.text
