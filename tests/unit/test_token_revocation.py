"""Token revocation is real: logout and revoke-all write the key the auth
dependency checks, so the tokens stop working on the next request."""
from __future__ import annotations

import time

import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock

from src.core.token_blacklist import TokenBlacklist

pytestmark = pytest.mark.asyncio

LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"
PASSWORD = "testpassword123"


def _stateful(redis_mock: AsyncMock) -> dict[str, str]:
    """Give the Redis mock a real key/value store for get, set, setex, exists."""
    store: dict[str, str] = {}

    async def _get(key: str):
        return store.get(key)

    async def _set(key: str, value, *args, **kwargs):
        store[key] = str(value)
        return True

    async def _setex(key: str, ttl: int, value):
        store[key] = str(value)
        return True

    async def _exists(key: str):
        return 1 if key in store else 0

    redis_mock.get = AsyncMock(side_effect=_get)
    redis_mock.set = AsyncMock(side_effect=_set)
    redis_mock.setex = AsyncMock(side_effect=_setex)
    redis_mock.exists = AsyncMock(side_effect=_exists)
    return store


async def test_blacklist_writes_the_keys_the_dependency_reads(redis_mock: AsyncMock) -> None:
    store = _stateful(redis_mock)
    bl = TokenBlacklist(redis_mock)
    assert await bl.revoke_all_user_tokens("u1") is True
    assert "revoke:u1" in store and int(store["revoke:u1"]) <= int(time.time())
    assert await bl.revoke_token("jti-1", expires_in=300) is True
    assert store.get("blacklist:jti-1") == "revoked"
    assert await bl.is_revoked("jti-1") is True
    assert await bl.is_user_revoked("u1", token_iat=int(time.time()) - 60) is True
    assert await bl.is_user_revoked("u1", token_iat=int(time.time()) + 60) is False


@pytest.mark.parametrize("route", ["/api/v1/auth/revoke-all", "/api/v1/auth/logout"])
async def test_revocation_kills_the_token_on_the_next_request(
    client: AsyncClient, redis_mock: AsyncMock, test_user, route: str,
) -> None:
    _stateful(redis_mock)
    email = test_user.email
    login = await client.post(LOGIN, json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.get(ME, headers=headers)).status_code == 200

    # The token's iat is this second; make the revocation land strictly after it.
    time.sleep(1.1)
    revoked = await client.post(route, headers=headers)
    assert revoked.status_code == 200, revoked.text
    after = await client.get(ME, headers=headers)
    assert after.status_code == 401, after.text
    assert "revoked" in after.json()["detail"].lower()
