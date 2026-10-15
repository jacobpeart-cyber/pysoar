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

    async def _incr(key: str):
        store[key] = str(int(store.get(key, 0)) + 1)
        return int(store[key])

    redis_mock.get = AsyncMock(side_effect=_get)
    redis_mock.incr = AsyncMock(side_effect=_incr)
    redis_mock.set = AsyncMock(side_effect=_set)
    redis_mock.setex = AsyncMock(side_effect=_setex)
    redis_mock.exists = AsyncMock(side_effect=_exists)
    return store


async def test_blacklist_writes_the_keys_the_dependency_reads(redis_mock: AsyncMock) -> None:
    store = _stateful(redis_mock)
    bl = TokenBlacklist(redis_mock)
    assert await bl.revoke_all_user_tokens("u1") is True
    assert "revoke:u1" in store and int(store["revoke:u1"]) <= int(time.time())
    # The generation counter is the revocation primitive the dependency checks.
    assert await bl.current_generation("u1") == 1
    assert await bl.revoke_all_user_tokens("u1") is True
    assert await bl.current_generation("u1") == 2
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

    # No clock involved: the revocation bumps the generation, so a token issued
    # in the very same second is dead too.
    revoked = await client.post(route, headers=headers)
    assert revoked.status_code == 200, revoked.text
    after = await client.get(ME, headers=headers)
    assert after.status_code == 401, after.text
    assert "revoked" in after.json()["detail"].lower()


async def test_refresh_token_dies_with_the_revocation(
    client: AsyncClient, redis_mock: AsyncMock, test_user,
) -> None:
    _stateful(redis_mock)
    email = test_user.email
    login = await client.post(LOGIN, json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    refresh = login.json()["refresh_token"]
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})).status_code == 200
    assert (await client.post("/api/v1/auth/revoke-all", headers=headers)).status_code == 200
    dead = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert dead.status_code == 401, dead.text
    # A fresh login after the revocation works and its tokens carry the new generation.
    again = await client.post(LOGIN, json={"email": email, "password": PASSWORD})
    assert again.status_code == 200, again.text
    assert (await client.get(ME, headers={"Authorization": f"Bearer {again.json()['access_token']}"})).status_code == 200
