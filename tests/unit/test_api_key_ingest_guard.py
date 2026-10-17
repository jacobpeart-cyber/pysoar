"""The SIEM ingest API key is only as good as its owner: an empty permission
list grants nothing, and a key whose owner is inactive or no longer holds
write on siem is refused. Agentic policy treats custom-role holders as
protected targets."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.policy import _user_is_admin
from tests.helpers.tenancy import bearer, make_user

pytestmark = pytest.mark.asyncio

KEYS = "/api/v1/api-keys"
INGEST = "/api/v1/siem/logs/ingest/bulk"
LINE = '{"message": "guard test", "source": "unit", "severity": "info"}\n'


async def _mint(client: AsyncClient, headers: dict[str, str], permissions: list[str]) -> str:
    resp = await client.post(KEYS, json={"name": "ingest", "permissions": permissions}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["api_key"]


async def _ingest(client: AsyncClient, key: str) -> int:
    resp = await client.post(
        INGEST, content=LINE, headers={"X-API-Key": key, "Content-Type": "application/x-ndjson"},
    )
    return resp.status_code


async def test_key_permissions_and_owner_state_are_enforced(
    client: AsyncClient, db_session: AsyncSession, org_a,
) -> None:
    analyst = await make_user(db_session, role="analyst", organization_id=org_a.id, label="ingest-owner")
    await db_session.commit()
    owner_id = analyst.id
    headers = bearer(analyst)

    # An empty permission list used to mean full access; now it grants nothing.
    empty = await _mint(client, headers, [])
    assert await _ingest(client, empty) == 401

    good = await _mint(client, headers, ["siem:write"])
    assert await _ingest(client, good) == 202

    # The owner loses write on siem: the key stops working.
    from sqlalchemy import select

    from src.models.user import User

    owner = (await db_session.execute(select(User).where(User.id == owner_id))).scalar_one()
    owner.role = "viewer"
    await db_session.commit()
    assert await _ingest(client, good) == 401

    # A deactivated owner's key stops working too.
    owner.role = "analyst"
    owner.is_active = False
    await db_session.commit()
    assert await _ingest(client, good) == 401


def test_custom_role_holders_are_protected_targets() -> None:
    assert _user_is_admin(SimpleNamespace(role="admin", custom_role_id=None)) is True
    assert _user_is_admin(SimpleNamespace(role="viewer", custom_role_id=None)) is False
    # The holder's tiers are not loaded in the policy engine, so any custom role is protected.
    assert _user_is_admin(SimpleNamespace(role="viewer", custom_role_id="r1")) is True
