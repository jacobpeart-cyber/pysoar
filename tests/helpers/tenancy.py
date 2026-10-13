"""Two-tenant fixtures and the tenant-isolation assertion (wave 1 kit).

Imported by ``tests/conftest.py`` so every test can request these fixtures:

* ``org_a`` / ``org_b``: two organisations in the shared test database.
* ``org_a_user`` / ``org_a_headers``: analyst in org A.
* ``org_a_admin`` / ``org_a_admin_headers``: admin in org A.
* ``org_a_viewer`` / ``viewer_headers``: viewer in org A.
* ``org_b_user`` / ``org_b_headers``: analyst in org B.
* ``platform_superuser`` / ``superuser_headers``: ``is_superuser`` with NO
  organisation. Tenant-scoped routes refuse it (403 ``organization_required``)
  unless the route accepts an explicit ``organization_id``.

Emails use the ``.io`` TLD: reserved domains such as ``example.com`` fail the
profile endpoint's ``EmailStr`` validation.

Pattern for a router test::

    async def test_widget_isolated(client, db_session, org_a, org_a_headers, org_b_headers):
        resp = await client.post("/api/v1/widgets", json={...}, headers=org_a_headers)
        widget_id = resp.json()["id"]
        await assert_tenant_isolated(client, "GET", f"/api/v1/widgets/{widget_id}", org_b_headers)
        await assert_tenant_isolated(client, "DELETE", f"/api/v1/widgets/{widget_id}", org_b_headers)
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

import pytest_asyncio
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import create_access_token, get_password_hash
from src.models.organization import Organization
from src.models.user import User

#: Status codes that count as "the other tenant cannot see or touch it".
ISOLATED_STATUSES: frozenset[int] = frozenset({403, 404})


def bearer(user: User) -> dict[str, str]:
    """Authorization header for ``user``."""
    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def make_organization(db: AsyncSession, name: str) -> Organization:
    org = Organization(
        id=str(uuid.uuid4()),
        name=f"{name} {uuid.uuid4().hex[:6]}",
        slug=f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:6]}",
        is_active=True,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org


async def make_user(
    db: AsyncSession,
    *,
    role: str,
    organization_id: Optional[str],
    is_superuser: bool = False,
    label: str = "user",
) -> User:
    user = User(
        email=f"{label}-{uuid.uuid4().hex[:8]}@pysoar-tests.io",
        hashed_password=get_password_hash("testpassword123"),
        full_name=label.replace("-", " ").title(),
        role=role,
        is_active=True,
        is_superuser=is_superuser,
        organization_id=organization_id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def assert_tenant_isolated(
    client: AsyncClient,
    method: str,
    path: str,
    other_tenant_headers: dict[str, str],
    *,
    json: Any = None,
    params: Optional[dict[str, Any]] = None,
) -> Response:
    """Request an org-A resource as org B and assert it is refused (404 or 403).

    404 is preferred (it does not leak existence); 403 is accepted. Returns the
    response so callers can assert more (for example the error key).
    """
    response = await client.request(
        method.upper(), path, headers=other_tenant_headers, json=json, params=params
    )
    assert response.status_code in ISOLATED_STATUSES, (
        f"{method.upper()} {path} as the other tenant returned "
        f"{response.status_code}, expected 404/403: {response.text[:300]}"
    )
    return response


@pytest_asyncio.fixture
async def org_a(db_session: AsyncSession) -> Organization:
    return await make_organization(db_session, "Org A")


@pytest_asyncio.fixture
async def org_b(db_session: AsyncSession) -> Organization:
    return await make_organization(db_session, "Org B")


@pytest_asyncio.fixture
async def org_a_user(db_session: AsyncSession, org_a: Organization) -> User:
    return await make_user(db_session, role="analyst", organization_id=org_a.id, label="analyst-a")


@pytest_asyncio.fixture
async def org_a_admin(db_session: AsyncSession, org_a: Organization) -> User:
    return await make_user(db_session, role="admin", organization_id=org_a.id, label="admin-a")


@pytest_asyncio.fixture
async def org_a_viewer(db_session: AsyncSession, org_a: Organization) -> User:
    return await make_user(db_session, role="viewer", organization_id=org_a.id, label="viewer-a")


@pytest_asyncio.fixture
async def org_b_user(db_session: AsyncSession, org_b: Organization) -> User:
    return await make_user(db_session, role="analyst", organization_id=org_b.id, label="analyst-b")


@pytest_asyncio.fixture
async def platform_superuser(db_session: AsyncSession) -> User:
    return await make_user(
        db_session, role="admin", organization_id=None, is_superuser=True, label="platform-su"
    )


@pytest_asyncio.fixture
async def org_a_headers(org_a_user: User) -> dict[str, str]:
    return bearer(org_a_user)


@pytest_asyncio.fixture
async def org_a_admin_headers(org_a_admin: User) -> dict[str, str]:
    return bearer(org_a_admin)


@pytest_asyncio.fixture
async def viewer_headers(org_a_viewer: User) -> dict[str, str]:
    return bearer(org_a_viewer)


@pytest_asyncio.fixture
async def org_b_headers(org_b_user: User) -> dict[str, str]:
    return bearer(org_b_user)


@pytest_asyncio.fixture
async def orgless_user(db_session: AsyncSession) -> User:
    """An authenticated analyst with no organisation (expects 403 organization_required)."""
    return await make_user(db_session, role="analyst", organization_id=None, label="orgless")


@pytest_asyncio.fixture
async def orgless_headers(orgless_user: User) -> dict[str, str]:
    return bearer(orgless_user)


@pytest_asyncio.fixture
async def superuser_headers(platform_superuser: User) -> dict[str, str]:
    return bearer(platform_superuser)
