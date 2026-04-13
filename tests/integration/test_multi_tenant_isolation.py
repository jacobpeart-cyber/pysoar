"""Multi-tenant isolation integration tests.

Hands-on verification that PySOAR enforces organization boundaries on every
endpoint that touches tenant data. Two organizations are created, each with
its own user and its own row in every major tenant-scoped table. Then the
test logs in as each user and asserts that:

    1. Listing endpoints never return the other tenant's rows.
    2. Fetching by ID returns 404 (not 403) when the row belongs to the
       other tenant, so the endpoint does not leak existence.
    3. Update/delete against another tenant's row returns 404.
    4. Dashboard/stats aggregates reflect only the caller's tenant.
    5. Cross-entity references (e.g., linking an alert to an incident)
       refuse cross-tenant combinations.

These are the minimum assertions an auditor should run before trusting
any claim of multi-tenant isolation. Every failure here is a P0.

Run:
    pytest tests/integration/test_multi_tenant_isolation.py -v

Notes:
    - Uses the existing conftest.py fixtures but overrides some to create
      two orgs with distinct users.
    - Tests are intentionally ordered from "cheapest to diagnose" (list
      endpoints) to "most expensive to set up" (cross-reference linking).
    - Each test is independent — one failing doesn't cascade into others.
    - The test assumes migrations 014 and 015 have been applied (alerts,
      incidents, assets, playbook_executions all have organization_id).
"""

from __future__ import annotations

import uuid
from typing import AsyncGenerator

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_redis_client
from src.core.database import get_db
from src.core.security import create_access_token, get_password_hash
from src.main import app
from src.models.base import Base
from src.models.organization import Organization
from src.models.user import User


# ---------------------------------------------------------------------------
# Redis override — the production get_current_user fails closed to 503 if
# it can't reach Redis (blacklist check). Override the dependency with a
# stub that returns None for every key so all tokens are treated as valid.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def _mock_redis_for_auth():
    async def _fake_redis():
        stub = AsyncMock()
        stub.get = AsyncMock(return_value=None)
        stub.set = AsyncMock(return_value=True)
        stub.close = AsyncMock()
        yield stub

    app.dependency_overrides[get_redis_client] = _fake_redis
    yield
    app.dependency_overrides.pop(get_redis_client, None)


# ---------------------------------------------------------------------------
# Two-tenant fixtures — override the single-user conftest fixtures for these
# tests only.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def two_orgs(db_session: AsyncSession) -> tuple[Organization, Organization]:
    """Create two independent organizations in the same database."""
    org_a = Organization(
        id=str(uuid.uuid4()),
        name="Org A",
        slug=f"org-a-{uuid.uuid4().hex[:6]}",
        is_active=True,
    )
    org_b = Organization(
        id=str(uuid.uuid4()),
        name="Org B",
        slug=f"org-b-{uuid.uuid4().hex[:6]}",
        is_active=True,
    )
    db_session.add_all([org_a, org_b])
    await db_session.commit()
    await db_session.refresh(org_a)
    await db_session.refresh(org_b)
    return org_a, org_b


@pytest_asyncio.fixture
async def two_users(
    db_session: AsyncSession, two_orgs: tuple[Organization, Organization]
) -> tuple[User, User]:
    """Create one user per organization."""
    org_a, org_b = two_orgs
    user_a = User(
        email="alice@example.com",
        hashed_password=get_password_hash("testpassword123"),
        full_name="Alice A",
        role="admin",
        is_active=True,
        is_superuser=False,
        organization_id=org_a.id,
    )
    user_b = User(
        email="bob@example.org",
        hashed_password=get_password_hash("testpassword123"),
        full_name="Bob B",
        role="admin",
        is_active=True,
        is_superuser=False,
        organization_id=org_b.id,
    )
    db_session.add_all([user_a, user_b])
    await db_session.commit()
    await db_session.refresh(user_a)
    await db_session.refresh(user_b)
    return user_a, user_b


@pytest_asyncio.fixture
async def auth_a(two_users: tuple[User, User]) -> dict:
    return {"Authorization": f"Bearer {create_access_token(subject=two_users[0].id)}"}


@pytest_asyncio.fixture
async def auth_b(two_users: tuple[User, User]) -> dict:
    return {"Authorization": f"Bearer {create_access_token(subject=two_users[1].id)}"}


# ---------------------------------------------------------------------------
# Helper: create one row of every major tenant-scoped model for a given org.
# Returns a dict of {model_name: id} so tests can reference by name.
# ---------------------------------------------------------------------------


async def _seed_tenant_data(
    db_session: AsyncSession, org: Organization, user: User
) -> dict[str, str]:
    """Create one row of each tenant-scoped entity for `org`.

    Returns a dict keyed by short name (e.g., "alert", "incident", "asset")
    mapping to the id of the created row. Tests use this to cross-check
    tenant B's user against tenant A's entity ids.
    """
    from src.models.alert import Alert
    from src.models.incident import Incident
    from src.models.asset import Asset

    seeded: dict[str, str] = {}

    # --- Alert ---
    alert = Alert(
        title=f"alert for {org.name}",
        description="seeded by isolation test",
        severity="high",
        source="test",
        status="new",
        organization_id=org.id,
    )
    db_session.add(alert)
    await db_session.flush()
    seeded["alert"] = alert.id

    # --- Incident ---
    incident = Incident(
        title=f"incident for {org.name}",
        description="seeded by isolation test",
        severity="high",
        status="open",
        incident_type="malware",
        organization_id=org.id,
    )
    db_session.add(incident)
    await db_session.flush()
    seeded["incident"] = incident.id

    # --- Asset ---
    asset = Asset(
        name=f"asset for {org.name}",
        asset_type="server",
        status="active",
        criticality="medium",
        organization_id=org.id,
    )
    db_session.add(asset)
    await db_session.flush()
    seeded["asset"] = asset.id

    await db_session.commit()
    return seeded


@pytest_asyncio.fixture
async def seeded_data(
    db_session: AsyncSession,
    two_orgs: tuple[Organization, Organization],
    two_users: tuple[User, User],
) -> dict[str, dict[str, str]]:
    """Seed tenant data for both orgs. Returns {"a": {...}, "b": {...}}"""
    org_a, org_b = two_orgs
    user_a, user_b = two_users
    return {
        "a": await _seed_tenant_data(db_session, org_a, user_a),
        "b": await _seed_tenant_data(db_session, org_b, user_b),
    }


# ---------------------------------------------------------------------------
# 1. LIST ENDPOINTS — each caller sees only their own rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_alerts_tenant_isolated(
    client: AsyncClient, auth_a: dict, auth_b: dict, seeded_data: dict
):
    """GET /alerts must only return alerts belonging to the caller's org."""
    resp_a = await client.get("/api/v1/alerts", headers=auth_a)
    assert resp_a.status_code == 200, resp_a.text
    items_a = (resp_a.json() or {}).get("items") or []
    ids_a = {a.get("id") for a in items_a}
    assert seeded_data["a"]["alert"] in ids_a, "Org A should see its own alert"
    assert seeded_data["b"]["alert"] not in ids_a, (
        "Org A leaked Org B's alert in list response"
    )

    resp_b = await client.get("/api/v1/alerts", headers=auth_b)
    items_b = (resp_b.json() or {}).get("items") or []
    ids_b = {a.get("id") for a in items_b}
    assert seeded_data["b"]["alert"] in ids_b
    assert seeded_data["a"]["alert"] not in ids_b


@pytest.mark.asyncio
async def test_list_incidents_tenant_isolated(
    client: AsyncClient, auth_a: dict, auth_b: dict, seeded_data: dict
):
    """GET /incidents must only return incidents belonging to the caller's org."""
    resp_a = await client.get("/api/v1/incidents", headers=auth_a)
    assert resp_a.status_code == 200, resp_a.text
    items_a = (resp_a.json() or {}).get("items") or []
    ids_a = {i.get("id") for i in items_a}
    assert seeded_data["a"]["incident"] in ids_a
    assert seeded_data["b"]["incident"] not in ids_a

    resp_b = await client.get("/api/v1/incidents", headers=auth_b)
    items_b = (resp_b.json() or {}).get("items") or []
    ids_b = {i.get("id") for i in items_b}
    assert seeded_data["b"]["incident"] in ids_b
    assert seeded_data["a"]["incident"] not in ids_b


@pytest.mark.asyncio
async def test_list_assets_tenant_isolated(
    client: AsyncClient, auth_a: dict, auth_b: dict, seeded_data: dict
):
    """GET /assets must only return assets belonging to the caller's org."""
    resp_a = await client.get("/api/v1/assets", headers=auth_a)
    assert resp_a.status_code == 200, resp_a.text
    items_a = (resp_a.json() or {}).get("items") or []
    ids_a = {a.get("id") for a in items_a}
    assert seeded_data["a"]["asset"] in ids_a
    assert seeded_data["b"]["asset"] not in ids_a

    resp_b = await client.get("/api/v1/assets", headers=auth_b)
    items_b = (resp_b.json() or {}).get("items") or []
    ids_b = {a.get("id") for a in items_b}
    assert seeded_data["b"]["asset"] in ids_b
    assert seeded_data["a"]["asset"] not in ids_b


# ---------------------------------------------------------------------------
# 2. GET-BY-ID — fetching another tenant's row returns 404 (not 403)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alert_by_cross_tenant_id_returns_404(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    """Org A must not be able to fetch Org B's alert by id."""
    cross_id = seeded_data["b"]["alert"]
    resp = await client.get(f"/api/v1/alerts/{cross_id}", headers=auth_a)
    assert resp.status_code == 404, (
        f"IDOR on /alerts/{{id}}: expected 404, got {resp.status_code} body={resp.text}"
    )


@pytest.mark.asyncio
async def test_get_incident_by_cross_tenant_id_returns_404(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    """Org A must not be able to fetch Org B's incident by id."""
    cross_id = seeded_data["b"]["incident"]
    resp = await client.get(f"/api/v1/incidents/{cross_id}", headers=auth_a)
    assert resp.status_code == 404, (
        f"IDOR on /incidents/{{id}}: expected 404, got {resp.status_code} body={resp.text}"
    )


@pytest.mark.asyncio
async def test_get_asset_by_cross_tenant_id_returns_404(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    """Org A must not be able to fetch Org B's asset by id."""
    cross_id = seeded_data["b"]["asset"]
    resp = await client.get(f"/api/v1/assets/{cross_id}", headers=auth_a)
    assert resp.status_code == 404, (
        f"IDOR on /assets/{{id}}: expected 404, got {resp.status_code} body={resp.text}"
    )


# ---------------------------------------------------------------------------
# 3. UPDATE cross-tenant — writes against another tenant's row must 404
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_cross_tenant_alert_returns_404(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    cross_id = seeded_data["b"]["alert"]
    resp = await client.patch(
        f"/api/v1/alerts/{cross_id}",
        headers=auth_a,
        json={"status": "closed"},
    )
    assert resp.status_code == 404, (
        f"Cross-tenant PATCH /alerts/{{id}}: expected 404, got {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_delete_cross_tenant_incident_returns_404(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    cross_id = seeded_data["b"]["incident"]
    resp = await client.delete(f"/api/v1/incidents/{cross_id}", headers=auth_a)
    assert resp.status_code == 404, (
        f"Cross-tenant DELETE /incidents/{{id}}: expected 404, got {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_delete_cross_tenant_asset_returns_404(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    cross_id = seeded_data["b"]["asset"]
    resp = await client.delete(f"/api/v1/assets/{cross_id}", headers=auth_a)
    assert resp.status_code == 404, (
        f"Cross-tenant DELETE /assets/{{id}}: expected 404, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# 4. STATS/DASHBOARD — each tenant sees only their own aggregate counts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_stats_tenant_isolated(
    client: AsyncClient, auth_a: dict, auth_b: dict, seeded_data: dict
):
    """Each org's /alerts/stats total must be exactly 1 (their own row)."""
    resp_a = await client.get("/api/v1/alerts/stats", headers=auth_a)
    assert resp_a.status_code == 200, resp_a.text
    assert resp_a.json().get("total") == 1, (
        f"Org A expected total=1 (their own alert only), got {resp_a.json()}"
    )

    resp_b = await client.get("/api/v1/alerts/stats", headers=auth_b)
    assert resp_b.json().get("total") == 1, (
        f"Org B expected total=1, got {resp_b.json()}"
    )


@pytest.mark.asyncio
async def test_incident_stats_tenant_isolated(
    client: AsyncClient, auth_a: dict, auth_b: dict, seeded_data: dict
):
    resp_a = await client.get("/api/v1/incidents/stats", headers=auth_a)
    assert resp_a.status_code == 200, resp_a.text
    assert resp_a.json().get("total") == 1

    resp_b = await client.get("/api/v1/incidents/stats", headers=auth_b)
    assert resp_b.json().get("total") == 1


# ---------------------------------------------------------------------------
# 5. CROSS-ENTITY LINKING — can't link alert from one tenant to incident in another
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_link_cross_tenant_alert_to_incident_refused(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    """Org A must not be able to link Org B's alert into Org A's incident.

    Endpoint: POST /incidents/{incident_id}/alerts/{alert_id}
    Expected: 404 because the alert is not visible to Org A.
    """
    my_incident = seeded_data["a"]["incident"]
    cross_alert = seeded_data["b"]["alert"]
    resp = await client.post(
        f"/api/v1/incidents/{my_incident}/alerts/{cross_alert}",
        headers=auth_a,
    )
    assert resp.status_code == 404, (
        f"Cross-tenant alert link into own incident: expected 404, "
        f"got {resp.status_code} body={resp.text}"
    )


@pytest.mark.asyncio
async def test_link_own_alert_to_cross_tenant_incident_refused(
    client: AsyncClient, auth_a: dict, seeded_data: dict
):
    """Org A must not be able to link their own alert into Org B's incident."""
    cross_incident = seeded_data["b"]["incident"]
    own_alert = seeded_data["a"]["alert"]
    resp = await client.post(
        f"/api/v1/incidents/{cross_incident}/alerts/{own_alert}",
        headers=auth_a,
    )
    assert resp.status_code == 404, (
        f"Cross-tenant incident link via own alert: expected 404, "
        f"got {resp.status_code} body={resp.text}"
    )


# ---------------------------------------------------------------------------
# 6. USER MANAGEMENT — admin of org A cannot enumerate users of org B
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_tenant_isolated(
    client: AsyncClient, auth_a: dict, auth_b: dict, two_users: tuple[User, User]
):
    """GET /users must only return users in the caller's org."""
    user_a, user_b = two_users

    resp_a = await client.get("/api/v1/users", headers=auth_a)
    assert resp_a.status_code == 200, resp_a.text
    items_a = (resp_a.json() or {}).get("items") or []
    emails_a = {u.get("email") for u in items_a}
    assert user_a.email in emails_a
    assert user_b.email not in emails_a, (
        "Org A admin enumerated a user from Org B via GET /users"
    )

    resp_b = await client.get("/api/v1/users", headers=auth_b)
    items_b = (resp_b.json() or {}).get("items") or []
    emails_b = {u.get("email") for u in items_b}
    assert user_b.email in emails_b
    assert user_a.email not in emails_b


@pytest.mark.asyncio
async def test_get_cross_tenant_user_returns_404(
    client: AsyncClient, auth_a: dict, two_users: tuple[User, User]
):
    """Org A admin fetching Org B user by id must see 404."""
    _, user_b = two_users
    resp = await client.get(f"/api/v1/users/{user_b.id}", headers=auth_a)
    assert resp.status_code == 404, (
        f"IDOR on /users/{{id}}: expected 404, got {resp.status_code}"
    )
