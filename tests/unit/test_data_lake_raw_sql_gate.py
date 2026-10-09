"""Raw SQL on the data lake is platform-superuser only.

Found in the 2026-10-08 feature audit: ``POST /data-lake/query`` accepted raw
SQL from any user and relied on a regex tenant guard that scoped only the first
FROM table, ignored comma joins, JOIN targets and subqueries, and never
enforced the column whitelist, so a viewer could run
``SELECT users.email, users.hashed_password FROM alerts, users``. Until the
guard is rebuilt on a real parser, everyone but a platform superuser (tenant
admins included) gets 403 ``raw_sql_requires_superuser``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from src.api.v1.endpoints import data_lake as data_lake_endpoints
from src.data_lake.models import QueryJob

ORG = "dlq-org-0000-4000-8000-000000000001"
ATTACK = "SELECT users.email, users.hashed_password FROM alerts, users"


async def _org_user(db_session, *, email: str, role: str = "analyst", is_superuser: bool = False) -> tuple[object, dict]:
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, ORG) is None:
        db_session.add(Organization(id=ORG, name="DLQ-ORG", slug="dlq-org"))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        is_superuser=is_superuser,
        organization_id=ORG,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
async def test_raw_sql_is_refused_for_tenant_roles(client, db_session, role):
    _, headers = await _org_user(db_session, email=f"dlq-{role}@dlq-org.io", role=role)
    for key in ("query", "query_text", "sql"):
        resp = await client.post("/api/v1/data-lake/query", headers=headers, json={key: ATTACK})
        assert resp.status_code == 403, (role, key, resp.text)
        assert resp.json()["detail"]["error"] == "raw_sql_requires_superuser"
        assert "hashed_password" not in resp.text.replace(ATTACK, "")
    # Refused before execution: nothing was run or recorded.
    assert not (await db_session.execute(select(QueryJob))).scalars().all()


@pytest.mark.asyncio
async def test_catalog_filter_path_still_works_for_viewers(client, db_session):
    _, headers = await _org_user(db_session, email="dlq-cat@dlq-org.io", role="viewer")
    resp = await client.post("/api/v1/data-lake/query", headers=headers, json={"source_type": "siem"})
    assert resp.status_code == 200, resp.text
    assert resp.json().get("mode") != "sql"


@pytest.mark.asyncio
async def test_platform_superuser_can_still_run_sql_through_the_guard(client, db_session):
    _, headers = await _org_user(db_session, email="dlq-root@dlq-org.io", role="admin", is_superuser=True)
    resp = await client.post("/api/v1/data-lake/query", headers=headers, json={"query": "SELECT id FROM alerts"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "sql"
    # The guard is kept as defence in depth: non-whitelisted tables are still refused.
    resp = await client.post("/api/v1/data-lake/query", headers=headers, json={"query": "SELECT * FROM users"})
    assert resp.status_code == 400, resp.text


def test_guard_is_kept():
    assert callable(data_lake_endpoints._build_tenant_scoped_sql)
