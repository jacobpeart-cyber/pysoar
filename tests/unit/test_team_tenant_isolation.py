"""Teams are scoped to the caller's organization.

Found in the 2026-10-08 feature audit: ``GET /teams`` had no organization
filter for admins and ``_get_team`` let any admin through, so a tenant admin
could list, rename, delete and add members to every tenant's teams.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from src.models.organization import Team, TeamMember

ORG_A = "teamorg-a00-4000-8000-000000000001"
ORG_B = "teamorg-b00-4000-8000-000000000002"


async def _org_user(db_session, *, email: str, org: str, role: str = "admin", superuser: bool = False):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, org) is None:
        db_session.add(Organization(id=org, name=f"TEAM-{org[:9]}", slug=org[:12]))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        is_superuser=superuser,
        organization_id=org,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _team(db_session, org: str, name: str) -> Team:
    team = Team(name=name, organization_id=org, description="synthetic test team")
    db_session.add(team)
    await db_session.commit()
    return team


@pytest.mark.asyncio
async def test_tenant_admin_cannot_see_or_modify_other_tenant_teams(client, db_session):
    _, headers_a = await _org_user(db_session, email="admin-a@teamorg-a.io", org=ORG_A)
    victim, _ = await _org_user(db_session, email="admin-b@teamorg-b.io", org=ORG_B)
    victim_id = victim.id
    own = await _team(db_session, ORG_A, "A-blue")
    own_id = own.id
    foreign = await _team(db_session, ORG_B, "B-red")
    foreign_id = foreign.id

    listed = await client.get("/api/v1/teams", headers=headers_a)
    assert listed.status_code == 200, listed.text
    ids = {t["id"] for t in listed.json()}
    assert own_id in ids
    assert foreign_id not in ids

    explicit = await client.get(f"/api/v1/teams?organization_id={ORG_B}", headers=headers_a)
    assert explicit.status_code == 403

    assert (await client.get(f"/api/v1/teams/{foreign_id}", headers=headers_a)).status_code == 404
    assert (await client.patch(f"/api/v1/teams/{foreign_id}", headers=headers_a, json={"name": "pwned"})).status_code == 404
    assert (await client.get(f"/api/v1/teams/{foreign_id}/members", headers=headers_a)).status_code == 404
    add = await client.post(
        f"/api/v1/teams/{foreign_id}/members", headers=headers_a, json={"user_id": victim_id, "role": "member"}
    )
    assert add.status_code == 404
    assert (await client.delete(f"/api/v1/teams/{foreign_id}", headers=headers_a)).status_code == 404

    db_session.expire_all()
    row = (await db_session.execute(select(Team).where(Team.id == foreign_id))).scalar_one()
    assert row.name == "B-red"
    members = (await db_session.execute(select(TeamMember).where(TeamMember.team_id == foreign_id))).scalars().all()
    assert members == []


@pytest.mark.asyncio
async def test_tenant_admin_manages_own_team_but_cannot_add_foreign_user(client, db_session):
    _, headers_a = await _org_user(db_session, email="admin-a2@teamorg-a.io", org=ORG_A)
    colleague, _ = await _org_user(db_session, email="analyst-a2@teamorg-a.io", org=ORG_A, role="analyst")
    outsider, _ = await _org_user(db_session, email="analyst-b2@teamorg-b.io", org=ORG_B, role="analyst")
    colleague_id, outsider_id, outsider_email = colleague.id, outsider.id, outsider.email
    own = await _team(db_session, ORG_A, "A-green")
    own_id = own.id

    assert (await client.get(f"/api/v1/teams/{own_id}", headers=headers_a)).status_code == 200
    renamed = await client.patch(f"/api/v1/teams/{own_id}", headers=headers_a, json={"name": "A-green-2"})
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "A-green-2"

    ok = await client.post(
        f"/api/v1/teams/{own_id}/members", headers=headers_a, json={"user_id": colleague_id, "role": "member"}
    )
    assert ok.status_code == 201, ok.text

    foreign_by_id = await client.post(
        f"/api/v1/teams/{own_id}/members", headers=headers_a, json={"user_id": outsider_id, "role": "member"}
    )
    assert foreign_by_id.status_code == 404
    foreign_by_email = await client.post(
        f"/api/v1/teams/{own_id}/members", headers=headers_a, json={"email": outsider_email, "role": "member"}
    )
    assert foreign_by_email.status_code == 404


@pytest.mark.asyncio
async def test_superuser_can_list_and_read_any_org_teams(client, db_session):
    _, headers_root = await _org_user(db_session, email="root@teamorg-a.io", org=ORG_A, superuser=True)
    foreign = await _team(db_session, ORG_B, "B-purple")

    listed = await client.get(f"/api/v1/teams?organization_id={ORG_B}", headers=headers_root)
    assert listed.status_code == 200, listed.text
    assert foreign.id in {t["id"] for t in listed.json()}
    assert all(t["organization_id"] == ORG_B for t in listed.json())

    assert (await client.get(f"/api/v1/teams/{foreign.id}", headers=headers_root)).status_code == 200
