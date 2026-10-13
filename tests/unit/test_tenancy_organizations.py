"""Wave 1 tenancy and RBAC for ``/organizations`` (organizations.py).

* listing every organisation, creating and deleting organisations are
  platform-superuser actions (``get_current_superuser`` admitted tenant admins);
* everyone else reads only their own organisation; another tenant's is 404;
* only a tenant ``admin`` updates their own organisation (name/description),
  ``plan`` / ``is_active`` are platform-superuser only;
* member add/remove: admin of that organisation only, for users of that
  organisation only (no cross-tenant email oracle), ``owner`` not grantable;
* teams: scoped to the caller's organisation (another tenant's team is 404,
  an explicit other ``organization_id`` is 403 ``organization_mismatch``),
  writes need analyst or admin, viewers read only, members must belong to the
  team's organisation, and a created team is stamped with the caller's org.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.organization import Organization, OrganizationMember, Team, TeamMember
from src.models.user import User
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/organizations"


async def test_list_shows_only_own_org_and_superuser_sees_all(
    client: AsyncClient,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    a_id, b_id = org_a.id, org_b.id

    resp = await client.get(BASE, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert {o["id"] for o in resp.json()} == {a_id}

    resp = await client.get(BASE, headers=org_b_headers)
    assert {o["id"] for o in resp.json()} == {b_id}

    resp = await client.get(BASE, headers=superuser_headers, params={"limit": 100})
    assert resp.status_code == 200, resp.text
    ids = {o["id"] for o in resp.json()}
    assert {a_id, b_id} <= ids


async def test_get_isolated_and_own_org_readable(
    client: AsyncClient,
    org_a: Organization,
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    a_id = org_a.id
    assert (await client.get(f"{BASE}/{a_id}", headers=org_a_headers)).status_code == 200
    assert (await client.get(f"{BASE}/{a_id}", headers=viewer_headers)).status_code == 200
    await assert_tenant_isolated(client, "GET", f"{BASE}/{a_id}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{BASE}/{a_id}/members", org_b_headers)


async def test_create_is_platform_superuser_only(
    client: AsyncClient,
    org_a_admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    body = {"name": "New Tenant", "slug": f"new-tenant-{uuid.uuid4().hex[:8]}"}
    for headers in (org_a_admin_headers, viewer_headers):
        resp = await client.post(BASE, headers=headers, json=body)
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "platform_superuser_required"

    resp = await client.post(BASE, headers=superuser_headers, json=body)
    assert resp.status_code == 201, resp.text


async def test_delete_is_platform_superuser_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    a_id, b_id = org_a.id, org_b.id
    # A tenant admin can delete neither their own nor another organisation.
    for target in (a_id, b_id):
        resp = await client.delete(f"{BASE}/{target}", headers=org_a_admin_headers)
        assert resp.status_code == 403, resp.text

    victim = Organization(name="Disposable", slug=f"disposable-{uuid.uuid4().hex[:8]}")
    db_session.add(victim)
    await db_session.commit()
    victim_id = victim.id
    resp = await client.delete(f"{BASE}/{victim_id}", headers=superuser_headers)
    assert resp.status_code == 204, resp.text


async def test_update_admin_own_org_only(
    client: AsyncClient,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    a_id, b_id = org_a.id, org_b.id

    for headers in (org_a_headers, viewer_headers):
        resp = await client.patch(f"{BASE}/{a_id}", headers=headers, json={"name": "nope"})
        assert resp.status_code == 403, resp.text

    resp = await client.patch(f"{BASE}/{a_id}", headers=org_a_admin_headers, json={"name": "A renamed"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "A renamed"

    await assert_tenant_isolated(
        client, "PATCH", f"{BASE}/{b_id}", org_a_admin_headers, json={"name": "pwned"},
    )

    resp = await client.patch(f"{BASE}/{a_id}", headers=org_a_admin_headers, json={"plan": "enterprise"})
    assert resp.status_code == 403, resp.text
    resp = await client.patch(f"{BASE}/{a_id}", headers=org_a_admin_headers, json={"is_active": False})
    assert resp.status_code == 403, resp.text

    resp = await client.patch(f"{BASE}/{a_id}", headers=superuser_headers, json={"plan": "enterprise"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["plan"] == "enterprise"


async def test_member_management_scoped_to_admins_own_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_user: User,
    org_b_user: User,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    a_id, b_id = org_a.id, org_b.id
    colleague_id, colleague_email = org_a_user.id, org_a_user.email
    outsider_id, outsider_email = org_b_user.id, org_b_user.email

    # Analyst and viewer cannot manage members.
    for headers in (org_a_headers, viewer_headers):
        resp = await client.post(
            f"{BASE}/{a_id}/members", headers=headers, json={"user_id": colleague_id, "role": "member"},
        )
        assert resp.status_code == 403, resp.text

    # Foreign users are invisible, by id and by email (no enumeration oracle).
    for body in ({"user_id": outsider_id}, {"email": outsider_email}):
        resp = await client.post(
            f"{BASE}/{a_id}/members", headers=org_a_admin_headers, json={**body, "role": "member"},
        )
        assert resp.status_code == 404, resp.text
        assert outsider_email not in resp.text

    # owner is not grantable.
    resp = await client.post(
        f"{BASE}/{a_id}/members", headers=org_a_admin_headers, json={"user_id": colleague_id, "role": "owner"},
    )
    assert resp.status_code == 422, resp.text

    resp = await client.post(
        f"{BASE}/{a_id}/members", headers=org_a_admin_headers, json={"email": colleague_email, "role": "member"},
    )
    assert resp.status_code == 201, resp.text

    listed = await client.get(f"{BASE}/{a_id}/members", headers=org_a_admin_headers)
    assert listed.status_code == 200
    assert colleague_id in {m["user_id"] for m in listed.json()}

    # The admin cannot touch org B's membership.
    db_session.add(OrganizationMember(organization_id=b_id, user_id=outsider_id, role="member"))
    await db_session.commit()
    await assert_tenant_isolated(
        client, "POST", f"{BASE}/{b_id}/members", org_a_admin_headers,
        json={"user_id": outsider_id, "role": "admin"},
    )
    await assert_tenant_isolated(client, "DELETE", f"{BASE}/{b_id}/members/{outsider_id}", org_a_admin_headers)
    still = await db_session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == b_id, OrganizationMember.user_id == outsider_id,
        ),
    )
    assert still.scalar_one_or_none() is not None

    # Analyst cannot remove; admin can.
    resp = await client.delete(f"{BASE}/{a_id}/members/{colleague_id}", headers=org_a_headers)
    assert resp.status_code == 403, resp.text
    resp = await client.delete(f"{BASE}/{a_id}/members/{colleague_id}", headers=org_a_admin_headers)
    assert resp.status_code == 204, resp.text


async def test_orgless_non_superuser_cannot_list(
    client: AsyncClient, orgless_headers: dict[str, str],
) -> None:
    resp = await client.get(BASE, headers=orgless_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"


# ---------------------------------------------------------------------------
# teams
# ---------------------------------------------------------------------------

TEAMS = "/api/v1/teams"


async def _team(client: AsyncClient, headers: dict[str, str], name: str = "Blue") -> str:
    resp = await client.post(TEAMS, headers=headers, json={"name": name})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_team_create_is_stamped_with_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    a_id, b_id = org_a.id, org_b.id
    team_id = await _team(client, org_a_headers)
    assert (await db_session.get(Team, team_id)).organization_id == a_id

    # Naming another organisation is refused for a tenant user...
    resp = await client.post(TEAMS, headers=org_a_headers, json={"name": "x", "organization_id": b_id})
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_mismatch"

    # ...an org-less superuser must name one, and then it is used.
    resp = await client.post(TEAMS, headers=superuser_headers, json={"name": "x"})
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"
    resp = await client.post(TEAMS, headers=superuser_headers, json={"name": "Ops", "organization_id": b_id})
    assert resp.status_code == 201, resp.text
    assert resp.json()["organization_id"] == b_id


async def test_team_routes_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_admin: User,
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    team_id = await _team(client, org_a_admin_headers)
    lead_id = org_a_admin.id

    listed = await client.get(TEAMS, headers=org_b_headers)
    assert listed.status_code == 200, listed.text
    assert team_id not in {t["id"] for t in listed.json()}

    for method, path, json in (
        ("GET", f"{TEAMS}/{team_id}", None),
        ("PATCH", f"{TEAMS}/{team_id}", {"name": "pwned"}),
        ("DELETE", f"{TEAMS}/{team_id}", None),
        ("GET", f"{TEAMS}/{team_id}/members", None),
        ("POST", f"{TEAMS}/{team_id}/members", {"user_id": lead_id, "role": "member"}),
        ("DELETE", f"{TEAMS}/{team_id}/members/{lead_id}", None),
    ):
        resp = await assert_tenant_isolated(client, method, path, org_b_headers, json=json)
        assert resp.status_code == 404, (method, path, resp.text)

    db_session.expire_all()
    assert (await db_session.get(Team, team_id)).name == "Blue"


@pytest.mark.parametrize(
    "method,suffix,json",
    [
        ("POST", "", {"name": "x"}),
        ("PATCH", "/{team}", {"name": "x"}),
        ("DELETE", "/{team}", None),
        ("POST", "/{team}/members", {"user_id": "{viewer}", "role": "member"}),
        ("DELETE", "/{team}/members/{viewer}", None),
    ],
)
async def test_team_writes_need_analyst_or_admin(
    client: AsyncClient,
    org_a_viewer: User,
    org_a_admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    method: str,
    suffix: str,
    json,
) -> None:
    viewer_id = org_a_viewer.id
    team_id = await _team(client, org_a_admin_headers)
    fill = {"team": team_id, "viewer": viewer_id}
    body = {k: (v.format(**fill) if isinstance(v, str) else v) for k, v in json.items()} if json else None
    resp = await client.request(method, f"{TEAMS}" + suffix.format(**fill), headers=viewer_headers, json=body)
    assert resp.status_code == 403, resp.text

    # The viewer can still read.
    assert (await client.get(TEAMS, headers=viewer_headers)).status_code == 200


async def test_analyst_manages_teams_and_members_stay_in_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_viewer: User,
    org_b_user: User,
    org_a_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    colleague_id, outsider_id = org_a_viewer.id, org_b_user.id
    team_id = await _team(client, org_a_headers, name="Red")

    resp = await client.patch(f"{TEAMS}/{team_id}", headers=org_a_headers, json={"name": "Red 2"})
    assert resp.status_code == 200, resp.text

    resp = await client.post(
        f"{TEAMS}/{team_id}/members", headers=org_a_headers, json={"user_id": colleague_id, "role": "member"},
    )
    assert resp.status_code == 201, resp.text

    # Another tenant's user can never join, not even when a superuser asks.
    for headers in (org_a_headers, superuser_headers):
        resp = await client.post(
            f"{TEAMS}/{team_id}/members", headers=headers, json={"user_id": outsider_id, "role": "member"},
        )
        assert resp.status_code == 404, resp.text
    members = (
        await db_session.execute(select(TeamMember.user_id).where(TeamMember.team_id == team_id))
    ).scalars().all()
    assert outsider_id not in members

    resp = await client.delete(f"{TEAMS}/{team_id}/members/{colleague_id}", headers=org_a_headers)
    assert resp.status_code == 204, resp.text
    resp = await client.delete(f"{TEAMS}/{team_id}", headers=org_a_headers)
    assert resp.status_code == 204, resp.text


async def test_orgless_caller_cannot_list_teams(
    client: AsyncClient, orgless_headers: dict[str, str],
) -> None:
    resp = await client.get(TEAMS, headers=orgless_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"
