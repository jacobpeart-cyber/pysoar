"""SSO binding hygiene: the group-to-role choice never depends on the map's key
order, and subject bindings do not survive a change of identity provider."""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.identity.oidc import first_mapped_group
from src.models.audit import AuditLog
from src.models.user import User
from tests.helpers.tenancy import make_user
from tests.unit.sso_fakes import FakeIdP, configure
from tests.unit.test_sso_oidc import _body, idp, store  # noqa: F401  (fixtures reused)

pytestmark = pytest.mark.asyncio


def test_mapping_precedence_is_independent_of_map_order() -> None:
    groups = ["readers", "responders", "soc-admins", "deputies"]
    ordered = {"readers": "viewer", "responders": "analyst", "soc-admins": "admin", "deputies": "role-id-1"}
    reversed_map = dict(reversed(list(ordered.items())))
    assert first_mapped_group(ordered, groups) == ("soc-admins", "admin")
    assert first_mapped_group(reversed_map, groups) == ("soc-admins", "admin")
    # Without an admin group: analyst beats a custom role beats viewer; ties by group name.
    no_admin = {k: v for k, v in ordered.items() if k != "soc-admins"}
    assert first_mapped_group(no_admin, groups) == ("responders", "analyst")
    assert first_mapped_group({"zeta": "role-b", "alpha": "role-a"}, ["zeta", "alpha"]) == ("alpha", "role-a")
    assert first_mapped_group(ordered, ["nobody"]) is None


async def test_changing_the_provider_clears_subject_bindings(
    client: AsyncClient, db_session, org_a, org_b, org_a_admin_headers, idp: FakeIdP, store,  # noqa: F811
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    await configure(db_session, org_a_id, idp)
    bound_a = await make_user(db_session, role="viewer", organization_id=org_a_id, label="bound-a")
    bound_a.sso_subject = "subject-a"
    bound_b = await make_user(db_session, role="viewer", organization_id=org_b_id, label="bound-b")
    bound_b.sso_subject = "subject-b"
    await db_session.commit()
    a_id, b_id = bound_a.id, bound_b.id

    # Same provider, other field: bindings stay.
    same = await client.put("/api/v1/settings/sso", json=_body(idp, display_name="Renamed"), headers=org_a_admin_headers)
    assert same.status_code == 200, same.text
    db_session.expire_all()
    assert (await db_session.execute(select(User.sso_subject).where(User.id == a_id))).scalar() == "subject-a"

    # New issuer: org A's bindings are cleared, org B's are untouched, and it is audited.
    moved = await client.put(
        "/api/v1/settings/sso", json=_body(idp, issuer="https://other-idp.example.com"), headers=org_a_admin_headers,
    )
    assert moved.status_code == 200, moved.text
    db_session.expire_all()
    assert (await db_session.execute(select(User.sso_subject).where(User.id == a_id))).scalar() is None
    assert (await db_session.execute(select(User.sso_subject).where(User.id == b_id))).scalar() == "subject-b"
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.organization_id == org_a_id, AuditLog.action == "sso_bindings_cleared")
    )).scalars().all()
    assert len(rows) == 1 and "1 subject bindings cleared" in (rows[0].description or "")
