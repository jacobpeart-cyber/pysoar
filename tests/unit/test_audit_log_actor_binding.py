"""Hand-written audit events cannot be attributed to someone else.

Found in the 2026-10-08 feature audit: ``POST /audit-evidence/audit/log``
took ``actor_id``, ``actor_type`` and ``actor_ip`` from the request body, so
any user (viewers included) could write hash-chained audit rows naming another
actor. The actor is now the authenticated caller, the IP is the connection's
client address, and viewers are refused.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from src.audit_evidence.models import AuditTrail

ORG = "alog-org-0000-4000-8000-000000000001"
OTHER_ORG = "alog-org-0000-4000-8000-000000000002"


async def _org_user(db_session, *, email: str, org: str = ORG, role: str = "analyst") -> tuple[object, dict]:
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, org) is None:
        db_session.add(Organization(id=org, name=f"ORG-{org[-2:]}", slug=f"alog-{org[-2:]}"))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=org,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


FORGED = {
    "event_type": "change",
    "action": "policy.update",
    "actor_type": "system",
    "actor_id": "ceo-user-id",
    "actor_ip": "10.66.66.66",
    "resource_type": "policy",
    "resource_id": "pol-1",
    "description": "changed retention",
}


@pytest.mark.asyncio
async def test_actor_fields_come_from_the_caller_not_the_body(client, db_session):
    analyst, headers = await _org_user(db_session, email="alog1@alog-org.io")
    analyst_id = analyst.id

    resp = await client.post("/api/v1/audit-evidence/audit/log", headers=headers, json=FORGED)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["actor_id"] == analyst_id
    assert body["actor_type"] == "user"
    assert body["actor_ip"] != "10.66.66.66"
    assert body["organization_id"] == ORG

    rows = (await db_session.execute(select(AuditTrail).where(AuditTrail.organization_id == ORG))).scalars().all()
    assert len(rows) == 1
    assert rows[0].actor_id == analyst_id
    assert rows[0].actor_type == "user"
    assert rows[0].actor_ip != "10.66.66.66"
    assert rows[0].description == "changed retention"
    assert not (await db_session.execute(select(AuditTrail).where(AuditTrail.actor_id == "ceo-user-id"))).scalars().all()


@pytest.mark.asyncio
async def test_viewers_cannot_write_audit_events(client, db_session):
    _, headers = await _org_user(db_session, email="alog2@alog-org.io", role="viewer")
    resp = await client.post("/api/v1/audit-evidence/audit/log", headers=headers, json=FORGED)
    assert resp.status_code == 403, resp.text
    assert not (await db_session.execute(select(AuditTrail).where(AuditTrail.organization_id == ORG))).scalars().all()


@pytest.mark.asyncio
async def test_events_land_in_the_callers_organization_only(client, db_session):
    _, headers = await _org_user(db_session, email="alog3@alog-other.io", org=OTHER_ORG, role="admin")
    resp = await client.post("/api/v1/audit-evidence/audit/log", headers=headers, json=FORGED)
    assert resp.status_code == 200, resp.text
    assert resp.json()["organization_id"] == OTHER_ORG
    assert not (await db_session.execute(select(AuditTrail).where(AuditTrail.organization_id == ORG))).scalars().all()
