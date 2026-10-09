"""``POST /ai/triage/batch`` only touches the caller's organization's alerts.

Found in the 2026-10-08 feature audit: the alert query had no organization
filter, so any user could rewrite the priority of every tenant's alerts, and
the AgenticSOC toast read keys the endpoint never returned ("Triaged 0").
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from src.models.alert import Alert

ORG_A = "aiorg-a000-4000-8000-000000000001"
ORG_B = "aiorg-b000-4000-8000-000000000002"


async def _org_user(db_session, *, email: str, org: str | None, role: str = "analyst"):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if org is not None and await db_session.get(Organization, org) is None:
        db_session.add(Organization(id=org, name=f"AI-{org[:7]}", slug=org[:12]))
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


async def _alert(db_session, org: str, title: str) -> str:
    alert = Alert(title=title, organization_id=org, severity="critical", source="siem", priority=4)
    db_session.add(alert)
    await db_session.commit()
    return alert.id


@pytest.mark.asyncio
async def test_batch_triage_ignores_other_tenant_alert_ids(client, db_session):
    _, headers_a = await _org_user(db_session, email="ai-a@aiorg-a.io", org=ORG_A)
    own_id = await _alert(db_session, ORG_A, "own critical alert")
    foreign_id = await _alert(db_session, ORG_B, "foreign critical alert")

    resp = await client.post(
        "/api/v1/ai/triage/batch", headers=headers_a, json={"alert_ids": [own_id, foreign_id], "limit": 10}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The key the AgenticSOC toast reads.
    assert body["alerts_triaged"] == 1
    assert [t["alert_id"] for t in body["triaged_alerts"]] == [own_id]

    db_session.expire_all()
    own = (await db_session.execute(select(Alert).where(Alert.id == own_id))).scalar_one()
    foreign = (await db_session.execute(select(Alert).where(Alert.id == foreign_id))).scalar_one()
    assert own.priority == 1
    assert foreign.priority == 4


@pytest.mark.asyncio
async def test_batch_triage_without_ids_stays_in_tenant(client, db_session):
    _, headers_a = await _org_user(db_session, email="ai-a2@aiorg-a.io", org=ORG_A)
    foreign_id = await _alert(db_session, ORG_B, "foreign alert 2")

    resp = await client.post("/api/v1/ai/triage/batch", headers=headers_a, json={"limit": 500})
    assert resp.status_code == 200, resp.text
    assert foreign_id not in {t["alert_id"] for t in resp.json()["triaged_alerts"]}

    db_session.expire_all()
    foreign = (await db_session.execute(select(Alert).where(Alert.id == foreign_id))).scalar_one()
    assert foreign.priority == 4


@pytest.mark.asyncio
async def test_batch_triage_refuses_users_without_organization(client, db_session):
    _, headers = await _org_user(db_session, email="ai-noorg@aiorg.io", org=None)
    foreign_id = await _alert(db_session, ORG_B, "foreign alert 3")

    resp = await client.post("/api/v1/ai/triage/batch", headers=headers, json={"limit": 50})
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"

    db_session.expire_all()
    foreign = (await db_session.execute(select(Alert).where(Alert.id == foreign_id))).scalar_one()
    assert foreign.priority == 4
