"""A what-if access evaluation must never revoke the caller's own session.

Found in the 2026-10-08 feature audit: ``POST /zerotrust/evaluate`` injected
the caller's JWT ``jti`` as the session under evaluation, the engine pushed the
verdict into the session gate (24 h TTL for a deny), and an organisation with
no policies denies by default, so a single evaluation locked the analyst out
of the whole API for a day. Only the continuous-verification task may write
the gate, and it marks its context with ``enforce_session``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from src.zerotrust import engine as zt_engine
from src.zerotrust.models import AccessDecision

ORG = "zt-org-0000-4000-8000-000000000001"


async def _org_user(db_session, *, email: str, role: str = "analyst"):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, ORG) is None:
        db_session.add(Organization(id=ORG, name="ZT-ORG", slug="zt-org"))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=ORG,
    )
    db_session.add(user)
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


@pytest.fixture
def gate_spy(monkeypatch):
    calls: list[tuple[str, object]] = []

    async def _spy(session_id, decision):
        calls.append((session_id, decision))

    import src.zerotrust.session_gate as gate

    monkeypatch.setattr(gate, "invalidate_session_cache", _spy)
    return calls


@pytest.mark.asyncio
async def test_what_if_evaluation_does_not_touch_the_callers_session(client, db_session, gate_spy):
    user, headers = await _org_user(db_session, email="zt1@zt-org.io")

    resp = await client.post(
        "/api/v1/zerotrust/evaluate",
        headers=headers,
        json={
            "subject_type": "user",
            "subject_id": "someone-else",
            "resource_type": "application",
            "resource_id": "payroll",
            "context": {},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] in ("deny", "allow", "challenge", "step_up")

    # Nothing was pushed into the per-request session gate ...
    assert gate_spy == []
    # ... and the recorded decision is not bound to the caller's token.
    rows = (await db_session.execute(select(AccessDecision).where(AccessDecision.organization_id == ORG))).scalars().all()
    assert rows, "the evaluation must still be recorded"
    assert all(r.session_id is None for r in rows)

    # The caller can still use the API afterwards.
    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200, me.text


@pytest.mark.asyncio
async def test_client_supplied_session_id_is_recorded_but_not_enforced(client, db_session, gate_spy):
    _, headers = await _org_user(db_session, email="zt2@zt-org.io")

    resp = await client.post(
        "/api/v1/zerotrust/evaluate",
        headers=headers,
        json={
            "subject_type": "user",
            "subject_id": "victim",
            "resource_type": "application",
            "resource_id": "payroll",
            # A hostile client naming someone else's session, and trying to
            # smuggle the enforcement flag, must not revoke anything.
            "context": {"session_id": "victim-jti", "enforce_session": True},
        },
    )
    assert resp.status_code == 200, resp.text
    assert gate_spy == []


@pytest.mark.asyncio
async def test_viewers_cannot_run_evaluations(client, db_session, gate_spy):
    """An evaluation records a decision and can fire violation automation."""
    _, headers = await _org_user(db_session, email="zt-viewer@zt-org.io", role="viewer")

    resp = await client.post(
        "/api/v1/zerotrust/evaluate",
        headers=headers,
        json={"subject_type": "user", "subject_id": "x", "resource_type": "application", "resource_id": "y", "context": {}},
    )
    assert resp.status_code == 403, resp.text
    assert gate_spy == []
    rows = (await db_session.execute(select(AccessDecision).where(AccessDecision.organization_id == ORG))).scalars().all()
    assert all(r.subject_id != "x" for r in rows)


@pytest.mark.asyncio
async def test_engine_pushes_the_gate_only_with_enforce_session(db_session, gate_spy):
    pdp = zt_engine.PolicyDecisionPoint(db_session, ORG)
    from src.models.organization import Organization

    if await db_session.get(Organization, ORG) is None:
        db_session.add(Organization(id=ORG, name="ZT-ORG", slug="zt-org"))
        await db_session.commit()

    await pdp.evaluate_access_request("user", "u1", "application", "app", {"session_id": "jti-1"})
    assert gate_spy == []

    await pdp.evaluate_access_request(
        "user", "u1", "application", "app", {"session_id": "jti-1", "enforce_session": True},
    )
    assert [c[0] for c in gate_spy] == ["jti-1"]
