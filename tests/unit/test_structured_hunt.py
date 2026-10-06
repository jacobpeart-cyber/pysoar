"""run_structured_hunt — PY-HUNT-001 orchestration producing a structured
report with verdict + approval-gated recommendations.

Both hunt phases now run through ``AgentToolRegistry.call`` (design v2
section 1), so the hunt needs the organization *and* the analyst it runs as:
``organization_id`` and ``actor_user_id`` are required arguments.
"""

import json

import pytest
from sqlalchemy import select

from src.hunting.models import HuntFinding, HuntSession, HuntHypothesis
from src.siem.models import DetectionRule, LogEntry
from src.models.alert import Alert
from tests.unit.test_attack_loader import _bundle


ANALYST_ID = "eeeeeeee-0000-4000-8000-00000000000a"


async def _seed(db_session, org="org-1"):
    from src.attack.loader import load_stix_bundle
    await load_stix_bundle(db_session, _bundle(), domain="enterprise", attack_version="17.1")
    db_session.add(DetectionRule(
        name="cov-t1110", title="BF", status="active", enabled=True,
        severity="high", mitre_techniques=json.dumps(["T1110"]),
    ))
    # an alert the hunt keyword scan will hit
    db_session.add(Alert(
        title="brute force against dc-01", severity="high", status="new",
        source="siem", organization_id=org,
    ))
    await db_session.commit()


@pytest.mark.asyncio
async def test_structured_hunt_produces_report(db_session):
    from src.agentic.structured_hunt import run_structured_hunt
    await _seed(db_session)

    report = await run_structured_hunt(
        db_session, hypothesis="hunt for brute force T1110 against dc-01",
        organization_id="org-1", timeframe_hours=168,
        actor_user_id=ANALYST_ID,
    )

    # PY-HUNT-001 phase structure
    assert report["hypothesis"]
    assert "scope" in report["phases"]
    assert "data_collection" in report["phases"]
    assert report["phases"]["scope"]["techniques_in_scope"]
    # ATT&CK mapping present and grounded
    assert "T1110" in report["attack_mapping"]["techniques"]
    # verdict + confidence
    assert report["verdict"] in ("suspicious_activity", "benign", "inconclusive")
    assert 0 <= report["confidence"] <= 100


@pytest.mark.asyncio
async def test_recommendations_are_approval_gated(db_session):
    from src.agentic.structured_hunt import run_structured_hunt
    await _seed(db_session)
    report = await run_structured_hunt(
        db_session, hypothesis="hunt T1110 brute force", organization_id="org-1",
        actor_user_id=ANALYST_ID,
    )
    # every recommended action must be flagged for human approval
    assert report["recommendations"]
    assert all(r.get("requires_approval") is True for r in report["recommendations"])
    # no recommendation may claim an action was executed
    assert all("executed" not in json.dumps(r).lower() for r in report["recommendations"])


@pytest.mark.asyncio
async def test_honest_data_source_gaps_in_report(db_session):
    from src.agentic.structured_hunt import run_structured_hunt
    await _seed(db_session)
    report = await run_structured_hunt(
        db_session, hypothesis="hunt T1110", organization_id="org-1",
        actor_user_id=ANALYST_ID,
    )
    notes = " ".join(report.get("notes", [])).lower()
    assert "edr" in notes or "dns" in notes


@pytest.mark.asyncio
async def test_hunt_requires_an_actor(db_session):
    """Without an analyst identity the hunt cannot be policy-checked, so it
    refuses rather than running unattributed tool calls."""
    from src.agentic.structured_hunt import run_structured_hunt

    await _seed(db_session)
    with pytest.raises(ValueError, match="actor_user_id"):
        await run_structured_hunt(db_session, hypothesis="hunt T1110", organization_id="org-1")
    with pytest.raises(ValueError, match="organization_id"):
        await run_structured_hunt(
            db_session, hypothesis="hunt T1110", actor_user_id=ANALYST_ID
        )


HUNT_ORG = "ffffffff-0000-4000-8000-00000000000f"


async def _hunt_user(db_session, *, email: str, role: str):
    """An org-scoped caller: ``POST /agentic/hunts`` takes the organization,
    the actor id and the role straight off the JWT, so the default
    ``test_user`` fixture (no organization) cannot exercise it."""
    from src.core.security import get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, HUNT_ORG) is None:
        db_session.add(Organization(id=HUNT_ORG, name="HUNT-ORG", slug="hunt-org"))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=HUNT_ORG,
    )
    db_session.add(user)
    await db_session.flush()
    return user


def _hunt_headers(user) -> dict:
    from src.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


@pytest.mark.asyncio
async def test_endpoint_kicks_off_hunt(client, db_session):
    """The endpoint now passes the caller's identity through, so both hunt
    phases pass the policy gate and the hunt session is written for the
    caller's organization."""
    from src.attack.loader import load_stix_bundle

    await load_stix_bundle(db_session, _bundle(), domain="enterprise", attack_version="17.1")
    analyst = await _hunt_user(db_session, email="hunter@hunt-org.test", role="analyst")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/agentic/hunts",
        headers=_hunt_headers(analyst),
        json={"hypothesis": "hunt for T1110 brute force", "timeframe_hours": 24},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["hypothesis"]
    assert "phases" in body and "verdict" in body

    sessions = (await db_session.execute(select(HuntSession))).scalars().all()
    assert sessions, "the hunt must persist a hunt session"
    assert {s.organization_id for s in sessions} == {HUNT_ORG}


@pytest.mark.asyncio
async def test_endpoint_refuses_a_viewer(client, db_session):
    """``scope_hunt``/``run_threat_hunt`` write hunt sessions and findings, so
    a viewer cannot start a hunt."""
    from src.attack.loader import load_stix_bundle

    await load_stix_bundle(db_session, _bundle(), domain="enterprise", attack_version="17.1")
    viewer = await _hunt_user(db_session, email="viewer@hunt-org.test", role="viewer")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/agentic/hunts",
        headers=_hunt_headers(viewer),
        json={"hypothesis": "hunt for T1110 brute force", "timeframe_hours": 24},
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "role_not_permitted"
    assert (await db_session.execute(select(HuntSession))).scalars().all() == []


@pytest.mark.asyncio
async def test_endpoint_requires_hypothesis(client, auth_headers):
    resp = await client.post("/api/v1/agentic/hunts", headers=auth_headers, json={})
    assert resp.status_code == 422
