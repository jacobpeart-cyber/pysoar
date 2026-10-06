"""POST /itdr/threats/{id}/respond runs on the guarded runtime (work package 5B).

The ITDR response surface used to call ``AgentToolRegistry.execute``
directly, which bypassed the policy gate entirely (F14). It now shares one
implementation with ``POST /agentic/tools/{tool_name}/execute``
(``guarded_tool_call``), so a destructive response is *proposed* for
approval instead of executed, viewers are refused, a policy denial carries
its reason code, and another tenant's threat is a 404.
"""
from __future__ import annotations

from typing import Any, Optional

import pytest
from sqlalchemy import func, select

from src.agentic.models import ActionExecutionStatus, AgentAction, SOCAgent
from src.core.security import get_password_hash
from src.intel.models import ThreatIndicator
from src.itdr.models import IdentityProfile, IdentityThreat
from src.models.asset import Asset
from src.models.incident import Incident
from src.models.organization import Organization
from src.models.user import User

ORG_A = "11111111-0000-4000-8000-00000000000a"
ORG_B = "22222222-0000-4000-8000-00000000000b"


def _token(user: User) -> dict[str, str]:
    from src.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _orgs(db) -> None:
    for org_id, slug in ((ORG_A, "itdr-org-a"), (ORG_B, "itdr-org-b")):
        if await db.get(Organization, org_id) is None:
            db.add(Organization(id=org_id, name=slug.upper(), slug=slug))
    await db.flush()


async def _user(db, *, email: str, role: str, org_id: str = ORG_A) -> User:
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=org_id,
    )
    db.add(user)
    await db.flush()
    return user


async def _soc_agent(db, org_id: str = ORG_A) -> SOCAgent:
    """Proposals are recorded against a SOC agent's investigation."""
    agent = SOCAgent(
        organization_id=org_id,
        name="ITDR responder",
        agent_type="triage_analyst",
        llm_model="fake-1",
    )
    db.add(agent)
    await db.flush()
    return agent


async def _threat(
    db,
    *,
    org_id: str = ORG_A,
    with_identity: bool = True,
    source_ip: Optional[str] = "198.51.100.77",
) -> IdentityThreat:
    identity_id = None
    if with_identity:
        identity = IdentityProfile(
            organization_id=org_id,
            user_id="svc-backup",
            username="svc-backup",
            email="svc-backup@org-a.test",
            privilege_level="standard",
        )
        db.add(identity)
        await db.flush()
        identity_id = identity.id
    threat = IdentityThreat(
        organization_id=org_id,
        identity_id=identity_id,
        threat_type="credential_stuffing",
        severity="high",
        confidence_score=82.0,
        source_ip=source_ip,
        status="detected",
        evidence="48 failed authentications in 6 minutes",
    )
    db.add(threat)
    await db.flush()
    return threat


def _body(action: str, **details: Any) -> dict[str, Any]:
    return {"action_type": action, "action_details": details}


# ---------------------------------------------------------------------------
# Destructive -> proposal, never execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_ip_is_proposed_not_executed(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="responder@org-a.test", role="analyst")
    await _soc_agent(db_session)
    threat = await _threat(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{threat.id}/respond",
        headers=_token(analyst),
        json=_body("block_ip", ip="198.51.100.77", propose_actions=True),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposed"] is True
    assert body["executed"] is False
    assert body["status"] == "proposed"
    proposal = body["proposal"]
    assert proposal["tool"] == "block_ip"
    assert proposal["params_sha256"]
    assert proposal["id"]

    # The proposal is a real pending-approval row...
    action = (await db_session.execute(select(AgentAction))).scalars().one()
    assert action.organization_id == ORG_A
    assert action.tool_name == "block_ip"
    assert action.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value
    assert action.requires_approval is True
    # ...and nothing was blocked: no indicator, threat not claimed contained.
    assert (await db_session.execute(
        select(func.count()).select_from(ThreatIndicator)
    )).scalar() == 0
    await db_session.refresh(threat)
    assert threat.status == "detected"


@pytest.mark.asyncio
async def test_block_ip_without_propose_actions_is_denied_with_reason_code(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="responder2@org-a.test", role="analyst")
    await _soc_agent(db_session)
    threat = await _threat(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{threat.id}/respond",
        headers=_token(analyst),
        json=_body("block_ip", ip="198.51.100.77"),
    )
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "policy_denied"
    assert detail["reason_code"]
    assert (await db_session.execute(
        select(func.count()).select_from(ThreatIndicator)
    )).scalar() == 0


@pytest.mark.asyncio
async def test_quarantine_proposes_every_destructive_tool(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="responder3@org-a.test", role="analyst")
    # Both tools resolve their target inside the organization: ``disable_user``
    # by user email, ``isolate_host`` by asset hostname.
    await _user(db_session, email="svc-backup@org-a.test", role="viewer")
    db_session.add(Asset(organization_id=ORG_A, name="dc-01", hostname="dc-01"))
    await db_session.flush()
    await _soc_agent(db_session)
    threat = await _threat(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{threat.id}/respond",
        headers=_token(analyst),
        json=_body("quarantine", hostname="dc-01", propose_actions=True),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposed"] is True
    assert [p["tool"] for p in body["proposals"]] == ["disable_user", "isolate_host"]
    tools = {
        row.tool_name
        for row in (await db_session.execute(select(AgentAction))).scalars().all()
    }
    assert tools == {"disable_user", "isolate_host"}


# ---------------------------------------------------------------------------
# Role gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_respond(client, db_session):
    await _orgs(db_session)
    viewer = await _user(db_session, email="viewer@org-a.test", role="viewer")
    await _soc_agent(db_session)
    threat = await _threat(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{threat.id}/respond",
        headers=_token(viewer),
        json=_body("block_ip", ip="198.51.100.77", propose_actions=True),
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "role_not_permitted"
    assert (await db_session.execute(select(func.count()).select_from(AgentAction))).scalar() == 0


# ---------------------------------------------------------------------------
# Non-destructive path still works
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_incident_executes_through_the_policy_gate(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="responder4@org-a.test", role="analyst")
    threat = await _threat(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{threat.id}/respond",
        headers=_token(analyst),
        json=_body("open_incident"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is True
    assert body["proposed"] is False
    assert body["results"][0]["tool"] == "create_incident"

    incidents = (await db_session.execute(select(Incident))).scalars().all()
    assert len(incidents) == 1
    await db_session.refresh(threat)
    assert threat.status == "contained"


@pytest.mark.asyncio
async def test_contain_marks_the_threat_without_claiming_a_tool_ran(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="responder5@org-a.test", role="analyst")
    threat = await _threat(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{threat.id}/respond",
        headers=_token(analyst),
        json=_body("contain"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "marked_contained"
    assert body["results"] == []
    assert body["executed"] is False


@pytest.mark.asyncio
async def test_missing_required_argument_is_a_400(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="responder6@org-a.test", role="analyst")
    threat = await _threat(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{threat.id}/respond",
        headers=_token(analyst),
        json=_body("isolate_host", propose_actions=True),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["error"] == "invalid_arguments"


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_other_organizations_threat_is_a_404(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="responder7@org-a.test", role="analyst")
    await _soc_agent(db_session)
    other = await _threat(db_session, org_id=ORG_B, with_identity=False)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/itdr/threats/{other.id}/respond",
        headers=_token(analyst),
        json=_body("block_ip", ip="198.51.100.77", propose_actions=True),
    )
    assert resp.status_code == 404, resp.text
    assert (await db_session.execute(select(func.count()).select_from(AgentAction))).scalar() == 0
