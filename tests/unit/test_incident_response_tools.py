"""Incident-response tools for the Agentic SOC — work an incident like a
real SOC analyst (NIST 800-61 lifecycle).

Before this, the chat agent could list/read incidents but had ZERO tools
to act on them — so "remediate the open incidents" was impossible and it
looped on clarifying questions. These give it the analyst lifecycle:
assign -> drive status (investigating -> containment -> ... -> closed) ->
document findings -> orchestrate real containment actions.
"""

import json

import pytest
from sqlalchemy import select

from src.models.incident import Incident, IncidentStatus
from src.models.case import CaseNote, CaseTimeline
from src.models.asset import Asset
from src.intel.models import ThreatIndicator


async def _seed_incident(db, org="org-1", **kw):
    fields = dict(
        title="Ransomware encryption burst on file-share-01",
        description="Mass file encryption detected",
        severity="critical",
        status="open",
        incident_type="ransomware",
        organization_id=org,
        affected_systems=json.dumps(["file-share-01", "file-share-02"]),
        indicators=json.dumps(["203.0.113.50", "198.51.100.9"]),
    )
    fields.update(kw)
    inc = Incident(**fields)
    db.add(inc)
    await db.commit()
    await db.refresh(inc)
    return inc


@pytest.mark.asyncio
async def test_update_incident_status_drives_lifecycle(db_session):
    from src.services.agent_tools import AgentToolRegistry
    inc = await _seed_incident(db_session)
    reg = AgentToolRegistry(db_session)

    out = await reg.execute("update_incident_status", {
        "incident_id": inc.id, "status": "containment", "note": "isolating hosts",
    })
    assert out["success"] is True
    await db_session.refresh(inc)
    assert inc.status == "containment"
    # a timeline entry records the transition (old -> new)
    tl = (await db_session.execute(
        select(CaseTimeline).where(CaseTimeline.incident_id == inc.id)
    )).scalars().all()
    assert any(t.old_value == "open" and t.new_value == "containment" for t in tl)


@pytest.mark.asyncio
async def test_update_incident_status_rejects_invalid(db_session):
    from src.services.agent_tools import AgentToolRegistry
    inc = await _seed_incident(db_session)
    out = await AgentToolRegistry(db_session).execute("update_incident_status", {
        "incident_id": inc.id, "status": "banana",
    })
    assert out["success"] is True
    assert "error" in out["result"]
    assert "valid" in out["result"]["error"].lower()


@pytest.mark.asyncio
async def test_assign_incident_by_email(db_session):
    from src.services.agent_tools import AgentToolRegistry
    from src.models.user import User
    from src.core.security import get_password_hash
    u = User(email="analyst@corp.com", hashed_password=get_password_hash("x"),
             full_name="Analyst", role="analyst", is_active=True, organization_id="org-1")
    db_session.add(u)
    inc = await _seed_incident(db_session)
    await db_session.commit()

    out = await AgentToolRegistry(db_session).execute("assign_incident", {
        "incident_id": inc.id, "assignee": "analyst@corp.com",
    })
    assert out["success"] is True
    await db_session.refresh(inc)
    assert inc.assigned_to == u.id


@pytest.mark.asyncio
async def test_add_incident_note(db_session):
    from src.services.agent_tools import AgentToolRegistry
    inc = await _seed_incident(db_session)
    out = await AgentToolRegistry(db_session).execute("add_incident_note", {
        "incident_id": inc.id, "note": "Confirmed lateral movement from file-share-01",
    })
    assert out["success"] is True
    notes = (await db_session.execute(
        select(CaseNote).where(CaseNote.incident_id == inc.id)
    )).scalars().all()
    assert any("lateral movement" in n.content for n in notes)


@pytest.mark.asyncio
async def test_update_incident_findings(db_session):
    from src.services.agent_tools import AgentToolRegistry
    inc = await _seed_incident(db_session)
    out = await AgentToolRegistry(db_session).execute("update_incident_findings", {
        "incident_id": inc.id,
        "root_cause": "Phishing -> Cobalt Strike -> SMB spread",
        "resolution": "Hosts reimaged, creds reset",
        "lessons_learned": "Enforce MFA on file shares",
    })
    assert out["success"] is True
    await db_session.refresh(inc)
    assert "Cobalt Strike" in inc.root_cause
    assert "reimaged" in inc.resolution


@pytest.mark.asyncio
async def test_remediate_incident_orchestrates_real_containment(db_session):
    from src.services.agent_tools import AgentToolRegistry
    inc = await _seed_incident(db_session)
    reg = AgentToolRegistry(db_session)

    out = await reg.execute("remediate_incident", {"incident_id": inc.id})
    assert out["success"] is True
    r = out["result"]
    # isolated both affected hosts + blocked both indicators (real actions)
    assert set(r["hosts_isolated"]) == {"file-share-01", "file-share-02"}
    assert set(r["indicators_blocked"]) == {"203.0.113.50", "198.51.100.9"}
    # real IOCs were created for the blocked IPs
    iocs = (await db_session.execute(
        select(ThreatIndicator).where(ThreatIndicator.source == "agent_block")
    )).scalars().all()
    assert {i.value for i in iocs} == {"203.0.113.50", "198.51.100.9"}
    # incident advanced to containment
    await db_session.refresh(inc)
    assert inc.status == "containment"


@pytest.mark.asyncio
async def test_remediate_incident_honest_when_nothing_to_act_on(db_session):
    from src.services.agent_tools import AgentToolRegistry
    inc = await _seed_incident(db_session, affected_systems=None, indicators=None)
    out = await AgentToolRegistry(db_session).execute("remediate_incident", {"incident_id": inc.id})
    assert out["success"] is True
    r = out["result"]
    assert r["hosts_isolated"] == [] and r["indicators_blocked"] == []
    assert "no " in r["summary"].lower() or "manual" in r["summary"].lower()


@pytest.mark.asyncio
async def test_list_assets_filters_by_criticality(db_session):
    from src.services.agent_tools import AgentToolRegistry
    db_session.add_all([
        Asset(name="dc-01", hostname="dc-01", asset_type="server", criticality="critical", status="active", organization_id="org-1"),
        Asset(name="ws-09", hostname="ws-09", asset_type="workstation", criticality="low", status="active", organization_id="org-1"),
    ])
    await db_session.commit()

    out = await AgentToolRegistry(db_session).execute("list_assets", {"criticality": "critical"})
    assert out["success"] is True
    names = {a["name"] for a in out["result"]}
    assert "dc-01" in names and "ws-09" not in names
