"""Approval, direct execute and rollback surfaces (work package 5A).

Design v2 section 8 at the HTTP boundary: an approval is bound by hash to
the proposal, expired or suspect proposals are refused, execution goes
through ``AgentToolRegistry.call`` with the approver as actor (so the audit
pair is written), a destructive tool invoked directly is *proposed* rather
than executed, and a rollback reverses only the forward-effect ids the
execution recorded.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest
from sqlalchemy import func, select

from src.agentic.models import (
    ActionExecutionStatus,
    AgentAction,
    Investigation,
    InvestigationStatus,
    SOCAgent,
)
from src.agentic.policy import canonical_json
from src.audit_evidence.models import AuditTrail
from src.core.security import get_password_hash
from src.intel.models import ThreatIndicator
from src.models.organization import Organization
from src.models.user import User

ORG_A = "cccccccc-0000-4000-8000-000000000003"
ORG_B = "dddddddd-0000-4000-8000-000000000004"

EMPTY_EVIDENCE_SHA = hashlib.sha256(b"").hexdigest()


def _token(user: User) -> dict[str, str]:
    from src.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


def _params_sha(tool: str, args: dict[str, Any]) -> str:
    """The same binding the runtime computes when it materializes a proposal."""
    return hashlib.sha256(canonical_json({"tool": tool, "args": args}).encode("utf-8")).hexdigest()


async def _orgs(db) -> None:
    for org_id, slug in ((ORG_A, "org-c"), (ORG_B, "org-d")):
        if await db.get(Organization, org_id) is None:
            db.add(Organization(id=org_id, name=slug.upper(), slug=slug))
    await db.flush()


async def _user(db, *, email: str, role: str, org_id: str = ORG_A, superuser: bool = False) -> User:
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        is_superuser=superuser,
        organization_id=org_id,
    )
    db.add(user)
    await db.flush()
    return user


async def _investigation(db, org_id: str = ORG_A) -> Investigation:
    agent = SOCAgent(
        organization_id=org_id, name="Tier-1 triage", agent_type="triage_analyst", llm_model="fake-1",
    )
    db.add(agent)
    await db.flush()
    investigation = Investigation(
        organization_id=org_id,
        agent_id=agent.id,
        trigger_type="chat",
        title="Brute force from 198.51.100.24",
        status=InvestigationStatus.REASONING.value,
    )
    db.add(investigation)
    await db.flush()
    return investigation


async def _proposal(
    db,
    *,
    org_id: str = ORG_A,
    tool: str = "block_ip",
    args: Optional[dict[str, Any]] = None,
    suspect: bool = False,
    injection_tier: Optional[str] = None,
    expires_in_hours: Optional[float] = 72,
    proposed_by: Optional[str] = None,
) -> AgentAction:
    args = args if args is not None else {"ip": "198.51.100.24", "reason": "brute force source"}
    investigation = await _investigation(db, org_id)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
        if expires_in_hours is not None else None
    )
    action = AgentAction(
        organization_id=org_id,
        investigation_id=investigation.id,
        action_type=tool,
        target=str(args.get("ip") or args.get("hostname") or tool),
        parameters=args,
        requires_approval=True,
        execution_status=ActionExecutionStatus.PENDING_APPROVAL.value,
        rollback_available=False,
        run_id="run-test-1",
        tool_name=tool,
        proposed_by_user_id=proposed_by,
        source="chat",
        params_sha256=_params_sha(tool, args),
        evidence_sha256=EMPTY_EVIDENCE_SHA,
        effective_targets=[{"kind": "ip", "value": args.get("ip"), "resolved_id": None, "provenance": "structured"}],
        suspect=suspect,
        injection_tier=injection_tier,
        expires_at=expires_at,
    )
    db.add(action)
    await db.flush()
    return action


def _approval_body(action: AgentAction, **extra: Any) -> dict[str, Any]:
    body = {
        "approved": True,
        "params_sha256": action.params_sha256,
        "evidence_sha256": action.evidence_sha256,
    }
    body.update(extra)
    return body


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_executes_through_the_registry_and_audits(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="approver@org-c.test", role="analyst")
    action = await _proposal(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(analyst),
        json=_approval_body(action, reason="confirmed brute force"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is True
    assert body["execution_status"] == ActionExecutionStatus.COMPLETED.value
    assert body["result"]["ip"] == "198.51.100.24"

    await db_session.refresh(action)
    assert action.execution_status == ActionExecutionStatus.COMPLETED.value
    assert action.approved_by == analyst.id
    assert action.approver_role == "analyst"
    assert action.rollback_available is True

    # The forward effect really happened: an active blocked indicator.
    ioc = (await db_session.execute(
        select(ThreatIndicator).where(ThreatIndicator.organization_id == ORG_A)
    )).scalars().one()
    assert ioc.value == "198.51.100.24"
    assert ioc.is_active is True

    # Both audit events were written for the approved tool call.
    rows = (await db_session.execute(
        select(AuditTrail.event_type, AuditTrail.action).where(AuditTrail.organization_id == ORG_A)
    )).all()
    pairs = {(e, a) for e, a in rows}
    assert ("agent_policy", "tool.allow") in pairs
    assert ("agent_tool", "tool.executed") in pairs


@pytest.mark.asyncio
async def test_approve_with_stale_hash_is_409(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="approver2@org-c.test", role="analyst")
    action = await _proposal(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(analyst),
        json={"approved": True, "params_sha256": "0" * 64, "evidence_sha256": EMPTY_EVIDENCE_SHA},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "approval_stale"
    assert (await db_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar() == 0


@pytest.mark.asyncio
async def test_approve_without_hashes_is_rejected_by_validation(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="approver3@org-c.test", role="analyst")
    action = await _proposal(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(analyst),
        json={"approved": True},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_expired_proposal_is_409(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="approver4@org-c.test", role="analyst")
    action = await _proposal(db_session, expires_in_hours=-1)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(analyst),
        json=_approval_body(action),
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "approval_expired"


@pytest.mark.asyncio
async def test_suspect_proposal_needs_an_admin_acknowledgement(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="approver5@org-c.test", role="analyst")
    action = await _proposal(db_session, suspect=True, injection_tier="flagged")
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(analyst),
        json=_approval_body(action, reason="looks fine to me"),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "suspect_action_requires_reinvestigation"
    assert (await db_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar() == 0


@pytest.mark.asyncio
async def test_admin_can_acknowledge_a_suspect_proposal_with_a_reason(client, db_session):
    await _orgs(db_session)
    admin = await _user(db_session, email="admin@org-c.test", role="admin")
    action = await _proposal(db_session, suspect=True, injection_tier="flagged")
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(admin),
        json=_approval_body(
            action,
            acknowledge_suspect=True,
            reason="re-read the raw alert; the injected text does not change the verdict",
        ),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["executed"] is True
    assert (await db_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar() == 1

    actions = {a for (_, a) in (await db_session.execute(
        select(AuditTrail.event_type, AuditTrail.action).where(AuditTrail.organization_id == ORG_A)
    )).all()}
    assert "suspect.approved" in actions


@pytest.mark.asyncio
async def test_viewer_cannot_approve(client, db_session):
    await _orgs(db_session)
    viewer = await _user(db_session, email="viewer@org-c.test", role="viewer")
    action = await _proposal(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(viewer),
        json=_approval_body(action),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "role_not_permitted"


@pytest.mark.asyncio
async def test_cross_tenant_action_is_not_found(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="approver6@org-c.test", role="analyst")
    action = await _proposal(db_session, org_id=ORG_B)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(analyst),
        json=_approval_body(action),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_denial_records_the_decision_without_executing(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="approver7@org-c.test", role="analyst")
    action = await _proposal(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(analyst),
        json={"approved": False, "reason": "the source is a known scanner"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "denied"
    await db_session.refresh(action)
    assert action.execution_status == ActionExecutionStatus.DENIED.value
    assert action.approval_reason == "the source is a known scanner"
    assert (await db_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar() == 0


# ---------------------------------------------------------------------------
# Direct tool execute
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_direct_destructive_execute_returns_a_proposal(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="direct@org-c.test", role="analyst")
    db_session.add(SOCAgent(
        organization_id=ORG_A, name="Tier-1 triage", agent_type="triage_analyst", llm_model="fake-1",
    ))
    await db_session.commit()

    resp = await client.post(
        "/api/v1/agentic/tools/block_ip/execute",
        headers=_token(analyst),
        json={"params": {"ip": "203.0.113.19", "reason": "c2 callback"}, "propose_actions": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposed"] is True
    assert body["executed"] is False
    assert body["proposal"]["tool"] == "block_ip"

    action = (await db_session.execute(select(AgentAction))).scalars().one()
    assert action.tool_name == "block_ip"
    assert action.requires_approval is True
    assert action.params_sha256 == body["proposal"]["params_sha256"]
    # The tool did not run: no indicator exists.
    assert (await db_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar() == 0


@pytest.mark.asyncio
async def test_direct_destructive_execute_without_propose_is_denied(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="direct2@org-c.test", role="analyst")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/agentic/tools/block_ip/execute",
        headers=_token(analyst),
        json={"ip": "203.0.113.19", "reason": "c2 callback"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason_code"] == "proposal_disabled"


@pytest.mark.asyncio
async def test_viewer_can_execute_a_read_tool_directly(client, db_session):
    await _orgs(db_session)
    viewer = await _user(db_session, email="viewer2@org-c.test", role="viewer")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/agentic/tools/list_alerts/execute",
        headers=_token(viewer),
        json={"limit": 5},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is True
    assert body["tool"] == "list_alerts"


@pytest.mark.asyncio
async def test_unknown_tool_is_404(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="direct3@org-c.test", role="analyst")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/agentic/tools/definitely_not_a_tool/execute",
        headers=_token(analyst),
        json={},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "unknown_tool"


@pytest.mark.asyncio
async def test_tool_listing_is_role_scoped(client, db_session):
    await _orgs(db_session)
    viewer = await _user(db_session, email="viewer3@org-c.test", role="viewer")
    analyst = await _user(db_session, email="direct4@org-c.test", role="analyst")
    await db_session.commit()

    viewer_tools = (await client.get("/api/v1/agentic/tools", headers=_token(viewer))).json()
    analyst_tools = (await client.get("/api/v1/agentic/tools", headers=_token(analyst))).json()
    viewer_names = {t["name"] for t in viewer_tools["tools"]}
    analyst_names = {t["name"] for t in analyst_tools["tools"]}
    assert "list_alerts" in viewer_names
    assert "block_ip" not in viewer_names
    assert "block_ip" in analyst_names
    assert all({"name", "description", "parameters", "tier", "min_role"} <= set(t) for t in analyst_tools["tools"])


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_deactivates_the_recorded_indicator(client, db_session):
    import json

    await _orgs(db_session)
    analyst = await _user(db_session, email="rollback@org-c.test", role="analyst")
    action = await _proposal(db_session)
    ioc = ThreatIndicator(
        value="198.51.100.24", indicator_type="ipv4", severity="high", is_active=True,
        is_whitelisted=False, source="agent_block", confidence=80, organization_id=ORG_A,
    )
    db_session.add(ioc)
    await db_session.flush()
    action.execution_status = ActionExecutionStatus.COMPLETED.value
    action.rollback_available = True
    action.result = json.dumps(
        {"ip": "198.51.100.24", "status": "recorded", "mode": "detection_only", "ioc_id": ioc.id,
         "agent_commands": []}
    )
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/rollback", headers=_token(analyst),
    )
    assert resp.status_code == 200, resp.text
    detail = resp.json()["detail"]
    assert detail["reversed"]["indicator_deactivated"] == ioc.id

    await db_session.refresh(ioc)
    await db_session.refresh(action)
    assert ioc.is_active is False
    assert action.rollback_executed is True
    assert action.execution_status == ActionExecutionStatus.ROLLED_BACK.value


@pytest.mark.asyncio
async def test_rollback_without_recorded_effects_is_refused(client, db_session):
    import json

    await _orgs(db_session)
    analyst = await _user(db_session, email="rollback2@org-c.test", role="analyst")
    action = await _proposal(db_session)
    action.execution_status = ActionExecutionStatus.COMPLETED.value
    action.result = json.dumps({"status": "recorded", "note": "nothing with an id"})
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/rollback", headers=_token(analyst),
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "not_reversible"


@pytest.mark.asyncio
async def test_viewer_cannot_rollback(client, db_session):
    await _orgs(db_session)
    viewer = await _user(db_session, email="viewer4@org-c.test", role="viewer")
    action = await _proposal(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/rollback", headers=_token(viewer),
    )
    assert resp.status_code == 403
