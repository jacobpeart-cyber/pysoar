"""``require_second_approver`` (AC-5 separation of duties) end to end.

Covers the pure quorum rule in ``src.agentic.policy``, the org setting
surface (``GET/PUT /settings/agentic-policy`` + audit), the two-step approval
flow on ``POST /agentic/actions/{id}/approve`` and the pending-approval
projection. Proposals are built with the helpers of the approval endpoint
tests so the hash binding is the real one.
"""
from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import func, select

from src.agentic.models import ActionExecutionStatus
from src.agentic.policy import (
    AGENTIC_POLICY_SECTION,
    OrgPolicySettings,
    evaluate_approval_quorum,
    load_org_policy_settings,
    org_policy_settings_from_section,
)
from src.agentic.toolspec import Tier
from src.audit_evidence.models import AuditTrail
from src.intel.models import ThreatIndicator
from src.models.settings import AppSetting
from tests.unit.test_agentic_approval_endpoints import (
    EMPTY_EVIDENCE_SHA,
    ORG_A,
    ORG_B,
    _approval_body,
    _orgs,
    _proposal,
    _token,
    _user,
)

ON = OrgPolicySettings(require_second_approver=True)
OFF = OrgPolicySettings()


# ---------------------------------------------------------------------------
# Pure rule
# ---------------------------------------------------------------------------


def test_quorum_off_by_default_executes_on_one_approval() -> None:
    assert OrgPolicySettings().require_second_approver is False
    q = evaluate_approval_quorum(OFF, tier=Tier.DESTRUCTIVE, approver_user_id="u1", proposer_user_id="u1", first_approved_by=None)
    assert q.outcome == "execute" and q.requires_second_approver is False


@pytest.mark.parametrize("tier", [Tier.READ, Tier.WRITE, None])
def test_quorum_ignores_non_destructive_tiers(tier: Tier | None) -> None:
    q = evaluate_approval_quorum(ON, tier=tier, approver_user_id="u1", proposer_user_id=None, first_approved_by=None)
    assert q.outcome == "execute" and q.requires_second_approver is False


@pytest.mark.parametrize("tier", [Tier.DESTRUCTIVE, Tier.PRIVILEGED])
def test_quorum_two_distinct_approvers(tier: Tier) -> None:
    first = evaluate_approval_quorum(ON, tier=tier, approver_user_id="a", proposer_user_id="p", first_approved_by=None)
    assert first.outcome == "record_first"
    same = evaluate_approval_quorum(ON, tier=tier, approver_user_id="a", proposer_user_id="p", first_approved_by="a")
    assert same.outcome == "deny" and same.reason_code == "second_approver_required"
    second = evaluate_approval_quorum(ON, tier=tier, approver_user_id="b", proposer_user_id="p", first_approved_by="a")
    assert second.outcome == "execute" and second.requires_second_approver is True


def test_quorum_proposer_never_counts() -> None:
    for first in (None, "a"):
        q = evaluate_approval_quorum(ON, tier=Tier.DESTRUCTIVE, approver_user_id="p", proposer_user_id="p", first_approved_by=first)
        assert q.outcome == "deny" and q.reason_code == "proposer_cannot_approve"


def test_quorum_refuses_anonymous_approver() -> None:
    q = evaluate_approval_quorum(ON, tier=Tier.DESTRUCTIVE, approver_user_id=None, proposer_user_id=None, first_approved_by=None)
    assert q.outcome == "deny"


def test_section_parsing_is_strict_boolean() -> None:
    assert org_policy_settings_from_section({"require_second_approver": True}).require_second_approver is True
    assert org_policy_settings_from_section({"require_second_approver": "true"}).require_second_approver is False
    assert org_policy_settings_from_section(None).require_second_approver is False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _enable(db, org_id: str = ORG_A, value: bool = True) -> None:
    db.add(AppSetting(organization_id=org_id, section=AGENTIC_POLICY_SECTION, value={"require_second_approver": value}))
    await db.flush()


async def _approve(client, db, user, action, **extra: Any):
    # An error response rolls the shared session back and expires loaded rows;
    # reload them asynchronously before reading attributes.
    await db.refresh(user)
    await db.refresh(action)
    return await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(user),
        json=_approval_body(action, **extra),
    )


async def _ioc_count(db) -> int:
    return int((await db.execute(select(func.count()).select_from(ThreatIndicator))).scalar() or 0)


async def _audit_actions(db, org_id: str = ORG_A) -> list[str]:
    rows = (await db.execute(select(AuditTrail.action).where(AuditTrail.organization_id == org_id))).all()
    return [a for (a,) in rows]


# ---------------------------------------------------------------------------
# Org settings surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_settings_default_off_and_admin_can_enable_with_audit(client, db_session):
    await _orgs(db_session)
    admin = await _user(db_session, email="sod-admin@org-c.test", role="admin")
    await db_session.commit()

    resp = await client.get("/api/v1/settings/agentic-policy", headers=_token(admin))
    assert resp.status_code == 200, resp.text
    assert resp.json()["require_second_approver"] is False

    resp = await client.put(
        "/api/v1/settings/agentic-policy", headers=_token(admin), json={"require_second_approver": True},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["require_second_approver"] is True
    assert resp.json()["updated_by"] == admin.id

    resp = await client.get("/api/v1/settings/agentic-policy", headers=_token(admin))
    assert resp.json()["require_second_approver"] is True
    assert (await load_org_policy_settings(db_session, ORG_A)).require_second_approver is True
    # Scoped to the organization: the other tenant is untouched.
    assert (await load_org_policy_settings(db_session, ORG_B)).require_second_approver is False

    audit = (await db_session.execute(
        select(AuditTrail).where(AuditTrail.organization_id == ORG_A, AuditTrail.action == "agentic_policy.set"),
    )).scalars().all()
    assert len(audit) == 1
    assert audit[0].actor_id == admin.id

    resp = await client.put(
        "/api/v1/settings/agentic-policy", headers=_token(admin), json={"require_second_approver": False},
    )
    assert resp.status_code == 200
    assert resp.json()["require_second_approver"] is False
    assert (await load_org_policy_settings(db_session, ORG_A)).require_second_approver is False


@pytest.mark.asyncio
async def test_settings_rejects_analyst_and_unknown_keys(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="sod-analyst@org-c.test", role="analyst")
    admin = await _user(db_session, email="sod-admin2@org-c.test", role="admin")
    await db_session.commit()
    analyst_auth, admin_auth = _token(analyst), _token(admin)

    assert (await client.get("/api/v1/settings/agentic-policy", headers=analyst_auth)).status_code == 403
    resp = await client.put(
        "/api/v1/settings/agentic-policy", headers=analyst_auth, json={"require_second_approver": False},
    )
    assert resp.status_code == 403
    resp = await client.put(
        "/api/v1/settings/agentic-policy",
        headers=admin_auth,
        json={"require_second_approver": True, "autonomous_allowlist": ["block_ip"]},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Approval flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_setting_keeps_single_approval(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="sod-single@org-c.test", role="analyst")
    action = await _proposal(db_session, proposed_by=analyst.id)
    await db_session.commit()

    resp = await _approve(client, db_session, analyst, action)
    assert resp.status_code == 200, resp.text
    assert resp.json()["executed"] is True
    assert resp.json()["approvals_required"] == 1
    assert await _ioc_count(db_session) == 1


@pytest.mark.asyncio
async def test_two_distinct_approvers_execute_once(client, db_session):
    await _orgs(db_session)
    await _enable(db_session)
    proposer = await _user(db_session, email="sod-proposer@org-c.test", role="analyst")
    first = await _user(db_session, email="sod-first@org-c.test", role="analyst")
    second = await _user(db_session, email="sod-second@org-c.test", role="analyst")
    action = await _proposal(db_session, proposed_by=proposer.id)
    await db_session.commit()
    first_id, second_id = first.id, second.id

    resp = await _approve(client, db_session, first, action, reason="confirmed")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "awaiting_second_approval"
    assert body["executed"] is False
    assert body["first_approved_by"] == first_id
    assert body["approvals_received"] == 1 and body["approvals_required"] == 2
    assert await _ioc_count(db_session) == 0

    await db_session.refresh(action)
    assert action.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value
    assert action.first_approved_by == first_id
    assert action.first_approved_at is not None
    assert action.first_approver_role == "analyst"
    assert action.approved_by is None

    # The first approver cannot supply the second approval.
    resp = await _approve(client, db_session, first, action)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "second_approver_required"
    assert await _ioc_count(db_session) == 0

    # The second approval must still echo the hash binding.
    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(second),
        json={"approved": True, "params_sha256": "0" * 64, "evidence_sha256": EMPTY_EVIDENCE_SHA},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "approval_stale"
    assert await _ioc_count(db_session) == 0

    resp = await _approve(client, db_session, second, action)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "approved" and body["executed"] is True
    assert body["approvals_required"] == 2
    assert body["first_approved_by"] == first_id
    assert await _ioc_count(db_session) == 1

    await db_session.refresh(action)
    assert action.execution_status == ActionExecutionStatus.COMPLETED.value
    assert action.approved_by == second_id
    assert action.first_approved_by == first_id
    assert action.rollback_available is True

    actions = await _audit_actions(db_session)
    assert "action.first_approval" in actions
    assert "action.second_approval" in actions
    assert "action.approval_refused" in actions
    assert "tool.executed" in actions

    # Executed: a further approval is no longer possible.
    resp = await _approve(client, db_session, proposer, action)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_proposer_cannot_approve_when_enabled(client, db_session):
    await _orgs(db_session)
    await _enable(db_session)
    proposer = await _user(db_session, email="sod-self@org-c.test", role="analyst")
    other = await _user(db_session, email="sod-other@org-c.test", role="analyst")
    action = await _proposal(db_session, proposed_by=proposer.id)
    await db_session.commit()

    resp = await _approve(client, db_session, proposer, action)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "proposer_cannot_approve"

    # Nor as the second approver.
    assert (await _approve(client, db_session, other, action)).json()["status"] == "awaiting_second_approval"
    resp = await _approve(client, db_session, proposer, action)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "proposer_cannot_approve"
    assert await _ioc_count(db_session) == 0

    await db_session.refresh(action)
    assert action.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value


@pytest.mark.asyncio
async def test_proposer_may_still_deny_when_enabled(client, db_session):
    await _orgs(db_session)
    await _enable(db_session)
    proposer = await _user(db_session, email="sod-withdraw@org-c.test", role="analyst")
    action = await _proposal(db_session, proposed_by=proposer.id)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/agentic/actions/{action.id}/approve",
        headers=_token(proposer),
        json={"approved": False, "reason": "withdrawn"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "denied"


@pytest.mark.asyncio
async def test_setting_of_another_org_does_not_apply(client, db_session):
    await _orgs(db_session)
    await _enable(db_session, org_id=ORG_B)
    analyst = await _user(db_session, email="sod-orga@org-c.test", role="analyst")
    action = await _proposal(db_session, proposed_by=analyst.id)
    await db_session.commit()

    resp = await _approve(client, db_session, analyst, action)
    assert resp.status_code == 200, resp.text
    assert resp.json()["executed"] is True


@pytest.mark.asyncio
async def test_suspect_with_second_approver_needs_two_admin_acknowledgements(client, db_session):
    await _orgs(db_session)
    await _enable(db_session)
    analyst = await _user(db_session, email="sod-sus-analyst@org-c.test", role="analyst")
    admin1 = await _user(db_session, email="sod-sus-admin1@org-c.test", role="admin")
    admin2 = await _user(db_session, email="sod-sus-admin2@org-c.test", role="admin")
    action = await _proposal(db_session, suspect=True, injection_tier="flagged")
    await db_session.commit()

    ack = {"acknowledge_suspect": True, "reason": "raw alert re-read; injected text is irrelevant"}

    # The suspect rule still applies on top: an analyst cannot even record the first approval.
    resp = await _approve(client, db_session, analyst, action, reason="fine")
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "suspect_action_requires_reinvestigation"

    resp = await _approve(client, db_session, admin1, action, **ack)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "awaiting_second_approval"

    # The second admin must also acknowledge with a reason.
    resp = await _approve(client, db_session, admin2, action)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "suspect_action_requires_reinvestigation"
    assert await _ioc_count(db_session) == 0

    resp = await _approve(client, db_session, admin2, action, **ack)
    assert resp.status_code == 200, resp.text
    assert resp.json()["executed"] is True
    assert await _ioc_count(db_session) == 1
    assert (await _audit_actions(db_session)).count("suspect.approved") == 2


@pytest.mark.asyncio
async def test_expiry_between_approvals_blocks_the_second(client, db_session):
    from datetime import datetime, timedelta, timezone

    await _orgs(db_session)
    await _enable(db_session)
    first = await _user(db_session, email="sod-exp1@org-c.test", role="analyst")
    second = await _user(db_session, email="sod-exp2@org-c.test", role="analyst")
    action = await _proposal(db_session)
    await db_session.commit()

    assert (await _approve(client, db_session, first, action)).json()["status"] == "awaiting_second_approval"
    await db_session.refresh(action)
    action.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()

    resp = await _approve(client, db_session, second, action)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "approval_expired"
    assert await _ioc_count(db_session) == 0


# ---------------------------------------------------------------------------
# Pending-approval projection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_projection_carries_second_approver_state(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="sod-list@org-c.test", role="analyst")
    first = await _user(db_session, email="sod-list-first@org-c.test", role="analyst")
    action = await _proposal(db_session)
    await db_session.commit()

    resp = await client.get("/api/v1/agentic/actions/pending-approval", headers=_token(analyst))
    assert resp.status_code == 200, resp.text
    row = next(i for i in resp.json()["items"] if i["action_id"] == action.id)
    assert row["requires_second_approver"] is False
    assert row["first_approved_by"] is None and row["first_approved_at"] is None

    await _enable(db_session)
    await db_session.commit()
    assert (await _approve(client, db_session, first, action)).json()["status"] == "awaiting_second_approval"

    resp = await client.get("/api/v1/agentic/actions/pending-approval", headers=_token(analyst))
    row = next(i for i in resp.json()["items"] if i["action_id"] == action.id)
    assert row["requires_second_approver"] is True
    assert row["first_approved_by"] == first.id
    assert row["first_approved_at"] is not None
