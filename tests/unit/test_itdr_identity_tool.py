"""The guarded ``identity_provider_action`` agent tool (ITDR directory actions).

Identity-provider actions (Okta / Entra ID) run only through the agentic
policy gate: an analyst or the ITDR respond route gets a *proposal* naming
``identity_provider_action`` with its stored parameters, and the provider is
called only when an approver executes that proposal, which reaches
``src.itdr.directory.run_identity_action`` with the stored identity and action
(never the PySOAR login account). Another tenant's identity, an unsupported
action and an unattended context are all refused without a provider call.

The provider is mocked at the HTTP boundary with the same helpers W3-C uses
(httpx MockTransport behind the real DNS-pinning guard).
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.context import AgentContext, Mode, UserRole
from src.agentic.models import AgentAction
from src.itdr import directory
from src.itdr.models import IdentityProfile, IdentityThreat
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.services.agent_tools import AgentToolRegistry
from tests.helpers.tenancy import bearer, make_user
from tests.unit.test_tool_spec_invariants import run_tool
from tests.unit.test_wave3_itdr import _dns, _idp, _okta_handler, _okta_integration, _responder

ITDR = "/api/v1/itdr"
AGENTIC = "/api/v1/agentic"
TOOL = "identity_provider_action"


def _spy(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record every ``run_identity_action`` call while keeping the real behaviour."""
    seen: list[dict[str, Any]] = []
    real = directory.run_identity_action

    async def wrapper(db, org_id, identity, action, *, actor_user_id, reason):
        seen.append({
            "org_id": org_id, "identity_id": identity.id, "action": action,
            "actor_user_id": actor_user_id, "reason": reason,
        })
        return await real(db, org_id, identity, action, actor_user_id=actor_user_id, reason=reason)

    monkeypatch.setattr(directory, "run_identity_action", wrapper)
    return seen


async def _okta_identity(db: AsyncSession, org_id: str, integration_id: str) -> str:
    ident = IdentityProfile(organization_id=org_id, user_id="00u2", username="bert@corp.io", email="bert@corp.io",
                            identity_provider="okta", source="okta", source_integration_id=integration_id)
    db.add(ident)
    await db.commit()
    return ident.id


async def _identity_audits(db: AsyncSession) -> list[AuditLog]:
    return list((await db.execute(
        select(AuditLog).where(AuditLog.resource_type == "identity_profile"),
    )).scalars().all())


def _registry(db: AsyncSession, org_id: str, actor_id: str) -> AgentToolRegistry:
    ctx = AgentContext(org_id=org_id, role=UserRole.ADMIN, mode=Mode.APPROVAL, actor_user_id=actor_id)
    return AgentToolRegistry(db, ctx)


# ---------------------------------------------------------------------------
# Proposal -> approval -> directory
# ---------------------------------------------------------------------------


async def test_analyst_execute_yields_a_proposal_and_no_provider_call(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident_id = await _okta_identity(db_session, org_id, integration_id)
    await _responder(db_session, org_id)
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)
    seen = _spy(monkeypatch)

    resp = await client.post(
        f"{AGENTIC}/tools/{TOOL}/execute", headers=org_a_headers,
        json={"params": {"identity_id": ident_id, "action": "disable_account", "reason": "brute force"},
              "propose_actions": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposed"] is True and body["executed"] is False
    assert body["proposal"]["tool"] == TOOL
    assert body["proposal"]["args"] == {"identity_id": ident_id, "action": "disable_account", "reason": "brute force"}
    action = (await db_session.execute(select(AgentAction))).scalar_one()
    assert action.tool_name == TOOL
    assert seen == [] and calls == []
    assert await _identity_audits(db_session) == []


async def test_respond_proposal_approved_by_admin_reaches_the_directory(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident_id = await _okta_identity(db_session, org_id, integration_id)
    threat = IdentityThreat(organization_id=org_id, identity_id=ident_id, threat_type="brute_force",
                            severity="high", confidence_score=70.0, status="detected")
    db_session.add(threat)
    approver = await make_user(db_session, role="admin", organization_id=org_id, label="approver-a")
    await db_session.commit()
    threat_id, approver_id = threat.id, approver.id
    await _responder(db_session, org_id)
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)
    seen = _spy(monkeypatch)

    resp = await client.post(f"{ITDR}/threats/{threat_id}/respond", headers=org_a_admin_headers,
                             json={"action_type": "disable_account", "action_details": {"propose_actions": True}})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    proposal = body["proposal"]
    assert proposal["tool"] == TOOL
    assert proposal["args"]["identity_id"] == ident_id and proposal["args"]["action"] == "disable_account"
    assert body["identity_provider"]["status"] == "proposed"
    assert body["identity_provider"]["integration_id"] == integration_id
    assert [r["tool"] for r in body["results"]] == [TOOL]  # no PySOAR-login disable_user
    assert seen == [] and calls == []

    approved = await client.post(
        f"{AGENTIC}/actions/{proposal['id']}/approve", headers=bearer(approver),
        json={"approved": True, "params_sha256": proposal["params_sha256"],
              "evidence_sha256": proposal["evidence_sha256"], "reason": "confirmed"},
    )
    assert approved.status_code == 200, approved.text
    out = approved.json()
    assert out["executed"] is True and out["tool"] == TOOL
    assert out["execution_status"] == "completed"

    assert seen == [{
        "org_id": org_id, "identity_id": ident_id, "action": "disable_account",
        "actor_user_id": approver_id, "reason": proposal["args"]["reason"],
    }]
    assert [c.url.path for c in calls] == ["/api/v1/users/00u2/lifecycle/suspend"]

    result = out["result"]
    assert result["status"] == "executed" and result["provider"] == "okta"
    assert result["integration_id"] == integration_id
    audits = await _identity_audits(db_session)
    assert len(audits) == 1 and audits[0].resource_id == ident_id and audits[0].user_id == approver_id
    assert result["audit_log_id"] == audits[0].id
    assert "okta-test-token" not in approved.text
    ident = await db_session.get(IdentityProfile, ident_id)
    await db_session.refresh(ident)
    assert ident.account_status == "SUSPENDED"


async def test_approved_proposal_never_touches_the_pysoar_login(
    db_session: AsyncSession, org_a: Organization, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The approval path executes ``registry.call`` with the stored parameters:
    the handler acts on the directory identity, never the same-email User row."""
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident_id = await _okta_identity(db_session, org_id, integration_id)
    login = await make_user(db_session, role="viewer", organization_id=org_id, label="bert")
    admin = await make_user(db_session, role="admin", organization_id=org_id, label="admin-x")
    login.email = "bert@corp.io"
    await db_session.commit()
    _dns(monkeypatch)
    _idp(monkeypatch, _okta_handler)
    seen = _spy(monkeypatch)

    result = await run_tool(_registry(db_session, org_id, admin.id), TOOL,
                            {"identity_id": ident_id, "action": "disable_account", "reason": "approved"})
    assert result["status"] == "executed"
    assert [s["identity_id"] for s in seen] == [ident_id]
    await db_session.refresh(login)
    assert login.is_active is True


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


async def test_other_tenants_identity_is_not_found_and_never_called(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_b: Organization,
    org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    integration_b = await _okta_integration(db_session, org_b.id)
    ident_b = await _okta_identity(db_session, org_b.id, integration_b)
    admin_a = await make_user(db_session, role="admin", organization_id=org_a.id, label="admin-a2")
    await db_session.commit()
    await _responder(db_session, org_a.id)
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)
    seen = _spy(monkeypatch)

    # Handler on its own (permissive policy): a 404-style error result.
    result = await run_tool(_registry(db_session, org_a.id, admin_a.id), TOOL,
                            {"identity_id": ident_b, "action": "disable_account", "reason": "x"})
    assert result["status"] == "not_found" and "error" in result
    assert "bert@corp.io" not in str(result) and integration_b not in str(result)

    # Policy gate: the reference does not resolve in org A.
    resp = await client.post(
        f"{AGENTIC}/tools/{TOOL}/execute", headers=org_a_headers,
        json={"params": {"identity_id": ident_b, "action": "disable_account", "reason": "x"}, "propose_actions": True},
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["reason_code"] == "cross_tenant_reference"
    assert seen == [] and calls == []
    assert (await db_session.execute(select(func.count()).select_from(AgentAction))).scalar() == 0


async def test_unsupported_action_is_an_error_result(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident_id = await _okta_identity(db_session, org_id, integration_id)
    admin = await make_user(db_session, role="admin", organization_id=org_id, label="admin-y")
    await db_session.commit()
    await _responder(db_session, org_id)
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)
    seen = _spy(monkeypatch)

    result = await run_tool(_registry(db_session, org_id, admin.id), TOOL,
                            {"identity_id": ident_id, "action": "delete_everything", "reason": "x"})
    assert result["status"] == "invalid_action" and "disable_account" in result["error"]

    resp = await client.post(
        f"{AGENTIC}/tools/{TOOL}/execute", headers=org_a_headers,
        json={"params": {"identity_id": ident_id, "action": "delete_everything", "reason": "x"}, "propose_actions": True},
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["reason_code"] == "invalid_arguments"
    assert seen == [] and calls == []
    assert await _identity_audits(db_session) == []


async def test_unattended_context_is_refused(
    db_session: AsyncSession, org_a: Organization, monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident_id = await _okta_identity(db_session, org_id, integration_id)
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)
    seen = _spy(monkeypatch)

    ctx = AgentContext(org_id=org_id, role=UserRole.ANALYST, mode=Mode.AUTONOMOUS, soc_agent_id="soc-agent-1")
    registry = AgentToolRegistry(db_session, ctx)
    result = await run_tool(registry, TOOL, {"identity_id": ident_id, "action": "disable_account", "reason": "auto"})
    assert result["status"] == "refused" and "human actor" in result["error"]
    assert seen == [] and calls == []
    assert await _identity_audits(db_session) == []
