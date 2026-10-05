"""Action-tier behaviour of the agent tool registry (work package 2B).

Covers: ``effective_targets`` shapes and provenance for every destructive /
privileged tool (incl. the 25-target cap), composite dispatch through
``_sub_call`` (a denied sub-call aborts with an honest partial result),
``execute_playbook`` tenant hardening + declared-input validation,
``block_ip`` / ``isolate_host`` enforcement modes, ``disable_user`` refusals
and autonomous note attribution.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import func, select

from src.agentic.context import AgentContext, Mode, UserRole
from src.agentic.decisions import Decision, TrustState
from src.agentic.toolspec import ToolSpec
from src.agents.models import AgentCommand, EndpointAgent
from src.core.security import get_password_hash
from src.integrations.models import InstalledIntegration
from src.intel.models import ThreatIndicator
from src.models.alert import Alert
from src.models.asset import Asset
from src.models.incident import Incident
from src.models.playbook import Playbook, PlaybookExecution
from src.models.user import User
from src.services.agent_tools import MAX_COMPOSITE_TARGETS, AgentToolRegistry
from src.tickethub.models import TicketActivity
from tests.unit.test_tool_spec_invariants import AllowAllPolicy, make_context, make_registry, run_tool

ORG_A = "org-a"
ORG_B = "org-b"


# ---------------------------------------------------------------------------
# Seeding helpers (real rows, no fixtures with placeholder content)
# ---------------------------------------------------------------------------


async def _user(db, org: str, email: str, **kw: Any) -> User:
    fields: dict[str, Any] = dict(
        email=email, hashed_password=get_password_hash("pw"), full_name=email.split("@")[0],
        role="analyst", is_active=True, organization_id=org,
    )
    fields.update(kw)
    u = User(**fields)
    db.add(u)
    await db.flush()
    return u


async def _asset(db, org: str, hostname: str, **kw: Any) -> Asset:
    a = Asset(name=hostname, hostname=hostname, asset_type="server", status="active", criticality="high", organization_id=org, **kw)
    db.add(a)
    await db.flush()
    return a


async def _agent(db, org: str, hostname: str, capabilities: list[str], status: str = "active") -> EndpointAgent:
    ag = EndpointAgent(hostname=hostname, display_name=hostname, os_type="linux", status=status, capabilities=capabilities, organization_id=org)
    db.add(ag)
    await db.flush()
    return ag


async def _incident(db, org: str, hosts: list[str] | None = None, ips: list[str] | None = None, **kw: Any) -> Incident:
    inc = Incident(
        title="Ransomware on file share", severity="critical", status="open", incident_type="ransomware", organization_id=org,
        affected_systems=json.dumps(hosts) if hosts is not None else None,
        indicators=json.dumps(ips) if ips is not None else None, **kw,
    )
    db.add(inc)
    await db.flush()
    return inc


async def _alert(db, org: str, **kw: Any) -> Alert:
    fields: dict[str, Any] = dict(title="Suspicious login", severity="high", status="new", source="siem", organization_id=org)
    fields.update(kw)
    a = Alert(**fields)
    db.add(a)
    await db.flush()
    return a


async def _playbook(db, org: str, name: str = "Contain host", variables: dict[str, Any] | None = None) -> Playbook:
    pb = Playbook(
        name=name, description="containment", status="active", is_enabled=True, organization_id=org,
        steps=json.dumps([{"name": "wait", "action": "wait", "parameters": {"seconds": 0}}]),
        variables=json.dumps(variables) if variables is not None else None,
    )
    db.add(pb)
    await db.flush()
    return pb


async def _targets(registry: AgentToolRegistry, tool: str, args: dict[str, Any]):
    spec: ToolSpec = registry.specs[tool]
    assert spec.effective_targets is not None, tool
    return await spec.effective_targets(args, registry)


# ---------------------------------------------------------------------------
# effective_targets shapes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_ip_targets_provenance_from_org_alert(db_session):
    await _alert(db_session, ORG_A, source_ip="203.0.113.10")
    await _alert(db_session, ORG_B, source_ip="203.0.113.99")
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    structured = await _targets(reg, "block_ip", {"ip": "203.0.113.10", "reason": "c2"})
    assert [(t.kind, t.value, t.provenance, t.resolved_id) for t in structured] == [("ip", "203.0.113.10", "structured", None)]
    # Only present on an org-B alert: from org A's point of view it is free text.
    foreign = await _targets(reg, "block_ip", {"ip": "203.0.113.99", "reason": "c2"})
    assert foreign[0].provenance == "untrusted_text"
    unknown = await _targets(reg, "block_ip", {"ip": "198.51.100.7", "reason": "c2"})
    assert unknown[0].provenance == "untrusted_text"


@pytest.mark.asyncio
async def test_block_ip_targets_provenance_from_ioc_and_incident(db_session):
    db_session.add(ThreatIndicator(value="198.51.100.20", indicator_type="ipv4", organization_id=ORG_A, is_active=True))
    await _incident(db_session, ORG_A, ips=["198.51.100.30"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    assert (await _targets(reg, "block_ip", {"ip": "198.51.100.20", "reason": "x"}))[0].provenance == "structured"
    assert (await _targets(reg, "block_ip", {"ip": "198.51.100.30", "reason": "x"}))[0].provenance == "structured"


@pytest.mark.asyncio
async def test_isolate_host_targets_resolve_org_asset(db_session):
    a = await _asset(db_session, ORG_A, "web-01")
    await _asset(db_session, ORG_B, "web-02")
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    t = (await _targets(reg, "isolate_host", {"hostname": "web-01", "reason": "r"}))[0]
    assert (t.kind, t.resolved_id, t.provenance) == ("host", a.id, "structured")
    # The policy hands the handler the resolved asset id; both spellings resolve.
    t_by_id = (await _targets(reg, "isolate_host", {"hostname": a.id, "reason": "r"}))[0]
    assert t_by_id.resolved_id == a.id and t_by_id.value == "web-01"
    foreign = (await _targets(reg, "isolate_host", {"hostname": "web-02", "reason": "r"}))[0]
    assert foreign.resolved_id is None and foreign.provenance == "untrusted_text"


@pytest.mark.asyncio
async def test_disable_user_targets(db_session):
    u = await _user(db_session, ORG_A, "victim@a.example")
    await _user(db_session, ORG_B, "someone@b.example")
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    t = (await _targets(reg, "disable_user", {"user_email": "victim@a.example", "reason": "r"}))[0]
    assert (t.kind, t.resolved_id, t.provenance) == ("user", u.id, "structured")
    t = (await _targets(reg, "disable_user", {"user_email": u.id, "reason": "r"}))[0]
    assert t.resolved_id == u.id
    foreign = (await _targets(reg, "disable_user", {"user_email": "someone@b.example", "reason": "r"}))[0]
    assert foreign.resolved_id is None and foreign.provenance == "unknown"


@pytest.mark.asyncio
async def test_execute_playbook_targets_include_input_data_entities(db_session):
    pb = await _playbook(db_session, ORG_A)
    a = await _asset(db_session, ORG_A, "db-01")
    await _alert(db_session, ORG_A, source_ip="203.0.113.5")
    u = await _user(db_session, ORG_A, "ops@a.example")
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    targets = await _targets(reg, "execute_playbook", {
        "playbook_id": pb.id,
        "input_data": {"hostname": "db-01", "ip": "203.0.113.5", "nested": {"user_email": "ops@a.example"}, "note": "free text"},
    })
    kinds = [(t.kind, t.resolved_id, t.provenance) for t in targets]
    assert kinds[0] == ("playbook", pb.id, "structured")
    assert ("host", a.id, "structured") in kinds
    assert ("ip", None, "structured") in kinds
    assert ("user", u.id, "structured") in kinds
    missing = await _targets(reg, "execute_playbook", {"playbook_id": "nope"})
    assert missing[0].kind == "playbook" and missing[0].resolved_id is None and missing[0].provenance == "unknown"


@pytest.mark.asyncio
async def test_execute_integration_action_targets(db_session):
    ii = InstalledIntegration(
        organization_id=ORG_A, connector_id="slack", display_name="Slack", config_encrypted="x", auth_credentials_encrypted="y", status="active",
    )
    db_session.add(ii)
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    targets = await _targets(reg, "execute_integration_action", {
        "installation_id": ii.id, "action_name": "notify", "input_data": {"target_ip": "192.0.2.9"},
    })
    assert (targets[0].kind, targets[0].resolved_id, targets[0].provenance) == ("integration", ii.id, "structured")
    assert (targets[1].kind, targets[1].value, targets[1].provenance) == ("ip", "192.0.2.9", "untrusted_text")


@pytest.mark.asyncio
async def test_remediate_incident_targets_expand_hosts_and_ips_with_provenance(db_session):
    a = await _asset(db_session, ORG_A, "file-share-01")
    await _alert(db_session, ORG_A, source_ip="203.0.113.50")
    inc = await _incident(db_session, ORG_A, hosts=["file-share-01", "ghost-host"], ips=["203.0.113.50", "198.51.100.9", "not-an-ip"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    targets = await _targets(reg, "remediate_incident", {"incident_id": inc.id})
    shaped = [(t.kind, t.value, t.resolved_id, t.provenance) for t in targets]
    assert shaped == [
        ("incident", inc.id, inc.id, "structured"),
        ("host", "file-share-01", a.id, "structured"),
        # In Incident.affected_systems (a human-written field) -> structured even without an Asset row.
        ("host", "ghost-host", None, "structured"),
        ("ip", "203.0.113.50", None, "structured"),
        ("ip", "198.51.100.9", None, "structured"),
    ]
    only_ips = await _targets(reg, "remediate_incident", {"incident_id": inc.id, "isolate_hosts": False})
    assert [t.kind for t in only_ips] == ["incident", "ip", "ip"]


@pytest.mark.asyncio
async def test_remediate_incident_targets_capped_at_25(db_session):
    inc = await _incident(db_session, ORG_A, hosts=[f"host-{i}" for i in range(40)], ips=[f"10.1.{i}.1" for i in range(40)])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    targets = await _targets(reg, "remediate_incident", {"incident_id": inc.id})
    assert len(targets) == MAX_COMPOSITE_TARGETS == 25
    assert targets[0].kind == "incident"


@pytest.mark.asyncio
async def test_remediate_incident_targets_missing_incident_does_not_raise(db_session):
    reg = make_registry(db_session, org=ORG_A)
    targets = await _targets(reg, "remediate_incident", {"incident_id": "does-not-exist"})
    assert len(targets) == 1 and targets[0].resolved_id is None and targets[0].provenance == "unknown"


@pytest.mark.asyncio
async def test_create_remediation_ticket_and_simulate_attack_and_queue_endpoint_targets(db_session):
    inc = await _incident(db_session, ORG_A)
    a = await _asset(db_session, ORG_A, "lab-01")
    ag = await _agent(db_session, ORG_A, "lab-01", ["ir"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    t = (await _targets(reg, "create_remediation_ticket", {"title": "Patch", "incident_id": inc.id}))[0]
    assert (t.kind, t.resolved_id, t.provenance) == ("incident", inc.id, "structured")
    t = (await _targets(reg, "create_remediation_ticket", {"title": "Patch"}))[0]
    assert (t.kind, t.value, t.provenance) == ("other", "Patch", "untrusted_text")

    t = (await _targets(reg, "simulate_attack", {"technique": "T1059", "target": "lab-01"}))[0]
    assert (t.kind, t.resolved_id, t.provenance) == ("host", a.id, "structured")

    targets = await _targets(reg, "queue_endpoint_command", {"agent_id": ag.id, "action": "block_ip", "payload": {"ip": "203.0.113.1"}})
    assert (targets[0].kind, targets[0].resolved_id, targets[0].provenance) == ("endpoint_agent", ag.id, "structured")
    assert targets[1].kind == "ip"
    t = (await _targets(reg, "queue_endpoint_command", {"agent_id": "missing", "action": "block_ip"}))[0]
    assert t.resolved_id is None and t.provenance == "unknown"


# ---------------------------------------------------------------------------
# Composite dispatch
# ---------------------------------------------------------------------------


class DenyToolPolicy(AllowAllPolicy):
    """Allows everything except ``denied`` tools; records every evaluation."""

    def __init__(self, denied: set[str], code: str = "rate_limited") -> None:
        self.denied = denied
        self.code = code
        self.evaluated: list[str] = []

    async def evaluate(self, ctx: AgentContext, spec: ToolSpec, args: dict[str, Any], trust: Any) -> Decision:
        self.evaluated.append(spec.name)
        if spec.name in self.denied:
            return Decision(kind="deny", reason_code=self.code, tool=spec.name, tier=spec.tier, risk="high", resolved_args=dict(args), effective_targets=[])
        return await super().evaluate(ctx, spec, args, trust)


@pytest.mark.asyncio
async def test_composite_aborts_on_denied_sub_call_with_honest_partial(db_session):
    inc = await _incident(db_session, ORG_A, hosts=["file-share-01"], ips=["203.0.113.50", "198.51.100.9"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    policy = DenyToolPolicy({"block_ip"})

    out = await reg.call(reg.ctx, "remediate_incident", {"incident_id": inc.id}, policy=policy)
    assert out["aborted_at"] == "block_ip" and out["reason"] == "rate_limited"
    assert out["aborted_target"] == "203.0.113.50"
    assert [c["tool"] for c in out["completed"]] == ["isolate_host"]
    assert out["hosts_isolated"] == ["file-share-01"] and out["indicators_blocked"] == []
    # every sub-action was separately evaluated by the policy in force for the outer call
    assert policy.evaluated == ["remediate_incident", "isolate_host", "block_ip"]
    # nothing was blocked once the abort hit
    iocs = (await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.source == "agent_block"))).scalars().all()
    assert iocs == []
    await db_session.refresh(inc)
    assert inc.status == "open"


@pytest.mark.asyncio
async def test_composite_fails_closed_without_policy_in_scope(db_session):
    inc = await _incident(db_session, ORG_A, hosts=["file-share-01"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    spec = reg.specs["remediate_incident"]
    decision = Decision(kind="allow", reason_code="ok", tool=spec.name, tier=spec.tier, risk="high", resolved_args={"incident_id": inc.id}, effective_targets=[])
    out = await reg.call(reg.ctx, "remediate_incident", {"incident_id": inc.id}, decision=decision)
    assert out["aborted_at"] == "isolate_host" and out["reason"] == "composite_requires_policy"
    assert out["completed"] == []


@pytest.mark.asyncio
async def test_bound_policy_serves_sub_calls_when_call_gets_a_decision(db_session):
    inc = await _incident(db_session, ORG_A, hosts=["file-share-01"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    policy = DenyToolPolicy(set())
    reg.bind_policy(policy)
    spec = reg.specs["remediate_incident"]
    decision = Decision(kind="allow", reason_code="ok", tool=spec.name, tier=spec.tier, risk="high", resolved_args={"incident_id": inc.id}, effective_targets=[])
    out = await reg.call(reg.ctx, "remediate_incident", {"incident_id": inc.id}, decision=decision)
    assert out["hosts_isolated"] == ["file-share-01"]
    assert policy.evaluated == ["isolate_host"]
    assert reg._active_policy is None  # restored after the call


@pytest.mark.asyncio
async def test_sub_call_propose_decision_aborts_with_kind(db_session):
    class ProposePolicy(AllowAllPolicy):
        async def evaluate(self, ctx, spec, args, trust):
            d = await super().evaluate(ctx, spec, args, trust)
            if spec.name == "isolate_host":
                d.kind = "propose"
            return d

    inc = await _incident(db_session, ORG_A, hosts=["file-share-01"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    out = await reg.call(reg.ctx, "remediate_incident", {"incident_id": inc.id}, policy=ProposePolicy())
    assert out["aborted_at"] == "isolate_host" and out["reason"] == "decision_propose"


# ---------------------------------------------------------------------------
# execute_playbook
# ---------------------------------------------------------------------------


async def _count_org_rows(db, model: type, org: str) -> int:
    return int((await db.execute(select(func.count(model.id)).where(model.organization_id == org))).scalar() or 0)


@pytest.mark.asyncio
async def test_execute_playbook_org_override_in_input_data_produces_zero_org_b_rows(db_session):
    from src.services.playbook_engine import PlaybookAction, PlaybookEngine

    pb = await _playbook(db_session, ORG_A, variables={"hostname": "", "organization_id": ""})
    await _playbook(db_session, ORG_B, name="B playbook")
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    with patch("src.playbooks.tasks.run_playbook_execution") as task:
        out = await run_tool(reg, "execute_playbook", {
            "playbook_id": pb.id,
            "input_data": {"organization_id": ORG_B, "actor_user_id": "attacker", "playbook_execution_id": "x", "hostname": "web-01"},
        })
    assert out["status"] == "queued" and out["input_keys"] == ["hostname"]
    task.delay.assert_called_once_with(out["execution_id"])

    execution = await db_session.get(PlaybookExecution, out["execution_id"])
    assert execution.organization_id == ORG_A
    assert execution.triggered_by_user_id == reg.ctx.actor_user_id
    stored = json.loads(execution.input_data)
    assert stored["organization_id"] == ORG_A and stored["actor_user_id"] == reg.ctx.actor_user_id
    assert "playbook_execution_id" not in stored

    # The engine derives the tenant from the execution row and ignores any
    # organization_id that reaches the context through input_data/variables.
    execution.input_data = json.dumps({**stored, "organization_id": ORG_B})
    await db_session.commit()
    seen: list[dict[str, Any]] = []

    async def fake_execute(action: str, parameters: dict, context: dict) -> dict:
        seen.append(dict(context))
        return {"success": True, "details": {}}

    with patch.object(PlaybookAction, "execute", side_effect=fake_execute):
        result = await PlaybookEngine(db_session).execute(execution.id)
    assert result.status == "completed"
    assert seen and all(c["organization_id"] == ORG_A for c in seen)

    assert await _count_org_rows(db_session, PlaybookExecution, ORG_B) == 0
    assert await _count_org_rows(db_session, TicketActivity, ORG_B) == 0
    assert await _count_org_rows(db_session, PlaybookExecution, ORG_A) == 1


@pytest.mark.asyncio
async def test_execute_playbook_validates_declared_inputs(db_session):
    pb = await _playbook(db_session, ORG_A, variables={"hostname": "", "retries": 3, "notify": {"type": "boolean"}})
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    with patch("src.playbooks.tasks.run_playbook_execution"):
        with pytest.raises(ValueError, match="does not declare"):
            await run_tool(reg, "execute_playbook", {"playbook_id": pb.id, "input_data": {"hostname": "h", "bogus": 1}})
        with pytest.raises(ValueError, match="retries"):
            await run_tool(reg, "execute_playbook", {"playbook_id": pb.id, "input_data": {"retries": "three"}})
        with pytest.raises(ValueError, match="notify"):
            await run_tool(reg, "execute_playbook", {"playbook_id": pb.id, "input_data": {"notify": "yes"}})
        out = await run_tool(reg, "execute_playbook", {"playbook_id": pb.id, "input_data": {"hostname": "h", "retries": 5, "notify": True}})
    assert out["status"] == "queued"
    assert await _count_org_rows(db_session, PlaybookExecution, ORG_A) == 1


@pytest.mark.asyncio
async def test_execute_playbook_rejects_foreign_playbook(db_session):
    pb_b = await _playbook(db_session, ORG_B)
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    with patch("src.playbooks.tasks.run_playbook_execution") as task:
        out = await run_tool(reg, "execute_playbook", {"playbook_id": pb_b.id})
    assert out == {"error": "Playbook not found"}
    task.delay.assert_not_called()
    assert await _count_org_rows(db_session, PlaybookExecution, ORG_B) == 0


# ---------------------------------------------------------------------------
# block_ip / isolate_host enforcement modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_ip_detection_only_without_eligible_agent(db_session):
    await _agent(db_session, ORG_A, "bas-only", ["bas"])          # not IR-capable
    await _agent(db_session, ORG_B, "b-ir", ["ir"])                # other tenant
    await _agent(db_session, ORG_A, "revoked-ir", ["ir"], status="revoked")
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    out = await run_tool(reg, "block_ip", {"ip": "203.0.113.77", "reason": "c2 beacon"})
    assert out["mode"] == "detection_only" and out["status"] == "recorded"
    assert out["agent_commands"] == [] and "manually" in out["note"]
    ioc = await db_session.get(ThreatIndicator, out["ioc_id"])
    assert ioc.organization_id == ORG_A and ioc.value == "203.0.113.77" and ioc.is_active
    assert (await db_session.execute(select(func.count(AgentCommand.id)))).scalar() == 0


@pytest.mark.asyncio
async def test_block_ip_enforced_via_org_agents_only(db_session):
    a1 = await _agent(db_session, ORG_A, "ir-01", ["ir"])
    a2 = await _agent(db_session, ORG_A, "ir-02", ["ir"], status="offline")
    await _agent(db_session, ORG_B, "b-ir", ["ir"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    out = await run_tool(reg, "block_ip", {"ip": "203.0.113.77", "reason": "c2 beacon"})
    assert out["mode"] == "enforced_via_agents" and out["status"] == "blocked"
    assert {c["agent_id"] for c in out["agent_commands"]} == {a1.id, a2.id}
    cmds = (await db_session.execute(select(AgentCommand))).scalars().all()
    assert {c.agent_id for c in cmds} == {a1.id, a2.id}
    assert all(c.organization_id == ORG_A and c.action == "block_ip" and c.payload["ip"] == "203.0.113.77" for c in cmds)
    assert all(c.status == "queued" for c in cmds)  # policy already authorized: no second approval gate
    acts = (await db_session.execute(select(TicketActivity).where(TicketActivity.activity_type == "block_ip"))).scalars().all()
    assert len(acts) == 1 and acts[0].organization_id == ORG_A and acts[0].extra_metadata["mode"] == "enforced_via_agents"


@pytest.mark.asyncio
async def test_isolate_host_enforced_via_enrolled_agent(db_session):
    asset = await _asset(db_session, ORG_A, "Web-01")
    ag = await _agent(db_session, ORG_A, "web-01", ["ir"])
    await _agent(db_session, ORG_B, "web-01", ["ir"])  # same hostname, other tenant
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    out = await run_tool(reg, "isolate_host", {"hostname": asset.id, "reason": "ransomware"})
    assert out["mode"] == "enforced_via_agent" and out["status"] == "isolation_queued"
    assert out["agent_id"] == ag.id and out["asset_id"] == asset.id and out["command_status"] == "queued"
    cmd = await db_session.get(AgentCommand, out["command_id"])
    assert cmd.agent_id == ag.id and cmd.organization_id == ORG_A and cmd.action == "isolate_host"


@pytest.mark.asyncio
async def test_isolate_host_detection_only_without_agent(db_session):
    asset = await _asset(db_session, ORG_A, "db-01")
    await _agent(db_session, ORG_A, "db-01", ["bas"])  # enrolled, but not for IR
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    out = await run_tool(reg, "isolate_host", {"hostname": "db-01", "reason": "r"})
    assert out["mode"] == "detection_only" and out["status"] == "recorded"
    assert out["command_id"] is None and "recorded only" in out["note"]
    assert (await db_session.execute(select(func.count(AgentCommand.id)))).scalar() == 0
    act = (await db_session.execute(select(TicketActivity).where(TicketActivity.activity_type == "isolate_host"))).scalars().one()
    assert act.organization_id == ORG_A and act.source_id == asset.id and act.extra_metadata["mode"] == "detection_only"


@pytest.mark.asyncio
async def test_remediate_incident_reports_enforcement_modes(db_session):
    await _asset(db_session, ORG_A, "file-share-01")
    await _agent(db_session, ORG_A, "file-share-01", ["ir"])
    inc = await _incident(db_session, ORG_A, hosts=["file-share-01", "no-agent-host"], ips=["203.0.113.50"])
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)

    out = await run_tool(reg, "remediate_incident", {"incident_id": inc.id})
    assert out["enforcement"]["hosts"] == {"file-share-01": "enforced_via_agent", "no-agent-host": "detection_only"}
    assert out["enforcement"]["ips"] == {"203.0.113.50": "enforced_via_agents"}
    assert "1 enforced via endpoint agent" in out["summary"] and "1 recorded only" in out["summary"]
    assert out["new_status"] == "containment"


# ---------------------------------------------------------------------------
# disable_user / notes attribution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_user_refuses_superuser_and_actor(db_session):
    actor = await _user(db_session, ORG_A, "actor@a.example")
    root = await _user(db_session, ORG_A, "root@a.example", is_superuser=True)
    victim = await _user(db_session, ORG_A, "victim@a.example")
    await db_session.commit()
    reg = make_registry(db_session, user=actor)

    assert "superuser" in (await run_tool(reg, "disable_user", {"user_email": "root@a.example", "reason": "r"}))["error"]
    assert "own account" in (await run_tool(reg, "disable_user", {"user_email": "me", "reason": "r"}))["error"]
    assert "own account" in (await run_tool(reg, "disable_user", {"user_email": actor.id, "reason": "r"}))["error"]
    out = await run_tool(reg, "disable_user", {"user_email": victim.id, "reason": "compromised"})
    assert out["status"] == "disabled"
    await db_session.commit()
    for u in (actor, root, victim):
        await db_session.refresh(u)
    assert actor.is_active and root.is_active and not victim.is_active
    assert (await run_tool(reg, "disable_user", {"user_email": victim.id, "reason": "r"}))["status"] == "already_disabled"


@pytest.mark.asyncio
async def test_disable_user_never_touches_other_org(db_session):
    foreign = await _user(db_session, ORG_B, "victim@b.example")
    await db_session.commit()
    reg = make_registry(db_session, org=ORG_A)
    out = await run_tool(reg, "disable_user", {"user_email": "victim@b.example", "reason": "r"})
    assert "error" in out
    await db_session.refresh(foreign)
    assert foreign.is_active


@pytest.mark.asyncio
async def test_autonomous_notes_require_agent_author_column(db_session):
    from src.models.case import CaseNote

    inc = await _incident(db_session, ORG_A)
    await db_session.commit()
    ctx = AgentContext(org_id=ORG_A, role=UserRole.ANALYST, mode=Mode.AUTONOMOUS, soc_agent_id="soc-agent-1")
    reg = AgentToolRegistry(db_session, ctx)

    expected = {"error": "autonomous_notes_require_agent_author_column"}
    if hasattr(CaseNote, "created_by_agent_id"):
        pytest.skip("CaseNote now carries created_by_agent_id; autonomous notes are attributable")
    assert await run_tool(reg, "add_incident_note", {"incident_id": inc.id, "note": "n"}) == expected
    assert await run_tool(reg, "update_incident_findings", {"incident_id": inc.id, "root_cause": "x"}) == expected
    assert (await db_session.execute(select(func.count(CaseNote.id)))).scalar() == 0
    await db_session.refresh(inc)
    assert inc.root_cause is None


@pytest.mark.asyncio
async def test_interactive_notes_attributed_to_actor(db_session):
    from src.models.case import CaseNote, CaseTimeline

    actor = await _user(db_session, ORG_A, "actor@a.example")
    inc = await _incident(db_session, ORG_A)
    await db_session.commit()
    reg = make_registry(db_session, user=actor)
    out = await run_tool(reg, "add_incident_note", {"incident_id": inc.id, "note": "confirmed"})
    note = await db_session.get(CaseNote, out["note_id"])
    assert note.author_id == actor.id
    tl = (await db_session.execute(select(CaseTimeline).where(CaseTimeline.incident_id == inc.id))).scalars().all()
    assert tl and all(t.actor_id == actor.id for t in tl)
