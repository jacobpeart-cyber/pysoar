"""Tenant isolation of EVERY registered agent tool (work package 2B).

For each tool: seed one row per organization for every model the spec
declares (plus their parents), execute the tool as org A with arguments that
reference org-B ids and values, and prove that

(a) no org-B primary key or org-B-distinctive value appears anywhere in the
    JSON-serialized result (values the caller itself supplied as arguments are
    excluded - echoing input is not a leak), and
(b) no org-B row was mutated (column snapshots before/after are identical),

and, for every read-tier tool, that no row is added to the session at all
(``before_flush`` listener).

The permissive ``AllowAllPolicy`` is used on purpose: the handlers must be
org-safe on their own, without relying on the policy's reference resolution.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from unittest.mock import patch

import pytest
from sqlalchemy import event, inspect

from src.agentic.toolspec import ParamSpec, Tier, ToolSpec
from src.agents.models import AgentCommand, EndpointAgent
from src.collaboration.models import ActionItem, WarRoom
from src.compliance.models import POAM, ComplianceControl, ComplianceEvidence, ComplianceFramework
from src.core.security import get_password_hash
from src.darkweb.models import DarkWebFinding
from src.deception.models import DecoyInteraction
from src.dfir.models import ForensicCase
from src.exposure.models import RemediationTicket
from src.hunting.models import HuntFinding, HuntHypothesis, HuntSession
from src.integrations.models import InstalledIntegration
from src.intel.models import ThreatActor, ThreatCampaign, ThreatIndicator
from src.models.alert import Alert
from src.models.asset import Asset
from src.models.audit import AuditLog
from src.models.case import CaseNote, CaseTimeline
from src.models.incident import Incident
from src.models.playbook import Playbook, PlaybookExecution
from src.models.user import User
from src.phishing_sim.models import PhishingCampaign
from src.remediation.models import RemediationExecution
from src.risk_quant.models import FAIRAnalysis, RiskScenario
from src.services.agent_tools import MODEL_REGISTRY, AgentToolRegistry
from src.siem.models import DetectionRule, LogEntry
from src.simulation.models import AttackSimulation, SimulationTest
from src.tickethub.models import TicketActivity
from src.ueba.models import EntityProfile, UEBARiskAlert
from src.vulnmgmt.models import Vulnerability
from tests.unit.test_tool_spec_invariants import make_registry, run_tool

ORG_A = "org-a"
ORG_B = "org-b"

Seeder = Callable[[Any, str, str, dict[str, Any]], Awaitable[Any]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# One seeder per model. ``tag`` is unique per org and embedded in every
# distinctive string so a leak is detectable by substring.
# ---------------------------------------------------------------------------


async def _seed_user(db, org, tag, rows):
    u = User(email=f"{tag}@example.test", hashed_password=get_password_hash("pw"), full_name=f"{tag} user", role="analyst", is_active=True, organization_id=org)
    db.add(u)
    return u


async def _seed_alert(db, org, tag, rows):
    a = Alert(
        title=f"{tag} alert title", description=f"{tag} alert description", severity="high", status="new", source="siem", category="malware",
        source_ip="203.0.113.10" if org == ORG_A else "203.0.113.20", hostname=f"{tag}-alert-host", organization_id=org,
    )
    db.add(a)
    return a


async def _seed_incident(db, org, tag, rows):
    i = Incident(
        title=f"{tag} incident title", description=f"{tag} incident description", severity="critical", status="open", incident_type="malware",
        affected_systems=json.dumps([f"{tag}-asset-host"]), indicators=json.dumps(["203.0.113.10" if org == ORG_A else "203.0.113.20"]),
        organization_id=org,
    )
    db.add(i)
    return i


async def _seed_asset(db, org, tag, rows):
    a = Asset(name=f"{tag}-asset-name", hostname=f"{tag}-asset-host", asset_type="server", status="active", criticality="high", ip_address="10.0.0.1" if org == ORG_A else "10.0.0.2", organization_id=org)
    db.add(a)
    return a


async def _seed_ioc(db, org, tag, rows):
    i = ThreatIndicator(value=f"{tag}.example.test", indicator_type="domain", severity="high", is_active=True, is_whitelisted=False, source=f"{tag}-source", confidence=80, organization_id=org)
    db.add(i)
    return i


async def _seed_threat_actor(db, org, tag, rows):
    t = ThreatActor(name=f"{tag} actor", confidence=50, organization_id=org)
    db.add(t)
    return t


async def _seed_threat_campaign(db, org, tag, rows):
    c = ThreatCampaign(name=f"{tag} campaign", status="active", confidence=50, organization_id=org)
    db.add(c)
    return c


async def _seed_playbook(db, org, tag, rows):
    p = Playbook(name=f"{tag} playbook", description=f"{tag} playbook description", status="active", is_enabled=True, category=f"{tag}-cat", steps=json.dumps([{"name": "wait", "action": "wait", "parameters": {"seconds": 0}}]), organization_id=org)
    db.add(p)
    return p


async def _seed_playbook_execution(db, org, tag, rows):
    e = PlaybookExecution(playbook_id=rows["Playbook"].id, status="pending", input_data=json.dumps({"organization_id": org}), trigger_source="manual", triggered_by=rows["User"].id, organization_id=org)
    db.add(e)
    return e


async def _seed_investigation(db, org, tag, rows):
    from src.agentic.models import Investigation

    inv = Investigation(agent_id=f"{tag}-soc-agent", organization_id=org, trigger_type="alert", title=f"{tag} investigation")
    db.add(inv)
    await db.flush()
    return inv


async def _seed_agent_action(db, org, tag, rows):
    from src.agentic.models import AgentAction

    a = AgentAction(investigation_id=rows["Investigation"].id, organization_id=org, action_type="block_ip", target=f"{tag}-target")
    db.add(a)
    return a


async def _seed_war_room(db, org, tag, rows):
    r = WarRoom(organization_id=org, name=f"{tag} war room", severity_level="high", room_type="incident_response", status="active", created_by=rows["User"].id)
    db.add(r)
    await db.flush()
    return r


async def _seed_action_item(db, org, tag, rows):
    a = ActionItem(organization_id=org, room_id=rows["WarRoom"].id, title=f"{tag} action item", assigned_by=rows["User"].id, priority="high", status="pending")
    db.add(a)
    return a


async def _seed_endpoint_agent(db, org, tag, rows):
    a = EndpointAgent(hostname=f"{tag}-asset-host", display_name=f"{tag} agent", os_type="linux", status="active", capabilities=["ir", "bas"], organization_id=org)
    db.add(a)
    await db.flush()
    return a


async def _seed_agent_command(db, org, tag, rows):
    c = AgentCommand(agent_id=rows["EndpointAgent"].id, action="collect_process_list", payload={}, command_hash=f"{tag}-hash", chain_hash=f"{tag}-chain", status="queued", organization_id=org)
    db.add(c)
    return c


async def _seed_installed_integration(db, org, tag, rows):
    i = InstalledIntegration(organization_id=org, connector_id=f"{tag}-connector", display_name=f"{tag} integration", config_encrypted=f"{tag}-config", auth_credentials_encrypted=f"{tag}-secret", status="active", health_status="healthy")
    db.add(i)
    return i


async def _seed_forensic_case(db, org, tag, rows):
    c = ForensicCase(case_number=f"{tag}-CASE-1", title=f"{tag} forensic case", case_type="malware", severity="high", status="open", organization_id=org, created_by=rows["User"].id)
    db.add(c)
    return c


async def _seed_remediation_ticket(db, org, tag, rows):
    t = RemediationTicket(title=f"{tag} remediation ticket", description=f"{tag} desc", remediation_type="manual", status="open", priority="high", organization_id=org)
    db.add(t)
    return t


async def _seed_remediation_execution(db, org, tag, rows):
    e = RemediationExecution(trigger_source="manual", trigger_id=f"{tag}-trigger", target_entity=f"{tag}-target", target_type="ip", status="completed", organization_id=org)
    db.add(e)
    return e


async def _seed_hunt_hypothesis(db, org, tag, rows):
    h = HuntHypothesis(title=f"{tag} hunt", description=f"{tag} hunt description", hunt_type="hypothesis_driven", status="active", priority="medium", organization_id=org, created_by=rows["User"].id)
    db.add(h)
    await db.flush()
    return h


async def _seed_hunt_session(db, org, tag, rows):
    s = HuntSession(hypothesis_id=rows["HuntHypothesis"].id, status="completed", parameters={}, organization_id=org, created_by=rows["User"].id)
    db.add(s)
    await db.flush()
    return s


async def _seed_hunt_finding(db, org, tag, rows):
    f = HuntFinding(session_id=rows["HuntSession"].id, title=f"{tag} hunt finding", severity="high", organization_id=org, created_by=rows["User"].id)
    db.add(f)
    return f


async def _seed_log_entry(db, org, tag, rows):
    ts = _now().isoformat()
    e = LogEntry(timestamp=ts, received_at=ts, source_type="syslog", source_name=f"{tag}-log-source", source_ip="10.0.0.9", log_type="auth", severity="high", message=f"{tag} log message", raw_log=f"{tag} raw log", hostname=f"{tag}-asset-host", organization_id=org)
    db.add(e)
    return e


async def _seed_detection_rule(db, org, tag, rows):
    r = DetectionRule(name=f"{tag}-rule", title=f"{tag} rule title", description=f"{tag} rule description", severity="high", status="active", enabled=True, mitre_techniques=json.dumps(["T1059"]), organization_id=org)
    db.add(r)
    return r


async def _seed_vulnerability(db, org, tag, rows):
    v = Vulnerability(cve_id=f"CVE-2024-{tag.upper()}", title=f"{tag} vulnerability", severity="high", organization_id=org)
    db.add(v)
    return v


async def _seed_entity_profile(db, org, tag, rows):
    p = EntityProfile(entity_type="user", entity_id=f"{tag}-entity", display_name=f"{tag} entity", risk_score=80, risk_level="high", organization_id=org)
    db.add(p)
    await db.flush()
    return p


async def _seed_ueba_alert(db, org, tag, rows):
    a = UEBARiskAlert(entity_profile_id=rows["EntityProfile"].id, alert_type=f"{tag}-anomaly", severity="high", risk_score_delta=10.0, description=f"{tag} ueba alert", organization_id=org)
    db.add(a)
    return a


async def _seed_darkweb_finding(db, org, tag, rows):
    f = DarkWebFinding(organization_id=org, monitor_id=f"{tag}-monitor", finding_type="credential_leak", title=f"{tag} darkweb finding", severity="high", status="new")
    db.add(f)
    return f


async def _seed_decoy_interaction(db, org, tag, rows):
    d = DecoyInteraction(decoy_id=f"{tag}-decoy", interaction_type="connection", source_ip="10.9.9.9", source_hostname=f"{tag}-attacker", organization_id=org)
    db.add(d)
    return d


async def _seed_phishing_campaign(db, org, tag, rows):
    c = PhishingCampaign(name=f"{tag} phishing campaign", campaign_type="credential_harvest", created_by=rows["User"].id, status="draft", organization_id=org)
    db.add(c)
    return c


async def _seed_risk_scenario(db, org, tag, rows):
    r = RiskScenario(organization_id=org, name=f"{tag} risk scenario", asset_name=f"{tag}-asset-name", asset_value_usd=1000.0, threat_type="ransomware", vulnerability_exploited=f"{tag}-vuln", analyst_id=rows["User"].id, status="active")
    db.add(r)
    await db.flush()
    return r


async def _seed_fair_analysis(db, org, tag, rows):
    f = FAIRAnalysis(
        organization_id=org, scenario_id=rows["RiskScenario"].id,
        tef_min=1, tef_mode=2, tef_max=3, vuln_min=0.1, vuln_mode=0.2, vuln_max=0.3, tcap_min=1, tcap_mode=2, tcap_max=3,
        rs_min=1, rs_mode=2, rs_max=3, lm_min=1, lm_mode=2, lm_max=3, primary_loss_min=1, primary_loss_mode=2, primary_loss_max=3,
        secondary_loss_min=1, secondary_loss_mode=2, secondary_loss_max=3, secondary_loss_event_frequency=0.5,
    )
    db.add(f)
    return f


async def _seed_compliance_framework(db, org, tag, rows):
    f = ComplianceFramework(name=f"{tag} framework", short_name=f"{tag}-FW", version="1", authority=f"{tag}-authority", is_enabled=True, organization_id=org)
    db.add(f)
    await db.flush()
    return f


async def _seed_compliance_control(db, org, tag, rows):
    c = ComplianceControl(framework_id=rows["ComplianceFramework"].id, control_id=f"{tag}-AC-1", control_family="AC", title=f"{tag} control", organization_id=org)
    db.add(c)
    await db.flush()
    return c


async def _seed_poam(db, org, tag, rows):
    p = POAM(control_id_ref=rows["ComplianceControl"].id, weakness_name=f"{tag} weakness", weakness_source="audit", scheduled_completion_date=_now() + timedelta(days=30), status="open", risk_level="high", organization_id=org)
    db.add(p)
    return p


async def _seed_compliance_evidence(db, org, tag, rows):
    e = ComplianceEvidence(control_id_ref=rows["ComplianceControl"].id, evidence_type="document", title=f"{tag} evidence", collected_by=rows["User"].id, source_system=f"{tag}-system", organization_id=org)
    db.add(e)
    return e


async def _seed_ticket_activity(db, org, tag, rows):
    t = TicketActivity(source_type="incident", source_id=rows["Incident"].id, activity_type="comment", description=f"{tag} ticket activity", actor_id=rows["User"].id, organization_id=org)
    db.add(t)
    return t


async def _seed_attack_simulation(db, org, tag, rows):
    s = AttackSimulation(name=f"{tag} simulation", simulation_type="atomic_test", target_environment="lab", created_by=rows["User"].id, organization_id=org, status="pending")
    db.add(s)
    await db.flush()
    return s


async def _seed_simulation_test(db, org, tag, rows):
    t = SimulationTest(simulation_id=rows["AttackSimulation"].id, technique_id="T1059", test_name=f"{tag} sim test", executor="sh")
    db.add(t)
    return t


async def _seed_audit_log(db, org, tag, rows):
    a = AuditLog(action=f"{tag}-audit-action", resource_type="incident", resource_id=rows["Incident"].id, description=f"{tag} audit description", user_id=rows["User"].id, success=True)
    db.add(a)
    return a


async def _seed_case_note(db, org, tag, rows):
    n = CaseNote(incident_id=rows["Incident"].id, content=f"{tag} case note", author_id=rows["User"].id)
    db.add(n)
    return n


async def _seed_case_timeline(db, org, tag, rows):
    t = CaseTimeline(incident_id=rows["Incident"].id, event_type="note", title=f"{tag} timeline", actor_id=rows["User"].id)
    db.add(t)
    return t


#: Dependency-ordered seeders, one per registry model.
SEEDERS: dict[str, Seeder] = {
    "User": _seed_user,
    "Alert": _seed_alert,
    "Incident": _seed_incident,
    "Asset": _seed_asset,
    "ThreatIndicator": _seed_ioc,
    "ThreatActor": _seed_threat_actor,
    "ThreatCampaign": _seed_threat_campaign,
    "Playbook": _seed_playbook,
    "PlaybookExecution": _seed_playbook_execution,
    "Investigation": _seed_investigation,
    "AgentAction": _seed_agent_action,
    "WarRoom": _seed_war_room,
    "ActionItem": _seed_action_item,
    "EndpointAgent": _seed_endpoint_agent,
    "AgentCommand": _seed_agent_command,
    "InstalledIntegration": _seed_installed_integration,
    "ForensicCase": _seed_forensic_case,
    "RemediationTicket": _seed_remediation_ticket,
    "RemediationExecution": _seed_remediation_execution,
    "HuntHypothesis": _seed_hunt_hypothesis,
    "HuntSession": _seed_hunt_session,
    "HuntFinding": _seed_hunt_finding,
    "LogEntry": _seed_log_entry,
    "DetectionRule": _seed_detection_rule,
    "Vulnerability": _seed_vulnerability,
    "EntityProfile": _seed_entity_profile,
    "UEBARiskAlert": _seed_ueba_alert,
    "DarkWebFinding": _seed_darkweb_finding,
    "DecoyInteraction": _seed_decoy_interaction,
    "PhishingCampaign": _seed_phishing_campaign,
    "RiskScenario": _seed_risk_scenario,
    "FAIRAnalysis": _seed_fair_analysis,
    "ComplianceFramework": _seed_compliance_framework,
    "ComplianceControl": _seed_compliance_control,
    "POAM": _seed_poam,
    "ComplianceEvidence": _seed_compliance_evidence,
    "TicketActivity": _seed_ticket_activity,
    "AttackSimulation": _seed_attack_simulation,
    "SimulationTest": _seed_simulation_test,
    "AuditLog": _seed_audit_log,
    "CaseNote": _seed_case_note,
    "CaseTimeline": _seed_case_timeline,
}


def test_every_registry_model_has_a_seeder():
    assert set(SEEDERS) == set(MODEL_REGISTRY)


async def seed_org(db, org: str, tag: str) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for name, seeder in SEEDERS.items():
        rows[name] = await seeder(db, org, tag, rows)
        await db.flush()
    return rows


def _snapshot(row: Any) -> dict[str, Any]:
    return {c.key: getattr(row, c.key) for c in inspect(row).mapper.column_attrs}


async def _snapshot_all(db, rows: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for name, row in rows.items():
        await db.refresh(row)
        out[name] = _snapshot(row)
    return out


# ---------------------------------------------------------------------------
# Representative arguments that reference org-B ids / values
# ---------------------------------------------------------------------------

_HOST_PARAMS = {"hostname", "target", "asset_ref"}
_TEXT_PARAMS = {"title", "name", "note", "reason", "description", "root_cause", "resolution", "lessons_learned", "recommendations", "source", "category"}


def _value_for(tool: str, name: str, p: ParamSpec, b: dict[str, Any], tag: str) -> Any:
    if p.ref:
        return b[p.ref].id
    if p.ref_by_value:
        model, column = p.ref_by_value
        return getattr(b[model], column)
    if name in _HOST_PARAMS:
        return b["Asset"].hostname
    if name == "ip":
        return b["Alert"].source_ip
    if name == "vulnerability":
        return b["Vulnerability"].cve_id
    if name == "framework":
        return b["ComplianceFramework"].short_name
    if name == "control_ref":
        return b["ComplianceControl"].control_id
    if name in ("technique",):
        return "T1059"
    if name == "techniques":
        return ["T1059"]
    if name == "keyword":
        return {"search_alerts": b["Alert"].title, "search_logs": b["LogEntry"].message, "list_playbooks": b["Playbook"].name,
                "list_assets": b["Asset"].hostname, "list_vulnerabilities": b["Vulnerability"].title}.get(tool, f"{tag} keyword")
    if name == "query":
        return f"{tag} query"
    if name == "hypothesis":
        return b["LogEntry"].message
    if name == "value":
        return b["ThreatIndicator"].value
    if name == "ioc_type":
        return b["ThreatIndicator"].indicator_type
    if name == "action_name":
        return "notify"
    if name == "action":
        return "collect_process_list"
    if name in ("input_data", "payload"):
        return {"hostname": b["Asset"].hostname}
    if p.enum:
        return p.enum[0]
    if p.type == "integer":
        return p.minimum if p.minimum is not None else 5
    if p.type == "boolean":
        return True
    if p.type == "array":
        return []
    if p.type == "object":
        return {}
    return f"{tag} {name}"


def args_for(spec: ToolSpec, b: dict[str, Any], tag: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, p in spec.params.items():
        wanted = p.required or p.ref or p.ref_by_value or name in _HOST_PARAMS or name in {"ip", "vulnerability", "framework", "control_ref", "keyword", "input_data", "payload", "incident_id"}
        if wanted:
            out[name] = _value_for(spec.name, name, p, b, tag)
    return out


def _string_leaves(node: Any) -> set[str]:
    if isinstance(node, str):
        return {node}
    if isinstance(node, dict):
        return set().union(*(_string_leaves(v) for v in node.values())) if node else set()
    if isinstance(node, (list, tuple)):
        return set().union(*(_string_leaves(v) for v in node)) if node else set()
    return set()


def _distinctive_values(rows: dict[str, Any], tag: str) -> set[str]:
    values: set[str] = set()
    for row in rows.values():
        values.add(str(row.id))
        for v in _snapshot(row).values():
            if isinstance(v, str) and tag in v:
                values.add(v)
    return values


# ---------------------------------------------------------------------------
# The parametrized isolation test
# ---------------------------------------------------------------------------

ALL_TOOLS = sorted(make_registry(None).specs)  # type: ignore[arg-type]


def _external_patches(tool: str):
    """Patches for out-of-process side effects (the DB behaviour stays real)."""
    if tool == "execute_playbook":
        return [patch("src.playbooks.tasks.run_playbook_execution")]
    if tool == "simulate_attack":
        # No atomic technique library / endpoint dispatch in unit tests; the
        # orchestrator's DB writes still happen for org A.
        return [patch("src.simulation.engine.SimulationOrchestrator._try_dispatch_to_agent", return_value=None)]
    return []


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ALL_TOOLS)
async def test_tool_is_tenant_isolated(db_session, tool: str):
    tag_a = f"orga{uuid.uuid4().hex[:6]}"
    tag_b = f"orgb{uuid.uuid4().hex[:6]}"
    rows_a = await seed_org(db_session, ORG_A, tag_a)
    rows_b = await seed_org(db_session, ORG_B, tag_b)
    await db_session.commit()

    actor = rows_a["User"]
    registry: AgentToolRegistry = make_registry(db_session, user=actor, role=make_registry(None).specs[tool].min_role)  # type: ignore[arg-type]
    spec = registry.specs[tool]
    args = args_for(spec, rows_b, tag_b)

    before = await _snapshot_all(db_session, rows_b)
    distinctive = _distinctive_values(rows_b, tag_b)
    supplied = _string_leaves(args)

    added_rows: list[Any] = []

    def _before_flush(session, flush_context, instances) -> None:  # noqa: ARG001
        added_rows.extend(list(session.new))

    sync_session = db_session.sync_session
    event.listen(sync_session, "before_flush", _before_flush)
    patches = _external_patches(tool)
    try:
        for p in patches:
            p.start()
        result = await run_tool(registry, tool, args)
    finally:
        for p in patches:
            p.stop()
        event.remove(sync_session, "before_flush", _before_flush)

    # (a) no org-B id or org-B-distinctive value in the result (input echo excluded)
    serialized = json.dumps(result, default=str)
    leaked = sorted(v for v in distinctive - supplied if v in serialized)
    assert leaked == [], f"{tool} leaked org-B values: {leaked}"

    # (b) no org-B row mutated
    await db_session.commit()
    after = await _snapshot_all(db_session, rows_b)
    changed = {name: (before[name], after[name]) for name in before if before[name] != after[name]}
    assert changed == {}, f"{tool} mutated org-B rows: {list(changed)}"

    # every row the tool created belongs to org A (or hangs off an org-A parent)
    for row in added_rows:
        org = getattr(row, "organization_id", None)
        if org is not None:
            assert org == ORG_A, f"{tool} created a row for {org}: {row!r}"
        else:
            assert type(row).__name__ in ("CaseNote", "CaseTimeline", "SimulationTest", "AuditLog"), f"{tool} created an unscoped row: {row!r}"

    # read-tier tools add nothing at all
    if spec.tier is Tier.READ:
        assert added_rows == [], f"{tool} is read-tier but added rows: {[type(r).__name__ for r in added_rows]}"
