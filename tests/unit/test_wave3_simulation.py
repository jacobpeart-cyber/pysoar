"""Wave 3 (W3-E): attack-simulation / purple-team deliverables.

Covers:

* posture per tactic computed from runs, with ``not_assessed`` for tactics
  that have no executed tests (no invented percentages);
* BAS detection lookups scoped to the organisation (another tenant's rule
  never credits a test);
* purple-team correlation matched by host as well as time window;
* atomic-test status driven by the agent command result (an agent error is
  an errored test, never silently a pass).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.simulation.engine import SimulationOrchestrator
from src.simulation.models import AttackSimulation, AttackTechnique, SimulationTest
from src.siem.models import DetectionRule, LogEntry

BASE = "/api/v1/simulation"
TECH = "T1059.001"


def _tech(mitre=TECH):
    return SimpleNamespace(mitre_id=mitre)


async def _make_technique(db, *, mitre, tactic, commands=None):
    t = AttackTechnique(
        mitre_id=mitre,
        name=f"name-{mitre}",
        tactic=tactic,
        platform=["linux"],
        test_commands=commands or [],
    )
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return t.id


async def _completed_sim_with_test(db, org_id, technique_id, *, detected):
    sim = AttackSimulation(
        name=f"sim-{uuid.uuid4().hex[:6]}",
        simulation_type="atomic_test",
        status="completed",
        target_environment="lab",
        scope={},
        mitre_tactics=[],
        mitre_techniques=[],
        created_by="seed",
        organization_id=org_id,
    )
    db.add(sim)
    await db.commit()
    await db.refresh(sim)
    db.add(SimulationTest(
        simulation_id=sim.id,
        technique_id=technique_id,
        test_name="t",
        status="passed" if detected else "blocked",
        executor="sh",
        was_detected=detected,
    ))
    await db.commit()
    return sim.id


# ---------------------------------------------------------------------------
# posture per tactic
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_posture_by_tactic_marks_untested_tactics_not_assessed(
    client: AsyncClient, db_session, org_a, org_a_headers,
):
    org_id = org_a.id
    exec_tech = await _make_technique(db_session, mitre="T1059.001", tactic="Execution")
    await _make_technique(db_session, mitre="T1078", tactic="Persistence")  # never tested
    await _completed_sim_with_test(db_session, org_id, exec_tech, detected=True)

    resp = await client.get(f"{BASE}/posture/by-tactic", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    by_tactic = {t["tactic"]: t for t in resp.json()["tactics"]}

    assert by_tactic["Execution"]["status"] == "assessed"
    assert by_tactic["Execution"]["detection_rate"] == 100.0
    assert by_tactic["Persistence"]["status"] == "not_assessed"
    assert by_tactic["Persistence"]["detection_rate"] is None


@pytest.mark.asyncio
async def test_posture_by_tactic_is_tenant_scoped(
    client: AsyncClient, db_session, org_a, org_b, org_a_headers,
):
    tech = await _make_technique(db_session, mitre="T1059.001", tactic="Execution")
    # Only org B has a completed run; org A must see Execution not_assessed.
    await _completed_sim_with_test(db_session, org_b.id, tech, detected=True)

    resp = await client.get(f"{BASE}/posture/by-tactic", headers=org_a_headers)
    assert resp.status_code == 200
    by_tactic = {t["tactic"]: t for t in resp.json()["tactics"]}
    assert by_tactic["Execution"]["status"] == "not_assessed"


# ---------------------------------------------------------------------------
# detection scoped to the organisation
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_detection_rule_from_other_org_never_credits(db_session, org_a, org_b):
    sim = AttackSimulation(
        name="s", simulation_type="atomic_test", status="running",
        target_environment="lab", scope={}, mitre_tactics=[], mitre_techniques=[TECH],
        created_by="seed", organization_id=org_a.id,
    )
    db_session.add(sim)
    await db_session.commit()
    await db_session.refresh(sim)
    sim_id = sim.id

    # Rule lives in org B only.
    db_session.add(DetectionRule(
        organization_id=org_b.id, name="other-org-rule", title="x",
        status="active", severity="high", mitre_techniques=json.dumps([TECH]),
    ))
    await db_session.commit()

    orch = SimulationOrchestrator(db_session)
    test = SimulationTest(
        simulation_id=sim_id, technique_id="tech-x", test_name="t",
        status="running", executor="sh",
        detection_details={"execution_mode": "coverage_only"},
    )
    assert await orch._check_detection(test, _tech()) is False


# ---------------------------------------------------------------------------
# purple-team host correlation
# ---------------------------------------------------------------------------
async def _real_sim(db, org_id, host):
    sim = AttackSimulation(
        name="s", simulation_type="atomic_test", status="running",
        target_environment="lab", scope={"target_host": host},
        mitre_tactics=[], mitre_techniques=[TECH],
        created_by="seed", organization_id=org_id,
    )
    db.add(sim)
    await db.commit()
    await db.refresh(sim)
    return sim.id


def _real_test(sim_id):
    return SimulationTest(
        simulation_id=sim_id, technique_id="tech-x", test_name="t",
        status="running", executor="sh",
        started_at=datetime.now(timezone.utc) - timedelta(minutes=2),
        detection_details={"execution_mode": "real", "agent_id": "a1"},
    )


def _log(rule_id, host, org_id, *, secs_ago=60):
    fired = datetime.now(timezone.utc) - timedelta(seconds=secs_ago)
    return LogEntry(
        organization_id=org_id, timestamp=fired.isoformat(), received_at=fired.isoformat(),
        source_type="endpoint", source_name=host, source_ip="10.0.0.5",
        hostname=host, log_type="process", severity="high",
        raw_log="powershell", rule_matches=json.dumps([rule_id]),
    )


@pytest.mark.asyncio
async def test_detection_requires_matching_host(db_session, org_a):
    org_id = org_a.id
    rule = DetectionRule(
        organization_id=org_id, name=f"r-{uuid.uuid4().hex[:6]}", title="x",
        status="active", severity="high", mitre_techniques=json.dumps([TECH]),
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    rule_id = rule.id

    sim_id = await _real_sim(db_session, org_id, "host-x")

    # Evidence on a DIFFERENT host must not credit the run.
    db_session.add(_log(rule_id, "host-y", org_id))
    await db_session.commit()
    orch = SimulationOrchestrator(db_session)
    assert await orch._check_detection(_real_test(sim_id), _tech()) is False

    # Evidence on the targeted host does.
    db_session.add(_log(rule_id, "host-x", org_id))
    await db_session.commit()
    assert await orch._check_detection(_real_test(sim_id), _tech()) is True


# ---------------------------------------------------------------------------
# agent command result drives the test status
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_agent_error_marks_test_errored_not_passed(db_session, org_a):
    tech_id = await _make_technique(
        db_session, mitre="T1003", tactic="Credential Access",
        commands=[{"command": "whoami", "executor": "sh"}],
    )
    sim_id = await _real_sim(db_session, org_a.id, "host-x")
    test = SimulationTest(
        simulation_id=sim_id, technique_id=tech_id, test_name="t",
        status="pending", executor="sh",
    )
    db_session.add(test)
    await db_session.commit()

    orch = SimulationOrchestrator(db_session)

    async def _fake_dispatch(**kwargs):
        return SimpleNamespace(
            stdout="", stderr="command failed", status="error",
            agent_id="a1", command_id="c1",
        )

    orch._try_dispatch_to_agent = _fake_dispatch  # type: ignore[assignment]

    await orch._execute_test(test)

    # The command result (error) drives the status; it is NOT overwritten to
    # passed/blocked, and a technique that never ran is not scored detected.
    assert test.status == "error"
    assert test.was_detected is None
