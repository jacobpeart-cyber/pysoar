"""Purple-team temporal detection correlation.

Before this change, detection scoring was static: a technique counted as
"detected" if any active rule merely LISTED its MITRE id — whether or not
anything fired when the technique actually executed, and
detection_time_seconds was hardcoded to 0.

Now, for real agent executions, detection requires evidence that fired
inside the execution window (a rule match on an ingested log, or a
correlation event carrying the technique), and latency is measured.
Coverage-only runs (no agent enrolled) keep the labeled legacy scoring.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from src.siem.models import CorrelationEvent, DetectionRule, LogEntry
from src.simulation.models import SimulationTest


TECH = "T1059.001"


def _technique():
    return SimpleNamespace(mitre_id=TECH)


def _test_obj(mode="real", started_minutes_ago=2):
    return SimulationTest(
        simulation_id="sim-1",
        technique_id="tech-1",
        test_name="purple test",
        status="running",
        started_at=datetime.now(timezone.utc) - timedelta(minutes=started_minutes_ago),
        detection_details={"execution_mode": mode, "agent_id": "agent-1"},
    )


@pytest.fixture
async def active_rule(db_session):
    rule = DetectionRule(
        name=f"win-powershell-spawn-{datetime.now(timezone.utc).timestamp()}",
        title="PowerShell spawned by Office app",
        status="active",
        severity="high",
        mitre_techniques=json.dumps([TECH]),
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    return rule


def _log_entry(rule_id: str, received: datetime) -> LogEntry:
    return LogEntry(
        timestamp=received.isoformat(),
        received_at=received.isoformat(),
        source_type="endpoint",
        source_name="ep-01",
        source_ip="10.0.0.5",
        log_type="process",
        severity="high",
        raw_log="powershell.exe -enc ...",
        rule_matches=json.dumps([rule_id]),
    )


async def _orchestrator(db_session):
    from src.simulation.engine import SimulationOrchestrator
    return SimulationOrchestrator(db_session)


@pytest.mark.asyncio
async def test_real_execution_detected_when_rule_fired_in_window(db_session, active_rule):
    fired = datetime.now(timezone.utc) - timedelta(seconds=60)
    db_session.add(_log_entry(active_rule.id, fired))
    await db_session.commit()

    orch = await _orchestrator(db_session)
    test = _test_obj(mode="real", started_minutes_ago=2)
    detected = await orch._check_detection(test, _technique())

    assert detected is True
    assert test.detection_details["correlation"] == "fired"
    # ~60s between execution start (2 min ago) and the log (1 min ago)
    assert 30 <= test.detection_time_seconds <= 90
    # earlier execution stamps must survive (regression: they were clobbered)
    assert test.detection_details["execution_mode"] == "real"
    assert test.detection_details["agent_id"] == "agent-1"


@pytest.mark.asyncio
async def test_real_execution_not_detected_when_nothing_fired(db_session, active_rule):
    orch = await _orchestrator(db_session)
    test = _test_obj(mode="real")
    detected = await orch._check_detection(test, _technique())

    assert detected is False
    assert test.detection_details["correlation"] == "coverage_only_not_fired"
    # The most actionable purple-team finding: a rule CLAIMS coverage but
    # did not fire when the technique actually ran.
    assert test.detection_details["coverage_rule_id"] == active_rule.id
    assert test.detection_details["execution_mode"] == "real"


@pytest.mark.asyncio
async def test_real_execution_ignores_matches_outside_window(db_session, active_rule):
    stale = datetime.now(timezone.utc) - timedelta(hours=3)
    db_session.add(_log_entry(active_rule.id, stale))
    await db_session.commit()

    orch = await _orchestrator(db_session)
    test = _test_obj(mode="real", started_minutes_ago=2)
    detected = await orch._check_detection(test, _technique())

    assert detected is False
    assert test.detection_details["correlation"] == "coverage_only_not_fired"


@pytest.mark.asyncio
async def test_real_execution_detects_via_correlation_event(db_session, active_rule):
    now = datetime.now(timezone.utc)
    event = CorrelationEvent(
        correlation_id="corr-1",
        name="Office spawning shells",
        severity="high",
        mitre_techniques=json.dumps([TECH]),
        timespan_start=(now - timedelta(minutes=1)).isoformat(),
        timespan_end=now.isoformat(),
    )
    db_session.add(event)
    await db_session.commit()

    orch = await _orchestrator(db_session)
    test = _test_obj(mode="real", started_minutes_ago=2)
    detected = await orch._check_detection(test, _technique())

    assert detected is True
    assert test.detection_details["correlation"] == "fired"
    assert "correlation_event" in test.detection_source


@pytest.mark.asyncio
async def test_coverage_only_mode_keeps_mapping_score(db_session, active_rule):
    orch = await _orchestrator(db_session)
    test = _test_obj(mode="coverage_only")
    detected = await orch._check_detection(test, _technique())

    assert detected is True
    assert test.detection_details["correlation"] == "coverage_mapping"
    assert test.detection_details["execution_mode"] == "coverage_only"
    assert test.detection_details["rule_id"] == active_rule.id


@pytest.mark.asyncio
async def test_no_rule_at_all_is_never_detected(db_session):
    orch = await _orchestrator(db_session)
    for mode in ("real", "coverage_only"):
        test = _test_obj(mode=mode)
        assert await orch._check_detection(test, _technique()) is False
