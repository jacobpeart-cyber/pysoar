"""scope_hunt agent tool — PY-HUNT-001 Phase 1.

Validates a hunt hypothesis against the real ATT&CK KB: extracts/validates
techniques, reports detection-rule coverage and the telemetry that would
detect them (and whether PySOAR collects it), and surfaces asset
criticality for named hosts. Honest about EDR/DNS gaps.
"""

import json
from datetime import datetime, timezone

import pytest

from src.models.alert import Alert  # noqa: F401 (ensure metadata)
from src.models.asset import Asset
from src.siem.models import DetectionRule, LogEntry
from tests.unit.test_attack_loader import _bundle


_NOW = datetime.now(timezone.utc).isoformat()


async def _seed(db_session):
    from src.attack.loader import load_stix_bundle
    await load_stix_bundle(db_session, _bundle(), domain="enterprise", attack_version="17.1")
    # a rule covering T1110, and some collected syslog telemetry
    db_session.add(DetectionRule(
        name="cov-t1110", title="BF", status="active", enabled=True,
        severity="high", mitre_techniques=json.dumps(["T1110"]),
        organization_id="org-1",
    ))
    db_session.add(LogEntry(
        timestamp=_NOW, received_at=_NOW,
        source_type="syslog", source_name="syslog/host", source_ip="10.0.0.1",
        log_type="auth", severity="medium", raw_log="x",
        organization_id="org-1",
    ))
    db_session.add(Asset(
        name="dc-01", hostname="dc-01", asset_type="server", criticality="critical",
        organization_id="org-1",
    ))
    await db_session.commit()


@pytest.mark.asyncio
async def test_scope_extracts_and_validates_techniques(db_session):
    from tests.unit.test_tool_spec_invariants import make_registry, run_tool
    await _seed(db_session)
    reg = make_registry(db_session)

    out = await run_tool(reg, "scope_hunt", {
        "hypothesis": "Brute force T1110 against dc-01, also bogus T9999"
    })
    r = out
    ids = [t["technique"] for t in r["techniques_in_scope"]]
    assert "T1110" in ids
    assert "T9999" in r["unknown_techniques"]


@pytest.mark.asyncio
async def test_scope_reports_coverage_and_log_sources(db_session):
    from tests.unit.test_tool_spec_invariants import make_registry, run_tool
    await _seed(db_session)
    reg = make_registry(db_session)

    out = await run_tool(reg, "scope_hunt", {"hypothesis": "hunt T1110 brute force"})
    t = next(x for x in out["techniques_in_scope"] if x["technique"] == "T1110")
    assert t["detection_rule_count"] == 1
    assert t["covered"] is True
    assert "linux:syslog" in t["log_sources"]


@pytest.mark.asyncio
async def test_scope_surfaces_asset_criticality(db_session):
    from tests.unit.test_tool_spec_invariants import make_registry, run_tool
    await _seed(db_session)
    reg = make_registry(db_session)

    out = await run_tool(reg, "scope_hunt", {"hypothesis": "lateral movement to dc-01"})
    assets = out["assets_in_scope"]
    assert any(a["hostname"] == "dc-01" and a["criticality"] == "critical" for a in assets)


@pytest.mark.asyncio
async def test_scope_is_honest_about_collected_sources(db_session):
    from tests.unit.test_tool_spec_invariants import make_registry, run_tool
    await _seed(db_session)
    reg = make_registry(db_session)

    out = await run_tool(reg, "scope_hunt", {"hypothesis": "hunt T1110"})
    r = out
    assert "syslog" in r["collected_source_types"]
    # the honesty note must call out EDR/DNS not being integrated
    assert any("edr" in n.lower() or "dns" in n.lower() for n in r["notes"])


@pytest.mark.asyncio
async def test_scope_tool_in_investigator_allowlist():
    from src.agentic.investigator import INVESTIGATOR_READONLY_TOOLS
    assert "scope_hunt" in INVESTIGATOR_READONLY_TOOLS
