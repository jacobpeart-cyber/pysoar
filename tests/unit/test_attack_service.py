"""ATT&CK query service — lookups, search, id extraction, coverage."""

import json

import pytest

from src.siem.models import DetectionRule
from tests.unit.test_attack_loader import _bundle


async def _seed_kb(db):
    from src.attack.loader import load_stix_bundle
    await load_stix_bundle(db, _bundle(), domain="enterprise", attack_version="17.1")
    await db.commit()


@pytest.mark.asyncio
async def test_get_technique_full_context(db_session):
    from src.attack.service import AttackService

    await _seed_kb(db_session)
    svc = AttackService(db_session)
    tech = await svc.get_technique("T1110")

    assert tech is not None
    assert tech["external_id"] == "T1110"
    assert tech["name"] == "Brute Force"
    assert "credential-access" in tech["tactics"]
    # full graph context
    assert "M1032" in [m["external_id"] for m in tech["mitigations"]]
    assert "G0016" in [g["external_id"] for g in tech["groups"]]
    assert "Logon Session Creation" in [d["data_component"] for d in tech["data_components"]]
    assert tech["subtechniques"] and tech["subtechniques"][0]["external_id"] == "T1110.001"


@pytest.mark.asyncio
async def test_get_unknown_technique_returns_none(db_session):
    from src.attack.service import AttackService
    await _seed_kb(db_session)
    assert await AttackService(db_session).get_technique("T9999") is None


@pytest.mark.asyncio
async def test_search_by_name_and_id(db_session):
    from src.attack.service import AttackService
    await _seed_kb(db_session)
    svc = AttackService(db_session)

    by_name = await svc.search("brute")
    assert any(r["external_id"] == "T1110" for r in by_name["techniques"])

    by_group = await svc.search("cozy bear")
    assert any(r["external_id"] == "G0016" for r in by_group["groups"])


@pytest.mark.asyncio
async def test_extract_technique_ids_validates_against_kb(db_session):
    from src.attack.service import AttackService
    await _seed_kb(db_session)
    svc = AttackService(db_session)

    hyp = "Look for T1110 and T1110.001 brute force, plus bogus T9999 and lowercase t1110"
    out = await svc.extract_technique_ids(hyp)
    assert "T1110" in out["valid"]
    assert "T1110.001" in out["valid"]
    assert "T9999" in out["unknown"]
    # deprecated T1086 surfaced separately if present in text
    out2 = await svc.extract_technique_ids("hunt for T1086 powershell")
    assert "T1086" in out2["deprecated"]


@pytest.mark.asyncio
async def test_coverage_maps_detection_rules(db_session):
    from src.attack.service import AttackService
    await _seed_kb(db_session)

    # One active rule covers T1110, nothing covers T1110.001.
    db_session.add(DetectionRule(
        name="cov-bruteforce", title="BF", status="active", enabled=True,
        severity="high", mitre_techniques=json.dumps(["T1110"]),
    ))
    await db_session.commit()

    cov = await AttackService(db_session).coverage(["T1110", "T1110.001"])
    by_tech = {c["technique"]: c for c in cov}
    assert by_tech["T1110"]["covered"] is True
    assert by_tech["T1110"]["rule_count"] == 1
    assert by_tech["T1110.001"]["covered"] is False
