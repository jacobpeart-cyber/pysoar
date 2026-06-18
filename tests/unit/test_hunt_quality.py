"""Hunt result quality — no keyword-noise findings, no crying wolf.

A naive single-keyword OR scan flagged every benign log that contained
one common word (e.g. "application"), producing hundreds of
"Log search match" findings at severity unknown, which the structured
hunt then mislabeled "suspicious_activity". These guard real quality.
"""

import json
from datetime import datetime, timezone

import pytest

from src.models.alert import Alert
from src.siem.models import LogEntry
from src.hunting.models import HuntFinding


def _log(msg, sev="informational", host="PLUTO", src="PLUTO/System"):
    now = datetime.now(timezone.utc).isoformat()
    return LogEntry(
        timestamp=now, received_at=now, source_type="windows_eventlog",
        source_name=src, source_ip="0.0.0.0", log_type="application",
        severity=sev, raw_log=msg, message=msg, hostname=host,
    )


@pytest.mark.asyncio
async def test_single_common_keyword_does_not_create_finding(db_session):
    from src.services.agent_tools import AgentToolRegistry
    # benign log that only contains ONE of the hypothesis keywords
    db_session.add(_log("Application Foo started successfully"))
    await db_session.commit()

    reg = AgentToolRegistry(db_session)
    out = await reg.execute("run_threat_hunt", {
        "hypothesis": "faulting application crashes indicate exploitation client execution",
        "timeframe_hours": 24,
    })
    assert out["success"] is True
    # one common word ("application") must NOT be enough to flag it
    assert out["result"]["findings"] == 0


@pytest.mark.asyncio
async def test_cooccurring_keywords_create_meaningful_finding(db_session):
    from src.services.agent_tools import AgentToolRegistry
    db_session.add(_log("Faulting application name: evil.exe, exception code 0xc0000005"))
    await db_session.commit()

    reg = AgentToolRegistry(db_session)
    out = await reg.execute("run_threat_hunt", {
        "hypothesis": "faulting application exception crash",
        "timeframe_hours": 24,
    })
    assert out["result"]["findings"] >= 1
    f = (await db_session.execute(
        __import__("sqlalchemy").select(HuntFinding)
    )).scalars().first()
    # title must carry real content, not the generic placeholder
    assert "Log search match" not in f.title
    assert "evil.exe" in f.title or "evil.exe" in (f.description or "")


@pytest.mark.asyncio
async def test_structured_hunt_does_not_cry_wolf_on_low_sev(db_session):
    from src.agentic.structured_hunt import run_structured_hunt
    from src.attack.loader import load_stix_bundle
    from tests.unit.test_attack_loader import _bundle
    await load_stix_bundle(db_session, _bundle(), domain="enterprise", attack_version="17.1")
    # only informational logs that co-occur on benign words
    for i in range(3):
        db_session.add(_log(f"faulting application exception benign run {i}", sev="informational"))
    await db_session.commit()

    r = await run_structured_hunt(
        db_session, hypothesis="faulting application exception T1110",
        organization_id="org-1", timeframe_hours=24,
    )
    # informational-only findings must not be called suspicious_activity
    if r["verdict"] == "suspicious_activity":
        # only allowed if there's a real medium+ finding
        assert any(f["severity"] in ("medium", "high", "critical") for f in r["phases"]["findings"])
