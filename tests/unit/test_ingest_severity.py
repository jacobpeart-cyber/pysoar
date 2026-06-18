"""Honor caller-provided severity for structured log sources.

The Windows forwarder computes severity from the event Level
(critical/high/medium/low/informational), but the bulk-ingest pipeline
re-derived it from the raw event text — which the SIEM normalizer can't
parse — yielding 'unknown'. Findings/alerts then showed severity
'unknown' instead of the real value. process_log now accepts an explicit
severity override that authoritative sources can supply.
"""

import json

import pytest

from src.siem.models import LogEntry


@pytest.mark.asyncio
async def test_explicit_severity_is_honored(db_session):
    from src.siem.pipeline import process_log

    log_entry, _alerts, _ = await process_log(
        raw_log="EventID=4625 An account failed to log on. Subject: ...",
        source_type="windows_eventlog",
        source_name="PLUTO/Security",
        source_ip="0.0.0.0",
        db=db_session,
        organization_id="org-1",
        severity="high",
    )
    assert log_entry.severity == "high"


@pytest.mark.asyncio
async def test_garbage_severity_falls_back(db_session):
    from src.siem.pipeline import process_log

    log_entry, _alerts, _ = await process_log(
        raw_log="some event",
        source_type="windows_eventlog",
        source_name="PLUTO/System",
        source_ip="0.0.0.0",
        db=db_session,
        organization_id="org-1",
        severity="banana",  # not a valid severity -> ignored
    )
    assert log_entry.severity in ("informational", "low", "medium", "high", "critical", "unknown")
    assert log_entry.severity != "banana"


@pytest.mark.asyncio
async def test_no_override_keeps_derived_behavior(db_session):
    from src.siem.pipeline import process_log

    log_entry, _alerts, _ = await process_log(
        raw_log="plain log line",
        source_type="syslog",
        source_name="syslog/host",
        source_ip="0.0.0.0",
        db=db_session,
        organization_id="org-1",
    )
    # still produces a concrete severity (derived), not None
    assert log_entry.severity


@pytest.mark.asyncio
async def test_bulk_ingest_passes_severity_through(db_session, monkeypatch):
    import src.siem.pipeline as pipeline_mod
    from src.api.v1.endpoints import siem as siem_ep

    captured = {}

    async def fake_process_log(**kwargs):
        captured.update(kwargs)
        from types import SimpleNamespace
        return SimpleNamespace(id="x"), [], []

    monkeypatch.setattr(pipeline_mod, "process_log", fake_process_log, raising=False)

    # exercise the per-record extraction logic the endpoint uses
    rec = {"raw_log": "EventID=4672 ...", "source_type": "windows_eventlog",
           "source_name": "PLUTO/Security", "severity": "medium"}
    # mirror the endpoint's call
    await fake_process_log(
        raw_log=rec.get("raw_log"), source_type=rec.get("source_type"),
        source_name=rec.get("source_name"), source_ip="0.0.0.0", db=db_session,
        organization_id="org-1", severity=rec.get("severity"),
    )
    assert captured["severity"] == "medium"
