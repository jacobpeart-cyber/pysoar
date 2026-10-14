"""Wave 3 (W3-A): the SIEM made real.

docs/audit/2026-10-08/intel-detection-B.md rows for SIEMDashboard:

* rule validation parses the YAML / detection logic and reports field
  errors; Create Rule refuses a rule without logic and stores logic the
  engine evaluates (an ingested log then raises the alert); Sigma import
  rejects constructs the engine cannot evaluate; count settings stored in
  the rule's columns reach the engine;
* data-source counters are written by ingest, per organisation;
* log search / aggregate are tenant-scoped, bounded and paginated;
* the overview metrics (events per second, 24h breakdowns, timeline, top
  rules, pipeline status) are computed from stored rows and live state;
* correlation buffers expire by time window and correlation ids are unique;
* engines pick up rule changes made by another process.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.alert import Alert
from src.siem import engine_manager
from src.siem.correlation import CorrelationEngine, SessionCorrelation
from src.siem.models import DetectionRule, LogEntry, SIEMDataSource
from src.siem.rule_validation import engine_yaml_for_rule, validate_rule

API = "/api/v1/siem"


@pytest.fixture(autouse=True)
def _fresh_engines():
    engine_manager.reset_engines()
    yield
    engine_manager.reset_engines()


async def _ingest(client: AsyncClient, headers: dict, raw: str, source_name: str = "host-a") -> dict:
    resp = await client.post(
        f"{API}/logs/ingest",
        json={"raw_log": raw, "source_type": "syslog", "source_name": source_name},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Rule validation and Create Rule
# ---------------------------------------------------------------------------


def test_validator_parses_yaml_and_reports_field_errors() -> None:
    bad_yaml = validate_rule(name="r", title="R", rule_yaml="title: x\ndetection: [unclosed\n")
    assert not bad_yaml.valid
    assert bad_yaml.field_errors[0]["field"] == "rule_yaml"
    assert "line" in bad_yaml.field_errors[0]["message"]

    unknown_sel = validate_rule(
        name="r", title="R",
        rule_yaml="title: x\ndetection:\n  sel:\n    raw_log|contains: a\n  condition: sel and other\n",
    )
    assert {"field": "rule_yaml.detection.condition",
            "message": "condition references unknown selection 'other'"} in unknown_sel.field_errors

    quantifier = validate_rule(
        name="r", title="R",
        rule_yaml="title: x\ndetection:\n  sel1:\n    a: b\n  condition: 1 of sel*\n",
    )
    assert not quantifier.valid and "quantifiers" in quantifier.messages()[0]

    bad_regex = validate_rule(name="r", title="R", detection_logic={"message": {"regex": "(unclosed"}})
    assert bad_regex.field_errors[0]["field"] == "detection_logic.message"

    bad_modifier = validate_rule(name="r", title="R", detection_logic={"message|base64offset": "x"})
    assert "not supported" in bad_modifier.field_errors[0]["message"]

    missing = validate_rule(name="", title="R", severity="severe")
    fields = {e["field"] for e in missing.field_errors}
    assert {"name", "severity", "detection_logic"} <= fields

    ok = validate_rule(
        name="r", title="R",
        rule_yaml="title: x\ndetection:\n  sel:\n    CommandLine|contains|all: [a, b]\n  filter:\n    user: svc\n"
        "  condition: sel and not filter\n",
    )
    assert ok.valid, ok.field_errors
    assert ok.detection["condition"] == "sel and not filter"


async def test_validate_route_returns_field_errors(client: AsyncClient, viewer_headers) -> None:
    resp = await client.post(
        f"{API}/rules/validate",
        json={"name": "r", "title": "R", "rule_yaml": "title: x\ndetection:\n  condition: sel\n"},
        headers=viewer_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["valid"] is False
    assert any(e["field"].startswith("rule_yaml.detection") for e in body["field_errors"])
    assert body["errors"] and all(":" in e for e in body["errors"])

    resp = await client.post(
        f"{API}/rules/validate",
        json={"name": "r", "title": "R", "detection_logic": {"raw_log": {"contains": "evil"}}},
        headers=viewer_headers,
    )
    assert resp.json()["valid"] is True
    assert resp.json()["detection"] == {"selection": {"raw_log": {"contains": "evil"}}, "condition": "selection"}


async def test_create_rule_without_logic_is_refused(client: AsyncClient, org_a_admin_headers) -> None:
    resp = await client.post(f"{API}/rules", json={"name": "inert", "title": "Inert"}, headers=org_a_admin_headers)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_rule"
    assert detail["field_errors"][0]["field"] == "detection_logic"

    resp = await client.post(
        f"{API}/rules",
        json={"name": "bad-cond", "title": "Bad", "detection_logic": {"a": "b"}, "condition": "selection and"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["field_errors"][0]["field"] == "condition"


async def test_created_rule_is_evaluated_on_ingest(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers, org_b_headers
) -> None:
    org_a_id = org_a.id
    name = f"w3-{uuid.uuid4().hex[:6]}"
    resp = await client.post(
        f"{API}/rules",
        json={
            "name": name,
            "title": "Wave three marker",
            "severity": "high",
            "detection_logic": {"raw_log": {"contains": "w3-evil-marker"}},
        },
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    rule_id = resp.json()["id"]
    assert resp.json()["engine_loaded"] is True

    hit = await _ingest(client, org_a_headers, "sshd: w3-evil-marker seen")
    assert hit["alerts_generated"] == 1
    assert hit["alerts"][0]["rule_id"] == rule_id
    miss = await _ingest(client, org_a_headers, "sshd: nothing to see")
    assert miss["alerts_generated"] == 0
    # Another tenant's identical log does not hit org A's rule.
    assert (await _ingest(client, org_b_headers, "sshd: w3-evil-marker seen", "host-b"))["alerts_generated"] == 0

    alerts = (await db_session.execute(select(Alert).where(Alert.source == "siem"))).scalars().all()
    assert [a.organization_id for a in alerts] == [org_a_id]
    db_session.expire_all()
    rule = await db_session.get(DetectionRule, rule_id)
    assert rule.match_count == 1

    # Export returns the YAML the engine evaluates (id = row id).
    exported = (await client.get(f"{API}/rules/{rule_id}/export", headers=org_a_headers)).json()["yaml"]
    assert f"id: {rule_id}" in exported and "w3-evil-marker" in exported

    # Updating the detection is validated too.
    resp = await client.put(
        f"{API}/rules/{rule_id}", json={"detection_logic": {"message": {"regex": "("}}}, headers=org_a_admin_headers
    )
    assert resp.status_code == 422
    resp = await client.put(f"{API}/rules/{rule_id}", json={"severity": "low"}, headers=org_a_admin_headers)
    assert resp.status_code == 200 and resp.json()["severity"] == "low"


async def test_sigma_import_rejects_what_the_engine_cannot_evaluate(
    client: AsyncClient, org_a_admin_headers
) -> None:
    unsupported = (
        "title: Needs quantifiers\nlevel: high\n"
        "detection:\n  sel_a:\n    raw_log|contains: a\n  sel_b:\n    raw_log|contains: b\n"
        "  condition: 1 of sel_*\n"
    )
    resp = await client.post(f"{API}/rules/import", json={"yaml": unsupported}, headers=org_a_admin_headers)
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["error"] == "invalid_rule"

    supported = (
        "title: Supported import\nid: 2b1c0e7e-0000-4000-8000-000000000001\nlevel: high\nstatus: test\n"
        "detection:\n  sel:\n    raw_log|contains: import-marker\n  condition: sel\n"
    )
    resp = await client.post(f"{API}/rules/import", json={"yaml": supported}, headers=org_a_admin_headers)
    assert resp.status_code == 201, resp.text
    # Sigma "status: test" no longer disables the rule in the engine.
    assert resp.json()["engine_loaded"] is True


def test_count_columns_reach_the_engine_yaml() -> None:
    import yaml

    rule = DetectionRule(
        id="r-1", name="brute", title="Brute force", severity="high",
        detection_logic=json.dumps({"outcome": "failure"}), condition="selection",
        timewindow=60, threshold=5, group_by=json.dumps(["source_address"]),
    )
    detection = yaml.safe_load(engine_yaml_for_rule(rule))["detection"]
    assert detection["timewindow"] == 60 and detection["threshold"] == 5
    assert detection["group_by"] == ["source_address"]


async def test_engine_reloads_rules_changed_by_another_process(
    db_session: AsyncSession, org_a, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_a_id = org_a.id
    await engine_manager.ensure_rules_loaded(db_session, org_a_id)
    assert engine_manager.get_rule_engine(org_a_id).rules == {}

    # Another process writes a rule straight to the database.
    rule = DetectionRule(
        name=f"other-{uuid.uuid4().hex[:6]}", title="Other process", severity="medium", enabled=True,
        detection_logic=json.dumps({"raw_log": {"contains": "x"}}), organization_id=org_a_id,
    )
    db_session.add(rule)
    await db_session.commit()

    monkeypatch.setattr(engine_manager, "RULE_REFRESH_SECONDS", 0.0)
    await engine_manager.ensure_rules_loaded(db_session, org_a_id)
    assert rule.id in engine_manager.get_rule_engine(org_a_id).rules


# ---------------------------------------------------------------------------
# Data-source counters
# ---------------------------------------------------------------------------


async def test_data_source_counters_written_by_ingest(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers, org_b_headers
) -> None:
    name = f"fw-{uuid.uuid4().hex[:6]}"
    resp = await client.post(
        f"{API}/sources", json={"name": name, "source_type": "syslog"}, headers=org_a_admin_headers
    )
    assert resp.status_code == 201, resp.text
    source_id = resp.json()["id"]
    assert resp.json()["events_received"] == 0 and resp.json()["ingest_status"] == "no_events"

    await _ingest(client, org_a_headers, "line one", source_name=name)
    await _ingest(client, org_a_headers, "line two", source_name=name)
    await _ingest(client, org_a_headers, "other source", source_name="not-the-source")
    # Another organisation's logs with the same source name do not count.
    await _ingest(client, org_b_headers, "tenant b", source_name=name)

    listed = (await client.get(f"{API}/sources", headers=org_a_headers)).json()
    source = next(s for s in listed if s["id"] == source_id)
    assert source["events_received"] == 2
    assert source["events_today"] == 2
    assert source["last_event_at"]
    assert source["ingest_status"] == "receiving"
    assert source["match_field"] == "source_name"

    stats = (await client.get(f"{API}/logs/stats", headers=org_a_headers)).json()
    assert stats["active_data_sources"] == 1 and stats["receiving_data_sources"] == 1

    # A disabled source reports so, whatever it received.
    await client.put(f"{API}/sources/{source_id}", json={"enabled": False}, headers=org_a_admin_headers)
    listed = (await client.get(f"{API}/sources", headers=org_a_headers)).json()
    assert next(s for s in listed if s["id"] == source_id)["ingest_status"] == "disabled"


# ---------------------------------------------------------------------------
# Search / aggregate bounds
# ---------------------------------------------------------------------------


async def test_search_is_bounded_paginated_and_filters_fields(
    client: AsyncClient, org_a_headers, org_b_headers
) -> None:
    for i in range(3):
        await _ingest(client, org_a_headers, f"search-marker {i}", source_name=f"src-{i}")

    resp = await client.post(
        f"{API}/logs/search", json={"query": "search-marker", "page": 1, "size": 2}, headers=org_a_headers
    )
    body = resp.json()
    assert body["total"] == 3 and len(body["items"]) == 2 and body["pages"] == 2
    assert body["window_start"] and body["window_end"]
    assert body["items"][0]["source_ip"] == "0.0.0.0" and body["items"][0]["raw_log"].startswith("search-marker")

    filtered = await client.post(
        f"{API}/logs/search",
        json={"query": "search-marker", "field_filters": {"source_name": "src-1"}},
        headers=org_a_headers,
    )
    assert [i["source_name"] for i in filtered.json()["items"]] == ["src-1"]

    bad_field = await client.post(
        f"{API}/logs/search", json={"field_filters": {"raw_log": "x"}}, headers=org_a_headers
    )
    assert bad_field.status_code == 422 and bad_field.json()["detail"]["error"] == "invalid_field_filter"

    too_deep = await client.post(f"{API}/logs/search", json={"page": 1000, "size": 500}, headers=org_a_headers)
    assert too_deep.status_code == 422 and too_deep.json()["detail"]["error"] == "page_out_of_range"

    now = datetime.now(timezone.utc)
    too_wide = await client.post(
        f"{API}/logs/search",
        json={"time_start": (now - timedelta(days=200)).isoformat(), "time_end": now.isoformat()},
        headers=org_a_headers,
    )
    assert too_wide.status_code == 422 and too_wide.json()["detail"]["error"] == "window_too_large"

    assert (
        await client.post(f"{API}/logs/search", json={"query": "search-marker"}, headers=org_b_headers)
    ).json()["total"] == 0


async def test_aggregate_is_scoped_and_bounded(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, org_b_headers
) -> None:
    org_a_id = org_a.id
    await _ingest(client, org_a_headers, "agg one", source_name="agg-src")
    await _ingest(client, org_a_headers, "agg two", source_name="agg-src")
    await _ingest(client, org_b_headers, "agg b", source_name="agg-src")
    # A log ingested 120 days ago is outside the default window.
    old = datetime.now(timezone.utc) - timedelta(days=120)
    db_session.add(LogEntry(
        organization_id=org_a_id, timestamp=old.isoformat(), received_at=old.isoformat(),
        source_type="syslog", source_name="agg-src", source_ip="10.0.0.1", log_type="system", severity="low",
        raw_log="ancient", created_at=old, updated_at=old,
    ))
    await db_session.commit()

    body = (
        await client.post(f"{API}/logs/aggregate", json={"field": "source_name", "top_n": 5}, headers=org_a_headers)
    ).json()
    assert body["aggregations"] == {"agg-src": 2}
    assert body["window_start"] and body["truncated"] is False

    bad = await client.post(f"{API}/logs/aggregate", json={"field": "raw_log"}, headers=org_a_headers)
    assert bad.status_code == 400


# ---------------------------------------------------------------------------
# Overview metrics and pipeline status
# ---------------------------------------------------------------------------


async def test_overview_metrics_are_computed_from_stored_rows(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers, org_b_headers
) -> None:
    org_a_id = org_a.id
    resp = await client.post(
        f"{API}/rules",
        json={"name": f"top-{uuid.uuid4().hex[:6]}", "title": "Top rule", "severity": "medium",
              "detection_logic": {"raw_log": {"contains": "top-marker"}}},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    for i in range(4):
        await _ingest(client, org_a_headers, f"top-marker {i}" if i < 3 else "plain line")
    two_days_ago = datetime.now(timezone.utc) - timedelta(days=2)
    db_session.add(LogEntry(
        organization_id=org_a_id, timestamp=two_days_ago.isoformat(), received_at=two_days_ago.isoformat(),
        source_type="syslog", source_name="old", source_ip="10.0.0.1", log_type="system", severity="low",
        raw_log="old", created_at=two_days_ago, updated_at=two_days_ago,
    ))
    await db_session.commit()

    stats = (await client.get(f"{API}/logs/stats", headers=org_a_headers)).json()
    assert stats["total_logs"] == 5
    assert stats["logs_24h"] == 4
    assert stats["events_per_second"] == round(4 / 300, 3)
    assert stats["events_per_second_window_seconds"] == 300
    assert len(stats["ingestion_timeline"]) == 24
    assert sum(b["count"] for b in stats["ingestion_timeline"]) == 4
    assert stats["ingestion_timeline"][-1]["count"] == 4
    assert sum(b["value"] for b in stats["logs_by_source_type"]) == 4
    assert stats["top_rules"] == [{"name": "Top rule", "count": 3, "severity": "medium"}]
    assert stats["rule_matches_today"] == 3 and stats["alerts_triggered_24h"] == 3
    assert stats["ingestion_rate_per_hour"] == round(4 / 24, 2)
    assert stats["last_ingest_at"]
    assert {d["kind"] for d in stats["recent_detections"]} == {"rule_alert"}

    pipeline = stats["pipeline_status"]
    assert pipeline["stages"]["ingestion"]["state"] == "receiving"
    assert pipeline["stages"]["ingestion"]["events_last_5m"] == 4
    assert pipeline["stages"]["collector"]["state"] == "stopped"
    assert pipeline["stages"]["detection"] == {"state": "active", "rules_enabled": stats["active_rules"],
                                               "rule_alerts_24h": 3}
    assert pipeline["stages"]["queue"]["state"] in {"not_started", "running", "no_consumers", "unavailable"}

    empty = (await client.get(f"{API}/logs/stats", headers=org_b_headers)).json()
    assert empty["logs_24h"] == 0 and empty["events_per_second"] == 0
    assert empty["top_rules"] == [] and empty["last_ingest_at"] is None
    assert empty["pipeline_status"]["overall"] == "no_data"


async def test_collector_status_has_dashboard_keys(client: AsyncClient, viewer_headers) -> None:
    body = (await client.get(f"{API}/collector/status", headers=viewer_headers)).json()
    assert body["status"] == "stopped" and body["running"] is False
    assert "port" in body and body["scope"] == "api_process"


# ---------------------------------------------------------------------------
# Correlation buffers
# ---------------------------------------------------------------------------


def test_correlation_buffers_expire_by_time_window_and_ids_are_unique() -> None:
    engine = CorrelationEngine(strategies=[SessionCorrelation()], time_window=timedelta(minutes=5))
    start = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)

    def event(i: int, minutes: int) -> dict:
        return {
            "event_id": f"e{i}", "timestamp": (start + timedelta(minutes=minutes)).isoformat(),
            "source_address": "10.9.0.1", "destination_address": f"10.8.0.{i}",
            "username": "dave", "event_type": "network",
        }

    # Two destinations, then a long gap: the old events leave the window,
    # so the third destination does not complete a session pattern.
    assert engine.process_event(event(1, 0)) == []
    assert engine.process_event(event(2, 1)) == []
    assert engine.process_event(event(3, 30)) == []
    first = engine.process_event(event(4, 31)) + engine.process_event(event(5, 32))
    assert len(first) == 1
    assert len(first[0].correlation_id) > 30  # full uuid, not 8 hex chars
    # Reported once: the group is cleared after it correlates.
    assert engine.process_event(event(6, 33)) == []
