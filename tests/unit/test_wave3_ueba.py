"""Wave 3 (W3-C): the UEBA SIEM bridge feeds the UEBA module from stored logs.

Before wave 3 nothing created ``EntityProfile`` rows, so every UEBA widget
was empty. ``src/ueba/siem_bridge.py`` walks each organisation's stored
``log_entries`` from a per-org cursor, creates user / host entities, keeps
hourly activity buckets, scores each bucket against the entity's own earlier
buckets and raises ``UEBARiskAlert`` rows the dashboard reads.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.organization import Organization
from src.siem.models import LogEntry
from src.ueba import siem_bridge
from src.ueba.models import BehaviorBaseline, BehaviorEvent, EntityProfile, LogIngestCursor, UEBARiskAlert
from src.ueba.siem_bridge import log_window_query, run_bridge_for_org, score_bucket

NOW = datetime(2026, 10, 13, 12, 30, tzinfo=timezone.utc)
API = "/api/v1/ueba"


def _log(org_id: str, *, at: datetime, received: Optional[datetime] = None, username: Optional[str] = None,
         hostname: Optional[str] = None, outcome: Optional[str] = None, log_type: str = "authentication",
         action: Optional[str] = "login", source: Optional[str] = "203.0.113.10") -> LogEntry:
    return LogEntry(
        id=str(uuid.uuid4()),
        timestamp=at.isoformat(),
        received_at=(received or NOW - timedelta(minutes=30)).isoformat(),
        source_type="syslog", source_name="test", source_ip="192.0.2.1", log_type=log_type,
        severity="informational", raw_log="test", username=username, hostname=hostname,
        action=action, outcome=outcome, source_address=source, organization_id=org_id,
    )


def _history(org_id: str, user: str, hours: int = 30, ok: int = 10, failed: int = 2) -> list[LogEntry]:
    """``hours`` earlier clock hours of ordinary sign-in activity for ``user``."""
    rows: list[LogEntry] = []
    for h in range(2, hours + 2):
        at = NOW.replace(minute=5) - timedelta(hours=h)
        rows += [_log(org_id, at=at, username=user, outcome="success") for _ in range(ok)]
        rows += [_log(org_id, at=at, username=user, outcome="failure") for _ in range(failed)]
    return rows


async def _seed(db: AsyncSession, rows: list[LogEntry]) -> None:
    db.add_all(rows)
    await db.commit()


# ---------------------------------------------------------------------------
# Scoring method
# ---------------------------------------------------------------------------


def test_score_bucket_needs_a_baseline_and_flags_real_spikes() -> None:
    quiet = {"events": 12.0, "auth_successes": 10.0, "auth_failures": 2.0, "distinct_sources": 1.0,
             "distinct_peers": 0.0, "distinct_destinations": 0.0}
    spike = dict(quiet, events=25.0, auth_successes=0.0, auth_failures=25.0)

    warming = score_bucket(spike, [quiet] * 5)
    assert warming["status"] == "warming_up" and warming["flagged"] == [] and warming["anomaly_score"] == 0.0

    scored = score_bucket(spike, [quiet] * 30)
    flagged = {f["metric"]: f for f in scored["flagged"]}
    # std is 0, so the floor of 1 is used: z = (25 - 2) / 1
    assert flagged["auth_failures"]["z"] == 23.0
    assert flagged["events"]["z"] == 13.0
    assert scored["anomaly_score"] == 100.0  # min(100, 10 * 23)

    # A jump below the metric's absolute floor is not a spike.
    small = dict(quiet, auth_failures=4.0)
    assert score_bucket(small, [quiet] * 30)["flagged"] == []


def test_log_window_query_is_bounded_and_streamed() -> None:
    stmt = log_window_query("org", None, None, "2026-10-12T00:00:00+00:00", "2026-10-13T00:00:00+00:00",
                            500, (LogEntry.id,))
    assert stmt._limit_clause is not None
    assert stmt.get_execution_options().get("yield_per") == siem_bridge.BRIDGE_BATCH_SIZE
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    assert "organization_id = 'org'" in compiled


# ---------------------------------------------------------------------------
# Bridge run
# ---------------------------------------------------------------------------


async def test_bridge_creates_entities_buckets_and_an_alert_per_org(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    spike_at = NOW.replace(minute=10) - timedelta(hours=1)
    rows = _history(org_a_id, "alice")
    # Same source address as the history, so auth_failures is the top deviation.
    rows += [_log(org_a_id, at=spike_at, username="alice", outcome="failure") for _ in range(25)]
    rows.append(_log(org_a_id, at=spike_at, hostname="WS-01", log_type="process", action="exec", outcome=None))
    rows.append(_log(org_b_id, at=spike_at, username="bob", outcome="success"))
    await _seed(db_session, rows)

    result = await run_bridge_for_org(db_session, org_a_id, now=NOW)
    assert result["status"] == "ok"
    assert result["log_rows"] == 30 * 12 + 25 + 1
    assert result["alerts_created"] == 1

    entities = {
        (e.entity_type, e.entity_id): e
        for e in (await db_session.execute(
            select(EntityProfile).where(EntityProfile.organization_id == org_a_id)
        )).scalars().all()
    }
    assert set(entities) == {("user", "alice"), ("host", "ws-01")}
    # Org B's log never becomes an org A entity.
    assert ("user", "bob") not in entities

    alert = (await db_session.execute(
        select(UEBARiskAlert).where(UEBARiskAlert.organization_id == org_a_id)
    )).scalars().one()
    assert alert.alert_type == "auth_failure_spike"
    assert alert.severity == "high"
    assert alert.mitre_techniques == ["T1110"]
    top = alert.evidence[0]
    assert top["metric"] == "auth_failures" and top["value"] == 25.0 and top["baseline_buckets"] == 30

    alice = entities[("user", "alice")]
    assert alice.risk_score == alert.risk_score_delta > 0
    assert alice.anomaly_count_30d == 1
    assert alice.current_behavior["auth_failures"] == 25.0

    baseline = (await db_session.execute(
        select(BehaviorBaseline).where(
            BehaviorBaseline.entity_profile_id == alice.id,
            BehaviorBaseline.behavior_type == siem_bridge.EVENT_TYPE,
        )
    )).scalars().one()
    assert baseline.sample_count == 31
    assert baseline.statistical_model["metrics"]["auth_failures"]["n"] == 31

    cursor = (await db_session.execute(
        select(LogIngestCursor).where(LogIngestCursor.organization_id == org_a_id)
    )).scalars().one()
    assert cursor.consumer == "ueba_siem" and cursor.rows_processed_total == result["log_rows"]

    # A second run reads nothing new and counts nothing twice.
    again = await run_bridge_for_org(db_session, org_a_id, now=NOW)
    assert again["status"] == "idle" and again["log_rows"] == 0
    assert (await db_session.execute(
        select(func.count()).select_from(UEBARiskAlert).where(UEBARiskAlert.organization_id == org_a_id)
    )).scalar() == 1

    # Org B's own run creates only its entity.
    await run_bridge_for_org(db_session, org_b_id, now=NOW)
    names_b = (await db_session.execute(
        select(EntityProfile.entity_id).where(EntityProfile.organization_id == org_b_id)
    )).scalars().all()
    assert names_b == ["bob"]


async def test_new_logs_for_an_existing_hour_merge_into_the_same_bucket(
    db_session: AsyncSession, org_a: Organization,
) -> None:
    org_id = org_a.id
    at = NOW.replace(minute=1) - timedelta(hours=2)
    await _seed(db_session, [_log(org_id, at=at, username="carol", outcome="success",
                                  received=NOW - timedelta(hours=1)) for _ in range(3)])
    await run_bridge_for_org(db_session, org_id, now=NOW)
    await _seed(db_session, [_log(org_id, at=at, username="carol", outcome="failure",
                                  received=NOW - timedelta(minutes=5)) for _ in range(2)])
    await run_bridge_for_org(db_session, org_id, now=NOW)

    buckets = (await db_session.execute(
        select(BehaviorEvent).where(BehaviorEvent.organization_id == org_id,
                                    BehaviorEvent.event_type == siem_bridge.EVENT_TYPE)
    )).scalars().all()
    assert len(buckets) == 1
    counts = buckets[0].event_data["counts"]
    assert counts == {"events": 5, "auth_successes": 3, "auth_failures": 2}
    assert buckets[0].event_data["evaluation"]["status"] == "warming_up"


async def test_row_cap_defers_the_rest_to_the_next_run(db_session: AsyncSession, org_a: Organization) -> None:
    org_id = org_a.id
    at = NOW.replace(minute=0) - timedelta(hours=3)
    await _seed(db_session, [
        _log(org_id, at=at, username=f"user{i}", outcome="success", received=NOW - timedelta(minutes=40 - i))
        for i in range(10)
    ])
    first = await run_bridge_for_org(db_session, org_id, now=NOW, max_rows=4)
    assert first["status"] == "partial" and first["log_rows"] == 4
    second = await run_bridge_for_org(db_session, org_id, now=NOW, max_rows=100)
    assert second["log_rows"] == 6
    assert (await db_session.execute(
        select(func.count()).select_from(EntityProfile).where(EntityProfile.organization_id == org_id)
    )).scalar() == 10


async def test_daily_baseline_rebuild_leaves_the_bridge_baseline_alone(
    db_session: AsyncSession, org_a: Organization,
) -> None:
    from src.ueba.tasks import _update_entity_baselines_async

    org_id = org_a.id
    await _seed(db_session, _history(org_id, "dave", hours=3))
    await run_bridge_for_org(db_session, org_id, now=NOW)
    await _update_entity_baselines_async(org_id)
    row = (await db_session.execute(
        select(BehaviorBaseline).where(BehaviorBaseline.behavior_type == siem_bridge.EVENT_TYPE)
    )).scalars().one()
    await db_session.refresh(row)
    assert row.statistical_model["method"].startswith("per-active-hour")


async def test_task_sweeps_every_org_and_records_failures(
    db_session: AsyncSession, org_a: Organization, org_b: Organization, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.ueba import tasks

    org_a_id, org_b_id = org_a.id, org_b.id
    real = siem_bridge.run_bridge_for_org

    async def flaky(db: AsyncSession, org_id: str, **kw: Any) -> dict[str, Any]:
        if org_id == org_b_id:
            raise RuntimeError("boom")
        return await real(db, org_id, **kw)

    monkeypatch.setattr(siem_bridge, "run_bridge_for_org", flaky)
    totals = await tasks._bridge_siem_logs_async()
    assert totals["status"] == "partial"
    assert totals["failed_organizations"] == 1
    assert {e["organization_id"] for e in totals["errors"]} == {org_b_id}
    failed = (await db_session.execute(
        select(LogIngestCursor).where(LogIngestCursor.organization_id == org_b_id)
    )).scalars().one()
    assert failed.last_run_status == "failed" and failed.last_error == "boom"
    ok = (await db_session.execute(
        select(LogIngestCursor).where(LogIngestCursor.organization_id == org_a_id)
    )).scalars().one()
    assert ok.last_run_status in ("idle", "ok")


def test_bridge_task_is_scheduled_and_time_limited() -> None:
    from src.workers.celery_app import celery_app

    celery_app.loader.import_default_modules()
    assert "src.ueba.tasks.bridge_siem_logs" in celery_app.tasks
    entries = {e["task"]: e for e in celery_app.conf.beat_schedule.values()}
    assert entries["src.ueba.tasks.bridge_siem_logs"]["schedule"] == 300.0
    limits = celery_app.conf.task_annotations["src.ueba.tasks.bridge_siem_logs"]
    assert limits["time_limit"] < 300


# ---------------------------------------------------------------------------
# API: dashboard reads the bridge's rows; run / status routes
# ---------------------------------------------------------------------------


async def test_dashboard_shows_bridge_rows_and_status(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    spike_at = NOW.replace(minute=10) - timedelta(hours=1)
    rows = _history(org_id, "erin")
    rows += [_log(org_id, at=spike_at, username="erin", outcome="failure") for _ in range(25)]
    await _seed(db_session, rows)
    await run_bridge_for_org(db_session, org_id, now=NOW)

    resp = await client.get(f"{API}/dashboard", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_entities"] == 1
    assert body["siem_bridge"]["status"] == "ok"
    assert body["siem_bridge"]["last_run_summary"]["alerts_created"] == 1
    assert body["high_risk_entity_count"] == 0  # one high alert adds 20 risk points
    assert [d["severity"] for d in body["alert_distribution"]] == ["high"]

    other = (await client.get(f"{API}/dashboard", headers=org_b_headers)).json()
    assert other["total_entities"] == 0
    assert other["siem_bridge"]["status"] == "never_run"

    alerts = (await client.get(f"{API}/alerts", headers=org_a_headers)).json()
    items = alerts["items"] if isinstance(alerts, dict) else alerts
    assert any(a["alert_type"] == "auth_failure_spike" for a in items)


async def test_bridge_run_route_is_admin_only(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_headers: dict[str, str], org_a_admin_headers: dict[str, str], viewer_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    await _seed(db_session, [_log(org_id, at=datetime.now(timezone.utc) - timedelta(hours=1),
                                  received=datetime.now(timezone.utc) - timedelta(minutes=10),
                                  username="frank", outcome="success")])
    for headers in (viewer_headers, org_a_headers):
        assert (await client.post(f"{API}/siem-bridge/run", headers=headers)).status_code == 403

    resp = await client.post(f"{API}/siem-bridge/run", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["entities_created"] == 1

    status = (await client.get(f"{API}/siem-bridge/status", headers=viewer_headers)).json()
    assert status["status"] == "ok" and status["rows_processed_total"] == 1


async def test_bridge_routes_refuse_orgless_callers(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    resp = await client.get(f"{API}/siem-bridge/status", headers=superuser_headers)
    assert resp.status_code == 403
