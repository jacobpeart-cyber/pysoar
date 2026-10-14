"""Wave 3 (W3-A): threat hunting made real.

docs/audit/2026-10-08/intel-detection-B.md ThreatHunting rows:

* pause / resume / cancel are checked compare-and-set transitions (409
  ``invalid_transition`` otherwise) and the executor honours them at every
  query boundary: a cancelled hunt stops at the next query and keeps
  CANCELLED, a paused hunt waits and continues when resumed;
* resume refuses a paused session whose executor is gone (heartbeat),
  and a beat sweep closes live sessions without a heartbeat;
* the structured executor (``HuntExecutor``) checks status before each query;
* the hypotheses priority filter is typed (1-5 or a label, else 422) and
  matches both stored spellings.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints import hunting as hunting_router
from src.hunting import engine as hunting_engine
from src.hunting.engine import HuntExecutor
from src.hunting.models import HuntHypothesis, HuntSession
from src.hunting.tasks import reap_stale_sessions
from src.intel.models import ThreatIndicator
from src.siem.search import SearchQuery, SearchResult

API = "/api/v1/hunting"


async def _seed(db: AsyncSession, org_id: str, status: str, **hyp: Any) -> tuple[str, str]:
    hypothesis = HuntHypothesis(
        organization_id=org_id,
        title=hyp.pop("title", "seeded hunt"),
        description=hyp.pop("description", "seeded"),
        hunt_type="behavioral",
        **hyp,
    )
    db.add(hypothesis)
    await db.flush()
    session = HuntSession(organization_id=org_id, hypothesis_id=hypothesis.id, status=status)
    db.add(session)
    await db.commit()
    return hypothesis.id, session.id


async def _status(db: AsyncSession, session_id: str) -> HuntSession:
    db.expire_all()
    return (await db.execute(select(HuntSession).where(HuntSession.id == session_id))).scalar_one()


# ---------------------------------------------------------------------------
# Checked transitions
# ---------------------------------------------------------------------------


async def test_transitions_are_checked(client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers) -> None:
    org_a_id = org_a.id
    _, sess_id = await _seed(db_session, org_a_id, "RUNNING")

    resp = await client.post(f"{API}/sessions/{sess_id}/pause", headers=org_a_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "PAUSED"

    again = await client.post(f"{API}/sessions/{sess_id}/pause", headers=org_a_headers)
    assert again.status_code == 409
    assert again.json()["detail"]["error"] == "invalid_transition"
    assert again.json()["detail"]["status"] == "PAUSED"

    resp = await client.post(f"{API}/sessions/{sess_id}/resume", headers=org_a_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "RUNNING"
    assert (await client.post(f"{API}/sessions/{sess_id}/resume", headers=org_a_headers)).status_code == 409

    resp = await client.post(f"{API}/sessions/{sess_id}/cancel", headers=org_a_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "CANCELLED"
    assert resp.json()["completed_at"]
    for action in ("pause", "resume", "cancel"):
        late = await client.post(f"{API}/sessions/{sess_id}/{action}", headers=org_a_headers)
        assert late.status_code == 409, action

    _, pending_id = await _seed(db_session, org_a_id, "PENDING")
    assert (await client.post(f"{API}/sessions/{pending_id}/pause", headers=org_a_headers)).status_code == 409
    assert (await client.post(f"{API}/sessions/{pending_id}/cancel", headers=org_a_headers)).status_code == 200


async def test_resume_refuses_a_session_whose_executor_is_gone(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers
) -> None:
    _, sess_id = await _seed(db_session, org_a.id, "PAUSED")
    stale = datetime.now(timezone.utc) - timedelta(seconds=hunting_router.HUNT_HEARTBEAT_STALE_SECONDS + 60)
    await db_session.execute(update(HuntSession).where(HuntSession.id == sess_id).values(updated_at=stale))
    await db_session.commit()

    resp = await client.post(f"{API}/sessions/{sess_id}/resume", headers=org_a_headers)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["error"] == "executor_not_running"
    row = await _status(db_session, sess_id)
    assert row.status == "FAILED" and "no executor heartbeat" in row.error_message


# ---------------------------------------------------------------------------
# The background executor honours pause / cancel at query boundaries
# ---------------------------------------------------------------------------


async def _seed_ioc_hunt(db: AsyncSession, org_id: str) -> tuple[str, str]:
    values = ["198.51.100.7", "198.51.100.8", "198.51.100.9"]
    for value in values:
        db.add(ThreatIndicator(
            organization_id=org_id, indicator_type="ipv4", value=value, is_active=True,
            severity="high", source="test-feed",
        ))
    await db.commit()
    return await _seed(
        db, org_id, "PENDING", title="Beaconing to bad hosts", description="known bad infrastructure",
        data_sources=json.dumps(values),
    )


async def test_cancel_stops_the_hunt_at_the_next_query(
    db_session: AsyncSession, org_a, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_a_id = org_a.id
    _, sess_id = await _seed_ioc_hunt(db_session, org_a_id)
    real_checkpoint = hunting_router._hunt_checkpoint
    calls = {"n": 0}

    async def cancel_after_first_ioc(db, session_id):
        calls["n"] += 1
        if calls["n"] == 2:  # 1: after the log scan; 2: after the first IOC query
            await db.execute(update(HuntSession).where(HuntSession.id == session_id).values(status="CANCELLED"))
        await real_checkpoint(db, session_id)

    monkeypatch.setattr(hunting_router, "_hunt_checkpoint", cancel_after_first_ioc)
    await hunting_router.execute_hunt_session(sess_id)

    row = await _status(db_session, sess_id)
    assert row.status == "CANCELLED"
    telemetry = json.loads(row.queries_executed)
    assert telemetry["stopped"] == "CANCELLED"
    assert telemetry["iocs_checked"] == 1  # the remaining two IOC queries never ran
    assert telemetry["alerts_scanned"] == 0 and telemetry["audit_logs_scanned"] == 0
    assert calls["n"] == 2


async def test_pause_waits_and_resume_continues(
    db_session: AsyncSession, org_a, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_a_id = org_a.id
    _, sess_id = await _seed_ioc_hunt(db_session, org_a_id)
    monkeypatch.setattr(hunting_router, "HUNT_PAUSE_POLL_SECONDS", 0.01)
    real_checkpoint = hunting_router._hunt_checkpoint
    real_heartbeat = hunting_router._hunt_heartbeat
    state = {"checkpoints": 0, "paused_polls": 0}

    async def pause_at_first_boundary(db, session_id):
        state["checkpoints"] += 1
        if state["checkpoints"] == 1:
            await db.execute(update(HuntSession).where(HuntSession.id == session_id).values(status="PAUSED"))
        await real_checkpoint(db, session_id)

    async def heartbeat_then_resume(db, session_id):
        await real_heartbeat(db, session_id)
        current = (await db.execute(select(HuntSession.status).where(HuntSession.id == session_id))).scalar_one()
        if current == "PAUSED":
            state["paused_polls"] += 1
            if state["paused_polls"] == 3:  # the analyst resumes while the hunt waits
                await db.execute(update(HuntSession).where(HuntSession.id == session_id).values(status="RUNNING"))

    monkeypatch.setattr(hunting_router, "_hunt_checkpoint", pause_at_first_boundary)
    monkeypatch.setattr(hunting_router, "_hunt_heartbeat", heartbeat_then_resume)
    await hunting_router.execute_hunt_session(sess_id)

    row = await _status(db_session, sess_id)
    assert row.status == "COMPLETED", row.error_message
    assert state["paused_polls"] == 3  # it waited while paused
    telemetry = json.loads(row.queries_executed)
    assert telemetry["iocs_checked"] == 3 and telemetry["stopped"] is None
    assert row.findings_count == 3


# ---------------------------------------------------------------------------
# Structured executor (HuntExecutor)
# ---------------------------------------------------------------------------


class _CapturingSearch:
    def __init__(self) -> None:
        self.queries: list = []

    async def search(self, db: AsyncSession, query: Any) -> SearchResult:
        self.queries.append(query)
        return SearchResult(items=[], total=0, page=1, size=10, pages=0, query_time_ms=0.0)


async def test_structured_executor_checks_status_before_each_query(
    db_session: AsyncSession, org_a, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_a_id = org_a.id
    search = _CapturingSearch()
    executor = HuntExecutor(db_session, organization_id=org_a_id, search_service=search)

    _, cancelled_id = await _seed(db_session, org_a_id, "CANCELLED")
    cancelled = await _status(db_session, cancelled_id)
    await executor._run_queries(cancelled, [SearchQuery(query_text="a"), SearchQuery(query_text="b")])
    assert search.queries == []

    monkeypatch.setattr(hunting_engine, "EXECUTOR_PAUSE_MAX_SECONDS", 0.0)
    _, paused_id = await _seed(db_session, org_a_id, "PAUSED")
    paused = await _status(db_session, paused_id)
    await executor._run_queries(paused, [SearchQuery(query_text="a")])
    assert search.queries == []
    assert (await _status(db_session, paused_id)).status == "CANCELLED"

    _, running_id = await _seed(db_session, org_a_id, "RUNNING")
    running = await _status(db_session, running_id)
    results = await executor._run_queries(running, [SearchQuery(query_text="a"), SearchQuery(query_text="b")])
    assert len(results) == 2 and len(search.queries) == 2


# ---------------------------------------------------------------------------
# Stale-session sweep
# ---------------------------------------------------------------------------


async def test_sweep_closes_sessions_without_heartbeat(db_session: AsyncSession, org_a, org_b) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    _, stale_running = await _seed(db_session, org_a_id, "RUNNING")
    _, stale_paused = await _seed(db_session, org_b_id, "PAUSED")
    _, fresh_running = await _seed(db_session, org_a_id, "RUNNING")
    _, old_completed = await _seed(db_session, org_a_id, "COMPLETED")
    long_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    await db_session.execute(
        update(HuntSession)
        .where(HuntSession.id.in_([stale_running, stale_paused, old_completed]))
        .values(updated_at=long_ago)
    )
    await db_session.commit()

    outcome = await reap_stale_sessions(db_session)
    await db_session.commit()
    assert outcome["reaped"] == 2
    assert outcome["by_organization"] == {org_a_id: 1, org_b_id: 1}
    for sid in (stale_running, stale_paused):
        row = await _status(db_session, sid)
        assert row.status == "FAILED" and "no heartbeat" in row.error_message and row.completed_at
    assert (await _status(db_session, fresh_running)).status == "RUNNING"
    assert (await _status(db_session, old_completed)).status == "COMPLETED"


def test_sweep_is_scheduled_with_limits() -> None:
    from src.workers.celery_app import celery_app

    assert "src.hunting.tasks" in celery_app.conf.include
    entry = celery_app.conf.beat_schedule["hunting-reap-stale-sessions"]
    assert entry["task"] == "hunting.reap_stale_sessions"
    assert celery_app.conf.task_annotations["hunting.reap_stale_sessions"]["time_limit"] > 0


# ---------------------------------------------------------------------------
# Typed priority filter
# ---------------------------------------------------------------------------


async def test_priority_filter_is_typed(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers
) -> None:
    org_a_id = org_a.id
    resp = await client.post(
        f"{API}/hypotheses", json={"title": "High prio", "description": "d", "priority": "high"}, headers=org_a_headers
    )
    assert resp.status_code == 201, resp.text
    api_id = resp.json()["id"]
    assert resp.json()["priority"] == 2
    # A row stored with the label spelling (model default style).
    labelled = HuntHypothesis(
        organization_id=org_a_id, title="Labelled", description="d", priority="high", hunt_type="behavioral"
    )
    low = HuntHypothesis(organization_id=org_a_id, title="Low", description="d", priority="4", hunt_type="behavioral")
    db_session.add_all([labelled, low])
    await db_session.commit()
    labelled_id = labelled.id

    for value in ("2", "high", "HIGH"):
        listed = await client.get(f"{API}/hypotheses", params={"priority": value}, headers=org_a_headers)
        assert listed.status_code == 200, listed.text
        assert {h["id"] for h in listed.json()["items"]} == {api_id, labelled_id}, value

    bad = await client.get(f"{API}/hypotheses", params={"priority": "urgent"}, headers=org_a_headers)
    assert bad.status_code == 422 and bad.json()["detail"]["error"] == "invalid_priority"
    assert (await client.get(f"{API}/hypotheses", params={"priority": 9}, headers=org_a_headers)).status_code == 422

    created_bad = await client.post(
        f"{API}/hypotheses", json={"title": "x", "description": "d", "priority": 9}, headers=org_a_headers
    )
    assert created_bad.status_code == 422
    updated_bad = await client.put(f"{API}/hypotheses/{api_id}", json={"priority": "sometime"}, headers=org_a_headers)
    assert updated_bad.status_code == 422
