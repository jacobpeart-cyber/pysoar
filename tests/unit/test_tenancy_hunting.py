"""Wave 1 tenancy / RBAC conversion of the hunting router and executors.

docs/audit/2026-10-08/intel-detection-B.md (c) items 5, 6, 10, 11, 13 and 23:
hypotheses, sessions, findings and stats are scoped to the caller's
organisation and stamped on create; the background hunt executor only reads
the session organisation's logs, alerts, audit log and indicators (plus
platform feed intel); escalated incidents carry the organisation; every write
needs analyst or admin; pause / cancel are honoured by the executor.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints import hunting as hunting_router
from src.hunting.engine import HuntExecutor
from src.hunting.models import HuntFinding, HuntHypothesis, HuntSession, HuntTemplate, SessionStatus
from src.intel.models import ThreatIndicator
from src.models.alert import Alert
from src.models.incident import Incident
from src.models.organization import Organization
from src.siem.models import LogEntry
from src.siem.search import SearchQuery, SearchResult
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/hunting"


async def _create_hypothesis(client: AsyncClient, headers: dict[str, str], **extra: Any) -> str:
    body = {"title": "Credential dumping", "description": "mimikatz on domain controllers", **extra}
    resp = await client.post(f"{API}/hypotheses", json=body, headers=headers)
    assert resp.status_code == 201, resp.text[:300]
    return resp.json()["id"]


async def _seed_session(db: AsyncSession, org_id: str, status: str = "COMPLETED") -> tuple[str, str]:
    hyp = HuntHypothesis(organization_id=org_id, title="seeded", description="seeded", hunt_type="behavioral")
    db.add(hyp)
    await db.flush()
    sess = HuntSession(organization_id=org_id, hypothesis_id=hyp.id, status=status)
    db.add(sess)
    await db.commit()
    return hyp.id, sess.id


def _log(org_id: str, message: str) -> LogEntry:
    now = datetime.now(timezone.utc).isoformat()
    return LogEntry(
        organization_id=org_id,
        timestamp=now,
        received_at=now,
        source_type="syslog",
        source_name="dc",
        source_ip="10.0.0.1",
        log_type="process",
        raw_log=message,
        message=message,
    )


# ---------------------------------------------------------------------------
# hypotheses
# ---------------------------------------------------------------------------


async def test_hypotheses_stamped_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    hyp_id = await _create_hypothesis(client, org_a_headers, priority=2)
    row = (await db_session.execute(select(HuntHypothesis).where(HuntHypothesis.id == hyp_id))).scalar_one()
    assert row.organization_id == org_a_id

    for method, path, body in (
        ("GET", f"{API}/hypotheses/{hyp_id}", None),
        ("PUT", f"{API}/hypotheses/{hyp_id}", {"title": "pwned"}),
        ("POST", f"{API}/hypotheses/{hyp_id}/activate", None),
        ("DELETE", f"{API}/hypotheses/{hyp_id}", None),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    listed_b = await client.get(f"{API}/hypotheses", headers=org_b_headers)
    assert listed_b.status_code == 200
    assert hyp_id not in [h["id"] for h in listed_b.json()["items"]]

    # The owner can act on it (used to 404 because the row had a NULL org).
    own = await client.get(f"{API}/hypotheses/{hyp_id}", headers=org_a_headers)
    assert own.status_code == 200
    # priority filter: VARCHAR column compared as a string (regression)
    by_priority = await client.get(f"{API}/hypotheses", params={"priority": 2}, headers=org_a_headers)
    assert by_priority.status_code == 200
    assert [h["id"] for h in by_priority.json()["items"]] == [hyp_id]
    activated = await client.post(f"{API}/hypotheses/{hyp_id}/activate", headers=org_a_headers)
    assert activated.status_code == 200 and activated.json()["status"] == "ACTIVE"


async def test_org_less_superuser_needs_an_organisation(
    client: AsyncClient, superuser_headers: dict[str, str],
) -> None:
    for path in (f"{API}/hypotheses", f"{API}/sessions", f"{API}/findings", f"{API}/stats"):
        resp = await client.get(path, headers=superuser_headers)
        assert resp.status_code == 403, path
        assert "organization_required" in resp.text


# ---------------------------------------------------------------------------
# sessions + background executor
# ---------------------------------------------------------------------------


async def test_session_executor_only_hunts_own_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    log_a, log_b = _log(org_a_id, "mimikatz sekurlsa on dc-a"), _log(org_b_id, "mimikatz sekurlsa on dc-b")
    alert_a = Alert(title="mimikatz seen on dc-a", severity="high", status="new", source="siem", organization_id=org_a_id)
    alert_b = Alert(title="mimikatz seen on dc-b", severity="high", status="new", source="siem", organization_id=org_b_id)
    platform_ioc = ThreatIndicator(indicator_type="ip", value="203.0.113.9", is_active=True, organization_id=None)
    other_ioc = ThreatIndicator(indicator_type="ip", value="198.51.100.7", is_active=True, organization_id=org_b_id)
    db_session.add_all([log_a, log_b, alert_a, alert_b, platform_ioc, other_ioc])
    await db_session.commit()
    ids = {
        "log_a": log_a.id, "log_b": log_b.id, "alert_a": alert_a.id, "alert_b": alert_b.id,
        "ioc_platform": platform_ioc.id, "ioc_b": other_ioc.id,
    }

    hyp_id = await _create_hypothesis(
        client, org_a_headers, data_sources=["203.0.113.9", "198.51.100.7"],
    )
    resp = await client.post(f"{API}/sessions", json={"hypothesis_id": hyp_id}, headers=org_a_headers)
    assert resp.status_code == 201, resp.text[:300]
    sess_id = resp.json()["id"]

    db_session.expire_all()
    sess = (await db_session.execute(select(HuntSession).where(HuntSession.id == sess_id))).scalar_one()
    assert sess.organization_id == org_a_id
    assert sess.status == "COMPLETED", sess.error_message
    findings = list(
        (await db_session.execute(select(HuntFinding).where(HuntFinding.session_id == sess_id))).scalars().all()
    )
    assert findings and all(f.organization_id == org_a_id for f in findings)
    evidence = [json.loads(f.evidence) for f in findings]
    log_ids = {e.get("log_id") for e in evidence}
    alert_ids = {e.get("alert_id") for e in evidence}
    ioc_ids = {e.get("indicator_id") for e in evidence}
    assert ids["log_a"] in log_ids and ids["log_b"] not in log_ids
    assert ids["alert_a"] in alert_ids and ids["alert_b"] not in alert_ids
    assert ids["ioc_platform"] in ioc_ids and ids["ioc_b"] not in ioc_ids

    # Org B cannot see or steer org A's session, nor list its findings.
    for method, path in (
        ("GET", f"{API}/sessions/{sess_id}"),
        ("POST", f"{API}/sessions/{sess_id}/pause"),
        ("POST", f"{API}/sessions/{sess_id}/resume"),
        ("POST", f"{API}/sessions/{sess_id}/cancel"),
        ("GET", f"{API}/findings?session_id={sess_id}"),
        ("GET", f"{API}/sessions?hypothesis_id={hyp_id}"),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers)
    # ... nor start a hunt on A's hypothesis
    cross = await client.post(f"{API}/sessions", json={"hypothesis_id": hyp_id}, headers=org_b_headers)
    assert cross.status_code == 404
    listed_b = await client.get(f"{API}/sessions", headers=org_b_headers)
    assert sess_id not in [s["id"] for s in listed_b.json()["items"]]
    findings_b = await client.get(f"{API}/findings", headers=org_b_headers)
    assert findings_b.json()["total"] == 0
    stats_b = await client.get(f"{API}/stats", headers=org_b_headers)
    assert stats_b.status_code == 200
    assert stats_b.json()["total_hypotheses"] == 0 and stats_b.json()["total_findings"] == 0
    stats_a = await client.get(f"{API}/stats", headers=org_a_headers)
    assert stats_a.json()["total_hypotheses"] == 1
    assert stats_a.json()["total_findings"] == len(findings)


async def test_executor_refuses_org_less_session_and_respects_cancel(db_session: AsyncSession) -> None:
    orphan_hyp = HuntHypothesis(title="legacy", description="legacy", hunt_type="behavioral")
    db_session.add(orphan_hyp)
    await db_session.flush()
    orphan = HuntSession(hypothesis_id=orphan_hyp.id, status="PENDING")
    cancelled = HuntSession(organization_id="org-x", hypothesis_id=orphan_hyp.id, status="CANCELLED")
    db_session.add_all([orphan, cancelled])
    await db_session.commit()
    orphan_id, cancelled_id = orphan.id, cancelled.id

    await hunting_router.execute_hunt_session(orphan_id)
    await hunting_router.execute_hunt_session(cancelled_id)

    db_session.expire_all()
    orphan_row = (await db_session.execute(select(HuntSession).where(HuntSession.id == orphan_id))).scalar_one()
    assert orphan_row.status == "FAILED"
    assert "no organisation" in (orphan_row.error_message or "")
    cancelled_row = (
        await db_session.execute(select(HuntSession).where(HuntSession.id == cancelled_id))
    ).scalar_one()
    assert cancelled_row.status == "CANCELLED"


async def test_checkpoint_honours_cancel_and_pause_timeout(
    db_session: AsyncSession, org_a: Organization, monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a_id = org_a.id
    _, running_id = await _seed_session(db_session, org_a_id, status="RUNNING")
    _, cancelled_id = await _seed_session(db_session, org_a_id, status="CANCELLED")
    _, paused_id = await _seed_session(db_session, org_a_id, status="PAUSED")

    await hunting_router._hunt_checkpoint(db_session, running_id)  # keeps going
    with pytest.raises(hunting_router._HuntStopped):
        await hunting_router._hunt_checkpoint(db_session, cancelled_id)

    monkeypatch.setattr(hunting_router, "HUNT_PAUSE_MAX_SECONDS", 0.0)
    with pytest.raises(hunting_router._HuntStopped):
        await hunting_router._hunt_checkpoint(db_session, paused_id)
    db_session.expire_all()
    paused_row = (await db_session.execute(select(HuntSession).where(HuntSession.id == paused_id))).scalar_one()
    # a pause that outlives the limit cancels the hunt (no zombie RUNNING on resume)
    assert paused_row.status == "CANCELLED"


# ---------------------------------------------------------------------------
# findings + escalation
# ---------------------------------------------------------------------------


async def test_findings_stamped_isolated_and_escalation_carries_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    _, sess_a = await _seed_session(db_session, org_a_id)
    _, sess_b = await _seed_session(db_session, org_b_id)

    resp = await client.post(
        f"{API}/findings",
        json={"session_id": sess_a, "title": "beacon", "severity": "low"},
        headers=org_a_headers,
    )
    assert resp.status_code == 201, resp.text[:300]
    finding_id = resp.json()["id"]
    row = (await db_session.execute(select(HuntFinding).where(HuntFinding.id == finding_id))).scalar_one()
    assert row.organization_id == org_a_id

    # B cannot attach a finding to A's session or touch A's finding
    cross = await client.post(
        f"{API}/findings", json={"session_id": sess_a, "title": "x", "severity": "low"}, headers=org_b_headers,
    )
    assert cross.status_code == 404
    for method, path, body in (
        ("GET", f"{API}/findings/{finding_id}", None),
        ("PUT", f"{API}/findings/{finding_id}", {"classification": "false_positive"}),
        ("POST", f"{API}/findings/{finding_id}/escalate", None),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)
    own_b = await client.post(
        f"{API}/findings", json={"session_id": sess_b, "title": "b", "severity": "low"}, headers=org_b_headers,
    )
    assert own_b.status_code == 201
    listed_b = await client.get(f"{API}/findings", headers=org_b_headers)
    assert [f["id"] for f in listed_b.json()["items"]] == [own_b.json()["id"]]

    esc = await client.post(f"{API}/findings/{finding_id}/escalate", headers=org_a_headers)
    assert esc.status_code == 200, esc.text[:300]
    incident_id = esc.json()["incident_id"]
    incident = (await db_session.execute(select(Incident).where(Incident.id == incident_id))).scalar_one()
    assert incident.organization_id == org_a_id


# ---------------------------------------------------------------------------
# templates (platform scope, read-only)
# ---------------------------------------------------------------------------


async def test_platform_template_instantiates_into_caller_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    tpl = HuntTemplate(name="tpl-tenancy-test", hunt_type="behavioral", hypothesis_template="look for x")
    db_session.add(tpl)
    await db_session.commit()
    tpl_id = tpl.id

    # Regression: a template with NULL category/description/duration made the
    # whole list (and the by-id read) 500 on response validation.
    for headers in (org_a_headers, org_b_headers, viewer_headers):
        listed = await client.get(f"{API}/templates", headers=headers)
        assert listed.status_code == 200, listed.text[:300]
        assert tpl_id in [t["id"] for t in listed.json()]
    one = await client.get(f"{API}/templates/{tpl_id}", headers=org_b_headers)
    assert one.status_code == 200 and one.json()["category"] == ""

    denied = await client.post(f"{API}/templates/{tpl_id}/instantiate", json={}, headers=viewer_headers)
    assert denied.status_code == 403
    made = await client.post(f"{API}/templates/{tpl_id}/instantiate", json={}, headers=org_a_headers)
    assert made.status_code == 201, made.text[:300]
    hyp = (
        await db_session.execute(select(HuntHypothesis).where(HuntHypothesis.id == made.json()["id"]))
    ).scalar_one()
    assert hyp.organization_id == org_a_id
    await assert_tenant_isolated(client, "GET", f"{API}/hypotheses/{hyp.id}", org_b_headers)


# ---------------------------------------------------------------------------
# RBAC: viewers are read-only
# ---------------------------------------------------------------------------

WRITE_ROUTES = [
    ("POST", "/hypotheses", {"title": "t", "description": "d"}),
    ("PUT", "/hypotheses/{hyp}", {"title": "t"}),
    ("DELETE", "/hypotheses/{hyp}", None),
    ("POST", "/hypotheses/{hyp}/activate", None),
    ("POST", "/sessions", {"hypothesis_id": "{hyp}"}),
    ("POST", "/sessions/{sess}/pause", None),
    ("POST", "/sessions/{sess}/resume", None),
    ("POST", "/sessions/{sess}/cancel", None),
    ("POST", "/findings", {"session_id": "{sess}", "title": "t", "severity": "low"}),
    ("PUT", "/findings/{finding}", {"classification": "true_positive"}),
    ("POST", "/findings/{finding}/escalate", None),
    ("POST", "/templates/{finding}/instantiate", {}),
    ("POST", "/notebooks", {"session_id": "{sess}", "title": "n"}),
    ("PUT", "/notebooks/{finding}", {"title": "n"}),
    ("POST", "/notebooks/{finding}/execute-cell", {"cell_index": 0}),
    ("POST", "/notebooks/{finding}/publish", None),
]


@pytest.mark.parametrize(("method", "path", "body"), WRITE_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
    method: str,
    path: str,
    body: Any,
) -> None:
    hyp_id, sess_id = await _seed_session(db_session, org_a.id)
    finding = HuntFinding(organization_id=org_a.id, session_id=sess_id, title="f", severity="low")
    db_session.add(finding)
    await db_session.commit()
    subs = {"{hyp}": hyp_id, "{sess}": sess_id, "{finding}": finding.id}

    def fill(value: Any) -> Any:
        if isinstance(value, str):
            for k, v in subs.items():
                value = value.replace(k, v)
            return value
        if isinstance(value, dict):
            return {k: fill(v) for k, v in value.items()}
        return value

    resp = await client.request(method, API + fill(path), json=fill(body), headers=viewer_headers)
    assert resp.status_code == 403, resp.text[:300]
    still = (await db_session.execute(select(HuntHypothesis).where(HuntHypothesis.id == hyp_id))).scalar_one()
    assert still is not None


async def test_viewer_can_read(
    client: AsyncClient, viewer_headers: dict[str, str],
) -> None:
    for path in ("/hypotheses", "/sessions", "/findings", "/stats", "/templates", "/notebooks"):
        resp = await client.get(API + path, headers=viewer_headers)
        assert resp.status_code == 200, (path, resp.text[:200])


# ---------------------------------------------------------------------------
# src/hunting/engine.py HuntExecutor
# ---------------------------------------------------------------------------


class _CapturingSearch:
    def __init__(self) -> None:
        self.queries: list = []

    async def search(self, db: AsyncSession, query: Any) -> SearchResult:
        self.queries.append(query)
        return SearchResult(items=[], total=0, page=1, size=10, pages=0, query_time_ms=0.0)


async def test_engine_executor_is_tenant_scoped(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    with pytest.raises(ValueError):
        HuntExecutor(db_session, organization_id="")

    hyp_a, _ = await _seed_session(db_session, org_a_id)
    hyp_b, sess_b = await _seed_session(db_session, org_b_id)
    search = _CapturingSearch()
    executor = HuntExecutor(db_session, organization_id=org_a_id, search_service=search)

    with pytest.raises(LookupError):
        await executor.execute_hunt(hyp_b, {}, {"title": "x"})
    for op in (executor.pause_hunt, executor.resume_hunt, executor.cancel_hunt, executor.get_hunt_status):
        with pytest.raises(LookupError):
            await op(sess_b)

    session_id = await executor.execute_hunt(hyp_a, {}, {"title": "lateral movement"})
    assert search.queries and all(q.field_filters["organization_id"] == org_a_id for q in search.queries)
    row = (await db_session.execute(select(HuntSession).where(HuntSession.id == session_id))).scalar_one()
    assert row.organization_id == org_a_id and row.status == SessionStatus.COMPLETED.value
    status = await executor.get_hunt_status(session_id)
    assert status["status"] == SessionStatus.COMPLETED.value
    assert await executor.cancel_hunt(session_id) is False  # terminal stays terminal

    await executor._run_queries(row, [SearchQuery(field_filters={"organization_id": org_b_id})])
    assert search.queries[-1].field_filters["organization_id"] == org_a_id
