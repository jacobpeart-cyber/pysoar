"""Real-data dashboard trend/status endpoints (data-lake + api-security).

Covers the 2026-07-01 honesty fixes:

- ``GET /data-lake/dashboard/pipeline-status`` no longer returns the
  hardcoded 42 active / 3 paused / 1 error / 99.76% constants plus a
  fabricated "pl_001" execution — every number now comes from the org's
  own DataPipeline rows.
- ``GET /data-lake/dashboard/ingestion-trend`` (new) buckets real
  ingested rows (log_entries etc.) per hour.
- ``GET /api-security/dashboard/risk-trend`` (new) buckets real
  APIVulnerability findings per day by severity.

All three must be org-scoped: org B's rows must never leak into org A's
numbers, and an org with no data must get honest zeros / empty lists.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from src.core.security import create_access_token, get_password_hash
from src.models.organization import Organization
from src.models.user import User

API = "/api/v1"


# ---------------------------------------------------------------------------
# Fixtures: two orgs, one user each
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def two_tenants(db_session):
    async def _mk(label: str) -> tuple[Organization, User]:
        org = Organization(
            id=str(uuid.uuid4()),
            name=f"Trend Org {label}",
            slug=f"trend-org-{label.lower()}-{uuid.uuid4().hex[:6]}",
            is_active=True,
        )
        db_session.add(org)
        await db_session.flush()
        user = User(
            email=f"{label.lower()}@trend-test.local",
            hashed_password=get_password_hash("testpassword123"),
            full_name=f"Trend User {label}",
            role="admin",
            is_active=True,
            is_superuser=False,
            organization_id=org.id,
        )
        db_session.add(user)
        await db_session.flush()
        return org, user

    tenant_a = await _mk("A")
    tenant_b = await _mk("B")
    await db_session.commit()
    return tenant_a, tenant_b


def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


# ---------------------------------------------------------------------------
# /data-lake/dashboard/pipeline-status
# ---------------------------------------------------------------------------


async def _seed_pipelines(db_session, org_a, org_b):
    from src.data_lake.models import DataPipeline

    now = datetime.now(timezone.utc)
    p1 = DataPipeline(
        organization_id=org_a.id,
        name="A ingest",
        pipeline_type="ingestion",
        destination="lake/a",
        transform_rules=[],
        status="active",
        records_processed_total=800,
        error_count=0,
        avg_processing_time_ms=120,
        last_run=(now - timedelta(hours=2)).isoformat(),
    )
    p2 = DataPipeline(
        organization_id=org_a.id,
        name="A enrich",
        pipeline_type="enrichment",
        destination="lake/a2",
        transform_rules=[],
        status="active",
        records_processed_total=200,
        error_count=100,
        avg_processing_time_ms=340,
        last_run=(now - timedelta(minutes=5)).isoformat(),
    )
    p3 = DataPipeline(
        organization_id=org_a.id,
        name="A paused",
        pipeline_type="export",
        destination="lake/a3",
        transform_rules=[],
        status="paused",
    )
    p4 = DataPipeline(
        organization_id=org_a.id,
        name="A broken",
        pipeline_type="aggregation",
        destination="lake/a4",
        transform_rules=[],
        status="failed",
    )
    b_pipes = [
        DataPipeline(
            organization_id=org_b.id,
            name=f"B pipe {i}",
            pipeline_type="ingestion",
            destination=f"lake/b{i}",
            transform_rules=[],
            status="active",
            records_processed_total=10,
            error_count=10,  # B is all-errors; must not drag down A's rate
            last_run=now.isoformat(),
        )
        for i in range(5)
    ]
    db_session.add_all([p1, p2, p3, p4, *b_pipes])
    await db_session.commit()
    return p1, p2, p3, p4


@pytest.mark.asyncio
async def test_pipeline_status_is_computed_from_real_rows(
    client, db_session, two_tenants
):
    (org_a, user_a), (org_b, user_b) = two_tenants
    p1, p2, p3, p4 = await _seed_pipelines(db_session, org_a, org_b)

    resp = await client.get(
        f"{API}/data-lake/dashboard/pipeline-status",
        params={"include_builtins": "false"},
        headers=_auth(user_a),
    )
    assert resp.status_code == 200
    body = resp.json()

    # The old fabricated constants must be gone.
    assert body["active_pipelines"] == 2
    assert body["paused_pipelines"] == 1
    assert body["error_pipelines"] == 1
    assert body["total_pipelines"] == 4

    # Real success rate: (800+200 - 100) / 1000 = 90.0 — org B's
    # all-error pipelines (10 records / 10 errors each) must not count.
    assert body["avg_success_rate"] == 90.0

    # Recent executions come from A's own rows that actually ran,
    # newest first; the fabricated "pl_001" is gone.
    execs = body["recent_executions"]
    assert [e["pipeline_id"] for e in execs] == [p2.id, p1.id]
    assert execs[0]["records_processed"] == 200
    assert execs[0]["execution_time_ms"] == 340
    assert all(not e["pipeline_id"].startswith("pl_") for e in execs)


@pytest.mark.asyncio
async def test_pipeline_status_org_isolation_and_empty_org(
    client, db_session, two_tenants
):
    (org_a, user_a), (org_b, user_b) = two_tenants
    p1, p2, _, _ = await _seed_pipelines(db_session, org_a, org_b)

    # Org B sees only its own 5 active pipelines, none of A's runs.
    resp_b = await client.get(
        f"{API}/data-lake/dashboard/pipeline-status",
        params={"include_builtins": "false"},
        headers=_auth(user_b),
    )
    assert resp_b.status_code == 200
    body_b = resp_b.json()
    assert body_b["active_pipelines"] == 5
    assert body_b["paused_pipelines"] == 0
    assert body_b["error_pipelines"] == 0
    b_exec_ids = {e["pipeline_id"] for e in body_b["recent_executions"]}
    assert p1.id not in b_exec_ids and p2.id not in b_exec_ids
    # B processed 50 records with 50 errors -> 0.0, not A's 90.0.
    assert body_b["avg_success_rate"] == 0.0


@pytest.mark.asyncio
async def test_pipeline_status_empty_org_is_honest_zero(client, two_tenants):
    (_, user_a), _ = two_tenants
    resp = await client.get(
        f"{API}/data-lake/dashboard/pipeline-status",
        params={"include_builtins": "false"},
        headers=_auth(user_a),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["active_pipelines"] == 0
    assert body["paused_pipelines"] == 0
    assert body["error_pipelines"] == 0
    assert body["total_pipelines"] == 0
    assert body["recent_executions"] == []
    assert body["avg_success_rate"] == 0.0


# ---------------------------------------------------------------------------
# /data-lake/dashboard/ingestion-trend
# ---------------------------------------------------------------------------


def _log_entry(org_id: str, created_at: datetime):
    from src.siem.models import LogEntry

    iso = created_at.isoformat()
    return LogEntry(
        timestamp=iso,
        received_at=iso,
        source_type="syslog",
        source_name="trend-test",
        source_ip="192.0.2.10",
        log_type="syslog",
        severity="informational",
        raw_log="trend test event",
        organization_id=org_id,
        created_at=created_at,
    )


@pytest.mark.asyncio
async def test_ingestion_trend_buckets_real_rows_per_org(
    client, db_session, two_tenants
):
    (org_a, user_a), (org_b, user_b) = two_tenants
    now = datetime.now(timezone.utc)

    db_session.add_all(
        [
            _log_entry(org_a.id, now),
            _log_entry(org_a.id, now),
            _log_entry(org_a.id, now - timedelta(hours=3)),
            *[_log_entry(org_b.id, now) for _ in range(5)],
        ]
    )
    await db_session.commit()

    resp_a = await client.get(
        f"{API}/data-lake/dashboard/ingestion-trend",
        params={"hours": 24},
        headers=_auth(user_a),
    )
    assert resp_a.status_code == 200
    body_a = resp_a.json()
    assert body_a["window_hours"] == 24
    assert body_a["total_events"] == 3
    assert sum(p["count"] for p in body_a["points"]) == 3
    # Dense hourly series covering the window.
    assert len(body_a["points"]) == 24
    # The current hour holds 2 events; the 3-hours-ago bucket holds 1.
    current_key = now.strftime("%Y-%m-%dT%H:00:00")
    by_time = {p["time"]: p["count"] for p in body_a["points"]}
    assert by_time[current_key] == 2
    assert by_time[(now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:00:00")] == 1
    assert body_a["by_source"] == {"SIEM Logs": 3}

    # Org B sees only its own 5 events — no cross-tenant bleed.
    resp_b = await client.get(
        f"{API}/data-lake/dashboard/ingestion-trend",
        headers=_auth(user_b),
    )
    assert resp_b.status_code == 200
    assert resp_b.json()["total_events"] == 5


@pytest.mark.asyncio
async def test_ingestion_trend_empty_org_returns_empty_points(client, two_tenants):
    (_, user_a), _ = two_tenants
    resp = await client.get(
        f"{API}/data-lake/dashboard/ingestion-trend",
        headers=_auth(user_a),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["points"] == []
    assert body["total_events"] == 0
    assert body["by_source"] == {}


# ---------------------------------------------------------------------------
# /api-security/dashboard/risk-trend
# ---------------------------------------------------------------------------


async def _seed_vulns(db_session, org_a, org_b):
    from src.api_security.models import (
        APIEndpointInventory,
        APIVulnerability,
        VulnerabilityTypeEnum,
    )

    now = datetime.now(timezone.utc)

    def _endpoint(org_id: str, path: str) -> APIEndpointInventory:
        return APIEndpointInventory(
            service_name="trend-svc",
            base_url="https://api.trend-test.local",
            path=path,
            method="GET",
            organization_id=org_id,
        )

    ep_a = _endpoint(org_a.id, "/a")
    ep_b = _endpoint(org_b.id, "/b")
    db_session.add_all([ep_a, ep_b])
    await db_session.flush()

    def _vuln(org_id, endpoint_id, severity, created_at):
        return APIVulnerability(
            endpoint_id=endpoint_id,
            vulnerability_type=VulnerabilityTypeEnum.BOLA,
            severity=severity,
            description="trend test finding",
            status="open",
            organization_id=org_id,
            created_at=created_at,
        )

    db_session.add_all(
        [
            _vuln(org_a.id, ep_a.id, "critical", now),
            _vuln(org_a.id, ep_a.id, "critical", now),
            _vuln(org_a.id, ep_a.id, "high", now - timedelta(days=2)),
            *[_vuln(org_b.id, ep_b.id, "medium", now) for _ in range(3)],
        ]
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_risk_trend_buckets_findings_by_day_and_severity(
    client, db_session, two_tenants
):
    (org_a, user_a), (org_b, user_b) = two_tenants
    await _seed_vulns(db_session, org_a, org_b)
    today = datetime.now(timezone.utc).date().isoformat()

    resp_a = await client.get(
        f"{API}/api-security/dashboard/risk-trend",
        params={"days": 30},
        headers=_auth(user_a),
    )
    assert resp_a.status_code == 200
    body_a = resp_a.json()
    assert body_a["window_days"] == 30
    assert body_a["total_findings"] == 3
    assert len(body_a["points"]) == 30  # dense daily series

    by_date = {p["date"]: p for p in body_a["points"]}
    assert by_date[today]["critical"] == 2
    assert sum(p["high"] for p in body_a["points"]) == 1
    # Org B's medium findings must not leak into A's series.
    assert sum(p["medium"] for p in body_a["points"]) == 0

    # Org B: only its own 3 medium findings.
    resp_b = await client.get(
        f"{API}/api-security/dashboard/risk-trend",
        headers=_auth(user_b),
    )
    assert resp_b.status_code == 200
    body_b = resp_b.json()
    assert body_b["total_findings"] == 3
    assert sum(p["medium"] for p in body_b["points"]) == 3
    assert sum(p["critical"] for p in body_b["points"]) == 0


@pytest.mark.asyncio
async def test_risk_trend_empty_org_returns_empty_points(client, two_tenants):
    (_, user_a), _ = two_tenants
    resp = await client.get(
        f"{API}/api-security/dashboard/risk-trend",
        headers=_auth(user_a),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["points"] == []
    assert body["total_findings"] == 0
