"""Wave 1 tenancy / RBAC conversion of the SIEM router and pipeline.

Covers docs/audit/2026-10-08/intel-detection-B.md (c) items 1-9, 14, 17-22
and the always-500 correlation insert (pipeline.py vs the CorrelationEvent
model):

* every SIEM route is scoped to the caller's organisation and rows created
  through the API carry it (rules, imports, data sources, saved searches,
  ingested logs);
* built-in rules are platform rows (``organization_id IS NULL``): readable by
  every organisation, read-only for organisation users, evaluated for every
  organisation's logs with the alert carrying the log's organisation;
* rule engines and correlation buffers are per organisation;
* the correlation insert writes a valid row with the organisation, and a
  failing correlation insert no longer poisons the session;
* viewers cannot write, analysts cannot configure, organisation admins
  cannot run host-level actions, org-less superusers need a tenant.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.alert import Alert
from src.siem import engine_manager
from src.siem.models import CorrelationEvent, DetectionRule, LogEntry, SavedSearch, SIEMDataSource
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/siem"


@pytest.fixture(autouse=True)
def _fresh_engines():
    """Rule / correlation engines are process-wide caches; start each test clean."""
    engine_manager.reset_engines()
    yield
    engine_manager.reset_engines()


def _session_log(user: str, src: str, dst: str) -> str:
    return json.dumps({"user": user, "src_ip": src, "dst_ip": dst, "message": f"connection to {dst}"})


async def _rule(db: AsyncSession, org_id: str | None, *, name: str, contains: str) -> str:
    rule = DetectionRule(
        name=name,
        title=name.replace("-", " ").title(),
        description="test rule",
        status="active",
        enabled=True,
        severity="high",
        detection_logic=json.dumps({"raw_log": {"contains": contains}}),
        condition="selection",
        organization_id=org_id,
    )
    db.add(rule)
    await db.commit()
    return rule.id


async def _correlation(db: AsyncSession, org_id: str) -> str:
    corr = CorrelationEvent(
        correlation_id=f"session_{uuid.uuid4().hex[:8]}",
        name="SessionCorrelation",
        severity="high",
        timespan_start="2026-10-12T10:00:00+00:00",
        timespan_end="2026-10-12T10:05:00+00:00",
        event_count=3,
        organization_id=org_id,
    )
    db.add(corr)
    await db.commit()
    return corr.id


# ---------------------------------------------------------------------------
# Rows are stamped and isolated
# ---------------------------------------------------------------------------


async def test_rule_created_by_org_admin_is_stamped_and_isolated(
    client: AsyncClient, db_session, org_a, org_b, org_a_admin_headers, org_a_headers, org_b_headers
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    resp = await client.post(
        f"{API}/rules",
        json={"name": "org-a-rule", "title": "Org A rule", "detection_logic": {"raw_log": {"contains": "x"}}},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    rule_id = resp.json()["id"]
    assert resp.json()["organization_id"] == org_a_id

    # Follow-up actions by the creating org work (previously 404: NULL org).
    assert (await client.get(f"{API}/rules/{rule_id}", headers=org_a_headers)).status_code == 200
    assert (await client.get(f"{API}/rules/{rule_id}/export", headers=org_a_headers)).status_code == 200

    await assert_tenant_isolated(client, "GET", f"{API}/rules/{rule_id}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{API}/rules/{rule_id}/export", org_b_headers)
    await assert_tenant_isolated(
        client, "POST", f"{API}/rules/{rule_id}/test", org_b_headers, json={"sample_logs": ["x"]}
    )
    listed_b = await client.get(f"{API}/rules", headers=org_b_headers)
    assert rule_id not in {r["id"] for r in listed_b.json()["items"]}
    listed_a = await client.get(f"{API}/rules", headers=org_a_headers)
    assert rule_id in {r["id"] for r in listed_a.json()["items"]}

    # Org B's admin cannot modify it either.
    from tests.helpers.tenancy import bearer, make_user

    b_admin = bearer(await make_user(db_session, role="admin", organization_id=org_b_id, label="admin-b"))
    await assert_tenant_isolated(client, "PUT", f"{API}/rules/{rule_id}", b_admin, json={"enabled": False})
    await assert_tenant_isolated(client, "DELETE", f"{API}/rules/{rule_id}", b_admin)

    resp = await client.put(f"{API}/rules/{rule_id}", json={"enabled": False}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False
    assert (await client.delete(f"{API}/rules/{rule_id}", headers=org_a_admin_headers)).status_code == 204


async def test_sigma_import_is_stamped_with_org(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, org_a_headers, org_b_headers
) -> None:
    org_a_id = org_a.id
    sigma = (
        "title: Org A Sigma\n"
        "id: 11111111-2222-3333-4444-555555555555\n"
        "level: high\n"
        "logsource:\n  product: linux\n"
        "detection:\n  selection:\n    raw_log|contains: evil\n  condition: selection\n"
    )
    resp = await client.post(f"{API}/rules/import", json={"yaml": sigma}, headers=org_a_admin_headers)
    assert resp.status_code == 201, resp.text
    rule_id = resp.json()["id"]
    row = await db_session.get(DetectionRule, rule_id)
    assert row.organization_id == org_a_id
    assert (await client.get(f"{API}/rules/{rule_id}", headers=org_a_headers)).status_code == 200
    await assert_tenant_isolated(client, "GET", f"{API}/rules/{rule_id}", org_b_headers)


async def test_data_source_is_stamped_and_isolated(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, org_a_headers, org_b_headers
) -> None:
    org_a_id = org_a.id
    resp = await client.post(
        f"{API}/sources",
        json={"name": f"fw-{uuid.uuid4().hex[:6]}", "source_type": "syslog", "connection_config": {"host": "10.0.0.1"}},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    source_id = resp.json()["id"]
    row = await db_session.get(SIEMDataSource, source_id)
    assert row.organization_id == org_a_id

    await assert_tenant_isolated(client, "PUT", f"{API}/sources/{source_id}", org_b_headers, json={"enabled": False})
    await assert_tenant_isolated(client, "DELETE", f"{API}/sources/{source_id}", org_b_headers)
    assert source_id not in {s["id"] for s in (await client.get(f"{API}/sources", headers=org_b_headers)).json()}
    assert source_id in {s["id"] for s in (await client.get(f"{API}/sources", headers=org_a_headers)).json()}

    # Partial update (page-fix behaviour) still works for the owning admin.
    resp = await client.put(f"{API}/sources/{source_id}", json={"enabled": False}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False
    assert (await client.delete(f"{API}/sources/{source_id}", headers=org_a_admin_headers)).status_code == 204


async def test_saved_search_is_stamped_and_isolated(
    client: AsyncClient, db_session, org_a, org_a_headers, org_b_headers
) -> None:
    org_a_id = org_a.id
    resp = await client.post(f"{API}/saved-searches", json={"name": "s", "query": "sshd"}, headers=org_a_headers)
    assert resp.status_code == 201, resp.text
    search_id = resp.json()["id"]
    row = await db_session.get(SavedSearch, search_id)
    assert row.organization_id == org_a_id

    await assert_tenant_isolated(client, "POST", f"{API}/saved-searches/{search_id}/run", org_b_headers)
    await assert_tenant_isolated(client, "DELETE", f"{API}/saved-searches/{search_id}", org_b_headers)
    assert search_id not in {s["id"] for s in (await client.get(f"{API}/saved-searches", headers=org_b_headers)).json()}
    assert (await client.post(f"{API}/saved-searches/{search_id}/run", headers=org_a_headers)).status_code == 200


async def test_ingested_log_is_stamped_and_isolated_in_search_stats_and_aggregate(
    client: AsyncClient, db_session, org_a, org_b, org_a_headers, org_b_headers
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    resp = await client.post(
        f"{API}/logs/ingest",
        json={"raw_log": "tenant-a-marker sshd login", "source_type": "syslog", "source_name": "host-a"},
        headers=org_a_headers,
    )
    assert resp.status_code == 201, resp.text
    log_id = resp.json()["id"]
    row = await db_session.get(LogEntry, log_id)
    assert row.organization_id == org_a_id

    assert (await client.get(f"{API}/logs/{log_id}", headers=org_a_headers)).status_code == 200
    await assert_tenant_isolated(client, "GET", f"{API}/logs/{log_id}", org_b_headers)

    search = {"query": "tenant-a-marker", "page": 1, "size": 20}
    assert (await client.post(f"{API}/logs/search", json=search, headers=org_a_headers)).json()["total"] == 1
    assert (await client.post(f"{API}/logs/search", json=search, headers=org_b_headers)).json()["total"] == 0

    agg = {"field": "source_name", "agg_type": "terms", "top_n": 10}
    assert "host-a" in (await client.post(f"{API}/logs/aggregate", json=agg, headers=org_a_headers)).json()["aggregations"]
    assert "host-a" not in (await client.post(f"{API}/logs/aggregate", json=agg, headers=org_b_headers)).json()["aggregations"]

    stats_a = (await client.get(f"{API}/logs/stats", headers=org_a_headers)).json()
    stats_b = (await client.get(f"{API}/logs/stats", headers=org_b_headers)).json()
    assert stats_a["total_logs"] == 1
    assert stats_b["total_logs"] == 0
    assert org_b_id  # org B exists and simply has no logs


async def test_batch_ingest_body_org_only_for_platform_superuser(
    client: AsyncClient, db_session, org_a, org_b_headers, superuser_headers
) -> None:
    org_a_id = org_a.id
    body = {"logs": [{"raw_log": "batch-line one"}, {"raw_log": "batch-line two"}], "organization_id": org_a_id}

    # Another tenant cannot write into org A by naming it in the body.
    resp = await client.post(f"{API}/logs/batch", json=body, headers=org_b_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_mismatch"

    # Org-less superuser without an explicit tenant is refused...
    resp = await client.post(f"{API}/logs/batch", json={"logs": body["logs"]}, headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"

    # ...and with one, the rows land in that tenant.
    resp = await client.post(f"{API}/logs/batch", json=body, headers=superuser_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["success_count"] == 2
    rows = (await db_session.execute(select(LogEntry).where(LogEntry.raw_log.like("batch-line%")))).scalars().all()
    assert len(rows) == 2 and {r.organization_id for r in rows} == {org_a_id}


async def test_correlation_isolated_and_triage_validated(
    client: AsyncClient, db_session, org_a, org_a_headers, org_b_headers
) -> None:
    corr_id = await _correlation(db_session, org_a.id)

    await assert_tenant_isolated(client, "GET", f"{API}/correlations/{corr_id}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/correlations/{corr_id}/status", org_b_headers, json={"status": "resolved"}
    )
    assert corr_id not in {c["id"] for c in (await client.get(f"{API}/correlations", headers=org_b_headers)).json()}
    assert corr_id in {c["id"] for c in (await client.get(f"{API}/correlations", headers=org_a_headers)).json()}

    resp = await client.put(f"{API}/correlations/{corr_id}/status", json={"status": "bogus"}, headers=org_a_headers)
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_status"
    resp = await client.put(
        f"{API}/correlations/{corr_id}/status", json={"status": "investigating"}, headers=org_a_headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "investigating"


# ---------------------------------------------------------------------------
# Platform (built-in) rules
# ---------------------------------------------------------------------------


async def test_builtin_rules_are_platform_rows_readable_but_read_only(
    client: AsyncClient, db_session, org_a_admin_headers, org_b_headers
) -> None:
    from src.siem.rule_seeder import BUILTIN_RULES, seed_builtin_detection_rules

    await seed_builtin_detection_rules(db_session)
    await db_session.commit()
    builtin = (
        await db_session.execute(select(DetectionRule).where(DetectionRule.name == BUILTIN_RULES[0]["name"]))
    ).scalar_one()
    builtin_id = builtin.id
    assert builtin.organization_id is None

    listed = await client.get(f"{API}/rules", params={"size": 100}, headers=org_b_headers)
    assert builtin_id in {r["id"] for r in listed.json()["items"]}
    assert (await client.get(f"{API}/rules/{builtin_id}", headers=org_b_headers)).status_code == 200

    for method, kwargs in (("PUT", {"json": {"enabled": False}}), ("DELETE", {})):
        resp = await client.request(method, f"{API}/rules/{builtin_id}", headers=org_a_admin_headers, **kwargs)
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "platform_rule_read_only"
    await db_session.refresh(builtin)
    assert builtin.enabled is True


# ---------------------------------------------------------------------------
# Engine and correlation buffers are per organisation
# ---------------------------------------------------------------------------


async def test_org_rule_fires_only_for_its_org_and_platform_rule_for_all(db_session, org_a, org_b) -> None:
    from src.siem.pipeline import process_log

    org_a_id, org_b_id = org_a.id, org_b.id
    await _rule(db_session, org_a_id, name="org-a-only", contains="tenant-a-signal")
    await _rule(db_session, None, name="platform-wide", contains="platform-signal")

    _, alerts_b, _ = await process_log(
        raw_log="tenant-a-signal seen in org b", source_type="syslog", source_name="b",
        source_ip="10.9.9.9", db=db_session, organization_id=org_b_id,
    )
    assert alerts_b == [], "org A's custom rule fired on org B's log"

    _, alerts_a, _ = await process_log(
        raw_log="tenant-a-signal seen in org a", source_type="syslog", source_name="a",
        source_ip="10.9.9.8", db=db_session, organization_id=org_a_id,
    )
    assert [a["rule_title"] for a in alerts_a] == ["Org A Only"]

    for org_id in (org_a_id, org_b_id):
        _, alerts, _ = await process_log(
            raw_log="platform-signal here", source_type="syslog", source_name="x",
            source_ip="10.9.9.7", db=db_session, organization_id=org_id,
        )
        assert [a["rule_title"] for a in alerts] == ["Platform Wide"]
    await db_session.commit()

    platform_alerts = (
        await db_session.execute(select(Alert).where(Alert.title == "Detection: Platform Wide"))
    ).scalars().all()
    assert sorted(a.organization_id for a in platform_alerts) == sorted([org_a_id, org_b_id])


async def test_correlation_buffers_are_per_organisation(db_session, org_a, org_b) -> None:
    from src.siem.pipeline import process_log

    org_a_id, org_b_id = org_a.id, org_b.id

    async def send(org_id: str, dst: str) -> list[dict[str, Any]]:
        _, _, corrs = await process_log(
            raw_log=_session_log("alice", "10.0.0.5", dst), source_type="json", source_name="fw",
            source_ip="10.0.0.5", db=db_session, organization_id=org_id,
        )
        return corrs

    # Same user + source in both tenants, 4 distinct destinations overall but
    # only 2 per tenant: a shared buffer would correlate, per-org must not.
    assert await send(org_a_id, "10.1.0.1") == []
    assert await send(org_b_id, "10.1.0.2") == []
    assert await send(org_a_id, "10.1.0.3") == []
    assert await send(org_b_id, "10.1.0.4") == []
    await db_session.commit()
    assert (await db_session.execute(select(CorrelationEvent))).scalars().all() == []


# ---------------------------------------------------------------------------
# ALWAYS-500 regression: the correlation insert
# ---------------------------------------------------------------------------


async def test_pipeline_correlation_persists_with_org(db_session, org_a) -> None:
    """The insert used to miss correlation_id/timespan_*, pass an Enum severity
    and a non-FK rule_id, so the flush failed and the log was lost (500)."""
    from src.siem.pipeline import process_log

    org_a_id = org_a.id
    produced: list[dict[str, Any]] = []
    for i in range(1, 4):
        _, _, corrs = await process_log(
            raw_log=_session_log("alice", "10.0.0.5", f"10.2.0.{i}"), source_type="json",
            source_name="fw", source_ip="10.0.0.5", db=db_session, organization_id=org_a_id,
        )
        produced.extend(corrs)
    await db_session.commit()

    assert len(produced) == 1, produced
    rows = (await db_session.execute(select(CorrelationEvent))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.organization_id == org_a_id
    assert row.correlation_id == produced[0]["correlation_id"]
    assert row.name == "SessionCorrelation"
    assert row.severity == "high"
    assert row.rule_id is None
    assert row.timespan_start and row.timespan_end
    assert row.event_count == 3
    assert len(json.loads(row.log_entry_ids)) == 3
    assert json.loads(row.usernames) == ["alice"]
    assert (await db_session.execute(select(LogEntry))).scalars().all().__len__() == 3


async def test_correlation_via_api_is_listed_for_its_org_only(
    client: AsyncClient, db_session, org_a, org_a_headers, org_b_headers
) -> None:
    for i in range(1, 4):
        resp = await client.post(
            f"{API}/logs/ingest",
            json={"raw_log": _session_log("bob", "10.0.0.6", f"10.3.0.{i}"), "source_type": "json"},
            headers=org_a_headers,
        )
        assert resp.status_code == 201, resp.text
    assert resp.json()["correlations_triggered"] == 1

    listed_a = (await client.get(f"{API}/correlations", headers=org_a_headers)).json()
    assert [c["name"] for c in listed_a] == ["SessionCorrelation"]
    assert (await client.get(f"{API}/correlations", headers=org_b_headers)).json() == []


async def test_bad_correlation_row_does_not_poison_the_batch(db_session, org_a, monkeypatch) -> None:
    """A failing correlation insert is rolled back alone; the log, its alerts
    and every later log in the same session still persist."""
    import src.siem.pipeline as pipeline
    from src.siem.pipeline import process_log

    org_a_id = org_a.id
    real_build = pipeline.build_correlation_event

    def broken_build(corr, organization_id):
        row = real_build(corr, organization_id)
        row.timespan_start = None  # violates NOT NULL -> IntegrityError at flush
        return row

    monkeypatch.setattr(pipeline, "build_correlation_event", broken_build)
    for i in range(1, 4):
        _, _, corrs = await process_log(
            raw_log=_session_log("carol", "10.0.0.7", f"10.4.0.{i}"), source_type="json",
            source_name="fw", source_ip="10.0.0.7", db=db_session, organization_id=org_a_id,
        )
        assert corrs == []  # the failed row is skipped, not reported

    # The session is still usable for the rest of the batch.
    log_entry, _, _ = await process_log(
        raw_log="after the failure", source_type="syslog", source_name="fw",
        source_ip="10.0.0.7", db=db_session, organization_id=org_a_id,
    )
    await db_session.commit()
    logs = (await db_session.execute(select(LogEntry))).scalars().all()
    assert len(logs) == 4 and {log.organization_id for log in logs} == {org_a_id}
    assert (await db_session.execute(select(CorrelationEvent))).scalars().all() == []
    assert log_entry.id in {log.id for log in logs}


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

WRITE_ROUTES: list[tuple[str, str, Any]] = [
    ("POST", "/logs/ingest", {"raw_log": "x"}),
    ("POST", "/logs/batch", {"logs": [{"raw_log": "x"}]}),
    ("POST", "/rules", {"name": "v-rule", "title": "V"}),
    ("PUT", "/rules/RULE", {"enabled": False}),
    ("DELETE", "/rules/RULE", None),
    ("POST", "/rules/import", {"yaml": "title: x\ndetection: {}\n"}),
    ("PUT", "/correlations/CORR/status", {"status": "resolved"}),
    ("POST", "/sources", {"name": "v-src", "source_type": "syslog"}),
    ("PUT", "/sources/SOURCE", {"enabled": False}),
    ("DELETE", "/sources/SOURCE", None),
    ("POST", "/saved-searches", {"name": "s", "query": "q"}),
    ("DELETE", "/saved-searches/SEARCH", None),
    ("POST", "/cloud/poll-all", None),
    ("POST", "/logs/backfill", None),
    ("POST", "/collector/start", None),
    ("POST", "/collector/stop", None),
]

ADMIN_ONLY_ROUTES = [r for r in WRITE_ROUTES if r[1].startswith(("/rules", "/sources", "/cloud"))]
PLATFORM_ONLY_ROUTES: list[tuple[str, str, Any]] = [
    ("POST", "/logs/backfill", None),
    ("POST", "/collector/start", None),
    ("POST", "/collector/stop", None),
    ("GET", "/ingest/status", None),
]


async def _ids(db: AsyncSession, org_id: str) -> dict[str, str]:
    rule_id = await _rule(db, org_id, name=f"r-{uuid.uuid4().hex[:6]}", contains="zz")
    source = SIEMDataSource(name=f"s-{uuid.uuid4().hex[:6]}", source_type="syslog", organization_id=org_id)
    search = SavedSearch(name="s", query="q", organization_id=org_id)
    db.add_all([source, search])
    await db.commit()
    return {
        "RULE": rule_id,
        "SOURCE": source.id,
        "SEARCH": search.id,
        "CORR": await _correlation(db, org_id),
    }


def _path(template: str, ids: dict[str, str]) -> str:
    for key, value in ids.items():
        template = template.replace(key, value)
    return f"{API}{template}"


@pytest.mark.parametrize("method,path,body", WRITE_ROUTES)
async def test_viewer_cannot_write(client: AsyncClient, db_session, org_a, viewer_headers, method, path, body) -> None:
    ids = await _ids(db_session, org_a.id)
    resp = await client.request(method, _path(path, ids), headers=viewer_headers, json=body)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize("method,path,body", ADMIN_ONLY_ROUTES)
async def test_analyst_cannot_configure(client: AsyncClient, db_session, org_a, org_a_headers, method, path, body) -> None:
    ids = await _ids(db_session, org_a.id)
    resp = await client.request(method, _path(path, ids), headers=org_a_headers, json=body)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize("method,path,body", PLATFORM_ONLY_ROUTES)
async def test_org_admin_cannot_run_platform_actions(
    client: AsyncClient, org_a_admin_headers, method, path, body
) -> None:
    resp = await client.request(method, f"{API}{path}", headers=org_a_admin_headers, json=body)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "platform_superuser_required"


async def test_cloud_poll_is_scoped_to_callers_org(client: AsyncClient, org_a_admin_headers, monkeypatch) -> None:
    import src.siem.cloud_poller as cloud_poller

    seen: dict[str, Any] = {}

    async def fake_poll(db, organization_id=None):
        seen["organization_id"] = organization_id
        return []

    monkeypatch.setattr(cloud_poller, "poll_all_cloud_integrations", fake_poll)
    resp = await client.post(f"{API}/cloud/poll-all", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert seen["organization_id"] is not None


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/rules", None),
        ("GET", "/sources", None),
        ("GET", "/correlations", None),
        ("GET", "/saved-searches", None),
        ("GET", "/logs/stats", None),
        ("POST", "/logs/search", {"query": "x"}),
        ("POST", "/logs/aggregate", {"field": "severity"}),
        ("POST", "/logs/ingest", {"raw_log": "x"}),
        ("POST", "/rules", {"name": "su-rule", "title": "SU"}),
        ("POST", "/sources", {"name": "su-src", "source_type": "syslog"}),
    ],
)
async def test_orgless_superuser_needs_a_tenant(client: AsyncClient, superuser_headers, method, path, body) -> None:
    resp = await client.request(method, f"{API}{path}", headers=superuser_headers, json=body)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"


async def test_reads_allowed_for_viewer(client: AsyncClient, viewer_headers) -> None:
    for method, path, body in (
        ("GET", "/rules", None),
        ("GET", "/logs/stats", None),
        ("POST", "/logs/search", {"query": "x"}),
        ("GET", "/correlations", None),
        ("GET", "/sources", None),
    ):
        resp = await client.request(method, f"{API}{path}", headers=viewer_headers, json=body)
        assert resp.status_code == 200, (path, resp.text)
