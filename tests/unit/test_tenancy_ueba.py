"""Wave 1 tenancy / RBAC conversion of the UEBA router.

docs/audit/2026-10-08/intel-detection-C.md (c) items 1-5 and (b): every
UEBA route takes the mandatory ``OrganizationId`` (no ``_org_filter`` that
skipped filtering for an org-less caller), rows are stamped, lookups by id
404 outside the tenant, escalated incidents carry the organisation, writes
need analyst or admin (peer-group config and whole-org baseline rebuilds need
admin), and the four always-500 read routes (timeline, risk, peers,
baselines) answer 200 for an entity that has data.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.incident import Incident
from src.models.organization import Organization
from src.ueba.ingest import ingest_behavior_event
from src.ueba.models import (
    BehaviorBaseline,
    BehaviorEvent,
    EntityProfile,
    PeerGroup,
    UEBARiskAlert,
)
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/ueba"


async def _entity(db: AsyncSession, org_id: str, entity_id: str, **extra: Any) -> str:
    entity = EntityProfile(
        organization_id=org_id,
        entity_type="user",
        entity_id=entity_id,
        display_name=entity_id,
        risk_score=extra.pop("risk_score", 40.0),
        risk_level=extra.pop("risk_level", "medium"),
        baseline_data={},
        current_behavior={"logins": 3},
        **extra,
    )
    db.add(entity)
    await db.commit()
    return entity.id


async def _alert(db: AsyncSession, org_id: str, entity_pk: str, severity: str = "high") -> str:
    alert = UEBARiskAlert(
        organization_id=org_id,
        entity_profile_id=entity_pk,
        alert_type="impossible_travel",
        severity=severity,
        risk_score_delta=20.0,
        description="login from two continents in 10 minutes",
        evidence=[],
        contributing_events=[],
        mitre_techniques=[],
        status="new",
    )
    db.add(alert)
    await db.commit()
    return alert.id


async def _event(db: AsyncSession, org_id: str, entity_pk: str, *, anomalous: bool = True) -> str:
    event = BehaviorEvent(
        organization_id=org_id,
        entity_profile_id=entity_pk,
        event_type="authentication",
        event_data={"description": "interactive logon"},
        source_ip="203.0.113.9",
        is_anomalous=anomalous,
        anomaly_reasons=["new_source_ip:203.0.113.9"] if anomalous else [],
        risk_contribution=12.5 if anomalous else 0.0,
    )
    db.add(event)
    await db.commit()
    return event.id


async def _group(db: AsyncSession, org_id: str, members: list[str], name: str = "user-eng") -> str:
    group = PeerGroup(
        organization_id=org_id,
        name=name,
        group_type="auto_clustered",
        member_count=len(members),
        baseline_data={},
        risk_threshold=70.0,
        members=members,
    )
    db.add(group)
    await db.commit()
    return group.id


# ---------------------------------------------------------------------------
# isolation
# ---------------------------------------------------------------------------


async def test_entity_routes_are_tenant_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    entity_pk = await _entity(db_session, org_a_id, "alice@a.io")
    await _event(db_session, org_a_id, entity_pk)

    for method, path, params in (
        ("GET", f"{API}/entities/{entity_pk}", None),
        ("PUT", f"{API}/entities/{entity_pk}/watch", {"is_watched": True}),
        ("GET", f"{API}/entities/{entity_pk}/timeline", None),
        ("GET", f"{API}/entities/{entity_pk}/risk", None),
        ("GET", f"{API}/entities/{entity_pk}/peers", None),
        ("GET", f"{API}/baselines/{entity_pk}", None),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, params=params)

    for path in (f"{API}/entities", f"{API}/events"):
        listed = await client.get(path, headers=org_b_headers)
        assert listed.status_code == 200, listed.text[:300]
        assert listed.json() == [], path

    dash_b = await client.get(f"{API}/dashboard", headers=org_b_headers)
    assert dash_b.status_code == 200
    assert dash_b.json()["total_entities"] == 0
    heat_b = await client.get(f"{API}/risk-heatmap", headers=org_b_headers)
    assert heat_b.json()["total_entities"] == 0

    own = await client.get(f"{API}/entities", headers=org_a_headers)
    assert [e["id"] for e in own.json()] == [entity_pk]
    watched = await client.put(
        f"{API}/entities/{entity_pk}/watch", params={"is_watched": True}, headers=org_a_headers
    )
    assert watched.status_code == 200 and watched.json()["is_watched"] is True


async def test_alert_routes_are_tenant_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    entity_pk = await _entity(db_session, org_a_id, "bob@a.io")
    alert_id = await _alert(db_session, org_a_id, entity_pk)

    for method, path, body in (
        ("GET", f"{API}/alerts/{alert_id}", None),
        ("PUT", f"{API}/alerts/{alert_id}/status", {"status": "investigating"}),
        ("POST", f"{API}/alerts/{alert_id}/escalate", None),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    listed = await client.get(f"{API}/alerts", headers=org_b_headers)
    assert listed.status_code == 200 and listed.json() == []
    row = (await db_session.execute(select(UEBARiskAlert).where(UEBARiskAlert.id == alert_id))).scalar_one()
    assert row.status == "new"


async def test_escalation_creates_an_incident_in_the_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    entity_pk = await _entity(db_session, org_a_id, "carol@a.io")
    alert_id = await _alert(db_session, org_a_id, entity_pk, severity="medium")

    resp = await client.post(f"{API}/alerts/{alert_id}/escalate", headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    incident_id = resp.json()["escalated_to_incident"]
    incident = (await db_session.execute(select(Incident).where(Incident.id == incident_id))).scalar_one()
    # Used to be created with organization_id NULL (an orphan incident).
    assert incident.organization_id == org_a_id


async def test_escalation_cannot_link_another_tenants_incident(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    incident = Incident(
        title="org b incident", severity="high", status="open", organization_id=org_b_id
    )
    db_session.add(incident)
    await db_session.commit()
    incident_id = incident.id
    entity_pk = await _entity(db_session, org_a_id, "dave@a.io")
    alert_id = await _alert(db_session, org_a_id, entity_pk)

    resp = await client.post(
        f"{API}/alerts/{alert_id}/escalate", params={"incident_id": incident_id}, headers=org_a_headers
    )
    assert resp.status_code == 404


async def test_peer_groups_stamped_admin_only_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    body = {"name": "finance-analysts", "description": "custom", "group_type": "custom"}
    denied = await client.post(f"{API}/peer-groups", json=body, headers=org_a_headers)
    assert denied.status_code == 403

    created = await client.post(f"{API}/peer-groups", json=body, headers=org_a_admin_headers)
    assert created.status_code == 200, created.text[:300]
    group_id = created.json()["id"]
    row = (await db_session.execute(select(PeerGroup).where(PeerGroup.id == group_id))).scalar_one()
    assert row.organization_id == org_a_id

    await assert_tenant_isolated(client, "GET", f"{API}/peer-groups/{group_id}", org_b_headers)
    listed = await client.get(f"{API}/peer-groups", headers=org_b_headers)
    assert listed.status_code == 200 and listed.json() == []


async def test_auto_cluster_only_touches_the_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    for i in range(2):
        await _entity(db_session, org_a_id, f"a{i}@a.io", department="eng", role="dev")
    b_members = [
        await _entity(db_session, org_b_id, f"b{i}@b.io", department="eng", role="dev") for i in range(2)
    ]
    b_group = await _group(db_session, org_b_id, b_members, name="org-b-auto")

    resp = await client.post(f"{API}/peer-groups/auto-cluster", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text[:300]
    assert len(resp.json()) == 1
    db_session.expire_all()
    groups = (await db_session.execute(select(PeerGroup))).scalars().all()
    by_org = {g.id: g.organization_id for g in groups}
    assert by_org[b_group] == org_b_id  # org B's auto group survived
    assert all(org in (org_a_id, org_b_id) for org in by_org.values())


async def test_ingest_never_matches_another_tenants_entity(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    await _entity(db_session, org_a_id, "erin@a.io")
    body = {"entity_id": "erin@a.io", "event_type": "authentication", "event_data": {}}
    resp = await client.post(f"{API}/events", json=body, headers=org_b_headers)
    assert resp.status_code == 404
    batch = await client.post(f"{API}/events/batch", json={"events": [body]}, headers=org_b_headers)
    assert batch.status_code == 200 and batch.json()["failed_events"] == 1
    events = (await db_session.execute(select(BehaviorEvent))).scalars().all()
    assert events == []


async def test_ingest_helper_requires_an_organisation(db_session: AsyncSession) -> None:
    with pytest.raises(ValueError):
        await ingest_behavior_event(db_session, None, {"entity_id": "x", "event_type": "login"})


async def test_ingest_stamps_the_entity_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    await _entity(db_session, org_a_id, "frank@a.io")
    body = {"entity_id": "frank@a.io", "event_type": "authentication", "event_data": {}}
    resp = await client.post(f"{API}/events", json=body, headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    row = (await db_session.execute(select(BehaviorEvent).where(BehaviorEvent.id == resp.json()["id"]))).scalar_one()
    assert row.organization_id == org_a_id


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------

WRITE_ROUTES = [
    ("PUT", "/entities/{entity}/watch", {"is_watched": True}, None),
    ("PUT", "/alerts/{alert}/status", None, {"status": "investigating"}),
    ("POST", "/alerts/{alert}/escalate", None, None),
    ("POST", "/events", None, {"entity_id": "x", "event_type": "login", "event_data": {}}),
    ("POST", "/events/batch", None, {"events": [{"entity_id": "x", "event_type": "login", "event_data": {}}]}),
    ("POST", "/peer-groups", None, {"name": "g", "group_type": "custom"}),
    ("POST", "/peer-groups/auto-cluster", None, None),
    ("POST", "/baselines/rebuild", None, None),
]


@pytest.mark.parametrize("method,path,params,body", WRITE_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
    method: str,
    path: str,
    params: Any,
    body: Any,
) -> None:
    org_a_id = org_a.id
    entity_pk = await _entity(db_session, org_a_id, "viewer-target@a.io")
    alert_id = await _alert(db_session, org_a_id, entity_pk)
    url = API + path.format(entity=entity_pk, alert=alert_id)
    resp = await client.request(method, url, params=params, json=body, headers=viewer_headers)
    assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text[:200]}"


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/peer-groups", {"name": "g", "group_type": "custom"}),
        ("POST", "/peer-groups/auto-cluster", None),
        ("POST", "/baselines/rebuild", None),
    ],
)
async def test_config_and_rebuild_routes_are_admin_only(
    client: AsyncClient,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
    method: str,
    path: str,
    body: Any,
) -> None:
    analyst = await client.request(method, API + path, json=body, headers=org_a_headers)
    assert analyst.status_code == 403
    admin = await client.request(method, API + path, json=body, headers=org_a_admin_headers)
    assert admin.status_code == 200, admin.text[:300]


@pytest.mark.parametrize(
    "path",
    ["/entities", "/alerts", "/events", "/peer-groups", "/dashboard", "/risk-heatmap"],
)
async def test_org_less_superuser_needs_an_organisation(
    client: AsyncClient, superuser_headers: dict[str, str], path: str
) -> None:
    resp = await client.get(API + path, headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"


async def test_org_less_superuser_cannot_rebuild_every_tenant(
    client: AsyncClient, superuser_headers: dict[str, str]
) -> None:
    # Used to rebuild (and wipe) every tenant's baselines for an org-less caller.
    resp = await client.post(f"{API}/baselines/rebuild", headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"


# ---------------------------------------------------------------------------
# always-500 regressions
# ---------------------------------------------------------------------------


async def test_timeline_with_events_is_200(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    entity_pk = await _entity(db_session, org_a_id, "grace@a.io")
    event_id = await _event(db_session, org_a_id, entity_pk)

    resp = await client.get(f"{API}/entities/{entity_pk}/timeline", headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert body["event_count"] == 1 and body["anomaly_count"] == 1
    event = body["events"][0]
    assert event["id"] == event_id
    assert event["timestamp"] and event["created_at"]
    assert event["description"] == "interactive logon"
    assert event["is_anomalous"] is True


async def test_entity_risk_is_200_with_factors_and_trend(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    entity_pk = await _entity(db_session, org_a_id, "heidi@a.io", risk_score=65.0, risk_level="high")
    await _alert(db_session, org_a_id, entity_pk, severity="high")
    await _event(db_session, org_a_id, entity_pk)

    resp = await client.get(f"{API}/entities/{entity_pk}/risk", params={"days": 7}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    factors = {f["factor"]: f for f in body["risk_factors"]}
    assert factors["high_alerts"]["count"] == 1
    assert factors["anomalous_events"] == {"factor": "anomalous_events", "count": 1, "contribution": 12.5}
    assert len(body["risk_trend"]) == 7
    assert sum(p["risk_score"] for p in body["risk_trend"]) > 0
    assert body["alert_count"] == 1 and body["anomaly_count"] == 1


async def test_entity_peers_is_200_with_comparisons(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    target = await _entity(db_session, org_a_id, "ivan@a.io", risk_score=80.0, risk_level="critical")
    peers = [await _entity(db_session, org_a_id, f"peer{i}@a.io", risk_score=10.0) for i in range(3)]
    group_id = await _group(db_session, org_a_id, [target, *peers])

    resp = await client.get(f"{API}/entities/{target}/peers", headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert body["peer_group_id"] == group_id
    assert body["member_count"] == 4
    risk = next(c for c in body["comparisons"] if c["metric"] == "risk_score")
    assert risk["entity_value"] == 80.0 and risk["peer_average"] == 10.0 and risk["percentile"] == 100.0
    assert isinstance(body["deviations"], list)


async def test_entity_peers_without_a_group_is_an_empty_200(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    entity_pk = await _entity(db_session, org_a.id, "judy@a.io")
    resp = await client.get(f"{API}/entities/{entity_pk}/peers", headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    assert resp.json()["comparisons"] == [] and resp.json()["member_count"] == 0


async def test_entity_baselines_is_200(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    entity_pk = await _entity(db_session, org_a_id, "mallory@a.io")
    baseline = BehaviorBaseline(
        entity_profile_id=entity_pk,
        behavior_type="authentication",
        baseline_period_days=30,
        statistical_model={"sample_count": 12},
        typical_values=["203.0.113.9"],
        time_patterns={"hours": [9, 10]},
        peer_comparison={},
        confidence=0.12,
        sample_count=12,
        last_updated_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    db_session.add(baseline)
    await db_session.commit()
    baseline_id = baseline.id

    resp = await client.get(f"{API}/baselines/{entity_pk}", headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    assert [b["id"] for b in resp.json()] == [baseline_id]
