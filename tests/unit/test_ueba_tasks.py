"""The UEBA background Celery tasks must do real work.

Before this fix, all seven tasks in ``src.ueba.tasks`` fed hardcoded
empty lists into the (real) engine algorithms and returned zero-count
"completed" results. These tests exercise the real logic via the
module-level ``_*_async`` helpers the Celery entrypoints wrap:

- update_entity_baselines builds BehaviorBaseline rows from real events
  (in the shape ingest scoring consumes) and honestly skips thin data
- calculate_entity_risks decays stale risk and recounts real anomalies
- detect_impossible_travel persists exactly one deduped UEBARiskAlert
- update_peer_groups rebuilds PeerGroup rows from real EntityProfiles
- generate_ueba_alerts alerts on high-risk entities without spamming
- cleanup_old_behavior_events deletes only old rows in the right org
- process_behavior_events persists + scores a batch like the endpoint
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from src.ueba.models import (
    BehaviorBaseline,
    BehaviorEvent,
    EntityProfile,
    PeerGroup,
    UEBARiskAlert,
)
from src.ueba.tasks import (
    _calculate_entity_risks_async,
    _cleanup_old_behavior_events_async,
    _detect_impossible_travel_async,
    _generate_ueba_alerts_async,
    _process_behavior_events_async,
    _update_entity_baselines_async,
    _update_peer_groups_async,
)

ORG_A = "org-a"
ORG_B = "org-b"

NOW = datetime.now(timezone.utc)


def _entity(entity_id="alice", org=ORG_A, **overrides):
    params = {
        "entity_type": "user",
        "entity_id": entity_id,
        "display_name": entity_id.title(),
        "risk_score": 0.0,
        "risk_level": "low",
        "organization_id": org,
    }
    params.update(overrides)
    return EntityProfile(**params)


def _event(entity, event_type="authentication", age_days=1, **overrides):
    params = {
        "id": str(uuid.uuid4()),
        "entity_profile_id": entity.id,
        "event_type": event_type,
        "event_data": {},
        "organization_id": entity.organization_id,
        # Whole days only, so the event's hour matches "now" and the
        # baseline's typical-hours check is deterministic in tests.
        "created_at": NOW - timedelta(days=age_days),
    }
    params.update(overrides)
    return BehaviorEvent(**params)


def _alert(entity, alert_type="anomaly", severity="high", age_days=1, **overrides):
    params = {
        "id": str(uuid.uuid4()),
        "entity_profile_id": entity.id,
        "alert_type": alert_type,
        "severity": severity,
        "risk_score_delta": 10.0,
        "description": f"{alert_type} on {entity.entity_id}",
        "status": "new",
        "organization_id": entity.organization_id,
        "created_at": NOW - timedelta(days=age_days),
    }
    params.update(overrides)
    return UEBARiskAlert(**params)


@pytest.fixture
def anomaly_recorder(monkeypatch):
    """Record on_ueba_anomaly fanout calls instead of running automation."""
    from src.services.automation import AutomationService

    calls: list[dict] = []

    async def fake_on_ueba_anomaly(self, **kwargs):
        calls.append(kwargs)
        return None

    monkeypatch.setattr(AutomationService, "on_ueba_anomaly", fake_on_ueba_anomaly)
    return calls


# ============================================================================
# update_entity_baselines
# ============================================================================


@pytest.mark.asyncio
async def test_update_entity_baselines_builds_and_persists(db_session):
    entity = _entity()
    db_session.add(entity)
    await db_session.flush()
    entity_pk = entity.id
    for i in range(12):
        db_session.add(_event(entity, age_days=(i % 10) + 1, source_ip="10.0.0.1"))
    await db_session.commit()

    result = await _update_entity_baselines_async(ORG_A)

    assert result["status"] == "completed"
    assert result["baselines_updated"] == 1
    assert result["baselines_skipped"] == 0

    db_session.expire_all()
    rows = list(
        (
            await db_session.execute(
                select(BehaviorBaseline).where(
                    BehaviorBaseline.entity_profile_id == entity_pk
                )
            )
        ).scalars().all()
    )
    assert len(rows) == 1
    baseline = rows[0]
    assert baseline.behavior_type == "authentication"
    assert baseline.sample_count == 12
    assert baseline.confidence == pytest.approx(0.12)
    # The shape ingest scoring consumes: typical source IPs + typical hours
    assert "10.0.0.1" in baseline.typical_values
    assert baseline.time_patterns["hours"]

    # Re-run is an upsert, not a duplicate insert
    result = await _update_entity_baselines_async(ORG_A)
    assert result["baselines_updated"] == 1

    db_session.expire_all()
    count = len(
        (
            await db_session.execute(
                select(BehaviorBaseline.id).where(
                    BehaviorBaseline.entity_profile_id == entity_pk
                )
            )
        ).scalars().all()
    )
    assert count == 1


@pytest.mark.asyncio
async def test_update_entity_baselines_skips_insufficient_data(db_session):
    entity = _entity()
    db_session.add(entity)
    await db_session.flush()
    entity_pk = entity.id
    for i in range(3):  # below BaselineManager.min_samples (10)
        db_session.add(_event(entity, age_days=i + 1, source_ip="10.0.0.1"))
    await db_session.commit()

    result = await _update_entity_baselines_async(ORG_A)

    assert result["baselines_updated"] == 0
    assert result["baselines_skipped"] == 1

    db_session.expire_all()
    rows = (
        await db_session.execute(
            select(BehaviorBaseline.id).where(
                BehaviorBaseline.entity_profile_id == entity_pk
            )
        )
    ).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_baselines_feed_back_into_ingest_scoring(db_session):
    """The whole point of the baseline task: ingest scoring must use the
    learned baseline once its confidence crosses the 0.3 threshold."""
    from src.ueba.ingest import score_event_anomaly

    entity = _entity()
    db_session.add(entity)
    await db_session.flush()
    # Timestamps offset by whole days from *now* so every seeded event's
    # hour equals the hour the scoring call will run in — keeps the
    # typical-hours check deterministic.
    now = datetime.now(timezone.utc)
    for i in range(40):  # confidence 0.4 >= 0.3 -> baseline branch in scoring
        db_session.add(
            _event(
                entity,
                source_ip="10.0.0.1",
                created_at=now - timedelta(days=(i % 20) + 1),
            )
        )
    await db_session.commit()

    await _update_entity_baselines_async(ORG_A)

    known = BehaviorEvent(
        entity_profile_id=entity.id,
        event_type="authentication",
        event_data={},
        source_ip="10.0.0.1",
        organization_id=ORG_A,
    )
    is_anomalous, reasons, _ = await score_event_anomaly(db_session, entity, known)
    assert is_anomalous is False
    assert reasons == []

    unknown = BehaviorEvent(
        entity_profile_id=entity.id,
        event_type="authentication",
        event_data={},
        source_ip="203.0.113.9",
        organization_id=ORG_A,
    )
    is_anomalous, reasons, risk_delta = await score_event_anomaly(
        db_session, entity, unknown
    )
    assert is_anomalous is True
    assert any(r.startswith("new_source_ip:") for r in reasons)
    assert risk_delta > 0


# ============================================================================
# calculate_entity_risks
# ============================================================================


@pytest.mark.asyncio
async def test_calculate_entity_risks_decays_and_counts_real_rows(db_session):
    active = _entity("alice", risk_score=80.0, risk_level="critical", anomaly_count_30d=5)
    stale = _entity("bob", risk_score=90.0, risk_level="critical", anomaly_count_30d=7)
    other_org = _entity("carol", org=ORG_B, risk_score=70.0, risk_level="high")
    db_session.add_all([active, stale, other_org])
    await db_session.flush()

    db_session.add(_alert(active, severity="high", age_days=1))
    # Real anomalous events: one inside the 30d window, one aged out
    db_session.add(_event(active, age_days=2, is_anomalous=True))
    db_session.add(_event(active, age_days=40, is_anomalous=True))
    await db_session.commit()

    result = await _calculate_entity_risks_async(ORG_A)

    assert result["entities_updated"] == 2

    db_session.expire_all()
    rows = {
        row_entity_id: (score, level, anomalies)
        for row_entity_id, score, level, anomalies in (
            await db_session.execute(
                select(
                    EntityProfile.entity_id,
                    EntityProfile.risk_score,
                    EntityProfile.risk_level,
                    EntityProfile.anomaly_count_30d,
                )
            )
        ).all()
    }

    # active: 80 * 0.3 + 20 * exp(-1/30) ~= 43.3 -> "medium", counter rolls to 1
    score, level, anomalies = rows["alice"]
    assert 40.0 < score < 47.0
    assert level == "medium"
    assert anomalies == 1

    # stale: no alerts left -> risk decays to 30% of historical
    score, level, anomalies = rows["bob"]
    assert score == pytest.approx(27.0)
    assert level == "medium"
    assert anomalies == 0

    # org B untouched by an org A run
    score, level, _ = rows["carol"]
    assert score == 70.0
    assert level == "high"


# ============================================================================
# detect_impossible_travel
# ============================================================================


def _geo_auth_event(entity, city, lat, lon, hours_ago):
    return _event(
        entity,
        age_days=0,
        created_at=NOW - timedelta(hours=hours_ago),
        geo_location={"city": city, "latitude": lat, "longitude": lon},
    )


@pytest.mark.asyncio
async def test_detect_impossible_travel_creates_exactly_one_alert(
    db_session, anomaly_recorder
):
    entity = _entity()
    db_session.add(entity)
    await db_session.flush()
    entity_pk = entity.id
    # NYC -> Sydney in one hour: ~16,000 km/h, wildly impossible
    db_session.add(_geo_auth_event(entity, "New York", 40.7128, -74.0060, 2))
    db_session.add(_geo_auth_event(entity, "Sydney", -33.8688, 151.2093, 1))
    await db_session.commit()

    result = await _detect_impossible_travel_async(ORG_A)

    assert result["checked_count"] == 1
    assert result["alerts_created"] == 1
    assert len(anomaly_recorder) == 1
    assert anomaly_recorder[0]["anomaly_type"] == "impossible_travel"

    db_session.expire_all()
    alerts = list(
        (
            await db_session.execute(
                select(UEBARiskAlert).where(
                    UEBARiskAlert.alert_type == "impossible_travel"
                )
            )
        ).scalars().all()
    )
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "critical"
    assert alert.entity_profile_id == entity_pk
    assert alert.organization_id == ORG_A
    assert len(alert.contributing_events) == 2
    assert alert.evidence and alert.evidence[0]["required_speed_kmh"] > 900

    # Risk bumped by the alert's delta (critical weight = 40)
    risk_score = (
        await db_session.execute(
            select(EntityProfile.risk_score).where(EntityProfile.id == entity_pk)
        )
    ).scalar_one()
    assert risk_score == pytest.approx(40.0)

    # Re-run: same event pair must NOT re-alert
    result = await _detect_impossible_travel_async(ORG_A)
    assert result["alerts_created"] == 0
    assert len(anomaly_recorder) == 1

    db_session.expire_all()
    count = len(
        (
            await db_session.execute(
                select(UEBARiskAlert.id).where(
                    UEBARiskAlert.alert_type == "impossible_travel"
                )
            )
        ).scalars().all()
    )
    assert count == 1


@pytest.mark.asyncio
async def test_detect_impossible_travel_ignores_plausible_travel(
    db_session, anomaly_recorder
):
    entity = _entity()
    db_session.add(entity)
    await db_session.flush()
    # NYC -> Boston (~300 km) in 12 hours: perfectly possible
    db_session.add(_geo_auth_event(entity, "New York", 40.7128, -74.0060, 13))
    db_session.add(_geo_auth_event(entity, "Boston", 42.3601, -71.0589, 1))
    await db_session.commit()

    result = await _detect_impossible_travel_async(ORG_A)

    assert result["checked_count"] == 1
    assert result["alerts_created"] == 0
    assert anomaly_recorder == []


# ============================================================================
# update_peer_groups
# ============================================================================


@pytest.mark.asyncio
async def test_update_peer_groups_persists_real_groups_per_org(db_session):
    eng = [
        _entity(f"eng{i}", department="Engineering", role="developer")
        for i in range(3)
    ]
    sales = [_entity(f"sales{i}", department="Sales") for i in range(2)]
    loner = _entity("loner")  # no department -> unassigned bucket, skipped
    other_org = [_entity(f"b{i}", org=ORG_B, department="Engineering") for i in range(2)]
    db_session.add_all(eng + sales + [loner] + other_org)
    await db_session.commit()
    eng_ids = sorted(e.id for e in eng)

    result = await _update_peer_groups_async(ORG_A)

    assert result["orgs_processed"] == 1
    assert result["department_groups"] == 2  # Engineering + Sales

    db_session.expire_all()
    groups = list(
        (
            await db_session.execute(
                select(PeerGroup).where(PeerGroup.organization_id == ORG_A)
            )
        ).scalars().all()
    )
    by_name = {g.name: g for g in groups if g.group_type == "department"}
    assert set(by_name) == {"Engineering", "Sales"}
    assert by_name["Engineering"].member_count == 3
    assert sorted(by_name["Engineering"].members) == eng_ids

    # Org B untouched by an org A run
    org_b_groups = (
        await db_session.execute(
            select(PeerGroup.id).where(PeerGroup.organization_id == ORG_B)
        )
    ).scalars().all()
    assert org_b_groups == []

    # Re-run replaces (idempotent), never duplicates
    await _update_peer_groups_async(ORG_A)
    db_session.expire_all()
    names = (
        await db_session.execute(
            select(PeerGroup.name).where(
                PeerGroup.organization_id == ORG_A,
                PeerGroup.group_type == "department",
            )
        )
    ).scalars().all()
    assert sorted(names) == ["Engineering", "Sales"]


# ============================================================================
# generate_ueba_alerts
# ============================================================================


@pytest.mark.asyncio
async def test_generate_ueba_alerts_alerts_once_per_high_risk_entity(
    db_session, anomaly_recorder
):
    hot = _entity("alice", risk_score=82.0, risk_level="critical", anomaly_count_30d=4)
    calm = _entity("bob", risk_score=10.0, risk_level="low")
    other_org_hot = _entity("carol", org=ORG_B, risk_score=90.0, risk_level="critical")
    db_session.add_all([hot, calm, other_org_hot])
    await db_session.flush()
    hot_pk = hot.id
    db_session.add(_alert(hot, severity="critical", age_days=2))
    await db_session.commit()

    result = await _generate_ueba_alerts_async(ORG_A)

    assert result["entities_evaluated"] == 1
    assert result["alerts_generated"] == 1
    assert len(anomaly_recorder) == 1
    assert anomaly_recorder[0]["anomaly_type"] == "high_risk_entity"

    db_session.expire_all()
    alerts = list(
        (
            await db_session.execute(
                select(UEBARiskAlert).where(
                    UEBARiskAlert.alert_type == "high_risk_entity"
                )
            )
        ).scalars().all()
    )
    assert len(alerts) == 1
    assert alerts[0].entity_profile_id == hot_pk
    assert alerts[0].organization_id == ORG_A
    assert alerts[0].severity == "critical"  # 82 >= 75
    assert alerts[0].evidence  # real risk factors from the seeded alert

    # Second run: open alert already exists -> no spam
    result = await _generate_ueba_alerts_async(ORG_A)
    assert result["alerts_generated"] == 0
    assert result["skipped_existing"] == 1
    assert len(anomaly_recorder) == 1


# ============================================================================
# cleanup_old_behavior_events
# ============================================================================


@pytest.mark.asyncio
async def test_cleanup_deletes_only_old_rows_in_the_right_org(db_session):
    entity_a = _entity("alice")
    entity_b = _entity("bob", org=ORG_B)
    db_session.add_all([entity_a, entity_b])
    await db_session.flush()

    old_a = _event(entity_a, age_days=100)
    recent_a = _event(entity_a, age_days=5)
    old_b = _event(entity_b, age_days=100)
    db_session.add_all([old_a, recent_a, old_b])
    await db_session.commit()

    result = await _cleanup_old_behavior_events_async(ORG_A, retention_days=90)

    assert result["status"] == "completed"
    assert result["deleted_count"] == 1

    remaining = set(
        (await db_session.execute(select(BehaviorEvent.id))).scalars().all()
    )
    assert remaining == {recent_a.id, old_b.id}

    # Global (beat) run sweeps the remaining old row across all orgs
    result = await _cleanup_old_behavior_events_async(retention_days=90)
    assert result["deleted_count"] == 1

    remaining = set(
        (await db_session.execute(select(BehaviorEvent.id))).scalars().all()
    )
    assert remaining == {recent_a.id}


# ============================================================================
# process_behavior_events
# ============================================================================


@pytest.mark.asyncio
async def test_process_behavior_events_persists_and_scores_batch(
    db_session, anomaly_recorder
):
    entity = _entity()
    db_session.add(entity)
    await db_session.flush()
    entity_pk = entity.id
    # Warm-up history: 3 prior auth events from the entity's usual IP
    for i in range(3):
        db_session.add(_event(entity, age_days=i + 1, source_ip="10.0.0.1"))
    await db_session.commit()

    batch = [
        {"entity_id": "alice", "event_type": "authentication", "event_data": {}, "source_ip": "10.0.0.1"},
        {"entity_id": "alice", "event_type": "authentication", "event_data": {}, "source_ip": "203.0.113.9"},
        {"entity_id": "ghost", "event_type": "authentication", "event_data": {}, "source_ip": "10.0.0.1"},
    ]

    result = await _process_behavior_events_async(ORG_A, batch)

    assert result["status"] == "completed"
    assert result["processed_count"] == 2
    assert result["failed_count"] == 1  # unknown entity, honestly counted
    assert result["anomaly_count"] >= 1
    assert result["alerts_created"] == result["anomaly_count"]
    assert len(anomaly_recorder) == result["alerts_created"]

    db_session.expire_all()
    events = list(
        (
            await db_session.execute(
                select(BehaviorEvent).where(
                    BehaviorEvent.entity_profile_id == entity_pk
                )
            )
        ).scalars().all()
    )
    assert len(events) == 5  # 3 seeded + 2 ingested

    new_ip_events = [e for e in events if e.source_ip == "203.0.113.9"]
    assert len(new_ip_events) == 1
    assert new_ip_events[0].is_anomalous is True
    assert any(
        r.startswith("new_source_ip:") for r in new_ip_events[0].anomaly_reasons
    )
    assert new_ip_events[0].risk_contribution > 0
    assert new_ip_events[0].organization_id == ORG_A

    # Entity risk counters bumped by the anomaly
    score, anomalies, last_anomaly = (
        await db_session.execute(
            select(
                EntityProfile.risk_score,
                EntityProfile.anomaly_count_30d,
                EntityProfile.last_anomaly_at,
            ).where(EntityProfile.id == entity_pk)
        )
    ).one()
    assert score > 0
    assert anomalies >= 1
    assert last_anomaly is not None


@pytest.mark.asyncio
async def test_process_behavior_events_is_org_scoped(db_session, anomaly_recorder):
    """An org-A run must never touch (or find) org B's identically-named entity."""
    entity_b = _entity("alice", org=ORG_B, risk_score=5.0)
    db_session.add(entity_b)
    await db_session.commit()
    entity_b_pk = entity_b.id

    batch = [
        {"entity_id": "alice", "event_type": "authentication", "event_data": {}, "source_ip": "1.2.3.4"},
    ]
    result = await _process_behavior_events_async(ORG_A, batch)

    assert result["processed_count"] == 0
    assert result["failed_count"] == 1

    db_session.expire_all()
    org_b_events = (
        await db_session.execute(
            select(BehaviorEvent.id).where(
                BehaviorEvent.entity_profile_id == entity_b_pk
            )
        )
    ).scalars().all()
    assert org_b_events == []
