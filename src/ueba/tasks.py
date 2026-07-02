"""UEBA Celery Tasks
Background tasks for behavior analysis, baseline updates, and alert generation.

Each task delegates to a module-level ``_*_async`` coroutine so the real
logic is directly awaitable from tests (and anywhere else that already
has an event loop), while the Celery entrypoints bridge via ``run_async``
exactly like the other task modules.

All tasks operate on the real UEBA tables (EntityProfile, BehaviorEvent,
BehaviorBaseline, UEBARiskAlert, PeerGroup) and are org-scoped: every
per-entity query filters on the entity's own ``organization_id``. Tasks
invoked by beat with no arguments sweep every organization.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import and_, delete, desc, func, select

from src.core.logging import get_logger
from src.siem.tasks import run_async
from src.ueba.engine import (
    BaselineManager,
    ImpossibleTravelDetector,
    PeerGroupAnalyzer,
    RiskScorer,
)

logger = get_logger(__name__)

# Initialize components
baseline_manager = BaselineManager()
risk_scorer = RiskScorer()
travel_detector = ImpossibleTravelDetector()
peer_analyzer = PeerGroupAnalyzer()

# Entities scoring above this are candidates for a high-risk alert.
# 50 is the RiskScorer.update_risk_level "high" boundary.
HIGH_RISK_ALERT_THRESHOLD = 50.0

BASELINE_LOOKBACK_DAYS = 30

# Map BehaviorEvent.event_type onto the behavior keys BaselineManager's
# statistics extractor understands. Baselines are PERSISTED under the raw
# event_type because that is the key `score_event_anomaly` (ingest path)
# looks them up by.
_BASELINE_KIND_FOR_EVENT_TYPE = {
    "authentication": "login_pattern",
    "resource_access": "data_access",
    "network_connection": "network_activity",
}


def _as_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize a datetime to naive UTC for the engine's utcnow arithmetic."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


async def _load_target_entities(db, organization_id, entity_ids):
    """Load target EntityProfiles: all in org (or all orgs) unless entity_ids given.

    ``entity_ids`` are EntityProfile primary keys (same convention as the
    /ueba/baselines/rebuild endpoint).
    """
    from src.ueba.models import EntityProfile

    stmt = select(EntityProfile)
    if organization_id:
        stmt = stmt.where(EntityProfile.organization_id == organization_id)
    if entity_ids:
        stmt = stmt.where(EntityProfile.id.in_(entity_ids))
    return list((await db.execute(stmt)).scalars().all())


def _row_to_baseline_event(row) -> dict:
    """Map a BehaviorEvent row to the event dict shape BaselineManager expects."""
    event: dict[str, Any] = {}
    if row.created_at:
        event["timestamp"] = row.created_at
        event["hour"] = row.created_at.hour
    if row.source_ip:
        # `value` doubles as the typical_values source — the persisted
        # typical source IPs are what ingest scoring compares against.
        event["value"] = row.source_ip
    data = row.event_data or {}
    if isinstance(data, dict):
        for key in ("file_count", "bytes_transferred"):
            if isinstance(data.get(key), (int, float)):
                event[key] = data[key]
    return event


async def _process_behavior_events_async(
    organization_id: Optional[str], event_batch: list[dict]
) -> dict[str, Any]:
    """Persist + score a batch of behavior events via the shared ingest helper.

    Identical semantics to POST /ueba/events/batch: entity lookup by
    ``entity_id`` (org-filtered), ``score_event_anomaly`` scoring, entity
    risk bump, and ``on_ueba_anomaly`` automation fanout on anomalies.
    """
    from src.core.database import async_session_factory
    from src.ueba.ingest import ingest_behavior_event

    processed = 0
    failed = 0
    anomalies = 0
    alerts_created = 0

    async with async_session_factory() as db:
        for event in event_batch:
            try:
                behavior_event, alert_created = await ingest_behavior_event(
                    db, organization_id, event
                )
                if behavior_event is None:
                    failed += 1
                    continue
                processed += 1
                if behavior_event.is_anomalous:
                    anomalies += 1
                if alert_created:
                    alerts_created += 1
            except Exception as exc:  # noqa: BLE001
                logger.error(f"Behavior event ingest failed: {exc}", exc_info=True)
                failed += 1
        await db.commit()

    return {
        "status": "completed",
        "processed_count": processed,
        "failed_count": failed,
        "anomaly_count": anomalies,
        "alerts_created": alerts_created,
    }


async def _update_entity_baselines_async(
    organization_id: Optional[str] = None,
    entity_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Rebuild BehaviorBaseline rows from each entity's last-30d events.

    For every target entity, load its BehaviorEvents from the lookback
    window, group them by event_type, run BaselineManager.build_baseline
    over the mapped event dicts, and upsert one BehaviorBaseline row per
    (entity, event_type). Baselines are stored in the exact shape ingest
    scoring (`score_event_anomaly`) consumes: ``typical_values`` = typical
    source IPs, ``time_patterns.hours`` = typical activity hours — so
    ingest anomaly detection genuinely improves as baselines learn.

    Baselines with fewer than ``baseline_manager.min_samples`` events are
    honestly skipped, never fabricated.
    """
    from src.core.database import async_session_factory
    from src.ueba.models import BehaviorBaseline, BehaviorEvent

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=BASELINE_LOOKBACK_DAYS)

    entities_processed = 0
    baselines_updated = 0
    baselines_skipped = 0

    async with async_session_factory() as db:
        entities = await _load_target_entities(db, organization_id, entity_ids)

        for entity in entities:
            entities_processed += 1

            events_result = await db.execute(
                select(BehaviorEvent).where(
                    and_(
                        BehaviorEvent.entity_profile_id == entity.id,
                        BehaviorEvent.organization_id == entity.organization_id,
                        BehaviorEvent.created_at >= cutoff,
                    )
                )
            )
            events = list(events_result.scalars().all())
            if not events:
                continue

            by_type: dict[str, list] = {}
            for ev in events:
                by_type.setdefault(ev.event_type, []).append(ev)

            for event_type, rows in by_type.items():
                mapped = [_row_to_baseline_event(r) for r in rows]
                kind = _BASELINE_KIND_FOR_EVENT_TYPE.get(event_type, "login_pattern")
                built = baseline_manager.build_baseline(
                    entity.entity_id, kind, mapped, lookback_days=BASELINE_LOOKBACK_DAYS
                )
                if not built.get("statistical_model") and kind != "login_pattern":
                    # e.g. resource_access events without file_count in
                    # event_data — fall back to time-of-day statistics,
                    # which every event has.
                    built = baseline_manager.build_baseline(
                        entity.entity_id,
                        "login_pattern",
                        mapped,
                        lookback_days=BASELINE_LOOKBACK_DAYS,
                    )

                if not built.get("statistical_model"):
                    # Below min_samples (or no usable values) — honest skip.
                    baselines_skipped += 1
                    continue

                engine_time_patterns = built.get("time_patterns") or {}
                time_patterns = {
                    **engine_time_patterns,
                    # Key that ingest scoring reads.
                    "hours": engine_time_patterns.get("typical_hours", []),
                }
                typical_values = [v for v in built.get("typical_values", []) if v]

                existing_result = await db.execute(
                    select(BehaviorBaseline).where(
                        and_(
                            BehaviorBaseline.entity_profile_id == entity.id,
                            BehaviorBaseline.behavior_type == event_type,
                        )
                    ).limit(1)
                )
                baseline_row = existing_result.scalar_one_or_none()
                if baseline_row is None:
                    baseline_row = BehaviorBaseline(
                        id=str(uuid.uuid4()),
                        entity_profile_id=entity.id,
                        behavior_type=event_type,
                    )
                    db.add(baseline_row)

                baseline_row.baseline_period_days = BASELINE_LOOKBACK_DAYS
                baseline_row.statistical_model = built["statistical_model"]
                baseline_row.typical_values = typical_values
                baseline_row.time_patterns = time_patterns
                baseline_row.confidence = round(built.get("confidence", 0.0), 3)
                baseline_row.sample_count = built.get("sample_count", 0)
                baseline_row.last_updated_at = now
                baselines_updated += 1

            # Summary on the profile, same shape the rebuild endpoint writes.
            entity.baseline_data = {
                "baseline_days": BASELINE_LOOKBACK_DAYS,
                "event_types": list(by_type.keys()),
                "total_events": len(events),
                "last_rebuild": now.isoformat(),
            }

        await db.commit()

    return {
        "status": "completed",
        "entities_processed": entities_processed,
        "baselines_updated": baselines_updated,
        "baselines_skipped": baselines_skipped,
    }


async def _calculate_entity_risks_async(
    organization_id: Optional[str] = None,
    entity_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Recalculate risk score/level and the rolling 30d anomaly counter.

    Risk comes from the entity's real last-30d UEBARiskAlerts (severity-
    weighted with time decay) plus 30% of the historical score, so risk
    decays as alerts age out. ``anomaly_count_30d`` is recomputed from
    actual anomalous BehaviorEvent rows — ingest only ever increments it,
    this task is what makes it a true rolling window.
    """
    from src.core.database import async_session_factory
    from src.ueba.models import BehaviorEvent, UEBARiskAlert

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)

    entities_updated = 0
    high_risk_count = 0
    critical_risk_count = 0

    async with async_session_factory() as db:
        entities = await _load_target_entities(db, organization_id, entity_ids)

        for entity in entities:
            alerts_result = await db.execute(
                select(UEBARiskAlert).where(
                    and_(
                        UEBARiskAlert.entity_profile_id == entity.id,
                        UEBARiskAlert.organization_id == entity.organization_id,
                        UEBARiskAlert.created_at >= cutoff,
                    )
                )
            )
            recent_alerts = [
                {"severity": a.severity, "created_at": _as_naive_utc(a.created_at)}
                for a in alerts_result.scalars().all()
            ]

            risk_score = risk_scorer.calculate_entity_risk(
                entity.entity_id,
                recent_alerts,
                historical_risk=entity.risk_score or 0.0,
            )
            risk_level = risk_scorer.update_risk_level(risk_score)

            anomaly_count_result = await db.execute(
                select(func.count(BehaviorEvent.id)).where(
                    and_(
                        BehaviorEvent.entity_profile_id == entity.id,
                        BehaviorEvent.organization_id == entity.organization_id,
                        BehaviorEvent.is_anomalous.is_(True),
                        BehaviorEvent.created_at >= cutoff,
                    )
                )
            )
            anomaly_count = anomaly_count_result.scalar() or 0

            entity.risk_score = round(risk_score, 2)
            entity.risk_level = risk_level
            entity.anomaly_count_30d = anomaly_count

            entities_updated += 1
            if risk_level == "critical":
                critical_risk_count += 1
            elif risk_level == "high":
                high_risk_count += 1

        await db.commit()

    return {
        "status": "completed",
        "entities_updated": entities_updated,
        "critical_risk_count": critical_risk_count,
        "high_risk_count": high_risk_count,
    }


async def _detect_impossible_travel_async(
    organization_id: Optional[str] = None,
    entity_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Check each entity's last two geo-tagged authentication events.

    On a physically impossible hop, persist a UEBARiskAlert (deduped on
    the latest contributing event so re-runs don't re-alert on the same
    pair), bump the entity risk by the alert's ``risk_score_delta``, and
    fire the on_ueba_anomaly automation fanout like ingest does.
    """
    from src.core.database import async_session_factory
    from src.services.automation import AutomationService
    from src.ueba.ingest import risk_level_for_score
    from src.ueba.models import BehaviorEvent, UEBARiskAlert

    now = datetime.now(timezone.utc)
    checked_count = 0
    alerts_created = 0

    async with async_session_factory() as db:
        entities = await _load_target_entities(db, organization_id, entity_ids)

        for entity in entities:
            checked_count += 1

            events_result = await db.execute(
                select(BehaviorEvent).where(
                    and_(
                        BehaviorEvent.entity_profile_id == entity.id,
                        BehaviorEvent.organization_id == entity.organization_id,
                        BehaviorEvent.event_type == "authentication",
                        BehaviorEvent.geo_location.is_not(None),
                    )
                ).order_by(desc(BehaviorEvent.created_at)).limit(2)
            )
            recent = list(events_result.scalars().all())
            if len(recent) < 2:
                continue

            latest, previous = recent
            if not (latest.created_at and previous.created_at):
                continue

            detection = travel_detector.check_impossible_travel(
                entity.entity_id,
                latest.geo_location or {},
                latest.created_at,
                previous.geo_location or {},
                previous.created_at,
            )
            if not detection:
                continue

            # Dedupe: never re-alert on the same latest event.
            existing_result = await db.execute(
                select(UEBARiskAlert).where(
                    and_(
                        UEBARiskAlert.entity_profile_id == entity.id,
                        UEBARiskAlert.organization_id == entity.organization_id,
                        UEBARiskAlert.alert_type == "impossible_travel",
                        UEBARiskAlert.status != "dismissed",
                    )
                )
            )
            already_alerted = any(
                latest.id in (existing.contributing_events or [])
                for existing in existing_result.scalars().all()
            )
            if already_alerted:
                continue

            severity = detection.get("severity", "critical")
            risk_delta = float(risk_scorer.SEVERITY_WEIGHTS.get(severity, 20))

            alert = UEBARiskAlert(
                id=str(uuid.uuid4()),
                entity_profile_id=entity.id,
                alert_type="impossible_travel",
                severity=severity,
                risk_score_delta=risk_delta,
                description=detection["description"],
                evidence=[detection.get("evidence", {})],
                contributing_events=[latest.id, previous.id],
                mitre_techniques=["T1078"],
                status="new",
                organization_id=entity.organization_id,
            )
            db.add(alert)

            entity.risk_score = min(100.0, (entity.risk_score or 0.0) + risk_delta)
            entity.risk_level = risk_level_for_score(entity.risk_score)
            entity.last_anomaly_at = now

            try:
                automation = AutomationService(db)
                await automation.on_ueba_anomaly(
                    entity_type=entity.entity_type,
                    entity_id=entity.entity_id,
                    anomaly_type="impossible_travel",
                    risk_score=entity.risk_score or 0.0,
                    details=detection["description"],
                    organization_id=entity.organization_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(f"Impossible-travel automation fanout failed: {exc}")

            alerts_created += 1
            logger.warning(
                f"Impossible travel detected for {entity.entity_id}: {detection['description']}"
            )

        await db.commit()

    return {
        "status": "completed",
        "checked_count": checked_count,
        "alerts_created": alerts_created,
    }


async def _update_peer_groups_async(
    organization_id: Optional[str] = None,
) -> dict[str, Any]:
    """Rebuild department / role / auto-clustered PeerGroup rows per org.

    Existing task-managed groups (types department, role, auto_clustered)
    are replaced; analyst-created ``custom`` groups are left alone.
    """
    from src.core.database import async_session_factory
    from src.ueba.models import EntityProfile, PeerGroup

    now = datetime.now(timezone.utc)
    department_count = 0
    role_count = 0
    auto_count = 0
    orgs_processed = 0

    async with async_session_factory() as db:
        if organization_id:
            org_ids = [organization_id]
        else:
            org_ids = list(
                (
                    await db.execute(
                        select(EntityProfile.organization_id).distinct()
                    )
                ).scalars().all()
            )

        for org_id in org_ids:
            orgs_processed += 1

            entities_result = await db.execute(
                select(EntityProfile).where(EntityProfile.organization_id == org_id)
            )
            entities = list(entities_result.scalars().all())
            if not entities:
                continue

            entity_dicts = []
            risk_by_id: dict[str, float] = {}
            for e in entities:
                d: dict[str, Any] = {"id": e.id, "entity_type": e.entity_type}
                if e.department:
                    d["department"] = e.department
                if e.role:
                    d["role"] = e.role
                entity_dicts.append(d)
                risk_by_id[e.id] = e.risk_score or 0.0

            department_groups = peer_analyzer.build_peer_groups(
                entity_dicts, method="department"
            )
            role_groups = peer_analyzer.build_peer_groups(entity_dicts, method="role")
            auto_groups = peer_analyzer.auto_cluster_peers(
                entity_dicts, ["entity_type", "department", "role"]
            )

            # Replace this org's task-managed groups (leave `custom` alone).
            await db.execute(
                delete(PeerGroup).where(
                    and_(
                        PeerGroup.organization_id == org_id,
                        PeerGroup.group_type.in_(
                            ("department", "role", "auto_clustered")
                        ),
                    )
                )
            )

            for group_type, groups in (
                ("department", department_groups),
                ("role", role_groups),
                ("auto_clustered", auto_groups),
            ):
                for group in groups:
                    members = group.get("members", [])
                    # A peer group of one (or an unattributed bucket) isn't
                    # a useful comparison population.
                    if len(members) < 2 or group.get("name") in (None, "unassigned"):
                        continue

                    scores = [risk_by_id.get(m, 0.0) for m in members]
                    mean_risk = sum(scores) / len(scores) if scores else 0.0
                    baseline_data = {
                        "mean_risk_score": round(mean_risk, 2),
                        "member_count": len(members),
                    }
                    if group.get("centroid"):
                        baseline_data["centroid"] = group["centroid"]

                    db.add(
                        PeerGroup(
                            id=str(uuid.uuid4()),
                            name=str(group["name"]),
                            description=(
                                f"Rebuilt by UEBA peer-group task on "
                                f"{now.date().isoformat()}"
                            ),
                            group_type=group_type,
                            member_count=len(members),
                            baseline_data=baseline_data,
                            risk_threshold=max(70.0, mean_risk + 20.0),
                            members=list(members),
                            organization_id=org_id,
                        )
                    )
                    if group_type == "department":
                        department_count += 1
                    elif group_type == "role":
                        role_count += 1
                    else:
                        auto_count += 1

        await db.commit()

    return {
        "status": "completed",
        "orgs_processed": orgs_processed,
        "department_groups": department_count,
        "role_groups": role_count,
        "auto_clusters": auto_count,
        "total_groups": department_count + role_count + auto_count,
    }


async def _generate_ueba_alerts_async(
    organization_id: Optional[str] = None,
) -> dict[str, Any]:
    """Create high-risk-entity alerts for entities above the risk threshold.

    Risk factors come from the entity's real last-30d UEBARiskAlerts.
    Deduped: an entity with an open (new/investigating) high_risk_entity
    alert is skipped so hourly runs don't spam the same entity.
    """
    from src.core.database import async_session_factory
    from src.services.automation import AutomationService
    from src.ueba.models import EntityProfile, UEBARiskAlert

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)

    entities_evaluated = 0
    alerts_generated = 0
    skipped_existing = 0

    async with async_session_factory() as db:
        stmt = select(EntityProfile).where(
            EntityProfile.risk_score > HIGH_RISK_ALERT_THRESHOLD
        )
        if organization_id:
            stmt = stmt.where(EntityProfile.organization_id == organization_id)
        entities = list((await db.execute(stmt)).scalars().all())

        for entity in entities:
            entities_evaluated += 1

            existing_result = await db.execute(
                select(UEBARiskAlert.id).where(
                    and_(
                        UEBARiskAlert.entity_profile_id == entity.id,
                        UEBARiskAlert.organization_id == entity.organization_id,
                        UEBARiskAlert.alert_type == "high_risk_entity",
                        UEBARiskAlert.status.in_(("new", "investigating")),
                    )
                ).limit(1)
            )
            if existing_result.scalar_one_or_none():
                skipped_existing += 1
                continue

            alerts_result = await db.execute(
                select(UEBARiskAlert).where(
                    and_(
                        UEBARiskAlert.entity_profile_id == entity.id,
                        UEBARiskAlert.organization_id == entity.organization_id,
                        UEBARiskAlert.created_at >= cutoff,
                    )
                )
            )
            recent_alert_rows = list(alerts_result.scalars().all())
            risk_factors = risk_scorer.get_risk_factors(
                entity.entity_id,
                [{"severity": a.severity} for a in recent_alert_rows],
            )

            severity = "critical" if (entity.risk_score or 0.0) >= 75 else "high"
            factor_summary = ", ".join(
                f"{f['factor']}={f['count']}" for f in risk_factors
            )
            description = (
                f"Entity risk score {entity.risk_score:.1f} ({entity.risk_level}) "
                f"exceeds threshold {HIGH_RISK_ALERT_THRESHOLD:.0f}. "
                f"{entity.anomaly_count_30d or 0} anomalies in last 30 days."
            )
            if factor_summary:
                description += f" Risk factors: {factor_summary}."

            db.add(
                UEBARiskAlert(
                    id=str(uuid.uuid4()),
                    entity_profile_id=entity.id,
                    alert_type="high_risk_entity",
                    severity=severity,
                    # Summarizes existing risk; does not raise the score.
                    risk_score_delta=0.0,
                    description=description,
                    evidence=risk_factors,
                    contributing_events=[a.id for a in recent_alert_rows],
                    status="new",
                    organization_id=entity.organization_id,
                )
            )

            try:
                automation = AutomationService(db)
                await automation.on_ueba_anomaly(
                    entity_type=entity.entity_type,
                    entity_id=entity.entity_id,
                    anomaly_type="high_risk_entity",
                    risk_score=entity.risk_score or 0.0,
                    details=description,
                    organization_id=entity.organization_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(f"High-risk-entity automation fanout failed: {exc}")

            alerts_generated += 1

        await db.commit()

    return {
        "status": "completed",
        "entities_evaluated": entities_evaluated,
        "alerts_generated": alerts_generated,
        "skipped_existing": skipped_existing,
    }


async def _cleanup_old_behavior_events_async(
    organization_id: Optional[str] = None,
    retention_days: int = 90,
) -> dict[str, Any]:
    """Delete BehaviorEvent rows older than the retention cutoff."""
    from src.core.database import async_session_factory
    from src.ueba.models import BehaviorEvent

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

    async with async_session_factory() as db:
        stmt = delete(BehaviorEvent).where(BehaviorEvent.created_at < cutoff_date)
        if organization_id:
            stmt = stmt.where(BehaviorEvent.organization_id == organization_id)
        result = await db.execute(stmt)
        await db.commit()
        deleted_count = result.rowcount or 0

    return {
        "status": "completed",
        "deleted_count": deleted_count,
        "cutoff_date": cutoff_date.isoformat(),
    }


@shared_task(bind=True, max_retries=3)
def process_behavior_events(self, organization_id: Optional[str], event_batch: list[dict]) -> dict:
    """
    Ingest and analyze new behavior events.

    Persists and scores each event exactly like the batch ingest endpoint:
    entity lookup by entity_id (org-scoped), baseline anomaly scoring,
    entity risk bump, and on_ueba_anomaly automation fanout.

    Args:
        organization_id: Organization context
        event_batch: List of behavior event dictionaries (entity_id,
            event_type, event_data, source_ip, destination, geo_location,
            device_info)

    Returns:
        Dictionary with processing results
    """
    try:
        logger.info(f"Processing {len(event_batch)} behavior events for org {organization_id}")

        result = run_async(
            _process_behavior_events_async(organization_id, event_batch)
        )

        logger.info(
            f"Processed {result['processed_count']} events: "
            f"{result['anomaly_count']} anomalies, {result['alerts_created']} alerts"
        )
        return result

    except Exception as exc:
        logger.error(f"Error processing behavior events: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=2)
def update_entity_baselines(
    self,
    organization_id: Optional[str] = None,
    entity_ids: Optional[list[str]] = None,
) -> dict:
    """
    Recalculate entity baselines periodically.

    Builds BehaviorBaseline rows from each entity's real last-30d
    BehaviorEvents (per event_type), stored in the shape ingest scoring
    reads — so anomaly detection improves as baselines learn.

    Args:
        organization_id: Organization context (None = all organizations)
        entity_ids: Specific EntityProfile ids to update (None = all)

    Returns:
        Dictionary with update results
    """
    try:
        logger.info(f"Updating baselines for org {organization_id or 'all'}")

        result = run_async(
            _update_entity_baselines_async(organization_id, entity_ids)
        )

        logger.info(
            f"Baseline update completed: {result['baselines_updated']} updated, "
            f"{result['baselines_skipped']} skipped"
        )
        return result

    except Exception as exc:
        logger.error(f"Error in baseline update task: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def calculate_entity_risks(
    self,
    organization_id: Optional[str] = None,
    entity_ids: Optional[list[str]] = None,
) -> dict:
    """
    Recalculate all entity risk scores.

    Scores from real last-30d UEBARiskAlerts (severity-weighted, time
    decayed) and recomputes anomaly_count_30d from real BehaviorEvent
    rows so the counter rolls and stale risk decays.

    Args:
        organization_id: Organization context (None = all organizations)
        entity_ids: Specific EntityProfile ids to calculate (None = all)

    Returns:
        Dictionary with calculation results
    """
    try:
        logger.info(f"Calculating entity risks for org {organization_id or 'all'}")

        result = run_async(
            _calculate_entity_risks_async(organization_id, entity_ids)
        )

        logger.info(
            f"Risk calculation completed: {result['entities_updated']} updated, "
            f"{result['critical_risk_count']} critical, {result['high_risk_count']} high"
        )
        return result

    except Exception as exc:
        logger.error(f"Error in risk calculation task: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=2)
def detect_impossible_travel(
    self,
    organization_id: Optional[str] = None,
    entity_ids: Optional[list[str]] = None,
) -> dict:
    """
    Check for impossible travel events.

    Runs the haversine impossible-travel detector over each entity's last
    two geo-tagged authentication events; detections persist a real
    UEBARiskAlert (deduped per event pair) and fire automation fanout.

    Args:
        organization_id: Organization context (None = all organizations)
        entity_ids: Specific EntityProfile ids to check (None = all)

    Returns:
        Dictionary with detection results
    """
    try:
        logger.info(f"Detecting impossible travel for org {organization_id or 'all'}")

        result = run_async(
            _detect_impossible_travel_async(organization_id, entity_ids)
        )

        logger.info(
            f"Impossible travel detection completed: {result['checked_count']} checked, "
            f"{result['alerts_created']} alerts"
        )
        return result

    except Exception as exc:
        logger.error(f"Error in impossible travel detection task: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=2)
def update_peer_groups(self, organization_id: Optional[str] = None) -> dict:
    """
    Refresh peer group memberships and baselines.

    Rebuilds department / role / auto-clustered PeerGroup rows per org
    from real EntityProfiles (custom groups untouched).

    Args:
        organization_id: Organization context (None = all organizations)

    Returns:
        Dictionary with update results
    """
    try:
        logger.info(f"Updating peer groups for org {organization_id or 'all'}")

        result = run_async(_update_peer_groups_async(organization_id))

        logger.info(
            f"Peer groups updated: {result['department_groups']} departments, "
            f"{result['role_groups']} roles, {result['auto_clusters']} auto-clusters"
        )
        return result

    except Exception as exc:
        logger.error(f"Error in peer group update task: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def generate_ueba_alerts(self, organization_id: Optional[str] = None) -> dict:
    """
    Generate alerts for high-risk entities.

    Creates a UEBARiskAlert (plus main-feed alert via on_ueba_anomaly)
    for every entity whose risk score exceeds the high-risk threshold,
    skipping entities that already have an open high_risk_entity alert.

    Args:
        organization_id: Organization context (None = all organizations)

    Returns:
        Dictionary with alert generation results
    """
    try:
        logger.info(f"Generating UEBA alerts for org {organization_id or 'all'}")

        result = run_async(_generate_ueba_alerts_async(organization_id))

        logger.info(
            f"Alert generation completed: {result['alerts_generated']} alerts "
            f"from {result['entities_evaluated']} entities"
        )
        return result

    except Exception as exc:
        logger.error(f"Error in alert generation task: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=1)
def cleanup_old_behavior_events(
    self,
    organization_id: Optional[str] = None,
    retention_days: int = 90,
) -> dict:
    """
    Clean up old behavior events for data retention.

    Deletes BehaviorEvent rows older than the retention period
    (org-scoped when an organization is given, global for beat).

    Args:
        organization_id: Organization context (None = all organizations)
        retention_days: Number of days to retain

    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info(
            f"Cleaning up behavior events for org {organization_id or 'all'} "
            f"(retention: {retention_days}d)"
        )

        result = run_async(
            _cleanup_old_behavior_events_async(organization_id, retention_days)
        )

        logger.info(
            f"Behavior event cleanup completed: {result['deleted_count']} events deleted"
        )
        return result

    except Exception as exc:
        logger.error(f"Error in cleanup task: {exc}")
        raise self.retry(exc=exc, countdown=300)
