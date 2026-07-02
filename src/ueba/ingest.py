"""Shared UEBA event-ingest logic.

``score_event_anomaly`` and ``ingest_behavior_event`` are the single
source of truth for how a behavior event is scored, persisted, and
fanned out to automation. Both the REST ingest endpoints
(``src/api/v1/endpoints/ueba.py`` — ``POST /ueba/events`` and
``POST /ueba/events/batch``) and the Celery task
``src.ueba.tasks.process_behavior_events`` call these helpers, so the
API path and the background path cannot drift apart.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.ueba.models import BehaviorBaseline, BehaviorEvent, EntityProfile

logger = get_logger(__name__)


def _org_filter(model, org_id):
    """Return an org_id filter clause, or True if org_id is None (skip filtering)."""
    if org_id:
        return model.organization_id == org_id
    return True


def risk_level_for_score(risk_score: float) -> str:
    """Ingest-path risk bucketing (matches the /ueba/events endpoints)."""
    if risk_score >= 80:
        return "critical"
    if risk_score >= 60:
        return "high"
    if risk_score >= 30:
        return "medium"
    return "low"


async def score_event_anomaly(
    db: AsyncSession,
    entity: EntityProfile,
    behavior_event: BehaviorEvent,
) -> tuple[bool, list, float]:
    """Score a behavior event for anomaly-ness against the entity's baseline.

    Returns (is_anomalous, reasons, risk_contribution).

    Strategy:
    1. Look up a BehaviorBaseline for (entity, event_type). If one exists, check
       the incoming source_ip / destination / hour against its statistical model
       (typical_values, time_patterns).
    2. If no baseline, fall back to comparing against the entity's own recent
       events of the same type: a new source_ip, a never-before-seen destination,
       or an activity at an unusual hour (before 6am or after 10pm UTC) count
       as anomalous.
    3. The first few events per entity (when history < 3) are *not* flagged,
       otherwise every event on a cold entity looks anomalous. This mirrors
       real UEBA warm-up behavior.
    """
    reasons: list[str] = []
    risk_delta = 0.0

    event_hour = datetime.now(timezone.utc).hour
    unusual_hour = event_hour < 6 or event_hour >= 22

    # Try baseline first
    baseline_result = await db.execute(
        select(BehaviorBaseline).where(
            and_(
                BehaviorBaseline.entity_profile_id == entity.id,
                BehaviorBaseline.behavior_type == behavior_event.event_type,
            )
        ).limit(1)
    )
    baseline = baseline_result.scalar_one_or_none()

    if baseline and baseline.confidence >= 0.3:
        typical = baseline.typical_values or []
        time_patterns = baseline.time_patterns or {}
        typical_ips = set(typical) if isinstance(typical, list) else set()

        if behavior_event.source_ip and behavior_event.source_ip not in typical_ips:
            reasons.append(f"new_source_ip:{behavior_event.source_ip}")
            risk_delta += 8.0

        typical_hours = set(time_patterns.get("hours", [])) if isinstance(time_patterns, dict) else set()
        if typical_hours and event_hour not in typical_hours:
            reasons.append(f"unusual_hour:{event_hour}")
            risk_delta += 5.0

        if unusual_hour and not typical_hours:
            reasons.append(f"off_hours:{event_hour}")
            risk_delta += 3.0
    else:
        # Cold-start: use entity's recent history as the baseline
        recent_result = await db.execute(
            select(BehaviorEvent).where(
                and_(
                    BehaviorEvent.entity_profile_id == entity.id,
                    BehaviorEvent.event_type == behavior_event.event_type,
                )
            ).order_by(desc(BehaviorEvent.created_at)).limit(50)
        )
        recent = list(recent_result.scalars().all())

        # Warm-up: need at least 3 prior samples before flagging
        if len(recent) < 3:
            return (False, [], 0.0)

        seen_ips = {r.source_ip for r in recent if r.source_ip}
        seen_dests = {r.destination for r in recent if r.destination}

        if behavior_event.source_ip and behavior_event.source_ip not in seen_ips:
            reasons.append(f"new_source_ip:{behavior_event.source_ip}")
            risk_delta += 10.0

        if behavior_event.destination and behavior_event.destination not in seen_dests:
            reasons.append(f"new_destination:{behavior_event.destination}")
            risk_delta += 6.0

        if unusual_hour:
            reasons.append(f"off_hours:{event_hour}")
            risk_delta += 4.0

    # Geo impossibility: if geo_location differs from the entity's most recent event
    if behavior_event.geo_location and isinstance(behavior_event.geo_location, dict):
        new_country = behavior_event.geo_location.get("country")
        if new_country:
            last_geo_result = await db.execute(
                select(BehaviorEvent.geo_location).where(
                    and_(
                        BehaviorEvent.entity_profile_id == entity.id,
                        BehaviorEvent.geo_location.is_not(None),
                    )
                ).order_by(desc(BehaviorEvent.created_at)).limit(1)
            )
            last_geo = last_geo_result.scalar_one_or_none()
            if isinstance(last_geo, dict):
                last_country = last_geo.get("country")
                if last_country and last_country != new_country:
                    reasons.append(f"geo_change:{last_country}->{new_country}")
                    risk_delta += 12.0

    return (len(reasons) > 0, reasons, risk_delta)


async def ingest_behavior_event(
    db: AsyncSession,
    organization_id: Optional[str],
    event: dict,
) -> tuple[Optional[BehaviorEvent], bool]:
    """Persist and score one behavior event for the entity it belongs to.

    Looks up the EntityProfile by its ``entity_id`` field (org-scoped when
    ``organization_id`` is given), scores the event with
    ``score_event_anomaly``, bumps the entity's rolling risk counters on
    anomaly, and fires the ``on_ueba_anomaly`` automation fanout.

    Returns ``(behavior_event, alert_created)``. ``(None, False)`` means the
    entity does not exist in the organization — the caller decides whether
    that is a 404 (single ingest) or a failed-count (batch/task).

    The BehaviorEvent is ``db.add()``-ed but not flushed/committed; the
    caller owns transaction boundaries.
    """
    from src.services.automation import AutomationService

    entity_result = await db.execute(
        select(EntityProfile).where(
            and_(
                EntityProfile.entity_id == event.get("entity_id"),
                _org_filter(EntityProfile, organization_id),
            )
        )
    )
    entity = entity_result.scalar_one_or_none()
    if not entity:
        return (None, False)

    behavior_event = BehaviorEvent(
        id=str(uuid.uuid4()),
        entity_profile_id=entity.id,
        event_type=event.get("event_type"),
        event_data=event.get("event_data") or {},
        source_ip=event.get("source_ip"),
        destination=event.get("destination"),
        geo_location=event.get("geo_location"),
        device_info=event.get("device_info"),
        organization_id=entity.organization_id,
    )

    is_anomalous, reasons, risk_delta = await score_event_anomaly(
        db, entity, behavior_event
    )
    behavior_event.is_anomalous = is_anomalous
    behavior_event.anomaly_reasons = reasons
    behavior_event.risk_contribution = risk_delta

    now = datetime.now(timezone.utc)
    if is_anomalous:
        # Bump the entity's rolling risk score and anomaly counters
        entity.risk_score = min(100.0, (entity.risk_score or 0.0) + risk_delta)
        entity.anomaly_count_30d = (entity.anomaly_count_30d or 0) + 1
        entity.last_anomaly_at = now
        entity.risk_level = risk_level_for_score(entity.risk_score)
    entity.last_activity_at = now

    db.add(behavior_event)

    # Fire automation for UEBA anomaly so the downstream alert/incident
    # fanout matches across ingest paths.
    alert_created = False
    if is_anomalous:
        try:
            automation = AutomationService(db)
            await automation.on_ueba_anomaly(
                entity_type=entity.entity_type,
                entity_id=entity.entity_id,
                anomaly_type=behavior_event.event_type,
                risk_score=entity.risk_score or 0.0,
                organization_id=entity.organization_id,
            )
            alert_created = True
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Automation failed for UEBA anomaly: {exc}")

    return (behavior_event, alert_created)
