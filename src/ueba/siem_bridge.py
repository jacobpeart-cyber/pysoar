"""UEBA SIEM bridge: entity profiles, baselines and anomaly scores from stored logs.

Until wave 3 nothing created ``EntityProfile`` rows, so every UEBA widget was
permanently empty. This module walks the organisation's stored SIEM log
entries (``log_entries``, read through the model only) and turns them into
UEBA data:

1. **Cursor.** Each organisation has a ``LogIngestCursor`` (consumer
   ``ueba_siem``). A run reads log entries with ``(received_at, id)`` strictly
   after the cursor and ``received_at`` at least ``SETTLE_SECONDS`` old, in
   that order, streamed ``BRIDGE_BATCH_SIZE`` rows at a time, at most
   ``MAX_LOG_ROWS_PER_RUN`` rows and ``MAX_BUCKETS_PER_RUN`` (entity, hour)
   buckets per run. Whatever a cap leaves is read by the next run (the cursor
   only moves past rows that were folded in). A first run looks back
   ``INITIAL_LOOKBACK_HOURS``.

2. **Entities.** Every non-empty ``username`` becomes a ``user`` entity and
   every non-empty ``hostname`` a ``host`` entity (lower-cased; placeholders
   such as ``-`` / ``n/a`` / ``unknown`` are ignored). Missing profiles are
   created in the log's organisation; ``last_activity_at`` and
   ``current_behavior`` are updated from the newest bucket.

3. **Hourly activity buckets.** Per (entity, UTC hour of the event timestamp)
   one ``BehaviorEvent`` row of type ``activity_hourly`` holds real counts:

   * ``events``: log entries that named the entity;
   * ``auth_successes`` / ``auth_failures``: authentication entries
     (``log_type == "authentication"`` or a login/logon/auth action) with
     outcome success / failure;
   * ``distinct_sources``: distinct ``source_address`` values;
   * ``distinct_peers``: distinct hosts a user touched, or distinct users seen
     on a host;
   * ``distinct_destinations``: distinct ``destination_address`` values.

   The distinct sets are stored per bucket and capped at ``SET_CAP`` values,
   so those three counts saturate at ``SET_CAP`` per hour. An event timestamp
   that cannot be parsed, lies more than an hour in the future or is older
   than the baseline window is bucketed by ``received_at`` instead. The bucket
   row id is derived from (organisation, entity, hour), so a later run that
   sees more logs for the same hour merges into the same row.

4. **Baseline.** For each bucket touched by a run, the baseline is the
   entity's own earlier buckets within ``BASELINE_DAYS`` (at most
   ``MAX_BASELINE_BUCKETS``). For every metric it is the mean and population
   standard deviation of the per-active-hour counts. A bucket with fewer than
   ``MIN_BASELINE_BUCKETS`` earlier buckets is recorded as ``warming_up`` and
   never flagged. The entity's latest baseline is persisted as a
   ``BehaviorBaseline`` row (``behavior_type = "activity_hourly"``,
   ``confidence = min(1, n / 168)`` i.e. full confidence after a week of
   active hours, ``typical_values`` = most frequent source addresses).

5. **Anomaly score.** For each metric ``z = (x - mean) / max(std, STD_FLOOR)``.
   A metric is flagged when ``z >= Z_THRESHOLD`` and ``x`` reaches the
   metric's ``MIN_ABSOLUTE`` floor (a jump from 0 to 2 failures is not a
   spike). The bucket's anomaly score is ``min(100, 10 * max z)`` over the
   flagged metrics; nothing else feeds it.

6. **Alerts.** A flagged bucket raises one ``UEBARiskAlert`` (deduplicated per
   bucket): ``auth_failure_spike`` (MITRE T1110) when ``auth_failures`` has the
   highest z, otherwise ``activity_spike``. Severity from the highest z:
   ``>= 6`` high, ``>= 4`` medium, else low. ``risk_score_delta`` is the
   ``RiskScorer.SEVERITY_WEIGHTS`` weight of that severity (the same weights
   the hourly risk recalculation uses), added to the entity's risk score.
   Evidence carries every flagged metric with its value, baseline mean, std,
   z and the number of baseline buckets, plus sample log entry ids.

Each organisation's run is one transaction: buckets, entities, baselines,
alerts and the cursor commit together or not at all, so a failed run is
re-read in full by the next one and nothing is counted twice. The session is
flushed and expunged in fixed chunks, so the identity map never holds more
than one chunk of rows.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.ueba.engine import RiskScorer
from src.ueba.ingest import risk_level_for_score
from src.ueba.models import (
    BehaviorBaseline,
    BehaviorEvent,
    EntityProfile,
    LogIngestCursor,
    UEBARiskAlert,
)

logger = get_logger(__name__)

CONSUMER = "ueba_siem"
EVENT_TYPE = "activity_hourly"

#: Log rows per streamed round trip.
BRIDGE_BATCH_SIZE = 1_000
#: Log rows one organisation may fold in per run; the rest waits for the next run.
MAX_LOG_ROWS_PER_RUN = 50_000
#: Distinct (entity, hour) buckets one run may touch per organisation.
MAX_BUCKETS_PER_RUN = 5_000
#: Distinct values kept per bucket for each distinct-count metric.
SET_CAP = 50
#: Sample log entry ids kept per bucket (evidence links).
SAMPLE_LOG_IDS = 20
#: How far back the first run of an organisation reads.
INITIAL_LOOKBACK_HOURS = 24
#: Rows younger than this are left for the next run (late commits).
SETTLE_SECONDS = 30
#: Entities / buckets handled per flush + expunge.
WRITE_CHUNK = 500

BASELINE_DAYS = 30
MAX_BASELINE_BUCKETS = BASELINE_DAYS * 24
MIN_BASELINE_BUCKETS = 24
#: Hours of activity after which a baseline counts as fully confident.
FULL_CONFIDENCE_BUCKETS = 168
Z_THRESHOLD = 3.0
STD_FLOOR = 1.0
TYPICAL_SOURCES_KEPT = 50

METRICS: tuple[str, ...] = (
    "events",
    "auth_successes",
    "auth_failures",
    "distinct_sources",
    "distinct_peers",
    "distinct_destinations",
)
#: A metric is only flagged when its hourly value reaches this floor.
MIN_ABSOLUTE: dict[str, int] = {
    "events": 20,
    "auth_successes": 20,
    "auth_failures": 5,
    "distinct_sources": 3,
    "distinct_peers": 3,
    "distinct_destinations": 3,
}

_IGNORED_NAMES = frozenset({"", "-", "--", "n/a", "na", "none", "null", "unknown", "(null)"})
_AUTH_ACTION_HINTS = ("login", "logon", "logoff", "auth", "sign-in", "signin", "sign_in")
_FAILURE_OUTCOMES = frozenset({"failure", "failed", "fail", "denied", "error"})
_SUCCESS_OUTCOMES = frozenset({"success", "succeeded", "allowed"})

_BUCKET_NS = uuid.UUID("6f1d2c0e-9b7a-4d55-8a0e-3c6c2b1f7e01")

_scorer = RiskScorer()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def parse_log_time(value: Any) -> Optional[datetime]:
    """Aware UTC datetime from a stored ISO string, else None."""
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def naive_utc(dt: datetime) -> datetime:
    """Naive UTC for the ``DateTime`` (without time zone) UEBA columns."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def entity_key(value: Any) -> Optional[str]:
    """Normalised entity id (lower-case, trimmed) or None for placeholders."""
    if value is None:
        return None
    key = str(value).strip().lower()
    if key in _IGNORED_NAMES:
        return None
    return key[:255]


def is_auth_log(log_type: Any, action: Any) -> bool:
    if str(log_type or "").lower() == "authentication":
        return True
    act = str(action or "").lower()
    return any(hint in act for hint in _AUTH_ACTION_HINTS)


def auth_outcome(outcome: Any, action: Any) -> Optional[str]:
    """``success`` / ``failure`` / None for an authentication entry."""
    out = str(outcome or "").strip().lower()
    if out in _FAILURE_OUTCOMES:
        return "failure"
    if out in _SUCCESS_OUTCOMES:
        return "success"
    act = str(action or "").lower()
    if "fail" in act or "denied" in act:
        return "failure"
    if "success" in act:
        return "success"
    return None


def bucket_start(event_time: Optional[datetime], received: Optional[datetime], now: datetime) -> Optional[datetime]:
    """UTC hour the row is counted in (event time, else received_at)."""
    chosen = event_time
    if chosen is None or chosen > now + timedelta(hours=1) or chosen < now - timedelta(days=BASELINE_DAYS):
        chosen = received
    if chosen is None:
        return None
    return chosen.replace(minute=0, second=0, microsecond=0)


def bucket_id(org_id: str, entity_profile_id: str, start_iso: str) -> str:
    return str(uuid.uuid5(_BUCKET_NS, f"{org_id}|{entity_profile_id}|{start_iso}"))


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(var)


def bucket_metrics(data: dict[str, Any]) -> dict[str, float]:
    """The six metric values of a stored bucket's ``event_data``."""
    counts = data.get("counts") or {}
    return {
        "events": float(counts.get("events", 0) or 0),
        "auth_successes": float(counts.get("auth_successes", 0) or 0),
        "auth_failures": float(counts.get("auth_failures", 0) or 0),
        "distinct_sources": float(len(data.get("sources") or [])),
        "distinct_peers": float(len(data.get("peers") or [])),
        "distinct_destinations": float(len(data.get("destinations") or [])),
    }


def score_bucket(current: dict[str, float], prior: list[dict[str, float]]) -> dict[str, Any]:
    """Score one bucket against earlier buckets (see module docstring, steps 4-5)."""
    n = len(prior)
    if n < MIN_BASELINE_BUCKETS:
        return {"status": "warming_up", "baseline_buckets": n, "flagged": [], "anomaly_score": 0.0}
    z_scores: dict[str, float] = {}
    stats: dict[str, dict[str, float]] = {}
    flagged: list[dict[str, Any]] = []
    for metric in METRICS:
        mean, std = mean_std([p[metric] for p in prior])
        value = current[metric]
        z = (value - mean) / max(std, STD_FLOOR)
        z_scores[metric] = round(z, 2)
        stats[metric] = {"mean": round(mean, 3), "std": round(std, 3)}
        if z >= Z_THRESHOLD and value >= MIN_ABSOLUTE[metric]:
            flagged.append({
                "metric": metric,
                "value": value,
                "baseline_mean": round(mean, 3),
                "baseline_std": round(std, 3),
                "z": round(z, 2),
            })
    max_z = max((f["z"] for f in flagged), default=0.0)
    return {
        "status": "scored",
        "baseline_buckets": n,
        "z_scores": z_scores,
        "baseline": stats,
        "flagged": flagged,
        "anomaly_score": round(min(100.0, 10.0 * max_z), 1) if flagged else 0.0,
    }


def severity_for_z(max_z: float) -> str:
    if max_z >= 6.0:
        return "high"
    if max_z >= 4.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Accumulation
# ---------------------------------------------------------------------------


@dataclass
class _Delta:
    """Counts one run folds into one (entity, hour) bucket."""

    entity_type: str
    entity_key: str
    start: datetime
    events: int = 0
    auth_successes: int = 0
    auth_failures: int = 0
    sources: set[str] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    log_ids: list[str] = field(default_factory=list)
    last_seen: Optional[datetime] = None

    def add(self, *, log_id: str, seen: datetime, outcome: Optional[str], source: Optional[str],
            peer: Optional[str], destination: Optional[str]) -> None:
        self.events += 1
        if outcome == "success":
            self.auth_successes += 1
        elif outcome == "failure":
            self.auth_failures += 1
        if source and len(self.sources) < SET_CAP:
            self.sources.add(source)
        if peer and len(self.peers) < SET_CAP:
            self.peers.add(peer)
        if destination and len(self.destinations) < SET_CAP:
            self.destinations.add(destination)
        if len(self.log_ids) < SAMPLE_LOG_IDS:
            self.log_ids.append(log_id)
        if self.last_seen is None or seen > self.last_seen:
            self.last_seen = seen


def _merge_into(existing: Optional[dict[str, Any]], delta: _Delta) -> dict[str, Any]:
    """New ``event_data`` for a bucket row: stored counts plus this run's delta."""
    data = dict(existing or {})
    counts = dict(data.get("counts") or {})
    counts["events"] = int(counts.get("events", 0) or 0) + delta.events
    counts["auth_successes"] = int(counts.get("auth_successes", 0) or 0) + delta.auth_successes
    counts["auth_failures"] = int(counts.get("auth_failures", 0) or 0) + delta.auth_failures

    def _merged(name: str, new: set[str]) -> list[str]:
        values = list(data.get(name) or [])
        seen = set(values)
        for v in sorted(new):
            if len(values) >= SET_CAP:
                break
            if v not in seen:
                values.append(v)
                seen.add(v)
        return values

    data["counts"] = counts
    data["sources"] = _merged("sources", delta.sources)
    data["peers"] = _merged("peers", delta.peers)
    data["destinations"] = _merged("destinations", delta.destinations)
    samples = list(data.get("sample_log_entry_ids") or [])
    for log_id in delta.log_ids:
        if len(samples) >= SAMPLE_LOG_IDS:
            break
        if log_id not in samples:
            samples.append(log_id)
    data["sample_log_entry_ids"] = samples
    data["bucket_start"] = delta.start.isoformat()
    data["entity_type"] = delta.entity_type
    data["source"] = CONSUMER
    return data


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


async def _cursor(db: AsyncSession, org_id: str, consumer: str = CONSUMER) -> LogIngestCursor:
    row = (await db.execute(
        select(LogIngestCursor).where(
            LogIngestCursor.organization_id == org_id,
            LogIngestCursor.consumer == consumer,
        ).limit(1),
    )).scalar_one_or_none()
    if row is None:
        row = LogIngestCursor(organization_id=org_id, consumer=consumer, rows_processed_total=0,
                              last_run_rows=0, last_run_summary={})
        db.add(row)
        await db.flush()
    return row


def log_window_query(org_id: str, last_received_at: Optional[str], last_log_id: Optional[str],
                     lower_iso: str, upper_iso: str, limit: int, columns: tuple):
    """``log_entries`` of ``org_id`` strictly after the cursor, oldest first, streamed."""
    from src.siem.models import LogEntry

    stmt = select(*columns).where(
        LogEntry.organization_id == org_id,
        LogEntry.received_at <= upper_iso,
    )
    if last_received_at:
        stmt = stmt.where(or_(
            LogEntry.received_at > last_received_at,
            and_(LogEntry.received_at == last_received_at, LogEntry.id > (last_log_id or "")),
        ))
    else:
        stmt = stmt.where(LogEntry.received_at >= lower_iso)
    return (
        stmt.order_by(LogEntry.received_at, LogEntry.id)
        .limit(limit)
        .execution_options(yield_per=BRIDGE_BATCH_SIZE)
    )


async def run_bridge_for_org(
    db: AsyncSession,
    org_id: str,
    *,
    now: Optional[datetime] = None,
    max_rows: int = MAX_LOG_ROWS_PER_RUN,
) -> dict[str, Any]:
    """Fold the organisation's new log entries into UEBA rows (one transaction).

    The caller owns the session; this function commits on success and leaves
    rollback to the caller on error.
    """
    from src.siem.models import LogEntry

    if not org_id:
        raise ValueError("run_bridge_for_org requires an organization_id")
    now = now or datetime.now(timezone.utc)
    cursor = await _cursor(db, org_id)
    cursor_id = cursor.id
    upper_iso = (now - timedelta(seconds=SETTLE_SECONDS)).isoformat()
    lower_iso = (now - timedelta(hours=INITIAL_LOOKBACK_HOURS)).isoformat()

    deltas: dict[tuple[str, str, str], _Delta] = {}
    rows = 0
    unbucketed = 0
    last_ra: Optional[str] = cursor.last_received_at
    last_id: Optional[str] = cursor.last_log_id
    capped = False

    stmt = log_window_query(
        org_id, cursor.last_received_at, cursor.last_log_id, lower_iso, upper_iso, max_rows,
        (
            LogEntry.id, LogEntry.received_at, LogEntry.timestamp, LogEntry.username,
            LogEntry.hostname, LogEntry.source_address, LogEntry.destination_address,
            LogEntry.log_type, LogEntry.action, LogEntry.outcome,
        ),
    )
    result = await db.stream(stmt)
    stop = False
    async for chunk in result.partitions(BRIDGE_BATCH_SIZE):
        for (log_id, received_at, ts, username, hostname, src, dst, log_type, action, outcome) in chunk:
            received = parse_log_time(received_at)
            start = bucket_start(parse_log_time(ts), received, now)
            user = entity_key(username)
            host = entity_key(hostname)
            keys: list[tuple[str, str, Optional[str]]] = []
            if user:
                keys.append(("user", user, host))
            if host:
                keys.append(("host", host, user))
            if start is not None and keys:
                new_keys = [
                    (etype, ekey, start.isoformat()) for etype, ekey, _ in keys
                    if (etype, ekey, start.isoformat()) not in deltas
                ]
                if len(deltas) + len(new_keys) > MAX_BUCKETS_PER_RUN:
                    capped = True
                    stop = True
                    break
                outcome_v = auth_outcome(outcome, action) if is_auth_log(log_type, action) else None
                for etype, ekey, peer in keys:
                    k = (etype, ekey, start.isoformat())
                    d = deltas.get(k)
                    if d is None:
                        d = _Delta(entity_type=etype, entity_key=ekey, start=start)
                        deltas[k] = d
                    d.add(
                        log_id=log_id, seen=received or start, outcome=outcome_v,
                        source=(str(src).strip() if src else None),
                        peer=peer,
                        destination=(str(dst).strip() if dst else None),
                    )
            elif start is None:
                unbucketed += 1
            rows += 1
            last_ra, last_id = received_at, log_id
        if stop:
            break
    await result.close()
    if rows >= max_rows:
        capped = True

    summary: dict[str, Any] = {
        "log_rows": rows,
        "unbucketed_rows": unbucketed,
        "buckets_touched": len(deltas),
        "entities_created": 0,
        "entities_touched": 0,
        "buckets_scored": 0,
        "buckets_warming_up": 0,
        "anomalous_buckets": 0,
        "alerts_created": 0,
        "capped": capped,
    }

    if deltas:
        await _write(db, org_id, deltas, now, summary)

    cursor = await db.get(LogIngestCursor, cursor_id)
    assert cursor is not None
    if rows:
        cursor.last_received_at = last_ra
        cursor.last_log_id = last_id
    cursor.rows_processed_total = int(cursor.rows_processed_total or 0) + rows
    cursor.last_run_rows = rows
    cursor.last_run_at = now
    cursor.last_run_status = "partial" if capped else ("ok" if rows else "idle")
    cursor.last_error = None
    cursor.last_run_summary = dict(summary)
    await db.commit()
    if capped:
        logger.warning(
            "ueba_siem_bridge_capped",
            organization_id=org_id, rows=rows, buckets=len(deltas),
            max_rows=max_rows, max_buckets=MAX_BUCKETS_PER_RUN,
        )
    return {"organization_id": org_id, "status": cursor.last_run_status, **summary}


async def _write(db: AsyncSession, org_id: str, deltas: dict[tuple[str, str, str], _Delta],
                 now: datetime, summary: dict[str, Any]) -> None:
    # --- entities -----------------------------------------------------------
    entity_keys = sorted({(d.entity_type, d.entity_key) for d in deltas.values()})
    profile_ids: dict[tuple[str, str], str] = {}
    for offset in range(0, len(entity_keys), WRITE_CHUNK):
        chunk = entity_keys[offset:offset + WRITE_CHUNK]
        for etype in ("user", "host"):
            names = [k for t, k in chunk if t == etype]
            if not names:
                continue
            found = (await db.execute(
                select(EntityProfile.id, EntityProfile.entity_id).where(
                    EntityProfile.organization_id == org_id,
                    EntityProfile.entity_type == etype,
                    EntityProfile.entity_id.in_(names),
                ),
            )).all()
            for pid, eid in found:
                profile_ids[(etype, eid)] = pid
            for name in names:
                if (etype, name) in profile_ids:
                    continue
                profile = EntityProfile(
                    id=str(uuid.uuid4()), entity_type=etype, entity_id=name, display_name=name,
                    risk_score=0.0, risk_level="low", baseline_data={}, current_behavior={},
                    anomaly_count_30d=0, is_watched=False, tags=[],
                    extra_metadata={"created_by": CONSUMER}, organization_id=org_id,
                )
                db.add(profile)
                profile_ids[(etype, name)] = profile.id
                summary["entities_created"] += 1
        await db.flush()
        db.expunge_all()
    summary["entities_touched"] = len(entity_keys)

    # --- buckets ------------------------------------------------------------
    by_bucket_id: dict[str, _Delta] = {}
    touched_by_entity: dict[str, dict[str, datetime]] = {}
    for d in deltas.values():
        pid = profile_ids[(d.entity_type, d.entity_key)]
        bid = bucket_id(org_id, pid, d.start.isoformat())
        by_bucket_id[bid] = d
        touched_by_entity.setdefault(pid, {})[bid] = d.start
    bucket_ids = sorted(by_bucket_id)
    for offset in range(0, len(bucket_ids), WRITE_CHUNK):
        chunk = bucket_ids[offset:offset + WRITE_CHUNK]
        existing = {
            row.id: row for row in (await db.execute(
                select(BehaviorEvent).where(
                    BehaviorEvent.id.in_(chunk), BehaviorEvent.organization_id == org_id,
                ),
            )).scalars().all()
        }
        for bid in chunk:
            d = by_bucket_id[bid]
            pid = profile_ids[(d.entity_type, d.entity_key)]
            row = existing.get(bid)
            if row is None:
                row = BehaviorEvent(
                    id=bid, entity_profile_id=pid, event_type=EVENT_TYPE, event_data={},
                    risk_contribution=0.0, is_anomalous=False, anomaly_reasons=[],
                    organization_id=org_id, created_at=d.start, updated_at=now,
                )
                db.add(row)
            row.event_data = _merge_into(row.event_data, d)
            row.updated_at = now
        await db.flush()
        db.expunge_all()

    # --- profiles, baselines, scores, alerts --------------------------------
    pids = sorted(touched_by_entity)
    for offset in range(0, len(pids), WRITE_CHUNK):
        for pid in pids[offset:offset + WRITE_CHUNK]:
            await _evaluate_entity(db, org_id, pid, touched_by_entity[pid], now, summary)
        await db.flush()
        db.expunge_all()


async def _evaluate_entity(db: AsyncSession, org_id: str, pid: str, touched: dict[str, datetime],
                           now: datetime, summary: dict[str, Any]) -> None:
    """Score the entity's touched buckets, refresh its baseline and profile."""
    entity = await db.get(EntityProfile, pid)
    if entity is None or entity.organization_id != org_id:
        return
    earliest = min(touched.values(), default=now)
    window_start = earliest - timedelta(days=BASELINE_DAYS)
    rows = (await db.execute(
        select(BehaviorEvent.id, BehaviorEvent.event_data)
        .where(
            BehaviorEvent.entity_profile_id == pid,
            BehaviorEvent.organization_id == org_id,
            BehaviorEvent.event_type == EVENT_TYPE,
            BehaviorEvent.created_at >= window_start,
        )
        .order_by(desc(BehaviorEvent.created_at))
        .limit(MAX_BASELINE_BUCKETS + len(touched)),
    )).all()
    buckets = sorted(
        ((str((data or {}).get("bucket_start") or ""), bid, data or {}) for bid, data in rows),
        key=lambda b: b[0],
    )

    latest_metrics: Optional[dict[str, float]] = None
    latest_start = ""
    for start_iso, bid, data in buckets:
        if bid not in touched:
            continue
        start = parse_log_time(start_iso)
        if start is None:
            continue
        lower = (start - timedelta(days=BASELINE_DAYS)).isoformat()
        prior = [bucket_metrics(pd) for ps, _pb, pd in buckets if lower <= ps < start_iso][-MAX_BASELINE_BUCKETS:]
        current = bucket_metrics(data)
        evaluation = score_bucket(current, prior)
        row = await db.get(BehaviorEvent, bid)
        if row is None:
            continue
        new_data = dict(row.event_data or {})
        new_data["evaluation"] = evaluation
        if evaluation["status"] == "warming_up":
            summary["buckets_warming_up"] += 1
        else:
            summary["buckets_scored"] += 1
        flagged = evaluation["flagged"]
        row.is_anomalous = bool(flagged) or bool(row.is_anomalous)
        if flagged:
            summary["anomalous_buckets"] += 1
            row.anomaly_reasons = [
                f"{f['metric']}_spike:value={f['value']:g},mean={f['baseline_mean']:g},z={f['z']:g}"
                for f in flagged
            ]
            if not new_data.get("alert_id"):
                alert = _alert_for(org_id, entity, row.id, start_iso, evaluation, data)
                db.add(alert)
                new_data["alert_id"] = alert.id
                row.risk_contribution = alert.risk_score_delta
                entity.risk_score = min(100.0, float(entity.risk_score or 0.0) + alert.risk_score_delta)
                entity.risk_level = risk_level_for_score(entity.risk_score)
                entity.anomaly_count_30d = int(entity.anomaly_count_30d or 0) + 1
                entity.last_anomaly_at = naive_utc(now)
                summary["alerts_created"] += 1
        row.event_data = new_data
        if start_iso >= latest_start:
            latest_start, latest_metrics = start_iso, current

    # Latest baseline over the window ending now (persisted for the API).
    recent_lower = (now - timedelta(days=BASELINE_DAYS)).isoformat()
    window = [(s, d) for s, _b, d in buckets if s >= recent_lower][-MAX_BASELINE_BUCKETS:]
    await _upsert_baseline(db, pid, window, now)

    if latest_metrics is not None:
        entity.current_behavior = {
            "bucket_start": latest_start,
            **{m: latest_metrics[m] for m in METRICS},
            "source": CONSUMER,
        }
        seen = parse_log_time(latest_start)
        last_activity = entity.last_activity_at
        if last_activity is not None and last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)
        if seen is not None and (last_activity is None or seen > last_activity):
            entity.last_activity_at = naive_utc(seen)


async def _upsert_baseline(db: AsyncSession, pid: str,
                           window: list[tuple[str, dict[str, Any]]], now: datetime) -> None:
    n = len(window)
    if n == 0:
        return
    model: dict[str, Any] = {}
    for metric in METRICS:
        mean, std = mean_std([bucket_metrics(d)[metric] for _s, d in window])
        model[metric] = {"mean": round(mean, 3), "std": round(std, 3), "n": n}
    source_freq: dict[str, int] = {}
    hour_counts: dict[str, int] = {}
    for start_iso, data in window:
        for src in data.get("sources") or []:
            source_freq[src] = source_freq.get(src, 0) + 1
        start = parse_log_time(start_iso)
        if start is not None:
            hour_counts[str(start.hour)] = hour_counts.get(str(start.hour), 0) + 1
    typical = [s for s, _c in sorted(source_freq.items(), key=lambda kv: (-kv[1], kv[0]))][:TYPICAL_SOURCES_KEPT]
    row = (await db.execute(
        select(BehaviorBaseline).where(
            BehaviorBaseline.entity_profile_id == pid,
            BehaviorBaseline.behavior_type == EVENT_TYPE,
        ).limit(1),
    )).scalar_one_or_none()
    if row is None:
        row = BehaviorBaseline(id=str(uuid.uuid4()), entity_profile_id=pid, behavior_type=EVENT_TYPE)
        db.add(row)
    row.baseline_period_days = BASELINE_DAYS
    row.statistical_model = {"method": "per-active-hour mean / population std", "metrics": model}
    row.typical_values = typical
    row.time_patterns = {
        "hours": sorted(int(h) for h in hour_counts),
        "hour_counts": hour_counts,
    }
    row.peer_comparison = {}
    row.confidence = round(min(1.0, n / FULL_CONFIDENCE_BUCKETS), 3)
    row.sample_count = n
    row.last_updated_at = naive_utc(now)


def _alert_for(org_id: str, entity: EntityProfile, bucket_row_id: str, start_iso: str,
               evaluation: dict[str, Any], data: dict[str, Any]) -> UEBARiskAlert:
    flagged = sorted(evaluation["flagged"], key=lambda f: -f["z"])
    top = flagged[0]
    severity = severity_for_z(top["z"])
    alert_type = "auth_failure_spike" if top["metric"] == "auth_failures" else "activity_spike"
    parts = ", ".join(
        f"{f['metric']} {f['value']:g} vs mean {f['baseline_mean']:g} (z={f['z']:g})" for f in flagged
    )
    description = (
        f"{entity.entity_type} {entity.entity_id}: hour starting {start_iso} deviates from its "
        f"{evaluation['baseline_buckets']}-hour baseline: {parts}. "
        f"Anomaly score {evaluation['anomaly_score']:g}."
    )
    evidence = [
        {**f, "baseline_buckets": evaluation["baseline_buckets"], "bucket_start": start_iso}
        for f in flagged
    ]
    evidence.append({
        "sample_log_entry_ids": list(data.get("sample_log_entry_ids") or []),
        "anomaly_score": evaluation["anomaly_score"],
    })
    return UEBARiskAlert(
        id=str(uuid.uuid4()),
        entity_profile_id=entity.id,
        alert_type=alert_type,
        severity=severity,
        risk_score_delta=float(_scorer.SEVERITY_WEIGHTS.get(severity, 5)),
        description=description[:4000],
        evidence=evidence,
        contributing_events=[bucket_row_id],
        mitre_techniques=["T1110"] if alert_type == "auth_failure_spike" else [],
        status="new",
        organization_id=org_id,
    )


async def record_failure(org_id: str, error: str, consumer: str = CONSUMER) -> None:
    """Mark the organisation's cursor failed (separate session, cursor unchanged)."""
    from src.core.database import async_session_factory

    async with async_session_factory() as db:
        cursor = await _cursor(db, org_id, consumer)
        cursor.last_run_at = datetime.now(timezone.utc)
        cursor.last_run_status = "failed"
        cursor.last_run_rows = 0
        cursor.last_error = error[:2000]
        await db.commit()


async def cursor_status(db: AsyncSession, org_id: str, consumer: str = CONSUMER) -> dict[str, Any]:
    """Read-only view of a consumer's cursor for the API (no row is created)."""
    row = (await db.execute(
        select(LogIngestCursor).where(
            LogIngestCursor.organization_id == org_id,
            LogIngestCursor.consumer == consumer,
        ).limit(1),
    )).scalar_one_or_none()
    if row is None:
        return {
            "consumer": consumer, "status": "never_run", "last_run_at": None,
            "last_received_at": None, "rows_processed_total": 0, "last_run_rows": 0,
            "last_error": None, "last_run_summary": {},
        }
    return {
        "consumer": consumer,
        "status": row.last_run_status or "never_run",
        "last_run_at": row.last_run_at,
        "last_received_at": row.last_received_at,
        "rows_processed_total": int(row.rows_processed_total or 0),
        "last_run_rows": int(row.last_run_rows or 0),
        "last_error": row.last_error,
        "last_run_summary": dict(row.last_run_summary or {}),
    }
