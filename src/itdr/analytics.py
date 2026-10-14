"""ITDR analytics from stored authentication events and credential leaks.

Auth-event analysis (``analyze_auth_events_for_org``)
----------------------------------------------------
Walks the organisation's stored SIEM ``log_entries`` from its
``LogIngestCursor`` (consumer ``itdr_auth``) with the same windowed reader
as the UEBA bridge (``src.ueba.siem_bridge.log_window_query``: oldest first,
streamed, at most ``MAX_AUTH_ROWS_PER_RUN`` rows; the remainder waits for the
next run). Authentication entries are the ones the UEBA bridge counts as
such (``log_type == "authentication"`` or a login/logon/auth action) with a
success / failure outcome; the entry's ``username`` is matched
case-insensitively to an identity's username or email in the same
organisation. Unmatched names are counted, never invented as identities.

For every matched identity the run keeps:

* ``auth_baseline`` on the identity: counts of successful sign-ins per UTC
  hour of day (``hour_counts``) and per source address (``source_counts``,
  the ``MAX_BASELINE_SOURCES`` most frequent kept), ``success_total`` and
  failures per day (``failure_days``, last 30 days).
* ``last_authentication``: newest successful sign-in time.

Access anomalies (``AccessAnomaly`` rows) are raised only once the identity
has ``MIN_BASELINE_LOGINS`` successful sign-ins in its baseline, and are
judged against the baseline as it was *before* the sign-in is added:

* ``unusual_location``: a sign-in from a source address absent from
  ``source_counts``. ``deviation_score = 100 * (1 - p / p_max)`` where
  ``p = (count + 1) / (total + n_sources + 1)`` is the add-one smoothed
  share of that address and ``p_max`` the share of the most used address.
* ``unusual_time``: a sign-in in an hour of day holding less than
  ``RARE_HOUR_SHARE`` of the baseline sign-ins; same deviation formula over
  the 24 hour buckets.
* ``dormant_activation``: a successful sign-in by an identity marked dormant
  (no sign-in for 90 days per its directory); the flag is then cleared.

One anomaly per (identity, type, address or hour) per run.

Identity threats (``IdentityThreat``, deduplicated against open threats of
the same type for the same identity / source address):

* ``brute_force`` (T1110.001): at least ``BRUTE_FORCE_FAILURES`` failures for
  one identity inside one clock hour.
* ``password_spray`` (T1110.003): one source address failing against at least
  ``SPRAY_DISTINCT_IDENTITIES`` distinct names inside one clock hour.

``confidence_score`` is on the 0-100 scale: for brute force
``min(100, 50 + 2 * (failures - threshold))``, for spray
``min(100, 50 + 5 * (names - threshold))``.

Identity risk (``recompute_identity_risk``) uses the weights of
``GET /itdr/identities/{id}/risk-score`` over *open* findings only:
``min(40, 15 * open critical threats + 5 * other open threats)`` +
``min(30, 3 * unreviewed anomalies)`` + ``min(30, 5 * unremediated
exposures)``.

Credential monitoring (``check_credential_exposures_for_org``) matches the
organisation's own unremediated dark-web credential leak rows
(``darkweb_credential_leaks``) to identities by email or username and creates
one ``CredentialExposure`` per (identity, breach) not already tracked.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.itdr.models import (
    AccessAnomaly,
    AnomalyType,
    CredentialExposure,
    IdentityProfile,
    IdentityThreat,
    ThreatStatus,
)
from src.ueba.models import LogIngestCursor
from src.ueba.siem_bridge import (
    BRIDGE_BATCH_SIZE,
    INITIAL_LOOKBACK_HOURS,
    SETTLE_SECONDS,
    _cursor,
    auth_outcome,
    entity_key,
    is_auth_log,
    log_window_query,
    parse_log_time,
)

logger = get_logger(__name__)

CONSUMER = "itdr_auth"
MAX_AUTH_ROWS_PER_RUN = 50_000
#: Distinct names one run resolves to identities (and keeps per-name state for).
MAX_NAMES_PER_RUN = 20_000
MIN_BASELINE_LOGINS = 20
MAX_BASELINE_SOURCES = 200
RARE_HOUR_SHARE = 0.02
BRUTE_FORCE_FAILURES = 10
SPRAY_DISTINCT_IDENTITIES = 5
SPRAY_NAMES_KEPT = 50
FAILURE_DAYS_KEPT = 30
OPEN_THREAT_STATES = (ThreatStatus.DETECTED.value, ThreatStatus.INVESTIGATING.value, ThreatStatus.CONFIRMED.value)

LEAK_BATCH = 1_000
MAX_LEAKS_PER_RUN = 50_000


def smoothed_deviation(counts: dict[str, int], key: str, buckets: int) -> float:
    """``100 * (1 - p / p_max)`` with add-one smoothing (see module docstring)."""
    total = sum(counts.values())
    denom = total + buckets
    p = (counts.get(key, 0) + 1) / denom
    p_max = (max(counts.values(), default=0) + 1) / denom
    return round(max(0.0, 100.0 * (1.0 - p / p_max)), 1)


@dataclass
class _IdentityRun:
    successes: list[tuple[datetime, Optional[str], str]] = field(default_factory=list)  # (time, source, log id)
    failures_by_hour: dict[str, int] = field(default_factory=dict)
    failure_sources: dict[str, set[str]] = field(default_factory=dict)
    failures_by_day: dict[str, int] = field(default_factory=dict)
    sample_log_ids: list[str] = field(default_factory=list)


async def _resolve_names(db: AsyncSession, org_id: str, names: list[str]) -> dict[str, str]:
    """name (lower-case) -> identity id, for usernames and emails of ``org_id``."""
    out: dict[str, str] = {}
    for offset in range(0, len(names), 500):
        chunk = names[offset:offset + 500]
        rows = (await db.execute(
            select(IdentityProfile.id, IdentityProfile.username, IdentityProfile.email).where(
                IdentityProfile.organization_id == org_id,
                or_(func.lower(IdentityProfile.username).in_(chunk), func.lower(IdentityProfile.email).in_(chunk)),
            ),
        )).all()
        wanted = set(chunk)
        for iid, username, email in rows:
            for value in ((username or "").lower(), (email or "").lower()):
                if value in wanted:
                    out.setdefault(value, iid)
    return out


async def analyze_auth_events_for_org(db: AsyncSession, org_id: str, *, now: Optional[datetime] = None,
                                      max_rows: int = MAX_AUTH_ROWS_PER_RUN) -> dict[str, Any]:
    """Fold the organisation's new authentication log entries into ITDR rows (one transaction)."""
    from src.siem.models import LogEntry

    if not org_id:
        raise ValueError("analyze_auth_events_for_org requires an organization_id")
    now = now or datetime.now(timezone.utc)
    cursor = await _cursor(db, org_id, CONSUMER)
    cursor_id = cursor.id
    upper_iso = (now - timedelta(seconds=SETTLE_SECONDS)).isoformat()
    lower_iso = (now - timedelta(hours=INITIAL_LOOKBACK_HOURS)).isoformat()
    stmt = log_window_query(
        org_id, cursor.last_received_at, cursor.last_log_id, lower_iso, upper_iso, max_rows,
        (LogEntry.id, LogEntry.received_at, LogEntry.timestamp, LogEntry.username,
         LogEntry.source_address, LogEntry.log_type, LogEntry.action, LogEntry.outcome),
    )

    per_name: dict[str, _IdentityRun] = {}
    spray: dict[tuple[str, str], set[str]] = {}  # (source, hour) -> names
    rows = auth_rows = 0
    names_capped = False
    last_ra, last_id = cursor.last_received_at, cursor.last_log_id
    result = await db.stream(stmt)
    stop = False
    async for chunk in result.partitions(BRIDGE_BATCH_SIZE):
        for log_id, received_at, ts, username, source, log_type, action, outcome in chunk:
            name = entity_key(username)
            verdict = auth_outcome(outcome, action) if is_auth_log(log_type, action) else None
            if name and verdict:
                if name not in per_name and len(per_name) >= MAX_NAMES_PER_RUN:
                    names_capped = True
                    stop = True
                    break
                when = parse_log_time(ts) or parse_log_time(received_at) or now
                if when > now + timedelta(hours=1):
                    when = parse_log_time(received_at) or now
                src = str(source).strip() if source else None
                run = per_name.setdefault(name, _IdentityRun())
                hour = when.replace(minute=0, second=0, microsecond=0).isoformat()
                if verdict == "success":
                    run.successes.append((when, src, log_id))
                else:
                    run.failures_by_hour[hour] = run.failures_by_hour.get(hour, 0) + 1
                    run.failures_by_day[hour[:10]] = run.failures_by_day.get(hour[:10], 0) + 1
                    if src:
                        run.failure_sources.setdefault(hour, set()).add(src)
                        names = spray.setdefault((src, hour), set())
                        if len(names) < SPRAY_NAMES_KEPT:
                            names.add(name)
                if len(run.sample_log_ids) < 20:
                    run.sample_log_ids.append(log_id)
                auth_rows += 1
            rows += 1
            last_ra, last_id = received_at, log_id
        if stop:
            break
    await result.close()
    capped = names_capped or rows >= max_rows

    summary: dict[str, Any] = {
        "log_rows": rows, "auth_rows": auth_rows, "names_seen": len(per_name), "identities_matched": 0,
        "unmatched_names": 0, "anomalies_created": 0, "threats_created": 0, "capped": capped,
    }
    fired: list[tuple[str, str, str, str]] = []
    touched: set[str] = set()
    if per_name:
        id_by_name = await _resolve_names(db, org_id, sorted(per_name))
        summary["unmatched_names"] = sum(1 for n in per_name if n not in id_by_name)
        by_identity: dict[str, list[str]] = {}
        for name, iid in id_by_name.items():
            by_identity.setdefault(iid, []).append(name)
        summary["identities_matched"] = len(by_identity)
        open_threats = await _open_threat_keys(db, org_id)
        for iid in sorted(by_identity):
            identity = await db.get(IdentityProfile, iid)
            if identity is None or identity.organization_id != org_id:
                continue
            merged = _IdentityRun()
            for name in by_identity[iid]:
                part = per_name[name]
                merged.successes.extend(part.successes)
                for k, v in part.failures_by_hour.items():
                    merged.failures_by_hour[k] = merged.failures_by_hour.get(k, 0) + v
                for k, v in part.failures_by_day.items():
                    merged.failures_by_day[k] = merged.failures_by_day.get(k, 0) + v
                for k, v in part.failure_sources.items():
                    merged.failure_sources.setdefault(k, set()).update(v)
                merged.sample_log_ids.extend(part.sample_log_ids)
            _fold_identity(db, org_id, identity, merged, now, summary, open_threats, fired)
            touched.add(iid)
        await db.flush()
        _spray_threats(db, org_id, spray, open_threats, summary, fired)
        await db.flush()
        await recompute_identity_risk(db, org_id, sorted(touched))

    cursor = await db.get(LogIngestCursor, cursor_id)
    assert cursor is not None
    if rows:
        cursor.last_received_at, cursor.last_log_id = last_ra, last_id
    cursor.rows_processed_total = int(cursor.rows_processed_total or 0) + rows
    cursor.last_run_rows = rows
    cursor.last_run_at = now
    cursor.last_run_status = "partial" if capped else ("ok" if rows else "idle")
    cursor.last_error = None
    cursor.last_run_summary = dict(summary)
    await db.commit()
    await _fire_automation(db, org_id, fired)
    return {"organization_id": org_id, "status": cursor.last_run_status, **summary}


async def _open_threat_keys(db: AsyncSession, org_id: str) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    result = await db.stream(
        select(IdentityThreat.identity_id, IdentityThreat.threat_type, IdentityThreat.source_ip)
        .where(IdentityThreat.organization_id == org_id, IdentityThreat.status.in_(OPEN_THREAT_STATES))
        .execution_options(yield_per=BRIDGE_BATCH_SIZE),
    )
    async for chunk in result.partitions(BRIDGE_BATCH_SIZE):
        for identity_id, threat_type, source_ip in chunk:
            keys.add((f"id:{identity_id}" if identity_id else f"ip:{source_ip}", threat_type))
    await result.close()
    return keys


def _fold_identity(db: AsyncSession, org_id: str, identity: IdentityProfile, run: _IdentityRun, now: datetime,
                   summary: dict[str, Any], open_threats: set[tuple[str, str]],
                   fired: list[tuple[str, str, str, str]]) -> None:
    base = dict(identity.auth_baseline or {})
    hour_counts: dict[str, int] = {str(k): int(v) for k, v in (base.get("hour_counts") or {}).items()}
    source_counts: dict[str, int] = {str(k): int(v) for k, v in (base.get("source_counts") or {}).items()}
    failure_days: dict[str, int] = {str(k): int(v) for k, v in (base.get("failure_days") or {}).items()}
    success_total = int(base.get("success_total") or 0)
    raised: set[tuple[str, str]] = set()

    def anomaly(kind: str, key: str, deviation: float, observed: dict[str, Any], baseline: dict[str, Any]) -> None:
        if (kind, key) in raised:
            return
        raised.add((kind, key))
        db.add(AccessAnomaly(
            id=str(uuid.uuid4()), organization_id=org_id, identity_id=identity.id, anomaly_type=kind,
            baseline_data=baseline, observed_data=observed, deviation_score=deviation, is_reviewed=False,
        ))
        summary["anomalies_created"] += 1

    newest: Optional[datetime] = None
    for when, src, log_id in sorted(run.successes, key=lambda s: s[0]):
        hour = str(when.hour)
        if identity.is_dormant:
            anomaly(AnomalyType.DORMANT_ACTIVATION.value, "dormant", 100.0,
                    {"signed_in_at": when.isoformat(), "source_address": src, "log_entry_id": log_id},
                    {"last_authentication": identity.last_authentication, "dormant_after_days": 90})
            identity.is_dormant = False
        if success_total >= MIN_BASELINE_LOGINS:
            if src and src not in source_counts:
                anomaly(AnomalyType.UNUSUAL_LOCATION.value, f"src:{src}",
                        smoothed_deviation(source_counts, src, len(source_counts) + 1),
                        {"source_address": src, "signed_in_at": when.isoformat(), "log_entry_id": log_id},
                        {"baseline_logins": success_total, "known_sources": len(source_counts),
                         "top_sources": sorted(source_counts, key=lambda s: -source_counts[s])[:10]})
            share = hour_counts.get(hour, 0) / max(success_total, 1)
            if share < RARE_HOUR_SHARE:
                anomaly(AnomalyType.UNUSUAL_TIME.value, f"hour:{hour}",
                        smoothed_deviation(hour_counts, hour, 24),
                        {"hour_utc": int(hour), "signed_in_at": when.isoformat(), "log_entry_id": log_id},
                        {"baseline_logins": success_total, "share_of_logins_this_hour": round(share, 4),
                         "hour_counts": hour_counts})
        hour_counts[hour] = hour_counts.get(hour, 0) + 1
        if src:
            source_counts[src] = source_counts.get(src, 0) + 1
        success_total += 1
        newest = when if newest is None or when > newest else newest

    for day, n in run.failures_by_day.items():
        failure_days[day] = failure_days.get(day, 0) + n
    cutoff_day = (now - timedelta(days=FAILURE_DAYS_KEPT)).date().isoformat()
    failure_days = {d: n for d, n in failure_days.items() if d >= cutoff_day}
    if len(source_counts) > MAX_BASELINE_SOURCES:
        source_counts = dict(sorted(source_counts.items(), key=lambda kv: -kv[1])[:MAX_BASELINE_SOURCES])

    identity.auth_baseline = {
        "hour_counts": hour_counts, "source_counts": source_counts, "success_total": success_total,
        "failure_days": failure_days, "updated_at": now.isoformat(),
        "method": "counts of successful sign-ins per UTC hour and source address (src/itdr/analytics.py)",
    }
    if newest is not None:
        newest_iso = newest.isoformat()
        if not identity.last_authentication or identity.last_authentication < newest_iso:
            identity.last_authentication = newest_iso

    worst_hour, worst = max(run.failures_by_hour.items(), key=lambda kv: kv[1], default=(None, 0))
    key = (f"id:{identity.id}", "brute_force")
    if worst_hour and worst >= BRUTE_FORCE_FAILURES and key not in open_threats:
        open_threats.add(key)
        sources = sorted(run.failure_sources.get(worst_hour, set()))
        severity = "high" if worst >= 3 * BRUTE_FORCE_FAILURES else "medium"
        db.add(IdentityThreat(
            id=str(uuid.uuid4()), organization_id=org_id, identity_id=identity.id, threat_type="brute_force",
            severity=severity,
            confidence_score=float(min(100, 50 + 2 * (worst - BRUTE_FORCE_FAILURES))),
            source_ip=sources[0] if len(sources) == 1 else None, mitre_technique_id="T1110.001",
            evidence={"failures_in_hour": worst, "hour_start": worst_hour, "source_addresses": sources[:20],
                      "threshold": BRUTE_FORCE_FAILURES, "sample_log_entry_ids": run.sample_log_ids[:20]},
            status=ThreatStatus.DETECTED.value,
        ))
        summary["threats_created"] += 1
        fired.append(("brute_force", identity.username, severity,
                      f"{worst} failed sign-ins in the hour starting {worst_hour}"))


def _spray_threats(db: AsyncSession, org_id: str, spray: dict[tuple[str, str], set[str]],
                   open_threats: set[tuple[str, str]], summary: dict[str, Any],
                   fired: list[tuple[str, str, str, str]]) -> None:
    for (src, hour), names in sorted(spray.items()):
        if len(names) < SPRAY_DISTINCT_IDENTITIES:
            continue
        key = (f"ip:{src}", "password_spray")
        if key in open_threats:
            continue
        open_threats.add(key)
        db.add(IdentityThreat(
            id=str(uuid.uuid4()), organization_id=org_id, identity_id=None, threat_type="password_spray",
            severity="high", confidence_score=float(min(100, 50 + 5 * (len(names) - SPRAY_DISTINCT_IDENTITIES))),
            source_ip=src[:45], mitre_technique_id="T1110.003",
            evidence={"source_address": src, "hour_start": hour, "distinct_names": len(names),
                      "names": sorted(names), "threshold": SPRAY_DISTINCT_IDENTITIES},
            status=ThreatStatus.DETECTED.value,
        ))
        summary["threats_created"] += 1
        fired.append(("password_spray", src, "high", f"{len(names)} accounts failed from {src} in one hour"))


async def _fire_automation(db: AsyncSession, org_id: str, fired: list[tuple[str, str, str, str]]) -> None:
    if not fired:
        return
    from src.services.automation import AutomationService

    automation = AutomationService(db)
    for threat_type, who, severity, details in fired:
        try:
            await automation.on_itdr_threat(
                threat_type=threat_type, identity=who, risk_level=severity, details=details, organization_id=org_id,
            )
        except Exception as exc:
            logger.warning("itdr_threat_automation_failed", organization_id=org_id, threat_type=threat_type, error=str(exc))
    await db.commit()


async def recompute_identity_risk(db: AsyncSession, org_id: str, identity_ids: list[str]) -> int:
    """Persist ``risk_score`` for the given identities from their open findings (see module docstring)."""
    updated = 0
    for offset in range(0, len(identity_ids), 500):
        chunk = identity_ids[offset:offset + 500]
        if not chunk:
            continue
        threats = (await db.execute(
            select(IdentityThreat.identity_id, IdentityThreat.severity, func.count())
            .where(IdentityThreat.organization_id == org_id, IdentityThreat.identity_id.in_(chunk),
                   IdentityThreat.status.in_(OPEN_THREAT_STATES))
            .group_by(IdentityThreat.identity_id, IdentityThreat.severity),
        )).all()
        anomalies = dict((await db.execute(
            select(AccessAnomaly.identity_id, func.count())
            .where(AccessAnomaly.organization_id == org_id, AccessAnomaly.identity_id.in_(chunk),
                   AccessAnomaly.is_reviewed.is_(False))
            .group_by(AccessAnomaly.identity_id),
        )).all())
        exposures = dict((await db.execute(
            select(CredentialExposure.identity_id, func.count())
            .where(CredentialExposure.organization_id == org_id, CredentialExposure.identity_id.in_(chunk),
                   CredentialExposure.is_remediated.is_(False))
            .group_by(CredentialExposure.identity_id),
        )).all())
        crit: dict[str, int] = {}
        other: dict[str, int] = {}
        for iid, severity, n in threats:
            target = crit if severity == "critical" else other
            target[iid] = target.get(iid, 0) + int(n)
        for identity in (await db.execute(
            select(IdentityProfile).where(IdentityProfile.organization_id == org_id, IdentityProfile.id.in_(chunk)),
        )).scalars().all():
            score = (
                min(40.0, 15.0 * crit.get(identity.id, 0) + 5.0 * other.get(identity.id, 0))
                + min(30.0, 3.0 * int(anomalies.get(identity.id, 0)))
                + min(30.0, 5.0 * int(exposures.get(identity.id, 0)))
            )
            identity.risk_score = round(score, 1)
            updated += 1
        await db.flush()
    return updated


async def check_credential_exposures_for_org(db: AsyncSession, org_id: str) -> dict[str, Any]:
    """Create ``CredentialExposure`` rows for identities named in the org's leak records (one transaction)."""
    from src.darkweb.models import CredentialLeak

    now_iso = datetime.now(timezone.utc).isoformat()
    last_id: Optional[str] = None
    leaks_read = created = 0
    touched: set[str] = set()
    while leaks_read < MAX_LEAKS_PER_RUN:
        stmt = (
            select(CredentialLeak.id, CredentialLeak.email, CredentialLeak.username, CredentialLeak.breach_source,
                   CredentialLeak.breach_date, CredentialLeak.password_type)
            .where(CredentialLeak.organization_id == org_id, CredentialLeak.is_remediated.is_(False))
            .order_by(CredentialLeak.id)
            .limit(LEAK_BATCH)
        )
        if last_id is not None:
            stmt = stmt.where(CredentialLeak.id > last_id)
        leaks = (await db.execute(stmt)).all()
        if not leaks:
            break
        last_id = leaks[-1][0]
        leaks_read += len(leaks)
        names = sorted({str(v).lower() for row in leaks for v in (row[1], row[2]) if v})
        id_by_name = await _resolve_names(db, org_id, names)
        if id_by_name:
            ids = sorted(set(id_by_name.values()))
            existing = {
                (iid, breach or "")
                for iid, breach in (await db.execute(
                    select(CredentialExposure.identity_id, CredentialExposure.breach_name).where(
                        CredentialExposure.organization_id == org_id,
                        CredentialExposure.identity_id.in_(ids),
                        CredentialExposure.exposure_source == "darkweb",
                    ),
                )).all()
            }
            for _lid, email, username, breach, breach_date, pw_type in leaks:
                iid = id_by_name.get(str(email or "").lower()) or id_by_name.get(str(username or "").lower())
                if not iid or (iid, breach or "") in existing:
                    continue
                existing.add((iid, breach or ""))
                db.add(CredentialExposure(
                    organization_id=org_id, identity_id=iid, exposure_source="darkweb",
                    credential_type=pw_type or "password", exposure_date=breach_date, discovery_date=now_iso,
                    breach_name=breach, is_remediated=False,
                ))
                created += 1
                touched.add(iid)
            await db.flush()
        if len(leaks) < LEAK_BATCH:
            break
    await recompute_identity_risk(db, org_id, sorted(touched))
    await db.commit()
    return {
        "organization_id": org_id, "leaks_checked": leaks_read, "exposures_created": created,
        "identities_affected": len(touched), "capped": leaks_read >= MAX_LEAKS_PER_RUN,
    }
