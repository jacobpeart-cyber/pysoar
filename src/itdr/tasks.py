"""
Celery Tasks for ITDR (Identity Threat Detection & Response)

Background tasks for identity threat scanning, directory sync (Okta / Entra
ID, src/itdr/directory.py), authentication-event analysis and credential
monitoring (src/itdr/analytics.py), privileged access auditing and dormant
account detection. Every task reads and writes ``IdentityProfile`` and its
child rows of one organisation at a time; the beat sweeps loop over
organisations with a fresh session per organisation.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import select, func, and_

from src.core.logging import get_logger

logger = get_logger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# --- Memory bounds (prod OOM post-mortem 2026-09-01) -----------------------
# Rows pulled per round-trip when streaming the open-threat dedupe set.
ITDR_BATCH_SIZE = 1_000

# Per-org ceiling on identities scanned in one pass. The sweep runs hourly
# and the scan is idempotent (it skips identity/threat-type pairs that
# already have an open threat), so a cap defers work rather than losing it.
MAX_IDENTITIES_PER_SCAN = 50_000


def _fresh_itdr_session_factory():
    """Per-task NullPool engine, same pattern as src.agentic.tasks.
    Avoids 'Future attached to a different loop' errors from the
    shared module-level engine when Celery prefork workers re-enter
    asyncio.run per task."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker as _sm
    from sqlalchemy.pool import NullPool
    from src.core.config import settings as _settings
    e = create_async_engine(_settings.database_url, echo=False, poolclass=NullPool)
    return e, _sm(e, class_=AsyncSession, expire_on_commit=False)


async def _run_identity_scan_for_org(session, organization_id: str) -> dict:
    """Run the real identity-threat detection heuristics against the
    IdentityProfile table for one organization. Matches the logic in
    POST /itdr/threats/scan but callable from any context (Celery
    task, cross-org sweep, background job).
    Creates IdentityThreat rows for: dormant_admin, mfa_missing_privileged,
    stale_credential (>180 days).
    Returns counts + list of created threats.
    """
    import json as _json
    from src.itdr.models import IdentityProfile, IdentityThreat, ThreatStatus

    now = datetime.now(timezone.utc)
    cutoff_180d = now - timedelta(days=180)

    # Only the two columns the dedupe needs, streamed in fixed windows: the
    # old `select(IdentityThreat)` kept every open threat for the org as a
    # full ORM row (evidence JSON included) for the whole scan, and the
    # cross-org sweep shared one session so they accumulated across orgs too
    # (prod OOM post-mortem 2026-09-01).
    open_by_identity: dict[str, set[str]] = {}
    existing_result = await session.stream(
        select(IdentityThreat.identity_id, IdentityThreat.threat_type)
        .where(
            IdentityThreat.organization_id == organization_id,
            IdentityThreat.status.in_([
                ThreatStatus.DETECTED.value,
                ThreatStatus.INVESTIGATING.value,
            ]),
        )
        .execution_options(yield_per=ITDR_BATCH_SIZE)
    )
    async for chunk in existing_result.partitions(ITDR_BATCH_SIZE):
        for identity_id, threat_type in chunk:
            open_by_identity.setdefault(identity_id, set()).add(threat_type)

    identities_stmt = (
        select(IdentityProfile)
        .where(IdentityProfile.organization_id == organization_id)
        .order_by(IdentityProfile.id)
        .limit(MAX_IDENTITIES_PER_SCAN)
    )

    created = 0
    identities_scanned = 0
    fired: list[tuple[str, str, str, str]] = []

    def _parse_iso(ts):
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _make_threat(identity_id: str, threat_type: str, severity: str, evidence: dict) -> bool:
        if threat_type in open_by_identity.get(identity_id, set()):
            return False
        session.add(IdentityThreat(
            organization_id=organization_id,
            identity_id=identity_id,
            threat_type=threat_type,
            severity=severity,
            confidence_score=90.0,  # 0-100 scale (schemas/itdr.py)
            evidence=evidence,
            status=ThreatStatus.DETECTED.value,
        ))
        return True

    identities = list(await session.scalars(identities_stmt))
    identities_scanned = len(identities)
    if identities_scanned >= MAX_IDENTITIES_PER_SCAN:
        logger.warning(
            "identity scan capped at %d identities for org %s — remainder "
            "deferred to the next run",
            MAX_IDENTITIES_PER_SCAN,
            organization_id,
        )

    for identity in identities:
        roles = getattr(identity, "role_assignments", None) or []
        if isinstance(roles, str):
            try:
                roles = _json.loads(roles)
            except Exception:  # noqa: BLE001
                roles = []
        roles_lower = [str(r).lower() for r in roles] if isinstance(roles, list) else []
        has_admin = any(("admin" in r or "root" in r) for r in roles_lower)
        priv = (getattr(identity, "privilege_level", "") or "").lower()
        is_priv = has_admin or priv in ("admin", "privileged", "root", "super")

        if getattr(identity, "is_dormant", False) and has_admin:
            if _make_threat(identity.id, "dormant_admin", "high", {
                "username": identity.username, "roles": roles,
                "reason": "dormant account retains admin privileges",
            }):
                created += 1
                fired.append(("dormant_admin", identity.username, "high",
                             "Dormant privileged account retains admin privileges"))

        if is_priv and not getattr(identity, "mfa_enabled", False):
            if _make_threat(identity.id, "mfa_missing_privileged", "critical", {
                "username": identity.username, "privilege_level": priv,
                "reason": "privileged identity has no MFA enrolled",
            }):
                created += 1
                fired.append(("mfa_missing_privileged", identity.username, "critical",
                             "Privileged identity has no MFA enrolled"))

        last_pw = _parse_iso(getattr(identity, "last_password_change", None))
        if last_pw is not None and last_pw < cutoff_180d:
            age_days = (now - last_pw).days
            if _make_threat(identity.id, "stale_credential", "medium", {
                "username": identity.username,
                "last_password_change": last_pw.isoformat(),
                "age_days": age_days,
            }):
                created += 1
                fired.append(("stale_credential", identity.username, "medium",
                             f"Password last rotated {age_days} days ago"))

    await session.flush()

    # Fire the cross-module automation handler for each newly created
    # threat — this flows into the alerts + incident pipeline so the
    # autonomous investigator picks it up like any other signal.
    try:
        from src.services.automation import AutomationService
        automation = AutomationService(session)
        for threat_type, username, severity, details in fired:
            try:
                await automation.on_itdr_threat(
                    threat_type=threat_type,
                    identity=username,
                    risk_level=severity,
                    details=details,
                    organization_id=organization_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"on_itdr_threat failed for {username}/{threat_type}: {exc}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"AutomationService setup failed in identity scan: {exc}")

    from src.itdr.runs import SCAN, record_run

    result = {
        "organization_id": organization_id,
        "identities_scanned": identities_scanned,
        "threats_created": created,
    }
    await record_run(session, organization_id, SCAN, status="ok", summary=result, rows=identities_scanned)
    await session.commit()
    # Release this org's ORM rows so a cross-org sweep does not accumulate
    # every org's identities in one session.
    session.expunge_all()
    return result


@shared_task(bind=True, max_retries=0)
def identity_threat_scan(
    self,
    organization_id: str,
    scan_scope: str = "all",
    focus_high_risk: bool = False,
):
    """Scan one organization's identities and create IdentityThreat rows
    for dormant_admin / mfa_missing_privileged / stale_credential.
    Fires on_itdr_threat for each so the autonomous investigator
    picks up the signal through the alerts pipeline.
    """
    async def _run():
        _engine, _sf = _fresh_itdr_session_factory()
        async with _sf() as session:
            try:
                return await _run_identity_scan_for_org(session, organization_id)
            finally:
                await _engine.dispose()

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Identity threat scan failed for org={organization_id}: {e}")
        return {"status": "error", "error": str(e)[:200]}


@shared_task(bind=True)
def scheduled_identity_threat_sweep(self):
    """Cross-org identity threat sweep.

    Every hour, iterate every Organization row and run
    ``_run_identity_scan_for_org`` against each. Creates IdentityThreat
    rows + fires the automation chain so threats flow into the alert
    pipeline and the autonomous investigator. Idempotent: the scan
    skips identity/threat-type pairs that already have an open threat.
    """
    from src.models.organization import Organization

    async def _sweep():
        _engine, _sf = _fresh_itdr_session_factory()
        totals = {"orgs_scanned": 0, "identities_scanned": 0, "threats_created": 0}
        try:
            # Org ids only — never the Organization ORM rows — and a fresh
            # session per org so one org's identities/threats cannot stay
            # reachable while the next org is scanned.
            async with _sf() as session:
                org_ids = list(await session.scalars(select(Organization.id)))

            for org_id in org_ids:
                try:
                    async with _sf() as session:
                        r = await _run_identity_scan_for_org(session, org_id)
                    totals["orgs_scanned"] += 1
                    totals["identities_scanned"] += r["identities_scanned"]
                    totals["threats_created"] += r["threats_created"]
                except Exception as exc:  # noqa: BLE001
                    logger.warning(f"identity sweep: org {org_id} failed: {exc}")
        finally:
            # Was outside any try/finally: a failure mid-sweep leaked the
            # engine (and its connections) for the life of the worker child.
            await _engine.dispose()
        if totals["threats_created"]:
            logger.info(f"scheduled_identity_threat_sweep: {totals}")
        return totals

    try:
        return _run_async(_sweep())
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"scheduled_identity_threat_sweep failed: {exc}")
        return {"error": str(exc)[:200]}


#: Organisations one sweep walks; the rest wait for the next run.
MAX_ORGS_PER_SWEEP = 1_000


async def _org_ids(session_factory, organization_id: Optional[str]) -> list[str]:
    if organization_id:
        return [organization_id]
    from src.models.organization import Organization

    async with session_factory() as session:
        return list(await session.scalars(
            select(Organization.id).order_by(Organization.id).limit(MAX_ORGS_PER_SWEEP)
        ))


async def _per_org(session_factory, organization_id: Optional[str], job, label: str) -> dict[str, Any]:
    """Run ``job(session, org_id)`` per organisation, each in its own session."""
    totals: dict[str, Any] = {"status": "completed", "organizations": 0, "failed_organizations": 0,
                              "results": [], "errors": []}
    for org_id in await _org_ids(session_factory, organization_id):
        try:
            async with session_factory() as session:
                result = await job(session, org_id)
        except Exception as exc:  # noqa: BLE001 - recorded per organisation, the sweep continues
            totals["failed_organizations"] += 1
            totals["errors"].append({"organization_id": org_id, "error": str(exc)[:500]})
            logger.error(f"{label} failed for org {org_id}: {exc}")
            continue
        totals["organizations"] += 1
        if result:
            totals["results"].append(result)
    if totals["failed_organizations"]:
        totals["status"] = "partial" if totals["organizations"] else "failed"
    totals["results"] = totals["results"][:200]
    return totals


async def sync_org_directories(session, org_id: str, integration_id: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Sync the active Okta / Entra ID integrations of one organisation (or just ``integration_id``).

    Each integration is its own transaction; its run row
    (``itdr_sync:<integration id>``) records ok / partial / failed.
    Returns None when the organisation has no such integration.
    """
    from src.integrations.netguard import OutboundTargetRefused
    from src.itdr.directory import DirectoryError, identity_integrations, sync_integration
    from src.itdr.runs import record_run, sync_consumer

    integration_ids = [i.id for i in await identity_integrations(session, org_id)]
    if integration_id is not None:
        integration_ids = [i for i in integration_ids if i == integration_id]
    if not integration_ids:
        return None
    out: dict[str, Any] = {"organization_id": org_id, "integrations": []}
    for iid in integration_ids:
        integration = next((i for i in await identity_integrations(session, org_id) if i.id == iid), None)
        if integration is None:
            continue
        try:
            summary = await sync_integration(session, org_id, integration)
        except (DirectoryError, OutboundTargetRefused, ValueError) as exc:
            # ValueError: a provider answered with a body that is not JSON.
            await session.rollback()
            await record_run(session, org_id, sync_consumer(iid), status="failed", error=str(exc))
            await session.commit()
            out["integrations"].append({"integration_id": iid, "status": "failed", "error": str(exc)[:500]})
            continue
        status = "partial" if summary.get("capped") else "ok"
        await record_run(session, org_id, sync_consumer(iid), status=status, summary=summary,
                         rows=int(summary.get("fetched") or 0))
        await session.commit()
        session.expunge_all()
        out["integrations"].append({"status": status, **summary})
    return out


async def _sync_identity_directories_async(organization_id: Optional[str] = None, session_factory=None) -> dict[str, Any]:
    engine = None
    if session_factory is None:
        engine, session_factory = _fresh_itdr_session_factory()
    try:
        return await _per_org(session_factory, organization_id, sync_org_directories, "directory sync")
    finally:
        if engine is not None:
            await engine.dispose()


async def _analyze_identity_auth_events_async(organization_id: Optional[str] = None, session_factory=None) -> dict[str, Any]:
    from src.itdr.analytics import analyze_auth_events_for_org
    from src.itdr.runs import AUTH, record_run

    engine = None
    if session_factory is None:
        engine, session_factory = _fresh_itdr_session_factory()
    try:
        totals = await _per_org(session_factory, organization_id, analyze_auth_events_for_org, "auth analysis")
        # A failed organisation's transaction was rolled back (its cursor did
        # not move); record the failure on the cursor row in a new session.
        for err in totals["errors"]:
            async with session_factory() as session:
                await record_run(session, err["organization_id"], AUTH, status="failed", error=err["error"])
                await session.commit()
        return totals
    finally:
        if engine is not None:
            await engine.dispose()


async def _check_identity_credential_exposures_async(organization_id: Optional[str] = None,
                                                     session_factory=None) -> dict[str, Any]:
    from src.itdr.analytics import check_credential_exposures_for_org

    engine = None
    if session_factory is None:
        engine, session_factory = _fresh_itdr_session_factory()
    try:
        return await _per_org(session_factory, organization_id, check_credential_exposures_for_org,
                              "credential exposure check")
    finally:
        if engine is not None:
            await engine.dispose()


@shared_task(bind=True, max_retries=0, name="src.itdr.tasks.sync_identity_directories")
def sync_identity_directories(self, organization_id: Optional[str] = None):
    """Sync identities from every installed Okta / Entra ID integration (hourly)."""
    return _run_async(_sync_identity_directories_async(organization_id))


@shared_task(bind=True, max_retries=0, name="src.itdr.tasks.analyze_identity_auth_events")
def analyze_identity_auth_events(self, organization_id: Optional[str] = None):
    """Auth baselines, access anomalies and brute-force / spray threats from stored logs (every 5 min)."""
    return _run_async(_analyze_identity_auth_events_async(organization_id))


@shared_task(bind=True, max_retries=0, name="src.itdr.tasks.check_identity_credential_exposures")
def check_identity_credential_exposures(self, organization_id: Optional[str] = None):
    """Match identities against the organisation's dark-web credential leak rows (hourly)."""
    return _run_async(_check_identity_credential_exposures_async(organization_id))


@shared_task(bind=True, max_retries=0)
def credential_exposure_check(
    self,
    organization_id: str,
    check_type: str = "comprehensive",
    include_dark_web: bool = True,
):
    """One organisation's credential monitoring run (on demand).

    Formerly compared PySOAR login accounts with leak rows and persisted
    nothing; it now runs the same identity check as the hourly sweep.
    ``check_type`` / ``include_dark_web`` are kept for callers; the only
    source is the organisation's own dark-web leak records.
    """
    return _run_async(_check_identity_credential_exposures_async(organization_id))


@shared_task(bind=True, max_retries=0)
def update_identity_baseline(
    self,
    organization_id: str,
    baseline_type: str = "comprehensive",
):
    """One organisation's auth-event analysis run (on demand).

    Formerly counted rows and built nothing; the identity auth baseline is
    the ``auth_baseline`` the analysis maintains (src/itdr/analytics.py).
    """
    return _run_async(_analyze_identity_auth_events_async(organization_id))


async def _privileged_access_audit_async(organization_id: str, session_factory) -> dict[str, Any]:
    from src.itdr.models import IdentityProfile, PrivilegeLevel

    privileged = [PrivilegeLevel.ADMIN.value, PrivilegeLevel.PRIVILEGED_ACCESS.value, PrivilegeLevel.ELEVATED.value]
    async with session_factory() as session:
        base = select(func.count(IdentityProfile.id)).where(IdentityProfile.organization_id == organization_id)
        total = (await session.execute(base)).scalar() or 0
        priv = (await session.execute(base.where(IdentityProfile.privilege_level.in_(privileged)))).scalar() or 0
        priv_no_mfa = (await session.execute(
            base.where(IdentityProfile.privilege_level.in_(privileged), IdentityProfile.mfa_enabled.is_(False))
        )).scalar() or 0
        svc_priv = (await session.execute(
            base.where(IdentityProfile.privilege_level.in_(privileged), IdentityProfile.is_service_account.is_(True))
        )).scalar() or 0
    return {
        "status": "success",
        "organization_id": organization_id,
        "total_identities": total,
        "privileged_identities": priv,
        "privileged_without_mfa": priv_no_mfa,
        "privileged_service_accounts": svc_priv,
        "privilege_ratio": round(priv / total * 100, 1) if total else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@shared_task(bind=True, max_retries=0)
def privileged_access_audit(
    self,
    organization_id: str,
    include_service_accounts: bool = True,
):
    """Count the organisation's privileged identities (directory rows, not PySOAR logins)."""
    async def _run():
        engine, factory = _fresh_itdr_session_factory()
        try:
            return await _privileged_access_audit_async(organization_id, factory)
        finally:
            await engine.dispose()

    return _run_async(_run())


async def _dormant_account_detection_async(organization_id: str, inactive_days: int, session_factory) -> dict[str, Any]:
    """Set ``is_dormant`` from ``last_authentication`` (ISO UTC strings compare in time order)."""
    from sqlalchemy import update

    from src.itdr.models import IdentityProfile

    cutoff = (datetime.now(timezone.utc) - timedelta(days=inactive_days)).isoformat()
    async with session_factory() as session:
        marked = (await session.execute(
            update(IdentityProfile)
            .where(
                IdentityProfile.organization_id == organization_id,
                IdentityProfile.last_authentication.is_not(None),
                IdentityProfile.last_authentication < cutoff,
                IdentityProfile.is_dormant.is_(False),
            )
            .values(is_dormant=True)
        )).rowcount or 0
        cleared = (await session.execute(
            update(IdentityProfile)
            .where(
                IdentityProfile.organization_id == organization_id,
                IdentityProfile.last_authentication >= cutoff,
                IdentityProfile.is_dormant.is_(True),
            )
            .values(is_dormant=False)
        )).rowcount or 0
        unknown = (await session.execute(
            select(func.count(IdentityProfile.id)).where(
                IdentityProfile.organization_id == organization_id,
                IdentityProfile.last_authentication.is_(None),
            )
        )).scalar() or 0
        await session.commit()
    return {
        "status": "success",
        "organization_id": organization_id,
        "marked_dormant": marked,
        "cleared_dormant": cleared,
        "identities_without_sign_in_data": unknown,
        "inactive_threshold_days": inactive_days,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@shared_task(bind=True, max_retries=0)
def dormant_account_detection(
    self,
    organization_id: str,
    inactive_days: int = 90,
):
    """Mark identities dormant when their last sign-in is older than ``inactive_days``."""
    async def _run():
        engine, factory = _fresh_itdr_session_factory()
        try:
            return await _dormant_account_detection_async(organization_id, inactive_days, factory)
        finally:
            await engine.dispose()

    return _run_async(_run())
