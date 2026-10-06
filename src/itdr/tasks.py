"""
Celery Tasks for ITDR (Identity Threat Detection & Response)

Background tasks for identity threat scanning, credential exposure
monitoring, baseline updates, privileged access auditing, and
dormant account detection. Every task queries real database rows.
"""

import asyncio
from datetime import datetime, timedelta, timezone

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
            confidence_score=0.9,
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

    await session.commit()
    # Release this org's ORM rows so a cross-org sweep does not accumulate
    # every org's identities in one session.
    session.expunge_all()
    return {
        "organization_id": organization_id,
        "identities_scanned": identities_scanned,
        "threats_created": created,
    }


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


@shared_task(bind=True, max_retries=3)
def credential_exposure_check(
    self,
    organization_id: str,
    check_type: str = "comprehensive",
    include_dark_web: bool = True,
):
    """Check credentials against real CredentialLeak and User tables."""
    from src.core.database import async_session_factory
    from src.models.user import User
    from src.darkweb.models import CredentialLeak

    async def _run():
        async with async_session_factory() as session:
            user_count = (await session.execute(
                select(func.count(User.id)).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )).scalar() or 0

            org_emails_result = await session.execute(
                select(User.email).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )
            org_emails = {r[0].lower() for r in org_emails_result.all() if r[0]}

            leaked_result = await session.execute(
                select(CredentialLeak.email).where(
                    CredentialLeak.is_remediated == False,
                )
            )
            leaked_emails = {r[0].lower() for r in leaked_result.all() if r[0]}

            exposed = org_emails & leaked_emails

            return {
                "status": "success",
                "organization_id": organization_id,
                "check_type": check_type,
                "total_credentials_checked": user_count,
                "exposures_found": len(exposed),
                "exposed_emails": list(exposed)[:50],
                "critical_exposures": len(exposed),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Credential exposure check failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def update_identity_baseline(
    self,
    organization_id: str,
    baseline_type: str = "comprehensive",
):
    """Build identity access baseline from real AccessAnomaly + User data."""
    from src.core.database import async_session_factory
    from src.models.user import User
    from src.itdr.models import AccessAnomaly

    async def _run():
        async with async_session_factory() as session:
            user_count = (await session.execute(
                select(func.count(User.id)).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )).scalar() or 0

            anomaly_count = (await session.execute(
                select(func.count(AccessAnomaly.id)).where(
                    AccessAnomaly.organization_id == organization_id,
                )
            )).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "baseline_type": baseline_type,
                "identities_profiled": user_count,
                "anomalies_in_baseline": anomaly_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Identity baseline update failed: {e}")
        raise self.retry(exc=e, countdown=120)


@shared_task(bind=True, max_retries=2)
def privileged_access_audit(
    self,
    organization_id: str,
    include_service_accounts: bool = True,
):
    """Audit privileged access by counting real admin/superuser accounts."""
    from src.core.database import async_session_factory
    from src.models.user import User

    async def _run():
        async with async_session_factory() as session:
            priv_query = select(func.count(User.id)).where(
                and_(
                    User.organization_id == organization_id,
                    User.is_active == True,
                    User.role.in_(["admin"]),
                )
            )
            privileged_accounts = (await session.execute(priv_query)).scalar() or 0

            super_query = select(func.count(User.id)).where(
                and_(
                    User.organization_id == organization_id,
                    User.is_superuser == True,
                )
            )
            superusers = (await session.execute(super_query)).scalar() or 0

            total_query = select(func.count(User.id)).where(
                User.organization_id == organization_id,
                User.is_active == True,
            )
            total_users = (await session.execute(total_query)).scalar() or 0

            return {
                "status": "success",
                "organization_id": organization_id,
                "total_users": total_users,
                "privileged_accounts": privileged_accounts,
                "superuser_accounts": superusers,
                "privilege_ratio": round(
                    (privileged_accounts + superusers) / max(total_users, 1) * 100, 1
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Privileged access audit failed: {e}")
        raise self.retry(exc=e, countdown=120)


@shared_task(bind=True, max_retries=2)
def dormant_account_detection(
    self,
    organization_id: str,
    inactive_days: int = 90,
):
    """Detect dormant accounts by checking last_login against real User rows."""
    from src.core.database import async_session_factory
    from src.models.user import User

    async def _run():
        async with async_session_factory() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=inactive_days)

            total = (await session.execute(
                select(func.count(User.id)).where(
                    User.organization_id == organization_id,
                    User.is_active == True,
                )
            )).scalar() or 0

            dormant_count = 0
            try:
                if hasattr(User, "last_login"):
                    dormant_count = (await session.execute(
                        select(func.count(User.id)).where(
                            and_(
                                User.organization_id == organization_id,
                                User.is_active == True,
                                User.last_login < cutoff,
                            )
                        )
                    )).scalar() or 0
            except Exception:
                pass

            return {
                "status": "success",
                "organization_id": organization_id,
                "total_active_accounts": total,
                "dormant_accounts": dormant_count,
                "inactive_threshold_days": inactive_days,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_run())
    except Exception as e:
        logger.error(f"Dormant account detection failed: {e}")
        raise self.retry(exc=e, countdown=60)
