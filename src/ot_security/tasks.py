"""
OT/ICS Security Celery Tasks

Background tasks for asset discovery, protocol monitoring, firmware audits,
zone compliance verification, and safety system checks.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from src.core.logging import get_logger
from src.core.config import settings
from src.ot_security.models import (
    OTAsset,
    OTAlert,
    OTZone,
    OTIncident,
    OTPolicyRule,
)
from src.ot_security.engine import (
    OTMonitor,
    PurdueModelEnforcer,
    SafetyManager,
    OTVulnerabilityAssessor,
    ICSComplianceEngine,
)

logger = get_logger(__name__)

# Database session factory
engine = create_async_engine(
    settings.database_url, echo=False, pool_pre_ping=True
)
AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

__all__ = [
    "ot_asset_discovery",
    "protocol_monitoring",
    "firmware_audit",
    "zone_compliance_check",
    "safety_system_check",
]


@shared_task(bind=True, max_retries=3)
def ot_asset_discovery(self, organization_id: str, network_ranges: List[str]):
    """
    Discover OT assets on specified network ranges.

    Performs passive network monitoring to identify PLCs, HMIs, SCADA servers,
    field devices, and IoT sensors. Fingerprints devices by protocol response.

    Stores discovered assets in OTAsset table with purdue level estimation.
    """
    try:
        logger.info(
            f"Starting OT asset discovery for org {organization_id}, "
            f"ranges: {network_ranges}"
        )

        monitor = OTMonitor(organization_id)

        async def _discover():
            for network_range in network_ranges:
                discovered = await monitor.discover_assets(network_range)
                logger.info(f"Discovered {len(discovered)} assets in {network_range}")

            return {"discovered_count": len(discovered)}

        import asyncio
        return asyncio.run(_discover())

    except Exception as exc:
        logger.error(f"Asset discovery failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def protocol_monitoring(self, organization_id: str):
    """
    Monitor OT network communications and protocol usage.

    Analyzes network traffic for:
    - Modbus/DNP3/OPC-UA anomalies
    - Unauthorized commands
    - Protocol state violations
    - Unencrypted data flows

    Generates alerts for protocol violations and configuration anomalies.
    """
    try:
        logger.info(f"Starting protocol monitoring for org {organization_id}")

        monitor = OTMonitor(organization_id)
        enforcer = PurdueModelEnforcer(organization_id)

        async def _monitor():
            # Query real OTAlert rows for protocol violations and anomalies
            from src.core.database import async_session_factory
            from sqlalchemy import func

            async with async_session_factory() as db:
                # Get recent OT alerts for this organization
                alert_query = select(OTAlert).where(
                    OTAlert.organization_id == organization_id,
                    OTAlert.status == "new",
                )
                result = await db.execute(alert_query)
                recent_alerts = list(result.scalars().all())

                # Also run the monitor for zone violations
                violations = await monitor.monitor_communications(enforcer)

                # Count protocol-specific violations from real alerts
                protocol_violations = [a for a in recent_alerts if a.alert_type in ("protocol_violation", "unauthorized_command", "communication_anomaly")]

                # Get asset count for context
                asset_count_query = select(func.count(OTAsset.id)).where(
                    OTAsset.organization_id == organization_id
                )
                asset_result = await db.execute(asset_count_query)
                total_assets = asset_result.scalar() or 0

            total_violations = len(violations) + len(protocol_violations)
            logger.info(f"Found {total_violations} communication violations across {total_assets} assets")
            return {
                "violations": total_violations,
                "zone_violations": len(violations),
                "protocol_violations": len(protocol_violations),
                "total_assets_monitored": total_assets,
                "new_alerts": len(recent_alerts),
            }

        logger.info(f"Protocol monitoring task for {organization_id} queued")
        return asyncio.run(_monitor())

    except Exception as exc:
        logger.error(f"Protocol monitoring failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def firmware_audit(self, organization_id: str):
    """
    Audit firmware versions and detect unauthorized changes.

    Checks all OT assets for:
    - Known vulnerable firmware versions
    - Unexpected firmware changes
    - Firmware hash mismatches
    - End-of-life firmware

    Compares against baseline and ICS-CERT vulnerability database.
    """
    try:
        logger.info(f"Starting firmware audit for org {organization_id}")

        from src.core.database import async_session_factory
        from src.ot_security.advisories import load_advisories
        from src.ot_security.models import OTAsset
        from sqlalchemy import select
        import asyncio

        async def _audit():
            async with async_session_factory() as db:
                # Matches against the cached CISA ICS advisories (vendor + model);
                # there is no built-in CVE catalogue any more.
                assessor = OTVulnerabilityAssessor(organization_id, await load_advisories(db))
                result = await db.execute(select(OTAsset).where(OTAsset.organization_id == organization_id).limit(500))
                assets = list(result.scalars().all())
                vulnerabilities = await assessor.scan_firmware_versions(assets)
                logger.info(f"Found {len(vulnerabilities)} firmware vulnerabilities across {len(assets)} assets")
                return {"vulnerabilities": len(vulnerabilities), "assets_scanned": len(assets)}

        loop = asyncio.new_event_loop()
        audit_result = loop.run_until_complete(_audit())
        loop.close()
        return {"status": "completed", **audit_result}

    except Exception as exc:
        logger.error(f"Firmware audit failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=180)


@shared_task(bind=True, max_retries=3)
def zone_compliance_check(self, organization_id: str):
    """
    Verify OT network zone compliance with Purdue model.

    Checks all security zones for:
    - Proper network segmentation
    - Firewall rule completeness
    - Unauthorized zone crossings
    - Missing intermediaries
    - Protocol restrictions

    Generates compliance report and remediation recommendations.
    """
    try:
        logger.info(f"Starting zone compliance check for org {organization_id}")

        enforcer = PurdueModelEnforcer(organization_id)

        async def _check():
            from src.core.database import async_session_factory
            from src.ot_security.models import OTZone
            from sqlalchemy import select
            async with async_session_factory() as db:
                result = await db.execute(select(OTZone).where(OTZone.organization_id == organization_id))
                zones = list(result.scalars().all())
            report = await enforcer.generate_zone_compliance_report(zones)
            logger.info(
                f"Zone compliance: {report.get('maturity_level')}, "
                f"coverage: {report.get('coverage', 0):.1%}"
            )
            return report

        logger.info(f"Zone compliance check task for {organization_id} queued")
        return asyncio.run(_check())

    except Exception as exc:
        logger.error(f"Zone compliance check failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=150)


@shared_task(bind=True, max_retries=3)
def safety_system_check(self, organization_id: str):
    """
    Monitor safety-instrumented systems and SIL compliance.

    Checks all safety-critical assets for:
    - SIS online status
    - Safety Integrity Level (SIL) degradation
    - Proof test scheduling and execution
    - Safety function testing
    - Maintenance window compliance

    Alerts if SIL drops below required level or proof tests overdue.
    """
    try:
        logger.info(f"Starting safety system check for org {organization_id}")

        safety_mgr = SafetyManager(organization_id)

        async def _check():
            from src.core.database import async_session_factory
            from src.ot_security.models import OTAsset
            from sqlalchemy import select
            async with async_session_factory() as db:
                result = await db.execute(select(OTAsset).where(
                    OTAsset.organization_id == organization_id,
                    OTAsset.criticality == "safety_critical",
                ).limit(200))
                assets = list(result.scalars().all())
            monitoring = await safety_mgr.monitor_safety_systems(assets)
            logger.info(
                f"Safety system check: {len(monitoring.get('safety_systems', []))} "
                f"systems, {len(monitoring.get('degraded_systems', []))} degraded"
            )
            return monitoring

        import asyncio
        loop = asyncio.new_event_loop()
        check_result = loop.run_until_complete(_check())
        loop.close()
        return {"status": "completed", **check_result}

    except Exception as exc:
        logger.error(f"Safety system check failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=180)


# ---------------------------------------------------------------------------
# Wave 4: CISA ICS advisory sync and agent-command reconciliation
# ---------------------------------------------------------------------------

#: Bounds of the advisory rescoring sweep.
ADVISORY_SWEEP_MAX_ORGS = 500
ADVISORY_SWEEP_ASSETS_PER_ORG = 2000
ADVISORY_SWEEP_BATCH = 200


async def _sync_ics_advisories_async(force: bool = False) -> Dict[str, Any]:
    """Refresh the advisory cache, then write each asset's matched-advisory
    count and risk score (per org, 200-asset keyset batches, capped)."""
    from src.core.database import async_session_factory
    from src.ot_security.advisories import load_advisories, refresh_ics_advisories
    from src.ot_security.models import OTAsset

    async with async_session_factory() as db:
        feed = await refresh_ics_advisories(db, force=force)
        await db.commit()
        advisories = await load_advisories(db)
        org_ids = [row[0] for row in (await db.execute(
            select(OTAsset.organization_id).group_by(OTAsset.organization_id)
            .order_by(OTAsset.organization_id).limit(ADVISORY_SWEEP_MAX_ORGS),
        )).all()]

    rescored = 0
    with_advisories = 0
    for org_id in org_ids:
        assessor = OTVulnerabilityAssessor(org_id, advisories)
        last_id = ""
        seen = 0
        while seen < ADVISORY_SWEEP_ASSETS_PER_ORG:
            async with async_session_factory() as db:
                batch = list((await db.execute(
                    select(OTAsset).where(OTAsset.organization_id == org_id, OTAsset.id > last_id)
                    .order_by(OTAsset.id).limit(ADVISORY_SWEEP_BATCH),
                )).scalars().all())
                if not batch:
                    break
                for asset in batch:
                    data = asset.to_dict()
                    matches = await assessor.check_known_vulnerabilities(data)
                    asset.known_vulnerabilities_count = len(matches)
                    asset.risk_score = await assessor.calculate_ot_risk_score(data, matches)
                    rescored += 1
                    with_advisories += 1 if matches else 0
                await db.commit()
                last_id = batch[-1].id
                seen += len(batch)
    return {"feed": feed, "organizations": len(org_ids), "assets_rescored": rescored,
            "assets_with_advisories": with_advisories, "advisories_cached": len(advisories)}


@shared_task(bind=True, max_retries=2, name="src.ot_security.tasks.sync_ics_advisories")
def sync_ics_advisories(self, force: bool = False):
    """Daily: CISA ICS advisories (pinned fetch, cached) matched to stored OT assets."""
    try:
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_sync_ics_advisories_async(force))
        finally:
            loop.close()
        logger.info("ICS advisory sync complete", assets_rescored=result["assets_rescored"],
                    feed_status=result["feed"].get("status"))
        return result
    except Exception as exc:
        logger.error(f"ICS advisory sync failed: {exc}")
        raise self.retry(exc=exc, countdown=1800)


async def _reconcile_ot_agent_commands_async() -> Dict[str, int]:
    from src.core.database import async_session_factory
    from src.ot_security.actuation import reconcile_pending

    async with async_session_factory() as db:
        changed = await reconcile_pending(db, limit=200)
        await db.commit()
    return changed


@shared_task(bind=True, max_retries=0, name="src.ot_security.tasks.reconcile_ot_agent_commands")
def reconcile_ot_agent_commands(self):
    """Every 2 minutes: apply agent results to pending safe shutdowns and
    segmentation audits (200 of each per run)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_reconcile_ot_agent_commands_async())
    finally:
        loop.close()
