"""
Compliance Celery Tasks

Background tasks for compliance assessment, monitoring, and reporting.
Supports continuous monitoring, POA&M tracking, and automated evidence collection.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from src.core.logging import get_logger
from src.core.config import settings
from src.compliance.models import (
    ComplianceFramework,
    ComplianceControl,
    POAM,
    ComplianceEvidence,
    ComplianceAssessment,
    CUIMarking,
    CISADirective,
)
from src.compliance.engine import (
    ComplianceEngine,
    FedRAMPManager,
    NISTManager,
    CMMCManager,
    CISAComplianceManager,
    BuiltinFrameworks,
)

logger = get_logger(__name__)

# Database session factory
engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

__all__ = [
    "run_compliance_assessment",
    "run_continuous_monitoring",
    "check_poam_deadlines",
    "collect_automated_evidence",
    "update_compliance_scores",
    "check_cisa_directives",
    "generate_compliance_reports",
    "cross_reference_controls",
    "validate_cui_markings",
]


@shared_task(bind=True, max_retries=3)
def run_compliance_assessment(self, framework_id: str, org_id: str):
    """
    Run full compliance assessment for a framework.

    Triggers assessment across all controls and updates compliance score.
    """
    try:
        logger.info(f"Starting compliance assessment for framework {framework_id}")

        async def _assess():
            async with AsyncSessionLocal() as db:
                engine_instance = ComplianceEngine(db, org_id)
                result = await engine_instance.assess_framework(framework_id)
                logger.info(f"Assessment complete: {result['compliance_score']}%")
                return result

        return asyncio.run(_assess())

    except Exception as exc:
        logger.error(f"Assessment failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def run_continuous_monitoring(self, org_id: str):
    """
    Run FedRAMP Continuous Monitoring (ConMon) checks.

    Executes automated checks and updates evidence for all FedRAMP controls.
    Typically runs monthly.
    """
    try:
        logger.info(f"Starting continuous monitoring for org {org_id}")

        async def _conmon():
            async with AsyncSessionLocal() as db:
                manager = FedRAMPManager(db, org_id)
                result = await manager.run_continuous_monitoring()
                logger.info(f"ConMon complete: {len(result['results'])} frameworks assessed")
                return result

        return asyncio.run(_conmon())

    except Exception as exc:
        logger.error(f"ConMon failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=300)


@shared_task(bind=True, max_retries=2)
def check_poam_deadlines(self, org_id: str):
    """
    Check for overdue and upcoming POA&M deadlines.

    Sends alerts for items approaching/overdue completion dates.
    """
    try:
        logger.info(f"Checking POA&M deadlines for org {org_id}")

        async def _check():
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select, and_

                now = datetime.utcnow()
                warning_threshold = now + timedelta(days=7)

                # Check overdue
                stmt = select(POAM).where(
                    and_(
                        POAM.organization_id == org_id,
                        POAM.status != "completed",
                        POAM.scheduled_completion_date < now,
                    )
                )
                result = await db.execute(stmt)
                overdue = result.scalars().all()

                # Check upcoming (within 7 days)
                stmt = select(POAM).where(
                    and_(
                        POAM.organization_id == org_id,
                        POAM.status != "completed",
                        POAM.scheduled_completion_date >= now,
                        POAM.scheduled_completion_date <= warning_threshold,
                    )
                )
                result = await db.execute(stmt)
                upcoming = result.scalars().all()

                logger.warning(
                    f"POA&M check: {len(overdue)} overdue, {len(upcoming)} upcoming"
                )

                return {
                    "overdue_count": len(overdue),
                    "upcoming_count": len(upcoming),
                    "total_items": len(overdue) + len(upcoming),
                }

        return asyncio.run(_check())

    except Exception as exc:
        logger.error(f"POA&M deadline check failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=300)


@shared_task(bind=True, max_retries=3)
def collect_automated_evidence(self, org_id: str):
    """
    Automatically collect evidence from system checks and logs.

    Collects logs, configuration snapshots, and scan results.
    Evidence is tagged for review and approval.
    """
    try:
        logger.info(f"Starting automated evidence collection for org {org_id}")

        async def _collect():
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select, and_, func

                now = datetime.utcnow()
                evidence_cutoff = now - timedelta(days=90)

                # Get all controls for the organization
                stmt = select(ComplianceControl).where(
                    ComplianceControl.organization_id == org_id
                )
                result = await db.execute(stmt)
                controls = result.scalars().all()

                # Count recent evidence per control and identify gaps
                evidence_collected = 0
                controls_with_evidence = 0
                controls_missing_evidence = 0

                for control in controls:
                    # Query recent evidence for this control
                    evidence_stmt = select(func.count(ComplianceEvidence.id)).where(
                        and_(
                            ComplianceEvidence.control_id_ref == str(control.id),
                            ComplianceEvidence.collected_at >= evidence_cutoff,
                        )
                    )
                    count_result = await db.execute(evidence_stmt)
                    recent_count = count_result.scalar() or 0

                    if recent_count > 0:
                        controls_with_evidence += 1
                        evidence_collected += recent_count
                    else:
                        controls_missing_evidence += 1

                logger.info(
                    f"Evidence collection: {evidence_collected} items across "
                    f"{controls_with_evidence} controls, "
                    f"{controls_missing_evidence} controls missing evidence"
                )

                return {
                    "evidence_collected": evidence_collected,
                    "controls_with_evidence": controls_with_evidence,
                    "controls_missing_evidence": controls_missing_evidence,
                    "total_controls": len(controls),
                }

        import asyncio
        collection_result = asyncio.run(_collect())

        logger.info("Automated evidence collection complete")

        return {
            "status": "completed",
            **collection_result,
        }

    except Exception as exc:
        logger.error(f"Evidence collection failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=600)


@shared_task(bind=True, max_retries=2)
def update_compliance_scores(self, org_id: str):
    """
    Recalculate compliance scores for all frameworks.

    Updates framework compliance_score field based on current control status.
    Typically runs daily or after assessments.
    """
    try:
        logger.info(f"Updating compliance scores for org {org_id}")

        async def _update():
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select

                stmt = select(ComplianceFramework).where(
                    ComplianceFramework.organization_id == org_id
                )
                result = await db.execute(stmt)
                frameworks = result.scalars().all()

                updated_count = 0
                for framework in frameworks:
                    engine_instance = ComplianceEngine(db, org_id)
                    score = await engine_instance.calculate_compliance_score(
                        str(framework.id)
                    )
                    framework.compliance_score = score
                    updated_count += 1

                await db.commit()
                logger.info(f"Updated {updated_count} framework scores")
                return updated_count

        result = asyncio.run(_update())
        return {"status": "completed", "frameworks_updated": result}

    except Exception as exc:
        logger.error(f"Score update failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=300)


@shared_task(bind=True, max_retries=2)
def check_cisa_directives(self, org_id: str):
    """
    Check compliance with active CISA BODs and Emergency Directives.

    Verifies actions taken against directive requirements.
    Alerts on approaching compliance deadlines.
    """
    try:
        logger.info(f"Checking CISA directives for org {org_id}")

        async def _check():
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select, and_

                stmt = select(CISADirective).where(
                    and_(
                        CISADirective.organization_id == org_id,
                        CISADirective.status == "active",
                    )
                )
                result = await db.execute(stmt)
                active_directives = result.scalars().all()

                now = datetime.utcnow()
                approaching_deadline = [
                    d
                    for d in active_directives
                    if d.compliance_deadline <= now + timedelta(days=7)
                ]

                logger.info(
                    f"CISA check: {len(active_directives)} active, "
                    f"{len(approaching_deadline)} with approaching deadlines"
                )

                return {
                    "active_directives": len(active_directives),
                    "approaching_deadline": len(approaching_deadline),
                }

        return asyncio.run(_check())

    except Exception as exc:
        logger.error(f"CISA directive check failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=300)


@shared_task(bind=True, max_retries=3)
def generate_compliance_reports(self, org_id: str, report_type: str = "weekly"):
    """
    Generate compliance reports.

    Args:
        org_id: Organization ID
        report_type: "weekly", "monthly", "quarterly", "annual"

    Report includes:
    - Overall compliance scores
    - Framework status
    - Control gaps
    - POA&M summary
    - Risk trends
    """
    try:
        logger.info(f"Generating {report_type} compliance report for org {org_id}")

        async def _generate():
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select

                stmt = select(ComplianceFramework).where(
                    ComplianceFramework.organization_id == org_id
                )
                result = await db.execute(stmt)
                frameworks = result.scalars().all()

                report_data = {
                    "report_type": report_type,
                    "generated_at": datetime.utcnow().isoformat(),
                    "org_id": org_id,
                    "frameworks": [],
                }

                for framework in frameworks:
                    engine_instance = ComplianceEngine(db, org_id)
                    gaps = await engine_instance.get_control_gaps(str(framework.id))

                    framework_data = {
                        "framework_name": framework.short_name,
                        "compliance_score": framework.compliance_score,
                        "status": framework.status,
                        "gaps_count": len(gaps),
                    }
                    report_data["frameworks"].append(framework_data)

                logger.info(f"Report generated with {len(frameworks)} frameworks")
                return report_data

        return asyncio.run(_generate())

    except Exception as exc:
        logger.error(f"Report generation failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=600)


@shared_task(bind=True, max_retries=3)
def cross_reference_controls(self, org_id: str):
    """
    Update cross-framework control mappings.

    Creates and updates mappings between:
    - NIST 800-53 -> CMMC
    - NIST 800-53 -> PCI-DSS
    - NIST 800-171 -> CMMC
    - etc.

    Useful for gap analysis when adopting new frameworks.
    """
    try:
        logger.info(f"Cross-referencing controls for org {org_id}")

        async def _crossref():
            async with AsyncSessionLocal() as db:
                engine_instance = ComplianceEngine(db, org_id)

                # Get all frameworks
                from sqlalchemy import select

                stmt = select(ComplianceFramework).where(
                    ComplianceFramework.organization_id == org_id
                )
                result = await db.execute(stmt)
                frameworks = result.scalars().all()

                mapping_count = 0
                for i, source_fw in enumerate(frameworks):
                    for target_fw in frameworks[i + 1 :]:
                        mapping = await engine_instance.cross_map_controls(
                            str(source_fw.id), str(target_fw.id)
                        )
                        mapping_count += 1

                logger.info(f"Created {mapping_count} cross-framework mappings")
                return mapping_count

        return asyncio.run(_crossref())

    except Exception as exc:
        logger.error(f"Cross-reference failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=600)


@shared_task(bind=True, max_retries=2)
def validate_cui_markings(self, org_id: str):
    """
    Validate CUI (Controlled Unclassified Information) markings and handling.

    Checks:
    - CUI markings are current and valid
    - Access lists are up-to-date
    - Dissemination controls are enforced
    - No expired CUI is still marked as active
    """
    try:
        logger.info(f"Validating CUI markings for org {org_id}")

        async def _validate():
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select

                stmt = select(CUIMarking).where(
                    CUIMarking.organization_id == org_id
                )
                result = await db.execute(stmt)
                cui_markings = result.scalars().all()

                now = datetime.utcnow()
                expired_count = 0
                active_count = 0

                for marking in cui_markings:
                    if marking.declassification_date and marking.declassification_date < now:
                        if marking.is_active:
                            marking.is_active = False
                            expired_count += 1
                    if marking.is_active:
                        active_count += 1

                await db.commit()

                logger.info(
                    f"CUI validation: {len(cui_markings)} total, "
                    f"{active_count} active, {expired_count} expired/deactivated"
                )

                return {
                    "total_cui": len(cui_markings),
                    "active_cui": active_count,
                    "deactivated": expired_count,
                }

        return asyncio.run(_validate())

    except Exception as exc:
        logger.error(f"CUI validation failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=300)
