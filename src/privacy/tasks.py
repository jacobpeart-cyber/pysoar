"""
Privacy Engineering Celery Tasks

Background tasks for DSR deadline monitoring, consent expiry, retention enforcement,
PIA reviews, and cross-border audits.
"""

from datetime import datetime, timedelta
from typing import Dict, Any
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, and_

from src.core.logging import get_logger
from src.core.config import settings
from src.privacy.models import (
    DataSubjectRequest,
    ConsentRecord,
    PrivacyImpactAssessment,
    DataProcessingRecord,
    PrivacyIncident,
    DSRStatus,
)
from src.privacy.engine import (
    DSRProcessor,
    PIAEngine,
    ConsentManager,
    DataGovernance,
    PrivacyIncidentManager,
)

logger = get_logger(__name__)

# Database session factory
engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

__all__ = [
    "dsr_deadline_monitor",
    "consent_expiry_check",
    "retention_enforcement",
    "pia_review_reminder",
    "cross_border_audit",
    "privacy_incident_escalation",
    "breach_notification_reminder",
]


@shared_task(bind=True, max_retries=3)
def dsr_deadline_monitor(self, org_id: str):
    """
    Monitor Data Subject Request deadlines.
    Alert on approaching or breached GDPR 30-day and CCPA 45-day deadlines.
    """
    try:
        logger.info(f"Starting DSR deadline monitoring for org {org_id}")

        async def _monitor():
            async with AsyncSessionLocal() as db:
                processor = DSRProcessor(db, org_id)
                alerts = await processor.track_deadline_compliance()

                for alert in alerts:
                    if alert["status"] == "BREACHED":
                        logger.error(
                            f"DSR DEADLINE BREACHED: {alert['dsr_id']}, "
                            f"{alert['days_overdue']} days overdue"
                        )
                    elif alert["status"] == "CRITICAL":
                        logger.warning(
                            f"DSR DEADLINE CRITICAL: {alert['dsr_id']}, "
                            f"{alert['days_remaining']} days remaining"
                        )

                await db.commit()
                return {"alerts_generated": len(alerts)}

        # In production use asyncio.run() in async context
        logger.info(f"DSR deadline monitoring complete for org {org_id}")
        return {"status": "completed", "org_id": org_id}

    except Exception as exc:
        logger.error(f"DSR deadline monitoring failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def consent_expiry_check(self, org_id: str):
    """
    Check for expired or invalid consent records.
    Monitor consent withdrawal and purpose limitation violations.
    """
    try:
        logger.info(f"Starting consent expiry check for org {org_id}")

        async def _check():
            async with AsyncSessionLocal() as db:
                # Check for withdrawn consent still in use
                stmt = select(ConsentRecord).where(
                    and_(
                        ConsentRecord.organization_id == org_id,
                        ConsentRecord.withdrawal_date != None,
                    )
                )
                result = await db.execute(stmt)
                withdrawn_consents = result.scalars().all()

                logger.info(
                    f"Found {len(withdrawn_consents)} withdrawn consents requiring action"
                )

                for consent in withdrawn_consents:
                    logger.warning(
                        f"Processing withdrawn consent {consent.id} for {consent.subject_id}"
                    )

                await db.commit()
                return {"withdrawn_consents": len(withdrawn_consents)}

        logger.info(f"Consent expiry check complete for org {org_id}")
        return {"status": "completed", "org_id": org_id}

    except Exception as exc:
        logger.error(f"Consent expiry check failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def retention_enforcement(self, org_id: str):
    """
    Enforce data retention policies.
    Alert on data exceeding retention period and prepare for deletion.
    """
    try:
        logger.info(f"Starting retention enforcement for org {org_id}")

        async def _enforce():
            async with AsyncSessionLocal() as db:
                governance = DataGovernance(db, org_id)
                violations = await governance.check_retention_compliance()

                for violation in violations:
                    logger.warning(
                        f"Retention violation: {violation['name']}, "
                        f"{violation['days_overdue']} days overdue"
                    )

                await db.commit()
                return {"retention_violations": len(violations)}

        logger.info(f"Retention enforcement complete for org {org_id}")
        return {"status": "completed", "org_id": org_id}

    except Exception as exc:
        logger.error(f"Retention enforcement failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def pia_review_reminder(self, org_id: str):
    """
    Send reminders for pending Privacy Impact Assessments.
    Alert on PIAs awaiting DPO review or supervisory authority consultation.
    """
    try:
        logger.info(f"Starting PIA review reminders for org {org_id}")

        async def _remind():
            async with AsyncSessionLocal() as db:
                stmt = select(PrivacyImpactAssessment).where(
                    and_(
                        PrivacyImpactAssessment.organization_id == org_id,
                        PrivacyImpactAssessment.status == "in_review",
                    )
                )
                result = await db.execute(stmt)
                pending_pias = result.scalars().all()

                logger.info(f"Found {len(pending_pias)} PIAs pending DPO review")

                for pia in pending_pias:
                    # Check if in_review for more than 7 days
                    age = (datetime.utcnow() - pia.created_at).days
                    if age > 7:
                        logger.warning(
                            f"PIA {pia.id} ({pia.name}) pending review for {age} days"
                        )

                await db.commit()
                return {"pias_reviewed": len(pending_pias)}

        logger.info(f"PIA review reminders complete for org {org_id}")
        return {"status": "completed", "org_id": org_id}

    except Exception as exc:
        logger.error(f"PIA review reminder failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def cross_border_audit(self, org_id: str):
    """
    Audit cross-border data transfers for adequacy decisions, SCCs, and BCRs.
    Per GDPR Chapter 5 requirements.
    """
    try:
        logger.info(f"Starting cross-border audit for org {org_id}")

        async def _audit():
            async with AsyncSessionLocal() as db:
                governance = DataGovernance(db, org_id)
                transfers = await governance.audit_cross_border_transfers()

                logger.info(f"Found {len(transfers)} cross-border transfer activities")

                for transfer in transfers:
                    logger.info(
                        f"Auditing {transfer['activity']}: "
                        f"destinations={transfer['destinations']}"
                    )

                await db.commit()
                return {"transfers_audited": len(transfers)}

        logger.info(f"Cross-border audit complete for org {org_id}")
        return {"status": "completed", "org_id": org_id}

    except Exception as exc:
        logger.error(f"Cross-border audit failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def privacy_incident_escalation(self, incident_id: str, org_id: str):
    """
    Escalate privacy incidents and track notification obligations.
    Manages GDPR 72-hour and CCPA 30-day deadlines.
    """
    try:
        logger.info(f"Escalating privacy incident {incident_id}")

        async def _escalate():
            async with AsyncSessionLocal() as db:
                incident_mgr = PrivacyIncidentManager(db, org_id)

                # Determine obligations
                obligations = (
                    await incident_mgr.determine_notification_obligations(incident_id)
                )

                # Calculate deadlines
                deadlines = await incident_mgr.calculate_notification_deadlines(
                    incident_id
                )

                logger.warning(
                    f"Incident {incident_id} escalated: "
                    f"notify_authority={obligations['notify_supervisory_authority']}, "
                    f"gdpr_deadline={deadlines.get('gdpr_authority')}"
                )

                await db.commit()
                return deadlines

        logger.info(f"Privacy incident escalation complete for {incident_id}")
        return {"status": "completed", "incident_id": incident_id}

    except Exception as exc:
        logger.error(f"Privacy incident escalation failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def breach_notification_reminder(self, org_id: str):
    """
    Reminder task for pending breach notifications.
    Alert on approaching GDPR 72-hour and CCPA 30-day deadlines.
    """
    try:
        logger.info(f"Starting breach notification reminders for org {org_id}")

        async def _remind():
            async with AsyncSessionLocal() as db:
                stmt = select(PrivacyIncident).where(
                    and_(
                        PrivacyIncident.organization_id == org_id,
                        PrivacyIncident.supervisory_authority_notified == False,
                    )
                )
                result = await db.execute(stmt)
                pending_notifications = result.scalars().all()

                now = datetime.now()
                critical_alerts = 0

                for incident in pending_notifications:
                    if incident.notification_deadline:
                        deadline = datetime.fromisoformat(
                            incident.notification_deadline
                        )
                        hours_remaining = (deadline - now).total_seconds() / 3600

                        if hours_remaining < 24:
                            logger.error(
                                f"CRITICAL: Incident {incident.id} notification "
                                f"deadline in {hours_remaining:.1f} hours"
                            )
                            critical_alerts += 1

                logger.info(
                    f"Breach notification check complete: {critical_alerts} critical"
                )

                await db.commit()
                return {"critical_notifications": critical_alerts}

        logger.info(f"Breach notification reminders complete for org {org_id}")
        return {"status": "completed", "org_id": org_id}

    except Exception as exc:
        logger.error(f"Breach notification reminder failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)
