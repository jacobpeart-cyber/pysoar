"""Celery tasks for Zero Trust operations"""

from datetime import datetime, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.zerotrust.engine import (
    ContinuousAuthEngine,
    DeviceTrustAssessor,
    MicroSegmentationEngine,
    PolicyDecisionPoint,
    ZeroTrustScorer,
)
from src.zerotrust.models import AccessDecision, DeviceTrustProfile

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
async def continuous_session_evaluation(self: Any, organization_id: str) -> dict[str, Any]:
    """Re-evaluate active sessions periodically for ongoing risk changes

    Runs every 5 minutes to detect session anomalies and enforce
    continuous authentication policies.
    """
    logger.info("task_starting", task="continuous_session_evaluation")

    async with async_session_factory() as db:
        try:
            pdp = PolicyDecisionPoint(db, organization_id)

            # Get active sessions (last access within 5 minutes)
            result = await db.execute(
                select(AccessDecision)
                .where(
                    and_(
                        AccessDecision.organization_id == organization_id,
                        AccessDecision.session_id.isnot(None),
                        AccessDecision.decision == "allow",
                    )
                )
                .distinct(AccessDecision.session_id)
            )
            decisions = result.scalars().all()

            evaluated = 0
            escalated = 0

            for decision in decisions:
                if decision.session_id:
                    new_decision = await pdp.continuous_evaluation(
                        decision.session_id
                    )
                    evaluated += 1

                    if new_decision and new_decision.decision != "allow":
                        escalated += 1
                        logger.info(
                            "session_escalated",
                            session_id=decision.session_id,
                            new_decision=new_decision.decision,
                        )

            await db.commit()

            result_data = {
                "evaluated_sessions": evaluated,
                "escalated": escalated,
                "organization_id": organization_id,
            }

            logger.info("task_complete", task="continuous_session_evaluation", **result_data)
            return result_data

        except Exception as exc:
            logger.error("task_failed", task="continuous_session_evaluation", error=str(exc))
            raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
async def assess_device_fleet(self: Any, organization_id: str) -> dict[str, Any]:
    """Scan all devices for compliance and trust assessment

    Runs every hour to evaluate device posture and update trust scores.
    """
    logger.info("task_starting", task="assess_device_fleet")

    async with async_session_factory() as db:
        try:
            assessor = DeviceTrustAssessor(db, organization_id)

            # Get all devices
            result = await db.execute(
                select(DeviceTrustProfile).where(
                    DeviceTrustProfile.organization_id == organization_id
                )
            )
            devices = result.scalars().all()

            assessed = 0
            non_compliant = 0

            for device in devices:
                assessed_device = await assessor.assess_device(device.device_id)

                assessed += 1
                if assessed_device.trust_level in ["untrusted", "blocked"]:
                    non_compliant += 1
                    logger.warning(
                        "device_non_compliant",
                        device_id=device.device_id,
                        trust_level=assessed_device.trust_level,
                    )

            result_data = {
                "assessed_devices": assessed,
                "non_compliant": non_compliant,
                "organization_id": organization_id,
            }

            logger.info("task_complete", task="assess_device_fleet", **result_data)
            return result_data

        except Exception as exc:
            logger.error("task_failed", task="assess_device_fleet", error=str(exc))
            raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
async def update_micro_segments(self: Any, organization_id: str) -> dict[str, Any]:
    """Refresh micro-segment policies and traffic rules

    Runs every 2 hours to update segment policies based on
    organizational changes and threat intelligence.
    """
    logger.info("task_starting", task="update_micro_segments")

    async with async_session_factory() as db:
        try:
            segmentation = MicroSegmentationEngine(db, organization_id)

            # TODO: Implement segment update logic
            # - Fetch updated segment policies
            # - Check for policy conflicts
            # - Update segment rules

            result_data = {
                "updated_segments": 0,
                "conflicts_detected": 0,
                "organization_id": organization_id,
            }

            logger.info("task_complete", task="update_micro_segments", **result_data)
            return result_data

        except Exception as exc:
            logger.error("task_failed", task="update_micro_segments", error=str(exc))
            raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
async def detect_policy_violations(self: Any, organization_id: str) -> dict[str, Any]:
    """Detect unauthorized access patterns and policy violations

    Runs every 15 minutes to identify anomalous access patterns
    and potential security incidents.
    """
    logger.info("task_starting", task="detect_policy_violations")

    async with async_session_factory() as db:
        try:
            # Get recent deny decisions
            result = await db.execute(
                select(AccessDecision)
                .where(
                    and_(
                        AccessDecision.organization_id == organization_id,
                        AccessDecision.decision == "deny",
                    )
                )
                .order_by(AccessDecision.created_at.desc())
                .limit(100)
            )
            violations = result.scalars().all()

            # Analyze patterns
            violation_count = len(violations)

            # Check for brute force attempts (same subject multiple denies)
            subject_denies = {}
            for violation in violations:
                key = violation.subject_id
                subject_denies[key] = subject_denies.get(key, 0) + 1

            brute_force_attempts = {
                k: v for k, v in subject_denies.items() if v >= 5
            }

            result_data = {
                "violations_detected": violation_count,
                "brute_force_attempts": len(brute_force_attempts),
                "organization_id": organization_id,
            }

            if brute_force_attempts:
                logger.warning(
                    "potential_brute_force",
                    attempts=brute_force_attempts,
                )

            logger.info("task_complete", task="detect_policy_violations", **result_data)
            return result_data

        except Exception as exc:
            logger.error("task_failed", task="detect_policy_violations", error=str(exc))
            raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
async def calculate_zero_trust_maturity(self: Any, organization_id: str) -> dict[str, Any]:
    """Update Zero Trust maturity score and recommendations

    Runs daily to assess overall Zero Trust implementation
    maturity and generate improvement recommendations.
    """
    logger.info("task_starting", task="calculate_zero_trust_maturity")

    async with async_session_factory() as db:
        try:
            scorer = ZeroTrustScorer(db, organization_id)

            maturity_data = await scorer.calculate_maturity_score()

            result_data = {
                "overall_score": maturity_data["overall_score"],
                "maturity_level": maturity_data["maturity_level"],
                "pillars": maturity_data["pillars"],
                "organization_id": organization_id,
            }

            logger.info(
                "task_complete",
                task="calculate_zero_trust_maturity",
                score=maturity_data["overall_score"],
                level=maturity_data["maturity_level"],
            )

            return result_data

        except Exception as exc:
            logger.error(
                "task_failed", task="calculate_zero_trust_maturity", error=str(exc)
            )
            raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
async def rotate_session_tokens(self: Any, organization_id: str) -> dict[str, Any]:
    """Force re-authentication for long-lived sessions

    Runs every 4 hours to rotate session tokens and enforce
    continuous authentication for extended sessions.
    """
    logger.info("task_starting", task="rotate_session_tokens")

    async with async_session_factory() as db:
        try:
            # Find sessions older than configured TTL
            max_session_age_hours = 8  # Configurable

            # TODO: Implement session token rotation
            # - Find long-lived sessions
            # - Mark for re-authentication
            # - Notify users

            result_data = {
                "rotated_tokens": 0,
                "users_notified": 0,
                "organization_id": organization_id,
            }

            logger.info("task_complete", task="rotate_session_tokens", **result_data)
            return result_data

        except Exception as exc:
            logger.error("task_failed", task="rotate_session_tokens", error=str(exc))
            raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
async def generate_zero_trust_report(self: Any, organization_id: str) -> dict[str, Any]:
    """Generate daily Zero Trust posture report

    Runs daily to create comprehensive report on Zero Trust
    implementation, policy effectiveness, and recommendations.
    """
    logger.info("task_starting", task="generate_zero_trust_report")

    async with async_session_factory() as db:
        try:
            # Get maturity score
            scorer = ZeroTrustScorer(db, organization_id)
            maturity = await scorer.calculate_maturity_score()

            # Get device compliance
            assessor = DeviceTrustAssessor(db, organization_id)
            non_compliant = await assessor.get_non_compliant_devices()

            # Get recent violations
            result = await db.execute(
                select(AccessDecision)
                .where(
                    and_(
                        AccessDecision.organization_id == organization_id,
                        AccessDecision.decision.in_(["deny", "step_up", "challenge"]),
                    )
                )
                .order_by(AccessDecision.created_at.desc())
                .limit(100)
            )
            violations = result.scalars().all()

            report_data = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "organization_id": organization_id,
                "maturity": maturity,
                "non_compliant_devices": len(non_compliant),
                "recent_violations": len(violations),
                "report_location": f"/reports/zerotrust/{organization_id}",
            }

            logger.info("task_complete", task="generate_zero_trust_report", **report_data)
            return report_data

        except Exception as exc:
            logger.error("task_failed", task="generate_zero_trust_report", error=str(exc))
            raise self.retry(exc=exc, countdown=60)
