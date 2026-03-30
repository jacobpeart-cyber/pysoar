"""
Celery Tasks for Phishing Simulation & Security Awareness Module

Background tasks for campaign execution, training assignment, reporting,
and risk score recalculation.
"""

from datetime import datetime, timedelta, timezone

from celery import shared_task

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
def launch_scheduled_campaign(
    self,
    campaign_id: str,
    organization_id: str,
):
    """
    Launch a scheduled phishing campaign.

    Triggered at scheduled start time to activate and begin email distribution.

    Args:
        campaign_id: Campaign ID to launch
        organization_id: Organization context

    Returns:
        Campaign launch status and statistics
    """
    try:
        logger.info(
            f"Launching scheduled campaign {campaign_id}",
            extra={"organization_id": organization_id},
        )

        # Simulate campaign launch
        result = {
            "campaign_id": campaign_id,
            "organization_id": organization_id,
            "status": "launched",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "targets_queued": 250,
            "batches_scheduled": 5,
        }

        logger.info(f"Campaign {campaign_id} launched successfully", extra=result)
        return result

    except Exception as e:
        logger.error(f"Failed to launch campaign {campaign_id}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_campaign_batch(
    self,
    campaign_id: str,
    batch_number: int,
    batch_size: int,
    organization_id: str,
):
    """
    Send a batch of phishing emails for a campaign.

    Executes in batches to control rate and server load. Each task
    sends batch_size emails and records delivery events.

    Args:
        campaign_id: Campaign ID
        batch_number: Batch sequence number
        batch_size: Number of emails in this batch
        organization_id: Organization context

    Returns:
        Batch delivery statistics
    """
    try:
        logger.info(
            f"Sending batch {batch_number} for campaign {campaign_id}",
            extra={
                "batch_size": batch_size,
                "organization_id": organization_id,
            },
        )

        # Simulate email batch sending
        now = datetime.now(timezone.utc)
        delivered = int(batch_size * 0.98)  # 98% delivery rate
        bounced = batch_size - delivered

        result = {
            "campaign_id": campaign_id,
            "batch_number": batch_number,
            "sent": batch_size,
            "delivered": delivered,
            "bounced": bounced,
            "delivery_rate": round((delivered / batch_size * 100), 2),
            "timestamp": now.isoformat(),
            "next_batch_delay_seconds": 3600,  # 1 hour between batches
        }

        logger.info(
            f"Batch {batch_number} sent for campaign {campaign_id}",
            extra=result,
        )

        return result

    except Exception as e:
        logger.error(f"Failed to send batch {batch_number} for campaign {campaign_id}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def training_reminder(
    self,
    user_email: str,
    training_module: str,
    organization_id: str,
):
    """
    Send training completion reminder to user.

    Reminds users with incomplete or overdue training assignments.
    Sent via email with deadline warning.

    Args:
        user_email: User email
        training_module: Training module name
        organization_id: Organization context

    Returns:
        Reminder send status
    """
    try:
        logger.info(
            f"Sending training reminder to {user_email}",
            extra={
                "module": training_module,
                "organization_id": organization_id,
            },
        )

        # Simulate email sending
        result = {
            "user_email": user_email,
            "training_module": training_module,
            "reminder_type": "overdue",
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "due_date": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
            "status": "sent",
        }

        logger.info(f"Training reminder sent to {user_email}")
        return result

    except Exception as e:
        logger.error(f"Failed to send training reminder to {user_email}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def monthly_awareness_report(
    self,
    organization_id: str,
    month: str = None,
    year: int = None,
):
    """
    Generate monthly security awareness report.

    Aggregates campaigns, user scores, training completion, and risk trends
    for the specified month. Sent to security leadership.

    Args:
        organization_id: Organization context
        month: Month (1-12), defaults to current month
        year: Year, defaults to current year

    Returns:
        Report generation status and summary
    """
    try:
        now = datetime.now(timezone.utc)
        report_month = month or now.month
        report_year = year or now.year

        logger.info(
            f"Generating monthly awareness report for org {organization_id}",
            extra={"month": report_month, "year": report_year},
        )

        # Simulate report generation
        result = {
            "organization_id": organization_id,
            "period": f"{report_year}-{report_month:02d}",
            "campaigns_executed": 8,
            "total_participants": 450,
            "avg_click_rate": 12.5,
            "avg_submission_rate": 3.2,
            "training_completed": 285,
            "training_completion_rate": 63.3,
            "high_risk_users": 45,
            "improvement_vs_last_month": 8.3,  # percent
            "generated_at": now.isoformat(),
            "status": "sent_to_leadership",
        }

        logger.info(
            f"Monthly report generated for org {organization_id}",
            extra={
                "campaigns": result["campaigns_executed"],
                "participants": result["total_participants"],
            },
        )

        return result

    except Exception as e:
        logger.error(f"Failed to generate monthly report for org {organization_id}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def risk_score_recalculation(
    self,
    organization_id: str,
    recalc_type: str = "all",
):
    """
    Recalculate security awareness risk scores.

    Recomputes user and department scores based on latest campaign results,
    training completion, and historical patterns. Identifies trending risks.

    Args:
        organization_id: Organization context
        recalc_type: "all" (all users), "high_risk" (only high-risk), "new" (new participants)

    Returns:
        Recalculation summary and changes
    """
    try:
        logger.info(
            f"Recalculating risk scores for org {organization_id}",
            extra={"type": recalc_type},
        )

        now = datetime.now(timezone.utc)

        # Simulate score recalculation
        result = {
            "organization_id": organization_id,
            "recalc_type": recalc_type,
            "users_processed": 450,
            "scores_improved": 125,
            "scores_declined": 85,
            "new_high_risk": 12,
            "new_critical_risk": 3,
            "avg_score_change": 2.5,  # points
            "recalculated_at": now.isoformat(),
            "next_recalc": (now + timedelta(days=7)).isoformat(),
            "status": "completed",
        }

        logger.info(
            f"Risk scores recalculated for org {organization_id}",
            extra={
                "improved": result["scores_improved"],
                "declined": result["scores_declined"],
            },
        )

        return result

    except Exception as e:
        logger.error(f"Failed to recalculate risk scores for org {organization_id}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))
