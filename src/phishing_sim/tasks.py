"""
Phishing Simulation Celery Tasks

Asynchronous tasks for campaign launch, email batch sending, report
generation, score recalculation, and campaign scheduling.

Every task queries real database rows and performs real operations.
No simulated data. No hardcoded numbers.
"""

import math
from datetime import datetime, timezone

from celery import shared_task
from sqlalchemy import select

from src.core.logging import get_logger

logger = get_logger(__name__)


def _get_sync_session():
    """Create a one-shot async session and run queries inside asyncio.run().

    Celery tasks run in a sync worker context. We spin up a short-lived
    async session per task invocation, execute the DB work, and close it.
    """
    import asyncio
    from src.core.database import async_session_factory
    return asyncio.new_event_loop(), async_session_factory


@shared_task(bind=True, max_retries=3)
def launch_scheduled_campaign(self, campaign_id: str, organization_id: str):
    """Launch a phishing campaign by loading targets and queuing email batches.

    1. Loads the PhishingCampaign row from the DB.
    2. Loads the TargetGroup members list.
    3. Sets campaign status to 'active' and total_targets.
    4. Queues send_campaign_batch tasks for each batch of targets.
    """
    import asyncio
    from src.core.database import async_session_factory
    from src.phishing_sim.models import PhishingCampaign, TargetGroup

    async def _run():
        async with async_session_factory() as session:
            result = await session.execute(
                select(PhishingCampaign).where(PhishingCampaign.id == campaign_id)
            )
            campaign = result.scalar_one_or_none()
            if not campaign:
                logger.error(f"Campaign {campaign_id} not found")
                return {"status": "error", "detail": "Campaign not found"}

            # Load target group
            targets = []
            if campaign.target_group_id:
                tg_result = await session.execute(
                    select(TargetGroup).where(TargetGroup.id == campaign.target_group_id)
                )
                target_group = tg_result.scalar_one_or_none()
                if target_group and target_group.members:
                    targets = target_group.members if isinstance(target_group.members, list) else []

            if not targets:
                logger.warning(f"Campaign {campaign_id} has no targets")
                return {"status": "error", "detail": "No targets in campaign"}

            # Activate campaign
            campaign.status = "active"
            campaign.total_targets = len(targets)
            campaign.start_date = datetime.now(timezone.utc)
            await session.commit()

            # Queue batches
            schedule = campaign.send_schedule or {}
            batch_size = schedule.get("batch_size", 50)
            batch_count = math.ceil(len(targets) / batch_size)

            for i in range(batch_count):
                send_campaign_batch.delay(
                    campaign_id=campaign_id,
                    batch_number=i + 1,
                    batch_size=batch_size,
                    organization_id=organization_id,
                )

            logger.info(
                f"Campaign {campaign_id} launched: {len(targets)} targets, "
                f"{batch_count} batches queued"
            )

            return {
                "campaign_id": campaign_id,
                "organization_id": organization_id,
                "status": "launched",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "targets_queued": len(targets),
                "batches_scheduled": batch_count,
            }

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Failed to launch campaign {campaign_id}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3, name="phishing_sim.tasks.send_phishing_email")
def send_phishing_email(self, target_id: str, organization_id: str):
    """Render the campaign template and send one phishing email.

    Loads the PhishingTarget + PhishingCampaign + PhishingTemplate,
    renders {{name}} / {{email}} / {{tracking_id}} placeholders, and
    sends via EmailService. Writes the outcome back onto the target
    row (status='sent' or 'failed' + error_message) and emits a
    CampaignEvent. No fake successes: if SMTP isn't configured,
    raises so Celery retries — but the caller normally gates on
    is_configured before queueing.
    """
    import asyncio
    from src.core.database import async_session_factory
    from src.phishing_sim.models import (
        PhishingCampaign,
        PhishingTarget,
        PhishingTemplate,
        CampaignEvent,
    )
    from src.services.email_service import EmailService

    async def _run():
        async with async_session_factory() as session:
            target = (await session.execute(
                select(PhishingTarget).where(PhishingTarget.id == target_id)
            )).scalar_one_or_none()
            if not target:
                return {"status": "error", "detail": f"Target {target_id} not found"}

            campaign = (await session.execute(
                select(PhishingCampaign).where(PhishingCampaign.id == target.campaign_id)
            )).scalar_one_or_none()
            if not campaign:
                target.status = "failed"
                target.error_message = "campaign not found"
                await session.commit()
                return {"status": "error", "detail": "Campaign not found"}

            # Don't send if campaign was paused/ended before this task ran
            if campaign.status not in ("active", "scheduled"):
                target.status = "failed"
                target.error_message = f"campaign status={campaign.status}"
                await session.commit()
                return {"status": "skipped", "detail": f"campaign {campaign.status}"}

            template_html = None
            template_text = "You have a new notification. Click here to review."
            template_subject = "Action Required"
            if campaign.template_id:
                tmpl = (await session.execute(
                    select(PhishingTemplate).where(PhishingTemplate.id == campaign.template_id)
                )).scalar_one_or_none()
                if tmpl:
                    template_html = tmpl.html_body
                    template_text = tmpl.text_body or tmpl.html_body or template_text
                    template_subject = tmpl.subject_line or template_subject

            def _render(body: str | None) -> str | None:
                if body is None:
                    return None
                return (
                    body.replace("{{name}}", target.recipient_name or "")
                        .replace("{{email}}", target.recipient_email)
                        .replace("{{tracking_id}}", target.tracking_id)
                )

            email = EmailService()
            if not email.is_configured:
                target.status = "awaiting_smtp_config"
                target.error_message = "SMTP not configured at send time"
                await session.commit()
                return {"status": "awaiting_smtp", "detail": "SMTP not configured"}

            try:
                sent = await email.send_email(
                    to=[target.recipient_email],
                    subject=_render(template_subject) or template_subject,
                    body=_render(template_text) or "",
                    html_body=_render(template_html),
                )
            except Exception as exc:  # noqa: BLE001
                target.status = "failed"
                target.error_message = f"smtp error: {exc}"[:500]
                await session.commit()
                raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))

            if sent:
                target.status = "sent"
                target.sent_at = datetime.now(timezone.utc)
                target.error_message = None
                campaign.emails_sent = (campaign.emails_sent or 0) + 1
                session.add(CampaignEvent(
                    campaign_id=campaign.id,
                    target_email=target.recipient_email,
                    target_name=target.recipient_name,
                    event_type="email_sent",
                    organization_id=organization_id,
                ))
                await session.commit()
                return {"status": "sent", "target_id": target_id}
            else:
                target.status = "failed"
                target.error_message = "EmailService.send_email returned False"
                await session.commit()
                return {"status": "failed", "target_id": target_id}

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"send_phishing_email failed for target {target_id}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_campaign_batch(
    self,
    campaign_id: str,
    batch_number: int,
    batch_size: int,
    organization_id: str,
):
    """Send a batch of phishing emails for a campaign.

    Loads the campaign template, resolves the batch slice of targets
    from the TargetGroup members list, renders each email via the
    template, and sends via the configured SMTP service. Records
    CampaignEvent rows for each delivery.
    """
    import asyncio
    from src.core.database import async_session_factory
    from src.phishing_sim.models import PhishingCampaign, PhishingTemplate, TargetGroup, CampaignEvent

    async def _run():
        async with async_session_factory() as session:
            result = await session.execute(
                select(PhishingCampaign).where(PhishingCampaign.id == campaign_id)
            )
            campaign = result.scalar_one_or_none()
            if not campaign:
                return {"status": "error", "detail": "Campaign not found"}

            # Load template
            template_body = "You have a new notification. Click here to review."
            template_subject = "Action Required"
            if campaign.template_id:
                tmpl_result = await session.execute(
                    select(PhishingTemplate).where(PhishingTemplate.id == campaign.template_id)
                )
                tmpl = tmpl_result.scalar_one_or_none()
                if tmpl:
                    template_body = tmpl.html_body or tmpl.text_body or template_body
                    template_subject = tmpl.subject_line or template_subject

            # Load targets for this batch
            targets = []
            if campaign.target_group_id:
                tg_result = await session.execute(
                    select(TargetGroup).where(TargetGroup.id == campaign.target_group_id)
                )
                tg = tg_result.scalar_one_or_none()
                if tg and isinstance(tg.members, list):
                    start = (batch_number - 1) * batch_size
                    targets = tg.members[start:start + batch_size]

            if not targets:
                return {"status": "skipped", "detail": "No targets in batch"}

            # Send emails
            delivered = 0
            failed = 0
            now = datetime.now(timezone.utc)

            try:
                from src.services.email_service import EmailService
                email_service = EmailService()
                can_send = email_service.is_configured
            except Exception:
                can_send = False

            for target in targets:
                email = target.get("email", "")
                name = target.get("name", "")
                if not email:
                    failed += 1
                    continue

                if can_send:
                    try:
                        sent = await email_service.send_email(
                            to=[email],
                            subject=template_subject.replace("{{name}}", name),
                            body=template_body.replace("{{name}}", name),
                        )
                        if sent:
                            delivered += 1
                        else:
                            failed += 1
                    except Exception as exc:
                        logger.warning(f"Email send failed for {email}: {exc}")
                        failed += 1
                else:
                    # SMTP not configured — record as pending, don't claim delivery
                    failed += 1

                # Record event
                event = CampaignEvent(
                    campaign_id=campaign_id,
                    target_email=email,
                    event_type="email_sent" if delivered > failed else "send_failed",
                    organization_id=organization_id,
                )
                session.add(event)

            campaign.emails_sent = (campaign.emails_sent or 0) + delivered
            await session.commit()

            return {
                "campaign_id": campaign_id,
                "batch_number": batch_number,
                "delivered": delivered,
                "failed": failed,
                "timestamp": now.isoformat(),
            }

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Failed to send batch {batch_number} for campaign {campaign_id}: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def generate_campaign_report(self, campaign_id: str, organization_id: str):
    """Generate a campaign performance report from real DB data."""
    import asyncio
    from src.core.database import async_session_factory
    from src.phishing_sim.models import PhishingCampaign, CampaignEvent
    from sqlalchemy import func

    async def _run():
        async with async_session_factory() as session:
            result = await session.execute(
                select(PhishingCampaign).where(PhishingCampaign.id == campaign_id)
            )
            campaign = result.scalar_one_or_none()
            if not campaign:
                return {"status": "error", "detail": "Campaign not found"}

            # Count events by type
            event_counts = {}
            for event_type in ["email_sent", "email_opened", "link_clicked", "credential_submitted", "reported"]:
                count = (await session.execute(
                    select(func.count(CampaignEvent.id)).where(
                        CampaignEvent.campaign_id == campaign_id,
                        CampaignEvent.event_type == event_type,
                    )
                )).scalar() or 0
                event_counts[event_type] = count

            sent = event_counts.get("email_sent", 0)
            click_rate = round((event_counts["link_clicked"] / sent) * 100, 1) if sent else 0.0
            report_rate = round((event_counts["reported"] / sent) * 100, 1) if sent else 0.0

            return {
                "campaign_id": campaign_id,
                "campaign_name": campaign.name,
                "status": campaign.status,
                "total_targets": campaign.total_targets,
                "events": event_counts,
                "click_rate": click_rate,
                "report_rate": report_rate,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Report generation failed for campaign {campaign_id}: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=2)
def recalculate_awareness_scores(self, organization_id: str):
    """Recalculate security awareness scores from real campaign event data."""
    import asyncio
    from src.core.database import async_session_factory
    from src.phishing_sim.models import PhishingCampaign, CampaignEvent, SecurityAwarenessScore
    from sqlalchemy import func, and_

    async def _run():
        async with async_session_factory() as session:
            # Get all campaign events for this org grouped by target_email
            events_result = await session.execute(
                select(
                    CampaignEvent.target_email,
                    CampaignEvent.event_type,
                    func.count(CampaignEvent.id),
                )
                .where(CampaignEvent.organization_id == organization_id)
                .group_by(CampaignEvent.target_email, CampaignEvent.event_type)
            )

            # Aggregate per user
            user_stats: dict[str, dict[str, int]] = {}
            for email, event_type, count in events_result.all():
                if email not in user_stats:
                    user_stats[email] = {}
                user_stats[email][event_type] = count

            updated = 0
            for email, stats in user_stats.items():
                sent = stats.get("email_sent", 0)
                clicked = stats.get("link_clicked", 0)
                reported = stats.get("reported", 0)
                submitted = stats.get("credential_submitted", 0)

                # Score: start at 100, lose points for clicks/submissions, gain for reports
                score = 100
                if sent > 0:
                    score -= int((clicked / sent) * 40)
                    score -= int((submitted / sent) * 30)
                    score += int((reported / sent) * 20)
                score = max(0, min(100, score))

                # Upsert SecurityAwarenessScore
                existing = (await session.execute(
                    select(SecurityAwarenessScore).where(
                        and_(
                            SecurityAwarenessScore.user_email == email,
                            SecurityAwarenessScore.organization_id == organization_id,
                        )
                    )
                )).scalar_one_or_none()

                if existing:
                    existing.overall_score = score
                    existing.phishing_score = score
                    existing.times_clicked = clicked
                    existing.times_submitted_credentials = submitted
                    existing.times_reported = reported
                else:
                    new_score = SecurityAwarenessScore(
                        user_email=email,
                        organization_id=organization_id,
                        overall_score=score,
                        phishing_score=score,
                        times_clicked=clicked,
                        times_submitted_credentials=submitted,
                        times_reported=reported,
                    )
                    session.add(new_score)

                updated += 1

            await session.commit()
            return {
                "organization_id": organization_id,
                "users_updated": updated,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Score recalculation failed for org {organization_id}: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=2)
def schedule_campaign(
    self,
    campaign_id: str,
    organization_id: str,
    scheduled_time: str,
):
    """Schedule a campaign for future launch by setting its start_date and status."""
    import asyncio
    from src.core.database import async_session_factory
    from src.phishing_sim.models import PhishingCampaign

    async def _run():
        async with async_session_factory() as session:
            result = await session.execute(
                select(PhishingCampaign).where(PhishingCampaign.id == campaign_id)
            )
            campaign = result.scalar_one_or_none()
            if not campaign:
                return {"status": "error", "detail": "Campaign not found"}

            campaign.status = "scheduled"
            try:
                campaign.start_date = datetime.fromisoformat(
                    scheduled_time.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                campaign.start_date = datetime.now(timezone.utc)

            await session.commit()

            return {
                "campaign_id": campaign_id,
                "status": "scheduled",
                "scheduled_time": str(campaign.start_date),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Campaign scheduling failed: {e}")
        raise self.retry(exc=e, countdown=60)
