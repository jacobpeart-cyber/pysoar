"""
REST API endpoints for Phishing Simulation & Security Awareness module.

FastAPI routes for managing campaigns, templates, events, awareness scores,
training, and generating dashboards with comprehensive security metrics.
"""

import re
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, get_current_active_user, require_role
from src.core.database import get_db
from src.core.logging import get_logger
from src.core.rate_limiter import _limiter
from src.models.user import User, UserRole
from src.phishing_sim.tracking import (
    TRANSPARENT_GIF,
    generate_tracking_token,
    public_base_url,
    tracking_urls,
)
from src.phishing_sim.models import (
    CampaignEvent,
    PhishingCampaign,
    PhishingTarget,
    PhishingTemplate,
    SecurityAwarenessScore,
    TargetGroup,
)
from src.schemas.phishing_sim import (
    CampaignDetailResponse,
    CampaignEventCreateRequest,
    CampaignEventResponse,
    CampaignLaunchRequest,
    CampaignMetrics,
    PhishingCampaignCreateRequest,
    PhishingCampaignResponse,
    PhishingCampaignUpdateRequest,
    PhishingTemplateCreateRequest,
    PhishingTemplateResponse,
    PhishingTemplateUpdateRequest,
    RenderedTemplate,
    RiskReport,
    SecurityAwarenessScoreResponse,
    TargetGroupCreateRequest,
    TargetGroupResponse,
    TargetGroupUpdateRequest,
    TemplateValidationResult,
    TrainingAssignmentRequest,
    TrainingCompletionRequest,
    TrainingCertificateResponse,
    TrainingModuleResponse,
    UserScoreCalculationRequest,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/phishing_sim", tags=["phishing_sim"])

# Role gates. Viewers are read-only; analysts run day-to-day campaign work;
# sending mail to real staff and issuing training certificates is admin-only.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminOnlyUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


def _not_implemented(detail: str) -> HTTPException:
    """Honest 501 for a route whose previous behaviour faked its result."""
    return HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"error": "not_implemented", "detail": detail},
    )


async def _require_campaign_refs_in_org(
    db: AsyncSession,
    org_id: str,
    template_id: str | None,
    target_group_id: str | None,
) -> None:
    """404 unless the referenced template / target group belong to ``org_id``.

    The send task loads the template by id alone, so a campaign must never
    point at another tenant's template or recipient list.
    """
    if template_id:
        found = await db.scalar(
            select(PhishingTemplate.id).where(
                PhishingTemplate.id == str(template_id),
                PhishingTemplate.organization_id == org_id,
            ),
        )
        if found is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    if target_group_id:
        found = await db.scalar(
            select(TargetGroup.id).where(
                TargetGroup.id == str(target_group_id),
                TargetGroup.organization_id == org_id,
            ),
        )
        if found is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target group not found")


# ============================================================================
# TEMPLATE ENDPOINTS
# ============================================================================


@router.post(
    "/templates",
    response_model=PhishingTemplateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_template(
    request: PhishingTemplateCreateRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Create a new phishing template."""
    template = PhishingTemplate(
        id=str(uuid_mod.uuid4()),
        name=request.name,
        description=request.description,
        category=request.category,
        difficulty=request.difficulty,
        subject_line=request.subject_line,
        sender_name=request.sender_name,
        sender_email=request.sender_email,
        html_body=request.html_body,
        text_body=request.text_body,
        landing_page_html=request.landing_page_html,
        has_attachment=request.has_attachment,
        attachment_name=request.attachment_name,
        indicators_of_phishing=request.indicators_of_phishing,
        training_content_on_fail=request.training_content_on_fail,
        language=request.language,
        is_seasonal=request.is_seasonal,
        usage_count=0,
        average_click_rate=0.0,
        organization_id=org_id,
    )

    db.add(template)
    await db.flush()

    logger.info(
        f"Created template: {request.name}",
        extra={
            "template_id": template.id,
            "user_id": current_user.id,
        },
    )

    return template


@router.get("/templates", response_model=list[PhishingTemplateResponse])
async def list_templates(
    db: DatabaseSession,
    org_id: OrganizationId,
    category: str | None = Query(None),
    difficulty: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all phishing templates with optional filtering."""
    query = select(PhishingTemplate).where(
        PhishingTemplate.organization_id == org_id
    )

    if category:
        query = query.where(PhishingTemplate.category == category)
    if difficulty:
        query = query.where(PhishingTemplate.difficulty == difficulty)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    templates = result.scalars().all()

    logger.info(
        "Listed templates",
        extra={"count": len(templates), "filters": {"category": category, "difficulty": difficulty}},
    )

    return templates


@router.get("/templates/{template_id}", response_model=PhishingTemplateResponse)
async def get_template(
    template_id: UUID,
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Get a specific phishing template."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == org_id,
        )
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found",
        )

    return template


@router.patch(
    "/templates/{template_id}",
    response_model=PhishingTemplateResponse,
)
async def update_template(
    template_id: UUID,
    request: PhishingTemplateUpdateRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Update a phishing template."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == org_id,
        )
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found",
        )

    update_data = request.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(template, field, value)

    await db.flush()

    logger.info(
        f"Updated template {template_id}",
        extra={"user_id": current_user.id},
    )

    return template


@router.post("/templates/{template_id}/render", response_model=RenderedTemplate)
async def render_template(
    template_id: UUID,
    target_data: dict[str, Any],
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Render template with personalized target data."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == org_id,
        )
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found",
        )

    # Render with simple placeholder substitution
    subject = template.subject_line
    html = template.html_body
    for key, value in target_data.items():
        subject = subject.replace(f"{{{{{key}}}}}", str(value))
        html = html.replace(f"{{{{{key}}}}}", str(value))

    logger.info(
        f"Rendered template {template_id}",
        extra={"target_count": 1},
    )

    return RenderedTemplate(
        subject_line=subject,
        html_body=html,
        sender_name=template.sender_name,
        sender_email=template.sender_email,
    )


@router.post(
    "/templates/{template_id}/validate",
    response_model=TemplateValidationResult,
)
async def validate_template(
    template_id: UUID,
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Validate template for rendering issues and broken links."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == org_id,
        )
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found",
        )

    issues: list[str] = []
    if not template.subject_line:
        issues.append("Missing subject line")
    if not template.html_body:
        issues.append("Missing HTML body")
    if not template.sender_email:
        issues.append("Missing sender email")

    # Find placeholders in the template
    placeholders = re.findall(r"\{\{(\w+)\}\}", template.html_body or "")
    links = len(re.findall(r"https?://", template.html_body or ""))

    logger.info(
        f"Validated template {template_id}",
        extra={"is_valid": len(issues) == 0},
    )

    return TemplateValidationResult(
        template_id=str(template_id),
        is_valid=len(issues) == 0,
        issues=issues,
        placeholders_found=placeholders,
        links_found=links,
    )


# ============================================================================
# TARGET GROUP ENDPOINTS
# ============================================================================


@router.post(
    "/target-groups",
    response_model=TargetGroupResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_target_group(
    request: TargetGroupCreateRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Create a new target group."""
    members_data = [m.model_dump() for m in request.members]
    group = TargetGroup(
        id=str(uuid_mod.uuid4()),
        name=request.name,
        description=request.description,
        department=request.department,
        members=members_data,
        member_count=len(request.members),
        risk_level="moderate_risk",
        avg_click_rate=0.0,
        campaigns_participated=0,
        last_campaign_date=None,
        organization_id=org_id,
    )

    db.add(group)
    await db.flush()

    logger.info(
        f"Created target group: {request.name}",
        extra={
            "organization_id": org_id,
            "member_count": len(request.members),
        },
    )

    return group


@router.get("/target-groups", response_model=list[TargetGroupResponse])
async def list_target_groups(
    db: DatabaseSession,
    org_id: OrganizationId,
    department: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all target groups."""
    query = select(TargetGroup).where(
        TargetGroup.organization_id == org_id
    )

    if department:
        query = query.where(TargetGroup.department == department)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    groups = result.scalars().all()

    return groups


@router.get("/target-groups/{group_id}", response_model=TargetGroupResponse)
async def get_target_group(
    group_id: UUID,
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Get a specific target group."""
    result = await db.execute(
        select(TargetGroup).where(
            TargetGroup.id == str(group_id),
            TargetGroup.organization_id == org_id,
        )
    )
    group = result.scalar_one_or_none()

    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target group not found",
        )

    return group


@router.patch("/target-groups/{group_id}", response_model=TargetGroupResponse)
async def update_target_group(
    group_id: UUID,
    request: TargetGroupUpdateRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Update a target group."""
    result = await db.execute(
        select(TargetGroup).where(
            TargetGroup.id == str(group_id),
            TargetGroup.organization_id == org_id,
        )
    )
    group = result.scalar_one_or_none()

    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target group not found",
        )

    update_data = request.model_dump(exclude_unset=True)
    if "members" in update_data:
        update_data["members"] = [
            m.model_dump() if hasattr(m, "model_dump") else m
            for m in update_data["members"]
        ]
        update_data["member_count"] = len(update_data["members"])

    for field, value in update_data.items():
        setattr(group, field, value)

    await db.flush()

    logger.info(
        f"Updated target group {group_id}",
        extra={"user_id": current_user.id},
    )

    return group


@router.delete("/target-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target_group(
    group_id: UUID,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Delete a target group."""
    result = await db.execute(
        select(TargetGroup).where(
            TargetGroup.id == str(group_id),
            TargetGroup.organization_id == org_id,
        )
    )
    group = result.scalar_one_or_none()

    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target group not found",
        )

    await db.delete(group)
    await db.flush()

    logger.info(
        f"Deleted target group {group_id}",
        extra={"user_id": current_user.id},
    )


# ============================================================================
# CAMPAIGN ENDPOINTS
# ============================================================================


@router.post(
    "/campaigns",
    response_model=PhishingCampaignResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_campaign(
    request: PhishingCampaignCreateRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Create a new phishing campaign in draft status."""
    await _require_campaign_refs_in_org(db, org_id, request.template_id, request.target_group_id)
    campaign = PhishingCampaign(
        id=str(uuid_mod.uuid4()),
        name=request.name,
        description=request.description,
        campaign_type=request.campaign_type,
        status="draft",
        template_id=request.template_id,
        target_group_id=request.target_group_id,
        send_schedule=request.send_schedule.model_dump(),
        difficulty_level=request.difficulty_level,
        start_date=None,
        end_date=None,
        total_targets=0,
        emails_sent=0,
        emails_opened=0,
        links_clicked=0,
        credentials_submitted=0,
        attachments_opened=0,
        reported_count=0,
        created_by=current_user.id,
        organization_id=org_id,
    )

    db.add(campaign)
    await db.flush()

    logger.info(
        f"Created campaign: {request.name}",
        extra={
            "campaign_id": campaign.id,
            "user_id": current_user.id,
        },
    )

    return campaign


@router.get("/campaigns", response_model=list[PhishingCampaignResponse])
async def list_campaigns(
    db: DatabaseSession,
    org_id: OrganizationId,
    status_filter: str | None = Query(None, alias="status"),
    campaign_type: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all campaigns with optional filtering."""
    query = select(PhishingCampaign).where(
        PhishingCampaign.organization_id == org_id
    )

    if status_filter:
        query = query.where(PhishingCampaign.status == status_filter)
    if campaign_type:
        query = query.where(PhishingCampaign.campaign_type == campaign_type)

    # Newest first so "latest campaign" views are deterministic (the query
    # previously had no ORDER BY, so the funnel's "latest" was whatever row
    # Postgres returned first).
    query = query.order_by(PhishingCampaign.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    campaigns = result.scalars().all()

    logger.info(
        "Listed campaigns",
        extra={
            "count": len(campaigns),
            "filters": {"status": status_filter, "type": campaign_type},
        },
    )

    return campaigns


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(
    campaign_id: UUID,
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Get campaign details with current metrics."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    # Calculate metrics from campaign data
    sent = max(campaign.emails_sent or 0, 1)
    open_rate = ((campaign.emails_opened or 0) / sent) * 100
    click_rate = ((campaign.links_clicked or 0) / sent) * 100
    submission_rate = ((campaign.credentials_submitted or 0) / sent) * 100
    report_rate = ((campaign.reported_count or 0) / sent) * 100
    attachment_rate = ((campaign.attachments_opened or 0) / sent) * 100
    vulnerability_index = (click_rate + submission_rate * 2) / 3
    security_score = max(0, 100 - vulnerability_index)

    duration_hours = 0.0
    if campaign.start_date and campaign.end_date:
        delta = campaign.end_date - campaign.start_date
        duration_hours = delta.total_seconds() / 3600
    elif campaign.start_date:
        delta = datetime.now(timezone.utc) - campaign.start_date
        duration_hours = delta.total_seconds() / 3600

    metrics = CampaignMetrics(
        open_rate=round(open_rate, 2),
        click_rate=round(click_rate, 2),
        submission_rate=round(submission_rate, 2),
        report_rate=round(report_rate, 2),
        attachment_open_rate=round(attachment_rate, 2),
        vulnerability_index=round(vulnerability_index, 2),
        security_score=round(security_score, 2),
        duration_hours=round(duration_hours, 2),
    )

    return CampaignDetailResponse(
        id=campaign.id,
        name=campaign.name,
        description=campaign.description,
        campaign_type=campaign.campaign_type,
        status=campaign.status,
        template_id=campaign.template_id,
        target_group_id=campaign.target_group_id,
        send_schedule=campaign.send_schedule,
        difficulty_level=campaign.difficulty_level,
        start_date=campaign.start_date,
        end_date=campaign.end_date,
        total_targets=campaign.total_targets,
        emails_sent=campaign.emails_sent,
        emails_opened=campaign.emails_opened,
        links_clicked=campaign.links_clicked,
        credentials_submitted=campaign.credentials_submitted,
        attachments_opened=campaign.attachments_opened,
        reported_count=campaign.reported_count,
        created_by=campaign.created_by,
        created_at=campaign.created_at,
        updated_at=campaign.updated_at,
        metrics=metrics,
    )


@router.patch(
    "/campaigns/{campaign_id}",
    response_model=PhishingCampaignResponse,
)
async def update_campaign(
    campaign_id: UUID,
    request: PhishingCampaignUpdateRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Update campaign configuration (only in draft status)."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if campaign.status != "draft":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only update campaigns in draft status",
        )

    update_data = request.model_dump(exclude_unset=True)
    await _require_campaign_refs_in_org(
        db, org_id, update_data.get("template_id"), update_data.get("target_group_id"),
    )
    if "send_schedule" in update_data and update_data["send_schedule"] is not None:
        schedule = update_data["send_schedule"]
        update_data["send_schedule"] = (
            schedule.model_dump() if hasattr(schedule, "model_dump") else schedule
        )

    for field, value in update_data.items():
        setattr(campaign, field, value)

    await db.flush()

    logger.info(
        f"Updated campaign {campaign_id}",
        extra={"user_id": current_user.id},
    )

    return campaign


@router.post("/campaigns/{campaign_id}/launch", response_model=dict[str, Any])
async def launch_campaign(
    campaign_id: UUID,
    request: CampaignLaunchRequest,
    db: DatabaseSession,
    current_user: AdminOnlyUser,
    org_id: OrganizationId,
):
    """Launch a campaign - materialize target rows and queue email sends.

    Previously this only flipped ``status='active'`` and returned — no
    emails, no target rows, no Celery queue. This version:

    1. Expands the campaign's TargetGroup members list into
       PhishingTarget rows (one per recipient) with unique tracking_ids.
    2. Checks the organisation's SMTP configuration via
       ``EmailService.for_organization`` (tenant settings, else the platform relay). If not configured, every target
       lands as ``awaiting_smtp_config`` and nothing is queued — honest.
    3. If SMTP is configured, queues one ``send_phishing_email`` Celery
       task per target and marks rows ``queued``.
    4. Sets ``total_targets`` to the real count (request.total_targets
       is ignored, as documented on the schema).
    """
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if campaign.status not in ("draft", "scheduled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot launch campaign in {campaign.status} status",
        )

    # 1. Load the target group + its members
    if not campaign.target_group_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Campaign has no target_group_id; attach a target group before launch",
        )

    tg_result = await db.execute(
        select(TargetGroup).where(
            TargetGroup.id == campaign.target_group_id,
            TargetGroup.organization_id == org_id,
        )
    )
    target_group = tg_result.scalar_one_or_none()
    if not target_group:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Campaign's target_group not found",
        )

    members = target_group.members if isinstance(target_group.members, list) else []
    # De-duplicate by email — TargetGroup.members is a JSON blob and may
    # contain dupes from manual edits.
    seen_emails: set[str] = set()
    clean_members: list[dict[str, Any]] = []
    for m in members:
        if not isinstance(m, dict):
            continue
        email = (m.get("email") or "").strip().lower()
        if not email or email in seen_emails:
            continue
        seen_emails.add(email)
        clean_members.append(m)

    if not clean_members:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target group has no usable members (need at least one with an email)",
        )

    # 2. Check SMTP configuration: tenant SMTP (Settings > SMTP), falling back to the platform relay.
    from src.services.email_service import EmailService

    smtp_configured = (await EmailService.for_organization(db, org_id)).is_configured
    target_status = "pending" if smtp_configured else "awaiting_smtp_config"

    # 3. Create PhishingTarget rows
    created_targets: list[PhishingTarget] = []
    for m in clean_members:
        pt = PhishingTarget(
            id=str(uuid_mod.uuid4()),
            campaign_id=str(campaign.id),
            recipient_email=m.get("email", "").strip(),
            recipient_name=m.get("name"),
            recipient_department=m.get("department") or target_group.department,
            status=target_status,
            tracking_id=str(uuid_mod.uuid4()),
            tracking_token=generate_tracking_token(),
            organization_id=org_id,
        )
        db.add(pt)
        created_targets.append(pt)

    await db.flush()

    # 4. Activate campaign with the real count (ignore request.total_targets)
    campaign.status = "active"
    campaign.total_targets = len(created_targets)
    campaign.start_date = datetime.now(timezone.utc)
    await db.flush()

    # 5. Queue Celery sends if SMTP is configured; otherwise be honest
    queued_for_send = 0
    if not smtp_configured:
        logger.warning(
            f"Campaign {campaign_id} launched without SMTP configured — "
            f"{len(created_targets)} targets staged as awaiting_smtp_config",
            extra={"campaign_id": str(campaign_id), "user_id": current_user.id},
        )
        await db.commit()
        return {
            "status": "active",
            "campaign_id": str(campaign_id),
            "targets_created": len(created_targets),
            "queued_for_send": 0,
            "awaiting_smtp": len(created_targets),
            "smtp_configured": False,
        }

    # Commit the targets before queuing — Celery workers in a different
    # process need to see the rows.
    await db.commit()

    try:
        from src.phishing_sim.tasks import send_phishing_email
        for pt in created_targets:
            try:
                async_result = send_phishing_email.delay(
                    target_id=pt.id,
                    organization_id=org_id,
                )
                pt.celery_task_id = async_result.id if async_result else None
                pt.status = "queued"
                queued_for_send += 1
            except Exception as exc:  # noqa: BLE001 — we want to know which ones failed
                logger.error(
                    f"Failed to queue send task for target {pt.id}: {exc}",
                    extra={"campaign_id": str(campaign_id)},
                )
                pt.status = "failed"
                pt.error_message = f"celery enqueue failed: {exc}"[:500]
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            f"Celery dispatch failed entirely for campaign {campaign_id}: {exc}",
            extra={"campaign_id": str(campaign_id)},
        )
        # Targets are already in DB as 'pending' — leave them that way so
        # a later retry can pick them up. Don't lie about queued count.

    logger.info(
        f"Launched campaign {campaign_id}: {len(created_targets)} targets, "
        f"{queued_for_send} queued for send",
        extra={
            "campaign_id": str(campaign_id),
            "targets_created": len(created_targets),
            "queued_for_send": queued_for_send,
            "user_id": current_user.id,
        },
    )

    return {
        "status": "active",
        "campaign_id": str(campaign_id),
        "targets_created": len(created_targets),
        "queued_for_send": queued_for_send,
        "awaiting_smtp": 0,
        "smtp_configured": True,
    }


@router.post("/campaigns/{campaign_id}/pause", response_model=dict[str, Any])
async def pause_campaign(
    campaign_id: UUID,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Pause an active campaign."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if campaign.status != "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only pause active campaigns",
        )

    campaign.status = "paused"
    await db.flush()

    logger.info(f"Paused campaign {campaign_id}", extra={"user_id": current_user.id})

    return {"status": "paused", "campaign_id": str(campaign_id)}


@router.post("/campaigns/{campaign_id}/resume", response_model=dict[str, Any])
async def resume_campaign(
    campaign_id: UUID,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Resume a paused campaign."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if campaign.status != "paused":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only resume paused campaigns",
        )

    campaign.status = "active"
    await db.flush()

    logger.info(f"Resumed campaign {campaign_id}", extra={"user_id": current_user.id})

    return {"status": "active", "campaign_id": str(campaign_id)}


@router.post("/campaigns/{campaign_id}/end", response_model=dict[str, Any])
async def end_campaign(
    campaign_id: UUID,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """End a campaign and calculate final metrics."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if campaign.status not in ("active", "paused"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only end active or paused campaigns",
        )

    campaign.status = "completed"
    campaign.end_date = datetime.now(timezone.utc)
    await db.flush()

    logger.info(f"Ended campaign {campaign_id}", extra={"user_id": current_user.id})

    return {"status": "completed", "campaign_id": str(campaign_id)}


@router.post(
    "/campaigns/{campaign_id}/clone", response_model=PhishingCampaignResponse
)
async def clone_campaign(
    campaign_id: UUID,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
    new_name: str = Query(...),
):
    """Clone an existing campaign."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    cloned = PhishingCampaign(
        id=str(uuid_mod.uuid4()),
        name=new_name,
        description=campaign.description,
        campaign_type=campaign.campaign_type,
        status="draft",
        template_id=campaign.template_id,
        target_group_id=campaign.target_group_id,
        send_schedule=campaign.send_schedule,
        difficulty_level=campaign.difficulty_level,
        start_date=None,
        end_date=None,
        total_targets=0,
        emails_sent=0,
        emails_opened=0,
        links_clicked=0,
        credentials_submitted=0,
        attachments_opened=0,
        reported_count=0,
        created_by=current_user.id,
        organization_id=org_id,
    )

    db.add(cloned)
    await db.flush()

    logger.info(
        f"Cloned campaign {campaign_id} to {cloned.id}",
        extra={"user_id": current_user.id},
    )

    return cloned


@router.get("/campaigns/{campaign_id}/results", response_model=dict[str, Any])
async def get_campaign_results(
    campaign_id: UUID,
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Get current campaign results and metrics."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == org_id,
        )
    )
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    sent = max(campaign.emails_sent or 0, 1)
    return {
        "campaign_id": str(campaign_id),
        "status": campaign.status,
        "total_targets": campaign.total_targets,
        "emails_sent": campaign.emails_sent,
        "emails_opened": campaign.emails_opened,
        "links_clicked": campaign.links_clicked,
        "credentials_submitted": campaign.credentials_submitted,
        "attachments_opened": campaign.attachments_opened,
        "reported_count": campaign.reported_count,
        "open_rate": round(((campaign.emails_opened or 0) / sent) * 100, 2),
        "click_rate": round(((campaign.links_clicked or 0) / sent) * 100, 2),
        "submission_rate": round(
            ((campaign.credentials_submitted or 0) / sent) * 100, 2
        ),
        "report_rate": round(((campaign.reported_count or 0) / sent) * 100, 2),
    }


# ============================================================================
# CAMPAIGN EVENT ENDPOINTS
# ============================================================================

# Counter field each event type increments on the campaign row.
_EVENT_COUNTER_MAP = {
    "email_sent": "emails_sent",
    "email_delivered": "emails_sent",
    "email_opened": "emails_opened",
    "link_clicked": "links_clicked",
    "credential_submitted": "credentials_submitted",
    "attachment_opened": "attachments_opened",
    "reported_as_phishing": "reported_count",
}
_FAILURE_EVENTS = {"link_clicked", "credential_submitted", "attachment_opened"}
_POSITIVE_EVENTS = {"reported_as_phishing"}

# Public tracking rate limit: a recipient's mail client may fetch the pixel a
# few times, but a burst per (token, IP) is throttled so a scanned token
# cannot flood events. Returning the same response when throttled keeps it
# from becoming an enumeration oracle.
_TRACK_RATE_MAX = 30
# Stored repeats of one event type per recipient from the public endpoints;
# beyond this nothing is written (the response is unchanged). Counters and
# awareness only ever move on the first event of a type per recipient.
_PUBLIC_EVENT_CAP = 5
_TRACK_RATE_WINDOW = 60


async def _ingest_campaign_event(
    db: AsyncSession,
    campaign: PhishingCampaign,
    *,
    target_email: str,
    target_name: str | None,
    event_type: str,
    org_id: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    geo_location: dict[str, Any] | None = None,
    device_type: str | None = None,
    time_to_action_seconds: int | None = None,
    public: bool = False,
) -> CampaignEvent | None:
    """Record one campaign event and roll it into counters + awareness.

    Campaign counters (``emails_opened``, ``links_clicked`` ...) count
    recipients, so they and the awareness score move only on the first event
    of a type per recipient; repeats are stored as evidence but never inflate
    a rate past 100 %. Public (unauthenticated) sources are capped at
    ``_PUBLIC_EVENT_CAP`` stored repeats per recipient and type, after which
    nothing is written and ``None`` is returned.

    The single code path for both the authenticated analyst route and the
    public tracking endpoints, so a hand-entered event and a real recipient
    open update the same rows the same way. No fake data: every call writes a
    real CampaignEvent and only moves awareness on real failure/report events.
    """
    prior = (
        await db.execute(
            select(func.count(CampaignEvent.id)).where(
                CampaignEvent.campaign_id == str(campaign.id),
                CampaignEvent.target_email == target_email,
                CampaignEvent.event_type == event_type,
            )
        )
    ).scalar_one() or 0
    if public and prior >= _PUBLIC_EVENT_CAP:
        return None
    first_of_type = prior == 0

    event = CampaignEvent(
        id=str(uuid_mod.uuid4()),
        campaign_id=str(campaign.id),
        target_email=target_email,
        target_name=target_name,
        event_type=event_type,
        event_timestamp=datetime.now(timezone.utc),
        ip_address=ip_address,
        user_agent=user_agent,
        geo_location=geo_location,
        device_type=device_type,
        time_to_action_seconds=time_to_action_seconds,
        organization_id=org_id,
    )
    db.add(event)

    counter_field = _EVENT_COUNTER_MAP.get(event_type)
    if counter_field and first_of_type:
        setattr(campaign, counter_field, getattr(campaign, counter_field, 0) + 1)

    await db.flush()

    if first_of_type and event_type in _FAILURE_EVENTS | _POSITIVE_EVENTS:
        try:
            awareness = (
                await db.execute(
                    select(SecurityAwarenessScore).where(
                        SecurityAwarenessScore.user_email == target_email,
                        SecurityAwarenessScore.organization_id == org_id,
                    )
                )
            ).scalar_one_or_none()

            if awareness is None:
                awareness = SecurityAwarenessScore(
                    id=str(uuid_mod.uuid4()),
                    user_email=target_email,
                    user_name=target_name or target_email,
                    overall_score=50,
                    phishing_score=50,
                    training_completion_rate=0.0,
                    campaigns_participated=1,
                    times_clicked=0,
                    times_reported=0,
                    times_submitted_credentials=0,
                    risk_category="moderate_risk",
                    training_assignments=[],
                    certifications=[],
                    organization_id=org_id,
                )
                db.add(awareness)

            if event_type == "link_clicked":
                awareness.times_clicked = (awareness.times_clicked or 0) + 1
                awareness.overall_score = max(0, (awareness.overall_score or 50) - 10)
                awareness.phishing_score = max(0, (awareness.phishing_score or 50) - 10)
                awareness.last_failed_campaign = datetime.now(timezone.utc)
            elif event_type == "credential_submitted":
                awareness.times_submitted_credentials = (awareness.times_submitted_credentials or 0) + 1
                awareness.times_clicked = (awareness.times_clicked or 0) + 1
                awareness.overall_score = max(0, (awareness.overall_score or 50) - 20)
                awareness.phishing_score = max(0, (awareness.phishing_score or 50) - 20)
                awareness.last_failed_campaign = datetime.now(timezone.utc)
            elif event_type == "attachment_opened":
                awareness.times_clicked = (awareness.times_clicked or 0) + 1
                awareness.overall_score = max(0, (awareness.overall_score or 50) - 15)
                awareness.phishing_score = max(0, (awareness.phishing_score or 50) - 15)
                awareness.last_failed_campaign = datetime.now(timezone.utc)
            elif event_type == "reported_as_phishing":
                awareness.times_reported = (awareness.times_reported or 0) + 1
                awareness.overall_score = min(100, (awareness.overall_score or 50) + 5)
                awareness.phishing_score = min(100, (awareness.phishing_score or 50) + 5)

            score = awareness.overall_score or 0
            if score >= 80:
                awareness.risk_category = "champion"
            elif score >= 60:
                awareness.risk_category = "low_risk"
            elif score >= 40:
                awareness.risk_category = "moderate_risk"
            elif score >= 20:
                awareness.risk_category = "high_risk"
            else:
                awareness.risk_category = "critical_risk"

            if score < 50 and event_type in _FAILURE_EVENTS:
                existing_assignments = awareness.training_assignments or []
                has_pending = any(
                    a.get("status") == "pending" for a in existing_assignments
                )
                if not has_pending:
                    awareness.training_assignments = existing_assignments + [{
                        "module": "phishing_awareness_remedial",
                        "status": "pending",
                        "assigned_at": datetime.now(timezone.utc).isoformat(),
                        "reason": f"Score dropped to {score} after {event_type}",
                    }]
                    logger.info(
                        f"Auto-assigned remedial training to {target_email} (score={score})"
                    )

            await db.flush()
        except Exception as exc:  # noqa: BLE001 — awareness update must not fail the event write
            logger.error(f"Failed to update awareness score for {target_email}: {exc}")

    return event


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _resolve_target_by_token(
    db: AsyncSession, token: str,
) -> tuple[PhishingTarget | None, PhishingCampaign | None]:
    """Resolve a tracking token to its target + campaign, or (None, None).

    Never raises for an unknown token: the public endpoints must behave
    identically for a valid and an invalid token so the token space cannot be
    probed.
    """
    target = (
        await db.execute(
            select(PhishingTarget).where(PhishingTarget.tracking_token == token)
        )
    ).scalar_one_or_none()
    if target is None:
        return None, None
    campaign = (
        await db.execute(
            select(PhishingCampaign).where(PhishingCampaign.id == target.campaign_id)
        )
    ).scalar_one_or_none()
    return target, campaign


def _track_allowed(token: str, request: Request) -> bool:
    key = f"phish-track:{token}:{_client_ip(request)}"
    allowed, _ = _limiter.check_rate_limit(key, _TRACK_RATE_MAX, _TRACK_RATE_WINDOW)
    return allowed


# ---------------------------------------------------------------------------
# Public tracking endpoints (no authentication; keyed by unguessable token)
# ---------------------------------------------------------------------------


@router.get("/t/{token}.gif")
async def track_open_pixel(token: str, request: Request, db: DatabaseSession) -> Response:
    """1x1 tracking pixel. Records an ``email_opened`` event for the token.

    Always returns the transparent GIF — for a valid token, an invalid token,
    or a throttled request — so it is not an enumeration oracle.
    """
    pixel = Response(content=TRANSPARENT_GIF, media_type="image/gif")
    pixel.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    if not _track_allowed(token, request):
        return pixel
    target, campaign = await _resolve_target_by_token(db, token)
    if target and campaign:
        await _ingest_campaign_event(
            db, campaign,
            target_email=target.recipient_email,
            target_name=target.recipient_name,
            event_type="email_opened",
            org_id=target.organization_id,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            public=True,
        )
        await db.commit()
    return pixel


@router.get("/c/{token}")
async def track_click_redirect(token: str, request: Request, db: DatabaseSession) -> RedirectResponse:
    """Record a ``link_clicked`` event, then redirect the recipient.

    Campaign templates store only ``landing_page_html`` (no external landing
    URL), so the redirect always goes to ``{PYSOAR_PUBLIC_URL}/phishing-awareness``;
    valid, unknown and throttled tokens receive the same response.
    """
    safe_default = f"{public_base_url()}/phishing-awareness"
    destination = safe_default
    if _track_allowed(token, request):
        target, campaign = await _resolve_target_by_token(db, token)
        if target and campaign:
            await _ingest_campaign_event(
                db, campaign,
                target_email=target.recipient_email,
                target_name=target.recipient_name,
                event_type="link_clicked",
                org_id=target.organization_id,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                public=True,
            )
            await db.commit()
    return RedirectResponse(url=destination, status_code=status.HTTP_302_FOUND)


@router.post("/r/{token}", status_code=status.HTTP_204_NO_CONTENT)
async def track_report(token: str, request: Request, db: DatabaseSession) -> Response:
    """Record a ``reported_as_phishing`` event (recipient used the report button).

    Returns 204 for valid, invalid and throttled tokens alike (no oracle).
    """
    if _track_allowed(token, request):
        target, campaign = await _resolve_target_by_token(db, token)
        if target and campaign:
            await _ingest_campaign_event(
                db, campaign,
                target_email=target.recipient_email,
                target_name=target.recipient_name,
                event_type="reported_as_phishing",
                org_id=target.organization_id,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                public=True,
            )
            await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/campaigns/{campaign_id}/events",
    response_model=CampaignEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def record_event(
    campaign_id: UUID,
    request: CampaignEventCreateRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Record a campaign event (email open, link click, credential submission, etc.)."""
    campaign = (
        await db.execute(
            select(PhishingCampaign).where(
                PhishingCampaign.id == str(campaign_id),
                PhishingCampaign.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    event = await _ingest_campaign_event(
        db, campaign,
        target_email=request.target_email,
        target_name=request.target_name,
        event_type=request.event_type,
        org_id=org_id,
        ip_address=request.ip_address,
        user_agent=request.user_agent,
        geo_location=request.geo_location,
        device_type=request.device_type,
        time_to_action_seconds=request.time_to_action_seconds,
    )

    logger.info(
        f"Recorded event: {request.event_type}",
        extra={"campaign_id": str(campaign_id), "email": request.target_email},
    )

    return event


@router.get(
    "/campaigns/{campaign_id}/events",
    response_model=list[CampaignEventResponse],
)
async def list_campaign_events(
    campaign_id: UUID,
    db: DatabaseSession,
    org_id: OrganizationId,
    event_type: str | None = Query(None),
    target_email: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """List events for a campaign."""
    query = select(CampaignEvent).where(
        CampaignEvent.campaign_id == str(campaign_id),
        CampaignEvent.organization_id == org_id,
    )

    if event_type:
        query = query.where(CampaignEvent.event_type == event_type)
    if target_email:
        query = query.where(CampaignEvent.target_email == target_email)

    query = (
        query.order_by(CampaignEvent.event_timestamp).offset(skip).limit(limit)
    )
    result = await db.execute(query)
    events = result.scalars().all()

    return events


@router.get(
    "/campaigns/{campaign_id}/events/timeline",
    response_model=list[dict[str, Any]],
)
async def get_event_timeline(
    campaign_id: UUID,
    db: DatabaseSession,
    org_id: OrganizationId,
    target_email: str | None = Query(None),
):
    """Get event timeline for campaign or specific target."""
    query = select(CampaignEvent).where(
        CampaignEvent.campaign_id == str(campaign_id),
        CampaignEvent.organization_id == org_id,
    )

    if target_email:
        query = query.where(CampaignEvent.target_email == target_email)

    query = query.order_by(CampaignEvent.event_timestamp)
    result = await db.execute(query)
    events = result.scalars().all()

    timeline = []
    for event in events:
        timeline.append(
            {
                "id": event.id,
                "event_type": event.event_type,
                "target_email": event.target_email,
                "target_name": event.target_name,
                "timestamp": event.event_timestamp.isoformat(),
                "ip_address": event.ip_address,
                "device_type": event.device_type,
                "time_to_action_seconds": event.time_to_action_seconds,
            }
        )

    return timeline


# ============================================================================
# AWARENESS SCORE ENDPOINTS
# ============================================================================


@router.get(
    "/awareness-scores",
    response_model=list[SecurityAwarenessScoreResponse],
)
async def list_awareness_scores(
    db: DatabaseSession,
    org_id: OrganizationId,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """List all awareness scores for the organization."""
    query = select(SecurityAwarenessScore).where(
        SecurityAwarenessScore.organization_id == org_id
    ).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get(
    "/awareness-scores/high-risk",
    response_model=list[SecurityAwarenessScoreResponse],
)
async def get_high_risk_users(
    db: DatabaseSession,
    org_id: OrganizationId,
    threshold: int = Query(40, ge=0, le=100),
):
    """Identify users with awareness scores below threshold.

    Registered before ``/awareness-scores/{user_email}`` so the literal
    "high-risk" segment is not captured as an email address (which 404'd).
    """
    result = await db.execute(
        select(SecurityAwarenessScore)
        .where(
            SecurityAwarenessScore.overall_score < threshold,
            SecurityAwarenessScore.organization_id == org_id,
        )
        .order_by(SecurityAwarenessScore.overall_score)
    )
    return result.scalars().all()


@router.get(
    "/awareness-scores/{user_email}",
    response_model=SecurityAwarenessScoreResponse,
)
async def get_user_awareness_score(
    user_email: str,
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Get security awareness score for a user."""
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == org_id,
        )
    )
    score = result.scalar_one_or_none()

    if not score:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User awareness score not found",
        )

    return score


@router.post(
    "/awareness-scores/{user_email}/calculate",
    response_model=SecurityAwarenessScoreResponse,
)
async def calculate_user_score(
    user_email: str,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
    request: UserScoreCalculationRequest | None = None,
    user_name: str = Query(...),
    department: str | None = Query(None),
):
    """Recalculate a user's awareness score from their recorded event history.

    ``request`` is accepted but ignored: the score is derived from the user's
    recorded ``CampaignEvent`` rows, not from caller-supplied counts.

    The score is derived from this user's own ``CampaignEvent`` rows in the
    organisation — not from counts supplied by the caller. Starting from 100,
    the clicked / credential-submitted rates subtract and the reported rate
    adds, so the number always reflects real recorded behaviour. A user with
    no recorded events yet 404s rather than inventing a baseline.
    """
    counts = dict(
        (
            await db.execute(
                select(CampaignEvent.event_type, func.count(CampaignEvent.id))
                .where(
                    CampaignEvent.target_email == user_email,
                    CampaignEvent.organization_id == org_id,
                )
                .group_by(CampaignEvent.event_type)
            )
        ).all()
    )
    if not counts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No recorded events for this user; cannot derive a score",
        )

    sent = int(counts.get("email_sent", 0) or counts.get("email_delivered", 0) or 0)
    clicked = int(counts.get("link_clicked", 0))
    submitted = int(counts.get("credential_submitted", 0))
    reported = int(counts.get("reported_as_phishing", 0))

    score = 100
    if sent > 0:
        score -= int((clicked / sent) * 40)
        score -= int((submitted / sent) * 30)
        score += int((reported / sent) * 20)
    else:
        # No delivery recorded but interactions exist: penalise per interaction.
        score -= clicked * 10 + submitted * 20
        score += reported * 5
    score = max(0, min(100, score))

    if score >= 80:
        risk = "champion"
    elif score >= 60:
        risk = "low_risk"
    elif score >= 40:
        risk = "moderate_risk"
    elif score >= 20:
        risk = "high_risk"
    else:
        risk = "critical_risk"

    awareness = (
        await db.execute(
            select(SecurityAwarenessScore).where(
                SecurityAwarenessScore.user_email == user_email,
                SecurityAwarenessScore.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if awareness is None:
        awareness = SecurityAwarenessScore(
            id=str(uuid_mod.uuid4()),
            user_email=user_email,
            user_name=user_name,
            department=department,
            training_completion_rate=0.0,
            campaigns_participated=0,
            training_assignments=[],
            certifications=[],
            organization_id=org_id,
        )
        db.add(awareness)
    awareness.overall_score = score
    awareness.phishing_score = score
    awareness.times_clicked = clicked
    awareness.times_submitted_credentials = submitted
    awareness.times_reported = reported
    awareness.risk_category = risk
    if department:
        awareness.department = department
    await db.flush()

    logger.info(
        f"Recalculated awareness score for {user_email} from events",
        extra={"score": score, "risk": risk, "user_id": current_user.id},
    )
    return awareness


@router.get(
    "/awareness-scores/department/{department}",
    response_model=dict[str, Any],
)
async def get_department_scores(
    department: str,
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Get aggregated scores for a department."""
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.department == department,
            SecurityAwarenessScore.organization_id == org_id,
        )
    )
    scores = result.scalars().all()

    if not scores:
        return {
            "department": department,
            "user_count": 0,
            "avg_score": 0.0,
            "avg_phishing_score": 0.0,
            "min_score": 0.0,
            "max_score": 0.0,
            "risk_distribution": {},
        }

    avg_score = sum(s.overall_score for s in scores) / len(scores)
    avg_phishing = sum(s.phishing_score for s in scores) / len(scores)
    min_score = min(s.overall_score for s in scores)
    max_score = max(s.overall_score for s in scores)

    risk_dist: dict[str, int] = {}
    for s in scores:
        risk_dist[s.risk_category] = risk_dist.get(s.risk_category, 0) + 1

    return {
        "department": department,
        "user_count": len(scores),
        "avg_score": round(avg_score, 2),
        "avg_phishing_score": round(avg_phishing, 2),
        "min_score": float(min_score),
        "max_score": float(max_score),
        "risk_distribution": risk_dist,
    }


# ============================================================================
# TRAINING ENDPOINTS
# ============================================================================

# Static training content (reference data, not per-tenant)
TRAINING_MODULES = {
    "phishing_basics": {
        "title": "Phishing Basics",
        "description": "Learn to identify common phishing attacks",
        "duration_minutes": 30,
        "modules": [
            "identifying_phishing_emails",
            "safe_link_practices",
            "reporting_suspicious_emails",
        ],
    },
    "advanced_threats": {
        "title": "Advanced Threat Recognition",
        "description": "Recognize sophisticated social engineering attacks",
        "duration_minutes": 45,
        "modules": [
            "spear_phishing",
            "business_email_compromise",
            "pretexting",
        ],
    },
    "password_security": {
        "title": "Password & Authentication Security",
        "description": "Best practices for password management and MFA",
        "duration_minutes": 20,
        "modules": [
            "password_best_practices",
            "mfa_setup",
            "credential_management",
        ],
    },
    "data_protection": {
        "title": "Data Protection Fundamentals",
        "description": "Understand data classification and handling procedures",
        "duration_minutes": 35,
        "modules": [
            "data_classification",
            "secure_file_sharing",
            "privacy_regulations",
        ],
    },
}


@router.get("/training/modules", response_model=list[TrainingModuleResponse])
async def list_training_modules(
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Training catalogue — not implemented (honest 501).

    Previously this returned a hardcoded dict of slug titles with no stored
    content, no per-tenant backing and no completion data, served without
    authentication. There is no training-content table to back a real
    catalogue, so the listing is an honest 501 rather than fake rows. Named
    module assignment / completion / certification still operate on the real
    SecurityAwarenessScore rows (admins assign a module name, users complete
    it, and a certificate is only issued for a completed module).
    """
    raise _not_implemented(
        "training catalogue is not backed by stored content; assign/track/"
        "certify operate on named modules recorded against the user instead",
    )


@router.post("/training/{user_email}/assign", response_model=dict[str, Any])
async def assign_training(
    user_email: str,
    request: TrainingAssignmentRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
    user_name: str = Query(...),
):
    """Assign training modules to a user."""
    # Find or create the user's awareness score record
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == org_id,
        )
    )
    score_record = result.scalar_one_or_none()

    if not score_record:
        score_record = SecurityAwarenessScore(
            id=str(uuid_mod.uuid4()),
            user_email=user_email,
            user_name=user_name,
            department=None,
            overall_score=50,
            phishing_score=50,
            training_completion_rate=0.0,
            campaigns_participated=0,
            times_clicked=0,
            times_reported=0,
            times_submitted_credentials=0,
            last_failed_campaign=None,
            risk_category="moderate_risk",
            training_assignments=[],
            certifications=[],
            organization_id=org_id,
        )
        db.add(score_record)

    # Add training assignments
    now = datetime.now(timezone.utc)
    new_assignments = []
    for module_name in request.module_names:
        new_assignments.append(
            {
                "module": module_name,
                "status": "assigned",
                "assigned_at": now.isoformat(),
                "completion_date": None,
                "reason": request.reason,
            }
        )

    existing = list(score_record.training_assignments or [])
    existing.extend(new_assignments)
    score_record.training_assignments = existing

    await db.flush()

    logger.info(
        f"Assigned training to {user_email}",
        extra={
            "modules": request.module_names,
            "reason": request.reason,
        },
    )

    return {
        "user_email": user_email,
        "assigned_modules": request.module_names,
        "reason": request.reason,
        "total_assignments": len(existing),
    }


@router.post(
    "/training/{user_email}/track-completion", response_model=dict[str, Any]
)
async def track_training_completion(
    user_email: str,
    request: TrainingCompletionRequest,
    db: DatabaseSession,
    current_user: AnalystUser,
    org_id: OrganizationId,
):
    """Track training module completion."""
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == org_id,
        )
    )
    score_record = result.scalar_one_or_none()

    if not score_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User awareness score not found",
        )

    now = datetime.now(timezone.utc)
    assignments = list(score_record.training_assignments or [])
    updated = False
    for assignment in assignments:
        if (
            assignment.get("module") == request.module_name
            and assignment.get("status") != "completed"
        ):
            assignment["status"] = "completed"
            assignment["completion_date"] = now.isoformat()
            assignment["completion_time_minutes"] = (
                request.completion_time_minutes
            )
            updated = True
            break

    if not updated:
        # Add as a completed assignment if not found
        assignments.append(
            {
                "module": request.module_name,
                "status": "completed",
                "completion_date": now.isoformat(),
                "completion_time_minutes": request.completion_time_minutes,
            }
        )

    score_record.training_assignments = assignments

    # Update training completion rate
    total = len(assignments)
    completed = len(
        [a for a in assignments if a.get("status") == "completed"]
    )
    score_record.training_completion_rate = round(
        (completed / max(total, 1)) * 100, 2
    )

    await db.flush()

    logger.info(
        f"Tracked training completion for {user_email}",
        extra={"module": request.module_name},
    )

    return {
        "user_email": user_email,
        "module": request.module_name,
        "status": "completed",
        "completion_time_minutes": request.completion_time_minutes,
        "training_completion_rate": score_record.training_completion_rate,
    }


@router.post(
    "/training/{user_email}/certificate",
    response_model=TrainingCertificateResponse,
)
async def generate_certificate(
    user_email: str,
    db: DatabaseSession,
    current_user: AdminOnlyUser,
    org_id: OrganizationId,
    training_module: str = Query(...),
    user_name: str = Query(...),
):
    """Generate training certificate."""
    # Verify user has a score record
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == org_id,
        )
    )
    score_record = result.scalar_one_or_none()

    if not score_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User awareness score not found",
        )

    # A certificate attests completion; refuse one for a module the user
    # has no completed training record for.
    completed_modules = {
        a.get("module")
        for a in (score_record.training_assignments or [])
        if isinstance(a, dict) and a.get("status") == "completed"
    }
    if training_module not in completed_modules:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Training module has not been completed by this user",
        )

    now = datetime.now(timezone.utc)
    valid_until = now + timedelta(days=365)

    cert_id = str(uuid_mod.uuid4())
    cert_number = f"CERT-{cert_id[:8].upper()}"

    # Add certification to user record
    certs = list(score_record.certifications or [])
    certs.append(
        {
            "name": training_module,
            "completed_at": now.isoformat(),
            "valid_until": valid_until.isoformat(),
        }
    )
    score_record.certifications = certs
    await db.flush()

    logger.info(
        f"Generated certificate for {user_email}",
        extra={"module": training_module},
    )

    return TrainingCertificateResponse(
        id=cert_id,
        user_email=user_email,
        user_name=user_name,
        module=training_module,
        issued_at=now,
        valid_until=valid_until,
        certificate_number=cert_number,
    )


# ============================================================================
# DASHBOARD & REPORTING ENDPOINTS
# ============================================================================


@router.get("/reports/risk", response_model=dict[str, Any])
async def get_risk_report(
    db: DatabaseSession,
    org_id: OrganizationId,
):
    """Generate comprehensive risk assessment report."""
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.organization_id == org_id
        )
    )
    users = result.scalars().all()

    if not users:
        return {
            "total_users": 0,
            "total_departments": 0,
            "avg_score": 0.0,
            "risk_distribution": {},
            "high_risk_users": [],
            "critical_risk_users": [],
            "top_departments": [],
        }

    risk_dist: dict[str, int] = {}
    departments: set[str] = set()
    high_risk_users = []
    critical_risk_users = []

    for u in users:
        risk_dist[u.risk_category] = (
            risk_dist.get(u.risk_category, 0) + 1
        )
        if u.department:
            departments.add(u.department)
        if u.risk_category == "high_risk":
            high_risk_users.append(u)
        elif u.risk_category == "critical_risk":
            critical_risk_users.append(u)

    avg_score = sum(u.overall_score for u in users) / len(users)

    return {
        "total_users": len(users),
        "total_departments": len(departments),
        "avg_score": round(avg_score, 2),
        "risk_distribution": risk_dist,
        "high_risk_users": high_risk_users,
        "critical_risk_users": critical_risk_users,
        "top_departments": [],
    }
