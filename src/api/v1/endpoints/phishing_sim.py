"""
REST API endpoints for Phishing Simulation & Security Awareness module.

FastAPI routes for managing campaigns, templates, events, awareness scores,
training, and generating dashboards with comprehensive security metrics.
"""

import re
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user
from src.core.database import get_db
from src.core.logging import get_logger
from src.phishing_sim.models import (
    CampaignEvent,
    PhishingCampaign,
    PhishingTemplate,
    SecurityAwarenessScore,
    TargetGroup,
)
from src.schemas.phishing_sim import (
    CampaignComparisonResponse,
    CampaignDetailResponse,
    CampaignEventCreateRequest,
    CampaignEventResponse,
    CampaignLaunchRequest,
    CampaignMetrics,
    CampaignScheduleRequest,
    DashboardResponse,
    DepartmentStats,
    IndustryBenchmark,
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
    TemplateEffectivenessResponse,
    TemplateValidationResult,
    TrainingAssignmentRequest,
    TrainingCompletionRequest,
    TrainingCertificateResponse,
    TrainingModuleResponse,
    UserScoreCalculationRequest,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/phishing_sim", tags=["phishing_sim"])


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
    current_user: CurrentUser,
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
        organization_id=getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
    category: str | None = Query(None),
    difficulty: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all phishing templates with optional filtering."""
    query = select(PhishingTemplate).where(
        PhishingTemplate.organization_id == getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser,
):
    """Get a specific phishing template."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Update a phishing template."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Render template with personalized target data."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Validate template for rendering issues and broken links."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == getattr(current_user, "organization_id", None),
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


@router.get(
    "/templates/{template_id}/effectiveness",
    response_model=TemplateEffectivenessResponse,
)
async def get_template_effectiveness(
    template_id: UUID,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get historical effectiveness metrics for a template."""
    result = await db.execute(
        select(PhishingTemplate).where(
            PhishingTemplate.id == str(template_id),
            PhishingTemplate.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found",
        )

    # Determine effectiveness rating based on click rate
    if template.average_click_rate >= 30:
        rating = "highly_effective"
    elif template.average_click_rate >= 15:
        rating = "effective"
    elif template.average_click_rate >= 5:
        rating = "moderate"
    else:
        rating = "low_effectiveness"

    return TemplateEffectivenessResponse(
        template_id=str(template_id),
        name=template.name,
        usage_count=template.usage_count,
        average_click_rate=template.average_click_rate,
        category=template.category,
        difficulty=template.difficulty,
        effectiveness_rating=rating,
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
    current_user: CurrentUser,
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
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(group)
    await db.flush()

    logger.info(
        f"Created target group: {request.name}",
        extra={
            "organization_id": getattr(current_user, "organization_id", None),
            "member_count": len(request.members),
        },
    )

    return group


@router.get("/target-groups", response_model=list[TargetGroupResponse])
async def list_target_groups(
    db: DatabaseSession,
    current_user: CurrentUser,
    department: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all target groups."""
    query = select(TargetGroup).where(
        TargetGroup.organization_id == getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser,
):
    """Get a specific target group."""
    result = await db.execute(
        select(TargetGroup).where(
            TargetGroup.id == str(group_id),
            TargetGroup.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Update a target group."""
    result = await db.execute(
        select(TargetGroup).where(
            TargetGroup.id == str(group_id),
            TargetGroup.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Delete a target group."""
    result = await db.execute(
        select(TargetGroup).where(
            TargetGroup.id == str(group_id),
            TargetGroup.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Create a new phishing campaign in draft status."""
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
        organization_id=getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
    status_filter: str | None = Query(None, alias="status"),
    campaign_type: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all campaigns with optional filtering."""
    query = select(PhishingCampaign).where(
        PhishingCampaign.organization_id == getattr(current_user, "organization_id", None)
    )

    if status_filter:
        query = query.where(PhishingCampaign.status == status_filter)
    if campaign_type:
        query = query.where(PhishingCampaign.campaign_type == campaign_type)

    query = query.offset(skip).limit(limit)
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
    current_user: CurrentUser,
):
    """Get campaign details with current metrics."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Update campaign configuration (only in draft status)."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Launch a campaign - begin email distribution."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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

    campaign.status = "active"
    campaign.total_targets = request.total_targets
    campaign.start_date = datetime.now(timezone.utc)
    await db.flush()

    logger.info(
        f"Launched campaign {campaign_id}",
        extra={
            "total_targets": request.total_targets,
            "user_id": current_user.id,
        },
    )

    return {
        "status": "active",
        "campaign_id": str(campaign_id),
        "total_targets": request.total_targets,
    }


@router.post("/campaigns/{campaign_id}/pause", response_model=dict[str, Any])
async def pause_campaign(
    campaign_id: UUID,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Pause an active campaign."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Resume a paused campaign."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """End a campaign and calculate final metrics."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
    new_name: str = Query(...),
):
    """Clone an existing campaign."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(cloned)
    await db.flush()

    logger.info(
        f"Cloned campaign {campaign_id} to {cloned.id}",
        extra={"user_id": current_user.id},
    )

    return cloned


@router.post("/campaigns/{campaign_id}/schedule", response_model=dict[str, Any])
async def schedule_campaign(
    campaign_id: UUID,
    request: CampaignScheduleRequest,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Schedule a campaign to launch at specific time."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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
            detail="Can only schedule campaigns in draft status",
        )

    campaign.status = "scheduled"
    campaign.start_date = request.start_time
    await db.flush()

    logger.info(
        f"Scheduled campaign {campaign_id}",
        extra={
            "start_time": request.start_time.isoformat(),
            "user_id": current_user.id,
        },
    )

    return {
        "status": "scheduled",
        "campaign_id": str(campaign_id),
        "start_time": request.start_time.isoformat(),
    }


@router.get("/campaigns/{campaign_id}/results", response_model=dict[str, Any])
async def get_campaign_results(
    campaign_id: UUID,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get current campaign results and metrics."""
    result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
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


@router.post(
    "/campaigns/{campaign_id}/events",
    response_model=CampaignEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def record_event(
    campaign_id: UUID,
    request: CampaignEventCreateRequest,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Record a campaign event (email open, link click, credential submission, etc.)."""
    # Verify campaign exists
    campaign_result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.id == str(campaign_id),
            PhishingCampaign.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    campaign = campaign_result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    event = CampaignEvent(
        id=str(uuid_mod.uuid4()),
        campaign_id=str(campaign_id),
        target_email=request.target_email,
        target_name=request.target_name,
        event_type=request.event_type,
        event_timestamp=datetime.now(timezone.utc),
        ip_address=request.ip_address,
        user_agent=request.user_agent,
        geo_location=request.geo_location,
        device_type=request.device_type,
        time_to_action_seconds=request.time_to_action_seconds,
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(event)

    # Update campaign counters based on event type
    event_counter_map = {
        "email_sent": "emails_sent",
        "email_delivered": "emails_sent",
        "email_opened": "emails_opened",
        "link_clicked": "links_clicked",
        "credential_submitted": "credentials_submitted",
        "attachment_opened": "attachments_opened",
        "reported_as_phishing": "reported_count",
    }
    counter_field = event_counter_map.get(request.event_type)
    if counter_field:
        current_val = getattr(campaign, counter_field, 0)
        setattr(campaign, counter_field, current_val + 1)

    await db.flush()

    # --- Auto-update Security Awareness Score on failure/report events ---
    _failure_events = {"link_clicked", "credential_submitted", "attachment_opened"}
    _positive_events = {"reported_as_phishing"}

    if request.event_type in _failure_events | _positive_events:
        try:
            score_result = await db.execute(
                select(SecurityAwarenessScore).where(
                    SecurityAwarenessScore.user_email == request.target_email,
                )
            )
            awareness = score_result.scalar_one_or_none()

            if awareness is None:
                # Create a new score record for this user
                awareness = SecurityAwarenessScore(
                    id=str(uuid_mod.uuid4()),
                    user_email=request.target_email,
                    user_name=request.target_name or request.target_email,
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
                    organization_id=getattr(current_user, "organization_id", None) or "",
                )
                db.add(awareness)

            if request.event_type == "link_clicked":
                awareness.times_clicked = (awareness.times_clicked or 0) + 1
                awareness.overall_score = max(0, (awareness.overall_score or 50) - 10)
                awareness.phishing_score = max(0, (awareness.phishing_score or 50) - 10)
                awareness.last_failed_campaign = datetime.now(timezone.utc)
            elif request.event_type == "credential_submitted":
                awareness.times_submitted_credentials = (awareness.times_submitted_credentials or 0) + 1
                awareness.times_clicked = (awareness.times_clicked or 0) + 1
                awareness.overall_score = max(0, (awareness.overall_score or 50) - 20)
                awareness.phishing_score = max(0, (awareness.phishing_score or 50) - 20)
                awareness.last_failed_campaign = datetime.now(timezone.utc)
            elif request.event_type == "attachment_opened":
                awareness.times_clicked = (awareness.times_clicked or 0) + 1
                awareness.overall_score = max(0, (awareness.overall_score or 50) - 15)
                awareness.phishing_score = max(0, (awareness.phishing_score or 50) - 15)
                awareness.last_failed_campaign = datetime.now(timezone.utc)
            elif request.event_type == "reported_as_phishing":
                awareness.times_reported = (awareness.times_reported or 0) + 1
                awareness.overall_score = min(100, (awareness.overall_score or 50) + 5)
                awareness.phishing_score = min(100, (awareness.phishing_score or 50) + 5)

            # Recalculate risk category based on overall score
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

            # Auto-assign training when score drops below 50
            if score < 50 and request.event_type in _failure_events:
                existing_assignments = awareness.training_assignments or []
                # Avoid duplicate pending assignments
                has_pending = any(
                    a.get("status") == "pending" for a in existing_assignments
                )
                if not has_pending:
                    new_assignment = {
                        "module": "phishing_awareness_remedial",
                        "status": "pending",
                        "assigned_at": datetime.now(timezone.utc).isoformat(),
                        "reason": f"Score dropped to {score} after {request.event_type}",
                    }
                    awareness.training_assignments = existing_assignments + [new_assignment]
                    logger.info(
                        f"Auto-assigned remedial training to {request.target_email} "
                        f"(score={score})"
                    )

            await db.flush()

            logger.info(
                f"Updated awareness score for {request.target_email}: "
                f"overall_score={awareness.overall_score}, "
                f"risk_category={awareness.risk_category}"
            )
        except Exception as exc:
            logger.error(
                f"Failed to update awareness score for {request.target_email}: {exc}"
            )

    logger.info(
        f"Recorded event: {request.event_type}",
        extra={
            "campaign_id": str(campaign_id),
            "email": request.target_email,
        },
    )

    return event


@router.get(
    "/campaigns/{campaign_id}/events",
    response_model=list[CampaignEventResponse],
)
async def list_campaign_events(
    campaign_id: UUID,
    db: DatabaseSession,
    current_user: CurrentUser,
    event_type: str | None = Query(None),
    target_email: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """List events for a campaign."""
    query = select(CampaignEvent).where(
        CampaignEvent.campaign_id == str(campaign_id),
        CampaignEvent.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
    target_email: str | None = Query(None),
):
    """Get event timeline for campaign or specific target."""
    query = select(CampaignEvent).where(
        CampaignEvent.campaign_id == str(campaign_id),
        CampaignEvent.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """List all awareness scores for the organization."""
    query = select(SecurityAwarenessScore).where(
        SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None)
    ).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get(
    "/awareness-scores/{user_email}",
    response_model=SecurityAwarenessScoreResponse,
)
async def get_user_awareness_score(
    user_email: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get security awareness score for a user."""
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None),
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
    request: UserScoreCalculationRequest,
    db: DatabaseSession,
    current_user: CurrentUser,
    user_name: str = Query(...),
    department: str | None = Query(None),
):
    """Calculate or recalculate user awareness score."""
    # Calculate the overall score
    total_actions = (
        request.reported
        + request.no_action
        + request.clicked
        + request.submitted_credentials
        + request.training_completed
    )
    if total_actions > 0:
        phishing_score = int(
            (request.reported * 100 + request.no_action * 70)
            / max(total_actions, 1)
        )
    else:
        phishing_score = 50

    training_bonus = min(request.training_completed * 5, 20)
    overall_score = min(100, max(0, phishing_score + training_bonus))

    # Determine risk category
    if overall_score >= 80:
        risk_category = "champion"
    elif overall_score >= 60:
        risk_category = "low_risk"
    elif overall_score >= 40:
        risk_category = "moderate_risk"
    elif overall_score >= 20:
        risk_category = "high_risk"
    else:
        risk_category = "critical_risk"

    campaigns_participated = (
        request.reported
        + request.no_action
        + request.clicked
        + request.submitted_credentials
    )
    training_rate = (
        (request.training_completed / max(campaigns_participated, 1)) * 100
    )

    # Check if score already exists - update or create
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    score_record = result.scalar_one_or_none()

    if score_record:
        score_record.overall_score = overall_score
        score_record.phishing_score = phishing_score
        score_record.training_completion_rate = round(training_rate, 2)
        score_record.campaigns_participated = campaigns_participated
        score_record.times_clicked = request.clicked
        score_record.times_reported = request.reported
        score_record.times_submitted_credentials = request.submitted_credentials
        score_record.risk_category = risk_category
        if request.clicked > 0 or request.submitted_credentials > 0:
            score_record.last_failed_campaign = datetime.now(timezone.utc)
    else:
        score_record = SecurityAwarenessScore(
            id=str(uuid_mod.uuid4()),
            user_email=user_email,
            user_name=user_name,
            department=department,
            overall_score=overall_score,
            phishing_score=phishing_score,
            training_completion_rate=round(training_rate, 2),
            campaigns_participated=campaigns_participated,
            times_clicked=request.clicked,
            times_reported=request.reported,
            times_submitted_credentials=request.submitted_credentials,
            last_failed_campaign=(
                datetime.now(timezone.utc)
                if (request.clicked > 0 or request.submitted_credentials > 0)
                else None
            ),
            risk_category=risk_category,
            training_assignments=[],
            certifications=[],
            organization_id=getattr(current_user, "organization_id", None),
        )
        db.add(score_record)

    await db.flush()

    logger.info(
        f"Calculated awareness score for {user_email}",
        extra={"score": overall_score},
    )

    return score_record


@router.get(
    "/awareness-scores/department/{department}",
    response_model=dict[str, Any],
)
async def get_department_scores(
    department: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get aggregated scores for a department."""
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.department == department,
            SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None),
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


@router.get(
    "/awareness-scores/high-risk",
    response_model=list[SecurityAwarenessScoreResponse],
)
async def get_high_risk_users(
    db: DatabaseSession,
    current_user: CurrentUser,
    threshold: int = Query(40, ge=0, le=100),
):
    """Identify users with awareness scores below threshold."""
    result = await db.execute(
        select(SecurityAwarenessScore)
        .where(
            SecurityAwarenessScore.overall_score < threshold,
            SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None),
        )
        .order_by(SecurityAwarenessScore.overall_score)
    )
    high_risk = result.scalars().all()

    return high_risk


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
async def list_training_modules(db: DatabaseSession):
    """Get available training modules."""
    modules = [
        TrainingModuleResponse(
            id=key,
            title=mod["title"],
            description=mod["description"],
            duration_minutes=mod["duration_minutes"],
            modules=mod["modules"],
        )
        for key, mod in TRAINING_MODULES.items()
    ]

    return modules


@router.post("/training/{user_email}/assign", response_model=dict[str, Any])
async def assign_training(
    user_email: str,
    request: TrainingAssignmentRequest,
    db: DatabaseSession,
    current_user: CurrentUser,
    user_name: str = Query(...),
):
    """Assign training modules to a user."""
    # Find or create the user's awareness score record
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None),
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
            organization_id=getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
):
    """Track training module completion."""
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser,
    training_module: str = Query(...),
    user_name: str = Query(...),
):
    """Generate training certificate."""
    # Verify user has a score record
    result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == user_email,
            SecurityAwarenessScore.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    score_record = result.scalar_one_or_none()

    if not score_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User awareness score not found",
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


@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Get comprehensive phishing simulation dashboard."""
    org_id = getattr(current_user, "organization_id", None)

    # Fetch all campaigns for this org
    campaign_result = await db.execute(
        select(PhishingCampaign).where(
            PhishingCampaign.organization_id == org_id
        )
    )
    campaigns = campaign_result.scalars().all()

    active = len([c for c in campaigns if c.status == "active"])
    completed = len([c for c in campaigns if c.status == "completed"])

    # Calculate average metrics
    click_rates = [
        (c.links_clicked / max(c.emails_sent, 1)) * 100
        for c in campaigns
        if c.emails_sent > 0
    ]
    avg_click = (
        sum(click_rates) / len(click_rates) if click_rates else 0.0
    )

    submission_rates = [
        (c.credentials_submitted / max(c.emails_sent, 1)) * 100
        for c in campaigns
        if c.emails_sent > 0
    ]
    avg_submission = (
        sum(submission_rates) / len(submission_rates)
        if submission_rates
        else 0.0
    )

    # Fetch awareness scores
    score_result = await db.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.organization_id == org_id
        )
    )
    users = score_result.scalars().all()

    high_risk = len([u for u in users if u.risk_category == "high_risk"])
    critical = len(
        [u for u in users if u.risk_category == "critical_risk"]
    )

    risk_dist = {
        cat: len([u for u in users if u.risk_category == cat])
        for cat in [
            "champion",
            "low_risk",
            "moderate_risk",
            "high_risk",
            "critical_risk",
        ]
    }

    # Build recent campaigns
    sorted_campaigns = sorted(
        campaigns, key=lambda c: c.created_at, reverse=True
    )[:5]
    recent = [
        CampaignComparisonResponse(
            campaign_id=c.id,
            campaign_name=c.name,
            status=c.status,
            click_rate=round(
                (c.links_clicked / max(c.emails_sent, 1)) * 100, 2
            ),
            submission_rate=round(
                (c.credentials_submitted / max(c.emails_sent, 1)) * 100, 2
            ),
            report_rate=round(
                (c.reported_count / max(c.emails_sent, 1)) * 100, 2
            ),
            difficulty_level=c.difficulty_level,
            target_count=c.total_targets,
        )
        for c in sorted_campaigns
    ]

    # Department stats
    departments: dict[str, list] = {}
    for u in users:
        dept = u.department or "Unknown"
        departments.setdefault(dept, []).append(u)

    dept_stats = []
    for dept_name, dept_users in departments.items():
        dept_risk: dict[str, int] = {}
        for u in dept_users:
            dept_risk[u.risk_category] = (
                dept_risk.get(u.risk_category, 0) + 1
            )
        dept_stats.append(
            DepartmentStats(
                department=dept_name,
                user_count=len(dept_users),
                avg_score=round(
                    sum(u.overall_score for u in dept_users)
                    / len(dept_users),
                    2,
                ),
                avg_phishing_score=round(
                    sum(u.phishing_score for u in dept_users)
                    / len(dept_users),
                    2,
                ),
                min_score=float(
                    min(u.overall_score for u in dept_users)
                ),
                max_score=float(
                    max(u.overall_score for u in dept_users)
                ),
                risk_distribution=dept_risk,
            )
        )

    # Industry benchmark (static comparison)
    org_click_rate = round(avg_click, 2)
    industry_avg = 18.0
    benchmark = IndustryBenchmark(
        organization_click_rate=org_click_rate,
        industry_average=industry_avg,
        vs_industry=(
            "below_average"
            if org_click_rate > industry_avg
            else "above_average"
        ),
        percentile=(
            "top_25"
            if org_click_rate < 10
            else (
                "top_50"
                if org_click_rate < 18
                else (
                    "bottom_50" if org_click_rate < 30 else "bottom_25"
                )
            )
        ),
    )

    return DashboardResponse(
        total_campaigns=len(campaigns),
        active_campaigns=active,
        completed_campaigns=completed,
        avg_click_rate=round(avg_click, 2),
        avg_submission_rate=round(avg_submission, 2),
        total_users_at_risk=high_risk + critical,
        high_risk_count=high_risk,
        critical_risk_count=critical,
        recent_campaigns=recent,
        department_stats=dept_stats,
        risk_distribution=risk_dist,
        industry_benchmark=benchmark,
    )


@router.get("/reports/risk", response_model=dict[str, Any])
async def get_risk_report(
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Generate comprehensive risk assessment report."""
    org_id = getattr(current_user, "organization_id", None)

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
