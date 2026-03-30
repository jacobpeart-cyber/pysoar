"""
REST API endpoints for Phishing Simulation & Security Awareness module.

FastAPI routes for managing campaigns, templates, events, awareness scores,
training, and generating dashboards with comprehensive security metrics.
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user
from src.core.logging import get_logger
from src.phishing_sim.engine import (
    AwarenessScorer,
    CampaignManager,
    EventTracker,
    TemplateEngine,
    TrainingManager,
)
from src.schemas.phishing_sim import (
    CampaignDetailResponse,
    CampaignEventCreateRequest,
    CampaignEventResponse,
    CampaignLaunchRequest,
    CampaignMetrics,
    CampaignScheduleRequest,
    DashboardResponse,
    IndustryBenchmark,
    PhishingCampaignCreateRequest,
    PhishingCampaignResponse,
    PhishingCampaignUpdateRequest,
    PhishingTemplateCreateRequest,
    PhishingTemplateResponse,
    PhishingTemplateUpdateRequest,
    RenderedTemplate,
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

# Engine instances
campaign_manager = CampaignManager()
template_engine = TemplateEngine()
event_tracker = EventTracker()
awareness_scorer = AwarenessScorer()
training_manager = TrainingManager()


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
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Create a new phishing template."""
    try:
        template = template_engine.create_template(
            name=request.name,
            category=request.category,
            difficulty=request.difficulty,
            subject_line=request.subject_line,
            sender_name=request.sender_name,
            sender_email=request.sender_email,
            html_body=request.html_body,
            landing_page_html=request.landing_page_html,
            indicators_of_phishing=request.indicators_of_phishing,
            organization_id=request.organization_id,
            description=request.description,
            text_body=request.text_body,
            has_attachment=request.has_attachment,
            attachment_name=request.attachment_name,
            training_content_on_fail=request.training_content_on_fail,
            language=request.language,
            is_seasonal=request.is_seasonal,
        )

        logger.info(
            f"Created template: {request.name}",
            extra={
                "template_id": template["id"],
                "user_id": current_user.id,
            },
        )

        return PhishingTemplateResponse(**template)

    except Exception as e:
        logger.error(f"Failed to create template: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/templates", response_model=list[PhishingTemplateResponse])
async def list_templates(
    db: AsyncSession = Depends(get_db),
    category: str | None = Query(None),
    difficulty: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all phishing templates with optional filtering."""
    try:
        templates = [t for t in template_engine.templates.values()]

        if category:
            templates = [t for t in templates if t["category"] == category]
        if difficulty:
            templates = [t for t in templates if t["difficulty"] == difficulty]

        templates = templates[skip : skip + limit]

        logger.info(
            "Listed templates",
            extra={"count": len(templates), "filters": {"category": category, "difficulty": difficulty}},
        )

        return [PhishingTemplateResponse(**t) for t in templates]

    except Exception as e:
        logger.error(f"Failed to list templates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve templates",
        )


@router.get("/templates/{template_id}", response_model=PhishingTemplateResponse)
async def get_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific phishing template."""
    try:
        template = template_engine.templates.get(str(template_id))
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Template not found",
            )

        return PhishingTemplateResponse(**template)

    except Exception as e:
        logger.error(f"Failed to get template {template_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Operation failed. Please try again or contact support.",
        )


@router.patch(
    "/templates/{template_id}",
    response_model=PhishingTemplateResponse,
)
async def update_template(
    template_id: UUID,
    request: PhishingTemplateUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Update a phishing template."""
    try:
        template = template_engine.templates.get(str(template_id))
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Template not found",
            )

        # Update fields
        update_data = request.model_dump(exclude_unset=True)
        template.update(update_data)

        logger.info(
            f"Updated template {template_id}",
            extra={"user_id": current_user.id},
        )

        return PhishingTemplateResponse(**template)

    except Exception as e:
        logger.error(f"Failed to update template {template_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/templates/{template_id}/render", response_model=RenderedTemplate)
async def render_template(
    template_id: UUID,
    target_data: dict[str, Any],
    db: AsyncSession = Depends(get_db),
):
    """Render template with personalized target data."""
    try:
        rendered = template_engine.render_template(str(template_id), target_data)

        logger.info(
            f"Rendered template {template_id}",
            extra={"target_count": 1},
        )

        return RenderedTemplate(**rendered)

    except Exception as e:
        logger.error(f"Failed to render template {template_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post(
    "/templates/{template_id}/validate",
    response_model=TemplateValidationResult,
)
async def validate_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Validate template for rendering issues and broken links."""
    try:
        result = template_engine.validate_template(str(template_id))

        logger.info(
            f"Validated template {template_id}",
            extra={"is_valid": result["is_valid"]},
        )

        return TemplateValidationResult(**result)

    except Exception as e:
        logger.error(f"Failed to validate template {template_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get(
    "/templates/{template_id}/effectiveness",
    response_model=TemplateEffectivenessResponse,
)
async def get_template_effectiveness(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get historical effectiveness metrics for a template."""
    try:
        effectiveness = template_engine.get_template_effectiveness(str(template_id))

        return TemplateEffectivenessResponse(**effectiveness)

    except Exception as e:
        logger.error(f"Failed to get template effectiveness {template_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
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
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Create a new target group."""
    try:
        logger.info(
            f"Created target group: {request.name}",
            extra={
                "organization_id": request.organization_id,
                "member_count": len(request.members),
            },
        )

        # In real implementation, would save to database
        return TargetGroupResponse(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            **request.model_dump(),
            member_count=len(request.members),
            risk_level="moderate_risk",
            avg_click_rate=0.0,
            campaigns_participated=0,
        )

    except Exception as e:
        logger.error(f"Failed to create target group: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/target-groups", response_model=list[TargetGroupResponse])
async def list_target_groups(
    db: AsyncSession = Depends(get_db),
    department: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all target groups."""
    try:
        # In real implementation, would query from database
        return []

    except Exception as e:
        logger.error(f"Failed to list target groups: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve target groups",
        )


@router.get("/target-groups/{group_id}", response_model=TargetGroupResponse)
async def get_target_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific target group."""
    try:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target group not found",
        )

    except Exception as e:
        logger.error(f"Failed to get target group {group_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Operation failed. Please try again or contact support.",
        )


@router.patch("/target-groups/{group_id}", response_model=TargetGroupResponse)
async def update_target_group(
    group_id: UUID,
    request: TargetGroupUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Update a target group."""
    try:
        logger.info(
            f"Updated target group {group_id}",
            extra={"user_id": current_user.id},
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target group not found",
        )

    except Exception as e:
        logger.error(f"Failed to update target group {group_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.delete("/target-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Delete a target group."""
    try:
        logger.info(
            f"Deleted target group {group_id}",
            extra={"user_id": current_user.id},
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target group not found",
        )

    except Exception as e:
        logger.error(f"Failed to delete target group {group_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
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
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Create a new phishing campaign in draft status."""
    try:
        campaign = campaign_manager.create_campaign(
            name=request.name,
            description=request.description or "",
            campaign_type=request.campaign_type,
            template_id=request.template_id or "",
            target_group_id=request.target_group_id or "",
            send_schedule=request.send_schedule.model_dump(),
            difficulty_level=request.difficulty_level,
            created_by=current_user.id,
            organization_id=request.organization_id,
        )

        logger.info(
            f"Created campaign: {request.name}",
            extra={
                "campaign_id": campaign["id"],
                "user_id": current_user.id,
            },
        )

        return PhishingCampaignResponse(**campaign)

    except Exception as e:
        logger.error(f"Failed to create campaign: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/campaigns", response_model=list[PhishingCampaignResponse])
async def list_campaigns(
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = Query(None, alias="status"),
    campaign_type: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all campaigns with optional filtering."""
    try:
        campaigns = list(campaign_manager.campaigns.values())

        if status_filter:
            campaigns = [c for c in campaigns if c["status"] == status_filter]
        if campaign_type:
            campaigns = [c for c in campaigns if c["campaign_type"] == campaign_type]

        campaigns = campaigns[skip : skip + limit]

        logger.info(
            "Listed campaigns",
            extra={
                "count": len(campaigns),
                "filters": {"status": status_filter, "type": campaign_type},
            },
        )

        return [PhishingCampaignResponse(**c) for c in campaigns]

    except Exception as e:
        logger.error(f"Failed to list campaigns: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve campaigns",
        )


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get campaign details with current metrics."""
    try:
        campaign = campaign_manager.campaigns.get(str(campaign_id))
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Campaign not found",
            )

        metrics = campaign_manager.calculate_campaign_metrics(str(campaign_id))

        detail = {**campaign, "metrics": CampaignMetrics(**metrics)}

        return CampaignDetailResponse(**detail)

    except Exception as e:
        logger.error(f"Failed to get campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Operation failed. Please try again or contact support.",
        )


@router.patch(
    "/campaigns/{campaign_id}",
    response_model=PhishingCampaignResponse,
)
async def update_campaign(
    campaign_id: UUID,
    request: PhishingCampaignUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Update campaign configuration (only in draft status)."""
    try:
        campaign = campaign_manager.campaigns.get(str(campaign_id))
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Campaign not found",
            )

        if campaign["status"] != "draft":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Can only update campaigns in draft status",
            )

        update_data = request.model_dump(exclude_unset=True)
        if "send_schedule" in update_data:
            update_data["send_schedule"] = update_data["send_schedule"].model_dump()

        campaign.update(update_data)

        logger.info(
            f"Updated campaign {campaign_id}",
            extra={"user_id": current_user.id},
        )

        return PhishingCampaignResponse(**campaign)

    except Exception as e:
        logger.error(f"Failed to update campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/campaigns/{campaign_id}/launch", response_model=dict[str, Any])
async def launch_campaign(
    campaign_id: UUID,
    request: CampaignLaunchRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Launch a campaign - begin email distribution."""
    try:
        result = campaign_manager.launch_campaign(str(campaign_id), request.total_targets)

        logger.info(
            f"Launched campaign {campaign_id}",
            extra={
                "total_targets": request.total_targets,
                "user_id": current_user.id,
            },
        )

        return result

    except Exception as e:
        logger.error(f"Failed to launch campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/campaigns/{campaign_id}/pause", response_model=dict[str, Any])
async def pause_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Pause an active campaign."""
    try:
        result = campaign_manager.pause_campaign(str(campaign_id))

        logger.info(f"Paused campaign {campaign_id}", extra={"user_id": current_user.id})

        return result

    except Exception as e:
        logger.error(f"Failed to pause campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/campaigns/{campaign_id}/resume", response_model=dict[str, Any])
async def resume_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Resume a paused campaign."""
    try:
        result = campaign_manager.resume_campaign(str(campaign_id))

        logger.info(f"Resumed campaign {campaign_id}", extra={"user_id": current_user.id})

        return result

    except Exception as e:
        logger.error(f"Failed to resume campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/campaigns/{campaign_id}/end", response_model=dict[str, Any])
async def end_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """End a campaign and calculate final metrics."""
    try:
        result = campaign_manager.end_campaign(str(campaign_id))

        logger.info(f"Ended campaign {campaign_id}", extra={"user_id": current_user.id})

        return result

    except Exception as e:
        logger.error(f"Failed to end campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/campaigns/{campaign_id}/clone", response_model=PhishingCampaignResponse)
async def clone_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    new_name: str = Query(...),
    current_user=Depends(get_current_user),
):
    """Clone an existing campaign."""
    try:
        cloned = campaign_manager.clone_campaign(
            str(campaign_id),
            new_name,
            current_user.id,
        )

        logger.info(
            f"Cloned campaign {campaign_id} to {cloned['id']}",
            extra={"user_id": current_user.id},
        )

        return PhishingCampaignResponse(**cloned)

    except Exception as e:
        logger.error(f"Failed to clone campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/campaigns/{campaign_id}/schedule", response_model=dict[str, Any])
async def schedule_campaign(
    campaign_id: UUID,
    request: CampaignScheduleRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Schedule a campaign to launch at specific time."""
    try:
        result = campaign_manager.schedule_campaign(str(campaign_id), request.start_time)

        logger.info(
            f"Scheduled campaign {campaign_id}",
            extra={
                "start_time": request.start_time.isoformat(),
                "user_id": current_user.id,
            },
        )

        return result

    except Exception as e:
        logger.error(f"Failed to schedule campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/campaigns/{campaign_id}/results", response_model=dict[str, Any])
async def get_campaign_results(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get current campaign results and metrics."""
    try:
        results = campaign_manager.get_campaign_results(str(campaign_id))

        return results

    except Exception as e:
        logger.error(f"Failed to get campaign results {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


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
    db: AsyncSession = Depends(get_db),
):
    """Record a campaign event (email open, link click, credential submission, etc.)."""
    try:
        event = event_tracker.record_event(
            str(campaign_id),
            request.target_email,
            request.event_type,
            target_name=request.target_name,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            geo_location=request.geo_location,
            device_type=request.device_type,
            time_to_action_seconds=request.time_to_action_seconds,
        )

        logger.info(
            f"Recorded event: {request.event_type}",
            extra={
                "campaign_id": campaign_id,
                "email": request.target_email,
            },
        )

        return CampaignEventResponse(**event)

    except Exception as e:
        logger.error(f"Failed to record event for campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/campaigns/{campaign_id}/events", response_model=list[CampaignEventResponse])
async def list_campaign_events(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    event_type: str | None = Query(None),
    target_email: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """List events for a campaign."""
    try:
        events = event_tracker.event_timeline.get(str(campaign_id), [])

        if event_type:
            events = [e for e in events if e["event_type"] == event_type]
        if target_email:
            events = [e for e in events if e["target_email"] == target_email]

        events = events[skip : skip + limit]

        return [CampaignEventResponse(**e) for e in events]

    except Exception as e:
        logger.error(f"Failed to list events for campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve events",
        )


@router.get("/campaigns/{campaign_id}/events/timeline", response_model=list[dict[str, Any]])
async def get_event_timeline(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    target_email: str | None = Query(None),
):
    """Get event timeline for campaign or specific target."""
    try:
        timeline = event_tracker.generate_event_timeline(str(campaign_id), target_email)

        return timeline

    except Exception as e:
        logger.error(f"Failed to get event timeline for campaign {campaign_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve timeline",
        )


# ============================================================================
# AWARENESS SCORE ENDPOINTS
# ============================================================================


@router.get(
    "/awareness-scores/{user_email}",
    response_model=SecurityAwarenessScoreResponse,
)
async def get_user_awareness_score(
    user_email: str,
    db: AsyncSession = Depends(get_db),
):
    """Get security awareness score for a user."""
    try:
        score = awareness_scorer.user_scores.get(user_email)
        if not score:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User awareness score not found",
            )

        return SecurityAwarenessScoreResponse(**score)

    except Exception as e:
        logger.error(f"Failed to get awareness score for {user_email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post(
    "/awareness-scores/{user_email}/calculate",
    response_model=SecurityAwarenessScoreResponse,
)
async def calculate_user_score(
    user_email: str,
    request: UserScoreCalculationRequest,
    db: AsyncSession = Depends(get_db),
    user_name: str = Query(...),
    department: str | None = Query(None),
):
    """Calculate or recalculate user awareness score."""
    try:
        score = awareness_scorer.calculate_user_score(
            user_email=user_email,
            user_name=user_name,
            reported=request.reported,
            no_action=request.no_action,
            clicked=request.clicked,
            submitted_credentials=request.submitted_credentials,
            training_completed=request.training_completed,
            department=department,
        )

        logger.info(
            f"Calculated awareness score for {user_email}",
            extra={"score": score["overall_score"]},
        )

        return SecurityAwarenessScoreResponse(**score)

    except Exception as e:
        logger.error(f"Failed to calculate score for {user_email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/awareness-scores/department/{department}", response_model=dict[str, Any])
async def get_department_scores(
    department: str,
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated scores for a department."""
    try:
        dept_stats = awareness_scorer.calculate_department_scores(department)

        return dept_stats

    except Exception as e:
        logger.error(f"Failed to get department scores for {department}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/awareness-scores/high-risk", response_model=list[SecurityAwarenessScoreResponse])
async def get_high_risk_users(
    db: AsyncSession = Depends(get_db),
    threshold: int = Query(40, ge=0, le=100),
):
    """Identify users with awareness scores below threshold."""
    try:
        high_risk = awareness_scorer.identify_high_risk_users(threshold)

        return [SecurityAwarenessScoreResponse(**u) for u in high_risk]

    except Exception as e:
        logger.error(f"Failed to identify high-risk users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Operation failed. Please try again or contact support.",
        )


# ============================================================================
# TRAINING ENDPOINTS
# ============================================================================


@router.get("/training/modules", response_model=list[TrainingModuleResponse])
async def list_training_modules(db: AsyncSession = Depends(get_db)):
    """Get available training modules."""
    try:
        modules = [
            TrainingModuleResponse(
                id=key,
                title=mod["title"],
                description=mod["description"],
                duration_minutes=mod["duration_minutes"],
                modules=mod["modules"],
            )
            for key, mod in training_manager.training_content.items()
        ]

        return modules

    except Exception as e:
        logger.error(f"Failed to list training modules: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve modules",
        )


@router.post("/training/{user_email}/assign", response_model=dict[str, Any])
async def assign_training(
    user_email: str,
    request: TrainingAssignmentRequest,
    db: AsyncSession = Depends(get_db),
    user_name: str = Query(...),
    current_user=Depends(get_current_user),
):
    """Assign training modules to a user."""
    try:
        assignment = training_manager.assign_training(
            user_email,
            user_name,
            request.module_names,
            request.reason,
        )

        logger.info(
            f"Assigned training to {user_email}",
            extra={
                "modules": request.module_names,
                "reason": request.reason,
            },
        )

        return assignment

    except Exception as e:
        logger.error(f"Failed to assign training to {user_email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post("/training/{user_email}/track-completion", response_model=dict[str, Any])
async def track_training_completion(
    user_email: str,
    request: TrainingCompletionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Track training module completion."""
    try:
        assignment = training_manager.track_completion(
            user_email,
            request.module_name,
            request.completion_time_minutes,
        )

        logger.info(
            f"Tracked training completion for {user_email}",
            extra={"module": request.module_name},
        )

        return assignment

    except Exception as e:
        logger.error(f"Failed to track completion for {user_email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.post(
    "/training/{user_email}/certificate",
    response_model=TrainingCertificateResponse,
)
async def generate_certificate(
    user_email: str,
    db: AsyncSession = Depends(get_db),
    training_module: str = Query(...),
    user_name: str = Query(...),
):
    """Generate training certificate."""
    try:
        cert = training_manager.generate_certificate(user_email, user_name, training_module)

        logger.info(
            f"Generated certificate for {user_email}",
            extra={"module": training_module},
        )

        return TrainingCertificateResponse(**cert)

    except Exception as e:
        logger.error(f"Failed to generate certificate for {user_email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


# ============================================================================
# DASHBOARD & REPORTING ENDPOINTS
# ============================================================================


@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
):
    """Get comprehensive phishing simulation dashboard."""
    try:
        campaigns = list(campaign_manager.campaigns.values())
        active = len([c for c in campaigns if c["status"] == "active"])
        completed = len([c for c in campaigns if c["status"] == "completed"])

        # Calculate average metrics
        click_rates = [
            c["links_clicked"] / max(c["emails_sent"], 1) * 100
            for c in campaigns
            if c["emails_sent"] > 0
        ]
        avg_click = sum(click_rates) / len(click_rates) if click_rates else 0

        submission_rates = [
            c["credentials_submitted"] / max(c["emails_sent"], 1) * 100
            for c in campaigns
            if c["emails_sent"] > 0
        ]
        avg_submission = sum(submission_rates) / len(submission_rates) if submission_rates else 0

        users = list(awareness_scorer.user_scores.values())
        high_risk = len([u for u in users if u["risk_category"] == "high_risk"])
        critical = len([u for u in users if u["risk_category"] == "critical_risk"])

        risk_dist = {
            cat: len([u for u in users if u["risk_category"] == cat])
            for cat in ["champion", "low_risk", "moderate_risk", "high_risk", "critical_risk"]
        }

        benchmark = awareness_scorer.benchmark_against_industry()

        dashboard = {
            "total_campaigns": len(campaigns),
            "active_campaigns": active,
            "completed_campaigns": completed,
            "avg_click_rate": round(avg_click, 2),
            "avg_submission_rate": round(avg_submission, 2),
            "total_users_at_risk": high_risk + critical,
            "high_risk_count": high_risk,
            "critical_risk_count": critical,
            "recent_campaigns": [
                {
                    "campaign_id": c["id"],
                    "campaign_name": c["name"],
                    "status": c["status"],
                    "click_rate": c["links_clicked"] / max(c["emails_sent"], 1) * 100,
                    "submission_rate": c["credentials_submitted"] / max(c["emails_sent"], 1) * 100,
                    "report_rate": c["reported_count"] / max(c["emails_sent"], 1) * 100,
                    "difficulty_level": c["difficulty_level"],
                    "target_count": c["total_targets"],
                }
                for c in sorted(campaigns, key=lambda x: x["created_at"], reverse=True)[:5]
            ],
            "department_stats": [],
            "risk_distribution": risk_dist,
            "industry_benchmark": IndustryBenchmark(**benchmark),
        }

        return DashboardResponse(**dashboard)

    except Exception as e:
        logger.error(f"Failed to get dashboard: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard data",
        )


@router.get("/reports/risk", response_model=dict[str, Any])
async def get_risk_report(db: AsyncSession = Depends(get_db)):
    """Generate comprehensive risk assessment report."""
    try:
        report = awareness_scorer.generate_risk_report()

        return report

    except Exception as e:
        logger.error(f"Failed to generate risk report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate report",
        )
