"""
REST API endpoints for Deception Technology module.

FastAPI routes for deploying, managing, and monitoring deception infrastructure.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user
from src.core.database import get_db
from src.core.logging import get_logger
from src.deception.models import (
    Decoy,
    DecoyInteraction,
    DeceptionCampaign,
    HoneyToken,
)
from src.schemas.deception import (
    CampaignEffectivenessResponse,
    CampaignStatusUpdateRequest,
    CoverageMapResponse,
    CoverageZoneInfo,
    DeceptionCampaignCreateRequest,
    DeceptionCampaignDetailResponse,
    DeceptionCampaignResponse,
    DeceptionDashboardResponse,
    DeceptionDashboardStats,
    DecoyDeployRequest,
    DecoyDetailResponse,
    DecoyInteractionResponse,
    DecoyResponse,
    HoneyTokenCheckResponse,
    HoneyTokenGenerateRequest,
    HoneyTokenGenerateResponse,
    HoneyTokenResponse,
    InteractionAnalysisResponse,
    InteractionInvestigationRequest,
    InteractionInvestigationResponse,
    InteractionTimelineEntry,
    InteractionTimelineResponse,
    RecommendationsResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/deception", tags=["deception"])


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


async def get_decoy_or_404(db: AsyncSession, decoy_id: UUID) -> Decoy:
    """Get decoy by ID or raise 404."""
    result = await db.execute(
        select(Decoy).where(Decoy.id == str(decoy_id))
    )
    decoy = result.scalar_one_or_none()
    if not decoy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Decoy not found",
        )
    return decoy


async def get_token_or_404(db: AsyncSession, token_id: UUID) -> HoneyToken:
    """Get honey token by ID or raise 404."""
    result = await db.execute(
        select(HoneyToken).where(HoneyToken.id == str(token_id))
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found",
        )
    return token


async def get_interaction_or_404(
    db: AsyncSession, interaction_id: UUID
) -> DecoyInteraction:
    """Get interaction by ID or raise 404."""
    result = await db.execute(
        select(DecoyInteraction).where(
            DecoyInteraction.id == str(interaction_id)
        )
    )
    interaction = result.scalar_one_or_none()
    if not interaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Interaction not found",
        )
    return interaction


async def get_campaign_or_404(
    db: AsyncSession, campaign_id: UUID
) -> DeceptionCampaign:
    """Get campaign by ID or raise 404."""
    result = await db.execute(
        select(DeceptionCampaign).where(
            DeceptionCampaign.id == str(campaign_id)
        )
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )
    return campaign


# ============================================================================
# DECOY ENDPOINTS
# ============================================================================


@router.post(
    "/decoys",
    response_model=DecoyResponse,
    status_code=status.HTTP_201_CREATED,
)
async def deploy_decoy(
    request: DecoyDeployRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Deploy a new decoy asset."""
    try:
        data = request.model_dump()
        user_id = str(getattr(current_user, 'id', '')) if current_user else ''
        data["deployed_by"] = data.get("deployed_by") or user_id
        data["deployed_at"] = datetime.utcnow()
        data["status"] = "active"

        decoy = Decoy(**data)
        db.add(decoy)
        await db.flush()
        await db.refresh(decoy)

        logger.info(
            f"Deployed decoy: {decoy.name}",
            extra={
                "decoy_id": decoy.id,
                "decoy_type": decoy.decoy_type,
                "user_id": str(getattr(current_user, 'id', '')) if current_user else '',
            },
        )

        return DecoyResponse.model_validate(decoy)

    except Exception as e:
        logger.error(f"Failed to deploy decoy: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Operation failed: {str(e)[:200]}",
        )


@router.get("/decoys", response_model=list[DecoyResponse])
async def list_decoys(
    db: DatabaseSession = None,
    decoy_type: str | None = Query(None),
    decoy_status: str | None = Query(None, alias="status"),
    category: str | None = Query(None),
    organization_id: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all decoys with optional filtering."""
    try:
        query = select(Decoy)

        filters = []
        if decoy_type:
            filters.append(Decoy.decoy_type == decoy_type)
        if decoy_status:
            filters.append(Decoy.status == decoy_status)
        if category:
            filters.append(Decoy.category == category)
        if organization_id:
            filters.append(Decoy.organization_id == organization_id)

        if filters:
            query = query.where(and_(*filters))

        query = query.order_by(Decoy.created_at.desc()).offset(skip).limit(limit)

        result = await db.execute(query)
        decoys = list(result.scalars().all())

        logger.info(
            "Listed decoys",
            extra={
                "filters": {
                    "type": decoy_type,
                    "status": decoy_status,
                    "category": category,
                },
                "count": len(decoys),
            },
        )

        return [DecoyResponse.model_validate(d) for d in decoys]

    except Exception as e:
        logger.error(f"Failed to list decoys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve decoys",
        )


@router.get("/decoys/{decoy_id}", response_model=DecoyDetailResponse)
async def get_decoy_detail(
    decoy_id: UUID,
    db: DatabaseSession = None,
):
    """Get detailed information about a specific decoy."""
    try:
        decoy = await get_decoy_or_404(db, decoy_id)

        # Fetch recent interactions for this decoy
        interactions_result = await db.execute(
            select(DecoyInteraction)
            .where(DecoyInteraction.decoy_id == str(decoy_id))
            .order_by(DecoyInteraction.created_at.desc())
            .limit(20)
        )
        interactions = list(interactions_result.scalars().all())

        logger.info(
            f"Retrieved decoy detail: {decoy_id}",
            extra={
                "decoy_id": str(decoy_id),
                "interaction_count": len(interactions),
            },
        )

        decoy_dict = {
            c.name: getattr(decoy, c.name) for c in decoy.__table__.columns
        }
        decoy_dict["recent_interactions"] = [
            DecoyInteractionResponse.model_validate(i) for i in interactions
        ]

        return DecoyDetailResponse.model_validate(decoy_dict)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get decoy detail: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve decoy",
        )


@router.put("/decoys/{decoy_id}", response_model=DecoyResponse)
async def update_decoy(
    decoy_id: UUID,
    request: DecoyDeployRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update decoy configuration."""
    try:
        decoy = await get_decoy_or_404(db, decoy_id)

        update_data = request.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(decoy, key, value)

        await db.flush()
        await db.refresh(decoy)

        logger.info(
            f"Updated decoy: {decoy_id}",
            extra={"decoy_id": str(decoy_id), "user_id": str(getattr(current_user, 'id', '')) if current_user else ''},
        )

        return DecoyResponse.model_validate(decoy)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update decoy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update decoy",
        )


@router.post("/decoys/{decoy_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_decoy(
    decoy_id: UUID,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Disable a decoy."""
    try:
        decoy = await get_decoy_or_404(db, decoy_id)
        decoy.status = "disabled"

        await db.flush()

        logger.info(
            f"Disabled decoy: {decoy_id}",
            extra={"decoy_id": str(decoy_id), "user_id": str(getattr(current_user, 'id', '')) if current_user else ''},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable decoy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable decoy",
        )


@router.post("/decoys/{decoy_id}/rotate", response_model=DecoyResponse)
async def rotate_decoy(
    decoy_id: UUID,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Rotate/refresh a decoy to avoid fingerprinting."""
    try:
        decoy = await get_decoy_or_404(db, decoy_id)

        decoy.status = "active"
        decoy.deployed_at = datetime.now(timezone.utc)
        decoy.interaction_count = 0

        await db.flush()
        await db.refresh(decoy)

        logger.info(
            f"Rotated decoy: {decoy_id}",
            extra={"decoy_id": str(decoy_id), "user_id": str(getattr(current_user, 'id', '')) if current_user else ''},
        )

        return DecoyResponse.model_validate(decoy)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to rotate decoy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate decoy",
        )


@router.delete("/decoys/{decoy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def undeploy_decoy(
    decoy_id: UUID,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Undeploy and delete a decoy."""
    try:
        decoy = await get_decoy_or_404(db, decoy_id)
        await db.delete(decoy)
        await db.flush()

        logger.info(
            f"Undeployed decoy: {decoy_id}",
            extra={"decoy_id": str(decoy_id), "user_id": str(getattr(current_user, 'id', '')) if current_user else ''},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to undeploy decoy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to undeploy decoy",
        )


# ============================================================================
# HONEY TOKEN ENDPOINTS
# ============================================================================


@router.post(
    "/tokens",
    response_model=HoneyTokenGenerateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate_token(
    request: HoneyTokenGenerateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Generate a new honeytoken."""
    try:
        import hashlib

        data = request.model_dump()
        token_type = data.pop("token_type").lower()
        # Remove extra request fields not on the model
        service = data.pop("service", None)
        db_type = data.pop("db_type", None)
        domain = data.pop("domain", None)
        doc_type = data.pop("doc_type", None)
        doc_title = data.pop("doc_title", None)

        token_value = data.get("token_value", "")
        if not token_value:
            # Generate a placeholder token value based on type
            import secrets

            token_value = secrets.token_urlsafe(32)

        token_hash = hashlib.sha256(token_value.encode()).hexdigest()

        token = HoneyToken(
            name=f"{token_type}-{token_hash[:8]}",
            token_type=token_type,
            token_value=token_value,
            token_hash=token_hash,
            status="active",
            organization_id=data.get("organization_id"),
            deployed_by=data.get("deployed_by") or (str(getattr(current_user, 'id', '')) if current_user else ''),
        )

        db.add(token)
        await db.flush()
        await db.refresh(token)

        logger.info(
            f"Generated honeytoken: {token.name}",
            extra={
                "token_id": token.id,
                "token_type": token_type,
                "user_id": str(getattr(current_user, 'id', '')) if current_user else '',
            },
        )

        return HoneyTokenGenerateResponse.model_validate(token)

    except Exception as e:
        logger.error(f"Failed to generate token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate token",
        )


@router.get("/tokens", response_model=list[HoneyTokenResponse])
async def list_tokens(
    db: DatabaseSession = None,
    token_type: str | None = Query(None),
    token_status: str | None = Query(None, alias="status"),
    organization_id: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all honeytokens with optional filtering."""
    try:
        query = select(HoneyToken)

        filters = []
        if token_type:
            filters.append(HoneyToken.token_type == token_type)
        if token_status:
            filters.append(HoneyToken.status == token_status)
        if organization_id:
            filters.append(HoneyToken.organization_id == organization_id)

        if filters:
            query = query.where(and_(*filters))

        query = query.order_by(HoneyToken.created_at.desc()).offset(skip).limit(limit)

        result = await db.execute(query)
        tokens = list(result.scalars().all())

        logger.info(
            "Listed tokens",
            extra={
                "filters": {"type": token_type, "status": token_status},
                "count": len(tokens),
            },
        )

        return [HoneyTokenResponse.model_validate(t) for t in tokens]

    except Exception as e:
        logger.error(f"Failed to list tokens: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tokens",
        )


@router.get("/tokens/{token_id}", response_model=HoneyTokenResponse)
async def get_token(
    token_id: UUID,
    db: DatabaseSession = None,
):
    """Get details about a specific honeytoken."""
    try:
        token = await get_token_or_404(db, token_id)

        logger.info(f"Retrieved token: {token_id}")

        return HoneyTokenResponse.model_validate(token)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve token",
        )


@router.post("/tokens/{token_id}/check", response_model=HoneyTokenCheckResponse)
async def check_token(
    token_id: UUID,
    db: DatabaseSession = None,
):
    """Check if a honeytoken has been used/triggered."""
    try:
        token = await get_token_or_404(db, token_id)

        logger.info(
            f"Checked token usage: {token_id}",
            extra={
                "token_id": str(token_id),
                "triggered": token.triggered_count > 0,
            },
        )

        return HoneyTokenCheckResponse(
            token_id=token_id,
            token_hash=token.token_hash,
            has_been_used=token.triggered_count > 0,
            triggered_count=token.triggered_count,
            last_triggered_at=token.last_triggered_at,
            last_triggered_by=token.last_triggered_by,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check token",
        )


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(
    token_id: UUID,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Disable/delete a honeytoken."""
    try:
        token = await get_token_or_404(db, token_id)
        await db.delete(token)
        await db.flush()

        logger.info(
            f"Deleted token: {token_id}",
            extra={"token_id": str(token_id), "user_id": str(getattr(current_user, 'id', '')) if current_user else ''},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete token",
        )


@router.post("/tokens/rotate", status_code=status.HTTP_200_OK)
async def rotate_tokens(
    db: DatabaseSession = None,
    token_type: str = Query(...),
    organization_id: str | None = Query(None),
    current_user: CurrentUser = None,
):
    """Rotate all tokens of a specific type."""
    try:
        import hashlib
        import secrets

        query = select(HoneyToken).where(
            and_(
                HoneyToken.token_type == token_type,
                HoneyToken.status == "active",
            )
        )
        if organization_id:
            query = query.where(HoneyToken.organization_id == organization_id)

        result = await db.execute(query)
        tokens = list(result.scalars().all())

        rotated_count = 0
        for token in tokens:
            new_value = secrets.token_urlsafe(32)
            token.token_value = new_value
            token.token_hash = hashlib.sha256(new_value.encode()).hexdigest()
            token.triggered_count = 0
            token.last_triggered_at = None
            token.last_triggered_by = None
            rotated_count += 1

        await db.flush()

        logger.info(
            f"Rotated tokens of type: {token_type}",
            extra={"token_type": token_type, "rotated": rotated_count},
        )

        return {"status": "success", "tokens_rotated": rotated_count}

    except Exception as e:
        logger.error(f"Failed to rotate tokens: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate tokens",
        )


# ============================================================================
# INTERACTION ENDPOINTS
# ============================================================================


@router.get("/interactions", response_model=list[DecoyInteractionResponse])
async def list_interactions(
    db: DatabaseSession = None,
    decoy_id: UUID | None = Query(None),
    source_ip: str | None = Query(None),
    threat_level: str | None = Query(None),
    organization_id: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all decoy interactions with optional filtering."""
    try:
        query = select(DecoyInteraction)

        filters = []
        if decoy_id:
            filters.append(DecoyInteraction.decoy_id == str(decoy_id))
        if source_ip:
            filters.append(DecoyInteraction.source_ip == source_ip)
        if threat_level:
            filters.append(DecoyInteraction.threat_assessment == threat_level)
        if organization_id:
            filters.append(
                DecoyInteraction.organization_id == organization_id
            )

        if filters:
            query = query.where(and_(*filters))

        query = (
            query.order_by(DecoyInteraction.created_at.desc())
            .offset(skip)
            .limit(limit)
        )

        result = await db.execute(query)
        interactions = list(result.scalars().all())

        logger.info(
            "Listed interactions",
            extra={
                "filters": {
                    "decoy_id": str(decoy_id) if decoy_id else None,
                    "source_ip": source_ip,
                    "threat_level": threat_level,
                },
                "count": len(interactions),
            },
        )

        return [
            DecoyInteractionResponse.model_validate(i) for i in interactions
        ]

    except Exception as e:
        logger.error(f"Failed to list interactions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve interactions",
        )


@router.get(
    "/interactions/timeline", response_model=InteractionTimelineResponse
)
async def get_interaction_timeline(
    db: DatabaseSession = None,
    decoy_id: UUID = Query(...),
    hours: int = Query(24, ge=1, le=720),
):
    """Get interaction timeline for a decoy."""
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        result = await db.execute(
            select(DecoyInteraction)
            .where(
                and_(
                    DecoyInteraction.decoy_id == str(decoy_id),
                    DecoyInteraction.created_at >= cutoff,
                )
            )
            .order_by(DecoyInteraction.created_at.asc())
        )
        interactions = list(result.scalars().all())

        # Get decoy name for timeline entries
        decoy_result = await db.execute(
            select(Decoy).where(Decoy.id == str(decoy_id))
        )
        decoy = decoy_result.scalar_one_or_none()
        decoy_name = decoy.name if decoy else "Unknown"

        entries = [
            InteractionTimelineEntry(
                timestamp=i.created_at,
                interaction_id=i.id,
                decoy_id=i.decoy_id,
                decoy_name=decoy_name,
                source_ip=i.source_ip,
                interaction_type=i.interaction_type,
                threat_level=i.threat_assessment,
                description=f"{i.interaction_type} from {i.source_ip}",
            )
            for i in interactions
        ]

        logger.info(
            f"Retrieved interaction timeline for decoy: {decoy_id}",
            extra={
                "decoy_id": str(decoy_id),
                "hours": hours,
                "count": len(entries),
            },
        )

        return InteractionTimelineResponse(
            decoy_id=decoy_id,
            entries=entries,
            total_count=len(entries),
            time_span_hours=hours,
        )

    except Exception as e:
        logger.error(f"Failed to get interaction timeline: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve timeline",
        )


@router.get(
    "/interactions/{interaction_id}",
    response_model=DecoyInteractionResponse,
)
async def get_interaction(
    interaction_id: UUID,
    db: DatabaseSession = None,
):
    """Get details about a specific interaction."""
    try:
        interaction = await get_interaction_or_404(db, interaction_id)

        logger.info(f"Retrieved interaction: {interaction_id}")

        return DecoyInteractionResponse.model_validate(interaction)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get interaction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve interaction",
        )


@router.post(
    "/interactions/{interaction_id}/investigate",
    response_model=InteractionInvestigationResponse,
)
async def investigate_interaction(
    interaction_id: UUID,
    request: InteractionInvestigationRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Trigger deep investigation of an interaction."""
    try:
        interaction = await get_interaction_or_404(db, interaction_id)

        # Find correlated interactions (same source IP)
        correlated_result = await db.execute(
            select(DecoyInteraction)
            .where(
                and_(
                    DecoyInteraction.source_ip == interaction.source_ip,
                    DecoyInteraction.id != str(interaction_id),
                )
            )
            .order_by(DecoyInteraction.created_at.desc())
            .limit(10)
        )
        correlated = list(correlated_result.scalars().all())

        analysis = InteractionAnalysisResponse(
            interaction_id=interaction_id,
            interaction_type=interaction.interaction_type,
            threat_level=interaction.threat_assessment,
            is_automated=interaction.is_automated_scan,
            tools_detected=[],
            techniques=interaction.mitre_techniques or [],
            skill_level="unknown",
            objectives=[],
            confidence=0.7,
        )

        logger.info(
            f"Investigated interaction: {interaction_id}",
            extra={
                "interaction_id": str(interaction_id),
                "user_id": str(getattr(current_user, 'id', '')) if current_user else '',
            },
        )

        return InteractionInvestigationResponse(
            interaction_id=interaction_id,
            analysis=analysis,
            correlated_interactions=[
                DecoyInteractionResponse.model_validate(c) for c in correlated
            ],
            attacker_profile={
                "source_ip": interaction.source_ip,
                "total_interactions": len(correlated) + 1,
            },
            threat_intel_matches=[],
            recommendations=[],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to investigate interaction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to investigate interaction",
        )


# ============================================================================
# CAMPAIGN ENDPOINTS
# ============================================================================


@router.post(
    "/campaigns",
    response_model=DeceptionCampaignResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_campaign(
    request: DeceptionCampaignCreateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Create a new deception campaign."""
    try:
        campaign = DeceptionCampaign(
            name=request.name,
            description=request.description,
            objective=request.objective,
            coverage_zones=request.coverage_zones,
            decoy_ids=[],
            status="active",
            started_at=datetime.now(timezone.utc),
            created_by=request.created_by or (str(getattr(current_user, 'id', '')) if current_user else ''),
            organization_id=request.organization_id,
        )

        db.add(campaign)
        await db.flush()
        await db.refresh(campaign)

        logger.info(
            f"Created campaign: {campaign.name}",
            extra={
                "campaign_id": campaign.id,
                "objective": request.objective,
                "user_id": str(getattr(current_user, 'id', '')) if current_user else '',
            },
        )

        return DeceptionCampaignResponse.model_validate(campaign)

    except Exception as e:
        logger.error(f"Failed to create campaign: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation failed. Please try again or contact support.",
        )


@router.get("/campaigns", response_model=list[DeceptionCampaignResponse])
async def list_campaigns(
    db: DatabaseSession = None,
    objective: str | None = Query(None),
    campaign_status: str | None = Query(None, alias="status"),
    organization_id: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all deception campaigns with optional filtering."""
    try:
        query = select(DeceptionCampaign)

        filters = []
        if objective:
            filters.append(DeceptionCampaign.objective == objective)
        if campaign_status:
            filters.append(DeceptionCampaign.status == campaign_status)
        if organization_id:
            filters.append(
                DeceptionCampaign.organization_id == organization_id
            )

        if filters:
            query = query.where(and_(*filters))

        query = (
            query.order_by(DeceptionCampaign.created_at.desc())
            .offset(skip)
            .limit(limit)
        )

        result = await db.execute(query)
        campaigns = list(result.scalars().all())

        logger.info(
            "Listed campaigns",
            extra={
                "filters": {"objective": objective, "status": campaign_status},
                "count": len(campaigns),
            },
        )

        return [
            DeceptionCampaignResponse.model_validate(c) for c in campaigns
        ]

    except Exception as e:
        logger.error(f"Failed to list campaigns: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve campaigns",
        )


@router.get(
    "/campaigns/{campaign_id}",
    response_model=DeceptionCampaignDetailResponse,
)
async def get_campaign_detail(
    campaign_id: UUID,
    db: DatabaseSession = None,
):
    """Get detailed information about a campaign."""
    try:
        campaign = await get_campaign_or_404(db, campaign_id)

        # Fetch associated decoys
        decoys = []
        if campaign.decoy_ids:
            decoy_result = await db.execute(
                select(Decoy).where(Decoy.id.in_(campaign.decoy_ids))
            )
            decoys = list(decoy_result.scalars().all())

        logger.info(f"Retrieved campaign detail: {campaign_id}")

        campaign_dict = {
            c.name: getattr(campaign, c.name)
            for c in campaign.__table__.columns
        }
        campaign_dict["decoys"] = [
            DecoyResponse.model_validate(d) for d in decoys
        ]

        return DeceptionCampaignDetailResponse.model_validate(campaign_dict)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get campaign detail: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve campaign",
        )


@router.put(
    "/campaigns/{campaign_id}/status",
    response_model=DeceptionCampaignResponse,
)
async def update_campaign_status(
    campaign_id: UUID,
    request: CampaignStatusUpdateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update campaign status (pause/resume/complete)."""
    try:
        campaign = await get_campaign_or_404(db, campaign_id)

        campaign.status = request.status
        if request.status == "completed":
            campaign.completed_at = datetime.now(timezone.utc)

        await db.flush()
        await db.refresh(campaign)

        logger.info(
            f"Updated campaign status: {campaign_id} -> {request.status}",
            extra={
                "campaign_id": str(campaign_id),
                "status": request.status,
                "user_id": str(getattr(current_user, 'id', '')) if current_user else '',
            },
        )

        return DeceptionCampaignResponse.model_validate(campaign)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update campaign status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update campaign",
        )


@router.get(
    "/campaigns/{campaign_id}/effectiveness",
    response_model=CampaignEffectivenessResponse,
)
async def get_campaign_effectiveness(
    campaign_id: UUID,
    db: DatabaseSession = None,
):
    """Get effectiveness assessment of a campaign."""
    try:
        campaign = await get_campaign_or_404(db, campaign_id)

        # Count interactions across campaign decoys
        total_interactions = 0
        unique_attackers = 0
        if campaign.decoy_ids:
            interaction_count_result = await db.execute(
                select(func.count(DecoyInteraction.id)).where(
                    DecoyInteraction.decoy_id.in_(campaign.decoy_ids)
                )
            )
            total_interactions = interaction_count_result.scalar() or 0

            attacker_count_result = await db.execute(
                select(
                    func.count(func.distinct(DecoyInteraction.source_ip))
                ).where(
                    DecoyInteraction.decoy_id.in_(campaign.decoy_ids)
                )
            )
            unique_attackers = attacker_count_result.scalar() or 0

        effectiveness_score = campaign.effectiveness_score or 0.0

        logger.info(
            f"Assessed campaign effectiveness: {campaign_id}",
            extra={
                "campaign_id": str(campaign_id),
                "score": effectiveness_score,
            },
        )

        return CampaignEffectivenessResponse(
            campaign_id=campaign_id,
            name=campaign.name,
            objective=campaign.objective,
            status=campaign.status,
            effectiveness_score=effectiveness_score,
            coverage_percentage=len(campaign.coverage_zones) * 10.0
            if campaign.coverage_zones
            else 0.0,
            total_interactions=total_interactions,
            unique_attackers=unique_attackers,
            attacks_detected=total_interactions,
            false_positives=0,
            detection_rate=100.0 if total_interactions > 0 else 0.0,
            mean_time_to_detection=0.0,
            recommendations=[],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assess campaign effectiveness: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assess effectiveness",
        )


# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================


@router.get("/dashboard", response_model=DeceptionDashboardResponse)
async def get_dashboard(
    db: DatabaseSession = None,
    organization_id: str | None = Query(None),
):
    """Get deception module dashboard statistics."""
    try:
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=today_start.weekday())

        # --- Decoy stats ---
        decoy_base = select(func.count(Decoy.id))
        if organization_id:
            decoy_base = decoy_base.where(
                Decoy.organization_id == organization_id
            )

        total_decoys_r = await db.execute(decoy_base)
        total_decoys = total_decoys_r.scalar() or 0

        active_decoys_r = await db.execute(
            decoy_base.where(Decoy.status == "active")
        )
        active_decoys = active_decoys_r.scalar() or 0

        disabled_decoys_r = await db.execute(
            decoy_base.where(Decoy.status == "disabled")
        )
        disabled_decoys = disabled_decoys_r.scalar() or 0

        # --- Token stats ---
        token_base = select(func.count(HoneyToken.id))
        if organization_id:
            token_base = token_base.where(
                HoneyToken.organization_id == organization_id
            )

        total_tokens_r = await db.execute(token_base)
        total_tokens = total_tokens_r.scalar() or 0

        active_tokens_r = await db.execute(
            token_base.where(HoneyToken.status == "active")
        )
        active_tokens = active_tokens_r.scalar() or 0

        triggered_tokens_r = await db.execute(
            token_base.where(HoneyToken.status == "triggered")
        )
        triggered_tokens = triggered_tokens_r.scalar() or 0

        # --- Campaign stats ---
        campaign_base = select(func.count(DeceptionCampaign.id))
        if organization_id:
            campaign_base = campaign_base.where(
                DeceptionCampaign.organization_id == organization_id
            )

        active_campaigns_r = await db.execute(
            campaign_base.where(DeceptionCampaign.status == "active")
        )
        active_campaigns = active_campaigns_r.scalar() or 0

        completed_campaigns_r = await db.execute(
            campaign_base.where(DeceptionCampaign.status == "completed")
        )
        completed_campaigns = completed_campaigns_r.scalar() or 0

        # --- Interaction stats ---
        interaction_base = select(func.count(DecoyInteraction.id))
        if organization_id:
            interaction_base = interaction_base.where(
                DecoyInteraction.organization_id == organization_id
            )

        interactions_today_r = await db.execute(
            interaction_base.where(
                DecoyInteraction.created_at >= today_start
            )
        )
        interactions_today = interactions_today_r.scalar() or 0

        interactions_week_r = await db.execute(
            interaction_base.where(
                DecoyInteraction.created_at >= week_start
            )
        )
        interactions_week = interactions_week_r.scalar() or 0

        # Unique attackers
        attacker_today_q = select(
            func.count(func.distinct(DecoyInteraction.source_ip))
        ).where(DecoyInteraction.created_at >= today_start)
        if organization_id:
            attacker_today_q = attacker_today_q.where(
                DecoyInteraction.organization_id == organization_id
            )
        unique_today_r = await db.execute(attacker_today_q)
        unique_attackers_today = unique_today_r.scalar() or 0

        attacker_week_q = select(
            func.count(func.distinct(DecoyInteraction.source_ip))
        ).where(DecoyInteraction.created_at >= week_start)
        if organization_id:
            attacker_week_q = attacker_week_q.where(
                DecoyInteraction.organization_id == organization_id
            )
        unique_week_r = await db.execute(attacker_week_q)
        unique_attackers_week = unique_week_r.scalar() or 0

        # Severity counts
        high_sev_q = interaction_base.where(
            DecoyInteraction.threat_assessment == "high"
        )
        high_sev_r = await db.execute(high_sev_q)
        high_severity = high_sev_r.scalar() or 0

        critical_q = interaction_base.where(
            DecoyInteraction.threat_assessment == "critical"
        )
        critical_r = await db.execute(critical_q)
        critical_interactions = critical_r.scalar() or 0

        stats = DeceptionDashboardStats(
            total_decoys=total_decoys,
            active_decoys=active_decoys,
            disabled_decoys=disabled_decoys,
            total_honeytokens=total_tokens,
            active_tokens=active_tokens,
            triggered_tokens=triggered_tokens,
            active_campaigns=active_campaigns,
            completed_campaigns=completed_campaigns,
            interactions_today=interactions_today,
            interactions_this_week=interactions_week,
            unique_attackers_today=unique_attackers_today,
            unique_attackers_this_week=unique_attackers_week,
            high_severity_interactions=high_severity,
            critical_interactions=critical_interactions,
            average_interaction_response_time_seconds=0.0,
        )

        # Recent interactions
        recent_q = (
            select(DecoyInteraction)
            .order_by(DecoyInteraction.created_at.desc())
            .limit(10)
        )
        if organization_id:
            recent_q = recent_q.where(
                DecoyInteraction.organization_id == organization_id
            )
        recent_result = await db.execute(recent_q)
        recent_interactions = list(recent_result.scalars().all())

        # Active campaigns list
        active_campaigns_q = select(DeceptionCampaign).where(
            DeceptionCampaign.status == "active"
        )
        if organization_id:
            active_campaigns_q = active_campaigns_q.where(
                DeceptionCampaign.organization_id == organization_id
            )
        active_camp_result = await db.execute(active_campaigns_q)
        active_camp_list = list(active_camp_result.scalars().all())

        logger.info("Retrieved dashboard statistics")

        return DeceptionDashboardResponse(
            stats=stats,
            recent_interactions=[
                DecoyInteractionResponse.model_validate(i)
                for i in recent_interactions
            ],
            active_campaigns=[
                DeceptionCampaignResponse.model_validate(c)
                for c in active_camp_list
            ],
            top_attacker_profiles=[],
            recommendations=[],
        )

    except Exception as e:
        logger.error(f"Failed to get dashboard: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard",
        )


@router.get("/coverage", response_model=CoverageMapResponse)
async def get_coverage_map(
    db: DatabaseSession = None,
    organization_id: str | None = Query(None),
):
    """Get network coverage map for deception infrastructure."""
    try:
        query = select(Decoy).where(Decoy.status == "active")
        if organization_id:
            query = query.where(Decoy.organization_id == organization_id)

        result = await db.execute(query)
        decoys = list(result.scalars().all())

        # Build zone map from active decoys
        zones: dict[str, CoverageZoneInfo] = {}
        for decoy in decoys:
            zone = decoy.deployment_target or "default"
            if zone not in zones:
                zones[zone] = CoverageZoneInfo(
                    zone_name=zone,
                    covered=True,
                    decoy_count=0,
                    decoy_types=[],
                    last_interaction=None,
                )
            zones[zone].decoy_count += 1
            if decoy.decoy_type not in zones[zone].decoy_types:
                zones[zone].decoy_types.append(decoy.decoy_type)
            if decoy.last_interaction_at:
                if (
                    zones[zone].last_interaction is None
                    or decoy.last_interaction_at > zones[zone].last_interaction
                ):
                    zones[zone].last_interaction = decoy.last_interaction_at

        total_zones = max(len(zones), 1)
        covered_zones = len(zones)

        logger.info("Retrieved coverage map")

        return CoverageMapResponse(
            zones=zones,
            total_zones=total_zones,
            covered_zones=covered_zones,
            total_coverage_percentage=(covered_zones / total_zones) * 100.0
            if total_zones > 0
            else 0.0,
            gaps=[],
            recommendations=[],
        )

    except Exception as e:
        logger.error(f"Failed to get coverage map: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve coverage map",
        )


@router.get("/recommendations", response_model=RecommendationsResponse)
async def get_recommendations(
    db: DatabaseSession = None,
    organization_id: str | None = Query(None),
):
    """Get recommendations for improving deception coverage."""
    try:
        # Count decoys by category to find gaps
        query = (
            select(Decoy.category, func.count(Decoy.id))
            .where(Decoy.status == "active")
            .group_by(Decoy.category)
        )
        if organization_id:
            query = query.where(Decoy.organization_id == organization_id)

        result = await db.execute(query)
        coverage_by_category = dict(result.all())

        all_categories = [
            "network",
            "credential",
            "file",
            "dns",
            "email",
            "cloud",
            "active_directory",
            "database",
        ]
        gaps = [
            cat for cat in all_categories if cat not in coverage_by_category
        ]

        logger.info("Retrieved deception recommendations")

        return RecommendationsResponse(
            recommendations=[],
            coverage_gaps=gaps,
            high_priority_items=[],
        )

    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve recommendations",
        )
