"""
REST API endpoints for Deception Technology module.

FastAPI routes for deploying, managing, and monitoring deception infrastructure.
"""

from datetime import datetime, timedelta, timezone
import uuid
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.core.database import get_db
from src.core.logging import get_logger
from src.deception.models import (
    Decoy,
    DecoyInteraction,
    DeceptionCampaign,
    HoneyToken,
    HoneyTokenTrigger,
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
    HoneyTokenTriggerResponse,
    HoneyTokenTypeInfo,
    InteractionAnalysisResponse,
    InteractionInvestigationRequest,
    InteractionInvestigationResponse,
    InteractionTimelineEntry,
    InteractionTimelineResponse,
    RecommendationsResponse,
)

from src.models.audit import AuditLog
from src.models.user import User, UserRole
from src.services.automation import AutomationService

logger = get_logger(__name__)

# Operational writes (disable a decoy, record/investigate interactions,
# tokens and campaigns) need analyst or admin. Creating, configuring,
# deleting and rotating decoys, and deleting/rotating tokens, need admin.
_ANALYST_ROLES = [UserRole.ADMIN, UserRole.ANALYST]
_ADMIN_ROLES = [UserRole.ADMIN]

# Request fields that must never be taken from the client: the tenant and
# the deploying user come from the session.
_SERVER_OWNED_DECOY_FIELDS = {"organization_id", "deployed_by"}
# On update the deployment state is also server-owned: it follows the agent
# command result, never the request body.
_SERVER_OWNED_DECOY_UPDATE_FIELDS = _SERVER_OWNED_DECOY_FIELDS | {"status"}
_SERVER_OWNED_CONFIG_KEYS = ("listener", "deployment", "removal")

router = APIRouter(prefix="/deception", tags=["deception"])


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


async def get_decoy_or_404(
    db: AsyncSession, decoy_id: UUID, org_id: str
) -> Decoy:
    """Get decoy by ID or raise 404 within the caller's organisation."""
    stmt = select(Decoy).where(Decoy.id == str(decoy_id))
    stmt = stmt.where(Decoy.organization_id == org_id)
    result = await db.execute(stmt)
    decoy = result.scalar_one_or_none()
    if not decoy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Decoy not found",
        )
    return decoy


async def get_token_or_404(
    db: AsyncSession, token_id: UUID, org_id: str
) -> HoneyToken:
    """Get honey token by ID or raise 404 within the caller's organisation."""
    stmt = select(HoneyToken).where(HoneyToken.id == str(token_id))
    stmt = stmt.where(HoneyToken.organization_id == org_id)
    result = await db.execute(stmt)
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found",
        )
    return token


async def get_interaction_or_404(
    db: AsyncSession, interaction_id: UUID, org_id: str
) -> DecoyInteraction:
    """Get interaction by ID or raise 404 within the caller's organisation."""
    stmt = select(DecoyInteraction).where(
        DecoyInteraction.id == str(interaction_id)
    )
    stmt = stmt.where(DecoyInteraction.organization_id == org_id)
    result = await db.execute(stmt)
    interaction = result.scalar_one_or_none()
    if not interaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Interaction not found",
        )
    return interaction


async def get_campaign_or_404(
    db: AsyncSession, campaign_id: UUID, org_id: str
) -> DeceptionCampaign:
    """Get campaign by ID or raise 404 within the caller's organisation."""
    stmt = select(DeceptionCampaign).where(
        DeceptionCampaign.id == str(campaign_id)
    )
    stmt = stmt.where(DeceptionCampaign.organization_id == org_id)
    result = await db.execute(stmt)
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )
    return campaign


async def _audit(
    db: AsyncSession,
    org_id: str,
    *,
    user: Optional[User],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    description: str,
    payload: dict[str, Any],
    success: bool = True,
    error: Optional[str] = None,
) -> None:
    """One AuditLog row per deception actuation (agent command or canary trigger)."""
    import json as _json

    db.add(
        AuditLog(
            user_id=str(user.id) if user is not None else None,
            organization_id=org_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description[:4000],
            new_value=_json.dumps(payload, default=str),
            success=success,
            error_message=error,
        )
    )
    await db.flush()


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
    current_user: User = Depends(require_role(_ADMIN_ROLES)),
    org_id: OrganizationId = None,
):
    """Deploy a new decoy asset.

    Honeypots go to a deception agent as ``deploy_honeypot`` (``record_only``
    without one); honeyfile / honeycred / canary_file / breadcrumb /
    honeytoken decoys go as ``deploy_decoy``. Either way the decoy is
    ``deploying`` until the agent's result arrives, then ``active`` or
    ``failed``. Without an agent, or for a type no agent can deploy
    (honeydns, honeynet), it is ``not_deployed`` with the reason in
    ``configuration.deployment``. The status is never set from the request.
    """
    try:
        data = request.model_dump(exclude=_SERVER_OWNED_DECOY_FIELDS)
        data["deployed_by"] = str(current_user.id)
        data["deployed_at"] = datetime.utcnow()
        data["status"] = "inactive"
        data["organization_id"] = org_id
        data["configuration"] = {
            k: v for k, v in (data.get("configuration") or {}).items() if k not in _SERVER_OWNED_CONFIG_KEYS
        }

        decoy = Decoy(**data)
        db.add(decoy)
        await db.flush()
        await db.refresh(decoy)

        # Honeypots become real listeners on a deception-capable endpoint
        # agent; without one the decoy is honestly marked record_only
        # instead of pretending to be live (audit gap #9).
        if decoy.decoy_type == "honeypot":
            from src.deception.engine import dispatch_honeypot_to_agent
            outcome = await dispatch_honeypot_to_agent(db, decoy)
        else:
            from src.deception.engine import dispatch_decoy_to_agent
            outcome = await dispatch_decoy_to_agent(db, decoy, issued_by=str(current_user.id))
        await db.flush()
        await _audit(
            db, org_id, user=current_user, action="deception_deploy_decoy", resource_type="decoy",
            resource_id=decoy.id,
            description=f"deploy {decoy.decoy_type} decoy '{decoy.name}': {decoy.status}",
            payload={"decoy_type": decoy.decoy_type, "status": decoy.status, **outcome},
            success=bool(outcome.get("dispatched")),
            error=None if outcome.get("dispatched") else str(outcome.get("reason")),
        )

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
    org_id: OrganizationId = None,
    decoy_type: str | None = Query(None),
    decoy_status: str | None = Query(None, alias="status"),
    category: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all decoys with optional filtering.

    **Auth + tenancy**: caller must be authenticated. Results are
    scoped to the caller's organization — there is deliberately no
    ``organization_id`` query parameter (previous versions accepted
    one, which let anonymous callers dump any tenant's decoys).
    """
    try:
        query = select(Decoy)

        filters = []
        if decoy_type:
            filters.append(Decoy.decoy_type == decoy_type)
        if decoy_status:
            filters.append(Decoy.status == decoy_status)
        if category:
            filters.append(Decoy.category == category)

        filters.append(Decoy.organization_id == org_id)

        if filters:
            query = query.where(and_(*filters))

        query = query.order_by(Decoy.created_at.desc()).offset(skip).limit(limit)

        result = await db.execute(query)
        decoys = list(result.scalars().all())

        # Interaction counts come from the interaction rows: the agent
        # honeypot ingest writes rows without touching the decoy counters.
        stats: dict[str, tuple[int, Any]] = {}
        if decoys:
            for decoy_ref, count, last_at in (
                await db.execute(
                    select(
                        DecoyInteraction.decoy_id,
                        func.count(DecoyInteraction.id),
                        func.max(DecoyInteraction.created_at),
                    )
                    .where(
                        DecoyInteraction.organization_id == org_id,
                        DecoyInteraction.decoy_id.in_([d.id for d in decoys]),
                    )
                    .group_by(DecoyInteraction.decoy_id)
                )
            ).all():
                stats[decoy_ref] = (int(count), last_at)

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

        out = []
        for d in decoys:
            item = DecoyResponse.model_validate(d)
            count, last_at = stats.get(d.id, (0, None))
            item.interaction_count = count
            item.last_interaction_at = last_at
            out.append(item)
        return out

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
    org_id: OrganizationId = None,
):
    """Get detailed information about a specific decoy."""
    try:
        decoy = await get_decoy_or_404(
            db, decoy_id, org_id
        )

        # Fetch recent interactions for this decoy
        interactions_result = await db.execute(
            select(DecoyInteraction)
            .where(
                DecoyInteraction.decoy_id == str(decoy_id),
                DecoyInteraction.organization_id == org_id,
            )
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
    current_user: User = Depends(require_role(_ADMIN_ROLES)),
    org_id: OrganizationId = None,
):
    """Update decoy configuration."""
    try:
        decoy = await get_decoy_or_404(
            db, decoy_id, org_id
        )

        # organization_id / deployed_by in the body are ignored: a decoy can
        # never be moved to another tenant through this route.
        update_data = request.model_dump(
            exclude_unset=True, exclude=_SERVER_OWNED_DECOY_UPDATE_FIELDS
        )
        if "configuration" in update_data:
            # The agent dispatch records stay as the server wrote them.
            current = dict(decoy.configuration or {})
            incoming = {
                k: v for k, v in (update_data["configuration"] or {}).items()
                if k not in _SERVER_OWNED_CONFIG_KEYS
            }
            incoming.update({k: current[k] for k in _SERVER_OWNED_CONFIG_KEYS if k in current})
            update_data["configuration"] = incoming
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
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
):
    """Disable a decoy; a dispatched decoy is also stopped / removed on its agent."""
    try:
        decoy = await get_decoy_or_404(
            db, decoy_id, org_id
        )
        from src.deception.engine import remove_decoy_from_agent

        removal = await remove_decoy_from_agent(db, decoy, issued_by=str(current_user.id))
        decoy.status = "disabled"

        await db.flush()
        await _audit(
            db, org_id, user=current_user, action="deception_disable_decoy", resource_type="decoy",
            resource_id=decoy.id, description=f"disable decoy '{decoy.name}': agent removal {removal}",
            payload=removal, success=removal.get("sent", False) or removal.get("reason") == "never_dispatched",
            error=removal.get("error"),
        )

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
    _current_user: User = Depends(require_role(_ADMIN_ROLES)),
    org_id: OrganizationId = None,
):
    """Rotate/refresh a decoy to avoid fingerprinting.

    Not implemented: rotation previously only reset ``status`` and wiped
    ``interaction_count`` without re-fingerprinting anything on the agent.
    """
    await get_decoy_or_404(db, decoy_id, org_id)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": "decoy rotation is not implemented: nothing re-fingerprints "
            "the decoy on its agent, so the route no longer reports success",
        },
    )


@router.post(
    "/decoys/{decoy_id}/interactions",
    status_code=status.HTTP_201_CREATED,
)
async def record_decoy_interaction(
    decoy_id: UUID,
    payload: dict = Body(...),
    db: DatabaseSession = None,
    _current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
):
    """Record an attacker interaction with a deployed decoy.

    Exposes a real ingestion path so an external honeypot process, a
    webhook from a canary service, or a purple-team script can drive
    ``decoy.interaction_count``, ``decoy.last_interaction_at``, and
    create a linked ``Alert`` when ``alert_generated`` is true.

    Previously the DB had the table and the UI charted "Interactions
    Today" but nothing on the backend could write a row — so the
    counter was forever 0 in any honest deployment.
    """
    from src.deception.models import DecoyInteraction
    from src.models.alert import Alert
    import json as _json

    try:
        decoy = await get_decoy_or_404(
            db, decoy_id, org_id
        )

        interaction = DecoyInteraction(
            id=str(uuid.uuid4()),
            decoy_id=str(decoy.id),
            interaction_type=(payload.get("interaction_type") or "connection"),
            source_ip=payload.get("source_ip") or "0.0.0.0",
            source_port=payload.get("source_port"),
            source_hostname=payload.get("source_hostname"),
            source_user=payload.get("source_user"),
            protocol=payload.get("protocol"),
            credentials_captured=payload.get("credentials_captured"),
            commands_captured=payload.get("commands_captured") or [],
            payloads_captured=payload.get("payloads_captured") or [],
            files_accessed=payload.get("files_accessed") or [],
            session_duration_seconds=payload.get("session_duration_seconds"),
            geo_location=payload.get("geo_location"),
            threat_assessment=payload.get("threat_assessment") or "high",
            is_automated_scan=bool(payload.get("is_automated_scan", False)),
            raw_traffic=payload.get("raw_traffic"),
            alert_generated=bool(payload.get("alert_generated", True)),
            mitre_techniques=payload.get("mitre_techniques") or [],
            organization_id=org_id,
        )
        db.add(interaction)

        # Bump counters on the decoy so the dashboard reflects the hit.
        now_utc = datetime.now(timezone.utc)
        decoy.interaction_count = (decoy.interaction_count or 0) + 1
        decoy.last_interaction_at = now_utc

        alert_id: Optional[str] = None
        if interaction.alert_generated:
            alert = Alert(
                id=str(uuid.uuid4()),
                title=f"Decoy interaction: {decoy.name} from {interaction.source_ip}",
                description=(
                    f"Interaction type: {interaction.interaction_type}. "
                    f"Source IP {interaction.source_ip} engaged decoy '{decoy.name}'. "
                    f"Any engagement with a decoy is suspicious by design."
                ),
                severity=interaction.threat_assessment or "high",
                status="new",
                source="deception",
                source_id=str(interaction.id),
                alert_type="decoy_interaction",
                category="honeypot",
                source_ip=interaction.source_ip,
                username=interaction.source_user,
                raw_data=_json.dumps({
                    "interaction_type": interaction.interaction_type,
                    "protocol": interaction.protocol,
                    "commands_captured": interaction.commands_captured,
                    "mitre_techniques": interaction.mitre_techniques,
                }),
                organization_id=org_id,
                created_at=now_utc,
                updated_at=now_utc,
            )
            db.add(alert)
            await db.flush()
            alert_id = alert.id
            interaction.alert_id = alert_id

        await db.flush()

        return {
            "interaction_id": str(interaction.id),
            "decoy_id": str(decoy.id),
            "alert_generated": bool(alert_id),
            "alert_id": alert_id,
            "interaction_count": decoy.interaction_count,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to record decoy interaction: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record decoy interaction",
        )


@router.delete("/decoys/{decoy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def undeploy_decoy(
    decoy_id: UUID,
    db: DatabaseSession = None,
    current_user: User = Depends(require_role(_ADMIN_ROLES)),
    org_id: OrganizationId = None,
):
    """Undeploy and delete a decoy (stop_honeypot / remove_decoy goes to its agent first)."""
    try:
        decoy = await get_decoy_or_404(
            db, decoy_id, org_id
        )
        from src.deception.engine import remove_decoy_from_agent

        removal = await remove_decoy_from_agent(db, decoy, issued_by=str(current_user.id))
        await _audit(
            db, org_id, user=current_user, action="deception_delete_decoy", resource_type="decoy",
            resource_id=decoy.id, description=f"delete decoy '{decoy.name}': agent removal {removal}",
            payload={"name": decoy.name, "decoy_type": decoy.decoy_type, **removal},
            success=removal.get("sent", False) or removal.get("reason") == "never_dispatched",
            error=removal.get("error"),
        )
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


_CANARY_PATH = "/api/v1/deception/canary/{token_id}"


def _canary_path(token_id: str) -> str:
    return _CANARY_PATH.format(token_id=token_id)


def _trigger_mechanism(token_type: str) -> str:
    from src.deception.engine import SUPPORTED_TOKEN_TYPES

    return SUPPORTED_TOKEN_TYPES.get(
        (token_type or "").lower(),
        "Only a request to the canary URL fires this token (created before wave 3; its value was not kept).",
    )


async def _trigger_counts(db: AsyncSession, org_id: str, token_ids: list[str]) -> dict[str, tuple[int, int]]:
    """token_id -> (triggers, triggers that presented the token value), from rows."""
    if not token_ids:
        return {}
    rows = (
        await db.execute(
            select(
                HoneyTokenTrigger.token_id,
                func.count(HoneyTokenTrigger.id),
                func.count(HoneyTokenTrigger.id).filter(HoneyTokenTrigger.value_presented.is_(True)),
            )
            .where(
                HoneyTokenTrigger.organization_id == org_id,
                HoneyTokenTrigger.token_id.in_(token_ids),
            )
            .group_by(HoneyTokenTrigger.token_id)
        )
    ).all()
    return {r[0]: (int(r[1]), int(r[2])) for r in rows}


def _token_fields(token: HoneyToken, triggered: int) -> dict[str, Any]:
    return {
        "id": token.id,
        "name": token.name,
        "token_type": token.token_type,
        "status": token.status,
        "deployment_location": token.deployment_location,
        "deployment_context": token.deployment_context,
        "expires_at": token.expires_at,
        "alert_severity": token.alert_severity,
        "deployed_by": token.deployed_by,
        "token_hash": token.token_hash,
        "triggered_count": triggered,
        "last_triggered_at": token.last_triggered_at,
        "last_triggered_by": token.last_triggered_by,
        "created_at": token.created_at,
        "updated_at": token.updated_at,
        "token_preview": token.token_value,  # the column holds the preview only
        "canary_path": _canary_path(token.id),
        "trigger_mechanism": _trigger_mechanism(token.token_type),
    }


@router.get("/tokens/types", response_model=list[HoneyTokenTypeInfo])
async def list_token_types(org_id: OrganizationId = None):
    """Token types and how each one fires (or why it cannot be generated)."""
    from src.deception.engine import SUPPORTED_TOKEN_TYPES, UNSUPPORTED_TOKEN_TYPES

    return [
        HoneyTokenTypeInfo(token_type=t, supported=True, trigger_mechanism=m)
        for t, m in SUPPORTED_TOKEN_TYPES.items()
    ] + [
        HoneyTokenTypeInfo(token_type=t, supported=False, reason=r)
        for t, r in UNSUPPORTED_TOKEN_TYPES.items()
    ]


@router.post(
    "/tokens",
    response_model=HoneyTokenGenerateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate_token(
    request: HoneyTokenGenerateRequest,
    http_request: Request,
    db: DatabaseSession = None,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
):
    """Generate a honeytoken wired to its canary URL.

    The value is generated here and returned in this response only
    (``token_value``, ``planting``); PySOAR keeps its SHA-256 and a short
    preview. Any request to ``canary_url`` records a trigger and raises an
    alert. Types whose use cannot reach the canary are refused with 400
    ``unsupported_token_type`` (see GET /deception/tokens/types).
    """
    from src.deception.engine import (
        UnsupportedTokenTypeError,
        generate_honeytoken,
        token_hash,
        token_preview,
    )

    token_type = (request.token_type or "").lower()
    token_id = str(uuid.uuid4())
    canary_url = str(http_request.base_url).rstrip("/") + _canary_path(token_id)
    try:
        generated = generate_honeytoken(token_type, canary_url)
    except UnsupportedTokenTypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "unsupported_token_type",
                "detail": f"{exc.token_type or 'token'} honeytokens are not supported: {exc.reason}",
            },
        ) from None

    hashed = token_hash(generated["match_material"])
    token = HoneyToken(
        id=token_id,
        name=request.name or f"{token_type}-{hashed[:8]}",
        token_type=token_type,
        token_value=token_preview(generated["value"]),
        token_hash=hashed,
        deployment_location=request.deployment_location,
        deployment_context=request.deployment_context,
        status="active",
        organization_id=org_id,
        deployed_by=str(current_user.id),
    )
    db.add(token)
    await db.flush()
    await db.refresh(token)

    logger.info(
        "honeytoken_generated",
        token_id=token.id, token_type=token_type, organization_id=org_id, user_id=str(current_user.id),
    )
    return HoneyTokenGenerateResponse(
        **_token_fields(token, 0),
        token_value=generated["value"],
        canary_url=canary_url,
        planting=generated["planting"],
    )


@router.get("/tokens", response_model=list[HoneyTokenResponse])
async def list_tokens(
    db: DatabaseSession = None,
    org_id: OrganizationId = None,
    token_type: str | None = Query(None),
    token_status: str | None = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List honeytokens (org-scoped); trigger counts come from the trigger rows."""
    query = select(HoneyToken).where(HoneyToken.organization_id == org_id)
    if token_type:
        query = query.where(HoneyToken.token_type == token_type)
    if token_status:
        query = query.where(HoneyToken.status == token_status)
    query = query.order_by(HoneyToken.created_at.desc()).offset(skip).limit(limit)
    tokens = list((await db.execute(query)).scalars().all())
    counts = await _trigger_counts(db, org_id, [t.id for t in tokens])
    return [HoneyTokenResponse(**_token_fields(t, counts.get(t.id, (0, 0))[0])) for t in tokens]


@router.get("/tokens/{token_id}", response_model=HoneyTokenResponse)
async def get_token(
    token_id: UUID,
    db: DatabaseSession = None,
    org_id: OrganizationId = None,
):
    """Get details about a specific honeytoken (never its value)."""
    token = await get_token_or_404(db, token_id, org_id)
    counts = await _trigger_counts(db, org_id, [token.id])
    return HoneyTokenResponse(**_token_fields(token, counts.get(token.id, (0, 0))[0]))


@router.get("/tokens/{token_id}/triggers", response_model=list[HoneyTokenTriggerResponse])
async def list_token_triggers(
    token_id: UUID,
    db: DatabaseSession = None,
    org_id: OrganizationId = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Recorded canary calls for a token, newest first."""
    token = await get_token_or_404(db, token_id, org_id)
    rows = (
        await db.execute(
            select(HoneyTokenTrigger)
            .where(HoneyTokenTrigger.token_id == token.id, HoneyTokenTrigger.organization_id == org_id)
            .order_by(HoneyTokenTrigger.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
    ).scalars().all()
    return [HoneyTokenTriggerResponse.model_validate(r) for r in rows]


@router.post("/tokens/{token_id}/check", response_model=HoneyTokenCheckResponse)
async def check_token(
    token_id: UUID,
    db: DatabaseSession = None,
    _current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
):
    """Whether a honeytoken has fired, counted from its trigger rows."""
    token = await get_token_or_404(db, token_id, org_id)
    total, with_value = (await _trigger_counts(db, org_id, [token.id])).get(token.id, (0, 0))
    return HoneyTokenCheckResponse(
        token_id=token_id,
        token_hash=token.token_hash,
        has_been_used=total > 0,
        triggered_count=total,
        last_triggered_at=token.last_triggered_at,
        last_triggered_by=token.last_triggered_by,
        triggers_with_value_presented=with_value,
        status=token.status,
    )


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(
    token_id: UUID,
    db: DatabaseSession = None,
    current_user: User = Depends(require_role(_ADMIN_ROLES)),
    org_id: OrganizationId = None,
):
    """Disable/delete a honeytoken."""
    try:
        token = await get_token_or_404(
            db, token_id, org_id
        )
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
    _db: DatabaseSession = None,
    _token_type: str = Query(..., alias="token_type"),
    _current_user: User = Depends(require_role(_ADMIN_ROLES)),
    _org_id: OrganizationId = None,
):
    """Rotate all tokens of a specific type.

    Not implemented: rotation previously replaced token values that were
    never returned or re-deployed, and wiped the trigger evidence.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": "honeytoken rotation is not implemented: new token values "
            "are not deployed anywhere, so the route no longer reports success",
        },
    )


# ============================================================================
# CANARY CALLBACK (unauthenticated)
# ============================================================================

#: Bytes of a canary request body kept in the trigger record.
_CANARY_BODY_EXCERPT = 2048
#: Bodies larger than this are not read at all.
_CANARY_MAX_BODY = 64 * 1024
#: A second trigger from the same source inside this window joins the open alert.
_CANARY_ALERT_DEDUPE = timedelta(minutes=10)
_CANARY_HEADERS_KEPT = ("user-agent", "referer", "content-type", "x-forwarded-for", "x-real-ip", "host")


def _presented_values(request: Request, body_json: Any) -> list[str]:
    """Credential-looking values a canary caller presented (never stored raw)."""
    import base64
    import re

    found: list[str] = []
    auth = request.headers.get("authorization", "")
    scheme, _, rest = auth.partition(" ")
    if scheme.lower() == "bearer" and rest.strip():
        found.append(rest.strip())
    elif scheme.lower() == "basic" and rest.strip():
        try:
            user, _, password = base64.b64decode(rest.strip()).decode("utf-8", "replace").partition(":")
            found.extend(v for v in (user, password) if v)
        except ValueError:
            pass
    elif scheme.upper().startswith("AWS4-HMAC-SHA256"):
        match = re.search(r"Credential=([A-Z0-9]{16,128})/", auth)
        if match:
            found.append(match.group(1))
    for header in ("x-api-key", "x-auth-token"):
        if request.headers.get(header):
            found.append(request.headers[header])
    for param in ("token", "api_key", "key", "access_key_id"):
        if request.query_params.get(param):
            found.append(request.query_params[param])
    if isinstance(body_json, dict):
        for field in ("token", "api_key", "key", "access_key_id"):
            if isinstance(body_json.get(field), str):
                found.append(body_json[field])
    return [v[:8192] for v in found]


@router.api_route("/canary/{token_id}", methods=["POST", "GET"])
async def canary_callback(
    token_id: str,
    request: Request,
    db: DatabaseSession = None,
):
    """Record a honeytoken firing. Unauthenticated by design.

    Keyed by the token's unguessable id (UUID4) from its canary URL. Each
    call stores a ``honey_token_triggers`` row with the caller's source
    address, forwarded-for chain, user agent, selected headers and a body
    excerpt; bumps the token's trigger count; and raises a ``deception``
    alert for the owning organisation (calls from the same source within
    10 minutes join the open alert). If the call presents the token's
    secret it is marked ``value_presented``. GET is accepted for URL
    canaries opened in a browser or mail client.
    """
    import hmac
    import json as _json

    from src.deception.engine import token_hash
    from src.models.alert import Alert

    if len(token_id) > 64:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "not_found"})
    token = (await db.execute(select(HoneyToken).where(HoneyToken.id == token_id))).scalar_one_or_none()
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "not_found"})

    raw = b""
    length = request.headers.get("content-length")
    if request.method == "POST" and (length is None or (length.isdigit() and int(length) <= _CANARY_MAX_BODY)):
        raw = (await request.body())[:_CANARY_MAX_BODY]
    body_json: Any = None
    if raw and "json" in request.headers.get("content-type", ""):
        try:
            body_json = _json.loads(raw)
        except ValueError:
            body_json = None

    presented = _presented_values(request, body_json)
    if presented:
        value_presented: Optional[bool] = any(
            hmac.compare_digest(token_hash(v), token.token_hash) for v in presented
        )
    else:
        value_presented = None

    source_ip = request.client.host if request.client else None
    forwarded_for = request.headers.get("x-forwarded-for")
    auth_scheme = request.headers.get("authorization", "").partition(" ")[0][:40] or None
    metadata = {
        "headers": {h: request.headers[h][:500] for h in _CANARY_HEADERS_KEPT if h in request.headers},
        "authorization_scheme": auth_scheme,
        "query": str(request.url.query)[:1000] or None,
        "body_excerpt": raw[:_CANARY_BODY_EXCERPT].decode("utf-8", "replace") if raw else None,
        "body_bytes": len(raw),
        "credentials_presented": len(presented),
    }
    now = datetime.now(timezone.utc)
    trigger = HoneyTokenTrigger(
        id=str(uuid.uuid4()),
        token_id=token.id,
        organization_id=token.organization_id,
        source_ip=(source_ip or "")[:45] or None,
        forwarded_for=forwarded_for[:500] if forwarded_for else None,
        user_agent=(request.headers.get("user-agent") or "")[:500] or None,
        http_method=request.method,
        request_metadata=metadata,
        value_presented=value_presented,
    )
    db.add(trigger)

    token.triggered_count = (token.triggered_count or 0) + 1
    token.last_triggered_at = now
    token.last_triggered_by = (forwarded_for or source_ip or "unknown")[:255]
    if token.status == "active":
        token.status = "triggered"

    alert_id: Optional[str] = None
    new_alert: Optional[Alert] = None
    if token.status != "disabled":
        recent = (
            await db.execute(
                select(HoneyTokenTrigger.alert_id)
                .where(
                    HoneyTokenTrigger.token_id == token.id,
                    HoneyTokenTrigger.alert_id.is_not(None),
                    HoneyTokenTrigger.source_ip == trigger.source_ip,
                    HoneyTokenTrigger.created_at >= now - _CANARY_ALERT_DEDUPE,
                )
                .order_by(HoneyTokenTrigger.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if recent:
            alert_id = recent
        else:
            new_alert = Alert(
                id=str(uuid.uuid4()),
                title=f"Honeytoken triggered: {token.name} ({token.token_type})",
                description=(
                    f"The {token.token_type} honeytoken '{token.name}' was used from "
                    f"{trigger.source_ip or 'an unknown address'}"
                    + (f" (forwarded for {forwarded_for})" if forwarded_for else "")
                    + (". The caller presented the token value." if value_presented else ".")
                    + (f" Planted at: {token.deployment_location}." if token.deployment_location else "")
                ),
                severity=token.alert_severity or "critical",
                status="new",
                source="deception",
                source_id=trigger.id,
                alert_type="honeytoken_trigger",
                category="honeytoken",
                source_ip=trigger.source_ip,
                raw_data=_json.dumps({
                    "token_id": token.id,
                    "token_type": token.token_type,
                    "trigger_id": trigger.id,
                    "value_presented": value_presented,
                    "user_agent": trigger.user_agent,
                    "forwarded_for": forwarded_for,
                }),
                organization_id=token.organization_id,
                created_at=now,
                updated_at=now,
            )
            db.add(new_alert)
            alert_id = new_alert.id
    trigger.alert_id = alert_id
    await db.flush()
    await _audit(
        db, token.organization_id, user=None, action="deception_honeytoken_triggered",
        resource_type="honey_token", resource_id=token.id,
        description=f"honeytoken '{token.name}' fired from {trigger.source_ip}",
        payload={"trigger_id": trigger.id, "alert_id": alert_id, "value_presented": value_presented},
    )

    if new_alert is not None:
        # The alert pipeline (IOC match, incident, playbooks) must not undo
        # the recorded trigger if one of its steps fails.
        try:
            async with db.begin_nested():
                await AutomationService(db).on_alert_created(new_alert, token.organization_id)
        except Exception as exc:  # noqa: BLE001 - trigger and alert are already recorded
            logger.error("honeytoken_alert_pipeline_failed", token_id=token.id, error=str(exc))

    logger.warning(
        "honeytoken_triggered",
        token_id=token.id, organization_id=token.organization_id, source_ip=trigger.source_ip,
        value_presented=value_presented, alert_id=alert_id,
    )
    return {"status": "recorded"}


# ============================================================================
# INTERACTION ENDPOINTS
# ============================================================================


@router.get("/interactions", response_model=list[DecoyInteractionResponse])
async def list_interactions(
    db: DatabaseSession = None,
    org_id: OrganizationId = None,
    decoy_id: UUID | None = Query(None),
    source_ip: str | None = Query(None),
    threat_level: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all decoy interactions with optional filtering.

    Authenticated and org-scoped. Interactions from other tenants are
    never returned, and there is no client-supplied organization_id.
    """
    try:
        query = select(DecoyInteraction)

        filters = []
        if decoy_id:
            filters.append(DecoyInteraction.decoy_id == str(decoy_id))
        if source_ip:
            filters.append(DecoyInteraction.source_ip == source_ip)
        if threat_level:
            filters.append(DecoyInteraction.threat_assessment == threat_level)
        filters.append(DecoyInteraction.organization_id == org_id)

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
    org_id: OrganizationId = None,
    decoy_id: UUID = Query(...),
    hours: int = Query(24, ge=1, le=720),
):
    """Get interaction timeline for a decoy (404 outside the caller's organisation)."""
    try:
        decoy = await get_decoy_or_404(db, decoy_id, org_id)
        decoy_name = decoy.name
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        result = await db.execute(
            select(DecoyInteraction)
            .where(
                and_(
                    DecoyInteraction.decoy_id == str(decoy_id),
                    DecoyInteraction.organization_id == org_id,
                    DecoyInteraction.created_at >= cutoff,
                )
            )
            .order_by(DecoyInteraction.created_at.asc())
        )
        interactions = list(result.scalars().all())

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

    except HTTPException:
        raise
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
    org_id: OrganizationId = None,
):
    """Get details about a specific interaction."""
    try:
        interaction = await get_interaction_or_404(
            db, interaction_id, org_id
        )

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
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
):
    """Trigger deep investigation of an interaction."""
    try:
        interaction = await get_interaction_or_404(
            db, interaction_id, org_id
        )

        # Find correlated interactions (same source IP)
        correlated_result = await db.execute(
            select(DecoyInteraction)
            .where(
                and_(
                    DecoyInteraction.source_ip == interaction.source_ip,
                    DecoyInteraction.id != str(interaction_id),
                    DecoyInteraction.organization_id == org_id,
                )
            )
            .order_by(DecoyInteraction.created_at.desc())
            .limit(10)
        )
        correlated = list(correlated_result.scalars().all())

        # Only facts recorded on the interaction. No analyzer runs here, so
        # skill level and confidence are left empty rather than invented
        # (previously a hard-coded "unknown" / 0.7).
        analysis = InteractionAnalysisResponse(
            interaction_id=interaction_id,
            interaction_type=interaction.interaction_type,
            threat_level=interaction.threat_assessment,
            is_automated=interaction.is_automated_scan,
            tools_detected=[],
            techniques=interaction.mitre_techniques or [],
            skill_level="",
            objectives=[],
            confidence=0.0,
        )

        logger.info(
            f"Investigated interaction: {interaction_id}",
            extra={
                "interaction_id": str(interaction_id),
                "user_id": str(getattr(current_user, 'id', '')) if current_user else '',
            },
        )

        # Fire automation for deception trigger
        try:
            # Look up the decoy for this interaction
            decoy_result = await db.execute(
                select(Decoy).where(
                    Decoy.id == interaction.decoy_id,
                    Decoy.organization_id == org_id,
                )
            )
            decoy = decoy_result.scalar_one_or_none()
            if decoy:
                automation = AutomationService(db)
                await automation.on_deception_triggered(
                    decoy_name=decoy.name,
                    decoy_type=decoy.decoy_type,
                    attacker_ip=interaction.source_ip,
                    organization_id=org_id,
                )
        except Exception as e:
            logger.error(f"Automation failed for deception trigger: {e}")

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
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
):
    """Create a new deception campaign."""
    try:
        campaign = DeceptionCampaign(
            name=request.name,
            description=request.description,
            objective=request.objective,
            coverage_zones=request.coverage_zones or [],
            decoy_ids=[],
            status="active",
            started_at=datetime.utcnow(),
            created_by=str(current_user.id),
            organization_id=org_id,
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
    org_id: OrganizationId = None,
    objective: str | None = Query(None),
    campaign_status: str | None = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List all deception campaigns with optional filtering.

    Authenticated and org-scoped. No client-supplied organization_id.
    """
    try:
        query = select(DeceptionCampaign)

        filters = []
        if objective:
            filters.append(DeceptionCampaign.objective == objective)
        if campaign_status:
            filters.append(DeceptionCampaign.status == campaign_status)
        filters.append(DeceptionCampaign.organization_id == org_id)

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
    org_id: OrganizationId = None,
):
    """Get detailed information about a campaign."""
    try:
        campaign = await get_campaign_or_404(
            db, campaign_id, org_id
        )

        # Fetch associated decoys
        decoys = []
        if campaign.decoy_ids:
            decoy_result = await db.execute(
                select(Decoy).where(
                    Decoy.id.in_(campaign.decoy_ids),
                    Decoy.organization_id == org_id,
                )
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
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
):
    """Update campaign status (pause/resume/complete)."""
    try:
        campaign = await get_campaign_or_404(
            db, campaign_id, org_id
        )

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
    org_id: OrganizationId = None,
):
    """Get effectiveness assessment of a campaign."""
    try:
        campaign = await get_campaign_or_404(
            db, campaign_id, org_id
        )

        # Count interactions across campaign decoys
        total_interactions = 0
        unique_attackers = 0
        if campaign.decoy_ids:
            interaction_count_result = await db.execute(
                select(func.count(DecoyInteraction.id)).where(
                    DecoyInteraction.decoy_id.in_(campaign.decoy_ids),
                    DecoyInteraction.organization_id == org_id,
                )
            )
            total_interactions = interaction_count_result.scalar() or 0

            attacker_count_result = await db.execute(
                select(
                    func.count(func.distinct(DecoyInteraction.source_ip))
                ).where(
                    DecoyInteraction.decoy_id.in_(campaign.decoy_ids),
                    DecoyInteraction.organization_id == org_id,
                )
            )
            unique_attackers = attacker_count_result.scalar() or 0

        # Compute effectiveness_score from real interaction data rather
        # than reading the stored column (which nothing ever wrote to,
        # so every card showed 0.0 regardless of actual activity).
        # Weighted formula: 40% interaction volume (saturated at 100),
        # 30% unique attacker diversity (saturated at 10 distinct IPs),
        # 30% coverage (decoys in campaign / 5 decoys-target).
        decoy_count = len(campaign.decoy_ids or [])
        interaction_component = min(total_interactions / 1.0, 100.0) * 0.4 if total_interactions <= 100 else 40.0
        diversity_component = min(unique_attackers / 10.0, 1.0) * 30.0
        coverage_component = min(decoy_count / 5.0, 1.0) * 30.0
        effectiveness_score = round(interaction_component + diversity_component + coverage_component, 2)

        # Persist back so the Campaigns list card reflects the score
        # without every client having to recompute.
        campaign.effectiveness_score = effectiveness_score
        await db.flush()

        # Real MTTD from first interaction after campaign start, if any.
        mttd_seconds = 0.0
        if campaign.decoy_ids and campaign.start_date:
            first_hit_res = await db.execute(
                select(func.min(DecoyInteraction.created_at)).where(
                    DecoyInteraction.decoy_id.in_(campaign.decoy_ids),
                    DecoyInteraction.organization_id == org_id,
                )
            )
            first_hit = first_hit_res.scalar()
            if first_hit:
                mttd_seconds = max(
                    0.0,
                    (first_hit - campaign.start_date).total_seconds(),
                )

        recommendations: list[str] = []
        if total_interactions == 0 and decoy_count > 0:
            recommendations.append(
                "No interactions yet — verify the campaign's decoys are reachable from the attacker path."
            )
        if decoy_count < 3:
            recommendations.append(
                f"Campaign only covers {decoy_count} decoy(s). Add more to increase coverage."
            )
        if unique_attackers == 1 and total_interactions > 10:
            recommendations.append(
                "All interactions came from a single source — investigate whether this is a scanner or a real adversary."
            )

        logger.info(
            f"Assessed campaign effectiveness: {campaign_id}",
            extra={
                "campaign_id": str(campaign_id),
                "score": effectiveness_score,
                "interactions": total_interactions,
                "attackers": unique_attackers,
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
            mean_time_to_detection=round(mttd_seconds / 60.0, 2),  # minutes
            recommendations=recommendations,
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
    org_id: OrganizationId = None,
):
    """Get deception module dashboard statistics.

    Authenticated and org-scoped to the caller's organization. No
    client-supplied ``organization_id`` — that was a cross-tenant leak
    vector that let anonymous callers dump any tenant's stats.
    """
    try:
        organization_id = org_id
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=today_start.weekday())

        # --- Decoy stats ---
        decoy_base = select(func.count(Decoy.id))
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
        attacker_today_q = attacker_today_q.where(
            DecoyInteraction.organization_id == organization_id
        )
        unique_today_r = await db.execute(attacker_today_q)
        unique_attackers_today = unique_today_r.scalar() or 0

        attacker_week_q = select(
            func.count(func.distinct(DecoyInteraction.source_ip))
        ).where(DecoyInteraction.created_at >= week_start)
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

        # Average interaction duration over the last 30 days. The frontend
        # labels this "average response time" — we interpret that as the
        # mean session duration on a decoy (how long an attacker stayed
        # engaged), which is what the DecoyInteraction model actually
        # tracks via session_duration_seconds.
        avg_duration_q = select(
            func.avg(DecoyInteraction.session_duration_seconds)
        ).where(
            and_(
                DecoyInteraction.created_at >= now - timedelta(days=30),
                DecoyInteraction.session_duration_seconds.is_not(None),
            )
        )
        avg_duration_q = avg_duration_q.where(
            DecoyInteraction.organization_id == organization_id
        )
        avg_duration_r = await db.execute(avg_duration_q)
        avg_session_duration = float(avg_duration_r.scalar() or 0.0)

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
            average_interaction_response_time_seconds=round(avg_session_duration, 2),
        )

        # Recent interactions
        recent_q = (
            select(DecoyInteraction)
            .order_by(DecoyInteraction.created_at.desc())
            .limit(10)
        )
        recent_q = recent_q.where(
            DecoyInteraction.organization_id == organization_id
        )
        recent_result = await db.execute(recent_q)
        recent_interactions = list(recent_result.scalars().all())

        # Active campaigns list
        active_campaigns_q = select(DeceptionCampaign).where(
            DeceptionCampaign.status == "active"
        )
        active_campaigns_q = active_campaigns_q.where(
            DeceptionCampaign.organization_id == organization_id
        )
        active_camp_result = await db.execute(active_campaigns_q)
        active_camp_list = list(active_camp_result.scalars().all())

        # --- Top attacker profiles (last 30d) ---
        # Group DecoyInteraction by source_ip to find the top 5 busiest
        # attackers, with their interaction count, highest threat level
        # seen, and their most recent hit. This is the foundation for an
        # "attacker timeline" view when the frontend adds one.
        top_attackers_q = (
            select(
                DecoyInteraction.source_ip,
                func.count(DecoyInteraction.id).label("interaction_count"),
                func.max(DecoyInteraction.created_at).label("last_seen"),
            )
            .where(DecoyInteraction.created_at >= now - timedelta(days=30))
            .group_by(DecoyInteraction.source_ip)
            .order_by(func.count(DecoyInteraction.id).desc())
            .limit(5)
        )
        top_attackers_q = top_attackers_q.where(
            DecoyInteraction.organization_id == organization_id
        )
        top_attackers_result = await db.execute(top_attackers_q)
        top_attacker_profiles = [
            {
                "source_ip": row.source_ip,
                "interaction_count": int(row.interaction_count),
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
            for row in top_attackers_result.all()
            if row.source_ip
        ]

        # --- Dashboard recommendations ---
        # Derive from real coverage state + threat state. Each rule
        # here is a simple, surfaceable recommendation the operator can
        # act on in a single click from the UI.
        dashboard_recs: list[str] = []
        if total_decoys == 0:
            dashboard_recs.append(
                "No decoys deployed — deploy at least one network honeypot to start catching reconnaissance."
            )
        elif active_decoys == 0 and total_decoys > 0:
            dashboard_recs.append(
                "You have decoys defined but none are active — re-enable or rotate them."
            )
        if active_tokens == 0 and total_tokens == 0:
            dashboard_recs.append(
                "No honeytokens active — deploy at least one (AWS key or API key) in a plausible location to detect credential theft."
            )
        if triggered_tokens > 0:
            dashboard_recs.append(
                f"{triggered_tokens} honeytoken(s) triggered — investigate in the Interactions tab and rotate compromised tokens."
            )
        if critical_interactions > 0:
            dashboard_recs.append(
                f"{critical_interactions} critical-severity interaction(s) detected — review and escalate to incidents."
            )
        if active_campaigns == 0 and total_decoys > 2:
            dashboard_recs.append(
                "Decoys are deployed but not grouped into campaigns — create a campaign to track effectiveness."
            )

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
            top_attacker_profiles=top_attacker_profiles,
            recommendations=dashboard_recs,
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
    org_id: OrganizationId = None,
):
    """Get network coverage map for deception infrastructure.

    Authenticated and org-scoped. No client-supplied organization_id.
    """
    try:
        organization_id = org_id
        query = select(Decoy).where(Decoy.status == "active")
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
    org_id: OrganizationId = None,
):
    """Get recommendations for improving deception coverage.

    Authenticated and org-scoped. No client-supplied organization_id.
    """
    try:
        organization_id = org_id
        # Count decoys by category to find gaps
        query = (
            select(Decoy.category, func.count(Decoy.id))
            .where(Decoy.status == "active")
            .group_by(Decoy.category)
        )
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

        # Map each category gap to a concrete DeploymentRecommendation.
        # Must match the DeploymentRecommendation schema shape, not a
        # bare string. The ``high_priority`` ones are gaps in categories
        # where the tenant has zero coverage against a common attack
        # vector (credential theft, AD lateral movement, cloud key abuse).
        from src.schemas.deception import DeploymentRecommendation

        rec_templates: dict[str, dict] = {
            "network": {
                "decoy_type": "honeypot",
                "service": "ssh",
                "purpose": "Catch scanning and lateral movement with an SSH/RDP emulation.",
                "priority": "medium",
                "estimated_value": "high",
            },
            "credential": {
                "decoy_type": "honeytoken",
                "location": "config files, CI environment, .env",
                "purpose": "Detect credential theft via fake AWS keys and API keys.",
                "priority": "high",
                "estimated_value": "high",
            },
            "file": {
                "decoy_type": "honeyfile",
                "location": "shared drives, user profiles",
                "filename": "customer-data-backup.xlsx",
                "purpose": "Detect ransomware reconnaissance and insider data access.",
                "priority": "medium",
                "estimated_value": "high",
            },
            "dns": {
                "decoy_type": "honeypot",
                "service": "dns",
                "purpose": "Catch subdomain enumeration and exfiltration over DNS.",
                "priority": "medium",
                "estimated_value": "medium",
            },
            "email": {
                "decoy_type": "honeytoken",
                "location": "address book, archived mailboxes",
                "purpose": "Catch mailbox compromise via honeytoken email aliases.",
                "priority": "medium",
                "estimated_value": "medium",
            },
            "cloud": {
                "decoy_type": "honeytoken",
                "location": "AWS/GCP/Azure",
                "purpose": "Detect cloud enumeration and IAM key abuse with decoy buckets/IAM users.",
                "priority": "high",
                "estimated_value": "high",
            },
            "active_directory": {
                "decoy_type": "honeycred",
                "location": "Active Directory",
                "purpose": "Catch Kerberoasting with SPN-protected decoy accounts.",
                "priority": "high",
                "estimated_value": "high",
            },
            "database": {
                "decoy_type": "honeypot",
                "service": "postgres",
                "purpose": "Catch SQL injection and data theft with a decoy DB and plausible table names.",
                "priority": "medium",
                "estimated_value": "high",
            },
        }
        high_priority_categories = {"credential", "active_directory", "cloud"}

        def _build_rec(cat: str) -> DeploymentRecommendation:
            t = rec_templates[cat]
            return DeploymentRecommendation(
                zone=cat,
                decoy_type=t.get("decoy_type", ""),
                service=t.get("service"),
                location=t.get("location"),
                filename=t.get("filename"),
                purpose=t.get("purpose", ""),
                priority=t.get("priority", "medium"),
                estimated_value=t.get("estimated_value", "high"),
            )

        recommendations = [_build_rec(g) for g in gaps if g in rec_templates]
        high_priority_items = [
            _build_rec(g)
            for g in gaps
            if g in rec_templates and g in high_priority_categories
        ]

        logger.info("Retrieved deception recommendations")

        return RecommendationsResponse(
            recommendations=recommendations,
            coverage_gaps=gaps,
            high_priority_items=high_priority_items,
        )

    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve recommendations",
        )
