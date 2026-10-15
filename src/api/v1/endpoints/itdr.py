"""
ITDR (Identity Threat Detection & Response) API Endpoints

Provides REST API for identity threat detection, credential monitoring,
access anomaly analysis, and privileged access management.
"""

import math
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status, BackgroundTasks
import json

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.context import Mode
from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    RedisClient,
    require_role,
)
from src.models.user import User, UserRole
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.services.automation import AutomationService
from src.itdr.models import (
    IdentityProfile,
    IdentityThreat,
    CredentialExposure,
    AccessAnomaly,
    PrivilegedAccessEvent,
)
from src.itdr.analytics import analyze_auth_events_for_org, check_credential_exposures_for_org
from src.itdr.directory import (
    CSV_ALIASES,
    CSV_MAX_BYTES,
    CSV_MAX_ROWS,
    IDP_ACTIONS,
    SUPPORTED_CONNECTORS,
    awaiting_integration_detail,
    connector_name,
    identity_integrations,
    parse_identity_csv,
    provider_for_identity,
    run_identity_action,
    upsert_identities,
)
from src.itdr.runs import SCAN, SYNC_PREFIX, run_statuses
from src.itdr.engine import (
    IdentityThreatDetector,
    CredentialMonitor,
    AccessBehaviorAnalyzer,
    PrivilegedAccessManager,
)
from src.schemas.itdr import (
    IdentityProfileCreate,
    IdentityProfileUpdate,
    IdentityProfileResponse,
    IdentityProfileListResponse,
    IdentityThreatCreate,
    IdentityThreatUpdate,
    IdentityThreatResponse,
    IdentityThreatListResponse,
    CredentialExposureCreate,
    CredentialExposureUpdate,
    CredentialExposureResponse,
    CredentialExposureListResponse,
    AccessAnomalyCreate,
    AccessAnomalyUpdate,
    AccessAnomalyResponse,
    AccessAnomalyListResponse,
    PrivilegedAccessEventCreate,
    PrivilegedAccessEventUpdate,
    PrivilegedAccessEventResponse,
    PrivilegedAccessEventListResponse,
    ThreatResponseAction,
    CredentialRemediationRequest,
    ElevationRequest,
    ITDRDashboardMetrics,
    IdentityActionRequest,
    IdentityImportResult,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/itdr", tags=["ITDR"])

#: Operational writes: identities, threats, triage, exposure checks, reviews.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
#: Access decisions and response actions: approve/revoke elevation.
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

#: Log rows one on-demand auth analysis may read (the beat run allows more).
ON_DEMAND_AUTH_ROWS = 10_000
#: Threat states that count as active on the dashboard.
ACTIVE_THREAT_STATES = ("detected", "investigating", "confirmed")
#: Privilege levels counted as privileged.
PRIVILEGED_LEVELS = ("admin", "privileged_access", "elevated")
#: ``action_type`` values whose account part goes to the identity provider
#: when one can act on the identity (see respond_to_threat).
IDENTITY_PROVIDER_ACTION: dict[str, str] = {
    "disable_account": "disable_account",
    "disable_user": "disable_account",
    "force_password_reset": "force_password_reset",
    "quarantine": "disable_account",
}


async def get_identity_or_404(
    db: AsyncSession, identity_id: str, org_id: str
) -> IdentityProfile:
    """Get the caller's identity profile by ID or raise 404 (always tenant-scoped)"""
    stmt = select(IdentityProfile).where(IdentityProfile.id == identity_id)
    stmt = stmt.where(IdentityProfile.organization_id == org_id)
    result = await db.execute(stmt)
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity profile not found",
        )
    return identity


async def get_threat_or_404(
    db: AsyncSession, threat_id: str, org_id: str
) -> IdentityThreat:
    """Get the caller's identity threat by ID or raise 404 (always tenant-scoped)"""
    stmt = select(IdentityThreat).where(IdentityThreat.id == threat_id)
    stmt = stmt.where(IdentityThreat.organization_id == org_id)
    result = await db.execute(stmt)
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity threat not found",
        )
    return threat


# ============================================================================
# Identity Profile Endpoints
# ============================================================================


@router.get("/identities", response_model=IdentityProfileListResponse)
async def list_identities(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    privilege_level: Optional[str] = None,
    is_service_account: Optional[bool] = None,
    is_dormant: Optional[bool] = None,
    min_risk_score: Optional[float] = Query(None, ge=0.0, le=100.0),
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List identity profiles with filtering and pagination"""
    query = select(IdentityProfile)

    # Filter by organization
    query = query.where(IdentityProfile.organization_id == org_id)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (IdentityProfile.username.ilike(search_filter))
            | (IdentityProfile.email.ilike(search_filter))
            | (IdentityProfile.display_name.ilike(search_filter))
        )

    if privilege_level:
        query = query.where(IdentityProfile.privilege_level == privilege_level)

    if is_service_account is not None:
        query = query.where(IdentityProfile.is_service_account == is_service_account)

    if is_dormant is not None:
        query = query.where(IdentityProfile.is_dormant == is_dormant)

    if min_risk_score is not None:
        query = query.where(IdentityProfile.risk_score >= min_risk_score)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(IdentityProfile, sort_by, IdentityProfile.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    identities = result.scalars().all()

    return IdentityProfileListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[IdentityProfileResponse.model_validate(i) for i in identities],
    )


@router.get("/identities/{identity_id}", response_model=IdentityProfileResponse)
async def get_identity(
    identity_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get identity profile details"""
    identity = await get_identity_or_404(
        db, identity_id, org_id
    )
    return IdentityProfileResponse.model_validate(identity)


@router.post("/identities", response_model=IdentityProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_identity(
    data: IdentityProfileCreate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create new identity profile"""
    identity = IdentityProfile(
        organization_id=org_id,
        **data.dict()
    )
    db.add(identity)
    await db.commit()
    await db.refresh(identity)
    logger.info(f"Identity created: {identity.username}")
    return IdentityProfileResponse.model_validate(identity)


@router.put("/identities/{identity_id}", response_model=IdentityProfileResponse)
async def update_identity(
    identity_id: str,
    data: IdentityProfileUpdate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update identity profile"""
    identity = await get_identity_or_404(
        db, identity_id, org_id
    )
    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(identity, field, value)
    await db.commit()
    await db.refresh(identity)
    logger.info(f"Identity updated: {identity.username}")
    return IdentityProfileResponse.model_validate(identity)


@router.get("/identities/{identity_id}/risk-score")
async def get_identity_risk_score(
    identity_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get identity risk score breakdown"""
    identity = await get_identity_or_404(
        db, identity_id, org_id
    )

    # Count threats
    threat_result = await db.execute(
        select(func.count()).where(
            IdentityThreat.identity_id == identity_id,
            IdentityThreat.organization_id == org_id,
        )
    )
    threat_count = threat_result.scalar() or 0

    # Count critical threats
    critical_result = await db.execute(
        select(func.count()).where(
            (IdentityThreat.identity_id == identity_id)
            & (IdentityThreat.organization_id == org_id)
            & (IdentityThreat.severity == "critical")
        )
    )
    critical_count = critical_result.scalar() or 0

    # Count anomalies
    anomaly_result = await db.execute(
        select(func.count()).where(
            AccessAnomaly.identity_id == identity_id,
            AccessAnomaly.organization_id == org_id,
        )
    )
    anomaly_count = anomaly_result.scalar() or 0

    # Count exposures
    exposure_result = await db.execute(
        select(func.count()).where(
            CredentialExposure.identity_id == identity_id,
            CredentialExposure.organization_id == org_id,
        )
    )
    exposure_count = exposure_result.scalar() or 0

    return {
        "identity_id": identity_id,
        "username": identity.username,
        "risk_score": identity.risk_score,
        "threat_count": threat_count,
        "critical_threats": critical_count,
        "anomalies": anomaly_count,
        "credential_exposures": exposure_count,
        "risk_breakdown": {
            "threats_contribution": min(40.0, critical_count * 15 + (threat_count - critical_count) * 5),
            "anomalies_contribution": min(30.0, anomaly_count * 3),
            "credentials_contribution": min(30.0, exposure_count * 5),
        },
    }


# ============================================================================
# Identity Threat Endpoints
# ============================================================================


@router.get("/threats", response_model=IdentityThreatListResponse)
async def list_threats(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    identity_id: Optional[str] = None,
    min_confidence: Optional[float] = Query(None, ge=0.0, le=100.0),
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List identity threats with filtering"""
    query = select(IdentityThreat)

    # Filter by organization
    query = query.where(IdentityThreat.organization_id == org_id)

    if threat_type:
        query = query.where(IdentityThreat.threat_type == threat_type)

    if severity:
        query = query.where(IdentityThreat.severity == severity)

    if status:
        query = query.where(IdentityThreat.status == status)

    if identity_id:
        query = query.where(IdentityThreat.identity_id == identity_id)

    if min_confidence is not None:
        query = query.where(IdentityThreat.confidence_score >= min_confidence)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(IdentityThreat, sort_by, IdentityThreat.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    threats = result.scalars().all()

    return IdentityThreatListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[IdentityThreatResponse.model_validate(t) for t in threats],
    )


@router.get("/threats/{threat_id}", response_model=IdentityThreatResponse)
async def get_threat(
    threat_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get identity threat details"""
    threat = await get_threat_or_404(
        db, threat_id, org_id
    )
    return IdentityThreatResponse.model_validate(threat)


@router.post("/threats", response_model=IdentityThreatResponse, status_code=status.HTTP_201_CREATED)
async def create_threat(
    data: IdentityThreatCreate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create new identity threat"""
    threat_data = data.dict()
    # Convert empty identity_id to None to avoid FK violation
    if not threat_data.get("identity_id"):
        threat_data["identity_id"] = None
    else:
        # Never link a threat to another tenant's identity (or a missing one,
        # which used to surface as a foreign-key 500).
        await get_identity_or_404(db, threat_data["identity_id"], org_id)
    threat = IdentityThreat(
        organization_id=org_id,
        **threat_data
    )
    db.add(threat)
    await db.commit()
    await db.refresh(threat)

    # Trigger automation rules
    try:
        automation = AutomationService(db)
        await automation.on_itdr_threat(
            threat_type=threat.threat_type,
            identity=threat.identity_id or "unknown",
            risk_level=threat.severity or "high",
            organization_id=org_id,
        )
    except Exception as e:
        logger.error(f"Automation failed for ITDR threat {threat.id}: {e}")

    logger.warning(f"Identity threat created: {threat.threat_type} ({threat.severity})")
    return IdentityThreatResponse.model_validate(threat)


@router.put("/threats/{threat_id}", response_model=IdentityThreatResponse)
async def update_threat(
    threat_id: str,
    data: IdentityThreatUpdate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update identity threat status and details"""
    threat = await get_threat_or_404(
        db, threat_id, org_id
    )
    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(threat, field, value)
    await db.commit()
    await db.refresh(threat)
    logger.info(f"Identity threat updated: {threat.threat_type} -> {threat.status}")
    return IdentityThreatResponse.model_validate(threat)


#: ``action_type`` -> the guarded tools that carry it out. Everything here is
#: a real registry tool; ``contain`` deliberately maps to nothing, because
#: marking a threat contained is a bookkeeping act, not a response action.
RESPONSE_TOOLS: dict[str, tuple[str, ...]] = {
    "disable_account": ("disable_user",),
    "disable_user": ("disable_user",),
    "force_password_reset": ("disable_user",),
    "isolate_host": ("isolate_host",),
    "block_ip": ("block_ip",),
    "quarantine": ("disable_user", "isolate_host"),
    "open_incident": ("create_incident",),
    "contain": (),
}


def _propose_actions(data: ThreatResponseAction) -> bool:
    """``propose_actions`` out of ``action_details`` (default ``False``).

    ``ThreatResponseAction`` is shared with the other ITDR surfaces, so the
    flag travels in ``action_details`` rather than widening that schema.
    Default ``False`` means a destructive action is *denied* unless the
    caller asked for a proposal -- it is never silently escalated.
    """
    details = data.action_details if isinstance(data.action_details, dict) else {}
    return bool(details.get("propose_actions", False))


def _missing_argument(action: str, name: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error": "invalid_arguments",
            "detail": f"action_type '{action}' requires action_details.{name}",
        },
    )


def _response_tool_calls(
    action: str,
    threat: IdentityThreat,
    details: dict[str, Any],
    target_user: Optional[str],
) -> list[tuple[str, dict[str, Any]]]:
    """The (tool, arguments) pairs one ``action_type`` expands into.

    Raises 400 when the action needs a target the request did not supply:
    the previous implementation swallowed that case and still reported the
    threat contained, which claimed a response that never happened.
    """
    tools = RESPONSE_TOOLS.get(action)
    if tools is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "unknown_action",
                "detail": f"unsupported action_type '{action}'",
                "supported": sorted(RESPONSE_TOOLS),
            },
        )

    threat_type = threat.threat_type or "identity threat"
    reason = (
        f"password reset required: {threat_type}" if action == "force_password_reset"
        else f"ITDR quarantine: {threat_type}" if action == "quarantine"
        else f"ITDR threat {threat_type}"
    )
    calls: list[tuple[str, dict[str, Any]]] = []
    for tool in tools:
        if tool == "disable_user":
            if not target_user:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "no_identity_target",
                        "detail": (
                            "this threat has no identity profile with an email or username, "
                            "so no account can be disabled"
                        ),
                    },
                )
            calls.append(("disable_user", {"user_email": target_user, "reason": reason}))
        elif tool == "isolate_host":
            hostname = details.get("hostname")
            if not hostname:
                raise _missing_argument(action, "hostname")
            calls.append(("isolate_host", {"hostname": str(hostname), "reason": reason}))
        elif tool == "block_ip":
            ip = details.get("ip") or threat.source_ip
            if not ip:
                raise _missing_argument(action, "ip")
            calls.append(("block_ip", {"ip": str(ip), "reason": reason}))
        elif tool == "create_incident":
            calls.append((
                "create_incident",
                {
                    "title": f"ITDR: {threat_type} on {target_user or threat.identity_id or threat.id}"[:500],
                    "severity": threat.severity or "high",
                    "description": str(threat.evidence or "")[:1500],
                },
            ))
    return calls


@router.post("/threats/{threat_id}/respond")
async def respond_to_threat(
    threat_id: str,
    data: ThreatResponseAction,
    request: Request,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
):
    """Respond to an identity threat through the guarded agent runtime.

    The response action is no longer dispatched with the ungated
    ``AgentToolRegistry.execute``. It runs through ``guarded_tool_call`` --
    the single implementation shared with
    ``POST /agentic/tools/{tool_name}/execute`` -- so role, tier, reference
    scoping, the per-(org, tool) rate limit and the pre/post audit pair all
    apply, and a ``destructive`` tool is *proposed* for approval instead of
    being executed inline (design v2 sections 1, 3 and 8). The policy/tool
    audit pair is written by that path, so this endpoint adds no audit rows
    of its own.

    Identity comes from the JWT: the caller's organization, user id, agent
    role and client IP. Only admins may respond (viewers and analysts get
    403 ``role_not_permitted``); the threat is looked up inside
    the caller's organization, so another tenant's threat is a 404.

    ``action_details`` carries the tool arguments for the action
    (``ip`` for ``block_ip``, ``hostname`` for ``isolate_host``) and
    ``propose_actions`` (default ``false``): without it a destructive action
    is denied with ``403 {"reason_code": ...}`` rather than silently
    proposed.

    Action types:
      - ``disable_account`` / ``disable_user`` -> ``disable_user``
      - ``force_password_reset``              -> ``disable_user`` (reset reason)
      - ``isolate_host``                      -> ``isolate_host``
      - ``block_ip``                          -> ``block_ip``
      - ``quarantine``                        -> ``disable_user`` + ``isolate_host``
      - ``open_incident``                     -> ``create_incident``
      - ``contain`` (default)                 -> marks the threat contained only

    Returns ``{"proposed": true, "proposal": {...}}`` for a destructive
    action, exactly as the direct-execute surface does, and
    ``{"executed": true, "results": [...]}`` once the tools actually ran.
    ``quarantine`` expands to two tools, so it also returns ``proposals``
    with one entry per tool; if the second is refused the request fails with
    that denial while the first proposal stays recorded as pending approval
    (nothing was executed either way, and both decisions are in the audit
    trail).

    The threat is only marked ``contained`` once a tool actually executed --
    a proposal leaves the status untouched rather than claiming a response
    that has not happened yet.

    Wave 3: for ``disable_account`` / ``disable_user`` /
    ``force_password_reset`` / ``quarantine`` the payload carries
    ``identity_provider``. When an installed Okta / Entra ID integration can
    act on the threat's identity, the account step runs as the guarded
    ``identity_provider_action`` tool (in place of ``disable_user``, which
    only touches a PySOAR login) through the same ``guarded_tool_call`` path:
    the response is a proposal naming that tool and its parameters, and the
    provider is only called once an approver executes it
    (``POST /agentic/actions/{id}/approve``). When no integration can act on
    the account, ``identity_provider`` reports ``awaiting_integration`` with
    the missing dependency and ``disable_user`` is proposed as before.
    """
    from src.api.v1.endpoints.agentic import (
        _agent_context,
        _require_admin,
        guarded_tool_call,
    )

    ctx = _agent_context(
        current_user,
        Mode.INTERACTIVE,
        propose_actions=_propose_actions(data),
        request=request,
    )
    # Response actions (disable account, block, isolate, quarantine) are
    # admin-only; analysts triage via PUT /threats/{id} and /investigate.
    _require_admin(ctx)

    threat = await get_threat_or_404(db, threat_id, org_id)
    action = (data.action_type or "contain").strip().lower()
    details = data.action_details if isinstance(data.action_details, dict) else {}

    identity_row: Optional[IdentityProfile] = None
    if threat.identity_id:
        identity_row = (await db.execute(
            select(IdentityProfile).where(
                IdentityProfile.id == threat.identity_id,
                IdentityProfile.organization_id == ctx.org_id,
            )
        )).scalar_one_or_none()
    target_user = getattr(identity_row, "email", None) or getattr(
        identity_row, "username", None
    )

    idp_action = IDENTITY_PROVIDER_ACTION.get(action)
    idp_integration = None
    if idp_action and identity_row is not None:
        idp_integration = await provider_for_identity(db, ctx.org_id, identity_row)

    calls = _response_tool_calls(action, threat, details, target_user)
    if idp_action and idp_integration is not None and identity_row is not None:
        # The account lives in the directory: act on it there, through the
        # guarded identity_provider_action tool (policy gate, propose mode,
        # approval), instead of disabling a PySOAR login with the same email.
        calls = [
            (
                "identity_provider_action",
                {"identity_id": identity_row.id, "action": idp_action, "reason": params["reason"]},
            )
            if tool_name == "disable_user" else (tool_name, params)
            for tool_name, params in calls
        ]

    results: list[dict[str, Any]] = []
    proposals: list[dict[str, Any]] = []
    executed = 0
    identity_provider: Optional[dict[str, Any]] = None
    if idp_action and idp_integration is None:
        identity_provider = {
            "status": "awaiting_integration",
            "missing_dependency": (
                awaiting_integration_detail(identity_row) if identity_row is not None
                else "an identity profile linked to this threat"
            ),
            "detail": (
                "No identity-provider integration can act on this account, so it was not changed in any "
                "directory. The disable_user tool below acts on a PySOAR login account with the same email, "
                "if one exists."
            ),
        }
    for tool_name, params in calls:
        outcome = await guarded_tool_call(
            db,
            ctx,
            redis,
            tool_name,
            params,
            purpose="itdr_response",
            proposal_trigger_type="itdr_threat",
            proposal_source_id=threat_id,
            proposal_title=f"ITDR response proposals: {threat.threat_type or 'identity threat'}",
            proposal_hypothesis=(
                "Destructive identity-threat responses are proposed for approval, "
                "never executed inline."
            ),
        )
        results.append({"tool": tool_name, **outcome})
        if outcome.get("proposed"):
            proposals.append(outcome["proposal"])
        else:
            executed += 1
        if tool_name == "identity_provider_action" and idp_integration is not None:
            provider = connector_name(idp_integration)
            if outcome.get("proposed"):
                identity_provider = {
                    "status": "proposed",
                    "tool": tool_name,
                    "provider": provider,
                    "integration_id": idp_integration.id,
                    "action": idp_action,
                    "proposal_id": outcome["proposal"].get("id"),
                    "detail": (
                        f"Nothing has been sent to {provider} yet: the {idp_action} call runs against the "
                        "directory account once an approver executes this proposal."
                    ),
                }
            else:
                tool_result = outcome.get("result") if isinstance(outcome.get("result"), dict) else {}
                identity_provider = {
                    "status": tool_result.get("status"),
                    "tool": tool_name,
                    "provider": tool_result.get("provider") or provider,
                    "integration_id": tool_result.get("integration_id") or idp_integration.id,
                    "action": idp_action,
                    "audit_log_id": tool_result.get("audit_log_id"),
                    "detail": tool_result.get("detail") or tool_result.get("error"),
                }

    if executed and not proposals:
        threat.status = "contained"
    elif not calls:
        threat.status = "contained"
    await db.commit()

    logger.info(
        "itdr_threat_response",
        threat_id=threat_id,
        organization_id=ctx.org_id,
        actor_id=ctx.actor_user_id,
        action=action,
        tools=[tool for tool, _params in calls],
        executed=executed,
        proposed=len(proposals),
    )

    payload: dict[str, Any] = {
        "threat_id": threat_id,
        "action": action,
        "proposed": bool(proposals),
        "executed": bool(executed),
        "results": results,
        "status": (
            "proposed" if proposals
            else "executed" if executed
            else "marked_contained"
        ),
        "threat_status": threat.status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if identity_provider is not None:
        payload["identity_provider"] = identity_provider
    if proposals:
        payload["proposal"] = proposals[0]
        payload["proposals"] = proposals
    return payload


@router.post("/threats/scan")
async def run_threat_scan(
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Run identity threat detection scan synchronously.

    Previously returned a fake scan_id and claimed work was happening
    in the background — nothing actually ran. Now scans every
    IdentityProfile in the caller's organization for three real
    risk signals and creates IdentityThreat rows for each hit:

      - **dormant_admin**: is_dormant == True AND role contains "admin"
      - **mfa_missing_privileged**: mfa_enabled == False AND
        role contains "admin" or "root" or is_privileged == True
      - **stale_credential**: last_password_change older than 180 days

    Already-open threats of the same type on the same identity are
    skipped so re-running the scan is idempotent within its cooldown
    window. The dropped ``organization_id`` query parameter was a
    cross-tenant vector — the scan always runs in the caller's organisation
    (``OrganizationId``; an org-less caller is refused).
    """
    from src.itdr.models import ThreatStatus, PrivilegeLevel

    logger.info(f"Running identity threat scan for org={org_id}")

    now = datetime.now(timezone.utc)
    cutoff_180d = now - timedelta(days=180)

    id_query = select(IdentityProfile)
    id_query = id_query.where(IdentityProfile.organization_id == org_id)
    identities = list((await db.execute(id_query)).scalars().all())

    # Preload open threats so we can dedupe
    existing_q = select(IdentityThreat).where(
        IdentityThreat.status.in_([
            ThreatStatus.DETECTED.value,
            ThreatStatus.INVESTIGATING.value,
        ])
    )
    existing_q = existing_q.where(IdentityThreat.organization_id == org_id)
    existing_rows = list((await db.execute(existing_q)).scalars().all())
    existing_by_identity: dict[str, set[str]] = {}
    for t in existing_rows:
        existing_by_identity.setdefault(t.identity_id, set()).add(t.threat_type)

    def _create_threat(
        identity_id: str,
        threat_type: str,
        severity: str,
        evidence: dict,
    ) -> bool:
        if threat_type in existing_by_identity.get(identity_id, set()):
            return False
        threat = IdentityThreat(
            organization_id=org_id,
            identity_id=identity_id,
            threat_type=threat_type,
            severity=severity,
            confidence_score=90.0,  # 0-100 scale (schemas/itdr.py)
            evidence=evidence,
            status=ThreatStatus.DETECTED.value,
        )
        db.add(threat)
        return True

    def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
        """IdentityProfile stores last_password_change as an ISO
        string rather than a DateTime column, so normalize it here."""
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    scanned = len(identities)
    created = 0
    # Collect (identity, threat_type, severity) tuples so we can fire
    # automation.on_itdr_threat for each one AFTER the flush — that
    # keeps the event fan-out outside the tight loop and ensures the
    # threat row is committed before downstream handlers read it.
    fired_threats: list[tuple[str, str, str, str]] = []
    for identity in identities:
        # role_assignments is a JSON list on the model, not a scalar role.
        role_list = getattr(identity, "role_assignments", None) or []
        if isinstance(role_list, str):
            try:
                role_list = json.loads(role_list)
            except Exception:  # noqa: BLE001
                role_list = []
        roles_lower = [str(r).lower() for r in role_list] if isinstance(role_list, list) else []
        has_admin_role = any(("admin" in r or "root" in r) for r in roles_lower)

        privilege_level = (getattr(identity, "privilege_level", "") or "").lower()
        is_privileged = has_admin_role or privilege_level in (
            PrivilegeLevel.ADMIN.value if hasattr(PrivilegeLevel, "ADMIN") else "admin",
            "privileged",
            "root",
            "super",
        )

        # 1) dormant_admin
        if getattr(identity, "is_dormant", False) and has_admin_role:
            if _create_threat(
                identity.id,
                "dormant_admin",
                "high",
                {
                    "username": identity.username,
                    "roles": role_list,
                    "reason": "dormant account retains admin privileges",
                },
            ):
                created += 1
                fired_threats.append(
                    ("dormant_admin", identity.username, "high",
                     "Dormant privileged account retains admin privileges")
                )

        # 2) mfa_missing_privileged
        if is_privileged and not getattr(identity, "mfa_enabled", False):
            if _create_threat(
                identity.id,
                "mfa_missing_privileged",
                "critical",
                {
                    "username": identity.username,
                    "privilege_level": privilege_level,
                    "reason": "privileged identity has no MFA enrolled",
                },
            ):
                created += 1
                fired_threats.append(
                    ("mfa_missing_privileged", identity.username, "critical",
                     "Privileged identity has no MFA enrolled")
                )

        # 3) stale_credential (password > 180 days old)
        last_pw = _parse_iso(getattr(identity, "last_password_change", None))
        if last_pw is not None and last_pw < cutoff_180d:
            age_days = (now - last_pw).days
            if _create_threat(
                identity.id,
                "stale_credential",
                "medium",
                {
                    "username": identity.username,
                    "last_password_change": last_pw.isoformat(),
                    "age_days": age_days,
                },
            ):
                created += 1
                fired_threats.append(
                    ("stale_credential", identity.username, "medium",
                     f"Password last rotated {age_days} days ago")
                )

    await db.flush()

    # Fan out to the cross-module automation pipeline. Each threat
    # that was actually created (not deduped) fires on_itdr_threat,
    # which creates an Alert and runs the full on_alert_created chain
    # (IOC match -> auto-incident -> war room -> remediation policy
    # eval -> agent containment if affected_systems is set). Failures
    # are logged but don't roll back the scan — we'd rather have the
    # threat rows persisted than lose the whole scan on an
    # automation hiccup.
    try:
        automation = AutomationService(db)
        for threat_type, username, severity, details in fired_threats:
            try:
                await automation.on_itdr_threat(
                    threat_type=threat_type,
                    identity=username,
                    risk_level=severity,
                    details=details,
                    organization_id=org_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    f"on_itdr_threat failed for {username}/{threat_type}: {exc}"
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"AutomationService setup failed during threat scan: {exc}")

    logger.info(
        f"Identity threat scan complete: scanned={scanned} created={created}"
    )
    from src.itdr.runs import record_run

    await record_run(
        db, org_id, SCAN, status="ok", rows=scanned,
        summary={"identities_scanned": scanned, "threats_created": created},
    )
    await db.commit()
    return {
        "status": "completed",
        "organization_id": org_id,
        "identities_scanned": scanned,
        "threats_created": created,
        "completed_at": now.isoformat(),
    }


# ============================================================================
# Credential Exposure Endpoints
# ============================================================================


@router.get("/credential-exposures", response_model=CredentialExposureListResponse)
async def list_exposures(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    credential_type: Optional[str] = None,
    exposure_source: Optional[str] = None,
    is_remediated: Optional[bool] = None,
    identity_id: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List credential exposures"""
    query = select(CredentialExposure)

    # Filter by organization
    query = query.where(CredentialExposure.organization_id == org_id)

    if credential_type:
        query = query.where(CredentialExposure.credential_type == credential_type)

    if exposure_source:
        query = query.where(CredentialExposure.exposure_source == exposure_source)

    if is_remediated is not None:
        query = query.where(CredentialExposure.is_remediated == is_remediated)

    if identity_id:
        query = query.where(CredentialExposure.identity_id == identity_id)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(CredentialExposure, sort_by, CredentialExposure.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    exposures = result.scalars().all()

    return CredentialExposureListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[CredentialExposureResponse.model_validate(e) for e in exposures],
    )


@router.get("/credential-exposures/{exposure_id}", response_model=CredentialExposureResponse)
async def get_exposure(
    exposure_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get credential exposure details"""
    stmt = select(CredentialExposure).where(CredentialExposure.id == exposure_id)
    stmt = stmt.where(CredentialExposure.organization_id == org_id)
    result = await db.execute(stmt)
    exposure = result.scalar_one_or_none()
    if not exposure:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential exposure not found",
        )
    return CredentialExposureResponse.model_validate(exposure)


@router.post("/credential-exposures/check")
async def check_credential_exposure(
    identity_id: str,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Check an identity's credentials against known exposure sources.

    Queries the ``darkweb_credential_leaks`` table for any leaks that
    match this identity's email or username, and creates a new
    ``CredentialExposure`` row for each unique hit that isn't already
    tracked for this identity. Returns the number of new exposures
    found plus the existing ones so the operator can act immediately.

    Previous version just returned ``{"status": "check_initiated"}``
    and did nothing — the button was theater.
    """
    from src.darkweb.models import CredentialLeak

    identity = await get_identity_or_404(db, identity_id, org_id)

    # Match leaks by email OR username (case-insensitive)
    email = (identity.email or "").lower()
    username = (identity.username or "").lower()

    leak_query = select(CredentialLeak).where(
        CredentialLeak.organization_id == org_id
    )
    if email or username:
        conditions = []
        if email:
            conditions.append(func.lower(CredentialLeak.email) == email)
        if username:
            conditions.append(func.lower(CredentialLeak.username) == username)
        leak_query = leak_query.where(or_(*conditions))
    else:
        leak_query = leak_query.where(CredentialLeak.email.is_(None))  # no-op

    leak_rows = list((await db.execute(leak_query)).scalars().all())

    # Dedupe against existing CredentialExposure rows for this identity
    existing_q = select(CredentialExposure).where(
        and_(
            CredentialExposure.organization_id == org_id,
            CredentialExposure.identity_id == identity_id,
        )
    )
    existing = list((await db.execute(existing_q)).scalars().all())
    existing_sources = {
        f"{e.exposure_source}:{e.breach_name or ''}" for e in existing
    }

    new_exposures: list[CredentialExposure] = []
    for leak in leak_rows:
        key = f"darkweb:{leak.breach_source or ''}"
        if key in existing_sources:
            continue
        exposure = CredentialExposure(
            organization_id=org_id,
            identity_id=identity_id,
            exposure_source="darkweb",
            credential_type=leak.password_type or "password",
            exposure_date=leak.breach_date,
            discovery_date=datetime.now(timezone.utc).isoformat(),
            breach_name=leak.breach_source,
            is_remediated=leak.is_remediated,
        )
        db.add(exposure)
        new_exposures.append(exposure)
        existing_sources.add(key)

    await db.flush()

    logger.info(
        f"Credential exposure check for {identity_id}: "
        f"{len(leak_rows)} leaks matched, {len(new_exposures)} new exposures created"
    )

    # Cross-module loop: NEW credential exposures are high-severity
    # events that should kick the full automation chain. Use the
    # darkweb handler because that's where the evidence lives — it
    # creates an Alert with source=darkweb and fires on_alert_created
    # (IOC match / auto-incident / remediation policy eval).
    if new_exposures:
        try:
            automation = AutomationService(db)
            sources = sorted({e.breach_name or "unknown" for e in new_exposures})
            await automation.on_darkweb_finding(
                finding_type="exposed_credentials",
                description=(
                    f"{len(new_exposures)} new credential exposure(s) found for "
                    f"{identity.email or identity.username} in breaches: "
                    f"{', '.join(sources)}"
                ),
                severity="high",
                organization_id=org_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"on_darkweb_finding failed for new credential exposures: {exc}"
            )

    return {
        "status": "completed",
        "identity_id": identity_id,
        "leaks_matched": len(leak_rows),
        "new_exposures_created": len(new_exposures),
        "total_exposures_now": len(existing) + len(new_exposures),
        "sources_checked": ["darkweb_credential_leaks"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/credential-exposures/remediate")
async def remediate_exposures(
    data: CredentialRemediationRequest,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Mark credential exposures as remediated and record the action.

    Previously returned ``remediation_initiated`` without touching the
    database — the exposure rows stayed unremediated forever. Now
    updates each CredentialExposure row with ``is_remediated=True``,
    the remediation_action string, and a remediation_date stamp.
    Only exposures belonging to the caller's org are touched, so one
    tenant can't remediate another tenant's exposures.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    updated_count = 0
    skipped_count = 0

    if not data.exposure_ids:
        return {
            "status": "no_exposures_provided",
            "updated": 0,
            "skipped": 0,
        }

    query = select(CredentialExposure).where(
        and_(
            CredentialExposure.id.in_(data.exposure_ids),
            CredentialExposure.organization_id == org_id,
        )
    )
    exposures = list((await db.execute(query)).scalars().all())

    for exposure in exposures:
        if exposure.is_remediated:
            skipped_count += 1
            continue
        exposure.is_remediated = True
        exposure.remediation_date = now_iso
        exposure.remediation_action = data.remediation_type
        updated_count += 1

    # Any IDs the caller supplied that didn't belong to this org or
    # didn't exist get counted as skipped so the operator can see they
    # were ignored rather than silently succeeded.
    missing = set(data.exposure_ids) - {e.id for e in exposures}
    skipped_count += len(missing)

    await db.flush()

    logger.info(
        f"Credential remediation: updated={updated_count} skipped={skipped_count}"
    )

    return {
        "status": "completed",
        "updated": updated_count,
        "skipped": skipped_count,
        "remediation_type": data.remediation_type,
        "timestamp": now_iso,
    }


# ============================================================================
# Access Anomaly Endpoints
# ============================================================================


@router.get("/anomalies", response_model=AccessAnomalyListResponse)
async def list_anomalies(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    anomaly_type: Optional[str] = None,
    is_reviewed: Optional[bool] = None,
    identity_id: Optional[str] = None,
    min_deviation: Optional[float] = Query(None, ge=0.0, le=1.0),
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List access anomalies"""
    query = select(AccessAnomaly)

    # Filter by organization
    query = query.where(AccessAnomaly.organization_id == org_id)

    if anomaly_type:
        query = query.where(AccessAnomaly.anomaly_type == anomaly_type)

    if is_reviewed is not None:
        query = query.where(AccessAnomaly.is_reviewed == is_reviewed)

    if identity_id:
        query = query.where(AccessAnomaly.identity_id == identity_id)

    if min_deviation is not None:
        query = query.where(AccessAnomaly.deviation_score >= min_deviation)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(AccessAnomaly, sort_by, AccessAnomaly.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    anomalies = result.scalars().all()

    return AccessAnomalyListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[AccessAnomalyResponse.model_validate(a) for a in anomalies],
    )


@router.get("/anomalies/{anomaly_id}", response_model=AccessAnomalyResponse)
async def get_anomaly(
    anomaly_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get access anomaly details"""
    stmt = select(AccessAnomaly).where(AccessAnomaly.id == anomaly_id)
    stmt = stmt.where(AccessAnomaly.organization_id == org_id)
    result = await db.execute(stmt)
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access anomaly not found",
        )
    return AccessAnomalyResponse.model_validate(anomaly)


# ============================================================================
# Privileged Access Endpoints
# ============================================================================


@router.get("/privileged-access", response_model=PrivilegedAccessEventListResponse)
async def list_privileged_events(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    event_type: Optional[str] = None,
    identity_id: Optional[str] = None,
    was_revoked: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List privileged access events"""
    query = select(PrivilegedAccessEvent)

    # Filter by organization
    query = query.where(PrivilegedAccessEvent.organization_id == org_id)

    if event_type:
        query = query.where(PrivilegedAccessEvent.event_type == event_type)

    if identity_id:
        query = query.where(PrivilegedAccessEvent.identity_id == identity_id)

    if was_revoked is not None:
        query = query.where(PrivilegedAccessEvent.was_revoked == was_revoked)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(PrivilegedAccessEvent, sort_by, PrivilegedAccessEvent.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())

    # Apply pagination
    offset = (page - 1) * size
    result = await db.execute(query.offset(offset).limit(size))
    events = result.scalars().all()

    return PrivilegedAccessEventListResponse(
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size),
        items=[PrivilegedAccessEventResponse.model_validate(e) for e in events],
    )


@router.post("/privileged-access/request")
async def request_elevation(
    data: ElevationRequest,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Request privilege elevation"""
    identity = await get_identity_or_404(
        db, data.identity_id, org_id
    )

    event = PrivilegedAccessEvent(
        organization_id=org_id,
        identity_id=data.identity_id,
        event_type="elevation_request",
        target_resource=data.target_resource,
        justification=data.justification,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    logger.info(f"Elevation request created: {data.identity_id} for {data.target_resource}")

    return {
        "request_id": event.id,
        "identity_id": data.identity_id,
        "status": "pending_approval",
        "created_at": event.created_at,
    }


# ============================================================================
# Dashboard and Reporting Endpoints
# ============================================================================


@router.get("/dashboard/metrics", response_model=ITDRDashboardMetrics)
async def get_dashboard_metrics(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get ITDR dashboard metrics"""

    identity_base = select(func.count()).select_from(IdentityProfile)
    threat_base = select(func.count()).select_from(IdentityThreat)
    exposure_base = select(func.count()).select_from(CredentialExposure)
    anomaly_base = select(func.count()).select_from(AccessAnomaly)
    priv_base = select(func.count()).select_from(PrivilegedAccessEvent)

    identity_base = identity_base.where(IdentityProfile.organization_id == org_id)
    threat_base = threat_base.where(IdentityThreat.organization_id == org_id)
    exposure_base = exposure_base.where(CredentialExposure.organization_id == org_id)
    anomaly_base = anomaly_base.where(AccessAnomaly.organization_id == org_id)
    priv_base = priv_base.where(PrivilegedAccessEvent.organization_id == org_id)

    identities_result = await db.execute(identity_base)
    total_identities = identities_result.scalar() or 0

    at_risk_result = await db.execute(
        identity_base.where(IdentityProfile.risk_score >= 50)
    )
    at_risk = at_risk_result.scalar() or 0

    active_threat_base = threat_base.where(IdentityThreat.status.in_(ACTIVE_THREAT_STATES))
    critical_threats_result = await db.execute(
        active_threat_base.where(IdentityThreat.severity == "critical")
    )
    critical_threats = critical_threats_result.scalar() or 0

    high_threats_result = await db.execute(
        active_threat_base.where(IdentityThreat.severity == "high")
    )
    high_threats = high_threats_result.scalar() or 0
    active_threats = (await db.execute(active_threat_base)).scalar() or 0

    exposures_result = await db.execute(
        exposure_base.where(CredentialExposure.is_remediated == False)
    )
    exposures = exposures_result.scalar() or 0

    anomalies_result = await db.execute(
        anomaly_base.where(AccessAnomaly.is_reviewed == False)
    )
    anomalies = anomalies_result.scalar() or 0

    # Service accounts holding an admin / privileged / elevated level.
    service_accounts_result = await db.execute(
        identity_base.where(
            IdentityProfile.is_service_account.is_(True),
            IdentityProfile.privilege_level.in_(PRIVILEGED_LEVELS),
        ),
    )
    service_accounts_privileged = service_accounts_result.scalar() or 0
    privileged = (await db.execute(
        identity_base.where(IdentityProfile.privilege_level.in_(PRIVILEGED_LEVELS)),
    )).scalar() or 0
    with_mfa = (await db.execute(identity_base.where(IdentityProfile.mfa_enabled.is_(True)))).scalar() or 0
    by_source = dict((await db.execute(
        select(IdentityProfile.source, func.count(IdentityProfile.id))
        .where(IdentityProfile.organization_id == org_id)
        .group_by(IdentityProfile.source),
    )).all())

    dormant_result = await db.execute(
        identity_base.where(IdentityProfile.is_dormant == True)
    )
    dormant = dormant_result.scalar() or 0

    # Just-in-time grants not revoked and not past their expiry.
    now_iso = datetime.now(timezone.utc).isoformat()
    jit_result = await db.execute(
        priv_base.where(
            PrivilegedAccessEvent.event_type == "just_in_time_access",
            PrivilegedAccessEvent.was_revoked.is_(False),
            or_(
                PrivilegedAccessEvent.expiry_timestamp.is_(None),
                PrivilegedAccessEvent.expiry_timestamp > now_iso,
            ),
        ),
    )
    jit_active = jit_result.scalar() or 0

    overall_risk = min(100.0, critical_threats * 20 + high_threats * 10 + exposures * 5)
    jobs = await run_statuses(db, org_id)
    scan_runs = [j["last_run_at"] for j in jobs if j["job"] == SCAN and j["last_run_at"]]
    sync_runs = [
        j["last_run_at"] for j in jobs
        if j["job"].startswith(SYNC_PREFIX) and j["last_run_at"] and j["status"] in ("ok", "partial")
    ]
    integrations = [
        {"integration_id": i.id, "provider": connector_name(i), "display_name": i.display_name}
        for i in await identity_integrations(db, org_id)
    ]

    return ITDRDashboardMetrics(
        total_identities=total_identities,
        identities_at_risk=at_risk,
        critical_threats_active=critical_threats,
        high_threats_active=high_threats,
        credential_exposures_active=exposures,
        anomalies_pending_review=anomalies,
        service_accounts_over_privileged=service_accounts_privileged,
        dormant_accounts=dormant,
        jit_access_active=jit_active,
        last_scan_timestamp=max(scan_runs) if scan_runs else None,
        overall_risk_score=overall_risk,
        active_threats_total=active_threats,
        privileged_identities=privileged,
        identities_with_mfa=with_mfa,
        mfa_coverage_percent=round(100.0 * with_mfa / total_identities, 1) if total_identities else None,
        identities_by_source={(k or "manual"): int(v) for k, v in by_source.items()},
        last_directory_sync_at=max(sync_runs) if sync_runs else None,
        identity_integrations=integrations,
        jobs=jobs,
    )


# ============================================================================
# Edit endpoints for exposure / anomaly / privileged-access
# (threat update already exists at PUT /threats/{threat_id})
# ============================================================================


@router.put(
    "/credential-exposures/{exposure_id}",
    response_model=CredentialExposureResponse,
)
async def update_credential_exposure(
    exposure_id: str,
    data: CredentialExposureUpdate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update a single credential exposure record (tenant-scoped).

    Backs the ITDR dashboard's "Edit" modal so analysts can flip
    ``is_remediated``, set a ``remediation_action`` string, or adjust
    the ``remediation_date`` without going through the bulk
    remediate endpoint.
    """
    result = await db.execute(
        select(CredentialExposure).where(
            and_(
                CredentialExposure.id == exposure_id,
                CredentialExposure.organization_id == org_id,
            )
        )
    )
    exposure = result.scalar_one_or_none()
    if not exposure:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential exposure not found",
        )
    for field, value in data.dict(exclude_unset=True).items():
        setattr(exposure, field, value)
    await db.commit()
    await db.refresh(exposure)
    logger.info(f"Credential exposure updated: {exposure_id}")
    return CredentialExposureResponse.model_validate(exposure)


@router.put("/anomalies/{anomaly_id}", response_model=AccessAnomalyResponse)
async def update_access_anomaly(
    anomaly_id: str,
    data: AccessAnomalyUpdate,
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update an access anomaly record (tenant-scoped)."""
    result = await db.execute(
        select(AccessAnomaly).where(
            and_(
                AccessAnomaly.id == anomaly_id,
                AccessAnomaly.organization_id == org_id,
            )
        )
    )
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access anomaly not found",
        )
    for field, value in data.dict(exclude_unset=True).items():
        setattr(anomaly, field, value)
    await db.commit()
    await db.refresh(anomaly)
    logger.info(f"Access anomaly updated: {anomaly_id}")
    return AccessAnomalyResponse.model_validate(anomaly)


@router.put(
    "/privileged-access/{event_id}",
    response_model=PrivilegedAccessEventResponse,
)
async def update_privileged_access_event(
    event_id: str,
    data: PrivilegedAccessEventUpdate,
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update a privileged access event (tenant-scoped)."""
    result = await db.execute(
        select(PrivilegedAccessEvent).where(
            and_(
                PrivilegedAccessEvent.id == event_id,
                PrivilegedAccessEvent.organization_id == org_id,
            )
        )
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Privileged access event not found",
        )
    for field, value in data.dict(exclude_unset=True).items():
        setattr(event, field, value)
    await db.commit()
    await db.refresh(event)
    logger.info(f"Privileged access event updated: {event_id}")
    return PrivilegedAccessEventResponse.model_validate(event)


# ============================================================================
# Identity sources (wave 3): directory sync, CSV import, provider actions
# ============================================================================


@router.get("/identity-sources")
async def get_identity_sources(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Where identities come from: installed Okta / Entra ID integrations, job runs, CSV format.

    ``integrations`` lists the organisation's active identity-provider
    integrations PySOAR can sync and act on; ``jobs`` the last run of the
    directory syncs, the auth-event analysis and the identity scan;
    ``csv_import`` the accepted columns of ``POST /itdr/identities/import``
    (Active Directory exports use it: PySOAR has no LDAP connector).
    """
    integrations = [
        {"integration_id": i.id, "provider": connector_name(i), "display_name": i.display_name,
         "health_status": i.health_status}
        for i in await identity_integrations(db, org_id)
    ]
    counts = dict((await db.execute(
        select(IdentityProfile.source, func.count(IdentityProfile.id))
        .where(IdentityProfile.organization_id == org_id)
        .group_by(IdentityProfile.source)
    )).all())
    return {
        "integrations": integrations,
        "supported_providers": list(SUPPORTED_CONNECTORS),
        "identities_by_source": {(k or "manual"): int(v) for k, v in counts.items()},
        "jobs": await run_statuses(db, org_id),
        "csv_import": {
            "required": ["username", "email"],
            "columns": {k: list(v) for k, v in CSV_ALIASES.items()},
            "max_rows": CSV_MAX_ROWS,
            "max_bytes": CSV_MAX_BYTES,
            "list_separator": "; or |",
        },
    }


@router.post("/identities/sync")
async def sync_identities(
    integration_id: Optional[str] = Query(None, description="Sync only this installed integration"),
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Sync identities now from the organisation's Okta / Entra ID integrations (admin).

    409 ``no_identity_integration`` when none is installed and active (use
    ``POST /itdr/identities/import`` for Active Directory or other exports).
    Each integration reports ``ok`` / ``partial`` (the per-run user cap was
    reached) / ``failed`` with the provider's error.
    """
    from src.itdr.tasks import sync_org_directories

    result = await sync_org_directories(db, org_id, integration_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "no_identity_integration",
                "detail": (
                    "No active Okta or Entra ID integration is installed for this organisation"
                    + (f" with id {integration_id}" if integration_id else "")
                    + ". Install one under Integrations, or import a CSV export with POST /itdr/identities/import."
                ),
            },
        )
    return result


@router.post("/identities/import", response_model=IdentityImportResult)
async def import_identities(
    file: UploadFile = File(..., description="CSV export (UTF-8) with a header row"),
    dry_run: bool = Query(False, description="Validate only; write nothing"),
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create or update identities from a CSV export (admin).

    Required columns: ``username`` and ``email`` (``SamAccountName`` /
    ``UserPrincipalName`` / ``mail`` from ``Get-ADUser`` are accepted). Every
    row is validated; valid rows are imported and invalid ones reported with
    their line number. A file with no valid row is a 422.
    """
    content = await file.read(CSV_MAX_BYTES + 1)
    try:
        parsed = parse_identity_csv(content)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_csv", "detail": str(exc)},
        ) from exc
    if not parsed.records:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "no_valid_rows", "rows_read": parsed.rows_read, "errors": parsed.errors},
        )
    counts = {"created": 0, "updated": 0}
    if not dry_run:
        counts = await upsert_identities(db, org_id, parsed.records, source="csv_import")
        await db.commit()
    logger.info(
        "itdr_identity_import", organization_id=org_id, rows=parsed.rows_read, valid=len(parsed.records),
        invalid=parsed.error_count, dry_run=dry_run, **counts,
    )
    return IdentityImportResult(
        dry_run=dry_run, rows_read=parsed.rows_read, valid_rows=len(parsed.records),
        invalid_rows=parsed.error_count, created=counts["created"], updated=counts["updated"],
        columns=parsed.columns, errors=parsed.errors,
    )


@router.post("/identities/{identity_id}/actions/{action}")
async def identity_provider_action(
    identity_id: str,
    action: str,
    data: Optional[IdentityActionRequest] = None,
    current_user: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Act on the account in its identity provider (admin).

    ``action``: ``disable_account``, ``enable_account``,
    ``force_password_reset`` or ``revoke_sessions``. The result ``status`` is
    ``executed`` (the provider accepted every call) or
    ``awaiting_integration`` (no installed Okta / Entra ID integration can act
    on this identity; ``missing_dependency`` names it and nothing changed). A
    provider failure is a 502 carrying the same result. Every call writes an
    audit log row.
    """
    if action not in IDP_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "unknown_action", "supported": list(IDP_ACTIONS)},
        )
    identity = await get_identity_or_404(db, identity_id, org_id)
    reason = (data.reason if data else "") or f"ITDR {action} by {current_user.email}"
    result = await run_identity_action(db, org_id, identity, action, actor_user_id=current_user.id, reason=reason)
    await db.commit()
    if result["status"] == "failed":
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "identity_provider_failed", "result": result},
        )
    return result


@router.post("/auth-analysis/run")
async def run_auth_analysis(
    _caller: AdminRoleUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Analyse this organisation's new authentication log entries now (admin).

    Same job as the 5-minute beat run (src/itdr/analytics.py) with a smaller
    per-call cap; the remainder is read by the next run.
    """
    return await analyze_auth_events_for_org(db, org_id, max_rows=ON_DEMAND_AUTH_ROWS)


@router.post("/credential-exposures/check-all")
async def check_all_credential_exposures(
    _caller: AnalystUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Match every identity of the organisation against its dark-web credential leak rows.

    One call instead of one ``/credential-exposures/check`` per identity; the
    hourly beat runs the same check.
    """
    return await check_credential_exposures_for_org(db, org_id)
