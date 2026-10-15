"""Zero Trust Architecture REST API endpoints (NIST 800-207)"""

import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, desc, func, select

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.models.user import User, UserRole
from src.schemas.zerotrust import (
    AccessDecisionResponse,
    AccessRequestSchema,
    DeviceComplianceUpdate,
    DeviceTrustProfileResponse,
    IdentityVerificationCreate,
    IdentityVerificationResponse,
    MicroSegmentCreate,
    MicroSegmentResponse,
    MicroSegmentUpdate,
    SegmentTrafficRequest,
    SegmentTrafficResponse,
    ZeroTrustDashboardStats,
    ZeroTrustMaturityResponse,
    ZeroTrustPolicyCreate,
    ZeroTrustPolicyResponse,
    ZeroTrustPolicyUpdate,
)
from src.services.automation import AutomationService
from src.zerotrust.engine import (
    ContinuousAuthEngine,
    DeviceTrustAssessor,
    MicroSegmentationEngine,
    PolicyDecisionPoint,
    ZeroTrustScorer,
    device_posture,
)
from src.zerotrust.models import (
    AccessDecision,
    DeviceTrustProfile,
    IdentityVerification,
    MicroSegment,
    ZeroTrustPolicy,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/zerotrust", tags=["Zero Trust"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


def _device_response(device: DeviceTrustProfile) -> DeviceTrustProfileResponse:
    """Device profile plus the posture fields derived from its stored checks."""
    posture = device_posture(device)
    response = DeviceTrustProfileResponse.model_validate(device)
    return response.model_copy(update=posture)


def _device_summary(d: DeviceTrustProfile) -> dict[str, Any]:
    """List-row shape: stored fields plus derived posture (never a fabricated verdict)."""
    posture = device_posture(d)
    return {
        "id": d.id,
        "device_id": d.device_id,
        "hostname": d.hostname,
        "device_type": d.device_type,
        "os_type": d.os_type,
        "os_version": d.os_version,
        "trust_score": d.trust_score,
        "trust_level": d.trust_level,
        "last_seen": d.last_seen_at,
        "last_seen_at": d.last_seen_at,
        "last_assessment_at": d.last_assessment_at,
        "compliance_checks": posture["compliance_checks"],
        "is_compliant": posture["is_compliant"],
        "posture_status": posture["posture_status"],
        "posture_source": posture["posture_source"],
        "posture_reported_at": posture["posture_reported_at"],
    }


async def _get_segment_or_404(db: DatabaseSession, segment_id: str, org_id: str) -> MicroSegment:
    """Load a micro-segment in the caller's tenant, or 404."""
    result = await db.execute(
        select(MicroSegment).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == org_id,
            ),
        ),
    )
    segment = result.scalar_one_or_none()
    if not segment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Segment not found")
    return segment


async def _require_segment_field(db: DatabaseSession, segment_id: str | None, org_id: str) -> None:
    """422 naming ``microsegment_id`` when it is not a segment of this tenant."""
    if not segment_id:
        return
    result = await db.execute(
        select(MicroSegment.id).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == org_id,
            ),
        ),
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_field", "field": "microsegment_id",
                    "detail": "microsegment_id is not a segment of this organisation"},
        )


# ============================================================================
# ACCESS CONTROL ENDPOINTS
# ============================================================================


@router.post("/evaluate", response_model=AccessDecisionResponse)
async def evaluate_access_request(
    request: AccessRequestSchema,
    raw_request: Request,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    # Analyst or above: an evaluation records an AccessDecision and can fire
    # violation automation, so viewers may not run one.
    _user: User = Depends(require_role([UserRole.ADMIN, UserRole.ANALYST])),
) -> AccessDecisionResponse:
    """Evaluate access request and return decision (Policy Decision Point)

    Core Zero Trust endpoint that evaluates all access requests against
    policies, device trust, risk scores, and contextual factors.
    """
    logger.info(
        "api_evaluate_access_request",
        subject=f"{request.subject_type}:{request.subject_id}",
        resource=f"{request.resource_type}:{request.resource_id}",
    )

    try:
        pdp = PolicyDecisionPoint(db, org_id)

        # This endpoint is a what-if evaluation of a principal/resource pair.
        # It used to inject the CALLER's own JWT jti as the session under
        # evaluation, and the engine pushed the verdict into the session gate
        # with a 24 h TTL for denies, so one evaluation in an organisation
        # with no policies (default deny) locked the analyst out of the whole
        # API for a day. The caller's session is never bound here; a
        # client-supplied session_id is evaluated but not enforced (the
        # enforce_session flag is reserved for the continuous-verification
        # task, which is the only legitimate writer of the gate cache).
        context = dict(request.context or {})
        context.pop("enforce_session", None)

        decision = await pdp.evaluate_access_request(
            subject_type=request.subject_type,
            subject_id=request.subject_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            context=context,
        )

        # Determine required actions based on decision
        required_actions = []
        challenge_id = None

        if decision.decision == "challenge":
            required_actions.append("mfa_required")
            challenge_id = f"challenge_{decision.id}"
        elif decision.decision == "step_up":
            required_actions.append("step_up_authentication")
            challenge_id = f"challenge_{decision.id}"
        elif decision.decision == "isolate":
            required_actions.append("network_isolation")

        if decision.decision in ("deny", "isolate"):
            try:
                automation = AutomationService(db)
                await automation.on_zerotrust_policy_violation(
                    policy_name=getattr(decision, "policy_name", None) or "unknown",
                    user_email=getattr(decision, "user_email", None) or getattr(decision, "subject_id", None) or "unknown",
                    violation_type=decision.decision or "deny",
                    organization_id=org_id,
                )
            except Exception as automation_exc:
                logger.warning(f"Automation on_zerotrust_policy_violation failed: {automation_exc}")

        return AccessDecisionResponse(
            id=decision.id,
            decision=decision.decision,
            risk_score=decision.risk_score,
            risk_factors=safe_json_loads(decision.risk_factors or "[]", []),
            reason=decision.decision_reason,
            required_actions=required_actions,
            mfa_required=decision.decision in ["challenge", "step_up"],
            challenge_id=challenge_id,
            created_at=decision.created_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error("api_error_evaluate_access", error=str(e), traceback=traceback.format_exc()[-1500:])
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error evaluating access request",
        ) from e


@router.post("/evaluate-access", response_model=AccessDecisionResponse)
async def evaluate_access_alias(
    request: AccessRequestSchema,
    raw_request: Request,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    # Analyst or above: an evaluation records an AccessDecision and can fire
    # violation automation, so viewers may not run one.
    current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.ANALYST])),
) -> AccessDecisionResponse:
    """Alias for /evaluate — evaluate access request and return decision"""
    return await evaluate_access_request(
        request, raw_request, org_id, db=db, _user=current_user
    )


@router.post("/continuous-eval/{session_id}", response_model=AccessDecisionResponse)
async def continuous_session_evaluation(
    session_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
) -> AccessDecisionResponse:
    """Re-evaluate active session for risk changes

    Continuous evaluation of active sessions to detect anomalies
    and enforce ongoing authentication requirements.
    """
    logger.info("api_continuous_evaluation", session_id=session_id)

    try:
        pdp = PolicyDecisionPoint(db, org_id)

        new_decision = await pdp.continuous_evaluation(session_id)

        if not new_decision:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or no re-evaluation needed",
            )

        return AccessDecisionResponse(
            id=new_decision.id,
            decision=new_decision.decision,
            risk_score=new_decision.risk_score,
            risk_factors=safe_json_loads(new_decision.risk_factors or "[]", []),
            reason=new_decision.decision_reason,
            required_actions=[],
            mfa_required=False,
            created_at=new_decision.created_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("api_error_continuous_evaluation", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error evaluating session",
        ) from e


@router.get("/decisions", response_model=None)
async def list_access_decisions(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    decision_filter: str = Query(None, description="allow, deny, challenge, step_up, isolate"),
) -> dict[str, Any]:
    """List access decisions (audit trail)"""
    logger.info("api_list_access_decisions", skip=skip, limit=limit)


    query = select(AccessDecision).where(
        AccessDecision.organization_id == org_id,
    )

    if decision_filter:
        query = query.where(AccessDecision.decision == decision_filter)

    # Get total count
    count_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            AccessDecision.organization_id == org_id,
        ),
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(AccessDecision.created_at)).offset(skip).limit(limit),
    )
    decisions = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "decisions": [
            {
                "id": d.id,
                "subject": f"{d.subject_type}:{d.subject_id}",
                "resource": f"{d.resource_type}:{d.resource_id}",
                "decision": d.decision,
                "risk_score": d.risk_score,
                "created_at": d.created_at,
            }
            for d in decisions
        ],
    }


# ============================================================================
# POLICY MANAGEMENT ENDPOINTS
# ============================================================================


@router.post("/policies", response_model=ZeroTrustPolicyResponse)
async def create_policy(
    policy: ZeroTrustPolicyCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
) -> ZeroTrustPolicyResponse:
    """Create a new Zero Trust policy (admin: access-policy configuration)"""
    logger.info("api_create_policy", name=policy.name, type=policy.policy_type)
    await _require_segment_field(db, policy.microsegment_id, org_id)

    db_policy = ZeroTrustPolicy(
        name=policy.name,
        policy_type=policy.policy_type,
        description=policy.description,
        conditions=json.dumps(policy.conditions),
        actions=json.dumps(policy.actions),
        risk_threshold=policy.risk_threshold,
        requires_mfa=policy.requires_mfa,
        requires_device_trust=policy.requires_device_trust,
        minimum_device_trust_score=policy.minimum_device_trust_score,
        allowed_locations=json.dumps(policy.allowed_locations),
        blocked_locations=json.dumps(policy.blocked_locations),
        time_restrictions=json.dumps(policy.time_restrictions),
        data_classification_required=policy.data_classification_required,
        microsegment_id=policy.microsegment_id,
        is_enabled=policy.is_enabled,
        priority=policy.priority,
        tags=json.dumps(policy.tags),
        organization_id=org_id,
    )

    db.add(db_policy)
    await db.commit()
    await db.refresh(db_policy)

    return ZeroTrustPolicyResponse.model_validate(db_policy)


@router.get("/policies", response_model=None)
async def list_policies(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    enabled_only: bool = Query(True),
) -> dict[str, Any]:
    """List Zero Trust policies"""

    query = select(ZeroTrustPolicy).where(
        ZeroTrustPolicy.organization_id == org_id,
    )

    if enabled_only:
        query = query.where(ZeroTrustPolicy.is_enabled == True)

    # Get total count
    count_result = await db.execute(
        select(func.count(ZeroTrustPolicy.id)).where(
            ZeroTrustPolicy.organization_id == org_id,
        ),
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(ZeroTrustPolicy.priority)).offset(skip).limit(limit),
    )
    policies = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "policies": [ZeroTrustPolicyResponse.model_validate(p) for p in policies],
    }


@router.get("/policies/{policy_id}", response_model=ZeroTrustPolicyResponse)
async def get_policy(
    policy_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> ZeroTrustPolicyResponse:
    """Get policy details"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == org_id,
            ),
        ),
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found",
        )

    return ZeroTrustPolicyResponse.model_validate(policy)


@router.put("/policies/{policy_id}", response_model=ZeroTrustPolicyResponse)
async def update_policy(
    policy_id: str,
    policy_update: ZeroTrustPolicyUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
) -> ZeroTrustPolicyResponse:
    """Update Zero Trust policy (admin: access-policy configuration)"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == org_id,
            ),
        ),
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found",
        )

    # Update fields
    update_data = policy_update.dict(exclude_unset=True)
    await _require_segment_field(db, update_data.get("microsegment_id"), org_id)
    for key, value in update_data.items():
        if value is not None:
            if key in ["conditions", "actions", "allowed_locations", "blocked_locations", "time_restrictions", "tags"]:
                setattr(policy, key, json.dumps(value))
            else:
                setattr(policy, key, value)

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    return ZeroTrustPolicyResponse.model_validate(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
) -> None:
    """Delete Zero Trust policy (admin: access-policy configuration)"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == org_id,
            ),
        ),
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found",
        )

    await db.delete(policy)
    await db.commit()


@router.post("/policies/{policy_id}/test")
async def test_policy(
    policy_id: str,
    test_request: AccessRequestSchema,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
) -> dict[str, Any]:
    """Test policy against sample access request"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == org_id,
            ),
        ),
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found",
        )

    # Evaluate test request
    pdp = PolicyDecisionPoint(db, org_id)
    decision = await pdp.evaluate_access_request(
        subject_type=test_request.subject_type,
        subject_id=test_request.subject_id,
        resource_type=test_request.resource_type,
        resource_id=test_request.resource_id,
        context=test_request.context,
    )

    return {
        "policy_id": policy_id,
        "test_decision": decision.decision,
        "risk_score": decision.risk_score,
        "matched": decision.policy_id == policy_id,
    }


# ============================================================================
# DEVICE TRUST ENDPOINTS
# ============================================================================


@router.get("/device-stats", response_model=None)
async def get_device_stats(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> dict[str, Any]:
    """Get aggregate device trust stats"""

    total_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            DeviceTrustProfile.organization_id == org_id,
        ),
    )
    total = total_result.scalar_one() or 0

    trusted_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == org_id,
                DeviceTrustProfile.trust_level == "trusted",
            ),
        ),
    )
    trusted = trusted_result.scalar_one() or 0

    conditional_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == org_id,
                DeviceTrustProfile.trust_level == "conditional",
            ),
        ),
    )
    conditional = conditional_result.scalar_one() or 0

    untrusted_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == org_id,
                DeviceTrustProfile.trust_level == "untrusted",
            ),
        ),
    )
    untrusted = untrusted_result.scalar_one() or 0

    blocked_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == org_id,
                DeviceTrustProfile.trust_level == "blocked",
            ),
        ),
    )
    blocked = blocked_result.scalar_one() or 0

    unknown_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == org_id,
                DeviceTrustProfile.trust_level == "unknown",
            ),
        ),
    )
    unknown = unknown_result.scalar_one() or 0

    return {
        "total": total,
        "trusted": trusted,
        "conditional": conditional,
        "untrusted": untrusted,
        "blocked": blocked,
        # Profiles that never reported posture: neither trusted nor blocked.
        "not_reported": unknown,
    }


@router.post("/assess-devices", response_model=None)
async def assess_all_devices(
    org_id: OrganizationId,
    payload: dict = Body(default_factory=dict),
    db: DatabaseSession = None,
    _user: AnalystUser = None,
) -> dict[str, Any]:
    """Trigger assessment of devices.

    Accepts an optional ``device_ids`` filter in the body; when
    provided, only those devices are reassessed. Previously the body
    was ignored, so the UI's "Re-assess" button on a single device
    actually kicked off a full org-wide assessment — misleading and
    potentially expensive.
    """
    assessor = DeviceTrustAssessor(db, org_id)

    requested_ids = payload.get("device_ids") if isinstance(payload, dict) else None
    if isinstance(requested_ids, list) and requested_ids:
        device_ids = [str(d) for d in requested_ids if d]
    else:
        result = await db.execute(
            select(DeviceTrustProfile.device_id).where(
                DeviceTrustProfile.organization_id == org_id,
            ),
        )
        device_ids = [row[0] for row in result.all()]

    assessed = 0
    failed = 0
    for device_id in device_ids:
        try:
            await assessor.assess_device(device_id)
            assessed += 1
        except Exception:
            failed += 1

    return {
        "assessed": assessed,
        "failed": failed,
        "total": len(device_ids),
        "filtered": bool(requested_ids),
    }


@router.get("/devices", response_model=None)
async def list_devices(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    trust_level: str = Query(None, description="trusted, conditional, untrusted, blocked"),
) -> dict[str, Any]:
    """List devices with trust scores"""

    query = select(DeviceTrustProfile).where(
        DeviceTrustProfile.organization_id == org_id,
    )

    if trust_level:
        query = query.where(DeviceTrustProfile.trust_level == trust_level)

    # Get total count (of the filtered set)
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery()),
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(DeviceTrustProfile.trust_score), DeviceTrustProfile.device_id)
        .offset(skip).limit(limit),
    )
    devices = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "devices": [_device_summary(d) for d in devices],
    }


@router.get("/devices/non-compliant", response_model=None)
async def list_non_compliant_devices(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> dict[str, Any]:
    """Get devices below compliance threshold"""
    assessor = DeviceTrustAssessor(db, org_id)
    non_compliant = await assessor.get_non_compliant_devices()

    return {
        "count": len(non_compliant),
        "devices": [_device_summary(d) for d in non_compliant],
    }


@router.get("/devices/{device_id}", response_model=DeviceTrustProfileResponse)
async def get_device(
    device_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> DeviceTrustProfileResponse:
    """Get device trust details"""
    result = await db.execute(
        select(DeviceTrustProfile).where(
            and_(
                DeviceTrustProfile.device_id == device_id,
                DeviceTrustProfile.organization_id == org_id,
            ),
        ),
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found",
        )

    return _device_response(device)


@router.post("/devices/{device_id}/assess", response_model=DeviceTrustProfileResponse)
async def assess_device(
    device_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
) -> DeviceTrustProfileResponse:
    """Assess device compliance and trust score"""
    assessor = DeviceTrustAssessor(db, org_id)

    try:
        device = await assessor.assess_device(device_id)
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found",
        ) from None

    return _device_response(device)


@router.put("/devices/{device_id}/compliance", response_model=DeviceTrustProfileResponse)
async def update_device_compliance(
    device_id: str,
    compliance: DeviceComplianceUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
) -> DeviceTrustProfileResponse:
    """Override device compliance data (admin only: it feeds the PDP device check).

    Upsert within the caller's organisation: an unknown ``device_id`` creates
    this tenant's profile (device ids are unique per organisation, so the
    same id in another tenant is a separate row and is never touched). The
    stored posture is marked ``posture_source="admin_override"`` and the
    change is written to the audit log.
    """
    from src.models.audit import AuditLog

    assessor = DeviceTrustAssessor(db, org_id)

    compliance_data = compliance.model_dump(exclude_unset=True, exclude_none=True)
    device = await assessor.update_device_compliance(
        device_id, compliance_data, source="admin_override",
    )
    db.add(AuditLog(
        user_id=str(_user.id) if _user is not None else None,
        organization_id=org_id,
        action="zerotrust_device_compliance_override",
        resource_type="device_trust_profile",
        resource_id=device.id,
        description=f"Device {device_id} posture overridden by an administrator",
        new_value=json.dumps(compliance_data),
        success=True,
    ))
    await db.commit()
    await db.refresh(device)

    return _device_response(device)


# ============================================================================
# MICRO-SEGMENTATION ENDPOINTS
# ============================================================================


@router.post("/segments", response_model=MicroSegmentResponse)
async def create_segment(
    segment: MicroSegmentCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
) -> MicroSegmentResponse:
    """Create a new micro-segment (admin: network-policy configuration)"""
    engine = MicroSegmentationEngine(db, org_id)

    seg = await engine.create_segment(
        name=segment.name,
        segment_type=segment.segment_type,
        config=segment.dict(),
    )

    return MicroSegmentResponse.model_validate(seg)


@router.get("/segments", response_model=None)
async def list_segments(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """List micro-segments"""

    query = select(MicroSegment).where(
        MicroSegment.organization_id == org_id,
    )

    # Get total count
    count_result = await db.execute(
        select(func.count(MicroSegment.id)).where(
            MicroSegment.organization_id == org_id,
        ),
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(MicroSegment.created_at).offset(skip).limit(limit),
    )
    segments = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "segments": [MicroSegmentResponse.model_validate(s) for s in segments],
    }


@router.get("/segments/{segment_id}", response_model=MicroSegmentResponse)
async def get_segment(
    segment_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> MicroSegmentResponse:
    """Get segment details"""
    result = await db.execute(
        select(MicroSegment).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == org_id,
            ),
        ),
    )
    segment = result.scalar_one_or_none()

    if not segment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Segment not found",
        )

    return MicroSegmentResponse.model_validate(segment)


@router.put("/segments/{segment_id}", response_model=MicroSegmentResponse)
async def update_segment(
    segment_id: str,
    segment_update: MicroSegmentUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
) -> MicroSegmentResponse:
    """Update micro-segment (admin: network-policy configuration)"""
    result = await db.execute(
        select(MicroSegment).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == org_id,
            ),
        ),
    )
    segment = result.scalar_one_or_none()

    if not segment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Segment not found",
        )

    # Update fields
    update_data = segment_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        if value is not None:
            if key in ["cidr_ranges", "allowed_protocols", "allowed_ports"]:
                setattr(segment, key, json.dumps(value))
            else:
                setattr(segment, key, value)

    db.add(segment)
    await db.commit()
    await db.refresh(segment)

    return MicroSegmentResponse.model_validate(segment)


@router.delete("/segments/{segment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_segment(
    segment_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
) -> None:
    """Delete micro-segment (admin: network-policy configuration)"""
    result = await db.execute(
        select(MicroSegment).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == org_id,
            ),
        ),
    )
    segment = result.scalar_one_or_none()

    if not segment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Segment not found",
        )

    await db.delete(segment)
    await db.commit()


@router.post("/segments/{segment_id}/evaluate-traffic", response_model=SegmentTrafficResponse)
async def evaluate_segment_traffic(
    segment_id: str,
    traffic: SegmentTrafficRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> SegmentTrafficResponse:
    """Evaluate if traffic is allowed within segment

    Read-only computation over this tenant's segments (persists nothing), so
    viewers may run it.
    """
    await _get_segment_or_404(db, segment_id, org_id)
    engine = MicroSegmentationEngine(db, org_id)

    result = await engine.evaluate_traffic(
        source=traffic.source,
        destination=traffic.destination,
        protocol=traffic.protocol,
        port=traffic.port,
    )

    return SegmentTrafficResponse(**result)


@router.get("/segments/{segment_id}/violations", response_model=None)
async def get_segment_violations(
    segment_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> dict[str, Any]:
    """Get policy violations for segment"""
    await _get_segment_or_404(db, segment_id, org_id)
    engine = MicroSegmentationEngine(db, org_id)

    violations = await engine.get_segment_violations(segment_id)

    return {"segment_id": segment_id, "violations": violations}


@router.get("/topology", response_model=None)
async def get_segment_topology(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> dict[str, Any]:
    """Get network topology visualization"""
    engine = MicroSegmentationEngine(db, org_id)

    return await engine.visualize_segments()


# ============================================================================
# IDENTITY VERIFICATION ENDPOINTS
# ============================================================================


@router.post("/verify", response_model=IdentityVerificationResponse)
async def initiate_verification(
    verification: IdentityVerificationCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
) -> IdentityVerificationResponse:
    """Initiate identity verification"""
    auth_engine = ContinuousAuthEngine(db, org_id)

    v = await auth_engine.initiate_verification(
        user_id=verification.user_id,
        verification_type=verification.verification_type,
        trigger_reason=verification.trigger_reason,
        context={
            "device_id": verification.device_id,
            "source_ip": verification.source_ip,
        },
    )

    return IdentityVerificationResponse.model_validate(v)


@router.post("/step-up/{session_id}", response_model=None)
async def step_up_authentication(
    session_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    required_level: str = Query(..., description="mfa, biometric, password"),
) -> dict[str, Any]:
    """Initiate step-up authentication (not implemented).

    This used to return ``challenge_<session_id>`` as if a challenge had been
    issued; no challenge was ever sent to the user and nothing could verify a
    response. It now says so instead of faking success.
    """
    logger.info(
        "api_step_up_not_implemented",
        organization_id=org_id,
        session_id=session_id,
        required_level=required_level,
    )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": "step-up authentication challenges are not issued yet; no challenge was sent",
        },
    )


@router.get("/verifications", response_model=None)
async def list_verifications(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    user_id: str = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """Get verification history"""

    query = select(IdentityVerification).where(
        IdentityVerification.organization_id == org_id,
    )

    if user_id:
        query = query.where(IdentityVerification.user_id == user_id)

    # Get total count
    count_result = await db.execute(
        select(func.count(IdentityVerification.id)).where(
            IdentityVerification.organization_id == org_id,
        ),
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(IdentityVerification.created_at))
        .offset(skip)
        .limit(limit),
    )
    verifications = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "verifications": [IdentityVerificationResponse.model_validate(v) for v in verifications],
    }


# ============================================================================
# MATURITY & RECOMMENDATIONS ENDPOINTS
# ============================================================================


@router.get("/maturity", response_model=ZeroTrustMaturityResponse)
async def get_maturity_score(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> ZeroTrustMaturityResponse:
    """Get Zero Trust maturity score and assessment"""
    scorer = ZeroTrustScorer(db, org_id)

    maturity = await scorer.calculate_maturity_score()

    return ZeroTrustMaturityResponse(
        overall_score=maturity["overall_score"],
        maturity_level=maturity["maturity_level"],
        pillars=maturity["pillars"],
        recommendations=maturity["recommendations"],
        assessed_at=datetime.now(timezone.utc),
        configured_pillars=maturity["configured_pillars"],
    )


@router.get("/maturity/pillars", response_model=None)
async def get_maturity_pillars(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> dict[str, Any]:
    """Get per-pillar maturity breakdown"""
    scorer = ZeroTrustScorer(db, org_id)

    maturity = await scorer.calculate_maturity_score()

    return {"pillars": maturity["pillars"]}


@router.get("/recommendations", response_model=None)
async def get_recommendations(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> dict[str, Any]:
    """Get improvement recommendations"""
    scorer = ZeroTrustScorer(db, org_id)

    maturity = await scorer.calculate_maturity_score()

    return {
        "recommendations": maturity["recommendations"],
        "maturity_level": maturity["maturity_level"],
    }


# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================


@router.get("/dashboard", response_model=ZeroTrustDashboardStats)
async def get_dashboard_stats(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> ZeroTrustDashboardStats:
    """Get Zero Trust dashboard statistics"""
    logger.info("api_get_dashboard_stats")


    # Get policy stats
    policy_result = await db.execute(
        select(func.count(ZeroTrustPolicy.id)).where(
            ZeroTrustPolicy.organization_id == org_id,
        ),
    )
    total_policies = policy_result.scalar_one() or 0

    enabled_result = await db.execute(
        select(func.count(ZeroTrustPolicy.id)).where(
            and_(
                ZeroTrustPolicy.organization_id == org_id,
                ZeroTrustPolicy.is_enabled == True,
            ),
        ),
    )
    enabled_policies = enabled_result.scalar_one() or 0

    # Get device stats
    device_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            DeviceTrustProfile.organization_id == org_id,
        ),
    )
    total_devices = device_result.scalar_one() or 0

    compliant_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == org_id,
                DeviceTrustProfile.trust_level.in_(["trusted", "conditional"]),
            ),
        ),
    )
    compliant_devices = compliant_result.scalar_one() or 0
    not_reported_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == org_id,
                DeviceTrustProfile.trust_level == "unknown",
            ),
        ),
    )
    not_reported_devices = not_reported_result.scalar_one() or 0
    # A device that never reported posture is not "non-compliant".
    non_compliant = max(total_devices - compliant_devices - not_reported_devices, 0)

    # Get average device trust
    avg_trust_result = await db.execute(
        select(func.avg(DeviceTrustProfile.trust_score)).where(
            DeviceTrustProfile.organization_id == org_id,
        ),
    )
    avg_trust = avg_trust_result.scalar_one() or 0.0

    # Get decision stats
    decision_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            AccessDecision.organization_id == org_id,
        ),
    )
    total_decisions = decision_result.scalar_one() or 0

    decisions_24h_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            and_(
                AccessDecision.organization_id == org_id,
                AccessDecision.created_at >= datetime.now(timezone.utc) - timedelta(hours=24),
            ),
        ),
    )
    decisions_24h = decisions_24h_result.scalar_one() or 0

    allowed_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            and_(
                AccessDecision.organization_id == org_id,
                AccessDecision.decision == "allow",
            ),
        ),
    )
    allowed = allowed_result.scalar_one() or 0

    denied_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            and_(
                AccessDecision.organization_id == org_id,
                AccessDecision.decision == "deny",
            ),
        ),
    )
    denied = denied_result.scalar_one() or 0

    challenged_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            and_(
                AccessDecision.organization_id == org_id,
                AccessDecision.decision.in_(["challenge", "step_up"]),
            ),
        ),
    )
    challenged = challenged_result.scalar_one() or 0

    # Get segment stats
    segment_result = await db.execute(
        select(func.count(MicroSegment.id)).where(
            MicroSegment.organization_id == org_id,
        ),
    )
    total_segments = segment_result.scalar_one() or 0

    active_result = await db.execute(
        select(func.count(MicroSegment.id)).where(
            and_(
                MicroSegment.organization_id == org_id,
                MicroSegment.is_active == True,
            ),
        ),
    )
    active_segments = active_result.scalar_one() or 0

    violation_result = await db.execute(
        select(func.sum(MicroSegment.violation_count)).where(
            MicroSegment.organization_id == org_id,
        ),
    )
    violations = violation_result.scalar_one() or 0

    # Get maturity score
    scorer = ZeroTrustScorer(db, org_id)
    maturity = await scorer.calculate_maturity_score()

    return ZeroTrustDashboardStats(
        total_policies=total_policies,
        enabled_policies=enabled_policies,
        total_devices=total_devices,
        compliant_devices=compliant_devices,
        non_compliant_devices=non_compliant,
        average_device_trust_score=float(avg_trust),
        total_access_decisions=total_decisions,
        allowed_decisions=allowed,
        denied_decisions=denied,
        challenged_decisions=challenged,
        total_segments=total_segments,
        active_segments=active_segments,
        violation_count=violations,
        maturity_score=maturity["overall_score"],
        maturity_level=maturity["maturity_level"],
        pillars=maturity["pillars"],
        last_updated=datetime.now(timezone.utc),
        not_reported_devices=not_reported_devices,
        access_decisions_24h=decisions_24h,
        configured_pillars=maturity["configured_pillars"],
    )
