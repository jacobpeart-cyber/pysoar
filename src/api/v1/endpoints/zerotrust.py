"""Zero Trust Architecture REST API endpoints (NIST 800-207)"""

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger
from src.schemas.zerotrust import (
    AccessDecisionResponse,
    AccessRequestSchema,
    DeviceComplianceUpdate,
    DeviceTrustProfileCreate,
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
from src.zerotrust.engine import (
    ContinuousAuthEngine,
    DeviceTrustAssessor,
    MicroSegmentationEngine,
    PolicyDecisionPoint,
    ZeroTrustScorer,
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


# ============================================================================
# ACCESS CONTROL ENDPOINTS
# ============================================================================


@router.post("/evaluate", response_model=AccessDecisionResponse)
async def evaluate_access_request(
    request: AccessRequestSchema,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        pdp = PolicyDecisionPoint(db, current_user.organization_id)

        decision = await pdp.evaluate_access_request(
            subject_type=request.subject_type,
            subject_id=request.subject_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            context=request.context,
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

        return AccessDecisionResponse(
            id=decision.id,
            decision=decision.decision,
            risk_score=decision.risk_score,
            risk_factors=json.loads(decision.risk_factors or "[]"),
            reason=decision.decision_reason,
            required_actions=required_actions,
            mfa_required=decision.decision in ["challenge", "step_up"],
            challenge_id=challenge_id,
            created_at=decision.created_at,
        )

    except Exception as e:
        logger.error("api_error_evaluate_access", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error evaluating access request",
        )


@router.post("/continuous-eval/{session_id}", response_model=AccessDecisionResponse)
async def continuous_session_evaluation(
    session_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> AccessDecisionResponse:
    """Re-evaluate active session for risk changes

    Continuous evaluation of active sessions to detect anomalies
    and enforce ongoing authentication requirements.
    """
    logger.info("api_continuous_evaluation", session_id=session_id)

    try:
        pdp = PolicyDecisionPoint(db, current_user.organization_id)

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
            risk_factors=json.loads(new_decision.risk_factors or "[]"),
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
        )


@router.get("/decisions", response_model=dict[str, Any])
async def list_access_decisions(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    decision_filter: str = Query(None, description="allow, deny, challenge, step_up, isolate"),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """List access decisions (audit trail)"""
    logger.info("api_list_access_decisions", skip=skip, limit=limit)

    query = select(AccessDecision).where(
        AccessDecision.organization_id == current_user.organization_id
    )

    if decision_filter:
        query = query.where(AccessDecision.decision == decision_filter)

    # Get total count
    count_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            AccessDecision.organization_id == current_user.organization_id
        )
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(AccessDecision.created_at)).offset(skip).limit(limit)
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> ZeroTrustPolicyResponse:
    """Create a new Zero Trust policy"""
    logger.info("api_create_policy", name=policy.name, type=policy.policy_type)

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
        organization_id=current_user.organization_id,
    )

    db.add(db_policy)
    await db.commit()
    await db.refresh(db_policy)

    return ZeroTrustPolicyResponse.from_orm(db_policy)


@router.get("/policies", response_model=dict[str, Any])
async def list_policies(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    enabled_only: bool = Query(True),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """List Zero Trust policies"""
    query = select(ZeroTrustPolicy).where(
        ZeroTrustPolicy.organization_id == current_user.organization_id
    )

    if enabled_only:
        query = query.where(ZeroTrustPolicy.is_enabled == True)

    # Get total count
    count_result = await db.execute(
        select(func.count(ZeroTrustPolicy.id)).where(
            ZeroTrustPolicy.organization_id == current_user.organization_id
        )
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(ZeroTrustPolicy.priority)).offset(skip).limit(limit)
    )
    policies = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "policies": [ZeroTrustPolicyResponse.from_orm(p) for p in policies],
    }


@router.get("/policies/{policy_id}", response_model=ZeroTrustPolicyResponse)
async def get_policy(
    policy_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> ZeroTrustPolicyResponse:
    """Get policy details"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == current_user.organization_id,
            )
        )
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )

    return ZeroTrustPolicyResponse.from_orm(policy)


@router.put("/policies/{policy_id}", response_model=ZeroTrustPolicyResponse)
async def update_policy(
    policy_id: str,
    policy_update: ZeroTrustPolicyUpdate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> ZeroTrustPolicyResponse:
    """Update Zero Trust policy"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == current_user.organization_id,
            )
        )
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )

    # Update fields
    update_data = policy_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        if value is not None:
            if key in ["conditions", "actions", "allowed_locations", "blocked_locations", "time_restrictions", "tags"]:
                setattr(policy, key, json.dumps(value))
            else:
                setattr(policy, key, value)

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    return ZeroTrustPolicyResponse.from_orm(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> None:
    """Delete Zero Trust policy"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == current_user.organization_id,
            )
        )
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )

    await db.delete(policy)
    await db.commit()


@router.post("/policies/{policy_id}/test")
async def test_policy(
    policy_id: str,
    test_request: AccessRequestSchema,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Test policy against sample access request"""
    result = await db.execute(
        select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.id == policy_id,
                ZeroTrustPolicy.organization_id == current_user.organization_id,
            )
        )
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )

    # Evaluate test request
    pdp = PolicyDecisionPoint(db, current_user.organization_id)
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


@router.get("/devices", response_model=dict[str, Any])
async def list_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    trust_level: str = Query(None, description="trusted, conditional, untrusted, blocked"),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """List devices with trust scores"""
    query = select(DeviceTrustProfile).where(
        DeviceTrustProfile.organization_id == current_user.organization_id
    )

    if trust_level:
        query = query.where(DeviceTrustProfile.trust_level == trust_level)

    # Get total count
    count_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            DeviceTrustProfile.organization_id == current_user.organization_id
        )
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(DeviceTrustProfile.trust_score)).offset(skip).limit(limit)
    )
    devices = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "devices": [
            {
                "id": d.id,
                "device_id": d.device_id,
                "hostname": d.hostname,
                "device_type": d.device_type,
                "trust_score": d.trust_score,
                "trust_level": d.trust_level,
                "last_seen": d.last_seen_at,
            }
            for d in devices
        ],
    }


@router.get("/devices/{device_id}", response_model=DeviceTrustProfileResponse)
async def get_device(
    device_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> DeviceTrustProfileResponse:
    """Get device trust details"""
    result = await db.execute(
        select(DeviceTrustProfile).where(
            and_(
                DeviceTrustProfile.device_id == device_id,
                DeviceTrustProfile.organization_id == current_user.organization_id,
            )
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )

    return DeviceTrustProfileResponse.from_orm(device)


@router.post("/devices/{device_id}/assess", response_model=DeviceTrustProfileResponse)
async def assess_device(
    device_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> DeviceTrustProfileResponse:
    """Assess device compliance and trust score"""
    assessor = DeviceTrustAssessor(db, current_user.organization_id)

    device = await assessor.assess_device(device_id)

    return DeviceTrustProfileResponse.from_orm(device)


@router.put("/devices/{device_id}/compliance", response_model=DeviceTrustProfileResponse)
async def update_device_compliance(
    device_id: str,
    compliance: DeviceComplianceUpdate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> DeviceTrustProfileResponse:
    """Update device compliance data"""
    assessor = DeviceTrustAssessor(db, current_user.organization_id)

    compliance_data = compliance.dict(exclude_unset=True, exclude_none=True)
    device = await assessor.update_device_compliance(device_id, compliance_data)

    return DeviceTrustProfileResponse.from_orm(device)


@router.get("/devices/non-compliant", response_model=dict[str, Any])
async def list_non_compliant_devices(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Get devices below compliance threshold"""
    assessor = DeviceTrustAssessor(db, current_user.organization_id)
    non_compliant = await assessor.get_non_compliant_devices()

    return {
        "count": len(non_compliant),
        "devices": [
            {
                "id": d.id,
                "device_id": d.device_id,
                "hostname": d.hostname,
                "trust_score": d.trust_score,
                "trust_level": d.trust_level,
            }
            for d in non_compliant
        ],
    }


# ============================================================================
# MICRO-SEGMENTATION ENDPOINTS
# ============================================================================


@router.post("/segments", response_model=MicroSegmentResponse)
async def create_segment(
    segment: MicroSegmentCreate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> MicroSegmentResponse:
    """Create a new micro-segment"""
    engine = MicroSegmentationEngine(db, current_user.organization_id)

    seg = await engine.create_segment(
        name=segment.name,
        segment_type=segment.segment_type,
        config=segment.dict(),
    )

    return MicroSegmentResponse.from_orm(seg)


@router.get("/segments", response_model=dict[str, Any])
async def list_segments(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """List micro-segments"""
    query = select(MicroSegment).where(
        MicroSegment.organization_id == current_user.organization_id
    )

    # Get total count
    count_result = await db.execute(
        select(func.count(MicroSegment.id)).where(
            MicroSegment.organization_id == current_user.organization_id
        )
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(MicroSegment.created_at).offset(skip).limit(limit)
    )
    segments = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "segments": [MicroSegmentResponse.from_orm(s) for s in segments],
    }


@router.get("/segments/{segment_id}", response_model=MicroSegmentResponse)
async def get_segment(
    segment_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> MicroSegmentResponse:
    """Get segment details"""
    result = await db.execute(
        select(MicroSegment).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == current_user.organization_id,
            )
        )
    )
    segment = result.scalar_one_or_none()

    if not segment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Segment not found"
        )

    return MicroSegmentResponse.from_orm(segment)


@router.put("/segments/{segment_id}", response_model=MicroSegmentResponse)
async def update_segment(
    segment_id: str,
    segment_update: MicroSegmentUpdate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> MicroSegmentResponse:
    """Update micro-segment"""
    result = await db.execute(
        select(MicroSegment).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == current_user.organization_id,
            )
        )
    )
    segment = result.scalar_one_or_none()

    if not segment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Segment not found"
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

    return MicroSegmentResponse.from_orm(segment)


@router.delete("/segments/{segment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_segment(
    segment_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> None:
    """Delete micro-segment"""
    result = await db.execute(
        select(MicroSegment).where(
            and_(
                MicroSegment.id == segment_id,
                MicroSegment.organization_id == current_user.organization_id,
            )
        )
    )
    segment = result.scalar_one_or_none()

    if not segment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Segment not found"
        )

    await db.delete(segment)
    await db.commit()


@router.post("/segments/{segment_id}/evaluate-traffic", response_model=SegmentTrafficResponse)
async def evaluate_segment_traffic(
    segment_id: str,
    traffic: SegmentTrafficRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> SegmentTrafficResponse:
    """Evaluate if traffic is allowed within segment"""
    engine = MicroSegmentationEngine(db, current_user.organization_id)

    result = await engine.evaluate_traffic(
        source=traffic.source,
        destination=traffic.destination,
        protocol=traffic.protocol,
        port=traffic.port,
    )

    return SegmentTrafficResponse(**result)


@router.get("/segments/{segment_id}/violations", response_model=dict[str, Any])
async def get_segment_violations(
    segment_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Get policy violations for segment"""
    engine = MicroSegmentationEngine(db, current_user.organization_id)

    violations = await engine.get_segment_violations(segment_id)

    return {"segment_id": segment_id, "violations": violations}


@router.get("/topology", response_model=dict[str, Any])
async def get_segment_topology(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Get network topology visualization"""
    engine = MicroSegmentationEngine(db, current_user.organization_id)

    return await engine.visualize_segments()


# ============================================================================
# IDENTITY VERIFICATION ENDPOINTS
# ============================================================================


@router.post("/verify", response_model=IdentityVerificationResponse)
async def initiate_verification(
    verification: IdentityVerificationCreate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> IdentityVerificationResponse:
    """Initiate identity verification"""
    auth_engine = ContinuousAuthEngine(db, current_user.organization_id)

    v = await auth_engine.initiate_verification(
        user_id=verification.user_id,
        verification_type=verification.verification_type,
        trigger_reason=verification.trigger_reason,
        context={
            "device_id": verification.device_id,
            "source_ip": verification.source_ip,
        },
    )

    return IdentityVerificationResponse.from_orm(v)


@router.post("/step-up/{session_id}", response_model=dict[str, Any])
async def step_up_authentication(
    session_id: str,
    required_level: str = Query(..., description="mfa, biometric, password"),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Initiate step-up authentication"""
    auth_engine = ContinuousAuthEngine(db, current_user.organization_id)

    return await auth_engine.step_up_authentication(session_id, required_level)


@router.get("/verifications", response_model=dict[str, Any])
async def list_verifications(
    user_id: str = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Get verification history"""
    query = select(IdentityVerification).where(
        IdentityVerification.organization_id == current_user.organization_id
    )

    if user_id:
        query = query.where(IdentityVerification.user_id == user_id)

    # Get total count
    count_result = await db.execute(
        select(func.count(IdentityVerification.id)).where(
            IdentityVerification.organization_id == current_user.organization_id
        )
    )
    total = count_result.scalar_one()

    # Get paginated results
    result = await db.execute(
        query.order_by(desc(IdentityVerification.created_at))
        .offset(skip)
        .limit(limit)
    )
    verifications = result.scalars().all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "verifications": [IdentityVerificationResponse.from_orm(v) for v in verifications],
    }


# ============================================================================
# MATURITY & RECOMMENDATIONS ENDPOINTS
# ============================================================================


@router.get("/maturity", response_model=ZeroTrustMaturityResponse)
async def get_maturity_score(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> ZeroTrustMaturityResponse:
    """Get Zero Trust maturity score and assessment"""
    scorer = ZeroTrustScorer(db, current_user.organization_id)

    maturity = await scorer.calculate_maturity_score()

    return ZeroTrustMaturityResponse(
        overall_score=maturity["overall_score"],
        maturity_level=maturity["maturity_level"],
        pillars=maturity["pillars"],
        recommendations=maturity["recommendations"],
        assessed_at=datetime.now(timezone.utc),
    )


@router.get("/maturity/pillars", response_model=dict[str, Any])
async def get_maturity_pillars(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Get per-pillar maturity breakdown"""
    scorer = ZeroTrustScorer(db, current_user.organization_id)

    maturity = await scorer.calculate_maturity_score()

    return {"pillars": maturity["pillars"]}


@router.get("/recommendations", response_model=dict[str, Any])
async def get_recommendations(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> dict[str, Any]:
    """Get improvement recommendations"""
    scorer = ZeroTrustScorer(db, current_user.organization_id)

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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> ZeroTrustDashboardStats:
    """Get Zero Trust dashboard statistics"""
    logger.info("api_get_dashboard_stats")

    # Get policy stats
    policy_result = await db.execute(
        select(func.count(ZeroTrustPolicy.id)).where(
            ZeroTrustPolicy.organization_id == current_user.organization_id
        )
    )
    total_policies = policy_result.scalar_one() or 0

    enabled_result = await db.execute(
        select(func.count(ZeroTrustPolicy.id)).where(
            and_(
                ZeroTrustPolicy.organization_id == current_user.organization_id,
                ZeroTrustPolicy.is_enabled == True,
            )
        )
    )
    enabled_policies = enabled_result.scalar_one() or 0

    # Get device stats
    device_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            DeviceTrustProfile.organization_id == current_user.organization_id
        )
    )
    total_devices = device_result.scalar_one() or 0

    compliant_result = await db.execute(
        select(func.count(DeviceTrustProfile.id)).where(
            and_(
                DeviceTrustProfile.organization_id == current_user.organization_id,
                DeviceTrustProfile.trust_level.in_(["trusted", "conditional"]),
            )
        )
    )
    compliant_devices = compliant_result.scalar_one() or 0
    non_compliant = total_devices - compliant_devices

    # Get average device trust
    avg_trust_result = await db.execute(
        select(func.avg(DeviceTrustProfile.trust_score)).where(
            DeviceTrustProfile.organization_id == current_user.organization_id
        )
    )
    avg_trust = avg_trust_result.scalar_one() or 0.0

    # Get decision stats
    decision_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            AccessDecision.organization_id == current_user.organization_id
        )
    )
    total_decisions = decision_result.scalar_one() or 0

    allowed_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            and_(
                AccessDecision.organization_id == current_user.organization_id,
                AccessDecision.decision == "allow",
            )
        )
    )
    allowed = allowed_result.scalar_one() or 0

    denied_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            and_(
                AccessDecision.organization_id == current_user.organization_id,
                AccessDecision.decision == "deny",
            )
        )
    )
    denied = denied_result.scalar_one() or 0

    challenged_result = await db.execute(
        select(func.count(AccessDecision.id)).where(
            and_(
                AccessDecision.organization_id == current_user.organization_id,
                AccessDecision.decision.in_(["challenge", "step_up"]),
            )
        )
    )
    challenged = challenged_result.scalar_one() or 0

    # Get segment stats
    segment_result = await db.execute(
        select(func.count(MicroSegment.id)).where(
            MicroSegment.organization_id == current_user.organization_id
        )
    )
    total_segments = segment_result.scalar_one() or 0

    active_result = await db.execute(
        select(func.count(MicroSegment.id)).where(
            and_(
                MicroSegment.organization_id == current_user.organization_id,
                MicroSegment.is_active == True,
            )
        )
    )
    active_segments = active_result.scalar_one() or 0

    violation_result = await db.execute(
        select(func.sum(MicroSegment.violation_count)).where(
            MicroSegment.organization_id == current_user.organization_id
        )
    )
    violations = violation_result.scalar_one() or 0

    # Get maturity score
    scorer = ZeroTrustScorer(db, current_user.organization_id)
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
        last_updated=datetime.now(timezone.utc),
    )
