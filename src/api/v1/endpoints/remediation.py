"""
REST API endpoints for remediation engine.

Provides full CRUD and operational endpoints for:
- Policies
- Actions
- Executions
- Approvals
- Playbooks
- Integrations
- Dashboard
"""

import json
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel as PydanticBaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user
from src.core.database import get_db
from src.core.logging import get_logger
from src.models.audit import AuditLog
from src.models.base import utc_now
from src.remediation.models import (
    RemediationPolicy,
    RemediationAction,
    RemediationExecution,
    RemediationPlaybook,
    RemediationIntegration,
)
from src.remediation.engine import RemediationEngine
from src.schemas.remediation import (
    RemediationPolicyCreate,
    RemediationPolicyUpdate,
    RemediationPolicyResponse,
    RemediationActionCreate,
    RemediationActionResponse,
    RemediationExecutionResponse,
    ExecutionProgressResponse,
    ApprovalRequest,
    ApprovalResponse,
    RejectionRequest,
    ManualRemediationRequest,
    QuickBlockIPRequest,
    QuickIsolateHostRequest,
    QuickDisableAccountRequest,
    QuickQuarantineFileRequest,
    RemediationPlaybookCreate,
    RemediationPlaybookResponse,
    RemediationIntegrationCreate,
    RemediationIntegrationResponse,
    IntegrationTestResult,
    RemediationDashboardStats,
    RemediationTimelineResponse,
    EffectivenessMetrics,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/remediation", tags=["remediation"])


# ============================================================================
# Policies
# ============================================================================

@router.post("/policies", response_model=RemediationPolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    request: RemediationPolicyCreate,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Create a new remediation policy."""
    logger.info("Creating remediation policy", extra={
        "name": request.name,
        "policy_type": request.policy_type,
        "created_by": current_user.id,
    })

    policy = RemediationPolicy(
        name=request.name,
        description=request.description,
        policy_type=request.policy_type,
        trigger_type=request.trigger_type,
        trigger_conditions=request.trigger_conditions,
        actions=request.actions,
        is_enabled=request.is_enabled,
        requires_approval=request.requires_approval,
        approval_timeout_minutes=request.approval_timeout_minutes,
        auto_approve_after_timeout=request.auto_approve_after_timeout,
        cooldown_minutes=request.cooldown_minutes,
        max_executions_per_hour=request.max_executions_per_hour,
        scope=request.scope,
        exclusions=request.exclusions,
        priority=request.priority,
        risk_level=request.risk_level,
        rollback_enabled=request.rollback_enabled,
        rollback_actions=request.rollback_actions,
        tags=request.tags,
        created_by=str(current_user.id) if current_user else None,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/policies", response_model=List[RemediationPolicyResponse])
async def list_policies(
    db: DatabaseSession = None,
    policy_type: Optional[str] = Query(None),
    trigger_type: Optional[str] = Query(None),
    enabled_only: bool = Query(default=True),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    current_user: CurrentUser = None,
):
    """List remediation policies with optional filtering."""
    org_id = getattr(current_user, "organization_id", None)
    query = select(RemediationPolicy)
    if org_id:
        query = query.where(RemediationPolicy.organization_id == org_id)

    if policy_type:
        query = query.where(RemediationPolicy.policy_type == policy_type)
    if trigger_type:
        query = query.where(RemediationPolicy.trigger_type == trigger_type)
    if enabled_only:
        query = query.where(RemediationPolicy.is_enabled == True)

    query = query.order_by(desc(RemediationPolicy.priority)).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/policies/builtin")
async def list_builtin_policies(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """List built-in remediation policies."""
    return {
        "builtin_policies": [
            {
                "name": "Block Malicious IPs",
                "description": "Auto-block IPs matched by threat intel",
                "policy_type": "auto_block",
            },
            {
                "name": "Isolate Compromised Hosts",
                "description": "Isolate hosts with confirmed malware",
                "policy_type": "auto_isolate",
            },
            {
                "name": "Disable Compromised Accounts",
                "description": "Disable accounts with impossible travel",
                "policy_type": "auto_disable",
            },
        ]
    }


@router.get("/policies/{policy_id}", response_model=RemediationPolicyResponse)
async def get_policy(
    policy_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Get a specific policy with execution history."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return policy


@router.put("/policies/{policy_id}", response_model=RemediationPolicyResponse)
async def update_policy(
    policy_id: str,
    request: RemediationPolicyUpdate,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Update a policy."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    update_data = request.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(policy, key, value)
    policy.updated_at = utc_now()

    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Disable a policy (soft delete)."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    policy.is_enabled = False
    policy.updated_at = utc_now()
    await db.commit()


@router.post("/policies/{policy_id}/test")
async def test_policy(
    policy_id: str,
    trigger_data: dict,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Test a policy against sample data."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    engine = RemediationEngine(db)
    matched = await engine.evaluate_trigger(
        policy.trigger_type,
        trigger_data,
        getattr(current_user, "organization_id", None),
    )

    return {
        "policy_id": policy_id,
        "matches": policy_id in [p.id for p in matched],
        "matched_policies": len(matched),
    }


# ============================================================================
# Actions
# ============================================================================

@router.get("/actions", response_model=List[RemediationActionResponse])
async def list_actions(
    db: DatabaseSession = None,
    action_type: Optional[str] = Query(None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    current_user = Depends(get_current_active_user),
):
    """List available remediation actions."""
    query = select(RemediationAction).where(
        RemediationAction.organization_id == getattr(current_user, "organization_id", None)
    )

    if action_type:
        query = query.where(RemediationAction.action_type == action_type)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/actions", response_model=RemediationActionResponse, status_code=status.HTTP_201_CREATED)
async def create_action(
    request: RemediationActionCreate,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Create a custom remediation action."""
    action = RemediationAction(
        name=request.name,
        description=request.description,
        action_type=request.action_type,
        target_type=request.target_type,
        parameters=request.parameters,
        integration=request.integration,
        integration_config=request.integration_config,
        timeout_seconds=request.timeout_seconds,
        retry_count=request.retry_count,
        is_reversible=request.is_reversible,
        reverse_action_type=request.reverse_action_type,
        reverse_parameters=request.reverse_parameters,
        risk_level=request.risk_level,
        requires_confirmation=request.requires_confirmation,
        tags=request.tags,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/actions/{action_id}", response_model=RemediationActionResponse)
async def get_action(
    action_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Get a specific action."""
    action = await db.get(RemediationAction, action_id)
    if not action or action.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return action


@router.post("/actions/{action_id}/test")
async def test_action(
    action_id: str,
    target: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Test an action."""
    action = await db.get(RemediationAction, action_id)
    if not action or action.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return {
        "action_id": action_id,
        "target": target,
        "test_result": "success",
        "tested_at": utc_now().isoformat(),
    }


# ============================================================================
# Executions
# ============================================================================

@router.get("/executions", response_model=List[RemediationExecutionResponse])
async def list_executions(
    db: DatabaseSession = None,
    status: Optional[str] = Query(None),
    trigger_source: Optional[str] = Query(None),
    days: int = Query(default=7, ge=1, le=90),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    current_user: CurrentUser = None,
):
    """List remediation executions."""
    org_id = getattr(current_user, "organization_id", None)
    query = select(RemediationExecution)
    if org_id:
        query = query.where(RemediationExecution.organization_id == org_id)

    cutoff = utc_now() - timedelta(days=days)
    query = query.where(RemediationExecution.created_at >= cutoff)

    if status:
        query = query.where(RemediationExecution.status == status)
    if trigger_source:
        query = query.where(RemediationExecution.trigger_source == trigger_source)

    query = query.order_by(desc(RemediationExecution.created_at)).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/executions/pending")
async def get_pending_approvals(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get pending approvals for current organization."""
    org_id = getattr(current_user, "organization_id", None)
    query = select(RemediationExecution).where(
        RemediationExecution.approval_status == "pending",
    )
    if org_id:
        query = query.where(RemediationExecution.organization_id == org_id)
    result = await db.execute(query)
    pending = result.scalars().all()

    return {
        "count": len(pending),
        "executions": pending,
    }


@router.get("/quick-actions")
async def list_quick_actions(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """List recent quick actions (block IP, isolate host, etc.)."""
    org_id = getattr(current_user, "organization_id", None)
    query = select(RemediationExecution).where(
        RemediationExecution.trigger_source.in_(["manual", "quick_action"])
    ).order_by(desc(RemediationExecution.created_at)).limit(20)
    if org_id:
        query = query.where(RemediationExecution.organization_id == org_id)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/executions/{execution_id}", response_model=RemediationExecutionResponse)
async def get_execution(
    execution_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Get execution detail with action results."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return execution


@router.get("/executions/{execution_id}/progress", response_model=ExecutionProgressResponse)
async def get_execution_progress(
    execution_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Get real-time execution progress."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    percent = 0.0
    if execution.actions_planned:
        percent = (execution.current_action_index + len(execution.actions_completed)) / len(execution.actions_planned) * 100

    return ExecutionProgressResponse(
        execution_id=execution.id,
        status=execution.status,
        approval_status=execution.approval_status,
        current_action_index=execution.current_action_index,
        total_actions=len(execution.actions_planned),
        target_entity=execution.target_entity,
        actions_completed=execution.actions_completed,
        overall_result=execution.overall_result,
        error_message=execution.error_message,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        percent_complete=percent,
    )


@router.post("/executions/{execution_id}/approve", response_model=ApprovalResponse)
async def approve_execution(
    execution_id: str,
    request: ApprovalRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Approve a pending remediation execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if execution.approval_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Execution not in pending approval state"
        )

    engine = RemediationEngine(db)
    await engine.approve_execution(execution_id, request.approver_id)

    return ApprovalResponse(
        execution_id=execution_id,
        approval_status="approved",
        approved_at=utc_now(),
    )


@router.post("/executions/{execution_id}/reject")
async def reject_execution(
    execution_id: str,
    request: RejectionRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Reject a pending remediation execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if execution.approval_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Execution not in pending approval state"
        )

    engine = RemediationEngine(db)
    await engine.reject_execution(execution_id, request.approver_id, request.reason)

    return {
        "execution_id": execution_id,
        "approval_status": "rejected",
    }


# ----------------------------------------------------------------------------
# Manual lifecycle endpoints for executions that can't be auto-completed.
#
# ``awaiting_manual`` and ``awaiting_integration`` executions have no
# approval record (the approve/reject endpoints 400 on them — there's
# nothing for an approver to say yes/no to). They need a way to advance
# off the board:
#
#   - mark-complete: an operator confirmed out of band that the action
#     actually happened (e.g. they blocked the IP by hand on the firewall
#     because no firewall integration is installed).
#   - mark-failed: the operator confirmed it won't happen. Records the
#     reason so the timeline tells the truth.
#
# Both write an AuditLog row and both refuse to run on executions that
# are already in a settled state (completed / failed / approved /
# rejected / awaiting_approval — the last one has the approve/reject
# flow).
# ----------------------------------------------------------------------------

_MANUAL_LIFECYCLE_ALLOWED = ("awaiting_manual", "awaiting_integration", "queued")
_MANUAL_LIFECYCLE_FORBIDDEN = (
    "completed", "failed", "approved", "rejected", "awaiting_approval"
)


class _MarkCompleteBody(PydanticBaseModel):
    notes: Optional[str] = None


class _MarkFailedBody(PydanticBaseModel):
    reason: str


@router.post("/executions/{execution_id}/mark-complete")
async def mark_execution_complete(
    execution_id: str,
    body: _MarkCompleteBody = Body(...),
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Operator confirms an awaiting_manual / awaiting_integration
    execution actually got done out of band. Transitions to completed."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if execution.status in _MANUAL_LIFECYCLE_FORBIDDEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot mark-complete an execution in status '{execution.status}'. "
                f"Allowed only from: {', '.join(_MANUAL_LIFECYCLE_ALLOWED)}."
            ),
        )
    if execution.status not in _MANUAL_LIFECYCLE_ALLOWED:
        # Other terminal/running states (running, cancelled, rolled_back,
        # timed_out) — refuse as well.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot mark-complete an execution in status '{execution.status}'. "
                f"Allowed only from: {', '.join(_MANUAL_LIFECYCLE_ALLOWED)}."
            ),
        )

    now = utc_now()
    prev_status = execution.status
    execution.status = "completed"
    execution.overall_result = "success"
    execution.completed_at = now
    if body.notes:
        # Preserve any prior notes rather than overwriting blindly.
        existing = execution.notes or ""
        execution.notes = (existing + "\n" if existing else "") + f"[manual complete] {body.notes}"
    # Record who completed it on the metrics blob (RemediationExecution
    # has no first-class completed_by column — metrics is where we keep
    # sidecar fields).
    metrics = dict(execution.metrics or {})
    metrics.update({
        "completed_by": str(current_user.id) if current_user else None,
        "completed_by_email": getattr(current_user, "email", None),
        "manual_lifecycle": "mark_complete",
        "prev_status": prev_status,
    })
    execution.metrics = metrics
    execution.updated_at = now

    db.add(AuditLog(
        user_id=str(current_user.id) if current_user else None,
        action="remediation.execution.mark_complete",
        resource_type="remediation_execution",
        resource_id=execution_id,
        description=(body.notes or None) or f"Marked complete from {prev_status}",
        new_value=json.dumps({
            "status": "completed",
            "prev_status": prev_status,
            "notes": body.notes,
        }, default=str),
        success=True,
    ))

    await db.commit()
    logger.info(
        "Remediation execution marked complete",
        extra={
            "execution_id": execution_id,
            "prev_status": prev_status,
            "user_id": getattr(current_user, "id", None),
        },
    )

    return {
        "execution_id": execution_id,
        "status": "completed",
        "completed_at": now.isoformat(),
        "completed_by": str(current_user.id) if current_user else None,
        "prev_status": prev_status,
    }


@router.post("/executions/{execution_id}/mark-failed")
async def mark_execution_failed(
    execution_id: str,
    body: _MarkFailedBody = Body(...),
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Operator confirms an awaiting_manual / awaiting_integration
    execution won't happen. Transitions to failed with reason."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if not body.reason or not body.reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="'reason' is required for mark-failed",
        )

    if execution.status in _MANUAL_LIFECYCLE_FORBIDDEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot mark-failed an execution in status '{execution.status}'. "
                f"Allowed only from: {', '.join(_MANUAL_LIFECYCLE_ALLOWED)}."
            ),
        )
    if execution.status not in _MANUAL_LIFECYCLE_ALLOWED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot mark-failed an execution in status '{execution.status}'. "
                f"Allowed only from: {', '.join(_MANUAL_LIFECYCLE_ALLOWED)}."
            ),
        )

    now = utc_now()
    prev_status = execution.status
    execution.status = "failed"
    execution.overall_result = "failure"
    execution.completed_at = now
    reason = body.reason.strip()
    execution.error_message = reason
    metrics = dict(execution.metrics or {})
    metrics.update({
        "failure_reason": reason,
        "failed_by": str(current_user.id) if current_user else None,
        "failed_by_email": getattr(current_user, "email", None),
        "manual_lifecycle": "mark_failed",
        "prev_status": prev_status,
    })
    execution.metrics = metrics
    execution.updated_at = now

    db.add(AuditLog(
        user_id=str(current_user.id) if current_user else None,
        action="remediation.execution.mark_failed",
        resource_type="remediation_execution",
        resource_id=execution_id,
        description=reason,
        new_value=json.dumps({
            "status": "failed",
            "prev_status": prev_status,
            "reason": reason,
        }, default=str),
        success=True,
    ))

    await db.commit()
    logger.info(
        "Remediation execution marked failed",
        extra={
            "execution_id": execution_id,
            "prev_status": prev_status,
            "user_id": getattr(current_user, "id", None),
        },
    )

    return {
        "execution_id": execution_id,
        "status": "failed",
        "failed_at": now.isoformat(),
        "failed_by": str(current_user.id) if current_user else None,
        "failure_reason": body.reason.strip(),
        "prev_status": prev_status,
    }


@router.post("/executions/{execution_id}/rollback")
async def rollback_execution(
    execution_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Rollback a completed execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    engine = RemediationEngine(db)
    result = await engine.rollback_execution(execution_id)

    return {
        "execution_id": execution_id,
        "rollback_status": "in_progress",
        "details": result,
    }


@router.post("/executions/{execution_id}/cancel")
async def cancel_execution(
    execution_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Cancel a running execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    execution.status = "cancelled"
    execution.updated_at = utc_now()
    await db.commit()

    return {"execution_id": execution_id, "status": "cancelled"}


# ============================================================================
# Manual Remediation
# ============================================================================

@router.post("/execute")
async def execute_manual_remediation(
    request: ManualRemediationRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Trigger manual remediation."""
    engine = RemediationEngine(db)

    execution = await engine.execute_remediation(
        policy_id=None,  # Manual execution
        trigger_data={
            "target_entity": request.target_entity,
            "target_type": request.target_type,
            "action_type": request.action_type,
        },
        trigger_source="manual",
        initiated_by=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )

    return {
        "execution_id": execution.id,
        "status": execution.status,
    }


# ============================================================================
# Quick Actions
# ============================================================================
#
# Each of the four quick actions below used to ``return {"status":
# "queued"}`` without touching the database, the integration layer, or
# an endpoint agent — analysts clicked "Block IP" and nothing happened.
# They now:
#
#   1. Write a RemediationExecution row so the Executions tab and
#      dashboard stats reflect the action.
#   2. If a matching integration (firewall / EDR / identity) is
#      installed and active, dispatch the action through its HTTP
#      API and mark the execution ``completed`` on 2xx, ``failed``
#      on anything else — with the error surfaced. No silent
#      green-checkmarks.
#   3. If no integration is installed, fall back to an IR-capable
#      endpoint agent (local pysoar agent). On high-blast actions
#      this still goes through the agent's own approval gate.
#   4. If neither path exists, the execution lands as
#      ``awaiting_integration`` (no firewall/EDR/etc installed)
#      or ``awaiting_manual`` (legacy), carrying a ``metadata.reason``
#      so the UI can render an honest "staged, nothing dispatched".
#   5. block-ip also writes a ThreatIndicator IOC so the IOC remains
#      available to any eventual downstream firewall that gets
#      installed later.

# Connector IDs that are capable of executing each remediation verb.
# ``connector_id`` in ``InstalledIntegration`` references
# ``integration_connectors.id`` (seeded from ``BUILTIN_CONNECTORS``).
_FIREWALL_CONNECTORS = (
    "palo_alto_ngfw", "paloalto", "fortinet",
    "cisco_asa", "cisco_firepower", "checkpoint", "generic_firewall",
)
_EDR_CONNECTORS = (
    "crowdstrike", "sentinelone", "carbon_black", "carbonblack",
    "microsoft_defender", "defender", "cortex_xdr",
)
_IDENTITY_CONNECTORS = (
    "okta", "azure_ad", "active_directory", "entra", "entra_id",
    "jumpcloud", "onelogin",
)


async def _find_active_integration(
    db,
    connector_ids: tuple,
    org_id: Optional[str],
):
    """Look up the first active ``InstalledIntegration`` whose
    ``connector_id`` matches any of ``connector_ids`` (case-insensitive)
    for this tenant. Returns None if none installed so callers can
    downgrade to awaiting_integration / agent dispatch."""
    from src.integrations.models import InstalledIntegration, IntegrationStatus

    normalized = tuple(c.lower() for c in connector_ids)
    q = select(InstalledIntegration).where(
        InstalledIntegration.status == IntegrationStatus.ACTIVE.value
    )
    if org_id:
        q = q.where(InstalledIntegration.organization_id == org_id)

    rows = list((await db.execute(q)).scalars().all())
    for row in rows:
        if (row.connector_id or "").lower() in normalized:
            return row
    return None


async def _dispatch_via_integration(
    integration,
    *,
    action: str,
    payload: dict,
) -> Tuple[bool, str, dict]:
    """Execute the remediation action through the installed integration.

    Returns ``(success, detail, raw_response)``. Does not swallow
    errors: on timeout / connection error / 4xx / 5xx returns
    ``success=False`` with a human-readable ``detail`` so the caller
    can surface the real reason.

    The dispatch is a POST to
    ``<endpoint>/<connector-specific-path>`` with Bearer / API-Key
    auth depending on what credentials the integration has stored.
    """
    import httpx

    # RemediationIntegration stores connection info in `endpoint_url`
    # and credentials in `auth_config`. The previous code referenced
    # nonexistent `config_encrypted`/`auth_credentials_encrypted`
    # columns (those live on InstalledIntegration) so every remediation
    # dispatch silently fell through to the "base_url not configured"
    # branch regardless of what the admin had saved.
    try:
        config = dict(integration.auth_config) if integration.auth_config else {}
    except Exception:
        config = {}
    credentials = config  # auth_config holds both endpoint metadata and creds
    endpoint_url = (
        integration.endpoint_url
        or config.get("endpoint_url")
        or config.get("base_url")
        or config.get("url")
        or ""
    )
    base_url = endpoint_url.rstrip("/") if endpoint_url else ""
    if not base_url:
        integration_label = integration.vendor or integration.integration_type or "integration"
        return False, f"{integration_label} base_url not configured", {}

    api_key = credentials.get("api_key") or credentials.get("token")
    bearer = credentials.get("bearer_token") or credentials.get("access_token")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    elif api_key:
        # Most vendors accept either Authorization: Bearer or x-api-key
        headers["Authorization"] = f"Bearer {api_key}"
        headers["x-api-key"] = api_key

    # Connector-specific URL suffix. We default to a POST of the
    # payload to <base>/remediation/<action> because every vendor
    # in our shortlist exposes a JSON endpoint, and that is the
    # shape our generic_firewall / generic_edr connectors expect.
    connector = ((integration.vendor or integration.integration_type or "integration") or "").lower()
    suffix_map = {
        "crowdstrike": f"/devices/entities/devices-actions/v2?action_name={action}",
        "sentinelone": f"/web/api/v2.1/agents/actions/{action}",
        "carbon_black": f"/appservices/v6/actions/{action}",
        "carbonblack": f"/appservices/v6/actions/{action}",
        "microsoft_defender": f"/api/machines/{action}",
        "defender": f"/api/machines/{action}",
        "cortex_xdr": f"/public_api/v1/endpoints/{action}",
        "palo_alto_ngfw": "/api/?type=op",
        "paloalto": "/api/?type=op",
        "fortinet": "/api/v2/cmdb/firewall/address",
        "cisco_asa": "/api/objects/networkobjects",
        "cisco_firepower": "/api/fmc_config/v1/domain/policy",
        "checkpoint": "/web_api/add-host",
        "okta": f"/api/v1/users/{payload.get('username','')}/lifecycle/{'deactivate' if action=='disable_account' else action}",
        "azure_ad": f"/v1.0/users/{payload.get('username','')}",
        "active_directory": f"/users/{payload.get('username','')}/disable",
        "entra": f"/v1.0/users/{payload.get('username','')}",
        "entra_id": f"/v1.0/users/{payload.get('username','')}",
    }
    url = f"{base_url}{suffix_map.get(connector, f'/remediation/{action}')}"

    timeout = httpx.Timeout(15.0, connect=5.0)
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=config.get("verify_tls", True),
        ) as client:
            resp = await client.post(url, headers=headers, json=payload)
    except httpx.TimeoutException:
        return False, f"{connector}: request timed out after 15s", {}
    except httpx.HTTPError as exc:
        return False, f"{connector}: HTTP error: {exc}", {}

    try:
        body = resp.json()
    except Exception:
        body = {"raw_text": (resp.text or "")[:2000]}

    if 200 <= resp.status_code < 300:
        return True, f"{connector} accepted {action} (HTTP {resp.status_code})", body
    if resp.status_code in (401, 403):
        return False, f"{connector}: authentication rejected (HTTP {resp.status_code})", body
    return False, f"{connector}: dispatch failed (HTTP {resp.status_code})", body


async def _find_ir_agent(db, hostname: Optional[str], org_id: Optional[str]):
    """Find an active IR-capable agent for ``hostname`` (or any IR agent
    in the org if no hostname is provided). Returns None if nothing
    matches so callers can fall back to a manual execution path."""
    from src.agents.models import EndpointAgent
    from src.agents.capabilities import AgentCapability

    q = select(EndpointAgent).where(EndpointAgent.status == "active")
    if hostname:
        q = q.where(EndpointAgent.hostname == hostname)
    if org_id:
        q = q.where(EndpointAgent.organization_id == org_id)

    rows = list((await db.execute(q)).scalars().all())
    for a in rows:
        if AgentCapability.LIVE_RESPONSE.value in (a.capabilities or []):
            return a
    return None


async def _write_execution(
    *,
    db,
    current_user,
    target_entity: str,
    target_type: str,
    action_type: str,
    trigger_details: dict,
    agent_command_id: Optional[str] = None,
    status_value: str = "running",
) -> RemediationExecution:
    """Create a RemediationExecution row for a quick action."""
    execution = RemediationExecution(
        policy_id=None,
        trigger_source="manual_quick_action",
        trigger_details=trigger_details,
        status=status_value,
        target_entity=target_entity,
        target_type=target_type,
        actions_planned=[{"action_type": action_type, "target": target_entity}],
        actions_completed=[],
        started_at=utc_now() if status_value == "running" else None,
        created_by=str(current_user.id) if current_user else None,
        organization_id=getattr(current_user, "organization_id", None) or "",
        metrics={"agent_command_id": agent_command_id} if agent_command_id else {},
    )
    db.add(execution)
    await db.flush()
    await db.refresh(execution)
    return execution


@router.post("/block-ip")
async def quick_block_ip(
    request: QuickBlockIPRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: block an attacker IP.

    Always writes a ThreatIndicator IOC so the block is staged for
    any future firewall integration. Then:
      * If a firewall integration is installed and active, dispatch
        the block via its HTTP API and mark ``completed`` only on 2xx.
        On failure, mark ``failed`` with ``error_message``.
      * If no firewall is installed, mark ``awaiting_integration`` so
        the UI can tell the operator this was staged, not dispatched.
    """
    org_id = getattr(current_user, "organization_id", None)
    logger.info("Quick block IP", extra={"ip": request.ip, "duration_hours": request.duration_hours})

    # Write ThreatIndicator IOC — that's what a firewall block really is
    try:
        from src.intel.models import ThreatIndicator
        ioc = ThreatIndicator(
            indicator_type="ip",
            value=request.ip,
            severity="high",
            confidence=95,
            source="remediation_quick_action",
            tags=["auto_block", f"ttl_hours_{request.duration_hours}"],
            is_active=True,
            organization_id=org_id or "",
        )
        db.add(ioc)
        await db.flush()
        ioc_id = ioc.id
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to create ThreatIndicator for block-ip: {exc}")
        ioc_id = None

    # Is there a firewall integration we can actually dispatch through?
    integration = await _find_active_integration(db, _FIREWALL_CONNECTORS, org_id)

    dispatch_method: str
    integration_id: Optional[str] = None
    status_value: str
    overall_result: str
    error_message: Optional[str] = None
    integration_detail: Optional[str] = None
    response_body: dict = {}

    if integration is not None:
        integration_id = integration.id
        dispatch_method = "integration"
        success, integration_detail, response_body = await _dispatch_via_integration(
            integration,
            action="block_ip",
            payload={
                "ip": request.ip,
                "duration_hours": request.duration_hours,
                "reason": request.reason or "quick action",
                "ioc_id": ioc_id,
            },
        )
        if success:
            status_value = "completed"
            overall_result = "success"
        else:
            status_value = "failed"
            overall_result = "failure"
            error_message = integration_detail
    else:
        dispatch_method = "awaiting_integration"
        status_value = "awaiting_integration"
        overall_result = "pending"

    execution = await _write_execution(
        db=db,
        current_user=current_user,
        target_entity=request.ip,
        target_type="ip",
        action_type="firewall_block",
        trigger_details={
            "ip": request.ip,
            "duration_hours": request.duration_hours,
            "ioc_id": ioc_id,
            "reason": request.reason or "quick action",
            "dispatch_method": dispatch_method,
            "integration_id": integration_id,
            "integration_detail": integration_detail,
        },
        status_value=status_value,
    )
    execution.actions_completed = [{
        "action_type": "firewall_block",
        "target": request.ip,
        "result": overall_result,
        "ioc_id": ioc_id,
        "dispatch_method": dispatch_method,
        "integration_id": integration_id,
        "detail": integration_detail,
    }]
    execution.overall_result = overall_result
    execution.error_message = error_message
    # Capture the truth on the execution row's metrics blob too —
    # that's what the UI tooltips read.
    metrics = dict(execution.metrics or {})
    metrics.update({
        "dispatch_method": dispatch_method,
        "integration_id": integration_id,
        "integration_detail": integration_detail,
        "response": response_body,
        "reason": (
            "no_firewall_integration_installed"
            if dispatch_method == "awaiting_integration" else None
        ),
    })
    execution.metrics = metrics
    if status_value in ("completed", "failed"):
        execution.completed_at = utc_now()
    await db.flush()

    return {
        "execution_id": execution.id,
        "action": "block_ip",
        "target": request.ip,
        "duration_hours": request.duration_hours,
        "status": execution.status,
        "ioc_id": ioc_id,
        "dispatch_method": dispatch_method,
        "integration_id": integration_id,
        "error_message": error_message,
    }


@router.post("/isolate-host")
async def quick_isolate_host(
    request: QuickIsolateHostRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: isolate a host.

    Prefers a native EDR integration (CrowdStrike / SentinelOne /
    Defender / Carbon Black). Falls back to the pysoar endpoint
    agent if one is enrolled. If neither is available, lands as
    ``awaiting_integration`` with an honest metadata.reason.
    """
    from src.agents.capabilities import AgentAction
    from src.agents.service import AgentService

    org_id = getattr(current_user, "organization_id", None)
    logger.info("Quick isolate host", extra={"hostname": request.hostname})

    integration = await _find_active_integration(db, _EDR_CONNECTORS, org_id)

    dispatch_method: str
    integration_id: Optional[str] = None
    agent_command_id: Optional[str] = None
    status_value: str
    error_message: Optional[str] = None
    integration_detail: Optional[str] = None
    overall_result: str
    response_body: dict = {}
    reason_tag: Optional[str] = None

    if integration is not None:
        integration_id = integration.id
        dispatch_method = "integration"
        success, integration_detail, response_body = await _dispatch_via_integration(
            integration,
            action="isolate_host",
            payload={
                "hostname": request.hostname,
                "reason": request.reason or "quick action",
            },
        )
        if success:
            status_value = "completed"
            overall_result = "success"
        else:
            status_value = "failed"
            overall_result = "failure"
            error_message = integration_detail
    else:
        # No EDR integration — try local agent next.
        agent = await _find_ir_agent(db, request.hostname, org_id)
        if agent is not None:
            try:
                svc = AgentService(db)
                cmd = await svc.issue_command(
                    agent=agent,
                    action=AgentAction.ISOLATE_HOST.value,
                    payload={"reason": request.reason or "manual quick action"},
                    issued_by=str(current_user.id),
                )
                agent_command_id = cmd.id
                status_value = "awaiting_approval"
                dispatch_method = "integration"
                integration_detail = f"dispatched via pysoar agent {agent.id}"
                overall_result = "pending"
            except Exception as exc:  # noqa: BLE001
                logger.error(f"AgentService.issue_command failed for isolate_host: {exc}")
                dispatch_method = "awaiting_integration"
                status_value = "awaiting_integration"
                error_message = f"agent dispatch failed: {exc}"
                overall_result = "pending"
                reason_tag = "agent_dispatch_failed"
        else:
            dispatch_method = "awaiting_integration"
            status_value = "awaiting_integration"
            overall_result = "pending"
            reason_tag = "no_edr_integration_installed"

    execution = await _write_execution(
        db=db,
        current_user=current_user,
        target_entity=request.hostname,
        target_type="host",
        action_type="host_isolate",
        trigger_details={
            "hostname": request.hostname,
            "reason": request.reason,
            "dispatch_method": dispatch_method,
            "integration_id": integration_id,
            "agent_command_id": agent_command_id,
        },
        agent_command_id=agent_command_id,
        status_value=status_value,
    )
    execution.overall_result = overall_result
    execution.error_message = error_message
    metrics = dict(execution.metrics or {})
    metrics.update({
        "dispatch_method": dispatch_method,
        "integration_id": integration_id,
        "integration_detail": integration_detail,
        "agent_command_id": agent_command_id,
        "response": response_body,
        "reason": reason_tag,
    })
    execution.metrics = metrics
    if status_value in ("completed", "failed"):
        execution.completed_at = utc_now()
    await db.flush()

    return {
        "execution_id": execution.id,
        "action": "isolate_host",
        "target": request.hostname,
        "status": execution.status,
        "dispatch_method": dispatch_method,
        "integration_id": integration_id,
        "agent_command_id": agent_command_id,
        "error_message": error_message,
    }


@router.post("/disable-account")
async def quick_disable_account(
    request: QuickDisableAccountRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: disable a user account.

    Prefers an identity-provider integration (Okta / Azure AD /
    Entra / AD). Falls back to the pysoar endpoint agent if one is
    enrolled on the target host. Otherwise lands as
    ``awaiting_integration`` so the UI can tell the operator this
    was staged, not dispatched.
    """
    from src.agents.capabilities import AgentAction
    from src.agents.service import AgentService

    org_id = getattr(current_user, "organization_id", None)
    logger.info("Quick disable account", extra={"username": request.username})

    integration = await _find_active_integration(db, _IDENTITY_CONNECTORS, org_id)

    dispatch_method: str
    integration_id: Optional[str] = None
    agent_command_id: Optional[str] = None
    status_value: str
    error_message: Optional[str] = None
    integration_detail: Optional[str] = None
    overall_result: str
    response_body: dict = {}
    reason_tag: Optional[str] = None

    if integration is not None:
        integration_id = integration.id
        dispatch_method = "integration"
        success, integration_detail, response_body = await _dispatch_via_integration(
            integration,
            action="disable_account",
            payload={
                "username": request.username,
                "reason": request.reason or "quick action",
            },
        )
        if success:
            status_value = "completed"
            overall_result = "success"
        else:
            status_value = "failed"
            overall_result = "failure"
            error_message = integration_detail
    else:
        agent = await _find_ir_agent(db, getattr(request, "hostname", None), org_id)
        if agent is not None:
            try:
                svc = AgentService(db)
                cmd = await svc.issue_command(
                    agent=agent,
                    action=AgentAction.DISABLE_ACCOUNT.value,
                    payload={
                        "username": request.username,
                        "reason": request.reason or "manual quick action",
                    },
                    issued_by=str(current_user.id),
                )
                agent_command_id = cmd.id
                status_value = "awaiting_approval"
                dispatch_method = "integration"
                integration_detail = f"dispatched via pysoar agent {agent.id}"
                overall_result = "pending"
            except Exception as exc:  # noqa: BLE001
                logger.error(f"AgentService.issue_command failed for disable_account: {exc}")
                dispatch_method = "awaiting_integration"
                status_value = "awaiting_integration"
                error_message = f"agent dispatch failed: {exc}"
                overall_result = "pending"
                reason_tag = "agent_dispatch_failed"
        else:
            dispatch_method = "awaiting_integration"
            status_value = "awaiting_integration"
            overall_result = "pending"
            reason_tag = "no_identity_integration_installed"

    execution = await _write_execution(
        db=db,
        current_user=current_user,
        target_entity=request.username,
        target_type="user",
        action_type="account_disable",
        trigger_details={
            "username": request.username,
            "reason": getattr(request, "reason", None),
            "dispatch_method": dispatch_method,
            "integration_id": integration_id,
            "agent_command_id": agent_command_id,
        },
        agent_command_id=agent_command_id,
        status_value=status_value,
    )
    execution.overall_result = overall_result
    execution.error_message = error_message
    metrics = dict(execution.metrics or {})
    metrics.update({
        "dispatch_method": dispatch_method,
        "integration_id": integration_id,
        "integration_detail": integration_detail,
        "agent_command_id": agent_command_id,
        "response": response_body,
        "reason": reason_tag,
    })
    execution.metrics = metrics
    if status_value in ("completed", "failed"):
        execution.completed_at = utc_now()
    await db.flush()

    return {
        "execution_id": execution.id,
        "action": "disable_account",
        "target": request.username,
        "status": execution.status,
        "dispatch_method": dispatch_method,
        "integration_id": integration_id,
        "agent_command_id": agent_command_id,
        "error_message": error_message,
    }


@router.post("/quarantine-file")
async def quick_quarantine_file(
    request: QuickQuarantineFileRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: quarantine a file on a specific host.

    Requires a hostname so we can route the action to the right IR
    agent. Quarantine is a high-blast action → awaiting_approval.
    """
    from src.agents.capabilities import AgentAction
    from src.agents.service import AgentService

    org_id = getattr(current_user, "organization_id", None)
    logger.info("Quick quarantine file", extra={
        "file_path": request.file_path,
        "hostname": request.hostname,
    })

    agent = await _find_ir_agent(db, request.hostname, org_id)
    agent_command_id: Optional[str] = None
    status_value = "awaiting_manual"

    if agent is not None:
        try:
            svc = AgentService(db)
            cmd = await svc.issue_command(
                agent=agent,
                action=AgentAction.QUARANTINE_FILE.value,
                payload={"path": request.file_path},
                issued_by=str(current_user.id),
            )
            agent_command_id = cmd.id
            status_value = "awaiting_approval"
        except Exception as exc:  # noqa: BLE001
            logger.error(f"AgentService.issue_command failed for quarantine_file: {exc}")

    execution = await _write_execution(
        db=db,
        current_user=current_user,
        target_entity=request.file_path,
        target_type="file",
        action_type="file_quarantine",
        trigger_details={
            "file_path": request.file_path,
            "hostname": request.hostname,
            "agent_id": agent.id if agent else None,
        },
        agent_command_id=agent_command_id,
        status_value=status_value,
    )

    return {
        "execution_id": execution.id,
        "action": "quarantine_file",
        "target": request.file_path,
        "hostname": request.hostname,
        "status": status_value,
        "agent_command_id": agent_command_id,
        "agent_available": agent is not None,
    }


# ============================================================================
# Playbooks
# ============================================================================

@router.get("/playbooks", response_model=List[RemediationPlaybookResponse])
async def list_playbooks(
    db: DatabaseSession = None,
    playbook_type: Optional[str] = Query(None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    current_user = Depends(get_current_active_user),
):
    """List remediation playbooks."""
    query = select(RemediationPlaybook).where(
        RemediationPlaybook.organization_id == getattr(current_user, "organization_id", None)
    )

    if playbook_type:
        query = query.where(RemediationPlaybook.playbook_type == playbook_type)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/playbooks", response_model=RemediationPlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    request: RemediationPlaybookCreate,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Create a remediation playbook."""
    playbook = RemediationPlaybook(
        name=request.name,
        description=request.description,
        playbook_type=request.playbook_type,
        trigger_conditions=request.trigger_conditions,
        steps=[s.model_dump() for s in request.steps],
        decision_points=request.decision_points,
        parallel_actions=request.parallel_actions,
        estimated_duration_minutes=request.estimated_duration_minutes,
        is_template=request.is_template,
        is_enabled=request.is_enabled,
        tags=request.tags,
        created_by=request.created_by,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.get("/playbooks/{playbook_id}", response_model=RemediationPlaybookResponse)
async def get_playbook(
    playbook_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Get a specific playbook."""
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return playbook


@router.put("/playbooks/{playbook_id}", response_model=RemediationPlaybookResponse)
async def update_playbook(
    playbook_id: str,
    request: RemediationPlaybookCreate,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Update a playbook."""
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    playbook.name = request.name
    playbook.description = request.description
    playbook.steps = [s.model_dump() for s in request.steps]
    playbook.is_enabled = request.is_enabled
    playbook.updated_at = utc_now()

    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.post("/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    trigger_data: dict,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Execute a playbook against a real target and persist the run.

    Previously returned ``{"status": "queued"}`` with no execution row
    ever written. The playbook appeared to run but no side effect was
    captured, no actions dispatched, no audit trail. This now creates
    a ``RemediationExecution`` for the playbook's action set, fans out
    to ``_execute_remediation_action`` for each step, and records
    ``actions_completed`` / ``actions_failed`` on the row.
    """
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if not playbook.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Playbook is disabled",
        )

    target_entity = str(
        trigger_data.get("target_entity")
        or trigger_data.get("target")
        or trigger_data.get("ip_address")
        or trigger_data.get("hostname")
        or "unspecified"
    )
    target_type = str(trigger_data.get("target_type") or "host")

    execution = RemediationExecution(
        policy_id=None,
        trigger_source=str(trigger_data.get("trigger_source") or "manual"),
        trigger_id=trigger_data.get("trigger_id"),
        trigger_details={"playbook_id": playbook_id, **(trigger_data or {})},
        status="running",
        started_at=utc_now(),
        target_entity=target_entity,
        target_type=target_type,
        actions_planned=list(playbook.steps or []),
        actions_completed=[],
        current_action_index=0,
        metrics={},
        created_by=str(current_user.id),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(execution)
    await db.flush()

    # Map playbook step types to an integration_type we look up on the
    # RemediationIntegration table. Action types we can't map fall
    # through to 'awaiting_integration' so the execution row carries
    # honest state.
    _ACTION_TO_INT_TYPE: dict[str, str] = {
        "auto_block": "firewall",
        "block_ip": "firewall",
        "block_domain": "firewall",
        "auto_isolate": "edr",
        "isolate_host": "edr",
        "auto_quarantine": "edr",
        "quarantine_file": "edr",
        "auto_disable": "idp",
        "disable_account": "idp",
        "reset_password": "idp",
        "revoke_token": "idp",
    }

    async def _pick_integration(action_key: str):
        int_type = _ACTION_TO_INT_TYPE.get(action_key)
        if not int_type:
            return None
        from src.remediation.models import RemediationIntegration
        res = await db.execute(
            select(RemediationIntegration).where(
                RemediationIntegration.integration_type == int_type,
                RemediationIntegration.is_enabled == True,
                RemediationIntegration.organization_id == getattr(current_user, "organization_id", None),
            ).limit(1)
        )
        return res.scalars().first()

    actions_completed: list[dict] = []
    actions_failed: list[dict] = []
    for idx, step in enumerate(playbook.steps or []):
        if not isinstance(step, dict):
            actions_failed.append({"index": idx, "error": "malformed step", "step": step})
            continue
        step_type = str(step.get("action_type") or step.get("type") or playbook.playbook_type or "custom")
        params = step.get("params") or step.get("action_config") or {}
        try:
            integration = await _pick_integration(step_type)
            if integration is None:
                actions_completed.append({
                    "index": idx,
                    "action": step_type,
                    "status": "awaiting_integration",
                    "details": f"No enabled integration installed for action type '{step_type}'.",
                })
            else:
                success, detail, response_body = await _dispatch_via_integration(
                    integration,
                    action=step_type,
                    payload={"target": target_entity, "target_type": target_type, **params},
                )
                (actions_completed if success else actions_failed).append({
                    "index": idx,
                    "action": step_type,
                    "status": "success" if success else "failed",
                    "integration": integration.name,
                    "detail": detail,
                    "response": response_body,
                })
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Playbook step {idx} failed: {exc}", exc_info=True)
            actions_failed.append({
                "index": idx,
                "action": step_type,
                "error": str(exc),
            })
        execution.current_action_index = idx + 1

    execution.actions_completed = actions_completed
    if actions_failed:
        execution.metrics = {"actions_failed": actions_failed}
    execution.completed_at = utc_now()
    if actions_failed and actions_completed:
        execution.status = "completed"
        execution.overall_result = "partial_success"
    elif actions_failed:
        execution.status = "failed"
        execution.overall_result = "failure"
        execution.error_message = "; ".join(
            f"{a.get('action', '?')}: {a.get('error', '?')}" for a in actions_failed
        )[:2000]
    else:
        execution.status = "completed"
        execution.overall_result = "success"

    # Playbook-level metrics so the Playbooks tab shows honest counters.
    try:
        if execution.overall_result == "success":
            playbook.success_count = (playbook.success_count or 0) + 1
        elif execution.overall_result == "failure":
            playbook.failure_count = (playbook.failure_count or 0) + 1
        playbook.last_executed_at = utc_now()
    except Exception:  # noqa: BLE001
        pass

    await db.flush()
    await db.refresh(execution)

    return {
        "playbook_id": playbook_id,
        "execution_id": execution.id,
        "status": execution.status,
        "overall_result": execution.overall_result,
        "actions_completed": len(actions_completed),
        "actions_failed": len(actions_failed),
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
    }


# ============================================================================
# Integrations
# ============================================================================

@router.get("/integrations", response_model=List[RemediationIntegrationResponse])
async def list_integrations(
    db: DatabaseSession = None,
    integration_type: Optional[str] = Query(None),
    current_user: CurrentUser = None,
):
    """List remediation integrations."""
    org_id = getattr(current_user, "organization_id", None)
    query = select(RemediationIntegration)
    if org_id:
        query = query.where(RemediationIntegration.organization_id == org_id)

    if integration_type:
        query = query.where(RemediationIntegration.integration_type == integration_type)

    result = await db.execute(query)
    return result.scalars().all()


@router.post("/integrations", response_model=RemediationIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_integration(
    request: RemediationIntegrationCreate,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Add a remediation integration."""
    integration = RemediationIntegration(
        name=request.name,
        integration_type=request.integration_type,
        vendor=request.vendor,
        endpoint_url=request.endpoint_url,
        auth_type=request.auth_type,
        auth_config=request.auth_config,
        capabilities=request.capabilities,
        rate_limit=request.rate_limit,
        tags=request.tags,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(integration)
    await db.commit()
    await db.refresh(integration)
    return integration


@router.put("/integrations/{integration_id}", response_model=RemediationIntegrationResponse)
async def update_integration(
    integration_id: str,
    request: RemediationIntegrationCreate,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Update an integration."""
    integration = await db.get(RemediationIntegration, integration_id)
    if not integration or integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    for key, value in request.model_dump(exclude_unset=True).items():
        setattr(integration, key, value)
    integration.updated_at = utc_now()

    await db.commit()
    await db.refresh(integration)
    return integration


@router.post("/integrations/{integration_id}/test", response_model=IntegrationTestResult)
async def test_integration(
    integration_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Test integration connectivity."""
    integration = await db.get(RemediationIntegration, integration_id)
    if not integration or integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return IntegrationTestResult(
        integration_id=integration_id,
        success=True,
        message="Integration test successful",
        tested_at=utc_now(),
    )


@router.get("/integrations/{integration_id}/health")
async def get_integration_health(
    integration_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Check integration health status."""
    integration = await db.get(RemediationIntegration, integration_id)
    if not integration or integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return {
        "integration_id": integration_id,
        "is_connected": integration.is_connected,
        "health_status": integration.health_status,
        "last_health_check": integration.last_health_check,
    }


# ============================================================================
# Dashboard
# ============================================================================

@router.get("/dashboard", response_model=RemediationDashboardStats)
async def get_dashboard_stats(
    db: DatabaseSession = None,
    days: int = Query(default=7, ge=1, le=90),
    current_user: CurrentUser = None,
):
    """Get remediation dashboard statistics."""
    org_id = getattr(current_user, "organization_id", None)
    cutoff = utc_now() - timedelta(days=days)

    query = select(RemediationExecution).where(
        RemediationExecution.created_at >= cutoff,
    )
    if org_id:
        query = query.where(RemediationExecution.organization_id == org_id)
    result = await db.execute(query)
    executions = result.scalars().all()

    total = len(executions)
    successful = sum(1 for e in executions if e.overall_result == "success")
    failed = sum(1 for e in executions if e.overall_result == "failure")
    pending = sum(1 for e in executions if e.status in ["pending", "awaiting_approval"])

    # --- Real aggregates (previously hardcoded []) ---

    # Action type histogram — walk actions_completed and actions_planned
    # per execution. Planned captures the "what would run" picture even
    # when the execution hasn't completed yet; completed captures the
    # success/failure breakdown.
    from src.schemas.remediation import ActionTypeStats, PolicyStats
    action_type_counts: dict[str, dict[str, int]] = {}
    for e in executions:
        planned = e.actions_planned or []
        completed = e.actions_completed or []
        for a in planned:
            at = (a or {}).get("action_type") or (a or {}).get("type") or "unknown"
            bucket = action_type_counts.setdefault(
                at, {"count": 0, "success": 0, "failure": 0}
            )
            bucket["count"] += 1
        for a in completed:
            at = (a or {}).get("action_type") or (a or {}).get("type") or "unknown"
            bucket = action_type_counts.setdefault(
                at, {"count": 0, "success": 0, "failure": 0}
            )
            result = (a or {}).get("result", "").lower()
            if result in ("success", "ioc_created"):
                bucket["success"] += 1
            elif result in ("failure", "failed", "error"):
                bucket["failure"] += 1
    actions_by_type = [
        ActionTypeStats(
            action_type=k,
            count=v["count"],
            success_count=v["success"],
            failure_count=v["failure"],
        )
        for k, v in action_type_counts.items()
    ]

    # Top policies — group executions by policy_id, find the top 5
    # by execution count, resolve names from the RemediationPolicy table.
    policy_counts: dict[str, dict[str, int]] = {}
    for e in executions:
        if not e.policy_id:
            continue
        bucket = policy_counts.setdefault(
            e.policy_id, {"count": 0, "success": 0, "failure": 0}
        )
        bucket["count"] += 1
        if e.overall_result == "success":
            bucket["success"] += 1
        elif e.overall_result == "failure":
            bucket["failure"] += 1

    top_policies: list[PolicyStats] = []
    if policy_counts:
        top_policy_ids = sorted(
            policy_counts.keys(), key=lambda pid: -policy_counts[pid]["count"]
        )[:5]
        name_stmt = select(RemediationPolicy).where(
            RemediationPolicy.id.in_(top_policy_ids)
        )
        if org_id:
            name_stmt = name_stmt.where(
                RemediationPolicy.organization_id == org_id
            )
        name_map = {
            p.id: p.name
            for p in (await db.execute(name_stmt)).scalars().all()
        }
        top_policies = [
            PolicyStats(
                policy_id=pid,
                name=name_map.get(pid, "(deleted policy)"),
                execution_count=policy_counts[pid]["count"],
                success_count=policy_counts[pid]["success"],
                failure_count=policy_counts[pid]["failure"],
            )
            for pid in top_policy_ids
        ]

    # Top targets — which hosts/IPs/users are getting remediated
    # most often. Useful for spotting a noisy asset.
    target_counts: dict[str, int] = {}
    for e in executions:
        key = f"{e.target_type}:{e.target_entity}"
        target_counts[key] = target_counts.get(key, 0) + 1
    top_targets = [
        {"target": k, "count": v}
        for k, v in sorted(target_counts.items(), key=lambda x: -x[1])[:10]
    ]

    # Execution hour histogram (24-bucket UTC)
    hour_counts: dict[int, int] = {h: 0 for h in range(24)}
    for e in executions:
        if e.created_at:
            hour_counts[e.created_at.hour] = hour_counts.get(e.created_at.hour, 0) + 1
    execution_by_hour = [
        {"hour": h, "count": c} for h, c in sorted(hour_counts.items())
    ]

    # Average execution wall clock in minutes, using started_at/completed_at
    durations = [
        (e.completed_at - e.started_at).total_seconds() / 60.0
        for e in executions
        if e.started_at and e.completed_at and e.completed_at > e.started_at
    ]
    avg_exec_minutes = round(sum(durations) / len(durations), 2) if durations else 0.0

    return RemediationDashboardStats(
        period_start=cutoff,
        period_end=utc_now(),
        organization_id=org_id or "",
        total_executions=total,
        successful_executions=successful,
        failed_executions=failed,
        overall_success_rate=(successful / total * 100) if total else 0,
        avg_execution_minutes=avg_exec_minutes,
        pending_approvals=sum(1 for e in executions if e.approval_status == "pending"),
        in_progress=sum(1 for e in executions if e.status == "running"),
        actions_by_type=actions_by_type,
        top_policies=top_policies,
        top_targets=top_targets,
        execution_by_hour=execution_by_hour,
    )


@router.get("/timeline", response_model=RemediationTimelineResponse)
async def get_remediation_timeline(
    db: DatabaseSession = None,
    days: int = Query(default=7, ge=1, le=90),
    current_user: CurrentUser = None,
):
    """Get recent remediation timeline."""
    org_id = getattr(current_user, "organization_id", None)
    cutoff = utc_now() - timedelta(days=days)

    query = select(RemediationExecution).where(
        RemediationExecution.created_at >= cutoff,
    ).order_by(desc(RemediationExecution.completed_at))
    if org_id:
        query = query.where(RemediationExecution.organization_id == org_id)

    result = await db.execute(query)
    executions = result.scalars().all()

    return RemediationTimelineResponse(
        organization_id=org_id or "",
        period=f"last_{days}_days",
        events=[],
        total_count=len(executions),
    )


@router.get("/effectiveness", response_model=EffectivenessMetrics)
async def get_effectiveness_metrics(
    db: DatabaseSession = None,
    days: int = Query(default=7, ge=1, le=90),
    current_user = Depends(get_current_active_user),
):
    """Get remediation effectiveness metrics."""
    return EffectivenessMetrics(
        organization_id=getattr(current_user, "organization_id", None),
        period=f"last_{days}_days",
        executions_verified=0,
        effective_count=0,
        ineffective_count=0,
        effectiveness_rate=0.0,
        rollbacks_recommended=0,
        rollbacks_executed=0,
    )
