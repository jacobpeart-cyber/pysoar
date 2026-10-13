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
from typing import Any, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel as PydanticBaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.core.logging import get_logger
from src.models.audit import AuditLog
from src.models.base import utc_now
from src.models.user import UserRole
from src.remediation.actions import (
    UnknownActionError,
    is_containment_step,
    list_actions as registry_actions,
    normalize_actions,
    resolve_action,
    run_action,
    step_is_reversible,
    step_key,
    summarize_steps,
)
from src.remediation.engine import RemediationEngine
from src.remediation.models import (
    RemediationAction,
    RemediationExecution,
    RemediationPlaybook,
    RemediationPolicy,
)
from src.schemas.remediation import (
    ApprovalRequest,
    ApprovalResponse,
    EffectivenessMetrics,
    ExecutionActionResult,
    ExecutionProgressResponse,
    IntegrationTestResult,
    ManualRemediationRequest,
    QuickBlockIPRequest,
    QuickDisableAccountRequest,
    QuickIsolateHostRequest,
    QuickQuarantineFileRequest,
    RejectionRequest,
    RemediationActionCreate,
    RemediationActionResponse,
    RemediationActionSpecResponse,
    RemediationDashboardStats,
    RemediationExecutionResponse,
    RemediationIntegrationCreate,
    RemediationIntegrationResponse,
    RemediationIntegrationUpdate,
    RemediationPlaybookCreate,
    RemediationPlaybookResponse,
    RemediationPolicyCreate,
    RemediationPolicyResponse,
    RemediationPolicyUpdate,
    RemediationTimelineResponse,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/remediation", tags=["remediation"])

#: Operational writes (testing, manual lifecycle, cancel): analysts and admins.
_ANALYST_WRITE = [Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
#: Configuration (policies, actions, playbooks, integrations), containment
#: (quick actions, playbook runs, rollback) and approvals: admins only.
_ADMIN_WRITE = [Depends(require_role([UserRole.ADMIN]))]


def _validated_actions(actions: list) -> list[dict]:
    """Policy actions normalised to registry keys, or 400 ``unknown_action``."""
    try:
        return normalize_actions(actions)
    except UnknownActionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "unknown_action",
                "detail": str(exc),
                "unknown": exc.unknown,
                "allowed": [a["key"] for a in registry_actions()],
            },
        ) from exc


# ============================================================================
# Policies
# ============================================================================

@router.post("/policies", response_model=RemediationPolicyResponse, status_code=status.HTTP_201_CREATED, dependencies=_ADMIN_WRITE)
async def create_policy(
    request: RemediationPolicyCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        actions=_validated_actions(request.actions),
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
        organization_id=org_id,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/policies", response_model=List[RemediationPolicyResponse])
async def list_policies(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    policy_type: Optional[str] = Query(None),
    trigger_type: Optional[str] = Query(None),
    enabled_only: bool = Query(default=False),
    policy_type_alias: Optional[str] = Query(None, alias="type", description="Alias of policy_type"),
    enabled: Optional[bool] = Query(None, description="Filter on is_enabled (true or false)"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    current_user: CurrentUser = None,
):
    """List remediation policies, disabled ones included unless filtered out."""
    query = select(RemediationPolicy)
    query = query.where(RemediationPolicy.organization_id == org_id)

    policy_type = policy_type or policy_type_alias
    if policy_type:
        query = query.where(RemediationPolicy.policy_type == policy_type)
    if trigger_type:
        query = query.where(RemediationPolicy.trigger_type == trigger_type)
    if enabled is not None:
        query = query.where(RemediationPolicy.is_enabled.is_(enabled))
    elif enabled_only:
        query = query.where(RemediationPolicy.is_enabled.is_(True))

    query = query.order_by(desc(RemediationPolicy.priority)).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/policies/builtin")
async def list_builtin_policies(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """The starter policies ``register_builtin_policies`` installs (disabled,
    approval required). Same list the Celery task uses."""
    from src.remediation.tasks import BUILTIN_POLICY_SPECS

    return {"builtin_policies": [dict(spec) for spec in BUILTIN_POLICY_SPECS]}


@router.get("/policies/{policy_id}", response_model=RemediationPolicyResponse)
async def get_policy(
    policy_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get a specific policy with execution history."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return policy


@router.put("/policies/{policy_id}", response_model=RemediationPolicyResponse, dependencies=_ADMIN_WRITE)
async def update_policy(
    policy_id: str,
    request: RemediationPolicyUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update a policy."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    update_data = request.model_dump(exclude_unset=True)
    if update_data.get("actions") is not None:
        update_data["actions"] = _validated_actions(update_data["actions"])
    for key, value in update_data.items():
        setattr(policy, key, value)
    policy.updated_at = utc_now()

    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=_ADMIN_WRITE)
async def delete_policy(
    policy_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Disable a policy (soft delete)."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    policy.is_enabled = False
    policy.updated_at = utc_now()
    await db.commit()


@router.post("/policies/{policy_id}/test", dependencies=_ANALYST_WRITE)
async def test_policy(
    policy_id: str,
    trigger_data: dict,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Test a policy against sample data."""
    policy = await db.get(RemediationPolicy, policy_id)
    if not policy or policy.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    engine = RemediationEngine(db)
    matched = await engine.evaluate_trigger(
        policy.trigger_type,
        trigger_data,
        org_id,
    )

    return {
        "policy_id": policy_id,
        "matches": policy_id in [p.id for p in matched],
        "matched_policies": len(matched),
    }


# ============================================================================
# Actions
# ============================================================================

@router.get("/actions", response_model=List[RemediationActionSpecResponse])
async def list_actions(
    org_id: OrganizationId,
    action_type: Optional[str] = Query(None, description="A registry key or alias"),
    current_user: CurrentUser = None,
):
    """The action registry: every key a policy, playbook step or manual
    remediation may use, with its parameters, approval and reversibility."""
    if action_type:
        spec = resolve_action(action_type)
        return [spec.to_dict()] if spec else []
    return registry_actions()


@router.post("/actions", response_model=RemediationActionResponse, status_code=status.HTTP_201_CREATED, dependencies=_ADMIN_WRITE)
async def create_action(
    request: RemediationActionCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        organization_id=org_id,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/actions/{action_id}", response_model=RemediationActionResponse)
async def get_action(
    action_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get a specific action."""
    action = await db.get(RemediationAction, action_id)
    if not action or action.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return action


@router.post("/actions/{action_id}/test", dependencies=_ANALYST_WRITE)
async def test_action(
    action_id: str,
    target: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Test an action: not implemented (it used to report success without doing anything)."""
    action = await db.get(RemediationAction, action_id)
    if not action or action.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": "remediation actions cannot be dry-run yet; nothing was executed",
        },
    )


# ============================================================================
# Executions
# ============================================================================

@router.get("/executions", response_model=List[RemediationExecutionResponse])
async def list_executions(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    status: Optional[str] = Query(None),
    trigger_source: Optional[str] = Query(None),
    trigger: Optional[str] = Query(None, description="Alias of trigger_source"),
    days: int = Query(default=7, ge=1, le=90),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    current_user: CurrentUser = None,
):
    """List remediation executions created in the last ``days`` days."""
    trigger_source = trigger_source or trigger
    query = select(RemediationExecution)
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
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get pending approvals for current organization."""
    query = select(RemediationExecution).where(
        RemediationExecution.approval_status == "pending",
    )
    query = query.where(RemediationExecution.organization_id == org_id)
    query = query.order_by(desc(RemediationExecution.created_at))
    result = await db.execute(query)
    pending = result.scalars().all()

    return {
        "count": len(pending),
        "executions": [RemediationExecutionResponse.model_validate(e) for e in pending],
    }


@router.get("/quick-actions", response_model=List[RemediationExecutionResponse])
async def list_quick_actions(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """List recent quick actions (block IP, isolate host, etc.)."""
    query = select(RemediationExecution).where(
        # Quick actions are written with trigger_source="manual_quick_action".
        RemediationExecution.trigger_source.in_(["manual", "quick_action", "manual_quick_action"])
    ).order_by(desc(RemediationExecution.created_at)).limit(20)
    query = query.where(RemediationExecution.organization_id == org_id)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/executions/{execution_id}", response_model=RemediationExecutionResponse)
async def get_execution(
    execution_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get execution detail with action results."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return execution


@router.get("/executions/{execution_id}/progress", response_model=ExecutionProgressResponse)
async def get_execution_progress(
    execution_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get real-time execution progress."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
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


def _require_separate_approver(execution: RemediationExecution, current_user: CurrentUser) -> None:
    """Separation of duties: whoever started an execution cannot approve or reject it."""
    if execution.created_by and str(execution.created_by) == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "separation_of_duties",
                "detail": "the user who initiated this execution cannot approve or reject it",
            },
        )


@router.post("/executions/{execution_id}/approve", response_model=ApprovalResponse, dependencies=_ADMIN_WRITE)
async def approve_execution(
    execution_id: str,
    _request: ApprovalRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Approve a pending remediation execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if execution.approval_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Execution not in pending approval state"
        )
    _require_separate_approver(execution, current_user)

    # The approver is the authenticated caller, never a client-supplied id
    # (the page used to send approver_id: "" against an FK to users.id).
    # The planned actions run now through the action registry (containment
    # service / agent queue); each records its own honest status.
    engine = RemediationEngine(db)
    run = await engine.approve_execution(execution_id, str(current_user.id))
    await db.refresh(execution)

    return ApprovalResponse(
        execution_id=execution_id,
        approval_status=execution.approval_status or "approved",
        approved_at=execution.approved_at,
        status=execution.status,
        overall_result=execution.overall_result,
        error_message=execution.error_message,
        action_results=[ExecutionActionResult.model_validate(r) for r in (run or {}).get("results", [])],
    )


@router.post("/executions/{execution_id}/reject", dependencies=_ADMIN_WRITE)
async def reject_execution(
    execution_id: str,
    request: RejectionRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Reject a pending remediation execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if execution.approval_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Execution not in pending approval state"
        )
    _require_separate_approver(execution, current_user)

    engine = RemediationEngine(db)
    await engine.reject_execution(execution_id, str(current_user.id), request.reason)

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

_MANUAL_LIFECYCLE_ALLOWED = ("awaiting_manual", "awaiting_integration", "detection_only", "manual_required", "queued")
_MANUAL_LIFECYCLE_FORBIDDEN = (
    "completed", "failed", "approved", "rejected", "awaiting_approval"
)


class _MarkCompleteBody(PydanticBaseModel):
    notes: Optional[str] = None


class _MarkFailedBody(PydanticBaseModel):
    reason: str


@router.post("/executions/{execution_id}/mark-complete", dependencies=_ANALYST_WRITE)
async def mark_execution_complete(
    execution_id: str,
    org_id: OrganizationId,
    body: _MarkCompleteBody = Body(...),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Operator confirms an awaiting_manual / awaiting_integration
    execution actually got done out of band. Transitions to completed."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
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


@router.post("/executions/{execution_id}/mark-failed", dependencies=_ANALYST_WRITE)
async def mark_execution_failed(
    execution_id: str,
    org_id: OrganizationId,
    body: _MarkFailedBody = Body(...),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Operator confirms an awaiting_manual / awaiting_integration
    execution won't happen. Transitions to failed with reason."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
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


#: Legacy engine action types with a real inverse in
#: ``RemediationEngine._rollback_single_action`` (rows written before the
#: action registry recorded revert handles).
_LEGACY_REVERSIBLE = frozenset({
    "firewall_block", "dns_sinkhole", "host_isolate", "account_disable", "account_lock",
    "password_reset", "session_terminate", "token_revoke", "file_quarantine", "patch_deploy",
})


def _step_rollback_possible(step: dict) -> bool:
    if is_containment_step(step):
        return step_is_reversible(step)
    return bool(step.get("success")) and step.get("action_type") in _LEGACY_REVERSIBLE


@router.post("/executions/{execution_id}/rollback", dependencies=_ADMIN_WRITE)
async def rollback_execution(
    execution_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Reverse an execution's actions.

    Only actions that actuated and recorded a revert handle (or a legacy
    engine action with a real inverse) are reversed. When none qualifies the
    route answers 409 ``not_reversible`` and nothing is attempted.
    """
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if execution.status == "rolled_back":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "already_rolled_back", "detail": "this execution was already rolled back"},
        )

    steps = [s for s in (execution.actions_completed or []) if isinstance(s, dict)]
    reversible = [s for s in steps if _step_rollback_possible(s)]
    if not reversible:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "not_reversible",
                "detail": "no action of this execution actuated with a stored revert handle; nothing was changed",
                "actions": [
                    {
                        "action_type": s.get("action_type"),
                        "status": s.get("status") or s.get("result"),
                        "reversible": bool(s.get("reversible")),
                    }
                    for s in steps
                ],
            },
        )

    engine = RemediationEngine(db)
    result = await engine.rollback_execution(execution_id, actor=str(current_user.id))

    return {
        "execution_id": execution_id,
        "rollback_status": result.get("rollback_status"),
        "details": result,
    }


@router.post("/executions/{execution_id}/cancel", dependencies=_ANALYST_WRITE)
async def cancel_execution(
    execution_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Cancel a running execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    execution.status = "cancelled"
    execution.updated_at = utc_now()
    await db.commit()

    return {"execution_id": execution_id, "status": "cancelled"}


# ============================================================================
# Manual Remediation
# ============================================================================

@router.post("/execute", dependencies=_ADMIN_WRITE)
async def execute_manual_remediation(
    request: ManualRemediationRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Run one registry action against a target without a policy.

    ``action_type`` must be a registry key (``GET /remediation/actions``),
    else 400 ``unknown_action``. With ``requires_approval`` the execution
    waits for a second admin (``/executions/{id}/approve``); otherwise it
    runs now and the response carries the per-action result.
    """
    spec = resolve_action(request.action_type)
    if spec is None:
        _validated_actions([{"type": request.action_type}])
    if not (request.target_entity or "").strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_target", "detail": "target_entity is required"},
        )
    engine = RemediationEngine(db)
    execution = await engine.execute_manual(
        action_type=spec.key,
        target_entity=request.target_entity.strip(),
        target_type=request.target_type or spec.target_type,
        parameters=request.parameters or {},
        requires_approval=request.requires_approval,
        initiated_by=str(current_user.id),
        organization_id=org_id,
    )
    await db.refresh(execution)
    return {
        "execution_id": execution.id,
        "action_type": spec.key,
        "target": execution.target_entity,
        "status": execution.status,
        "approval_status": execution.approval_status,
        "overall_result": execution.overall_result,
        "error_message": execution.error_message,
        "action_results": [
            ExecutionActionResult.model_validate(r).model_dump(mode="json")
            for r in (execution.actions_completed or [])
        ],
    }


# ============================================================================
# Quick Actions
# ============================================================================
#
# Each quick action creates a RemediationExecution row and runs ONE registry
# action through ``src.remediation.actions.run_action``, the same path
# policies, approvals, manual remediations and remediation playbooks use:
#
#   * containment goes through ``src.services.containment`` (endpoint agent
#     command queue, or an executable integration such as CrowdStrike), which
#     writes the AuditLog row;
#   * the response carries the service's honest status: ``executed``,
#     ``queued_for_approval`` (the agent command waits in
#     /agents/commands/{id}/approve), ``detection_only`` or
#     ``awaiting_integration`` (nothing actuated; ``missing_dependency`` says
#     what is missing), or ``failed``;
#   * reversible results store a revert handle so
#     ``/executions/{id}/rollback`` can undo exactly what was issued.


async def _run_quick_action(
    db,
    *,
    current_user,
    org_id: str,
    action_key: str,
    target: str,
    target_type: str,
    parameters: dict,
    trigger_details: dict,
    reason: str,
) -> tuple[RemediationExecution, dict]:
    """Create the execution row, run the action, and record the honest outcome."""
    execution = RemediationExecution(
        policy_id=None,
        trigger_source="manual_quick_action",
        trigger_details=trigger_details,
        status="running",
        started_at=utc_now(),
        target_entity=target,
        target_type=target_type,
        actions_planned=[{"type": action_key, "parameters": parameters}],
        actions_completed=[],
        created_by=str(current_user.id),
        organization_id=org_id,
        metrics={},
    )
    db.add(execution)
    await db.flush()

    step = await run_action(
        db, org_id, action_key, target, parameters,
        actor=str(current_user.id), reason=reason, execution_ref=execution.id,
        trigger_data=trigger_details,
    )
    run_status, overall, error_message = summarize_steps([step])
    execution.actions_completed = [step]
    execution.status = run_status
    execution.overall_result = overall
    execution.error_message = error_message or (step.get("error") if not step.get("success") else None)
    execution.current_action_index = 1
    details = step.get("details") or {}
    execution.metrics = {
        "dispatch_method": step.get("status"),
        "containment_status": step.get("status"),
        "agent_command_id": details.get("command_id"),
        "integration": details.get("integration"),
        "missing_dependency": step.get("missing_dependency"),
        "audit_log_id": step.get("audit_log_id"),
        "reason": step.get("detail"),
    }
    if run_status in ("completed", "failed"):
        execution.completed_at = utc_now()
    await db.flush()
    return execution, step


def _quick_response(execution: RemediationExecution, step: dict, *, action: str, target: str, **extra: Any) -> dict:
    """Quick-action response: the historic keys plus the containment outcome."""
    details = step.get("details") or {}
    return {
        "execution_id": execution.id,
        "action": action,
        "target": target,
        "status": execution.status,
        "dispatch_method": step.get("status"),
        "integration_id": extra.pop("integration_id", None),
        "agent_command_id": details.get("command_id"),
        "error_message": execution.error_message,
        "containment_status": step.get("status"),
        "detail": step.get("detail"),
        "missing_dependency": step.get("missing_dependency"),
        "reversible": bool(step.get("reversible")),
        "audit_log_id": step.get("audit_log_id"),
        "result": ExecutionActionResult.model_validate(step).model_dump(mode="json"),
        **extra,
    }


async def _integration_id_for(db, org_id: str, connector_name: Optional[str]) -> Optional[str]:
    if not connector_name:
        return None
    from src.integrations.models import InstalledIntegration, IntegrationConnector

    row = (await db.execute(
        select(InstalledIntegration.id)
        .join(IntegrationConnector, IntegrationConnector.id == InstalledIntegration.connector_id)
        .where(
            InstalledIntegration.organization_id == org_id,
            func.lower(IntegrationConnector.name) == connector_name.lower(),
        ),
    )).scalars().first()
    return row


@router.post("/block-ip", dependencies=_ADMIN_WRITE)
async def quick_block_ip(
    request: QuickBlockIPRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Quick action: block an IP on every IR-enrolled endpoint agent.

    Also registers the IP as an active detection IOC for ``duration_hours``
    (the agent firewall rules stay until the execution is rolled back; a
    rollback deactivates the IOC too).
    """
    import ipaddress

    ip = (request.ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_ip", "detail": f"{ip!r} is not an IP address"},
        ) from exc

    from src.intel.models import ThreatIndicator

    now = utc_now()
    ioc = ThreatIndicator(
        indicator_type="ip",
        value=ip,
        severity="high",
        confidence=95,
        source="remediation_quick_action",
        tags=["auto_block", f"ttl_hours_{request.duration_hours}"],
        is_active=True,
        first_seen=now,
        last_seen=now,
        expires_at=now + timedelta(hours=request.duration_hours),
        organization_id=org_id,
    )
    db.add(ioc)
    await db.flush()

    execution, step = await _run_quick_action(
        db, current_user=current_user, org_id=org_id, action_key="firewall_block", target=ip,
        target_type="ip", parameters={},
        trigger_details={
            "ip": ip, "duration_hours": request.duration_hours, "ioc_id": ioc.id,
            "reason": request.reason or "quick action",
        },
        reason=request.reason or "quick action: block IP",
    )
    # The IOC is part of what a rollback reverses.
    step = {**step, "ioc_id": ioc.id}
    execution.actions_completed = [step]
    await db.flush()
    return _quick_response(
        execution, step, action="block_ip", target=ip,
        duration_hours=request.duration_hours, ioc_id=ioc.id,
    )


@router.post("/isolate-host", dependencies=_ADMIN_WRITE)
async def quick_isolate_host(
    request: QuickIsolateHostRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Quick action: isolate a host via its endpoint agent, else CrowdStrike Falcon."""
    hostname = (request.hostname or "").strip()
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_target", "detail": "hostname is required"},
        )
    execution, step = await _run_quick_action(
        db, current_user=current_user, org_id=org_id, action_key="host_isolate", target=hostname,
        target_type="host", parameters={},
        trigger_details={"hostname": hostname, "reason": request.reason},
        reason=request.reason or "quick action: isolate host",
    )
    integration_id = await _integration_id_for(db, org_id, (step.get("details") or {}).get("integration"))
    return _quick_response(execution, step, action="isolate_host", target=hostname, integration_id=integration_id)


@router.post("/disable-account", dependencies=_ADMIN_WRITE)
async def quick_disable_account(
    request: QuickDisableAccountRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Quick action: disable a local account through the agent on ``hostname``.

    Directory accounts need an identity-provider connector PySOAR does not
    implement: the result is ``awaiting_integration`` (one is installed) or
    ``detection_only``. Not reversible.
    """
    username = (request.username or "").strip()
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_target", "detail": "username is required"},
        )
    hostname = (request.hostname or "").strip() or None
    execution, step = await _run_quick_action(
        db, current_user=current_user, org_id=org_id, action_key="account_disable", target=username,
        target_type="user", parameters={"hostname": hostname} if hostname else {},
        trigger_details={"username": username, "hostname": hostname, "reason": request.reason},
        reason=request.reason or "quick action: disable account",
    )
    return _quick_response(execution, step, action="disable_account", target=username, hostname=hostname)


@router.post("/quarantine-file", dependencies=_ADMIN_WRITE)
async def quick_quarantine_file(
    request: QuickQuarantineFileRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Quick action: quarantine a file on a named host through its endpoint agent."""
    hostname = (request.hostname or "").strip()
    file_path = (request.file_path or "").strip()
    if not hostname or not file_path:
        # Never route a quarantine to an arbitrary agent.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="hostname and file_path are required",
        )
    execution, step = await _run_quick_action(
        db, current_user=current_user, org_id=org_id, action_key="file_quarantine", target=hostname,
        target_type="host", parameters={"file_path": file_path},
        trigger_details={"file_path": file_path, "hostname": hostname, "reason": request.reason},
        reason=request.reason or "quick action: quarantine file",
    )
    details = step.get("details") or {}
    return _quick_response(
        execution, step, action="quarantine_file", target=file_path, hostname=hostname,
        agent_available=bool(details.get("agent_id")),
    )


# ============================================================================
# Playbooks
# ============================================================================

@router.get("/playbooks", response_model=List[RemediationPlaybookResponse])
async def list_playbooks(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    playbook_type: Optional[str] = Query(None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    current_user: CurrentUser = None,
):
    """List remediation playbooks."""
    query = select(RemediationPlaybook).where(
        RemediationPlaybook.organization_id == org_id
    )

    if playbook_type:
        query = query.where(RemediationPlaybook.playbook_type == playbook_type)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/playbooks", response_model=RemediationPlaybookResponse, status_code=status.HTTP_201_CREATED, dependencies=_ADMIN_WRITE)
async def create_playbook(
    request: RemediationPlaybookCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        created_by=str(current_user.id),
        organization_id=org_id,
    )
    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.get("/playbooks/{playbook_id}", response_model=RemediationPlaybookResponse)
async def get_playbook(
    playbook_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get a specific playbook."""
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return playbook


@router.put("/playbooks/{playbook_id}", response_model=RemediationPlaybookResponse, dependencies=_ADMIN_WRITE)
async def update_playbook(
    playbook_id: str,
    request: RemediationPlaybookCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update a playbook."""
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    playbook.name = request.name
    playbook.description = request.description
    playbook.steps = [s.model_dump() for s in request.steps]
    playbook.is_enabled = request.is_enabled
    playbook.updated_at = utc_now()

    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.post("/playbooks/{playbook_id}/execute", dependencies=_ADMIN_WRITE)
async def execute_playbook(
    playbook_id: str,
    trigger_data: dict,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Run a remediation playbook's steps against a target.

    Each step's action key (``action_type`` / ``type`` / ``action_id``) must
    be a registry key; the steps run in order through the same runner as
    policies and quick actions (``RemediationEngine._run_actions``), and the
    execution row records every step's honest status. A failed step fails
    the run; steps that could not act never count as success.
    """
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != org_id:
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
        or "",
    ).strip()
    if not target_entity:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_target", "detail": "trigger_data.target_entity is required"},
        )

    planned: list[dict] = []
    for step in playbook.steps or []:
        params = {}
        if isinstance(step, dict):
            params = step.get("parameters") or step.get("params") or step.get("action_config") or {}
        planned.append({
            "type": step_key(step) or "",
            "parameters": params if isinstance(params, dict) else {},
            "on_failure": (step.get("on_failure") if isinstance(step, dict) else None) or "continue",
        })
    if not planned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "empty_playbook", "detail": "playbook has no steps"},
        )

    # The admin running the playbook is the authorisation; high-blast agent
    # commands still wait in the agent approval queue (no override).
    execution = RemediationExecution(
        policy_id=None,
        trigger_source=str(trigger_data.get("trigger_source") or "manual"),
        trigger_id=trigger_data.get("trigger_id"),
        trigger_details={"playbook_id": playbook_id, **(trigger_data or {})},
        status="approved",
        approval_status="auto_approved",
        approved_at=utc_now(),
        target_entity=target_entity,
        target_type=str(trigger_data.get("target_type") or "host"),
        actions_planned=planned,
        actions_completed=[],
        current_action_index=0,
        metrics={"playbook_id": playbook_id},
        created_by=str(current_user.id),
        organization_id=org_id,
    )
    db.add(execution)
    await db.commit()

    engine = RemediationEngine(db)
    run = await engine._run_actions(execution.id)
    await db.refresh(execution)
    results = run.get("results", [])

    if execution.overall_result == "success":
        playbook.success_count = (playbook.success_count or 0) + 1
    elif execution.overall_result in ("failure", "partial_success"):
        playbook.failure_count = (playbook.failure_count or 0) + 1
    playbook.last_executed_at = utc_now()
    await db.commit()
    await db.refresh(execution)

    succeeded = [r for r in results if r.get("success")]
    awaiting = [
        r for r in results
        if not r.get("success") and r.get("status") in ("awaiting_integration", "detection_only", "manual_required")
    ]
    failed = [r for r in results if r not in succeeded and r not in awaiting]
    return {
        "playbook_id": playbook_id,
        "execution_id": execution.id,
        "status": execution.status,
        "overall_result": execution.overall_result,
        "actions_completed": len(succeeded),
        "actions_failed": len(failed),
        "actions_awaiting_integration": len(awaiting),
        "error": execution.error_message or (
            execution.status if execution.status in ("awaiting_integration", "detection_only", "manual_required") else None
        ),
        "action_results": [ExecutionActionResult.model_validate(r).model_dump(mode="json") for r in results],
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
    }


# ============================================================================
# Integrations
# ============================================================================
#
# The Remediation page shows the organisation's InstalledIntegration rows
# (the table /integrations/install writes and the containment service
# dispatches through), with their real ids. The legacy
# remediation_integrations table is no longer read or written here.

#: containment action -> registry key (for the per-integration action lists).
_CONTAINMENT_TO_REGISTRY = {
    "block_ip": "firewall_block",
    "isolate_host": "host_isolate",
    "quarantine_file": "file_quarantine",
    "disable_user": "account_disable",
}


def _integration_action_lists(connector_name: str, category: str) -> tuple[list[str], list[str]]:
    """(registry keys this connector executes, keys its category could serve but has no implementation for)."""
    from src.services import containment

    executable = getattr(containment, "_EXECUTABLE_CONNECTORS", {}) or {}
    categories = getattr(containment, "_CATEGORY_FOR_ACTION", {}) or {}
    can: list[str] = []
    awaiting: list[str] = []
    for action, key in _CONTAINMENT_TO_REGISTRY.items():
        if connector_name in executable.get(action, ()):
            can.append(key)
        elif category in categories.get(action, ()):
            awaiting.append(key)
    return can, awaiting


def _parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime) or value is None:
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _integration_response(integ) -> RemediationIntegrationResponse:
    """InstalledIntegration -> page shape. Credentials are never returned."""
    connector = integ.connector
    connector_name = ((connector.name if connector is not None else None) or integ.connector_id or "").lower()
    category = str(getattr(connector, "category", "") or "").lower()
    try:
        config = json.loads(integ.config_encrypted or "{}")
    except (TypeError, ValueError):
        config = {}
    if not isinstance(config, dict):
        config = {}
    try:
        supported = json.loads(getattr(connector, "supported_actions", None) or "[]")
    except (TypeError, ValueError):
        supported = []
    can, awaiting = _integration_action_lists(connector_name, category)
    return RemediationIntegrationResponse(
        id=integ.id,
        name=integ.display_name,
        display_name=integ.display_name,
        connector_id=integ.connector_id,
        connector_name=connector_name,
        integration_type=category,
        category=category,
        vendor=getattr(connector, "vendor", None),
        endpoint_url=config.get("base_url") or config.get("url") or config.get("host"),
        auth_type=str(getattr(connector, "auth_type", "") or ""),
        auth_config={},
        capabilities=[str(a) for a in supported] if isinstance(supported, list) else [],
        remediation_actions=can,
        awaiting_actions=awaiting,
        status=integ.status,
        is_connected=integ.health_status == "healthy",
        last_health_check=_parse_ts(integ.last_health_check),
        health_status=integ.health_status or "",
        error_message=integ.error_message,
        created_at=integ.created_at,
        updated_at=integ.updated_at,
        organization_id=integ.organization_id,
    )


async def _installed_integration_or_404(db, integration_id: str, org_id: str):
    from src.integrations.models import InstalledIntegration

    integ = (await db.execute(
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(InstalledIntegration.id == integration_id, InstalledIntegration.organization_id == org_id),
    )).scalar_one_or_none()
    if integ is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return integ


@router.get("/integrations", response_model=List[RemediationIntegrationResponse])
async def list_integrations(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    integration_type: Optional[str] = Query(None, description="Connector category, e.g. edr, firewall"),
    remediation_only: bool = Query(default=False, description="Only connectors that can serve a remediation action"),
    current_user: CurrentUser = None,
):
    """The organisation's installed integrations with their real ids."""
    from src.integrations.models import InstalledIntegration

    rows = (await db.execute(
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(InstalledIntegration.organization_id == org_id)
        .order_by(InstalledIntegration.created_at.desc()),
    )).scalars().all()
    items = [_integration_response(r) for r in rows]
    if integration_type:
        items = [i for i in items if i.category == integration_type.lower()]
    if remediation_only:
        items = [i for i in items if i.remediation_actions or i.awaiting_actions]
    return items


@router.post("/integrations", response_model=RemediationIntegrationResponse, status_code=status.HTTP_201_CREATED, dependencies=_ADMIN_WRITE)
async def create_integration(
    request: RemediationIntegrationCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Install a connector for this organisation (same row /integrations/install writes).

    The installation starts in the connector's ``configuring`` status, like
    /integrations/install; enable it with /integrations/installed/{id}/enable.
    """
    from src.core.secrets import _encrypt_secret_json
    from src.integrations.models import InstalledIntegration, IntegrationConnector

    connector = (await db.execute(
        select(IntegrationConnector).where(
            (IntegrationConnector.id == request.connector_id) | (IntegrationConnector.name == request.connector_id),
        ),
    )).scalars().first()
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "unknown_connector", "detail": f"connector {request.connector_id!r} is not in the catalogue"},
        )
    existing = (await db.execute(
        select(InstalledIntegration.id).where(
            InstalledIntegration.organization_id == org_id,
            InstalledIntegration.connector_id == connector.id,
        ),
    )).scalars().first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "already_installed", "detail": "Connector already installed", "integration_id": existing},
        )

    config = dict(request.config or {})
    if request.endpoint_url and not config.get("base_url"):
        config["base_url"] = request.endpoint_url
    credentials = dict(request.credentials or request.auth_config or {})
    integ = InstalledIntegration(
        organization_id=org_id,
        connector_id=connector.id,
        display_name=request.display_name or request.name or connector.display_name,
        config_encrypted=json.dumps(config),
        auth_credentials_encrypted=_encrypt_secret_json(credentials),
    )
    db.add(integ)
    await db.flush()
    db.add(AuditLog(
        user_id=str(current_user.id),
        organization_id=org_id,
        action="remediation.integration.install",
        resource_type="installed_integration",
        resource_id=integ.id,
        description=f"Installed connector {connector.name} as {integ.display_name}",
        new_value=json.dumps({"connector": connector.name, "config_keys": sorted(config)}),
        success=True,
    ))
    await db.commit()
    return _integration_response(await _installed_integration_or_404(db, integ.id, org_id))


@router.put("/integrations/{integration_id}", response_model=RemediationIntegrationResponse, dependencies=_ADMIN_WRITE)
async def update_integration(
    integration_id: str,
    request: RemediationIntegrationUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update an installed integration's name, config or credentials."""
    from src.core.secrets import _encrypt_secret_json

    integ = await _installed_integration_or_404(db, integration_id, org_id)
    name = request.display_name or request.name
    if name:
        integ.display_name = name
    if request.config is not None or request.endpoint_url:
        try:
            config = json.loads(integ.config_encrypted or "{}")
        except (TypeError, ValueError):
            config = {}
        if request.config is not None:
            config = dict(request.config)
        if request.endpoint_url:
            config["base_url"] = request.endpoint_url
        integ.config_encrypted = json.dumps(config)
    credentials = request.credentials if request.credentials is not None else request.auth_config
    if credentials:
        integ.auth_credentials_encrypted = _encrypt_secret_json(credentials)
    db.add(AuditLog(
        user_id=str(current_user.id),
        organization_id=org_id,
        action="remediation.integration.update",
        resource_type="installed_integration",
        resource_id=integ.id,
        description=f"Updated integration {integ.display_name}",
        new_value=json.dumps({"name_changed": bool(name), "config_changed": request.config is not None,
                              "credentials_changed": bool(credentials)}),
        success=True,
    ))
    await db.commit()
    return _integration_response(await _installed_integration_or_404(db, integration_id, org_id))


@router.post("/integrations/{integration_id}/test", response_model=IntegrationTestResult, dependencies=_ANALYST_WRITE)
async def test_integration(
    integration_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Probe the installed integration's API for real and store the verdict.

    Uses the integration engine's per-connector probe; a configured base URL
    must pass the engine's outbound-target guard first. Connectors without a
    probe report ``unknown`` (never ``healthy``).
    """
    from src.core.secrets import _decrypt_secret_json
    from src.integrations.engine import (
        ActionExecutor,
        ConnectorRegistry,
        IntegrationManager,
        OutboundTargetRefused,
    )

    integ = await _installed_integration_or_404(db, integration_id, org_id)
    connector_name = ((integ.connector.name if integ.connector is not None else None) or integ.connector_id or "").lower()
    try:
        config = json.loads(integ.config_encrypted or "{}")
    except (TypeError, ValueError):
        config = {}
    if not isinstance(config, dict):
        config = {}
    credentials = _decrypt_secret_json(integ.auth_credentials_encrypted) or {}

    base_url = config.get("base_url") or config.get("url")
    health: str
    message: Optional[str]
    try:
        if base_url:
            await ActionExecutor()._resolve_generic_target("/", config)
        health, message = await IntegrationManager(ConnectorRegistry())._probe_connector(
            connector_name, config, credentials,
        )
    except OutboundTargetRefused as exc:
        health, message = "unhealthy", f"outbound target refused: {exc}"

    now = utc_now()
    integ.health_status = health
    integ.last_health_check = now.isoformat()
    integ.error_message = message if health != "healthy" else None
    await db.commit()
    return IntegrationTestResult(
        integration_id=integ.id,
        success=health == "healthy",
        status=health,
        message=message or "connection healthy",
        details={"connector": connector_name, "base_url": base_url},
        tested_at=now,
    )


@router.get("/integrations/{integration_id}/health")
async def get_integration_health(
    integration_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """The stored verdict of the last connectivity probe."""
    integ = await _installed_integration_or_404(db, integration_id, org_id)
    return {
        "integration_id": integration_id,
        "is_connected": integ.health_status == "healthy",
        "health_status": integ.health_status,
        "last_health_check": integ.last_health_check,
        "error_message": integ.error_message,
        "status": integ.status,
    }


# ============================================================================
# Dashboard
# ============================================================================

@router.get("/dashboard", response_model=RemediationDashboardStats)
async def get_dashboard_stats(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    days: int = Query(default=7, ge=1, le=90),
    current_user: CurrentUser = None,
):
    """Get remediation dashboard statistics."""
    cutoff = utc_now() - timedelta(days=days)

    query = select(RemediationExecution).where(
        RemediationExecution.created_at >= cutoff,
    )
    query = query.where(RemediationExecution.organization_id == org_id)
    result = await db.execute(query)
    executions = result.scalars().all()

    total = len(executions)
    successful = sum(1 for e in executions if e.overall_result == "success")
    failed = sum(1 for e in executions if e.overall_result == "failure")

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
            outcome = str((a or {}).get("status") or (a or {}).get("result") or "").lower()
            if (a or {}).get("success") is True or outcome in ("success", "ioc_created", "executed", "queued_for_approval"):
                bucket["success"] += 1
            elif (a or {}).get("success") is False or outcome in ("failure", "failed", "error"):
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

    # Per-day series for the "Execution Timeline" chart (UTC dates, oldest first).
    day_buckets: dict[str, dict[str, int]] = {}
    for offset in range(days - 1, -1, -1):
        day = (utc_now() - timedelta(days=offset)).date().isoformat()
        day_buckets[day] = {"total": 0, "success": 0, "failure": 0}
    for e in executions:
        if not e.created_at:
            continue
        bucket = day_buckets.get(e.created_at.date().isoformat())
        if bucket is None:
            continue
        bucket["total"] += 1
        if e.overall_result == "success":
            bucket["success"] += 1
        elif e.overall_result == "failure":
            bucket["failure"] += 1
    execution_by_day = [{"date": d, **v} for d, v in day_buckets.items()]

    # Actions recorded today (UTC): every step result of executions created today.
    today = utc_now().date()
    actions_today = sum(
        len(e.actions_completed or [])
        for e in executions
        if e.created_at and e.created_at.date() == today
    )
    active_policies = (await db.execute(
        select(func.count()).select_from(RemediationPolicy).where(
            RemediationPolicy.organization_id == org_id,
            RemediationPolicy.is_enabled.is_(True),
        ),
    )).scalar() or 0
    newest = sorted(
        (e for e in executions if e.created_at), key=lambda e: e.created_at, reverse=True,
    )[:10]

    return RemediationDashboardStats(
        period_start=cutoff,
        period_end=utc_now(),
        organization_id=org_id,
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
        active_policies=active_policies,
        actions_today=actions_today,
        execution_by_day=execution_by_day,
        recent_executions=[RemediationExecutionResponse.model_validate(e) for e in newest],
    )


@router.get("/timeline", response_model=RemediationTimelineResponse)
async def get_remediation_timeline(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    days: int = Query(default=7, ge=1, le=90),
    current_user: CurrentUser = None,
):
    """Get recent remediation timeline."""
    cutoff = utc_now() - timedelta(days=days)

    query = select(RemediationExecution).where(
        RemediationExecution.created_at >= cutoff,
    ).order_by(desc(RemediationExecution.completed_at))
    query = query.where(RemediationExecution.organization_id == org_id)

    result = await db.execute(query)
    executions = result.scalars().all()

    from src.schemas.remediation import TimelineEvent

    policy_ids = {e.policy_id for e in executions if e.policy_id}
    policy_names: dict[str, str] = {}
    if policy_ids:
        rows = await db.execute(
            select(RemediationPolicy.id, RemediationPolicy.name).where(
                RemediationPolicy.id.in_(policy_ids),
                RemediationPolicy.organization_id == org_id,
            )
        )
        policy_names = {pid: name for pid, name in rows.all()}

    # Only finished executions have a completion time to place on the timeline.
    events = [
        TimelineEvent(
            execution_id=e.id,
            policy_name=policy_names.get(e.policy_id) if e.policy_id else None,
            target=e.target_entity or "",
            action_count=len(e.actions_planned or []),
            status=e.status or "",
            overall_result=e.overall_result,
            completed_at=e.completed_at,
        )
        for e in executions
        if e.completed_at is not None
    ]

    return RemediationTimelineResponse(
        organization_id=org_id,
        period=f"last_{days}_days",
        events=events,
        total_count=len(executions),
    )


@router.get("/effectiveness", response_model=EffectivenessMetrics)
async def get_effectiveness_metrics(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    days: int = Query(default=7, ge=1, le=90),
    current_user: CurrentUser = None,
):
    """Remediation effectiveness computed from this organisation's execution rows.

    An execution is *effective* when every action actuated (overall_result
    ``success``) and it was not rolled back; *ineffective* when it ended in
    ``failure`` or ``partial_success``. Executions still pending (approval,
    awaiting integration, detection only) are counted separately and not
    rated. ``rollbacks_recommended`` counts partial runs that left a
    reversible action in place. No post-remediation re-check is performed
    (``verification_method`` = ``execution_outcome``).
    """
    cutoff = utc_now() - timedelta(days=days)
    executions = (await db.execute(
        select(RemediationExecution).where(
            RemediationExecution.organization_id == org_id,
            RemediationExecution.created_at >= cutoff,
        ),
    )).scalars().all()

    rated = [e for e in executions if e.overall_result in ("success", "failure", "partial_success")]
    effective = [e for e in rated if e.overall_result == "success" and e.status != "rolled_back"]
    ineffective = [e for e in rated if e.overall_result in ("failure", "partial_success")]
    pending = [e for e in executions if e not in rated]
    durations = [
        (e.completed_at - e.created_at).total_seconds() / 60.0
        for e in effective
        if e.completed_at and e.created_at and e.completed_at >= e.created_at
    ]
    rollbacks_recommended = sum(
        1 for e in executions
        if e.overall_result == "partial_success"
        and e.status != "rolled_back"
        and not e.rollback_status
        and any(isinstance(s, dict) and _step_rollback_possible(s) for s in (e.actions_completed or []))
    )
    rollbacks_executed = sum(1 for e in executions if e.rollback_status in ("completed", "partial"))

    return EffectivenessMetrics(
        organization_id=org_id,
        period=f"last_{days}_days",
        total_executions=len(executions),
        pending_count=len(pending),
        executions_verified=len(rated),
        effective_count=len(effective),
        ineffective_count=len(ineffective),
        effectiveness_rate=round(len(effective) / len(rated) * 100, 2) if rated else 0.0,
        avg_time_to_effectiveness=round(sum(durations) / len(durations), 2) if durations else None,
        rollbacks_recommended=rollbacks_recommended,
        rollbacks_executed=rollbacks_executed,
    )
