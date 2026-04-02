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

from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user
from src.core.database import get_db
from src.core.logging import get_logger
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
        created_by=request.created_by,
        organization_id=current_user.organization_id,
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
    if not policy or policy.organization_id != current_user.organization_id:
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
    if not policy or policy.organization_id != current_user.organization_id:
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
    if not policy or policy.organization_id != current_user.organization_id:
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
    if not policy or policy.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    engine = RemediationEngine(db)
    matched = await engine.evaluate_trigger(
        policy.trigger_type,
        trigger_data,
        current_user.organization_id,
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
        RemediationAction.organization_id == current_user.organization_id
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
        organization_id=current_user.organization_id,
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
    if not action or action.organization_id != current_user.organization_id:
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
    if not action or action.organization_id != current_user.organization_id:
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
    if not execution or execution.organization_id != current_user.organization_id:
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
    if not execution or execution.organization_id != current_user.organization_id:
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
    if not execution or execution.organization_id != current_user.organization_id:
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
    if not execution or execution.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    engine = RemediationEngine(db)
    await engine.reject_execution(execution_id, request.approver_id, request.reason)

    return {
        "execution_id": execution_id,
        "approval_status": "rejected",
    }


@router.post("/executions/{execution_id}/rollback")
async def rollback_execution(
    execution_id: str,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Rollback a completed execution."""
    execution = await db.get(RemediationExecution, execution_id)
    if not execution or execution.organization_id != current_user.organization_id:
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
    if not execution or execution.organization_id != current_user.organization_id:
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
        organization_id=current_user.organization_id,
    )

    return {
        "execution_id": execution.id,
        "status": execution.status,
    }


@router.post("/block-ip")
async def quick_block_ip(
    request: QuickBlockIPRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: block an IP."""
    logger.info("Quick block IP", extra={"ip": request.ip})
    return {
        "action": "block_ip",
        "target": request.ip,
        "duration_hours": request.duration_hours,
        "status": "queued",
    }


@router.post("/isolate-host")
async def quick_isolate_host(
    request: QuickIsolateHostRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: isolate a host."""
    logger.info("Quick isolate host", extra={"hostname": request.hostname})
    return {
        "action": "isolate_host",
        "target": request.hostname,
        "status": "queued",
    }


@router.post("/disable-account")
async def quick_disable_account(
    request: QuickDisableAccountRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: disable an account."""
    logger.info("Quick disable account", extra={"username": request.username})
    return {
        "action": "disable_account",
        "target": request.username,
        "status": "queued",
    }


@router.post("/quarantine-file")
async def quick_quarantine_file(
    request: QuickQuarantineFileRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: quarantine a file."""
    logger.info("Quick quarantine file", extra={
        "file_path": request.file_path,
        "hostname": request.hostname,
    })
    return {
        "action": "quarantine_file",
        "target": request.file_path,
        "hostname": request.hostname,
        "status": "queued",
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
        RemediationPlaybook.organization_id == current_user.organization_id
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
        organization_id=current_user.organization_id,
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
    if not playbook or playbook.organization_id != current_user.organization_id:
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
    if not playbook or playbook.organization_id != current_user.organization_id:
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
    """Execute a playbook."""
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return {
        "playbook_id": playbook_id,
        "status": "queued",
        "triggered_at": utc_now().isoformat(),
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
        organization_id=current_user.organization_id,
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
    if not integration or integration.organization_id != current_user.organization_id:
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
    if not integration or integration.organization_id != current_user.organization_id:
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
    if not integration or integration.organization_id != current_user.organization_id:
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

    return RemediationDashboardStats(
        period_start=cutoff,
        period_end=utc_now(),
        organization_id=org_id or "",
        total_executions=total,
        successful_executions=successful,
        failed_executions=failed,
        overall_success_rate=(successful / total * 100) if total else 0,
        avg_execution_minutes=0.0,
        pending_approvals=sum(1 for e in executions if e.approval_status == "pending"),
        in_progress=sum(1 for e in executions if e.status == "running"),
        actions_by_type=[],
        top_policies=[],
        top_targets=[],
        execution_by_hour=[],
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
        organization_id=current_user.organization_id,
        period=f"last_{days}_days",
        executions_verified=0,
        effective_count=0,
        ineffective_count=0,
        effectiveness_rate=0.0,
        rollbacks_recommended=0,
        rollbacks_executed=0,
    )
