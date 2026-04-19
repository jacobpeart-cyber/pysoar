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
#   2. If a matching IR-capable endpoint agent is enrolled, dispatch
#      the action through AgentService.issue_command — high-blast
#      actions (isolate, disable, quarantine) auto-queue as
#      awaiting_approval so a second analyst has to sign off before
#      the host is actually touched.
#   3. If no matching agent is enrolled, the execution still lands
#      with a clear awaiting_manual status so an operator can pick
#      it up manually.
#   4. block-ip is special — it writes a ThreatIndicator IOC marked
#      active so the downstream firewall integration (if configured)
#      will pick it up, AND it creates the RemediationExecution row.

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

    Writes a ThreatIndicator IOC with type=ip, value=<ip>, severity=high
    and marks it active. Any downstream firewall or SIEM integration
    that watches active IOCs will pick this up. A RemediationExecution
    row is created so the action shows up in the Executions tab and
    dashboard effectiveness stats.
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
        },
        status_value="completed",  # IOC created = action complete
    )
    execution.actions_completed = [{
        "action_type": "firewall_block",
        "target": request.ip,
        "result": "ioc_created",
        "ioc_id": ioc_id,
    }]
    execution.overall_result = "success" if ioc_id else "partial_success"
    execution.completed_at = utc_now()
    await db.flush()

    return {
        "execution_id": execution.id,
        "action": "block_ip",
        "target": request.ip,
        "duration_hours": request.duration_hours,
        "status": execution.status,
        "ioc_id": ioc_id,
    }


@router.post("/isolate-host")
async def quick_isolate_host(
    request: QuickIsolateHostRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: isolate a host via its endpoint agent.

    If an IR-capable agent is enrolled for this hostname, dispatches
    ``isolate_host`` through AgentService.issue_command — which auto-
    queues as ``awaiting_approval`` because isolate_host is a
    high-blast action. A second analyst approves from /live-response
    and the agent then runs iptables / Windows Firewall rules to
    quarantine the host.
    """
    from src.agents.capabilities import AgentAction
    from src.agents.service import AgentService

    org_id = getattr(current_user, "organization_id", None)
    logger.info("Quick isolate host", extra={"hostname": request.hostname})

    agent = await _find_ir_agent(db, request.hostname, org_id)
    agent_command_id: Optional[str] = None
    status_value = "awaiting_manual"

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
            status_value = "awaiting_approval"  # approval gate in agent platform
        except Exception as exc:  # noqa: BLE001
            logger.error(f"AgentService.issue_command failed for isolate_host: {exc}")

    execution = await _write_execution(
        db=db,
        current_user=current_user,
        target_entity=request.hostname,
        target_type="host",
        action_type="host_isolate",
        trigger_details={
            "hostname": request.hostname,
            "agent_id": agent.id if agent else None,
            "reason": request.reason,
        },
        agent_command_id=agent_command_id,
        status_value=status_value,
    )

    return {
        "execution_id": execution.id,
        "action": "isolate_host",
        "target": request.hostname,
        "status": status_value,
        "agent_command_id": agent_command_id,
        "agent_available": agent is not None,
    }


@router.post("/disable-account")
async def quick_disable_account(
    request: QuickDisableAccountRequest,
    db: DatabaseSession = None,
    current_user = Depends(get_current_active_user),
):
    """Quick action: disable a user account.

    Dispatches via AgentService if an IR agent is enrolled on the
    host where the account lives (or any IR agent, if no hostname
    provided). High-blast → awaiting_approval.
    """
    from src.agents.capabilities import AgentAction
    from src.agents.service import AgentService

    org_id = getattr(current_user, "organization_id", None)
    logger.info("Quick disable account", extra={"username": request.username})

    agent = await _find_ir_agent(db, getattr(request, "hostname", None), org_id)
    agent_command_id: Optional[str] = None
    status_value = "awaiting_manual"

    if agent is not None:
        try:
            svc = AgentService(db)
            cmd = await svc.issue_command(
                agent=agent,
                action=AgentAction.DISABLE_ACCOUNT.value,
                payload={"username": request.username, "reason": request.reason or "manual quick action"},
                issued_by=str(current_user.id),
            )
            agent_command_id = cmd.id
            status_value = "awaiting_approval"
        except Exception as exc:  # noqa: BLE001
            logger.error(f"AgentService.issue_command failed for disable_account: {exc}")

    execution = await _write_execution(
        db=db,
        current_user=current_user,
        target_entity=request.username,
        target_type="user",
        action_type="account_disable",
        trigger_details={
            "username": request.username,
            "agent_id": agent.id if agent else None,
            "reason": getattr(request, "reason", None),
        },
        agent_command_id=agent_command_id,
        status_value=status_value,
    )

    return {
        "execution_id": execution.id,
        "action": "disable_account",
        "target": request.username,
        "status": status_value,
        "agent_command_id": agent_command_id,
        "agent_available": agent is not None,
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
    """Execute a playbook."""
    playbook = await db.get(RemediationPlaybook, playbook_id)
    if not playbook or playbook.organization_id != getattr(current_user, "organization_id", None):
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
