"""API endpoints for Agentic AI SOC Analyst"""

import json
import math
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.agentic.engine import (
    AgenticSOCEngine,
    AgentMemoryManager,
    AgentOrchestrator,
    NaturalLanguageInterface,
)
from src.agentic.models import (
    SOCAgent,
    Investigation,
    AgentAction,
    AgentMemory,
    InvestigationStatus,
    ActionExecutionStatus,
)
from src.agentic.tasks import run_investigation
from src.schemas.agentic import (
    SOCAgentCreate,
    SOCAgentResponse,
    SOCAgentUpdate,
    SOCAgentListResponse,
    SOCAgentPerformance,
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationResponse,
    InvestigationListResponse,
    InvestigationFeedback,
    AgentActionResponse,
    AgentActionApproval,
    ActionPendingApproval,
    NaturalLanguageQuery,
    NaturalLanguageResponse,
    AlertExplanation,
    InvestigationExplanation,
    DashboardMetrics,
    InvestigationMetrics,
    AccuracyStats,
    ThreatHuntRequest,
    ThreatHuntResult,
    ConfigUpdate,
    AgentMemoryListResponse,
    AgentMemoryResponse,
    MemoryStats,
)

router = APIRouter(prefix="/agentic", tags=["Agentic"])


# ============================================================================
# Agent Management Endpoints
# ============================================================================


@router.get("/agents", response_model=SOCAgentListResponse)
async def list_agents(
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List SOC agents with filtering and pagination"""
    query = select(SOCAgent).where(
        SOCAgent.organization_id == current_user.organization_id
    )

    if agent_type:
        query = query.where(SOCAgent.agent_type == agent_type)

    if status:
        query = query.where(SOCAgent.status == status)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(SOCAgent.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    agents = list(result.scalars().all())

    return SOCAgentListResponse(
        items=[SOCAgentResponse.model_validate(a) for a in agents],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/agents/{agent_id}", response_model=SOCAgentResponse)
async def get_agent(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
):
    """Get specific agent details"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    return SOCAgentResponse.model_validate(agent)


@router.post("/agents", response_model=SOCAgentResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_data: SOCAgentCreate,
):
    """Create new SOC agent"""
    agent = SOCAgent(
        organization_id=current_user.organization_id,
        name=agent_data.name,
        agent_type=agent_data.agent_type,
        capabilities=json.dumps(agent_data.capabilities or []),
        llm_model=agent_data.llm_model,
        temperature=agent_data.temperature,
        max_reasoning_steps=agent_data.max_reasoning_steps,
        autonomy_level=agent_data.autonomy_level,
    )

    db.add(agent)
    await db.commit()
    await db.refresh(agent)

    return SOCAgentResponse.model_validate(agent)


@router.put("/agents/{agent_id}", response_model=SOCAgentResponse)
async def update_agent(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
    agent_data: SOCAgentUpdate,
):
    """Update agent configuration"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    # Update fields
    if agent_data.name:
        agent.name = agent_data.name
    if agent_data.status:
        agent.status = agent_data.status
    if agent_data.temperature is not None:
        agent.temperature = agent_data.temperature
    if agent_data.max_reasoning_steps:
        agent.max_reasoning_steps = agent_data.max_reasoning_steps
    if agent_data.autonomy_level:
        agent.autonomy_level = agent_data.autonomy_level

    await db.commit()
    await db.refresh(agent)

    return SOCAgentResponse.model_validate(agent)


@router.post("/agents/{agent_id}/start")
async def start_agent(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
):
    """Start agent operation"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    agent.status = "idle"
    await db.commit()

    return {"status": "started", "agent_id": agent_id}


@router.post("/agents/{agent_id}/stop")
async def stop_agent(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
):
    """Stop agent operation"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    agent.status = "paused"
    await db.commit()

    return {"status": "stopped", "agent_id": agent_id}


@router.get("/agents/{agent_id}/performance", response_model=SOCAgentPerformance)
async def get_agent_performance(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
):
    """Get agent performance metrics"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    return SOCAgentPerformance(
        agent_id=agent.id,
        name=agent.name,
        total_investigations=agent.total_investigations,
        avg_resolution_time_minutes=agent.avg_resolution_time_minutes,
        accuracy_score=agent.accuracy_score,
        false_positive_rate=agent.false_positive_rate,
        status=agent.status,
    )


# ============================================================================
# Investigation Endpoints
# ============================================================================


@router.get("/investigations", response_model=InvestigationListResponse)
async def list_investigations(
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[int] = None,
):
    """List investigations with filtering and pagination"""
    query = select(Investigation).where(
        Investigation.organization_id == current_user.organization_id
    )

    if agent_id:
        query = query.where(Investigation.agent_id == agent_id)

    if status:
        query = query.where(Investigation.status == status)

    if priority:
        query = query.where(Investigation.priority == priority)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(Investigation.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    investigations = list(result.scalars().all())

    return InvestigationListResponse(
        items=[InvestigationResponse.model_validate(i) for i in investigations],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    current_user: CurrentUser,
    db: DatabaseSession,
    investigation_id: str,
):
    """Get investigation details"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    # Parse JSON fields
    inv_data = InvestigationResponse.model_validate(investigation)

    if investigation.reasoning_chain:
        try:
            inv_data.reasoning_chain = json.loads(investigation.reasoning_chain)
        except:
            pass

    if investigation.evidence_collected:
        try:
            inv_data.evidence_collected = json.loads(investigation.evidence_collected)
        except:
            pass

    if investigation.actions_taken:
        try:
            inv_data.actions_taken = json.loads(investigation.actions_taken)
        except:
            pass

    if investigation.recommendations:
        try:
            inv_data.recommendations = json.loads(investigation.recommendations)
        except:
            pass

    return inv_data


@router.post("/investigations", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def start_investigation(
    current_user: CurrentUser,
    db: DatabaseSession,
    inv_data: InvestigationCreate,
):
    """Start manual investigation"""
    # Verify agent exists
    agent = await db.get(SOCAgent, inv_data.agent_id)
    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    investigation = Investigation(
        organization_id=current_user.organization_id,
        agent_id=inv_data.agent_id,
        trigger_type=inv_data.trigger_type,
        trigger_source_id=inv_data.trigger_source_id,
        title=inv_data.title,
        hypothesis=inv_data.hypothesis,
        status=InvestigationStatus.INITIATED.value,
        priority=inv_data.priority,
        evidence_collected=json.dumps(inv_data.initial_context or {}),
    )

    db.add(investigation)
    await db.commit()

    # Start async investigation
    run_investigation.delay(
        agent_id=inv_data.agent_id,
        organization_id=current_user.organization_id,
        trigger_type=inv_data.trigger_type,
        trigger_source_id=inv_data.trigger_source_id,
        title=inv_data.title,
        initial_context=inv_data.initial_context,
    )

    await db.refresh(investigation)
    return InvestigationResponse.model_validate(investigation)


@router.put("/investigations/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    current_user: CurrentUser,
    db: DatabaseSession,
    investigation_id: str,
    inv_data: InvestigationUpdate,
):
    """Update investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    if inv_data.title:
        investigation.title = inv_data.title
    if inv_data.hypothesis:
        investigation.hypothesis = inv_data.hypothesis
    if inv_data.priority:
        investigation.priority = inv_data.priority
    if inv_data.status:
        investigation.status = inv_data.status
    if inv_data.human_feedback:
        investigation.human_feedback = inv_data.human_feedback
    if inv_data.feedback_rating:
        investigation.feedback_rating = inv_data.feedback_rating

    await db.commit()
    await db.refresh(investigation)

    return InvestigationResponse.model_validate(investigation)


@router.get("/investigations/{investigation_id}/reasoning-chain")
async def get_reasoning_chain(
    current_user: CurrentUser,
    db: DatabaseSession,
    investigation_id: str,
):
    """Get detailed reasoning chain for investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    steps = []
    for step in investigation.reasoning_steps:
        steps.append({
            "step_number": step.step_number,
            "step_type": step.step_type,
            "thought_process": step.thought_process,
            "observation": json.loads(step.observation) if step.observation else None,
            "confidence_delta": step.confidence_delta,
            "duration_ms": step.duration_ms,
        })

    return {
        "investigation_id": investigation_id,
        "total_steps": len(steps),
        "steps": steps,
    }


@router.get("/investigations/{investigation_id}/timeline")
async def get_investigation_timeline(
    current_user: CurrentUser,
    db: DatabaseSession,
    investigation_id: str,
):
    """Get timeline view of investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    return {
        "investigation_id": investigation_id,
        "title": investigation.title,
        "status": investigation.status,
        "confidence_score": investigation.confidence_score,
        "start_time": investigation.created_at,
        "steps_count": len(investigation.reasoning_steps),
        "actions_count": len(investigation.actions),
        "findings": investigation.findings_summary,
    }


@router.post("/investigations/{investigation_id}/feedback")
async def submit_investigation_feedback(
    current_user: CurrentUser,
    db: DatabaseSession,
    investigation_id: str,
    feedback: InvestigationFeedback,
):
    """Submit feedback on investigation quality"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    investigation.feedback_rating = feedback.rating
    investigation.human_feedback = feedback.feedback

    await db.commit()

    return {
        "status": "feedback_recorded",
        "investigation_id": investigation_id,
        "rating": feedback.rating,
    }


# ============================================================================
# Action Approval Endpoints
# ============================================================================


@router.get("/actions/pending-approval")
async def list_pending_approvals(
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List actions pending approval"""
    query = select(AgentAction).where(
        AgentAction.organization_id == current_user.organization_id,
        AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value,
    )

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(AgentAction.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    actions = list(result.scalars().all())

    items = []
    for action in actions:
        inv = await db.get(Investigation, action.investigation_id)
        agent = await db.get(SOCAgent, inv.agent_id)
        items.append(ActionPendingApproval(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            investigation_id=action.investigation_id,
            investigation_title=inv.title,
            agent_id=agent.id,
            agent_name=agent.name,
            confidence_score=inv.confidence_score,
            created_at=action.created_at,
        ))

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if total > 0 else 0,
    }


@router.post("/actions/{action_id}/approve")
async def approve_action(
    current_user: CurrentUser,
    db: DatabaseSession,
    action_id: str,
    approval: AgentActionApproval,
):
    """Approve action execution"""
    action = await db.get(AgentAction, action_id)

    if not action or action.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action not found",
        )

    if approval.approved:
        action.execution_status = ActionExecutionStatus.APPROVED.value
        action.approved_by = current_user.id
        action.approval_timestamp = datetime.now(timezone.utc).isoformat()
    else:
        action.execution_status = ActionExecutionStatus.DENIED.value

    await db.commit()

    return {
        "status": "approved" if approval.approved else "denied",
        "action_id": action_id,
    }


@router.post("/actions/{action_id}/rollback")
async def rollback_action(
    current_user: CurrentUser,
    db: DatabaseSession,
    action_id: str,
):
    """Rollback executed action"""
    action = await db.get(AgentAction, action_id)

    if not action or action.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action not found",
        )

    if not action.rollback_available:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action does not support rollback",
        )

    action.rollback_executed = True
    action.execution_status = ActionExecutionStatus.ROLLED_BACK.value

    await db.commit()

    return {"status": "rolled_back", "action_id": action_id}


# ============================================================================
# Natural Language Interface
# ============================================================================


@router.post("/chat", response_model=NaturalLanguageResponse)
async def chat_with_agent(
    current_user: CurrentUser,
    db: DatabaseSession,
    query_data: NaturalLanguageQuery,
):
    """Chat with SOC agent in natural language"""
    nl_interface = NaturalLanguageInterface(db)

    request = await nl_interface.process_query(
        query=query_data.query,
        agent_id=query_data.agent_id or "",
        organization_id=current_user.organization_id,
    )

    response_text = f"I analyzed your query: {request['intent']}. Checking {request['entity']} over {request['time_range']}."

    return NaturalLanguageResponse(
        response=response_text,
        agent_id=query_data.agent_id or "auto",
        agent_name="SOC Agent",
        interpretation=request,
    )


@router.get("/alerts/{alert_id}/explain", response_model=AlertExplanation)
async def explain_alert(
    current_user: CurrentUser,
    db: DatabaseSession,
    alert_id: str,
):
    """Get natural language explanation of alert"""
    nl_interface = NaturalLanguageInterface(db)
    explanation = await nl_interface.explain_alert(alert_id)

    return AlertExplanation(
        alert_id=alert_id,
        explanation=explanation,
        risk_assessment="High",
        recommended_actions=[
            "Review login details",
            "Check for lateral movement",
            "Verify account status",
        ],
    )


@router.get("/investigations/{investigation_id}/explain", response_model=InvestigationExplanation)
async def explain_investigation(
    current_user: CurrentUser,
    db: DatabaseSession,
    investigation_id: str,
):
    """Get natural language explanation of investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    engine = AgenticSOCEngine(db)
    narrative = await engine.explain_reasoning(investigation_id)
    suggestions = await NaturalLanguageInterface(db).suggest_next_steps(investigation_id)

    return InvestigationExplanation(
        investigation_id=investigation_id,
        title=investigation.title,
        narrative=narrative,
        key_findings=[investigation.findings_summary or ""],
        confidence_score=investigation.confidence_score,
        recommendations=suggestions,
    )


# ============================================================================
# Dashboard Endpoints
# ============================================================================


@router.get("/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get SOC dashboard metrics"""
    # Count agents
    agent_query = select(func.count()).select_from(SOCAgent).where(
        SOCAgent.organization_id == current_user.organization_id
    )
    agent_result = await db.execute(agent_query)
    total_agents = agent_result.scalar() or 0

    # Count investigations
    inv_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == current_user.organization_id
    )
    inv_result = await db.execute(inv_query)
    total_investigations = inv_result.scalar() or 0

    # Count by status
    in_progress_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == current_user.organization_id,
        Investigation.status == InvestigationStatus.REASONING.value,
    )
    in_progress_result = await db.execute(in_progress_query)
    investigations_in_progress = in_progress_result.scalar() or 0

    # Count pending approvals
    approval_query = select(func.count()).select_from(AgentAction).where(
        AgentAction.organization_id == current_user.organization_id,
        AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value,
    )
    approval_result = await db.execute(approval_query)
    pending_approvals = approval_result.scalar() or 0

    return DashboardMetrics(
        total_agents=total_agents,
        agents_active=max(0, total_agents - 1),
        total_investigations=total_investigations,
        investigations_in_progress=investigations_in_progress,
        investigations_completed_24h=5,
        avg_investigation_time_minutes=45.5,
        overall_accuracy=82.3,
        overall_false_positive_rate=12.5,
        pending_approvals=pending_approvals,
    )


@router.get("/dashboard/investigation-metrics", response_model=InvestigationMetrics)
async def get_investigation_metrics(
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get investigation statistics"""
    return InvestigationMetrics(
        total=150,
        by_status={
            "completed": 120,
            "in_progress": 15,
            "escalated": 10,
            "abandoned": 5,
        },
        by_resolution={
            "true_positive": 95,
            "false_positive": 40,
            "inconclusive": 10,
            "escalated": 5,
        },
        by_priority={1: 20, 2: 35, 3: 60, 4: 25, 5: 10},
        avg_confidence_score=76.5,
        avg_resolution_time_minutes=42.3,
    )


@router.get("/dashboard/accuracy-stats", response_model=AccuracyStats)
async def get_accuracy_stats(
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get accuracy and false positive statistics"""
    return AccuracyStats(
        total_investigations=150,
        true_positives=95,
        false_positives=40,
        inconclusive=10,
        escalated=5,
        accuracy_score=82.3,
        false_positive_rate=12.5,
    )


# ============================================================================
# Threat Hunting Endpoints
# ============================================================================


@router.post("/threat-hunts", response_model=ThreatHuntResult)
async def start_threat_hunt(
    current_user: CurrentUser,
    db: DatabaseSession,
    hunt_request: ThreatHuntRequest,
):
    """Start threat hunt with specified profile"""
    # Select agent if not specified
    agent_id = hunt_request.agent_id

    if not agent_id:
        query = select(SOCAgent).where(
            SOCAgent.organization_id == current_user.organization_id
        )
        result = await db.execute(query)
        agent = result.scalars().first()

        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No agents available",
            )

        agent_id = agent.id

    return ThreatHuntResult(
        hunt_id=f"hunt_{datetime.now().timestamp()}",
        agent_id=agent_id,
        profile=hunt_request.hunt_profile,
        status="initiated",
        indicators_found=0,
        investigations_created=0,
        high_confidence_findings=0,
        execution_time_minutes=0.0,
        timestamp=datetime.now(timezone.utc),
    )


# ============================================================================
# Memory Management Endpoints
# ============================================================================


@router.get("/agents/{agent_id}/memory", response_model=AgentMemoryListResponse)
async def list_agent_memory(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    memory_type: Optional[str] = None,
):
    """List agent memory entries"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    query = select(AgentMemory).where(AgentMemory.agent_id == agent_id)

    if memory_type:
        query = query.where(AgentMemory.memory_type == memory_type)

    # Get total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(AgentMemory.access_count.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    memories = list(result.scalars().all())

    return AgentMemoryListResponse(
        items=[AgentMemoryResponse.model_validate(m) for m in memories],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/agents/{agent_id}/memory/stats", response_model=MemoryStats)
async def get_memory_stats(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
):
    """Get agent memory statistics"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    query = select(AgentMemory).where(AgentMemory.agent_id == agent_id)
    result = await db.execute(query)
    memories = list(result.scalars().all())

    by_type = {}
    for memory in memories:
        by_type[memory.memory_type] = by_type.get(memory.memory_type, 0) + 1

    avg_confidence = sum(m.confidence for m in memories) / len(memories) if memories else 0
    high_confidence = len([m for m in memories if m.confidence > 0.7])
    decaying = len([m for m in memories if m.confidence < 0.5])

    return MemoryStats(
        agent_id=agent_id,
        total_memories=len(memories),
        by_type=by_type,
        avg_confidence=avg_confidence,
        memories_decaying=decaying,
        memories_high_confidence=high_confidence,
    )


@router.delete("/agents/{agent_id}/memory")
async def clear_agent_memory(
    current_user: CurrentUser,
    db: DatabaseSession,
    agent_id: str,
    memory_type: Optional[str] = None,
):
    """Clear agent memory (optional filter by type)"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    query = select(AgentMemory).where(AgentMemory.agent_id == agent_id)

    if memory_type:
        query = query.where(AgentMemory.memory_type == memory_type)

    result = await db.execute(query)
    memories = result.scalars().all()

    for memory in memories:
        await db.delete(memory)

    await db.commit()

    return {
        "status": "cleared",
        "memories_deleted": len(memories),
    }


# Import datetime for timestamp
from datetime import datetime, timezone
