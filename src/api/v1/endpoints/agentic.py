"""API endpoints for Agentic AI SOC Analyst"""

import json
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Path, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession
from src.core.utils import safe_json_loads
from src.models.alert import Alert
from src.models.incident import Incident

logger = logging.getLogger(__name__)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List SOC agents with filtering and pagination"""
    query = select(SOCAgent).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Get specific agent details"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    return SOCAgentResponse.model_validate(agent)


@router.post("/agents", response_model=SOCAgentResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    agent_data: SOCAgentCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create new SOC agent"""
    agent = SOCAgent(
        organization_id=getattr(current_user, "organization_id", None),
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
    agent_data: SOCAgentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Update agent configuration"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Start agent operation"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    agent.status = "idle"
    await db.commit()

    return {"status": "started", "agent_id": agent_id}


@router.post("/agents/{agent_id}/stop")
async def stop_agent(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Stop agent operation"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    agent.status = "paused"
    await db.commit()

    return {"status": "stopped", "agent_id": agent_id}


@router.get("/agents/{agent_id}/performance", response_model=SOCAgentPerformance)
async def get_agent_performance(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Get agent performance metrics"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[int] = None,
):
    """List investigations with filtering and pagination"""
    query = select(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get investigation details"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    # Parse JSON fields
    inv_data = InvestigationResponse.model_validate(investigation)

    if investigation.reasoning_chain:
        try:
            inv_data.reasoning_chain = safe_json_loads(investigation.reasoning_chain, {})
        except:
            pass

    if investigation.evidence_collected:
        try:
            inv_data.evidence_collected = safe_json_loads(investigation.evidence_collected, {})
        except:
            pass

    if investigation.actions_taken:
        try:
            inv_data.actions_taken = safe_json_loads(investigation.actions_taken, {})
        except:
            pass

    if investigation.recommendations:
        try:
            inv_data.recommendations = safe_json_loads(investigation.recommendations, {})
        except:
            pass

    return inv_data


@router.post("/investigations", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def start_investigation(
    inv_data: InvestigationCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Start manual investigation"""
    # Verify agent exists
    agent = await db.get(SOCAgent, inv_data.agent_id)
    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    investigation = Investigation(
        organization_id=getattr(current_user, "organization_id", None),
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
        organization_id=getattr(current_user, "organization_id", None),
        trigger_type=inv_data.trigger_type,
        trigger_source_id=inv_data.trigger_source_id,
        title=inv_data.title,
        initial_context=inv_data.initial_context,
    )

    await db.refresh(investigation)
    return InvestigationResponse.model_validate(investigation)


@router.put("/investigations/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    inv_data: InvestigationUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Update investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get detailed reasoning chain for investigation"""
    result = await db.execute(
        select(Investigation)
        .options(selectinload(Investigation.reasoning_steps))
        .where(Investigation.id == investigation_id)
    )
    investigation = result.scalar_one_or_none()

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
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
            "observation": safe_json_loads(step.observation, {}) if step.observation else None,
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get timeline view of investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
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
    feedback: InvestigationFeedback,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Submit feedback on investigation quality"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List actions pending approval"""
    org_id = getattr(current_user, "organization_id", None)
    filters = [AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value]
    if org_id:
        filters.append(AgentAction.organization_id == org_id)
    query = select(AgentAction).where(*filters)

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
        if not inv:
            continue
        if org_id and getattr(inv, "organization_id", None) and inv.organization_id != org_id:
            continue
        agent = await db.get(SOCAgent, inv.agent_id) if inv.agent_id else None
        items.append(ActionPendingApproval(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            investigation_id=action.investigation_id,
            investigation_title=inv.title,
            agent_id=agent.id if agent else "",
            agent_name=agent.name if agent else "Unknown",
            confidence_score=inv.confidence_score or 0,
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
    approval: AgentActionApproval,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    action_id: str = Path(...),
):
    """Approve action execution"""
    action = await db.get(AgentAction, action_id)

    if not action or action.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    action_id: str = Path(...),
):
    """Rollback executed action"""
    action = await db.get(AgentAction, action_id)

    if not action or action.organization_id != getattr(current_user, "organization_id", None):
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


@router.get("/tools")
async def list_agent_tools(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    category: Optional[str] = None,
):
    """List all tools the AI agent can invoke."""
    from src.services.agent_tools import AgentToolRegistry
    registry = AgentToolRegistry(db)
    return {"tools": registry.list_tools(category=category), "total": len(registry.tools)}


@router.post("/tools/{tool_name}/execute")
async def execute_agent_tool(
    tool_name: str,
    params: dict,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Execute an agent tool directly."""
    from src.services.agent_tools import AgentToolRegistry
    registry = AgentToolRegistry(db)
    result = await registry.execute(tool_name, params)
    await db.commit()
    return result


@router.post("/chat", response_model=NaturalLanguageResponse)
async def chat_with_agent(
    query_data: NaturalLanguageQuery,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Autonomous SOC agent chat with real function calling.

    The agent loop:
      1. Send user query + tool declarations to Gemini
      2. If Gemini returns a tool_call, execute the tool against real DB
      3. Feed tool result back to Gemini
      4. Repeat up to MAX_STEPS times
      5. Return final grounded answer + log of all tools invoked
    """
    from src.ai.engine import AIAnalyzer
    from src.services.agent_tools import AgentToolRegistry

    org_id = getattr(current_user, "organization_id", None)
    tool_registry = AgentToolRegistry(db)
    tool_declarations = tool_registry.gemini_function_declarations()
    analyzer = AIAnalyzer()

    system_prompt = (
        "You are an autonomous SOC agent for PySOAR. You have direct access to the security platform "
        "via function tools. When the user asks for information, CALL the appropriate query tool. "
        "When the user asks you to take an action (block, create, assign, execute), CALL the action tool. "
        "Do not just suggest tools - actually call them. After calling tools, summarize the results for the user "
        "in 2-4 sentences. If the user is authorizing you to act on a previous recommendation, execute the action now."
    )

    tool_log: list[dict] = []
    final_text: str = ""
    MAX_STEPS = 4

    # Initial query
    current_prompt = query_data.query
    for step in range(MAX_STEPS):
        llm_result = analyzer.call_llm_with_tools(
            system_prompt=system_prompt,
            user_prompt=current_prompt,
            tools=tool_declarations,
        )

        if llm_result.get("type") == "error":
            # Gemini failed - fall back to heuristic tool execution
            logger.warning(f"Gemini tool call failed: {llm_result.get('error')}")
            try:
                stats_res = await tool_registry.execute("platform_stats", {})
                final_text = (
                    f"AI service temporarily unavailable. Current platform state: "
                    f"{stats_res.get('result', {})}"
                )
            except Exception:
                final_text = f"AI unavailable: {llm_result.get('error', 'unknown')[:200]}"
            break

        if llm_result.get("type") == "text":
            final_text = llm_result.get("text", "")
            break

        if llm_result.get("type") == "tool_call":
            tool_name = llm_result.get("name", "")
            tool_args = llm_result.get("args", {}) or {}

            logger.info(f"Agent step {step+1}: calling tool {tool_name} with {tool_args}")

            exec_result = await tool_registry.execute(tool_name, tool_args)
            tool_log.append({
                "step": step + 1,
                "tool": tool_name,
                "args": tool_args,
                "result": exec_result,
            })

            # Feed the result back to Gemini for a natural-language answer
            followup = analyzer.call_llm_followup(
                system_prompt=system_prompt,
                user_prompt=current_prompt,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_result=exec_result,
            )
            final_text = followup

            # Check if Gemini wants another tool call by feeding the followup back through
            # For simplicity, stop after one tool execution unless the final_text is empty
            if final_text and final_text.strip():
                break

            # If we got empty followup, try another round with context
            current_prompt = (
                f"Original question: {query_data.query}\n\n"
                f"Tool {tool_name} returned: {json.dumps(exec_result, default=str)[:800]}\n\n"
                f"Summarize this for the user or call another tool if needed."
            )

    if not final_text:
        # Absolute fallback - build from tool log
        if tool_log:
            final_text = f"Executed {len(tool_log)} tools. Latest result: {json.dumps(tool_log[-1].get('result', {}), default=str)[:400]}"
        else:
            final_text = "I couldn't determine how to answer that. Please rephrase your question."

    # Commit any DB changes made by action tools
    try:
        await db.commit()
    except Exception as e:
        logger.error(f"Failed to commit agent tool changes: {e}")

    return NaturalLanguageResponse(
        response=final_text,
        agent_id=query_data.agent_id or "auto",
        agent_name="SOC Agent",
        interpretation={"tools_invoked": tool_log},
    )


@router.get("/alerts/{alert_id}/explain", response_model=AlertExplanation)
async def explain_alert(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    alert_id: str = Path(...),
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    investigation_id: str = Path(...),
):
    """Get natural language explanation of investigation"""
    investigation = await db.get(Investigation, investigation_id)

    if not investigation or investigation.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get SOC dashboard metrics"""
    # Count agents
    agent_query = select(func.count()).select_from(SOCAgent).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None)
    )
    agent_result = await db.execute(agent_query)
    total_agents = agent_result.scalar() or 0

    # Count investigations
    inv_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None)
    )
    inv_result = await db.execute(inv_query)
    total_investigations = inv_result.scalar() or 0

    # Count by status
    in_progress_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None),
        Investigation.status == InvestigationStatus.REASONING.value,
    )
    in_progress_result = await db.execute(in_progress_query)
    investigations_in_progress = in_progress_result.scalar() or 0

    # Count pending approvals
    approval_query = select(func.count()).select_from(AgentAction).where(
        AgentAction.organization_id == getattr(current_user, "organization_id", None),
        AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value,
    )
    approval_result = await db.execute(approval_query)
    pending_approvals = approval_result.scalar() or 0

    # Count active agents (status != 'paused')
    active_agent_query = select(func.count()).select_from(SOCAgent).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.status != "paused",
    )
    active_agent_result = await db.execute(active_agent_query)
    agents_active = active_agent_result.scalar() or 0

    # Investigations completed in last 24h
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    completed_24h_query = select(func.count()).select_from(Investigation).where(
        Investigation.organization_id == getattr(current_user, "organization_id", None),
        Investigation.status == InvestigationStatus.COMPLETED.value,
        Investigation.updated_at >= cutoff_24h.isoformat(),
    )
    completed_24h_result = await db.execute(completed_24h_query)
    investigations_completed_24h = completed_24h_result.scalar() or 0

    # Average resolution time from agent stats
    avg_time_query = select(func.avg(SOCAgent.avg_resolution_time_minutes)).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.total_investigations > 0,
    )
    avg_time_result = await db.execute(avg_time_query)
    avg_investigation_time = avg_time_result.scalar() or 0.0

    # Overall accuracy from agent stats
    accuracy_query = select(func.avg(SOCAgent.accuracy_score)).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.total_investigations > 0,
    )
    accuracy_result = await db.execute(accuracy_query)
    overall_accuracy = accuracy_result.scalar() or 0.0

    # Overall false positive rate from agent stats
    fpr_query = select(func.avg(SOCAgent.false_positive_rate)).where(
        SOCAgent.organization_id == getattr(current_user, "organization_id", None),
        SOCAgent.total_investigations > 0,
    )
    fpr_result = await db.execute(fpr_query)
    overall_fpr = fpr_result.scalar() or 0.0

    return DashboardMetrics(
        total_agents=total_agents,
        agents_active=agents_active,
        total_investigations=total_investigations,
        investigations_in_progress=investigations_in_progress,
        investigations_completed_24h=investigations_completed_24h,
        avg_investigation_time_minutes=round(float(avg_investigation_time), 1),
        overall_accuracy=round(float(overall_accuracy), 1),
        overall_false_positive_rate=round(float(overall_fpr), 1),
        pending_approvals=pending_approvals,
    )


@router.get("/dashboard/investigation-metrics", response_model=InvestigationMetrics)
async def get_investigation_metrics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get investigation statistics from real database data"""
    org_id = getattr(current_user, "organization_id", None)
    base_filter = Investigation.organization_id == org_id

    # Total investigations
    total_result = await db.execute(
        select(func.count()).select_from(Investigation).where(base_filter)
    )
    total = total_result.scalar() or 0

    # Count by status
    status_result = await db.execute(
        select(Investigation.status, func.count())
        .where(base_filter)
        .group_by(Investigation.status)
    )
    by_status = {row[0]: row[1] for row in status_result.all()}

    # Count by resolution type
    resolution_result = await db.execute(
        select(Investigation.resolution_type, func.count())
        .where(base_filter, Investigation.resolution_type.isnot(None))
        .group_by(Investigation.resolution_type)
    )
    by_resolution = {row[0]: row[1] for row in resolution_result.all()}

    # Count by priority
    priority_result = await db.execute(
        select(Investigation.priority, func.count())
        .where(base_filter)
        .group_by(Investigation.priority)
    )
    by_priority = {row[0]: row[1] for row in priority_result.all()}

    # Average confidence score
    avg_conf_result = await db.execute(
        select(func.avg(Investigation.confidence_score)).where(
            base_filter, Investigation.confidence_score.isnot(None)
        )
    )
    avg_confidence = avg_conf_result.scalar() or 0.0

    # Average resolution time from agents
    avg_time_result = await db.execute(
        select(func.avg(SOCAgent.avg_resolution_time_minutes)).where(
            SOCAgent.organization_id == org_id,
            SOCAgent.total_investigations > 0,
        )
    )
    avg_resolution_time = avg_time_result.scalar() or 0.0

    return InvestigationMetrics(
        total=total,
        by_status=by_status,
        by_resolution=by_resolution,
        by_priority=by_priority,
        avg_confidence_score=round(float(avg_confidence), 1),
        avg_resolution_time_minutes=round(float(avg_resolution_time), 1),
    )


@router.get("/dashboard/accuracy-stats", response_model=AccuracyStats)
async def get_accuracy_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get accuracy and false positive statistics from real database data"""
    org_id = getattr(current_user, "organization_id", None)
    base_filter = Investigation.organization_id == org_id

    # Total investigations
    total_result = await db.execute(
        select(func.count()).select_from(Investigation).where(base_filter)
    )
    total = total_result.scalar() or 0

    # Count by resolution type
    resolution_result = await db.execute(
        select(Investigation.resolution_type, func.count())
        .where(base_filter, Investigation.resolution_type.isnot(None))
        .group_by(Investigation.resolution_type)
    )
    resolution_counts = {row[0]: row[1] for row in resolution_result.all()}

    true_positives = resolution_counts.get("true_positive", 0)
    false_positives = resolution_counts.get("false_positive", 0)
    inconclusive = resolution_counts.get("inconclusive", 0)
    escalated = resolution_counts.get("escalated", 0)

    # Calculate rates
    resolved_total = true_positives + false_positives + inconclusive + escalated
    accuracy_score = (
        round((true_positives / resolved_total) * 100, 1) if resolved_total > 0 else 0.0
    )
    false_positive_rate = (
        round((false_positives / resolved_total) * 100, 1) if resolved_total > 0 else 0.0
    )

    return AccuracyStats(
        total_investigations=total,
        true_positives=true_positives,
        false_positives=false_positives,
        inconclusive=inconclusive,
        escalated=escalated,
        accuracy_score=accuracy_score,
        false_positive_rate=false_positive_rate,
    )


# ============================================================================
# Threat Hunting Endpoints
# ============================================================================


@router.post("/threat-hunts", response_model=ThreatHuntResult)
async def start_threat_hunt(
    hunt_request: ThreatHuntRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Start threat hunt with specified profile"""
    # Select agent if not specified
    agent_id = hunt_request.agent_id

    if not agent_id:
        query = select(SOCAgent).where(
            SOCAgent.organization_id == getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    memory_type: Optional[str] = None,
):
    """List agent memory entries"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
):
    """Get agent memory statistics"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    agent_id: str = Path(...),
    memory_type: Optional[str] = None,
):
    """Clear agent memory (optional filter by type)"""
    agent = await db.get(SOCAgent, agent_id)

    if not agent or agent.organization_id != getattr(current_user, "organization_id", None):
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
