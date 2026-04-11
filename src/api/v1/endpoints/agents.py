"""REST endpoints for the PySOAR Agent Platform.

Two audiences share this router:

1. **Operators** — authenticated via the normal JWT. They enroll agents,
   list them, dispatch commands, and approve high-blast actions.

2. **Agents themselves** — authenticated via their long-lived agent
   token (``Authorization: Bearer pst_...``). They exchange enrollment
   tokens, send heartbeats, poll for commands, and post results.

Agent-only endpoints all live under ``/agents/_agent/*`` so the router
can enforce agent-token auth without false-positive JWT checks. Every
request is tied to the reporting agent via the token, so a compromised
agent cannot read or write commands for a different host.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import desc, select

from src.agents.capabilities import AgentAction
from src.agents.models import AgentCommand, AgentResult, EndpointAgent
from src.agents.service import AgentService, AgentServiceError
from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger
from src.schemas.agents import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    AgentExchangeRequest,
    AgentExchangeResponse,
    AgentListResponse,
    AgentPollResponse,
    AgentSummary,
    ApprovalRequest,
    ChainVerificationResponse,
    CommandResultRequest,
    CommandSummary,
    HeartbeatRequest,
    IssueCommandRequest,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/agents", tags=["agents"])


# ---------------------------------------------------------------------------
# Agent-token auth dependency
# ---------------------------------------------------------------------------

async def _require_agent(
    session: DatabaseSession,
    authorization: Optional[str] = Header(default=None),
) -> EndpointAgent:
    """Authenticate an inbound call from an agent via bearer token."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent bearer token",
        )
    token = authorization.split(" ", 1)[1].strip()
    if not token.startswith("pst_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not an agent token",
        )
    svc = AgentService(session)
    agent = await svc.authenticate_agent(token)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown agent token",
        )
    if agent.status in ("disabled", "revoked"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent is {agent.status}",
        )
    return agent


# ===========================================================================
# OPERATOR ENDPOINTS  (JWT-authenticated)
# ===========================================================================

@router.post("/enroll", response_model=AgentEnrollResponse, status_code=201)
async def enroll_agent(
    request: AgentEnrollRequest,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> AgentEnrollResponse:
    """Create a new endpoint agent and return its one-time enrollment token.

    The token is shown exactly once. Ship it to the target host through
    whatever secure channel you use (Ansible secret, SSM param, etc.)
    and have the agent call ``/agents/_agent/exchange`` within 30
    minutes.
    """
    svc = AgentService(session)
    try:
        agent, enrollment_token = await svc.enroll(
            hostname=request.hostname,
            capabilities=request.capabilities,
            display_name=request.display_name,
            tags=request.tags,
            enrolled_by=str(current_user.id) if current_user else None,
            organization_id=getattr(current_user, "organization_id", None),
        )
    except AgentServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return AgentEnrollResponse(
        agent_id=agent.id,
        hostname=agent.hostname,
        capabilities=agent.capabilities,
        status=agent.status,
        enrollment_token=enrollment_token,
        enrollment_expires_at=agent.enrollment_expires_at,
    )


@router.get("/dashboard")
async def agents_dashboard(
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> dict:
    """Stats feed for the AgentManagement UI tile row.

    Returns aggregate counts and a recent-activity window. Scoped to
    the caller's organization. Lazy-refreshes stale-offline flips on
    every call so the numbers stay fresh without a separate cron.
    """
    from sqlalchemy import func as _func

    try:
        await AgentService(session).mark_stale_agents_offline()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"mark_stale_agents_offline failed: {e}")

    org_id = getattr(current_user, "organization_id", None)

    def _scope(q):
        if org_id is None:
            return q
        return q.where(EndpointAgent.organization_id == org_id)

    def _scope_cmd(q):
        if org_id is None:
            return q
        return q.where(AgentCommand.organization_id == org_id)

    total = (await session.execute(_scope(select(_func.count(EndpointAgent.id))))).scalar() or 0
    active = (await session.execute(
        _scope(select(_func.count(EndpointAgent.id))).where(EndpointAgent.status == "active")
    )).scalar() or 0
    offline = (await session.execute(
        _scope(select(_func.count(EndpointAgent.id))).where(EndpointAgent.status == "offline")
    )).scalar() or 0
    pending_enroll = (await session.execute(
        _scope(select(_func.count(EndpointAgent.id))).where(EndpointAgent.status == "pending")
    )).scalar() or 0

    # Commands in flight
    in_flight_statuses = ("queued", "dispatched", "running")
    in_flight = (await session.execute(
        _scope_cmd(select(_func.count(AgentCommand.id))).where(
            AgentCommand.status.in_(in_flight_statuses)
        )
    )).scalar() or 0
    awaiting = (await session.execute(
        _scope_cmd(select(_func.count(AgentCommand.id))).where(
            AgentCommand.status == "awaiting_approval"
        )
    )).scalar() or 0

    # Capability breakdown (in-Python count since JSON array filtering
    # is dialect-specific)
    all_agents = list(
        (await session.execute(_scope(select(EndpointAgent)))).scalars().all()
    )
    cap_counts: dict[str, int] = {"bas": 0, "ir": 0, "purple": 0}
    for a in all_agents:
        for c in a.capabilities or []:
            if c in cap_counts:
                cap_counts[c] += 1

    # Recent commands (last 20)
    recent_stmt = _scope_cmd(select(AgentCommand)).order_by(
        desc(AgentCommand.created_at)
    ).limit(20)
    recent_cmds = list((await session.execute(recent_stmt)).scalars().all())

    return {
        "total_agents": total,
        "active_agents": active,
        "offline_agents": offline,
        "pending_enroll": pending_enroll,
        "capability_counts": cap_counts,
        "commands_in_flight": in_flight,
        "commands_awaiting_approval": awaiting,
        "recent_commands": [
            {
                "id": c.id,
                "action": c.action,
                "status": c.status,
                "agent_id": c.agent_id,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "completed_at": c.completed_at.isoformat() if c.completed_at else None,
                "incident_id": c.incident_id,
                "simulation_id": c.simulation_id,
            }
            for c in recent_cmds
        ],
    }


@router.get("", response_model=AgentListResponse)
async def list_agents(
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    capability: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> AgentListResponse:
    # Refresh liveness before listing so the caller sees accurate status
    try:
        await AgentService(session).mark_stale_agents_offline()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"mark_stale_agents_offline failed: {e}")

    org_id = getattr(current_user, "organization_id", None)
    stmt = select(EndpointAgent)
    if org_id is not None:
        stmt = stmt.where(EndpointAgent.organization_id == org_id)
    if status_filter:
        stmt = stmt.where(EndpointAgent.status == status_filter)

    stmt = stmt.order_by(desc(EndpointAgent.created_at))
    rows = list((await session.execute(stmt.offset(offset).limit(limit))).scalars().all())

    if capability:
        rows = [r for r in rows if capability in (r.capabilities or [])]

    return AgentListResponse(
        total=len(rows),
        agents=[AgentSummary.model_validate(r) for r in rows],
    )


@router.get("/{agent_id}", response_model=AgentSummary)
async def get_agent(
    agent_id: str,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> AgentSummary:
    agent = (
        await session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))
    ).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentSummary.model_validate(agent)


@router.post("/{agent_id}/commands", response_model=CommandSummary, status_code=202)
async def issue_command(
    agent_id: str,
    request: IssueCommandRequest,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> CommandSummary:
    agent = (
        await session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))
    ).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    svc = AgentService(session)
    try:
        cmd = await svc.issue_command(
            agent=agent,
            action=request.action,
            payload=request.payload,
            issued_by=str(current_user.id),
            simulation_id=request.simulation_id,
            incident_id=request.incident_id,
        )
    except AgentServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return CommandSummary.model_validate(cmd)


@router.get("/{agent_id}/commands", response_model=list[CommandSummary])
async def list_commands(
    agent_id: str,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
    limit: int = Query(50, ge=1, le=500),
) -> list[CommandSummary]:
    stmt = (
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id)
        .order_by(desc(AgentCommand.created_at))
        .limit(limit)
    )
    rows = list((await session.execute(stmt)).scalars().all())
    return [CommandSummary.model_validate(r) for r in rows]


@router.get("/commands/pending-approval", response_model=list[CommandSummary])
async def pending_approval_queue(
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
    limit: int = Query(100, ge=1, le=500),
) -> list[CommandSummary]:
    """Approval queue for high-blast Live Response actions.

    Rendered in the UI as a single pane of "things a second analyst
    needs to sign off on before they hit an endpoint." Ordered oldest
    first so long-waiting approvals rise to the top. Scoped to the
    caller's organization so one tenant's approvers never see another
    tenant's pending commands.
    """
    org_id = getattr(current_user, "organization_id", None)
    stmt = select(AgentCommand).where(AgentCommand.status == "awaiting_approval")
    if org_id is not None:
        stmt = stmt.where(AgentCommand.organization_id == org_id)
    stmt = stmt.order_by(AgentCommand.created_at.asc()).limit(limit)
    rows = list((await session.execute(stmt)).scalars().all())
    return [CommandSummary.model_validate(r) for r in rows]


@router.post("/commands/{command_id}/approve", response_model=CommandSummary)
async def approve_command(
    command_id: str,
    request: ApprovalRequest,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> CommandSummary:
    cmd = (
        await session.execute(select(AgentCommand).where(AgentCommand.id == command_id))
    ).scalar_one_or_none()
    if cmd is None:
        raise HTTPException(status_code=404, detail="Command not found")

    svc = AgentService(session)
    try:
        cmd = await svc.approve_command(
            command=cmd,
            approver_id=str(current_user.id),
            reason=request.reason,
        )
    except AgentServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return CommandSummary.model_validate(cmd)


@router.post("/commands/{command_id}/reject", response_model=CommandSummary)
async def reject_command(
    command_id: str,
    request: ApprovalRequest,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> CommandSummary:
    """Deny a pending-approval high-blast command.

    Rejection is terminal — the rejected row stays in the audit chain
    so the rejection itself is a signed record. Rejecter must be a
    different user from the issuer."""
    cmd = (
        await session.execute(select(AgentCommand).where(AgentCommand.id == command_id))
    ).scalar_one_or_none()
    if cmd is None:
        raise HTTPException(status_code=404, detail="Command not found")
    if cmd.status != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Command status is {cmd.status}; cannot reject",
        )
    if cmd.issued_by and cmd.issued_by == str(current_user.id):
        raise HTTPException(
            status_code=400,
            detail="Rejecter cannot be the same user who issued the command",
        )
    cmd.status = "rejected"
    cmd.approved_by = str(current_user.id)  # audit: who performed the rejection
    from datetime import datetime, timezone
    cmd.approved_at = datetime.now(timezone.utc)
    cmd.approval_reason = f"REJECTED: {request.reason or ''}"
    await session.flush()
    await session.refresh(cmd)
    return CommandSummary.model_validate(cmd)


@router.get("/{agent_id}/verify-chain", response_model=ChainVerificationResponse)
async def verify_chain(
    agent_id: str,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> ChainVerificationResponse:
    agent = (
        await session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))
    ).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    svc = AgentService(session)
    result = await svc.verify_chain(agent)
    return ChainVerificationResponse(**result)


# ===========================================================================
# AGENT ENDPOINTS  (agent-token authenticated)
# ===========================================================================

@router.post("/_agent/exchange", response_model=AgentExchangeResponse)
async def exchange(
    request: AgentExchangeRequest,
    session: DatabaseSession = None,
) -> AgentExchangeResponse:
    """Called by a newly installed agent to trade its enrollment token
    for a long-lived agent token. No user auth; the enrollment token
    itself is the credential. One-shot — reuse returns 401."""
    svc = AgentService(session)
    try:
        agent, agent_token = await svc.exchange_enrollment_token(request.enrollment_token)
    except AgentServiceError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    # Apply host fingerprinting from the first check-in
    if request.os_type:
        agent.os_type = request.os_type
    if request.os_version:
        agent.os_version = request.os_version
    if request.agent_version:
        agent.agent_version = request.agent_version
    if request.ip_address:
        agent.ip_address = request.ip_address
    await session.flush()

    return AgentExchangeResponse(
        agent_id=agent.id,
        agent_token=agent_token,
        capabilities=agent.capabilities,
    )


@router.post("/_agent/heartbeat")
async def agent_heartbeat(
    request: HeartbeatRequest,
    agent: EndpointAgent = Depends(_require_agent),
    session: DatabaseSession = None,
) -> dict:
    if request.os_type:
        agent.os_type = request.os_type
    if request.os_version:
        agent.os_version = request.os_version
    if request.agent_version:
        agent.agent_version = request.agent_version
    if request.ip_address:
        agent.ip_address = request.ip_address

    svc = AgentService(session)
    await svc.record_heartbeat(agent, telemetry=request.telemetry)
    return {"status": "ok", "agent_id": agent.id, "capabilities": agent.capabilities}


@router.get("/_agent/poll", response_model=AgentPollResponse)
async def agent_poll(
    agent: EndpointAgent = Depends(_require_agent),
    session: DatabaseSession = None,
    limit: int = Query(10, ge=1, le=100),
) -> AgentPollResponse:
    svc = AgentService(session)
    await svc.record_heartbeat(agent)  # poll doubles as a heartbeat
    commands = await svc.fetch_pending_commands(agent, limit=limit)
    return AgentPollResponse(
        commands=[CommandSummary.model_validate(c) for c in commands]
    )


@router.post("/_agent/commands/{command_id}/result")
async def agent_post_result(
    command_id: str,
    request: CommandResultRequest,
    agent: EndpointAgent = Depends(_require_agent),
    session: DatabaseSession = None,
) -> dict:
    svc = AgentService(session)
    try:
        await svc.ingest_result(
            agent=agent,
            command_id=command_id,
            status=request.status,
            exit_code=request.exit_code,
            stdout=request.stdout,
            stderr=request.stderr,
            duration_seconds=request.duration_seconds,
            artifacts=request.artifacts,
        )
    except AgentServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "accepted", "command_id": command_id}
