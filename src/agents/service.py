"""AgentService — enrollment, command dispatch, result ingestion.

This is the trust boundary for the agent platform. All capability
checks, allowlist enforcement, and hash-chain generation live here so
no other code path can bypass them.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.capabilities import (
    AgentAction,
    AgentCapability,
    capability_allows,
    command_hash,
    requires_approval,
)
from src.agents.models import (
    AgentCommand,
    AgentHeartbeat,
    AgentResult,
    EndpointAgent,
)
from src.core.logging import get_logger

logger = get_logger(__name__)


async def _broadcast(channel: str, message: dict[str, Any]) -> None:
    """Best-effort WebSocket publish — never blocks or raises.

    Used to push real-time agent-command events into the PySOAR
    frontend (the AgentManagement live table, the LiveResponse result
    stream, the PurpleTeam correlation view). Any failure is logged
    and swallowed so the HTTP path stays on the happy path.
    """
    try:
        from src.services.websocket_manager import manager as _ws_manager
        await _ws_manager.broadcast_channel(channel, message)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"ws broadcast {channel} failed: {exc}")


# Agents are considered offline if they haven't checked in for this long
HEARTBEAT_LIVENESS_SECONDS = 120


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AgentServiceError(Exception):
    """Raised for any rejected agent operation. The HTTP layer maps
    this to 400 so callers get the reason without leaking internals."""


class AgentService:
    def __init__(self, session: AsyncSession):
        self.session = session

    # ------------------------------------------------------------------
    # Enrollment
    # ------------------------------------------------------------------

    async def enroll(
        self,
        *,
        hostname: str,
        capabilities: list[str],
        display_name: Optional[str] = None,
        tags: Optional[list[str]] = None,
        enrolled_by: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> tuple[EndpointAgent, str]:
        """Create a new EndpointAgent row and issue a one-time enrollment token.

        Returns ``(agent, plaintext_enrollment_token)``. The plaintext
        token is shown to the operator exactly once; only its SHA-256
        hash is persisted. The agent exchanges it for a long-lived
        ``agent_token`` on first check-in.
        """
        # Normalize + validate capabilities
        valid_caps: list[str] = []
        for cap in capabilities:
            try:
                valid_caps.append(AgentCapability(cap).value)
            except ValueError:
                raise AgentServiceError(f"Unknown capability: {cap}")
        if not valid_caps:
            raise AgentServiceError("At least one capability is required")

        enrollment_token = f"pse_{secrets.token_urlsafe(32)}"
        agent = EndpointAgent(
            hostname=hostname,
            display_name=display_name,
            status="pending",
            capabilities=valid_caps,
            enrollment_token_hash=_sha256(enrollment_token),
            enrollment_expires_at=_utc_now() + timedelta(minutes=30),
            tags=tags or [],
            enrolled_by=enrolled_by,
            organization_id=organization_id,
        )
        self.session.add(agent)
        await self.session.flush()
        await self.session.refresh(agent)
        logger.info(
            f"Enrolled agent id={agent.id} host={hostname} caps={valid_caps}"
        )
        return agent, enrollment_token

    async def exchange_enrollment_token(
        self, enrollment_token: str
    ) -> tuple[EndpointAgent, str]:
        """Agent-side: trade one-time enrollment token for a long-lived agent token.

        Raises AgentServiceError if the token is unknown, already used,
        or expired.
        """
        token_hash = _sha256(enrollment_token)
        stmt = select(EndpointAgent).where(
            EndpointAgent.enrollment_token_hash == token_hash
        )
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()
        if agent is None:
            raise AgentServiceError("Invalid enrollment token")
        if agent.status != "pending":
            raise AgentServiceError("Enrollment token already used")
        if agent.enrollment_expires_at and agent.enrollment_expires_at < _utc_now():
            raise AgentServiceError("Enrollment token expired")

        agent_token = f"pst_{secrets.token_urlsafe(48)}"
        agent.token_hash = _sha256(agent_token)
        agent.enrollment_token_hash = None
        agent.enrollment_expires_at = None
        agent.status = "active"
        agent.last_heartbeat_at = _utc_now()
        await self.session.flush()
        await self.session.refresh(agent)
        logger.info(f"Agent id={agent.id} exchanged enrollment for long-lived token")
        return agent, agent_token

    async def authenticate_agent(self, agent_token: str) -> Optional[EndpointAgent]:
        """Look up an agent by its long-lived token hash."""
        token_hash = _sha256(agent_token)
        stmt = select(EndpointAgent).where(EndpointAgent.token_hash == token_hash)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # Heartbeat / liveness
    # ------------------------------------------------------------------

    async def record_heartbeat(
        self,
        agent: EndpointAgent,
        telemetry: Optional[dict[str, Any]] = None,
    ) -> None:
        agent.last_heartbeat_at = _utc_now()
        if agent.status in ("offline", "pending"):
            agent.status = "active"
        self.session.add(
            AgentHeartbeat(
                agent_id=agent.id,
                reported_at=agent.last_heartbeat_at,
                telemetry=telemetry or {},
            )
        )
        await self.session.flush()

    async def mark_stale_agents_offline(self) -> int:
        """Flip any agent whose heartbeat is older than the liveness window
        to ``offline``. Called by the health endpoint as a lazy GC."""
        cutoff = _utc_now() - timedelta(seconds=HEARTBEAT_LIVENESS_SECONDS)
        stmt = select(EndpointAgent).where(
            and_(
                EndpointAgent.status == "active",
                EndpointAgent.last_heartbeat_at.is_not(None),
                EndpointAgent.last_heartbeat_at < cutoff,
            )
        )
        result = await self.session.execute(stmt)
        stale = list(result.scalars().all())
        for a in stale:
            a.status = "offline"
        if stale:
            await self.session.flush()
        return len(stale)

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    async def issue_command(
        self,
        *,
        agent: EndpointAgent,
        action: str,
        payload: Optional[dict[str, Any]] = None,
        issued_by: Optional[str] = None,
        simulation_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        approval_override: bool = False,
    ) -> AgentCommand:
        """Enqueue a command for an agent.

        Enforces:
        1. Agent is not disabled/revoked.
        2. The action is in the agent's enrolled capability set.
        3. High-blast actions get queued as ``awaiting_approval`` unless
           the caller is explicitly overriding (e.g. automation playbook
           that already passed an approval gate).
        4. Command hash chains to the previous command for this agent
           so history is tamper-evident.
        """
        if agent.status in ("disabled", "revoked"):
            raise AgentServiceError(
                f"Agent {agent.id} is {agent.status}; commands are not dispatched"
            )

        if not capability_allows(agent.capabilities or [], action):
            raise AgentServiceError(
                f"Action '{action}' is not permitted for agent capabilities "
                f"{agent.capabilities}. Re-enroll with the required capability."
            )

        prev_hash = agent.last_command_hash
        c_hash = command_hash(action, payload)
        chain_input = (prev_hash or "GENESIS") + "|" + c_hash
        chain_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

        needs_approval = requires_approval(action) and not approval_override
        status = "awaiting_approval" if needs_approval else "queued"

        cmd = AgentCommand(
            agent_id=agent.id,
            action=action,
            payload=payload or {},
            command_hash=c_hash,
            prev_hash=prev_hash,
            chain_hash=chain_hash,
            status=status,
            approval_required=needs_approval,
            simulation_id=simulation_id,
            incident_id=incident_id,
            issued_by=issued_by,
            organization_id=agent.organization_id,
            expires_at=_utc_now() + timedelta(minutes=15),
        )
        self.session.add(cmd)

        # Only update the chain tip once the command is actually queued
        # for delivery. If it's pending approval, it hasn't happened yet
        # from the agent's perspective — but we still chain the hash so
        # the audit record is sealed even if approval is later denied.
        agent.last_command_hash = chain_hash
        await self.session.flush()
        await self.session.refresh(cmd)

        logger.info(
            f"Queued command id={cmd.id} action={action} agent={agent.id} "
            f"status={status}"
        )

        # Real-time broadcast so AgentManagement, LiveResponse, and
        # Purple Team views update without a poll.
        event = {
            "type": "agent_command_queued",
            "command_id": cmd.id,
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "action": action,
            "status": status,
            "approval_required": needs_approval,
            "simulation_id": simulation_id,
            "incident_id": incident_id,
        }
        await _broadcast("agents", event)
        if simulation_id:
            await _broadcast(f"purple:{simulation_id}", event)
        return cmd

    async def approve_command(
        self,
        *,
        command: AgentCommand,
        approver_id: str,
        reason: Optional[str] = None,
    ) -> AgentCommand:
        if command.status != "awaiting_approval":
            raise AgentServiceError(
                f"Command {command.id} is not awaiting approval (status={command.status})"
            )
        if command.issued_by and command.issued_by == approver_id:
            raise AgentServiceError(
                "Approver cannot be the same user who issued the command"
            )
        command.approved_by = approver_id
        command.approved_at = _utc_now()
        command.approval_reason = reason
        command.status = "queued"
        await self.session.flush()
        await self.session.refresh(command)
        return command

    async def fetch_pending_commands(
        self,
        agent: EndpointAgent,
        limit: int = 10,
    ) -> list[AgentCommand]:
        """Agent-side: pull the next batch of queued commands and mark them dispatched."""
        now = _utc_now()

        # Expire any stale queued rows first
        stmt = select(AgentCommand).where(
            and_(
                AgentCommand.agent_id == agent.id,
                AgentCommand.status == "queued",
                AgentCommand.expires_at.is_not(None),
                AgentCommand.expires_at < now,
            )
        )
        for stale in (await self.session.execute(stmt)).scalars().all():
            stale.status = "expired"

        stmt = (
            select(AgentCommand)
            .where(
                and_(
                    AgentCommand.agent_id == agent.id,
                    AgentCommand.status == "queued",
                )
            )
            .order_by(AgentCommand.created_at.asc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        commands = list(result.scalars().all())
        for c in commands:
            c.status = "dispatched"
            c.dispatched_at = now
        if commands:
            await self.session.flush()
            for c in commands:
                event = {
                    "type": "agent_command_dispatched",
                    "command_id": c.id,
                    "agent_id": agent.id,
                    "hostname": agent.hostname,
                    "action": c.action,
                }
                await _broadcast("agents", event)
                if c.simulation_id:
                    await _broadcast(f"purple:{c.simulation_id}", event)
        return commands

    async def ingest_result(
        self,
        *,
        agent: EndpointAgent,
        command_id: str,
        status: str,
        exit_code: Optional[int] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        artifacts: Optional[dict[str, Any]] = None,
    ) -> AgentResult:
        """Agent-side: post the result of an executed command.

        Enforces that the command actually belongs to the reporting
        agent. Otherwise a compromised agent could write results for
        any command in the system.
        """
        stmt = select(AgentCommand).where(AgentCommand.id == command_id)
        cmd = (await self.session.execute(stmt)).scalar_one_or_none()
        if cmd is None:
            raise AgentServiceError(f"Unknown command {command_id}")
        if cmd.agent_id != agent.id:
            raise AgentServiceError(
                "Command does not belong to this agent — refusing to ingest"
            )
        if cmd.status not in ("dispatched", "running", "queued"):
            raise AgentServiceError(
                f"Command {command_id} is in status {cmd.status}; cannot accept result"
            )

        result = AgentResult(
            command_id=command_id,
            agent_id=agent.id,
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration_seconds,
            artifacts=artifacts or {},
            reported_at=_utc_now(),
        )
        self.session.add(result)

        cmd.status = "completed" if status == "success" else "failed"
        if status == "rejected":
            cmd.status = "rejected"
        cmd.completed_at = _utc_now()

        await self.session.flush()
        await self.session.refresh(result)

        event = {
            "type": "agent_command_result",
            "command_id": command_id,
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "action": cmd.action,
            "status": cmd.status,
            "exit_code": exit_code,
            "duration_seconds": duration_seconds,
            "stdout_preview": (stdout or "")[:512],
            "stderr_preview": (stderr or "")[:512],
        }
        await _broadcast("agents", event)
        if cmd.simulation_id:
            await _broadcast(f"purple:{cmd.simulation_id}", event)
        return result

    # ------------------------------------------------------------------
    # Audit chain verification
    # ------------------------------------------------------------------

    async def verify_chain(self, agent: EndpointAgent) -> dict[str, Any]:
        """Walk every command for an agent and recompute the hash chain.

        Returns a dict summarizing validity plus the first offending
        row (if any). Exposed via an admin endpoint so operators (or an
        auditor) can prove the command history has not been tampered
        with.
        """
        stmt = (
            select(AgentCommand)
            .where(AgentCommand.agent_id == agent.id)
            .order_by(AgentCommand.created_at.asc())
        )
        rows = list((await self.session.execute(stmt)).scalars().all())
        prev = None
        for row in rows:
            expected_cmd_hash = command_hash(row.action, row.payload)
            if row.command_hash != expected_cmd_hash:
                return {
                    "valid": False,
                    "reason": "command_hash_mismatch",
                    "command_id": row.id,
                }
            expected_chain = hashlib.sha256(
                ((prev or "GENESIS") + "|" + row.command_hash).encode("utf-8")
            ).hexdigest()
            if row.chain_hash != expected_chain:
                return {
                    "valid": False,
                    "reason": "chain_break",
                    "command_id": row.id,
                }
            if row.prev_hash != prev:
                return {
                    "valid": False,
                    "reason": "prev_hash_mismatch",
                    "command_id": row.id,
                }
            prev = row.chain_hash
        return {"valid": True, "commands_verified": len(rows), "chain_tip": prev}
