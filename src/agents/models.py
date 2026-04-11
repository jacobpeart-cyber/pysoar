"""SQLAlchemy models for the PySOAR Agent Platform.

Four tables:

- ``endpoint_agents``  — one row per enrolled host/agent installation
- ``agent_commands``   — dispatched commands, hash-chained per agent
- ``agent_results``    — command execution results (stdout/stderr/artifacts)
- ``agent_heartbeats`` — connectivity pings (last N kept per agent for
  the dashboard, older rows pruned on a schedule)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel, utc_now


class EndpointAgent(BaseModel):
    """An enrolled PySOAR agent installation on a customer endpoint.

    Created by ``POST /agents/enroll`` which returns a one-time
    enrollment token. The agent exchanges the token for a long-lived
    ``agent_token`` (stored as a SHA-256 hash here, never in plaintext).
    """

    __tablename__ = "endpoint_agents"

    # Customer-visible identifiers
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Host fingerprinting (sent by agent on first heartbeat)
    os_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)   # windows/linux/macos
    os_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    agent_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Enrollment state
    # pending  -> enrollment token issued, agent has not checked in yet
    # active   -> last heartbeat within the liveness window
    # offline  -> no recent heartbeat
    # disabled -> operator disabled the agent (no more commands dispatched)
    # revoked  -> token rotated, agent must re-enroll
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)

    # Capabilities this agent was enrolled with. JSON array of strings
    # matching AgentCapability values. Enforcement happens server-side
    # in AgentService.issue_command and agent-side in the allowlist.
    capabilities: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Hash of the agent's authentication token. The plaintext token is
    # only shown once at enrollment and never stored. Compare via
    # ``hashlib.sha256(plaintext).hexdigest()``.
    token_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    enrollment_token_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    enrollment_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Last-seen telemetry
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_command_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Ownership
    enrolled_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True, index=True
    )

    # Free-form tags so operators can group "lab-west", "prod-dc", etc.
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    extra_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AgentCommand(BaseModel):
    """A command dispatched from PySOAR to an agent.

    Commands are hash-linked via ``prev_hash`` so the sequence is
    tamper-evident. ``command_hash`` is ``sha256(action || payload)``
    and ``chain_hash`` is ``sha256(prev_hash || command_hash)``. If an
    attacker with DB access rewrites history, every subsequent
    ``chain_hash`` stops validating.
    """

    __tablename__ = "agent_commands"

    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoint_agents.id"), nullable=False, index=True
    )

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Tamper-evident chain
    command_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Status:
    # queued     -> waiting to be picked up by the agent
    # dispatched -> agent has polled and acknowledged
    # running    -> agent is executing
    # completed  -> result posted
    # failed     -> agent reported error
    # rejected   -> agent's local allowlist refused it
    # expired    -> timed out before agent picked it up
    # awaiting_approval -> high-blast action pending operator approval
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)

    # Optional linkage to a simulation/case
    simulation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    # Approval workflow — present for high-blast actions only
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Lifecycle timestamps
    dispatched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Who issued the command
    issued_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True, index=True
    )

    __table_args__ = (
        Index("ix_agent_commands_agent_status", "agent_id", "status"),
    )


class AgentResult(BaseModel):
    """Execution result reported by an agent for a given command."""

    __tablename__ = "agent_results"

    command_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("agent_commands.id"), nullable=False, index=True, unique=True
    )
    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoint_agents.id"), nullable=False, index=True
    )

    # success / error / rejected / timeout
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    stdout: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stderr: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Structured output — for collect_* actions this holds the harvested
    # artifacts; for run_atomic_test it holds executor / detection hints.
    artifacts: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class AgentHeartbeat(BaseModel):
    """Single ping from an agent. Latest row per agent surfaces "live" status."""

    __tablename__ = "agent_heartbeats"

    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoint_agents.id"), nullable=False, index=True
    )
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # Lightweight host telemetry: cpu%, mem%, uptime, etc.
    telemetry: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
