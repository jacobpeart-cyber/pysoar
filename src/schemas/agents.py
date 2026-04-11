"""Pydantic schemas for the agent platform."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AgentEnrollRequest(BaseModel):
    hostname: str
    capabilities: list[str] = Field(
        ..., description="Any of: bas, ir, purple"
    )
    display_name: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class AgentEnrollResponse(BaseModel):
    """Returned exactly once. The plaintext ``enrollment_token`` is
    NOT recoverable later — ship it to the agent installer via secure
    channel or expire it and re-enroll."""

    agent_id: str
    hostname: str
    capabilities: list[str]
    status: str
    enrollment_token: str = Field(
        ..., description="One-time token; exchange within 30 min at /agents/exchange"
    )
    enrollment_expires_at: Optional[datetime] = None


class AgentExchangeRequest(BaseModel):
    enrollment_token: str
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    ip_address: Optional[str] = None


class AgentExchangeResponse(BaseModel):
    agent_id: str
    agent_token: str = Field(..., description="Long-lived; agent stores locally")
    capabilities: list[str]


class AgentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostname: str
    display_name: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    capabilities: list[str]
    last_heartbeat_at: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None


class AgentListResponse(BaseModel):
    total: int
    agents: list[AgentSummary]


class HeartbeatRequest(BaseModel):
    telemetry: dict[str, Any] = Field(default_factory=dict)
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    ip_address: Optional[str] = None


class IssueCommandRequest(BaseModel):
    action: str
    payload: dict[str, Any] = Field(default_factory=dict)
    simulation_id: Optional[str] = None
    incident_id: Optional[str] = None


class CommandSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    action: str
    payload: dict[str, Any]
    status: str
    approval_required: bool
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    command_hash: str
    chain_hash: str
    dispatched_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class CommandResultRequest(BaseModel):
    """Agent -> PySOAR: post execution result for a command."""

    status: str = Field(..., description="success / error / rejected / timeout")
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    duration_seconds: Optional[float] = None
    artifacts: dict[str, Any] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    reason: Optional[str] = None


class ChainVerificationResponse(BaseModel):
    valid: bool
    reason: Optional[str] = None
    command_id: Optional[str] = None
    commands_verified: Optional[int] = None
    chain_tip: Optional[str] = None


class AgentPollResponse(BaseModel):
    """Agent poll result — includes chain tip for idempotency."""

    commands: list[CommandSummary]
