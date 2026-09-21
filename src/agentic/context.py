"""Agent execution context (shared contract — see src/agentic/contracts_reference.py).

Every tool invocation, policy decision and LLM turn carries an
``AgentContext``: which organization the caller belongs to, who they are
(user or SOC agent), what role they hold and in which mode the run executes.

Nothing here performs I/O; it must stay importable from Celery, tests and
endpoints without pulling FastAPI or SQLAlchemy sessions in.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from src.agentic.decisions import TrustTier


class Mode(str, Enum):
    INTERACTIVE = "interactive"   # chat / direct tool execute
    AUTONOMOUS = "autonomous"     # Celery investigator: read-only allow-list
    APPROVAL = "approval"         # /actions/{id}/approve executing a proposal


class UserRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


ROLE_RANK = {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}


@dataclass
class AgentContext:
    org_id: str
    role: UserRole
    mode: Mode
    actor_user_id: Optional[str] = None       # set for interactive/approval
    soc_agent_id: Optional[str] = None        # set for autonomous (validated in-org)
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    propose_actions: bool = False             # analyst+: agent may propose destructive actions
    session_id: Optional[str] = None
    investigation_id: Optional[str] = None
    # Approval mode only: the originating run's trust tier + the AgentAction being executed
    origin_trust_tier: Optional["TrustTier"] = None
    approving_action_id: Optional[str] = None
    is_superuser: bool = False
    actor_ip: Optional[str] = None
    deadline_seconds: float = 90.0
    max_steps: int = 6
    max_tokens: int = 8192
    run_token_ceiling: int = 150_000

    def __post_init__(self) -> None:
        if not self.org_id:
            raise ValueError("AgentContext.org_id is required")
        if self.mode is Mode.AUTONOMOUS and not self.soc_agent_id:
            raise ValueError("autonomous mode requires soc_agent_id")
        if self.mode is not Mode.AUTONOMOUS and not self.actor_user_id:
            raise ValueError("interactive/approval mode requires actor_user_id")
