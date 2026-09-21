"""Policy / trust decision contracts (verbatim from src/agentic/contracts_reference.py).

Nothing here performs I/O. Keep it importable from Celery, tests, and endpoints
without pulling FastAPI or SQLAlchemy sessions in.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

from src.agentic.toolspec import Target, Tier


class TrustTier(str, Enum):
    CLEAN = "clean"
    FLAGGED = "flagged"
    LOCKDOWN = "lockdown"


@dataclass
class TrustHit:
    family: str
    start: int
    length: int
    snippet_sha256: str
    preview: str          # <= 40 chars, value-redacted
    label: str            # which DATA block, e.g. "alert:1a2b"


@dataclass
class TrustState:
    tier: TrustTier = TrustTier.CLEAN
    hits: list[TrustHit] = field(default_factory=list)
    score: float = 0.0
    contaminated_labels: set[str] = field(default_factory=set)
    first_seen_message_id: Optional[str] = None

    @property
    def lockdown(self) -> bool:
        return self.tier is TrustTier.LOCKDOWN

    @property
    def flagged(self) -> bool:
        return self.tier is not TrustTier.CLEAN


DecisionKind = Literal["allow", "deny", "propose"]

ReasonCode = Literal[
    "ok",
    "invalid_arguments",
    "unknown_tool",
    "role_not_permitted",
    "autonomous_mode_readonly",
    "proposal_disabled",
    "injection_lockdown",
    "cross_tenant_reference",
    "ambiguous_target",
    "value_not_in_org",
    "invalid_target",
    "too_many_targets",
    "rate_limited",
    "audit_unavailable",
]


@dataclass
class Decision:
    kind: DecisionKind
    reason_code: ReasonCode
    tool: str
    tier: Tier
    risk: Literal["info", "low", "medium", "high", "critical"]
    resolved_args: dict[str, Any]            # by-value refs rewritten to in-org ids
    effective_targets: list[Target]
    audit_id: Optional[str] = None           # AuditTrail row id of the pre-decision event
    detail: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.kind == "allow"


@dataclass
class PolicyEvent:
    step: int
    tool: str
    decision: DecisionKind
    reason_code: ReasonCode
    tier: Tier
    audit_id: Optional[str]
    proposal_id: Optional[str] = None       # AgentAction id when kind == "propose"
