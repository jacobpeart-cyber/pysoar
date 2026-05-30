"""Closed-enum action classifier schemas.

Every value in ActionType maps end-to-end to a verified handler in
src/remediation/engine.py (proven by tests/integration/test_action_handlers_are_real.py).
Enum values match the canonical RemediationAction.action_type strings, so the
classifier output flows directly into RemediationEngine without translation.

PR 3 of sub-project E will add the ActionClassifier service that calls Gemini
with this schema and feeds the result into the agentic investigator's verdict
finalization. This module ships the schemas + enum only; no caller yet.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Closed enum: each value has a verified handler in the remediation engine.

    Adding a new value REQUIRES adding a corresponding executor and proving it
    passes tests/integration/test_action_handlers_are_real.py. Values are the
    canonical RemediationAction.action_type strings (not the colloquial names
    in the original spec).
    """

    FIREWALL_BLOCK = "firewall_block"          # FirewallBlockExecutor
    HOST_ISOLATE = "host_isolate"              # HostIsolationExecutor
    ACCOUNT_DISABLE = "account_disable"        # AccountActionExecutor (action=disable)
    PASSWORD_RESET = "password_reset"          # AccountActionExecutor (action=password_reset)
    PROCESS_KILL = "process_kill"              # ProcessActionExecutor (action=kill)
    FILE_QUARANTINE = "file_quarantine"        # FileActionExecutor
    COLLECT_FORENSICS = "collect_forensics"    # ForensicsCollectionExecutor (composite)


class ClassifiedAction(BaseModel):
    """One LLM recommendation mapped to a structured action.

    recommendation_text is the original English the LLM emitted; action_type
    is the matched enum; args are the parameters the corresponding executor
    expects in its `parameters` dict.
    """

    recommendation_text: str = Field(max_length=2000)
    action_type: ActionType
    args: dict[str, Any] = Field(default_factory=dict)


class ActionClassification(BaseModel):
    """Result of running the action classifier against an investigation's
    final recommendations.

    `actions` is the list of mapped, executable actions. `unsupported` is the
    list of recommendation_text strings the LLM could not map to the enum —
    these become visible system capability gaps via the
    /agentic/capability-gaps endpoint (PR 5), never silently dropped.
    """

    actions: list[ClassifiedAction] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
