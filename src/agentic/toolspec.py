"""Typed tool specification (shared contract — see src/agentic/contracts_reference.py).

``ToolSpec`` is the single source of truth for what a tool is allowed to do:
its typed parameters, its effects, its tier, the minimum role that may call
it and every model it touches. Gating is by ``effects``/``tier``, never by
the human-facing ``category``.

``ToolSpec.json_schema()`` and ``ToolSpec.to_llm()`` are implemented in the
registry module (``src/services/agent_tools.py``) and delegated to from here
so the dataclass shape stays identical to the contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal, Optional

from src.agentic.context import UserRole

if TYPE_CHECKING:  # pragma: no cover - typing only
    from src.llm.base import ToolSpecForLLM


class Tier(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    PRIVILEGED = "privileged"


@dataclass(frozen=True)
class Effects:
    reads_org: bool = True
    writes_org: bool = False
    external: bool = False
    executes_code: bool = False

    @property
    def is_read_only(self) -> bool:
        return not (self.writes_org or self.external or self.executes_code)


@dataclass
class ParamSpec:
    type: Literal["string", "integer", "number", "boolean", "array", "object"]
    description: str
    required: bool = False
    enum: Optional[list[str]] = None
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    max_length: Optional[int] = None
    items: Optional["ParamSpec"] = None            # for arrays
    schema: Optional[dict[str, Any]] = None         # nested object schema (additionalProperties=false)
    ref: Optional[str] = None                       # model name, e.g. "Incident": resolved with _scoped_get
    ref_by_value: Optional[tuple[str, str]] = None  # (model name, column), e.g. ("User", "email")
    ref_list: bool = False                          # array of refs


@dataclass
class Target:
    kind: Literal["host", "ip", "user", "incident", "alert", "asset", "integration", "playbook", "endpoint_agent", "other"]
    value: str
    resolved_id: Optional[str] = None
    provenance: Literal["structured", "untrusted_text", "unknown"] = "unknown"


@dataclass
class ToolSpec:
    name: str
    description: str
    params: dict[str, ParamSpec]
    effects: Effects
    tier: Tier
    min_role: UserRole
    models: tuple[str, ...]                         # every model the handler touches; all must carry organization_id
    handler: Callable[..., Awaitable[Any]]
    category: str = "query"                         # human-facing only; never used for gating
    returns_sensitive: bool = False
    effective_targets: Optional[Callable[[dict[str, Any], Any], Awaitable[list[Target]]]] = None  # required for DESTRUCTIVE/PRIVILEGED

    def to_llm(self) -> "ToolSpecForLLM":
        """Render as the provider-neutral LLM tool declaration.

        Implemented in the registry module; ``ToolSpecForLLM`` lives in
        ``src/llm/base.py`` (work package 1). Importing lazily keeps this
        module free of the provider layer.
        """
        from src.services.agent_tools import render_tool_for_llm

        return render_tool_for_llm(self)

    def json_schema(self) -> dict[str, Any]:
        """Render ``params`` to JSON Schema (additionalProperties=false, all required listed)."""
        from src.services.agent_tools import render_json_schema

        return render_json_schema(self)
