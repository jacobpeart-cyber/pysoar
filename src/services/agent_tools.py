"""PySOAR Agent Tool Registry (Agentic SOC rebuild, work package 2A).

Every capability the Agentic SOC can invoke is registered as a typed
:class:`~src.agentic.toolspec.ToolSpec`. The spec — not the human-facing
``category`` — is the single source of truth for what a tool may do: its
typed parameters (with model references the policy engine resolves in-org),
its effects, its tier and the minimum role that may call it.

Tenancy rules enforced here:

* The registry is bound to one :class:`~src.agentic.context.AgentContext`
  and therefore one organization. ``ctx.org_id`` is required.
* Every query goes through :meth:`AgentToolRegistry._scoped`, which appends
  the organization predicate for the model being read (``SCOPE_RULES`` holds
  the few models that are scoped through a parent or a legacy fallback).
* Every row a write tool creates carries ``organization_id=ctx.org_id`` and
  is attributed to ``ctx.actor_user_id`` / ``ctx.soc_agent_id``. There is no
  default organization and no synthetic system user.
* :meth:`AgentToolRegistry.call` is the only entry point. Handlers are
  private methods; nothing outside this module may invoke them directly.
* Composite handlers (``remediate_incident``) never invoke another handler
  directly: every sub-action goes through :meth:`AgentToolRegistry._sub_call`
  so it receives its own policy decision, rate charge and audit pair. A
  denied sub-call aborts the composite with an honest partial result.
* Every destructive/privileged spec declares ``effective_targets`` so the
  policy engine (and the approval card) sees every concrete host / ip /
  user / record the call would touch, each with its provenance.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.context import ROLE_RANK, AgentContext, UserRole
from src.agentic.decisions import Decision, TrustState
from src.agentic.models import AgentAction as AgenticAction
from src.agentic.models import Investigation
from src.agentic.toolspec import Effects, ParamSpec, Target, Tier, ToolSpec
from src.agents.capabilities import AgentAction as EndpointAction
from src.agents.models import AgentCommand, EndpointAgent
from src.collaboration.models import ActionItem, WarRoom
from src.compliance.models import POAM, ComplianceControl, ComplianceEvidence, ComplianceFramework
from src.darkweb.models import DarkWebFinding
from src.deception.models import DecoyInteraction
from src.dfir.models import ForensicCase
from src.exposure.models import RemediationTicket
from src.hunting.models import HuntFinding, HuntHypothesis, HuntSession
from src.integrations.models import InstalledIntegration
from src.intel.models import ThreatActor, ThreatCampaign, ThreatIndicator
from src.llm.base import ToolSpecForLLM
from src.models.alert import Alert
from src.models.asset import Asset
from src.models.audit import AuditLog
from src.models.case import CaseNote, CaseTimeline
from src.models.incident import Incident, IncidentStatus
from src.models.playbook import ExecutionStatus, Playbook, PlaybookExecution
from src.models.user import User
from src.phishing_sim.models import PhishingCampaign
from src.remediation.models import RemediationExecution
from src.risk_quant.models import FAIRAnalysis, RiskScenario
from src.siem.models import DetectionRule, LogEntry
from src.simulation.models import AttackSimulation, SimulationTest
from src.tickethub.models import TicketActivity
from src.ueba.models import EntityProfile, UEBARiskAlert
from src.vulnmgmt.models import Vulnerability

logger = structlog.get_logger(__name__)

__all__ = [
    "MODEL_REGISTRY",
    "PARENT_SCOPED",
    "SCOPE_RULES",
    "AgentToolRegistry",
    "render_json_schema",
    "render_tool_for_llm",
]

# ---------------------------------------------------------------------------
# Model registry and scoping rules
# ---------------------------------------------------------------------------

#: Model names used in ``ParamSpec.ref`` / ``ref_by_value`` / ``ToolSpec.models``
#: mapped to their SQLAlchemy classes.
MODEL_REGISTRY: dict[str, type] = {
    "Alert": Alert,
    "Incident": Incident,
    "Asset": Asset,
    "User": User,
    "ThreatIndicator": ThreatIndicator,
    "ThreatActor": ThreatActor,
    "ThreatCampaign": ThreatCampaign,
    "Playbook": Playbook,
    "PlaybookExecution": PlaybookExecution,
    "Investigation": Investigation,
    "AgentAction": AgenticAction,
    "WarRoom": WarRoom,
    "ActionItem": ActionItem,
    "EndpointAgent": EndpointAgent,
    "AgentCommand": AgentCommand,
    "InstalledIntegration": InstalledIntegration,
    "ForensicCase": ForensicCase,
    "RemediationTicket": RemediationTicket,
    "RemediationExecution": RemediationExecution,
    "HuntHypothesis": HuntHypothesis,
    "HuntSession": HuntSession,
    "HuntFinding": HuntFinding,
    "LogEntry": LogEntry,
    "DetectionRule": DetectionRule,
    "Vulnerability": Vulnerability,
    "EntityProfile": EntityProfile,
    "UEBARiskAlert": UEBARiskAlert,
    "DarkWebFinding": DarkWebFinding,
    "DecoyInteraction": DecoyInteraction,
    "PhishingCampaign": PhishingCampaign,
    "RiskScenario": RiskScenario,
    "FAIRAnalysis": FAIRAnalysis,
    "ComplianceFramework": ComplianceFramework,
    "ComplianceControl": ComplianceControl,
    "POAM": POAM,
    "ComplianceEvidence": ComplianceEvidence,
    "TicketActivity": TicketActivity,
    "AttackSimulation": AttackSimulation,
    "AuditLog": AuditLog,
    "CaseNote": CaseNote,
    "CaseTimeline": CaseTimeline,
    "SimulationTest": SimulationTest,
}


def _org_users(org_id: str) -> Select:
    """Sub-select of the user ids belonging to ``org_id``."""
    return select(User.id).where(User.organization_id == org_id)


def _playbook_scope(org_id: str) -> Any:
    """Playbook predicate: owned by the org, or a legacy NULL-org row created by one of its users."""
    return or_(
        Playbook.organization_id == org_id,
        and_(Playbook.organization_id.is_(None), Playbook.created_by.in_(_org_users(org_id))),
    )


def _audit_log_scope(org_id: str) -> Any:
    """AuditLog has no organization column; scope through the acting user's org."""
    return AuditLog.user_id.in_(_org_users(org_id))


def _simulation_test_scope(org_id: str) -> Any:
    """SimulationTest is scoped through its parent AttackSimulation."""
    return SimulationTest.simulation_id.in_(
        select(AttackSimulation.id).where(AttackSimulation.organization_id == org_id),
    )


#: Models whose org predicate is not the plain ``organization_id == org`` column.
SCOPE_RULES: dict[str, Callable[[str], Any]] = {
    "Playbook": _playbook_scope,
    "AuditLog": _audit_log_scope,
    "SimulationTest": _simulation_test_scope,
}

#: Child tables without an ``organization_id`` column that are only ever written
#: through an org-scoped parent row (never queried directly by a handler).
PARENT_SCOPED: dict[str, str] = {
    "CaseNote": "Incident",
    "CaseTimeline": "Incident",
    "SimulationTest": "AttackSimulation",
}

#: Columns compared case-insensitively in :meth:`AgentToolRegistry.resolve_by_value`.
_CASE_INSENSITIVE_COLUMNS = {"email", "hostname", "name", "fqdn"}

#: Hard cap on rows returned by by-value resolution (policy treats >1 as ambiguous).
_RESOLVE_LIMIT = 5

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

#: ``execute_playbook`` input keys that are always taken from the context.
PLAYBOOK_RESERVED_KEYS: frozenset[str] = frozenset({"organization_id", "actor_user_id", "playbook_execution_id"})

#: Cap on the concrete targets a composite tool may expand to (mirrors policy.MAX_EFFECTIVE_TARGETS).
MAX_COMPOSITE_TARGETS = 25

#: Endpoint agents in these states may receive a command (matches the remediation engine's eligibility rule).
_DISPATCHABLE_AGENT_STATES: tuple[str, ...] = ("active", "offline")

#: ``input_data`` keys whose values name hosts / ips / users and therefore become effective targets.
_INPUT_HOST_KEYS: frozenset[str] = frozenset({"hostname", "host", "target_host", "asset", "asset_ref", "target"})
_INPUT_IP_KEYS: frozenset[str] = frozenset({"ip", "ip_address", "source_ip", "destination_ip", "target_ip"})
_INPUT_USER_KEYS: frozenset[str] = frozenset({"user", "username", "user_email", "email", "user_id", "account"})

#: JSON-schema type names accepted in a ``Playbook.variables`` declaration.
_JSON_TYPE_CHECKS: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}


def _model_is_scopable(name: str) -> bool:
    model = MODEL_REGISTRY.get(name)
    if model is None:
        return False
    if name in SCOPE_RULES or name in PARENT_SCOPED:
        return True
    return hasattr(model, "organization_id")


# ---------------------------------------------------------------------------
# JSON-schema rendering
# ---------------------------------------------------------------------------


def _param_schema(p: ParamSpec) -> dict[str, Any]:
    if p.schema is not None:
        out: dict[str, Any] = dict(p.schema)
        out.setdefault("type", p.type)
        out["description"] = p.description
        if out["type"] == "object":
            out.setdefault("properties", {})
            out.setdefault("additionalProperties", False)
        return out
    out = {"type": p.type, "description": p.description}
    if p.enum:
        out["enum"] = list(p.enum)
    if p.minimum is not None:
        out["minimum"] = p.minimum
    if p.maximum is not None:
        out["maximum"] = p.maximum
    if p.max_length is not None:
        out["maxLength"] = p.max_length
    if p.type == "array":
        out["items"] = _param_schema(p.items) if p.items is not None else {"type": "string"}
    if p.type == "object":
        out["properties"] = {}
        out["additionalProperties"] = False
    return out


def render_json_schema(spec: ToolSpec) -> dict[str, Any]:
    """Render ``spec.params`` as a JSON Schema (draft-07 style) object."""
    return {
        "type": "object",
        "properties": {name: _param_schema(p) for name, p in spec.params.items()},
        "required": [name for name, p in spec.params.items() if p.required],
        "additionalProperties": False,
    }


def render_tool_for_llm(spec: ToolSpec) -> ToolSpecForLLM:
    """Provider-neutral tool declaration (strict schema)."""
    return ToolSpecForLLM(
        name=spec.name,
        description=spec.description,
        input_schema=render_json_schema(spec),
        strict=True,
    )


# ---------------------------------------------------------------------------
# ParamSpec helpers
# ---------------------------------------------------------------------------


def _s(
    description: str,
    *,
    required: bool = False,
    enum: Optional[list[str]] = None,
    max_length: Optional[int] = None,
    ref: Optional[str] = None,
    ref_by_value: Optional[tuple[str, str]] = None,
) -> ParamSpec:
    return ParamSpec(
        type="string",
        description=description,
        required=required,
        enum=enum,
        max_length=max_length,
        ref=ref,
        ref_by_value=ref_by_value,
    )


def _limit(default: int) -> ParamSpec:
    return ParamSpec(
        type="integer",
        description=f"Maximum rows to return (default {default}, max 100)",
        minimum=1,
        maximum=100,
    )


def _bool(description: str) -> ParamSpec:
    return ParamSpec(type="boolean", description=description)


SEVERITIES = ["critical", "high", "medium", "low"]
INCIDENT_STATUSES = [s.value for s in IncidentStatus]
ENDPOINT_ACTIONS = [a.value for a in EndpointAction]

ENDPOINT_PAYLOAD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "mitre_id": {"type": "string", "description": "run_atomic_test / purple_fire_technique: ATT&CK technique id"},
        "target_host": {"type": "string", "description": "run_atomic_test: hostname the test targets"},
        "pid": {"type": "integer", "minimum": 1, "description": "kill_process: process id"},
        "process_name": {"type": "string", "description": "kill_process: process image name"},
        "ip": {"type": "string", "description": "block_ip / unblock_ip: IPv4 address"},
        "username": {"type": "string", "description": "disable_account: local account name"},
        "path": {"type": "string", "description": "collect_file / quarantine_file / unquarantine_file: absolute path"},
        "rule_id": {"type": "string", "description": "run_stig_check / run_cis_check: benchmark rule id"},
        "check_content": {"type": "string", "description": "run_stig_check / run_cis_check: check content"},
        "os_type": {"type": "string", "enum": ["windows", "linux", "macos"], "description": "run_stig_check / run_cis_check"},
        "decoy_id": {"type": "string", "description": "deploy_honeypot / stop_honeypot: decoy id"},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "deploy_honeypot: listen port"},
        "banner": {"type": "string", "description": "deploy_honeypot: service banner"},
        "service": {"type": "string", "description": "deploy_honeypot: emulated service"},
    },
}

# Part B tightens these against Playbook.variables / the connector's declared
# action schema. Until then they are open objects; the policy still walks them
# for x-ref markers and enforces the 16 KB args cap.
OPEN_OBJECT_SCHEMA: dict[str, Any] = {"type": "object", "additionalProperties": True}


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class AgentToolRegistry:
    """Org-bound registry of every tool the agent can invoke."""

    def __init__(self, db: AsyncSession, ctx: AgentContext):
        if ctx is None or not getattr(ctx, "org_id", None):
            raise ValueError("AgentToolRegistry requires an AgentContext with org_id")
        self.db = db
        self.ctx = ctx
        self.specs: dict[str, ToolSpec] = {}
        #: Policy bound for the registry's lifetime (``bind_policy``); used when
        #: ``call`` is handed a pre-evaluated decision and no policy object.
        self.policy: Any = None
        #: Policy in force for the duration of the current ``call`` (sub-calls reuse it).
        self._active_policy: Any = None
        self._register_all()

    def bind_policy(self, policy: Any) -> None:
        """Bind the policy engine composite handlers use for their sub-actions."""
        self.policy = policy

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    async def execute(self, tool_name: str, params: dict) -> dict:
        """Legacy entry point — removed. Use ``call(ctx, tool, args)``."""
        raise NotImplementedError("use registry.call(ctx, tool, args)")

    async def call(
        self,
        ctx: AgentContext,
        tool: str,
        args: dict[str, Any],
        *,
        decision: Optional[Decision] = None,
        policy: Any = None,
    ) -> Any:
        """Execute ``tool`` for ``ctx`` after a policy decision.

        Returns the handler's raw result; the runtime wraps it. Raises
        ``KeyError`` for an unknown tool and ``PermissionError`` (carrying the
        decision reason code) when the decision is not ``allow``.
        """
        spec = self.specs.get(tool)
        if spec is None:
            raise KeyError(tool)
        if ctx.org_id != self.ctx.org_id:
            raise PermissionError("cross_tenant_reference")
        effective_policy = policy if policy is not None else self.policy
        if decision is None:
            if effective_policy is None:
                raise ValueError("call() requires a Decision or a policy to evaluate one")
            decision = await effective_policy.evaluate(ctx, spec, args, TrustState())
        if decision.kind != "allow":
            # A propose/deny decision carries ``reason_code == "ok"`` only when it
            # is a proposal; surface the kind so composites report it honestly.
            raise PermissionError(decision.reason_code if decision.reason_code != "ok" else f"decision_{decision.kind}")
        if decision.tool != spec.name:
            raise PermissionError("invalid_arguments")
        logger.info(
            "agent_tool_call",
            run_id=ctx.run_id,
            org_id=ctx.org_id,
            tool=spec.name,
            tier=spec.tier.value,
            mode=ctx.mode.value,
        )
        previous_policy = self._active_policy
        self._active_policy = effective_policy
        try:
            return await spec.handler(**decision.resolved_args)
        finally:
            self._active_policy = previous_policy

    async def _sub_call(self, ctx: AgentContext, tool: str, args: dict[str, Any]) -> Any:
        """Invoke ``tool`` as a sub-action of the handler currently executing.

        The sub-action is evaluated by the policy in force for the outer
        call, so it gets its own decision, rate charge and audit pair. A
        denied sub-call raises ``PermissionError`` (the composite must abort).
        Without a policy in scope the composite fails closed.
        """
        policy = self._active_policy if self._active_policy is not None else self.policy
        if policy is None:
            raise PermissionError("composite_requires_policy")
        return await self.call(ctx, tool, dict(args), policy=policy)

    def visible_specs(self, role: Optional[UserRole] = None) -> list[ToolSpec]:
        """Tools ``role`` (default: the bound context's role) may invoke."""
        rank = ROLE_RANK[role or self.ctx.role]
        return [s for s in self.specs.values() if ROLE_RANK[s.min_role] <= rank]

    def list_tools(self, category: Optional[str] = None) -> list[dict[str, Any]]:
        """Tool discovery for the caller's role (JSON-schema parameters)."""
        out = []
        for s in self.visible_specs():
            if category and s.category != category:
                continue
            out.append(
                {
                    "name": s.name,
                    "description": s.description,
                    "parameters": render_json_schema(s),
                    "category": s.category,
                    "tier": s.tier.value,
                    "min_role": s.min_role.value,
                },
            )
        return out

    def gemini_function_declarations(self) -> list[dict[str, Any]]:
        """Gemini ``function_declarations`` for the tools visible to ``ctx.role``."""
        return [
            {"name": s.name, "description": s.description, "parameters": render_json_schema(s)}
            for s in self.visible_specs()
        ]

    # ------------------------------------------------------------------
    # Scoping helpers (the only places a query may be built)
    # ------------------------------------------------------------------

    def _scoped(self, stmt: Select, model: type) -> Select:
        """Append the organization predicate for ``model`` to ``stmt``."""
        rule = SCOPE_RULES.get(model.__name__)
        if rule is not None:
            return stmt.where(rule(self.ctx.org_id))
        column = getattr(model, "organization_id", None)
        if column is None:
            raise TypeError(f"{model.__name__} has no organization_id and no scope rule; it may not be queried")
        return stmt.where(column == self.ctx.org_id)

    async def _scoped_get(self, model_name: str, row_id: str) -> Any | None:
        """Load one row of ``model_name`` by primary key inside the org, or ``None``."""
        model = MODEL_REGISTRY[model_name]
        if not isinstance(row_id, str) or not row_id:
            return None
        stmt = self._scoped(select(model).where(model.id == row_id), model)
        return (await self.db.execute(stmt)).scalar_one_or_none()

    async def resolve_by_value(self, model_name: str, column: str, value: str) -> list[Any]:
        """Rows of ``model_name`` whose ``column`` equals ``value`` inside the org."""
        model = MODEL_REGISTRY[model_name]
        col = getattr(model, column, None)
        if col is None:
            raise KeyError(f"{model_name}.{column}")
        if column in _CASE_INSENSITIVE_COLUMNS:
            predicate = func.lower(col) == value.lower()
        else:
            predicate = col == value
        stmt = self._scoped(select(model).where(predicate), model).limit(_RESOLVE_LIMIT)
        return list((await self.db.execute(stmt)).scalars().all())

    def _actor_id(self) -> str:
        actor = self.ctx.actor_user_id or self.ctx.soc_agent_id
        if not actor:
            raise ValueError("AgentContext carries neither actor_user_id nor soc_agent_id")
        return actor

    async def _incident(self, incident_id: str) -> Optional[Incident]:
        return await self._scoped_get("Incident", incident_id)

    async def _alert(self, alert_id: str) -> Optional[Alert]:
        return await self._scoped_get("Alert", alert_id)

    def _add_timeline(
        self,
        incident: Incident,
        event_type: str,
        title: str,
        description: Optional[str] = None,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
    ) -> None:
        self.db.add(
            CaseTimeline(
                incident_id=incident.id,
                event_type=event_type,
                title=title,
                description=description,
                old_value=old_value,
                new_value=new_value,
                # users FK: attributed to the human actor, never to another user; NULL for agents.
                actor_id=self.ctx.actor_user_id,
            ),
        )

    # ------------------------------------------------------------------
    # Effective-target expansion (destructive / privileged tools)
    # ------------------------------------------------------------------
    #
    # Each ``_targets_*`` method has the ``ToolSpec.effective_targets``
    # signature ``(args, registry) -> list[Target]``. They never raise for a
    # missing row: the target is returned with ``resolved_id=None`` and
    # ``provenance="unknown"`` and the policy's ``_check_target`` decides.

    @staticmethod
    def _parse_json_list(jsonish: Any) -> list[str]:
        """Parse a JSON-array text column (or a comma list) into strings."""
        if not jsonish:
            return []
        try:
            v = json.loads(jsonish) if isinstance(jsonish, str) else jsonish
        except (TypeError, json.JSONDecodeError):
            return [s.strip() for s in str(jsonish).split(",") if s.strip()]
        if isinstance(v, list):
            return [str(x) for x in v if x is not None and str(x).strip()]
        return [str(v)] if v else []

    async def _ip_is_structured(self, ip: str) -> bool:
        """True when ``ip`` appears in a structured, human/system-written org field."""
        alert_q = self._scoped(select(func.count(Alert.id)), Alert).where(
            or_(Alert.source_ip == ip, Alert.destination_ip == ip),
        )
        if int((await self.db.execute(alert_q)).scalar() or 0):
            return True
        ioc_q = self._scoped(select(func.count(ThreatIndicator.id)), ThreatIndicator).where(ThreatIndicator.value == ip)
        if int((await self.db.execute(ioc_q)).scalar() or 0):
            return True
        inc_q = self._scoped(select(func.count(Incident.id)), Incident).where(Incident.indicators.like(f'%"{ip}"%'))
        return bool(int((await self.db.execute(inc_q)).scalar() or 0))

    async def _host_is_structured(self, host: str) -> bool:
        """True when ``host`` names an org Asset or appears on an org Alert / Incident."""
        if await self._find_asset(host) is not None:
            return True
        alert_q = self._scoped(select(func.count(Alert.id)), Alert).where(func.lower(Alert.hostname) == host.lower())
        if int((await self.db.execute(alert_q)).scalar() or 0):
            return True
        inc_q = self._scoped(select(func.count(Incident.id)), Incident).where(Incident.affected_systems.like(f'%"{host}"%'))
        return bool(int((await self.db.execute(inc_q)).scalar() or 0))

    async def _ip_target(self, ip: str) -> Target:
        value = str(ip).strip()
        structured = await self._ip_is_structured(value) if value else False
        return Target(kind="ip", value=value, resolved_id=None, provenance="structured" if structured else "untrusted_text")

    async def _host_target(self, host: str) -> Target:
        value = str(host).strip()
        asset = await self._find_asset(value) if value else None
        if asset is not None:
            return Target(kind="host", value=asset.hostname or asset.name or value, resolved_id=asset.id, provenance="structured")
        structured = await self._host_is_structured(value) if value else False
        return Target(kind="host", value=value, resolved_id=None, provenance="structured" if structured else "untrusted_text")

    async def _user_target(self, ref: str) -> Target:
        value = str(ref).strip()
        user = await self._resolve_user_ref(value) if value else None
        if user is not None:
            return Target(kind="user", value=user.email, resolved_id=user.id, provenance="structured")
        return Target(kind="user", value=value, resolved_id=None, provenance="unknown")

    async def _row_target(self, kind: str, model_name: str, row_id: Any) -> Target:
        value = str(row_id) if row_id is not None else ""
        row = await self._scoped_get(model_name, value) if value else None
        if row is None:
            return Target(kind=kind, value=value, resolved_id=None, provenance="unknown")  # type: ignore[arg-type]
        return Target(kind=kind, value=value, resolved_id=row.id, provenance="structured")  # type: ignore[arg-type]

    async def _targets_in_input_data(self, data: Any) -> list[Target]:
        """Hosts / ips / users named by well-known keys anywhere inside ``data``."""
        out: list[Target] = []
        seen: set[tuple[str, str]] = set()

        async def walk(node: Any) -> None:
            if len(out) >= MAX_COMPOSITE_TARGETS:
                return
            if isinstance(node, dict):
                for key, val in node.items():
                    k = str(key).lower()
                    if isinstance(val, str) and val.strip():
                        target: Optional[Target] = None
                        if k in _INPUT_IP_KEYS:
                            target = await self._ip_target(val)
                        elif k in _INPUT_HOST_KEYS:
                            target = await self._host_target(val)
                        elif k in _INPUT_USER_KEYS:
                            target = await self._user_target(val)
                        if target is not None and (target.kind, target.value) not in seen:
                            seen.add((target.kind, target.value))
                            out.append(target)
                    elif isinstance(val, (dict, list)):
                        await walk(val)
            elif isinstance(node, list):
                for item in node:
                    await walk(item)

        await walk(data)
        return out[:MAX_COMPOSITE_TARGETS]

    async def _targets_block_ip(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        return [await self._ip_target(args.get("ip") or "")]

    async def _targets_isolate_host(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        return [await self._host_target(args.get("hostname") or "")]

    async def _targets_disable_user(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        return [await self._user_target(args.get("user_email") or "")]

    async def _targets_execute_playbook(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        targets = [await self._row_target("playbook", "Playbook", args.get("playbook_id"))]
        targets.extend(await self._targets_in_input_data(args.get("input_data") or {}))
        return targets[:MAX_COMPOSITE_TARGETS]

    async def _targets_execute_integration_action(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        targets = [await self._row_target("integration", "InstalledIntegration", args.get("installation_id"))]
        targets.extend(await self._targets_in_input_data(args.get("input_data") or {}))
        return targets[:MAX_COMPOSITE_TARGETS]

    async def _targets_remediate_incident(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        incident_id = args.get("incident_id")
        inc = await self._incident(str(incident_id)) if incident_id else None
        if inc is None:
            return [Target(kind="incident", value=str(incident_id or ""), resolved_id=None, provenance="unknown")]
        targets: list[Target] = [Target(kind="incident", value=inc.id, resolved_id=inc.id, provenance="structured")]
        if args.get("isolate_hosts", True) in (True, "true", "True", 1):
            for host in self._parse_json_list(inc.affected_systems):
                if len(targets) >= MAX_COMPOSITE_TARGETS:
                    break
                targets.append(await self._host_target(host))
        if args.get("block_indicators", True) in (True, "true", "True", 1):
            for ind in self._parse_json_list(inc.indicators):
                if len(targets) >= MAX_COMPOSITE_TARGETS:
                    break
                if _IPV4_RE.match(ind):
                    targets.append(await self._ip_target(ind))
        return targets[:MAX_COMPOSITE_TARGETS]

    async def _targets_create_remediation_ticket(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        incident_id = args.get("incident_id")
        if incident_id:
            return [await self._row_target("incident", "Incident", incident_id)]
        return [Target(kind="other", value=str(args.get("title") or "")[:200], resolved_id=None, provenance="untrusted_text")]

    async def _targets_simulate_attack(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        return [await self._host_target(args.get("target") or "")]

    async def _targets_queue_endpoint_command(self, args: dict[str, Any], registry: Any = None) -> list[Target]:
        targets = [await self._row_target("endpoint_agent", "EndpointAgent", args.get("agent_id"))]
        targets.extend(await self._targets_in_input_data(args.get("payload") or {}))
        return targets[:MAX_COMPOSITE_TARGETS]

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def _register(self, spec: ToolSpec) -> None:
        if spec.name in self.specs:
            raise ValueError(f"duplicate tool {spec.name}")
        for model_name in spec.models:
            if not _model_is_scopable(model_name):
                raise TypeError(f"{spec.name}: model {model_name!r} is not org-scopable")
        for pname, p in spec.params.items():
            for ref_model in (p.ref, p.ref_by_value[0] if p.ref_by_value else None):
                if ref_model is not None and not _model_is_scopable(ref_model):
                    raise TypeError(f"{spec.name}.{pname}: ref model {ref_model!r} is not org-scopable")
        self.specs[spec.name] = spec

    def _register_all(self) -> None:
        READ = Effects()  # noqa: N806
        WRITE = Effects(writes_org=True)  # noqa: N806

        # ===== QUERY =====
        self._register(ToolSpec(
            name="list_alerts",
            description="List recent alerts with optional filters",
            params={
                "severity": _s("Alert severity", enum=SEVERITIES),
                "status": _s("Alert status", max_length=50),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Alert",),
            handler=self._list_alerts, category="query",
        ))
        self._register(ToolSpec(
            name="list_incidents",
            description="List recent incidents",
            params={
                "status": _s("Incident status", enum=INCIDENT_STATUSES),
                "severity": _s("Incident severity", enum=SEVERITIES),
                "limit": _limit(10),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Incident",),
            handler=self._list_incidents, category="query",
        ))
        self._register(ToolSpec(
            name="list_iocs",
            description="List active IOCs (threat indicators)",
            params={
                "ioc_type": _s("Indicator type (ipv4/ipv6/domain/hash/url/email)", max_length=50),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("ThreatIndicator",),
            handler=self._list_iocs, category="query",
        ))
        self._register(ToolSpec(
            name="get_alert",
            description="Get full details of a specific alert",
            params={"alert_id": _s("Alert UUID", required=True, ref="Alert")},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Alert",),
            handler=self._get_alert, category="query",
        ))
        self._register(ToolSpec(
            name="get_incident",
            description="Get full details of a specific incident",
            params={"incident_id": _s("Incident UUID", required=True, ref="Incident")},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Incident",),
            handler=self._get_incident, category="query",
        ))
        self._register(ToolSpec(
            name="platform_stats",
            description="Organization-wide security stats (alert counts, incident counts)",
            params={},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Alert", "Incident"),
            handler=self._platform_stats, category="query",
        ))
        self._register(ToolSpec(
            name="search_alerts",
            description="Search alerts by keyword in title/description",
            params={"keyword": _s("Keyword", required=True, max_length=200), "limit": _limit(10)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Alert",),
            handler=self._search_alerts, category="query",
        ))
        self._register(ToolSpec(
            name="list_playbooks",
            description="List enabled response playbooks (read-only). Use to find the SOP matching the current alert/incident type before concluding.",
            params={
                "keyword": _s("Filter by name/description", max_length=200),
                "category": _s("Playbook category", max_length=100),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Playbook",),
            handler=self._list_playbooks, category="query",
        ))
        self._register(ToolSpec(
            name="get_playbook",
            description="Get a playbook's full definition including its ordered steps (read-only; does NOT execute it)",
            params={"playbook_id": _s("Playbook UUID", required=True, ref="Playbook")},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Playbook",),
            handler=self._get_playbook, category="query",
        ))
        self._register(ToolSpec(
            name="lookup_attack_technique",
            description="Look up a MITRE ATT&CK technique by id (e.g. T1110 or T1110.001): name, tactics, detection guidance, data sources, mitigations, groups and software.",
            params={"technique": _s("ATT&CK technique id like T1110 or T1110.001", required=True, max_length=20)},
            effects=Effects(reads_org=False), tier=Tier.READ, min_role=UserRole.VIEWER, models=(),
            handler=self._lookup_attack_technique, category="query",
        ))
        self._register(ToolSpec(
            name="search_attack",
            description="Search the MITRE ATT&CK knowledge base for techniques, threat groups, or software by name/alias/id.",
            params={"query": _s("Keyword, name, alias or id", required=True, max_length=200), "limit": _limit(25)},
            effects=Effects(reads_org=False), tier=Tier.READ, min_role=UserRole.VIEWER, models=(),
            handler=self._search_attack, category="query",
        ))
        self._register(ToolSpec(
            name="get_attack_coverage",
            description="For a list of ATT&CK technique ids, report how many of this organization's enabled detection rules cover each (the detection blind-spot map).",
            params={
                "techniques": ParamSpec(
                    type="array", description="ATT&CK technique ids (e.g. [\"T1110\",\"T1059.001\"])", required=True,
                    items=ParamSpec(type="string", description="ATT&CK technique id", max_length=20),
                ),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("DetectionRule",),
            handler=self._get_attack_coverage, category="query",
        ))
        self._register(ToolSpec(
            name="search_logs",
            description="Search SIEM logs by keyword across message/source fields",
            params={
                "keyword": _s("Keyword", required=True, max_length=200),
                "severity": _s("Log severity", max_length=50),
                "log_type": _s("Log type", max_length=50),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.ANALYST, models=("LogEntry",),
            handler=self._search_logs, category="query", returns_sensitive=True,
        ))
        self._register(ToolSpec(
            name="list_siem_rules",
            description="List SIEM detection rules",
            params={"status": _s("Rule status (active/disabled)", max_length=50), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.ANALYST, models=("DetectionRule",),
            handler=self._list_siem_rules, category="query",
        ))
        self._register(ToolSpec(
            name="list_entity_risks",
            description="List top high-risk UEBA entities (users/devices) by risk score",
            params={
                "risk_level": _s("Risk level", enum=SEVERITIES),
                "entity_type": _s("Entity type (user/device)", max_length=50),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("EntityProfile",),
            handler=self._list_entity_risks, category="query",
        ))
        self._register(ToolSpec(
            name="list_ueba_alerts",
            description="List UEBA behavior risk alerts",
            params={"severity": _s("Severity", enum=SEVERITIES), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("UEBARiskAlert",),
            handler=self._list_ueba_alerts, category="query",
        ))
        self._register(ToolSpec(
            name="list_vulnerabilities",
            description="List known vulnerabilities (CVE records)",
            params={
                "severity": _s("Severity", enum=SEVERITIES),
                "keyword": _s("Title keyword", max_length=200),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Vulnerability",),
            handler=self._list_vulnerabilities, category="query",
        ))
        self._register(ToolSpec(
            name="get_vulnerability",
            description="Get full detail on a vulnerability by CVE id or vulnerability UUID",
            params={"vulnerability": _s("CVE id (CVE-YYYY-NNNN) or vulnerability UUID", required=True, max_length=64)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Vulnerability",),
            handler=self._get_vulnerability, category="query",
        ))
        self._register(ToolSpec(
            name="list_forensic_cases",
            description="List DFIR forensic cases",
            params={"status": _s("Case status", max_length=50), "severity": _s("Severity", enum=SEVERITIES), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("ForensicCase",),
            handler=self._list_forensic_cases, category="query",
        ))
        self._register(ToolSpec(
            name="list_darkweb_findings",
            description="List dark web findings (credential leaks, brand mentions, etc)",
            params={
                "finding_type": _s("Finding type", max_length=50),
                "severity": _s("Severity", enum=SEVERITIES),
                "status": _s("Finding status", max_length=50),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.ANALYST, models=("DarkWebFinding",),
            handler=self._list_darkweb_findings, category="query", returns_sensitive=True,
        ))
        self._register(ToolSpec(
            name="list_hunts",
            description="List threat-hunting hypotheses (prior and active hunts)",
            params={"status": _s("Hunt status", max_length=50), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("HuntHypothesis",),
            handler=self._list_hunts, category="query",
        ))
        self._register(ToolSpec(
            name="list_hunt_findings",
            description="List findings produced by threat hunts",
            params={"severity": _s("Severity", enum=SEVERITIES), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("HuntFinding",),
            handler=self._list_hunt_findings, category="query",
        ))
        self._register(ToolSpec(
            name="list_threat_actors",
            description="List threat actors tracked in the intel database",
            params={"limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("ThreatActor",),
            handler=self._list_threat_actors, category="query",
        ))
        self._register(ToolSpec(
            name="list_threat_campaigns",
            description="List known threat campaigns",
            params={"limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("ThreatCampaign",),
            handler=self._list_threat_campaigns, category="query",
        ))
        self._register(ToolSpec(
            name="list_assets",
            description="List inventoried assets (hosts, endpoints, cloud resources). Filter by criticality to find the most important assets, or by status/type/keyword.",
            params={
                "criticality": _s("Business criticality", enum=SEVERITIES),
                "asset_type": _s("Asset type", max_length=50),
                "status": _s("Asset status", max_length=50),
                "keyword": _s("Name/hostname/IP keyword", max_length=200),
                "limit": _limit(20),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Asset",),
            handler=self._list_assets, category="query",
        ))
        self._register(ToolSpec(
            name="get_asset",
            description="Get details on a specific asset by id, name or hostname",
            params={"asset_ref": _s("Asset UUID, name or hostname", required=True, max_length=255)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Asset",),
            handler=self._get_asset, category="query",
        ))
        self._register(ToolSpec(
            name="list_remediation_executions",
            description="List recent remediation executions (actions the platform has run)",
            params={"status": _s("Execution status", max_length=50), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("RemediationExecution",),
            handler=self._list_remediation_executions, category="query",
        ))
        self._register(ToolSpec(
            name="list_decoy_interactions",
            description="List recent decoy/honeypot interactions (attacker touched deception assets)",
            params={"limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("DecoyInteraction",),
            handler=self._list_decoy_interactions, category="query",
        ))
        self._register(ToolSpec(
            name="list_phishing_campaigns",
            description="List phishing simulation campaigns and their completion status",
            params={"status": _s("Campaign status", max_length=50), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("PhishingCampaign",),
            handler=self._list_phishing_campaigns, category="query",
        ))
        self._register(ToolSpec(
            name="list_risks",
            description="List FAIR risk scenarios with loss-exposure estimates",
            params={"status": _s("Scenario status", max_length=50), "limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("RiskScenario", "FAIRAnalysis"),
            handler=self._list_risks, category="query",
        ))
        self._register(ToolSpec(
            name="list_tickets",
            description="List unified tickets across incidents, remediation, POAMs, war-room actions, case tasks",
            params={
                "source_type": _s("Ticket source type", max_length=50),
                "status": _s("Ticket status", max_length=50),
                "priority": _s("Priority", max_length=50),
                "limit": _limit(25),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER,
            models=("Incident", "RemediationTicket", "POAM", "ActionItem"),
            handler=self._list_tickets, category="query",
        ))
        self._register(ToolSpec(
            name="list_configured_integrations",
            description=(
                "List integrations installed for this organization and their health. REQUIRED READ before "
                "recommending any notification, ticket, or enrichment action; only recommend channels that are installed."
            ),
            params={},
            effects=READ, tier=Tier.READ, min_role=UserRole.ANALYST, models=("InstalledIntegration",),
            handler=self._list_configured_integrations, category="query", returns_sensitive=True,
        ))
        self._register(ToolSpec(
            name="list_compliance_frameworks",
            description="List enabled compliance frameworks with scores. Use for ANY question about NIST, FedRAMP, PCI, HIPAA, SOC2, CMMC, ISO-27001 posture.",
            params={"limit": _limit(20)},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("ComplianceFramework",),
            handler=self._list_compliance_frameworks, category="query",
        ))
        self._register(ToolSpec(
            name="list_compliance_controls",
            description="List compliance controls. `framework` matches by short_name (NIST-800-53, FedRAMP, PCI-DSS, HIPAA), full name, or UUID.",
            params={
                "framework": _s("Framework short_name, full name, or UUID", max_length=200),
                "status": _s("Control status", enum=["implemented", "not_implemented", "partial", "planned", "not_applicable"]),
                "limit": _limit(25),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("ComplianceControl", "ComplianceFramework"),
            handler=self._list_compliance_controls, category="query",
        ))
        self._register(ToolSpec(
            name="list_poams",
            description="List Plan-of-Action-&-Milestones items (compliance deficiencies being remediated).",
            params={
                "status": _s("POAM status", enum=["open", "in_progress", "completed", "closed"]),
                "priority": _s("Risk level (critical/high/moderate/low)", max_length=20),
                "limit": _limit(25),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("POAM",),
            handler=self._list_poams, category="query",
        ))
        self._register(ToolSpec(
            name="list_compliance_evidence",
            description="List evidence artifacts collected to support compliance control attestations.",
            params={"control_ref": _s("Control identifier (e.g. AC-2)", max_length=50), "limit": _limit(25)},
            effects=READ, tier=Tier.READ, min_role=UserRole.ANALYST, models=("ComplianceEvidence",),
            handler=self._list_compliance_evidence, category="query", returns_sensitive=True,
        ))
        self._register(ToolSpec(
            name="list_endpoint_agents",
            description="List enrolled endpoint agents (hosts with the PySOAR agent installed)",
            params={"status": _s("Agent status", enum=["active", "pending", "offline", "decommissioned"]), "limit": _limit(25)},
            effects=READ, tier=Tier.READ, min_role=UserRole.ANALYST, models=("EndpointAgent",),
            handler=self._list_endpoint_agents, category="query",
        ))

        # ===== WRITE =====
        self._register(ToolSpec(
            name="update_incident_status",
            description="Advance an incident through its lifecycle: open -> investigating -> containment -> eradication -> recovery -> closed. Records the transition on the incident timeline.",
            params={
                "incident_id": _s("Incident UUID", required=True, ref="Incident"),
                "status": _s("New status", required=True, enum=INCIDENT_STATUSES),
                "note": _s("Reason for the transition", max_length=2000),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Incident", "CaseTimeline"),
            handler=self._update_incident_status, category="action",
        ))
        self._register(ToolSpec(
            name="assign_incident",
            description="Assign an incident to an analyst (by email) or to yourself ('me').",
            params={
                "incident_id": _s("Incident UUID", required=True, ref="Incident"),
                "assignee": _s("User email or 'me'", required=True, max_length=255, ref_by_value=("User", "email")),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Incident", "User", "CaseTimeline"),
            handler=self._assign_incident, category="action",
        ))
        self._register(ToolSpec(
            name="add_incident_note",
            description="Append an investigation note to an incident's record (documentation / handoff).",
            params={
                "incident_id": _s("Incident UUID", required=True, ref="Incident"),
                "note": _s("Note content", required=True, max_length=8000),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Incident", "CaseNote", "CaseTimeline"),
            handler=self._add_incident_note, category="action",
        ))
        self._register(ToolSpec(
            name="update_incident_findings",
            description="Document post-incident findings: root cause, resolution, lessons learned, recommendations.",
            params={
                "incident_id": _s("Incident UUID", required=True, ref="Incident"),
                "root_cause": _s("Root cause", max_length=8000),
                "resolution": _s("Resolution", max_length=8000),
                "lessons_learned": _s("Lessons learned", max_length=8000),
                "recommendations": _s("Recommendations", max_length=8000),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Incident", "CaseTimeline"),
            handler=self._update_incident_findings, category="action",
        ))
        self._register(ToolSpec(
            name="create_alert",
            description="Create a new security alert",
            params={
                "title": _s("Title", required=True, max_length=500),
                "severity": _s("Severity", required=True, enum=SEVERITIES),
                "source": _s("Alert source", required=True, max_length=100),
                "description": _s("Description", max_length=8000),
                "category": _s("Category", max_length=100),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Alert",),
            handler=self._create_alert, category="action",
        ))
        self._register(ToolSpec(
            name="create_incident",
            description="Create a security incident (escalate an alert)",
            params={
                "title": _s("Title", required=True, max_length=500),
                "severity": _s("Severity", required=True, enum=SEVERITIES),
                "description": _s("Description", max_length=8000),
                "alert_id": _s("Alert to link", ref="Alert"),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Incident", "Alert"),
            handler=self._create_incident, category="action",
        ))
        self._register(ToolSpec(
            name="update_alert_status",
            description="Update an alert's status",
            params={
                "alert_id": _s("Alert UUID", required=True, ref="Alert"),
                "status": _s("New status", required=True, enum=["new", "open", "investigating", "resolved", "closed", "false_positive"]),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Alert",),
            handler=self._update_alert_status, category="action",
        ))
        self._register(ToolSpec(
            name="assign_alert",
            description="Assign an alert to a user",
            params={
                "alert_id": _s("Alert UUID", required=True, ref="Alert"),
                "user_id": _s("User UUID (or 'me')", required=True, ref="User"),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("Alert", "User"),
            handler=self._assign_alert, category="action",
        ))
        self._register(ToolSpec(
            name="create_war_room",
            description="Create an incident response war room",
            params={
                "name": _s("Room name", required=True, max_length=255),
                "severity": _s("Severity", required=True, enum=SEVERITIES),
                "incident_id": _s("Incident to attach", ref="Incident"),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("WarRoom", "Incident"),
            handler=self._create_war_room, category="action",
        ))
        self._register(ToolSpec(
            name="create_action_item",
            description="Create an action item in a war room",
            params={
                "room_id": _s("War room UUID", required=True, ref="WarRoom"),
                "title": _s("Title", required=True, max_length=500),
                "priority": _s("Priority", enum=SEVERITIES),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("ActionItem", "WarRoom"),
            handler=self._create_action_item, category="action",
        ))
        self._register(ToolSpec(
            name="create_ioc",
            description="Add an IOC to the threat intel database",
            params={
                "value": _s("Indicator value", required=True, max_length=2048),
                "ioc_type": _s("Indicator type", required=True, enum=["ipv4", "ipv6", "domain", "url", "hash", "email"]),
                "threat_level": _s("Threat level", enum=SEVERITIES),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("ThreatIndicator",),
            handler=self._create_ioc, category="action",
        ))
        self._register(ToolSpec(
            name="create_forensic_case",
            description="Open a new DFIR forensic case",
            params={
                "title": _s("Title", required=True, max_length=500),
                "severity": _s("Severity", required=True, enum=SEVERITIES),
                "case_type": _s(
                    "Case type (default incident_response)",
                    enum=["incident_response", "malware_analysis", "data_breach", "insider_threat", "legal_investigation", "compliance_audit"],
                ),
                "description": _s("Description", max_length=8000),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("ForensicCase",),
            handler=self._create_forensic_case, category="action",
        ))
        self._register(ToolSpec(
            name="run_threat_hunt",
            description="Run a threat hunt against this organization's logs/alerts/audit trail using a hypothesis; persists a hunt session and its findings.",
            params={
                "hypothesis": _s("Hunt hypothesis", required=True, max_length=4000),
                "timeframe_hours": ParamSpec(type="integer", description="Look-back window in hours (default 24)", minimum=1, maximum=720),
            },
            effects=WRITE, tier=Tier.WRITE, min_role=UserRole.ANALYST,
            models=("HuntHypothesis", "HuntSession", "HuntFinding", "LogEntry", "Alert", "AuditLog", "ThreatIndicator"),
            handler=self._run_threat_hunt, category="analyze",
        ))
        self._register(ToolSpec(
            name="scope_hunt",
            description="PY-HUNT-001 Phase 1: validate a hunt hypothesis against the ATT&CK KB. Returns techniques in scope with detection-rule coverage, which log sources this organization collects, and asset criticality for named hosts. Run BEFORE run_threat_hunt.",
            params={"hypothesis": _s("Hunt hypothesis / question", required=True, max_length=4000)},
            effects=READ, tier=Tier.WRITE, min_role=UserRole.ANALYST, models=("DetectionRule", "LogEntry", "Asset"),
            handler=self._scope_hunt, category="analyze",
        ))

        # ===== DESTRUCTIVE =====
        self._register(ToolSpec(
            name="remediate_incident",
            description="Orchestrate NIST containment for an incident: isolate its affected hosts and block its indicator IPs, then advance the incident to 'containment'.",
            params={
                "incident_id": _s("Incident UUID", required=True, ref="Incident"),
                "isolate_hosts": _bool("Isolate affected hosts (default true)"),
                "block_indicators": _bool("Block indicator IPs (default true)"),
            },
            effects=Effects(writes_org=True, external=True), tier=Tier.DESTRUCTIVE, min_role=UserRole.ANALYST,
            models=("Incident", "Asset", "ThreatIndicator", "TicketActivity", "CaseTimeline", "EndpointAgent", "AgentCommand"),
            handler=self._remediate_incident, category="action",
            effective_targets=self._targets_remediate_incident,
        ))
        self._register(ToolSpec(
            name="execute_playbook",
            description=(
                "Queue a playbook execution by playbook id. input_data keys must be declared in the playbook's "
                "variables (unknown keys and wrong types are rejected); organization/actor keys always come from the caller."
            ),
            params={
                "playbook_id": _s("Playbook UUID", required=True, ref="Playbook"),
                "input_data": ParamSpec(type="object", description="Playbook input variables", schema=OPEN_OBJECT_SCHEMA),
            },
            effects=Effects(writes_org=True, external=True, executes_code=True), tier=Tier.DESTRUCTIVE,
            min_role=UserRole.ANALYST, models=("Playbook", "PlaybookExecution", "Asset", "Alert", "Incident", "ThreatIndicator", "User"),
            handler=self._execute_playbook, category="action",
            effective_targets=self._targets_execute_playbook,
        ))
        self._register(ToolSpec(
            name="block_ip",
            description=(
                "Block an IP address: records it as an active blocked indicator and dispatches a host-firewall block_ip "
                "command to every enrolled IR-capable endpoint agent (mode=enforced_via_agents), or reports mode=detection_only "
                "when no eligible agent exists."
            ),
            params={
                "ip": _s("IPv4 address", required=True, max_length=45),
                "reason": _s("Reason", required=True, max_length=2000),
            },
            effects=Effects(writes_org=True, external=True), tier=Tier.DESTRUCTIVE, min_role=UserRole.ANALYST,
            models=("ThreatIndicator", "TicketActivity", "EndpointAgent", "AgentCommand", "Alert", "Incident"),
            handler=self._block_ip, category="action",
            effective_targets=self._targets_block_ip,
        ))
        self._register(ToolSpec(
            name="isolate_host",
            description=(
                "Isolate a host from the network via its enrolled endpoint agent (mode=enforced_via_agent); when the host has "
                "no enrolled agent the request is recorded only (mode=detection_only) and must be actioned manually."
            ),
            params={
                "hostname": _s("Asset hostname", required=True, max_length=255, ref_by_value=("Asset", "hostname")),
                "reason": _s("Reason", required=True, max_length=2000),
            },
            effects=Effects(writes_org=True, external=True), tier=Tier.DESTRUCTIVE, min_role=UserRole.ANALYST,
            models=("Asset", "TicketActivity", "EndpointAgent", "AgentCommand", "Alert", "Incident"),
            handler=self._isolate_host, category="action",
            effective_targets=self._targets_isolate_host,
        ))
        self._register(ToolSpec(
            name="disable_user",
            description="Disable a user account in this organization (never a superuser, never yourself).",
            params={
                "user_email": _s("User email", required=True, max_length=255, ref_by_value=("User", "email")),
                "reason": _s("Reason", required=True, max_length=2000),
            },
            effects=WRITE, tier=Tier.DESTRUCTIVE, min_role=UserRole.ANALYST, models=("User",),
            handler=self._disable_user, category="action",
            effective_targets=self._targets_disable_user,
        ))
        self._register(ToolSpec(
            name="create_remediation_ticket",
            description="Create a remediation ticket for a vulnerability, optionally linked to an incident",
            params={
                "title": _s("Title", required=True, max_length=500),
                "priority": _s("Priority", enum=SEVERITIES),
                "description": _s("Description", max_length=8000),
                "incident_id": _s("Incident to link the ticket to", ref="Incident"),
            },
            effects=WRITE, tier=Tier.DESTRUCTIVE, min_role=UserRole.ANALYST, models=("RemediationTicket", "Incident"),
            handler=self._create_remediation_ticket, category="action",
            effective_targets=self._targets_create_remediation_ticket,
        ))
        self._register(ToolSpec(
            name="execute_integration_action",
            description="Execute a configured integration action by installation id and action name (notify channels, enrich IOCs, run connector API actions).",
            params={
                "installation_id": _s("Installed integration UUID", required=True, ref="InstalledIntegration"),
                "action_name": _s("Connector action name", required=True, max_length=100),
                "input_data": ParamSpec(type="object", description="Action input", schema=OPEN_OBJECT_SCHEMA),
            },
            effects=Effects(writes_org=True, external=True), tier=Tier.DESTRUCTIVE, min_role=UserRole.ANALYST,
            models=("InstalledIntegration", "Asset", "Alert", "Incident", "ThreatIndicator", "User"),
            handler=self._execute_integration_action, category="action", returns_sensitive=True,
            effective_targets=self._targets_execute_integration_action,
        ))
        self._register(ToolSpec(
            name="simulate_attack",
            description="Run a Breach & Attack Simulation for a MITRE ATT&CK technique against a lab target",
            params={
                "technique": _s("ATT&CK technique id (e.g. T1059)", required=True, max_length=20),
                "target": _s("Target host", required=True, max_length=255),
            },
            effects=Effects(writes_org=True, external=True, executes_code=True), tier=Tier.DESTRUCTIVE,
            min_role=UserRole.ANALYST, models=("AttackSimulation", "SimulationTest", "Asset", "Alert", "Incident"),
            handler=self._simulate_attack, category="analyze",
            effective_targets=self._targets_simulate_attack,
        ))

        # ===== PRIVILEGED =====
        self._register(ToolSpec(
            name="queue_endpoint_command",
            description="Queue a live-response command on an endpoint agent. The action must be one the agent was enrolled for.",
            params={
                "agent_id": _s("Endpoint agent UUID", required=True, ref="EndpointAgent"),
                "action": _s("Command action", required=True, enum=ENDPOINT_ACTIONS),
                "payload": ParamSpec(type="object", description="Action parameters", schema=ENDPOINT_PAYLOAD_SCHEMA),
            },
            effects=Effects(writes_org=True, external=True, executes_code=True), tier=Tier.PRIVILEGED,
            min_role=UserRole.ADMIN, models=("EndpointAgent", "AgentCommand", "Asset", "Alert", "Incident", "ThreatIndicator", "User"),
            handler=self._queue_endpoint_command, category="action",
            effective_targets=self._targets_queue_endpoint_command,
        ))

        # ===== ANALYZE (read-only) =====
        self._register(ToolSpec(
            name="triage_alert",
            description="Heuristic triage of an alert (priority, confidence, recommendations)",
            params={"alert_id": _s("Alert UUID", required=True, ref="Alert")},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Alert",),
            handler=self._triage_alert, category="analyze",
        ))
        self._register(ToolSpec(
            name="enrich_ioc",
            description="Enrich an IOC with the organization's threat intel records",
            params={
                "value": _s("Indicator value", required=True, max_length=2048),
                "ioc_type": _s("Indicator type", required=True, max_length=50),
            },
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("ThreatIndicator",),
            handler=self._enrich_ioc, category="analyze",
        ))
        self._register(ToolSpec(
            name="correlate_alerts",
            description="Find alerts related to a given alert (same source IP or category)",
            params={"alert_id": _s("Alert UUID", required=True, ref="Alert")},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Alert",),
            handler=self._correlate_alerts, category="analyze",
        ))
        self._register(ToolSpec(
            name="check_ioc_matches",
            description="Check whether any active IOCs match an alert's indicators",
            params={"alert_id": _s("Alert UUID", required=True, ref="Alert")},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Alert", "ThreatIndicator"),
            handler=self._check_ioc_matches, category="analyze",
        ))
        self._register(ToolSpec(
            name="generate_incident_summary",
            description="Generate a summary of an incident",
            params={"incident_id": _s("Incident UUID", required=True, ref="Incident")},
            effects=READ, tier=Tier.READ, min_role=UserRole.VIEWER, models=("Incident",),
            handler=self._generate_incident_summary, category="analyze",
        ))

    # ==================================================================
    # QUERY handlers
    # ==================================================================

    async def _list_alerts(self, severity: Optional[str] = None, status: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(Alert), Alert).order_by(Alert.created_at.desc())
        if severity:
            q = q.where(Alert.severity == severity)
        if status:
            q = q.where(Alert.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "source": a.source, "created_at": _iso(a.created_at)}
            for a in rows
        ]

    async def _list_incidents(self, status: Optional[str] = None, severity: Optional[str] = None, limit: int = 10) -> list[dict[str, Any]]:
        q = self._scoped(select(Incident), Incident).order_by(Incident.created_at.desc())
        if status:
            q = q.where(Incident.status == status)
        if severity:
            q = q.where(Incident.severity == severity)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "created_at": _iso(i.created_at)} for i in rows]

    async def _list_iocs(self, ioc_type: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(ThreatIndicator), ThreatIndicator).where(ThreatIndicator.is_active == True).order_by(ThreatIndicator.created_at.desc())  # noqa: E712
        if ioc_type:
            q = q.where(ThreatIndicator.indicator_type == ioc_type)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{"id": i.id, "value": i.value, "type": i.indicator_type, "threat_level": i.severity, "source": i.source} for i in rows]

    async def _get_alert(self, alert_id: str) -> dict[str, Any]:
        a = await self._alert(alert_id)
        if not a:
            return {"error": "Alert not found"}
        return {
            "id": a.id, "title": a.title, "description": a.description,
            "severity": a.severity, "status": a.status, "source": a.source,
            "category": a.category, "source_ip": a.source_ip,
            "created_at": _iso(a.created_at),
        }

    async def _get_incident(self, incident_id: str) -> dict[str, Any]:
        i = await self._incident(incident_id)
        if not i:
            return {"error": "Incident not found"}
        return {
            "id": i.id, "title": i.title, "description": i.description,
            "severity": i.severity, "status": i.status, "incident_type": i.incident_type,
            "created_at": _iso(i.created_at),
        }

    async def _platform_stats(self) -> dict[str, int]:
        async def count(model: type, *where: Any) -> int:
            stmt = self._scoped(select(func.count(model.id)), model)
            for w in where:
                stmt = stmt.where(w)
            return int((await self.db.execute(stmt)).scalar() or 0)

        return {
            "total_alerts": await count(Alert),
            "open_alerts": await count(Alert, Alert.status.in_(["new", "open", "investigating"])),
            "critical_alerts": await count(Alert, Alert.severity == "critical"),
            "total_incidents": await count(Incident),
            "open_incidents": await count(Incident, Incident.status != "closed"),
        }

    async def _search_alerts(self, keyword: str, limit: int = 10) -> list[dict[str, Any]]:
        pat = f"%{keyword}%"
        q = self._scoped(select(Alert), Alert).where(or_(Alert.title.ilike(pat), Alert.description.ilike(pat)))
        rows = (await self.db.execute(q.order_by(Alert.created_at.desc()).limit(int(limit)))).scalars().all()
        return [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status} for a in rows]

    async def _list_playbooks(self, keyword: Optional[str] = None, category: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(Playbook), Playbook).where(Playbook.is_enabled == True).order_by(Playbook.name)  # noqa: E712
        if keyword:
            like = f"%{keyword}%"
            q = q.where(or_(Playbook.name.ilike(like), Playbook.description.ilike(like)))
        if category:
            q = q.where(Playbook.category == category)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": p.id, "name": p.name, "description": p.description, "category": p.category,
             "status": p.status, "trigger_type": p.trigger_type, "version": p.version}
            for p in rows
        ]

    async def _get_playbook(self, playbook_id: str) -> dict[str, Any]:
        p = await self._scoped_get("Playbook", playbook_id)
        if not p:
            return {"error": "Playbook not found"}
        try:
            steps = json.loads(p.steps) if p.steps else []
        except (TypeError, json.JSONDecodeError):
            steps = p.steps  # surface raw text rather than hide it
        return {
            "id": p.id, "name": p.name, "description": p.description,
            "category": p.category, "status": p.status,
            "trigger_type": p.trigger_type, "version": p.version,
            "is_enabled": p.is_enabled, "steps": steps,
        }

    async def _lookup_attack_technique(self, technique: str) -> dict[str, Any]:
        from src.attack.service import AttackService

        tech = await AttackService(self.db).get_technique(str(technique).upper())
        if tech is None:
            return {"error": f"ATT&CK technique {technique} not found (KB may be unsynced; run /attack/sync)"}
        return tech

    async def _search_attack(self, query: str, limit: int = 25) -> dict[str, list]:
        from src.attack.service import AttackService

        return await AttackService(self.db).search(query, limit=int(limit))

    async def _rule_technique_sets(self) -> list[set[str]]:
        """Parsed ``mitre_techniques`` of this organization's enabled detection rules."""
        rules = (await self.db.execute(self._scoped(select(DetectionRule), DetectionRule).where(DetectionRule.enabled == True))).scalars().all()  # noqa: E712
        out: list[set[str]] = []
        for r in rules:
            try:
                techs = json.loads(r.mitre_techniques or "[]")
            except (ValueError, TypeError):
                continue
            if isinstance(techs, list):
                out.append({str(t).upper() for t in techs})
        return out

    async def _coverage(self, technique_ids: list[str]) -> list[dict[str, Any]]:
        sets = await self._rule_technique_sets()
        out = []
        for tid in technique_ids:
            count = sum(1 for s in sets if tid in s)
            out.append({"technique": tid, "covered": count > 0, "rule_count": count})
        return out

    async def _get_attack_coverage(self, techniques: list[str]) -> list[dict[str, Any]]:
        if isinstance(techniques, str):
            techniques = [t.strip() for t in techniques.replace("[", "").replace("]", "").replace('"', "").split(",") if t.strip()]
        return await self._coverage([str(t).upper() for t in (techniques or [])])

    async def _search_logs(self, keyword: str, severity: Optional[str] = None, log_type: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        pat = f"%{keyword}%"
        q = self._scoped(select(LogEntry), LogEntry).where(or_(LogEntry.message.ilike(pat), LogEntry.source_name.ilike(pat)))
        if severity:
            q = q.where(LogEntry.severity == severity)
        if log_type:
            q = q.where(LogEntry.log_type == log_type)
        rows = (await self.db.execute(q.order_by(LogEntry.received_at.desc()).limit(int(limit)))).scalars().all()
        return [
            {"id": r.id, "timestamp": r.timestamp, "source_type": r.source_type, "source_name": r.source_name,
             "log_type": r.log_type, "severity": r.severity, "message": (r.message or "")[:500]}
            for r in rows
        ]

    async def _list_siem_rules(self, status: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(DetectionRule), DetectionRule).order_by(DetectionRule.updated_at.desc())
        if status:
            q = q.where(DetectionRule.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": r.id, "name": r.name, "status": r.status, "severity": r.severity, "description": (r.description or "")[:200]}
            for r in rows
        ]

    async def _list_entity_risks(self, risk_level: Optional[str] = None, entity_type: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(EntityProfile), EntityProfile).order_by(EntityProfile.risk_score.desc())
        if risk_level:
            q = q.where(EntityProfile.risk_level == risk_level)
        if entity_type:
            q = q.where(EntityProfile.entity_type == entity_type)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": p.id, "entity_type": p.entity_type, "entity_id": p.entity_id, "display_name": p.display_name,
             "risk_score": p.risk_score, "risk_level": p.risk_level, "anomaly_count_30d": p.anomaly_count_30d}
            for p in rows
        ]

    async def _list_ueba_alerts(self, severity: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(UEBARiskAlert), UEBARiskAlert).order_by(UEBARiskAlert.created_at.desc())
        if severity:
            q = q.where(UEBARiskAlert.severity == severity)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": a.id, "alert_type": a.alert_type, "severity": a.severity, "entity_profile_id": a.entity_profile_id,
             "risk_score_delta": a.risk_score_delta, "created_at": _iso(a.created_at)}
            for a in rows
        ]

    async def _list_vulnerabilities(self, severity: Optional[str] = None, keyword: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(Vulnerability), Vulnerability).order_by(Vulnerability.created_at.desc())
        if severity:
            q = q.where(Vulnerability.severity == severity)
        if keyword:
            q = q.where(Vulnerability.title.ilike(f"%{keyword}%"))
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": v.id, "cve_id": v.cve_id, "title": v.title, "severity": v.severity,
             "cvss_score": float(v.cvss_v3_score) if v.cvss_v3_score is not None else None}
            for v in rows
        ]

    async def _get_vulnerability(self, vulnerability: str) -> dict[str, Any]:
        q = self._scoped(select(Vulnerability), Vulnerability).where(or_(Vulnerability.id == vulnerability, Vulnerability.cve_id == vulnerability))
        row = (await self.db.execute(q)).scalars().first()
        if not row:
            return {"error": "Vulnerability not found"}
        return {
            "id": row.id, "cve_id": row.cve_id, "title": row.title, "severity": row.severity,
            "description": (row.description or "")[:1000],
            "cvss_score": float(row.cvss_v3_score) if row.cvss_v3_score is not None else None,
        }

    async def _list_forensic_cases(self, status: Optional[str] = None, severity: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(ForensicCase), ForensicCase).order_by(ForensicCase.created_at.desc())
        if status:
            q = q.where(ForensicCase.status == status)
        if severity:
            q = q.where(ForensicCase.severity == severity)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{"id": c.id, "title": c.title, "status": c.status, "severity": c.severity, "created_at": _iso(c.created_at)} for c in rows]

    async def _list_darkweb_findings(self, finding_type: Optional[str] = None, severity: Optional[str] = None, status: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(DarkWebFinding), DarkWebFinding).order_by(DarkWebFinding.created_at.desc())
        if finding_type:
            q = q.where(DarkWebFinding.finding_type == finding_type)
        if severity:
            q = q.where(DarkWebFinding.severity == severity)
        if status:
            q = q.where(DarkWebFinding.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": f.id, "finding_type": f.finding_type, "title": f.title, "severity": f.severity, "status": f.status, "created_at": _iso(f.created_at)}
            for f in rows
        ]

    async def _list_hunts(self, status: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(HuntHypothesis), HuntHypothesis).order_by(HuntHypothesis.created_at.desc())
        if status:
            q = q.where(HuntHypothesis.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{"id": h.id, "title": h.title, "status": h.status, "priority": h.priority, "created_at": _iso(h.created_at)} for h in rows]

    async def _list_hunt_findings(self, severity: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(HuntFinding), HuntFinding).order_by(HuntFinding.created_at.desc())
        if severity:
            q = q.where(HuntFinding.severity == severity)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{"id": f.id, "title": f.title, "severity": f.severity, "session_id": f.session_id, "created_at": _iso(f.created_at)} for f in rows]

    async def _list_threat_actors(self, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(ThreatActor), ThreatActor).order_by(ThreatActor.created_at.desc()).limit(int(limit))
        rows = (await self.db.execute(q)).scalars().all()
        return [{"id": a.id, "name": a.name, "aliases": a.aliases, "motivation": a.primary_motivation, "sophistication": a.sophistication} for a in rows]

    async def _list_threat_campaigns(self, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(ThreatCampaign), ThreatCampaign).order_by(ThreatCampaign.created_at.desc()).limit(int(limit))
        rows = (await self.db.execute(q)).scalars().all()
        return [{"id": c.id, "name": c.name, "status": c.status, "first_seen": _iso(c.first_observed)} for c in rows]

    async def _list_assets(self, criticality: Optional[str] = None, asset_type: Optional[str] = None, status: Optional[str] = None, keyword: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        crit_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        q = self._scoped(select(Asset), Asset)
        if criticality:
            q = q.where(Asset.criticality == str(criticality).lower())
        if asset_type:
            q = q.where(Asset.asset_type == asset_type)
        if status:
            q = q.where(Asset.status == status)
        if keyword:
            pat = f"%{keyword}%"
            q = q.where(or_(Asset.name.ilike(pat), Asset.hostname.ilike(pat), Asset.ip_address.ilike(pat)))
        rows = (await self.db.execute(q.limit(500))).scalars().all()
        rows = sorted(rows, key=lambda a: crit_rank.get((a.criticality or "").lower(), 9))[: int(limit)]
        return [
            {"id": a.id, "name": a.name, "hostname": a.hostname, "asset_type": a.asset_type,
             "status": a.status, "criticality": a.criticality, "ip_address": a.ip_address}
            for a in rows
        ]

    async def _find_asset(self, ref: str) -> Optional[Asset]:
        q = self._scoped(select(Asset), Asset).where(or_(Asset.id == ref, Asset.name == ref, func.lower(Asset.hostname) == ref.lower()))
        return (await self.db.execute(q)).scalars().first()

    async def _get_asset(self, asset_ref: str) -> dict[str, Any]:
        row = await self._find_asset(str(asset_ref))
        if not row:
            return {"error": "Asset not found"}
        return {
            "id": row.id, "name": row.name, "hostname": row.hostname, "asset_type": row.asset_type,
            "status": row.status, "ip_address": row.ip_address, "fqdn": row.fqdn, "mac_address": row.mac_address,
        }

    async def _list_remediation_executions(self, status: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(RemediationExecution), RemediationExecution).order_by(RemediationExecution.created_at.desc())
        if status:
            q = q.where(RemediationExecution.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": e.id, "status": e.status, "trigger_source": e.trigger_source, "trigger_id": e.trigger_id,
             "approval_status": e.approval_status, "started_at": _iso(e.started_at), "completed_at": _iso(e.completed_at)}
            for e in rows
        ]

    async def _list_decoy_interactions(self, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(DecoyInteraction), DecoyInteraction).order_by(DecoyInteraction.created_at.desc()).limit(int(limit))
        rows = (await self.db.execute(q)).scalars().all()
        return [
            {"id": i.id, "decoy_id": i.decoy_id, "interaction_type": i.interaction_type, "source_ip": i.source_ip,
             "source_hostname": i.source_hostname, "protocol": i.protocol, "created_at": _iso(i.created_at)}
            for i in rows
        ]

    async def _list_phishing_campaigns(self, status: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(PhishingCampaign), PhishingCampaign).order_by(PhishingCampaign.created_at.desc())
        if status:
            q = q.where(PhishingCampaign.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{"id": c.id, "name": c.name, "status": c.status, "created_at": _iso(c.created_at)} for c in rows]

    async def _list_risks(self, status: Optional[str] = None, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(RiskScenario), RiskScenario).order_by(RiskScenario.created_at.desc())
        if status:
            q = q.where(RiskScenario.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        out = []
        for r in rows:
            # ALE lives on the latest FAIR analysis of the scenario, not the scenario row.
            aq = self._scoped(select(FAIRAnalysis), FAIRAnalysis).where(FAIRAnalysis.scenario_id == r.id).order_by(FAIRAnalysis.created_at.desc()).limit(1)
            analysis = (await self.db.execute(aq)).scalars().first()
            out.append({
                "id": r.id, "name": r.name, "status": r.status, "asset_name": r.asset_name,
                "asset_value_usd": r.asset_value_usd, "loss_type": r.loss_type,
                "annualized_loss_expectancy": analysis.ale_mean if analysis else None,
                "analysis_id": analysis.id if analysis else None,
            })
        return out

    async def _list_tickets(self, source_type: Optional[str] = None, status: Optional[str] = None, priority: Optional[str] = None, limit: int = 25) -> dict[str, Any]:
        from src.tickethub.engine import TicketAggregator

        result = await TicketAggregator(self.db).get_unified_tickets(
            organization_id=self.ctx.org_id,
            source_types=[source_type] if source_type else None,
            priority=priority,
            size=int(limit),
        )
        items = result.get("tickets") or result.get("items") or []
        if status:
            items = [t for t in items if (t.get("status") or "").lower() == status.lower()]
        return {"total": len(items), "tickets": items[: int(limit)]}

    async def _list_configured_integrations(self) -> dict[str, Any]:
        """Installed integrations for this org. Non-admins see only id + health."""
        q = self._scoped(select(InstalledIntegration), InstalledIntegration).order_by(InstalledIntegration.connector_id)
        rows = (await self.db.execute(q)).scalars().all()
        is_admin = self.ctx.role is UserRole.ADMIN
        items = []
        for ii in rows:
            entry: dict[str, Any] = {"id": ii.id, "health": ii.health_status or "unknown"}
            if is_admin:
                entry.update({
                    "connector_id": ii.connector_id,
                    "enabled": ii.status == "active",
                    "status": ii.status,
                    "last_health_check": _iso(ii.last_health_check),
                })
            items.append(entry)
        return {"total": len(items), "integrations": items}

    async def _list_compliance_frameworks(self, limit: int = 20) -> list[dict[str, Any]]:
        q = self._scoped(select(ComplianceFramework), ComplianceFramework).where(ComplianceFramework.is_enabled == True)  # noqa: E712
        rows = (await self.db.execute(q.order_by(ComplianceFramework.compliance_score.desc()).limit(int(limit)))).scalars().all()
        return [
            {"id": f.id, "name": f.name, "short_name": f.short_name, "version": f.version, "authority": f.authority,
             "total_controls": f.total_controls, "implemented_controls": f.implemented_controls,
             "compliance_score": float(f.compliance_score) if f.compliance_score is not None else 0.0, "status": f.status}
            for f in rows
        ]

    async def _list_compliance_controls(self, framework: Optional[str] = None, status: Optional[str] = None, limit: int = 25) -> Any:
        q = self._scoped(select(ComplianceControl), ComplianceControl)
        if framework:
            norm = framework.lower().replace(" ", "").replace("-", "").replace("_", "")
            fw_rows = (await self.db.execute(self._scoped(select(ComplianceFramework), ComplianceFramework))).scalars().all()
            match_id = None
            for fw in fw_rows:
                if fw.id == framework:
                    match_id = fw.id
                    break
                for candidate in (fw.name or "", fw.short_name or ""):
                    if candidate.lower().replace(" ", "").replace("-", "").replace("_", "") == norm:
                        match_id = fw.id
                        break
                if match_id:
                    break
            if not match_id:
                return {"warning": f"No framework matched '{framework}'. Call list_compliance_frameworks first.", "controls": []}
            q = q.where(ComplianceControl.framework_id == match_id)
        if status:
            q = q.where(ComplianceControl.status == status)
        rows = (await self.db.execute(q.order_by(ComplianceControl.priority.asc()).limit(int(limit)))).scalars().all()
        return [
            {"id": c.id, "control_id": c.control_id, "title": c.title, "control_family": c.control_family,
             "priority": c.priority, "status": c.status,
             "implementation_status": float(c.implementation_status) if c.implementation_status is not None else 0.0}
            for c in rows
        ]

    async def _list_poams(self, status: Optional[str] = None, priority: Optional[str] = None, limit: int = 25) -> list[dict[str, Any]]:
        q = self._scoped(select(POAM), POAM).order_by(POAM.created_at.desc())
        if status:
            q = q.where(POAM.status == status)
        if priority:
            q = q.where(POAM.risk_level == priority)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": p.id, "weakness_name": p.weakness_name, "control_id_ref": p.control_id_ref, "status": p.status,
             "risk_level": p.risk_level,
             "residual_risk_rating": float(p.residual_risk_rating) if p.residual_risk_rating is not None else None,
             "scheduled_completion_date": _iso(p.scheduled_completion_date)}
            for p in rows
        ]

    async def _list_compliance_evidence(self, control_ref: Optional[str] = None, limit: int = 25) -> list[dict[str, Any]]:
        q = self._scoped(select(ComplianceEvidence), ComplianceEvidence).order_by(ComplianceEvidence.collected_at.desc())
        if control_ref:
            q = q.where(ComplianceEvidence.control_id_ref == control_ref)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": e.id, "control_id_ref": e.control_id_ref, "evidence_type": e.evidence_type, "title": e.title,
             "source_system": e.source_system, "is_automated": e.is_automated, "is_valid": e.is_valid,
             "collected_at": _iso(e.collected_at)}
            for e in rows
        ]

    async def _list_endpoint_agents(self, status: Optional[str] = None, limit: int = 25) -> list[dict[str, Any]]:
        q = self._scoped(select(EndpointAgent), EndpointAgent).order_by(EndpointAgent.last_heartbeat_at.desc().nullslast())
        if status:
            q = q.where(EndpointAgent.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [
            {"id": a.id, "hostname": a.hostname, "display_name": a.display_name, "os_type": a.os_type,
             "os_version": a.os_version, "status": a.status, "ip_address": a.ip_address,
             "last_heartbeat_at": _iso(a.last_heartbeat_at)}
            for a in rows
        ]

    # ==================================================================
    # WRITE handlers (NIST 800-61 lifecycle + record creation)
    # ==================================================================

    async def _update_incident_status(self, incident_id: str, status: str, note: Optional[str] = None) -> dict[str, Any]:
        inc = await self._incident(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        new = str(status).lower().strip()
        if new not in INCIDENT_STATUSES:
            return {"error": f"'{status}' is not a valid status. Valid: {sorted(INCIDENT_STATUSES)}"}
        old = inc.status
        inc.status = new
        self._add_timeline(inc, "status_change", f"Status: {old} -> {new}", description=note, old_value=old, new_value=new)
        await self.db.commit()
        return {"incident_id": inc.id, "old_status": old, "new_status": new, "note": note}

    async def _resolve_user_ref(self, ref: str) -> Optional[User]:
        """Accept a policy-resolved user id, or (fallback) an email / 'me'."""
        ref = str(ref).strip()
        if ref.lower() == "me":
            return await self._scoped_get("User", self.ctx.actor_user_id) if self.ctx.actor_user_id else None
        user = await self._scoped_get("User", ref)
        if user is None and "@" in ref:
            rows = await self.resolve_by_value("User", "email", ref)
            user = rows[0] if len(rows) == 1 else None
        return user

    async def _assign_incident(self, incident_id: str, assignee: str) -> dict[str, Any]:
        inc = await self._incident(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        user = await self._resolve_user_ref(assignee)
        if not user:
            return {"error": f"Could not resolve assignee '{assignee}' to a user in this organization"}
        inc.assigned_to = user.id
        self._add_timeline(inc, "assignment", f"Assigned to {user.email}", new_value=user.email)
        await self.db.commit()
        return {"incident_id": inc.id, "assigned_to": user.email}

    async def _add_incident_note(self, incident_id: str, note: str) -> dict[str, Any]:
        inc = await self._incident(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        author = self._note_author_fields()
        if author is None:
            return {"error": "autonomous_notes_require_agent_author_column"}
        n = CaseNote(incident_id=inc.id, content=str(note), note_type="investigation", is_internal=True, **author)
        self.db.add(n)
        self._add_timeline(inc, "note", "Investigation note added")
        await self.db.commit()
        return {"incident_id": inc.id, "note_id": n.id, "status": "added", "author": author}

    def _note_author_fields(self) -> Optional[dict[str, str]]:
        """Author attribution for a CaseNote: the human actor, or the SOC agent
        when the model carries an agent-author column. Never another user."""
        if self.ctx.actor_user_id:
            return {"author_id": self.ctx.actor_user_id}
        if self.ctx.soc_agent_id and hasattr(CaseNote, "created_by_agent_id"):
            return {"created_by_agent_id": self.ctx.soc_agent_id}
        return None

    async def _update_incident_findings(
        self,
        incident_id: str,
        root_cause: Optional[str] = None,
        resolution: Optional[str] = None,
        lessons_learned: Optional[str] = None,
        recommendations: Optional[str] = None,
    ) -> dict[str, Any]:
        inc = await self._incident(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        if self._note_author_fields() is None:
            # Findings are analyst attestations; without an attributable author they are not recorded.
            return {"error": "autonomous_notes_require_agent_author_column"}
        updated = []
        for field_name, val in (("root_cause", root_cause), ("resolution", resolution), ("lessons_learned", lessons_learned), ("recommendations", recommendations)):
            if val:
                setattr(inc, field_name, str(val))
                updated.append(field_name)
        if not updated:
            return {"error": "No findings provided to update"}
        self._add_timeline(inc, "findings", f"Findings updated: {', '.join(updated)}")
        await self.db.commit()
        return {"incident_id": inc.id, "updated_fields": updated}

    async def _create_alert(self, title: str, severity: str, source: str, description: str = "", category: str = "") -> dict[str, Any]:
        from src.services.automation import AutomationService

        alert = Alert(
            title=title, description=description, severity=severity, source=source, status="new",
            category=category or None, organization_id=self.ctx.org_id,
        )
        self.db.add(alert)
        await self.db.flush()
        await AutomationService(self.db).on_alert_created(alert, organization_id=self.ctx.org_id, created_by=self.ctx.actor_user_id)
        return {"id": alert.id, "created": True}

    async def _create_incident(self, title: str, severity: str, description: str = "", alert_id: Optional[str] = None) -> dict[str, Any]:
        from src.services.automation import AutomationService

        if alert_id and await self._alert(alert_id) is None:
            return {"error": "Alert not found"}
        incident = Incident(
            title=title, description=description, severity=severity, status="open", incident_type="other",
            organization_id=self.ctx.org_id,
        )
        self.db.add(incident)
        await self.db.flush()
        await AutomationService(self.db).on_incident_created(incident, organization_id=self.ctx.org_id, created_by=self.ctx.actor_user_id)
        return {"id": incident.id, "created": True, "linked_alert_id": alert_id}

    async def _update_alert_status(self, alert_id: str, status: str) -> dict[str, Any]:
        alert = await self._alert(alert_id)
        if not alert:
            return {"error": "Alert not found"}
        alert.status = status
        await self.db.flush()
        return {"id": alert.id, "new_status": status}

    async def _assign_alert(self, alert_id: str, user_id: str) -> dict[str, Any]:
        alert = await self._alert(alert_id)
        if not alert:
            return {"error": "Alert not found"}
        user = await self._resolve_user_ref(user_id)
        if not user:
            return {"error": "User not found in this organization"}
        alert.assigned_to = user.id
        await self.db.flush()
        return {"id": alert.id, "assigned_to": user.id}

    async def _create_war_room(self, name: str, severity: str, incident_id: Optional[str] = None) -> dict[str, Any]:
        if incident_id and await self._incident(incident_id) is None:
            return {"error": "Incident not found"}
        room = WarRoom(
            organization_id=self.ctx.org_id, name=name, severity_level=severity, room_type="incident_response",
            status="active", created_by=self._actor_id(), incident_id=incident_id,
        )
        self.db.add(room)
        await self.db.flush()
        return {"id": room.id, "name": name}

    async def _create_action_item(self, room_id: str, title: str, priority: str = "medium") -> dict[str, Any]:
        room = await self._scoped_get("WarRoom", room_id)
        if room is None:
            return {"error": "War room not found"}
        action = ActionItem(
            organization_id=self.ctx.org_id, room_id=room.id, title=title, assigned_by=self._actor_id(),
            priority=priority, status="pending",
        )
        self.db.add(action)
        await self.db.flush()
        return {"id": action.id, "title": title}

    async def _create_ioc(self, value: str, ioc_type: str, threat_level: str = "medium") -> dict[str, Any]:
        ioc = ThreatIndicator(
            value=value, indicator_type=ioc_type, severity=threat_level, is_active=True, is_whitelisted=False,
            source="agent_manual", confidence=70, organization_id=self.ctx.org_id,
        )
        self.db.add(ioc)
        await self.db.flush()
        return {"id": ioc.id, "value": value, "type": ioc_type}

    async def _create_forensic_case(
        self, title: str, severity: str, case_type: str = "incident_response", description: str = ""
    ) -> dict[str, Any]:
        # ForensicCase.case_number is NOT NULL and unique; the DFIR endpoint takes
        # it from the analyst, so an agent-opened case mints its own: date-stamped
        # plus a random suffix (no sequence lookup, no cross-tenant counter).
        case_number = f"FC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
        case = ForensicCase(
            case_number=case_number,
            title=title, severity=severity, status="open", case_type=case_type, description=description,
            organization_id=self.ctx.org_id, created_by=self._actor_id(),
        )
        self.db.add(case)
        await self.db.commit()
        await self.db.refresh(case)
        return {"id": case.id, "title": case.title, "severity": case.severity, "status": case.status}

    # ==================================================================
    # DESTRUCTIVE / PRIVILEGED handlers
    # ==================================================================

    async def _remediate_incident(self, incident_id: str, isolate_hosts: bool = True, block_indicators: bool = True) -> dict[str, Any]:
        """NIST short-term containment: isolate affected hosts + block indicator
        IPs, then advance the incident to 'containment'.

        Every sub-action goes through ``_sub_call`` so it is separately
        policy-checked, rate-charged and audited. A denied sub-call aborts the
        composite and the result says exactly what completed before the abort.
        Honest when there is nothing to act on and about enforcement mode.
        """
        inc = await self._incident(incident_id)
        if not inc:
            return {"error": "Incident not found"}

        reason = f"Containment for incident {inc.id}: {inc.title}"
        completed: list[dict[str, Any]] = []
        hosts_isolated: list[str] = []
        indicators_blocked: list[str] = []
        enforcement: dict[str, dict[str, str]] = {"hosts": {}, "ips": {}}

        planned: list[tuple[str, str, dict[str, Any]]] = []
        if isolate_hosts in (True, "true", "True", 1):
            for host in self._parse_json_list(inc.affected_systems):
                planned.append(("isolate_host", host, {"hostname": host, "reason": reason}))
        if block_indicators in (True, "true", "True", 1):
            for ind in self._parse_json_list(inc.indicators):
                if _IPV4_RE.match(ind):
                    planned.append(("block_ip", ind, {"ip": ind, "reason": reason}))
        planned = planned[:MAX_COMPOSITE_TARGETS]

        for tool, value, args in planned:
            try:
                res = await self._sub_call(self.ctx, tool, args)
            except PermissionError as exc:
                code = str(exc) or "denied"
                logger.warning("composite_sub_call_denied", tool=tool, parent="remediate_incident", reason=code, incident_id=inc.id)
                self._add_timeline(
                    inc, "remediation", "Containment aborted",
                    description=f"{tool} on {value} was denied ({code}); completed before abort: {len(completed)} action(s).",
                )
                await self.db.commit()
                return {
                    "incident_id": inc.id,
                    "completed": completed,
                    "aborted_at": tool,
                    "aborted_target": value,
                    "reason": code,
                    "hosts_isolated": hosts_isolated,
                    "indicators_blocked": indicators_blocked,
                    "enforcement": enforcement,
                    "new_status": inc.status,
                }
            if not isinstance(res, dict) or res.get("error"):
                completed.append({"tool": tool, "target": value, "result": res})
                continue
            completed.append({"tool": tool, "target": value, "mode": res.get("mode"), "result": res})
            if tool == "isolate_host":
                hosts_isolated.append(value)
                enforcement["hosts"][value] = str(res.get("mode"))
            else:
                indicators_blocked.append(value)
                enforcement["ips"][value] = str(res.get("mode"))

        acted = bool(hosts_isolated or indicators_blocked)
        old = inc.status
        if acted and inc.status in ("open", "investigating"):
            inc.status = "containment"

        if acted:
            enforced_hosts = [h for h, m in enforcement["hosts"].items() if m == "enforced_via_agent"]
            enforced_ips = [i for i, m in enforcement["ips"].items() if m == "enforced_via_agents"]
            summary = (
                f"Containment initiated: {len(hosts_isolated)} host isolation(s) {hosts_isolated} "
                f"({len(enforced_hosts)} enforced via endpoint agent, {len(hosts_isolated) - len(enforced_hosts)} recorded only - no enrolled agent), "
                f"{len(indicators_blocked)} indicator IP block(s) {indicators_blocked} "
                f"({len(enforced_ips)} enforced via endpoint agents, {len(indicators_blocked) - len(enforced_ips)} detection-only). "
                f"Incident moved {old} -> {inc.status}."
            )
        else:
            summary = (
                "No containable artifacts on this incident (no affected_systems hosts and no indicator IPs). "
                "Triage it and document affected systems first, or remediate manually."
            )
        self._add_timeline(inc, "remediation", "Containment actions executed", description=summary)
        await self.db.commit()
        return {
            "incident_id": inc.id,
            "completed": completed,
            "hosts_isolated": hosts_isolated,
            "indicators_blocked": indicators_blocked,
            "enforcement": enforcement,
            "new_status": inc.status,
            "summary": summary,
        }

    @staticmethod
    def _declared_playbook_inputs(pb: Playbook) -> Optional[dict[str, Any]]:
        """``Playbook.variables`` parsed as the declared-input map, or ``None`` when undeclared."""
        if not pb.variables:
            return None
        try:
            declared = json.loads(pb.variables)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("playbook variables are not valid JSON; fix the playbook before executing it") from exc
        if not isinstance(declared, dict) or not declared:
            return None
        return declared

    @staticmethod
    def _validate_playbook_input(declared: dict[str, Any], data: dict[str, Any]) -> None:
        """Reject keys the playbook does not declare and values of the wrong type.

        A declaration is either a default value (its Python type is the
        contract) or a ``{"type": <json type>, ...}`` descriptor.
        """
        unknown = sorted(k for k in data if k not in declared)
        if unknown:
            raise ValueError(f"input_data has keys the playbook does not declare: {unknown}")
        for key, value in data.items():
            decl = declared[key]
            expected: Optional[tuple[type, ...]] = None
            if isinstance(decl, dict) and isinstance(decl.get("type"), str):
                expected = _JSON_TYPE_CHECKS.get(decl["type"].lower())
            elif isinstance(decl, bool):
                expected = (bool,)
            elif isinstance(decl, int):
                expected = (int,)
            elif isinstance(decl, float):
                expected = (int, float)
            elif isinstance(decl, str):
                expected = (str,)
            elif isinstance(decl, list):
                expected = (list,)
            if expected is None or value is None:
                continue
            if isinstance(value, bool) and bool not in expected:
                raise ValueError(f"input_data.{key}: expected {expected[0].__name__}, got boolean")
            if not isinstance(value, expected):
                raise ValueError(f"input_data.{key}: expected {expected[0].__name__}, got {type(value).__name__}")

    async def _execute_playbook(self, playbook_id: str, input_data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        from src.playbooks.tasks import run_playbook_execution

        pb = await self._scoped_get("Playbook", playbook_id)
        if not pb:
            return {"error": "Playbook not found"}
        supplied = dict(input_data or {})
        # Reserved keys are always taken from the context, never from the model.
        for key in PLAYBOOK_RESERVED_KEYS:
            supplied.pop(key, None)
        declared = self._declared_playbook_inputs(pb)
        if declared is not None:
            self._validate_playbook_input(declared, supplied)
        data = dict(supplied)
        data["organization_id"] = self.ctx.org_id
        data["actor_user_id"] = self.ctx.actor_user_id
        execution = PlaybookExecution(
            playbook_id=pb.id,
            organization_id=self.ctx.org_id,
            status=ExecutionStatus.PENDING.value if hasattr(ExecutionStatus, "PENDING") else "pending",
            input_data=json.dumps(data),
            trigger_source="agent",
            triggered_by=self._actor_id(),
            triggered_by_user_id=self.ctx.actor_user_id,
        )
        self.db.add(execution)
        # Commit (not just flush) before dispatch: the worker reads this row
        # from its own connection, so it must be durable first.
        await self.db.commit()
        run_playbook_execution.delay(execution.id)
        return {"execution_id": execution.id, "playbook": pb.name, "status": "queued", "input_keys": sorted(supplied)}

    async def _dispatchable_agents(self) -> list[EndpointAgent]:
        """Enrolled endpoint agents in this org that may receive a command."""
        q = self._scoped(select(EndpointAgent), EndpointAgent).where(EndpointAgent.status.in_(_DISPATCHABLE_AGENT_STATES))
        return list((await self.db.execute(q)).scalars().all())

    async def _block_ip(self, ip: str, reason: str) -> dict[str, Any]:
        """Detection layer (active blocked IOC) + enforcement layer (host-firewall
        ``block_ip`` command on every enrolled IR-capable endpoint agent, the
        same dispatch the remediation engine's FirewallBlockExecutor uses).
        ``mode`` states honestly which layers took effect."""
        from src.agents.capabilities import capability_allows
        from src.agents.service import AgentService, AgentServiceError

        ioc = ThreatIndicator(
            value=ip, indicator_type="ipv4", severity="high", is_active=True, is_whitelisted=False,
            source="agent_block", confidence=80, context={"reason": reason, "action": "block_ip"},
            organization_id=self.ctx.org_id,
        )
        self.db.add(ioc)
        await self.db.flush()

        commands: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        svc = AgentService(self.db)
        for agent in await self._dispatchable_agents():
            if not capability_allows(list(agent.capabilities or []), "block_ip"):
                continue  # not IR-enrolled: ineligible, not a failure
            try:
                # approval_override: the policy/approval flow already authorized this destructive call.
                cmd = await svc.issue_command(
                    agent=agent, action="block_ip", payload={"ip": ip, "reason": reason},
                    issued_by=self.ctx.actor_user_id, approval_override=True,
                )
                commands.append({"agent_id": agent.id, "hostname": agent.hostname, "command_id": cmd.id, "command_status": cmd.status})
            except AgentServiceError as exc:
                rejected.append({"agent_id": agent.id, "hostname": agent.hostname, "error": str(exc)})

        if commands:
            mode = "enforced_via_agents"
            note = f"block_ip queued to {len(commands)} endpoint agent(s); per-host firewall rules tagged pysoar-block-{ip}"
        else:
            mode = "detection_only"
            note = (
                "Recorded as an active blocked indicator for detection/correlation only: no enrolled, "
                "IR-capable endpoint agent is available to enforce a host-firewall block. Block it at the perimeter manually."
            )
        self.db.add(TicketActivity(
            source_type="remediation", source_id=ip, activity_type="block_ip",
            description=f"IP {ip} block ({mode}) by agent. Reason: {reason}",
            actor_id=self._actor_id(), organization_id=self.ctx.org_id,
            extra_metadata={"ioc_id": ioc.id, "mode": mode, "agent_commands": commands, "rejected_agents": rejected},
        ))
        await self.db.flush()
        return {
            "ip": ip, "status": "blocked" if commands else "recorded", "mode": mode, "ioc_id": ioc.id,
            "agent_commands": commands, "rejected_agents": rejected, "note": note, "reason": reason,
        }

    async def _agent_for_host(self, asset: Optional[Asset], hostname: str) -> Optional[EndpointAgent]:
        """The enrolled endpoint agent for ``asset`` (or the raw hostname), if any."""
        names = {n.lower() for n in (hostname, getattr(asset, "hostname", None), getattr(asset, "name", None), getattr(asset, "fqdn", None)) if n}
        if not names:
            return None
        q = self._scoped(select(EndpointAgent), EndpointAgent).where(
            EndpointAgent.status.in_(_DISPATCHABLE_AGENT_STATES), func.lower(EndpointAgent.hostname).in_(sorted(names)),
        ).order_by(EndpointAgent.last_heartbeat_at.desc().nullslast())
        return (await self.db.execute(q)).scalars().first()

    async def _isolate_host(self, hostname: str, reason: str) -> dict[str, Any]:
        """Network isolation through the host's enrolled endpoint agent. With no
        agent the request is recorded only (``mode=detection_only``) - nothing is
        simulated."""
        from src.agents.service import AgentService, AgentServiceError

        # The policy resolves ``hostname`` to an in-org Asset id; accept either.
        asset = await self._find_asset(str(hostname))
        label = (asset.hostname or asset.name) if asset else str(hostname)
        agent = await self._agent_for_host(asset, str(hostname))

        command_id: Optional[str] = None
        command_status: Optional[str] = None
        error: Optional[str] = None
        if agent is not None:
            try:
                # approval_override: the policy/approval flow already authorized this destructive call.
                cmd = await AgentService(self.db).issue_command(
                    agent=agent, action="isolate_host", payload={"hostname": label, "reason": reason},
                    issued_by=self.ctx.actor_user_id, approval_override=True,
                )
                command_id, command_status = cmd.id, cmd.status
            except AgentServiceError as exc:
                error = str(exc)

        if command_id:
            mode, status = "enforced_via_agent", "isolation_queued"
            note = f"isolate_host command {command_id} queued to endpoint agent {agent.id} ({agent.hostname})"  # type: ignore[union-attr]
        elif agent is not None:
            mode, status = "detection_only", "recorded"
            note = f"Endpoint agent {agent.hostname} rejected isolate_host: {error}. Isolation request recorded only; isolate manually."
        else:
            mode, status = "detection_only", "recorded"
            note = (
                f"No enrolled endpoint agent for host {label}: isolation request recorded as a remediation activity only. "
                "Enroll the PySOAR agent with the isolate_host capability or isolate the host manually."
            )
        self.db.add(TicketActivity(
            source_type="remediation", source_id=asset.id if asset else label, activity_type="isolate_host",
            description=f"Host {label} isolation ({mode}) by agent. Reason: {reason}",
            actor_id=self._actor_id(), organization_id=self.ctx.org_id,
            extra_metadata={
                "asset_id": asset.id if asset else None, "mode": mode, "agent_id": agent.id if agent else None,
                "command_id": command_id, "command_status": command_status, "error": error,
            },
        ))
        await self.db.flush()
        return {
            "hostname": label, "asset_id": asset.id if asset else None, "status": status, "mode": mode,
            "agent_id": agent.id if agent else None, "command_id": command_id, "command_status": command_status,
            "note": note, "reason": reason,
        }

    async def _disable_user(self, user_email: str, reason: str) -> dict[str, Any]:
        user = await self._resolve_user_ref(user_email)
        if not user:
            return {"error": "User not found in this organization"}
        if bool(getattr(user, "is_superuser", False)):
            return {"error": "Refusing to disable a superuser account"}
        if self.ctx.actor_user_id and user.id == self.ctx.actor_user_id:
            return {"error": "Refusing to disable the acting user's own account"}
        if not user.is_active:
            return {"user_email": user.email, "user_id": user.id, "status": "already_disabled", "reason": reason}
        user.is_active = False
        await self.db.flush()
        return {"user_email": user.email, "user_id": user.id, "status": "disabled", "reason": reason}

    async def _create_remediation_ticket(
        self, title: str, priority: str = "medium", description: str = "", incident_id: Optional[str] = None,
    ) -> dict[str, Any]:
        tags: list[str] = []
        if incident_id:
            inc = await self._incident(incident_id)
            if inc is None:
                return {"error": "Incident not found"}
            tags.append(f"incident:{inc.id}")
        ticket = RemediationTicket(
            title=title, description=description, priority=priority, status="open", remediation_type="manual",
            organization_id=self.ctx.org_id, tags=tags,
        )
        self.db.add(ticket)
        await self.db.flush()
        return {"id": ticket.id, "title": title, "incident_id": incident_id}

    async def _execute_integration_action(self, installation_id: str, action_name: str, input_data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        from src.integrations.engine import ActionExecutor

        integration = await self._scoped_get("InstalledIntegration", installation_id)
        if not integration:
            return {"success": False, "error": "Integration installation not found"}
        if integration.status != "active":
            return {"success": False, "error": "Integration is not active"}
        execution_result = await ActionExecutor().execute_action(
            installation_id=integration.id,
            action_name=action_name,
            input_data=dict(input_data or {}),
            triggered_by="agent_tool",
        )
        return {"installation_id": integration.id, "action_name": action_name, "execution_result": execution_result}

    async def _simulate_attack(self, technique: str, target: str) -> dict[str, Any]:
        from src.simulation.engine import SimulationOrchestrator

        if not self.ctx.actor_user_id:
            # attack_simulations.created_by is a users FK.
            return {"error": "simulate_attack requires a user actor"}
        orchestrator = SimulationOrchestrator(self.db)
        simulation = await orchestrator.create_simulation(
            name=f"Agent-initiated simulation {technique}",
            sim_type="atomic_test",
            techniques=[technique],
            scope={"target_host": target} if target else {},
            target_environment="lab",
            created_by=self.ctx.actor_user_id,
            organization_id=self.ctx.org_id,
            description=f"Agent tool launched an atomic MITRE ATT&CK simulation for technique {technique} against {target}.",
        )
        await orchestrator.start_simulation(simulation.id)
        tests = (await self.db.execute(self._scoped(select(SimulationTest), SimulationTest).where(SimulationTest.simulation_id == simulation.id))).scalars().all()
        results = [await orchestrator._execute_test(test) for test in tests]
        await orchestrator.finalize_simulation(simulation.id)
        await self.db.refresh(simulation)
        return {
            "simulation_id": simulation.id,
            "status": simulation.status,
            "total_tests": len(results),
            "passed_tests": simulation.passed_tests,
            "failed_tests": simulation.failed_tests,
            "blocked_tests": simulation.blocked_tests,
            "detection_rate": simulation.detection_rate,
            "tests": results,
        }

    async def _queue_endpoint_command(self, agent_id: str, action: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Queue a live-response command; hash-chains into the command ledger."""
        from src.agents.capabilities import capability_allows

        agent = await self._scoped_get("EndpointAgent", agent_id)
        if agent is None:
            return {"error": "Endpoint agent not found"}
        if action not in ENDPOINT_ACTIONS:
            return {"error": f"'{action}' is not a known endpoint action"}
        if not capability_allows(list(agent.capabilities or []), action):
            return {"error": f"Agent {agent.hostname} is not enrolled for action '{action}'"}
        payload_dict = dict(payload or {})
        prev_hash = agent.last_command_hash or ""
        body = json.dumps({"agent_id": agent.id, "action": action, "payload": payload_dict}, sort_keys=True)
        cmd_hash = hashlib.sha256(body.encode()).hexdigest()
        chain = hashlib.sha256((prev_hash + cmd_hash).encode()).hexdigest()
        cmd = AgentCommand(
            agent_id=agent.id, action=action, payload=payload_dict, command_hash=cmd_hash,
            prev_hash=prev_hash or None, chain_hash=chain, status="queued", organization_id=self.ctx.org_id,
        )
        self.db.add(cmd)
        agent.last_command_hash = chain
        await self.db.commit()
        await self.db.refresh(cmd)
        return {"command_id": cmd.id, "agent_id": agent.id, "action": action, "status": cmd.status, "chain_hash": chain}

    # ==================================================================
    # ANALYZE handlers
    # ==================================================================

    async def _triage_alert(self, alert_id: str) -> dict[str, Any]:
        alert = await self._alert(alert_id)
        if not alert:
            return {"error": "Alert not found"}
        severity_score = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(alert.severity, 50)
        confidence = 0.85 if alert.source in ("edr", "siem", "firewall") else 0.65
        priority = "p1" if severity_score >= 90 else "p2" if severity_score >= 70 else "p3"
        recommendations = []
        if alert.severity == "critical":
            recommendations.append("Immediate containment: isolate affected systems")
            recommendations.append("Activate incident response team")
        if alert.source_ip:
            recommendations.append(f"Block source IP {alert.source_ip} at firewall")
        recommendations.append("Create forensic snapshot before remediation")
        return {"alert_id": alert.id, "priority": priority, "severity_score": severity_score, "confidence": confidence, "recommendations": recommendations}

    async def _enrich_ioc(self, value: str, ioc_type: str) -> dict[str, Any]:
        q = self._scoped(select(ThreatIndicator), ThreatIndicator).where(ThreatIndicator.value == value, ThreatIndicator.indicator_type == ioc_type)
        matches = (await self.db.execute(q)).scalars().all()
        if not matches:
            return {"value": value, "type": ioc_type, "known": False, "message": "No threat intel match"}
        sources = [m.source for m in matches if m.source]
        confidences = [m.confidence for m in matches if m.confidence is not None]
        severities = [m.severity for m in matches if m.severity]
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        worst = max(severities, key=lambda s: severity_rank.get(s, 0)) if severities else None
        first = matches[0]
        return {
            "value": value, "type": ioc_type, "known": True, "match_count": len(matches), "threat_level": worst,
            "confidence": int(sum(confidences) / len(confidences)) if confidences else None,
            "sources": sources,
            "first_seen": _iso(first.first_seen) or _iso(first.created_at),
        }

    async def _correlate_alerts(self, alert_id: str) -> dict[str, Any]:
        alert = await self._alert(alert_id)
        if not alert:
            return {"error": "Alert not found"}
        conditions = []
        if alert.source_ip:
            conditions.append(Alert.source_ip == alert.source_ip)
        if alert.category:
            conditions.append(Alert.category == alert.category)
        if not conditions:
            return {"related_alerts": [], "message": "No correlation fields"}
        q = self._scoped(select(Alert), Alert).where(Alert.id != alert.id).where(or_(*conditions)).limit(10)
        related = (await self.db.execute(q)).scalars().all()
        return {
            "alert_id": alert.id,
            "related_count": len(related),
            "related_alerts": [{"id": r.id, "title": r.title, "severity": r.severity} for r in related],
        }

    async def _check_ioc_matches(self, alert_id: str) -> dict[str, Any]:
        alert = await self._alert(alert_id)
        if not alert:
            return {"error": "Alert not found"}
        indicators = [v for v in (alert.source_ip, alert.destination_ip) if v]
        if not indicators:
            return {"matches": [], "message": "No indicators to check"}
        q = self._scoped(select(ThreatIndicator), ThreatIndicator).where(
            ThreatIndicator.value.in_(indicators),
            ThreatIndicator.is_active == True,  # noqa: E712
            ThreatIndicator.is_whitelisted == False,  # noqa: E712
        )
        matches = (await self.db.execute(q)).scalars().all()
        return {
            "matches": [{"value": m.value, "type": m.indicator_type, "threat_level": m.severity, "source": m.source} for m in matches],
            "match_count": len(matches),
        }

    async def _scope_hunt(self, hypothesis: str) -> dict[str, Any]:
        """PY-HUNT-001 Phase 1: validate a hypothesis against the ATT&CK KB.

        Honest by construction: reports the telemetry each in-scope technique
        needs, which sources this organization actually collects, and flags
        that EDR/DNS streaming telemetry is not integrated.
        """
        from src.attack.service import AttackService

        svc = AttackService(self.db)
        extracted = await svc.extract_technique_ids(hypothesis or "")

        covered = await self._coverage(extracted["valid"]) if extracted["valid"] else []
        cov_by_id = {c["technique"]: c for c in covered}
        techniques_in_scope = []
        needed_log_sources: set[str] = set()
        for tid in extracted["valid"]:
            tech = await svc.get_technique(tid)
            if not tech:
                continue
            ls = tech.get("log_sources") or []
            needed_log_sources.update(ls)
            techniques_in_scope.append({
                "technique": tid,
                "name": tech.get("name"),
                "tactics": tech.get("tactics") or [],
                "detection_rule_count": cov_by_id.get(tid, {}).get("rule_count", 0),
                "covered": cov_by_id.get(tid, {}).get("covered", False),
                "log_sources": ls[:12],
            })

        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        q = self._scoped(select(LogEntry.source_type), LogEntry).where(LogEntry.received_at >= cutoff).distinct()
        collected = sorted({s for s in (await self.db.execute(q)).scalars().all() if s})

        assets_in_scope = []
        words = {w.strip(".,;:'\"()").lower() for w in (hypothesis or "").split()}
        if words:
            asset_rows = (await self.db.execute(self._scoped(select(Asset), Asset).limit(500))).scalars().all()
            for a in asset_rows:
                hn = (a.hostname or "").lower()
                nm = (a.name or "").lower()
                if (hn and hn in words) or (nm and nm in words):
                    assets_in_scope.append({"hostname": a.hostname or a.name, "asset_type": a.asset_type, "criticality": a.criticality})

        uncovered = [t["technique"] for t in techniques_in_scope if not t["covered"]]
        notes = [
            "Telemetry availability is heuristic: ATT&CK log-source names are vendor channels; "
            "compare them against collected_source_types manually.",
            "EDR streaming telemetry (process trees, module loads) and a DNS sensor are NOT "
            "integrated in PySOAR; techniques relying solely on those cannot be hunted here.",
        ]
        if extracted["deprecated"]:
            notes.append(f"Deprecated technique ids cited: {extracted['deprecated']}; map to current ids.")
        if uncovered:
            notes.append(f"No detection rule covers: {uncovered}; the hunt is the compensating control.")

        return {
            "hypothesis": hypothesis,
            "techniques_in_scope": techniques_in_scope,
            "deprecated_techniques": extracted["deprecated"],
            "unknown_techniques": extracted["unknown"],
            "needed_log_sources": sorted(needed_log_sources)[:25],
            "collected_source_types": collected,
            "assets_in_scope": assets_in_scope,
            "coverage_summary": {
                "techniques": len(techniques_in_scope),
                "covered": sum(1 for t in techniques_in_scope if t["covered"]),
                "uncovered": len(uncovered),
            },
            "notes": notes,
        }

    async def _run_threat_hunt(self, hypothesis: str, timeframe_hours: int = 24) -> dict[str, Any]:
        org_id = self.ctx.org_id
        actor = self.ctx.actor_user_id  # hunt created_by is a users FK; None for autonomous runs

        title = hypothesis.strip() or "Threat hunt"
        if len(title) > 200:
            title = title[:197] + "..."
        mitre_ids = [m.upper() for m in re.findall(r"\bT\d{4}(?:\.\d+)?\b", hypothesis)]

        hunt = HuntHypothesis(
            title=title, description=hypothesis, status="active", priority="medium", hunt_type="hypothesis_driven",
            mitre_techniques=mitre_ids or None, data_sources=None, created_by=actor, organization_id=org_id,
        )
        self.db.add(hunt)
        await self.db.flush()

        session = HuntSession(
            hypothesis_id=hunt.id, status="running",
            parameters={"timeframe_hours": int(timeframe_hours), "target_hosts": [], "log_types": []},
            created_by=actor, organization_id=org_id,
        )
        self.db.add(session)
        await self.db.flush()

        stopwords = {"the", "and", "for", "with", "this", "that", "from", "user", "data", "have", "will", "should", "could", "would"}
        keywords = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", hypothesis) if w.lower() not in stopwords]
        if not keywords:
            session.status = "failed"
            session.error_message = "Hypothesis too vague"
            await self.db.commit()
            return {"hypothesis": hypothesis, "findings": 0, "message": "Hypothesis too vague"}

        cutoff = datetime.now(timezone.utc) - timedelta(hours=int(timeframe_hours))
        findings_created = 0
        iocs_checked = 0

        # Require keyword CO-OCCURRENCE so a single common word doesn't flag
        # every benign log; for 1-2 keyword hypotheses require all of them.
        unique_keywords = list(dict.fromkeys(keywords))
        min_match = 2 if len(unique_keywords) >= 3 else len(unique_keywords)
        max_findings = 50

        log_q = self._scoped(select(LogEntry), LogEntry).where(LogEntry.timestamp >= cutoff.isoformat()).limit(2000)
        log_rows = (await self.db.execute(log_q)).scalars().all()
        logs_scanned = len(log_rows)
        log_candidates = []
        for log in log_rows:
            haystack = " ".join(filter(None, [log.message, log.raw_log, log.hostname, log.username, log.process_name, log.action, log.source_name])).lower()
            matched = {k for k in unique_keywords if k in haystack}
            if len(matched) >= min_match:
                log_candidates.append((len(matched), log, sorted(matched)))
        log_candidates.sort(key=lambda c: c[0], reverse=True)
        for match_count, log, matched in log_candidates[:max_findings]:
            snippet = (log.message or log.raw_log or "").strip().replace("\n", " ")
            if len(snippet) > 100:
                snippet = snippet[:100] + "..."
            host = log.hostname or log.source_name or "log"
            self.db.add(HuntFinding(
                session_id=session.id,
                title=f"[{host}] {snippet}" if snippet else f"Log event on {host}",
                description=f"Log entry matched {match_count} hunt terms ({', '.join(matched[:10])}). Source: {log.source_name}.",
                severity=(log.severity or "medium"), classification="needs_review",
                evidence=json.dumps({"log_id": log.id, "timestamp": log.timestamp, "source_type": log.source_type, "match_count": match_count, "matched_keywords": matched[:10]}),
                affected_assets=json.dumps([log.hostname] if log.hostname else []),
                iocs_found=json.dumps([]),
                mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                organization_id=org_id, created_by=actor,
            ))
            findings_created += 1

        alert_q = self._scoped(select(Alert), Alert).where(Alert.created_at >= cutoff).limit(500)
        alert_rows = (await self.db.execute(alert_q)).scalars().all()
        alerts_scanned = len(alert_rows)
        for alert in alert_rows:
            haystack = " ".join(filter(None, [
                alert.title, alert.description, alert.hostname, alert.username, alert.source, alert.category,
                alert.source_ip, alert.destination_ip, alert.domain, alert.url, alert.file_hash,
            ])).lower()
            matched = sorted({k for k in unique_keywords if k in haystack})
            if not matched:
                continue
            self.db.add(HuntFinding(
                session_id=session.id,
                title=f"Related alert: {alert.title}",
                description=f"Historical alert matched hunt terms: {', '.join(matched[:10])}",
                severity=alert.severity or "medium", classification="needs_review",
                evidence=json.dumps({"alert_id": alert.id, "alert_status": alert.status, "matched_keywords": matched[:10], "source_ip": alert.source_ip}),
                affected_assets=json.dumps([alert.hostname] if alert.hostname else []),
                iocs_found=json.dumps([]),
                mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                organization_id=org_id, created_by=actor,
            ))
            findings_created += 1

        audit_q = self._scoped(select(AuditLog), AuditLog).where(AuditLog.created_at >= cutoff).limit(500)
        audit_rows = (await self.db.execute(audit_q)).scalars().all()
        audit_scanned = len(audit_rows)
        for audit in audit_rows:
            haystack = " ".join(filter(None, [audit.action, audit.resource_type, audit.resource_id, audit.description, audit.ip_address])).lower()
            matched = sorted({k for k in keywords if k in haystack})
            if not matched:
                continue
            self.db.add(HuntFinding(
                session_id=session.id,
                title=f"Audit search match: {audit.action or 'audit event'}",
                description=f"Audit event matched hunt keywords: {', '.join(matched[:10])}",
                severity="high" if not audit.success else "medium", classification="needs_review",
                evidence=json.dumps({"audit_id": audit.id, "action": audit.action, "resource_type": audit.resource_type, "resource_id": audit.resource_id, "matched_keywords": matched[:10]}),
                affected_assets=json.dumps([]), iocs_found=json.dumps([]),
                organization_id=org_id, created_by=actor,
            ))
            findings_created += 1

        ioc_candidates = [k for k in keywords if _IPV4_RE.match(k) or "." in k or "/" in k]
        if ioc_candidates:
            ioc_q = self._scoped(select(ThreatIndicator), ThreatIndicator).where(
                ThreatIndicator.value.in_(ioc_candidates), ThreatIndicator.is_active == True,  # noqa: E712
            ).limit(100)
            ioc_rows = (await self.db.execute(ioc_q)).scalars().all()
            iocs_checked = len(ioc_rows)
            for ioc in ioc_rows:
                self.db.add(HuntFinding(
                    session_id=session.id,
                    title=f"IOC match: {ioc.indicator_type}:{ioc.value}",
                    description="Threat indicator matched hunt hypothesis keywords.",
                    severity=ioc.severity or "high", classification="needs_review",
                    evidence=json.dumps({"indicator_id": ioc.id, "type": ioc.indicator_type, "value": ioc.value, "source": ioc.source}),
                    affected_assets=json.dumps([]), iocs_found=json.dumps([ioc.value]),
                    mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                    organization_id=org_id, created_by=actor,
                ))
                findings_created += 1

        session.findings_count = findings_created
        session.events_analyzed = logs_scanned + alerts_scanned + audit_scanned
        session.query_count = 3 + iocs_checked
        session.queries_executed = {
            "logs_scanned": logs_scanned, "alerts_scanned": alerts_scanned, "audit_logs_scanned": audit_scanned,
            "iocs_checked": iocs_checked, "keywords": sorted(set(keywords))[:50],
        }
        session.status = "completed"
        session.completed_at = datetime.now(timezone.utc)
        await self.db.commit()

        return {
            "hypothesis": hypothesis, "session_id": session.id, "findings": findings_created,
            "logs_scanned": logs_scanned, "alerts_scanned": alerts_scanned, "audit_scanned": audit_scanned,
            "iocs_checked": iocs_checked, "matched_keywords": sorted(set(keywords))[:10],
        }

    async def _generate_incident_summary(self, incident_id: str) -> dict[str, Any]:
        inc = await self._incident(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        summary = f"Incident '{inc.title}' ({inc.severity} severity, {inc.status} status)"
        if inc.description:
            summary += f"\nDescription: {inc.description[:200]}"
        return {
            "incident_id": inc.id, "summary": summary, "severity": inc.severity, "status": inc.status,
            "recommended_actions": [
                "Triage and assess scope",
                "Containment: isolate affected systems",
                "Evidence preservation",
                "Stakeholder notification",
            ],
        }
