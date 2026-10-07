"""Policy engine for agent tool calls (design v2 section 3).

``PolicyEngine.evaluate`` runs the eight checks in the stated order and
returns a :class:`Decision`:

1. schema        -> ``invalid_arguments``
2. role          -> ``role_not_permitted``
3. mode          -> ``autonomous_mode_readonly`` / ``proposal_disabled`` /
                    ``propose`` (interactive destructive+ with propose_actions)
4. trust         -> ``injection_lockdown`` (documentation-only tools exempt)
5. refs          -> ``cross_tenant_reference`` / ``value_not_in_org`` /
                    ``ambiguous_target`` / ``invalid_target`` (+ semantic validators)
6. targets       -> ``too_many_targets`` / ``invalid_target``
7. rate          -> ``rate_limited`` (fail closed for write+ when the backend is down)
8. audit         -> pre-decision row via ``AuditLogger.log_event``;
                    a failed write aborts execution: ``audit_unavailable``

Every reference is resolved through the registry's organization-scoped
loaders (``_scoped_get`` / ``resolve_by_value``), so a row from another
tenant is indistinguishable from a missing one. The engine never touches
a session directly; the caller (the runtime) commits once per step.
"""
from __future__ import annotations

import ipaddress
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Protocol, runtime_checkable

from src.agentic.context import ROLE_RANK, AgentContext, Mode, UserRole
from src.agentic.decisions import Decision, DecisionKind, ReasonCode, TrustState, TrustTier
from src.agentic.toolspec import ParamSpec, Target, Tier, ToolSpec
from src.core.logging import get_logger
from src.core.metrics import AGENT_POLICY_DECISIONS_TOTAL
from src.core.metrics import increment as metric_increment
from src.core.redact import redact

logger = get_logger(__name__)

__all__ = [
    "AGENTIC_POLICY_SECTION",
    "ARGS_MAX_BYTES",
    "AUDIT_EVENT_POLICY",
    "AUDIT_EVENT_TOOL",
    "DOCUMENTATION_ONLY_TOOLS",
    "MAX_EFFECTIVE_TARGETS",
    "SECOND_APPROVER_TIERS",
    "ApprovalQuorum",
    "AuditSink",
    "OrgPolicySettings",
    "PolicyEngine",
    "PolicyError",
    "RateLimitUnavailable",
    "ToolRateLimiter",
    "ToolRegistryProtocol",
    "audit_rows_fallback_counter",
    "canonical_json",
    "evaluate_approval_quorum",
    "load_org_policy_settings",
    "org_policy_settings_from_section",
    "validate_args",
]

ARGS_MAX_BYTES = 16 * 1024
MAX_EFFECTIVE_TARGETS = 25
AUDIT_EVENT_POLICY = "agent_policy"
AUDIT_EVENT_TOOL = "agent_tool"

# Tools that only document analyst findings; allowed even under lockdown
# (design section 3 step 4).
DOCUMENTATION_ONLY_TOOLS: frozenset[str] = frozenset({"add_incident_note", "update_incident_findings"})

# Tools whose write+ traffic counts toward the per-(org, tool) bucket.
_RATE_LIMITED_TIERS: frozenset[Tier] = frozenset({Tier.WRITE, Tier.DESTRUCTIVE, Tier.PRIVILEGED})

# Parameter names that carry an IP address and get the semantic IP validator.
_IP_PARAM_NAMES: frozenset[str] = frozenset(
    {"ip", "ip_address", "source_ip", "target_ip", "destination_ip", "src_ip", "dst_ip", "address"},
)

_JSON_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


class PolicyError(Exception):
    """Raised for programming errors in policy wiring (never for a denial)."""


class RateLimitUnavailable(Exception):
    """The rate-limit backend (Redis) could not answer."""


@runtime_checkable
class ToolRateLimiter(Protocol):
    """Interface expected from WP1's quota module for per-(org, tool) buckets.

    ``try_acquire`` returns ``True`` when a token was taken, ``False`` when the
    bucket is exhausted, and raises :class:`RateLimitUnavailable` (or any
    exception) when the backend cannot answer. The engine fails closed for
    write+ tools in that case unless a fallback counter is configured.
    """

    async def try_acquire(self, org_id: str, tool: str) -> bool: ...


@runtime_checkable
class ToolRegistryProtocol(Protocol):
    """The subset of ``AgentToolRegistry`` (WP2) the policy engine needs."""

    specs: Mapping[str, ToolSpec]

    async def _scoped_get(self, model: str, row_id: str) -> Any | None: ...

    async def resolve_by_value(self, model: str, column: str, value: str) -> list[Any]: ...


class AuditSink(Protocol):
    """``AuditLogger.log_event`` (src/audit_evidence/engine.py) signature."""

    async def log_event(
        self,
        event_type: str,
        action: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        description: str,
        old_value: Optional[dict[str, Any]] = None,
        new_value: Optional[dict[str, Any]] = None,
        result: str = "success",
        risk_level: str = "info",
        actor_ip: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> Any: ...


@dataclass(frozen=True)
class OrgPolicySettings:
    """Organization-level knobs the engine consults (all default to the safe side)."""

    allow_special_ip_targets: bool = False   # loopback / link-local / CIDR as block targets
    tool_rate_limit_per_minute: int = 30     # bucket size used by the audit-row fallback
    autonomous_allowlist: frozenset[str] = frozenset()
    # Terminal tools end an autonomous run (design section 6, "Verdicts are a tool").
    # They carry no side effects (tier read, read-only effects) and are always
    # callable in autonomous mode even when absent from the allow-list, because
    # the allow-list enumerates *evidence* tools and the verdict is the exit.
    terminal_tools: frozenset[str] = frozenset({"submit_verdict"})
    # Separation of duties (AC-5): when on, a destructive/privileged proposal
    # needs two distinct approvers, neither of whom is the proposer. Off by
    # default (a single-analyst SOC must still be able to act); an org admin
    # opts in through ``PUT /settings/agentic-policy``.
    require_second_approver: bool = False


#: ``app_settings.section`` holding the org-admin-editable policy knobs.
AGENTIC_POLICY_SECTION = "agentic_policy"

#: Tiers that fall under ``require_second_approver``.
SECOND_APPROVER_TIERS: frozenset[Tier] = frozenset({Tier.DESTRUCTIVE, Tier.PRIVILEGED})


def org_policy_settings_from_section(value: Mapping[str, Any] | None, **overrides: Any) -> OrgPolicySettings:
    """Build :class:`OrgPolicySettings` from a stored ``agentic_policy`` section.

    Only keys an org admin may set are read; everything else keeps the safe
    default. A non-boolean stored value is treated as unset (False), never
    coerced from a truthy string.
    """
    raw = value.get("require_second_approver") if isinstance(value, Mapping) else None
    return OrgPolicySettings(require_second_approver=raw is True, **overrides)


async def load_org_policy_settings(session: Any, org_id: str, **overrides: Any) -> OrgPolicySettings:
    """Read the org's ``agentic_policy`` section (organization-scoped) into settings.

    Errors propagate: a caller gating an approval must not silently fall back
    to the weaker single-approver default when the setting cannot be read.
    """
    from sqlalchemy import select

    from src.models.settings import AppSetting

    stmt = select(AppSetting.value).where(
        AppSetting.organization_id == org_id,
        AppSetting.section == AGENTIC_POLICY_SECTION,
    )
    stored = (await session.execute(stmt)).scalar_one_or_none()
    return org_policy_settings_from_section(stored if isinstance(stored, dict) else None, **overrides)


ApprovalOutcome = Literal["execute", "record_first", "deny"]


@dataclass(frozen=True)
class ApprovalQuorum:
    """What an approve call may do given the org's separation-of-duties rule.

    ``outcome``: ``execute`` (quorum met), ``record_first`` (store this as the
    first of two approvals and leave the proposal pending) or ``deny``
    (``reason_code`` is ``proposer_cannot_approve`` -> 403 or
    ``second_approver_required`` -> 409).
    """

    outcome: ApprovalOutcome
    requires_second_approver: bool
    reason_code: Optional[str] = None
    detail: Optional[str] = None


def evaluate_approval_quorum(
    settings: OrgPolicySettings,
    *,
    tier: Tier | None,
    approver_user_id: Optional[str],
    proposer_user_id: Optional[str],
    first_approved_by: Optional[str],
) -> ApprovalQuorum:
    """Decide the separation-of-duties step of an approval (design v2 section 8).

    Applies only when ``settings.require_second_approver`` is on and the tool
    tier is destructive/privileged. The proposer never counts as an approver,
    the same user can never supply both approvals, and an approver with no
    user id (which cannot be told apart from anyone) is refused.
    """
    required = bool(settings.require_second_approver) and tier in SECOND_APPROVER_TIERS
    if not required:
        return ApprovalQuorum(outcome="execute", requires_second_approver=False)
    if not approver_user_id:
        return ApprovalQuorum(
            outcome="deny",
            requires_second_approver=True,
            reason_code="proposer_cannot_approve",
            detail="separation of duties requires an identified human approver",
        )
    if proposer_user_id and approver_user_id == proposer_user_id:
        return ApprovalQuorum(
            outcome="deny",
            requires_second_approver=True,
            reason_code="proposer_cannot_approve",
            detail="the user who proposed this action cannot approve it (separation of duties)",
        )
    if not first_approved_by:
        return ApprovalQuorum(outcome="record_first", requires_second_approver=True)
    if first_approved_by == approver_user_id:
        return ApprovalQuorum(
            outcome="deny",
            requires_second_approver=True,
            reason_code="second_approver_required",
            detail="you already gave the first approval; a different user must give the second",
        )
    return ApprovalQuorum(outcome="execute", requires_second_approver=True)


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for hashing and size checks."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Step 1: schema validation
# ---------------------------------------------------------------------------


def _validate_json_schema(value: Any, schema: Mapping[str, Any], path: str, errors: list[str]) -> None:
    """Validate ``value`` against the JSON-Schema subset ToolSpec nesting uses."""
    stype = schema.get("type")
    if stype is not None:
        types = stype if isinstance(stype, list) else [stype]
        if not any(_JSON_TYPE_CHECKS.get(t, lambda _v: False)(value) for t in types):
            errors.append(f"{path}: expected {stype}")
            return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: not one of {schema['enum']}")
        return
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")
        if "max_length" in schema and len(value) > schema["max_length"]:
            errors.append(f"{path}: longer than {schema['max_length']}")
    if isinstance(value, dict):
        props: Mapping[str, Any] = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}.{req}: required")
        if schema.get("additionalProperties", False) is False:
            for key in value:
                if key not in props:
                    errors.append(f"{path}.{key}: unexpected property")
        for key, sub in props.items():
            if key in value and isinstance(sub, Mapping):
                _validate_json_schema(value[key], sub, f"{path}.{key}", errors)
    if isinstance(value, list):
        items = schema.get("items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if isinstance(items, Mapping):
            for idx, item in enumerate(value):
                _validate_json_schema(item, items, f"{path}[{idx}]", errors)


def _validate_param(value: Any, spec: ParamSpec, path: str, errors: list[str]) -> None:
    if not _JSON_TYPE_CHECKS[spec.type](value):
        errors.append(f"{path}: expected {spec.type}")
        return
    if spec.enum is not None and value not in spec.enum:
        errors.append(f"{path}: not one of {spec.enum}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if spec.minimum is not None and value < spec.minimum:
            errors.append(f"{path}: below minimum {spec.minimum}")
        if spec.maximum is not None and value > spec.maximum:
            errors.append(f"{path}: above maximum {spec.maximum}")
    if isinstance(value, str) and spec.max_length is not None and len(value) > spec.max_length:
        errors.append(f"{path}: longer than {spec.max_length}")
    if isinstance(value, list):
        if spec.maximum is not None and len(value) > spec.maximum:
            errors.append(f"{path}: more than {spec.maximum} items")
        if spec.items is not None:
            for idx, item in enumerate(value):
                _validate_param(item, spec.items, f"{path}[{idx}]", errors)
        elif spec.ref_list or spec.ref is not None:
            for idx, item in enumerate(value):
                if not isinstance(item, str) or not item:
                    errors.append(f"{path}[{idx}]: expected id string")
        elif spec.schema is not None:
            _validate_json_schema(value, spec.schema, path, errors)
    if isinstance(value, dict):
        if spec.schema is not None:
            _validate_json_schema(value, spec.schema, path, errors)
        else:
            errors.append(f"{path}: object parameters must declare a schema")


def validate_args(spec: ToolSpec, args: Any) -> list[str]:
    """Return a list of validation errors (empty when ``args`` is valid)."""
    errors: list[str] = []
    if not isinstance(args, dict):
        return ["arguments must be an object"]
    try:
        size = len(canonical_json(args).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        return [f"arguments are not JSON-serializable: {exc}"]
    if size > ARGS_MAX_BYTES:
        return [f"arguments exceed {ARGS_MAX_BYTES} bytes"]
    for name, pspec in spec.params.items():
        if name not in args or args[name] is None:
            if pspec.required:
                errors.append(f"{name}: required")
            continue
        _validate_param(args[name], pspec, name, errors)
    for name in args:
        if name not in spec.params:
            errors.append(f"{name}: unexpected argument")
    return errors


# ---------------------------------------------------------------------------
# Step 5 helpers: reference resolution (recursive)
# ---------------------------------------------------------------------------


@dataclass
class _RefResolution:
    """Accumulates the outcome of resolving every ref in an argument tree."""

    resolved_args: dict[str, Any]
    missing: list[str] = field(default_factory=list)          # cross_tenant_reference
    not_in_org: list[str] = field(default_factory=list)       # value_not_in_org
    ambiguous: list[str] = field(default_factory=list)        # ambiguous_target
    invalid: list[str] = field(default_factory=list)          # invalid_target
    users: dict[str, Any] = field(default_factory=dict)       # path -> User row (for disable_user checks)
    ref_targets: list[Target] = field(default_factory=list)


_TARGET_KIND_BY_MODEL: dict[str, str] = {
    "User": "user",
    "Incident": "incident",
    "Alert": "alert",
    "Asset": "asset",
    "InstalledIntegration": "integration",
    "Playbook": "playbook",
    "EndpointAgent": "endpoint_agent",
}


def _target_kind(model: str) -> str:
    return _TARGET_KIND_BY_MODEL.get(model, "other")


class PolicyEngine:
    """Evaluates every tool call before the registry executes it."""

    def __init__(
        self,
        registry: ToolRegistryProtocol,
        audit: AuditSink,
        *,
        limiter: ToolRateLimiter | None = None,
        rate_fallback_counter: Callable[[str, str, int], Awaitable[int]] | None = None,
        settings: OrgPolicySettings | None = None,
    ) -> None:
        self.registry = registry
        self.audit = audit
        self.limiter = limiter
        self.rate_fallback_counter = rate_fallback_counter
        self.settings = settings or OrgPolicySettings()

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def evaluate_tool(
        self, ctx: AgentContext, tool: str, args: dict[str, Any], trust: TrustState, *, step: int = 0,
    ) -> Decision:
        """Look the tool up in the registry, then :meth:`evaluate`."""
        spec = self.registry.specs.get(tool)
        if spec is None:
            decision = Decision(
                kind="deny",
                reason_code="unknown_tool",
                tool=tool,
                tier=Tier.READ,
                risk="low",
                resolved_args=dict(args) if isinstance(args, dict) else {},
                effective_targets=[],
                detail="tool is not registered",
            )
            return await self._audit_pre(ctx, decision, args, step=step)
        return await self.evaluate(ctx, spec, args, trust, step=step)

    async def evaluate(
        self, ctx: AgentContext, spec: ToolSpec, args: dict[str, Any], trust: TrustState, *, step: int = 0,
    ) -> Decision:
        """Run the eight checks in order; always ends with the pre-decision audit row."""
        decision = await self._evaluate_unaudited(ctx, spec, args, trust)
        audited = await self._audit_pre(ctx, decision, args, step=step)
        metric_increment(AGENT_POLICY_DECISIONS_TOTAL, decision=audited.kind, reason=audited.reason_code)
        return audited

    # ------------------------------------------------------------------
    # Steps 1-7
    # ------------------------------------------------------------------

    async def _evaluate_unaudited(
        self, ctx: AgentContext, spec: ToolSpec, args: dict[str, Any], trust: TrustState,
    ) -> Decision:
        tool = spec.name
        tier = spec.tier
        safe_args: dict[str, Any] = dict(args) if isinstance(args, dict) else {}

        def deny(reason: ReasonCode, detail: str, *, risk: str = "medium", tier_: Tier = tier) -> Decision:
            return Decision(
                kind="deny",
                reason_code=reason,
                tool=tool,
                tier=tier_,
                risk=risk,  # type: ignore[arg-type]
                resolved_args=safe_args,
                effective_targets=[],
                detail=detail,
            )

        # 1. schema
        errors = validate_args(spec, args)
        if errors:
            return deny("invalid_arguments", "; ".join(errors[:8]), risk="low")

        # 2. role
        if ROLE_RANK[ctx.role] < ROLE_RANK[spec.min_role]:
            return deny("role_not_permitted", f"requires role {spec.min_role.value}, caller is {ctx.role.value}")

        # 3. mode
        kind: DecisionKind = "allow"
        if ctx.mode is Mode.AUTONOMOUS:
            allowed_ro = (
                (tool in self.settings.autonomous_allowlist or tool in self.settings.terminal_tools)
                and tier is Tier.READ
                and spec.effects.is_read_only
            )
            if not allowed_ro:
                return deny("autonomous_mode_readonly", "autonomous runs may only call allow-listed read tools")
        elif ctx.mode is Mode.INTERACTIVE:
            if tier in (Tier.DESTRUCTIVE, Tier.PRIVILEGED):
                if not ctx.propose_actions:
                    return deny("proposal_disabled", "destructive tools require propose_actions to create a proposal")
                kind = "propose"
        elif ctx.mode is Mode.APPROVAL:
            if tier is Tier.PRIVILEGED and ctx.role is not UserRole.ADMIN:
                return deny("role_not_permitted", "privileged actions require an admin approver")
        else:  # pragma: no cover - enum exhaustiveness
            return deny("invalid_arguments", f"unknown mode {ctx.mode}")

        # 4. trust
        effective_trust_tier = trust.tier
        if ctx.mode is Mode.APPROVAL and ctx.origin_trust_tier is TrustTier.LOCKDOWN:
            effective_trust_tier = TrustTier.LOCKDOWN
        if effective_trust_tier is TrustTier.LOCKDOWN and tier is not Tier.READ and tool not in DOCUMENTATION_ONLY_TOOLS:
            return deny("injection_lockdown", "session is in injection lockdown; write tools are disabled", risk="high")
        suspect = effective_trust_tier is not TrustTier.CLEAN

        # 5. refs + semantic validators
        resolution = await self._resolve_refs(ctx, spec, args)
        if resolution.invalid:
            return deny("invalid_target", "; ".join(resolution.invalid[:8]))
        if resolution.missing:
            # Reported exactly like not-found; the message never says which tenant owns the row.
            return deny("cross_tenant_reference", "referenced record not found in organization")
        if resolution.not_in_org:
            return deny("value_not_in_org", "referenced value not found in organization")
        if resolution.ambiguous:
            return deny("ambiguous_target", "value matches more than one record; supply an id")

        semantic = self._semantic_checks(ctx, spec, resolution)
        if semantic is not None:
            reason, detail, escalated_tier = semantic
            return deny(reason, detail, risk="high", tier_=escalated_tier)
        if spec.name == "disable_user" and any(_user_is_admin(u) for u in resolution.users.values()):
            tier = Tier.PRIVILEGED
            if ctx.mode is Mode.INTERACTIVE:
                kind = "propose"

        # 6. effective targets
        targets: list[Target]
        if spec.effective_targets is not None:
            try:
                targets = list(await spec.effective_targets(resolution.resolved_args, self.registry))
            except Exception as exc:
                logger.warning("effective_targets_failed", tool=tool, error=str(exc))
                return deny("invalid_target", f"could not expand targets: {exc.__class__.__name__}")
        elif tier in (Tier.DESTRUCTIVE, Tier.PRIVILEGED):
            return deny("invalid_target", "destructive tool declares no effective_targets", risk="high")
        else:
            targets = list(resolution.ref_targets)
        if len(targets) > MAX_EFFECTIVE_TARGETS:
            return deny("too_many_targets", f"{len(targets)} targets exceed the cap of {MAX_EFFECTIVE_TARGETS}")
        for target in targets:
            problem = await self._check_target(ctx, spec, target)
            if problem is not None:
                return deny("invalid_target", problem)

        # 7. rate
        if tier in _RATE_LIMITED_TIERS and kind == "allow":
            rate_problem = await self._check_rate(ctx, tool)
            if rate_problem is not None:
                return deny("rate_limited", rate_problem, risk="low")

        risk = _risk_for(tier, suspect)
        detail = "trust_flagged:suspect" if suspect else None
        return Decision(
            kind=kind,
            reason_code="ok",
            tool=tool,
            tier=tier,
            risk=risk,  # type: ignore[arg-type]
            resolved_args=resolution.resolved_args,
            effective_targets=targets,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Step 5: refs
    # ------------------------------------------------------------------

    async def _resolve_refs(self, ctx: AgentContext, spec: ToolSpec, args: dict[str, Any]) -> _RefResolution:
        out = _RefResolution(resolved_args=json.loads(canonical_json(args)))
        for name, pspec in spec.params.items():
            if name not in args or args[name] is None:
                continue
            out.resolved_args[name] = await self._resolve_param(ctx, pspec, args[name], name, out)
        return out

    async def _resolve_param(self, ctx: AgentContext, pspec: ParamSpec, value: Any, path: str, out: _RefResolution) -> Any:
        if pspec.ref is not None:
            if isinstance(value, list):
                return [await self._resolve_ref(ctx, pspec.ref, item, f"{path}[{i}]", out) for i, item in enumerate(value)]
            return await self._resolve_ref(ctx, pspec.ref, value, path, out)
        if pspec.ref_by_value is not None:
            model, column = pspec.ref_by_value
            if isinstance(value, list):
                return [
                    await self._resolve_by_value(ctx, model, column, item, f"{path}[{i}]", out)
                    for i, item in enumerate(value)
                ]
            return await self._resolve_by_value(ctx, model, column, value, path, out)
        if isinstance(value, list) and pspec.items is not None:
            return [await self._resolve_param(ctx, pspec.items, item, f"{path}[{i}]", out) for i, item in enumerate(value)]
        if isinstance(value, (dict, list)) and pspec.schema is not None:
            return await self._resolve_schema(ctx, pspec.schema, value, path, out)
        return value

    async def _resolve_schema(self, ctx: AgentContext, schema: Mapping[str, Any], value: Any, path: str, out: _RefResolution) -> Any:
        """Walk a nested JSON-schema-typed value looking for ``x-ref`` / ``x-ref-by-value``."""
        ref = schema.get("x-ref")
        ref_by_value = schema.get("x-ref-by-value")
        if ref and isinstance(value, str):
            return await self._resolve_ref(ctx, str(ref), value, path, out)
        if ref_by_value and isinstance(value, str):
            model, column = ref_by_value
            return await self._resolve_by_value(ctx, str(model), str(column), value, path, out)
        if isinstance(value, dict):
            props: Mapping[str, Any] = schema.get("properties", {})
            resolved: dict[str, Any] = {}
            for key, item in value.items():
                sub = props.get(key)
                resolved[key] = (
                    await self._resolve_schema(ctx, sub, item, f"{path}.{key}", out) if isinstance(sub, Mapping) else item
                )
            return resolved
        if isinstance(value, list):
            items = schema.get("items")
            if isinstance(items, Mapping):
                return [await self._resolve_schema(ctx, items, item, f"{path}[{i}]", out) for i, item in enumerate(value)]
        return value

    async def _resolve_ref(self, ctx: AgentContext, model: str, value: Any, path: str, out: _RefResolution) -> Any:
        if not isinstance(value, str) or not value:
            out.invalid.append(f"{path}: expected an id")
            return value
        if model == "User" and value == "me":
            return await self._bind_me(ctx, path, out)
        row = await self.registry._scoped_get(model, value)
        if row is None:
            out.missing.append(path)
            return value
        if model == "User":
            out.users[path] = row
        out.ref_targets.append(Target(kind=_target_kind(model), value=value, resolved_id=value, provenance="structured"))  # type: ignore[arg-type]
        return value

    async def _resolve_by_value(self, ctx: AgentContext, model: str, column: str, value: Any, path: str, out: _RefResolution) -> Any:
        if not isinstance(value, str) or not value.strip():
            out.invalid.append(f"{path}: expected a value")
            return value
        if model == "User" and value.strip().lower() == "me":
            return await self._bind_me(ctx, path, out)
        rows = await self.registry.resolve_by_value(model, column, value.strip())
        if not rows:
            out.not_in_org.append(path)
            return value
        if len(rows) > 1:
            out.ambiguous.append(path)
            return value
        row = rows[0]
        row_id = str(row.id)
        if model == "User":
            out.users[path] = row
        out.ref_targets.append(Target(kind=_target_kind(model), value=value, resolved_id=row_id, provenance="structured"))  # type: ignore[arg-type]
        return row_id

    async def _bind_me(self, ctx: AgentContext, path: str, out: _RefResolution) -> Any:
        if not ctx.actor_user_id:
            out.invalid.append(f"{path}: 'me' has no meaning without a user actor")
            return "me"
        row = await self.registry._scoped_get("User", ctx.actor_user_id)
        if row is None:
            out.missing.append(path)
            return "me"
        out.users[path] = row
        out.ref_targets.append(Target(kind="user", value="me", resolved_id=ctx.actor_user_id, provenance="structured"))
        return ctx.actor_user_id

    # ------------------------------------------------------------------
    # Semantic validators
    # ------------------------------------------------------------------

    def _semantic_checks(
        self, ctx: AgentContext, spec: ToolSpec, resolution: _RefResolution,
    ) -> tuple[ReasonCode, str, Tier] | None:
        args = resolution.resolved_args
        for name, value in args.items():
            if name in _IP_PARAM_NAMES and isinstance(value, str):
                problem = self._check_ip(value)
                if problem is not None:
                    return "invalid_target", f"{name}: {problem}", spec.tier
            if name in _IP_PARAM_NAMES and isinstance(value, list):
                for idx, item in enumerate(value):
                    if isinstance(item, str):
                        problem = self._check_ip(item)
                        if problem is not None:
                            return "invalid_target", f"{name}[{idx}]: {problem}", spec.tier
        if spec.name == "disable_user":
            if not resolution.users:
                return "invalid_target", "disable_user requires a resolvable in-org user", spec.tier
            for path, user in resolution.users.items():
                user_id = str(getattr(user, "id", ""))
                if ctx.actor_user_id and user_id == ctx.actor_user_id:
                    return "invalid_target", f"{path}: cannot disable the acting user", spec.tier
                if bool(getattr(user, "is_superuser", False)):
                    return "invalid_target", f"{path}: cannot disable a superuser", Tier.PRIVILEGED
                if _user_is_admin(user) and ctx.role is not UserRole.ADMIN:
                    return "role_not_permitted", f"{path}: disabling an admin requires admin role", Tier.PRIVILEGED
        return None

    def _check_ip(self, value: str) -> str | None:
        if "/" in value:
            if self.settings.allow_special_ip_targets:
                try:
                    ipaddress.ip_network(value, strict=False)
                    return None
                except ValueError:
                    return "not a valid CIDR"
            return "CIDR ranges are not allowed as targets"
        try:
            addr = ipaddress.ip_address(value.strip())
        except ValueError:
            return "not a valid IP address"
        if self.settings.allow_special_ip_targets:
            return None
        if addr.is_loopback:
            return "loopback addresses are not allowed as targets"
        if addr.is_link_local:
            return "link-local addresses are not allowed as targets"
        if addr.is_unspecified:
            return "unspecified address is not allowed as a target"
        return None

    async def _check_target(self, ctx: AgentContext, spec: ToolSpec, target: Target) -> str | None:
        if not target.value:
            return "empty target"
        if target.kind == "ip":
            problem = self._check_ip(target.value)
            if problem is not None:
                return f"target {target.value}: {problem}"
            return None
        model = _MODEL_BY_TARGET_KIND.get(target.kind)
        if model is not None and target.resolved_id:
            row = await self.registry._scoped_get(model, target.resolved_id)
            if row is None:
                return "target record not found in organization"
        return None

    # ------------------------------------------------------------------
    # Step 7: rate
    # ------------------------------------------------------------------

    async def _check_rate(self, ctx: AgentContext, tool: str) -> str | None:
        if self.limiter is not None:
            try:
                if await self.limiter.try_acquire(ctx.org_id, tool):
                    return None
                return f"per-organization rate limit for {tool} exceeded"
            except Exception as exc:
                logger.warning("tool_rate_limiter_unavailable", tool=tool, error=str(exc), organization_id=ctx.org_id)
        if self.rate_fallback_counter is not None:
            try:
                recent = await self.rate_fallback_counter(ctx.org_id, tool, 60)
            except Exception as exc:
                logger.error("tool_rate_fallback_unavailable", tool=tool, error=str(exc), organization_id=ctx.org_id)
                return "rate-limit backend unavailable; write actions are denied (fail closed)"
            if recent >= self.settings.tool_rate_limit_per_minute:
                return f"per-organization rate limit for {tool} exceeded (audit fallback)"
            return None
        return "rate-limit backend unavailable; write actions are denied (fail closed)"

    # ------------------------------------------------------------------
    # Step 8: audit (pre-decision)
    # ------------------------------------------------------------------

    async def _audit_pre(self, ctx: AgentContext, decision: Decision, args: Any, *, step: int) -> Decision:
        redacted_args, _ = redact(args if isinstance(args, dict) else {"args": args})
        action = f"tool.{decision.kind}"
        payload: dict[str, Any] = {
            "step": step,
            "tool": decision.tool,
            "tier": decision.tier.value,
            "reason_code": decision.reason_code,
            "mode": ctx.mode.value,
            "role": ctx.role.value,
            "propose_actions": ctx.propose_actions,
            "args": redacted_args,
            "effective_targets": [
                {"kind": t.kind, "value": t.value, "resolved_id": t.resolved_id, "provenance": t.provenance}
                for t in decision.effective_targets
            ],
            "detail": decision.detail,
        }
        try:
            row = await self.audit.log_event(
                event_type=AUDIT_EVENT_POLICY,
                action=action,
                actor_type="agent" if ctx.soc_agent_id else "user",
                actor_id=ctx.soc_agent_id or ctx.actor_user_id or "unknown",
                resource_type="agent_tool",
                resource_id=decision.tool,
                description=f"policy {decision.kind} {decision.tool}: {decision.reason_code}",
                new_value=payload,
                result="success" if decision.kind != "deny" else "denied",
                risk_level=decision.risk,
                actor_ip=ctx.actor_ip,
                session_id=ctx.session_id,
                request_id=ctx.run_id,
                run_id=ctx.run_id,
            )
        except Exception as exc:
            logger.error("policy_audit_unavailable", tool=decision.tool, error=str(exc), run_id=ctx.run_id)
            return Decision(
                kind="deny",
                reason_code="audit_unavailable",
                tool=decision.tool,
                tier=decision.tier,
                risk="high",
                resolved_args=decision.resolved_args,
                effective_targets=decision.effective_targets,
                audit_id=None,
                detail=f"audit write failed: {exc.__class__.__name__}",
            )
        decision.audit_id = str(getattr(row, "id", None)) if row is not None and getattr(row, "id", None) else None
        logger.info(
            "agent_policy_decision",
            run_id=ctx.run_id,
            tool=decision.tool,
            decision=decision.kind,
            reason_code=decision.reason_code,
            tier=decision.tier.value,
            audit_id=decision.audit_id,
        )
        return decision


_MODEL_BY_TARGET_KIND: dict[str, str] = {v: k for k, v in _TARGET_KIND_BY_MODEL.items()}


def _user_is_admin(user: Any) -> bool:
    role = getattr(user, "role", None)
    role_value = getattr(role, "value", role)
    return str(role_value).lower() == UserRole.ADMIN.value


def _risk_for(tier: Tier, suspect: bool) -> str:
    base = {Tier.READ: "info", Tier.WRITE: "low", Tier.DESTRUCTIVE: "high", Tier.PRIVILEGED: "critical"}[tier]
    if suspect and base in ("info", "low"):
        return "medium"
    if suspect and base == "high":
        return "critical"
    return base


def audit_rows_fallback_counter(session: Any) -> Callable[[str, str, int], Awaitable[int]]:
    """Build the Redis-down fallback: count post-execution audit rows in the window.

    The query is scoped to the organization and the tool. Any exception
    propagates so the engine can fail closed.
    """
    from sqlalchemy import func, select

    from src.audit_evidence.models import AuditTrail

    async def _count(org_id: str, tool: str, window_seconds: int) -> int:
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        stmt = (
            select(func.count())
            .select_from(AuditTrail)
            .where(
                AuditTrail.organization_id == org_id,
                AuditTrail.event_type == AUDIT_EVENT_TOOL,
                AuditTrail.resource_id == tool,
                AuditTrail.created_at >= since,
            )
        )
        result = await session.execute(stmt)
        return int(result.scalar_one())

    return _count
