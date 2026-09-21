"""Policy engine matrix: mode x role x tier x trust x refs (design v2 section 3).

Everything runs against an in-test FakeRegistry (org-scoped loaders backed by
dicts) and a FakeAudit sink; no network, no database. Every decision path
is exercised for its exact reason code and audit side effect.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import pytest

from src.agentic.context import AgentContext, Mode, UserRole
from src.agentic.decisions import TrustState, TrustTier
from src.agentic.policy import (
    ARGS_MAX_BYTES,
    AUDIT_EVENT_POLICY,
    MAX_EFFECTIVE_TARGETS,
    OrgPolicySettings,
    PolicyEngine,
    RateLimitUnavailable,
    validate_args,
)
from src.agentic.toolspec import Effects, ParamSpec, Target, Tier, ToolSpec

ORG_A = "org-a"
ORG_B = "org-b"
ANALYST = "user-analyst"
ADMIN = "user-admin"
SUPER = "user-super"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass
class Row:
    id: str
    organization_id: str
    email: str = ""
    role: str = "analyst"
    is_superuser: bool = False
    hostname: str = ""


@dataclass
class FakeAudit:
    events: list[dict[str, Any]] = field(default_factory=list)
    fail: bool = False

    async def log_event(self, **kwargs: Any) -> Any:
        if self.fail:
            raise RuntimeError("audit backend down")
        self.events.append(kwargs)
        return Row(id=f"audit-{len(self.events)}", organization_id="")


class FakeRegistry:
    """Org-scoped loaders over in-memory rows; ``call`` runs the handler."""

    def __init__(self, specs: dict[str, ToolSpec], org_id: str, rows: list[Row]) -> None:
        self.specs = specs
        self.org_id = org_id
        self.rows = rows
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.policy: Optional[PolicyEngine] = None
        self.model_of: dict[str, str] = {}

    def add(self, model: str, row: Row) -> Row:
        self.rows.append(row)
        self.model_of[row.id] = model
        return row

    async def _scoped_get(self, model: str, row_id: str) -> Any | None:
        for row in self.rows:
            if row.id == row_id and self.model_of.get(row.id) == model and row.organization_id == self.org_id:
                return row
        return None

    async def resolve_by_value(self, model: str, column: str, value: str) -> list[Any]:
        return [
            r for r in self.rows
            if self.model_of.get(r.id) == model and r.organization_id == self.org_id and getattr(r, column, None) == value
        ]

    async def call(self, ctx: AgentContext, tool: str, args: dict[str, Any]) -> Any:
        # Composite handlers route sub-actions through here so each gets its own decision.
        assert self.policy is not None
        decision = await self.policy.evaluate_tool(ctx, tool, args, TrustState())
        if not decision.allowed:
            raise PermissionError(f"{tool}: {decision.reason_code}")
        self.calls.append((tool, decision.resolved_args))
        return await self.specs[tool].handler(ctx, decision.resolved_args, self)


class FakeLimiter:
    def __init__(self, allow: bool = True, broken: bool = False) -> None:
        self.allow = allow
        self.broken = broken
        self.acquired: list[tuple[str, str]] = []

    async def try_acquire(self, org_id: str, tool: str) -> bool:
        if self.broken:
            raise RateLimitUnavailable("redis down")
        self.acquired.append((org_id, tool))
        return self.allow


async def _noop(ctx: AgentContext, args: dict[str, Any], registry: Any) -> Any:
    return {"ok": True, "args": args}


async def _targets_from_ip(args: dict[str, Any], registry: Any) -> list[Target]:
    return [Target(kind="ip", value=args["ip"], provenance="structured")]


async def _targets_from_user(args: dict[str, Any], registry: Any) -> list[Target]:
    return [Target(kind="user", value=args["user_email"], resolved_id=args["user_email"], provenance="structured")]


async def _targets_many(args: dict[str, Any], registry: Any) -> list[Target]:
    return [Target(kind="ip", value=f"203.0.113.{i}", provenance="structured") for i in range(args["count"])]


async def _targets_raise(args: dict[str, Any], registry: Any) -> list[Target]:
    raise RuntimeError("expansion failed")


async def _remediate(ctx: AgentContext, args: dict[str, Any], registry: FakeRegistry) -> Any:
    results = []
    for ip in args["ips"]:
        results.append(await registry.call(ctx, "block_ip", {"ip": ip}))
    return {"sub": results}


def _spec(
    name: str,
    tier: Tier,
    min_role: UserRole,
    params: dict[str, ParamSpec],
    *,
    effects: Effects | None = None,
    effective_targets: Any = None,
    handler: Any = _noop,
    returns_sensitive: bool = False,
) -> ToolSpec:
    if effects is None:
        effects = Effects() if tier is Tier.READ else Effects(writes_org=True)
    return ToolSpec(
        name=name, description=f"{name} tool", params=params, effects=effects, tier=tier, min_role=min_role,
        models=("Incident",), handler=handler, effective_targets=effective_targets, returns_sensitive=returns_sensitive,
    )


def build_specs() -> dict[str, ToolSpec]:
    specs = [
        _spec("list_alerts", Tier.READ, UserRole.VIEWER, {"limit": ParamSpec("integer", "max rows", maximum=100, minimum=1)}),
        _spec("search_logs", Tier.READ, UserRole.ANALYST, {"query": ParamSpec("string", "q", required=True, max_length=200)}),
        _spec("get_incident", Tier.READ, UserRole.VIEWER, {"incident_id": ParamSpec("string", "id", required=True, ref="Incident")}),
        _spec("add_incident_note", Tier.WRITE, UserRole.ANALYST, {
            "incident_id": ParamSpec("string", "id", required=True, ref="Incident"),
            "note": ParamSpec("string", "note", required=True, max_length=4000),
        }),
        _spec("create_ticket", Tier.WRITE, UserRole.ANALYST, {
            "title": ParamSpec("string", "t", required=True),
            "priority": ParamSpec("string", "p", enum=["low", "high"]),
            "assignee": ParamSpec("string", "who", ref_by_value=("User", "email")),
        }),
        _spec("tag_alerts", Tier.WRITE, UserRole.ANALYST, {
            "alert_ids": ParamSpec("array", "ids", required=True, ref="Alert", ref_list=True, maximum=50),
            "tag": ParamSpec("string", "tag", required=True),
        }),
        _spec("bulk_update", Tier.WRITE, UserRole.ANALYST, {
            "changes": ParamSpec("object", "nested", required=True, schema={
                "type": "object",
                "properties": {
                    "incident": {"type": "object", "properties": {"id": {"type": "string", "x-ref": "Incident"}}, "required": ["id"], "additionalProperties": False},
                    "assignees": {"type": "array", "items": {"type": "string", "x-ref-by-value": ["User", "email"]}},
                },
                "required": ["incident"],
                "additionalProperties": False,
            }),
        }),
        _spec("block_ip", Tier.DESTRUCTIVE, UserRole.ANALYST, {"ip": ParamSpec("string", "ip", required=True)},
              effects=Effects(writes_org=True, external=True), effective_targets=_targets_from_ip),
        _spec("disable_user", Tier.DESTRUCTIVE, UserRole.ANALYST,
              {"user_email": ParamSpec("string", "email", required=True, ref_by_value=("User", "email"))},
              effective_targets=_targets_from_user),
        _spec("queue_endpoint_command", Tier.PRIVILEGED, UserRole.ADMIN,
              {"action": ParamSpec("string", "a", required=True, enum=["run_script", "kill_process"])},
              effects=Effects(writes_org=True, external=True, executes_code=True),
              effective_targets=lambda args, reg: _targets_many({"count": 1}, reg)),
        _spec("mass_block", Tier.DESTRUCTIVE, UserRole.ANALYST, {"count": ParamSpec("integer", "n", required=True)},
              effective_targets=_targets_many),
        _spec("broken_targets", Tier.DESTRUCTIVE, UserRole.ANALYST, {}, effective_targets=_targets_raise),
        _spec("no_targets_declared", Tier.DESTRUCTIVE, UserRole.ANALYST, {}),
        _spec("remediate_incident", Tier.DESTRUCTIVE, UserRole.ANALYST,
              {"ips": ParamSpec("array", "ips", required=True, items=ParamSpec("string", "ip"))},
              effective_targets=lambda args, reg: _targets_many({"count": len(args["ips"])}, reg), handler=_remediate),
    ]
    return {s.name: s for s in specs}


@dataclass
class Harness:
    registry: FakeRegistry
    audit: FakeAudit
    limiter: FakeLimiter
    engine: PolicyEngine


def make(
    *, limiter: FakeLimiter | None = None, fallback: Any = None, settings: OrgPolicySettings | None = None,
    audit_fail: bool = False,
) -> Harness:
    registry = FakeRegistry(build_specs(), ORG_A, [])
    registry.add("Incident", Row(id="inc-a", organization_id=ORG_A))
    registry.add("Incident", Row(id="inc-b", organization_id=ORG_B))
    registry.add("Alert", Row(id="al-1", organization_id=ORG_A))
    registry.add("Alert", Row(id="al-2", organization_id=ORG_A))
    registry.add("Alert", Row(id="al-b", organization_id=ORG_B))
    registry.add("User", Row(id=ANALYST, organization_id=ORG_A, email="analyst@a.test", role="analyst"))
    registry.add("User", Row(id=ADMIN, organization_id=ORG_A, email="admin@a.test", role="admin"))
    registry.add("User", Row(id=SUPER, organization_id=ORG_A, email="root@a.test", role="admin", is_superuser=True))
    registry.add("User", Row(id="user-bob", organization_id=ORG_A, email="bob@a.test"))
    registry.add("User", Row(id="user-dup1", organization_id=ORG_A, email="dup@a.test"))
    registry.add("User", Row(id="user-dup2", organization_id=ORG_A, email="dup@a.test"))
    registry.add("User", Row(id="user-b", organization_id=ORG_B, email="eve@b.test"))
    audit = FakeAudit(fail=audit_fail)
    limiter = limiter if limiter is not None else FakeLimiter()
    engine = PolicyEngine(
        registry, audit, limiter=limiter, rate_fallback_counter=fallback,
        settings=settings or OrgPolicySettings(autonomous_allowlist=frozenset({"list_alerts", "get_incident"})),
    )
    registry.policy = engine
    return Harness(registry, audit, limiter, engine)


def ctx(
    mode: Mode = Mode.INTERACTIVE, role: UserRole = UserRole.ANALYST, *, propose: bool = True,
    actor: str = ANALYST, origin: TrustTier | None = None,
) -> AgentContext:
    if mode is Mode.AUTONOMOUS:
        return AgentContext(org_id=ORG_A, role=role, mode=mode, soc_agent_id="agent-1", propose_actions=propose)
    return AgentContext(org_id=ORG_A, role=role, mode=mode, actor_user_id=actor, propose_actions=propose, origin_trust_tier=origin)


def clean() -> TrustState:
    return TrustState()


def lockdown() -> TrustState:
    return TrustState(tier=TrustTier.LOCKDOWN)


def flagged() -> TrustState:
    return TrustState(tier=TrustTier.FLAGGED)


# ---------------------------------------------------------------------------
# Step 1: schema
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool,args,fragment",
    [
        ("search_logs", {}, "query: required"),
        ("search_logs", {"query": 5}, "expected string"),
        ("search_logs", {"query": "x" * 201}, "longer than"),
        ("list_alerts", {"limit": 500}, "above maximum"),
        ("list_alerts", {"limit": True}, "expected integer"),
        ("create_ticket", {"title": "t", "priority": "urgent"}, "not one of"),
        ("create_ticket", {"title": "t", "bogus": 1}, "unexpected argument"),
        ("bulk_update", {"changes": {"incident": {"id": "inc-a", "extra": 1}}}, "unexpected property"),
        ("bulk_update", {"changes": {}}, "incident: required"),
        ("tag_alerts", {"alert_ids": "al-1", "tag": "x"}, "expected array"),
    ],
)
async def test_schema_violations_are_invalid_arguments(tool: str, args: dict[str, Any], fragment: str) -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), tool, args, clean())
    assert d.kind == "deny" and d.reason_code == "invalid_arguments"
    assert fragment in (d.detail or "")
    assert h.audit.events[-1]["action"] == "tool.deny"


async def test_args_over_16kb_rejected() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "x" * (ARGS_MAX_BYTES + 1)}, clean())
    assert d.reason_code == "invalid_arguments"
    assert "16384" in (d.detail or "")


def test_validate_args_rejects_non_dict() -> None:
    spec = build_specs()["search_logs"]
    assert validate_args(spec, ["query"]) == ["arguments must be an object"]


async def test_unknown_tool_is_denied_and_audited() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "nope", {}, clean())
    assert d.kind == "deny" and d.reason_code == "unknown_tool"
    assert h.audit.events[-1]["resource_id"] == "nope"


# ---------------------------------------------------------------------------
# Step 2: role
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "role,tool,expected",
    [
        (UserRole.VIEWER, "list_alerts", "ok"),
        (UserRole.VIEWER, "search_logs", "role_not_permitted"),
        (UserRole.VIEWER, "add_incident_note", "role_not_permitted"),
        (UserRole.VIEWER, "block_ip", "role_not_permitted"),
        (UserRole.ANALYST, "search_logs", "ok"),
        (UserRole.ANALYST, "queue_endpoint_command", "role_not_permitted"),
        (UserRole.ADMIN, "queue_endpoint_command", "ok"),
    ],
)
async def test_role_matrix(role: UserRole, tool: str, expected: str) -> None:
    h = make()
    args = {"query": "x"} if tool == "search_logs" else {"incident_id": "inc-a", "note": "n"} if tool == "add_incident_note" \
        else {"ip": "203.0.113.9"} if tool == "block_ip" else {"action": "kill_process"} if tool == "queue_endpoint_command" else {}
    d = await h.engine.evaluate_tool(ctx(role=role, actor=ADMIN if role is UserRole.ADMIN else ANALYST), tool, args, clean())
    assert d.reason_code == expected


async def test_viewer_cannot_write_even_with_propose_actions() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(role=UserRole.VIEWER, propose=True), "add_incident_note", {"incident_id": "inc-a", "note": "n"}, clean())
    assert d.reason_code == "role_not_permitted"


# ---------------------------------------------------------------------------
# Step 3: mode
# ---------------------------------------------------------------------------


async def test_autonomous_allowlisted_read_tool_allowed() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(Mode.AUTONOMOUS), "list_alerts", {"limit": 5}, clean())
    assert d.kind == "allow"


async def test_autonomous_read_tool_not_on_allowlist_denied() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(Mode.AUTONOMOUS), "search_logs", {"query": "x"}, clean())
    assert d.reason_code == "autonomous_mode_readonly"


async def test_autonomous_write_denied_even_for_admin() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(Mode.AUTONOMOUS, UserRole.ADMIN), "add_incident_note", {"incident_id": "inc-a", "note": "n"}, clean())
    assert d.reason_code == "autonomous_mode_readonly"


async def test_interactive_destructive_without_propose_actions() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(propose=False), "block_ip", {"ip": "203.0.113.9"}, clean())
    assert d.kind == "deny" and d.reason_code == "proposal_disabled"


async def test_interactive_destructive_with_propose_actions_is_proposal_never_allow() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "block_ip", {"ip": "203.0.113.9"}, clean())
    assert d.kind == "propose" and d.reason_code == "ok" and not d.allowed
    assert d.effective_targets[0].value == "203.0.113.9"
    assert h.audit.events[-1]["action"] == "tool.propose"


async def test_interactive_privileged_by_admin_is_still_a_proposal() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(role=UserRole.ADMIN, actor=ADMIN), "queue_endpoint_command", {"action": "run_script"}, clean())
    assert d.kind == "propose" and d.tier is Tier.PRIVILEGED


async def test_interactive_write_tool_executes_inline() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "add_incident_note", {"incident_id": "inc-a", "note": "n"}, clean())
    assert d.kind == "allow" and d.risk == "low"


async def test_approval_mode_allows_destructive_after_checks() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(Mode.APPROVAL), "block_ip", {"ip": "203.0.113.9"}, clean())
    assert d.kind == "allow"
    assert h.limiter.acquired == [(ORG_A, "block_ip")]


async def test_approval_mode_privileged_requires_admin_approver() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(Mode.APPROVAL, UserRole.ANALYST), "queue_endpoint_command", {"action": "run_script"}, clean())
    assert d.reason_code == "role_not_permitted"
    d = await h.engine.evaluate_tool(ctx(Mode.APPROVAL, UserRole.ADMIN, actor=ADMIN), "queue_endpoint_command", {"action": "run_script"}, clean())
    assert d.kind == "allow"


# ---------------------------------------------------------------------------
# Step 4: trust
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool,args,expected_kind,expected_reason",
    [
        ("list_alerts", {"limit": 1}, "allow", "ok"),
        ("add_incident_note", {"incident_id": "inc-a", "note": "tampered"}, "allow", "ok"),
        ("create_ticket", {"title": "t"}, "deny", "injection_lockdown"),
        ("block_ip", {"ip": "203.0.113.9"}, "deny", "injection_lockdown"),
    ],
)
async def test_lockdown_matrix(tool: str, args: dict[str, Any], expected_kind: str, expected_reason: str) -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), tool, args, lockdown())
    assert (d.kind, d.reason_code) == (expected_kind, expected_reason)


async def test_flagged_allows_but_marks_suspect() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t"}, flagged())
    assert d.kind == "allow" and d.detail == "trust_flagged:suspect" and d.risk == "medium"
    p = await h.engine.evaluate_tool(ctx(), "block_ip", {"ip": "203.0.113.9"}, flagged())
    assert p.kind == "propose" and p.detail == "trust_flagged:suspect" and p.risk == "critical"


async def test_approval_inherits_origin_lockdown() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(Mode.APPROVAL, origin=TrustTier.LOCKDOWN), "block_ip", {"ip": "203.0.113.9"}, clean())
    assert d.reason_code == "injection_lockdown"


# ---------------------------------------------------------------------------
# Step 5: refs
# ---------------------------------------------------------------------------


async def test_in_org_ref_resolves_and_records_target() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "get_incident", {"incident_id": "inc-a"}, clean())
    assert d.kind == "allow"
    assert [t.kind for t in d.effective_targets] == ["incident"]


async def test_cross_tenant_and_missing_refs_are_indistinguishable() -> None:
    h = make()
    other = await h.engine.evaluate_tool(ctx(), "get_incident", {"incident_id": "inc-b"}, clean())
    missing = await h.engine.evaluate_tool(ctx(), "get_incident", {"incident_id": "inc-zzz"}, clean())
    assert other.reason_code == missing.reason_code == "cross_tenant_reference"
    assert other.detail == missing.detail
    assert ORG_B not in (other.detail or "")


async def test_ref_list_with_one_foreign_id_denied() -> None:
    h = make()
    ok = await h.engine.evaluate_tool(ctx(), "tag_alerts", {"alert_ids": ["al-1", "al-2"], "tag": "x"}, clean())
    assert ok.kind == "allow" and len(ok.effective_targets) == 2
    bad = await h.engine.evaluate_tool(ctx(), "tag_alerts", {"alert_ids": ["al-1", "al-b"], "tag": "x"}, clean())
    assert bad.reason_code == "cross_tenant_reference"


async def test_nested_dict_and_list_refs_resolved_recursively() -> None:
    h = make()
    args = {"changes": {"incident": {"id": "inc-a"}, "assignees": ["bob@a.test", "me"]}}
    d = await h.engine.evaluate_tool(ctx(), "bulk_update", args, clean())
    assert d.kind == "allow"
    assert d.resolved_args["changes"]["assignees"] == ["user-bob", ANALYST]
    assert d.resolved_args["changes"]["incident"]["id"] == "inc-a"
    bad = await h.engine.evaluate_tool(ctx(), "bulk_update", {"changes": {"incident": {"id": "inc-b"}}}, clean())
    assert bad.reason_code == "cross_tenant_reference"
    foreign_user = await h.engine.evaluate_tool(ctx(), "bulk_update", {"changes": {"incident": {"id": "inc-a"}, "assignees": ["eve@b.test"]}}, clean())
    assert foreign_user.reason_code == "value_not_in_org"


async def test_by_value_unique_match_rewrites_to_id() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t", "assignee": "bob@a.test"}, clean())
    assert d.kind == "allow" and d.resolved_args["assignee"] == "user-bob"


async def test_by_value_ambiguous_denied() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t", "assignee": "dup@a.test"}, clean())
    assert d.reason_code == "ambiguous_target"


async def test_by_value_not_in_org_denied() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t", "assignee": "eve@b.test"}, clean())
    assert d.reason_code == "value_not_in_org"


async def test_me_binds_to_actor() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t", "assignee": "me"}, clean())
    assert d.kind == "allow" and d.resolved_args["assignee"] == ANALYST


async def test_me_without_user_actor_is_invalid() -> None:
    h = make()
    h.engine.settings = OrgPolicySettings(autonomous_allowlist=frozenset({"create_ticket"}))
    # Force the tool to be read-only so the autonomous gate passes and the ref step is reached.
    h.registry.specs["create_ticket"].tier = Tier.READ
    h.registry.specs["create_ticket"].effects = Effects()
    d = await h.engine.evaluate_tool(ctx(Mode.AUTONOMOUS), "create_ticket", {"title": "t", "assignee": "me"}, clean())
    assert d.reason_code == "invalid_target"


# ---------------------------------------------------------------------------
# Semantic validators
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "169.254.10.10", "fe80::1", "10.0.0.0/8", "0.0.0.0", "not-an-ip", "203.0.113.9/32"])
async def test_special_ip_targets_rejected_by_default(ip: str) -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "block_ip", {"ip": ip}, clean())
    assert d.reason_code == "invalid_target", ip


async def test_special_ip_targets_allowed_when_org_setting_permits() -> None:
    h = make(settings=OrgPolicySettings(allow_special_ip_targets=True))
    for ip in ["127.0.0.1", "10.0.0.0/8"]:
        d = await h.engine.evaluate_tool(ctx(), "block_ip", {"ip": ip}, clean())
        assert d.kind == "propose", ip
    d = await h.engine.evaluate_tool(ctx(), "block_ip", {"ip": "not-an-ip"}, clean())
    assert d.reason_code == "invalid_target"


async def test_disable_user_cannot_target_actor() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "disable_user", {"user_email": "analyst@a.test"}, clean())
    assert d.reason_code == "invalid_target" and "acting user" in (d.detail or "")
    d = await h.engine.evaluate_tool(ctx(), "disable_user", {"user_email": "me"}, clean())
    assert d.reason_code == "invalid_target"


async def test_disable_user_cannot_target_superuser_even_for_admin() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(role=UserRole.ADMIN, actor=ADMIN), "disable_user", {"user_email": "root@a.test"}, clean())
    assert d.reason_code == "invalid_target" and "superuser" in (d.detail or "")


async def test_disable_user_admin_target_requires_admin_and_is_privileged() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "disable_user", {"user_email": "admin@a.test"}, clean())
    assert d.reason_code == "role_not_permitted" and d.tier is Tier.PRIVILEGED
    admin_ctx = AgentContext(org_id=ORG_A, role=UserRole.ADMIN, mode=Mode.INTERACTIVE, actor_user_id="user-other-admin", propose_actions=True)
    h.registry.add("User", Row(id="user-other-admin", organization_id=ORG_A, email="other@a.test", role="admin"))
    d = await h.engine.evaluate_tool(admin_ctx, "disable_user", {"user_email": "admin@a.test"}, clean())
    assert d.kind == "propose" and d.tier is Tier.PRIVILEGED


async def test_disable_user_plain_analyst_target_is_proposal() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "disable_user", {"user_email": "bob@a.test"}, clean())
    assert d.kind == "propose" and d.tier is Tier.DESTRUCTIVE and d.resolved_args["user_email"] == "user-bob"


# ---------------------------------------------------------------------------
# Step 6: effective targets
# ---------------------------------------------------------------------------


async def test_too_many_targets() -> None:
    h = make()
    ok = await h.engine.evaluate_tool(ctx(), "mass_block", {"count": MAX_EFFECTIVE_TARGETS}, clean())
    assert ok.kind == "propose"
    d = await h.engine.evaluate_tool(ctx(), "mass_block", {"count": MAX_EFFECTIVE_TARGETS + 1}, clean())
    assert d.reason_code == "too_many_targets"


async def test_target_expansion_failure_denies() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "broken_targets", {}, clean())
    assert d.reason_code == "invalid_target" and "RuntimeError" in (d.detail or "")


async def test_destructive_without_effective_targets_declared_is_denied() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "no_targets_declared", {}, clean())
    assert d.reason_code == "invalid_target"


# ---------------------------------------------------------------------------
# Composite sub-calls
# ---------------------------------------------------------------------------


async def test_composite_sub_calls_get_their_own_decisions_and_abort_on_denial() -> None:
    h = make()
    c = ctx(Mode.APPROVAL)
    top = await h.engine.evaluate_tool(c, "remediate_incident", {"ips": ["203.0.113.5", "203.0.113.6"]}, clean())
    assert top.kind == "allow"
    result = await h.registry.call(c, "remediate_incident", top.resolved_args)
    assert [t for t, _ in h.registry.calls] == ["remediate_incident", "block_ip", "block_ip"]
    assert len(result["sub"]) == 2
    # Each sub-call wrote its own pre-decision audit row and charged the bucket.
    assert [e["resource_id"] for e in h.audit.events] == ["remediate_incident", "remediate_incident", "block_ip", "block_ip"]
    assert h.limiter.acquired.count((ORG_A, "block_ip")) == 2

    h.registry.calls.clear()
    with pytest.raises(PermissionError, match="block_ip: invalid_target"):
        await h.registry.call(c, "remediate_incident", {"ips": ["203.0.113.5", "127.0.0.1"]})
    # The composite aborted after the first denied sub-call.
    assert [t for t, _ in h.registry.calls] == ["remediate_incident", "block_ip"]


# ---------------------------------------------------------------------------
# Step 7: rate limiting
# ---------------------------------------------------------------------------


async def test_rate_limited_when_bucket_exhausted() -> None:
    h = make(limiter=FakeLimiter(allow=False))
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t"}, clean())
    assert d.reason_code == "rate_limited"


async def test_read_tools_never_touch_the_bucket() -> None:
    h = make(limiter=FakeLimiter(broken=True))
    d = await h.engine.evaluate_tool(ctx(), "list_alerts", {"limit": 3}, clean())
    assert d.kind == "allow"


async def test_rate_backend_down_fails_closed_for_writes() -> None:
    h = make(limiter=FakeLimiter(broken=True))
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t"}, clean())
    assert d.reason_code == "rate_limited" and "fail closed" in (d.detail or "")


async def test_rate_backend_down_uses_audit_fallback_counter() -> None:
    counts: dict[str, int] = {"create_ticket": 3}
    seen: list[tuple[str, str, int]] = []

    async def fallback(org_id: str, tool: str, window: int) -> int:
        seen.append((org_id, tool, window))
        return counts.get(tool, 0)

    h = make(limiter=FakeLimiter(broken=True), fallback=fallback, settings=OrgPolicySettings(tool_rate_limit_per_minute=5))
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t"}, clean())
    assert d.kind == "allow" and seen == [(ORG_A, "create_ticket", 60)]
    counts["create_ticket"] = 5
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t"}, clean())
    assert d.reason_code == "rate_limited" and "audit fallback" in (d.detail or "")


async def test_rate_fallback_also_down_denies() -> None:
    async def fallback(org_id: str, tool: str, window: int) -> int:
        raise ConnectionError("db down")

    h = make(limiter=FakeLimiter(broken=True), fallback=fallback)
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "t"}, clean())
    assert d.reason_code == "rate_limited"


async def test_no_limiter_configured_fails_closed_for_writes() -> None:
    registry = FakeRegistry(build_specs(), ORG_A, [])
    engine = PolicyEngine(registry, FakeAudit())
    d = await engine.evaluate_tool(ctx(), "create_ticket", {"title": "t"}, clean())
    assert d.reason_code == "rate_limited"


# ---------------------------------------------------------------------------
# Step 8: audit
# ---------------------------------------------------------------------------


async def test_pre_decision_audit_row_shape_and_redaction() -> None:
    h = make()
    d = await h.engine.evaluate_tool(ctx(), "create_ticket", {"title": "api_key=sk-ant-abcdefghijklmnop", "priority": "high"}, clean(), step=3)
    assert d.audit_id == "audit-1"
    ev = h.audit.events[-1]
    assert ev["event_type"] == AUDIT_EVENT_POLICY and ev["action"] == "tool.allow"
    assert ev["run_id"] == ev["request_id"]
    assert ev["actor_type"] == "user" and ev["actor_id"] == ANALYST
    assert ev["new_value"]["step"] == 3 and ev["new_value"]["tier"] == "write"
    assert "sk-ant-" not in ev["new_value"]["args"]["title"]
    assert "[REDACTED" in ev["new_value"]["args"]["title"]


async def test_audit_failure_denies_with_audit_unavailable() -> None:
    h = make(audit_fail=True)
    d = await h.engine.evaluate_tool(ctx(), "list_alerts", {"limit": 1}, clean())
    assert d.kind == "deny" and d.reason_code == "audit_unavailable" and d.audit_id is None
    assert d.risk == "high"


async def test_denied_decisions_are_audited_as_denied() -> None:
    h = make()
    await h.engine.evaluate_tool(ctx(role=UserRole.VIEWER), "search_logs", {"query": "x"}, clean())
    ev = h.audit.events[-1]
    assert ev["action"] == "tool.deny" and ev["result"] == "denied"
    assert ev["new_value"]["reason_code"] == "role_not_permitted"


async def test_check_order_schema_before_role_before_mode() -> None:
    """A viewer in autonomous mode with bad args gets invalid_arguments, not a role/mode code."""
    h = make()
    d = await h.engine.evaluate_tool(ctx(Mode.AUTONOMOUS, UserRole.VIEWER), "add_incident_note", {"note": "n"}, clean())
    assert d.reason_code == "invalid_arguments"
    d = await h.engine.evaluate_tool(ctx(Mode.AUTONOMOUS, UserRole.VIEWER), "add_incident_note", {"incident_id": "inc-a", "note": "n"}, clean())
    assert d.reason_code == "role_not_permitted"
    d = await h.engine.evaluate_tool(ctx(Mode.AUTONOMOUS, UserRole.ANALYST), "add_incident_note", {"incident_id": "inc-a", "note": "n"}, clean())
    assert d.reason_code == "autonomous_mode_readonly"
    d = await h.engine.evaluate_tool(ctx(Mode.INTERACTIVE, UserRole.ANALYST), "add_incident_note", {"incident_id": "inc-b", "note": "n"}, lockdown())
    assert d.reason_code == "cross_tenant_reference", "documentation tool passes trust, then refs are checked"
    d = await h.engine.evaluate_tool(ctx(Mode.INTERACTIVE, UserRole.ANALYST), "create_ticket", {"title": "t", "assignee": "eve@b.test"}, lockdown())
    assert d.reason_code == "injection_lockdown", "trust is checked before refs"
