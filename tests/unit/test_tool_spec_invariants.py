"""Structural invariants of the agent tool registry (replaces test_destructive_tool_gate.py).

Tool tiers and the role matrix live in the specs, so these tests pin the
properties the policy engine relies on: every tool is typed, every id-shaped
parameter is a resolvable in-org reference, declared effects match what the
handler body actually does, and no query in the module escapes ``_scoped``.

This module also exports the small harness the behavioural tool tests use
(``make_registry`` / ``run_tool``): a registry bound to an analyst context
and a permissive fake policy that hands the handler its args unchanged.
"""
from __future__ import annotations

import inspect
import re
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.agentic.context import AgentContext, Mode, UserRole
from src.agentic.decisions import Decision
from src.agentic.toolspec import Effects, ParamSpec, Tier, ToolSpec
from src.services import agent_tools as module
from src.services.agent_tools import (
    MODEL_REGISTRY,
    PARENT_SCOPED,
    SCOPE_RULES,
    AgentToolRegistry,
    render_json_schema,
    render_tool_for_llm,
)

TEST_ORG = "org-1"

DESTRUCTIVE_OR_PRIVILEGED = {
    "block_ip",
    "isolate_host",
    "disable_user",
    "execute_playbook",
    "execute_integration_action",
    "remediate_incident",
    "create_remediation_ticket",
    "simulate_attack",
    "queue_endpoint_command",
}

WRITE_MARKERS = ("db.add(", ".commit(", ".delay(", "httpx", "ActionExecutor", "SimulationOrchestrator")


# ---------------------------------------------------------------------------
# Shared harness for the behavioural tool tests
# ---------------------------------------------------------------------------


class AllowAllPolicy:
    """Fake policy: allows every call and passes args through untouched."""

    async def evaluate(self, ctx: AgentContext, spec: ToolSpec, args: dict[str, Any], trust: Any) -> Decision:  # noqa: ARG002
        return Decision(
            kind="allow", reason_code="ok", tool=spec.name, tier=spec.tier, risk="low",
            resolved_args=dict(args), effective_targets=[],
        )


def make_context(user: Any = None, org: str = TEST_ORG, role: UserRole = UserRole.ANALYST) -> AgentContext:
    org_id = (getattr(user, "organization_id", None) if user is not None else None) or org
    actor = getattr(user, "id", None) or "test-actor"
    return AgentContext(org_id=org_id, role=role, mode=Mode.INTERACTIVE, actor_user_id=actor, propose_actions=True)


def make_registry(db: Any, user: Any = None, org: str = TEST_ORG, role: UserRole = UserRole.ANALYST) -> AgentToolRegistry:
    return AgentToolRegistry(db, make_context(user=user, org=org, role=role))


async def run_tool(registry: AgentToolRegistry, tool: str, args: dict[str, Any] | None = None) -> Any:
    """Invoke ``tool`` through ``registry.call`` with the permissive policy; returns the raw result."""
    return await registry.call(registry.ctx, tool, dict(args or {}), policy=AllowAllPolicy())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> AgentToolRegistry:
    return make_registry(AsyncMock())


@pytest.fixture(scope="module")
def specs(registry: AgentToolRegistry) -> dict[str, ToolSpec]:
    return registry.specs


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_registry_requires_org_context():
    with pytest.raises(ValueError):
        AgentToolRegistry(AsyncMock(), None)  # type: ignore[arg-type]


def test_registry_registers_all_tools(specs):
    assert len(specs) == 65
    by_category = {}
    for s in specs.values():
        by_category.setdefault(s.category, set()).add(s.name)
    assert len(by_category["query"]) == 37
    assert len(by_category["action"]) == 20
    assert len(by_category["analyze"]) == 8


@pytest.mark.asyncio
async def test_legacy_execute_is_gone(registry):
    with pytest.raises(NotImplementedError):
        await registry.execute("list_alerts", {})


@pytest.mark.asyncio
async def test_call_unknown_tool_is_keyerror(registry):
    with pytest.raises(KeyError):
        await run_tool(registry, "not_a_tool", {})


@pytest.mark.asyncio
async def test_call_denied_decision_raises_permission_error(registry):
    spec = registry.specs["list_alerts"]
    denied = Decision(kind="deny", reason_code="role_not_permitted", tool=spec.name, tier=spec.tier, risk="low", resolved_args={}, effective_targets=[])
    with pytest.raises(PermissionError, match="role_not_permitted"):
        await registry.call(registry.ctx, "list_alerts", {}, decision=denied)


@pytest.mark.asyncio
async def test_call_rejects_foreign_org_context(registry):
    other = AgentContext(org_id="org-2", role=UserRole.ANALYST, mode=Mode.INTERACTIVE, actor_user_id="x")
    with pytest.raises(PermissionError, match="cross_tenant_reference"):
        await registry.call(other, "list_alerts", {}, policy=AllowAllPolicy())


# ---------------------------------------------------------------------------
# Spec completeness
# ---------------------------------------------------------------------------


def test_every_spec_is_fully_typed(specs):
    for name, s in specs.items():
        assert isinstance(s.effects, Effects), name
        assert isinstance(s.tier, Tier), name
        assert isinstance(s.min_role, UserRole), name
        assert isinstance(s.models, tuple), name
        assert callable(s.handler), name
        assert s.handler.__name__.startswith("_"), f"{name}: handler must be private"
        for pname, p in s.params.items():
            assert isinstance(p, ParamSpec), f"{name}.{pname}"


def test_every_id_param_has_ref(specs):
    for name, s in specs.items():
        for pname, p in s.params.items():
            if pname.endswith("_id") or pname.endswith("_ids"):
                assert p.ref, f"{name}.{pname} must carry ref=<Model>"


def test_ref_models_are_org_scoped(specs):
    for name, s in specs.items():
        for pname, p in s.params.items():
            refs = [p.ref] if p.ref else []
            if p.ref_by_value:
                refs.append(p.ref_by_value[0])
            for model_name in refs:
                assert model_name in MODEL_REGISTRY, f"{name}.{pname}: {model_name} not in MODEL_REGISTRY"
                model = MODEL_REGISTRY[model_name]
                assert hasattr(model, "organization_id") or model_name in SCOPE_RULES, f"{name}.{pname}: {model_name} lacks organization_id"


def test_spec_models_are_scopable(specs):
    for name, s in specs.items():
        for model_name in s.models:
            assert model_name in MODEL_REGISTRY, f"{name}: {model_name}"
            model = MODEL_REGISTRY[model_name]
            scopable = hasattr(model, "organization_id") or model_name in SCOPE_RULES or model_name in PARENT_SCOPED
            assert scopable, f"{name}: {model_name} is not org-scopable"


def test_registration_rejects_unscopable_model(registry):
    class Orphan:  # no organization_id
        id = None

    MODEL_REGISTRY["Orphan"] = Orphan
    try:
        bad = ToolSpec(
            name="bad_tool", description="x", params={}, effects=Effects(), tier=Tier.READ,
            min_role=UserRole.VIEWER, models=("Orphan",), handler=registry._list_alerts,
        )
        with pytest.raises(TypeError):
            registry._register(bad)
    finally:
        MODEL_REGISTRY.pop("Orphan", None)
        registry.specs.pop("bad_tool", None)


def test_limit_params_are_bounded_integers(specs):
    for name, s in specs.items():
        p = s.params.get("limit")
        if p is None:
            continue
        assert p.type == "integer" and p.minimum == 1 and p.maximum == 100, name


def test_no_opaque_object_params(specs):
    for name, s in specs.items():
        for pname, p in s.params.items():
            if p.type == "object":
                assert p.schema is not None, f"{name}.{pname}: object params need a schema"


def test_queue_endpoint_command_action_enum_matches_capabilities(specs):
    from src.agents.capabilities import AgentAction

    p = specs["queue_endpoint_command"].params["action"]
    assert set(p.enum) == {a.value for a in AgentAction}
    payload = specs["queue_endpoint_command"].params["payload"]
    assert payload.schema["additionalProperties"] is False


# ---------------------------------------------------------------------------
# Tier / role matrix
# ---------------------------------------------------------------------------


def test_destructive_and_privileged_set(specs):
    actual = {n for n, s in specs.items() if s.tier in (Tier.DESTRUCTIVE, Tier.PRIVILEGED)}
    assert actual == DESTRUCTIVE_OR_PRIVILEGED
    assert specs["queue_endpoint_command"].tier is Tier.PRIVILEGED
    assert specs["queue_endpoint_command"].min_role is UserRole.ADMIN


def test_non_read_tools_require_analyst(specs):
    for name, s in specs.items():
        if s.tier is not Tier.READ:
            assert s.min_role in (UserRole.ANALYST, UserRole.ADMIN), name


def test_sensitive_reads_require_analyst(specs):
    for name in ("list_compliance_evidence", "list_darkweb_findings", "list_configured_integrations", "search_logs", "list_siem_rules", "list_endpoint_agents"):
        assert specs[name].min_role is UserRole.ANALYST, name


def test_read_tier_effects_are_read_only(specs):
    for name, s in specs.items():
        if s.tier is Tier.READ:
            assert s.effects.is_read_only, name


def test_handler_bodies_match_declared_effects(specs):
    for name, s in specs.items():
        src = inspect.getsource(s.handler)
        writes = any(marker in src for marker in WRITE_MARKERS)
        if writes:
            assert s.tier is not Tier.READ, f"{name}: handler writes but is declared read"
            assert not s.effects.is_read_only, f"{name}: handler writes but effects are read-only"


def test_visible_specs_follow_role(registry):
    viewer = {s.name for s in registry.visible_specs(UserRole.VIEWER)}
    analyst = {s.name for s in registry.visible_specs(UserRole.ANALYST)}
    admin = {s.name for s in registry.visible_specs(UserRole.ADMIN)}
    assert viewer < analyst < admin
    assert "queue_endpoint_command" in admin - analyst
    assert "search_logs" not in viewer


# ---------------------------------------------------------------------------
# Schema rendering
# ---------------------------------------------------------------------------


def test_render_json_schema_shape(specs):
    for name, s in specs.items():
        schema = render_json_schema(s)
        assert schema["type"] == "object", name
        assert schema["additionalProperties"] is False, name
        assert schema["required"] == [p for p, ps in s.params.items() if ps.required], name
        for pname, prop in schema["properties"].items():
            assert "type" in prop and "description" in prop, f"{name}.{pname}"
            if prop["type"] == "array":
                assert "items" in prop, f"{name}.{pname}"


def test_render_json_schema_carries_constraints(specs):
    schema = render_json_schema(specs["list_alerts"])
    assert schema["properties"]["limit"] == {"type": "integer", "description": specs["list_alerts"].params["limit"].description, "minimum": 1, "maximum": 100}
    assert schema["properties"]["severity"]["enum"] == ["critical", "high", "medium", "low"]
    assert "maxLength" in render_json_schema(specs["search_alerts"])["properties"]["keyword"]


def test_render_tool_for_llm_is_strict(specs):
    t = render_tool_for_llm(specs["get_alert"])
    assert t.name == "get_alert" and t.strict is True
    assert t.input_schema["required"] == ["alert_id"]
    assert specs["get_alert"].to_llm().input_schema == t.input_schema


def test_gemini_declarations_respect_role(registry):
    decls = registry.gemini_function_declarations()
    names = {d["name"] for d in decls}
    assert "queue_endpoint_command" not in names  # analyst context
    assert all(set(d) == {"name", "description", "parameters"} for d in decls)
    assert all(d["parameters"]["additionalProperties"] is False for d in decls)


# ---------------------------------------------------------------------------
# Scoping discipline (source scan)
# ---------------------------------------------------------------------------


def test_no_bare_select_outside_scoped_helpers():
    source = inspect.getsource(module)
    exempt = (module._org_users, module._playbook_scope, module._audit_log_scope, module._simulation_test_scope,
              AgentToolRegistry._scoped_get, AgentToolRegistry.resolve_by_value)
    for fn in exempt:
        source = source.replace(inspect.getsource(fn), "")
    offenders = [
        line.strip() for line in source.splitlines()
        if re.search(r"\bselect\(", line) and "_scoped(" not in line and not line.lstrip().startswith("#")
    ]
    assert offenders == [], f"unscoped select() calls: {offenders}"


def test_no_legacy_default_org_or_system_user():
    source = inspect.getsource(module)
    assert "_get_or_create_default_org" not in source
    assert "_get_or_create_system_user" not in source
    assert '"agent"' not in source.replace('trigger_source="agent"', "").replace('"agent_tool"', "")


def test_scoped_rejects_models_without_org(registry):
    from sqlalchemy import select

    from src.attack.models import AttackTechnique

    with pytest.raises(TypeError):
        registry._scoped(select(AttackTechnique), AttackTechnique)
