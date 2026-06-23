"""The destructive-tool authorization gate must cover every action tool.

Background: ``execute_integration_action`` (which fires arbitrary
connector-specific API actions on third-party integrations) was registered
as a category="action" tool but was missing from DESTRUCTIVE_TOOLS, so the
chat agent could invoke it with authorize_actions=False. The gate was a
local variable inside the endpoint, so the omission was invisible.

The gate is now a module-level constant with a hard invariant: every
action-category tool is either gated (DESTRUCTIVE_TOOLS) or explicitly
allow-listed as documentation-only (UNGATED_ACTION_TOOLS). A new action
tool that lands in neither set fails this test — the gate cannot silently
drift again.
"""

from unittest.mock import AsyncMock

from src.api.v1.endpoints.agentic import DESTRUCTIVE_TOOLS, UNGATED_ACTION_TOOLS
from src.services.agent_tools import AgentToolRegistry


def _action_tools() -> set[str]:
    reg = AgentToolRegistry(AsyncMock())
    return {name for name, tool in reg.tools.items() if tool.category == "action"}


def test_execute_integration_action_is_gated():
    assert "execute_integration_action" in DESTRUCTIVE_TOOLS


def test_every_action_tool_is_gated_or_explicitly_ungated():
    action_tools = _action_tools()
    classified = DESTRUCTIVE_TOOLS | UNGATED_ACTION_TOOLS
    ungoverned = action_tools - classified
    assert not ungoverned, (
        "These action-category tools are neither gated nor allow-listed as "
        f"documentation-only — classify each: {sorted(ungoverned)}"
    )


def test_gate_and_allowlist_are_disjoint():
    assert not (DESTRUCTIVE_TOOLS & UNGATED_ACTION_TOOLS)


def test_ungated_tools_are_documentation_only():
    # Guard the allow-list itself: only note/findings documentation belongs here.
    assert UNGATED_ACTION_TOOLS == {"add_incident_note", "update_incident_findings"}
