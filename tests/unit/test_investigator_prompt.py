"""Invariants of the autonomous investigator's system prompt.

The prompt is the contract between the runtime and the model. It is now built
by ``src.agentic.prompts.build_system_prompt`` for every mode (the
investigator's own ``_SYSTEM_PROMPT`` constant is gone, along with the
free-text verdict JSON contract it described: the verdict is a tool).

These tests pin the parts the autonomous run depends on, so a future prompt
rewrite cannot silently drop a safety rule or the verdict instruction.
"""

from src.agentic.context import Mode, UserRole
from src.agentic.prompts import PROMPT_VERSION, build_system_prompt

TOOLS = ["list_alerts", "get_alert", "list_playbooks", "get_playbook", "submit_verdict"]


def _autonomous(lockdown: bool = False) -> str:
    return build_system_prompt(Mode.AUTONOMOUS, UserRole.ANALYST, TOOLS, lockdown)


def test_verdict_is_a_tool_not_a_json_blob():
    prompt = _autonomous()
    assert "submit_verdict" in prompt
    assert "recommended_actions" in prompt
    # The old contract told the model to emit a fenced JSON verdict.
    assert "```json" not in prompt
    assert "never emit a verdict as prose" in prompt


def test_old_module_level_prompt_is_gone():
    import src.agentic.investigator as investigator

    assert not hasattr(investigator, "_SYSTEM_PROMPT")


def test_only_the_offered_tools_are_named():
    prompt = _autonomous()
    for tool in TOOLS:
        assert f"`{tool}`" in prompt
    assert "do not invent others" in prompt


def test_prompt_injection_defense_present():
    prompt = _autonomous()
    assert "UNTRUSTED DATA" in prompt
    assert "injection attempts" in prompt
    # Data can never lift a policy decision.
    assert "lockdown" in prompt.lower()


def test_anti_fabrication_rule_present():
    prompt = _autonomous()
    assert "fabricate" in prompt.lower()
    assert "Never claim an action was taken unless a tool result confirms it" in prompt


def test_playbook_grounding_references_real_tools():
    prompt = _autonomous()
    assert "list_playbooks" in prompt
    assert "get_playbook" in prompt


def test_operational_rules_survive_merge():
    prompt = _autonomous()
    assert "configured_integrations" in prompt
    assert "PROHIBITED" in prompt
    assert "block_ip" in prompt and "isolate_host" in prompt


def test_lockdown_notice_is_appended_when_flagged():
    assert "LOCKDOWN IN EFFECT" not in _autonomous()
    assert "LOCKDOWN IN EFFECT" in _autonomous(lockdown=True)


def test_prompt_records_mode_and_version():
    prompt = _autonomous()
    assert PROMPT_VERSION in prompt
    assert "Mode: autonomous" in prompt
