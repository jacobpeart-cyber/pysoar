"""Invariants of the autonomous investigator's system prompt.

The prompt is the contract between the OODA loop code and the LLM. These
tests pin the parts the runtime depends on, so a future prompt rewrite
can't silently break verdict parsing or drop safety rules.
"""

from src.agentic.investigator import _SYSTEM_PROMPT


def test_json_verdict_contract_is_present():
    # _extract_verdict() looks for a ```json fence with these exact keys.
    for marker in (
        '"verdict"',
        '"confidence"',
        '"reasoning"',
        '"mitre_techniques"',
        '"affected_assets"',
        '"recommendations"',
        "```json",
        "true_positive",
        "false_positive",
        "inconclusive",
    ):
        assert marker in _SYSTEM_PROMPT, f"verdict contract lost: {marker}"


def test_prompt_injection_defense_present():
    # Logs/alerts/tickets are attacker-controllable; the agent must treat
    # their content as data, never as instructions.
    assert "untrusted" in _SYSTEM_PROMPT.lower()


def test_anti_fabrication_rule_present():
    assert "fabricate" in _SYSTEM_PROMPT.lower()


def test_playbook_grounding_references_real_tools():
    # The knowledge-grounding mandate must point at tools that exist.
    assert "list_playbooks" in _SYSTEM_PROMPT
    assert "get_playbook" in _SYSTEM_PROMPT


def test_operational_rules_survive_merge():
    assert "configured_integrations" in _SYSTEM_PROMPT
    assert "PROHIBITED" in _SYSTEM_PROMPT
