"""Schema validation tests for the closed ActionType enum + Pydantic models.

The enum values are the canonical RemediationAction.action_type strings
(firewall_block, host_isolate, etc.) — not the colloquial spec names.
Tests here are pure schema validation; the capability gate test in
tests/integration/test_action_handlers_are_real.py verifies each enum
value actually maps to a real handler.
"""

from pydantic import ValidationError
import pytest

from src.agentic.action_classifier import (
    ActionType,
    ClassifiedAction,
    ActionClassification,
)


class TestActionTypeEnum:
    def test_has_exactly_seven_values(self):
        assert len(ActionType) == 7

    def test_canonical_values(self):
        assert ActionType.FIREWALL_BLOCK.value == "firewall_block"
        assert ActionType.HOST_ISOLATE.value == "host_isolate"
        assert ActionType.ACCOUNT_DISABLE.value == "account_disable"
        assert ActionType.PASSWORD_RESET.value == "password_reset"
        assert ActionType.PROCESS_KILL.value == "process_kill"
        assert ActionType.FILE_QUARANTINE.value == "file_quarantine"
        assert ActionType.COLLECT_FORENSICS.value == "collect_forensics"


class TestClassifiedActionSchema:
    def test_valid_classified_action(self):
        a = ClassifiedAction(
            recommendation_text="block 1.2.3.4 at the firewall",
            action_type=ActionType.FIREWALL_BLOCK,
            args={"ip": "1.2.3.4"},
        )
        assert a.action_type == ActionType.FIREWALL_BLOCK
        assert a.args["ip"] == "1.2.3.4"

    def test_invalid_action_type_rejected(self):
        with pytest.raises(ValidationError):
            ClassifiedAction(
                recommendation_text="x",
                action_type="block_ip",  # colloquial; not in enum
                args={},
            )

    def test_args_must_be_dict(self):
        with pytest.raises(ValidationError):
            ClassifiedAction(
                recommendation_text="x",
                action_type=ActionType.FIREWALL_BLOCK,
                args="not a dict",
            )


class TestActionClassificationSchema:
    def test_empty_lists_valid(self):
        c = ActionClassification(actions=[], unsupported=[])
        assert c.actions == []
        assert c.unsupported == []

    def test_full_classification(self):
        c = ActionClassification(
            actions=[
                ClassifiedAction(
                    recommendation_text="block c2",
                    action_type=ActionType.FIREWALL_BLOCK,
                    args={"ip": "203.0.113.42"},
                )
            ],
            unsupported=["schedule a tabletop exercise next quarter"],
        )
        assert len(c.actions) == 1
        assert c.actions[0].action_type == ActionType.FIREWALL_BLOCK
        assert c.unsupported == ["schedule a tabletop exercise next quarter"]
