import pytest
from unittest.mock import AsyncMock

from src.agentic.engine import AgenticSOCEngine
from src.agentic.guardrails import Guardrails
from src.agentic.skills import registry
from src.agentic.tools import ToolExecutor


@pytest.mark.asyncio
class TestSkillRegistry:
    async def test_list_skills_contains_expert_names(self):
        skills = registry.list_skills()
        assert "triage_gather_evidence" in skills
        assert "threat_hunt_from_alert" in skills
        assert "ioc_contextualization" in skills
        assert "incident_response_recommendation" in skills
        assert "summarize_investigation" in skills

    async def test_run_skill_unknown_raises(self):
        with pytest.raises(KeyError):
            await registry.run_skill("not_a_skill")

    async def test_run_skill_recommendation(self):
        result = await registry.run_skill(
            "incident_response_recommendation",
            tool_executor=None,
            incident_summary="Suspicious login from foreign country",
            severity="high",
        )
        assert result["severity"] == "high"
        assert "Notify incident response team" in result["recommended_actions"]
        assert result["analyst_level"] == "expert"


@pytest.mark.asyncio
class TestGuardrails:
    async def test_block_high_risk_tool(self):
        guardrails = Guardrails()
        allowed, reason = await guardrails.check_tool_call(
            "isolate_host", {"hostname": "host1"}, user_id="u1", organization_id="org1"
        )
        assert allowed is False
        assert reason == "tool_requires_human_approval"

    async def test_rate_limit_blocks_after_threshold(self):
        guardrails = Guardrails(window_seconds=1, max_calls_per_window=2)
        for _ in range(2):
            allowed, reason = await guardrails.check_tool_call(
                "lookup_ioc", {"indicator": "1.2.3.4"}, organization_id="org1"
            )
            assert allowed is True
            assert reason is None

        allowed, reason = await guardrails.check_tool_call(
            "lookup_ioc", {"indicator": "1.2.3.4"}, organization_id="org1"
        )
        assert allowed is False
        assert reason == "rate_limited"

    async def test_suspicious_input_is_blocked(self):
        guardrails = Guardrails()
        allowed, reason = await guardrails.check_tool_call(
            "lookup_ioc", {"indicator": "1.2.3.4; rm -rf /"}, organization_id="org1"
        )
        assert allowed is False
        assert reason.startswith("suspicious_input")


@pytest.mark.asyncio
class TestToolExecutorSkills:
    async def test_execute_run_skill_returns_success(self):
        executor = ToolExecutor()
        response = await executor.run_skill(
            "incident_response_recommendation",
            incident_summary="High-risk ransomware activity",
            severity="critical",
        )
        assert response["success"] is True
        assert response["skill"] == "incident_response_recommendation"
        assert response["result"]["severity"] == "critical"

    async def test_run_expert_skill_with_tool_executor(self):
        executor = ToolExecutor()
        executor.execute = AsyncMock(return_value={"status": "success", "result": {"title": "alert"}})

        result = await registry.run_skill(
            "threat_hunt_from_alert",
            tool_executor=executor,
            alert_id="alert-123",
        )

        assert "alert_context" in result
        assert "siem_correlation" in result
        assert result["alert_context"]["status"] == "success"

    async def test_triac_gather_evidence_skill_requires_executor(self):
        result = await registry.run_skill(
            "triage_gather_evidence",
            tool_executor=None,
            alert_id="alert-123",
        )
        assert result["status"] == "error"
        assert result["error"] == "tool_executor_required"

    async def test_engine_run_skill_forwards_to_tool_executor(self):
        engine = AgenticSOCEngine(db=AsyncMock(), llm_orchestrator=None)
        engine.tool_executor.run_skill = AsyncMock(
            return_value={
                "success": True,
                "skill": "incident_response_recommendation",
                "result": {"severity": "medium"},
            }
        )

        result = await engine.run_skill(
            "incident_response_recommendation",
            incident_summary="Test incident summary",
            severity="medium",
        )

        assert result["success"] is True
        assert result["skill"] == "incident_response_recommendation"
        assert result["result"]["severity"] == "medium"
        engine.tool_executor.run_skill.assert_awaited_once_with(
            "incident_response_recommendation",
            db=engine.db,
            incident_summary="Test incident summary",
            severity="medium",
        )
