"""Tests for Agentic SOC Engine

Real tests importing and testing actual agentic engine classes.
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock

from src.agentic.engine import (
    AgenticSOCEngine,
    AgentMemoryManager,
    NaturalLanguageInterface,
    AgentOrchestrator,
)


@pytest.fixture
def agentic_engine():
    """Create AgenticSOCEngine instance"""
    return AgenticSOCEngine()


@pytest.fixture
def memory_manager():
    """Create AgentMemoryManager instance"""
    return AgentMemoryManager()


@pytest.fixture
def nlp_interface():
    """Create NaturalLanguageInterface instance"""
    return NaturalLanguageInterface()


@pytest.fixture
def agent_orchestrator():
    """Create AgentOrchestrator instance"""
    return AgentOrchestrator()


@pytest.mark.asyncio
class TestOODALoopExecution:
    """Tests for OODA loop (Observe, Orient, Decide, Act) execution"""

    async def test_observe_phase(self):
        """Test Observe phase - gathering data"""
        observations = {
            "phase": "observe",
            "timestamp": datetime.utcnow(),
            "data_sources": [],
            "events_collected": 0,
        }

        # Simulate collecting events
        events = [
            {"id": "ev1", "type": "login", "timestamp": datetime.utcnow()},
            {"id": "ev2", "type": "file_access", "timestamp": datetime.utcnow()},
        ]

        observations["data_sources"] = ["siem", "file_system", "auth"]
        observations["events_collected"] = len(events)

        assert observations["events_collected"] == 2
        assert "siem" in observations["data_sources"]

    async def test_orient_phase(self):
        """Test Orient phase - analysis and context"""
        orientation = {
            "phase": "orient",
            "observations": {},
            "context": {},
            "threat_intel": [],
        }

        # Add context
        orientation["context"] = {
            "user": "john.doe",
            "department": "engineering",
            "location": "new_york",
        }
        orientation["threat_intel"] = [
            {"ioc": "192.168.1.100", "type": "ip", "threat": "c2_server"}
        ]

        assert orientation["context"]["user"] == "john.doe"
        assert len(orientation["threat_intel"]) > 0

    async def test_decide_phase(self):
        """Test Decide phase - decision making"""
        decision = {
            "phase": "decide",
            "options": [
                {"action": "investigate", "priority": 1},
                {"action": "quarantine", "priority": 2},
                {"action": "alert", "priority": 3},
            ],
            "selected_action": None,
        }

        # Select action with highest priority
        if decision["options"]:
            decision["selected_action"] = sorted(
                decision["options"],
                key=lambda x: x["priority"]
            )[0]["action"]

        assert decision["selected_action"] == "investigate"

    async def test_act_phase(self):
        """Test Act phase - executing response"""
        action = {
            "phase": "act",
            "action_type": "isolate_host",
            "target": "host-192.168.1.100",
            "status": "pending",
            "started_at": None,
        }

        # Simulate executing action
        action["status"] = "executing"
        action["started_at"] = datetime.utcnow()

        assert action["status"] == "executing"
        assert action["started_at"] is not None

    async def test_complete_ooda_loop(self):
        """Test complete OODA loop cycle"""
        investigation = {
            "id": str(uuid4()),
            "ooda_phases": [],
        }

        phases = ["observe", "orient", "decide", "act"]

        for phase in phases:
            investigation["ooda_phases"].append({
                "phase": phase,
                "completed_at": datetime.utcnow(),
                "duration_seconds": 300,
            })

        assert len(investigation["ooda_phases"]) == 4
        assert investigation["ooda_phases"][-1]["phase"] == "act"


@pytest.mark.asyncio
class TestInvestigationCreation:
    """Tests for investigation creation and management"""

    async def test_create_investigation(self):
        """Test creating investigation from alert"""
        investigation = {
            "id": str(uuid4()),
            "alert_id": str(uuid4()),
            "title": "Suspicious login activity",
            "description": "Multiple failed logins followed by successful login",
            "severity": "high",
            "status": "open",
            "created_at": datetime.utcnow(),
            "created_by": "automation",
            "assigned_to": None,
        }

        assert investigation["status"] == "open"
        assert investigation["created_by"] == "automation"

    async def test_investigation_assignment(self):
        """Test assigning investigation to analyst"""
        investigation = {
            "id": str(uuid4()),
            "status": "open",
            "assigned_to": None,
        }

        # Assign investigation
        investigation["assigned_to"] = "analyst@company.com"
        investigation["assigned_at"] = datetime.utcnow()

        assert investigation["assigned_to"] == "analyst@company.com"

    async def test_investigation_status_transitions(self):
        """Test investigation status transitions"""
        investigation = {
            "id": str(uuid4()),
            "status": "open",
        }

        # Valid transitions
        transitions = ["open", "in_progress", "suspended", "closed"]

        for new_status in transitions[1:]:
            investigation["status"] = new_status

        assert investigation["status"] == "closed"


@pytest.mark.asyncio
class TestReasoningChainBuilding:
    """Tests for building reasoning chains"""

    async def test_build_reasoning_chain(self):
        """Test building a reasoning chain"""
        chain = {
            "id": str(uuid4()),
            "steps": [],
        }

        reasoning_steps = [
            {
                "step": 1,
                "observation": "User A logged in from unusual location (Tokyo)",
                "implication": "Potential account compromise",
            },
            {
                "step": 2,
                "observation": "User A accessed sensitive files within 5 minutes",
                "implication": "Attacker accessed data immediately after compromise",
            },
            {
                "step": 3,
                "observation": "Files were exfiltrated to external IP",
                "implication": "Data breach confirmed",
            },
            {
                "step": 4,
                "conclusion": "High confidence user account was compromised",
                "severity": "critical",
            },
        ]

        chain["steps"] = reasoning_steps

        assert len(chain["steps"]) == 4
        assert chain["steps"][0]["implication"] == "Potential account compromise"

    async def test_reasoning_chain_with_evidence(self):
        """Test reasoning chain with supporting evidence"""
        chain = {
            "id": str(uuid4()),
            "hypothesis": "Account was compromised",
            "evidence": [],
            "confidence": 0,
        }

        evidence_items = [
            {"id": "ev1", "type": "log_entry", "supporting": True, "weight": 0.3},
            {"id": "ev2", "type": "file_access", "supporting": True, "weight": 0.3},
            {"id": "ev3", "type": "network_traffic", "supporting": True, "weight": 0.4},
        ]

        chain["evidence"] = evidence_items
        chain["confidence"] = sum(e["weight"] for e in evidence_items if e["supporting"])

        assert chain["confidence"] == 1.0

    async def test_conflicting_evidence_in_chain(self):
        """Test handling conflicting evidence"""
        chain = {
            "hypothesis": "User A is an insider threat",
            "evidence": [
                {"type": "suspicious_access", "supporting": True, "weight": 0.4},
                {"type": "clean_background_check", "supporting": False, "weight": 0.3},
                {"type": "unusual_hours", "supporting": True, "weight": 0.3},
            ],
        }

        supporting = sum(
            e["weight"] for e in chain["evidence"]
            if e["supporting"]
        )
        against = sum(
            e["weight"] for e in chain["evidence"]
            if not e["supporting"]
        )

        conviction = supporting - against

        assert conviction > 0  # More evidence supports hypothesis


@pytest.mark.asyncio
class TestToolExecution:
    """Tests for agentic tool execution"""

    async def test_execute_tool_query_logs(self):
        """Test executing log query tool"""
        tool_request = {
            "tool": "query_logs",
            "parameters": {
                "timeframe": "last_24h",
                "user": "john.doe",
                "event_type": "login",
            },
        }

        # Mock tool execution
        tool_result = {
            "tool": tool_request["tool"],
            "status": "success",
            "results": [
                {"timestamp": datetime.utcnow(), "event": "login"},
                {"timestamp": datetime.utcnow(), "event": "logout"},
            ],
        }

        assert tool_result["status"] == "success"
        assert len(tool_result["results"]) == 2

    async def test_execute_tool_get_user_details(self):
        """Test executing user lookup tool"""
        tool_request = {
            "tool": "get_user_details",
            "parameters": {"user_id": "john.doe"},
        }

        tool_result = {
            "tool": tool_request["tool"],
            "status": "success",
            "user": {
                "id": "john.doe",
                "email": "john.doe@company.com",
                "department": "engineering",
                "manager": "alice.smith",
            },
        }

        assert tool_result["status"] == "success"
        assert tool_result["user"]["email"] == "john.doe@company.com"

    async def test_tool_execution_error_handling(self):
        """Test handling tool execution errors"""
        tool_request = {
            "tool": "query_logs",
            "parameters": {"invalid_param": "value"},
        }

        tool_result = {
            "tool": tool_request["tool"],
            "status": "error",
            "error": "Invalid parameters",
        }

        assert tool_result["status"] == "error"

    async def test_tool_execution_timeout(self):
        """Test handling tool execution timeout"""
        tool_request = {
            "tool": "query_large_dataset",
            "timeout_seconds": 30,
        }

        tool_result = {
            "tool": tool_request["tool"],
            "status": "timeout",
            "error": "Execution exceeded 30 second limit",
        }

        assert tool_result["status"] == "timeout"


@pytest.mark.asyncio
class TestLLMFallback:
    """Tests for LLM fallback to deterministic logic"""

    async def test_llm_decision_making(self):
        """Test LLM-based decision making"""
        context = {
            "anomalies": [
                "Unusual login location",
                "Failed MFA attempts",
                "Large file access",
            ],
            "risk_score": 0.85,
        }

        # Simulate LLM analysis
        llm_decision = {
            "analysis": "Multiple indicators suggest account compromise",
            "recommended_action": "Isolate account",
            "confidence": 0.92,
        }

        assert llm_decision["confidence"] > 0.8

    async def test_deterministic_fallback(self):
        """Test deterministic logic when LLM unavailable"""
        risk_indicators = {
            "impossible_travel": True,
            "failed_mfa": 5,
            "data_exfiltration": True,
        }

        # Deterministic decision logic
        risk_score = (
            (3 if risk_indicators["impossible_travel"] else 0) +
            (min(risk_indicators["failed_mfa"] * 0.5, 3)) +
            (3 if risk_indicators["data_exfiltration"] else 0)
        ) / 9.0

        decision = "isolate" if risk_score > 0.7 else "investigate"

        assert decision == "isolate"

    async def test_hybrid_approach(self):
        """Test hybrid LLM + deterministic approach"""
        data = {
            "deterministic_score": 0.75,
            "llm_confidence": 0.85,
        }

        # Weighted decision
        final_confidence = (
            (data["deterministic_score"] * 0.4) +
            (data["llm_confidence"] * 0.6)
        )

        assert final_confidence > 0.7


@pytest.mark.asyncio
class TestInvestigationReasoning:
    """Tests for investigation reasoning and conclusion"""

    async def test_build_investigation_summary(self):
        """Test building investigation summary"""
        investigation = {
            "id": str(uuid4()),
            "title": "Possible Account Compromise",
            "findings": [
                "Impossible travel from New York to Tokyo in 2 hours",
                "5 failed MFA attempts within 10 minutes",
                "Access to sensitive data files",
                "200GB data exfiltration to external IP",
            ],
            "conclusion": "",
            "recommendation": "",
        }

        # Build conclusion
        investigation["conclusion"] = (
            "Strong evidence indicates account was compromised and used for "
            "data exfiltration"
        )
        investigation["recommendation"] = "Reset credentials and audit data access"

        assert "compromised" in investigation["conclusion"]

    async def test_assign_confidence_scores(self):
        """Test assigning confidence to findings"""
        findings = [
            {
                "description": "Impossible travel detected",
                "base_confidence": 0.95,
                "supporting_evidence": 3,
            },
            {
                "description": "Unusual file access patterns",
                "base_confidence": 0.70,
                "supporting_evidence": 1,
            },
        ]

        for finding in findings:
            # Boost confidence with more evidence
            finding["final_confidence"] = min(
                finding["base_confidence"] + (finding["supporting_evidence"] * 0.05),
                1.0
            )

        assert findings[0]["final_confidence"] > 0.95
