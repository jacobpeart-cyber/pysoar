"""
Core Agentic SOC Engine

Implements the autonomous investigation loop following the OODA cycle
(Observe-Orient-Decide-Act), with long-term memory, natural language interface,
and multi-agent orchestration.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.agentic.models import (
    SOCAgent,
    Investigation,
    ReasoningStep,
    AgentAction,
    AgentMemory,
    InvestigationStatus,
    StepType,
    ActionType,
    ActionTool,
    ActionExecutionStatus,
    MemoryType,
    ResolutionType,
)
from src.core.config import settings

logger = logging.getLogger(__name__)

# LLM integration (optional, set USE_LLM_ENABLED in config)
try:
    from src.agentic.llm import LLMOrchestrator, LocalProvider
    from src.agentic.tools import SecurityTools, ToolExecutor
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.warning("LLM modules not available, using deterministic investigation")


class AgenticSOCEngine:
    """
    Core autonomous investigation engine

    Orchestrates the complete OODA loop for security investigations.
    Manages hypothesis generation, evidence gathering, reasoning, and action
    execution with support for human approval workflows.
    """

    def __init__(self, db: AsyncSession, llm_orchestrator: Optional[Any] = None):
        """
        Initialize engine with database session

        Args:
            db: Async database session
            llm_orchestrator: Optional LLMOrchestrator for enhanced investigations
        """
        self.db = db
        self.memory_manager = AgentMemoryManager(db)
        self.nl_interface = NaturalLanguageInterface(db)
        self.llm_orchestrator = llm_orchestrator
        self.tool_executor = None
        self.use_llm = settings.get("AGENTIC_LLM_ENABLED", False) and LLM_AVAILABLE

        if self.use_llm and self.llm_orchestrator:
            self.tool_executor = ToolExecutor()
            logger.info("Agentic SOC Engine initialized with LLM support")

    async def investigate(
        self,
        agent_id: str,
        organization_id: str,
        trigger_type: str,
        trigger_source_id: str,
        title: str,
        initial_context: Optional[dict] = None,
    ) -> Investigation:
        """
        Initiate autonomous investigation

        Main entry point: receives alert/anomaly, creates investigation,
        and starts the autonomous reasoning loop.

        Args:
            agent_id: SOC Agent ID
            organization_id: Organization context
            trigger_type: Type of trigger (alert, anomaly, etc)
            trigger_source_id: ID of the triggering entity
            title: Investigation title
            initial_context: Optional context data

        Returns:
            Investigation object
        """
        logger.info(f"Starting investigation: {title}")

        # Create investigation record
        investigation = Investigation(
            agent_id=agent_id,
            organization_id=organization_id,
            trigger_type=trigger_type,
            trigger_source_id=trigger_source_id,
            title=title,
            status=InvestigationStatus.INITIATED.value,
            priority=3,
            confidence_score=0.0,
            reasoning_chain=json.dumps([]),
            evidence_collected=json.dumps(initial_context or {}),
            actions_taken=json.dumps([]),
        )

        self.db.add(investigation)
        await self.db.flush()

        # Start reasoning loop
        await self._reasoning_loop(agent_id, investigation)

        await self.db.commit()
        return investigation

    async def _reasoning_loop(
        self,
        agent_id: str,
        investigation: Investigation,
    ) -> None:
        """
        Execute the OODA reasoning loop

        Repeatedly calls reason_step until investigation is complete
        or max steps reached.
        """
        agent = await self.db.get(SOCAgent, agent_id)
        if not agent:
            raise ValueError(f"Agent {agent_id} not found")

        max_steps = agent.max_reasoning_steps
        step_count = 0

        while step_count < max_steps:
            if investigation.status in [
                InvestigationStatus.COMPLETED.value,
                InvestigationStatus.ESCALATED.value,
                InvestigationStatus.ABANDONED.value,
            ]:
                break

            await self.reason_step(agent_id, investigation)
            step_count += 1
            logger.debug(f"Completed reasoning step {step_count}")

        if investigation.status == InvestigationStatus.REASONING.value:
            await self.conclude_investigation(agent_id, investigation)

    async def reason_step(
        self,
        agent_id: str,
        investigation: Investigation,
    ) -> ReasoningStep:
        """
        Execute one OODA cycle iteration

        - Observe: Gather current evidence
        - Orient: Contextualize with agent memory
        - Decide: Determine next action
        - Act: Execute or propose action

        Returns:
            ReasoningStep object
        """
        logger.debug(f"Executing reasoning step for investigation {investigation.id}")

        step_num = len(investigation.reasoning_steps) + 1
        start_time = datetime.now(timezone.utc)

        # Observe: Determine what information we need
        step_type = await self._determine_next_step(investigation)
        observation = await self.gather_evidence(agent_id, investigation, step_type)

        # Orient: Analyze evidence in context
        analysis = await self.analyze_evidence(observation)

        # Decide: Update hypothesis and confidence
        if step_type == StepType.HYPOTHESIZE.value:
            hypothesis = await self.generate_hypothesis(
                investigation, analysis
            )
            investigation.hypothesis = hypothesis
            confidence_delta = 15.0
        else:
            confidence_delta = await self.evaluate_hypothesis(
                investigation, analysis
            )

        # Act: Decide next action
        decision = await self.decide_action(investigation, confidence_delta)

        # Create reasoning step record
        step = ReasoningStep(
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            step_number=step_num,
            step_type=step_type,
            thought_process=decision.get("reasoning", ""),
            action_tool=decision.get("tool", None),
            action_parameters=json.dumps(decision.get("parameters", {})),
            observation=json.dumps(observation),
            confidence_delta=confidence_delta,
            duration_ms=int(
                (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            ),
            tokens_used=decision.get("tokens_used", 0),
        )

        self.db.add(step)
        investigation.reasoning_steps.append(step)

        # Update investigation confidence
        investigation.confidence_score = min(
            100.0, investigation.confidence_score + confidence_delta
        )

        # Execute action if needed
        if decision.get("action"):
            action = await self.execute_action(agent_id, investigation, decision)
            if action:
                investigation.actions.append(action)

        # Update status
        if decision.get("status"):
            investigation.status = decision["status"]

        await self.db.flush()
        return step

    async def _determine_next_step(
        self,
        investigation: Investigation,
    ) -> str:
        """Determine what type of step to execute next"""
        if not investigation.hypothesis:
            return StepType.HYPOTHESIZE.value

        steps = len(investigation.reasoning_steps)
        if steps == 0:
            return StepType.OBSERVE.value
        elif steps < 3:
            return StepType.GATHER_EVIDENCE.value
        elif steps < 6:
            return StepType.ANALYZE.value
        elif investigation.confidence_score < 70:
            return StepType.CORRELATE.value
        else:
            return StepType.DECIDE.value

    async def gather_evidence(
        self,
        agent_id: str,
        investigation: Investigation,
        evidence_type: str,
    ) -> dict:
        """
        Gather evidence relevant to hypothesis

        Queries SIEM, EDR, threat intel, logs based on investigation context.
        Returns evidence data to feed into analysis.

        Args:
            agent_id: Agent ID
            investigation: Current investigation
            evidence_type: Type of evidence to gather

        Returns:
            Evidence dictionary
        """
        logger.debug(f"Gathering evidence for investigation {investigation.id}")

        evidence = {
            "source": evidence_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {},
        }

        # Simulate evidence gathering from different sources
        if evidence_type == StepType.OBSERVE.value:
            evidence["data"] = {
                "alert_count": 5,
                "affected_systems": 3,
                "time_window": "last_24h",
            }
        elif evidence_type == StepType.GATHER_EVIDENCE.value:
            evidence["data"] = {
                "siem_events": 150,
                "edr_detections": 8,
                "threat_intel_hits": 2,
                "anomaly_score": 0.78,
            }
        elif evidence_type == StepType.ANALYZE.value:
            evidence["data"] = {
                "event_correlation": "5 related events",
                "pattern_match": "Lateral movement indicators",
                "risk_assessment": "High",
            }
        elif evidence_type == StepType.CORRELATE.value:
            evidence["data"] = {
                "related_investigations": 2,
                "similar_patterns": "3 previous cases",
                "threat_actor": "APT28",
                "confidence": 0.85,
            }

        return evidence

    async def analyze_evidence(self, evidence: dict) -> dict:
        """
        Analyze gathered evidence

        Performs pattern matching, anomaly scoring, correlation.
        Returns analysis results with key findings.

        Args:
            evidence: Evidence dictionary

        Returns:
            Analysis results
        """
        analysis = {
            "anomaly_score": 0.0,
            "patterns_found": [],
            "correlations": [],
            "risk_level": "unknown",
        }

        evidence_data = evidence.get("data", {})

        # Simulate pattern matching
        if evidence_data.get("anomaly_score", 0) > 0.7:
            analysis["anomaly_score"] = evidence_data["anomaly_score"]
            analysis["risk_level"] = "high"
            analysis["patterns_found"] = [
                "Unusual process execution",
                "Network anomaly",
            ]

        if "related_investigations" in evidence_data:
            analysis["correlations"] = [
                "Similar to investigation 2 weeks ago",
                "Matches known APT pattern",
            ]

        return analysis

    async def generate_hypothesis(
        self,
        investigation: Investigation,
        analysis: dict,
    ) -> str:
        """
        Generate initial hypothesis based on evidence

        Uses analysis and agent memory to propose what's happening.

        Args:
            investigation: Current investigation
            analysis: Analysis results

        Returns:
            Hypothesis string
        """
        risk_level = analysis.get("risk_level", "unknown")
        patterns = analysis.get("patterns_found", [])

        if risk_level == "high" and patterns:
            hypothesis = f"Potential {patterns[0]} detected. Possible lateral movement or data exfiltration attack in progress."
        elif risk_level == "medium":
            hypothesis = (
                "Suspicious activity detected. Investigating for true positive."
            )
        else:
            hypothesis = "Anomalous behavior detected. Requires further investigation."

        logger.debug(f"Generated hypothesis: {hypothesis}")
        return hypothesis

    async def evaluate_hypothesis(
        self,
        investigation: Investigation,
        analysis: dict,
    ) -> float:
        """
        Evaluate confidence in current hypothesis

        Scores hypothesis against evidence, identifies gaps.
        Returns confidence delta.

        Args:
            investigation: Current investigation
            analysis: Analysis results

        Returns:
            Confidence delta (0-100)
        """
        correlations = len(analysis.get("correlations", []))
        patterns = len(analysis.get("patterns_found", []))
        anomaly_score = analysis.get("anomaly_score", 0.0)

        # Simple scoring: more evidence = higher confidence
        confidence_delta = (
            (correlations * 10) + (patterns * 15) + (anomaly_score * 30)
        ) / 3
        confidence_delta = min(100.0, confidence_delta)

        return confidence_delta

    async def decide_action(
        self,
        investigation: Investigation,
        confidence_delta: float,
    ) -> dict:
        """
        Decide what action to take next

        Based on confidence, autonomy level, and findings.
        Returns decision dict with next action.

        Args:
            investigation: Current investigation
            confidence_delta: Change in confidence

        Returns:
            Decision dictionary with action, status, etc
        """
        current_confidence = investigation.confidence_score + confidence_delta

        decision = {
            "reasoning": f"Confidence now at {current_confidence:.1f}",
            "action": None,
            "status": None,
            "tokens_used": 250,
        }

        if current_confidence > 85:
            decision["action"] = {
                "type": ActionType.CREATE_TICKET.value,
                "target": "true_positive_queue",
                "priority": "high",
            }
            decision["status"] = InvestigationStatus.ACTION_PROPOSED.value
        elif current_confidence < 30:
            decision["status"] = InvestigationStatus.ABANDONED.value
        else:
            decision["status"] = InvestigationStatus.REASONING.value

        return decision

    async def execute_action(
        self,
        agent_id: str,
        investigation: Investigation,
        decision: dict,
    ) -> Optional[AgentAction]:
        """
        Execute or propose action

        Based on autonomy level, either executes or requires approval.

        Args:
            agent_id: Agent ID
            investigation: Current investigation
            decision: Decision with action details

        Returns:
            AgentAction object or None
        """
        if not decision.get("action"):
            return None

        action_data = decision["action"]
        action = AgentAction(
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            action_type=action_data.get("type", ActionType.CREATE_TICKET.value),
            target=action_data.get("target", ""),
            parameters=json.dumps(action_data),
            requires_approval=True,
            execution_status=ActionExecutionStatus.PENDING_APPROVAL.value,
        )

        self.db.add(action)
        investigation.status = InvestigationStatus.ACTION_PROPOSED.value

        logger.info(
            f"Proposed action: {action.action_type} on {action.target}"
        )

        return action

    async def verify_action(
        self,
        action_id: str,
    ) -> bool:
        """
        Verify action execution success

        Checks if action had intended effect.

        Args:
            action_id: Action ID to verify

        Returns:
            Success boolean
        """
        action = await self.db.get(AgentAction, action_id)
        if not action:
            return False

        # Simulate verification
        action.result = json.dumps({"status": "success", "timestamp": datetime.now(timezone.utc).isoformat()})
        await self.db.flush()

        return True

    async def investigate_with_llm(
        self,
        alert_data: dict,
        investigation: Investigation,
    ) -> dict:
        """
        LLM-powered investigation with tool use

        Uses LLM to generate investigation plan, execute tools, and analyze results
        in an agentic loop (observe → orient → decide → act).

        Args:
            alert_data: Alert/anomaly data
            investigation: Investigation record

        Returns:
            Investigation result dictionary
        """
        if not self.llm_orchestrator or not self.tool_executor:
            logger.warning("LLM not available, falling back to deterministic mode")
            return {"status": "fallback_to_deterministic"}

        logger.info(f"Starting LLM-powered investigation for {investigation.id}")

        # Step 1: Generate investigation plan
        try:
            plan = await self.llm_orchestrator.investigate_alert(alert_data)
        except Exception as e:
            logger.error(f"Failed to generate investigation plan: {e}")
            return {"status": "plan_generation_failed", "error": str(e)}

        reasoning_chain = []
        collected_evidence = {}

        # Step 2-4: OODA loop with tool execution
        max_iterations = 5
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            logger.debug(f"LLM investigation iteration {iteration}")

            # Observe: Ask LLM what to investigate next
            observation_prompt = f"""Based on this investigation:

Alert: {json.dumps(alert_data, indent=2)}
Plan: {json.dumps(plan, indent=2)}
Evidence collected so far: {json.dumps(collected_evidence, indent=2)}

What is the next investigation step? Should we:
1. Execute specific tools to gather evidence?
2. Correlate findings into a threat narrative?
3. Conclude the investigation?

If executing tools, request them in JSON format like:
{{"tool_calls": [{{"tool": "search_siem_events", "args": {{...}}}}]}}

If concluding, respond with:
{{"action": "conclude", "conclusion": "..."}}
"""

            try:
                response = await self.llm_orchestrator.complete(
                    prompt=observation_prompt,
                    temperature=0.5,
                    max_tokens=1024,
                )

                reasoning_chain.append({
                    "iteration": iteration,
                    "reasoning": response.content,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

                # Parse tool calls from response
                try:
                    # Try to extract JSON from response
                    import re
                    json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
                    if json_match:
                        response_data = json.loads(json_match.group())
                    else:
                        response_data = {}
                except json.JSONDecodeError:
                    logger.warning("Failed to parse LLM response as JSON")
                    response_data = {}

                # Act: Execute tool calls if requested
                if "tool_calls" in response_data:
                    for tool_call in response_data["tool_calls"]:
                        tool_name = tool_call.get("tool")
                        args = tool_call.get("args", {})

                        logger.info(f"Executing tool: {tool_name}")

                        result = await self.tool_executor.execute(
                            tool_name=tool_name,
                            arguments=args,
                            organization_id=investigation.organization_id,
                        )

                        if result.get("success"):
                            collected_evidence[tool_name] = result.get("result")
                        else:
                            logger.warning(f"Tool failed: {result.get('error')}")

                elif response_data.get("action") == "conclude":
                    logger.info("LLM concluding investigation")
                    investigation.findings_summary = response_data.get("conclusion", "")
                    break

            except Exception as e:
                logger.error(f"LLM iteration failed: {e}")
                break

        # Store reasoning chain
        investigation.reasoning_chain = json.dumps(reasoning_chain)
        investigation.evidence_collected = json.dumps(collected_evidence)

        # Update confidence based on evidence
        evidence_count = len(collected_evidence)
        investigation.confidence_score = min(100.0, evidence_count * 20)

        await self.db.flush()

        return {
            "status": "investigation_complete",
            "iterations": iteration,
            "evidence_sources": list(collected_evidence.keys()),
            "confidence_score": investigation.confidence_score,
        }

    async def conclude_investigation(
        self,
        agent_id: str,
        investigation: Investigation,
    ) -> None:
        """
        Summarize findings and update memory

        Finalizes investigation, generates report, learns from outcome.

        Args:
            agent_id: Agent ID
            investigation: Investigation to conclude
        """
        logger.info(f"Concluding investigation {investigation.id}")

        # Generate summary
        investigation.findings_summary = await self._generate_summary(
            investigation
        )

        # Determine resolution type
        if investigation.confidence_score > 80:
            investigation.resolution_type = ResolutionType.TRUE_POSITIVE.value
        elif investigation.confidence_score < 30:
            investigation.resolution_type = ResolutionType.FALSE_POSITIVE.value
        else:
            investigation.resolution_type = ResolutionType.INCONCLUSIVE.value

        # Generate recommendations
        investigation.recommendations = json.dumps(
            await self._generate_recommendations(investigation)
        )

        # Update status
        investigation.status = InvestigationStatus.COMPLETED.value

        # Store learnings in memory
        await self.memory_manager.learn_from_investigation(
            agent_id, investigation
        )

        await self.db.flush()

    async def _generate_summary(
        self,
        investigation: Investigation,
    ) -> str:
        """Generate executive summary of investigation"""
        return (
            f"Investigation completed. Confidence: {investigation.confidence_score:.0f}%. "
            f"Resolution: {investigation.resolution_type}. "
            f"Steps executed: {len(investigation.reasoning_steps)}."
        )

    async def _generate_recommendations(
        self,
        investigation: Investigation,
    ) -> list:
        """Generate recommendations from investigation"""
        recommendations = []

        if investigation.resolution_type == ResolutionType.TRUE_POSITIVE.value:
            recommendations.append("Escalate to incident response team")
            recommendations.append("Block identified IOCs")
            recommendations.append("Notify affected users")

        if investigation.confidence_score > 70:
            recommendations.append("Create case for documentation")
            recommendations.append("Update detection rules if applicable")

        return recommendations

    async def explain_reasoning(
        self,
        investigation_id: str,
    ) -> str:
        """
        Generate natural language explanation of investigation

        Converts technical reasoning chain to human-readable narrative.

        Args:
            investigation_id: Investigation ID

        Returns:
            Natural language explanation
        """
        investigation = await self.db.get(Investigation, investigation_id)
        if not investigation:
            return "Investigation not found"

        explanation = f"Investigation: {investigation.title}\n"
        explanation += f"Status: {investigation.status}\n"
        explanation += f"Confidence: {investigation.confidence_score:.0f}%\n\n"
        explanation += "Reasoning Chain:\n"

        for i, step in enumerate(investigation.reasoning_steps, 1):
            explanation += f"{i}. {step.step_type}: {step.thought_process}\n"

        explanation += f"\nConclusion: {investigation.findings_summary}"

        return explanation


class AgentMemoryManager:
    """
    Manage agent learning and memory

    Stores patterns, baselines, preferences learned from investigations.
    Decays confidence over time on stale patterns.
    """

    def __init__(self, db: AsyncSession):
        """Initialize with database session"""
        self.db = db

    async def store_pattern(
        self,
        agent_id: str,
        organization_id: str,
        memory_type: str,
        key: str,
        value: dict,
        confidence: float = 1.0,
    ) -> AgentMemory:
        """
        Store a learned pattern in agent memory

        Args:
            agent_id: Agent ID
            organization_id: Organization ID
            memory_type: Type of memory (MemoryType enum)
            key: Memory key (e.g., "apt28_lateral_movement")
            value: Memory value (pattern data)
            confidence: Initial confidence (0-1)

        Returns:
            AgentMemory object
        """
        memory = AgentMemory(
            agent_id=agent_id,
            organization_id=organization_id,
            memory_type=memory_type,
            key=key,
            value=json.dumps(value),
            confidence=confidence,
            access_count=0,
            last_accessed=datetime.now(timezone.utc).isoformat(),
            decay_rate=0.95,
        )

        self.db.add(memory)
        await self.db.flush()

        logger.debug(f"Stored pattern: {memory_type}/{key}")
        return memory

    async def recall_similar(
        self,
        agent_id: str,
        context: dict,
        memory_type: Optional[str] = None,
        limit: int = 5,
    ) -> list[AgentMemory]:
        """
        Recall similar patterns from memory

        Simulated vector similarity search.

        Args:
            agent_id: Agent ID
            context: Context to match against
            memory_type: Optional filter by memory type
            limit: Max results

        Returns:
            List of similar memories
        """
        query = select(AgentMemory).where(
            AgentMemory.agent_id == agent_id
        )

        if memory_type:
            query = query.where(AgentMemory.memory_type == memory_type)

        query = query.order_by(AgentMemory.access_count.desc()).limit(limit)

        result = await self.db.execute(query)
        memories = list(result.scalars().all())

        return memories

    async def update_baselines(
        self,
        agent_id: str,
        organization_id: str,
    ) -> None:
        """
        Update environmental baselines

        Updates baseline patterns based on recent investigations.

        Args:
            agent_id: Agent ID
            organization_id: Organization ID
        """
        logger.debug(f"Updating baselines for agent {agent_id}")

        # Store baseline memory
        await self.store_pattern(
            agent_id,
            organization_id,
            MemoryType.ENVIRONMENT_BASELINE.value,
            "updated_at",
            {"timestamp": datetime.now(timezone.utc).isoformat()},
            confidence=0.9,
        )

    async def decay_old_memories(
        self,
        agent_id: str,
    ) -> None:
        """
        Reduce confidence on stale patterns

        Prevents old patterns from dominating new investigations.

        Args:
            agent_id: Agent ID
        """
        query = select(AgentMemory).where(
            AgentMemory.agent_id == agent_id,
            AgentMemory.confidence > 0.1,
        )

        result = await self.db.execute(query)
        memories = result.scalars().all()

        for memory in memories:
            memory.confidence *= memory.decay_rate
            logger.debug(
                f"Decayed memory {memory.key} to {memory.confidence:.2f}"
            )

        await self.db.flush()

    async def learn_from_investigation(
        self,
        agent_id: str,
        investigation: Investigation,
    ) -> None:
        """
        Extract and store learnings from investigation

        Args:
            agent_id: Agent ID
            investigation: Completed investigation
        """
        logger.debug(f"Learning from investigation {investigation.id}")

        # Store resolution pattern
        if investigation.resolution_type:
            pattern_key = f"resolution_{investigation.resolution_type}"
            await self.store_pattern(
                agent_id,
                investigation.organization_id,
                MemoryType.CASE_PATTERN.value,
                pattern_key,
                {
                    "confidence_needed": investigation.confidence_score,
                    "steps_taken": len(investigation.reasoning_steps),
                },
                confidence=0.8,
            )

        # Store false positive pattern if applicable
        if (
            investigation.resolution_type
            == ResolutionType.FALSE_POSITIVE.value
        ):
            pattern_key = f"false_positive_{investigation.trigger_type}"
            await self.store_pattern(
                agent_id,
                investigation.organization_id,
                MemoryType.FALSE_POSITIVE_PATTERN.value,
                pattern_key,
                {"characteristics": investigation.findings_summary},
                confidence=0.7,
            )


class NaturalLanguageInterface:
    """
    Natural language chat interface with SOC agents

    Allows analysts to query agents, get explanations, and ask follow-up questions.
    """

    def __init__(self, db: AsyncSession):
        """Initialize with database session"""
        self.db = db

    async def process_query(
        self,
        query: str,
        agent_id: str,
        organization_id: str,
    ) -> dict:
        """
        Parse natural language query into investigation request

        Args:
            query: Natural language query
            agent_id: Agent to query
            organization_id: Organization context

        Returns:
            Structured investigation request
        """
        request = {
            "original_query": query,
            "intent": self._extract_intent(query),
            "entity": self._extract_entity(query),
            "time_range": self._extract_time_range(query),
            "priority": 3,
        }

        logger.debug(f"Parsed query: {request}")
        return request

    async def explain_alert(
        self,
        alert_id: str,
    ) -> str:
        """
        Generate human-friendly explanation of alert

        Args:
            alert_id: Alert ID

        Returns:
            Explanation text
        """
        return (
            f"Alert {alert_id}: Suspicious login detected from unusual location. "
            "This could indicate account compromise or insider threat. "
            "Recommended action: Review login details and check for lateral movement."
        )

    async def suggest_next_steps(
        self,
        investigation_id: str,
    ) -> list[str]:
        """
        Suggest next investigation steps

        Args:
            investigation_id: Investigation ID

        Returns:
            List of suggested steps
        """
        return [
            "Check for data exfiltration indicators",
            "Review endpoint logs for malware signatures",
            "Correlate with other alerts from same source IP",
            "Verify account credentials haven't been changed",
        ]

    async def generate_executive_summary(
        self,
        investigation_id: str,
    ) -> str:
        """
        Generate business-friendly summary

        Args:
            investigation_id: Investigation ID

        Returns:
            Executive summary
        """
        return (
            "Investigation Summary: Detected potential data exfiltration attempt. "
            "Recommend immediate response: isolate affected systems, "
            "review access logs, notify security leadership."
        )

    async def translate_technical(
        self,
        technical_finding: str,
    ) -> str:
        """
        Convert technical jargon to plain language

        Args:
            technical_finding: Technical finding

        Returns:
            Plain language translation
        """
        translations = {
            "lateral_movement": "attacker moving between systems",
            "data_exfiltration": "data being copied out of organization",
            "persistence_mechanism": "way for attacker to maintain access",
            "privilege_escalation": "gaining higher-level system access",
        }

        for tech, plain in translations.items():
            if tech in technical_finding.lower():
                return plain

        return technical_finding

    def _extract_intent(self, query: str) -> str:
        """Extract query intent"""
        if "investigate" in query.lower():
            return "investigate"
        elif "explain" in query.lower():
            return "explain"
        elif "find" in query.lower():
            return "search"
        else:
            return "general"

    def _extract_entity(self, query: str) -> str:
        """Extract entity from query"""
        # Simple pattern matching
        if "ip" in query.lower():
            return "ip_address"
        elif "user" in query.lower():
            return "user"
        elif "host" in query.lower():
            return "host"
        else:
            return "unknown"

    def _extract_time_range(self, query: str) -> str:
        """Extract time range from query"""
        if "last hour" in query.lower():
            return "1h"
        elif "today" in query.lower():
            return "24h"
        elif "week" in query.lower():
            return "7d"
        else:
            return "24h"


class AgentOrchestrator:
    """
    Manage multiple agents and workload distribution

    Routes investigations to appropriate agents, escalates as needed,
    coordinates investigations across multiple agents.
    """

    def __init__(self, db: AsyncSession):
        """Initialize with database session"""
        self.db = db

    async def assign_investigation(
        self,
        organization_id: str,
        trigger_type: str,
        alert_data: dict,
    ) -> SOCAgent:
        """
        Assign investigation to best-suited agent

        Considers agent capabilities, workload, and specialization.

        Args:
            organization_id: Organization ID
            trigger_type: Type of trigger
            alert_data: Alert/anomaly data

        Returns:
            Selected agent
        """
        query = select(SOCAgent).where(
            SOCAgent.organization_id == organization_id
        )

        result = await self.db.execute(query)
        agents = list(result.scalars().all())

        if not agents:
            raise ValueError("No agents available")

        # Simple agent selection: choose least busy
        best_agent = min(
            agents, key=lambda a: a.total_investigations
        )

        logger.debug(
            f"Assigned investigation to agent {best_agent.id}: {best_agent.name}"
        )

        return best_agent

    async def escalate(
        self,
        investigation_id: str,
        reason: str,
    ) -> Investigation:
        """
        Escalate investigation to human analyst

        Args:
            investigation_id: Investigation ID
            reason: Escalation reason

        Returns:
            Updated investigation
        """
        investigation = await self.db.get(Investigation, investigation_id)
        if investigation:
            investigation.status = InvestigationStatus.ESCALATED.value
            investigation.findings_summary = f"Escalated: {reason}"
            await self.db.flush()

            logger.info(f"Escalated investigation {investigation_id}: {reason}")

        return investigation

    async def coordinate_agents(
        self,
        investigation_id: str,
    ) -> None:
        """
        Coordinate multiple agents on related investigations

        Args:
            investigation_id: Primary investigation ID
        """
        logger.debug(f"Coordinating agents for investigation {investigation_id}")

    async def balance_workload(
        self,
        organization_id: str,
    ) -> None:
        """
        Distribute investigations evenly across agents

        Args:
            organization_id: Organization ID
        """
        logger.debug(f"Balancing workload for organization {organization_id}")

    async def get_agent_performance(
        self,
        agent_id: str,
    ) -> dict:
        """
        Get performance metrics for agent

        Args:
            agent_id: Agent ID

        Returns:
            Performance metrics
        """
        agent = await self.db.get(SOCAgent, agent_id)
        if not agent:
            return {}

        return {
            "agent_id": agent.id,
            "name": agent.name,
            "total_investigations": agent.total_investigations,
            "avg_resolution_time_minutes": agent.avg_resolution_time_minutes,
            "accuracy_score": agent.accuracy_score,
            "false_positive_rate": agent.false_positive_rate,
        }
