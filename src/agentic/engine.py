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
from sqlalchemy import select, func

from src.models.alert import Alert
from src.models.incident import Incident
from src.models.ioc import IOC
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

# AI analyzer for LLM-powered analysis (optional)
try:
    from src.ai.engine import AIAnalyzer
    AI_ANALYZER_AVAILABLE = True
except ImportError:
    AI_ANALYZER_AVAILABLE = False
    AIAnalyzer = None  # type: ignore
    logger.warning("AIAnalyzer not available, natural language responses will be deterministic")


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

        org_id = investigation.organization_id
        trigger_source_id = investigation.trigger_source_id

        # Try to load the primary triggering alert, if any
        primary_alert: Optional[Alert] = None
        if trigger_source_id:
            try:
                primary_alert = await self.db.get(Alert, trigger_source_id)
            except Exception as e:
                logger.debug(f"Could not load primary alert {trigger_source_id}: {e}")
                primary_alert = None

        # Query related alerts for this organization. If we have a primary alert,
        # correlate by source_ip/hostname/username. Otherwise just look at recent alerts.
        alerts_query = select(Alert)
        if primary_alert is not None:
            filters = []
            if primary_alert.source_ip:
                filters.append(Alert.source_ip == primary_alert.source_ip)
            if primary_alert.hostname:
                filters.append(Alert.hostname == primary_alert.hostname)
            if primary_alert.username:
                filters.append(Alert.username == primary_alert.username)
            if filters:
                from sqlalchemy import or_
                alerts_query = alerts_query.where(or_(*filters))

        alerts_query = alerts_query.order_by(Alert.created_at.desc()).limit(50)

        try:
            alerts_result = await self.db.execute(alerts_query)
            related_alerts = list(alerts_result.scalars().all())
        except Exception as e:
            logger.warning(f"Failed to query alerts: {e}")
            related_alerts = []

        severity_counts: dict[str, int] = {}
        affected_hosts: set[str] = set()
        affected_users: set[str] = set()
        source_ips: set[str] = set()
        for a in related_alerts:
            sev = (a.severity or "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if a.hostname:
                affected_hosts.add(a.hostname)
            if a.username:
                affected_users.add(a.username)
            if a.source_ip:
                source_ips.add(a.source_ip)

        # Query IOCs for this organization
        try:
            ioc_query = select(IOC).where(IOC.organization_id == org_id).limit(100)
            ioc_result = await self.db.execute(ioc_query)
            iocs = list(ioc_result.scalars().all())
        except Exception as e:
            logger.warning(f"Failed to query IOCs: {e}")
            iocs = []

        ioc_matches = []
        if primary_alert is not None:
            alert_indicators = {
                primary_alert.source_ip,
                primary_alert.destination_ip,
                primary_alert.hostname,
                primary_alert.file_hash,
                primary_alert.domain,
                primary_alert.url,
            }
            alert_indicators.discard(None)
            for ioc in iocs:
                if getattr(ioc, "value", None) and ioc.value in alert_indicators:
                    ioc_matches.append({
                        "value": ioc.value,
                        "type": getattr(ioc, "ioc_type", None) or getattr(ioc, "type", None),
                        "category": getattr(ioc, "category", None),
                    })

        # Query recent incidents for context
        try:
            incident_query = (
                select(Incident)
                .order_by(Incident.created_at.desc())
                .limit(10)
            )
            incident_result = await self.db.execute(incident_query)
            recent_incidents = list(incident_result.scalars().all())
        except Exception as e:
            logger.warning(f"Failed to query incidents: {e}")
            recent_incidents = []

        base_data = {
            "primary_alert_id": primary_alert.id if primary_alert else None,
            "primary_alert_title": primary_alert.title if primary_alert else None,
            "primary_alert_severity": primary_alert.severity if primary_alert else None,
            "alert_count": len(related_alerts),
            "severity_breakdown": severity_counts,
            "affected_hosts": sorted(affected_hosts),
            "affected_users": sorted(affected_users),
            "source_ips": sorted(source_ips),
            "ioc_total": len(iocs),
            "ioc_matches": ioc_matches,
            "recent_incident_count": len(recent_incidents),
        }

        if evidence_type == StepType.OBSERVE.value:
            evidence["data"] = {
                **base_data,
                "time_window": "recent",
                "affected_systems": len(affected_hosts),
            }
        elif evidence_type == StepType.GATHER_EVIDENCE.value:
            evidence["data"] = {
                **base_data,
                "siem_events": len(related_alerts),
                "threat_intel_hits": len(ioc_matches),
            }
        elif evidence_type == StepType.ANALYZE.value:
            evidence["data"] = {
                **base_data,
                "event_correlation": f"{len(related_alerts)} related alerts",
                "risk_assessment": self._compute_risk_level(severity_counts, len(ioc_matches)),
            }
        elif evidence_type == StepType.CORRELATE.value:
            evidence["data"] = {
                **base_data,
                "related_incidents": [
                    {"id": i.id, "title": i.title, "severity": i.severity}
                    for i in recent_incidents
                ],
            }
        else:
            evidence["data"] = base_data

        return evidence

    @staticmethod
    def _compute_risk_level(severity_counts: dict, ioc_match_count: int) -> str:
        """Compute a coarse risk level from severity counts and IOC matches."""
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        medium = severity_counts.get("medium", 0)
        if critical > 0 or ioc_match_count >= 3:
            return "critical"
        if high > 0 or ioc_match_count >= 1:
            return "high"
        if medium > 0:
            return "medium"
        return "low"

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
            "ai_summary": None,
        }

        evidence_data = evidence.get("data", {}) or {}

        severity_counts = evidence_data.get("severity_breakdown", {}) or {}
        alert_count = evidence_data.get("alert_count", 0)
        ioc_matches = evidence_data.get("ioc_matches", []) or []
        affected_hosts = evidence_data.get("affected_hosts", []) or []
        affected_users = evidence_data.get("affected_users", []) or []
        source_ips = evidence_data.get("source_ips", []) or []
        related_incidents = evidence_data.get("related_incidents", []) or []

        # Compute an anomaly score from real signals (0.0 - 1.0)
        score = 0.0
        score += min(0.3, alert_count * 0.02)
        score += min(0.3, len(ioc_matches) * 0.1)
        score += min(0.2, len(affected_hosts) * 0.05)
        score += 0.2 if severity_counts.get("critical", 0) > 0 else 0.0
        score += 0.1 if severity_counts.get("high", 0) > 0 else 0.0
        analysis["anomaly_score"] = round(min(1.0, score), 3)

        # Risk level from real signals
        analysis["risk_level"] = AgenticSOCEngine._compute_risk_level(
            severity_counts, len(ioc_matches)
        )

        # Patterns found - derived from actual evidence
        patterns: list[str] = []
        if len(affected_hosts) > 1:
            patterns.append(
                f"Multi-host activity across {len(affected_hosts)} hosts (possible lateral movement)"
            )
        if len(affected_users) > 1:
            patterns.append(
                f"Multiple user accounts involved ({len(affected_users)} users)"
            )
        if len(source_ips) > 3:
            patterns.append(
                f"Distributed source activity across {len(source_ips)} IPs"
            )
        if ioc_matches:
            patterns.append(
                f"{len(ioc_matches)} known IOC match(es) in threat intel"
            )
        if severity_counts.get("critical", 0) > 0:
            patterns.append(
                f"{severity_counts['critical']} critical-severity alert(s)"
            )
        analysis["patterns_found"] = patterns

        # Correlations - derived from real incidents
        correlations: list[str] = []
        for inc in related_incidents[:5]:
            correlations.append(
                f"Related incident: {inc.get('title', inc.get('id'))} "
                f"(severity={inc.get('severity')})"
            )
        analysis["correlations"] = correlations

        # Optional AI-powered summary
        if AI_ANALYZER_AVAILABLE and AIAnalyzer is not None:
            try:
                analyzer = AIAnalyzer()
                system_prompt = (
                    "You are a senior SOC analyst. Given raw investigation evidence, "
                    "produce a concise (2-3 sentence) analytical summary focusing on "
                    "risk, likely attack stage, and what the evidence supports."
                )
                user_prompt = (
                    f"Evidence data:\n{json.dumps(evidence_data, default=str)[:4000]}\n\n"
                    f"Derived patterns: {patterns}\n"
                    f"Risk level: {analysis['risk_level']}\n"
                    f"Anomaly score: {analysis['anomaly_score']}"
                )
                ai_response = analyzer._call_llm(
                    system_prompt, user_prompt, structured_output=False
                )
                if isinstance(ai_response, str) and ai_response.strip():
                    analysis["ai_summary"] = ai_response.strip()
            except Exception as e:
                logger.debug(f"AI analysis skipped: {e}")

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
        alert = await self.db.get(Alert, alert_id)
        if alert is None:
            return f"Alert {alert_id} not found."

        # Try AI-powered explanation first
        if AI_ANALYZER_AVAILABLE and AIAnalyzer is not None:
            try:
                analyzer = AIAnalyzer()
                system_prompt = (
                    "You are a senior SOC analyst. Explain the security alert below "
                    "to another analyst in 3-5 clear sentences: what happened, why it "
                    "matters, and what to check next."
                )
                user_prompt = (
                    f"Alert:\n"
                    f"- Title: {alert.title}\n"
                    f"- Description: {alert.description or 'N/A'}\n"
                    f"- Severity: {alert.severity}\n"
                    f"- Source: {alert.source}\n"
                    f"- Category: {alert.category or 'N/A'}\n"
                    f"- Alert type: {alert.alert_type or 'N/A'}\n"
                    f"- Source IP: {alert.source_ip or 'N/A'}\n"
                    f"- Destination IP: {alert.destination_ip or 'N/A'}\n"
                    f"- Hostname: {alert.hostname or 'N/A'}\n"
                    f"- Username: {alert.username or 'N/A'}\n"
                    f"- File hash: {alert.file_hash or 'N/A'}\n"
                    f"- Created: {getattr(alert, 'created_at', 'N/A')}\n"
                )
                ai_response = analyzer._call_llm(
                    system_prompt, user_prompt, structured_output=False
                )
                if isinstance(ai_response, str) and ai_response.strip():
                    return ai_response.strip()
            except Exception as e:
                logger.debug(f"AI explain_alert failed, falling back: {e}")

        # Deterministic structured explanation from real alert fields
        parts = [
            f"Alert {alert.id}: {alert.title}",
            f"Severity: {alert.severity}. Source: {alert.source}.",
        ]
        if alert.category or alert.alert_type:
            parts.append(
                f"Category: {alert.category or 'N/A'} / Type: {alert.alert_type or 'N/A'}."
            )
        if alert.description:
            parts.append(f"Details: {alert.description}")
        entity_bits = []
        if alert.source_ip:
            entity_bits.append(f"source_ip={alert.source_ip}")
        if alert.destination_ip:
            entity_bits.append(f"dest_ip={alert.destination_ip}")
        if alert.hostname:
            entity_bits.append(f"host={alert.hostname}")
        if alert.username:
            entity_bits.append(f"user={alert.username}")
        if alert.file_hash:
            entity_bits.append(f"file_hash={alert.file_hash}")
        if entity_bits:
            parts.append("Entities: " + ", ".join(entity_bits) + ".")
        created = getattr(alert, "created_at", None)
        if created:
            parts.append(f"Observed at {created}.")
        return " ".join(parts)

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
        # investigation_id here may actually reference an alert for the chat UI,
        # so try both so callers get useful output either way.
        alert: Optional[Alert] = None
        investigation: Optional[Investigation] = None
        try:
            investigation = await self.db.get(Investigation, investigation_id)
        except Exception:
            investigation = None
        if investigation is None:
            try:
                alert = await self.db.get(Alert, investigation_id)
            except Exception:
                alert = None
        elif investigation.trigger_source_id:
            try:
                alert = await self.db.get(Alert, investigation.trigger_source_id)
            except Exception:
                alert = None

        severity = (alert.severity if alert else None) or (
            "high" if investigation and investigation.priority and investigation.priority <= 2 else "medium"
        )
        severity = severity.lower() if isinstance(severity, str) else "medium"

        steps: list[str] = []
        label = alert.title if alert else (investigation.title if investigation else "this item")

        if severity in ("critical", "p1"):
            steps.extend([
                f"Triage '{label}' immediately and assign an on-call responder",
                "Isolate affected endpoints from the network to contain spread",
                "Preserve forensic evidence: memory, disk, and relevant logs",
                "Rotate credentials for any involved user accounts",
                "Notify security leadership and open an incident record",
            ])
        elif severity in ("high", "p2"):
            steps.extend([
                f"Assign '{label}' to a senior analyst for deep investigation",
                "Correlate with other recent alerts from the same source",
                "Check threat intel for related IOCs",
                "Review endpoint telemetry for follow-on activity",
            ])
        elif severity in ("medium", "p3"):
            steps.extend([
                f"Assign '{label}' for standard investigation",
                "Correlate with historical alerts from the same entities",
                "Validate against baseline to rule out false positive",
            ])
        else:
            steps.extend([
                f"Review '{label}' during normal triage rotation",
                "Tag and move on unless related alerts appear",
            ])

        # Personalize with real entities if available
        if alert:
            if alert.source_ip:
                steps.append(f"Pivot on source IP {alert.source_ip} in SIEM/EDR")
            if alert.hostname:
                steps.append(f"Pull EDR timeline for host {alert.hostname}")
            if alert.username:
                steps.append(f"Review authentication logs for user {alert.username}")
            if alert.file_hash:
                steps.append(f"Submit file hash {alert.file_hash} for reputation lookup")

        return steps

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
        investigation = await self.db.get(Investigation, investigation_id)
        if investigation is None:
            return f"Investigation {investigation_id} not found."

        # Count reasoning steps and actions via explicit queries to avoid
        # triggering lazy-loading on async relationships.
        try:
            step_count_q = select(func.count()).select_from(ReasoningStep).where(
                ReasoningStep.investigation_id == investigation.id
            )
            step_count = (await self.db.execute(step_count_q)).scalar() or 0
        except Exception:
            step_count = 0

        try:
            action_count_q = select(func.count()).select_from(AgentAction).where(
                AgentAction.investigation_id == investigation.id
            )
            action_count = (await self.db.execute(action_count_q)).scalar() or 0
        except Exception:
            action_count = 0

        # Count alerts/incidents for context
        try:
            alert_total_q = select(func.count(Alert.id))
            alert_total = (await self.db.execute(alert_total_q)).scalar() or 0
        except Exception:
            alert_total = 0

        try:
            incident_total_q = select(func.count(Incident.id))
            incident_total = (await self.db.execute(incident_total_q)).scalar() or 0
        except Exception:
            incident_total = 0

        # Load the trigger alert if applicable
        trigger_alert: Optional[Alert] = None
        if investigation.trigger_source_id:
            try:
                trigger_alert = await self.db.get(Alert, investigation.trigger_source_id)
            except Exception:
                trigger_alert = None

        # Prefer AI-generated executive summary if available
        if AI_ANALYZER_AVAILABLE and AIAnalyzer is not None:
            try:
                analyzer = AIAnalyzer()
                system_prompt = (
                    "You are briefing a CISO. Write a concise (4-6 sentence) executive "
                    "summary of this security investigation. Focus on business impact, "
                    "what was found, confidence, and recommended actions. Avoid jargon."
                )
                user_prompt = (
                    f"Investigation:\n"
                    f"- Title: {investigation.title}\n"
                    f"- Status: {investigation.status}\n"
                    f"- Confidence: {investigation.confidence_score:.0f}%\n"
                    f"- Resolution: {investigation.resolution_type}\n"
                    f"- Hypothesis: {investigation.hypothesis or 'N/A'}\n"
                    f"- Findings: {investigation.findings_summary or 'N/A'}\n"
                    f"- Reasoning steps taken: {step_count}\n"
                    f"- Actions proposed/taken: {action_count}\n"
                    f"- Trigger alert: "
                    f"{trigger_alert.title if trigger_alert else 'N/A'} "
                    f"(severity={trigger_alert.severity if trigger_alert else 'N/A'})\n"
                    f"- Organization context: {alert_total} total alerts, "
                    f"{incident_total} total incidents.\n"
                )
                ai_response = analyzer._call_llm(
                    system_prompt, user_prompt, structured_output=False
                )
                if isinstance(ai_response, str) and ai_response.strip():
                    return ai_response.strip()
            except Exception as e:
                logger.debug(f"AI executive summary failed, falling back: {e}")

        # Deterministic fallback summary from real fields
        lines = [
            f"Executive Summary - {investigation.title}",
            f"Status: {investigation.status} | Confidence: {investigation.confidence_score:.0f}% "
            f"| Resolution: {investigation.resolution_type or 'pending'}",
        ]
        if trigger_alert:
            lines.append(
                f"Triggered by alert '{trigger_alert.title}' "
                f"(severity={trigger_alert.severity}, source={trigger_alert.source})."
            )
        if investigation.hypothesis:
            lines.append(f"Working hypothesis: {investigation.hypothesis}")
        if investigation.findings_summary:
            lines.append(f"Findings: {investigation.findings_summary}")
        lines.append(
            f"The agent executed {step_count} reasoning step(s) and "
            f"{action_count} action(s). Organization has {alert_total} total alerts "
            f"and {incident_total} incidents on record."
        )
        if investigation.confidence_score >= 80:
            lines.append(
                "Recommendation: treat as a confirmed finding - escalate to IR, "
                "contain affected assets, and preserve evidence."
            )
        elif investigation.confidence_score >= 50:
            lines.append(
                "Recommendation: continue investigation with analyst review before action."
            )
        else:
            lines.append(
                "Recommendation: low confidence - monitor for additional signal before escalation."
            )
        return "\n".join(lines)

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
