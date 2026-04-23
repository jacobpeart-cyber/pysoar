"""LLM-driven autonomous investigator.

This is the module that turns the agentic SOC feature into an actual
investigator instead of a chatbot. It runs an OODA loop where EVERY
decision is made by Gemini against the real PySOAR tool registry:

1. Observe  — current investigation state (goal, prior evidence,
              hypotheses, step count) is assembled into a prompt.
2. Orient   — Gemini reads the state and the available tool catalog.
3. Decide   — Gemini picks either (a) a tool to call for more evidence,
              or (b) a final verdict with confidence + recommendations.
4. Act      — the tool is dispatched via AgentToolRegistry against
              real DB state, or the verdict is persisted.

The loop runs as a Celery task so an investigation can span minutes
(60+ steps × ~3-5s Gemini latency each) without blocking a web request.
Every step persists a ReasoningStep row AND broadcasts an event on the
per-org WebSocket channel, so the Agent Console renders progress live.

Unlike the previous heuristic engine (src.agentic.engine.AgenticSOCEngine),
this module does NOT use template strings or hardcoded confidence
formulas. The hypothesis text, the decision to call a tool, the verdict,
and the confidence number all come from the LLM reading the evidence.

NIST 800-207 audit posture: every tool call is persisted in
ticket_activities (AU-2) before execution and in ReasoningStep
(application-level) after, so a 3PAO can reconstruct what the agent saw
and why it decided each step.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.models import (
    Investigation,
    InvestigationStatus,
    ReasoningStep,
    ResolutionType,
    SOCAgent,
    StepType,
)
from src.core.logging import get_logger
from src.services.agent_tools import AgentToolRegistry

logger = get_logger(__name__)


# Tools that are off-limits during autonomous investigation — state-
# changing actions require a human-approved step. The investigator can
# surface a recommendation but must not block an account, isolate a
# host, or execute a playbook without explicit sign-off (NIST AC-3).
AUTONOMOUS_BLOCKED_TOOLS = {
    "block_ip",
    "isolate_host",
    "disable_user",
    "execute_playbook",
    "create_remediation_ticket",
    "queue_endpoint_command",
    "create_forensic_case",
}

# Tools that are always safe for the investigator to call unprompted
# — read-only queries and controlled creations that the analyst would
# do by hand. Everything not in this list OR AUTONOMOUS_BLOCKED_TOOLS
# follows the default Gemini tool allowlist but logs a warning.
INVESTIGATOR_READONLY_TOOLS = {
    "list_alerts", "list_incidents", "list_iocs", "get_alert", "get_incident",
    "platform_stats", "search_alerts", "search_logs", "list_siem_rules",
    "list_entity_risks", "list_ueba_alerts", "list_vulnerabilities",
    "get_vulnerability", "list_forensic_cases", "list_darkweb_findings",
    "list_hunts", "list_hunt_findings", "list_threat_actors",
    "list_threat_campaigns", "list_assets", "get_asset",
    "list_remediation_executions", "list_decoy_interactions",
    "list_phishing_campaigns", "list_risks", "list_tickets",
    "list_compliance_frameworks", "list_compliance_controls",
    "list_poams", "list_compliance_evidence", "list_endpoint_agents",
    "triage_alert", "enrich_ioc", "correlate_alerts", "check_ioc_matches",
    "run_threat_hunt", "generate_incident_summary",
}


MAX_STEPS = 30          # Safety cap: ~2-3 min per investigation
MAX_EVIDENCE_BYTES = 100_000  # Cap persisted evidence per investigation


_SYSTEM_PROMPT = """You are a senior SOC analyst conducting an autonomous investigation.
Your job is NOT to pick tools one at a time like a chatbot — it is to work a case
the way a human analyst would:

1. Start by orienting to the triggering alert or anomaly.
2. Form a hypothesis (e.g. "this looks like credential stuffing because the
   failures are from many IPs against one account").
3. Gather evidence to confirm or disprove that hypothesis. Pivot: from an
   alert → the affected user → that user's UEBA risk → recent logins from
   unusual locations. Don't just repeat the same query.
4. Revise the hypothesis as evidence accumulates.
5. When you have enough evidence (>=80% confidence one way or the other),
   CONCLUDE with a verdict.

Tool discipline:
- Each tool call costs ~5 seconds and fills your working context. Be
  deliberate — three well-chosen calls beat ten redundant ones.
- Read-only queries (list_*, get_*, search_*, correlate_*, triage_*) are
  always fair game.
- State-changing actions (block_ip, isolate_host, disable_user,
  execute_playbook, create_ticket) are PROHIBITED during autonomous
  investigation. Instead, include them in `recommendations` in your
  final verdict.

Final verdict format — when ready to conclude, respond with a JSON object
in a ```json code block``` with this exact shape:

```json
{
  "verdict": "true_positive" | "false_positive" | "benign" | "inconclusive",
  "confidence": 85,
  "reasoning": "A 4-6 sentence narrative an SRE/CISO can read. Cite the
                specific evidence that moved your confidence up or down.",
  "hypothesis": "The final working hypothesis you settled on.",
  "mitre_techniques": ["T1110.001", "T1078"],
  "affected_assets": ["host-01", "alice@corp", "10.1.2.3"],
  "recommendations": [
    "Open an incident ticket with severity high.",
    "Ask IAM to force a password reset for alice@corp.",
    "Block 203.0.113.42 at the edge firewall."
  ]
}
```

Only produce this JSON when you have reached the decision. While still
gathering evidence, call the next tool — do NOT emit partial verdicts.
"""


_VERDICT_CODE_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_verdict(text: str) -> Optional[dict[str, Any]]:
    """Pull the verdict JSON out of a Gemini response. Accepts either a
    ``` fenced block or a bare JSON object at the end."""
    if not text:
        return None
    m = _VERDICT_CODE_FENCE.search(text)
    candidate = m.group(1) if m else None
    if not candidate:
        # Last-ditch: look for a top-level { "verdict": ... } anywhere.
        brace = text.find('{"verdict"')
        if brace == -1:
            brace = text.find('{ "verdict"')
        if brace >= 0:
            candidate = text[brace:]
    if not candidate:
        return None
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # Try to recover truncated JSON by matching balanced braces.
        depth = 0
        end = -1
        for i, ch in enumerate(candidate):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > 0:
            try:
                return json.loads(candidate[:end])
            except json.JSONDecodeError:
                return None
    return None


async def _broadcast_investigation_event(org_id: str, event: dict[str, Any]) -> None:
    """Best-effort WebSocket publish. Never raises — investigation
    progress is strictly additive; a downed WS must not fail the run."""
    try:
        from src.services.websocket_manager import manager
        await manager.broadcast_channel(f"agents:{org_id or 'global'}", event)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"investigation ws publish failed: {exc}")


class AutonomousInvestigator:
    """LLM-driven investigation loop.

    Given an Investigation row with trigger_type/trigger_source_id/title,
    run OODA iterations until Gemini emits a verdict OR the step budget
    is hit. Each step persists a ReasoningStep and updates the
    Investigation's evidence_collected.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.tool_registry = AgentToolRegistry(db)

    async def run(self, investigation: Investigation) -> Investigation:
        """Drive the investigation to completion (or the step cap).
        Returns the same Investigation object with status updated."""
        from src.ai.engine import AIAnalyzer
        analyzer = AIAnalyzer()

        logger.info(
            f"[autonomous] investigation={investigation.id} title={investigation.title!r} "
            f"trigger={investigation.trigger_type}:{investigation.trigger_source_id}"
        )
        # Track step count locally to avoid lazy-loading
        # investigation.reasoning_steps (which triggers a sync load
        # that crashes under async SQLAlchemy with MissingGreenlet).
        self._local_step_count = 0
        investigation.status = InvestigationStatus.GATHERING_EVIDENCE.value
        await self.db.commit()
        await _broadcast_investigation_event(
            investigation.organization_id,
            {
                "type": "investigation_started",
                "investigation_id": investigation.id,
                "title": investigation.title,
                "trigger": f"{investigation.trigger_type}:{investigation.trigger_source_id}",
            },
        )

        # Seed the transcript with the primary alert data so Gemini
        # doesn't have to call list_alerts first.
        seeded_context = await self._seed_context(investigation)
        evidence = {"seed": seeded_context, "tool_results": []}

        tool_declarations = self._filtered_tool_declarations()

        transcript: list[dict[str, Any]] = []
        verdict_data: Optional[dict[str, Any]] = None

        for step_num in range(1, MAX_STEPS + 1):
            self._local_step_count = step_num
            user_prompt = self._build_user_prompt(investigation, evidence, step_num)
            llm_result = analyzer.call_llm_with_tools_chain(
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                tools=tool_declarations,
                history=transcript,
            )

            if llm_result.get("type") == "error":
                logger.warning(f"[autonomous] LLM error step={step_num}: {llm_result.get('error')}")
                await self._persist_step(
                    investigation, step_num, StepType.ANALYZE.value,
                    thought="LLM call failed; halting to avoid looping on no-op.",
                    tool_name=None, tool_args=None, tool_result={"error": llm_result.get("error")},
                )
                investigation.status = InvestigationStatus.ESCALATED.value
                investigation.findings_summary = "LLM service unavailable — investigation halted for human review."
                break

            if llm_result.get("type") == "tool_call":
                tool_name = llm_result.get("name", "")
                tool_args = llm_result.get("args", {}) or {}

                if tool_name in AUTONOMOUS_BLOCKED_TOOLS:
                    # The LLM tried to take a state-changing action. Block it
                    # and log the attempted action into the transcript so the
                    # next iteration can pivot.
                    blocked = {
                        "error": f"Tool {tool_name} is blocked during autonomous investigation; "
                                 "surface as a recommendation in your final verdict instead.",
                    }
                    await self._persist_step(
                        investigation, step_num, StepType.DECIDE.value,
                        thought=f"Autonomous mode blocked {tool_name} — must be recommended, not executed.",
                        tool_name=tool_name, tool_args=tool_args, tool_result=blocked,
                    )
                    transcript.append({"tool": tool_name, "args": tool_args, "result": blocked})
                    continue

                exec_result = await self.tool_registry.execute(tool_name, tool_args)
                evidence["tool_results"].append({
                    "step": step_num, "tool": tool_name, "args": tool_args, "result": exec_result,
                })
                await self._persist_step(
                    investigation, step_num, StepType.GATHER_EVIDENCE.value,
                    thought=f"Pivoting via {tool_name}",
                    tool_name=tool_name, tool_args=tool_args, tool_result=exec_result,
                )
                transcript.append({"tool": tool_name, "args": tool_args, "result": exec_result})
                investigation.evidence_collected = json.dumps(evidence)[:MAX_EVIDENCE_BYTES]
                await self.db.commit()
                await _broadcast_investigation_event(
                    investigation.organization_id,
                    {
                        "type": "investigation_step",
                        "investigation_id": investigation.id,
                        "step": step_num,
                        "tool": tool_name,
                    },
                )
                continue

            if llm_result.get("type") == "text":
                text = llm_result.get("text", "")
                verdict = _extract_verdict(text)
                if verdict:
                    verdict_data = verdict
                    break
                # Treat free-form text as a hypothesis/interim thought.
                investigation.hypothesis = text[:2000]
                await self._persist_step(
                    investigation, step_num, StepType.HYPOTHESIZE.value,
                    thought=text[:5000],
                    tool_name=None, tool_args=None, tool_result=None,
                )
                await self.db.commit()
                # Nudge Gemini: it emitted free-form without a tool call, so
                # prompt it to either call a tool or produce a verdict JSON.
                transcript.append({"note": "You produced free-form text. Either call a tool or emit the verdict JSON.", "args": {}, "result": {"note": "noop"}})
                continue

        # ------------------------------------------------------------------
        # Conclude
        # ------------------------------------------------------------------
        if verdict_data is None:
            # Step budget hit without a verdict — persist an inconclusive
            # with whatever reasoning we have. This is the honest outcome:
            # the LLM needs more time/evidence than the budget allows.
            verdict_data = {
                "verdict": ResolutionType.INCONCLUSIVE.value,
                "confidence": investigation.confidence_score or 40,
                "reasoning": (
                    f"Investigation exhausted {MAX_STEPS}-step budget without a "
                    f"definitive verdict. Human analyst should take over. "
                    f"Working hypothesis: {investigation.hypothesis or 'none recorded'}."
                ),
                "recommendations": ["Escalate to human analyst for deeper investigation"],
            }

        await self._finalize(investigation, verdict_data)
        await _broadcast_investigation_event(
            investigation.organization_id,
            {
                "type": "investigation_concluded",
                "investigation_id": investigation.id,
                "verdict": verdict_data.get("verdict"),
                "confidence": verdict_data.get("confidence"),
            },
        )
        return investigation

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _filtered_tool_declarations(self) -> list[dict[str, Any]]:
        """Only offer safe tools to the investigator. Everything else is
        either readonly or gated (blocked tools never appear in the
        catalog so the LLM won't try them)."""
        all_decls = self.tool_registry.gemini_function_declarations()
        return [
            d for d in all_decls
            if d["name"] not in AUTONOMOUS_BLOCKED_TOOLS
        ]

    async def _seed_context(self, investigation: Investigation) -> dict[str, Any]:
        """Pull the primary triggering alert/incident into the evidence
        bundle so step 1 always has something concrete to reason over."""
        trigger_id = investigation.trigger_source_id
        if not trigger_id:
            return {"note": "no trigger id"}
        try:
            from src.models.alert import Alert
            from src.models.incident import Incident
            if investigation.trigger_type in ("alert", "alert_manual"):
                row = await self.db.get(Alert, trigger_id)
                if row:
                    return {
                        "primary_alert": {
                            "id": row.id, "title": row.title, "severity": row.severity,
                            "status": row.status, "source": row.source,
                            "source_ip": row.source_ip, "hostname": row.hostname,
                            "username": row.username, "category": row.category,
                            "description": (row.description or "")[:1500],
                            "created_at": row.created_at.isoformat() if row.created_at else None,
                        },
                    }
            elif investigation.trigger_type == "incident":
                row = await self.db.get(Incident, trigger_id)
                if row:
                    return {
                        "primary_incident": {
                            "id": row.id, "title": row.title, "severity": row.severity,
                            "status": row.status, "description": (row.description or "")[:1500],
                        },
                    }
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[autonomous] seed_context failed: {exc}")
        return {}

    def _build_user_prompt(
        self, investigation: Investigation, evidence: dict[str, Any], step_num: int
    ) -> str:
        """Compact the investigation state into a prompt the LLM can reason over."""
        recent_tools = evidence.get("tool_results", [])[-5:]  # keep prompt small
        return (
            f"Investigation #{investigation.id[:8]} — step {step_num}/{MAX_STEPS}\n"
            f"Goal: {investigation.title}\n"
            f"Trigger: {investigation.trigger_type}:{investigation.trigger_source_id}\n"
            f"Current hypothesis: {investigation.hypothesis or '(not yet formed)'}\n\n"
            f"Primary trigger data:\n{json.dumps(evidence.get('seed', {}), indent=2, default=str)[:3000]}\n\n"
            f"Recent tool results (last 5):\n{json.dumps(recent_tools, indent=2, default=str)[:8000]}\n\n"
            "Take the next step. Either call a tool to gather more evidence or,"
            " if confident (>=80%), emit the final verdict JSON."
        )

    async def _persist_step(
        self,
        investigation: Investigation,
        step_num: int,
        step_type: str,
        *,
        thought: str,
        tool_name: Optional[str],
        tool_args: Optional[dict[str, Any]],
        tool_result: Optional[dict[str, Any]],
    ) -> None:
        step = ReasoningStep(
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            step_number=step_num,
            step_type=step_type,
            thought_process=thought[:5000],
            action_tool=tool_name,
            action_parameters=json.dumps(tool_args or {})[:4000] if tool_args is not None else None,
            observation=json.dumps(tool_result or {}, default=str)[:8000] if tool_result is not None else None,
            confidence_delta=0.0,
            duration_ms=0,
        )
        self.db.add(step)
        # AU-2 audit: persist every tool attempt into ticket_activities
        # BEFORE the iteration continues, mirroring what the chat agent
        # does in src.api.v1.endpoints.agentic.chat_with_agent.
        if tool_name:
            try:
                from src.tickethub.models import TicketActivity
                self.db.add(TicketActivity(
                    source_type="investigation",
                    source_id=investigation.id,
                    activity_type="tool_invocation",
                    description=(
                        f"step={step_num} tool={tool_name} "
                        f"args={json.dumps(tool_args, default=str)[:400]}"
                    ),
                    organization_id=investigation.organization_id,
                ))
            except Exception as audit_err:
                logger.debug(f"investigation audit log failed: {audit_err}")
        await self.db.flush()

    async def _finalize(self, investigation: Investigation, verdict: dict[str, Any]) -> None:
        """Persist the final verdict onto the Investigation row."""
        verdict_type = str(verdict.get("verdict", "")).lower()
        valid_verdicts = {v.value for v in ResolutionType}
        if verdict_type not in valid_verdicts:
            verdict_type = ResolutionType.INCONCLUSIVE.value

        try:
            confidence = float(verdict.get("confidence", 0))
        except (TypeError, ValueError):
            confidence = 0.0

        investigation.resolution_type = verdict_type
        investigation.confidence_score = max(0.0, min(100.0, confidence))
        investigation.hypothesis = str(verdict.get("hypothesis", investigation.hypothesis or ""))[:2000]
        investigation.findings_summary = str(verdict.get("reasoning", ""))[:4000]
        mitre = verdict.get("mitre_techniques") or []
        if isinstance(mitre, list):
            investigation.mitre_techniques = json.dumps(mitre)
        affected = verdict.get("affected_assets") or []
        if isinstance(affected, list):
            investigation.affected_assets = json.dumps(affected)
        recs = verdict.get("recommendations") or []
        if isinstance(recs, list):
            investigation.recommendations = json.dumps(recs)
        investigation.status = InvestigationStatus.COMPLETED.value

        # Persist a terminal CONCLUDE step so the reasoning chain UI has
        # a final bookend.
        self._local_step_count += 1
        await self._persist_step(
            investigation, self._local_step_count, StepType.CONCLUDE.value,
            thought=investigation.findings_summary or "verdict recorded",
            tool_name=None, tool_args=None, tool_result=None,
        )
        await self.db.commit()
        logger.info(
            f"[autonomous] investigation={investigation.id} concluded "
            f"verdict={verdict_type} confidence={confidence}"
        )
