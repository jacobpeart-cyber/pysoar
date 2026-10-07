"""Autonomous investigator (design v2 sections 5, 6, 8).

One investigation is one guarded ``AgentRunner`` run in
:class:`~src.agentic.context.Mode.AUTONOMOUS`:

* the tool list is an explicit read-only evidence allow-list, so the agent
  can look at anything in its own organization and change nothing;
* the trigger row, the org's installed integrations and the recent analyst
  corrections are seeded as UNTRUSTED DATA, scanned for prompt injection;
* the run ends when the model calls ``submit_verdict`` -- the verdict is a
  tool, not parsed prose. There is no regex verdict extractor and no
  regex action materializer any more;
* every recommended action becomes an approval-gated ``AgentAction``
  proposal, but only when its target has provenance in a structured field
  reachable from the trigger. A target that exists only inside attacker-
  controllable text becomes a human task with no ``tool_name``, never an
  executable proposal;
* when the run does not end in a verdict the investigation says so
  (``outcome``) and ``confidence_score`` stays NULL. Nothing is invented.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.context import AgentContext, Mode, UserRole
from src.agentic.decisions import TrustTier
from src.agentic.models import (
    ActionExecutionStatus,
    ActionType,
    AgentAction,
    Investigation,
    InvestigationStatus,
    ReasoningStep,
    ResolutionType,
    SOCAgent,
    StepType,
)
from src.agentic.policy import OrgPolicySettings, canonical_json
from src.agentic.runtime import RunResult, StepEvent
from src.agentic.runtime_factory import build_runtime
from src.agentic.toolspec import Target, Tier, ToolSpec
from src.agentic.transcript import persist_run_transcript
from src.agentic.trust import trust_state_to_dict
from src.core.logging import get_logger
from src.llm.base import LLMNotConfigured

logger = get_logger(__name__)


#: Read-only evidence tools the autonomous investigator may call. Anything
#: whose spec is not ``tier=read`` + read-only effects is filtered out at run
#: time (see :func:`evidence_allowlist`), so a tool that later gains a side
#: effect silently leaves the autonomous surface instead of becoming a hole.
INVESTIGATOR_READONLY_TOOLS: frozenset[str] = frozenset({
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
    "generate_incident_summary",
    # Which notification / ITSM / enrichment channels actually exist, so a
    # recommendation can only name a channel this org has installed.
    "list_configured_integrations",
    # Read-only playbook retrieval: the prompt requires consulting the
    # matching SOP before a verdict. execute_playbook stays off the list.
    "list_playbooks", "get_playbook",
    # MITRE ATT&CK knowledge base for grounded technique mapping.
    "lookup_attack_technique", "search_attack", "get_attack_coverage",
})

#: Autonomous per-run caps (design section 5).
MAX_STEPS = 15
MAX_TOKENS = 4_096
RUN_TOKEN_CEILING = 120_000
DEADLINE_SECONDS = 600.0

#: Proposal caps (design section 8).
MAX_RECOMMENDATIONS = 5
MAX_PENDING_PER_ORG_PER_HOUR = 50
PROPOSAL_TTL_HOURS = 72

MAX_EVIDENCE_BYTES = 100_000
TP_INCIDENT_CONFIDENCE = 70.0

#: ``Investigation.outcome`` values. ``setup_error`` is not in design v2's
#: list; it covers the pre-LLM configuration failures (no SOC agent in the
#: organization) that would otherwise have to be mislabelled.
OUTCOME_VERDICT = "verdict"
OUTCOME_INCONCLUSIVE_BUDGET = "inconclusive_budget"
OUTCOME_REFUSED = "refused"
OUTCOME_PROVIDER_ERROR = "provider_error"
OUTCOME_INJECTION_SUSPECTED = "injection_suspected"
OUTCOME_QUEUED_BUDGET_EXCEEDED = "queued_budget_exceeded"
OUTCOME_LLM_NOT_CONFIGURED = "llm_not_configured"
OUTCOME_SETUP_ERROR = "setup_error"


class InvestigationSetupError(Exception):
    """The investigation cannot start for a reason no LLM call can fix."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def evidence_allowlist(specs: Mapping[str, ToolSpec]) -> frozenset[str]:
    """``INVESTIGATOR_READONLY_TOOLS`` narrowed to genuinely read-only specs."""
    return frozenset(
        name
        for name in INVESTIGATOR_READONLY_TOOLS
        if (spec := specs.get(name)) is not None
        and spec.tier is Tier.READ
        and spec.effects.is_read_only
    )


def _autonomous_settings(specs: Mapping[str, ToolSpec]) -> OrgPolicySettings:
    return OrgPolicySettings(autonomous_allowlist=evidence_allowlist(specs))


async def _broadcast_investigation_event(org_id: str, event: dict[str, Any]) -> None:
    """Best-effort WebSocket publish. Never raises: investigation progress is
    strictly additive and a downed WS must not fail the run."""
    try:
        from src.services.websocket_manager import manager

        await manager.broadcast_channel(f"agents:{org_id or 'global'}", event)
    except Exception as exc:  # noqa: BLE001 - observers never break a run
        logger.debug("investigation_ws_publish_failed", error=str(exc)[:200])


def _json_list(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return [raw]
        return parsed if isinstance(parsed, list) else [parsed]
    return []


class AutonomousInvestigator:
    """Drives one :class:`Investigation` through the guarded runtime."""

    def __init__(self, db: AsyncSession, *, redis: Any = None, quota: Any = None) -> None:
        self.db = db
        self.redis = redis
        self.quota = quota
        self._step_rows: list[ReasoningStep] = []
        self._step_number = 0
        #: The org-bound registry of the run in flight; proposals re-use it so
        #: every target resolves against the same organization.
        self._registry: Any = None

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, investigation: Investigation) -> Investigation:
        org_id = investigation.organization_id
        agent = await self._agent_in_org(investigation)

        logger.info(
            "autonomous_investigation_start",
            investigation_id=investigation.id,
            organization_id=org_id,
            soc_agent_id=agent.id,
            trigger=f"{investigation.trigger_type}:{investigation.trigger_source_id}",
        )

        ctx = AgentContext(
            org_id=org_id,
            role=UserRole.ANALYST,
            mode=Mode.AUTONOMOUS,
            soc_agent_id=agent.id,
            investigation_id=investigation.id,
            propose_actions=False,
            deadline_seconds=DEADLINE_SECONDS,
            max_steps=MAX_STEPS,
            max_tokens=MAX_TOKENS,
            run_token_ceiling=RUN_TOKEN_CEILING,
        )

        investigation.status = InvestigationStatus.GATHERING_EVIDENCE.value
        investigation.outcome = None
        investigation.failure_reason = None
        investigation.run_ids = list(investigation.run_ids or []) + [ctx.run_id]
        await self.db.commit()
        await _broadcast_investigation_event(org_id, {
            "type": "investigation_started",
            "investigation_id": investigation.id,
            "title": investigation.title,
            "trigger": f"{investigation.trigger_type}:{investigation.trigger_source_id}",
        })

        try:
            runtime = await build_runtime(
                self.db,
                ctx,
                redis=self.redis,
                quota=self.quota,
                purpose="investigation",
                settings=_autonomous_settings,
                step_callback=self._make_step_callback(investigation),
            )
        except LLMNotConfigured as exc:
            await self._finalize_no_run(
                investigation,
                outcome=OUTCOME_LLM_NOT_CONFIGURED,
                failure_reason=(
                    f"llm_not_configured source={getattr(exc, 'source', 'unknown')} "
                    f"reason={getattr(exc, 'reason', 'unknown')}"
                ),
                summary=(
                    "No LLM provider is configured for this organization, so no autonomous "
                    f"analysis was performed ({exc}). Configure an AI provider in Settings, "
                    "or investigate this trigger manually."
                ),
            )
            return investigation

        self._registry = runtime.registry
        trigger = await self._trigger_snapshot(investigation)
        seed = {
            "investigation_id": investigation.id,
            "trigger": {
                "type": investigation.trigger_type,
                "source_id": investigation.trigger_source_id,
                "data": trigger["data"],
            },
            "configured_integrations": await self._configured_integrations(runtime, ctx),
            "recent_analyst_corrections": await self._recent_corrections(investigation),
        }
        query = self._build_query(investigation)

        provider = runtime.provider
        run_started_at = datetime.now(timezone.utc)
        try:
            async with provider:  # type: ignore[union-attr]
                result = await runtime.runner.run(ctx, query, seed_context=seed, seed_label="trigger")
        finally:
            # Only a quota this investigator created is closed here; one handed
            # in by the task is that task's to settle and close.
            if self.quota is None:
                await self._close_quota(runtime)

        await self._persist_run(investigation, agent, result, trigger, ctx=ctx, started_at=run_started_at)
        return investigation

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    async def _agent_in_org(self, investigation: Investigation) -> SOCAgent:
        """The investigation's SOC agent, validated in-organization."""
        if not investigation.agent_id:
            raise InvestigationSetupError("soc_agent_missing", "investigation has no agent_id")
        agent = (await self.db.execute(
            select(SOCAgent).where(
                SOCAgent.id == investigation.agent_id,
                SOCAgent.organization_id == investigation.organization_id,
            )
        )).scalar_one_or_none()
        if agent is None:
            raise InvestigationSetupError(
                "soc_agent_not_in_organization",
                f"soc agent {investigation.agent_id} does not belong to organization "
                f"{investigation.organization_id}",
            )
        return agent

    async def _configured_integrations(self, runtime: Any, ctx: AgentContext) -> Any:
        """Installed integrations, read through the guarded registry.

        Returned verbatim: for a non-admin actor the tool exposes ids and
        health only, so the model is told that rather than shown names it
        cannot have.
        """
        try:
            return await runtime.registry.call(ctx, "list_configured_integrations", {}, policy=runtime.policy)
        except Exception as exc:  # noqa: BLE001 - the seed must never fail the run
            logger.warning("investigation_integrations_unavailable", error_class=exc.__class__.__name__)
            return {"error": "integration inventory unavailable", "error_class": exc.__class__.__name__}

    async def _recent_corrections(self, investigation: Investigation) -> list[dict[str, Any]]:
        """The org's most recent analyst corrections: the feedback loop that
        stops the agent repeating a disposition a human already overturned."""
        from src.agentic.models import InvestigationFeedback

        rows = list(await self.db.scalars(
            select(InvestigationFeedback)
            .where(
                InvestigationFeedback.organization_id == investigation.organization_id,
                InvestigationFeedback.investigation_id != investigation.id,
            )
            .order_by(InvestigationFeedback.created_at.desc())
            .limit(5)
        ))
        return [
            {
                "agent_verdict": r.agent_verdict,
                "agent_confidence": r.agent_confidence,
                "corrected_verdict": r.corrected_verdict,
                "correction_note": (r.correction_note or "")[:500],
            }
            for r in rows
        ]

    async def _trigger_snapshot(self, investigation: Investigation) -> dict[str, Any]:
        """The triggering row's structured fields plus the values that may be
        used as action targets.

        ``provenance`` holds only values read out of structured, human- or
        detector-written columns. A hostname that appears solely inside a log
        line or an alert description is deliberately absent.
        """
        trigger_id = investigation.trigger_source_id
        kind = (investigation.trigger_type or "").lower()
        empty: dict[str, Any] = {"data": {"note": "no trigger row referenced"}, "provenance": set()}
        if not trigger_id:
            return empty

        if kind in ("alert", "alert_manual"):
            return await self._alert_snapshot(investigation, trigger_id)
        if kind == "incident":
            return await self._incident_snapshot(investigation, trigger_id)
        if kind == "ueba_alert":
            return await self._ueba_snapshot(investigation, trigger_id)
        if kind == "darkweb_finding":
            return await self._darkweb_snapshot(investigation, trigger_id)
        if kind == "decoy_interaction":
            return await self._decoy_snapshot(investigation, trigger_id)
        return {
            "data": {"note": f"trigger type {kind!r} carries no loadable row in this build"},
            "provenance": set(),
        }

    async def _alert_snapshot(self, investigation: Investigation, trigger_id: str) -> dict[str, Any]:
        from src.models.alert import Alert

        row = (await self.db.execute(
            select(Alert).where(Alert.id == trigger_id, Alert.organization_id == investigation.organization_id)
        )).scalar_one_or_none()
        if row is None:
            return {"data": {"note": "triggering alert not found in this organization"}, "provenance": set()}
        data = {
            "primary_alert": {
                "id": row.id, "title": row.title, "severity": row.severity, "status": row.status,
                "source": row.source, "category": row.category, "alert_type": row.alert_type,
                "source_ip": row.source_ip, "destination_ip": row.destination_ip,
                "hostname": row.hostname, "username": row.username, "domain": row.domain,
                "file_hash": row.file_hash, "url": row.url,
                "description": (row.description or "")[:1500],
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        }
        provenance = {
            v for v in (row.source_ip, row.destination_ip, row.hostname, row.username, row.domain, row.file_hash)
            if isinstance(v, str) and v.strip()
        }
        return {"data": data, "provenance": provenance}

    async def _incident_snapshot(self, investigation: Investigation, trigger_id: str) -> dict[str, Any]:
        from src.models.incident import Incident

        row = (await self.db.execute(
            select(Incident).where(
                Incident.id == trigger_id, Incident.organization_id == investigation.organization_id
            )
        )).scalar_one_or_none()
        if row is None:
            return {"data": {"note": "triggering incident not found in this organization"}, "provenance": set()}
        systems = [str(s) for s in _json_list(row.affected_systems) if s]
        users = [str(u) for u in _json_list(row.affected_users) if u]
        data = {
            "primary_incident": {
                "id": row.id, "title": row.title, "severity": row.severity, "status": row.status,
                "incident_type": row.incident_type, "affected_systems": systems, "affected_users": users,
                "description": (row.description or "")[:1500],
            }
        }
        return {"data": data, "provenance": set(systems) | set(users)}

    async def _ueba_snapshot(self, investigation: Investigation, trigger_id: str) -> dict[str, Any]:
        from src.ueba.models import EntityProfile, UEBARiskAlert

        row = await self.db.get(UEBARiskAlert, trigger_id)
        if row is None:
            return {"data": {"note": "triggering UEBA alert not found"}, "provenance": set()}
        entity = await self.db.get(EntityProfile, row.entity_profile_id)
        if entity is None or entity.organization_id != investigation.organization_id:
            return {"data": {"note": "triggering UEBA alert is not in this organization"}, "provenance": set()}
        data = {
            "primary_ueba_alert": {
                "id": row.id, "alert_type": row.alert_type, "severity": row.severity,
                "risk_score": getattr(row, "risk_score", None),
                "description": (getattr(row, "description", "") or "")[:1500],
                "entity_id": entity.entity_id, "entity_type": entity.entity_type,
                "display_name": entity.display_name,
            }
        }
        provenance = {v for v in (entity.entity_id, entity.display_name) if isinstance(v, str) and v.strip()}
        return {"data": data, "provenance": provenance}

    async def _darkweb_snapshot(self, investigation: Investigation, trigger_id: str) -> dict[str, Any]:
        from src.darkweb.models import DarkWebFinding

        row = (await self.db.execute(
            select(DarkWebFinding).where(
                DarkWebFinding.id == trigger_id,
                DarkWebFinding.organization_id == investigation.organization_id,
            )
        )).scalar_one_or_none()
        if row is None:
            return {"data": {"note": "triggering dark web finding not found in this organization"}, "provenance": set()}
        data = {
            "primary_darkweb_finding": {
                "id": row.id, "finding_type": row.finding_type, "severity": row.severity,
                "status": row.status, "title": row.title,
                "description": (getattr(row, "description", "") or "")[:1500],
            }
        }
        return {"data": data, "provenance": set()}

    async def _decoy_snapshot(self, investigation: Investigation, trigger_id: str) -> dict[str, Any]:
        from src.deception.models import Decoy, DecoyInteraction

        row = await self.db.get(DecoyInteraction, trigger_id)
        if row is None:
            return {"data": {"note": "triggering decoy interaction not found"}, "provenance": set()}
        decoy = await self.db.get(Decoy, row.decoy_id)
        if decoy is None or decoy.organization_id != investigation.organization_id:
            return {"data": {"note": "triggering decoy interaction is not in this organization"}, "provenance": set()}
        data = {
            "primary_decoy_interaction": {
                "id": row.id, "interaction_type": row.interaction_type, "source_ip": row.source_ip,
                "decoy_name": decoy.name, "decoy_type": getattr(decoy, "decoy_type", None),
            }
        }
        provenance = {v for v in (row.source_ip,) if isinstance(v, str) and v.strip()}
        return {"data": data, "provenance": provenance}

    def _build_query(self, investigation: Investigation) -> str:
        return (
            f"Investigate PySOAR investigation {investigation.id}.\n"
            f"Goal: {investigation.title}\n"
            f"Trigger: {investigation.trigger_type}:{investigation.trigger_source_id}\n"
            f"Working hypothesis so far: {investigation.hypothesis or '(none recorded)'}\n\n"
            "The triggering record, this organization's installed integrations and the most recent "
            "analyst corrections are loaded as data. Gather the evidence you need with the read-only "
            "tools, then call submit_verdict exactly once with your disposition, your confidence and "
            "the actions a human should approve. You have "
            f"{MAX_STEPS} steps; if the evidence does not support a decision, submit an "
            "'inconclusive' verdict saying what is missing."
        )

    # ------------------------------------------------------------------
    # Live progress
    # ------------------------------------------------------------------

    def _make_step_callback(self, investigation: Investigation) -> Any:
        """Persist one ReasoningStep per tool decision and broadcast it.

        Rows are created while the run is in flight (the console renders
        progress live) and enriched from ``RunResult.tool_log`` afterwards,
        which is emitted in the same order.
        """
        tool_kinds = {"tool_denied", "tool_proposed", "tool_executed", "tool_failed"}

        async def _on_event(event: StepEvent) -> None:
            if event.kind in tool_kinds:
                row = self._new_step(
                    investigation,
                    StepType.GATHER_EVIDENCE.value if event.kind == "tool_executed" else StepType.DECIDE.value,
                    thought=f"{event.kind}: {event.tool}"
                    + (f" ({event.reason_code})" if event.reason_code else ""),
                    tool_name=event.tool,
                )
                self._step_rows.append(row)
                self.db.add(row)
            await _broadcast_investigation_event(investigation.organization_id, {
                "type": "investigation_step",
                "investigation_id": investigation.id,
                "run_id": event.run_id,
                "step": event.step,
                "kind": event.kind,
                "tool": event.tool,
                "decision": event.decision,
                "reason_code": event.reason_code,
            })

        return _on_event

    def _new_step(
        self,
        investigation: Investigation,
        step_type: str,
        *,
        thought: str,
        tool_name: Optional[str] = None,
        observation: Optional[str] = None,
    ) -> ReasoningStep:
        self._step_number += 1
        return ReasoningStep(
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            step_number=self._step_number,
            step_type=step_type,
            thought_process=thought[:5000],
            action_tool=tool_name,
            observation=observation[:8000] if observation else None,
            confidence_delta=0.0,
            duration_ms=0,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _finalize_no_run(
        self,
        investigation: Investigation,
        *,
        outcome: str,
        failure_reason: str,
        summary: str,
    ) -> None:
        """Record an investigation that never reached the provider.

        ``confidence_score`` is NULL and no ``AgentAction`` rows exist: there
        is no analysis to be confident about.
        """
        investigation.outcome = outcome
        investigation.failure_reason = failure_reason[:2000]
        investigation.confidence_score = None
        investigation.resolution_type = None
        investigation.findings_summary = summary[:4000]
        investigation.status = InvestigationStatus.ESCALATED.value
        self.db.add(self._new_step(
            investigation, StepType.CONCLUDE.value, thought=summary[:5000], observation=None,
        ))
        await self.db.commit()
        await _broadcast_investigation_event(investigation.organization_id, {
            "type": "investigation_concluded",
            "investigation_id": investigation.id,
            "outcome": outcome,
            "verdict": None,
            "confidence": None,
        })
        logger.warning(
            "autonomous_investigation_not_run",
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            outcome=outcome,
            failure_reason=failure_reason[:200],
        )

    async def _persist_run(
        self,
        investigation: Investigation,
        agent: SOCAgent,
        result: RunResult,
        trigger: dict[str, Any],
        *,
        ctx: AgentContext,
        started_at: datetime,
    ) -> None:
        verdict = result.verdict if isinstance(result.verdict, dict) else None
        lockdown = result.trust.tier is TrustTier.LOCKDOWN
        outcome, failure_reason = self._classify(result, verdict, lockdown)

        self._enrich_steps(result)
        investigation.llm_provider = result.provider
        investigation.llm_model = result.model
        investigation.tokens_used = result.usage.total_billable
        investigation.injection_tier = result.trust.tier.value
        investigation.outcome = outcome
        investigation.failure_reason = failure_reason[:2000] if failure_reason else None
        investigation.evidence_collected = json.dumps({
            "run_id": result.run_id,
            "stop_reason": result.stop_reason,
            "trust": trust_state_to_dict(result.trust),
            "tools": [
                {
                    "step": e.step, "tool": e.tool, "decision": e.decision, "reason_code": e.reason_code,
                    "success": e.success, "result_sha256": e.result_sha256,
                    "result_preview": e.result_preview,
                }
                for e in result.tool_log
            ],
        }, default=str)[:MAX_EVIDENCE_BYTES]

        if result.final_text:
            investigation.hypothesis = result.final_text[:2000]

        if outcome == OUTCOME_VERDICT and verdict is not None:
            await self._persist_verdict(investigation, agent, result, verdict, trigger)
        else:
            investigation.confidence_score = None
            investigation.resolution_type = None
            investigation.findings_summary = self._honest_summary(outcome, result, verdict)[:4000]
            investigation.recommendations = json.dumps(
                self._recommendation_text(verdict, reason=outcome)
            ) if verdict else None
            investigation.status = (
                InvestigationStatus.ESCALATED.value
                if outcome in (OUTCOME_PROVIDER_ERROR, OUTCOME_INJECTION_SUSPECTED, OUTCOME_REFUSED)
                else InvestigationStatus.AWAITING_HUMAN.value
            )

        self.db.add(self._new_step(
            investigation,
            StepType.CONCLUDE.value,
            thought=investigation.findings_summary or f"outcome={outcome}",
            observation=json.dumps({
                "outcome": outcome,
                "stop_reason": result.stop_reason,
                "injection_tier": result.trust.tier.value,
                "tokens": result.usage.total_billable,
            }),
        ))
        # Evidence record of the run (AU-3/AU-12), committed with the
        # conclusion below. Never raises.
        await persist_run_transcript(
            self.db, ctx, result, mode=ctx.mode, started_at=started_at, outcome=outcome,
        )
        await self.db.commit()
        await _broadcast_investigation_event(investigation.organization_id, {
            "type": "investigation_concluded",
            "investigation_id": investigation.id,
            "outcome": outcome,
            "verdict": investigation.resolution_type,
            "confidence": investigation.confidence_score,
        })
        logger.info(
            "autonomous_investigation_finished",
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            outcome=outcome,
            stop_reason=result.stop_reason,
            injection_tier=result.trust.tier.value,
            tokens=result.usage.total_billable,
        )

    def _classify(
        self, result: RunResult, verdict: Optional[dict[str, Any]], lockdown: bool
    ) -> tuple[str, Optional[str]]:
        """Map the run's stop reason onto ``Investigation.outcome``.

        Lockdown outranks a verdict: a run whose evidence contained prompt
        injection produced a disposition from tampered data, so it is handed
        to a human instead of being recorded as the agent's verdict.
        """
        if lockdown:
            return OUTCOME_INJECTION_SUSPECTED, "injection_lockdown during evidence collection"
        if verdict is not None:
            return OUTCOME_VERDICT, None
        if result.stop_reason == "refusal":
            return OUTCOME_REFUSED, result.stop_detail or "model refused"
        if result.stop_reason == "error":
            return OUTCOME_PROVIDER_ERROR, result.error_code or result.stop_detail or "provider error"
        return (
            OUTCOME_INCONCLUSIVE_BUDGET,
            f"stop_reason={result.stop_reason} detail={result.stop_detail or 'none'}",
        )

    def _honest_summary(
        self, outcome: str, result: RunResult, verdict: Optional[dict[str, Any]]
    ) -> str:
        reasoning = str((verdict or {}).get("reasoning") or "").strip()
        if outcome == OUTCOME_INJECTION_SUSPECTED:
            labels = ", ".join(sorted(result.trust.contaminated_labels)) or "unknown records"
            head = (
                "Prompt-injection content was found in the evidence for this investigation "
                f"({labels}); state-changing tools were disabled and no verdict is recorded. "
                "A human analyst must review the tampered records before acting."
            )
        elif outcome == OUTCOME_REFUSED:
            head = (
                "The model declined to analyse this trigger "
                f"({result.stop_detail or 'refusal'}); no verdict and no confidence are recorded."
            )
        elif outcome == OUTCOME_PROVIDER_ERROR:
            head = (
                "The LLM provider call failed "
                f"({result.error_code or result.stop_detail or 'no error code reported'}); "
                "no analysis was completed."
            )
        else:
            head = (
                f"The investigation ran out of budget after {len(result.steps)} step(s) "
                f"({result.stop_reason}: {result.stop_detail or 'no detail'}) without reaching a "
                "verdict. A human analyst should take over."
            )
        if reasoning:
            head += f"\n\nModel's last reasoning (unverified, no verdict recorded):\n{reasoning}"
        return head

    def _recommendation_text(self, verdict: Optional[dict[str, Any]], *, reason: str) -> list[str]:
        """Recommended actions kept as text only (no executable proposals)."""
        actions = (verdict or {}).get("recommended_actions") or []
        out = [
            f"[not proposed: {reason}] {a.get('tool')} {canonical_json(a.get('args') or {})}"
            f" - {a.get('rationale') or 'no rationale given'}"
            for a in actions
            if isinstance(a, dict)
        ]
        return out

    def _enrich_steps(self, result: RunResult) -> None:
        """Fill the live-created step rows with the arguments and observations
        from the matching tool-log entries (same order as the events)."""
        for row, entry in zip(self._step_rows, result.tool_log):
            row.action_tool = entry.tool
            row.action_parameters = canonical_json(entry.args)[:4000]
            row.observation = json.dumps({
                "decision": entry.decision,
                "reason_code": entry.reason_code,
                "success": entry.success,
                "is_error": entry.is_error,
                "duration_ms": entry.duration_ms,
                "result_sha256": entry.result_sha256,
                "result_preview": entry.result_preview,
                "error_class": entry.error_class,
            }, default=str)[:8000]
            row.duration_ms = int(entry.duration_ms)

    async def _persist_verdict(
        self,
        investigation: Investigation,
        agent: SOCAgent,
        result: RunResult,
        verdict: dict[str, Any],
        trigger: dict[str, Any],
    ) -> None:
        valid = {v.value for v in ResolutionType}
        verdict_type = str(verdict.get("verdict") or "").lower()
        if verdict_type not in valid:
            verdict_type = ResolutionType.INCONCLUSIVE.value
        try:
            confidence = float(verdict.get("confidence"))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(100.0, confidence))

        investigation.resolution_type = verdict_type
        investigation.confidence_score = confidence
        investigation.findings_summary = str(verdict.get("reasoning") or "")[:4000]
        investigation.mitre_techniques = json.dumps(
            [str(t) for t in (verdict.get("mitre_techniques") or []) if isinstance(t, str)]
        )
        investigation.affected_assets = json.dumps(
            [str(a) for a in (verdict.get("affected_assets") or []) if isinstance(a, str)]
        )
        investigation.status = InvestigationStatus.COMPLETED.value

        kept, overflow = await self._materialize_recommendations(
            investigation, agent, result, verdict, trigger,
        )
        investigation.recommendations = json.dumps(kept)
        if overflow:
            investigation.findings_summary = (
                f"{investigation.findings_summary}\n\n"
                f"Additional recommended actions not proposed (cap reached):\n"
                + "\n".join(f"- {line}" for line in overflow)
            )[:4000]

        if verdict_type == ResolutionType.TRUE_POSITIVE.value and confidence >= TP_INCIDENT_CONFIDENCE:
            await self._open_incident_for_verdict(investigation, agent, verdict)

    # ------------------------------------------------------------------
    # Proposals (design section 8)
    # ------------------------------------------------------------------

    async def _materialize_recommendations(
        self,
        investigation: Investigation,
        agent: SOCAgent,
        result: RunResult,
        verdict: dict[str, Any],
        trigger: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Turn each recommended action into an approval-gated proposal.

        Returns ``(persisted, overflow_text)``. Nothing executes here: every
        row is ``requires_approval=True`` / ``pending_approval``.
        """
        raw = verdict.get("recommended_actions") or []
        actions = [a for a in raw if isinstance(a, dict)]
        kept: list[dict[str, Any]] = []
        overflow: list[str] = []

        if not actions:
            return kept, overflow

        remaining_budget = await self._pending_budget(investigation.organization_id)
        params_evidence_sha = self._evidence_sha256(result)
        suspect = result.trust.tier is not TrustTier.CLEAN
        expires_at = datetime.now(timezone.utc) + timedelta(hours=PROPOSAL_TTL_HOURS)
        registry_specs = None

        for index, action in enumerate(actions):
            tool = str(action.get("tool") or "").strip()
            args = action.get("args") if isinstance(action.get("args"), dict) else {}
            rationale = str(action.get("rationale") or "")[:1000]
            text = f"{tool} {canonical_json(args)} - {rationale or 'no rationale given'}"

            if index >= MAX_RECOMMENDATIONS:
                overflow.append(f"[not proposed: per-investigation cap of {MAX_RECOMMENDATIONS}] {text}")
                continue
            if remaining_budget <= 0:
                overflow.append(
                    f"[not proposed: {MAX_PENDING_PER_ORG_PER_HOUR} pending proposals/hour cap for this "
                    f"organization] {text}"
                )
                continue

            if registry_specs is None:
                registry_specs = self._specs()
            spec = registry_specs.get(tool)
            targets, provenance_ok, note = await self._targets(spec, args, trigger)

            row = AgentAction(
                investigation_id=investigation.id,
                organization_id=investigation.organization_id,
                action_type=self._action_type(spec, tool),
                target=(", ".join(t["value"] for t in targets) or tool or "human-analyst")[:255],
                parameters=dict(args),
                requires_approval=True,
                execution_status=ActionExecutionStatus.PENDING_APPROVAL.value,
                rollback_available=False,
                run_id=result.run_id,
                tool_name=tool if (spec is not None and provenance_ok) else None,
                proposed_by_user_id=None,
                proposed_by_agent_id=agent.id,
                source="autonomous",
                params_sha256=hashlib.sha256(
                    canonical_json({"tool": tool, "args": args}).encode("utf-8")
                ).hexdigest(),
                evidence_sha256=params_evidence_sha,
                effective_targets=targets,
                suspect=suspect,
                injection_tier=result.trust.tier.value,
                expires_at=expires_at,
            )
            self.db.add(row)
            remaining_budget -= 1
            kept.append({
                "tool": tool if (spec is not None and provenance_ok) else None,
                "args": args,
                "rationale": rationale,
                "executable": bool(spec is not None and provenance_ok),
                "human_task_reason": note,
                "effective_targets": targets,
                "requires_approval": True,
                "executed": False,
            })

        await self.db.flush()
        logger.info(
            "autonomous_recommendations_materialized",
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            proposed=len(kept),
            executable=sum(1 for k in kept if k["executable"]),
            overflow=len(overflow),
        )
        return kept, overflow

    def _specs(self) -> Mapping[str, ToolSpec]:
        """Tool specs of the run's own org-bound registry. Only specs are read
        here; no handler is reachable from this path."""
        if self._registry is None:
            return {}
        return self._registry.specs

    @staticmethod
    def _action_type(spec: Optional[ToolSpec], tool: str) -> str:
        """Legacy ``action_type`` label. ``tool_name`` is the executable
        field; this is what the existing UI groups rows by."""
        mapping = {
            "block_ip": ActionType.BLOCK_IP.value,
            "isolate_host": ActionType.ISOLATE_HOST.value,
            "disable_user": ActionType.DISABLE_ACCOUNT.value,
            "execute_playbook": ActionType.RUN_PLAYBOOK.value,
            "create_remediation_ticket": ActionType.CREATE_TICKET.value,
            "create_forensic_case": ActionType.CREATE_TICKET.value,
            "execute_integration_action": ActionType.SEND_NOTIFICATION.value,
            "enrich_ioc": ActionType.ENRICH_IOC.value,
        }
        if spec is None:
            return ActionType.ESCALATE.value
        return mapping.get(tool, ActionType.ESCALATE.value)

    async def _pending_budget(self, org_id: str) -> int:
        """How many more proposals this org may receive this hour."""
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        pending = await self.db.scalar(
            select(func.count(AgentAction.id)).where(
                AgentAction.organization_id == org_id,
                AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value,
                AgentAction.created_at >= since,
            )
        )
        return max(0, MAX_PENDING_PER_ORG_PER_HOUR - int(pending or 0))

    async def _targets(
        self,
        spec: Optional[ToolSpec],
        args: dict[str, Any],
        trigger: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], bool, Optional[str]]:
        """Expand the action's effective targets and decide whether every one
        of them has structured provenance.

        A target qualifies when it resolves to a row in this organization or
        when its value appears verbatim in a structured column of the trigger
        (``Alert.hostname/source_ip/username``, ``Incident.affected_systems``,
        an entity id, ...). Anything the model could only have read out of
        untrusted text is not executable.
        """
        if spec is None:
            return [], False, "tool is not a registered platform tool"
        if spec.effective_targets is None:
            return [], False, "tool declares no effective targets to verify"
        try:
            raw: list[Target] = list(await spec.effective_targets(dict(args), self._registry))
        except Exception as exc:  # noqa: BLE001 - any expansion failure means "not executable"
            logger.warning("proposal_target_expansion_failed", tool=spec.name, error_class=exc.__class__.__name__)
            return [], False, f"targets could not be expanded ({exc.__class__.__name__})"

        provenance: set[str] = {str(v).strip().lower() for v in trigger.get("provenance") or set() if v}
        targets: list[dict[str, Any]] = []
        unproven: list[str] = []
        for target in raw:
            value = str(target.value or "").strip()
            structured = bool(target.resolved_id) or value.lower() in provenance
            targets.append({
                "kind": target.kind,
                "value": value,
                "resolved_id": target.resolved_id,
                "provenance": "structured" if structured else "untrusted_text",
            })
            if not structured:
                unproven.append(value)
        if not targets:
            return targets, False, "action named no verifiable target"
        if unproven:
            return targets, False, (
                "target(s) " + ", ".join(unproven[:5]) + " have no provenance in a structured field "
                "reachable from the trigger"
            )
        return targets, True, None

    def _evidence_sha256(self, result: RunResult) -> str:
        """Digest binding a proposal to the evidence the run actually read.

        ``RunResult`` does not expose the wrapped evidence text the runtime
        hashes internally, so this chains the per-result digests the tool log
        does carry, in order. It is deterministic and recomputable, which is
        what ``/actions/{id}/approve`` needs to detect a stale approval.
        """
        chain = "".join(e.result_sha256 or "" for e in result.tool_log)
        return hashlib.sha256(f"{result.run_id}:{chain}".encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Incident-response loop closure
    # ------------------------------------------------------------------

    async def _open_incident_for_verdict(
        self,
        investigation: Investigation,
        agent: SOCAgent,
        verdict: dict[str, Any],
    ) -> None:
        """Open an Incident for a confirmed true positive, attributed to the
        SOC agent that produced the verdict. Idempotent: an alert that already
        has an incident is linked instead of re-opened."""
        from src.models.alert import Alert
        from src.models.incident import Incident

        trigger_id = investigation.trigger_source_id
        if not trigger_id or (investigation.trigger_type or "") not in ("alert", "alert_manual"):
            return
        alert = (await self.db.execute(
            select(Alert).where(
                Alert.id == trigger_id, Alert.organization_id == investigation.organization_id
            )
        )).scalar_one_or_none()
        if alert is None:
            return

        if alert.incident_id:
            self._link_incident(investigation, alert.incident_id)
            return

        attribution = f"Opened by SOC agent {agent.name} ({agent.id}) from investigation {investigation.id}."
        summary = str(verdict.get("reasoning") or investigation.findings_summary or "")
        incident = Incident(
            title=f"{alert.title} (auto-opened from investigation {investigation.id[:8]})"[:500],
            severity=(alert.severity or "high").lower(),
            status="open",
            description=f"{attribution}\n\n{summary}"[:4000],
            organization_id=investigation.organization_id,
            detected_at=datetime.now(timezone.utc).isoformat(),
            evidence=json.dumps({
                "opened_by_agent_id": agent.id,
                "investigation_id": investigation.id,
                "source_alert_id": alert.id,
                "confidence_score": investigation.confidence_score,
            }),
        )
        self.db.add(incident)
        await self.db.flush()

        alert.incident_id = incident.id
        alert.status = "investigating"
        self._link_incident(investigation, incident.id)
        logger.info(
            "autonomous_incident_opened",
            incident_id=incident.id,
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            soc_agent_id=agent.id,
        )

    def _link_incident(self, investigation: Investigation, incident_id: str) -> None:
        try:
            evidence = json.loads(investigation.evidence_collected or "{}")
        except json.JSONDecodeError:
            evidence = {}
        if not isinstance(evidence, dict):
            evidence = {}
        evidence["linked_incident_id"] = incident_id
        investigation.evidence_collected = json.dumps(evidence, default=str)[:MAX_EVIDENCE_BYTES]

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    @staticmethod
    async def _close_quota(runtime: Any) -> None:
        closer = getattr(runtime.quota, "aclose", None)
        if closer is None:
            return
        try:
            await closer()
        except Exception as exc:  # noqa: BLE001 - closing is best effort
            logger.warning("investigation_quota_close_failed", error=str(exc)[:200])
