"""PY-HUNT-001 — structured threat hunt orchestration.

Runs the defensive hunt phases in order against the real engine and the
ATT&CK KB, and produces a structured report: scope, data collection,
findings, ATT&CK mapping, verdict, and recommendations that are ALWAYS
flagged for human approval (no auto-remediation).

Both hunt phases go through ``AgentToolRegistry.call``, so ``scope_hunt`` and
``run_threat_hunt`` get the same policy evaluation, org scoping, rate charge
and audit pair here as they do from chat (design v2 section 1: no code path
executes a tool handler directly). That needs an actor: the caller passes the
authenticated analyst's id and role, exactly as the chat surface does.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.context import AgentContext, Mode, UserRole
from src.core.logging import get_logger

logger = get_logger(__name__)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


async def run_structured_hunt(
    db: AsyncSession,
    hypothesis: str,
    organization_id: Optional[str] = None,
    timeframe_hours: int = 24,
    *,
    actor_user_id: Optional[str] = None,
    role: UserRole = UserRole.ANALYST,
    actor_ip: Optional[str] = None,
    redis: Any = None,
) -> dict[str, Any]:
    """Execute PY-HUNT-001 and return a structured hunt report.

    ``organization_id`` and ``actor_user_id`` are required: the hunt writes a
    hunt session and findings for one organization on behalf of one analyst,
    and the policy engine will not evaluate a call without that identity.
    """
    from src.agentic.runtime_factory import build_policy
    from src.hunting.models import HuntFinding

    if not organization_id:
        raise ValueError("run_structured_hunt requires organization_id")
    if not actor_user_id:
        raise ValueError(
            "run_structured_hunt requires actor_user_id: the hunt runs as the authenticated "
            "analyst so its tool calls can be policy-checked and audited"
        )

    ctx = AgentContext(
        org_id=organization_id,
        role=role,
        mode=Mode.INTERACTIVE,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
    )
    registry, policy, _audit = build_policy(db, ctx, redis=redis)

    # --- Phase 1: Scope (ATT&CK-validated) ---
    scope = await registry.call(ctx, "scope_hunt", {"hypothesis": hypothesis}, policy=policy)

    # --- Phases 2-3: Data collection + correlation (real multi-source scan) ---
    hunt = await registry.call(
        ctx,
        "run_threat_hunt",
        {"hypothesis": hypothesis, "timeframe_hours": int(timeframe_hours)},
        policy=policy,
    )
    session_id = hunt.get("session_id")

    findings = []
    if session_id:
        rows = (await db.execute(
            select(HuntFinding).where(
                HuntFinding.session_id == session_id,
                HuntFinding.organization_id == organization_id,
            )
        )).scalars().all()
        for f in rows:
            try:
                evidence = json.loads(f.evidence) if f.evidence else []
            except (TypeError, json.JSONDecodeError):
                evidence = []
            try:
                techs = json.loads(f.mitre_techniques) if f.mitre_techniques else []
            except (TypeError, json.JSONDecodeError):
                techs = []
            findings.append({
                "title": f.title, "severity": f.severity,
                "description": f.description, "evidence": evidence,
                "mitre_techniques": techs,
            })

    # --- Phase 4: ATT&CK mapping (grounded in scope + findings) ---
    techniques = {t["technique"] for t in scope.get("techniques_in_scope", [])}
    for f in findings:
        techniques.update(f.get("mitre_techniques") or [])
    tactics = sorted({tac for t in scope.get("techniques_in_scope", []) for tac in (t.get("tactics") or [])})

    # --- Phase 5: Scoring → verdict ---
    max_rank = max((_SEVERITY_RANK.get(f["severity"], 0) for f in findings), default=-1)
    severity = next((s for s, r in _SEVERITY_RANK.items() if r == max_rank), "informational") if findings else "none"

    # Only findings of medium severity or higher constitute a positive
    # result. Low/informational matches are context/noise — surfacing
    # them is useful, but they must NOT drive a "suspicious" verdict, or
    # the hunt cries wolf on every benign keyword co-occurrence.
    strong_findings = [f for f in findings if _SEVERITY_RANK.get(f["severity"], 0) >= 2]
    uncovered = scope.get("coverage_summary", {}).get("uncovered", 0)
    collected = scope.get("collected_source_types")
    if strong_findings and max_rank >= 3:
        verdict, confidence = "suspicious_activity", 75
    elif strong_findings:
        verdict, confidence = "suspicious_activity", 55
    elif findings:
        # we looked and matched only low/informational events
        verdict, confidence = "benign", 55
    elif uncovered and not collected:
        # nothing found, but we also lacked the telemetry to find it
        verdict, confidence = "inconclusive", 30
    else:
        verdict, confidence = "benign", 60

    # --- Phase 6/7: Recommendations (advisory, ALWAYS approval-gated) ---
    recommendations = []
    high_findings = [f for f in findings if _SEVERITY_RANK.get(f["severity"], 0) >= 3]
    for f in high_findings[:10]:
        recommendations.append({
            "action": f"Open an incident to investigate finding: {f['title']}",
            "rationale": f"{f['severity']} severity hunt finding",
            "requires_approval": True,
        })
    # A suspicious verdict driven by medium-severity findings still needs a
    # triage recommendation — never "no action" when the hunt flagged
    # something. Reference the affected hosts so the analyst can act.
    if verdict == "suspicious_activity" and not high_findings and strong_findings:
        techs = ", ".join(sorted(techniques)) if techniques else "the cited techniques"
        recommendations.append({
            "action": (
                f"Triage the {len(strong_findings)} suspicious finding(s) for {techs} "
                "and confirm true/false positive"
            ),
            "rationale": "hunt surfaced medium-severity activity matching the hypothesis",
            "requires_approval": True,
        })
    for t in scope.get("techniques_in_scope", []):
        if not t.get("covered"):
            recommendations.append({
                "action": f"Author a detection rule for {t['technique']} ({t.get('name')})",
                "rationale": "no active detection rule covers this in-scope technique",
                "requires_approval": True,
            })
    if verdict == "inconclusive":
        recommendations.append({
            "action": "Onboard the missing telemetry (see needed_log_sources) before re-running this hunt",
            "rationale": "hunt could not reach a conclusion without the detecting data sources",
            "requires_approval": True,
        })
    if not recommendations:
        recommendations.append({
            "action": "No action required; document the hunt as a negative result",
            "rationale": "no suspicious findings and adequate coverage",
            "requires_approval": True,
        })

    return {
        "playbook": "PY-HUNT-001",
        "hypothesis": hypothesis,
        "phases": {
            "scope": scope,
            "data_collection": {
                "logs_scanned": hunt.get("logs_scanned", 0),
                "alerts_scanned": hunt.get("alerts_scanned", 0),
                "audit_scanned": hunt.get("audit_scanned", 0),
                "iocs_checked": hunt.get("iocs_checked", 0),
                "matched_keywords": hunt.get("matched_keywords", []),
                "session_id": session_id,
            },
            "findings": findings,
        },
        "attack_mapping": {
            "techniques": sorted(techniques),
            "tactics": tactics,
        },
        "severity": severity,
        "verdict": verdict,
        "confidence": confidence,
        "recommendations": recommendations,
        "notes": scope.get("notes", []),
    }
