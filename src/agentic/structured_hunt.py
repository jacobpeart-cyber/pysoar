"""PY-HUNT-001 — structured threat hunt orchestration.

Runs the defensive hunt phases in order against the real engine and the
ATT&CK KB, and produces a structured report: scope, data collection,
findings, ATT&CK mapping, verdict, and recommendations that are ALWAYS
flagged for human approval (no auto-remediation). One place, called by
both the API endpoint and the registered agent skill.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


async def run_structured_hunt(
    db: AsyncSession,
    hypothesis: str,
    organization_id: Optional[str] = None,
    timeframe_hours: int = 24,
) -> dict[str, Any]:
    """Execute PY-HUNT-001 and return a structured hunt report."""
    from src.services.agent_tools import AgentToolRegistry
    from src.hunting.models import HuntFinding

    registry = AgentToolRegistry(db)

    # --- Phase 1: Scope (ATT&CK-validated) ---
    scope = await registry._scope_hunt(hypothesis)

    # --- Phases 2-3: Data collection + correlation (real multi-source scan) ---
    hunt = await registry._run_threat_hunt(hypothesis, timeframe_hours=timeframe_hours)
    session_id = hunt.get("session_id")

    findings = []
    if session_id:
        rows = (await db.execute(
            select(HuntFinding).where(HuntFinding.session_id == session_id)
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
    for f in findings[:10]:
        if _SEVERITY_RANK.get(f["severity"], 0) >= 3:
            recommendations.append({
                "action": f"Open an incident to investigate finding: {f['title']}",
                "rationale": f"{f['severity']} severity hunt finding",
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
            "rationale": "no findings and adequate coverage",
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
