"""
AI/ML Security Engine REST API Endpoints.

Provides REST API for natural language queries, anomaly detection, threat
predictions, incident analysis, and ML model management.
"""

import asyncio
import json
import math
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger
from src.ai.engine import AIAnalyzer, AnomalyDetector, ThreatPredictor
from src.ai.models import MLModel, AnomalyDetection, AIAnalysis, ThreatPrediction, NLQuery
from src.schemas.ai import (
    NLQueryRequest,
    NLQueryResponse,
    QueryHistoryResponse,
    AlertTriageRequest,
    AlertTriageResponse,
    BatchTriageRequest,
    BatchTriageResponse,
    TriageStatsResponse,
    IncidentAnalysisRequest,
    IncidentAnalysisResponse,
    ImpactAssessment,
    RootCauseAnalysis,
    ResponseRecommendationRequest,
    ResponseRecommendation,
    AnomalyDetectionResponse,
    AnomalyFeedback,
    AnomalyListResponse,
    AnomalyStatsResponse,
    ThreatPredictionRequest,
    ThreatPredictionResponse,
    PredictionDashboard,
    MLModelResponse,
    ModelTrainingRequest,
    ModelDriftResponse,
    AIFeedbackRequest,
    AIDashboardResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/ai", tags=["ai"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Helper: simple heuristic functions (stand-ins for real ML)
# ---------------------------------------------------------------------------

def _compute_triage_priority(severity: str, source: str) -> dict[str, Any]:
    """Heuristic alert triage based on severity and source."""
    severity_map = {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4"}
    priority = severity_map.get(severity, "p3")
    # EDR and IDS sources bump priority up one level
    if source in ("EDR", "IDS") and priority in ("p3", "p4"):
        priority = "p2" if priority == "p3" else "p3"

    confidence_map = {"p1": 0.95, "p2": 0.88, "p3": 0.78, "p4": 0.65}
    confidence = confidence_map.get(priority, 0.75)
    fp_map = {"p1": 0.05, "p2": 0.15, "p3": 0.30, "p4": 0.45}
    fp_prob = fp_map.get(priority, 0.25)

    actions = []
    if priority in ("p1", "p2"):
        actions.extend(["isolate_host", "collect_forensic_artifacts", "notify_soc_lead"])
    else:
        actions.extend(["review_logs", "check_related_alerts"])

    reasoning = (
        f"Alert severity '{severity}' from source '{source}' indicates {priority} priority. "
        f"Confidence {confidence:.0%}."
    )
    return {
        "priority": priority,
        "confidence": confidence,
        "false_positive_probability": fp_prob,
        "recommended_actions": actions,
        "reasoning": reasoning,
        "model_used": "heuristic-v1",
    }


def _llm_available() -> bool:
    """Check whether an LLM provider key is configured."""
    return bool(os.environ.get("GEMINI_API_KEY"))


def _parse_json_field(raw: Any) -> Any:
    """Parse a TEXT/JSON-string column safely. Returns [] / {} / None on failure."""
    if raw is None:
        return None
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None
    return None


async def _load_incident_context(db: AsyncSession, incident_id: str) -> dict[str, Any]:
    """
    Load an incident plus its linked alerts and derived facts from the DB.

    Returns a dict with: incident (ORM object or None), alerts (list of Alert),
    affected_systems (list[str]), affected_users (list[str]), tags (list[str]),
    mitre_techniques (list[str]), mitre_tactics (list[str]),
    earliest_alert_at (datetime|None), dwell_time_days (int|None).
    """
    from src.models.alert import Alert
    from src.models.incident import Incident

    inc_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = inc_result.scalar_one_or_none()

    alerts: list[Any] = []
    if incident is not None:
        alert_q = (
            select(Alert)
            .where(Alert.incident_id == incident_id)
            .order_by(Alert.created_at.asc())
        )
        alerts = list((await db.execute(alert_q)).scalars().all())

    affected_systems: list[str] = []
    affected_users: list[str] = []
    tags: list[str] = []
    mitre_techniques: list[str] = []
    mitre_tactics: list[str] = []
    earliest_alert_at: datetime | None = None

    if incident is not None:
        affected_systems = _parse_json_field(incident.affected_systems) or []
        affected_users = _parse_json_field(incident.affected_users) or []
        tags = _parse_json_field(incident.tags) or []
        mitre_techniques = _parse_json_field(incident.mitre_techniques) or []
        mitre_tactics = _parse_json_field(incident.mitre_tactics) or []

    # Augment from linked alerts
    for a in alerts:
        if a.hostname and a.hostname not in affected_systems:
            affected_systems.append(a.hostname)
        if a.username and a.username not in affected_users:
            affected_users.append(a.username)
        if a.created_at and (earliest_alert_at is None or a.created_at < earliest_alert_at):
            earliest_alert_at = a.created_at

    dwell_time_days: int | None = None
    if incident is not None and incident.created_at and earliest_alert_at:
        # Dwell time = time between first observed alert and incident creation.
        delta = incident.created_at - earliest_alert_at
        dwell_time_days = max(0, int(delta.total_seconds() // 86400))

    return {
        "incident": incident,
        "alerts": alerts,
        "affected_systems": affected_systems,
        "affected_users": affected_users,
        "tags": tags,
        "mitre_techniques": mitre_techniques,
        "mitre_tactics": mitre_tactics,
        "earliest_alert_at": earliest_alert_at,
        "dwell_time_days": dwell_time_days,
    }


def _serialize_incident(incident: Any) -> dict[str, Any]:
    """Serialize an Incident ORM row for LLM consumption."""
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description or "",
        "severity": incident.severity,
        "status": incident.status,
        "incident_type": incident.incident_type,
        "priority": incident.priority,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "detected_at": incident.detected_at,
        "tags": _parse_json_field(incident.tags) or [],
        "mitre_techniques": _parse_json_field(incident.mitre_techniques) or [],
    }


def _serialize_alert(alert: Any) -> dict[str, Any]:
    """Serialize an Alert ORM row for LLM consumption."""
    return {
        "id": alert.id,
        "title": alert.title,
        "description": (alert.description or "")[:500],
        "severity": alert.severity,
        "status": alert.status,
        "source": alert.source,
        "category": alert.category,
        "hostname": alert.hostname,
        "username": alert.username,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


def _build_incident_timeline(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Construct a chronological timeline from incident + linked alerts."""
    timeline: list[dict[str, Any]] = []
    incident = ctx.get("incident")
    if incident is not None and incident.created_at:
        timeline.append({
            "timestamp": incident.created_at.isoformat(),
            "event": "incident_created",
            "detail": incident.title,
        })
    for a in ctx.get("alerts", []) or []:
        if a.created_at:
            timeline.append({
                "timestamp": a.created_at.isoformat(),
                "event": "alert_observed",
                "detail": f"{a.severity}: {a.title}",
            })
    timeline.sort(key=lambda x: x.get("timestamp") or "")
    return timeline


def _heuristic_incident_analysis(ctx: dict[str, Any]) -> dict[str, Any]:
    """Derive an incident analysis from real DB context — no LLM, no canned strings."""
    incident = ctx.get("incident")
    alerts = ctx.get("alerts", []) or []
    affected_systems = ctx.get("affected_systems", []) or []
    affected_users = ctx.get("affected_users", []) or []
    tags = ctx.get("tags", []) or []
    mitre = ctx.get("mitre_techniques", []) or []
    dwell = ctx.get("dwell_time_days")

    if incident is None:
        return {
            "executive_summary": "Incident not found in database; no analysis possible.",
            "technical_details": "",
            "impact_assessment": {
                "affected_systems": [],
                "data_exposed": [],
                "users_affected": 0,
                "severity": "unknown",
            },
            "recommendations": [],
            "confidence": 0.0,
            "derivation": "rule_based",
        }

    severity = (incident.severity or "medium").lower()
    inc_type = incident.incident_type or "incident"
    title = incident.title or "(untitled)"
    n_alerts = len(alerts)

    sev_counts: dict[str, int] = {}
    sources: set[str] = set()
    for a in alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        if a.source:
            sources.add(a.source)

    sev_breakdown = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items())) or "none"
    sources_str = ", ".join(sorted(sources)) or "no recorded sources"

    exec_summary = (
        f"{severity.capitalize()}-severity {inc_type} incident '{title}' "
        f"correlates {n_alerts} alert(s) ({sev_breakdown}) across "
        f"{len(affected_systems)} host(s) and {len(affected_users)} user account(s)."
    )

    tech_lines = [
        f"Incident {incident.id} (status={incident.status}, priority={incident.priority}) "
        f"was opened on {incident.created_at.isoformat() if incident.created_at else 'unknown'}.",
        f"Linked telemetry: {n_alerts} alert(s) from sources [{sources_str}].",
    ]
    if affected_systems:
        tech_lines.append("Affected systems: " + ", ".join(affected_systems[:10]))
    if affected_users:
        tech_lines.append("Affected users: " + ", ".join(affected_users[:10]))
    if mitre:
        tech_lines.append("Mapped MITRE techniques: " + ", ".join(mitre[:10]))
    if tags:
        tech_lines.append("Tags: " + ", ".join(tags[:10]))
    if dwell is not None:
        tech_lines.append(
            f"Approximate dwell time (first alert -> incident creation): {dwell} day(s)."
        )
    if alerts:
        sample_titles = [a.title for a in alerts[:3] if a.title]
        if sample_titles:
            tech_lines.append("Earliest alert titles: " + " | ".join(sample_titles))
    tech = "\n".join(tech_lines)

    recs: list[str] = []
    if severity in ("critical", "high"):
        recs.append("Activate incident response team and notify SOC leadership")
    if affected_systems:
        recs.append(f"Isolate or contain affected systems: {', '.join(affected_systems[:5])}")
    if affected_users:
        recs.append(
            f"Reset credentials and review session activity for: {', '.join(affected_users[:5])}"
        )
    if "phishing" in (inc_type or "").lower() or any(
        "phish" in (a.title or "").lower() for a in alerts
    ):
        recs.append("Block sender domains and quarantine related emails at the gateway")
    if mitre:
        recs.append(
            f"Hunt for related TTPs in SIEM logs (techniques: {', '.join(mitre[:5])})"
        )
    if not recs:
        recs.append("Triage the linked alerts and confirm the scope before further action")

    confidence = 0.55 if n_alerts == 0 else min(0.85, 0.55 + 0.05 * min(n_alerts, 6))

    return {
        "executive_summary": exec_summary,
        "technical_details": tech,
        "impact_assessment": {
            "affected_systems": affected_systems,
            "data_exposed": [],  # not tracked structurally
            "users_affected": len(affected_users),
            "severity": severity,
        },
        "recommendations": recs,
        "confidence": round(confidence, 2),
        "derivation": "rule_based",
    }


def _heuristic_root_cause(ctx: dict[str, Any]) -> dict[str, Any]:
    """Derive a root-cause sketch from real DB fields; no canned narrative."""
    incident = ctx.get("incident")
    alerts = ctx.get("alerts", []) or []
    dwell = ctx.get("dwell_time_days")

    if incident is None:
        return {
            "root_cause": "Incident not found in database; root cause cannot be determined.",
            "attack_chain": [],
            "entry_point": "unknown",
            "dwell_time_days": 0,
            "confidence": 0.0,
            "derivation": "rule_based",
        }

    # Use Incident.root_cause column if analysts populated it.
    declared_root = (incident.root_cause or "").strip()

    # Otherwise derive from earliest alert source/category.
    earliest = alerts[0] if alerts else None
    inferred_root = ""
    entry_point = "unknown"
    if earliest is not None:
        src = earliest.source or "unknown source"
        cat = earliest.category or earliest.alert_type or "unknown category"
        inferred_root = (
            f"Earliest observed alert '{earliest.title}' from {src} "
            f"(category: {cat}) suggests initial vector of compromise."
        )
        entry_point = src

    root_cause = declared_root or inferred_root or (
        f"No root cause has been recorded for incident '{incident.title}' "
        f"and no linked alerts are available to infer one."
    )

    # Build attack chain from alert ordering.
    chain: list[str] = []
    for a in alerts[:8]:
        ts = a.created_at.isoformat() if a.created_at else "unknown time"
        chain.append(f"[{ts}] {a.severity} alert from {a.source or 'unknown'}: {a.title}")
    if not chain:
        chain.append(
            f"No linked alerts; chain reconstruction unavailable for incident {incident.id}."
        )

    confidence = 0.7 if declared_root else (0.5 if alerts else 0.2)

    return {
        "root_cause": root_cause,
        "attack_chain": chain,
        "entry_point": entry_point,
        "dwell_time_days": int(dwell) if dwell is not None else 0,
        "confidence": confidence,
        "derivation": "rule_based",
    }


def _heuristic_response_recommendations(
    ctx: dict[str, Any], incident_type: str, severity: str
) -> dict[str, Any]:
    """Derive response steps that reference real affected systems/users where present."""
    incident = ctx.get("incident")
    affected_systems = ctx.get("affected_systems", []) or []
    affected_users = ctx.get("affected_users", []) or []
    n_alerts = len(ctx.get("alerts", []) or [])

    # Build action lists that reference real entities when available.
    immediate: list[str] = ["Activate incident response team", "Preserve volatile evidence"]
    containment: list[str] = []
    investigation: list[str] = [
        f"Review the {n_alerts} linked alert(s) and pivot on shared indicators"
        if n_alerts
        else "Search SIEM for additional indicators related to this incident"
    ]
    recovery: list[str] = []

    if affected_systems:
        sys_str = ", ".join(affected_systems[:5])
        containment.append(f"Network-isolate affected hosts: {sys_str}")
        investigation.append(f"Pull EDR forensics from: {sys_str}")
        recovery.append(f"Re-image or restore from clean baseline: {sys_str}")
    else:
        containment.append("Identify affected hosts via SIEM/EDR before isolation")

    if affected_users:
        u_str = ", ".join(affected_users[:5])
        containment.append(f"Disable or force re-auth for accounts: {u_str}")
        recovery.append(f"Reset credentials and revoke active sessions for: {u_str}")
    else:
        containment.append("Identify and lock any compromised user accounts")

    if not recovery:
        recovery.append("Patch any exploited vulnerabilities and verify hardening")

    sev = (severity or "").lower()
    if sev in ("critical", "high"):
        immediate.append("Notify executive leadership and legal/compliance")
        hours = 48 if sev == "critical" else 72
    else:
        hours = 120

    # Type-specific tweaks based on real incident_type.
    itype = (incident_type or (incident.incident_type if incident is not None else "") or "").lower()
    if "phish" in itype:
        containment.append("Quarantine the malicious email and block sender at the gateway")
    if "ransom" in itype:
        immediate.append("Engage backup/restore team; preserve encrypted samples")
    if "data_breach" in itype or "exfil" in itype:
        investigation.append("Quantify data egress volume from network/proxy logs")
        recovery.append("Notify affected data subjects per regulatory obligations")

    return {
        "immediate_actions": immediate,
        "containment_steps": containment,
        "investigation_steps": investigation,
        "recovery_plan": recovery,
        "timeline_estimate_hours": hours,
        "derivation": "rule_based",
    }


async def _load_entity_risk_signals(
    db: AsyncSession, entity_type: str, entity_id: str, org_id: str | None
) -> dict[str, Any]:
    """
    Pull real risk signals for an entity:
      - UEBA EntityProfile.risk_score, anomaly_count_30d
      - Count of recent AnomalyDetection rows for this entity
      - Count of recent UEBARiskAlert rows
      - For host entities: Asset.criticality, security_score
    """
    from src.ueba.models import EntityProfile, UEBARiskAlert
    from src.models.asset import Asset

    signals: dict[str, Any] = {
        "ueba_risk_score": None,
        "anomaly_count_30d": 0,
        "recent_anomalies": 0,
        "recent_ueba_alerts": 0,
        "asset_criticality": None,
        "asset_security_score": None,
        "peer_deviation": None,
    }

    # UEBA profile
    profile_q = select(EntityProfile).where(
        EntityProfile.entity_type == entity_type,
        EntityProfile.entity_id == entity_id,
    )
    if org_id:
        profile_q = profile_q.where(EntityProfile.organization_id == org_id)
    profile = (await db.execute(profile_q)).scalar_one_or_none()
    if profile is not None:
        signals["ueba_risk_score"] = float(profile.risk_score or 0.0)
        signals["anomaly_count_30d"] = int(profile.anomaly_count_30d or 0)
        # Peer deviation if baseline_data carries peer comparison
        baseline = profile.baseline_data or {}
        peer = baseline.get("peer_comparison") if isinstance(baseline, dict) else None
        if isinstance(peer, dict) and "deviation" in peer:
            try:
                signals["peer_deviation"] = float(peer["deviation"])
            except (TypeError, ValueError):
                pass

        # Recent UEBA alerts for this profile
        recent_cutoff = _utc_now() - timedelta(days=30)
        ueba_alert_q = select(func.count(UEBARiskAlert.id)).where(
            UEBARiskAlert.entity_profile_id == profile.id,
            UEBARiskAlert.created_at >= recent_cutoff,
        )
        signals["recent_ueba_alerts"] = int((await db.execute(ueba_alert_q)).scalar() or 0)

    # Anomaly detections for this entity
    recent_cutoff = _utc_now() - timedelta(days=30)
    anom_q = select(func.count(AnomalyDetection.id)).where(
        AnomalyDetection.entity_type == entity_type,
        AnomalyDetection.entity_id == entity_id,
        AnomalyDetection.created_at >= recent_cutoff,
    )
    if org_id:
        anom_q = anom_q.where(AnomalyDetection.organization_id == org_id)
    signals["recent_anomalies"] = int((await db.execute(anom_q)).scalar() or 0)

    # Asset metadata if entity is a host
    if entity_type in ("host", "asset"):
        from sqlalchemy import or_ as _or
        asset_q = select(Asset).where(
            _or(
                Asset.id == entity_id,
                Asset.hostname == entity_id,
                Asset.name == entity_id,
            )
        )
        if org_id:
            asset_q = asset_q.where(Asset.organization_id == org_id)
        asset = (await db.execute(asset_q)).scalars().first()
        if asset is not None:
            signals["asset_criticality"] = asset.criticality
            signals["asset_security_score"] = asset.security_score

    return signals


def _compute_threat_prediction_from_signals(
    entity_type: str, entity_id: str, signals: dict[str, Any]
) -> dict[str, Any]:
    """
    Compute risk score (0-100) from real signals — NOT hash(entity_id).
    Weighted blend:
      - UEBA risk_score (0-100)        : weight 0.40
      - anomaly_count_30d (cap 20)     : weight 0.20
      - recent anomaly detections (cap 10): weight 0.15
      - recent UEBA alerts (cap 10)    : weight 0.10
      - asset criticality              : weight 0.10
      - peer deviation (cap 1.0)       : weight 0.05
    Falls back to 0 (with low confidence factors) when no signals are present.
    """
    components: list[tuple[float, float, str]] = []  # (value_0_100, weight, factor_name)

    ueba = signals.get("ueba_risk_score")
    if ueba is not None:
        components.append((max(0.0, min(100.0, float(ueba))), 0.40, "ueba_risk_score"))

    anom_30d = signals.get("anomaly_count_30d") or 0
    if anom_30d > 0:
        components.append((min(20, anom_30d) / 20.0 * 100.0, 0.20, "ueba_anomaly_count_30d"))

    recent_anom = signals.get("recent_anomalies") or 0
    if recent_anom > 0:
        components.append((min(10, recent_anom) / 10.0 * 100.0, 0.15, "recent_anomaly_detections"))

    recent_ueba = signals.get("recent_ueba_alerts") or 0
    if recent_ueba > 0:
        components.append((min(10, recent_ueba) / 10.0 * 100.0, 0.10, "recent_ueba_alerts"))

    crit = (signals.get("asset_criticality") or "").lower()
    crit_map = {"critical": 100.0, "high": 80.0, "medium": 50.0, "low": 25.0}
    if crit in crit_map:
        components.append((crit_map[crit], 0.10, f"asset_criticality:{crit}"))

    peer_dev = signals.get("peer_deviation")
    if peer_dev is not None:
        components.append((max(0.0, min(1.0, float(peer_dev))) * 100.0, 0.05, "peer_deviation"))

    if not components:
        risk_score = 0.0
        factors = ["no_risk_signals_available"]
    else:
        total_w = sum(w for _, w, _ in components)
        risk_score = sum(v * w for v, w, _ in components) / total_w if total_w > 0 else 0.0
        factors = [name for _, _, name in components]

    risk_score = round(max(0.0, min(100.0, risk_score)), 2)
    probability = round(risk_score / 100.0, 2)

    actions: list[str] = []
    if risk_score >= 70:
        actions.extend([
            "increase_monitoring_for_entity",
            "review_recent_authentications_and_privileges",
            "preempt_with_credential_rotation_or_isolation",
        ])
    elif risk_score >= 40:
        actions.extend([
            "increase_monitoring_for_entity",
            "review_anomalies_for_this_entity",
        ])
    else:
        actions.append("continue_baseline_monitoring")

    if (signals.get("asset_security_score") or 100) < 60:
        actions.append("remediate_open_vulnerabilities_on_asset")

    return {
        "prediction_type": "attack_probability",
        "risk_score": risk_score,
        "probability": probability,
        "contributing_factors": factors,
        "recommended_actions": actions,
        "derivation": "rule_based",
        "raw_signals": signals,
    }


# ---------------------------------------------------------------------------
# Natural Language Query Endpoints
# ---------------------------------------------------------------------------

@router.post("/query", response_model=NLQueryResponse, summary="Natural language query")
async def natural_language_query(
    request: NLQueryRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Process natural language security query.

    Interprets the query, stores it in the database, and returns results.
    """
    try:
        logger.info(f"Processing NL query: {request.natural_language[:50]}...")

        import time as _time
        _query_start = _time.monotonic()

        # Intent classification heuristic
        text_lower = request.natural_language.lower()
        if "failed login" in text_lower or "authentication" in text_lower or "brute force" in text_lower:
            intent = "log_search"
            generated_query = "SELECT * FROM alerts WHERE title/description matches authentication failures"
        elif "vulnerability" in text_lower or "cve" in text_lower or "patch" in text_lower:
            intent = "vulnerability_search"
            generated_query = "SELECT * FROM alerts WHERE category relates to vulnerabilities"
        elif "lateral movement" in text_lower or "pivot" in text_lower:
            intent = "threat_hunt"
            generated_query = "SELECT * FROM alerts WHERE category relates to lateral movement"
        elif "threat actor" in text_lower or "apt" in text_lower or "threat intel" in text_lower:
            intent = "threat_intel"
            generated_query = "SELECT * FROM alerts WHERE category relates to threat actors"
        elif "incident" in text_lower and "alert" not in text_lower:
            intent = "incident_search"
            generated_query = "SELECT * FROM incidents matching query terms"
        elif "critical" in text_lower or "high" in text_lower or "severity" in text_lower:
            intent = "severity_search"
            generated_query = "SELECT * FROM alerts WHERE severity IN ('critical','high') ORDER BY created_at DESC"
        elif any(w in text_lower for w in ["alert", "alerts", "recent", "latest", "all", "show", "list"]):
            intent = "list_alerts"
            generated_query = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 20"
        else:
            intent = "general_search"
            generated_query = f"SELECT * FROM alerts ORDER BY created_at DESC LIMIT 20"

        # Query real data from the database based on detected intent
        from src.models.alert import Alert
        from src.models.incident import Incident

        results = []

        if intent == "incident_search":
            # Search incidents
            search_terms = text_lower.replace("incident", "").strip()
            incident_query = select(Incident).order_by(Incident.created_at.desc()).limit(20)
            if search_terms:
                incident_query = (
                    select(Incident)
                    .where(
                        Incident.title.ilike(f"%{search_terms}%")
                        | Incident.description.ilike(f"%{search_terms}%")
                    )
                    .order_by(Incident.created_at.desc())
                    .limit(20)
                )
            inc_result = await db.execute(incident_query)
            incidents = list(inc_result.scalars().all())
            for i, inc in enumerate(incidents):
                results.append({
                    "row": i + 1,
                    "type": "incident",
                    "id": inc.id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "status": inc.status,
                    "created_at": inc.created_at.isoformat() if inc.created_at else "",
                })
        else:
            # Search alerts based on intent-specific filters
            alert_query = select(Alert).order_by(Alert.created_at.desc()).limit(20)

            if intent == "log_search":
                # Look for authentication-related alerts
                alert_query = (
                    select(Alert)
                    .where(
                        Alert.title.ilike("%login%")
                        | Alert.title.ilike("%auth%")
                        | Alert.title.ilike("%credential%")
                        | Alert.description.ilike("%login%")
                        | Alert.description.ilike("%auth%")
                    )
                    .order_by(Alert.created_at.desc())
                    .limit(20)
                )
            elif intent == "vulnerability_search":
                alert_query = (
                    select(Alert)
                    .where(
                        Alert.title.ilike("%vuln%")
                        | Alert.title.ilike("%cve%")
                        | Alert.description.ilike("%vuln%")
                        | Alert.description.ilike("%cve%")
                        | Alert.category.ilike("%vuln%")
                    )
                    .order_by(Alert.created_at.desc())
                    .limit(20)
                )
            elif intent == "threat_hunt":
                alert_query = (
                    select(Alert)
                    .where(
                        Alert.title.ilike("%lateral%")
                        | Alert.description.ilike("%lateral%")
                        | Alert.category.ilike("%lateral%")
                    )
                    .order_by(Alert.created_at.desc())
                    .limit(20)
                )
            elif intent == "severity_search":
                # Filter by severity
                severities = []
                if "critical" in text_lower:
                    severities.append("critical")
                if "high" in text_lower:
                    severities.append("high")
                if "medium" in text_lower:
                    severities.append("medium")
                if "low" in text_lower:
                    severities.append("low")
                if not severities:
                    severities = ["critical", "high"]
                alert_query = (
                    select(Alert)
                    .where(Alert.severity.in_(severities))
                    .order_by(Alert.created_at.desc())
                    .limit(20)
                )
            elif intent == "threat_intel":
                alert_query = (
                    select(Alert)
                    .where(
                        Alert.title.ilike("%threat%")
                        | Alert.description.ilike("%threat%")
                        | Alert.title.ilike("%actor%")
                    )
                    .order_by(Alert.created_at.desc())
                    .limit(20)
                )
            elif intent == "list_alerts":
                # Just return latest alerts
                alert_query = select(Alert).order_by(Alert.created_at.desc()).limit(20)
            else:
                # General search: look for query terms in title/description
                search_terms = text_lower[:60]
                stop_words = {"show", "me", "all", "the", "get", "find", "list", "what", "are", "from", "last", "recent", "hours", "days", "my", "our", "with", "and", "for", "that", "this", "have", "has"}
                words = [w for w in search_terms.split() if len(w) > 2 and w not in stop_words]
                if words:
                    # Search for the first meaningful term
                    term = words[0]
                    alert_query = (
                        select(Alert)
                        .where(
                            Alert.title.ilike(f"%{term}%")
                            | Alert.description.ilike(f"%{term}%")
                        )
                        .order_by(Alert.created_at.desc())
                        .limit(20)
                    )

            alert_result = await db.execute(alert_query)
            alerts = list(alert_result.scalars().all())
            for i, a in enumerate(alerts):
                results.append({
                    "row": i + 1,
                    "type": "alert",
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "source": a.source,
                    "created_at": a.created_at.isoformat() if a.created_at else "",
                })

        results_count = len(results)
        execution_time_ms = int((_time.monotonic() - _query_start) * 1000)
        summary = f"Found {results_count} results matching your query about '{request.natural_language[:60]}'."

        # Resolve org_id
        org_id = getattr(current_user, "organization_id", None)
        if not org_id:
            from src.models.organization import Organization
            org_result = await db.execute(select(Organization).limit(1))
            org = org_result.scalars().first()
            org_id = org.id if org else None

        # Persist to database
        nl_query = NLQuery(
            natural_language=request.natural_language,
            interpreted_intent=intent,
            generated_query=generated_query,
            query_parameters=request.user_context or {},
            results_summary=summary,
            result_count=results_count,
            execution_time_ms=execution_time_ms,
            user_id=current_user.id,
            was_helpful=None,
            organization_id=org_id or "",
        )
        db.add(nl_query)
        await db.flush()
        await db.refresh(nl_query)

        return NLQueryResponse(
            id=nl_query.id,
            interpreted_intent=nl_query.interpreted_intent,
            generated_query=nl_query.generated_query,
            results_count=nl_query.result_count,
            results=results,
            summary=summary,
            execution_time_ms=nl_query.execution_time_ms,
            created_at=nl_query.created_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Query processing error: {e}")
        raise HTTPException(status_code=500, detail="Query processing failed")


@router.get("/queries", response_model=list[QueryHistoryResponse], summary="Query history")
async def query_history(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
    skip: Annotated[int, Query(ge=0)] = 0,
):
    """
    Get natural language query history for the current user's organization.
    """
    query = (
        select(NLQuery)
        .where(NLQuery.organization_id == getattr(current_user, "organization_id", None))
        .order_by(NLQuery.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(query)
    queries = list(result.scalars().all())

    return [
        QueryHistoryResponse(
            id=q.id,
            natural_language=q.natural_language,
            interpreted_intent=q.interpreted_intent,
            results_count=q.result_count,
            created_at=q.created_at,
            was_helpful=q.was_helpful,
        )
        for q in queries
    ]


# ---------------------------------------------------------------------------
# Alert Triage Endpoints
# ---------------------------------------------------------------------------

@router.post("/triage/alert/{alert_id}", response_model=AlertTriageResponse, summary="Triage single alert")
async def triage_single_alert(
    alert_id: str,
    request: AlertTriageRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    AI triage for a single alert.

    Looks up the alert, computes a triage priority via heuristics, and persists
    the analysis result to the database.
    """
    try:
        logger.info(f"Triaging alert {alert_id}")

        # Try to fetch the real alert for context
        from src.models.alert import Alert

        alert_result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = alert_result.scalar_one_or_none()

        if alert:
            severity = getattr(alert, "severity", "medium") or "medium"
            source = getattr(alert, "source", "unknown") or "unknown"
        else:
            severity = "medium"
            source = "unknown"

        triage = _compute_triage_priority(severity, source)

        # Write back the triage priority to the alert record
        if alert:
            priority_map = {"p1": 1, "p2": 2, "p3": 3, "p4": 4}
            alert.priority = priority_map.get(triage["priority"], 3)
            await db.flush()

        # Persist analysis
        analysis = AIAnalysis(
            analysis_type="alert_triage",
            source_type="alert",
            source_id=alert_id,
            input_data={"alert_id": alert_id, "severity": severity, "source": source},
            ai_response=triage["reasoning"],
            structured_output=triage,
            confidence=triage["confidence"],
            model_used=triage["model_used"],
            tokens_used=0,
            latency_ms=0,
            organization_id=getattr(current_user, "organization_id", None),
        )
        db.add(analysis)
        await db.flush()
        await db.refresh(analysis)

        return AlertTriageResponse(
            alert_id=alert_id,
            priority=triage["priority"],
            reasoning=triage["reasoning"],
            confidence=triage["confidence"],
            false_positive_probability=triage["false_positive_probability"],
            recommended_actions=triage["recommended_actions"],
            model_used=triage["model_used"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alert triage error: {e}")
        raise HTTPException(status_code=500, detail="Triage failed")


@router.post("/triage/batch", response_model=BatchTriageResponse, summary="Batch triage alerts")
async def batch_triage_alerts(
    request: BatchTriageRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Batch triage of multiple alerts.

    If alert_ids are provided, triages those specific alerts. Otherwise triages
    the most recent untriaged alerts up to the limit.
    """
    try:
        from src.models.alert import Alert

        logger.info(f"Batch triaging up to {request.limit} alerts")

        if request.alert_ids:
            query = select(Alert).where(Alert.id.in_(request.alert_ids)).limit(request.limit)
        else:
            query = select(Alert).order_by(Alert.created_at.desc()).limit(request.limit)

        result = await db.execute(query)
        alerts = list(result.scalars().all())

        triaged_alerts: list[AlertTriageResponse] = []
        total_confidence = 0.0
        total_fp = 0.0

        for alert_obj in alerts:
            severity = getattr(alert_obj, "severity", "medium") or "medium"
            source = getattr(alert_obj, "source", "unknown") or "unknown"
            triage = _compute_triage_priority(severity, source)

            # Write back the triage priority to the alert record
            priority_map = {"p1": 1, "p2": 2, "p3": 3, "p4": 4}
            alert_obj.priority = priority_map.get(triage["priority"], 3)

            # Persist each triage analysis
            analysis = AIAnalysis(
                analysis_type="alert_triage",
                source_type="alert",
                source_id=alert_obj.id,
                input_data={"alert_id": alert_obj.id, "severity": severity, "source": source},
                ai_response=triage["reasoning"],
                structured_output=triage,
                confidence=triage["confidence"],
                model_used=triage["model_used"],
                tokens_used=0,
                latency_ms=0,
                organization_id=getattr(current_user, "organization_id", None),
            )
            db.add(analysis)

            total_confidence += triage["confidence"]
            total_fp += triage["false_positive_probability"]

            triaged_alerts.append(
                AlertTriageResponse(
                    alert_id=alert_obj.id,
                    priority=triage["priority"],
                    reasoning=triage["reasoning"],
                    confidence=triage["confidence"],
                    false_positive_probability=triage["false_positive_probability"],
                    recommended_actions=triage["recommended_actions"],
                    model_used=triage["model_used"],
                )
            )

        await db.flush()

        count = max(1, len(triaged_alerts))
        return BatchTriageResponse(
            alerts_triaged=len(triaged_alerts),
            average_confidence=total_confidence / count,
            average_false_positive_probability=total_fp / count,
            triaged_alerts=triaged_alerts,
            timestamp=_utc_now(),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch triage error: {e}")
        raise HTTPException(status_code=500, detail="Batch triage failed")


@router.get("/alerts/triaged", summary="List triaged alerts")
async def list_triaged_alerts(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    """
    Return AI triage analyses so the frontend can display triaged alerts.

    Queries AIAnalysis rows where analysis_type='alert_triage'.
    """
    org_id = getattr(current_user, "organization_id", None)

    query = (
        select(AIAnalysis)
        .where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.analysis_type == "alert_triage",
        )
        .order_by(AIAnalysis.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(query)
    analyses = list(result.scalars().all())

    triaged: list[dict] = []
    for a in analyses:
        output = a.structured_output or {}
        triaged.append({
            "id": a.source_id or str(a.id),
            "title": f"Alert {a.source_id or a.id}",
            "ai_priority": output.get("priority", "medium"),
            "confidence": a.confidence or 0.0,
            "reasoning": a.ai_response or "",
            "analyst_override": a.feedback_score is not None,
        })

    return triaged


@router.post("/alerts/triage", summary="Triage pending alerts (alias)")
async def triage_pending_alerts(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Convenience endpoint that triages the most recent untriaged alerts.

    Delegates to the batch triage logic with default parameters.
    """
    batch_request = BatchTriageRequest(alert_ids=[], limit=10)
    return await batch_triage_alerts(batch_request, current_user, db)


@router.get("/triage/stats", response_model=TriageStatsResponse, summary="Triage statistics")
async def triage_statistics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Get alert triage performance statistics from the database.
    """
    org_id = getattr(current_user, "organization_id", None)

    # Total triage analyses
    total_result = await db.execute(
        select(func.count(AIAnalysis.id)).where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.analysis_type == "alert_triage",
        )
    )
    total_triaged = total_result.scalar() or 0

    # Average confidence
    avg_conf_result = await db.execute(
        select(func.avg(AIAnalysis.confidence)).where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.analysis_type == "alert_triage",
        )
    )
    avg_confidence = avg_conf_result.scalar() or 0.0

    # Accuracy: ratio of positive-feedback triages
    positive_result = await db.execute(
        select(func.count(AIAnalysis.id)).where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.analysis_type == "alert_triage",
            AIAnalysis.feedback_score == 1,
        )
    )
    positive = positive_result.scalar() or 0

    feedback_total_result = await db.execute(
        select(func.count(AIAnalysis.id)).where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.analysis_type == "alert_triage",
            AIAnalysis.feedback_score.isnot(None),
        )
    )
    feedback_total = feedback_total_result.scalar() or 0
    accuracy_rate = (positive / feedback_total) if feedback_total > 0 else 0.0

    # Estimate false positive reduction and time saved from data
    fp_reduction = round(1.0 - (1.0 / max(1, total_triaged / 10)), 2) if total_triaged > 0 else 0.0
    time_saved = round(total_triaged * 0.125, 1)  # ~7.5 min saved per triage

    return TriageStatsResponse(
        total_triaged=total_triaged,
        average_confidence=round(float(avg_confidence), 4),
        accuracy_rate=round(accuracy_rate, 4),
        false_positive_reduction=fp_reduction,
        time_saved_hours=time_saved,
    )


# ---------------------------------------------------------------------------
# Incident Analysis Endpoints
# ---------------------------------------------------------------------------

@router.post("/analyze/incident/{incident_id}", response_model=IncidentAnalysisResponse, summary="Analyze incident")
async def analyze_incident(
    incident_id: str,
    request: IncidentAnalysisRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Full AI analysis of an incident.

    Loads the incident and its linked alerts, then either calls the LLM via
    AIAnalyzer.summarize_incident or derives a summary from real DB fields
    when no LLM is configured. Persists the result to AIAnalysis.
    """
    logger.info(f"Analyzing incident {incident_id}")

    ctx = await _load_incident_context(db, incident_id)
    incident = ctx["incident"]
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    timeline = _build_incident_timeline(ctx) if request.include_related else []
    related_alerts_serialized: list[dict[str, Any]] = (
        [_serialize_alert(a) for a in ctx["alerts"]] if request.include_related else []
    )

    derivation = "rule_based"
    model_used = "heuristic-v1"
    result_data: dict[str, Any]

    if _llm_available():
        try:
            analyzer = AIAnalyzer()
            llm_out = await asyncio.to_thread(
                analyzer.summarize_incident,
                _serialize_incident(incident),
                related_alerts_serialized,
                timeline,
            )
            # Merge LLM output with our DB-derived impact when LLM omits fields.
            heuristic = _heuristic_incident_analysis(ctx)
            impact = llm_out.get("impact_assessment") or {}
            result_data = {
                "executive_summary": llm_out.get("executive_summary")
                or heuristic["executive_summary"],
                "technical_details": llm_out.get("technical_details")
                or heuristic["technical_details"],
                "impact_assessment": {
                    "affected_systems": impact.get("affected_systems")
                    or heuristic["impact_assessment"]["affected_systems"],
                    "data_exposed": impact.get("data_exposed")
                    or heuristic["impact_assessment"]["data_exposed"],
                    "users_affected": int(
                        impact.get("users_affected")
                        or heuristic["impact_assessment"]["users_affected"]
                    ),
                    "severity": impact.get("severity")
                    or heuristic["impact_assessment"]["severity"],
                },
                "recommendations": llm_out.get("recommendations")
                or heuristic["recommendations"],
                "confidence": 0.85,
                "derivation": "llm",
            }
            derivation = "llm"
            model_used = "gemini-2.5-flash"
        except HTTPException:
            raise
        except Exception as e:  # network/parse — fall back, surface in derivation
            logger.warning(
                f"LLM incident analysis failed for {incident_id}: {e}; "
                f"falling back to rule-based derivation"
            )
            result_data = _heuristic_incident_analysis(ctx)
    else:
        logger.warning(
            f"LLM not configured (GEMINI_API_KEY unset); using rule-based "
            f"incident analysis for {incident_id}"
        )
        result_data = _heuristic_incident_analysis(ctx)

    # Persist analysis with REAL content
    analysis = AIAnalysis(
        analysis_type="incident_summary",
        source_type="incident",
        source_id=incident_id,
        input_data={
            "incident_id": incident_id,
            "include_related": request.include_related,
            "alert_count": len(ctx["alerts"]),
        },
        ai_response=result_data["executive_summary"],
        structured_output=result_data,
        confidence=result_data["confidence"],
        model_used=model_used,
        tokens_used=0,
        latency_ms=0,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(analysis)
    await db.flush()
    await db.refresh(analysis)

    impact = result_data["impact_assessment"]

    return IncidentAnalysisResponse(
        incident_id=incident_id,
        executive_summary=result_data["executive_summary"],
        technical_details=result_data["technical_details"],
        impact_assessment=ImpactAssessment(
            affected_systems=impact["affected_systems"],
            data_exposed=impact["data_exposed"],
            users_affected=impact["users_affected"],
            severity=impact["severity"],
        ),
        recommendations=result_data["recommendations"],
        analysis_complete=True,
    )


@router.post("/analyze/root-cause/{incident_id}", response_model=RootCauseAnalysis, summary="Root cause analysis")
async def analyze_root_cause(
    incident_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Determine root cause of incident using real linked-alert evidence.

    Routes through AIAnalyzer.analyze_root_cause when an LLM is configured;
    otherwise derives a chain from the alerts attached to the incident and
    computes dwell time as (incident.created_at - earliest_alert.created_at).
    """
    logger.info(f"Analyzing root cause for incident {incident_id}")

    ctx = await _load_incident_context(db, incident_id)
    incident = ctx["incident"]
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    timeline = _build_incident_timeline(ctx)
    log_evidence: list[str] = []
    for a in ctx["alerts"][:10]:
        log_evidence.append(
            f"{a.created_at.isoformat() if a.created_at else 'unknown'} "
            f"[{a.severity}] {a.source}: {a.title}"
        )

    derivation = "rule_based"
    model_used = "heuristic-v1"
    rca: dict[str, Any]

    if _llm_available():
        try:
            analyzer = AIAnalyzer()
            llm_out = await asyncio.to_thread(
                analyzer.analyze_root_cause,
                _serialize_incident(incident),
                log_evidence,
                timeline,
            )
            heuristic = _heuristic_root_cause(ctx)
            # Always trust REAL dwell time computed from DB over LLM guess.
            real_dwell = heuristic["dwell_time_days"]
            rca = {
                "root_cause": llm_out.get("root_cause") or heuristic["root_cause"],
                "attack_chain": llm_out.get("attack_chain") or heuristic["attack_chain"],
                "entry_point": llm_out.get("entry_point") or heuristic["entry_point"],
                "dwell_time_days": int(real_dwell),
                "confidence": float(llm_out.get("confidence") or heuristic["confidence"]),
                "derivation": "llm",
            }
            derivation = "llm"
            model_used = "gemini-2.5-flash"
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(
                f"LLM root cause analysis failed for {incident_id}: {e}; "
                f"falling back to rule-based derivation"
            )
            rca = _heuristic_root_cause(ctx)
    else:
        logger.warning(
            f"LLM not configured (GEMINI_API_KEY unset); deriving root cause for "
            f"{incident_id} from linked alerts"
        )
        rca = _heuristic_root_cause(ctx)

    analysis = AIAnalysis(
        analysis_type="root_cause",
        source_type="incident",
        source_id=incident_id,
        input_data={
            "incident_id": incident_id,
            "alert_count": len(ctx["alerts"]),
        },
        ai_response=rca["root_cause"],
        structured_output=rca,
        confidence=rca["confidence"],
        model_used=model_used,
        tokens_used=0,
        latency_ms=0,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(analysis)
    await db.flush()
    await db.refresh(analysis)

    return RootCauseAnalysis(
        incident_id=incident_id,
        root_cause=rca["root_cause"],
        attack_chain=rca["attack_chain"],
        entry_point=rca["entry_point"],
        dwell_time_days=rca["dwell_time_days"],
        confidence=rca["confidence"],
        evidence=log_evidence,
    )


@router.post("/recommend/response/{incident_id}", response_model=ResponseRecommendation, summary="Response recommendations")
async def recommend_response(
    incident_id: str,
    request: ResponseRecommendationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Get incident response recommendations.

    Loads the incident + linked alerts so suggestions reference real
    affected systems and users. Uses AIAnalyzer.recommend_response when
    an LLM is configured; otherwise derives action lists from real DB
    fields (no canned text).
    """
    logger.info(f"Generating response recommendations for incident {incident_id}")

    ctx = await _load_incident_context(db, incident_id)
    incident = ctx["incident"]
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    derivation = "rule_based"
    model_used = "heuristic-v1"
    rec: dict[str, Any]

    if _llm_available():
        try:
            analyzer = AIAnalyzer()
            llm_context = {
                "incident": _serialize_incident(incident),
                "affected_systems": ctx["affected_systems"],
                "affected_users": ctx["affected_users"],
                "alert_count": len(ctx["alerts"]),
                "mitre_techniques": ctx["mitre_techniques"],
            }
            llm_out = await asyncio.to_thread(
                analyzer.recommend_response,
                request.incident_type or incident.incident_type,
                request.severity or incident.severity,
                llm_context,
            )
            heuristic = _heuristic_response_recommendations(
                ctx, request.incident_type, request.severity
            )
            rec = {
                "immediate_actions": llm_out.get("immediate_actions") or heuristic["immediate_actions"],
                "containment_steps": llm_out.get("containment_steps") or heuristic["containment_steps"],
                "investigation_steps": llm_out.get("investigation_steps") or heuristic["investigation_steps"],
                "recovery_plan": llm_out.get("recovery_plan") or heuristic["recovery_plan"],
                "timeline_estimate_hours": int(
                    llm_out.get("timeline_estimate_hours") or heuristic["timeline_estimate_hours"]
                ),
                "derivation": "llm",
            }
            derivation = "llm"
            model_used = "gemini-2.5-flash"
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(
                f"LLM response recommendation failed for {incident_id}: {e}; "
                f"falling back to rule-based derivation"
            )
            rec = _heuristic_response_recommendations(
                ctx, request.incident_type, request.severity
            )
    else:
        logger.warning(
            f"LLM not configured (GEMINI_API_KEY unset); deriving response "
            f"recommendations for {incident_id} from incident DB fields"
        )
        rec = _heuristic_response_recommendations(
            ctx, request.incident_type, request.severity
        )

    confidence = 0.85 if derivation == "llm" else 0.6
    analysis = AIAnalysis(
        analysis_type="response_recommendation",
        source_type="incident",
        source_id=incident_id,
        input_data={
            "incident_id": incident_id,
            "incident_type": request.incident_type,
            "severity": request.severity,
            "affected_systems": ctx["affected_systems"],
            "affected_users": ctx["affected_users"],
        },
        ai_response="; ".join(rec["immediate_actions"]),
        structured_output=rec,
        confidence=confidence,
        model_used=model_used,
        tokens_used=0,
        latency_ms=0,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(analysis)
    await db.flush()

    return ResponseRecommendation(
        immediate_actions=rec["immediate_actions"],
        containment_steps=rec["containment_steps"],
        investigation_steps=rec["investigation_steps"],
        recovery_plan=rec["recovery_plan"],
        timeline_estimate_hours=rec["timeline_estimate_hours"],
    )


@router.post("/generate/playbook", response_model=None, summary="Generate playbook")
async def generate_playbook(
    incident_pattern: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    limit: int = 5,
):
    """
    Generate incident response playbook from pattern.

    Uses AIAnalyzer.generate_playbook with real historical incident
    summaries when an LLM is configured. Otherwise, derives a step list
    from prior incidents in the DB whose type/title match the pattern,
    rather than returning an identical 5-step canned playbook.
    """
    logger.info(f"Generating playbook for pattern: {incident_pattern}")

    from src.models.incident import Incident

    org_id = getattr(current_user, "organization_id", None)
    pattern_lower = (incident_pattern or "").lower().strip()

    # Pull up to 10 prior incidents matching the pattern to ground the playbook.
    history_q = (
        select(Incident)
        .where(
            Incident.organization_id == org_id,
            (
                Incident.incident_type.ilike(f"%{pattern_lower}%")
                | Incident.title.ilike(f"%{pattern_lower}%")
                | Incident.description.ilike(f"%{pattern_lower}%")
            ),
        )
        .order_by(Incident.created_at.desc())
        .limit(10)
    )
    historical_rows = list((await db.execute(history_q)).scalars().all())
    historical_responses: list[dict[str, Any]] = []
    for inc in historical_rows:
        historical_responses.append({
            "id": inc.id,
            "title": inc.title,
            "incident_type": inc.incident_type,
            "severity": inc.severity,
            "status": inc.status,
            "resolution": (inc.resolution or "")[:400],
            "lessons_learned": (inc.lessons_learned or "")[:400],
            "recommendations": (inc.recommendations or "")[:400],
        })

    derivation = "rule_based"
    model_used = "heuristic-v1"
    confidence = 0.6
    playbook_data: dict[str, Any]

    if _llm_available():
        try:
            analyzer = AIAnalyzer()
            llm_out = await asyncio.to_thread(
                analyzer.generate_playbook, incident_pattern, historical_responses
            )
            steps_raw = llm_out.get("steps") or []
            # Normalize step shape and apply limit.
            steps: list[dict[str, Any]] = []
            for i, s in enumerate(steps_raw[:limit], start=1):
                if isinstance(s, dict):
                    steps.append({
                        "step": s.get("step", i),
                        "action": s.get("action") or s.get("description") or str(s),
                        "automated": bool(s.get("automated", False)),
                    })
                else:
                    steps.append({"step": i, "action": str(s), "automated": False})
            playbook_data = {
                "playbook_name": llm_out.get("playbook_name")
                or f"Response playbook for {incident_pattern}",
                "steps": steps,
                "conditions": llm_out.get("conditions")
                or [f"Trigger on {incident_pattern} pattern detection"],
                "automations": llm_out.get("automations") or [],
                "historical_basis": [h["id"] for h in historical_responses],
                "derivation": "llm",
            }
            derivation = "llm"
            model_used = "gemini-2.5-flash"
            confidence = 0.8
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(
                f"LLM playbook generation failed for pattern '{incident_pattern}': {e}; "
                f"falling back to history-derived playbook"
            )
            playbook_data = _derive_playbook_from_history(
                incident_pattern, historical_responses, limit
            )
    else:
        logger.warning(
            f"LLM not configured (GEMINI_API_KEY unset); deriving playbook for "
            f"'{incident_pattern}' from {len(historical_responses)} historical incidents"
        )
        playbook_data = _derive_playbook_from_history(
            incident_pattern, historical_responses, limit
        )

    analysis = AIAnalysis(
        analysis_type="playbook_generation",
        source_type="incident",
        source_id=None,
        input_data={
            "incident_pattern": incident_pattern,
            "limit": limit,
            "historical_count": len(historical_responses),
        },
        ai_response=playbook_data["playbook_name"],
        structured_output=playbook_data,
        confidence=confidence,
        model_used=model_used,
        tokens_used=0,
        latency_ms=0,
        organization_id=org_id,
    )
    db.add(analysis)
    await db.flush()

    return playbook_data


def _derive_playbook_from_history(
    pattern: str, historical: list[dict[str, Any]], limit: int
) -> dict[str, Any]:
    """
    Build a step list derived from real historical incident resolutions.

    Each historical resolution / recommendation entry becomes a step. If we
    have no history at all, we fall back to a generic IR cycle, but the
    playbook name still references the requested pattern.
    """
    steps: list[dict[str, Any]] = []
    automations: set[str] = set()

    for inc in historical:
        for field, automated_hint in (
            ("resolution", False),
            ("recommendations", False),
            ("lessons_learned", False),
        ):
            text = (inc.get(field) or "").strip()
            if not text:
                continue
            for line in [ln.strip(" -*\t") for ln in text.splitlines() if ln.strip()]:
                if len(steps) >= limit:
                    break
                steps.append({
                    "step": len(steps) + 1,
                    "action": line[:240],
                    "automated": False,
                    "source_incident": inc.get("id"),
                })
            if "isolate" in text.lower():
                automations.add("host_isolation")
            if "block" in text.lower() and "ip" in text.lower():
                automations.add("ip_block")
            if "evidence" in text.lower() or "forensic" in text.lower():
                automations.add("evidence_collection")

    if not steps:
        # Truly nothing in history — build a phase-based fallback that still
        # explicitly says it's not history-derived.
        for i, action in enumerate(
            [
                "Identify affected systems and users from SIEM/EDR",
                "Contain by isolating affected hosts and disabling accounts",
                "Collect forensic evidence (memory, disk, logs)",
                "Eradicate the threat (remove malware, close access paths)",
                "Recover from clean backups and restore service",
            ][:limit],
            start=1,
        ):
            steps.append({"step": i, "action": action, "automated": False})

    return {
        "playbook_name": f"Response playbook for {pattern}",
        "steps": steps,
        "conditions": [f"Trigger on {pattern} pattern detection"],
        "automations": sorted(automations) if automations else [],
        "historical_basis": [h.get("id") for h in historical],
        "derivation": "rule_based",
    }


# ---------------------------------------------------------------------------
# Anomaly Detection Endpoints
# ---------------------------------------------------------------------------

@router.get("/anomalies", response_model=AnomalyListResponse, summary="List anomalies")
async def list_anomalies(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    """
    List detected anomalies with filtering and pagination.

    The ``status`` filter accepts ``active``, ``confirmed``, or ``dismissed``.
    These map to the ``is_confirmed`` / ``is_false_positive`` boolean columns.
    """
    logger.info(f"Listing anomalies (skip={skip}, limit={limit}, status={status})")

    query = select(AnomalyDetection).where(
        AnomalyDetection.organization_id == getattr(current_user, "organization_id", None)
    )

    if entity_type:
        query = query.where(AnomalyDetection.entity_type == entity_type)
    if entity_id:
        query = query.where(AnomalyDetection.entity_id == entity_id)
    if severity:
        query = query.where(AnomalyDetection.severity == severity)

    # Virtual status filter mapped to boolean columns
    if status == "confirmed":
        query = query.where(AnomalyDetection.is_confirmed == True)
    elif status == "dismissed":
        query = query.where(AnomalyDetection.is_false_positive == True)
    elif status == "active":
        query = query.where(
            (AnomalyDetection.is_confirmed.is_(None) | (AnomalyDetection.is_confirmed == False)),
            AnomalyDetection.is_false_positive == False,
        )

    # Total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Fetch page
    query = query.order_by(AnomalyDetection.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    anomalies = list(result.scalars().all())

    return AnomalyListResponse(
        total=total,
        skip=skip,
        limit=limit,
        anomalies=[
            AnomalyDetectionResponse(
                id=a.id,
                entity_type=a.entity_type,
                entity_id=a.entity_id,
                anomaly_type=a.anomaly_type,
                anomaly_score=a.anomaly_score,
                confidence=a.confidence,
                severity=a.severity,
                description=a.description,
                features=a.features,
                baseline=a.baseline,
                deviation=a.deviation,
                is_confirmed=a.is_confirmed,
                is_false_positive=a.is_false_positive,
                related_alerts=a.related_alerts,
                mitre_techniques=a.mitre_techniques,
                created_at=a.created_at,
            )
            for a in anomalies
        ],
    )


@router.get("/anomalies/stats", response_model=AnomalyStatsResponse, summary="Anomaly statistics")
async def anomaly_statistics(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get anomaly detection statistics from the database."""
    org_id = getattr(current_user, "organization_id", None)

    # Total detected
    total_result = await db.execute(
        select(func.count(AnomalyDetection.id)).where(
            AnomalyDetection.organization_id == org_id
        )
    )
    total_detected = total_result.scalar() or 0

    # By severity
    sev_result = await db.execute(
        select(AnomalyDetection.severity, func.count(AnomalyDetection.id))
        .where(AnomalyDetection.organization_id == org_id)
        .group_by(AnomalyDetection.severity)
    )
    by_severity = dict(sev_result.all())

    # By type
    type_result = await db.execute(
        select(AnomalyDetection.anomaly_type, func.count(AnomalyDetection.id))
        .where(AnomalyDetection.organization_id == org_id)
        .group_by(AnomalyDetection.anomaly_type)
    )
    by_type = dict(type_result.all())

    # By entity
    entity_result = await db.execute(
        select(AnomalyDetection.entity_type, func.count(AnomalyDetection.id))
        .where(AnomalyDetection.organization_id == org_id)
        .group_by(AnomalyDetection.entity_type)
    )
    by_entity = dict(entity_result.all())

    # Confirmed rate
    confirmed_result = await db.execute(
        select(func.count(AnomalyDetection.id)).where(
            AnomalyDetection.organization_id == org_id,
            AnomalyDetection.is_confirmed == True,
        )
    )
    confirmed = confirmed_result.scalar() or 0
    confirmed_rate = (confirmed / total_detected) if total_detected > 0 else 0.0

    # False positive rate
    fp_result = await db.execute(
        select(func.count(AnomalyDetection.id)).where(
            AnomalyDetection.organization_id == org_id,
            AnomalyDetection.is_false_positive == True,
        )
    )
    fp_count = fp_result.scalar() or 0
    fp_rate = (fp_count / total_detected) if total_detected > 0 else 0.0

    return AnomalyStatsResponse(
        total_detected=total_detected,
        by_severity=by_severity,
        by_type=by_type,
        by_entity=by_entity,
        confirmed_rate=round(confirmed_rate, 4),
        false_positive_rate=round(fp_rate, 4),
        avg_detection_latency_seconds=0.0,
    )


@router.get("/anomalies/{anomaly_id}", response_model=AnomalyDetectionResponse, summary="Get anomaly")
async def get_anomaly(
    anomaly_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get detailed anomaly information."""
    logger.info(f"Fetching anomaly {anomaly_id}")

    result = await db.execute(
        select(AnomalyDetection).where(
            AnomalyDetection.id == anomaly_id,
            AnomalyDetection.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anomaly not found",
        )

    return AnomalyDetectionResponse(
        id=anomaly.id,
        entity_type=anomaly.entity_type,
        entity_id=anomaly.entity_id,
        anomaly_type=anomaly.anomaly_type,
        anomaly_score=anomaly.anomaly_score,
        confidence=anomaly.confidence,
        severity=anomaly.severity,
        description=anomaly.description,
        features=anomaly.features,
        baseline=anomaly.baseline,
        deviation=anomaly.deviation,
        is_confirmed=anomaly.is_confirmed,
        is_false_positive=anomaly.is_false_positive,
        related_alerts=anomaly.related_alerts,
        mitre_techniques=anomaly.mitre_techniques,
        created_at=anomaly.created_at,
    )


@router.post("/anomalies/{anomaly_id}/feedback", summary="Provide anomaly feedback")
async def submit_anomaly_feedback(
    anomaly_id: str,
    feedback: AnomalyFeedback,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Submit analyst feedback on anomaly.

    Used to confirm/reject anomalies and improve model accuracy.
    """
    logger.info(f"Recording feedback for anomaly {anomaly_id}")

    result = await db.execute(
        select(AnomalyDetection).where(
            AnomalyDetection.id == anomaly_id,
            AnomalyDetection.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anomaly not found",
        )

    if feedback.is_confirmed is not None:
        anomaly.is_confirmed = feedback.is_confirmed
    if feedback.is_false_positive is not None:
        anomaly.is_false_positive = feedback.is_false_positive

    await db.flush()

    return {"status": "success", "message": "Feedback recorded", "anomaly_id": anomaly_id}


# ---------------------------------------------------------------------------
# Threat Prediction Endpoints
# ---------------------------------------------------------------------------

@router.get("/predictions", response_model=list[ThreatPredictionResponse], summary="List predictions")
async def list_threat_predictions(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    entity_type: str | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    """List active threat predictions."""
    logger.info("Listing threat predictions")

    query = select(ThreatPrediction).where(
        ThreatPrediction.organization_id == getattr(current_user, "organization_id", None),
        ThreatPrediction.expires_at > _utc_now(),
    )

    if entity_type:
        query = query.where(ThreatPrediction.entity_type == entity_type)

    query = query.order_by(ThreatPrediction.risk_score.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    predictions = list(result.scalars().all())

    return [
        ThreatPredictionResponse(
            id=p.id,
            entity_type=p.entity_type,
            entity_id=p.entity_id,
            prediction_type=p.prediction_type,
            risk_score=p.risk_score,
            probability=p.probability,
            time_horizon_hours=p.time_horizon_hours,
            contributing_factors=p.contributing_factors,
            recommended_actions=p.recommended_actions,
            mitre_techniques=p.mitre_techniques,
            expires_at=p.expires_at,
            was_accurate=p.was_accurate,
            created_at=p.created_at,
        )
        for p in predictions
    ]


@router.post("/predictions/entity/{entity_id}", response_model=ThreatPredictionResponse, summary="Predict entity threat")
async def predict_entity_threat(
    entity_id: str,
    request: ThreatPredictionRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Predict threat probability for entity using REAL UEBA/anomaly signals.

    Score is a weighted blend of:
      - UEBA EntityProfile.risk_score (when available)
      - EntityProfile.anomaly_count_30d
      - Recent AnomalyDetection rows for this entity
      - Recent UEBARiskAlert rows
      - Asset criticality (for host entities)
      - Peer-group deviation (when present in baseline_data)

    No hash-of-id fakery.
    """
    logger.info(f"Generating threat prediction for {request.entity_type}/{entity_id}")

    org_id = getattr(current_user, "organization_id", None)
    signals = await _load_entity_risk_signals(db, request.entity_type, entity_id, org_id)
    pred = _compute_threat_prediction_from_signals(request.entity_type, entity_id, signals)

    if pred["contributing_factors"] == ["no_risk_signals_available"]:
        logger.warning(
            f"No risk signals found for {request.entity_type}/{entity_id}; "
            f"returning 0 risk score with derivation=rule_based"
        )

    # Don't persist raw_signals into the DB row (not part of schema).
    raw_signals = pred.pop("raw_signals", {})

    prediction = ThreatPrediction(
        prediction_type=pred["prediction_type"],
        entity_type=request.entity_type,
        entity_id=entity_id,
        risk_score=pred["risk_score"],
        probability=pred["probability"],
        time_horizon_hours=request.time_horizon_hours,
        contributing_factors=pred["contributing_factors"],
        recommended_actions=pred["recommended_actions"],
        mitre_techniques=[],
        model_id=None,
        expires_at=_utc_now() + timedelta(hours=request.time_horizon_hours),
        was_accurate=None,
        organization_id=org_id,
    )
    db.add(prediction)
    await db.flush()
    await db.refresh(prediction)

    # Also persist the derivation breakdown as an AIAnalysis for traceability.
    db.add(AIAnalysis(
        analysis_type="threat_assessment",
        source_type="query",
        source_id=prediction.id,
        input_data={
            "entity_type": request.entity_type,
            "entity_id": entity_id,
            "time_horizon_hours": request.time_horizon_hours,
            "raw_signals": raw_signals,
        },
        ai_response=(
            f"{request.entity_type}/{entity_id} risk score {pred['risk_score']} "
            f"derived from {len(pred['contributing_factors'])} signals"
        ),
        structured_output={**pred, "raw_signals": raw_signals},
        confidence=0.7 if signals.get("ueba_risk_score") is not None else 0.4,
        model_used="rule_based-v1",
        tokens_used=0,
        latency_ms=0,
        organization_id=org_id,
    ))
    await db.flush()

    return ThreatPredictionResponse(
        id=prediction.id,
        entity_type=prediction.entity_type,
        entity_id=prediction.entity_id,
        prediction_type=prediction.prediction_type,
        risk_score=prediction.risk_score,
        probability=prediction.probability,
        time_horizon_hours=prediction.time_horizon_hours,
        contributing_factors=prediction.contributing_factors,
        recommended_actions=prediction.recommended_actions,
        mitre_techniques=prediction.mitre_techniques,
        expires_at=prediction.expires_at,
        was_accurate=prediction.was_accurate,
        created_at=prediction.created_at,
    )


@router.get("/predictions/dashboard", response_model=PredictionDashboard, summary="Prediction dashboard")
async def prediction_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get threat prediction dashboard data from the database."""
    org_id = getattr(current_user, "organization_id", None)
    now = _utc_now()

    # Active predictions (not expired)
    active_result = await db.execute(
        select(func.count(ThreatPrediction.id)).where(
            ThreatPrediction.organization_id == org_id,
            ThreatPrediction.expires_at > now,
        )
    )
    active_predictions = active_result.scalar() or 0

    # Critical risk entities (risk_score > 80)
    critical_result = await db.execute(
        select(func.count(func.distinct(ThreatPrediction.entity_id))).where(
            ThreatPrediction.organization_id == org_id,
            ThreatPrediction.expires_at > now,
            ThreatPrediction.risk_score > 80,
        )
    )
    critical_risk_entities = critical_result.scalar() or 0

    # Average risk score
    avg_risk_result = await db.execute(
        select(func.avg(ThreatPrediction.risk_score)).where(
            ThreatPrediction.organization_id == org_id,
            ThreatPrediction.expires_at > now,
        )
    )
    avg_risk_score = avg_risk_result.scalar() or 0.0

    # Predictions by type
    by_type_result = await db.execute(
        select(ThreatPrediction.prediction_type, func.count(ThreatPrediction.id))
        .where(
            ThreatPrediction.organization_id == org_id,
            ThreatPrediction.expires_at > now,
        )
        .group_by(ThreatPrediction.prediction_type)
    )
    predictions_by_type = dict(by_type_result.all())

    # Top at-risk entities
    top_entities_result = await db.execute(
        select(ThreatPrediction.entity_id, func.max(ThreatPrediction.risk_score).label("risk_score"))
        .where(
            ThreatPrediction.organization_id == org_id,
            ThreatPrediction.expires_at > now,
        )
        .group_by(ThreatPrediction.entity_id)
        .order_by(func.max(ThreatPrediction.risk_score).desc())
        .limit(10)
    )
    top_entities = [
        {"entity_id": row[0], "risk_score": row[1]}
        for row in top_entities_result.all()
    ]

    # Trending threats from contributing factors
    trending: list[str] = []
    if predictions_by_type:
        trending = list(predictions_by_type.keys())[:5]

    return PredictionDashboard(
        active_predictions=active_predictions,
        critical_risk_entities=critical_risk_entities,
        avg_risk_score=round(float(avg_risk_score), 1),
        predictions_by_type=predictions_by_type,
        trending_threats=trending,
        top_at_risk_entities=top_entities,
    )


# ---------------------------------------------------------------------------
# ML Model Endpoints
# ---------------------------------------------------------------------------

@router.get("/models", response_model=list[MLModelResponse], summary="List ML models")
async def list_models(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """List all ML models."""
    logger.info("Listing ML models")

    result = await db.execute(
        select(MLModel)
        .where(MLModel.organization_id == getattr(current_user, "organization_id", None))
        .order_by(MLModel.created_at.desc())
    )
    models = list(result.scalars().all())

    return [
        MLModelResponse(
            id=m.id,
            name=m.name,
            model_type=m.model_type,
            algorithm=m.algorithm,
            version=m.version,
            status=m.status,
            description=m.description,
            feature_columns=m.feature_columns,
            hyperparameters=m.hyperparameters,
            training_metrics=m.training_metrics,
            training_data_size=m.training_data_size,
            last_trained_at=m.last_trained_at,
            last_prediction_at=m.last_prediction_at,
            prediction_count=m.prediction_count,
            drift_score=m.drift_score,
            tags=m.tags,
            created_at=m.created_at,
        )
        for m in models
    ]


@router.post("/models/train", response_model=None, summary="Train ML model")
async def train_model(
    request: ModelTrainingRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Register or train an ML model.

    Behavior:
      - If ``trigger_retraining`` is True: a real training backend is required.
        We currently have no async training pipeline that can ingest a
        labelled dataset from this endpoint, so we return 503 rather than
        fabricating metrics like {accuracy: 0.90}.
      - Otherwise: register the model record with status=``pending_data`` and
        an empty metrics dict so the frontend can list it without showing
        invented performance numbers. Real metrics are populated only after
        an actual training job runs (e.g. via ``AnomalyDetector.train_model``
        in src/ai/engine.py, called from a background task with real data).
    """
    logger.info(
        f"Train-model request: type={request.model_type} algo={request.algorithm} "
        f"trigger_retraining={request.trigger_retraining}"
    )

    if request.trigger_retraining:
        # No training data was supplied by the request schema and there is
        # no in-process training service that pulls labelled data on demand.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "training backend not configured: no labelled dataset is available "
                "via this endpoint and no async training service is wired up. "
                "Register the model without trigger_retraining and run training "
                "out-of-band (e.g. via src/ai/engine.py AnomalyDetector.train_model)."
            ),
        )

    version = request.version or "1.0.0"
    name = f"{request.model_type}_{request.algorithm}_{version}"

    model = MLModel(
        name=name,
        model_type=request.model_type,
        algorithm=request.algorithm,
        version=version,
        status="pending_data",
        description=request.description,
        feature_columns=[],
        hyperparameters=request.hyperparameters or {},
        # Empty metrics — DO NOT insert fake numbers. Real metrics get
        # written once an actual training job finishes.
        training_metrics={},
        training_data_size=0,
        last_trained_at=None,
        prediction_count=0,
        drift_score=0.0,
        tags=request.tags or [],
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(model)
    await db.flush()
    await db.refresh(model)

    return {
        "status": "registered",
        "model_id": model.id,
        "model_type": model.model_type,
        "algorithm": model.algorithm,
        "metrics": model.training_metrics,
        "training_data_size": model.training_data_size,
        "note": (
            "Model registered without training. Run "
            "src/ai/engine.py AnomalyDetector.train_model with real data to "
            "populate training_metrics and set status=ready."
        ),
    }


@router.get("/models/{model_id}", response_model=MLModelResponse, summary="Get model details")
async def get_model(
    model_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get ML model details and metrics."""
    logger.info(f"Fetching model {model_id}")

    result = await db.execute(
        select(MLModel).where(
            MLModel.id == model_id,
            MLModel.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model not found",
        )

    return MLModelResponse(
        id=model.id,
        name=model.name,
        model_type=model.model_type,
        algorithm=model.algorithm,
        version=model.version,
        status=model.status,
        description=model.description,
        feature_columns=model.feature_columns,
        hyperparameters=model.hyperparameters,
        training_metrics=model.training_metrics,
        training_data_size=model.training_data_size,
        last_trained_at=model.last_trained_at,
        last_prediction_at=model.last_prediction_at,
        prediction_count=model.prediction_count,
        drift_score=model.drift_score,
        tags=model.tags,
        created_at=model.created_at,
    )


@router.get("/models/{model_id}/drift", response_model=ModelDriftResponse, summary="Check model drift")
async def check_model_drift(
    model_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Check for model drift in deployed model."""
    logger.info(f"Checking drift for model {model_id}")

    result = await db.execute(
        select(MLModel).where(
            MLModel.id == model_id,
            MLModel.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model not found",
        )

    drift_score = model.drift_score
    if drift_score < 0.15:
        drift_status = "ok"
        recommendation = None
    elif drift_score < 0.25:
        drift_status = "warning"
        recommendation = "Monitor closely and consider retraining"
    else:
        drift_status = "critical"
        recommendation = "Immediate retraining recommended"

    return ModelDriftResponse(
        model_id=model.id,
        drift_score=drift_score,
        status=drift_status,
        last_checked_at=_utc_now(),
        recommendation=recommendation,
    )


@router.delete("/models/{model_id}", summary="Retire model")
async def retire_model(
    model_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Retire ML model from service."""
    logger.info(f"Retiring model {model_id}")

    result = await db.execute(
        select(MLModel).where(
            MLModel.id == model_id,
            MLModel.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model not found",
        )

    model.status = "retired"
    await db.flush()

    return {"status": "success", "message": f"Model {model_id} retired"}


# ---------------------------------------------------------------------------
# AI Feedback Endpoint
# ---------------------------------------------------------------------------

@router.post("/feedback", summary="Submit AI feedback")
async def submit_ai_feedback(
    feedback: AIFeedbackRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Submit feedback on AI analysis results.

    Updates the corresponding AIAnalysis record with the feedback score and notes.
    """
    logger.info(f"Recording feedback for analysis {feedback.analysis_id}")

    result = await db.execute(
        select(AIAnalysis).where(
            AIAnalysis.id == feedback.analysis_id,
            AIAnalysis.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )

    analysis.feedback_score = feedback.feedback_score
    if feedback.feedback_notes:
        analysis.feedback_notes = feedback.feedback_notes

    await db.flush()

    return {"status": "success", "message": "Feedback recorded", "analysis_id": analysis.id}


# ---------------------------------------------------------------------------
# Dashboard Endpoint
# ---------------------------------------------------------------------------

@router.get("/dashboard", response_model=AIDashboardResponse, summary="AI engine dashboard")
async def ai_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """
    Get AI engine dashboard statistics aggregated from the database.
    """
    logger.info("Fetching AI dashboard")

    org_id = getattr(current_user, "organization_id", None)
    now = _utc_now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # --- Analyses ---
    total_analyses_result = await db.execute(
        select(func.count(AIAnalysis.id)).where(AIAnalysis.organization_id == org_id)
    )
    total_analyses = total_analyses_result.scalar() or 0

    analyses_today_result = await db.execute(
        select(func.count(AIAnalysis.id)).where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.created_at >= today_start,
        )
    )
    analyses_today = analyses_today_result.scalar() or 0

    avg_conf_result = await db.execute(
        select(func.avg(AIAnalysis.confidence)).where(AIAnalysis.organization_id == org_id)
    )
    average_confidence = avg_conf_result.scalar() or 0.0

    # Accuracy from feedback
    positive_result = await db.execute(
        select(func.count(AIAnalysis.id)).where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.feedback_score == 1,
        )
    )
    positive = positive_result.scalar() or 0

    feedback_total_result = await db.execute(
        select(func.count(AIAnalysis.id)).where(
            AIAnalysis.organization_id == org_id,
            AIAnalysis.feedback_score.isnot(None),
        )
    )
    feedback_total = feedback_total_result.scalar() or 0
    accuracy_rate = (positive / feedback_total) if feedback_total > 0 else 0.0

    # --- Anomalies ---
    total_anomalies_result = await db.execute(
        select(func.count(AnomalyDetection.id)).where(
            AnomalyDetection.organization_id == org_id
        )
    )
    total_anomalies = total_anomalies_result.scalar() or 0

    confirmed_result = await db.execute(
        select(func.count(AnomalyDetection.id)).where(
            AnomalyDetection.organization_id == org_id,
            AnomalyDetection.is_confirmed == True,
        )
    )
    confirmed = confirmed_result.scalar() or 0
    anomalies_confirmed_rate = (confirmed / total_anomalies) if total_anomalies > 0 else 0.0

    fp_result = await db.execute(
        select(func.count(AnomalyDetection.id)).where(
            AnomalyDetection.organization_id == org_id,
            AnomalyDetection.is_false_positive == True,
        )
    )
    fp_count = fp_result.scalar() or 0
    false_positive_rate = (fp_count / total_anomalies) if total_anomalies > 0 else 0.0

    # --- Models ---
    models_deployed_result = await db.execute(
        select(func.count(MLModel.id)).where(
            MLModel.organization_id == org_id,
            MLModel.status == "deployed",
        )
    )
    models_deployed = models_deployed_result.scalar() or 0

    models_training_result = await db.execute(
        select(func.count(MLModel.id)).where(
            MLModel.organization_id == org_id,
            MLModel.status == "training",
        )
    )
    models_in_training = models_training_result.scalar() or 0

    avg_drift_result = await db.execute(
        select(func.avg(MLModel.drift_score)).where(
            MLModel.organization_id == org_id,
            MLModel.status.in_(["deployed", "ready"]),
        )
    )
    avg_model_drift = avg_drift_result.scalar() or 0.0

    models_retrain_result = await db.execute(
        select(func.count(MLModel.id)).where(
            MLModel.organization_id == org_id,
            MLModel.drift_score > 0.25,
            MLModel.status.in_(["deployed", "ready"]),
        )
    )
    models_needing_retrain = models_retrain_result.scalar() or 0

    # --- Predictions ---
    active_pred_result = await db.execute(
        select(func.count(ThreatPrediction.id)).where(
            ThreatPrediction.organization_id == org_id,
            ThreatPrediction.expires_at > now,
        )
    )
    active_threat_predictions = active_pred_result.scalar() or 0

    critical_ent_result = await db.execute(
        select(func.count(func.distinct(ThreatPrediction.entity_id))).where(
            ThreatPrediction.organization_id == org_id,
            ThreatPrediction.expires_at > now,
            ThreatPrediction.risk_score > 80,
        )
    )
    critical_risk_entities = critical_ent_result.scalar() or 0

    # --- Queries ---
    queries_total_result = await db.execute(
        select(func.count(NLQuery.id)).where(NLQuery.organization_id == org_id)
    )
    queries_processed = queries_total_result.scalar() or 0

    queries_today_result = await db.execute(
        select(func.count(NLQuery.id)).where(
            NLQuery.organization_id == org_id,
            NLQuery.created_at >= today_start,
        )
    )
    queries_today = queries_today_result.scalar() or 0

    helpful_result = await db.execute(
        select(func.count(NLQuery.id)).where(
            NLQuery.organization_id == org_id,
            NLQuery.was_helpful == True,
        )
    )
    helpful = helpful_result.scalar() or 0

    rated_result = await db.execute(
        select(func.count(NLQuery.id)).where(
            NLQuery.organization_id == org_id,
            NLQuery.was_helpful.isnot(None),
        )
    )
    rated = rated_result.scalar() or 0
    avg_query_accuracy = (helpful / rated) if rated > 0 else 0.0

    return AIDashboardResponse(
        total_analyses=total_analyses,
        analyses_today=analyses_today,
        average_confidence=round(float(average_confidence), 4),
        accuracy_rate=round(accuracy_rate, 4),
        total_anomalies_detected=total_anomalies,
        anomalies_confirmed_rate=round(anomalies_confirmed_rate, 4),
        false_positive_rate=round(false_positive_rate, 4),
        models_deployed=models_deployed,
        models_in_training=models_in_training,
        avg_model_drift=round(float(avg_model_drift), 4),
        models_needing_retrain=models_needing_retrain,
        active_threat_predictions=active_threat_predictions,
        critical_risk_entities=critical_risk_entities,
        queries_processed=queries_processed,
        queries_today=queries_today,
        avg_query_accuracy=round(avg_query_accuracy, 4),
        last_updated=now,
    )
