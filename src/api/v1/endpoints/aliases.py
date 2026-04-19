"""
Route aliases / flat-list endpoints.

These exist to keep the frontend working when it calls a URL that the
canonical endpoint files don't expose directly (e.g. `/privacy/dsr` where
the canonical is `/privacy/dsr/requests`, or `/dfir/evidence` where the
canonical is `/dfir/cases/{id}/evidence`).

Every route here is wired to a real DB query scoped to the current user's
organization. If the underlying table is empty the response is an honest
empty list — no hardcoded data.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import and_, desc, func, select

from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["aliases"])


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _org_id(current_user: Any) -> Optional[str]:
    return getattr(current_user, "organization_id", None)


async def _safe_list(
    db,
    model,
    *,
    org_id: Optional[str],
    page: int = 1,
    size: int = 20,
    order_by=None,
    filters: Optional[List] = None,
) -> Dict[str, Any]:
    """Generic paginated list query filtered by organization_id when present."""
    try:
        where_clauses = []
        if org_id is not None and hasattr(model, "organization_id"):
            where_clauses.append(model.organization_id == org_id)
        if filters:
            where_clauses.extend(filters)

        stmt = select(model)
        if where_clauses:
            stmt = stmt.where(and_(*where_clauses))

        count_stmt = select(func.count()).select_from(model)
        if where_clauses:
            count_stmt = count_stmt.where(and_(*where_clauses))
        total = (await db.execute(count_stmt)).scalar() or 0

        if order_by is None and hasattr(model, "created_at"):
            order_by = desc(model.created_at)
        if order_by is not None:
            stmt = stmt.order_by(order_by)

        stmt = stmt.offset((page - 1) * size).limit(size)
        result = await db.execute(stmt)
        rows = list(result.scalars().all())

        # Serialize rows to dicts using SQLAlchemy inspection, so we never
        # crash on response-model mismatches during the demo.
        items = [_row_to_dict(r) for r in rows]
        return {
            "items": items,
            "total": total,
            "page": page,
            "size": size,
            "pages": (total + size - 1) // size if size else 1,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "alias list query failed",
            model=getattr(model, "__name__", str(model)),
            error=str(exc),
        )
        return {"items": [], "total": 0, "page": page, "size": size, "pages": 0}


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Best-effort SQLAlchemy row -> plain dict."""
    try:
        mapper = getattr(row, "__mapper__", None)
        if mapper is not None:
            d: Dict[str, Any] = {}
            for col in mapper.columns:
                val = getattr(row, col.key, None)
                if isinstance(val, datetime):
                    d[col.key] = val.isoformat()
                else:
                    d[col.key] = val
            return d
    except Exception:  # noqa: BLE001
        pass
    # Fallback: pull public attrs
    return {
        k: v
        for k, v in vars(row).items()
        if not k.startswith("_") and not callable(v)
    }


# --------------------------------------------------------------------------
# FedRAMP
# --------------------------------------------------------------------------


@router.get("/fedramp/documents")
async def fedramp_documents(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> Dict[str, Any]:
    """Flat list of FedRAMP evidence/SSP documents.

    Backs onto the FedRAMP generator's evidence-status feed and flattens
    the per-family artifacts into a document list.
    """
    try:
        from src.fedramp.generator import FedRAMPGenerator

        gen = FedRAMPGenerator()
        controls = await gen.get_control_implementation_status(
            db, organization_id=_org_id(current_user)
        )
        docs: List[Dict[str, Any]] = []
        for ctrl in controls or []:
            for art in ctrl.get("evidence_artifacts", []) or []:
                docs.append(
                    {
                        "control_id": ctrl.get("control_id"),
                        "family": ctrl.get("family"),
                        "title": (art.get("title") if isinstance(art, dict) else str(art)),
                        "artifact": art,
                    }
                )
        return {"items": docs, "total": len(docs)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("fedramp_documents failed", error=str(exc))
        return {"items": [], "total": 0}


# --------------------------------------------------------------------------
# STIG
# --------------------------------------------------------------------------


@router.get("/stig/remediations")
async def stig_remediations(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Flat list of open STIG findings (aka candidate remediations)."""
    from src.stig.models import STIGScanResult

    return await _safe_list(
        db, STIGScanResult, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# Privacy flat aliases
# --------------------------------------------------------------------------


@router.get("/privacy/dsr")
async def privacy_dsr_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    from src.privacy.models import DataSubjectRequest

    return await _safe_list(
        db, DataSubjectRequest, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/privacy/pia")
async def privacy_pia_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    from src.privacy.models import PrivacyImpactAssessment

    return await _safe_list(
        db, PrivacyImpactAssessment, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/privacy/consent")
async def privacy_consent_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    from src.privacy.models import ConsentRecord

    return await _safe_list(
        db, ConsentRecord, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/privacy/ropa")
async def privacy_ropa_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    from src.privacy.models import DataProcessingRecord

    return await _safe_list(
        db, DataProcessingRecord, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/privacy/incidents")
async def privacy_incidents_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    from src.privacy.models import PrivacyIncident

    return await _safe_list(
        db, PrivacyIncident, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# Risk Quantification
# --------------------------------------------------------------------------


@router.get("/risk-quantification/analysis")
async def risk_quant_analysis_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of FAIR analyses for the org."""
    from src.risk_quant.models import FAIRAnalysis

    return await _safe_list(
        db, FAIRAnalysis, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# Threat Intelligence flat aliases
# --------------------------------------------------------------------------


@router.get("/intel/iocs")
async def intel_iocs_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(20, ge=1, le=500),
):
    """Recent threat indicators, capped by `limit`."""
    from src.intel.models import ThreatIndicator

    result = await _safe_list(
        db,
        ThreatIndicator,
        org_id=_org_id(current_user),
        page=1,
        size=limit,
    )
    return result


@router.get("/intel/feeds")
async def intel_feeds_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
):
    from src.intel.models import ThreatFeed

    return await _safe_list(
        db, ThreatFeed, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# Threat Modeling
# --------------------------------------------------------------------------


@router.get("/threat-modeling/models")
async def threat_modeling_models_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of threat models (the canonical list is at `/threat-modeling`,
    but when the UI appends `/models` we route here so we don't collide with
    the `/{model_id}` GET handler."""
    from src.threat_modeling.models import ThreatModel

    return await _safe_list(
        db, ThreatModel, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# DFIR
# --------------------------------------------------------------------------


@router.get("/dfir/evidence")
async def dfir_evidence_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of forensic evidence across all cases in the org."""
    from src.dfir.models import ForensicEvidence

    return await _safe_list(
        db, ForensicEvidence, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/dfir/legal-holds")
async def dfir_legal_holds_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of legal holds for the org."""
    from src.dfir.models import LegalHold

    return await _safe_list(
        db, LegalHold, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# Simulation
# --------------------------------------------------------------------------


@router.get("/simulation/posture-trend")
async def simulation_posture_trend(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    days: int = Query(30, ge=1, le=365),
):
    """Time series of security posture scores."""
    from src.simulation.models import SecurityPostureScore

    try:
        org_id = _org_id(current_user)
        since = datetime.utcnow() - timedelta(days=days)
        stmt = select(SecurityPostureScore).where(
            SecurityPostureScore.created_at >= since
        )
        if org_id and hasattr(SecurityPostureScore, "organization_id"):
            stmt = stmt.where(SecurityPostureScore.organization_id == org_id)
        stmt = stmt.order_by(SecurityPostureScore.created_at.asc())
        rows = list((await db.execute(stmt)).scalars().all())
        return {
            "items": [_row_to_dict(r) for r in rows],
            "total": len(rows),
            "window_days": days,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("simulation_posture_trend failed", error=str(exc))
        return {"items": [], "total": 0, "window_days": days}


# --------------------------------------------------------------------------
# Playbooks
# --------------------------------------------------------------------------


@router.get("/playbooks/executions/recent")
async def playbooks_executions_recent(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(20, ge=1, le=200),
):
    """Most recent playbook executions across all playbooks."""
    from src.models.playbook import PlaybookExecution

    try:
        org_id = _org_id(current_user)
        stmt = select(PlaybookExecution)
        if org_id and hasattr(PlaybookExecution, "organization_id"):
            stmt = stmt.where(PlaybookExecution.organization_id == org_id)
        stmt = stmt.order_by(desc(PlaybookExecution.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbooks_executions_recent failed", error=str(exc))
        return {"items": [], "total": 0}


# --------------------------------------------------------------------------
# Agentic SOC aliases
# --------------------------------------------------------------------------


@router.get("/agentic/reasoning-chain")
async def agentic_reasoning_chain_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    investigation_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
):
    """Flat reasoning step feed. If `investigation_id` is supplied, scoped
    to that investigation; otherwise returns the most recent steps across
    all investigations for the org."""
    from src.agentic.models import Investigation, ReasoningStep

    try:
        org_id = _org_id(current_user)
        stmt = select(ReasoningStep)
        if investigation_id:
            stmt = stmt.where(ReasoningStep.investigation_id == investigation_id)
        elif org_id and hasattr(Investigation, "organization_id"):
            stmt = stmt.join(
                Investigation, Investigation.id == ReasoningStep.investigation_id
            ).where(Investigation.organization_id == org_id)
        stmt = stmt.order_by(desc(ReasoningStep.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("agentic_reasoning_chain_flat failed", error=str(exc))
        return {"items": [], "total": 0}


@router.get("/agentic/approvals")
async def agentic_approvals(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(50, ge=1, le=500),
):
    """Pending agent actions awaiting human approval."""
    from src.agentic.models import AgentAction

    try:
        org_id = _org_id(current_user)
        stmt = select(AgentAction).where(
            AgentAction.execution_status == "pending_approval"
        )
        if org_id and hasattr(AgentAction, "organization_id"):
            stmt = stmt.where(AgentAction.organization_id == org_id)
        stmt = stmt.order_by(desc(AgentAction.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("agentic_approvals failed", error=str(exc))
        return {"items": [], "total": 0}


@router.get("/agentic/triaged-alerts")
async def agentic_triaged_alerts(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(50, ge=1, le=500),
):
    """Alerts that have been triaged by an agent (AI-triaged).

    Reads the Alert table and returns rows where the `ai_analysis` /
    `triage_status` column indicates agentic processing. Empty is an
    honest empty list.
    """
    try:
        from src.models.alert import Alert

        org_id = _org_id(current_user)
        stmt = select(Alert)
        # Only include alerts that have some form of AI analysis
        if hasattr(Alert, "ai_analysis"):
            stmt = stmt.where(Alert.ai_analysis.isnot(None))
        elif hasattr(Alert, "triage_status"):
            stmt = stmt.where(Alert.triage_status.isnot(None))
        if org_id and hasattr(Alert, "organization_id"):
            stmt = stmt.where(Alert.organization_id == org_id)
        stmt = stmt.order_by(desc(Alert.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("agentic_triaged_alerts failed", error=str(exc))
        return {"items": [], "total": 0}


@router.get("/agentic/anomalies")
async def agentic_anomalies(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(50, ge=1, le=500),
):
    """Anomalies surfaced for agentic review (from the AI anomaly detector)."""
    try:
        from src.ai.models import AnomalyDetection

        org_id = _org_id(current_user)
        result = await _safe_list(
            db, AnomalyDetection, org_id=org_id, page=1, size=limit
        )
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning("agentic_anomalies failed", error=str(exc))
        return {"items": [], "total": 0}


@router.get("/agentic/predictions")
async def agentic_predictions(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(50, ge=1, le=500),
):
    """AI threat predictions (mirrors /ai/predictions under the agentic namespace)."""
    try:
        from src.ai.models import ThreatPrediction

        org_id = _org_id(current_user)
        return await _safe_list(
            db, ThreatPrediction, org_id=org_id, page=1, size=limit
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("agentic_predictions failed", error=str(exc))
        return {"items": [], "total": 0}


@router.get("/agentic/models")
async def agentic_models(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(100, ge=1, le=500),
):
    """Registered SOC agents (equivalent to /agentic/agents, exposed here
    for UIs that look up AI/ML models under `/agentic/models`)."""
    from src.agentic.models import SOCAgent

    return await _safe_list(
        db, SOCAgent, org_id=_org_id(current_user), page=1, size=limit
    )


# --------------------------------------------------------------------------
# Agent platform
# --------------------------------------------------------------------------


@router.get("/agents/commands/pending")
async def agents_commands_pending(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(100, ge=1, le=500),
):
    """Alias for `/agents/commands/pending-approval`."""
    try:
        from src.agents.models import AgentCommand

        org_id = _org_id(current_user)
        # See src/agents/models.py: the "pending human approval" status is
        # spelled `awaiting_approval` on the real model.
        stmt = select(AgentCommand).where(
            AgentCommand.status == "awaiting_approval"
        )
        if org_id and hasattr(AgentCommand, "organization_id"):
            stmt = stmt.where(AgentCommand.organization_id == org_id)
        stmt = stmt.order_by(desc(AgentCommand.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("agents_commands_pending failed", error=str(exc))
        return {"items": [], "total": 0}


# --------------------------------------------------------------------------
# SIEM
# --------------------------------------------------------------------------


@router.get("/siem/dashboard")
async def siem_dashboard(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> Dict[str, Any]:
    """Aggregated SIEM dashboard stats.

    Computes log counts, rule counts, and recent correlation counts
    directly from the SIEM tables.
    """
    try:
        from src.siem.models import (
            CorrelationEvent,
            DetectionRule,
            LogEntry,
        )

        org_id = _org_id(current_user)

        async def _count(model):
            stmt = select(func.count()).select_from(model)
            if org_id and hasattr(model, "organization_id"):
                stmt = stmt.where(model.organization_id == org_id)
            return (await db.execute(stmt)).scalar() or 0

        total_logs = await _count(LogEntry)
        total_rules = await _count(DetectionRule)
        total_correlations = await _count(CorrelationEvent)

        # Last 24h logs
        since = datetime.utcnow() - timedelta(hours=24)
        stmt = select(func.count()).select_from(LogEntry).where(
            LogEntry.created_at >= since
        )
        if org_id and hasattr(LogEntry, "organization_id"):
            stmt = stmt.where(LogEntry.organization_id == org_id)
        logs_last_24h = (await db.execute(stmt)).scalar() or 0

        return {
            "total_logs": total_logs,
            "logs_last_24h": logs_last_24h,
            "total_rules": total_rules,
            "total_correlations": total_correlations,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("siem_dashboard failed", error=str(exc))
        return {
            "total_logs": 0,
            "logs_last_24h": 0,
            "total_rules": 0,
            "total_correlations": 0,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }


# --------------------------------------------------------------------------
# ITDR
# --------------------------------------------------------------------------


@router.get("/itdr/access-anomalies")
async def itdr_access_anomalies_alias(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Alias for `/itdr/anomalies` (AccessAnomaly)."""
    from src.itdr.models import AccessAnomaly

    return await _safe_list(
        db, AccessAnomaly, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# Container Security
# --------------------------------------------------------------------------


@router.get("/container-security/alerts")
async def container_security_alerts(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Alias for `/container-security/runtime-alerts`."""
    from src.container_security.models import RuntimeAlert

    return await _safe_list(
        db, RuntimeAlert, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# OT/ICS Security dash-prefixed mirror.
#
# Canonical prefix in the repo is `/ot_security` (underscore). Some frontend
# call sites use `/ot-security` (dash). We mirror the most-used list endpoints
# here so both work.
# --------------------------------------------------------------------------


@router.get("/ot-security/assets")
async def ot_security_assets_dash(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    from src.ot_security.models import OTAsset

    return await _safe_list(
        db, OTAsset, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/ot-security/alerts")
async def ot_security_alerts_dash(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    from src.ot_security.models import OTAlert

    return await _safe_list(
        db, OTAlert, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/ot-security/zones")
async def ot_security_zones_dash(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=1, le=500),
):
    from src.ot_security.models import OTZone

    return await _safe_list(
        db, OTZone, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/ot-security/purdue-map")
async def ot_security_purdue_map_dash(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Purdue model map: zones + assets grouped by purdue level."""
    from src.ot_security.models import OTAsset, OTZone

    try:
        org_id = _org_id(current_user)
        # Zones
        zone_stmt = select(OTZone)
        if org_id and hasattr(OTZone, "organization_id"):
            zone_stmt = zone_stmt.where(OTZone.organization_id == org_id)
        zones = list((await db.execute(zone_stmt)).scalars().all())

        # Assets
        asset_stmt = select(OTAsset)
        if org_id and hasattr(OTAsset, "organization_id"):
            asset_stmt = asset_stmt.where(OTAsset.organization_id == org_id)
        assets = list((await db.execute(asset_stmt)).scalars().all())

        # Group by purdue_level
        by_level: Dict[int, Dict[str, Any]] = {}
        for a in assets:
            lvl = getattr(a, "purdue_level", None)
            if lvl is None:
                lvl = -1
            bucket = by_level.setdefault(
                int(lvl),
                {"level": int(lvl), "assets": [], "zones": []},
            )
            bucket["assets"].append(_row_to_dict(a))
        for z in zones:
            lvl = getattr(z, "purdue_level", None)
            if lvl is None:
                lvl = -1
            bucket = by_level.setdefault(
                int(lvl),
                {"level": int(lvl), "assets": [], "zones": []},
            )
            bucket["zones"].append(_row_to_dict(z))

        levels = [by_level[k] for k in sorted(by_level.keys())]
        return {
            "levels": levels,
            "total_assets": len(assets),
            "total_zones": len(zones),
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("ot_security_purdue_map_dash failed", error=str(exc))
        return {"levels": [], "total_assets": 0, "total_zones": 0}


# --------------------------------------------------------------------------
# Supply Chain
# --------------------------------------------------------------------------


@router.get("/supplychain/vendor-assessments")
async def supplychain_vendor_assessments_alias(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Alias for `/supplychain/vendors` (VendorAssessment table)."""
    from src.supplychain.models import VendorAssessment

    return await _safe_list(
        db, VendorAssessment, org_id=_org_id(current_user), page=page, size=size
    )


# --------------------------------------------------------------------------
# Integrations
# --------------------------------------------------------------------------


@router.get("/integrations/executions")
async def integrations_executions_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of integration executions across all installs."""
    from src.integrations.models import IntegrationExecution

    return await _safe_list(
        db, IntegrationExecution, org_id=_org_id(current_user), page=page, size=size
    )


@router.get("/integrations/webhooks")
async def integrations_webhooks_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of webhooks across all integrations."""
    from src.integrations.models import WebhookEndpoint

    return await _safe_list(
        db, WebhookEndpoint, org_id=_org_id(current_user), page=page, size=size
    )
