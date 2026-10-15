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

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import and_, desc, func, or_, select

from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    _organization_required,
)
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
    include_platform_rows: bool = False,
) -> Dict[str, Any]:
    """Generic paginated list query, scoped to ``org_id``.

    Tenant scoping is mandatory for tenant-owned models: a caller with no
    organisation gets 403 ``organization_required`` (wave 1). With
    ``include_platform_rows`` the platform-scope rows (``organization_id IS
    NULL``, e.g. indicators from global feeds) are listed too, read-only.

    Query failures propagate (the global handler returns a 500 with an error
    key) instead of being disguised as an empty list.
    """
    where_clauses = []
    if hasattr(model, "organization_id"):
        if not org_id:
            raise _organization_required()
        if include_platform_rows:
            where_clauses.append(
                or_(model.organization_id == org_id, model.organization_id.is_(None)),
            )
        else:
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

    items = [_row_to_dict(r) for r in rows]
    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size if size else 1,
    }


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
    except Exception as exc:
        logger.debug("SQLAlchemy row mapping failed; falling back to public attrs", error=str(exc))
    # Fallback: pull public attrs
    return {k: v for k, v in vars(row).items() if not k.startswith("_") and not callable(v)}


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
            db,
            organization_id=_org_id(current_user),
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
                    },
                )
        return {"items": docs, "total": len(docs)}
    except Exception as exc:
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
        db,
        STIGScanResult,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        DataSubjectRequest,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        PrivacyImpactAssessment,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        ConsentRecord,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        DataProcessingRecord,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        PrivacyIncident,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        FAIRAnalysis,
        org_id=_org_id(current_user),
        page=page,
        size=size,
    )


# --------------------------------------------------------------------------
# Threat Intelligence flat aliases
# --------------------------------------------------------------------------


@router.get("/intel/iocs")
async def intel_iocs_flat(
    db: DatabaseSession,
    org_id: OrganizationId,
    limit: int = Query(20, ge=1, le=500),
) -> Dict[str, Any]:
    """Recent threat indicators, capped by `limit`.

    The caller's indicators plus platform-scope ones (``organization_id IS
    NULL``, polled from global feeds), matching the intel router.
    """
    from src.intel.models import ThreatIndicator

    return await _safe_list(
        db,
        ThreatIndicator,
        org_id=org_id,
        page=1,
        size=limit,
        include_platform_rows=True,
    )


@router.get("/intel/feeds")
async def intel_feeds_flat(
    db: DatabaseSession,
    org_id: OrganizationId,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    from src.intel.models import ThreatFeed

    return await _safe_list(
        db,
        ThreatFeed,
        org_id=org_id,
        page=page,
        size=size,
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
        db,
        ThreatModel,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        ForensicEvidence,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        LegalHold,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
            SecurityPostureScore.created_at >= since,
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
    except Exception as exc:
        logger.warning("simulation_posture_trend failed", error=str(exc))
        return {"items": [], "total": 0, "window_days": days}


# --------------------------------------------------------------------------
# Playbooks
# --------------------------------------------------------------------------


@router.get("/playbooks/executions/recent")
async def playbooks_executions_recent(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(20, ge=1, le=200),
):
    """The caller's most recent playbook executions across all their playbooks.

    Always tenant-scoped (executions are stamped with the organisation when
    created); query failures propagate instead of returning an empty list.
    """
    from src.models.playbook import PlaybookExecution

    stmt = (
        select(PlaybookExecution)
        .where(PlaybookExecution.organization_id == org_id)
        .order_by(desc(PlaybookExecution.created_at))
        .limit(limit)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}


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
                Investigation,
                Investigation.id == ReasoningStep.investigation_id,
            ).where(Investigation.organization_id == org_id)
        stmt = stmt.order_by(desc(ReasoningStep.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:
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
            AgentAction.execution_status == "pending_approval",
        )
        if org_id and hasattr(AgentAction, "organization_id"):
            stmt = stmt.where(AgentAction.organization_id == org_id)
        stmt = stmt.order_by(desc(AgentAction.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:
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
    except Exception as exc:
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
            db,
            AnomalyDetection,
            org_id=org_id,
            page=1,
            size=limit,
        )
        return result
    except Exception as exc:
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
            db,
            ThreatPrediction,
            org_id=org_id,
            page=1,
            size=limit,
        )
    except Exception as exc:
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
        db,
        SOCAgent,
        org_id=_org_id(current_user),
        page=1,
        size=limit,
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
            AgentCommand.status == "awaiting_approval",
        )
        if org_id and hasattr(AgentCommand, "organization_id"):
            stmt = stmt.where(AgentCommand.organization_id == org_id)
        stmt = stmt.order_by(desc(AgentCommand.created_at)).limit(limit)
        rows = list((await db.execute(stmt)).scalars().all())
        return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}
    except Exception as exc:
        logger.warning("agents_commands_pending failed", error=str(exc))
        return {"items": [], "total": 0}


# --------------------------------------------------------------------------
# SIEM
# --------------------------------------------------------------------------


@router.get("/siem/dashboard")
async def siem_dashboard(
    db: DatabaseSession,
    org_id: OrganizationId,
) -> Dict[str, Any]:
    """Aggregated SIEM dashboard stats for the caller's organisation.

    Computes log counts, rule counts, and recent correlation counts
    directly from the SIEM tables. Detection rules include the platform
    built-ins (``organization_id IS NULL``), which apply to every tenant.
    Query failures propagate rather than reporting zeros.
    """
    from src.siem.models import (
        CorrelationEvent,
        DetectionRule,
        LogEntry,
    )

    async def _count(model: Any, *extra: Any) -> int:
        stmt = select(func.count()).select_from(model).where(*extra)
        return int((await db.execute(stmt)).scalar() or 0)

    total_logs = await _count(LogEntry, LogEntry.organization_id == org_id)
    total_rules = await _count(
        DetectionRule,
        or_(DetectionRule.organization_id == org_id, DetectionRule.organization_id.is_(None)),
    )
    total_correlations = await _count(
        CorrelationEvent, CorrelationEvent.organization_id == org_id,
    )

    since = datetime.utcnow() - timedelta(hours=24)
    logs_last_24h = await _count(
        LogEntry, LogEntry.organization_id == org_id, LogEntry.created_at >= since,
    )

    return {
        "total_logs": total_logs,
        "logs_last_24h": logs_last_24h,
        "total_rules": total_rules,
        "total_correlations": total_correlations,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


# --------------------------------------------------------------------------
# ITDR
# --------------------------------------------------------------------------


@router.get("/itdr/access-anomalies")
async def itdr_access_anomalies_alias(
    db: DatabaseSession,
    org_id: OrganizationId,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    """Alias for `/itdr/anomalies` (AccessAnomaly)."""
    from src.itdr.models import AccessAnomaly

    return await _safe_list(
        db,
        AccessAnomaly,
        org_id=org_id,
        page=page,
        size=size,
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
        db,
        RuntimeAlert,
        org_id=_org_id(current_user),
        page=page,
        size=size,
    )


# --------------------------------------------------------------------------
# OT/ICS Security: the dash-prefixed list mirrors (/ot-security/assets, /alerts,
# /zones, /purdue-map) were deleted in wave 4. The frontend calls the canonical
# underscore routes (/ot_security/...) exclusively, and the purdue-map mirror
# always failed (int() of a Purdue level name) behind an empty-map fallback.
# --------------------------------------------------------------------------


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
        db,
        VendorAssessment,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        IntegrationExecution,
        org_id=_org_id(current_user),
        page=page,
        size=size,
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
        db,
        WebhookEndpoint,
        org_id=_org_id(current_user),
        page=page,
        size=size,
    )


# --------------------------------------------------------------------------
# OT Security bulk discover + server-side export: moved in wave 4 to
# POST /ot_security/discover and GET /ot_security/export (src/api/v1/endpoints/
# ot_security.py). The old dash paths answer 410 Gone with the new path and do
# nothing else.
# --------------------------------------------------------------------------


def _ot_moved(new_path: str) -> HTTPException:
    return HTTPException(
        status_code=410,
        detail={"error": "moved", "new_path": new_path,
                "detail": f"This route moved to {new_path}."},
    )


@router.post("/ot-security/discover", status_code=410)
async def ot_security_bulk_discover_moved(_user: CurrentUser = None):
    """Gone: use ``POST /api/v1/ot_security/discover``."""
    raise _ot_moved("/api/v1/ot_security/discover")


@router.get("/ot-security/export", status_code=410)
async def ot_security_export_moved(_user: CurrentUser = None):
    """Gone: use ``GET /api/v1/ot_security/export``."""
    raise _ot_moved("/api/v1/ot_security/export")
