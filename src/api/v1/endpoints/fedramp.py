"""
FedRAMP Compliance REST API Endpoints

Endpoints for FedRAMP Moderate baseline control management, System Security
Plan (SSP) generation, readiness assessments, POA&M reporting, and
evidence tracking.
"""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user, OrganizationId, require_role
from src.models.user import User, UserRole
from src.core.database import get_db
from src.core.logging import get_logger
from src.fedramp.controls import (
    FEDRAMP_MODERATE_CONTROLS,
    CONTROLS_BY_ID,
    CONTROLS_BY_FAMILY,
    FAMILY_CODES,
)
from src.compliance.system_facts import collect_system_facts
from src.fedramp.generator import FedRAMPGenerator
from src.services.automation import AutomationService

logger = get_logger(__name__)

router = APIRouter(prefix="/fedramp", tags=["fedramp"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

_generator = FedRAMPGenerator()


def _org_name(requested: Optional[str], facts: Dict[str, Any]) -> str:
    """The organisation name for document headers: the caller's value, else
    the stored name (a placeholder when none is stored)."""
    return requested or str((facts.get("organization") or {}).get("name") or "")


# ============================================================================
# Controls
# ============================================================================


@router.get("/controls")
async def list_fedramp_controls(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    family: Optional[str] = Query(
        None, description="Filter by family code (e.g. AC, AU, IR)"
    ),
    priority: Optional[str] = Query(
        None, description="Filter by priority (P1, P2, P3)"
    ),
    status_filter: Optional[str] = Query(
        None,
        alias="status",
        description="Filter by implementation status",
    ),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """List all FedRAMP Moderate baseline controls with implementation status.

    Returns the full control catalog enriched with persisted implementation
    status from the database when available.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )

        # Apply filters
        if family:
            family_upper = family.upper()
            controls = [
                c for c in controls if c["id"].startswith(family_upper + "-")
            ]
        if priority:
            controls = [c for c in controls if c.get("priority") == priority]
        if status_filter:
            wanted = {"partial": "partially_implemented"}.get(status_filter, status_filter)
            controls = [
                c
                for c in controls
                if c.get("implementation_status") == wanted
            ]

        total = len(controls)
        paginated = controls[skip : skip + limit]

        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "baseline": "FedRAMP Moderate",
            "families": list(FAMILY_CODES.keys()),
            "controls": paginated,
        }
    except Exception as exc:
        logger.error(f"Error listing FedRAMP controls: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve FedRAMP controls",
        )


# ============================================================================
# Readiness
# ============================================================================


@router.get("/readiness")
async def fedramp_readiness(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> Dict[str, Any]:
    """FedRAMP readiness score with gap analysis and recommendations.

    Computes the percentage of controls implemented, identifies gaps
    organized by priority, and returns actionable recommendations for
    achieving FedRAMP Moderate authorization.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )
        report = _generator.generate_readiness_report(controls)
        return report
    except Exception as exc:
        logger.error(f"Error generating readiness report: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate readiness report",
        )


# ============================================================================
# SSP Generation
# ============================================================================


@router.get("/ssp/generate")
async def generate_ssp(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    org_name: Optional[str] = Query(None, description="Organization name (defaults to the stored organisation name)"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP System Security Plan (SSP) as a JSON structure.

    The returned document follows the FedRAMP Rev 5 SSP template structure
    and includes all control family sections with implementation narratives.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )
        facts = await collect_system_facts(db, org_id)
        ssp = _generator.generate_ssp(_org_name(org_name, facts), system_name, controls, facts)
        return ssp
    except Exception as exc:
        logger.error(f"Error generating SSP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate SSP document",
        )


@router.get("/ssp/export")
async def export_ssp(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    org_name: Optional[str] = Query(None, description="Organization name (defaults to the stored organisation name)"),
    system_name: str = Query("PySOAR", description="System name"),
    format: str = Query("json", description="Export format: json"),
) -> Dict[str, Any]:
    """Export the SSP as a downloadable document.

    JSON only: the full SSP is in ``document`` (``download_url`` is null;
    it used to name a route that does not exist).
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )
        facts = await collect_system_facts(db, org_id)
        ssp = _generator.generate_ssp(_org_name(org_name, facts), system_name, controls, facts)

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        filename = f"SSP_{system_name.replace(' ', '_')}_{timestamp}.json"

        return {
            "filename": filename,
            "format": format,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "size_estimate_kb": round(len(str(ssp)) / 1024, 1),
            # No download route exists; the document is in the response.
            "download_url": None,
            "document": ssp,
        }
    except Exception as exc:
        logger.error(f"Error exporting SSP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export SSP document",
        )


# ============================================================================
# IRP / CMP / ConMon Plan Generation
# ============================================================================


@router.get("/irp/generate")
async def generate_irp(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    org_name: Optional[str] = Query(None, description="Organization name (defaults to the stored organisation name)"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP Incident Response Plan (IR control family).

    Returns a JSON document structured to meet NIST 800-61r2 and FedRAMP
    IR control requirements. Content is sourced from the IR family of the
    Moderate baseline with per-tenant implementation status.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )
        facts = await collect_system_facts(db, org_id)
        inputs = await _generator.collect_plan_inputs(db, org_id)
        doc = _generator.generate_irp(_org_name(org_name, facts), system_name, controls, facts, inputs)
        return doc
    except Exception as exc:
        logger.error(f"Error generating IRP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Incident Response Plan",
        )


@router.get("/cmp/generate")
async def generate_cmp(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    org_name: Optional[str] = Query(None, description="Organization name (defaults to the stored organisation name)"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP Configuration Management Plan (CM control family)."""
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )
        facts = await collect_system_facts(db, org_id)
        inputs = await _generator.collect_plan_inputs(db, org_id)
        doc = _generator.generate_cmp(_org_name(org_name, facts), system_name, controls, facts, inputs)
        return doc
    except Exception as exc:
        logger.error(f"Error generating CMP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Configuration Management Plan",
        )


@router.get("/conmon-plan/generate")
async def generate_conmon_plan(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    org_name: Optional[str] = Query(None, description="Organization name (defaults to the stored organisation name)"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP Continuous Monitoring Plan (CA and SI control families)."""
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )
        facts = await collect_system_facts(db, org_id)
        inputs = await _generator.collect_plan_inputs(db, org_id)
        doc = _generator.generate_conmon_plan(_org_name(org_name, facts), system_name, controls, facts, inputs)
        return doc
    except Exception as exc:
        logger.error(f"Error generating ConMon Plan: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Continuous Monitoring Plan",
        )


# ============================================================================
# POA&M
# ============================================================================


@router.get("/poam/report")
async def poam_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by status"
    ),
) -> Dict[str, Any]:
    """POA&M status report.

    Retrieves POA&M items from the database, formats them into the
    FedRAMP POA&M template, and returns summary statistics including
    overdue items.
    """
    try:
        from sqlalchemy import select as sa_select

        from src.compliance.models import POAM, ComplianceControl

        # POAM has no severity/control_id/responsible_party columns: severity is
        # risk_level, the control code comes from the referenced control row,
        # the owner is assigned_to. A ``severity`` filter used to call the
        # missing POAM.severity, raise, and be swallowed into an empty report.
        stmt = (
            sa_select(POAM, ComplianceControl.control_id)
            .outerjoin(
                ComplianceControl,
                (ComplianceControl.id == POAM.control_id_ref)
                & (ComplianceControl.organization_id == org_id),
            )
            .where(POAM.organization_id == org_id)
        )
        if severity:
            stmt = stmt.where(POAM.risk_level == severity)
        if status_filter:
            stmt = stmt.where(POAM.status == status_filter)

        poams: List[Dict[str, Any]] = []
        for row, control_code in (await db.execute(stmt)).all():
            poams.append({
                "poam_id": str(row.id),
                "control_id": control_code or "",
                "weakness_description": row.weakness_description or row.weakness_name or "",
                "severity": row.risk_level or "",
                "status": row.status or "open",
                "scheduled_completion_date": row.scheduled_completion_date,
                "milestones": row.milestones or [],
                "responsible_party": row.assigned_to or "",
                "resources_required": row.resources_required or "",
                "vendor_dependency": bool(row.vendor_dependencies),
                "comments": row.comments or [],
            })

        report = _generator.generate_poam_report(poams)
        return report
    except Exception as exc:
        logger.error(f"Error generating POA&M report: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate POA&M report",
        )


# ============================================================================
# Evidence
# ============================================================================


@router.get("/evidence/status")
async def evidence_status(
    org_id: OrganizationId,
    db: DatabaseSession = None,
) -> Dict[str, Any]:
    """Evidence collection status per control family.

    For each NIST 800-53 family in the FedRAMP Moderate baseline, returns
    the number of controls, how many have evidence artifacts attached, and
    an overall evidence-collection percentage.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=org_id
        )

        family_evidence: Dict[str, Dict[str, Any]] = {}
        for ctrl in controls:
            fam = ctrl.get("family", "Unknown")
            if fam not in family_evidence:
                family_evidence[fam] = {
                    "family": fam,
                    "total_controls": 0,
                    "controls_with_evidence": 0,
                    "evidence_artifacts": [],
                }
            family_evidence[fam]["total_controls"] += 1
            artifacts = ctrl.get("evidence_artifacts", [])
            if artifacts:
                family_evidence[fam]["controls_with_evidence"] += 1
                family_evidence[fam]["evidence_artifacts"].extend(artifacts)

        for fam, stats in family_evidence.items():
            t = stats["total_controls"]
            stats["evidence_coverage_pct"] = (
                round((stats["controls_with_evidence"] / t) * 100, 2)
                if t
                else 0.0
            )

        total_controls = sum(f["total_controls"] for f in family_evidence.values())
        total_with_evidence = sum(
            f["controls_with_evidence"] for f in family_evidence.values()
        )
        overall_pct = (
            round((total_with_evidence / total_controls) * 100, 2)
            if total_controls
            else 0.0
        )

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "overall_evidence_coverage_pct": overall_pct,
            "total_controls": total_controls,
            "controls_with_evidence": total_with_evidence,
            "families": list(family_evidence.values()),
        }
    except Exception as exc:
        logger.error(f"Error generating evidence status: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate evidence status report",
        )


# ============================================================================
# Control Update
# ============================================================================


@router.post("/controls/{control_id}/update")
async def update_control_status(
    control_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
    implementation_status: str = Query(
        ...,
        description="New status: implemented, partially_implemented, planned, alternative, not_applicable",
    ),
    implementation_narrative: Optional[str] = Query(
        None, description="Implementation narrative text"
    ),
    assessor_notes: Optional[str] = Query(None, description="Assessor notes"),
) -> Dict[str, Any]:
    """Update the implementation status for a specific FedRAMP control (admin only).

    Validates that the control ID exists in the Moderate baseline and
    persists the status (and narrative, as ``implementation_details``) to the
    caller's row in ``compliance_controls`` under their FedRAMP framework.
    404 ``control_not_tracked`` when the organisation has no such row;
    501 for ``assessor_notes``, which has no storage column.
    """
    # Validate control exists in baseline
    if control_id not in CONTROLS_BY_ID:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Control {control_id} not found in FedRAMP Moderate baseline",
        )

    valid_statuses = FedRAMPGenerator.IMPLEMENTATION_STATUSES
    if implementation_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_implementation_status",
                "field": "implementation_status",
                "detail": f"Must be one of: {valid_statuses}",
            },
        )

    if assessor_notes is not None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={
                "error": "not_implemented",
                "detail": "assessor_notes cannot be stored: compliance_controls has no assessor-notes column",
            },
        )

    from sqlalchemy import select as sa_select

    from src.compliance.engine import FEDRAMP_SHORT_NAME_PREFIX
    from src.compliance.models import ComplianceControl, ComplianceFramework

    try:
        baseline_ctrl = CONTROLS_BY_ID[control_id]

        rows = (
            await db.execute(
                sa_select(ComplianceControl, ComplianceFramework.short_name)
                .join(
                    ComplianceFramework,
                    ComplianceControl.framework_id == ComplianceFramework.id,
                )
                .where(
                    ComplianceControl.control_id == control_id,
                    ComplianceControl.organization_id == org_id,
                    ComplianceFramework.organization_id == org_id,
                    ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
                )
            )
        ).all()
        if not rows:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "control_not_tracked",
                    "detail": (
                        f"Your organization has no FedRAMP control record for {control_id}; "
                        "enable the FedRAMP Moderate framework first"
                    ),
                },
            )
        # Prefer the Moderate framework when several FedRAMP baselines exist.
        rows.sort(key=lambda r: r[1] != "fedramp_moderate")
        existing = rows[0][0]

        existing.status = implementation_status
        # Set by a person: the attester will not overwrite it.
        existing.status_source = "manual"
        if implementation_narrative is not None:
            existing.implementation_details = implementation_narrative
        await db.commit()
        persisted = True
        logger.info(
            "fedramp_control_status_updated",
            control_id=control_id,
            organization_id=org_id,
            implementation_status=implementation_status,
        )

        if implementation_status in ("planned", "partially_implemented", "alternative"):
            try:
                automation = AutomationService(db)
                await automation.on_fedramp_evidence_gap(
                    control_id=control_id,
                    control_title=baseline_ctrl["title"],
                    organization_id=org_id,
                )
            except Exception as automation_exc:
                logger.warning(f"Automation on_fedramp_evidence_gap failed: {automation_exc}")

        return {
            "control_id": control_id,
            "family": baseline_ctrl["family"],
            "title": baseline_ctrl["title"],
            "implementation_status": implementation_status,
            "implementation_narrative": implementation_narrative,
            "assessor_notes": assessor_notes,
            "persisted_to_database": persisted,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error updating control {control_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update control {control_id}",
        )
