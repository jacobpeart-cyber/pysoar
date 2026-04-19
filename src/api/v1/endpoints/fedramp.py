"""
FedRAMP Compliance REST API Endpoints

Endpoints for FedRAMP Moderate baseline control management, System Security
Plan (SSP) generation, readiness assessments, POA&M reporting, and
evidence tracking.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user
from src.core.database import get_db
from src.core.logging import get_logger
from src.fedramp.controls import (
    FEDRAMP_MODERATE_CONTROLS,
    CONTROLS_BY_ID,
    CONTROLS_BY_FAMILY,
    FAMILY_CODES,
)
from src.fedramp.generator import FedRAMPGenerator
from src.services.automation import AutomationService

logger = get_logger(__name__)

router = APIRouter(prefix="/fedramp", tags=["fedramp"])

_generator = FedRAMPGenerator()


# ============================================================================
# Controls
# ============================================================================


@router.get("/controls")
async def list_fedramp_controls(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
            db, organization_id=getattr(current_user, "organization_id", None)
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
            controls = [
                c
                for c in controls
                if c.get("implementation_status") == status_filter
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> Dict[str, Any]:
    """FedRAMP readiness score with gap analysis and recommendations.

    Computes the percentage of controls implemented, identifies gaps
    organized by priority, and returns actionable recommendations for
    achieving FedRAMP Moderate authorization.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=getattr(current_user, "organization_id", None)
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    org_name: str = Query("PySOAR Inc.", description="Organization name"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP System Security Plan (SSP) as a JSON structure.

    The returned document follows the FedRAMP Rev 5 SSP template structure
    and includes all control family sections with implementation narratives.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=getattr(current_user, "organization_id", None)
        )
        ssp = _generator.generate_ssp(org_name, system_name, controls)
        return ssp
    except Exception as exc:
        logger.error(f"Error generating SSP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate SSP document",
        )


@router.get("/ssp/export")
async def export_ssp(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    org_name: str = Query("PySOAR Inc.", description="Organization name"),
    system_name: str = Query("PySOAR", description="System name"),
    format: str = Query("json", description="Export format: json"),
) -> Dict[str, Any]:
    """Export the SSP as a downloadable document.

    Currently supports JSON export.  The response includes a
    ``download_url`` placeholder and the full SSP payload.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=getattr(current_user, "organization_id", None)
        )
        ssp = _generator.generate_ssp(org_name, system_name, controls)

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        filename = f"SSP_{system_name.replace(' ', '_')}_{timestamp}.json"

        return {
            "filename": filename,
            "format": format,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "size_estimate_kb": round(len(str(ssp)) / 1024, 1),
            "download_url": f"/api/v1/fedramp/ssp/download/{filename}",
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    org_name: str = Query("PySOAR Inc.", description="Organization name"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP Incident Response Plan (IR control family).

    Returns a JSON document structured to meet NIST 800-61r2 and FedRAMP
    IR control requirements. Content is sourced from the IR family of the
    Moderate baseline with per-tenant implementation status.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=getattr(current_user, "organization_id", None)
        )
        doc = _generator.generate_irp(org_name, system_name, controls)
        return doc
    except Exception as exc:
        logger.error(f"Error generating IRP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Incident Response Plan",
        )


@router.get("/cmp/generate")
async def generate_cmp(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    org_name: str = Query("PySOAR Inc.", description="Organization name"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP Configuration Management Plan (CM control family)."""
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=getattr(current_user, "organization_id", None)
        )
        doc = _generator.generate_cmp(org_name, system_name, controls)
        return doc
    except Exception as exc:
        logger.error(f"Error generating CMP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Configuration Management Plan",
        )


@router.get("/conmon-plan/generate")
async def generate_conmon_plan(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    org_name: str = Query("PySOAR Inc.", description="Organization name"),
    system_name: str = Query("PySOAR", description="System name"),
) -> Dict[str, Any]:
    """Generate a FedRAMP Continuous Monitoring Plan (CA and SI control families)."""
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=getattr(current_user, "organization_id", None)
        )
        doc = _generator.generate_conmon_plan(org_name, system_name, controls)
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        poams: List[Dict[str, Any]] = []

        # Attempt to load POA&M records from the database
        try:
            from src.compliance.models import POAM

            if db and hasattr(db, "execute"):
                from sqlalchemy import select as sa_select

                org_id = getattr(current_user, "organization_id", None)
                stmt = sa_select(POAM)
                if hasattr(POAM, "organization_id"):
                    stmt = stmt.where(POAM.organization_id == org_id)
                if severity:
                    stmt = stmt.where(POAM.severity == severity)
                if status_filter:
                    stmt = stmt.where(POAM.status == status_filter)

                result = await db.scalars(stmt)
                rows = result.all()

                for row in rows:
                    poams.append({
                        "poam_id": str(getattr(row, "id", "")),
                        "control_id": getattr(row, "control_id", ""),
                        "weakness_description": getattr(
                            row, "weakness_description", ""
                        ),
                        "severity": getattr(row, "severity", "low"),
                        "status": getattr(row, "status", "open"),
                        "scheduled_completion_date": str(
                            getattr(row, "scheduled_completion_date", "")
                        ),
                        "milestones": getattr(row, "milestones", []),
                        "responsible_party": getattr(
                            row, "responsible_party", ""
                        ),
                        "resources_required": getattr(
                            row, "resources_required", ""
                        ),
                        "vendor_dependency": getattr(
                            row, "vendor_dependency", False
                        ),
                        "comments": getattr(row, "comments", ""),
                    })
        except Exception:
            logger.warning("Could not load POA&M records from database")

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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> Dict[str, Any]:
    """Evidence collection status per control family.

    For each NIST 800-53 family in the FedRAMP Moderate baseline, returns
    the number of controls, how many have evidence artifacts attached, and
    an overall evidence-collection percentage.
    """
    try:
        controls = await _generator.get_control_implementation_status(
            db, organization_id=getattr(current_user, "organization_id", None)
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    implementation_status: str = Query(
        ...,
        description="New status: implemented, partially_implemented, planned, alternative, not_applicable",
    ),
    implementation_narrative: Optional[str] = Query(
        None, description="Implementation narrative text"
    ),
    assessor_notes: Optional[str] = Query(None, description="Assessor notes"),
) -> Dict[str, Any]:
    """Update the implementation status for a specific FedRAMP control.

    Validates that the control ID exists in the Moderate baseline and
    persists the updated status to the compliance controls table.
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
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {valid_statuses}",
        )

    try:
        baseline_ctrl = CONTROLS_BY_ID[control_id]

        # Attempt to persist to database
        persisted = False
        try:
            from src.compliance.models import ComplianceControl

            if db and hasattr(db, "execute"):
                from sqlalchemy import select as sa_select

                org_id = getattr(current_user, "organization_id", None)
                stmt = sa_select(ComplianceControl).where(
                    ComplianceControl.control_id == control_id,
                    ComplianceControl.framework == "FedRAMP",
                )
                if hasattr(ComplianceControl, "organization_id"):
                    stmt = stmt.where(
                        ComplianceControl.organization_id == org_id
                    )
                result = await db.scalars(stmt)
                existing = result.first()

                if existing:
                    existing.status = implementation_status
                    if implementation_narrative is not None:
                        existing.implementation_narrative = implementation_narrative
                    if assessor_notes is not None:
                        existing.assessor_notes = assessor_notes
                    existing.last_assessed = datetime.utcnow()
                else:
                    new_ctrl = ComplianceControl(
                        control_id=control_id,
                        framework="FedRAMP",
                        status=implementation_status,
                        title=baseline_ctrl["title"],
                        description=baseline_ctrl["description"],
                        family=baseline_ctrl["family"],
                    )
                    if hasattr(ComplianceControl, "organization_id"):
                        new_ctrl.organization_id = org_id
                    if implementation_narrative is not None:
                        new_ctrl.implementation_narrative = implementation_narrative
                    if assessor_notes is not None:
                        new_ctrl.assessor_notes = assessor_notes
                    db.add(new_ctrl)

                await db.commit()
                persisted = True
        except Exception as db_exc:
            logger.warning(
                f"Could not persist control update to database: {db_exc}"
            )

        if implementation_status in ("planned", "partially_implemented", "alternative"):
            try:
                org_id = getattr(current_user, "organization_id", None)
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
