"""
Compliance REST API Endpoints

Complete API for managing compliance frameworks, controls, assessments, and evidence.
Supports FedRAMP, NIST, CMMC, SOC 2, HIPAA, PCI-DSS, DFARS, and CISA compliance.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Query
from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.models.user import User, UserRole
from sqlalchemy import select, and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.services.automation import AutomationService
from src.api.deps import get_current_active_user as get_current_user
from src.api.v1.endpoints.audit_evidence import REMOTE_EVIDENCE_SCHEMES
from src.core.database import get_db
from src.schemas.compliance import (
    ComplianceFrameworkResponse,
    ComplianceControlResponse,
    POAMResponse,
    ComplianceEvidenceResponse,
    ComplianceAssessmentResponse,
    CUIMarkingResponse,
    CISADirectiveResponse,
    FrameworkAssessmentResponse,
    POAMCreateRequest,
    POAMUpdateRequest,
    SSPGenerationRequest,
    SSPGenerationResponse,
    ConMonReportResponse,
    CUIMarkingRequest,
    ComplianceDashboardStats,
    ControlGapAnalysisResponse,
    CrossFrameworkMappingResponse,
    CISADirectiveStatusResponse,
    ControlStatusUpdateRequest,
    PaginationParams,
)
from src.compliance.models import (
    ComplianceFramework,
    ComplianceControl,
    POAM,
    ComplianceEvidence,
    ComplianceAssessment,
    CUIMarking,
    CISADirective,
)
from src.tickethub.models import TicketActivity
from src.compliance.engine import (
    FEDRAMP_SHORT_NAME_PREFIX,
    ComplianceEngine,
    FedRAMPManager,
    NISTManager,
    CMMCManager,
    CISAComplianceManager,
)
from src.compliance.tasks import (
    run_compliance_assessment,
    run_continuous_monitoring,
    check_poam_deadlines,
    collect_automated_evidence,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/compliance", tags=["compliance"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


async def _resolve_tenant_control_ref(
    db: AsyncSession, org_id: str, value: Optional[str], field: str,
) -> str:
    """Return the id of the caller's control that ``value`` names.

    ``value`` is a control row id, or a control code (``AC-2``) when exactly
    one of the tenant's controls carries that code. Anything else (empty,
    another tenant's control, an ambiguous code) is a 422 naming ``field``.
    """
    ref = (value or "").strip()
    if not ref:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_control_reference", "field": field,
                    "detail": f"{field} is required"},
        )
    by_id = await db.execute(
        select(ComplianceControl.id).where(
            ComplianceControl.id == ref, ComplianceControl.organization_id == org_id,
        ),
    )
    control_pk = by_id.scalar_one_or_none()
    if control_pk:
        return control_pk
    by_code = await db.execute(
        select(ComplianceControl.id).where(
            ComplianceControl.control_id == ref, ComplianceControl.organization_id == org_id,
        ).limit(2),
    )
    matches = by_code.scalars().all()
    if len(matches) == 1:
        return matches[0]
    reason = (
        f"control code {ref!r} matches more than one of your controls (one per framework); "
        "send the control's id"
        if matches
        else f"{ref!r} is not a control id or control code in your organization"
    )
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"error": "invalid_control_reference", "field": field, "detail": reason},
    )


# ============================================================================
# FRAMEWORKS ENDPOINTS
# ============================================================================


@router.get("/frameworks", response_model=List[ComplianceFrameworkResponse])
async def list_frameworks(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    enabled_only: bool = True,
):
    """
    List all compliance frameworks for organization.

    Query Parameters:
    - status: Filter by framework status (not_started, in_progress, etc.)
    - enabled_only: Only show enabled frameworks (default: true)
    - skip, limit: Pagination
    """
    stmt = select(ComplianceFramework).where(
        ComplianceFramework.organization_id == org_id,
    )

    if enabled_only:
        stmt = stmt.where(ComplianceFramework.is_enabled == True)

    if status:
        stmt = stmt.where(ComplianceFramework.status == status)

    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    frameworks = result.scalars().all()

    return frameworks


@router.get("/frameworks/{framework_id}", response_model=ComplianceFrameworkResponse)
async def get_framework(
    framework_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get framework details with control summary."""
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    return framework


@router.post("/frameworks/{framework_id}/assess", response_model=FrameworkAssessmentResponse)
async def trigger_assessment(
    framework_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """
    Trigger full compliance assessment for framework.

    Runs assessment across all controls and returns comprehensive results.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    # Trigger assessment task
    run_compliance_assessment.delay(framework_id, org_id)

    # Run assessment synchronously for immediate response
    engine = ComplianceEngine(db, org_id)
    assessment = await engine.assess_framework(framework_id)

    # Cross-module loop: if the framework's assessment came back
    # with less than 80% compliance, fire on_compliance_failure so
    # the framework drops into the automation pipeline — Alert,
    # POAM creation, and remediation policy evaluation all get
    # their shot at the finding. 80% is the standard FedRAMP
    # Moderate "partially compliant" threshold.
    try:
        score = (assessment.get("compliance_score") if isinstance(assessment, dict) else None) or 0
        if score < 80.0:
            from src.services.automation import AutomationService
            automation = AutomationService(db)
            await automation.on_compliance_failure(
                control_id=framework.short_name or framework_id,
                control_title=f"{framework.name}: {score:.1f}% compliant",
                framework=framework.name,
                organization_id=org_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"on_compliance_failure fan-out failed: {exc}")

    return assessment


@router.get("/frameworks/{framework_id}/gaps", response_model=ControlGapAnalysisResponse)
async def get_control_gaps(
    framework_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """
    Get control implementation gaps for framework.

    Returns gap list prioritized by risk and priority.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    engine = ComplianceEngine(db, org_id)
    gaps = await engine.get_control_gaps(framework_id)

    # Count distributions
    priority_dist = {}
    risk_dist = {}
    for gap in gaps:
        priority_dist[gap["priority"]] = priority_dist.get(gap["priority"], 0) + 1
        risk_dist[gap["risk_level"]] = risk_dist.get(gap["risk_level"], 0) + 1

    return {
        "framework_id": framework_id,
        "total_controls": len(gaps),
        "gaps_count": len(gaps),
        "gaps": gaps,
        "priority_distribution": priority_dist,
        "risk_distribution": risk_dist,
    }


@router.get("/frameworks/{framework_id}/ssp", response_model=SSPGenerationResponse)
async def generate_ssp(
    framework_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """
    Generate a System Security Plan (SSP) for a framework.

    Built from the stored control rows only. A GET does not run the
    Control Auto-Attester (it used to, and the attester records
    "implemented" for rules it never checks); run it explicitly through
    POST /frameworks/{id}/attest. Markdown export via /ssp/download.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    engine = ComplianceEngine(db, org_id)
    ssp = await engine.generate_ssp(framework_id, run_attester=False)

    return ssp


@router.get("/frameworks/{framework_id}/ssp/download")
async def download_ssp(
    framework_id: str,
    org_id: OrganizationId,
    format: str = "markdown",
    db: DatabaseSession = None,
):
    """Download the SSP as a file.

    `format` may be `markdown` (default, .md) or `json`. Response is
    served as an attachment so a browser save-as dialog opens —
    intended for handing the document to a 3PAO.
    """
    from fastapi.responses import Response as _Response
    from src.compliance.engine import ssp_to_markdown

    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
        ),
    )
    framework = (await db.execute(stmt)).scalar_one_or_none()
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    engine = ComplianceEngine(db, org_id)
    ssp = await engine.generate_ssp(framework_id, run_attester=False)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    base = f"ssp_{(framework.short_name or 'framework').lower().replace(' ', '_')}_{stamp}"

    if format == "json":
        import json as _json
        body = _json.dumps(ssp, indent=2, default=str).encode("utf-8")
        return _Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{base}.json"'},
        )

    md = ssp_to_markdown(ssp)
    return _Response(
        content=md.encode("utf-8"),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{base}.md"'},
    )


@router.post("/frameworks/{framework_id}/attest")
async def run_auto_attestation(
    framework_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: AdminRoleUser = None,
):
    """Run the control attester against this framework (admin only).

    Each control the attester has a rule for gets ``pass`` / ``fail`` /
    ``not_assessed`` with the facts the rule read (``assessment_basis``);
    the status changes only for controls whose status was not set by a
    person. Returns the counts and the per-control outcome.
    """
    from src.compliance.attester import ControlAutoAttester

    framework = await db.get(ComplianceFramework, framework_id)
    if not framework or framework.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Framework not found")

    attester = ControlAutoAttester(db, org_id)
    summary = await attester.attest_all(framework_id=framework_id)
    from src.models.audit import AuditLog

    db.add(AuditLog(
        user_id=str(current_user.id),
        organization_id=org_id,
        action="compliance_attest",
        resource_type="compliance_framework",
        resource_id=framework_id,
        description=(
            f"Control attester: {summary.get('passed', 0)} passed, {summary.get('failed', 0)} failed, "
            f"{summary.get('not_assessed', 0)} not assessed"
        ),
        new_value=json.dumps({k: v for k, v in summary.items() if k != "controls"}, default=str),
        success=True,
    ))
    await db.commit()
    return summary


@router.get("/frameworks/{framework_id}/report")
async def get_framework_report(
    framework_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get comprehensive framework compliance report."""
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    engine = ComplianceEngine(db, org_id)
    ssp = await engine.generate_ssp(framework_id, run_attester=False)
    gaps = await engine.get_control_gaps(framework_id)
    poam_report = await engine.generate_poam_report(framework_id)

    return {
        "framework_id": framework_id,
        "framework_name": framework.short_name,
        "compliance_score": framework.compliance_score,
        "status": framework.status,
        "last_assessment": framework.last_assessment_at,
        "ssp": ssp,
        "gaps": gaps,
        "poams": poam_report,
    }


@router.post("/frameworks/{framework_id}/conmon")
async def trigger_continuous_monitoring(
    framework_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """
    Run FedRAMP Continuous Monitoring (ConMon) checks.

    Returns ConMon status with control assessment results.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
            ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
        ),
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="FedRAMP framework not found")

    # Trigger ConMon task
    run_continuous_monitoring.delay(org_id)

    manager = FedRAMPManager(db, org_id)
    conmon_result = await manager.run_continuous_monitoring()

    return conmon_result


# ============================================================================
# CONTROLS ENDPOINTS
# ============================================================================


@router.get("/controls", response_model=List[ComplianceControlResponse])
async def list_controls(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    framework_id: Optional[str] = None,
    family: Optional[str] = None,
    status: Optional[str] = None,
    baseline: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=1000),
):
    """
    List controls with filtering by framework, family, status, baseline.

    Query Parameters:
    - framework_id: Filter by framework
    - family: Filter by control family
    - status: Filter by implementation status
    - baseline: Filter by baseline (low, moderate, high)
    """
    stmt = select(ComplianceControl).where(
        ComplianceControl.organization_id == org_id,
    )

    if framework_id:
        # The page sends the framework short name; ids still work.
        fw_ids = select(ComplianceFramework.id).where(
            ComplianceFramework.organization_id == org_id,
            or_(ComplianceFramework.id == framework_id, ComplianceFramework.short_name == framework_id),
        )
        stmt = stmt.where(ComplianceControl.framework_id.in_(fw_ids))
    if family:
        # A family code ("AC") matches the control-id prefix; a family name
        # ("Access Control") matches the stored family.
        if len(family) <= 3 and family.isalpha():
            stmt = stmt.where(ComplianceControl.control_id.like(f"{family.upper()}-%"))
        else:
            stmt = stmt.where(ComplianceControl.control_family == family)
    if status:
        status_aliases = {"partially": "partially_implemented", "partial": "partially_implemented"}
        stmt = stmt.where(ComplianceControl.status == status_aliases.get(status, status))
    if baseline:
        stmt = stmt.where(ComplianceControl.baseline == baseline)

    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    controls = result.scalars().all()

    return controls


# Static path: must be registered before /controls/{control_id}, which
# otherwise captures "cross-map" as a control id.
@router.get("/controls/cross-map")
async def cross_map_controls(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    source_framework_id: str = Query(...),
    target_framework_id: str = Query(...),
):
    """Get cross-framework control mapping.

    Verifies both frameworks belong to the caller's org before running
    the mapping. Without this check, an authenticated user could pass
    any framework UUID (e.g. another tenant's FedRAMP instance) and
    read its control relationships.
    """

    for fw_id in (source_framework_id, target_framework_id):
        check = await db.execute(
            select(ComplianceFramework).where(
                and_(
                    ComplianceFramework.id == fw_id,
                    ComplianceFramework.organization_id == org_id,
                ),
            ),
        )
        if check.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Framework {fw_id} not found in your organization",
            )

    engine = ComplianceEngine(db, org_id)
    mapping = await engine.cross_map_controls(source_framework_id, target_framework_id)
    return mapping


@router.get("/controls/{control_id}", response_model=ComplianceControlResponse)
async def get_control(
    control_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get control details with evidence."""
    stmt = select(ComplianceControl).where(
        and_(
            ComplianceControl.id == control_id,
            ComplianceControl.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    control = result.scalar_one_or_none()

    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    return control


@router.put("/controls/{control_id}", response_model=ComplianceControlResponse)
async def update_control(
    control_id: str,
    req: ControlStatusUpdateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: AdminRoleUser = None,
):
    """Update control implementation status."""
    stmt = select(ComplianceControl).where(
        and_(
            ComplianceControl.id == control_id,
            ComplianceControl.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    control = result.scalar_one_or_none()

    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    prev_status = control.status
    prev_impl = control.implementation_status

    control.status = req.status
    # A person set this status: the attester records its own result in
    # assessment_basis but no longer overwrites it.
    control.status_source = "manual"
    if req.implementation_status is not None:
        control.implementation_status = req.implementation_status
    if req.responsible_party:
        control.responsible_party = req.responsible_party
    if req.implementation_details:
        control.implementation_details = req.implementation_details

    await db.commit()
    await db.refresh(control)

    # -------------------------------------------------------------
    # Cross-module fan-out: if the control just moved into a non-
    # compliant state, auto-create a POAM so the weakness lands on
    # somebody's remediation queue. Skip if an open POAM for this
    # control already exists so re-saving the same status doesn't
    # spam the POAM list. Prior status is captured above BEFORE the
    # commit so we can compare old vs new and only fire on a real
    # transition.
    # -------------------------------------------------------------
    non_compliant_states = {"not_implemented", "non_compliant"}
    is_partial_low = (
        req.status == "partially_implemented"
        and (req.implementation_status is not None and req.implementation_status < 40.0)
    )
    should_create_poam = (
        (req.status in non_compliant_states and prev_status not in non_compliant_states)
        or is_partial_low
    )
    if should_create_poam:
        try:
            # Skip if an open POAM already exists for this control
            existing_q = select(POAM).where(
                and_(
                    POAM.control_id_ref == control.id,
                    POAM.organization_id == org_id,
                    POAM.status.in_(("open", "in_progress", "delayed")),
                ),
            )
            existing_res = await db.execute(existing_q)
            existing_poam = existing_res.scalars().first()
            if existing_poam is None:
                # Map control.priority (p1/p2/p3) and risk_if_not_implemented
                # to POAM risk_level.
                risk_map = {
                    "critical": "very_high",
                    "high": "high",
                    "medium": "moderate",
                    "low": "low",
                }
                risk_source = (
                    getattr(control, "risk_if_not_implemented", None)
                    or {"p1": "critical", "p2": "high", "p3": "medium"}.get(
                        (control.priority or "p2").lower(), "high",
                    )
                )
                poam_risk = risk_map.get(str(risk_source).lower(), "high")

                weakness_desc = (
                    control.description
                    or getattr(control, "remediation_guidance", None)
                    or f"Control {control.control_id} marked {req.status}"
                )
                new_poam = POAM(
                    control_id_ref=control.id,
                    weakness_name=f"Control {control.control_id} not implemented: {control.title}",
                    weakness_description=weakness_desc,
                    weakness_source="internal_assessment",
                    risk_level=poam_risk,
                    status="open",
                    scheduled_completion_date=datetime.now(timezone.utc) + timedelta(days=90),
                    organization_id=control.organization_id,
                )
                db.add(new_poam)
                await db.commit()
                await db.refresh(new_poam)

                # Back-link the control to the newly created POAM
                try:
                    control.poam_id = new_poam.id
                    await db.commit()
                except Exception as exc:
                    logger.warning(f"Failed to back-link control {control.id} to POAM {new_poam.id}: {exc}")

                # Log the auto-creation via TicketActivity for traceability
                try:
                    activity = TicketActivity(
                        source_type="poam",
                        source_id=str(new_poam.id),
                        activity_type="poam_auto_created",
                        actor_id=str(current_user.id) if current_user else None,
                        description=(
                            f"Auto-created POAM for control {control.control_id} "
                            f"({prev_status} -> {req.status})"
                        ),
                        new_value=json.dumps({
                            "control_id": control.id,
                            "control_ref": control.control_id,
                            "prev_status": prev_status,
                            "new_status": req.status,
                            "risk_level": poam_risk,
                        }),
                        organization_id=control.organization_id,
                    )
                    db.add(activity)
                    await db.commit()
                except Exception as exc:
                    logger.warning(f"Failed to log POAM auto-creation activity: {exc}")
        except Exception as e:
            logger.error(f"Auto-POAM creation failed for control {control.id}: {e}", exc_info=True)

    # Trigger automation if control is non-compliant or not implemented
    if req.status in ("non_compliant", "not_implemented"):
        try:
            automation = AutomationService(db)
            await automation.on_compliance_failure(
                control_id=control.control_id,
                control_title=control.title,
                organization_id=org_id,
            )
        except Exception as e:
            logger.error(f"Automation on_compliance_failure failed: {e}", exc_info=True)

    return control


@router.post("/controls/{control_id}/assess")
async def run_control_assessment(
    control_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Run automated check for specific control."""
    stmt = select(ComplianceControl).where(
        and_(
            ComplianceControl.id == control_id,
            ComplianceControl.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    control = result.scalar_one_or_none()

    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    nist_mgr = NISTManager(db, org_id)
    check_result = await nist_mgr.automated_control_check(
        control.control_id, framework_id=control.framework_id,
    )

    return check_result


# ============================================================================
# POA&M ENDPOINTS
# ============================================================================


@router.get("/poams", response_model=List[POAMResponse])
async def list_poams(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    overdue_only: bool = False,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """
    List POA&Ms with filtering by status, risk level, and due date.

    Query Parameters:
    - status: open, in_progress, delayed, completed, cancelled, accepted
    - risk_level: Filter by risk level
    - overdue_only: Show only overdue items
    """
    stmt = select(POAM).where(POAM.organization_id == org_id)

    if status:
        stmt = stmt.where(POAM.status == status)
    if risk_level:
        stmt = stmt.where(POAM.risk_level == risk_level)

    if overdue_only:
        now = datetime.now(timezone.utc)
        stmt = stmt.where(
            and_(
                POAM.scheduled_completion_date < now,
                POAM.status != "completed",
            ),
        )

    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    poams = result.scalars().all()

    return poams


@router.post("/poams", response_model=POAMResponse)
async def create_poam(
    req: POAMCreateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Create new POA&M.

    ``control_id_ref`` is the control row id, or a control code that names
    exactly one of the caller's controls; anything else is a 422.
    """
    control_ref = await _resolve_tenant_control_ref(db, org_id, req.control_id_ref, "control_id_ref")
    poam = POAM(
        control_id_ref=control_ref,
        weakness_name=req.weakness_name,
        weakness_description=req.weakness_description,
        weakness_source=req.weakness_source,
        risk_level=req.risk_level,
        scheduled_completion_date=req.scheduled_completion_date,
        resources_required=req.resources_required,
        cost_estimate=req.cost_estimate,
        assigned_to=req.assigned_to,
        organization_id=org_id,
    )
    db.add(poam)
    await db.commit()
    await db.refresh(poam)

    return poam


@router.get("/poams/overdue")
async def get_overdue_poams(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get overdue POA&Ms."""
    now = datetime.now(timezone.utc)
    stmt = select(POAM).where(
        and_(
            POAM.organization_id == org_id,
            POAM.scheduled_completion_date < now,
            POAM.status != "completed",
        ),
    )
    result = await db.execute(stmt)
    overdue_poams = result.scalars().all()

    return {"overdue_count": len(overdue_poams), "poams": overdue_poams}


@router.get("/poams/report")
async def get_poam_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get POA&M summary report."""
    stmt = select(POAM).where(POAM.organization_id == org_id)
    result = await db.execute(stmt)
    all_poams = result.scalars().all()

    now = datetime.now(timezone.utc)
    overdue = [p for p in all_poams if p.scheduled_completion_date < now and p.status != "completed"]
    open_items = [p for p in all_poams if p.status in ["open", "in_progress"]]
    completed = [p for p in all_poams if p.status == "completed"]

    return {
        "total": len(all_poams),
        "open": len(open_items),
        "overdue": len(overdue),
        "completed": len(completed),
        "poams": all_poams,
    }


@router.get("/poams/{poam_id}", response_model=POAMResponse)
async def get_poam(
    poam_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get POA&M details."""
    stmt = select(POAM).where(
        and_(
            POAM.id == poam_id,
            POAM.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    poam = result.scalar_one_or_none()

    if not poam:
        raise HTTPException(status_code=404, detail="POA&M not found")

    return poam


@router.put("/poams/{poam_id}", response_model=POAMResponse)
async def update_poam(
    poam_id: str,
    req: POAMUpdateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Update POA&M."""
    stmt = select(POAM).where(
        and_(
            POAM.id == poam_id,
            POAM.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    poam = result.scalar_one_or_none()

    if not poam:
        raise HTTPException(status_code=404, detail="POA&M not found")

    if req.status:
        poam.status = req.status
    if req.scheduled_completion_date:
        poam.scheduled_completion_date = req.scheduled_completion_date
    if req.actual_completion_date:
        poam.actual_completion_date = req.actual_completion_date
    if req.assigned_to:
        poam.assigned_to = req.assigned_to
    if req.approved_by:
        poam.approved_by = req.approved_by
    if req.residual_risk_rating:
        poam.residual_risk_rating = req.residual_risk_rating

    await db.commit()
    await db.refresh(poam)

    return poam


@router.delete("/poams/{poam_id}", status_code=204)
async def delete_poam(
    poam_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: AnalystUser = None,
):
    """Delete a POA&M item (analyst or admin), with an audit-trail row.

    The control that pointed at it is unlinked first.
    """
    from src.audit_evidence.engine import AuditLogger

    poam = (await db.execute(
        select(POAM).where(POAM.id == poam_id, POAM.organization_id == org_id),
    )).scalar_one_or_none()
    if not poam:
        raise HTTPException(status_code=404, detail="POA&M not found")

    linked = (await db.execute(
        select(ComplianceControl).where(
            ComplianceControl.organization_id == org_id, ComplianceControl.poam_id == poam.id,
        ),
    )).scalars().all()
    for control in linked:
        control.poam_id = None
    snapshot = {"weakness_name": poam.weakness_name, "status": poam.status, "control_id_ref": poam.control_id_ref}
    await db.flush()
    await db.delete(poam)
    try:
        await AuditLogger(db, org_id).log_event(
            event_type="change",
            action="poam.delete",
            actor_type="user",
            actor_id=str(current_user.id),
            resource_type="POAM",
            resource_id=poam_id,
            description=f"POA&M {poam_id} deleted",
            old_value=snapshot,
            result="success",
            risk_level="low",
        )
    except Exception as exc:  # noqa: BLE001 - fail closed: no delete without its audit row
        await db.rollback()
        logger.error("poam_delete_audit_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="Audit trail unavailable; POA&M not deleted") from exc
    await db.commit()


# ============================================================================
# EVIDENCE ENDPOINTS
# ============================================================================


@router.get("/evidence", response_model=List[ComplianceEvidenceResponse])
async def list_evidence(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    control_id_ref: Optional[str] = None,
    evidence_type: Optional[str] = None,
    review_status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List evidence with filtering."""
    stmt = select(ComplianceEvidence).where(
        ComplianceEvidence.organization_id == org_id,
    )

    if control_id_ref:
        stmt = stmt.where(ComplianceEvidence.control_id_ref == control_id_ref)
    if evidence_type:
        stmt = stmt.where(ComplianceEvidence.evidence_type == evidence_type)
    if review_status:
        stmt = stmt.where(ComplianceEvidence.review_status == review_status)

    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    evidence = result.scalars().all()

    return evidence


@router.post("/evidence", response_model=ComplianceEvidenceResponse)
async def upload_evidence(
    control_id_ref: str,
    evidence_type: str,
    title: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    description: Optional[str] = None,
    content: Optional[str] = None,
    file_path: Optional[str] = None,
    current_user: AnalystUser = None,
):
    """Register compliance evidence.

    ``file_path`` may only be an https:// or s3:// object URL. Local files are
    registered solely through POST /audit-evidence/evidence/upload, which
    writes under EVIDENCE_UPLOAD_ROOT; accepting a local path here let any
    user register "/opt/pysoar/.env" and download it (fixed 2026-10-08).
    """
    if file_path and not file_path.startswith(REMOTE_EVIDENCE_SCHEMES):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_evidence_location",
                "detail": (
                    "file_path must be an https:// or s3:// object URL; local files are "
                    "registered through POST /audit-evidence/evidence/upload"
                ),
            },
        )
    control_ref = await _resolve_tenant_control_ref(db, org_id, control_id_ref, "control_id_ref")
    evidence = ComplianceEvidence(
        control_id_ref=control_ref,
        evidence_type=evidence_type,
        title=title,
        description=description,
        content=content,
        file_path=file_path or None,
        collected_at=datetime.now(timezone.utc),
        collected_by=current_user.id,
        organization_id=org_id,
    )
    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)

    return evidence


@router.get("/evidence/{evidence_id}", response_model=ComplianceEvidenceResponse)
async def get_evidence(
    evidence_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get evidence details."""
    stmt = select(ComplianceEvidence).where(
        and_(
            ComplianceEvidence.id == evidence_id,
            ComplianceEvidence.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    evidence = result.scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    return evidence


@router.put("/evidence/{evidence_id}/review")
async def review_evidence(
    evidence_id: str,
    review_status: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: AdminRoleUser = None,
    reviewed_by: Optional[str] = Query(
        None, description="Ignored: the reviewer is always the authenticated user.",
    ),
):
    """Review and approve evidence (admin only).

    The recorded reviewer is the caller; a client-supplied ``reviewed_by``
    used to be stored verbatim, which let anyone forge the approver.
    """
    stmt = select(ComplianceEvidence).where(
        and_(
            ComplianceEvidence.id == evidence_id,
            ComplianceEvidence.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    evidence = result.scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    if review_status == "approved":
        # Separation of duties: the uploader cannot approve their own evidence.
        from src.compliance.separation_of_duties import ensure_not_uploader

        ensure_not_uploader(evidence, current_user)

    evidence.review_status = review_status
    evidence.reviewed_by = str(current_user.id)
    evidence.reviewed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(evidence)

    return evidence


# ============================================================================
# CUI ENDPOINTS
# ============================================================================


@router.get("/cui", response_model=List[CUIMarkingResponse])
async def list_cui_markings(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    active_only: bool = True,
):
    """List CUI markings."""
    stmt = select(CUIMarking).where(
        CUIMarking.organization_id == org_id,
    )

    if active_only:
        stmt = stmt.where(CUIMarking.is_active == True)

    result = await db.execute(stmt)
    markings = result.scalars().all()

    return markings


@router.post("/cui", response_model=CUIMarkingResponse)
async def mark_cui(
    req: CUIMarkingRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Mark asset as CUI.

    NARA CUI Notice 2022-02: every marking must identify the asset, the
    category, and the CUI designation. Reject empty markings that would
    render as a blank row in the registry and mislead stat counts.
    """
    if not (req.asset_id and (req.asset_id or "").strip()):
        raise HTTPException(status_code=400, detail="asset_id is required")
    if not (req.cui_category and (req.cui_category or "").strip()):
        raise HTTPException(status_code=400, detail="cui_category is required")
    if not (req.cui_designation and (req.cui_designation or "").strip()):
        raise HTTPException(status_code=400, detail="cui_designation is required")

    marking = CUIMarking(
        asset_id=req.asset_id,
        asset_type=req.asset_type,
        cui_category=req.cui_category,
        cui_designation=req.cui_designation,
        dissemination_controls=req.dissemination_controls,
        handling_instructions=req.handling_instructions,
        classification_authority=req.classification_authority,
        declassification_date=req.declassification_date,
        access_list=req.access_list,
        organization_id=org_id,
    )
    db.add(marking)
    await db.commit()
    await db.refresh(marking)

    return marking


@router.put("/cui/{marking_id}", response_model=CUIMarkingResponse)
async def update_cui_marking(
    marking_id: str,
    req: CUIMarkingRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Update CUI marking."""
    stmt = select(CUIMarking).where(
        and_(
            CUIMarking.id == marking_id,
            CUIMarking.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    marking = result.scalar_one_or_none()

    if not marking:
        raise HTTPException(status_code=404, detail="CUI marking not found")

    marking.cui_category = req.cui_category
    marking.cui_designation = req.cui_designation
    marking.dissemination_controls = req.dissemination_controls
    marking.handling_instructions = req.handling_instructions
    marking.access_list = req.access_list
    marking.declassification_date = req.declassification_date

    await db.commit()
    await db.refresh(marking)

    return marking


@router.get("/cui/audit")
async def audit_cui_handling(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """CUI handling compliance audit."""
    stmt = select(CUIMarking).where(
        CUIMarking.organization_id == org_id,
    )
    result = await db.execute(stmt)
    markings = result.scalars().all()

    now = datetime.now(timezone.utc)
    total = len(markings)
    active = sum(1 for m in markings if m.is_active)
    expired = sum(1 for m in markings if m.declassification_date and m.declassification_date < now)

    return {
        "total_cui": total,
        "active_cui": active,
        "expired": expired,
        "compliance_status": "compliant" if expired == 0 else "review_required",
    }


# ============================================================================
# CISA DIRECTIVES ENDPOINTS
# ============================================================================


@router.get("/cisa/directives", response_model=List[CISADirectiveResponse])
async def list_cisa_directives(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    active_only: bool = True,
):
    """List CISA BODs and Emergency Directives."""
    stmt = select(CISADirective).where(
        CISADirective.organization_id == org_id,
    )

    if active_only:
        stmt = stmt.where(CISADirective.status == "active")

    result = await db.execute(stmt)
    directives = result.scalars().all()

    return directives


@router.get("/cisa/directives/{directive_id}", response_model=CISADirectiveResponse)
async def get_cisa_directive(
    directive_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get CISA directive details."""
    stmt = select(CISADirective).where(
        and_(
            CISADirective.directive_id == directive_id,
            CISADirective.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    directive = result.scalar_one_or_none()

    if not directive:
        raise HTTPException(status_code=404, detail="Directive not found")

    return directive


@router.post("/cisa/directives/{directive_id}/check")
async def check_cisa_compliance(
    directive_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Check compliance with specific CISA directive (row id or code such as "BOD 22-01")."""
    stmt = select(CISADirective).where(
        and_(
            or_(CISADirective.id == directive_id, CISADirective.directive_id == directive_id),
            CISADirective.organization_id == org_id,
        ),
    )
    result = await db.execute(stmt)
    directive = result.scalar_one_or_none()

    if not directive:
        raise HTTPException(status_code=404, detail="Directive not found")

    manager = CISAComplianceManager(db, org_id)

    if directive.directive_type == "bod":
        compliance = await manager.check_bod_compliance(directive.directive_id)
    else:
        compliance = await manager.check_ed_compliance(directive.directive_id)

    return compliance


# ============================================================================
# DASHBOARD & REPORTING ENDPOINTS
# ============================================================================


@router.get("/dashboard", response_model=ComplianceDashboardStats)
async def get_dashboard_stats(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get compliance dashboard statistics."""
    # Frameworks
    stmt = select(ComplianceFramework).where(
        ComplianceFramework.organization_id == org_id,
    )
    result = await db.execute(stmt)
    frameworks = result.scalars().all()

    total_frameworks = len(frameworks)
    compliant_frameworks = sum(1 for f in frameworks if f.compliance_score >= 95)
    overall_score = (
        sum(f.compliance_score for f in frameworks) / total_frameworks
        if frameworks
        else 0
    )

    # Controls
    stmt = select(func.count(ComplianceControl.id)).where(
        ComplianceControl.organization_id == org_id,
    )
    result = await db.execute(stmt)
    control_count = result.scalar() or 0

    stmt = select(func.count(ComplianceControl.id)).where(
        and_(
            ComplianceControl.organization_id == org_id,
            ComplianceControl.status == "implemented",
        ),
    )
    result = await db.execute(stmt)
    implemented_count = result.scalar() or 0
    status_rows = (await db.execute(
        select(ComplianceControl.status, func.count(ComplianceControl.id))
        .where(ComplianceControl.organization_id == org_id)
        .group_by(ComplianceControl.status),
    )).all()
    by_status = {str(s or "not_implemented"): int(n) for s, n in status_rows}

    # POA&Ms
    now = datetime.now(timezone.utc)
    stmt = select(POAM).where(
        and_(
            POAM.organization_id == org_id,
            POAM.status != "completed",
            POAM.scheduled_completion_date < now,
        ),
    )
    result = await db.execute(stmt)
    overdue_poams = len(result.scalars().all())

    stmt = select(POAM).where(
        and_(
            POAM.organization_id == org_id,
            POAM.status != "completed",
            POAM.scheduled_completion_date >= now,
            POAM.scheduled_completion_date <= now + timedelta(days=7),
        ),
    )
    result = await db.execute(stmt)
    upcoming_poams = len(result.scalars().all())

    # Assessments
    stmt = select(ComplianceAssessment).where(
        and_(
            ComplianceAssessment.organization_id == org_id,
            ComplianceAssessment.status == "planned",
        ),
    )
    result = await db.execute(stmt)
    upcoming_assessments = len(result.scalars().all())

    # CUI
    stmt = select(CUIMarking).where(
        CUIMarking.organization_id == org_id,
    )
    result = await db.execute(stmt)
    cui_markings = result.scalars().all()
    total_cui = len(cui_markings)
    active_cui = sum(1 for m in cui_markings if m.is_active)

    # CISA
    stmt = select(CISADirective).where(
        and_(
            CISADirective.organization_id == org_id,
            CISADirective.status == "active",
        ),
    )
    result = await db.execute(stmt)
    active_directives = len(result.scalars().all())

    return {
        "frameworks_total": total_frameworks,
        "frameworks_compliant": compliant_frameworks,
        "overall_compliance_score": overall_score,
        "framework_scores": [
            {"name": f.short_name, "score": f.compliance_score} for f in frameworks
        ],
        "overdue_poams": overdue_poams,
        "upcoming_poams": upcoming_poams,
        "upcoming_assessments": upcoming_assessments,
        "control_status_breakdown": {
            **by_status,
            "total": control_count,
            "implemented": implemented_count,
        },
        # Stored assessment scores of the last 90 days (the trend chart read
        # a field the dashboard never returned).
        "trends": await _score_history(db, org_id, None, 90),
        "active_cisa_directives": active_directives,
        "cui_assets_total": total_cui,
        "cui_assets_active": active_cui,
        "last_updated": datetime.now(timezone.utc),
    }


@router.get("/score-history")
async def get_score_history(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    framework_id: Optional[str] = None,
    days: int = Query(90, ge=1, le=365),
):
    """Get compliance score history and trends."""
    history = await _score_history(db, org_id, framework_id, days)
    return {
        "history": history,
        "period_days": days,
        "assessment_count": len(history),
    }


async def _score_history(
    db: AsyncSession, org_id: str, framework_id: Optional[str], days: int,
) -> List[Dict[str, Any]]:
    """Scores of the stored assessments in the window, oldest first.

    Uses the score the assessment stored (``results.compliance_score``);
    older rows without one fall back to satisfied / (satisfied + other than
    satisfied). The previous code read ``control_count``, which the model
    does not have, so any stored assessment made this a 500.
    """
    stmt = select(ComplianceAssessment).where(
        ComplianceAssessment.organization_id == org_id,
        ComplianceAssessment.assessment_type != "conmon",
        ComplianceAssessment.assessment_date >= datetime.now(timezone.utc) - timedelta(days=days),
    )
    if framework_id:
        stmt = stmt.where(ComplianceAssessment.framework_id == framework_id)
    stmt = stmt.order_by(ComplianceAssessment.assessment_date.asc()).limit(1000)
    history = []
    for a in (await db.execute(stmt)).scalars().all():
        results = a.results or {}
        judged = (a.satisfied_count or 0) + (a.other_than_satisfied_count or 0)
        stored = results.get("compliance_score")
        score = float(stored) if stored is not None else (
            round((a.satisfied_count or 0) / judged * 100, 2) if judged else 0.0)
        history.append({
            "date": a.assessment_date.isoformat() if a.assessment_date else None,
            "framework_id": a.framework_id,
            "score": score,
            "satisfied": a.satisfied_count or 0,
            "failed": a.other_than_satisfied_count or 0,
            "controls": results.get("total_controls", judged),
        })
    return history
