"""
Compliance REST API Endpoints

Complete API for managing compliance frameworks, controls, assessments, and evidence.
Supports FedRAMP, NIST, CMMC, SOC 2, HIPAA, PCI-DSS, DFARS, and CISA compliance.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Query
from src.api.deps import CurrentUser, DatabaseSession
from sqlalchemy import select, and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.api.deps import get_current_active_user as get_current_user
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
from src.compliance.engine import (
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


# ============================================================================
# FRAMEWORKS ENDPOINTS
# ============================================================================


@router.get("/frameworks", response_model=List[ComplianceFrameworkResponse])
async def list_frameworks(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        ComplianceFramework.organization_id == user.organization_id
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get framework details with control summary."""
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    return framework


@router.post("/frameworks/{framework_id}/assess", response_model=FrameworkAssessmentResponse)
async def trigger_assessment(
    framework_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Trigger full compliance assessment for framework.

    Runs assessment across all controls and returns comprehensive results.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    # Trigger assessment task
    run_compliance_assessment.delay(framework_id, user.organization_id)

    # Run assessment synchronously for immediate response
    engine = ComplianceEngine(db, user.organization_id)
    assessment = await engine.assess_framework(framework_id)

    return assessment


@router.get("/frameworks/{framework_id}/gaps", response_model=ControlGapAnalysisResponse)
async def get_control_gaps(
    framework_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Get control implementation gaps for framework.

    Returns gap list prioritized by risk and priority.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    engine = ComplianceEngine(db, user.organization_id)
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Generate System Security Plan (SSP) for framework.

    Returns SSP document with all control implementations organized by family.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    engine = ComplianceEngine(db, user.organization_id)
    ssp = await engine.generate_ssp(framework_id)

    return ssp


@router.get("/frameworks/{framework_id}/report")
async def get_framework_report(
    framework_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get comprehensive framework compliance report."""
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    engine = ComplianceEngine(db, user.organization_id)
    ssp = await engine.generate_ssp(framework_id)
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
async def run_continuous_monitoring(
    framework_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Run FedRAMP Continuous Monitoring (ConMon) checks.

    Returns ConMon status with control assessment results.
    """
    stmt = select(ComplianceFramework).where(
        and_(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == user.organization_id,
            ComplianceFramework.short_name == "fedramp",
        )
    )
    result = await db.execute(stmt)
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="FedRAMP framework not found")

    # Trigger ConMon task
    run_continuous_monitoring.delay(user.organization_id)

    manager = FedRAMPManager(db, user.organization_id)
    conmon_result = await manager.run_continuous_monitoring()

    return conmon_result


# ============================================================================
# CONTROLS ENDPOINTS
# ============================================================================


@router.get("/controls", response_model=List[ComplianceControlResponse])
async def list_controls(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    framework_id: Optional[str] = None,
    family: Optional[str] = None,
    status: Optional[str] = None,
    baseline: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
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
        ComplianceControl.organization_id == user.organization_id
    )

    if framework_id:
        stmt = stmt.where(ComplianceControl.framework_id == framework_id)
    if family:
        stmt = stmt.where(ComplianceControl.control_family == family)
    if status:
        stmt = stmt.where(ComplianceControl.status == status)
    if baseline:
        stmt = stmt.where(ComplianceControl.baseline == baseline)

    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    controls = result.scalars().all()

    return controls


@router.get("/controls/{control_id}", response_model=ComplianceControlResponse)
async def get_control(
    control_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get control details with evidence."""
    stmt = select(ComplianceControl).where(
        and_(
            ComplianceControl.id == control_id,
            ComplianceControl.organization_id == user.organization_id,
        )
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update control implementation status."""
    stmt = select(ComplianceControl).where(
        and_(
            ComplianceControl.id == control_id,
            ComplianceControl.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    control = result.scalar_one_or_none()

    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    control.status = req.status
    if req.implementation_status is not None:
        control.implementation_status = req.implementation_status
    if req.responsible_party:
        control.responsible_party = req.responsible_party
    if req.implementation_details:
        control.implementation_details = req.implementation_details

    await db.commit()
    await db.refresh(control)

    return control


@router.post("/controls/{control_id}/assess")
async def run_control_assessment(
    control_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Run automated check for specific control."""
    stmt = select(ComplianceControl).where(
        and_(
            ComplianceControl.id == control_id,
            ComplianceControl.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    control = result.scalar_one_or_none()

    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    nist_mgr = NISTManager(db, user.organization_id)
    check_result = await nist_mgr.automated_control_check(control.control_id)

    return check_result


@router.get("/controls/cross-map")
async def cross_map_controls(
    db: DatabaseSession = None,
    source_framework_id: str = Query(...),
    target_framework_id: str = Query(...),
    current_user: CurrentUser = None,
):
    """Get cross-framework control mapping."""
    engine = ComplianceEngine(db, user.organization_id)
    mapping = await engine.cross_map_controls(source_framework_id, target_framework_id)

    return mapping


# ============================================================================
# POA&M ENDPOINTS
# ============================================================================


@router.get("/poams", response_model=List[POAMResponse])
async def list_poams(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
    stmt = select(POAM).where(POAM.organization_id == user.organization_id)

    if status:
        stmt = stmt.where(POAM.status == status)
    if risk_level:
        stmt = stmt.where(POAM.risk_level == risk_level)

    if overdue_only:
        now = datetime.utcnow()
        stmt = stmt.where(
            and_(
                POAM.scheduled_completion_date < now,
                POAM.status != "completed",
            )
        )

    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    poams = result.scalars().all()

    return poams


@router.post("/poams", response_model=POAMResponse)
async def create_poam(
    req: POAMCreateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Create new POA&M."""
    poam = POAM(
        control_id_ref=req.control_id_ref,
        weakness_name=req.weakness_name,
        weakness_description=req.weakness_description,
        weakness_source=req.weakness_source,
        risk_level=req.risk_level,
        scheduled_completion_date=req.scheduled_completion_date,
        resources_required=req.resources_required,
        cost_estimate=req.cost_estimate,
        assigned_to=req.assigned_to,
        organization_id=user.organization_id,
    )
    db.add(poam)
    await db.commit()
    await db.refresh(poam)

    return poam


@router.get("/poams/{poam_id}", response_model=POAMResponse)
async def get_poam(
    poam_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get POA&M details."""
    stmt = select(POAM).where(
        and_(
            POAM.id == poam_id,
            POAM.organization_id == user.organization_id,
        )
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update POA&M."""
    stmt = select(POAM).where(
        and_(
            POAM.id == poam_id,
            POAM.organization_id == user.organization_id,
        )
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


@router.get("/poams/overdue")
async def get_overdue_poams(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get overdue POA&Ms."""
    now = datetime.utcnow()
    stmt = select(POAM).where(
        and_(
            POAM.organization_id == user.organization_id,
            POAM.scheduled_completion_date < now,
            POAM.status != "completed",
        )
    )
    result = await db.execute(stmt)
    overdue_poams = result.scalars().all()

    return {"overdue_count": len(overdue_poams), "poams": overdue_poams}


@router.get("/poams/report")
async def get_poam_report(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get POA&M summary report."""
    stmt = select(POAM).where(POAM.organization_id == user.organization_id)
    result = await db.execute(stmt)
    all_poams = result.scalars().all()

    now = datetime.utcnow()
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


# ============================================================================
# EVIDENCE ENDPOINTS
# ============================================================================


@router.get("/evidence", response_model=List[ComplianceEvidenceResponse])
async def list_evidence(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    control_id_ref: Optional[str] = None,
    evidence_type: Optional[str] = None,
    review_status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List evidence with filtering."""
    stmt = select(ComplianceEvidence).where(
        ComplianceEvidence.organization_id == user.organization_id
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
    db: DatabaseSession = None,
    description: Optional[str] = None,
    content: Optional[str] = None,
    file_path: Optional[str] = None,
    current_user: CurrentUser = None,
):
    """Upload compliance evidence."""
    evidence = ComplianceEvidence(
        control_id_ref=control_id_ref,
        evidence_type=evidence_type,
        title=title,
        description=description,
        content=content,
        file_path=file_path,
        collected_at=datetime.utcnow(),
        collected_by=user.id,
        organization_id=user.organization_id,
    )
    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)

    return evidence


@router.get("/evidence/{evidence_id}", response_model=ComplianceEvidenceResponse)
async def get_evidence(
    evidence_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get evidence details."""
    stmt = select(ComplianceEvidence).where(
        and_(
            ComplianceEvidence.id == evidence_id,
            ComplianceEvidence.organization_id == user.organization_id,
        )
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
    reviewed_by: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Review and approve evidence."""
    stmt = select(ComplianceEvidence).where(
        and_(
            ComplianceEvidence.id == evidence_id,
            ComplianceEvidence.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    evidence = result.scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    evidence.review_status = review_status
    evidence.reviewed_by = reviewed_by
    evidence.reviewed_at = datetime.utcnow()

    await db.commit()
    await db.refresh(evidence)

    return evidence


# ============================================================================
# CUI ENDPOINTS
# ============================================================================


@router.get("/cui", response_model=List[CUIMarkingResponse])
async def list_cui_markings(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    active_only: bool = True,
):
    """List CUI markings."""
    stmt = select(CUIMarking).where(
        CUIMarking.organization_id == user.organization_id
    )

    if active_only:
        stmt = stmt.where(CUIMarking.is_active == True)

    result = await db.execute(stmt)
    markings = result.scalars().all()

    return markings


@router.post("/cui", response_model=CUIMarkingResponse)
async def mark_cui(
    req: CUIMarkingRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Mark asset as CUI."""
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
        organization_id=user.organization_id,
    )
    db.add(marking)
    await db.commit()
    await db.refresh(marking)

    return marking


@router.put("/cui/{marking_id}", response_model=CUIMarkingResponse)
async def update_cui_marking(
    marking_id: str,
    req: CUIMarkingRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update CUI marking."""
    stmt = select(CUIMarking).where(
        and_(
            CUIMarking.id == marking_id,
            CUIMarking.organization_id == user.organization_id,
        )
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """CUI handling compliance audit."""
    stmt = select(CUIMarking).where(
        CUIMarking.organization_id == user.organization_id
    )
    result = await db.execute(stmt)
    markings = result.scalars().all()

    now = datetime.utcnow()
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    active_only: bool = True,
):
    """List CISA BODs and Emergency Directives."""
    stmt = select(CISADirective).where(
        CISADirective.organization_id == user.organization_id
    )

    if active_only:
        stmt = stmt.where(CISADirective.status == "active")

    result = await db.execute(stmt)
    directives = result.scalars().all()

    return directives


@router.get("/cisa/directives/{directive_id}", response_model=CISADirectiveResponse)
async def get_cisa_directive(
    directive_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get CISA directive details."""
    stmt = select(CISADirective).where(
        and_(
            CISADirective.directive_id == directive_id,
            CISADirective.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    directive = result.scalar_one_or_none()

    if not directive:
        raise HTTPException(status_code=404, detail="Directive not found")

    return directive


@router.post("/cisa/directives/{directive_id}/check")
async def check_cisa_compliance(
    directive_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Check compliance with specific CISA directive."""
    stmt = select(CISADirective).where(
        and_(
            CISADirective.directive_id == directive_id,
            CISADirective.organization_id == user.organization_id,
        )
    )
    result = await db.execute(stmt)
    directive = result.scalar_one_or_none()

    if not directive:
        raise HTTPException(status_code=404, detail="Directive not found")

    manager = CISAComplianceManager(db, user.organization_id)

    if directive.directive_type == "bod":
        compliance = await manager.check_bod_compliance(directive_id)
    else:
        compliance = await manager.check_ed_compliance(directive_id)

    return compliance


# ============================================================================
# DASHBOARD & REPORTING ENDPOINTS
# ============================================================================


@router.get("/dashboard", response_model=ComplianceDashboardStats)
async def get_dashboard_stats(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get compliance dashboard statistics."""
    # Frameworks
    stmt = select(ComplianceFramework).where(
        ComplianceFramework.organization_id == user.organization_id
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
        ComplianceControl.organization_id == user.organization_id
    )
    result = await db.execute(stmt)
    control_count = result.scalar() or 0

    stmt = select(func.count(ComplianceControl.id)).where(
        and_(
            ComplianceControl.organization_id == user.organization_id,
            ComplianceControl.status == "implemented",
        )
    )
    result = await db.execute(stmt)
    implemented_count = result.scalar() or 0

    # POA&Ms
    now = datetime.utcnow()
    stmt = select(POAM).where(
        and_(
            POAM.organization_id == user.organization_id,
            POAM.status != "completed",
            POAM.scheduled_completion_date < now,
        )
    )
    result = await db.execute(stmt)
    overdue_poams = len(result.scalars().all())

    stmt = select(POAM).where(
        and_(
            POAM.organization_id == user.organization_id,
            POAM.status != "completed",
            POAM.scheduled_completion_date >= now,
            POAM.scheduled_completion_date <= now + timedelta(days=7),
        )
    )
    result = await db.execute(stmt)
    upcoming_poams = len(result.scalars().all())

    # Assessments
    stmt = select(ComplianceAssessment).where(
        and_(
            ComplianceAssessment.organization_id == user.organization_id,
            ComplianceAssessment.status == "planned",
        )
    )
    result = await db.execute(stmt)
    upcoming_assessments = len(result.scalars().all())

    # CUI
    stmt = select(CUIMarking).where(
        CUIMarking.organization_id == user.organization_id
    )
    result = await db.execute(stmt)
    cui_markings = result.scalars().all()
    total_cui = len(cui_markings)
    active_cui = sum(1 for m in cui_markings if m.is_active)

    # CISA
    stmt = select(CISADirective).where(
        and_(
            CISADirective.organization_id == user.organization_id,
            CISADirective.status == "active",
        )
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
            "total": control_count,
            "implemented": implemented_count,
        },
        "active_cisa_directives": active_directives,
        "cui_assets_total": total_cui,
        "cui_assets_active": active_cui,
        "last_updated": datetime.utcnow(),
    }


@router.get("/score-history")
async def get_score_history(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    framework_id: Optional[str] = None,
    days: int = Query(90, ge=1, le=365),
):
    """Get compliance score history and trends."""
    stmt = select(ComplianceAssessment).where(
        and_(
            ComplianceAssessment.organization_id == user.organization_id,
            ComplianceAssessment.assessment_date
            >= datetime.utcnow() - timedelta(days=days),
        )
    )

    if framework_id:
        stmt = stmt.where(ComplianceAssessment.framework_id == framework_id)

    result = await db.execute(stmt)
    assessments = result.scalars().all()

    history = [
        {
            "date": a.assessment_date.isoformat(),
            "framework_id": a.framework_id,
            "score": (a.satisfied_count / a.findings_count * 100)
            if a.findings_count > 0
            else 0,
        }
        for a in assessments
    ]

    return {
        "history": history,
        "period_days": days,
        "assessment_count": len(assessments),
    }
