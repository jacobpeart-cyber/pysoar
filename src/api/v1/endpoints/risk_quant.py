"""Risk Quantification API endpoints

REST API for FAIR analysis, risk management, control effectiveness, and BIA assessment.
"""

import json
import math
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, APIRouter, Body, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.models.user import User, UserRole
from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.risk_quant.engine import (
    FAIR_MODEL_DESCRIPTION,
    ControlEffectivenessAnalyzer,
    FAIREngine,
    FAIRInputError,
    RiskAggregator,
    simulate_analysis,
    simulate_portfolio,
    store_result,
)
from src.risk_quant.models import (
    BusinessImpactAssessment,
    FAIRAnalysis,
    RiskControl,
    RiskRegister,
    RiskScenario,
)
from src.risk_quant.tasks import (
    run_fair_simulation,
)
from src.schemas.risk_quant import (
    BusinessImpactAssessmentCreate,
    BusinessImpactAssessmentListResponse,
    BusinessImpactAssessmentResponse,
    BusinessImpactAssessmentUpdate,
    ControlROIResponse,
    FAIRAnalysisCreate,
    FAIRAnalysisListResponse,
    FAIRAnalysisResponse,
    FAIRResultsResponse,
    RiskControlCreate,
    RiskControlListResponse,
    RiskControlResponse,
    RiskControlUpdate,
    RiskDashboardResponse,
    RiskHeatmapResponse,
    RiskRegisterCreate,
    RiskRegisterListResponse,
    RiskRegisterResponse,
    RiskRegisterUpdate,
    RiskScenarioCreate,
    RiskScenarioListResponse,
    RiskScenarioResponse,
    RiskScenarioUpdate,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/risk-quantification", tags=["Risk Quantification"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


# Helper Functions
def _fair_input_422(exc: FAIRInputError) -> HTTPException:
    """422 naming the stored FAIR input that is missing or inconsistent."""
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"error": "invalid_fair_input", "field": exc.field, "detail": exc.detail},
    )


async def _latest_completed_analyses(db: AsyncSession, org_id: str) -> list[FAIRAnalysis]:
    """The most recent completed FAIRAnalysis of each scenario in the tenant.

    Portfolio figures use one analysis per scenario; several analyses of the
    same scenario are revisions, not separate risks, and summing them would
    count the scenario twice.
    """
    rows = (await db.execute(
        select(FAIRAnalysis)
        .where(
            FAIRAnalysis.organization_id == org_id,
            FAIRAnalysis.completed_at.is_not(None),
        )
        .order_by(FAIRAnalysis.scenario_id, FAIRAnalysis.completed_at.desc(), FAIRAnalysis.created_at.desc())
    )).scalars().all()
    latest: dict[str, FAIRAnalysis] = {}
    for row in rows:
        latest.setdefault(row.scenario_id, row)
    return list(latest.values())


async def get_risk_scenario_or_404(
    db: AsyncSession, scenario_id: str, org_id: str
) -> RiskScenario:
    """Get RiskScenario by ID or raise 404"""
    stmt = select(RiskScenario).where(RiskScenario.id == scenario_id)
    stmt = stmt.where(RiskScenario.organization_id == org_id)
    result = await db.execute(stmt)
    scenario = result.scalar_one_or_none()
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk scenario not found",
        )
    return scenario


async def get_fair_analysis_or_404(
    db: AsyncSession, analysis_id: str, org_id: str
) -> FAIRAnalysis:
    """Get FAIRAnalysis by ID or raise 404"""
    stmt = select(FAIRAnalysis).where(FAIRAnalysis.id == analysis_id)
    stmt = stmt.where(FAIRAnalysis.organization_id == org_id)
    result = await db.execute(stmt)
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="FAIR analysis not found",
        )
    return analysis


async def get_risk_register_or_404(
    db: AsyncSession, register_id: str, org_id: str
) -> RiskRegister:
    """Get RiskRegister by ID or raise 404"""
    stmt = select(RiskRegister).where(RiskRegister.id == register_id)
    stmt = stmt.where(RiskRegister.organization_id == org_id)
    result = await db.execute(stmt)
    register = result.scalar_one_or_none()
    if not register:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk register not found",
        )
    return register


async def get_risk_control_or_404(
    db: AsyncSession, control_id: str, org_id: str
) -> RiskControl:
    """Get RiskControl by ID or raise 404"""
    stmt = select(RiskControl).where(RiskControl.id == control_id)
    stmt = stmt.where(RiskControl.organization_id == org_id)
    result = await db.execute(stmt)
    control = result.scalar_one_or_none()
    if not control:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk control not found",
        )
    return control


async def get_bia_or_404(
    db: AsyncSession,
    bia_id: str,
    org_id: str,
) -> BusinessImpactAssessment:
    """Get BusinessImpactAssessment by ID or raise 404"""
    stmt = select(BusinessImpactAssessment).where(BusinessImpactAssessment.id == bia_id)
    stmt = stmt.where(BusinessImpactAssessment.organization_id == org_id)
    result = await db.execute(stmt)
    bia = result.scalar_one_or_none()
    if not bia:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Business Impact Assessment not found",
        )
    return bia


# Risk Scenario Endpoints
@router.get(
    "/scenarios",
    response_model=RiskScenarioListResponse,
)
async def list_risk_scenarios(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    threat_actor: Optional[str] = None,
):
    """List risk scenarios with filtering and pagination"""
    query = select(RiskScenario).where(
        RiskScenario.organization_id == org_id
    )

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (RiskScenario.name.ilike(search_filter))
            | (RiskScenario.description.ilike(search_filter))
            | (RiskScenario.asset_name.ilike(search_filter))
        )

    if status_filter:
        query = query.where(RiskScenario.status == status_filter)

    if threat_actor:
        query = query.where(RiskScenario.threat_actor == threat_actor)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(RiskScenario.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    scenarios = list(result.scalars().all())

    return RiskScenarioListResponse(
        items=[RiskScenarioResponse.model_validate(s) for s in scenarios],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post(
    "/scenarios",
    response_model=RiskScenarioResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_risk_scenario(
    scenario_data: RiskScenarioCreate,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new risk scenario"""
    scenario = RiskScenario(
        organization_id=org_id,
        name=scenario_data.name,
        description=scenario_data.description,
        asset_id=scenario_data.asset_id,
        asset_name=scenario_data.asset_name,
        asset_value_usd=scenario_data.asset_value_usd,
        threat_actor=scenario_data.threat_actor,
        threat_type=scenario_data.threat_type,
        vulnerability_exploited=scenario_data.vulnerability_exploited,
        loss_type=scenario_data.loss_type,
        analyst_id=current_user.id,
        confidence_level=scenario_data.confidence_level,
        status="draft",
    )

    db.add(scenario)
    await db.flush()
    await db.refresh(scenario)

    # No "high loss" incident here: the asset value is not a loss expectancy,
    # and the automation hook opened an Incident claiming the asset value as
    # the scenario's loss (without an organisation). Loss figures exist only
    # once a FAIR analysis with analyst inputs has been simulated.
    return RiskScenarioResponse.model_validate(scenario)


@router.get("/scenarios/{scenario_id}", response_model=RiskScenarioResponse)
async def get_risk_scenario(
    scenario_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get a risk scenario by ID"""
    scenario = await get_risk_scenario_or_404(
        db, scenario_id, org_id
    )
    return RiskScenarioResponse.model_validate(scenario)


@router.patch("/scenarios/{scenario_id}", response_model=RiskScenarioResponse)
async def update_risk_scenario(
    scenario_id: str,
    scenario_data: RiskScenarioUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update a risk scenario"""
    scenario = await get_risk_scenario_or_404(
        db, scenario_id, org_id
    )

    update_data = scenario_data.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in update_data.items():
        setattr(scenario, key, value)

    await db.flush()
    await db.refresh(scenario)

    return RiskScenarioResponse.model_validate(scenario)


@router.delete("/scenarios/{scenario_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_risk_scenario(
    scenario_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Delete a risk scenario"""
    scenario = await get_risk_scenario_or_404(
        db, scenario_id, org_id
    )
    await db.delete(scenario)
    await db.flush()


# FAIR Analysis Endpoints
@router.get("/fair-analyses", response_model=FAIRAnalysisListResponse)
async def list_fair_analyses(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    scenario_id: Optional[str] = None,
):
    """List FAIR analyses"""
    query = select(FAIRAnalysis).where(
        FAIRAnalysis.organization_id == org_id
    )

    if scenario_id:
        query = query.where(FAIRAnalysis.scenario_id == scenario_id)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(FAIRAnalysis.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    analyses = list(result.scalars().all())

    return FAIRAnalysisListResponse(
        items=[FAIRAnalysisResponse.model_validate(a) for a in analyses],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post(
    "/fair-analyses",
    response_model=FAIRAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_fair_analysis(
    analysis_data: FAIRAnalysisCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new FAIR analysis"""
    # Verify scenario exists in this tenant
    await get_risk_scenario_or_404(
        db, analysis_data.scenario_id, org_id
    )

    analysis = FAIRAnalysis(
        organization_id=org_id,
        scenario_id=analysis_data.scenario_id,
        tef_min=analysis_data.tef_min,
        tef_mode=analysis_data.tef_mode,
        tef_max=analysis_data.tef_max,
        vuln_min=analysis_data.vuln_min,
        vuln_mode=analysis_data.vuln_mode,
        vuln_max=analysis_data.vuln_max,
        tcap_min=analysis_data.tcap_min,
        tcap_mode=analysis_data.tcap_mode,
        tcap_max=analysis_data.tcap_max,
        rs_min=analysis_data.rs_min,
        rs_mode=analysis_data.rs_mode,
        rs_max=analysis_data.rs_max,
        lm_min=analysis_data.lm_min,
        lm_mode=analysis_data.lm_mode,
        lm_max=analysis_data.lm_max,
        primary_loss_min=analysis_data.primary_loss_min,
        primary_loss_mode=analysis_data.primary_loss_mode,
        primary_loss_max=analysis_data.primary_loss_max,
        secondary_loss_min=analysis_data.secondary_loss_min,
        secondary_loss_mode=analysis_data.secondary_loss_mode,
        secondary_loss_max=analysis_data.secondary_loss_max,
        secondary_loss_event_frequency=analysis_data.secondary_loss_event_frequency,
        simulation_iterations=analysis_data.simulation_iterations,
    )

    db.add(analysis)
    await db.flush()
    await db.refresh(analysis)
    response = FAIRAnalysisResponse.model_validate(analysis)
    # Commit before queueing so the worker can see the row it is asked to
    # simulate (it used to be queued before the commit and race it).
    await db.commit()

    # Queue simulation task (same stored inputs and seed as run-simulation)
    run_fair_simulation.delay(response.id, org_id)

    return response


@router.get("/fair-analyses/{analysis_id}", response_model=FAIRAnalysisResponse)
async def get_fair_analysis(
    analysis_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get a FAIR analysis by ID"""
    analysis = await get_fair_analysis_or_404(
        db, analysis_id, org_id
    )
    return FAIRAnalysisResponse.model_validate(analysis)


@router.post(
    "/fair-analyses/{analysis_id}/run-simulation",
    response_model=FAIRResultsResponse,
)
async def run_fair_simulation_endpoint(
    analysis_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Run the FAIR Monte Carlo simulation over the analysis's stored inputs.

    Nothing is defaulted: a missing or inconsistent stored estimate is a 422
    naming it (``detail.field``). The run is seeded per analysis, so repeating
    it reproduces the stored figures.
    """
    analysis = await get_fair_analysis_or_404(
        db, analysis_id, org_id
    )

    try:
        result = simulate_analysis(analysis)
    except FAIRInputError as exc:
        raise _fair_input_422(exc) from None

    store_result(analysis, result, datetime.now(timezone.utc))
    await db.flush()
    await db.refresh(analysis)

    report = FAIREngine().generate_risk_report(result)

    return FAIRResultsResponse(
        ale_mean=result.ale_mean,
        ale_p10=result.ale_p10,
        ale_p50=result.ale_p50,
        ale_p90=result.ale_p90,
        ale_p99=result.ale_p99,
        derived_vulnerability=result.derived_vulnerability,
        iterations=result.iterations,
        approximation=result.approximation,
        model=result.model,
        **report,
    )


@router.get(
    "/fair-analyses/{analysis_id}/loss-exceedance-curve",
    response_model=None,
)
async def get_loss_exceedance_curve(
    analysis_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get loss exceedance curve for FAIR analysis"""
    analysis = await get_fair_analysis_or_404(
        db, analysis_id, org_id
    )

    if not analysis.loss_exceedance_curve:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Simulation not completed",
        )

    return safe_json_loads(analysis.loss_exceedance_curve, {})


# Risk Register Endpoints
@router.get("/risk-registers", response_model=RiskRegisterListResponse)
async def list_risk_registers(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    category: Optional[str] = None,
    owner_id: Optional[str] = None,
):
    """List risk registers"""
    query = select(RiskRegister).where(
        RiskRegister.organization_id == org_id
    )

    if category:
        query = query.where(RiskRegister.risk_category == category)

    if owner_id:
        query = query.where(RiskRegister.owner_id == owner_id)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(RiskRegister.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    registers = list(result.scalars().all())

    return RiskRegisterListResponse(
        items=[RiskRegisterResponse.model_validate(r) for r in registers],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post(
    "/risk-registers",
    response_model=RiskRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_risk_register(
    register_data: RiskRegisterCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new risk register entry"""
    register = RiskRegister(
        organization_id=org_id,
        name=register_data.name,
        description=register_data.description,
        risk_category=register_data.risk_category,
        inherent_risk_score=register_data.inherent_risk_score,
        residual_risk_score=register_data.residual_risk_score,
        risk_treatment=register_data.risk_treatment,
        treatment_plan=register_data.treatment_plan,
        control_effectiveness=register_data.control_effectiveness,
        owner_id=register_data.owner_id,
        review_frequency_days=register_data.review_frequency_days,
        ale_annual_usd=register_data.ale_annual_usd,
        risk_appetite_threshold_usd=register_data.risk_appetite_threshold_usd,
        is_within_appetite=register_data.ale_annual_usd
        <= register_data.risk_appetite_threshold_usd,
        next_review=datetime.now(timezone.utc)
        + timedelta(days=register_data.review_frequency_days),
    )

    db.add(register)
    await db.flush()
    await db.refresh(register)

    return RiskRegisterResponse.model_validate(register)


@router.get("/risk-registers/{register_id}", response_model=RiskRegisterResponse)
async def get_risk_register(
    register_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get a risk register entry by ID"""
    register = await get_risk_register_or_404(
        db, register_id, org_id
    )
    return RiskRegisterResponse.model_validate(register)


@router.patch("/risk-registers/{register_id}", response_model=RiskRegisterResponse)
async def update_risk_register(
    register_id: str,
    register_data: RiskRegisterUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update a risk register entry"""
    register = await get_risk_register_or_404(
        db, register_id, org_id
    )

    update_data = register_data.model_dump(exclude_unset=True, exclude_none=True)

    for key, value in update_data.items():
        setattr(register, key, value)

    # Update appetite status
    register.is_within_appetite = (
        register.ale_annual_usd <= register.risk_appetite_threshold_usd
    )

    await db.flush()
    await db.refresh(register)

    return RiskRegisterResponse.model_validate(register)


@router.delete("/risk-registers/{register_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_risk_register(
    register_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Delete a risk register entry"""
    register = await get_risk_register_or_404(
        db, register_id, org_id
    )
    await db.delete(register)
    await db.flush()


# Risk Control Endpoints
@router.get("/controls", response_model=RiskControlListResponse)
async def list_risk_controls(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    control_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """List risk controls"""
    query = select(RiskControl).where(
        RiskControl.organization_id == org_id
    )

    if control_type:
        query = query.where(RiskControl.control_type == control_type)

    if status_filter:
        query = query.where(RiskControl.implementation_status == status_filter)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(RiskControl.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    controls = list(result.scalars().all())

    return RiskControlListResponse(
        items=[RiskControlResponse.model_validate(c) for c in controls],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post(
    "/controls",
    response_model=RiskControlResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_risk_control(
    control_data: RiskControlCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new risk control"""
    if control_data.risk_register_id:
        register_result = await db.execute(
            select(RiskRegister.id).where(
                and_(
                    RiskRegister.id == control_data.risk_register_id,
                    RiskRegister.organization_id == org_id,
                )
            )
        )
        if register_result.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "invalid_field",
                    "field": "risk_register_id",
                    "detail": "risk_register_id is not a risk register of this organisation",
                },
            )
    control = RiskControl(
        organization_id=org_id,
        risk_register_id=control_data.risk_register_id,
        control_name=control_data.control_name,
        control_type=control_data.control_type,
        implementation_status=control_data.implementation_status,
        effectiveness_score=control_data.effectiveness_score,
        cost_annual_usd=control_data.cost_annual_usd,
        frameworks_mapped=json.dumps(control_data.frameworks_mapped)
        if control_data.frameworks_mapped
        else None,
    )

    db.add(control)
    await db.flush()
    await db.refresh(control)

    return RiskControlResponse.model_validate(control)


@router.get("/controls/{control_id}", response_model=RiskControlResponse)
async def get_risk_control(
    control_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get a risk control by ID"""
    control = await get_risk_control_or_404(
        db, control_id, org_id
    )
    return RiskControlResponse.model_validate(control)


@router.patch("/controls/{control_id}", response_model=RiskControlResponse)
async def update_risk_control(
    control_id: str,
    control_data: RiskControlUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update a risk control"""
    control = await get_risk_control_or_404(
        db, control_id, org_id
    )

    update_data = control_data.model_dump(exclude_unset=True, exclude_none=True)

    for key, value in update_data.items():
        setattr(control, key, value)

    await db.flush()
    await db.refresh(control)

    return RiskControlResponse.model_validate(control)


@router.delete("/controls/{control_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_risk_control(
    control_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Delete a risk control"""
    control = await get_risk_control_or_404(
        db, control_id, org_id
    )
    await db.delete(control)
    await db.flush()


@router.post("/controls/{control_id}/audit", response_model=ControlROIResponse)
async def audit_control_effectiveness(
    control_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Calculate the control's ROI from its stored register ALE, effectiveness and cost.

    This is a financial calculation, not a control test: ``last_tested`` and
    ``test_result`` are left alone (they used to be stamped "passed" here).
    """
    control = await get_risk_control_or_404(db, control_id, org_id)
    register = await get_risk_register_or_404(db, control.risk_register_id, org_id)

    analyzer = ControlEffectivenessAnalyzer()

    # Estimate residual ALE with control
    effectiveness = control.effectiveness_score / 100.0
    mitigated_ale = register.ale_annual_usd * (1 - effectiveness)

    roi_data = analyzer.assess_control_roi(
        register.ale_annual_usd, mitigated_ale, control.cost_annual_usd
    )

    # Update control
    control.roi_percentage = roi_data["roi_5yr_percent"]

    await db.flush()
    await db.refresh(control)

    return ControlROIResponse(
        control_name=control.control_name,
        annual_benefit_usd=roi_data["annual_benefit"],
        annual_cost_usd=roi_data["annual_cost"],
        net_annual_benefit_usd=roi_data["net_annual_benefit"],
        roi_5_year_percent=roi_data["roi_5yr_percent"],
        payback_period_months=roi_data["payback_period_months"],
        effective=roi_data["effective"],
    )


# Business Impact Assessment Endpoints
@router.get("/bias", response_model=BusinessImpactAssessmentListResponse)
async def list_bias(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    criticality: Optional[str] = None,
):
    """List Business Impact Assessments"""
    query = select(BusinessImpactAssessment).where(
        BusinessImpactAssessment.organization_id == org_id
    )

    if criticality:
        query = query.where(BusinessImpactAssessment.criticality == criticality)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(BusinessImpactAssessment.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    bias = list(result.scalars().all())

    return BusinessImpactAssessmentListResponse(
        items=[BusinessImpactAssessmentResponse.model_validate(b) for b in bias],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post(
    "/bias",
    response_model=BusinessImpactAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_bia(
    bia_data: BusinessImpactAssessmentCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new Business Impact Assessment"""
    bia = BusinessImpactAssessment(
        organization_id=org_id,
        asset_name=bia_data.asset_name,
        asset_type=bia_data.asset_type,
        business_unit=bia_data.business_unit,
        criticality=bia_data.criticality,
        rto_hours=bia_data.rto_hours,
        rpo_hours=bia_data.rpo_hours,
        mtpd_hours=bia_data.mtpd_hours,
        financial_impact_per_hour_usd=bia_data.financial_impact_per_hour_usd,
        reputational_impact_score=bia_data.reputational_impact_score,
        regulatory_impact_score=bia_data.regulatory_impact_score,
        dependencies=json.dumps(bia_data.dependencies)
        if bia_data.dependencies
        else None,
        single_point_of_failure=bia_data.single_point_of_failure,
    )

    db.add(bia)
    await db.flush()
    await db.refresh(bia)

    return BusinessImpactAssessmentResponse.model_validate(bia)


@router.get("/bias/{bia_id}", response_model=BusinessImpactAssessmentResponse)
async def get_bia(
    bia_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get a BIA by ID"""
    bia = await get_bia_or_404(
        db, bia_id, org_id
    )
    return BusinessImpactAssessmentResponse.model_validate(bia)


@router.patch("/bias/{bia_id}", response_model=BusinessImpactAssessmentResponse)
async def update_bia(
    bia_id: str,
    bia_data: BusinessImpactAssessmentUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update a BIA"""
    bia = await get_bia_or_404(
        db, bia_id, org_id
    )

    update_data = bia_data.model_dump(exclude_unset=True, exclude_none=True)

    if "dependencies" in update_data and update_data["dependencies"]:
        update_data["dependencies"] = json.dumps(update_data["dependencies"])

    for key, value in update_data.items():
        setattr(bia, key, value)

    await db.flush()
    await db.refresh(bia)

    return BusinessImpactAssessmentResponse.model_validate(bia)


@router.delete("/bias/{bia_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_bia(
    bia_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Delete a BIA"""
    bia = await get_bia_or_404(
        db, bia_id, org_id
    )
    await db.delete(bia)
    await db.flush()


# Dashboard Endpoints
@router.get("/dashboard", response_model=RiskDashboardResponse)
async def get_risk_dashboard(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Organizational risk dashboard from stored rows only.

    Register figures come from the risk register; ``fair_*`` figures from the
    latest completed FAIR analysis of each scenario (None when there is none).
    """
    # Query all risks for organization
    query = select(RiskRegister).where(
        RiskRegister.organization_id == org_id
    )
    result = await db.execute(query)
    registers = list(result.scalars().all())

    number_of_controls = (await db.execute(
        select(func.count(RiskControl.id)).where(RiskControl.organization_id == org_id)
    )).scalar() or 0
    number_of_scenarios = (await db.execute(
        select(func.count(RiskScenario.id)).where(RiskScenario.organization_id == org_id)
    )).scalar() or 0
    scenarios_with_inputs = (await db.execute(
        select(func.count(func.distinct(FAIRAnalysis.scenario_id))).where(
            FAIRAnalysis.organization_id == org_id
        )
    )).scalar() or 0
    completed = await _latest_completed_analyses(db, org_id)
    fair_fields = {
        "number_of_controls": number_of_controls,
        "number_of_scenarios": number_of_scenarios,
        "fair_analyses_completed": len(completed),
        "fair_scenarios_without_inputs": max(number_of_scenarios - scenarios_with_inputs, 0),
        "fair_total_ale_mean": (
            round(sum(a.ale_mean or 0.0 for a in completed), 2) if completed else None
        ),
    }

    if not registers:
        return RiskDashboardResponse(
            total_ale_annual_usd=0,
            number_of_risks=0,
            average_ale_per_risk=0,
            risks_within_appetite=0,
            risks_exceeding_appetite=0,
            top_risks_by_ale=[],
            ale_by_category={},
            control_effectiveness_avg=0,
            **fair_fields,
        )

    # Calculate metrics
    total_ale = sum(r.ale_annual_usd for r in registers)
    within_appetite = sum(1 for r in registers if r.is_within_appetite)
    exceeding = len(registers) - within_appetite

    # Top risks
    top_risks = sorted(
        registers, key=lambda r: r.ale_annual_usd, reverse=True
    )[:5]

    # By category
    by_category = {}
    for register in registers:
        cat = register.risk_category
        by_category[cat] = by_category.get(cat, 0) + register.ale_annual_usd

    # Average control effectiveness
    avg_effectiveness = (
        sum(r.control_effectiveness for r in registers) / len(registers)
        if registers
        else 0
    )

    return RiskDashboardResponse(
        total_ale_annual_usd=total_ale,
        number_of_risks=len(registers),
        average_ale_per_risk=total_ale / len(registers) if registers else 0,
        risks_within_appetite=within_appetite,
        risks_exceeding_appetite=exceeding,
        top_risks_by_ale=[
            {"name": r.name, "ale": r.ale_annual_usd, "category": r.risk_category}
            for r in top_risks
        ],
        ale_by_category=by_category,
        control_effectiveness_avg=avg_effectiveness * 100,
        **fair_fields,
    )


@router.get("/heatmap", response_model=RiskHeatmapResponse)
async def get_risk_heatmap(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get risk heatmap (impact vs likelihood)"""
    aggregator = RiskAggregator()

    # Query all risks
    query = select(RiskRegister).where(
        RiskRegister.organization_id == org_id
    )
    result = await db.execute(query)
    registers = list(result.scalars().all())

    # Convert to aggregator format
    risks = [
        {
            "likelihood": min(register.inherent_risk_score / 100, 1.0),
            "impact": min(register.ale_annual_usd / 1000000, 1.0),
        }
        for register in registers
    ]

    heatmap_data = aggregator.generate_risk_heatmap(risks)
    return RiskHeatmapResponse(**heatmap_data)


# ---------------------------------------------------------------------------
# Frontend-compat endpoints.
#
# The RiskQuantification page calls two routes that didn't exist on the
# backend until this fix: POST /analyze and GET /loss-exceedance. Every
# tenant's Risk page has been broken since launch because
# ``riskquantApi.getLossExceedance()`` 404'd on the initial data load.
# Adding them here rather than changing the frontend so existing API
# consumers (if any) keep working.
# ---------------------------------------------------------------------------


@router.post("/analyze")
async def analyze_scenarios(
    org_id: OrganizationId,
    request: dict = Body(...),
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Run FAIR simulations for one or more scenarios.

    Accepts ``{"scenario_ids": ["...", "..."]}``. Runs the Monte Carlo FAIR
    simulation over each scenario's most recent analyst-authored
    FAIRAnalysis (``POST /fair-analyses``) and returns aggregate ALE
    statistics. If scenario_ids is empty, runs across every FAIRAnalysis row
    for the caller's org.

    A scenario with no FAIRAnalysis is NOT simulated: this route used to
    invent PERT inputs from the asset value and save them as an ordinary
    analysis, so every ALE on the page came from made-up defaults. Such
    scenarios are now listed under ``skipped`` with ``reason`` =
    ``no_fair_inputs``. An analysis whose stored inputs are inconsistent is
    listed under ``failed`` with ``error`` = ``invalid_fair_input`` and the
    ``field`` at fault.

    Each analysis runs with its own stored ``simulation_iterations`` and seed.
    The portfolio figures (``portfolio_var_95``, ``portfolio_p90`` /
    ``portfolio_p99``) re-simulate the analysed scenarios with a common
    ``iterations`` count and sum the draws (independent scenarios).
    """
    scenario_ids = request.get("scenario_ids") or []
    if not isinstance(scenario_ids, list) or not all(isinstance(x, str) for x in scenario_ids):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_field", "field": "scenario_ids",
                    "detail": "scenario_ids must be a list of scenario id strings"},
        )
    raw_iterations = request.get("iterations", 10000)
    if raw_iterations is None:
        raw_iterations = 10000
    # ``0`` is malformed, not "use the default": do not coerce it away.
    if isinstance(raw_iterations, bool) or not isinstance(raw_iterations, int):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_field", "field": "iterations",
                    "detail": "iterations must be an integer"},
        )
    iterations = raw_iterations
    if not 1 <= iterations <= 100000:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_field", "field": "iterations",
                    "detail": "iterations must be between 1 and 100000"},
        )
    skipped: list[dict] = []
    failed: list[dict] = []

    per_scenario: list[dict] = []
    analysed: list[FAIRAnalysis] = []

    # Helper: run sim + persist for a given FAIRAnalysis row
    async def _simulate_and_record(analysis: FAIRAnalysis) -> None:
        result = simulate_analysis(analysis)
        analysed.append(analysis)
        per_scenario.append({
            "analysis_id": analysis.id,
            "scenario_id": analysis.scenario_id,
            "ale_mean": result.ale_mean,
            "ale_p10": result.ale_p10,
            "ale_p50": result.ale_p50,
            "ale_p90": result.ale_p90,
            "ale_p99": result.ale_p99,
            "iterations": result.iterations,
            "derived_vulnerability": result.derived_vulnerability,
        })
        store_result(analysis, result, datetime.now(timezone.utc))

    # Determine target scenario set. If scenario_ids given, simulate each
    # scenario's latest FAIRAnalysis (several may exist; the most recent
    # wins instead of scalar_one_or_none raising a 500). If no scenario_ids
    # given, process every existing FAIRAnalysis row for the org.
    if scenario_ids:
        targets: list[FAIRAnalysis] = []
        for sid in scenario_ids:
            fa_res = await db.execute(
                select(FAIRAnalysis)
                .where(
                    and_(
                        FAIRAnalysis.organization_id == org_id,
                        FAIRAnalysis.scenario_id == sid,
                    )
                )
                .order_by(FAIRAnalysis.created_at.desc())
                .limit(1)
            )
            analysis = fa_res.scalar_one_or_none()
            if analysis is not None:
                targets.append(analysis)
                continue
            scen_res = await db.execute(
                select(RiskScenario.id).where(
                    and_(
                        RiskScenario.organization_id == org_id,
                        RiskScenario.id == sid,
                    )
                )
            )
            reason = "no_fair_inputs" if scen_res.scalar_one_or_none() else "scenario_not_found"
            skipped.append({"scenario_id": sid, "reason": reason})
    else:
        # Every scenario's latest analysis (several analyses of one scenario
        # are revisions; simulating all of them double-counted the scenario).
        fa_query = (
            select(FAIRAnalysis)
            .where(FAIRAnalysis.organization_id == org_id)
            .order_by(FAIRAnalysis.scenario_id, FAIRAnalysis.created_at.desc())
        )
        latest: dict[str, FAIRAnalysis] = {}
        for row in (await db.execute(fa_query)).scalars().all():
            latest.setdefault(row.scenario_id, row)
        targets = list(latest.values())

    for analysis in targets:
        try:
            await _simulate_and_record(analysis)
        except FAIRInputError as exc:
            failed.append({"analysis_id": analysis.id, "scenario_id": analysis.scenario_id,
                           "error": "invalid_fair_input", "field": exc.field, "detail": exc.detail})
        except Exception as exc:  # noqa: BLE001
            logger.error("fair_analyze_failed", analysis_id=analysis.id, error=str(exc))
            failed.append({"analysis_id": analysis.id, "scenario_id": analysis.scenario_id,
                           "error": "simulation_failed"})

    await db.flush()

    # Portfolio of the analysed scenarios: summed draws, not summed percentiles.
    portfolio = simulate_portfolio(analysed, iterations) if analysed else None
    total_mean = sum(s["ale_mean"] for s in per_scenario)

    return {
        "status": "completed" if per_scenario else "nothing_analyzed",
        "scenarios_analyzed": len(per_scenario),
        "skipped": skipped,
        "failed": failed,
        "total_ale_mean": round(total_mean, 2),
        "portfolio_var_95": round(portfolio["p95"], 2) if portfolio else 0.0,
        "portfolio_p90": round(portfolio["p90"], 2) if portfolio else None,
        "portfolio_p99": round(portfolio["p99"], 2) if portfolio else None,
        "portfolio_iterations": portfolio["iterations"] if portfolio else 0,
        "model": dict(FAIR_MODEL_DESCRIPTION),
        "per_scenario": per_scenario,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/loss-exceedance")
async def get_loss_exceedance_portfolio(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    iterations: int = Query(10000, ge=100, le=100000),
):
    """Portfolio loss-exceedance curve from stored FAIR analyses only.

    Uses the latest completed analysis of each scenario, re-simulates each
    from its stored inputs (its own seed, a common ``iterations`` count) and
    sums the draws, i.e. the scenarios are treated as independent. ``curve``
    is ``[{probability, loss}]`` with ``loss`` the annual portfolio loss that
    is exceeded with that probability. ``total_ale_p90`` / ``total_ale_p99``
    are percentiles of the summed distribution; they used to be sums of the
    per-scenario percentiles (which assumes perfectly correlated scenarios)
    across every analysis row, so a re-analysed scenario counted twice.
    An analysis whose stored inputs became inconsistent is listed under
    ``excluded`` with the field at fault.
    """
    analyses = await _latest_completed_analyses(db, org_id)

    if not analyses:
        return {
            "analyses_count": 0,
            "curve": [],
            "excluded": [],
            "note": "No completed FAIR analyses for this organization",
        }

    usable: list[FAIRAnalysis] = []
    excluded: list[dict] = []
    for analysis in analyses:
        try:
            simulate_analysis(analysis, iterations=1)
        except FAIRInputError as exc:
            excluded.append({"analysis_id": analysis.id, "scenario_id": analysis.scenario_id,
                             "error": "invalid_fair_input", "field": exc.field})
            continue
        usable.append(analysis)

    if not usable:
        return {
            "analyses_count": 0,
            "curve": [],
            "excluded": excluded,
            "note": "No completed FAIR analysis has consistent stored inputs",
        }

    portfolio = simulate_portfolio(usable, iterations)
    return {
        "analyses_count": len(usable),
        "total_ale_mean": round(portfolio["mean"], 2),
        "total_ale_p50": round(portfolio["p50"], 2),
        "total_ale_p90": round(portfolio["p90"], 2),
        "total_ale_p95": round(portfolio["p95"], 2),
        "total_ale_p99": round(portfolio["p99"], 2),
        "iterations": portfolio["iterations"],
        "method": "sum of independent per-scenario simulations (latest completed analysis per scenario)",
        "curve": portfolio["curve"],
        "excluded": excluded,
    }
