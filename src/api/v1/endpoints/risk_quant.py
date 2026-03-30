"""Risk Quantification API endpoints

REST API for FAIR analysis, risk management, control effectiveness, and BIA assessment.
"""

import json
import math
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.risk_quant.engine import (
    BIAEngine,
    ControlEffectivenessAnalyzer,
    FAIREngine,
    RiskAggregator,
)
from src.risk_quant.models import (
    BusinessImpactAssessment,
    FAIRAnalysis,
    RiskControl,
    RiskRegister,
    RiskScenario,
)
from src.risk_quant.tasks import (
    control_effectiveness_audit,
    run_fair_simulation,
    risk_appetite_check,
)
from src.schemas.risk_quant import (
    BusinessImpactAssessmentCreate,
    BusinessImpactAssessmentListResponse,
    BusinessImpactAssessmentResponse,
    BusinessImpactAssessmentUpdate,
    ComparisonResponse,
    ControlRecommendationResponse,
    ControlROIResponse,
    FAIRAnalysisCreate,
    FAIRAnalysisListResponse,
    FAIRAnalysisResponse,
    FAIRAnalysisUpdate,
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

router = APIRouter(prefix="/risk-quantification", tags=["Risk Quantification"])


# Helper Functions
async def get_risk_scenario_or_404(db: AsyncSession, scenario_id: str) -> RiskScenario:
    """Get RiskScenario by ID or raise 404"""
    result = await db.execute(select(RiskScenario).where(RiskScenario.id == scenario_id))
    scenario = result.scalar_one_or_none()
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk scenario not found",
        )
    return scenario


async def get_fair_analysis_or_404(db: AsyncSession, analysis_id: str) -> FAIRAnalysis:
    """Get FAIRAnalysis by ID or raise 404"""
    result = await db.execute(select(FAIRAnalysis).where(FAIRAnalysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="FAIR analysis not found",
        )
    return analysis


async def get_risk_register_or_404(db: AsyncSession, register_id: str) -> RiskRegister:
    """Get RiskRegister by ID or raise 404"""
    result = await db.execute(
        select(RiskRegister).where(RiskRegister.id == register_id)
    )
    register = result.scalar_one_or_none()
    if not register:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk register not found",
        )
    return register


async def get_risk_control_or_404(db: AsyncSession, control_id: str) -> RiskControl:
    """Get RiskControl by ID or raise 404"""
    result = await db.execute(select(RiskControl).where(RiskControl.id == control_id))
    control = result.scalar_one_or_none()
    if not control:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk control not found",
        )
    return control


async def get_bia_or_404(
    bia_id: str,
    db: AsyncSession,
) -> BusinessImpactAssessment:
    """Get BusinessImpactAssessment by ID or raise 404"""
    result = await db.execute(
        select(BusinessImpactAssessment).where(BusinessImpactAssessment.id == bia_id)
    )
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    threat_actor: Optional[str] = None,
):
    """List risk scenarios with filtering and pagination"""
    query = select(RiskScenario).where(
        RiskScenario.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new risk scenario"""
    scenario = RiskScenario(
        organization_id=current_user.organization_id,
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

    return RiskScenarioResponse.model_validate(scenario)


@router.get("/scenarios/{scenario_id}", response_model=RiskScenarioResponse)
async def get_risk_scenario(
    scenario_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a risk scenario by ID"""
    scenario = await get_risk_scenario_or_404(db, scenario_id)
    return RiskScenarioResponse.model_validate(scenario)


@router.patch("/scenarios/{scenario_id}", response_model=RiskScenarioResponse)
async def update_risk_scenario(
    scenario_id: str,
    scenario_data: RiskScenarioUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a risk scenario"""
    scenario = await get_risk_scenario_or_404(db, scenario_id)

    update_data = scenario_data.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in update_data.items():
        setattr(scenario, key, value)

    await db.flush()
    await db.refresh(scenario)

    return RiskScenarioResponse.model_validate(scenario)


@router.delete("/scenarios/{scenario_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_risk_scenario(
    scenario_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a risk scenario"""
    scenario = await get_risk_scenario_or_404(db, scenario_id)
    await db.delete(scenario)
    await db.flush()


# FAIR Analysis Endpoints
@router.get("/fair-analyses", response_model=FAIRAnalysisListResponse)
async def list_fair_analyses(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    scenario_id: Optional[str] = None,
):
    """List FAIR analyses"""
    query = select(FAIRAnalysis).where(
        FAIRAnalysis.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new FAIR analysis"""
    # Verify scenario exists
    scenario = await get_risk_scenario_or_404(db, analysis_data.scenario_id)

    analysis = FAIRAnalysis(
        organization_id=current_user.organization_id,
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

    # Queue simulation task
    run_fair_simulation.delay(analysis.id, current_user.organization_id)

    return FAIRAnalysisResponse.model_validate(analysis)


@router.get("/fair-analyses/{analysis_id}", response_model=FAIRAnalysisResponse)
async def get_fair_analysis(
    analysis_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a FAIR analysis by ID"""
    analysis = await get_fair_analysis_or_404(db, analysis_id)
    return FAIRAnalysisResponse.model_validate(analysis)


@router.post(
    "/fair-analyses/{analysis_id}/run-simulation",
    response_model=FAIRResultsResponse,
)
async def run_fair_simulation_endpoint(
    analysis_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Run FAIR Monte Carlo simulation"""
    analysis = await get_fair_analysis_or_404(db, analysis_id)

    # Prepare analysis data
    analysis_data = {
        "tef_min": analysis.tef_min,
        "tef_mode": analysis.tef_mode,
        "tef_max": analysis.tef_max,
        "tcap_min": analysis.tcap_min,
        "tcap_mode": analysis.tcap_mode,
        "tcap_max": analysis.tcap_max,
        "rs_min": analysis.rs_min,
        "rs_mode": analysis.rs_mode,
        "rs_max": analysis.rs_max,
        "primary_loss_min": analysis.primary_loss_min,
        "primary_loss_mode": analysis.primary_loss_mode,
        "primary_loss_max": analysis.primary_loss_max,
        "secondary_loss_min": analysis.secondary_loss_min,
        "secondary_loss_mode": analysis.secondary_loss_mode,
        "secondary_loss_max": analysis.secondary_loss_max,
        "secondary_loss_event_frequency": analysis.secondary_loss_event_frequency,
    }

    # Run simulation
    engine = FAIREngine()
    result = engine.run_simulation(analysis_data, analysis.simulation_iterations)

    # Store results
    analysis.ale_mean = result.ale_mean
    analysis.ale_p10 = result.ale_p10
    analysis.ale_p50 = result.ale_p50
    analysis.ale_p90 = result.ale_p90
    analysis.ale_p99 = result.ale_p99
    analysis.loss_exceedance_curve = json.dumps(result.loss_exceedance_curve)
    analysis.completed_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(analysis)

    # Generate report
    report = engine.generate_risk_report(result)

    return FAIRResultsResponse(
        ale_mean=result.ale_mean,
        ale_p10=result.ale_p10,
        ale_p50=result.ale_p50,
        ale_p90=result.ale_p90,
        ale_p99=result.ale_p99,
        loss_exceedance_curve=result.loss_exceedance_curve,
        **report,
    )


@router.get(
    "/fair-analyses/{analysis_id}/loss-exceedance-curve",
    response_model=None,
)
async def get_loss_exceedance_curve(
    analysis_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get loss exceedance curve for FAIR analysis"""
    analysis = await get_fair_analysis_or_404(db, analysis_id)

    if not analysis.loss_exceedance_curve:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Simulation not completed",
        )

    return json.loads(analysis.loss_exceedance_curve)


# Risk Register Endpoints
@router.get("/risk-registers", response_model=RiskRegisterListResponse)
async def list_risk_registers(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    category: Optional[str] = None,
    owner_id: Optional[str] = None,
):
    """List risk registers"""
    query = select(RiskRegister).where(
        RiskRegister.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new risk register entry"""
    register = RiskRegister(
        organization_id=current_user.organization_id,
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a risk register entry by ID"""
    register = await get_risk_register_or_404(db, register_id)
    return RiskRegisterResponse.model_validate(register)


@router.patch("/risk-registers/{register_id}", response_model=RiskRegisterResponse)
async def update_risk_register(
    register_id: str,
    register_data: RiskRegisterUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a risk register entry"""
    register = await get_risk_register_or_404(db, register_id)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a risk register entry"""
    register = await get_risk_register_or_404(db, register_id)
    await db.delete(register)
    await db.flush()


# Risk Control Endpoints
@router.get("/controls", response_model=RiskControlListResponse)
async def list_risk_controls(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    control_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """List risk controls"""
    query = select(RiskControl).where(
        RiskControl.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new risk control"""
    control = RiskControl(
        organization_id=current_user.organization_id,
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a risk control by ID"""
    control = await get_risk_control_or_404(db, control_id)
    return RiskControlResponse.model_validate(control)


@router.patch("/controls/{control_id}", response_model=RiskControlResponse)
async def update_risk_control(
    control_id: str,
    control_data: RiskControlUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a risk control"""
    control = await get_risk_control_or_404(db, control_id)

    update_data = control_data.model_dump(exclude_unset=True, exclude_none=True)

    for key, value in update_data.items():
        setattr(control, key, value)

    await db.flush()
    await db.refresh(control)

    return RiskControlResponse.model_validate(control)


@router.delete("/controls/{control_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_risk_control(
    control_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a risk control"""
    control = await get_risk_control_or_404(db, control_id)
    await db.delete(control)
    await db.flush()


@router.post("/controls/{control_id}/audit", response_model=ControlROIResponse)
async def audit_control_effectiveness(
    control_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Audit control effectiveness and calculate ROI"""
    control = await get_risk_control_or_404(db, control_id)
    register = await get_risk_register_or_404(db, control.risk_register_id)

    analyzer = ControlEffectivenessAnalyzer()

    # Estimate residual ALE with control
    effectiveness = control.effectiveness_score / 100.0
    mitigated_ale = register.ale_annual_usd * (1 - effectiveness)

    roi_data = analyzer.assess_control_roi(
        register.ale_annual_usd, mitigated_ale, control.cost_annual_usd
    )

    # Update control
    control.roi_percentage = roi_data["roi_5yr_percent"]
    control.last_tested = datetime.now(timezone.utc)
    control.test_result = "passed" if roi_data["effective"] else "needs_improvement"

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    criticality: Optional[str] = None,
):
    """List Business Impact Assessments"""
    query = select(BusinessImpactAssessment).where(
        BusinessImpactAssessment.organization_id == current_user.organization_id
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new Business Impact Assessment"""
    bia = BusinessImpactAssessment(
        organization_id=current_user.organization_id,
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a BIA by ID"""
    bia = await get_bia_or_404(db, bia_id)
    return BusinessImpactAssessmentResponse.model_validate(bia)


@router.patch("/bias/{bia_id}", response_model=BusinessImpactAssessmentResponse)
async def update_bia(
    bia_id: str,
    bia_data: BusinessImpactAssessmentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a BIA"""
    bia = await get_bia_or_404(db, bia_id)

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a BIA"""
    bia = await get_bia_or_404(db, bia_id)
    await db.delete(bia)
    await db.flush()


# Dashboard Endpoints
@router.get("/dashboard", response_model=RiskDashboardResponse)
async def get_risk_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get organizational risk dashboard"""
    # Query all risks for organization
    query = select(RiskRegister).where(
        RiskRegister.organization_id == current_user.organization_id
    )
    result = await db.execute(query)
    registers = list(result.scalars().all())

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
    )


@router.get("/heatmap", response_model=RiskHeatmapResponse)
async def get_risk_heatmap(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get risk heatmap (impact vs likelihood)"""
    aggregator = RiskAggregator()

    # Query all risks
    query = select(RiskRegister).where(
        RiskRegister.organization_id == current_user.organization_id
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
