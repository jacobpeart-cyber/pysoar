"""Threat modeling endpoints for STRIDE, PASTA, and attack tree analysis"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Path, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger
from src.models.organization import Organization
from src.services.automation import AutomationService

logger = get_logger(__name__)
from src.threat_modeling.models import (
    ThreatModel,
    ThreatModelComponent,
    IdentifiedThreat,
    ThreatMitigation,
    AttackTree,
    ThreatModelStatus,
    ThreatModelMethodology,
    ComponentType,
    STRIDECategory,
    ThreatStatus,
    LikelihoodLevel,
    ImpactLevel,
    MitigationType,
    ImplementationStatus,
)
from src.threat_modeling.engine import (
    STRIDEAnalyzer,
    PASTAEngine,
    AttackTreeGenerator,
    MitigationRecommender,
    ThreatModelValidator,
)
from src.schemas.threat_modeling import (
    ThreatModelCreate,
    ThreatModelUpdate,
    ThreatModelResponse,
    ThreatModelListResponse,
    ComponentCreate,
    ComponentUpdate,
    ComponentResponse,
    ThreatCreate,
    ThreatUpdate,
    ThreatResponse,
    ThreatListResponse,
    MitigationCreate,
    MitigationUpdate,
    MitigationResponse,
    MitigationListResponse,
    AttackTreeCreate,
    AttackTreeUpdate,
    AttackTreeResponse,
    AttackTreeListResponse,
    STRIDEAnalysisRequest,
    STRIDEAnalysisResponse,
    PASTAAnalysisRequest,
    PASTAAnalysisResponse,
    ValidationRequest,
    ValidationResponse,
    ThreatModelDashboard,
    MitigationRecommendation,
    RecommendationResponse,
)

router = APIRouter(prefix="/threat-modeling", tags=["Threat Modeling"])


async def get_threat_model_or_404(
    model_id: str,
    org_id: str,
    db: AsyncSession,
) -> ThreatModel:
    """Get threat model or raise 404"""
    result = await db.execute(
        select(ThreatModel).where(
            (ThreatModel.id == model_id)
            & (ThreatModel.organization_id == org_id)
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat model not found",
        )
    return model


async def get_component_or_404(
    component_id: str,
    org_id: str,
    db: AsyncSession,
) -> ThreatModelComponent:
    """Get component or raise 404"""
    result = await db.execute(
        select(ThreatModelComponent).where(
            (ThreatModelComponent.id == component_id)
            & (ThreatModelComponent.organization_id == org_id)
        )
    )
    component = result.scalar_one_or_none()
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Component not found",
        )
    return component


async def get_threat_or_404(
    threat_id: str,
    org_id: str,
    db: AsyncSession,
) -> IdentifiedThreat:
    """Get threat or raise 404"""
    result = await db.execute(
        select(IdentifiedThreat).where(
            (IdentifiedThreat.id == threat_id)
            & (IdentifiedThreat.organization_id == org_id)
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found",
        )
    return threat


# Threat Model CRUD endpoints

@router.post("", response_model=ThreatModelResponse, status_code=status.HTTP_201_CREATED)
async def create_threat_model(
    data: ThreatModelCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create new threat model"""
    model = ThreatModel(
        organization_id=getattr(current_user, "organization_id", None),
        name=data.name,
        description=data.description,
        application_name=data.application_name,
        version=data.version,
        methodology=data.methodology,
        status=ThreatModelStatus.DRAFT.value,
        scope=data.scope,
        architecture_description=data.architecture_description,
        created_by=current_user.id,
    )
    db.add(model)
    await db.commit()
    await db.refresh(model)
    return model


@router.get("", response_model=ThreatModelListResponse)
async def list_threat_models(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = None,
    methodology: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List threat models with filtering and pagination"""
    query = select(ThreatModel).where(
        ThreatModel.organization_id == getattr(current_user, "organization_id", None)
    )

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (ThreatModel.name.ilike(search_filter))
            | (ThreatModel.application_name.ilike(search_filter))
        )

    if status:
        query = query.where(ThreatModel.status == status)

    if methodology:
        query = query.where(ThreatModel.methodology == methodology)

    # Count total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
    order_col = getattr(ThreatModel, sort_by, ThreatModel.created_at)
    if sort_order == "desc":
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())

    # Pagination
    query = query.offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    items = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return ThreatModelListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/{model_id}", response_model=ThreatModelResponse)
async def get_threat_model(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """Get threat model by ID"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)
    return model


@router.put("/{model_id}", response_model=ThreatModelResponse)
async def update_threat_model(
    data: ThreatModelUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """Update threat model"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    for key, value in data.dict(exclude_unset=True).items():
        setattr(model, key, value)

    await db.commit()
    await db.refresh(model)
    return model


@router.delete("/{model_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat_model(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """Delete threat model"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)
    await db.delete(model)
    await db.commit()


# Component endpoints

@router.post("/{model_id}/components", response_model=ComponentResponse)
async def create_component(
    data: ComponentCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """Create component in threat model"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    component = ThreatModelComponent(
        organization_id=getattr(current_user, "organization_id", None),
        model_id=model_id,
        component_type=data.component_type,
        name=data.name,
        description=data.description,
        technology_stack=data.technology_stack,
        data_classification=data.data_classification,
        trust_level=data.trust_level,
        position=data.position,
        connections=data.connections,
    )
    db.add(component)
    await db.commit()
    await db.refresh(component)
    return component


@router.get("/{model_id}/components", response_model=list[ComponentResponse])
async def list_components(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """List components in threat model"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    result = await db.execute(
        select(ThreatModelComponent).where(
            ThreatModelComponent.model_id == model_id
        )
    )
    return result.scalars().all()


@router.put("/{model_id}/components/{component_id}", response_model=ComponentResponse)
async def update_component(
    data: ComponentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    component_id: str = Path(...),
):
    """Update component"""
    component = await get_component_or_404(component_id, getattr(current_user, "organization_id", None), db)

    for key, value in data.dict(exclude_unset=True).items():
        setattr(component, key, value)

    await db.commit()
    await db.refresh(component)
    return component


@router.delete("/{model_id}/components/{component_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_component(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    component_id: str = Path(...),
):
    """Delete component"""
    component = await get_component_or_404(component_id, getattr(current_user, "organization_id", None), db)
    await db.delete(component)
    await db.commit()


# Threat endpoints

@router.post("/{model_id}/threats", response_model=ThreatResponse)
async def create_threat(
    data: ThreatCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """Create identified threat"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    # Calculate risk score
    analyzer = STRIDEAnalyzer()
    risk_score = analyzer.calculate_risk_score(data.likelihood, data.impact)

    threat = IdentifiedThreat(
        organization_id=getattr(current_user, "organization_id", None),
        model_id=model_id,
        component_id=data.component_id,
        stride_category=data.stride_category,
        pasta_stage=data.pasta_stage,
        threat_description=data.threat_description,
        attack_vector=data.attack_vector,
        preconditions=data.preconditions,
        impact_description=data.impact_description,
        likelihood=data.likelihood,
        impact=data.impact,
        risk_score=risk_score,
        mitre_technique_ids=data.mitre_technique_ids,
        cwe_ids=data.cwe_ids,
        status=ThreatStatus.IDENTIFIED.value,
        priority=data.priority,
    )
    db.add(threat)
    await db.commit()
    await db.refresh(threat)

    # Update model threat count
    model.threats_count = (model.threats_count or 0) + 1
    await db.commit()

    try:
        org_id = getattr(current_user, "organization_id", None)
        risk_level = "high" if (threat.risk_score or 0) > 15 else ("medium" if (threat.risk_score or 0) > 8 else "low")
        automation = AutomationService(db)
        await automation.on_threat_model_risk(
            model_name=model.name,
            threat_name=threat.threat_description or "threat",
            stride_category=threat.stride_category or "",
            risk_level=risk_level,
            organization_id=org_id,
        )
    except Exception as automation_exc:
        logger.warning(f"Automation on_threat_model_risk failed: {automation_exc}")

    return threat


@router.get("/{model_id}/threats", response_model=ThreatListResponse)
async def list_threats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    stride_category: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[int] = None,
    sort_by: str = "risk_score",
    sort_order: str = "desc",
):
    """List threats in model"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    query = select(IdentifiedThreat).where(
        IdentifiedThreat.model_id == model_id
    )

    if stride_category:
        query = query.where(IdentifiedThreat.stride_category == stride_category)

    if status:
        query = query.where(IdentifiedThreat.status == status)

    if priority:
        query = query.where(IdentifiedThreat.priority == priority)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    order_col = getattr(IdentifiedThreat, sort_by, IdentifiedThreat.risk_score)
    if sort_order == "desc":
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())

    query = query.offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    items = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return ThreatListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/{model_id}/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    threat_id: str = Path(...),
):
    """Get threat by ID"""
    threat = await get_threat_or_404(threat_id, getattr(current_user, "organization_id", None), db)
    return threat


@router.put("/{model_id}/threats/{threat_id}", response_model=ThreatResponse)
async def update_threat(
    data: ThreatUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    threat_id: str = Path(...),
):
    """Update threat"""
    threat = await get_threat_or_404(threat_id, getattr(current_user, "organization_id", None), db)

    for key, value in data.dict(exclude_unset=True).items():
        setattr(threat, key, value)

    # Recalculate risk score if likelihood or impact changed
    if data.likelihood or data.impact:
        analyzer = STRIDEAnalyzer()
        threat.risk_score = analyzer.calculate_risk_score(
            threat.likelihood,
            threat.impact,
        )

    await db.commit()
    await db.refresh(threat)
    return threat


@router.delete("/{model_id}/threats/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    threat_id: str = Path(...),
):
    """Delete threat"""
    threat = await get_threat_or_404(threat_id, getattr(current_user, "organization_id", None), db)
    await db.delete(threat)
    await db.commit()

    # Update model threat count
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)
    model.threats_count = max(0, (model.threats_count or 0) - 1)
    await db.commit()


# Mitigation endpoints

@router.post("/{model_id}/threats/{threat_id}/mitigations", response_model=MitigationResponse)
async def create_mitigation(
    data: MitigationCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    threat_id: str = Path(...),
):
    """Create mitigation for threat"""
    threat = await get_threat_or_404(threat_id, getattr(current_user, "organization_id", None), db)

    mitigation = ThreatMitigation(
        organization_id=getattr(current_user, "organization_id", None),
        threat_id=threat_id,
        mitigation_type=data.mitigation_type,
        title=data.title,
        description=data.description,
        implementation_status=data.implementation_status,
        control_reference=data.control_reference,
        effectiveness_score=data.effectiveness_score,
        cost_estimate_usd=data.cost_estimate_usd,
        assigned_to=data.assigned_to,
        deadline=data.deadline,
        verification_method=data.verification_method,
    )
    db.add(mitigation)
    await db.commit()
    await db.refresh(mitigation)

    # Update model mitigation count
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)
    model.mitigations_count = (model.mitigations_count or 0) + 1
    await db.commit()

    return mitigation


@router.get("/{model_id}/threats/{threat_id}/mitigations", response_model=MitigationListResponse)
async def list_mitigations(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    threat_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List mitigations for threat"""
    threat = await get_threat_or_404(threat_id, getattr(current_user, "organization_id", None), db)

    query = select(ThreatMitigation).where(
        ThreatMitigation.threat_id == threat_id
    )

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    query = query.order_by(ThreatMitigation.created_at.desc()).offset(
        (page - 1) * size
    ).limit(size)
    result = await db.execute(query)
    items = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return MitigationListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.put("/{model_id}/threats/{threat_id}/mitigations/{mitigation_id}", response_model=MitigationResponse)
async def update_mitigation(
    data: MitigationUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    threat_id: str = Path(...),
    mitigation_id: str = Path(...),
):
    """Update mitigation"""
    result = await db.execute(
        select(ThreatMitigation).where(
            (ThreatMitigation.id == mitigation_id)
            & (ThreatMitigation.organization_id == getattr(current_user, "organization_id", None))
        )
    )
    mitigation = result.scalar_one_or_none()
    if not mitigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mitigation not found",
        )

    for key, value in data.dict(exclude_unset=True).items():
        setattr(mitigation, key, value)

    await db.commit()
    await db.refresh(mitigation)
    return mitigation


# Analysis endpoints

@router.post("/{model_id}/analyze/stride", response_model=STRIDEAnalysisResponse)
async def run_stride_analysis(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    request: STRIDEAnalysisRequest = Body(default_factory=STRIDEAnalysisRequest),
):
    """Run STRIDE analysis on threat model"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    analyzer = STRIDEAnalyzer()
    components_result = await db.execute(
        select(ThreatModelComponent).where(
            ThreatModelComponent.model_id == model_id
        )
    )
    components = components_result.scalars().all()

    if request.auto_generate:
        threats_data = analyzer.auto_generate_threats(model, components)
        threats_count = len(threats_data)

        # Persist generated threats as IdentifiedThreat records
        for threat_data in threats_data:
            risk_score = analyzer.calculate_risk_score(
                threat_data["likelihood"], threat_data["impact"]
            )
            threat_record = IdentifiedThreat(
                organization_id=getattr(current_user, "organization_id", None),
                model_id=model_id,
                component_id=threat_data.get("component_id"),
                stride_category=threat_data.get("category"),
                threat_description=threat_data.get("description", ""),
                attack_vector=", ".join(threat_data.get("attack_vectors", [])),
                likelihood=threat_data["likelihood"],
                impact=threat_data["impact"],
                risk_score=risk_score,
                cwe_ids=threat_data.get("cwe_ids", []),
                status=ThreatStatus.IDENTIFIED.value,
            )
            db.add(threat_record)

        await db.commit()

        # Update model threat count
        model.threats_count = (model.threats_count or 0) + threats_count
        await db.commit()
    else:
        threats_count = 0

    return STRIDEAnalysisResponse(
        status="success",
        model_id=model_id,
        threats_generated=threats_count,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.post("/{model_id}/analyze/pasta", response_model=PASTAAnalysisResponse)
async def run_pasta_analysis(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    request: PASTAAnalysisRequest = Body(default_factory=PASTAAnalysisRequest),
):
    """Run PASTA analysis on threat model"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    pasta = PASTAEngine()
    components_result = await db.execute(
        select(ThreatModelComponent).where(
            ThreatModelComponent.model_id == model_id
        )
    )
    components = components_result.scalars().all()

    threats_result = await db.execute(
        select(IdentifiedThreat).where(
            IdentifiedThreat.model_id == model_id
        )
    )
    threats = threats_result.scalars().all()

    analysis_result = pasta.run_full_pasta(model, components, threats)

    # Count stages that returned non-empty results
    stages_completed = sum(
        1 for key, value in analysis_result.items()
        if key.startswith("stage_") and value
    )

    return PASTAAnalysisResponse(
        status="success",
        model_id=model_id,
        stages_completed=stages_completed,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.post("/{model_id}/validate", response_model=ValidationResponse)
async def validate_model(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    request: ValidationRequest = Body(default_factory=ValidationRequest),
):
    """Validate threat model completeness"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    components_result = await db.execute(
        select(ThreatModelComponent).where(
            ThreatModelComponent.model_id == model_id
        )
    )
    components = components_result.scalars().all()

    threats_result = await db.execute(
        select(IdentifiedThreat).where(
            IdentifiedThreat.model_id == model_id
        )
    )
    threats = threats_result.scalars().all()

    validator = ThreatModelValidator()
    report = validator.generate_validation_report(model, components, threats)

    return ValidationResponse(
        model_id=model.id,
        model_name=model.name,
        overall_valid=report["overall_valid"],
        completeness=report["completeness"],
        coverage=report["coverage"],
        is_stale=report["is_stale"],
        recommendations=report["recommendations"],
        timestamp=report["timestamp"],
    )


@router.get("/{model_id}/mitigations/recommendations/{threat_id}", response_model=RecommendationResponse)
async def get_mitigation_recommendations(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
    threat_id: str = Path(...),
):
    """Get recommended mitigations for threat"""
    threat = await get_threat_or_404(threat_id, getattr(current_user, "organization_id", None), db)

    recommender = MitigationRecommender()
    recommendations = recommender.recommend_mitigations(threat)

    # Sort by cost effectiveness
    recommendations = recommender.prioritize_mitigations(
        recommendations, threat.risk_score
    )

    return RecommendationResponse(
        threat_id=threat_id,
        recommendations=[
            MitigationRecommendation(**rec) for rec in recommendations
        ],
    )


@router.get("/{model_id}/dashboard", response_model=ThreatModelDashboard)
async def get_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """Get threat modeling dashboard data"""
    model = await get_threat_model_or_404(model_id, getattr(current_user, "organization_id", None), db)

    threats_result = await db.execute(
        select(IdentifiedThreat).where(
            IdentifiedThreat.model_id == model_id
        )
    )
    threats = threats_result.scalars().all()

    mitigations_result = await db.execute(
        select(ThreatMitigation).where(
            ThreatMitigation.threat_id.in_([t.id for t in threats])
        )
    )
    mitigations = mitigations_result.scalars().all()

    high_risk = sum(1 for t in threats if t.risk_score > 15)
    planned = sum(1 for m in mitigations if m.implementation_status == "planned")
    implemented = sum(1 for m in mitigations if m.implementation_status == "implemented")

    # Group threats by STRIDE
    stride_counts = {}
    for threat in threats:
        cat = threat.stride_category or "unknown"
        stride_counts[cat] = stride_counts.get(cat, 0) + 1

    avg_risk = sum(t.risk_score for t in threats) / len(threats) if threats else 0

    return ThreatModelDashboard(
        total_models=1,
        total_threats=len(threats),
        high_risk_threats=high_risk,
        mitigations_planned=planned,
        mitigations_implemented=implemented,
        average_risk_score=round(avg_risk, 2),
        models_by_status={},
        threats_by_stride=stride_counts,
    )
