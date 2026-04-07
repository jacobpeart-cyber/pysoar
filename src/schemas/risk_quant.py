"""Risk Quantification schemas for request/response validation

Schemas for risk scenarios, FAIR analyses, risk registers, controls, and BIAs.
"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Risk Scenario Schemas
class RiskScenarioBase(BaseModel):
    """Base risk scenario schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    asset_id: Optional[str] = None
    asset_name: str = Field(..., max_length=255)
    asset_value_usd: float = Field(..., ge=0)
    threat_actor: str = Field(default="external_attacker", max_length=50)
    threat_type: str = Field(..., max_length=255)
    vulnerability_exploited: str = Field(..., max_length=255)
    loss_type: str = Field(default="productivity", max_length=50)
    analyst_id: str
    confidence_level: float = Field(default=0.5, ge=0, le=1)


class RiskScenarioCreate(RiskScenarioBase):
    """Schema for creating a risk scenario"""

    pass


class RiskScenarioUpdate(BaseModel):
    """Schema for updating a risk scenario"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    asset_id: Optional[str] = None
    asset_name: Optional[str] = Field(None, max_length=255)
    asset_value_usd: Optional[float] = Field(None, ge=0)
    threat_actor: Optional[str] = Field(None, max_length=50)
    threat_type: Optional[str] = Field(None, max_length=255)
    vulnerability_exploited: Optional[str] = Field(None, max_length=255)
    loss_type: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = Field(None, max_length=50)
    confidence_level: Optional[float] = Field(None, ge=0, le=1)


class RiskScenarioResponse(RiskScenarioBase, DBModel):
    """Schema for risk scenario response"""

    id: str
    status: str
    review_date: Optional[datetime]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RiskScenarioListResponse(BaseModel):
    """Schema for paginated risk scenario list"""

    items: list[RiskScenarioResponse]
    total: int
    page: int
    size: int
    pages: int


# FAIR Analysis Schemas
class FAIRAnalysisBase(BaseModel):
    """Base FAIR analysis schema"""

    scenario_id: str
    tef_min: float = Field(..., ge=0)
    tef_mode: float = Field(..., ge=0)
    tef_max: float = Field(..., ge=0)
    vuln_min: float = Field(..., ge=0, le=1)
    vuln_mode: float = Field(..., ge=0, le=1)
    vuln_max: float = Field(..., ge=0, le=1)
    tcap_min: float = Field(..., ge=0, le=1)
    tcap_mode: float = Field(..., ge=0, le=1)
    tcap_max: float = Field(..., ge=0, le=1)
    rs_min: float = Field(..., ge=0, le=1)
    rs_mode: float = Field(..., ge=0, le=1)
    rs_max: float = Field(..., ge=0, le=1)
    lm_min: float = Field(..., ge=0)
    lm_mode: float = Field(..., ge=0)
    lm_max: float = Field(..., ge=0)
    primary_loss_min: float = Field(..., ge=0)
    primary_loss_mode: float = Field(..., ge=0)
    primary_loss_max: float = Field(..., ge=0)
    secondary_loss_min: float = Field(..., ge=0)
    secondary_loss_mode: float = Field(..., ge=0)
    secondary_loss_max: float = Field(..., ge=0)
    secondary_loss_event_frequency: float = Field(..., ge=0, le=1)
    simulation_iterations: int = Field(default=10000, ge=100, le=100000)


class FAIRAnalysisCreate(FAIRAnalysisBase):
    """Schema for creating FAIR analysis"""

    pass


class FAIRAnalysisUpdate(BaseModel):
    """Schema for updating FAIR analysis"""

    tef_min: Optional[float] = Field(None, ge=0)
    tef_mode: Optional[float] = Field(None, ge=0)
    tef_max: Optional[float] = Field(None, ge=0)
    vuln_min: Optional[float] = Field(None, ge=0, le=1)
    vuln_mode: Optional[float] = Field(None, ge=0, le=1)
    vuln_max: Optional[float] = Field(None, ge=0, le=1)
    primary_loss_min: Optional[float] = Field(None, ge=0)
    primary_loss_mode: Optional[float] = Field(None, ge=0)
    primary_loss_max: Optional[float] = Field(None, ge=0)
    secondary_loss_min: Optional[float] = Field(None, ge=0)
    secondary_loss_mode: Optional[float] = Field(None, ge=0)
    secondary_loss_max: Optional[float] = Field(None, ge=0)
    simulation_iterations: Optional[int] = Field(None, ge=100, le=100000)


class FAIRAnalysisResponse(FAIRAnalysisBase, DBModel):
    """Schema for FAIR analysis response"""

    id: str
    organization_id: str
    ale_mean: Optional[float]
    ale_p10: Optional[float]
    ale_p50: Optional[float]
    ale_p90: Optional[float]
    ale_p99: Optional[float]
    loss_exceedance_curve: Optional[dict]
    completed_at: Optional[datetime]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FAIRAnalysisListResponse(BaseModel):
    """Schema for paginated FAIR analysis list"""

    items: list[FAIRAnalysisResponse]
    total: int
    page: int
    size: int
    pages: int


class FAIRResultsResponse(BaseModel):
    """Schema for FAIR simulation results"""

    ale_mean: float
    ale_p10: float
    ale_p50: float
    ale_p90: float
    ale_p99: float
    loss_exceedance_curve: dict
    ale_statistics: dict
    risk_distribution: dict


# Risk Register Schemas
class RiskRegisterBase(BaseModel):
    """Base risk register schema"""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    risk_category: str = Field(..., max_length=50)
    inherent_risk_score: float = Field(..., ge=0, le=100)
    residual_risk_score: float = Field(..., ge=0, le=100)
    risk_treatment: str = Field(..., max_length=50)
    treatment_plan: Optional[str] = None
    control_effectiveness: float = Field(default=0.0, ge=0, le=1)
    owner_id: str
    review_frequency_days: int = Field(default=90, ge=1, le=365)
    ale_annual_usd: float = Field(..., ge=0)
    risk_appetite_threshold_usd: float = Field(..., ge=0)


class RiskRegisterCreate(RiskRegisterBase):
    """Schema for creating risk register entry"""

    pass


class RiskRegisterUpdate(BaseModel):
    """Schema for updating risk register entry"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    risk_category: Optional[str] = Field(None, max_length=50)
    inherent_risk_score: Optional[float] = Field(None, ge=0, le=100)
    residual_risk_score: Optional[float] = Field(None, ge=0, le=100)
    risk_treatment: Optional[str] = Field(None, max_length=50)
    treatment_plan: Optional[str] = None
    control_effectiveness: Optional[float] = Field(None, ge=0, le=1)
    review_frequency_days: Optional[int] = Field(None, ge=1, le=365)
    ale_annual_usd: Optional[float] = Field(None, ge=0)


class RiskRegisterResponse(RiskRegisterBase, DBModel):
    """Schema for risk register response"""

    id: str
    organization_id: str
    status: str
    last_review: Optional[datetime]
    next_review: Optional[datetime]
    is_within_appetite: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RiskRegisterListResponse(BaseModel):
    """Schema for paginated risk register list"""

    items: list[RiskRegisterResponse]
    total: int
    page: int
    size: int
    pages: int


# Risk Control Schemas
class RiskControlBase(BaseModel):
    """Base risk control schema"""

    risk_register_id: str
    control_name: str = Field(..., min_length=1, max_length=255)
    control_type: str = Field(default="preventive", max_length=50)
    implementation_status: str = Field(default="planned", max_length=50)
    effectiveness_score: float = Field(default=0.0, ge=0, le=100)
    cost_annual_usd: float = Field(..., ge=0)
    frameworks_mapped: Optional[list[str]] = None


class RiskControlCreate(RiskControlBase):
    """Schema for creating risk control"""

    pass


class RiskControlUpdate(BaseModel):
    """Schema for updating risk control"""

    control_name: Optional[str] = Field(None, min_length=1, max_length=255)
    control_type: Optional[str] = Field(None, max_length=50)
    implementation_status: Optional[str] = Field(None, max_length=50)
    effectiveness_score: Optional[float] = Field(None, ge=0, le=100)
    cost_annual_usd: Optional[float] = Field(None, ge=0)
    test_result: Optional[str] = Field(None, max_length=50)


class RiskControlResponse(RiskControlBase, DBModel):
    """Schema for risk control response"""

    id: str
    organization_id: str
    roi_percentage: Optional[float]
    last_tested: Optional[datetime]
    test_result: Optional[str]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RiskControlListResponse(BaseModel):
    """Schema for paginated risk control list"""

    items: list[RiskControlResponse]
    total: int
    page: int
    size: int
    pages: int


# Business Impact Assessment Schemas
class BusinessImpactAssessmentBase(BaseModel):
    """Base BIA schema"""

    asset_name: str = Field(..., min_length=1, max_length=255)
    asset_type: str = Field(default="application", max_length=50)
    business_unit: str = Field(..., max_length=255)
    criticality: str = Field(default="business_critical", max_length=50)
    rto_hours: float = Field(..., ge=0)
    rpo_hours: float = Field(..., ge=0)
    mtpd_hours: float = Field(..., ge=0)
    financial_impact_per_hour_usd: float = Field(..., ge=0)
    reputational_impact_score: float = Field(..., ge=0, le=100)
    regulatory_impact_score: float = Field(..., ge=0, le=100)
    dependencies: Optional[list[dict]] = None
    single_point_of_failure: bool = False


class BusinessImpactAssessmentCreate(BusinessImpactAssessmentBase):
    """Schema for creating BIA"""

    pass


class BusinessImpactAssessmentUpdate(BaseModel):
    """Schema for updating BIA"""

    asset_name: Optional[str] = Field(None, min_length=1, max_length=255)
    asset_type: Optional[str] = Field(None, max_length=50)
    business_unit: Optional[str] = Field(None, max_length=255)
    criticality: Optional[str] = Field(None, max_length=50)
    rto_hours: Optional[float] = Field(None, ge=0)
    rpo_hours: Optional[float] = Field(None, ge=0)
    mtpd_hours: Optional[float] = Field(None, ge=0)
    financial_impact_per_hour_usd: Optional[float] = Field(None, ge=0)
    reputational_impact_score: Optional[float] = Field(None, ge=0, le=100)
    regulatory_impact_score: Optional[float] = Field(None, ge=0, le=100)
    dependencies: Optional[list[dict]] = None
    single_point_of_failure: Optional[bool] = None


class BusinessImpactAssessmentResponse(BusinessImpactAssessmentBase, DBModel):
    """Schema for BIA response"""

    id: str
    organization_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class BusinessImpactAssessmentListResponse(BaseModel):
    """Schema for paginated BIA list"""

    items: list[BusinessImpactAssessmentResponse]
    total: int
    page: int
    size: int
    pages: int


# Dashboard and Analytics Schemas
class RiskDashboardResponse(BaseModel):
    """Risk quantification dashboard response"""

    total_ale_annual_usd: float
    number_of_risks: int
    average_ale_per_risk: float
    risks_within_appetite: int
    risks_exceeding_appetite: int
    top_risks_by_ale: list[dict]
    ale_by_category: dict
    control_effectiveness_avg: float


class RiskHeatmapResponse(BaseModel):
    """Risk heatmap visualization data"""

    matrix: list[list[int]]
    likelihood_labels: list[str]
    impact_labels: list[str]


class ComparisonResponse(BaseModel):
    """Risk scenario comparison response"""

    scenario_1_name: str
    scenario_2_name: str
    ale_difference: float
    ale_percent_difference: float
    key_driver_differences: list[dict]


class ControlROIResponse(BaseModel):
    """Control ROI analysis response"""

    control_name: str
    annual_benefit_usd: float
    annual_cost_usd: float
    net_annual_benefit_usd: float
    roi_5_year_percent: float
    payback_period_months: float
    effective: bool


class ControlRecommendationResponse(BaseModel):
    """Control recommendation response"""

    rank: int
    control_name: str
    control_type: str
    annual_cost: float
    expected_effectiveness: float
    estimated_ale_reduction: float
    roi_percent: float
    implementation_priority: str
