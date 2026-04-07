"""Threat modeling schemas for API validation"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


# Enums for schema validation
class ThreatModelMethodologyEnum(str):
    """Threat modeling methodologies"""
    STRIDE = "stride"
    PASTA = "pasta"
    ATTACK_TREE = "attack_tree"
    LINDDUN = "linddun"
    VAST = "vast"
    OCTAVE = "octave"
    CUSTOM = "custom"


class ComponentTypeEnum(str):
    """Component types"""
    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"
    DATA_FLOW = "data_flow"
    TRUST_BOUNDARY = "trust_boundary"
    API_ENDPOINT = "api_endpoint"
    SERVICE = "service"
    DATABASE = "database"
    MESSAGE_QUEUE = "message_queue"


# Base schemas
class ThreatModelBase(BaseModel):
    """Base threat model schema"""
    name: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    application_name: str = Field(..., min_length=1, max_length=500)
    version: str = "1.0"
    methodology: str = Field(default="stride")
    scope: Optional[str] = None
    architecture_description: Optional[str] = None


class ThreatModelCreate(ThreatModelBase):
    """Schema for creating threat model"""
    pass


class ThreatModelUpdate(BaseModel):
    """Schema for updating threat model"""
    name: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    scope: Optional[str] = None
    architecture_description: Optional[str] = None
    reviewed_by: Optional[str] = None


class ThreatModelResponse(ThreatModelBase, DBModel):
    """Schema for threat model response"""
    id: str
    organization_id: str
    status: str
    risk_score: int
    threats_count: int
    mitigations_count: int
    created_by: Optional[str] = None
    reviewed_by: Optional[str] = None
    review_date: Optional[str] = None
    data_flow_diagram: Optional[dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ThreatModelListResponse(BaseModel):
    """Schema for paginated threat model list"""
    items: list[ThreatModelResponse]
    total: int
    page: int
    size: int
    pages: int


# Component schemas
class ComponentBase(BaseModel):
    """Base component schema"""
    component_type: str
    name: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    technology_stack: Optional[str] = None
    data_classification: Optional[str] = None
    trust_level: str = "untrusted"
    position: Optional[dict[str, int]] = None
    connections: Optional[list[str]] = None


class ComponentCreate(ComponentBase):
    """Schema for creating component"""
    model_id: str


class ComponentUpdate(BaseModel):
    """Schema for updating component"""
    name: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    technology_stack: Optional[str] = None
    data_classification: Optional[str] = None
    trust_level: Optional[str] = None
    position: Optional[dict[str, int]] = None
    connections: Optional[list[str]] = None


class ComponentResponse(ComponentBase, DBModel):
    """Schema for component response"""
    id: str
    model_id: str
    organization_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Threat schemas
class ThreatBase(BaseModel):
    """Base identified threat schema"""
    threat_description: str = Field(..., min_length=1)
    stride_category: Optional[str] = None
    pasta_stage: Optional[str] = None
    attack_vector: Optional[str] = None
    preconditions: Optional[str] = None
    impact_description: Optional[str] = None
    likelihood: str = "medium"
    impact: str = "medium"
    status: str = "identified"
    priority: int = Field(default=3, ge=1, le=5)


class ThreatCreate(ThreatBase):
    """Schema for creating threat"""
    model_id: str
    component_id: Optional[str] = None
    mitre_technique_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None


class ThreatUpdate(BaseModel):
    """Schema for updating threat"""
    threat_description: Optional[str] = None
    stride_category: Optional[str] = None
    likelihood: Optional[str] = None
    impact: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=5)
    mitre_technique_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None


class ThreatResponse(ThreatBase, DBModel):
    """Schema for threat response"""
    id: str
    model_id: str
    component_id: Optional[str] = None
    organization_id: str
    risk_score: int
    mitre_technique_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    """Schema for paginated threat list"""
    items: list[ThreatResponse]
    total: int
    page: int
    size: int
    pages: int


# Mitigation schemas
class MitigationBase(BaseModel):
    """Base mitigation schema"""
    mitigation_type: str
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    implementation_status: str = "planned"
    control_reference: Optional[dict[str, list[str]]] = None
    effectiveness_score: int = Field(default=0, ge=0, le=100)
    cost_estimate_usd: Optional[int] = Field(None, ge=0)
    deadline: Optional[str] = None
    verification_method: Optional[str] = None


class MitigationCreate(MitigationBase):
    """Schema for creating mitigation"""
    threat_id: str
    assigned_to: Optional[str] = None


class MitigationUpdate(BaseModel):
    """Schema for updating mitigation"""
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    mitigation_type: Optional[str] = None
    implementation_status: Optional[str] = None
    effectiveness_score: Optional[int] = Field(None, ge=0, le=100)
    cost_estimate_usd: Optional[int] = Field(None, ge=0)
    assigned_to: Optional[str] = None
    deadline: Optional[str] = None
    verification_method: Optional[str] = None


class MitigationResponse(MitigationBase, DBModel):
    """Schema for mitigation response"""
    id: str
    threat_id: str
    organization_id: str
    assigned_to: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class MitigationListResponse(BaseModel):
    """Schema for paginated mitigation list"""
    items: list[MitigationResponse]
    total: int
    page: int
    size: int
    pages: int


# Attack tree schemas
class AttackTreeBase(BaseModel):
    """Base attack tree schema"""
    name: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    root_goal: str = Field(..., min_length=1)
    tree_structure: Optional[dict[str, Any]] = None


class AttackTreeCreate(AttackTreeBase):
    """Schema for creating attack tree"""
    model_id: str


class AttackTreeUpdate(BaseModel):
    """Schema for updating attack tree"""
    name: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    root_goal: Optional[str] = None
    tree_structure: Optional[dict[str, Any]] = None


class AttackTreeResponse(AttackTreeBase, DBModel):
    """Schema for attack tree response"""
    id: str
    model_id: str
    organization_id: str
    total_attack_paths: int
    minimum_cost_path_usd: Optional[int] = None
    minimum_skill_path: Optional[str] = None
    highest_probability_path: Optional[str] = None
    generated_from_stride: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AttackTreeListResponse(BaseModel):
    """Schema for paginated attack tree list"""
    items: list[AttackTreeResponse]
    total: int
    page: int
    size: int
    pages: int


# Analysis schemas
class STRIDEAnalysisRequest(BaseModel):
    """Request for STRIDE analysis"""
    model_id: str
    component_ids: Optional[list[str]] = None
    auto_generate: bool = True


class STRIDEAnalysisResponse(BaseModel):
    """Response from STRIDE analysis"""
    status: str
    model_id: str
    threats_generated: int
    timestamp: str


class PASTAAnalysisRequest(BaseModel):
    """Request for PASTA analysis"""
    model_id: str
    include_attack_trees: bool = True


class PASTAAnalysisResponse(BaseModel):
    """Response from PASTA analysis"""
    status: str
    model_id: str
    stages_completed: int
    timestamp: str


# Validation schemas
class ValidationRequest(BaseModel):
    """Request for model validation"""
    model_id: str
    check_completeness: bool = True
    check_coverage: bool = True
    check_staleness: bool = True


class ValidationResponse(BaseModel):
    """Validation report response"""
    model_id: str
    model_name: str
    overall_valid: bool
    completeness: dict[str, Any]
    coverage: dict[str, Any]
    is_stale: bool
    recommendations: list[str]
    timestamp: str


# Dashboard schemas
class ThreatModelDashboard(BaseModel):
    """Dashboard data for threat models"""
    total_models: int
    total_threats: int
    high_risk_threats: int
    mitigations_planned: int
    mitigations_implemented: int
    average_risk_score: float
    models_by_status: dict[str, int]
    threats_by_stride: dict[str, int]


class RiskMatrix(BaseModel):
    """Risk matrix data"""
    likelihood_levels: list[str]
    impact_levels: list[str]
    data: dict[str, dict[str, int]]


# Recommendation schemas
class MitigationRecommendation(BaseModel):
    """Recommended mitigation"""
    type: str
    title: str
    description: str
    controls: dict[str, list[str]]
    cost_estimate: int
    priority_score: Optional[float] = None


class RecommendationResponse(BaseModel):
    """Response with mitigation recommendations"""
    threat_id: str
    recommendations: list[MitigationRecommendation]
