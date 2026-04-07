"""
Pydantic schemas for BAS engine API requests and responses.

Defines input validation and output serialization for simulation operations.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from src.schemas.base import DBModel
from pydantic import BaseModel, Field, validator


class AttackTechniqueSchema(DBModel):
    """Schema for AttackTechnique model."""

    id: str = ""
    mitre_id: str = ""
    name: str = ""
    tactic: str = ""
    description: Optional[str] = None
    platform: List[str] = Field(default_factory=list)
    test_commands: List[Dict[str, Any]] = Field(default_factory=list)
    detection_sources: List[str] = Field(default_factory=list)
    expected_detection: Optional[str] = None
    risk_level: str = "medium"
    requires_privileges: str = "user"
    is_safe: bool = True
    is_enabled: bool = True
    atomic_test_ref: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SimulationTestSchema(DBModel):
    """Schema for SimulationTest results."""

    id: str = ""
    simulation_id: str = ""
    technique_id: str = ""
    test_name: str = ""
    test_order: int = 0
    status: str = ""
    target_host: Optional[str] = None
    executor: str = ""
    command_executed: Optional[str] = None
    cleanup_command: Optional[str] = None
    cleanup_status: Optional[str] = None
    output: Optional[str] = None
    error_output: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    was_detected: Optional[bool] = None
    detection_time_seconds: Optional[int] = None
    detection_source: Optional[str] = None
    detection_details: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AttackSimulationSchema(DBModel):
    """Schema for AttackSimulation model."""

    id: str = ""
    name: str = ""
    description: Optional[str] = None
    simulation_type: str = ""
    status: str = ""
    target_environment: str = ""
    scope: Dict[str, Any]
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    blocked_tests: int = 0
    detection_rate: Optional[float] = None
    overall_score: Optional[float] = None
    created_by: str = ""
    approved_by: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AdversaryProfileSchema(DBModel):
    """Schema for AdversaryProfile model."""

    id: str = ""
    name: str = ""
    description: Optional[str] = None
    threat_actor_ref: Optional[str] = None
    sophistication: str = ""
    attack_chain: List[str] = Field(default_factory=list)
    objectives: List[str] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)
    target_sectors: List[str] = Field(default_factory=list)
    tools_used: List[str] = Field(default_factory=list)
    is_builtin: bool = False
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SecurityPostureScoreSchema(DBModel):
    """Schema for SecurityPostureScore model."""

    id: str = ""
    simulation_id: Optional[str] = None
    score_type: str = ""
    score: float = 0.0
    max_score: float = 100.0
    breakdown: Dict[str, Any] = Field(default_factory=dict)
    comparison_to_previous: Optional[float] = None
    recommendations: List[str] = Field(default_factory=list)
    assessed_at: Optional[datetime] = None
    organization_id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SimulationCreateRequest(BaseModel):
    """Request body for creating a simulation."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    simulation_type: str = Field(
        ...,
        description="atomic_test, attack_chain, adversary_emulation, purple_team, continuous_validation"
    )
    techniques: List[str] = Field(default_factory=list)
    scope: Dict[str, Any] = Field(default_factory=dict, description="Target scope: hosts, networks, users")
    target_environment: str = Field(
        ...,
        description="production, staging, lab, isolated"
    )
    tags: Optional[List[str]] = None

    @validator("target_environment")
    def validate_environment(cls, v):
        valid = ["production", "staging", "lab", "isolated"]
        if v not in valid:
            raise ValueError(f"target_environment must be one of {valid}")
        return v

    @validator("simulation_type")
    def validate_sim_type(cls, v):
        valid = ["atomic_test", "attack_chain", "adversary_emulation", "purple_team", "continuous_validation"]
        if v not in valid:
            raise ValueError(f"simulation_type must be one of {valid}")
        return v


class SimulationProgressResponse(BaseModel):
    """Response for simulation progress endpoint."""

    simulation_id: str = ""
    status: str = ""
    pending_tests: int = 0
    running_tests: int = 0
    completed_tests: int = 0
    total_tests: int = 0
    current_test: Optional[str] = None
    progress_percent: int = 0


class TechniqueTestResult(BaseModel):
    """Result of a single technique test execution."""

    test_id: str = ""
    status: str = ""
    detected: Optional[bool] = None
    detection_time: Optional[int] = None
    detection_source: Optional[str] = None
    detection_details: Optional[Dict[str, Any]] = None
    command_executed: Optional[str] = None
    output: Optional[str] = None
    error_output: Optional[str] = None


class PostureScoreResponse(BaseModel):
    """Response for posture score calculation."""

    simulation_id: Optional[str] = None
    score_type: str = ""
    score: float = 0.0
    max_score: float = 0.0
    breakdown: Dict[str, Any] = Field(default_factory=dict)
    comparison_to_previous: Optional[float] = None
    recommendations: List[str] = Field(default_factory=list)
    assessed_at: Optional[datetime] = None


class GapAnalysisItem(BaseModel):
    """Individual gap in security posture."""

    mitre_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    risk_level: str = ""
    detection_sources: List[str]
    expected_detection: Optional[str] = None
    recommendation: str = ""


class GapAnalysisResponse(BaseModel):
    """Response for gap analysis endpoint."""

    simulation_id: str = ""
    total_gaps: int = 0
    critical_gaps: int = 0
    high_gaps: int = 0
    medium_gaps: int = 0
    low_gaps: int = 0
    gaps: List[GapAnalysisItem]


class AttackChainItem(BaseModel):
    """Item in adversary attack chain."""

    order: int = 0
    mitre_id: str = ""
    name: str = ""
    tactic: str = ""
    description: Optional[str] = None


class AdversaryEmulationPlanResponse(BaseModel):
    """Response for adversary emulation plan creation."""

    simulation_id: str = ""
    adversary_name: str = ""
    attack_chain: List[AttackChainItem]
    total_techniques: int = 0
    objectives: List[str]
    description: Optional[str] = None


class SimulationDetailResponse(BaseModel):
    """Detailed response for a simulation with test results."""

    simulation: AttackSimulationSchema
    tests: List[SimulationTestSchema]
    posture_score: Optional[SecurityPostureScoreSchema] = None
    execution_summary: Dict[str, Any]


class SimulationReportResponse(BaseModel):
    """Comprehensive simulation report."""

    simulation_name: str = ""
    simulation_id: str = ""
    overall_score: float = 0.0
    total_tests: int = 0
    tests_detected: int = 0
    detection_rate_percent: float = 0.0
    techniques_assessed: int = 0
    tactics_covered: List[str]
    undetected_gaps: int = 0
    critical_gaps: int = 0
    top_recommendations: List[str]
    assessed_at: str = ""


class SimulationListResponse(BaseModel):
    """Response for listing simulations."""

    total: int = 0
    page: int = 0
    page_size: int = 0
    simulations: List[AttackSimulationSchema]


class TechniqueListResponse(BaseModel):
    """Response for listing techniques."""

    total: int = 0
    techniques: List[AttackTechniqueSchema]
    facets: Optional[Dict[str, Dict[str, int]]] = None  # Count by tactic, risk_level, etc.


class AdversaryListResponse(BaseModel):
    """Response for listing adversary profiles."""

    total: int = 0
    adversaries: List[AdversaryProfileSchema]


class DashboardStatsResponse(BaseModel):
    """BAS dashboard statistics."""

    total_simulations: int = 0
    completed_simulations: int = 0
    running_simulations: int = 0
    average_detection_rate: float = 0.0
    average_posture_score: float = 0.0
    techniques_in_library: int = 0
    adversary_profiles: int = 0
    top_tactics: List[Dict[str, Any]]
    recent_simulations: List[AttackSimulationSchema]
    security_trends: Dict[str, List[float]]  # Score trend over time


class SimulationApprovalRequest(BaseModel):
    """Request to approve a production simulation."""

    simulation_id: str = ""
    approved: bool = False
    approval_notes: Optional[str] = None


class BulkSimulationRequest(BaseModel):
    """Request to run multiple simulations in batch."""

    simulations: List[SimulationCreateRequest]
    run_sequentially: bool = False
    schedule_interval: Optional[int] = None  # Minutes between runs


class TechniqueSearchResponse(BaseModel):
    """Response for technique search/discovery."""

    results: List[AttackTechniqueSchema]
    total_results: int = 0
    facets: Dict[str, Dict[str, int]]
