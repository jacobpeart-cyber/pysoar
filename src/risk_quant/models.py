"""Risk Quantification models for FAIR-based risk analysis

Models for risk scenarios, FAIR analysis, risk registers, controls, and business impact assessment.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel


class ThreatActor(str, Enum):
    """Types of threat actors"""

    EXTERNAL_ATTACKER = "external_attacker"
    INSIDER_THREAT = "insider_threat"
    NATION_STATE = "nation_state"
    HACKTIVIST = "hacktivist"
    COMPETITOR = "competitor"
    ACCIDENTAL = "accidental"
    NATURAL_DISASTER = "natural_disaster"


class LossType(str, Enum):
    """Types of losses"""

    PRODUCTIVITY = "productivity"
    RESPONSE = "response"
    REPLACEMENT = "replacement"
    FINES_JUDGMENTS = "fines_judgments"
    REPUTATION = "reputation"
    COMPETITIVE_ADVANTAGE = "competitive_advantage"


class RiskStatus(str, Enum):
    """Status of risk scenario analysis"""

    DRAFT = "draft"
    ANALYSIS = "analysis"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    ARCHIVED = "archived"


class RiskScenario(BaseModel):
    """Risk scenario model for FAIR analysis"""

    __tablename__ = "risk_scenarios"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Basic identification
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Asset information
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    asset_name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_value_usd: Mapped[float] = mapped_column(Float, nullable=False)

    # Threat actor and type
    threat_actor: Mapped[str] = mapped_column(
        String(50),
        default=ThreatActor.EXTERNAL_ATTACKER.value,
        nullable=False,
    )
    threat_type: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerability_exploited: Mapped[str] = mapped_column(String(255), nullable=False)

    # Loss classification
    loss_type: Mapped[str] = mapped_column(
        String(50),
        default=LossType.PRODUCTIVITY.value,
        nullable=False,
    )

    # Status and analysis tracking
    status: Mapped[str] = mapped_column(
        String(50),
        default=RiskStatus.DRAFT.value,
        nullable=False,
    )
    analyst_id: Mapped[str] = mapped_column(String(36), nullable=False)
    review_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    confidence_level: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)

    def __repr__(self) -> str:
        return f"<RiskScenario {self.name}>"


class FAIRAnalysis(BaseModel):
    """FAIR (Factor Analysis of Information Risk) analysis model"""

    __tablename__ = "fair_analyses"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationship to scenario
    scenario_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Threat Event Frequency (TEF) - per year, PERT distribution
    tef_min: Mapped[float] = mapped_column(Float, nullable=False)
    tef_mode: Mapped[float] = mapped_column(Float, nullable=False)
    tef_max: Mapped[float] = mapped_column(Float, nullable=False)

    # Vulnerability (Vuln) - probability 0-1, PERT distribution
    vuln_min: Mapped[float] = mapped_column(Float, nullable=False)
    vuln_mode: Mapped[float] = mapped_column(Float, nullable=False)
    vuln_max: Mapped[float] = mapped_column(Float, nullable=False)

    # Threat Capability (ThreatCap) - 0-1 scale, PERT distribution
    tcap_min: Mapped[float] = mapped_column(Float, nullable=False)
    tcap_mode: Mapped[float] = mapped_column(Float, nullable=False)
    tcap_max: Mapped[float] = mapped_column(Float, nullable=False)

    # Resistance Strength (RS) - 0-1 scale, PERT distribution
    rs_min: Mapped[float] = mapped_column(Float, nullable=False)
    rs_mode: Mapped[float] = mapped_column(Float, nullable=False)
    rs_max: Mapped[float] = mapped_column(Float, nullable=False)

    # Loss Magnitude (LM) - USD, PERT distribution
    lm_min: Mapped[float] = mapped_column(Float, nullable=False)
    lm_mode: Mapped[float] = mapped_column(Float, nullable=False)
    lm_max: Mapped[float] = mapped_column(Float, nullable=False)

    # Primary loss distribution
    primary_loss_min: Mapped[float] = mapped_column(Float, nullable=False)
    primary_loss_mode: Mapped[float] = mapped_column(Float, nullable=False)
    primary_loss_max: Mapped[float] = mapped_column(Float, nullable=False)

    # Secondary loss distribution
    secondary_loss_min: Mapped[float] = mapped_column(Float, nullable=False)
    secondary_loss_mode: Mapped[float] = mapped_column(Float, nullable=False)
    secondary_loss_max: Mapped[float] = mapped_column(Float, nullable=False)
    secondary_loss_event_frequency: Mapped[float] = mapped_column(
        Float, nullable=False
    )

    # Simulation parameters
    simulation_iterations: Mapped[int] = mapped_column(Integer, default=10000)

    # Results: Annualized Loss Expectancy
    ale_mean: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ale_p10: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ale_p50: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ale_p90: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ale_p99: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Loss exceedance curve (JSON format: {x_values: [...], y_values: [...]})
    loss_exceedance_curve: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Completion timestamp
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<FAIRAnalysis {self.scenario_id}>"


class RiskRegister(BaseModel):
    """Enterprise risk register model"""

    __tablename__ = "risk_registers"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Basic identification
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Risk classification
    risk_category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Risk scoring
    inherent_risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    residual_risk_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Risk treatment
    risk_treatment: Mapped[str] = mapped_column(String(50), nullable=False)
    treatment_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Control effectiveness
    control_effectiveness: Mapped[float] = mapped_column(Float, default=0.0)

    # Ownership and review
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False)
    review_frequency_days: Mapped[int] = mapped_column(Integer, default=90)
    last_review: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_review: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Financial metrics
    ale_annual_usd: Mapped[float] = mapped_column(Float, nullable=False)
    risk_appetite_threshold_usd: Mapped[float] = mapped_column(Float, nullable=False)
    is_within_appetite: Mapped[bool] = mapped_column(Boolean, default=True)

    def __repr__(self) -> str:
        return f"<RiskRegister {self.name}>"


class ControlType(str, Enum):
    """Types of risk controls"""

    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    DETERRENT = "deterrent"
    COMPENSATING = "compensating"
    RECOVERY = "recovery"


class ControlStatus(str, Enum):
    """Implementation status of controls"""

    PLANNED = "planned"
    IMPLEMENTING = "implementing"
    OPERATIONAL = "operational"
    NEEDS_IMPROVEMENT = "needs_improvement"
    FAILED = "failed"


class RiskControl(BaseModel):
    """Risk control model for managing mitigation controls"""

    __tablename__ = "risk_controls"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Relationship to risk register
    risk_register_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Control identification
    control_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    control_type: Mapped[str] = mapped_column(
        String(50),
        default=ControlType.PREVENTIVE.value,
        nullable=False,
    )

    # Implementation status
    implementation_status: Mapped[str] = mapped_column(
        String(50),
        default=ControlStatus.PLANNED.value,
        nullable=False,
    )

    # Effectiveness metrics
    effectiveness_score: Mapped[float] = mapped_column(Float, default=0.0)
    cost_annual_usd: Mapped[float] = mapped_column(Float, nullable=False)
    roi_percentage: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Framework mappings (JSON: NIST, ISO, CIS controls)
    frameworks_mapped: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Testing and validation
    last_tested: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    test_result: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    def __repr__(self) -> str:
        return f"<RiskControl {self.control_name}>"


class AssetType(str, Enum):
    """Types of business assets"""

    APPLICATION = "application"
    DATABASE = "database"
    INFRASTRUCTURE = "infrastructure"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    CUSTOMER_DATA = "customer_data"
    FINANCIAL_SYSTEM = "financial_system"
    COMMUNICATION_SYSTEM = "communication_system"


class Criticality(str, Enum):
    """Asset criticality levels"""

    MISSION_CRITICAL = "mission_critical"
    BUSINESS_CRITICAL = "business_critical"
    IMPORTANT = "important"
    SUPPORTING = "supporting"
    NON_ESSENTIAL = "non_essential"


class BusinessImpactAssessment(BaseModel):
    """Business Impact Assessment (BIA) model"""

    __tablename__ = "business_impact_assessments"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Asset identification
    asset_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(
        String(50),
        default=AssetType.APPLICATION.value,
        nullable=False,
    )
    business_unit: Mapped[str] = mapped_column(String(255), nullable=False)

    # Criticality assessment
    criticality: Mapped[str] = mapped_column(
        String(50),
        default=Criticality.BUSINESS_CRITICAL.value,
        nullable=False,
    )

    # Recovery objectives
    rto_hours: Mapped[float] = mapped_column(Float, nullable=False)
    rpo_hours: Mapped[float] = mapped_column(Float, nullable=False)
    mtpd_hours: Mapped[float] = mapped_column(Float, nullable=False)

    # Financial impact
    financial_impact_per_hour_usd: Mapped[float] = mapped_column(Float, nullable=False)

    # Reputational and regulatory impact
    reputational_impact_score: Mapped[float] = mapped_column(Float, nullable=False)
    regulatory_impact_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Dependencies (JSON format)
    dependencies: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Single point of failure assessment
    single_point_of_failure: Mapped[bool] = mapped_column(Boolean, default=False)

    def __repr__(self) -> str:
        return f"<BusinessImpactAssessment {self.asset_name}>"


# Import Boolean from sqlalchemy
from sqlalchemy import Boolean
