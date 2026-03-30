"""
SQLAlchemy models for Breach & Attack Simulation (BAS) engine.

Defines schemas for simulations, techniques, tests, adversary profiles,
and security posture scoring.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, Integer, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from src.models.base import BaseModel


class AttackSimulation(BaseModel):
    """
    Represents a single breach and attack simulation campaign.

    Tracks the execution status, scope, test results, and security
    posture improvements from a simulation.
    """

    __tablename__ = "attack_simulations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    simulation_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="atomic_test, attack_chain, adversary_emulation, purple_team, continuous_validation"
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="draft",
        nullable=False,
        comment="draft, scheduled, running, paused, completed, failed, cancelled"
    )
    target_environment: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="production, staging, lab, isolated"
    )

    scope: Mapped[dict] = mapped_column(JSON, default={}, nullable=False)
    mitre_tactics: Mapped[list] = mapped_column(JSON, default=[], nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=[], nullable=False)

    scheduled_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    total_tests: Mapped[int] = mapped_column(Integer, default=0)
    passed_tests: Mapped[int] = mapped_column(Integer, default=0)
    failed_tests: Mapped[int] = mapped_column(Integer, default=0)
    blocked_tests: Mapped[int] = mapped_column(Integer, default=0)

    detection_rate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="blocked / total * 100"
    )
    overall_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="0-100 security posture score"
    )

    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
        comment="required for production simulations"
    )

    tags: Mapped[list] = mapped_column(JSON, default=[], nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    def __repr__(self) -> str:
        return f"<AttackSimulation(id={self.id}, name={self.name}, status={self.status})>"


class AttackTechnique(BaseModel):
    """
    Represents a MITRE ATT&CK technique with test commands and detection expectations.

    Used to execute atomic tests and validate detection capabilities.
    """

    __tablename__ = "attack_techniques"

    mitre_id: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    platform: Mapped[list] = mapped_column(
        JSON,
        default=[],
        nullable=False,
        comment="windows, linux, macos, cloud, network"
    )
    test_commands: Mapped[list] = mapped_column(
        JSON,
        default=[],
        nullable=False,
        comment="list of {platform, command, cleanup, executor}"
    )
    detection_sources: Mapped[list] = mapped_column(
        JSON,
        default=[],
        nullable=False,
        comment="where detection should trigger"
    )
    expected_detection: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="what the SIEM rule should catch"
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="medium",
        comment="low, medium, high, critical"
    )
    requires_privileges: Mapped[str] = mapped_column(
        String(50),
        default="user",
        comment="user, admin, system, root"
    )
    is_safe: Mapped[bool] = mapped_column(Boolean, default=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    atomic_test_ref: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Atomic Red Team reference"
    )
    tags: Mapped[list] = mapped_column(JSON, default=[], nullable=False)

    def __repr__(self) -> str:
        return f"<AttackTechnique(mitre_id={self.mitre_id}, name={self.name})>"


class SimulationTest(BaseModel):
    """
    Represents a single test execution within a simulation.

    Tracks execution status, command output, detection results,
    and timing information for each technique test.
    """

    __tablename__ = "simulation_tests"

    simulation_id: Mapped[str] = mapped_column(String(36), ForeignKey("attack_simulations.id"), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(36), ForeignKey("attack_techniques.id"), nullable=False)

    test_name: Mapped[str] = mapped_column(String(255), nullable=False)
    test_order: Mapped[int] = mapped_column(Integer, default=0)

    status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        comment="pending, running, passed, failed, blocked, error, skipped"
    )
    target_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    executor: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="powershell, bash, cmd, python, manual"
    )

    command_executed: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cleanup_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cleanup_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    was_detected: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    detection_time_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detection_source: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="which SIEM rule/system detected it"
    )
    detection_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<SimulationTest(id={self.id}, test_name={self.test_name}, status={self.status})>"


class AdversaryProfile(BaseModel):
    """
    Represents a threat actor profile with attack chain and objectives.

    Used for adversary emulation simulations to replay known attack patterns.
    """

    __tablename__ = "adversary_profiles"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    threat_actor_ref: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    sophistication: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="script_kiddie, intermediate, advanced, apt"
    )

    attack_chain: Mapped[list] = mapped_column(
        JSON,
        default=[],
        nullable=False,
        comment="ordered technique IDs representing their typical attack flow"
    )
    objectives: Mapped[list] = mapped_column(
        JSON,
        default=[],
        nullable=False,
        comment="attack objectives (e.g., data exfiltration, disruption)"
    )
    ttps: Mapped[list] = mapped_column(
        JSON,
        default=[],
        nullable=False,
        comment="MITRE technique IDs"
    )
    target_sectors: Mapped[list] = mapped_column(JSON, default=[], nullable=False)
    tools_used: Mapped[list] = mapped_column(JSON, default=[], nullable=False)

    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    def __repr__(self) -> str:
        return f"<AdversaryProfile(id={self.id}, name={self.name})>"


class SecurityPostureScore(BaseModel):
    """
    Represents a security posture assessment score.

    Tracks overall security effectiveness across multiple dimensions
    and provides recommendations for improvement.
    """

    __tablename__ = "security_posture_scores"

    simulation_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("attack_simulations.id"),
        nullable=True
    )

    score_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="overall, detection, prevention, response, by_tactic, by_kill_chain"
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    max_score: Mapped[float] = mapped_column(Float, default=100.0)

    breakdown: Mapped[dict] = mapped_column(
        JSON,
        default={},
        nullable=False,
        comment="per-tactic/technique scores"
    )
    comparison_to_previous: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="delta from previous score"
    )
    recommendations: Mapped[list] = mapped_column(JSON, default=[], nullable=False)

    assessed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    def __repr__(self) -> str:
        return f"<SecurityPostureScore(id={self.id}, score_type={self.score_type}, score={self.score})>"


# Import datetime at module level after class definitions
from datetime import datetime
