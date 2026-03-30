"""Threat modeling models for STRIDE, PASTA, and attack tree analysis"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.user import User


class ThreatModelMethodology(str, Enum):
    """Threat modeling methodologies"""

    STRIDE = "stride"
    PASTA = "pasta"
    ATTACK_TREE = "attack_tree"
    LINDDUN = "linddun"
    VAST = "vast"
    OCTAVE = "octave"
    CUSTOM = "custom"


class ThreatModelStatus(str, Enum):
    """Status of threat model"""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    OUTDATED = "outdated"
    ARCHIVED = "archived"


class ComponentType(str, Enum):
    """Types of architectural components"""

    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"
    DATA_FLOW = "data_flow"
    TRUST_BOUNDARY = "trust_boundary"
    API_ENDPOINT = "api_endpoint"
    SERVICE = "service"
    DATABASE = "database"
    MESSAGE_QUEUE = "message_queue"
    CACHE = "cache"
    CDN = "cdn"
    LOAD_BALANCER = "load_balancer"


class STRIDECategory(str, Enum):
    """STRIDE threat categories"""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatStatus(str, Enum):
    """Status of identified threat"""

    IDENTIFIED = "identified"
    ANALYZING = "analyzing"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    TRANSFERRED = "transferred"
    DEFERRED = "deferred"


class LikelihoodLevel(str, Enum):
    """Likelihood of threat occurrence"""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class ImpactLevel(str, Enum):
    """Impact level of threat"""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class MitigationType(str, Enum):
    """Types of mitigations"""

    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"
    DETERRENT = "deterrent"


class ImplementationStatus(str, Enum):
    """Status of mitigation implementation"""

    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    NOT_APPLICABLE = "not_applicable"


class ThreatModel(BaseModel):
    """Main threat model entity"""

    __tablename__ = "threat_models"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    application_name: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[str] = mapped_column(String(50), default="1.0", nullable=False)
    methodology: Mapped[str] = mapped_column(
        String(50),
        default=ThreatModelMethodology.STRIDE.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=ThreatModelStatus.DRAFT.value,
        nullable=False,
        index=True,
    )
    scope: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    architecture_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # DFD structure: {"nodes": [...], "edges": [...], "trust_boundaries": [...]}
    data_flow_diagram: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    created_by: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )
    reviewed_by: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )
    review_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    threats_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    mitigations_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    creator: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[created_by],
        lazy="selectin",
    )
    reviewer: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[reviewed_by],
        lazy="selectin",
    )
    components: Mapped[list["ThreatModelComponent"]] = relationship(
        "ThreatModelComponent",
        back_populates="model",
        cascade="all, delete-orphan",
    )
    threats: Mapped[list["IdentifiedThreat"]] = relationship(
        "IdentifiedThreat",
        back_populates="model",
        cascade="all, delete-orphan",
    )
    attack_trees: Mapped[list["AttackTree"]] = relationship(
        "AttackTree",
        back_populates="model",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ThreatModel {self.id}: {self.name}>"


class ThreatModelComponent(BaseModel):
    """Component within a threat model"""

    __tablename__ = "threat_model_components"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    model_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("threat_models.id"),
        nullable=False,
        index=True,
    )
    component_type: Mapped[str] = mapped_column(
        String(100),
        default=ComponentType.PROCESS.value,
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technology_stack: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    data_classification: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    trust_level: Mapped[str] = mapped_column(String(50), default="untrusted")

    # Position for diagram: {"x": 100, "y": 200}
    position: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Connected components: ["component_id_1", "component_id_2"]
    connections: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)

    # Relationships
    model: Mapped["ThreatModel"] = relationship(
        "ThreatModel",
        back_populates="components",
    )
    threats: Mapped[list["IdentifiedThreat"]] = relationship(
        "IdentifiedThreat",
        back_populates="component",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ThreatModelComponent {self.id}: {self.name}>"


class IdentifiedThreat(BaseModel):
    """Identified threat for a component"""

    __tablename__ = "identified_threats"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    model_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("threat_models.id"),
        nullable=False,
        index=True,
    )
    component_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("threat_model_components.id"),
        nullable=True,
        index=True,
    )

    stride_category: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )
    pasta_stage: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    threat_description: Mapped[str] = mapped_column(Text, nullable=False)
    attack_vector: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    preconditions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    impact_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    likelihood: Mapped[str] = mapped_column(
        String(50),
        default=LikelihoodLevel.MEDIUM.value,
        nullable=False,
    )
    impact: Mapped[str] = mapped_column(
        String(50),
        default=ImpactLevel.MEDIUM.value,
        nullable=False,
    )
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # MITRE ATT&CK and CWE mappings: ["T1234", "T5678"]
    mitre_technique_ids: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    cwe_ids: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)

    status: Mapped[str] = mapped_column(
        String(50),
        default=ThreatStatus.IDENTIFIED.value,
        nullable=False,
        index=True,
    )
    priority: Mapped[int] = mapped_column(Integer, default=3, nullable=False)

    # Relationships
    model: Mapped["ThreatModel"] = relationship(
        "ThreatModel",
        back_populates="threats",
    )
    component: Mapped[Optional["ThreatModelComponent"]] = relationship(
        "ThreatModelComponent",
        back_populates="threats",
    )
    mitigations: Mapped[list["ThreatMitigation"]] = relationship(
        "ThreatMitigation",
        back_populates="threat",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<IdentifiedThreat {self.id}: {self.threat_description[:50]}>"


class ThreatMitigation(BaseModel):
    """Mitigation for an identified threat"""

    __tablename__ = "threat_mitigations"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    threat_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("identified_threats.id"),
        nullable=False,
        index=True,
    )

    mitigation_type: Mapped[str] = mapped_column(
        String(50),
        default=MitigationType.PREVENTIVE.value,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    implementation_status: Mapped[str] = mapped_column(
        String(50),
        default=ImplementationStatus.PLANNED.value,
        nullable=False,
        index=True,
    )

    # Control references: {"nist": ["AC-2", "AC-3"], "cis": ["2.1"], "owasp": ["A01:2021"]}
    control_reference: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    effectiveness_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cost_estimate_usd: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=True,
    )
    deadline: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    verification_method: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    threat: Mapped["IdentifiedThreat"] = relationship(
        "IdentifiedThreat",
        back_populates="mitigations",
    )
    assignee: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[assigned_to],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<ThreatMitigation {self.id}: {self.title}>"


class AttackTree(BaseModel):
    """Attack tree for threat analysis"""

    __tablename__ = "attack_trees"

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    model_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("threat_models.id"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    root_goal: Mapped[str] = mapped_column(Text, nullable=False)

    # Tree structure: recursive JSON with nodes and AND/OR gates
    # {"id": "root", "goal": "...", "type": "OR", "children": [...]}
    tree_structure: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    total_attack_paths: Mapped[int] = mapped_column(Integer, default=0)
    minimum_cost_path_usd: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    minimum_skill_path: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    highest_probability_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    generated_from_stride: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    model: Mapped["ThreatModel"] = relationship(
        "ThreatModel",
        back_populates="attack_trees",
    )

    def __repr__(self) -> str:
        return f"<AttackTree {self.id}: {self.name}>"
