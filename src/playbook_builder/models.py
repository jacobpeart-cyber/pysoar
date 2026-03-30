"""Database models for Visual Playbook Builder"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    pass


class PlaybookCategory(str, Enum):
    """Playbook category types"""

    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"
    ENRICHMENT = "enrichment"
    NOTIFICATION = "notification"
    CUSTOM = "custom"


class PlaybookStatus(str, Enum):
    """Playbook status"""

    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class TriggerType(str, Enum):
    """Playbook trigger types"""

    ALERT = "alert"
    SCHEDULE = "schedule"
    WEBHOOK = "webhook"
    MANUAL = "manual"
    EVENT = "event"
    THRESHOLD = "threshold"
    API_CALL = "api_call"


class NodeType(str, Enum):
    """Node types in a playbook"""

    TRIGGER = "trigger"
    ACTION = "action"
    CONDITION = "condition"
    LOOP = "loop"
    PARALLEL = "parallel"
    DELAY = "delay"
    HUMAN_APPROVAL = "human_approval"
    TRANSFORM = "transform"
    SUBPLAYBOOK = "subplaybook"
    ERROR_HANDLER = "error_handler"
    VARIABLE_SET = "variable_set"
    API_CALL = "api_call"
    NOTIFICATION = "notification"
    ENRICHMENT = "enrichment"


class EdgeType(str, Enum):
    """Edge types connecting nodes"""

    SUCCESS = "success"
    FAILURE = "failure"
    CONDITIONAL = "conditional"
    ALWAYS = "always"
    TIMEOUT = "timeout"
    ERROR = "error"


class ExecutionStatus(str, Enum):
    """Playbook execution status"""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class NodeExecutionStatus(str, Enum):
    """Node execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"


class ErrorHandler(str, Enum):
    """Error handling strategies"""

    STOP = "stop"
    CONTINUE = "continue"
    GOTO = "goto"
    RETRY = "retry"


class VisualPlaybook(BaseModel):
    """Visual playbook model"""

    __tablename__ = "visual_playbooks"

    # Core fields
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Classification
    category: Mapped[str] = mapped_column(
        String(50),
        default=PlaybookCategory.CUSTOM.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=PlaybookStatus.DRAFT.value,
        nullable=False,
        index=True,
    )

    # Trigger configuration
    trigger_type: Mapped[str] = mapped_column(
        String(50),
        default=TriggerType.MANUAL.value,
        nullable=False,
    )
    trigger_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Visual editor data
    canvas_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Performance metrics
    execution_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    avg_execution_time_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    success_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_executed: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Metadata
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    is_template: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    template_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Relationships
    nodes: Mapped[list["PlaybookNode"]] = relationship(
        "PlaybookNode",
        back_populates="playbook",
        cascade="all, delete-orphan",
    )
    edges: Mapped[list["PlaybookEdge"]] = relationship(
        "PlaybookEdge",
        back_populates="playbook",
        cascade="all, delete-orphan",
    )
    executions: Mapped[list["VisualPlaybookExecution"]] = relationship(
        "VisualPlaybookExecution",
        back_populates="playbook",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<VisualPlaybook {self.name}>"


class PlaybookNode(BaseModel):
    """Node in a visual playbook"""

    __tablename__ = "playbook_nodes"

    # Foreign keys
    playbook_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("visual_playbooks.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Identity
    node_id: Mapped[str] = mapped_column(String(100), nullable=False)  # Unique within playbook
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Display
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Position (for visual editor)
    position_x: Mapped[float] = mapped_column(Float, nullable=False)
    position_y: Mapped[float] = mapped_column(Float, nullable=False)

    # Configuration
    config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    input_schema: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    output_schema: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Execution settings
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    on_error: Mapped[str] = mapped_column(
        String(50),
        default=ErrorHandler.STOP.value,
        nullable=False,
    )

    # Relationships
    playbook: Mapped["VisualPlaybook"] = relationship(
        "VisualPlaybook",
        back_populates="nodes",
    )
    def __repr__(self) -> str:
        return f"<PlaybookNode {self.node_id}:{self.node_type}>"


class PlaybookEdge(BaseModel):
    """Connection between nodes in a playbook"""

    __tablename__ = "playbook_edges"

    # Foreign keys
    playbook_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("visual_playbooks.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Connection
    source_node_id: Mapped[str] = mapped_column(String(100), nullable=False)
    target_node_id: Mapped[str] = mapped_column(String(100), nullable=False)

    # Edge properties
    edge_type: Mapped[str] = mapped_column(
        String(50),
        default=EdgeType.SUCCESS.value,
        nullable=False,
    )
    condition_expression: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    playbook: Mapped["VisualPlaybook"] = relationship(
        "VisualPlaybook",
        back_populates="edges",
    )

    def __repr__(self) -> str:
        return f"<PlaybookEdge {self.source_node_id}->{self.target_node_id}>"


class VisualPlaybookExecution(BaseModel):
    """Execution record of a visual playbook"""

    __tablename__ = "visual_playbook_executions"

    # Foreign keys
    playbook_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("visual_playbooks.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    parent_execution_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("visual_playbook_executions.id"),
        nullable=True,
    )

    # Trigger
    trigger_event: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        default=ExecutionStatus.PENDING.value,
        nullable=False,
        index=True,
    )
    current_node_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Timing
    started_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Execution data
    execution_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    variables: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    triggered_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Relationships
    playbook: Mapped["VisualPlaybook"] = relationship(
        "VisualPlaybook",
        back_populates="executions",
    )
    node_executions: Mapped[list["PlaybookNodeExecution"]] = relationship(
        "PlaybookNodeExecution",
        back_populates="execution",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<VisualPlaybookExecution {self.id}:{self.status}>"


class PlaybookNodeExecution(BaseModel):
    """Execution record for a specific node"""

    __tablename__ = "playbook_node_executions"

    # Foreign keys
    execution_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("visual_playbook_executions.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Node reference
    node_id: Mapped[str] = mapped_column(String(100), nullable=False)

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        default=NodeExecutionStatus.PENDING.value,
        nullable=False,
    )

    # Timing
    started_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Data
    input_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    output_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Retry tracking
    retry_attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Approval
    approved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Relationships
    execution: Mapped["VisualPlaybookExecution"] = relationship(
        "VisualPlaybookExecution",
        back_populates="node_executions",
    )
    def __repr__(self) -> str:
        return f"<PlaybookNodeExecution {self.node_id}:{self.status}>"
