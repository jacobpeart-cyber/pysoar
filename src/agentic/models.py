"""Models for Agentic AI SOC Analyst"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    from src.models.organization import Organization


class AgentType(str, Enum):
    """SOC Agent specialization types"""

    TRIAGE_ANALYST = "triage_analyst"
    THREAT_HUNTER = "threat_hunter"
    INCIDENT_RESPONDER = "incident_responder"
    FORENSIC_ANALYST = "forensic_analyst"
    COMPLIANCE_AUDITOR = "compliance_auditor"
    VULNERABILITY_ANALYST = "vulnerability_analyst"


class AgentStatus(str, Enum):
    """Agent operational status"""

    IDLE = "idle"
    INVESTIGATING = "investigating"
    REASONING = "reasoning"
    EXECUTING = "executing"
    AWAITING_APPROVAL = "awaiting_approval"
    PAUSED = "paused"
    ERROR = "error"


class AutonomyLevel(str, Enum):
    """Agent autonomy levels for action execution"""

    FULL_AUTO = "full_auto"  # Execute all actions automatically
    SEMI_AUTO = "semi_auto"  # Execute low-risk, seek approval for high-risk
    HUMAN_IN_LOOP = "human_in_loop"  # Require approval for all actions
    ADVISORY_ONLY = "advisory_only"  # Only provide recommendations


class TriggerType(str, Enum):
    """Investigation trigger sources"""

    ALERT = "alert"
    ANOMALY = "anomaly"
    SCHEDULED_HUNT = "scheduled_hunt"
    MANUAL_REQUEST = "manual_request"
    CORRELATION = "correlation"
    THREAT_INTEL = "threat_intel"
    POLICY_VIOLATION = "policy_violation"


class InvestigationStatus(str, Enum):
    """Investigation lifecycle status"""

    INITIATED = "initiated"
    GATHERING_EVIDENCE = "gathering_evidence"
    ANALYZING = "analyzing"
    REASONING = "reasoning"
    ACTION_PROPOSED = "action_proposed"
    ACTION_EXECUTING = "action_executing"
    AWAITING_HUMAN = "awaiting_human"
    COMPLETED = "completed"
    ESCALATED = "escalated"
    ABANDONED = "abandoned"


class ResolutionType(str, Enum):
    """Investigation resolution outcomes"""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"
    ESCALATED = "escalated"


class StepType(str, Enum):
    """Reasoning step types in the OODA loop"""

    OBSERVE = "observe"
    HYPOTHESIZE = "hypothesize"
    GATHER_EVIDENCE = "gather_evidence"
    ANALYZE = "analyze"
    CORRELATE = "correlate"
    DECIDE = "decide"
    ACT = "act"
    VERIFY = "verify"
    CONCLUDE = "conclude"


class ActionTool(str, Enum):
    """Available tools for gathering evidence and taking action"""

    QUERY_SIEM = "query_siem"
    QUERY_EDR = "query_edr"
    CHECK_THREAT_INTEL = "check_threat_intel"
    ANALYZE_PCAP = "analyze_pcap"
    CHECK_REPUTATION = "check_reputation"
    GEOIP_LOOKUP = "geoip_lookup"
    USER_LOOKUP = "user_lookup"
    ASSET_LOOKUP = "asset_lookup"
    RUN_SANDBOX = "run_sandbox"
    CHECK_VULNERABILITY = "check_vulnerability"
    QUERY_LOGS = "query_logs"
    CORRELATE_EVENTS = "correlate_events"
    CALCULATE_RISK = "calculate_risk"
    NATURAL_LANGUAGE_QUERY = "natural_language_query"


class ActionType(str, Enum):
    """Types of actions the agent can execute"""

    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    RESET_CREDENTIALS = "reset_credentials"
    QUARANTINE_FILE = "quarantine_file"
    UPDATE_FIREWALL_RULE = "update_firewall_rule"
    CREATE_TICKET = "create_ticket"
    SEND_NOTIFICATION = "send_notification"
    ENRICH_IOC = "enrich_ioc"
    RUN_PLAYBOOK = "run_playbook"
    ESCALATE = "escalate"
    ADD_WATCHLIST = "add_watchlist"
    SNAPSHOT_VM = "snapshot_vm"


class ActionExecutionStatus(str, Enum):
    """Action execution lifecycle"""

    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"
    ROLLED_BACK = "rolled_back"


class MemoryType(str, Enum):
    """Types of agent memory for learning"""

    CASE_PATTERN = "case_pattern"
    FALSE_POSITIVE_PATTERN = "false_positive_pattern"
    ATTACK_SIGNATURE = "attack_signature"
    ENVIRONMENT_BASELINE = "environment_baseline"
    ANALYST_PREFERENCE = "analyst_preference"
    ORGANIZATIONAL_CONTEXT = "organizational_context"
    THREAT_LANDSCAPE = "threat_landscape"
    REMEDIATION_OUTCOME = "remediation_outcome"


class SOCAgent(BaseModel):
    """
    Autonomous SOC Agent model

    Represents an AI-powered agent specialized in security investigation.
    Can be configured with different capabilities and autonomy levels.
    """

    __tablename__ = "soc_agents"

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    agent_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # AgentType enum
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(50), default=AgentStatus.IDLE.value, nullable=False, index=True
    )
    current_task_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True
    )

    # Capabilities and configuration
    capabilities: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of capability strings
    llm_model: Mapped[str] = mapped_column(
        String(100), default="gpt-4-turbo", nullable=False
    )
    temperature: Mapped[float] = mapped_column(
        Float, default=0.3, nullable=False
    )  # Lower = more deterministic
    max_reasoning_steps: Mapped[int] = mapped_column(
        Integer, default=15, nullable=False
    )
    autonomy_level: Mapped[str] = mapped_column(
        String(50), default=AutonomyLevel.SEMI_AUTO.value, nullable=False
    )

    # Performance metrics
    total_investigations: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    avg_resolution_time_minutes: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )
    accuracy_score: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )  # 0-100
    false_positive_rate: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )  # 0-100

    # Relationships
    investigations: Mapped[list["Investigation"]] = relationship(
        "Investigation",
        back_populates="agent",
        cascade="all, delete-orphan",
    )
    memories: Mapped[list["AgentMemory"]] = relationship(
        "AgentMemory",
        back_populates="agent",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<SOCAgent {self.id}: {self.name} ({self.agent_type})>"


class Investigation(BaseModel):
    """
    Autonomous investigation conducted by an agent

    Tracks the complete investigation lifecycle including evidence gathered,
    reasoning chain, actions proposed/executed, and outcomes.
    """

    __tablename__ = "investigations"

    # Ownership
    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("soc_agents.id"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Trigger information
    trigger_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # TriggerType enum
    trigger_source_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # Alert ID, anomaly ID, etc

    # Investigation metadata
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    hypothesis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), default=InvestigationStatus.INITIATED.value, nullable=False, index=True
    )
    priority: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    confidence_score: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )  # 0-100

    # Investigation data
    reasoning_chain: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of reasoning steps
    evidence_collected: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # Evidence data
    actions_taken: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # Summary of executed actions
    findings_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # List of recommendations

    # Security context
    mitre_techniques: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # MITRE ATT&CK techniques
    affected_assets: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # Affected IPs, hosts, users, etc
    resolution_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ResolutionType enum

    # Feedback
    human_feedback: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    feedback_rating: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # 1-5 rating

    # Relationships
    agent: Mapped["SOCAgent"] = relationship(
        "SOCAgent",
        back_populates="investigations",
    )
    reasoning_steps: Mapped[list["ReasoningStep"]] = relationship(
        "ReasoningStep",
        back_populates="investigation",
        cascade="all, delete-orphan",
    )
    actions: Mapped[list["AgentAction"]] = relationship(
        "AgentAction",
        back_populates="investigation",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Investigation {self.id}: {self.title}>"


class ReasoningStep(BaseModel):
    """
    Single step in the agent's reasoning chain

    Represents one complete iteration of the OODA loop:
    Observe (gather data), Orient (contextualize), Decide (reason), Act (execute).
    """

    __tablename__ = "reasoning_steps"

    # Ownership
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Step identity
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    step_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # StepType enum

    # Reasoning details
    thought_process: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    action_taken: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    action_tool: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ActionTool enum
    action_parameters: Mapped[Optional[str]] = mapped_column(
        JSON, nullable=True
    )  # Tool parameters
    observation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Confidence and metrics
    confidence_delta: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )  # Change in overall confidence
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="reasoning_steps",
    )

    def __repr__(self) -> str:
        return f"<ReasoningStep {self.id}: {self.step_type} #{self.step_number}>"


class AgentAction(BaseModel):
    """
    Action proposed or executed by an agent

    Represents a remediation, investigation, or response action.
    Supports approval workflows and rollback capabilities.
    """

    __tablename__ = "agent_actions"

    # Ownership
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Action definition
    action_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # ActionType enum
    target: Mapped[str] = mapped_column(String(255), nullable=False)  # IP, user, host, etc
    parameters: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Approval workflow
    requires_approval: Mapped[bool] = mapped_column(
        default=True, nullable=False
    )
    approved_by: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True
    )  # User ID
    approval_timestamp: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp

    # Execution
    execution_status: Mapped[str] = mapped_column(
        String(50),
        default=ActionExecutionStatus.PENDING_APPROVAL.value,
        nullable=False,
        index=True,
    )
    result: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    rollback_available: Mapped[bool] = mapped_column(default=True, nullable=False)
    rollback_executed: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="actions",
    )

    def __repr__(self) -> str:
        return f"<AgentAction {self.id}: {self.action_type} on {self.target}>"


class AgentMemory(BaseModel):
    """
    Long-term memory for agent learning and adaptation

    Stores patterns, baselines, preferences, and insights learned from
    investigations. Decays over time to prevent stale patterns from dominating.
    """

    __tablename__ = "agent_memories"

    # Ownership
    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("soc_agents.id"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Memory content
    memory_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # MemoryType enum
    key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    value: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Confidence and decay
    confidence: Mapped[float] = mapped_column(
        Float, default=1.0, nullable=False
    )  # 0-1
    access_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_accessed: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # ISO timestamp
    decay_rate: Mapped[float] = mapped_column(
        Float, default=0.95, nullable=False
    )  # Confidence *= decay_rate monthly

    # Relationships
    agent: Mapped["SOCAgent"] = relationship(
        "SOCAgent",
        back_populates="memories",
    )

    def __repr__(self) -> str:
        return f"<AgentMemory {self.id}: {self.memory_type}/{self.key}>"


class AgentChatSession(BaseModel):
    """A SOC analyst chat session with the agent.

    Sessions group related turns together so the analyst can return
    to a prior conversation, share it with a teammate, or audit what
    the agent was asked to do. Every turn writes two rows into
    agent_chat_messages (user + assistant).
    """

    __tablename__ = "agent_chat_sessions"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="New chat")
    is_archived: Mapped[bool] = mapped_column(default=False, nullable=False)


class AgentChatMessage(BaseModel):
    """One turn (user question OR assistant reply) in a chat session."""

    __tablename__ = "agent_chat_messages"

    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agent_chat_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # user | assistant | system
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # Tool invocations recorded on assistant turns; list of
    # {step, tool, args, result, blocked?} dicts.
    tool_calls: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
