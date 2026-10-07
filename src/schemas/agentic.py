"""Schemas for Agentic AI SOC Analyst API"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from src.schemas.base import DBModel

# ============================================================================
# SOCAgent Schemas
# ============================================================================


class SOCAgentBase(BaseModel):
    """Base SOC Agent schema"""

    name: str = Field(..., min_length=1, max_length=255)
    agent_type: str = Field(...)  # triage_analyst, threat_hunter, etc
    capabilities: Optional[list[str]] = None
    llm_model: str = "gpt-4-turbo"
    temperature: float = Field(default=0.3, ge=0.0, le=1.0)
    max_reasoning_steps: int = Field(default=15, ge=1, le=100)
    autonomy_level: str = Field(default="semi_auto")


class SOCAgentCreate(SOCAgentBase):
    """Schema for creating SOC Agent"""

    pass


class SOCAgentUpdate(BaseModel):
    """Schema for updating SOC Agent"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0.0, le=1.0)
    max_reasoning_steps: Optional[int] = Field(None, ge=1, le=100)
    autonomy_level: Optional[str] = None


class SOCAgentResponse(SOCAgentBase, DBModel):
    """Schema for SOC Agent response"""

    id: str = ""
    organization_id: str = ""
    status: str = ""
    current_task_id: Optional[str] = None
    total_investigations: int = 0
    avg_resolution_time_minutes: float = 0.0
    accuracy_score: float = 0.0
    false_positive_rate: float = 0.0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SOCAgentListResponse(BaseModel):
    """Schema for paginated agent list"""

    items: list[SOCAgentResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class SOCAgentPerformance(BaseModel):
    """Agent performance metrics"""

    agent_id: str = ""
    name: str = ""
    total_investigations: int = 0
    avg_resolution_time_minutes: float = 0.0
    accuracy_score: float = 0.0
    false_positive_rate: float = 0.0
    status: str = ""


# ============================================================================
# Investigation Schemas
# ============================================================================


class ReasoningStepResponse(DBModel):
    """Single reasoning step"""

    id: str = ""
    step_number: int = 0
    step_type: str = ""
    thought_process: Optional[str] = None
    action_taken: Optional[str] = None
    action_tool: Optional[str] = None
    observation: Optional[dict[str, Any]] = None
    confidence_delta: float = 0.0
    duration_ms: int = 0
    tokens_used: int = 0
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class InvestigationBase(BaseModel):
    """Base investigation schema"""

    title: str = Field(..., min_length=1, max_length=500)
    trigger_type: str = Field(...)
    trigger_source_id: Optional[str] = None
    priority: int = Field(default=3, ge=1, le=5)


class InvestigationCreate(InvestigationBase):
    """Schema for creating investigation"""

    agent_id: str = ""
    hypothesis: Optional[str] = None
    initial_context: Optional[dict[str, Any]] = None


class InvestigationUpdate(BaseModel):
    """Schema for updating investigation"""

    title: Optional[str] = Field(None, min_length=1, max_length=500)
    hypothesis: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=5)
    status: Optional[str] = None
    human_feedback: Optional[str] = None
    feedback_rating: Optional[int] = Field(None, ge=1, le=5)


class InvestigationResponse(InvestigationBase, DBModel):
    """Schema for investigation response"""

    id: str = ""
    agent_id: str = ""
    organization_id: str = ""
    hypothesis: Optional[str] = None
    status: str = ""
    confidence_score: float = 0.0
    reasoning_chain: Optional[list[dict[str, Any]]] = None
    evidence_collected: Optional[dict[str, Any]] = None
    actions_taken: Optional[list[dict[str, Any]]] = None
    findings_summary: Optional[str] = None
    recommendations: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    affected_assets: Optional[Any] = None
    resolution_type: Optional[str] = None
    human_feedback: Optional[str] = None
    feedback_rating: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class InvestigationListResponse(BaseModel):
    """Schema for paginated investigation list"""

    items: list[InvestigationResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class InvestigationTimeline(BaseModel):
    """Investigation timeline view"""

    investigation_id: str = ""
    title: str = ""
    status: str = ""
    confidence_score: float = 0.0
    start_time: datetime
    steps: list[ReasoningStepResponse]
    actions: list["AgentActionResponse"]
    conclusion: Optional[str] = None


# ============================================================================
# Reasoning and Actions
# ============================================================================


class AgentActionBase(BaseModel):
    """Base agent action schema"""

    action_type: str = ""
    target: str = Field(..., min_length=1)
    parameters: Optional[dict[str, Any]] = None
    requires_approval: bool = True


class AgentActionCreate(AgentActionBase):
    """Schema for proposing action"""

    pass


class AgentActionApproval(BaseModel):
    """Schema for approving/denying an agent-proposed action (design v2 §8).

    ``params_sha256``/``evidence_sha256`` bind the approval to the exact
    arguments and evidence the proposal was created with: the client echoes
    what it rendered on the approve card and a mismatch is rejected with
    ``approval_stale`` rather than executing something the approver never saw.
    """

    approved: bool = False
    approval_notes: Optional[str] = None
    params_sha256: Optional[str] = Field(default=None, max_length=64)
    evidence_sha256: Optional[str] = Field(default=None, max_length=64)
    # Admin-only escape hatch for proposals raised in a flagged/lockdown
    # session; requires an explicit written reason (audited, risk high).
    acknowledge_suspect: bool = False
    reason: Optional[str] = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _hashes_required_when_approving(self) -> "AgentActionApproval":
        if self.approved and not (self.params_sha256 and self.evidence_sha256):
            raise ValueError(
                "params_sha256 and evidence_sha256 must be echoed from the proposal when approving",
            )
        return self


class AgentActionResponse(AgentActionBase, DBModel):
    """Schema for action response"""

    id: str = ""
    investigation_id: str = ""
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    execution_status: str = ""
    result: Optional[dict[str, Any]] = None
    rollback_available: bool = False
    rollback_executed: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ActionPendingApproval(BaseModel):
    """A proposal awaiting approval, with the full binding the card needs.

    Design v2 section 8: an approve call must echo ``params_sha256`` and
    ``evidence_sha256``, and the reviewer must see the concrete arguments,
    every expanded target, the injection tier the evidence carried and when
    the proposal expires. The legacy ``action_type``/``target``/agent fields
    are kept so existing clients keep working.
    """

    action_id: str = ""
    action_type: str = ""
    target: str = ""
    investigation_id: str = ""
    investigation_title: str = ""
    agent_id: str = ""
    agent_name: str = ""
    confidence_score: float = 0.0
    created_at: datetime

    # Proposal provenance + binding (agent_actions columns, migration 020).
    tool_name: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    effective_targets: list[dict[str, Any]] = Field(default_factory=list)
    params_sha256: Optional[str] = None
    evidence_sha256: Optional[str] = None
    suspect: bool = False
    injection_tier: Optional[str] = None
    expires_at: Optional[datetime] = None
    source: Optional[str] = None
    proposed_by_user_id: Optional[str] = None
    proposed_by_agent_id: Optional[str] = None
    run_id: Optional[str] = None
    requires_approval: bool = True
    execution_status: str = ""

    # Separation of duties (AC-5, migration 021): true when the org requires
    # two distinct approvers for this proposal's tier. ``first_approved_*``
    # are set once the first of the two approvals is in.
    requires_second_approver: bool = False
    first_approved_by: Optional[str] = None
    first_approved_at: Optional[datetime] = None


class TrustAcknowledgeRequest(BaseModel):
    """Body of ``POST /agentic/trust/acknowledge`` (design v2 section 4).

    Names the persisted trust state to downgrade: a chat session, an
    investigation, or both. ``record_hash`` narrows the acknowledgment to one
    scanned content hash (``TrustHit.snippet_sha256``); without it every hit
    on that state is acknowledged. ``reason`` is mandatory and audited.
    """

    session_id: Optional[str] = None
    investigation_id: Optional[str] = None
    record_hash: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$", description="sha256 of the acknowledged snippet",
    )
    reason: str = Field(..., min_length=3, max_length=1000)

    @model_validator(mode="after")
    def _one_target(self) -> "TrustAcknowledgeRequest":
        if not (self.session_id or self.investigation_id):
            raise ValueError("session_id or investigation_id is required")
        return self


class ActionHistory(BaseModel):
    """Action execution history"""

    action_id: str = ""
    action_type: str = ""
    target: str = ""
    execution_status: str = ""
    executed_at: Optional[datetime] = None
    result: Optional[dict[str, Any]] = None


# ============================================================================
# Memory Schemas
# ============================================================================


class AgentMemoryResponse(DBModel):
    """Agent memory entry"""

    id: str = ""
    memory_type: str = ""
    key: str = ""
    value: Optional[dict[str, Any]] = None
    confidence: float = 0.0
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AgentMemoryListResponse(BaseModel):
    """Paginated memory list"""

    items: list[AgentMemoryResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class MemoryStats(BaseModel):
    """Agent memory statistics"""

    agent_id: str = ""
    total_memories: int = 0
    by_type: dict[str, int]
    avg_confidence: float = 0.0
    memories_decaying: int = 0
    memories_high_confidence: int = 0


# ============================================================================
# Natural Language Interface
# ============================================================================


class NaturalLanguageQuery(BaseModel):
    """Natural language query to agent"""

    query: str = Field(..., min_length=1)
    agent_id: Optional[str] = None  # Specific SOC agent (validated in-org) or auto-select
    # If provided, the turn is persisted into an existing chat session
    # (which must belong to the caller AND the caller's organization).
    session_id: Optional[str] = None
    # Analyst+: "the agent may propose destructive actions for my approval".
    # Destructive/privileged tools are never executed inline from chat; with
    # this flag the runtime materializes an approval-gated AgentAction instead
    # of refusing the call outright (design v2 §1/§8). Viewers may not set it.
    propose_actions: bool = False
    # Deprecated alias for ``propose_actions`` (v1.1 field name). Kept so
    # existing clients keep working; it maps onto ``propose_actions``.
    authorize_actions: bool = False

    @model_validator(mode="after")
    def _merge_deprecated_alias(self) -> "NaturalLanguageQuery":
        if self.authorize_actions and not self.propose_actions:
            object.__setattr__(self, "propose_actions", True)
        return self


class AgentProposal(BaseModel):
    """An approval-gated action the agent proposed during a run (design v2 §8)."""

    id: Optional[str] = None
    tool: str = ""
    args: dict[str, Any] = Field(default_factory=dict)
    effective_targets: list[dict[str, Any]] = Field(default_factory=list)
    params_sha256: str = ""
    evidence_sha256: str = ""
    suspect: bool = False
    expires_at: Optional[datetime] = None


class NaturalLanguageResponse(BaseModel):
    """Response from natural language query"""

    response: str = ""
    agent_id: str = ""
    agent_name: str = ""
    interpretation: dict[str, Any]
    session_id: Optional[str] = None
    # Design v2 §9: every chat turn reports its run id, what it proposed,
    # which policy decisions were taken, the session trust state and the
    # provider/model/usage that produced the answer.
    run_id: str = ""
    proposals: list[AgentProposal] = Field(default_factory=list)
    policy_events: list[dict[str, Any]] = Field(default_factory=list)
    trust: dict[str, Any] = Field(default_factory=dict)
    provider: str = ""
    model: str = ""
    credential_source: str = ""
    usage: dict[str, Any] = Field(default_factory=dict)


class ChatSessionResponse(BaseModel):
    """A persisted chat session."""
    id: str
    title: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_archived: bool = False


class ChatSessionListResponse(BaseModel):
    items: list[ChatSessionResponse]
    total: int = 0


class ChatMessageResponse(BaseModel):
    """One turn in a chat session."""
    id: str
    role: str
    content: str
    tool_calls: Optional[list[dict[str, Any]]] = None
    created_at: Optional[datetime] = None


class ChatMessageListResponse(BaseModel):
    items: list[ChatMessageResponse]
    total: int = 0


class ChatSessionCreate(BaseModel):
    title: Optional[str] = None


class AlertExplanation(BaseModel):
    """Explanation of alert"""

    alert_id: str = ""
    explanation: str = ""
    risk_assessment: str = ""
    recommended_actions: list[str]
    mitre_techniques: Optional[list[str]] = None


class InvestigationExplanation(BaseModel):
    """Natural language explanation of investigation"""

    investigation_id: str = ""
    title: str = ""
    narrative: str = ""
    key_findings: list[str]
    confidence_score: float = 0.0
    recommendations: list[str]


# ============================================================================
# Dashboard and Metrics
# ============================================================================


class AgentWorkload(BaseModel):
    """Current agent workload"""

    agent_id: str = ""
    agent_name: str = ""
    status: str = ""
    current_task_id: Optional[str] = None
    pending_investigations: int = 0
    active_investigations: int = 0
    pending_approvals: int = 0
    memory_count: int = 0


class DashboardMetrics(BaseModel):
    """SOC dashboard metrics"""

    total_agents: int = 0
    agents_active: int = 0
    total_investigations: int = 0
    investigations_in_progress: int = 0
    investigations_completed_24h: int = 0
    avg_investigation_time_minutes: float = 0.0
    overall_accuracy: float = 0.0
    overall_false_positive_rate: float = 0.0
    pending_approvals: int = 0


class InvestigationMetrics(BaseModel):
    """Investigation statistics"""

    total: int = 0
    by_status: dict[str, int]
    by_resolution: dict[str, int]
    by_priority: dict[int, int]
    avg_confidence_score: float = 0.0
    avg_resolution_time_minutes: float = 0.0


class AccuracyStats(BaseModel):
    """Accuracy statistics"""

    total_investigations: int = 0
    true_positives: int = 0
    false_positives: int = 0
    inconclusive: int = 0
    escalated: int = 0
    accuracy_score: float = 0.0
    false_positive_rate: float = 0.0


class ResolutionTimes(BaseModel):
    """Investigation resolution time stats"""

    min_minutes: float = 0.0
    max_minutes: float = 0.0
    avg_minutes: float = 0.0
    median_minutes: float = 0.0
    by_agent: dict[str, float]


# ============================================================================
# Feedback and Learning
# ============================================================================


class InvestigationCorrection(BaseModel):
    """Structured analyst correction for an investigation verdict.
    Captures the reviewer's corrected verdict + why, so future
    investigations can read recent corrections into their prompt
    context and avoid repeating the same wrong call."""
    corrected_verdict: str = Field(..., description="true_positive | false_positive | benign | inconclusive | escalated")
    correction_note: Optional[str] = Field(None, max_length=4000, description="What the agent missed or got wrong")


class InvestigationFeedback(BaseModel):
    """Feedback on investigation quality"""

    investigation_id: str = ""
    rating: int = Field(..., ge=1, le=5)
    feedback: Optional[str] = None
    correction: Optional[dict[str, Any]] = None


class FeedbackImpact(BaseModel):
    """Impact of feedback on agent learning"""

    investigation_id: str = ""
    memory_entries_updated: int = 0
    confidence_adjustments: int = 0
    pattern_refinements: int = 0


# ============================================================================
# Threat Hunting
# ============================================================================


class ThreatHuntRequest(BaseModel):
    """Request for threat hunt"""

    agent_id: Optional[str] = None
    hunt_profile: str = "standard"  # standard, aggressive, etc
    scope: Optional[str] = None
    time_window_days: int = 7


class ThreatHuntResult(BaseModel):
    """Threat hunt results"""

    hunt_id: str = ""
    agent_id: str = ""
    profile: str = ""
    status: str = ""
    indicators_found: int = 0
    investigations_created: int = 0
    high_confidence_findings: int = 0
    execution_time_minutes: float = 0.0
    timestamp: datetime


# ============================================================================
# Configuration
# ============================================================================


class AgentConfig(BaseModel):
    """Agent configuration"""

    agent_id: str = ""
    llm_model: str = ""
    temperature: float = 0.0
    max_reasoning_steps: int = 0
    autonomy_level: str = ""
    capabilities: list[str]


class ConfigUpdate(BaseModel):
    """Update agent configuration"""

    llm_model: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0.0, le=1.0)
    max_reasoning_steps: Optional[int] = Field(None, ge=1, le=100)
    autonomy_level: Optional[str] = None
    capabilities: Optional[list[str]] = None
