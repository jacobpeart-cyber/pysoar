"""Schemas for Agentic AI SOC Analyst API"""

from datetime import datetime
from typing import Any, Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, Field


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
    """Schema for approving/denying action"""

    approved: bool = False
    approval_notes: Optional[str] = None


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
    """Pending action requiring approval"""

    action_id: str = ""
    action_type: str = ""
    target: str = ""
    investigation_id: str = ""
    investigation_title: str = ""
    agent_id: str = ""
    agent_name: str = ""
    confidence_score: float = 0.0
    created_at: datetime


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
    agent_id: Optional[str] = None  # Specific agent or auto-select
    # If provided, the turn is persisted into an existing chat session.
    # If omitted, the chat remains ephemeral (backwards-compatible).
    session_id: Optional[str] = None
    # If False, destructive action tools (block_ip, isolate_host, disable_user,
    # execute_playbook, create_incident, etc.) are blocked — the agent can only
    # query and analyze. Caller must explicitly authorize actions.
    authorize_actions: bool = False


class NaturalLanguageResponse(BaseModel):
    """Response from natural language query"""

    response: str = ""
    agent_id: str = ""
    agent_name: str = ""
    interpretation: dict[str, Any]
    session_id: Optional[str] = None


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
