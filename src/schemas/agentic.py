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


class SOCAgentResponse(DBModel):
    """Schema for SOC Agent response"""

    id: str
    organization_id: str
    status: str
    current_task_id: Optional[str] = None
    total_investigations: int
    avg_resolution_time_minutes: float
    accuracy_score: float
    false_positive_rate: float
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SOCAgentListResponse(BaseModel):
    """Schema for paginated agent list"""

    items: list[SOCAgentResponse]
    total: int
    page: int
    size: int
    pages: int


class SOCAgentPerformance(BaseModel):
    """Agent performance metrics"""

    agent_id: str
    name: str
    total_investigations: int
    avg_resolution_time_minutes: float
    accuracy_score: float
    false_positive_rate: float
    status: str


# ============================================================================
# Investigation Schemas
# ============================================================================


class ReasoningStepResponse(DBModel):
    """Single reasoning step"""

    id: str
    step_number: int
    step_type: str
    thought_process: Optional[str] = None
    action_taken: Optional[str] = None
    action_tool: Optional[str] = None
    observation: Optional[dict[str, Any]] = None
    confidence_delta: float
    duration_ms: int
    tokens_used: int
    created_at: datetime

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

    agent_id: str
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


class InvestigationResponse(DBModel):
    """Schema for investigation response"""

    id: str
    agent_id: str
    organization_id: str
    hypothesis: Optional[str] = None
    status: str
    confidence_score: float
    reasoning_chain: Optional[list[dict[str, Any]]] = None
    evidence_collected: Optional[dict[str, Any]] = None
    actions_taken: Optional[list[dict[str, Any]]] = None
    findings_summary: Optional[str] = None
    recommendations: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    affected_assets: Optional[dict[str, Any]] = None
    resolution_type: Optional[str] = None
    human_feedback: Optional[str] = None
    feedback_rating: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class InvestigationListResponse(BaseModel):
    """Schema for paginated investigation list"""

    items: list[InvestigationResponse]
    total: int
    page: int
    size: int
    pages: int


class InvestigationTimeline(BaseModel):
    """Investigation timeline view"""

    investigation_id: str
    title: str
    status: str
    confidence_score: float
    start_time: datetime
    steps: list[ReasoningStepResponse]
    actions: list["AgentActionResponse"]
    conclusion: Optional[str] = None


# ============================================================================
# Reasoning and Actions
# ============================================================================


class AgentActionBase(BaseModel):
    """Base agent action schema"""

    action_type: str
    target: str = Field(..., min_length=1)
    parameters: Optional[dict[str, Any]] = None
    requires_approval: bool = True


class AgentActionCreate(AgentActionBase):
    """Schema for proposing action"""

    pass


class AgentActionApproval(BaseModel):
    """Schema for approving/denying action"""

    approved: bool
    approval_notes: Optional[str] = None


class AgentActionResponse(DBModel):
    """Schema for action response"""

    id: str
    investigation_id: str
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    execution_status: str
    result: Optional[dict[str, Any]] = None
    rollback_available: bool
    rollback_executed: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ActionPendingApproval(BaseModel):
    """Pending action requiring approval"""

    action_id: str
    action_type: str
    target: str
    investigation_id: str
    investigation_title: str
    agent_id: str
    agent_name: str
    confidence_score: float
    created_at: datetime


class ActionHistory(BaseModel):
    """Action execution history"""

    action_id: str
    action_type: str
    target: str
    execution_status: str
    executed_at: Optional[datetime] = None
    result: Optional[dict[str, Any]] = None


# ============================================================================
# Memory Schemas
# ============================================================================


class AgentMemoryResponse(DBModel):
    """Agent memory entry"""

    id: str
    memory_type: str
    key: str
    value: Optional[dict[str, Any]] = None
    confidence: float
    access_count: int
    last_accessed: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AgentMemoryListResponse(BaseModel):
    """Paginated memory list"""

    items: list[AgentMemoryResponse]
    total: int
    page: int
    size: int
    pages: int


class MemoryStats(BaseModel):
    """Agent memory statistics"""

    agent_id: str
    total_memories: int
    by_type: dict[str, int]
    avg_confidence: float
    memories_decaying: int
    memories_high_confidence: int


# ============================================================================
# Natural Language Interface
# ============================================================================


class NaturalLanguageQuery(BaseModel):
    """Natural language query to agent"""

    query: str = Field(..., min_length=1)
    agent_id: Optional[str] = None  # Specific agent or auto-select


class NaturalLanguageResponse(BaseModel):
    """Response from natural language query"""

    response: str
    agent_id: str
    agent_name: str
    interpretation: dict[str, Any]


class AlertExplanation(BaseModel):
    """Explanation of alert"""

    alert_id: str
    explanation: str
    risk_assessment: str
    recommended_actions: list[str]
    mitre_techniques: Optional[list[str]] = None


class InvestigationExplanation(BaseModel):
    """Natural language explanation of investigation"""

    investigation_id: str
    title: str
    narrative: str
    key_findings: list[str]
    confidence_score: float
    recommendations: list[str]


# ============================================================================
# Dashboard and Metrics
# ============================================================================


class AgentWorkload(BaseModel):
    """Current agent workload"""

    agent_id: str
    agent_name: str
    status: str
    current_task_id: Optional[str] = None
    pending_investigations: int
    active_investigations: int
    pending_approvals: int
    memory_count: int


class DashboardMetrics(BaseModel):
    """SOC dashboard metrics"""

    total_agents: int
    agents_active: int
    total_investigations: int
    investigations_in_progress: int
    investigations_completed_24h: int
    avg_investigation_time_minutes: float
    overall_accuracy: float
    overall_false_positive_rate: float
    pending_approvals: int


class InvestigationMetrics(BaseModel):
    """Investigation statistics"""

    total: int
    by_status: dict[str, int]
    by_resolution: dict[str, int]
    by_priority: dict[int, int]
    avg_confidence_score: float
    avg_resolution_time_minutes: float


class AccuracyStats(BaseModel):
    """Accuracy statistics"""

    total_investigations: int
    true_positives: int
    false_positives: int
    inconclusive: int
    escalated: int
    accuracy_score: float
    false_positive_rate: float


class ResolutionTimes(BaseModel):
    """Investigation resolution time stats"""

    min_minutes: float
    max_minutes: float
    avg_minutes: float
    median_minutes: float
    by_agent: dict[str, float]


# ============================================================================
# Feedback and Learning
# ============================================================================


class InvestigationFeedback(BaseModel):
    """Feedback on investigation quality"""

    investigation_id: str
    rating: int = Field(..., ge=1, le=5)
    feedback: Optional[str] = None
    correction: Optional[dict[str, Any]] = None


class FeedbackImpact(BaseModel):
    """Impact of feedback on agent learning"""

    investigation_id: str
    memory_entries_updated: int
    confidence_adjustments: int
    pattern_refinements: int


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

    hunt_id: str
    agent_id: str
    profile: str
    status: str
    indicators_found: int
    investigations_created: int
    high_confidence_findings: int
    execution_time_minutes: float
    timestamp: datetime


# ============================================================================
# Configuration
# ============================================================================


class AgentConfig(BaseModel):
    """Agent configuration"""

    agent_id: str
    llm_model: str
    temperature: float
    max_reasoning_steps: int
    autonomy_level: str
    capabilities: list[str]


class ConfigUpdate(BaseModel):
    """Update agent configuration"""

    llm_model: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0.0, le=1.0)
    max_reasoning_steps: Optional[int] = Field(None, ge=1, le=100)
    autonomy_level: Optional[str] = None
    capabilities: Optional[list[str]] = None
