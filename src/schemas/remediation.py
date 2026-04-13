"""
Pydantic schemas for remediation API requests and responses.

Handles serialization/deserialization of remediation entities,
validation, and API contract definitions.
"""

from datetime import datetime
from uuid import UUID
from typing import Any, Optional

from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# RemediationPolicy Schemas
# ============================================================================

class RemediationPolicyBase(BaseModel):
    """Base policy fields."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    policy_type: str = Field(..., pattern="^(auto_block|auto_isolate|auto_patch|auto_disable|auto_quarantine|auto_reset|auto_revoke|escalation|notification|custom)$")
    trigger_type: str = Field(..., pattern="^(alert_severity|anomaly_score|threat_intel_match|vulnerability_score|ueba_risk|deception_interaction|detection_rule|manual)$")
    trigger_conditions: dict = Field(default_factory=dict)
    actions: list[dict] = Field(default_factory=list)
    is_enabled: bool = True
    requires_approval: bool = False
    approval_timeout_minutes: int = Field(default=30, ge=1, le=1440)
    auto_approve_after_timeout: bool = False
    cooldown_minutes: int = Field(default=60, ge=0, le=10080)
    max_executions_per_hour: int = Field(default=10, ge=1, le=1000)
    scope: dict = Field(default_factory=dict)
    exclusions: list[str] = Field(default_factory=list)
    priority: int = Field(default=50, ge=1, le=100)
    risk_level: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    rollback_enabled: bool = True
    rollback_actions: list[dict] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class RemediationPolicyCreate(RemediationPolicyBase):
    """Create request."""
    created_by: str = ""


class RemediationPolicyUpdate(BaseModel):
    """Update request (partial)."""
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    actions: Optional[list[dict]] = None
    is_enabled: Optional[bool] = None
    requires_approval: Optional[bool] = None
    approval_timeout_minutes: Optional[int] = None
    auto_approve_after_timeout: Optional[bool] = None
    priority: Optional[int] = None
    tags: Optional[list[str]] = None


class RemediationPolicyResponse(RemediationPolicyBase):
    """Response with metadata."""
    id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    execution_count: int = 0
    last_executed_at: Optional[datetime] = None
    success_rate: Optional[float] = None
    created_by: str = ""
    organization_id: str = ""

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# RemediationAction Schemas
# ============================================================================

class RemediationActionBase(BaseModel):
    """Base action fields."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    action_type: str = Field(...)
    target_type: str = Field(...)
    parameters: dict = Field(default_factory=dict)
    integration: Optional[str] = None
    integration_config: dict = Field(default_factory=dict)
    timeout_seconds: int = Field(default=300, ge=10, le=3600)
    retry_count: int = Field(default=3, ge=0, le=10)
    is_reversible: bool = True
    reverse_action_type: Optional[str] = None
    reverse_parameters: dict = Field(default_factory=dict)
    risk_level: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    requires_confirmation: bool = False
    tags: list[str] = Field(default_factory=list)


class RemediationActionCreate(RemediationActionBase):
    """Create request."""
    pass


class RemediationActionResponse(RemediationActionBase):
    """Response with metadata."""
    id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    organization_id: str = ""

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# RemediationExecution Schemas
# ============================================================================

class RemediationExecutionBase(BaseModel):
    """Base execution fields."""
    policy_id: Optional[str] = None
    trigger_source: str = ""
    trigger_id: Optional[str] = None
    trigger_details: dict = Field(default_factory=dict)
    target_entity: str = ""
    target_type: str = ""
    actions_planned: list[dict] = Field(default_factory=list)


class ExecutionActionResult(BaseModel):
    """Single action execution result."""
    action_type: str = ""
    target: Optional[str] = None
    result: Optional[str] = None
    success: bool = False
    details: dict = Field(default_factory=dict)
    error: Optional[str] = None
    timestamp: Optional[datetime] = None
    ioc_id: Optional[str] = None


class ExecutionProgressResponse(BaseModel):
    """Real-time execution progress."""
    execution_id: str = ""
    status: str = ""
    approval_status: Optional[str] = None
    current_action_index: int = 0
    total_actions: int = 0
    target_entity: str = ""
    actions_completed: list[ExecutionActionResult] = Field(default_factory=list)
    overall_result: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    percent_complete: float = 0.0


class RemediationExecutionResponse(RemediationExecutionBase):
    """Response with full details."""
    id: str = ""
    status: str = ""
    approval_status: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    actions_completed: list[ExecutionActionResult] = Field(default_factory=list)
    overall_result: Optional[str] = None
    error_message: Optional[str] = None
    rollback_status: Optional[str] = None
    rolled_back_at: Optional[datetime] = None
    metrics: dict = Field(default_factory=dict)
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    organization_id: str = ""

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Approval and Manual Remediation Schemas
# ============================================================================

class ApprovalRequest(BaseModel):
    """Approve a pending execution."""
    execution_id: str = ""
    approver_id: str = ""


class ApprovalResponse(BaseModel):
    """Approval response."""
    execution_id: str = ""
    approval_status: str = ""
    approved_at: Optional[datetime] = None


class RejectionRequest(BaseModel):
    """Reject a pending execution."""
    execution_id: str = ""
    approver_id: str = ""
    reason: Optional[str] = None


class ManualRemediationRequest(BaseModel):
    """Manually trigger a remediation."""
    action_type: str = ""
    target_entity: str = ""
    target_type: str = ""
    parameters: dict = Field(default_factory=dict)
    priority: int = Field(default=50, ge=1, le=100)
    requires_approval: bool = False
    initiated_by: str = ""


class QuickBlockIPRequest(BaseModel):
    """Quick: block an IP."""
    ip: str = ""
    duration_hours: int = Field(default=24, ge=1, le=365*24)
    reason: Optional[str] = None


class QuickIsolateHostRequest(BaseModel):
    """Quick: isolate a host."""
    hostname: str = ""
    reason: Optional[str] = None


class QuickDisableAccountRequest(BaseModel):
    """Quick: disable an account."""
    username: str = ""
    reason: Optional[str] = None


class QuickQuarantineFileRequest(BaseModel):
    """Quick: quarantine a file."""
    file_path: str = ""
    hostname: str = ""
    reason: Optional[str] = None


# ============================================================================
# RemediationPlaybook Schemas
# ============================================================================

class PlaybookStep(BaseModel):
    """Single playbook step."""
    action_id: str = ""
    conditions: dict = Field(default_factory=dict)
    on_success: Optional[str] = None
    on_failure: Optional[str] = None
    timeout_seconds: Optional[int] = None


class RemediationPlaybookBase(BaseModel):
    """Base playbook fields."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    playbook_type: str = Field(..., pattern="^(incident_response|vulnerability_remediation|compliance_fix|threat_containment|recovery)$")
    trigger_conditions: dict = Field(default_factory=dict)
    steps: list[PlaybookStep] = Field(default_factory=list)
    decision_points: list[dict] = Field(default_factory=list)
    parallel_actions: list[list[str]] = Field(default_factory=list)
    estimated_duration_minutes: Optional[int] = None
    is_template: bool = True
    is_enabled: bool = True
    tags: list[str] = Field(default_factory=list)


class RemediationPlaybookCreate(RemediationPlaybookBase):
    """Create request."""
    created_by: str = ""


class RemediationPlaybookResponse(RemediationPlaybookBase):
    """Response with metadata."""
    id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    avg_execution_minutes: Optional[float] = None
    created_by: str = ""
    organization_id: str = ""

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# RemediationIntegration Schemas
# ============================================================================

class RemediationIntegrationBase(BaseModel):
    """Base integration fields."""
    name: str = Field(..., min_length=1, max_length=255)
    integration_type: str = ""
    vendor: Optional[str] = None
    endpoint_url: Optional[str] = None
    auth_type: str = Field(default="api_key")
    auth_config: dict = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)
    rate_limit: int = Field(default=60, ge=1)
    tags: list[str] = Field(default_factory=list)


class RemediationIntegrationCreate(RemediationIntegrationBase):
    """Create request."""
    pass


class RemediationIntegrationResponse(RemediationIntegrationBase):
    """Response with metadata."""
    id: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_connected: bool = False
    last_health_check: Optional[datetime] = None
    health_status: str = ""
    organization_id: str = ""

    model_config = ConfigDict(from_attributes=True)


class IntegrationTestResult(BaseModel):
    """Result of integration test."""
    integration_id: str = ""
    success: bool = False
    message: str = ""
    details: dict = Field(default_factory=dict)
    tested_at: datetime


# ============================================================================
# Dashboard and Reporting Schemas
# ============================================================================

class ActionTypeStats(BaseModel):
    """Statistics for action types."""
    action_type: str = ""
    count: int = 0
    success_count: int = 0
    failure_count: int = 0


class PolicyStats(BaseModel):
    """Statistics for policies."""
    policy_id: str = ""
    name: str = ""
    execution_count: int = 0
    success_count: int = 0
    failure_count: int = 0


class RemediationDashboardStats(BaseModel):
    """Dashboard summary statistics."""
    period_start: datetime
    period_end: datetime
    organization_id: str = ""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    overall_success_rate: float = 0.0
    avg_execution_minutes: float = 0.0
    pending_approvals: int = 0
    in_progress: int = 0
    actions_by_type: list[ActionTypeStats]
    top_policies: list[PolicyStats]
    top_targets: list[dict]
    execution_by_hour: list[dict]


class TimelineEvent(BaseModel):
    """Single timeline event."""
    execution_id: str = ""
    policy_name: Optional[str] = None
    target: str = ""
    action_count: int = 0
    status: str = ""
    overall_result: Optional[str] = None
    completed_at: datetime


class RemediationTimelineResponse(BaseModel):
    """Recent remediation timeline."""
    organization_id: str = ""
    period: str = ""
    events: list[TimelineEvent]
    total_count: int = 0


class EffectivenessMetrics(BaseModel):
    """Remediation effectiveness metrics."""
    organization_id: str = ""
    period: str = ""
    executions_verified: int = 0
    effective_count: int = 0
    ineffective_count: int = 0
    effectiveness_rate: float = 0.0
    avg_time_to_effectiveness: Optional[float] = None
    rollbacks_recommended: int = 0
    rollbacks_executed: int = 0
