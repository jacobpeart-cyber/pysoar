"""
Remediation data models using SQLAlchemy ORM.

Defines core remediation entities:
- RemediationPolicy: Define when and how to remediate
- RemediationAction: Individual remediation steps
- RemediationExecution: Track execution of policies
- RemediationPlaybook: Multi-step remediation workflows
- RemediationIntegration: External system connectors
"""

from typing import Any
from datetime import datetime

from sqlalchemy import String, Text, Integer, Boolean, DateTime, JSON, ForeignKey, Float
from sqlalchemy.orm import relationship, Mapped, mapped_column

from src.models.base import Base, BaseModel, generate_uuid, utc_now


class RemediationPolicy(BaseModel):
    """
    Remediation policy: defines conditions and actions for automated response.

    Policies can be triggered by various event types (alerts, anomalies, threat intel, etc.)
    and execute ordered sequences of remediation actions.
    """
    __tablename__ = "remediation_policies"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Policy behavior
    policy_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="auto_block, auto_isolate, auto_patch, auto_disable, auto_quarantine, auto_reset, auto_revoke, escalation, notification, custom"
    )
    trigger_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="alert_severity, anomaly_score, threat_intel_match, vulnerability_score, ueba_risk, deception_interaction, detection_rule, manual"
    )

    # Conditions and actions
    trigger_conditions: Mapped[dict] = mapped_column(JSON, nullable=False, default={})
    actions: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=[])

    # Control flags
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approval_timeout_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    auto_approve_after_timeout: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Rate limiting
    cooldown_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    max_executions_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=10)

    # Scope and exclusions
    scope: Mapped[dict] = mapped_column(JSON, nullable=False, default={})
    exclusions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=[])

    # Priority and risk
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium",
        comment="low, medium, high, critical"
    )

    # Rollback support
    rollback_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rollback_actions: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=[])

    # Metrics
    execution_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    success_rate: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=[])
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    # Relationships
    executions: Mapped[list["RemediationExecution"]] = relationship(
        "RemediationExecution", back_populates="policy", cascade="all, delete-orphan"
    )


class RemediationAction(BaseModel):
    """
    Individual remediation action that can be executed against a target.

    Actions are building blocks used by policies and playbooks to perform
    specific remediation steps (block IP, disable account, quarantine file, etc.)
    """
    __tablename__ = "remediation_actions"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Action classification
    action_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="firewall_block, host_isolate, account_disable, account_lock, password_reset, session_terminate, process_kill, file_quarantine, patch_deploy, config_change, dns_sinkhole, email_quarantine, token_revoke, webhook, script, notification, ticket_create"
    )
    target_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="ip, host, user, process, file, domain, url, email, service, application"
    )

    # Action parameters and integration
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default={})
    integration: Mapped[str | None] = mapped_column(
        String(100), nullable=True,
        comment="Which system executes: firewall, edr, ad, email_gateway, etc."
    )
    integration_config: Mapped[dict] = mapped_column(JSON, nullable=False, default={})

    # Execution settings
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=3)

    # Reversibility
    is_reversible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reverse_action_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    reverse_parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default={})

    # Risk and approval
    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium",
        comment="low, medium, high, critical"
    )
    requires_confirmation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=[])
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)


class RemediationExecution(BaseModel):
    """
    Tracks execution of a remediation policy or ad-hoc remediation action.

    Records lifecycle from trigger through execution to completion or failure,
    including approvals, action results, and optional rollback.
    """
    __tablename__ = "remediation_executions"

    # Policy reference
    policy_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("remediation_policies.id"), nullable=True
    )

    # Trigger information
    trigger_source: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="alert, anomaly, threat_intel, vulnerability, ueba, deception, manual, scheduled"
    )
    trigger_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    trigger_details: Mapped[dict] = mapped_column(JSON, nullable=False, default={})

    # Status tracking
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending",
        comment="pending, awaiting_approval, approved, running, completed, failed, rolled_back, cancelled, timed_out"
    )
    approval_status: Mapped[str | None] = mapped_column(
        String(50), nullable=True,
        comment="pending, approved, rejected, auto_approved"
    )
    approved_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Execution timeline
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Target and actions
    target_entity: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    actions_planned: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=[])
    actions_completed: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=[])
    current_action_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Results
    overall_result: Mapped[str | None] = mapped_column(
        String(50), nullable=True,
        comment="success, partial_success, failure"
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Rollback tracking
    rollback_status: Mapped[str | None] = mapped_column(
        String(50), nullable=True,
        comment="pending, in_progress, completed, failed"
    )
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Metrics
    metrics: Mapped[dict] = mapped_column(JSON, nullable=False, default={})
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Audit
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    # Relationships
    policy: Mapped["RemediationPolicy"] = relationship(
        "RemediationPolicy", back_populates="executions"
    )


class RemediationPlaybook(BaseModel):
    """
    Multi-step remediation workflow: sequence of actions with decision points.

    Playbooks enable complex, multi-step incident response scenarios:
    conditional logic, parallel actions, approval gates, estimated timing.
    """
    __tablename__ = "remediation_playbooks"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Playbook type and trigger
    playbook_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="incident_response, vulnerability_remediation, compliance_fix, threat_containment, recovery"
    )
    trigger_conditions: Mapped[dict] = mapped_column(JSON, nullable=False, default={})

    # Workflow definition
    steps: Mapped[list[dict]] = mapped_column(
        JSON, nullable=False, default=[],
        comment="Ordered list of {action_id, conditions, on_success, on_failure, timeout}"
    )
    decision_points: Mapped[list[dict]] = mapped_column(
        JSON, nullable=False, default=[],
        comment="Human decision gates"
    )
    parallel_actions: Mapped[list[list[str]]] = mapped_column(
        JSON, nullable=False, default=[],
        comment="Actions that can run simultaneously"
    )

    # Execution settings
    estimated_duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_template: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Metrics
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    avg_execution_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=[])
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)


class RemediationIntegration(BaseModel):
    """
    External system integration for remediation execution.

    Defines connection details and capabilities for systems that will
    execute remediation actions (firewalls, EDR, AD, cloud providers, etc.)
    """
    __tablename__ = "remediation_integrations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Integration type and vendor
    integration_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="firewall, edr, siem, email_gateway, active_directory, cloud_provider, ticketing, dns, waf, proxy, custom_api"
    )
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Connection details
    endpoint_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="api_key",
        comment="api_key, oauth, basic, certificate, aws_iam"
    )
    auth_config: Mapped[dict] = mapped_column(
        JSON, nullable=False, default={},
        comment="Encrypted reference to credentials"
    )

    # Capabilities
    capabilities: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=[],
        comment="Actions this integration supports"
    )

    # Health and performance
    is_connected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    health_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="unknown",
        comment="unknown, healthy, degraded, unavailable"
    )
    rate_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=60)

    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=[])
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
