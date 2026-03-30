"""Integration Connector and Marketplace models"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel

if TYPE_CHECKING:
    pass


class IntegrationCategory(str, Enum):
    """Connector categories"""

    SIEM = "siem"
    EDR = "edr"
    FIREWALL = "firewall"
    EMAIL_SECURITY = "email_security"
    CLOUD_PROVIDER = "cloud_provider"
    IDENTITY_PROVIDER = "identity_provider"
    TICKETING = "ticketing"
    COMMUNICATION = "communication"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    DLP = "dlp"
    CASB = "casb"
    WAF = "waf"
    DNS_SECURITY = "dns_security"
    NETWORK_MONITORING = "network_monitoring"
    CONTAINER_SECURITY = "container_security"
    CI_CD = "ci_cd"
    CODE_REPOSITORY = "code_repository"
    PAM = "pam"
    BACKUP = "backup"


class AuthType(str, Enum):
    """Authentication types"""

    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    CERTIFICATE = "certificate"
    SAML = "saml"
    CUSTOM = "custom"


class ActionType(str, Enum):
    """Integration action types"""

    QUERY = "query"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ENRICH = "enrich"
    CONTAIN = "contain"
    REMEDIATE = "remediate"
    NOTIFY = "notify"
    SCAN = "scan"
    EXPORT = "export"


class ExecutionStatus(str, Enum):
    """Integration execution status"""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ExecutionTrigger(str, Enum):
    """What triggered an execution"""

    PLAYBOOK = "playbook"
    MANUAL = "manual"
    AUTOMATION_RULE = "automation_rule"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"
    API = "api"


class IntegrationStatus(str, Enum):
    """Integration status"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    CONFIGURING = "configuring"
    RATE_LIMITED = "rate_limited"


class HealthStatus(str, Enum):
    """Health status of integration"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class IntegrationConnector(BaseModel):
    """Integration connector definition from marketplace"""

    __tablename__ = "integration_connectors"

    # Basic info
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Classification
    category: Mapped[str] = mapped_column(
        String(50),
        default=IntegrationCategory.THREAT_INTEL.value,
        nullable=False,
        index=True,
    )

    # Versioning
    version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    icon_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    documentation_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Capabilities
    supported_actions: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    supported_triggers: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array

    # Authentication
    auth_type: Mapped[str] = mapped_column(
        String(50),
        default=AuthType.API_KEY.value,
        nullable=False,
    )

    # Dynamic configuration schema
    config_schema: Mapped[str] = mapped_column(Text, nullable=False)  # JSON schema

    # Marketplace metadata
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_community: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rating: Mapped[Optional[float]] = mapped_column(nullable=True)
    install_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_updated: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Relationships
    installed_integrations: Mapped[list["InstalledIntegration"]] = relationship(
        "InstalledIntegration",
        back_populates="connector",
    )
    actions: Mapped[list["IntegrationAction"]] = relationship(
        "IntegrationAction",
        back_populates="connector",
    )

    def __repr__(self) -> str:
        return f"<IntegrationConnector {self.display_name}>"


class InstalledIntegration(BaseModel):
    """Installed integration instance"""

    __tablename__ = "installed_integrations"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Reference to connector
    connector_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("integration_connectors.id"),
        nullable=False,
        index=True,
    )

    # Custom display name
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Configuration and credentials (encrypted)
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)  # JSON encrypted
    auth_credentials_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )  # JSON encrypted

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        default=IntegrationStatus.CONFIGURING.value,
        nullable=False,
        index=True,
    )
    health_status: Mapped[str] = mapped_column(
        String(50),
        default=HealthStatus.UNKNOWN.value,
        nullable=False,
    )

    # Health monitoring
    last_health_check: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_successful_action: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Rate limiting
    rate_limit_remaining: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rate_limit_reset: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Webhook
    webhook_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    webhook_secret_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Relationships
    connector: Mapped["IntegrationConnector"] = relationship(
        "IntegrationConnector",
        back_populates="installed_integrations",
    )
    executions: Mapped[list["IntegrationExecution"]] = relationship(
        "IntegrationExecution",
        back_populates="installed_integration",
    )
    webhooks: Mapped[list["WebhookEndpoint"]] = relationship(
        "WebhookEndpoint",
        back_populates="installed_integration",
    )

    def __repr__(self) -> str:
        return f"<InstalledIntegration {self.display_name}>"


class IntegrationAction(BaseModel):
    """Available action for an integration connector"""

    __tablename__ = "integration_actions"

    # Reference to connector
    connector_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("integration_connectors.id"),
        nullable=False,
        index=True,
    )

    # Action identification
    action_name: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Action type
    action_type: Mapped[str] = mapped_column(
        String(50),
        default=ActionType.QUERY.value,
        nullable=False,
    )

    # I/O Schemas
    input_schema: Mapped[str] = mapped_column(Text, nullable=False)  # JSON schema
    output_schema: Mapped[str] = mapped_column(Text, nullable=False)  # JSON schema

    # Configuration
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    retry_policy: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    is_idempotent: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    connector: Mapped["IntegrationConnector"] = relationship(
        "IntegrationConnector",
        back_populates="actions",
    )
    executions: Mapped[list["IntegrationExecution"]] = relationship(
        "IntegrationExecution",
        back_populates="action",
    )

    def __repr__(self) -> str:
        return f"<IntegrationAction {self.action_name}>"


class IntegrationExecution(BaseModel):
    """Record of integration action execution"""

    __tablename__ = "integration_executions"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # References
    installed_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("installed_integrations.id"),
        nullable=False,
        index=True,
    )
    action_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("integration_actions.id"),
        nullable=False,
        index=True,
    )

    # Trigger information
    triggered_by: Mapped[str] = mapped_column(
        String(50),
        default=ExecutionTrigger.MANUAL.value,
        nullable=False,
    )
    playbook_run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Input and output
    input_data: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    output_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Execution status
    status: Mapped[str] = mapped_column(
        String(50),
        default=ExecutionStatus.PENDING.value,
        nullable=False,
        index=True,
    )

    # Timing
    started_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    installed_integration: Mapped["InstalledIntegration"] = relationship(
        "InstalledIntegration",
        back_populates="executions",
    )
    action: Mapped["IntegrationAction"] = relationship(
        "IntegrationAction",
        back_populates="executions",
    )

    def __repr__(self) -> str:
        return f"<IntegrationExecution {self.id} - {self.status}>"


class WebhookEndpoint(BaseModel):
    """Webhook endpoint for incoming integration events"""

    __tablename__ = "webhook_endpoints"

    # Multi-tenancy
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Reference to installed integration
    installed_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("installed_integrations.id"),
        nullable=False,
        index=True,
    )

    # Endpoint configuration
    endpoint_path: Mapped[str] = mapped_column(String(255), nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), default="POST", nullable=False)

    # Security
    secret_hash: Mapped[str] = mapped_column(String(256), nullable=False)

    # Event routing
    event_types: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    transform_template: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )  # Jinja2 template

    # Status and metrics
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_received: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    received_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    installed_integration: Mapped["InstalledIntegration"] = relationship(
        "InstalledIntegration",
        back_populates="webhooks",
    )

    def __repr__(self) -> str:
        return f"<WebhookEndpoint {self.endpoint_path}>"
