"""Settings and configuration schemas"""

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from src.agentic.policy import RETENTION_DEFAULT_DAYS, RETENTION_MAX_DAYS, RETENTION_MIN_DAYS


class IntegrationConfig(BaseModel):
    """Configuration for an integration"""
    enabled: bool = False
    api_key: Optional[str] = None
    webhook_url: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None


class SMTPConfig(BaseModel):
    """SMTP email configuration"""
    host: str = "smtp.gmail.com"
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    from_address: str = "noreply@pysoar.local"
    use_tls: bool = True


class NotificationConfig(BaseModel):
    """Notification settings"""
    email_enabled: bool = False
    slack_enabled: bool = False
    teams_enabled: bool = False
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None


class AlertCorrelationConfig(BaseModel):
    """Alert correlation settings"""
    enabled: bool = True
    time_window_minutes: int = 60
    similarity_threshold: float = 0.7
    auto_create_incident: bool = True
    min_alerts_for_incident: int = 3


class GeneralSettings(BaseModel):
    """General application settings"""
    app_name: str = "PySOAR"
    timezone: str = "UTC"
    date_format: str = "YYYY-MM-DD"
    time_format: str = "HH:mm:ss"
    session_timeout_minutes: int = 30
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15


class SettingsResponse(BaseModel):
    """Combined settings response"""
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    smtp: SMTPConfig = Field(default_factory=SMTPConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    alert_correlation: AlertCorrelationConfig = Field(default_factory=AlertCorrelationConfig)
    integrations: dict = Field(default_factory=dict)


class SettingsUpdate(BaseModel):
    """Settings update request"""
    general: Optional[GeneralSettings] = None
    smtp: Optional[SMTPConfig] = None
    notifications: Optional[NotificationConfig] = None
    alert_correlation: Optional[AlertCorrelationConfig] = None
    integrations: Optional[dict] = None


# ---------------------------------------------------------------------------
# AI provider settings (design v2 §9: GET/PUT /settings/ai)
# ---------------------------------------------------------------------------

AIProviderName = Literal["anthropic", "gemini", "openai", "ollama"]


class AICapabilities(BaseModel):
    """What the last successful model-list told us about the provider."""

    models_seen_at: str
    model_count: int


class AISettingsResponse(BaseModel):
    """Read model for ``GET /settings/ai``. Never carries an API key."""

    provider: Optional[AIProviderName] = None
    model: Optional[str] = None
    use_platform_default: bool = False
    configured: bool = False
    source: Literal["org", "platform", "none"] = "none"
    # Why the org is not configured (``missing_credential`` / ``model_not_set``
    # / ``ai_not_configured`` ...); None when ``configured`` is true.
    reason: Optional[str] = None
    # ``sha256[:12]:last4`` of the stored key — safe to display, never the key.
    key_fingerprint: Optional[str] = None
    rotated_at: Optional[str] = None
    last_successful_call_at: Optional[str] = None
    capabilities: Optional[AICapabilities] = None


class AISettingsUpdate(BaseModel):
    """Write model for ``PUT /settings/ai``.

    ``extra="forbid"`` is deliberate: a tenant must not be able to smuggle a
    base URL (or any other provider knob) into the request. The explicit
    URL-ish fields below exist only so such an attempt gets a precise
    ``400 tenant_url_not_allowed`` instead of a generic 422.
    """

    model_config = ConfigDict(extra="forbid")

    provider: AIProviderName
    model: str = Field(min_length=1, max_length=120)
    use_platform_default: bool = False
    api_key: Optional[str] = Field(default=None, min_length=8, max_length=1024, repr=False)

    base_url: Optional[str] = None
    url: Optional[str] = None
    host: Optional[str] = None
    api_base: Optional[str] = None
    endpoint: Optional[str] = None

    def supplied_url_keys(self) -> List[str]:
        """URL-ish keys the client sent a value for (always rejected)."""
        return [
            key
            for key in ("base_url", "url", "host", "api_base", "endpoint")
            if getattr(self, key, None)
        ]


class AIModelsResponse(BaseModel):
    """Read model for ``GET /settings/ai/models``."""

    provider: AIProviderName
    source: Literal["org", "platform"]
    models: List[str] = Field(default_factory=list)
    fetched_at: str


class AITenantRow(BaseModel):
    """One organization's AI configuration, for the superuser overview."""

    organization_id: str
    provider: Optional[str] = None
    model: Optional[str] = None
    source: Literal["org", "platform", "none"] = "none"
    last_successful_call_at: Optional[str] = None


class AITenantsResponse(BaseModel):
    """Read model for the superuser ``GET /settings/ai/tenants``."""

    tenants: List[AITenantRow] = Field(default_factory=list)
    count: int = 0


class LLMHealthResponse(BaseModel):
    """Read model for ``GET /health/llm`` (per-org provider reachability)."""

    status: Literal["ok", "not_configured", "degraded"]
    organization_id: Optional[str] = None
    configured: bool = False
    provider: Optional[str] = None
    model: Optional[str] = None
    source: Literal["org", "platform", "none"] = "none"
    reason: Optional[str] = None
    last_successful_call_at: Optional[str] = None
    # None when the breaker state could not be read (Redis unavailable).
    breaker_open: Optional[bool] = None
    checked_at: str
    cached: bool = False


# ---------------------------------------------------------------------------
# Agentic policy settings (GET/PUT /settings/agentic-policy)
# ---------------------------------------------------------------------------


class AgenticPolicySettingsResponse(BaseModel):
    """Read model for ``GET /settings/agentic-policy`` (org admin)."""

    # Separation of duties (AC-5): destructive/privileged agent actions need
    # two distinct approvers, neither of them the proposer. Off by default.
    require_second_approver: bool = False
    # Retention (AU-11), effective values: the org's own setting or the
    # 365-day platform default.
    llm_call_log_retention_days: int = RETENTION_DEFAULT_DAYS
    agent_transcript_retention_days: int = RETENTION_DEFAULT_DAYS
    retention_min_days: int = RETENTION_MIN_DAYS
    retention_max_days: int = RETENTION_MAX_DAYS
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None


class AgenticPolicySettingsUpdate(BaseModel):
    """Write model for ``PUT /settings/agentic-policy``.

    Partial update: omitted fields keep their stored value; at least one field
    is required. Unknown keys are rejected, and a retention value outside
    30..1095 days (or not an integer) is a 422.
    """

    model_config = ConfigDict(extra="forbid")

    require_second_approver: Optional[bool] = None
    llm_call_log_retention_days: Optional[StrictInt] = Field(
        default=None, ge=RETENTION_MIN_DAYS, le=RETENTION_MAX_DAYS,
    )
    agent_transcript_retention_days: Optional[StrictInt] = Field(
        default=None, ge=RETENTION_MIN_DAYS, le=RETENTION_MAX_DAYS,
    )

    @model_validator(mode="after")
    def _at_least_one_field(self) -> "AgenticPolicySettingsUpdate":
        if (
            self.require_second_approver is None
            and self.llm_call_log_retention_days is None
            and self.agent_transcript_retention_days is None
        ):
            raise ValueError("at least one setting is required")
        return self
