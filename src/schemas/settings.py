"""Settings and configuration schemas"""

from typing import Optional, List
from pydantic import BaseModel, Field


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
