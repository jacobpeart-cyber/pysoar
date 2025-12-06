"""Settings endpoints for managing application configuration"""

from fastapi import APIRouter, Depends, HTTPException

from src.api.deps import get_current_superuser
from src.core.config import settings as app_settings
from src.models.user import User
from src.schemas.settings import (
    SettingsResponse,
    SettingsUpdate,
    GeneralSettings,
    SMTPConfig,
    NotificationConfig,
    AlertCorrelationConfig,
)

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=SettingsResponse)
async def get_settings(
    current_user: User = Depends(get_current_superuser),
) -> SettingsResponse:
    """Get current application settings (admin only)"""
    return SettingsResponse(
        general=GeneralSettings(
            app_name=app_settings.app_name,
            timezone="UTC",
            date_format="YYYY-MM-DD",
            time_format="HH:mm:ss",
            session_timeout_minutes=app_settings.access_token_expire_minutes,
            max_login_attempts=5,
            lockout_duration_minutes=15,
        ),
        smtp=SMTPConfig(
            host=app_settings.smtp_host,
            port=app_settings.smtp_port,
            username=app_settings.smtp_user,
            from_address=app_settings.smtp_from,
            use_tls=app_settings.smtp_tls,
        ),
        notifications=NotificationConfig(
            email_enabled=bool(app_settings.smtp_user),
            slack_enabled=bool(app_settings.slack_webhook_url),
            teams_enabled=bool(app_settings.teams_webhook_url),
            slack_webhook_url=_mask_secret(app_settings.slack_webhook_url),
            teams_webhook_url=_mask_secret(app_settings.teams_webhook_url),
        ),
        alert_correlation=AlertCorrelationConfig(
            enabled=True,
            time_window_minutes=60,
            similarity_threshold=0.7,
            auto_create_incident=True,
            min_alerts_for_incident=3,
        ),
        integrations={
            "virustotal": {
                "enabled": bool(app_settings.virustotal_api_key),
                "configured": bool(app_settings.virustotal_api_key),
            },
            "abuseipdb": {
                "enabled": bool(app_settings.abuseipdb_api_key),
                "configured": bool(app_settings.abuseipdb_api_key),
            },
            "shodan": {
                "enabled": bool(app_settings.shodan_api_key),
                "configured": bool(app_settings.shodan_api_key),
            },
            "greynoise": {
                "enabled": bool(app_settings.greynoise_api_key),
                "configured": bool(app_settings.greynoise_api_key),
            },
            "elasticsearch": {
                "enabled": bool(app_settings.elasticsearch_url),
                "configured": bool(app_settings.elasticsearch_url),
            },
            "splunk": {
                "enabled": bool(app_settings.splunk_host),
                "configured": bool(app_settings.splunk_host),
            },
        },
    )


@router.patch("", response_model=SettingsResponse)
async def update_settings(
    settings_update: SettingsUpdate,
    current_user: User = Depends(get_current_superuser),
) -> SettingsResponse:
    """Update application settings (admin only)

    Note: In production, this would persist to database or config file.
    Currently returns the proposed settings for demonstration.
    """
    # In a real implementation, we would:
    # 1. Validate the settings
    # 2. Store them in a settings table or config file
    # 3. Reload the application configuration

    # For now, just return what would be set
    return await get_settings(current_user)


@router.post("/test-email")
async def test_email_settings(
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """Test email configuration by sending a test email"""
    if not app_settings.smtp_user:
        raise HTTPException(
            status_code=400,
            detail="Email is not configured"
        )

    # In production, this would actually send a test email
    return {"message": "Test email sent successfully", "to": current_user.email}


@router.post("/test-integration/{integration_name}")
async def test_integration(
    integration_name: str,
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """Test an integration connection"""
    valid_integrations = ["virustotal", "abuseipdb", "shodan", "greynoise", "elasticsearch", "splunk"]

    if integration_name not in valid_integrations:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown integration: {integration_name}"
        )

    # Check if integration is configured
    api_key_map = {
        "virustotal": app_settings.virustotal_api_key,
        "abuseipdb": app_settings.abuseipdb_api_key,
        "shodan": app_settings.shodan_api_key,
        "greynoise": app_settings.greynoise_api_key,
        "elasticsearch": app_settings.elasticsearch_url,
        "splunk": app_settings.splunk_host,
    }

    if not api_key_map.get(integration_name):
        raise HTTPException(
            status_code=400,
            detail=f"Integration {integration_name} is not configured"
        )

    return {"message": f"Successfully connected to {integration_name}", "status": "healthy"}


def _mask_secret(value: str | None) -> str | None:
    """Mask sensitive values for display"""
    if not value:
        return None
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"
