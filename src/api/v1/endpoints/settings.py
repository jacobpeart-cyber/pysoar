"""Settings endpoints for managing application configuration"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

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


class SecurityConfig(BaseModel):
    """Subset of security-related tunables exposed via PATCH /settings/security"""
    max_login_attempts: Optional[int] = None
    lockout_duration_minutes: Optional[int] = None
    session_timeout_minutes: Optional[int] = None
    password_min_length: Optional[int] = None
    require_mfa: Optional[bool] = None

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

    Persists settings by updating the runtime config object.
    Changes take effect immediately but do not survive a restart
    unless also written to environment or .env file.
    """
    update_data = settings_update.model_dump(exclude_unset=True, exclude_none=True)

    # Apply SMTP settings
    if settings_update.smtp:
        smtp = settings_update.smtp
        if smtp.host is not None:
            app_settings.smtp_host = smtp.host
        if smtp.port is not None:
            app_settings.smtp_port = smtp.port
        if smtp.username is not None:
            app_settings.smtp_user = smtp.username
        if smtp.password is not None:
            app_settings.smtp_password = smtp.password
        if smtp.from_address is not None:
            app_settings.smtp_from = smtp.from_address
        if smtp.use_tls is not None:
            app_settings.smtp_tls = smtp.use_tls

    # Apply notification settings
    if settings_update.notifications:
        notif = settings_update.notifications
        if notif.slack_webhook_url is not None:
            app_settings.slack_webhook_url = notif.slack_webhook_url
        if notif.teams_webhook_url is not None:
            app_settings.teams_webhook_url = notif.teams_webhook_url

    # Apply general settings
    if settings_update.general:
        gen = settings_update.general
        if gen.app_name is not None:
            app_settings.app_name = gen.app_name
        if gen.session_timeout_minutes is not None:
            app_settings.access_token_expire_minutes = gen.session_timeout_minutes

    return await get_settings(current_user)


@router.patch("/general", response_model=GeneralSettings)
async def update_general_settings(
    updates: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_superuser),
) -> GeneralSettings:
    """Update general settings. Accepts a dict of fields to update."""
    if "app_name" in updates and updates["app_name"] is not None:
        app_settings.app_name = str(updates["app_name"])
    if "session_timeout_minutes" in updates and updates["session_timeout_minutes"] is not None:
        try:
            app_settings.access_token_expire_minutes = int(updates["session_timeout_minutes"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="session_timeout_minutes must be int")
    # These fields are not currently bound to app_settings; keep them as
    # echo-through so the UI can render the saved value during the process.
    for key in ("timezone", "date_format", "time_format",
                "max_login_attempts", "lockout_duration_minutes"):
        if key in updates and updates[key] is not None:
            setattr(app_settings, f"_runtime_{key}", updates[key])

    return GeneralSettings(
        app_name=app_settings.app_name,
        timezone=getattr(app_settings, "_runtime_timezone", "UTC"),
        date_format=getattr(app_settings, "_runtime_date_format", "YYYY-MM-DD"),
        time_format=getattr(app_settings, "_runtime_time_format", "HH:mm:ss"),
        session_timeout_minutes=app_settings.access_token_expire_minutes,
        max_login_attempts=getattr(app_settings, "_runtime_max_login_attempts", 5),
        lockout_duration_minutes=getattr(app_settings, "_runtime_lockout_duration_minutes", 15),
    )


@router.patch("/smtp", response_model=SMTPConfig)
async def update_smtp_settings(
    updates: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_superuser),
) -> SMTPConfig:
    """Update SMTP settings. Accepts a dict of fields to update."""
    mapping = {
        "host": "smtp_host",
        "port": "smtp_port",
        "username": "smtp_user",
        "password": "smtp_password",
        "from_address": "smtp_from",
        "use_tls": "smtp_tls",
    }
    for in_key, attr in mapping.items():
        if in_key in updates and updates[in_key] is not None:
            value = updates[in_key]
            if in_key == "port":
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="port must be int")
            if in_key == "use_tls":
                value = bool(value)
            setattr(app_settings, attr, value)

    return SMTPConfig(
        host=app_settings.smtp_host,
        port=app_settings.smtp_port,
        username=app_settings.smtp_user,
        from_address=app_settings.smtp_from,
        use_tls=app_settings.smtp_tls,
    )


@router.patch("/notifications", response_model=NotificationConfig)
async def update_notification_settings(
    updates: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_superuser),
) -> NotificationConfig:
    """Update notification settings. Accepts a dict of fields to update."""
    if "slack_webhook_url" in updates:
        app_settings.slack_webhook_url = updates["slack_webhook_url"] or ""
    if "teams_webhook_url" in updates:
        app_settings.teams_webhook_url = updates["teams_webhook_url"] or ""
    # Booleans like email_enabled are derived in GET; store an override flag
    for key in ("email_enabled", "slack_enabled", "teams_enabled"):
        if key in updates and updates[key] is not None:
            setattr(app_settings, f"_runtime_{key}", bool(updates[key]))

    return NotificationConfig(
        email_enabled=getattr(app_settings, "_runtime_email_enabled", bool(app_settings.smtp_user)),
        slack_enabled=getattr(app_settings, "_runtime_slack_enabled", bool(app_settings.slack_webhook_url)),
        teams_enabled=getattr(app_settings, "_runtime_teams_enabled", bool(app_settings.teams_webhook_url)),
        slack_webhook_url=_mask_secret(app_settings.slack_webhook_url),
        teams_webhook_url=_mask_secret(app_settings.teams_webhook_url),
    )


@router.patch("/security", response_model=SecurityConfig)
async def update_security_settings(
    updates: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_superuser),
) -> SecurityConfig:
    """Update security settings. Accepts a dict of fields to update."""
    if "session_timeout_minutes" in updates and updates["session_timeout_minutes"] is not None:
        try:
            app_settings.access_token_expire_minutes = int(updates["session_timeout_minutes"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="session_timeout_minutes must be int")
    for key in ("max_login_attempts", "lockout_duration_minutes",
                "password_min_length", "require_mfa"):
        if key in updates and updates[key] is not None:
            setattr(app_settings, f"_runtime_{key}", updates[key])

    return SecurityConfig(
        max_login_attempts=getattr(app_settings, "_runtime_max_login_attempts", 5),
        lockout_duration_minutes=getattr(app_settings, "_runtime_lockout_duration_minutes", 15),
        session_timeout_minutes=app_settings.access_token_expire_minutes,
        password_min_length=getattr(app_settings, "_runtime_password_min_length", 8),
        require_mfa=getattr(app_settings, "_runtime_require_mfa", False),
    )


# Per-integration config keyed by canonical integration id (e.g. "virustotal",
# "abuseipdb", "shodan", "greynoise", "elasticsearch", "splunk"). The GET path
# reads `bool(app_settings.<id>_api_key)` for most of these, so mirroring the
# write path means setting those same attributes on app_settings.
_INTEGRATION_KEY_ATTR = {
    "virustotal": "virustotal_api_key",
    "abuseipdb": "abuseipdb_api_key",
    "shodan": "shodan_api_key",
    "greynoise": "greynoise_api_key",
    "elasticsearch": "elasticsearch_url",
    "splunk": "splunk_host",
}


@router.post("/integrations/{integration_id}")
async def save_integration_config(
    integration_id: str,
    config: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """Save configuration for a specific integration."""
    if integration_id not in _INTEGRATION_KEY_ATTR:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown integration: {integration_id}",
        )

    attr = _INTEGRATION_KEY_ATTR[integration_id]
    # The frontend typically sends {api_key, enabled, ...} OR for splunk/elasticsearch
    # it sends {host/url, ...}. Accept the common shapes.
    primary_value = (
        config.get("api_key")
        or config.get("url")
        or config.get("host")
        or config.get("token")
    )
    if primary_value is not None:
        setattr(app_settings, attr, str(primary_value))

    # Stash the full config for retrieval/enabled flag
    setattr(app_settings, f"_runtime_integration_{integration_id}", config)

    configured = bool(getattr(app_settings, attr, None))
    enabled = bool(config.get("enabled", configured))
    return {
        "integration_id": integration_id,
        "enabled": enabled,
        "configured": configured,
    }


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

    from src.services.email_service import EmailService
    email_service = EmailService()

    if not email_service.is_configured:
        raise HTTPException(
            status_code=400,
            detail="Email service is not fully configured (missing credentials)"
        )

    sent = await email_service.send_email(
        to=[current_user.email],
        subject="[PySOAR] Test Email",
        body="This is a test email from PySOAR to verify your SMTP configuration is working correctly.",
    )

    if not sent:
        raise HTTPException(
            status_code=500,
            detail="Failed to send test email. Check SMTP configuration and server logs."
        )

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

    import httpx

    test_endpoints = {
        "virustotal": ("https://www.virustotal.com/api/v3/urls", {"x-apikey": app_settings.virustotal_api_key}),
        "abuseipdb": ("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1", {"Key": app_settings.abuseipdb_api_key, "Accept": "application/json"}),
        "shodan": (f"https://api.shodan.io/api-info?key={app_settings.shodan_api_key}", {}),
        "greynoise": ("https://api.greynoise.io/v3/community/8.8.8.8", {"key": app_settings.greynoise_api_key}),
        "elasticsearch": (app_settings.elasticsearch_url or "", {}),
        "splunk": (f"https://{app_settings.splunk_host}:8089/services/server/info", {}),
    }

    url, headers = test_endpoints.get(integration_name, ("", {}))
    if not url:
        raise HTTPException(status_code=400, detail=f"No test endpoint for {integration_name}")

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code < 400:
                return {
                    "message": f"Successfully connected to {integration_name}",
                    "status": "healthy",
                    "http_status": resp.status_code,
                }
            else:
                raise HTTPException(
                    status_code=502,
                    detail=f"{integration_name} returned HTTP {resp.status_code}: {resp.text[:200]}",
                )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail=f"Connection to {integration_name} timed out after 10 seconds",
        )
    except httpx.ConnectError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot reach {integration_name}: {str(e)[:200]}",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Integration test failed: {str(e)[:200]}",
        )


def _mask_secret(value: str | None) -> str | None:
    """Mask sensitive values for display"""
    if not value:
        return None
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"
