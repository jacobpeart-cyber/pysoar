"""Settings endpoints for managing application configuration.

Settings are persisted in the ``app_settings`` DB table, keyed by
``(organization_id, section)``. The GET endpoint unions the env-derived
defaults with any per-org override rows — org values win. Each PATCH
endpoint upserts the row via ``INSERT ... ON CONFLICT DO UPDATE`` so
changes survive container restarts.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import json

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, get_current_superuser
from src.core.config import settings as app_settings
from src.models.settings import AppSetting
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


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

async def _load_section(
    db: AsyncSession, organization_id: Optional[str], section: str
) -> Dict[str, Any]:
    """Return the stored value for (org, section), or {} if no row exists."""
    stmt = select(AppSetting).where(AppSetting.section == section)
    if organization_id is not None:
        stmt = stmt.where(AppSetting.organization_id == organization_id)
    else:
        stmt = stmt.where(AppSetting.organization_id.is_(None))
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row and isinstance(row.value, dict):
        return row.value
    return {}


async def _upsert_section(
    db: AsyncSession,
    organization_id: Optional[str],
    section: str,
    value: Dict[str, Any],
    updated_by: Optional[str],
) -> Dict[str, Any]:
    """Upsert the stored value, merging with any pre-existing keys."""
    existing = await _load_section(db, organization_id, section)
    merged = {**existing, **{k: v for k, v in value.items() if v is not None}}

    dialect = db.bind.dialect.name if db.bind is not None else "postgresql"

    if dialect == "postgresql":
        stmt = pg_insert(AppSetting.__table__).values(
            organization_id=organization_id,
            section=section,
            value=merged,
            updated_by=updated_by,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_app_settings_org_section",
            set_={
                "value": merged,
                "updated_by": updated_by,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        await db.execute(stmt)
    else:
        # SQLite/test fallback: manual upsert
        stmt = select(AppSetting).where(AppSetting.section == section)
        if organization_id is None:
            stmt = stmt.where(AppSetting.organization_id.is_(None))
        else:
            stmt = stmt.where(AppSetting.organization_id == organization_id)
        existing_row = (await db.execute(stmt)).scalar_one_or_none()
        if existing_row is None:
            db.add(
                AppSetting(
                    organization_id=organization_id,
                    section=section,
                    value=merged,
                    updated_by=updated_by,
                )
            )
        else:
            existing_row.value = merged
            existing_row.updated_by = updated_by

    await db.commit()
    return merged


def _user_org(user: User) -> Optional[str]:
    return getattr(user, "organization_id", None)


# ---------------------------------------------------------------------------
# GET /settings
# ---------------------------------------------------------------------------

@router.get("", response_model=SettingsResponse)
async def get_settings(
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> SettingsResponse:
    """Get current application settings (admin only).

    Union of env-derived defaults with any stored per-org overrides.
    """
    org_id = _user_org(current_user)

    general_override = await _load_section(db, org_id, "general")
    smtp_override = await _load_section(db, org_id, "smtp")
    notif_override = await _load_section(db, org_id, "notifications")
    security_override = await _load_section(db, org_id, "security")

    def pick(ovr: Dict[str, Any], key: str, default: Any) -> Any:
        return ovr.get(key, default) if ovr else default

    integrations: dict = {
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
    }

    # Merge integration overrides: any section "integration:<id>"
    for integ_id in list(integrations.keys()):
        ovr = await _load_section(db, org_id, f"integration:{integ_id}")
        if ovr:
            configured = bool(
                ovr.get("api_key") or ovr.get("url") or ovr.get("host") or ovr.get("token")
            ) or integrations[integ_id]["configured"]
            integrations[integ_id] = {
                "enabled": bool(ovr.get("enabled", integrations[integ_id]["enabled"])),
                "configured": configured,
            }

    return SettingsResponse(
        general=GeneralSettings(
            app_name=pick(general_override, "app_name", app_settings.app_name),
            timezone=pick(general_override, "timezone", "UTC"),
            date_format=pick(general_override, "date_format", "YYYY-MM-DD"),
            time_format=pick(general_override, "time_format", "HH:mm:ss"),
            session_timeout_minutes=pick(
                general_override,
                "session_timeout_minutes",
                app_settings.access_token_expire_minutes,
            ),
            max_login_attempts=pick(
                security_override,
                "max_login_attempts",
                pick(general_override, "max_login_attempts", 5),
            ),
            lockout_duration_minutes=pick(
                security_override,
                "lockout_duration_minutes",
                pick(general_override, "lockout_duration_minutes", 15),
            ),
        ),
        smtp=SMTPConfig(
            host=pick(smtp_override, "host", app_settings.smtp_host),
            port=pick(smtp_override, "port", app_settings.smtp_port),
            username=pick(smtp_override, "username", app_settings.smtp_user),
            from_address=pick(smtp_override, "from_address", app_settings.smtp_from),
            use_tls=pick(smtp_override, "use_tls", app_settings.smtp_tls),
        ),
        notifications=NotificationConfig(
            email_enabled=pick(
                notif_override,
                "email_enabled",
                bool(app_settings.smtp_user),
            ),
            slack_enabled=pick(
                notif_override,
                "slack_enabled",
                bool(app_settings.slack_webhook_url),
            ),
            teams_enabled=pick(
                notif_override,
                "teams_enabled",
                bool(app_settings.teams_webhook_url),
            ),
            slack_webhook_url=_mask_secret(
                pick(
                    notif_override, "slack_webhook_url", app_settings.slack_webhook_url
                )
            ),
            teams_webhook_url=_mask_secret(
                pick(
                    notif_override, "teams_webhook_url", app_settings.teams_webhook_url
                )
            ),
        ),
        alert_correlation=AlertCorrelationConfig(
            enabled=True,
            time_window_minutes=60,
            similarity_threshold=0.7,
            auto_create_incident=True,
            min_alerts_for_incident=3,
        ),
        integrations=integrations,
    )


# ---------------------------------------------------------------------------
# PATCH /settings (combined)
# ---------------------------------------------------------------------------

@router.patch("", response_model=SettingsResponse)
async def update_settings(
    settings_update: SettingsUpdate,
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> SettingsResponse:
    """Update application settings (admin only) — persists to DB."""
    org_id = _user_org(current_user)
    uid = getattr(current_user, "id", None)

    if settings_update.smtp:
        smtp = settings_update.smtp
        value = smtp.model_dump(exclude_unset=True, exclude_none=True)
        await _upsert_section(db, org_id, "smtp", value, uid)
        # Mirror to runtime so the rest of this process sees the change
        for k, attr in (
            ("host", "smtp_host"),
            ("port", "smtp_port"),
            ("username", "smtp_user"),
            ("password", "smtp_password"),
            ("from_address", "smtp_from"),
            ("use_tls", "smtp_tls"),
        ):
            if k in value and value[k] is not None:
                setattr(app_settings, attr, value[k])

    if settings_update.notifications:
        notif = settings_update.notifications
        value = notif.model_dump(exclude_unset=True, exclude_none=True)
        await _upsert_section(db, org_id, "notifications", value, uid)
        if "slack_webhook_url" in value:
            app_settings.slack_webhook_url = value["slack_webhook_url"] or ""
        if "teams_webhook_url" in value:
            app_settings.teams_webhook_url = value["teams_webhook_url"] or ""

    if settings_update.general:
        gen = settings_update.general
        value = gen.model_dump(exclude_unset=True, exclude_none=True)
        await _upsert_section(db, org_id, "general", value, uid)
        if "app_name" in value and value["app_name"] is not None:
            app_settings.app_name = value["app_name"]
        if "session_timeout_minutes" in value and value["session_timeout_minutes"] is not None:
            app_settings.access_token_expire_minutes = int(value["session_timeout_minutes"])

    return await get_settings(db, current_user)


# ---------------------------------------------------------------------------
# PATCH /settings/general
# ---------------------------------------------------------------------------

@router.patch("/general", response_model=GeneralSettings)
async def update_general_settings(
    updates: Dict[str, Any] = Body(...),
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> GeneralSettings:
    """Update general settings. Accepts a dict of fields to update."""
    org_id = _user_org(current_user)
    uid = getattr(current_user, "id", None)

    if "session_timeout_minutes" in updates and updates["session_timeout_minutes"] is not None:
        try:
            updates["session_timeout_minutes"] = int(updates["session_timeout_minutes"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="session_timeout_minutes must be int")

    merged = await _upsert_section(db, org_id, "general", updates, uid)

    # Mirror to runtime for in-process effect
    if "app_name" in merged and merged["app_name"] is not None:
        app_settings.app_name = str(merged["app_name"])
    if "session_timeout_minutes" in merged and merged["session_timeout_minutes"] is not None:
        app_settings.access_token_expire_minutes = int(merged["session_timeout_minutes"])

    return GeneralSettings(
        app_name=merged.get("app_name", app_settings.app_name),
        timezone=merged.get("timezone", "UTC"),
        date_format=merged.get("date_format", "YYYY-MM-DD"),
        time_format=merged.get("time_format", "HH:mm:ss"),
        session_timeout_minutes=int(
            merged.get("session_timeout_minutes", app_settings.access_token_expire_minutes)
        ),
        max_login_attempts=int(merged.get("max_login_attempts", 5)),
        lockout_duration_minutes=int(merged.get("lockout_duration_minutes", 15)),
    )


# ---------------------------------------------------------------------------
# PATCH /settings/smtp
# ---------------------------------------------------------------------------

@router.patch("/smtp", response_model=SMTPConfig)
async def update_smtp_settings(
    updates: Dict[str, Any] = Body(...),
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> SMTPConfig:
    """Update SMTP settings. Accepts a dict of fields to update."""
    org_id = _user_org(current_user)
    uid = getattr(current_user, "id", None)

    clean: Dict[str, Any] = {}
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
            clean[in_key] = value
            setattr(app_settings, attr, value)

    merged = await _upsert_section(db, org_id, "smtp", clean, uid)

    return SMTPConfig(
        host=merged.get("host", app_settings.smtp_host),
        port=int(merged.get("port", app_settings.smtp_port)),
        username=merged.get("username", app_settings.smtp_user),
        from_address=merged.get("from_address", app_settings.smtp_from),
        use_tls=bool(merged.get("use_tls", app_settings.smtp_tls)),
    )


# ---------------------------------------------------------------------------
# PATCH /settings/notifications
# ---------------------------------------------------------------------------

@router.patch("/notifications", response_model=NotificationConfig)
async def update_notification_settings(
    updates: Dict[str, Any] = Body(...),
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> NotificationConfig:
    """Update notification settings. Accepts a dict of fields to update."""
    org_id = _user_org(current_user)
    uid = getattr(current_user, "id", None)

    clean: Dict[str, Any] = {}
    if "slack_webhook_url" in updates:
        clean["slack_webhook_url"] = updates["slack_webhook_url"] or ""
        app_settings.slack_webhook_url = clean["slack_webhook_url"]
    if "teams_webhook_url" in updates:
        clean["teams_webhook_url"] = updates["teams_webhook_url"] or ""
        app_settings.teams_webhook_url = clean["teams_webhook_url"]
    for key in ("email_enabled", "slack_enabled", "teams_enabled"):
        if key in updates and updates[key] is not None:
            clean[key] = bool(updates[key])

    merged = await _upsert_section(db, org_id, "notifications", clean, uid)

    return NotificationConfig(
        email_enabled=bool(merged.get("email_enabled", bool(app_settings.smtp_user))),
        slack_enabled=bool(
            merged.get("slack_enabled", bool(app_settings.slack_webhook_url))
        ),
        teams_enabled=bool(
            merged.get("teams_enabled", bool(app_settings.teams_webhook_url))
        ),
        slack_webhook_url=_mask_secret(
            merged.get("slack_webhook_url", app_settings.slack_webhook_url)
        ),
        teams_webhook_url=_mask_secret(
            merged.get("teams_webhook_url", app_settings.teams_webhook_url)
        ),
    )


# ---------------------------------------------------------------------------
# PATCH /settings/security
# ---------------------------------------------------------------------------

@router.patch("/security", response_model=SecurityConfig)
async def update_security_settings(
    updates: Dict[str, Any] = Body(...),
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> SecurityConfig:
    """Update security settings. Accepts a dict of fields to update."""
    org_id = _user_org(current_user)
    uid = getattr(current_user, "id", None)

    clean: Dict[str, Any] = {}
    if "session_timeout_minutes" in updates and updates["session_timeout_minutes"] is not None:
        try:
            clean["session_timeout_minutes"] = int(updates["session_timeout_minutes"])
            app_settings.access_token_expire_minutes = clean["session_timeout_minutes"]
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="session_timeout_minutes must be int")
    for key in ("max_login_attempts", "lockout_duration_minutes",
                "password_min_length", "require_mfa"):
        if key in updates and updates[key] is not None:
            clean[key] = updates[key]

    merged = await _upsert_section(db, org_id, "security", clean, uid)

    return SecurityConfig(
        max_login_attempts=int(merged.get("max_login_attempts", 5)),
        lockout_duration_minutes=int(merged.get("lockout_duration_minutes", 15)),
        session_timeout_minutes=int(
            merged.get("session_timeout_minutes", app_settings.access_token_expire_minutes)
        ),
        password_min_length=int(merged.get("password_min_length", 8)),
        require_mfa=bool(merged.get("require_mfa", False)),
    )


# ---------------------------------------------------------------------------
# POST /settings/integrations/{id}
# ---------------------------------------------------------------------------

_INTEGRATION_KEY_ATTR = {
    "virustotal": "virustotal_api_key",
    "abuseipdb": "abuseipdb_api_key",
    "shodan": "shodan_api_key",
    "greynoise": "greynoise_api_key",
    "elasticsearch": "elasticsearch_url",
    "splunk": "splunk_host",
    # Notification channels — Configure X buttons on the Settings page
    # for Slack / Teams / PagerDuty previously returned "Unknown
    # integration" because only the enrichment set was whitelisted.
    "slack": "slack_webhook_url",
    "teams": "teams_webhook_url",
    "pagerduty": "pagerduty_api_key",
    "opsgenie": "opsgenie_api_key",
    # Ticketing
    "jira": "jira_url",
    "servicenow": "servicenow_url",
    # OpenAI / AI providers
    "openai": "openai_api_key",
    "anthropic": "anthropic_api_key",
}


@router.post("/integrations/{integration_id}")
async def save_integration_config(
    integration_id: str,
    config: Dict[str, Any] = Body(...),
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """Save configuration for a specific integration (persisted)."""
    if integration_id not in _INTEGRATION_KEY_ATTR:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown integration: {integration_id}",
        )

    org_id = _user_org(current_user)
    uid = getattr(current_user, "id", None)
    attr = _INTEGRATION_KEY_ATTR[integration_id]

    primary_value = (
        config.get("api_key")
        or config.get("url")
        or config.get("host")
        or config.get("token")
        or config.get("webhook_url")
    )
    # Only mutate app_settings when the target attribute actually
    # exists on the BaseSettings object (pydantic v2 rejects unknown
    # attrs). Notification/ticketing integrations like Slack, Teams,
    # PagerDuty, Jira don't have corresponding app_settings attrs —
    # they're read exclusively from the DB-saved `integration:<name>`
    # row, which is what `_upsert_section` below persists.
    if primary_value is not None and hasattr(app_settings, attr):
        try:
            setattr(app_settings, attr, str(primary_value))
        except Exception:  # pydantic validation — non-fatal
            pass

    merged = await _upsert_section(
        db, org_id, f"integration:{integration_id}", config, uid
    )

    configured = bool(
        merged.get("api_key")
        or merged.get("url")
        or merged.get("host")
        or merged.get("token")
        or getattr(app_settings, attr, None)
    )
    enabled = bool(merged.get("enabled", configured))

    # Bridge: also upsert an InstalledIntegration row so the
    # Integrations marketplace page ("Installed: N · Active: N")
    # reflects what the operator configured through Settings. The two
    # pages used to be fully independent — you'd save VT through
    # Settings and the Integrations page still said "0 installed".
    try:
        from src.api.v1.endpoints.integrations import _encrypt_secret_json
        from src.integrations.models import InstalledIntegration
        res = await db.execute(
            select(InstalledIntegration).where(
                InstalledIntegration.connector_id == integration_id,
                InstalledIntegration.organization_id == org_id,
            ).limit(1)
        )
        existing = res.scalars().first()
        encrypted_creds = _encrypt_secret_json({k: v for k, v in config.items() if k in ("api_key", "token", "url", "host", "username", "password")})
        public_config = {k: v for k, v in config.items() if k not in ("api_key", "token", "password")}
        if existing is None:
            installation = InstalledIntegration(
                organization_id=org_id,
                connector_id=integration_id,
                display_name=integration_id.replace("_", " ").title(),
                config_encrypted=json.dumps(public_config) if public_config else "{}",
                auth_credentials_encrypted=encrypted_creds,
                status="active" if enabled else "disabled",
                health_status="unknown",
            )
            db.add(installation)
        else:
            existing.auth_credentials_encrypted = encrypted_creds
            existing.config_encrypted = json.dumps(public_config) if public_config else existing.config_encrypted
            existing.status = "active" if enabled else "disabled"
        await db.flush()
    except Exception as exc:  # noqa: BLE001
        # Bridge failure is non-fatal — the Settings save already
        # succeeded. Log and move on.
        import logging
        logging.getLogger(__name__).warning(
            "Bridge to InstalledIntegration failed for %s: %s", integration_id, exc
        )

    return {
        "integration_id": integration_id,
        "enabled": enabled,
        "configured": configured,
    }


# ---------------------------------------------------------------------------
# POST /settings/test-email and /settings/test-integration/{name}
# (unchanged — operational tests, no persistence)
# ---------------------------------------------------------------------------

@router.post("/test-email")
async def test_email_settings(
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """Test email configuration by sending a test email.

    Treats a DB-saved SMTP section as authoritative over the env-time
    ``app_settings.smtp_user``. Previously a user who configured SMTP
    through the UI got "Email is not configured" on Test until the
    container was restarted — save+test was broken within a session.
    """
    org_id = _user_org(current_user)
    saved_smtp = await _load_section(db, org_id, "smtp") if db is not None else {}
    configured_user = (saved_smtp or {}).get("smtp_user") or (saved_smtp or {}).get("user") or app_settings.smtp_user
    if not configured_user:
        raise HTTPException(
            status_code=400,
            detail="Email is not configured",
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
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """Test an integration connection.

    Previously this read every API key / URL / host directly from
    ``app_settings`` (which is loaded once from env at startup). A user
    who saved a new VirusTotal key through the UI and clicked Test
    immediately got a 400 / failed probe because the container hadn't
    restarted and ``app_settings`` still held the env-time value. Now
    we load the most-recently persisted ``integration:<name>`` section
    from ``system_settings`` and fall back to ``app_settings`` only
    when no DB override exists — so Save + Test actually works in the
    same session.
    """
    valid_integrations = ["virustotal", "abuseipdb", "shodan", "greynoise", "elasticsearch", "splunk"]

    if integration_name not in valid_integrations:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown integration: {integration_name}"
        )

    org_id = _user_org(current_user)
    saved = await _load_section(db, org_id, f"integration:{integration_name}") if db is not None else {}

    def _pick(keys: list[str], fallback: str = "") -> str:
        for k in keys:
            v = saved.get(k) if isinstance(saved, dict) else None
            if v:
                return str(v)
        return fallback or ""

    vt_key = _pick(["api_key"], app_settings.virustotal_api_key or "")
    abuse_key = _pick(["api_key"], app_settings.abuseipdb_api_key or "")
    shodan_key = _pick(["api_key"], app_settings.shodan_api_key or "")
    greynoise_key = _pick(["api_key"], app_settings.greynoise_api_key or "")
    es_url = _pick(["url"], app_settings.elasticsearch_url or "")
    splunk_host = _pick(["host"], app_settings.splunk_host or "")

    api_key_map = {
        "virustotal": vt_key,
        "abuseipdb": abuse_key,
        "shodan": shodan_key,
        "greynoise": greynoise_key,
        "elasticsearch": es_url,
        "splunk": splunk_host,
    }

    if not api_key_map.get(integration_name):
        raise HTTPException(
            status_code=400,
            detail=f"Integration {integration_name} is not configured"
        )

    import httpx

    test_endpoints = {
        # /urls returns 405 on GET (it's a POST-only submission endpoint).
        # /users/current is the canonical auth-check endpoint that returns
        # the API key's quota + privileges on GET.
        "virustotal": ("https://www.virustotal.com/api/v3/users/current", {"x-apikey": vt_key}),
        "abuseipdb": ("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1", {"Key": abuse_key, "Accept": "application/json"}),
        "shodan": (f"https://api.shodan.io/api-info?key={shodan_key}", {}),
        "greynoise": ("https://api.greynoise.io/v3/community/8.8.8.8", {"key": greynoise_key}),
        "elasticsearch": (es_url, {}),
        "splunk": (f"https://{splunk_host}:8089/services/server/info", {}),
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


def _mask_secret(value: Optional[str]) -> Optional[str]:
    """Mask sensitive values for display"""
    if not value:
        return None
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"
