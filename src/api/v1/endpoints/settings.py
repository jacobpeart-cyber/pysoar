"""Settings endpoints for managing application configuration.

Settings are persisted in the ``app_settings`` DB table, keyed by
``(organization_id, section)``. The GET endpoint unions the env-derived
defaults with any per-org override rows — org values win. Each PATCH
endpoint upserts the row via ``INSERT ... ON CONFLICT DO UPDATE`` so
changes survive container restarts.

Secrets inside a section value are encrypted at rest (design v2 §10 / F12):
``_upsert_section`` wraps every key in :data:`src.core.secrets.SECRET_KEYS`
in an ``enc:v1:`` envelope before persisting and ``_load_section`` opens them
on read. The operation is idempotent — an already-enveloped value is left
alone — so re-saving a section never double-encrypts. For the ``ai`` and
``integration:*`` sections an unreadable envelope is surfaced as
``503 {"error": "secret_unreadable"}`` instead of silently degrading to
``{}``; for the remaining sections the unreadable value is dropped (and
logged) so the rest of the section still renders.

Outbound probes use fixed provider hosts and TLS verification is always on:
no probe ever disables certificate verification, and a static test in
``tests/unit/test_settings_section_encryption.py`` greps this module to keep
it that way. Tenants never supply a base URL — ``ollama`` /
OpenAI-compatible endpoints come from platform settings only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncio
import json

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import AdminUser, DatabaseSession, get_current_superuser
from src.audit_evidence.engine import AuditLogger
from src.core.config import settings as app_settings
from src.core.logging import get_logger
from src.core.secrets import (
    SECRET_KEYS,
    SecretUnreadable,
    decrypt_secret_json,
    envelope_secret_keys,
    is_enveloped,
    open_secret_keys,
)
from src.llm.base import LLMAuthError, LLMError, LLMNotConfigured
from src.llm.factory import (
    AI_SECTION,
    KEYED_PROVIDERS,
    SUPPORTED_PROVIDERS,
    build_provider,
    key_fingerprint,
    load_org_credential,
    resolve_llm_config,
)
from src.models.settings import AppSetting
from src.models.user import User
from src.schemas.settings import (
    AISettingsResponse,
    AISettingsUpdate,
    AITenantRow,
    AITenantsResponse,
    AIModelsResponse,
    SettingsResponse,
    SettingsUpdate,
    GeneralSettings,
    SMTPConfig,
    NotificationConfig,
    AlertCorrelationConfig,
)

logger = get_logger(__name__)


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

def _section_is_strict(section: str) -> bool:
    """``ai`` and ``integration:*`` must fail loudly on an unreadable secret (§10)."""
    return section == AI_SECTION or section.startswith("integration:")


def _drop_unreadable_secrets(value: Any) -> Any:
    """Open what can be opened; replace secrets that cannot with ``None``.

    Used only for the non-credential sections (``general``/``smtp``/
    ``notifications``/``security``) so one rotated master key does not blank
    the whole settings page. The affected key reads back as "not set", which
    is the honest answer, and each miss is logged.
    """

    def _walk(node: Any, key: Optional[str]) -> Any:
        if isinstance(node, dict):
            return {k: _walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item, None) for item in node]
        if key is not None and key in SECRET_KEYS and is_enveloped(node):
            try:
                return decrypt_secret_json(node)
            except SecretUnreadable as exc:
                logger.warning("settings_secret_unreadable_dropped", key=key, reason=exc.reason)
                return None
        return node

    return _walk(value, None)


async def _load_section(
    db: AsyncSession, organization_id: Optional[str], section: str
) -> Dict[str, Any]:
    """Return the decrypted stored value for (org, section), or {} if no row exists.

    Every :data:`SECRET_KEYS` member stored as an ``enc:v1:`` envelope is
    opened here. For the ``ai`` / ``integration:*`` sections a
    ``SecretUnreadable`` propagates to the caller (which maps it to
    ``503 secret_unreadable``); elsewhere the unreadable value is dropped.
    """
    stmt = select(AppSetting).where(AppSetting.section == section)
    if organization_id is not None:
        stmt = stmt.where(AppSetting.organization_id == organization_id)
    else:
        stmt = stmt.where(AppSetting.organization_id.is_(None))
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None or not isinstance(row.value, dict):
        return {}
    try:
        opened = open_secret_keys(row.value)
    except SecretUnreadable as exc:
        if _section_is_strict(section):
            logger.error(
                "settings_section_secret_unreadable",
                section=section,
                organization_id=organization_id,
                reason=exc.reason,
            )
            raise
        logger.warning(
            "settings_section_secret_partially_unreadable",
            section=section,
            organization_id=organization_id,
            reason=exc.reason,
        )
        opened = _drop_unreadable_secrets(row.value)
    return opened if isinstance(opened, dict) else {}


async def _upsert_section(
    db: AsyncSession,
    organization_id: Optional[str],
    section: str,
    value: Dict[str, Any],
    updated_by: Optional[str],
) -> Dict[str, Any]:
    """Upsert the stored value, merging with any pre-existing keys.

    The persisted JSON has every :data:`SECRET_KEYS` member wrapped in an
    ``enc:v1:`` envelope; the dict returned to the caller is the plaintext
    merge so response builders can mask it themselves. Enveloping is
    idempotent, so merging a decrypted existing value with new input and
    re-enveloping never nests envelopes.
    """
    existing = await _load_section(db, organization_id, section)
    merged = {**existing, **{k: v for k, v in value.items() if v is not None}}
    stored, secrets_enveloped = envelope_secret_keys(merged)
    if secrets_enveloped:
        logger.info(
            "settings_section_secrets_encrypted",
            section=section,
            organization_id=organization_id,
            count=secrets_enveloped,
        )

    dialect = db.bind.dialect.name if db.bind is not None else "postgresql"

    if dialect == "postgresql":
        stmt = pg_insert(AppSetting.__table__).values(
            organization_id=organization_id,
            section=section,
            value=stored,
            updated_by=updated_by,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_app_settings_org_section",
            set_={
                "value": stored,
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
                    value=stored,
                    updated_by=updated_by,
                )
            )
        else:
            existing_row.value = stored
            existing_row.updated_by = updated_by

    await db.commit()
    return merged


def _user_org(user: User) -> Optional[str]:
    return getattr(user, "organization_id", None)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    # Base status from app_settings env attributes (for the 6 connectors
    # that have corresponding BaseSettings fields).
    integrations: dict = {
        "virustotal": {"enabled": bool(app_settings.virustotal_api_key), "configured": bool(app_settings.virustotal_api_key)},
        "abuseipdb": {"enabled": bool(app_settings.abuseipdb_api_key), "configured": bool(app_settings.abuseipdb_api_key)},
        "shodan": {"enabled": bool(app_settings.shodan_api_key), "configured": bool(app_settings.shodan_api_key)},
        "greynoise": {"enabled": bool(app_settings.greynoise_api_key), "configured": bool(app_settings.greynoise_api_key)},
        "elasticsearch": {"enabled": bool(app_settings.elasticsearch_url), "configured": bool(app_settings.elasticsearch_url)},
        "splunk": {"enabled": bool(app_settings.splunk_host), "configured": bool(app_settings.splunk_host)},
    }
    # Integration keys the UI knows how to render (must match the
    # _INTEGRATION_KEY_ATTR whitelist on the save endpoint). Start
    # every one as unconfigured; the DB merge below flips them on.
    for _k in (
        "slack", "teams", "pagerduty", "opsgenie",
        "jira", "servicenow", "openai", "anthropic",
        "gemini", "ollama",
        "misp", "cortex",
    ):
        integrations.setdefault(_k, {"enabled": False, "configured": False})

    # Merge DB-saved integration sections — scans every `integration:*`
    # row under this org, not just the hardcoded keys. Previously the
    # merge loop only iterated over the 6 pre-seeded keys, so saving
    # an API key for slack/teams/pagerduty/etc. persisted fine but
    # never flipped the UI's Configured indicator.
    #
    # This reads the RAW column on purpose: secret keys are ``enc:v1:``
    # envelopes and we only ever test them for presence. Nothing is
    # decrypted here and no value — enveloped or not — is returned; the
    # response carries only the `enabled`/`configured` booleans.
    # Read through the ORM so the JSON column is deserialized consistently on
    # every dialect. (The previous raw-SQL version got a JSON *string* back on
    # SQLite and silently skipped every row, so Configured never lit up there.)
    stmt = select(AppSetting.section, AppSetting.value).where(
        AppSetting.section.like("integration:%")
    )
    stmt = (
        stmt.where(AppSetting.organization_id == org_id)
        if org_id is not None
        else stmt.where(AppSetting.organization_id.is_(None))
    )
    rows = await db.execute(stmt)
    for section, value in rows.all():
        integ_id = section.split(":", 1)[1] if ":" in section else section
        ovr = value if isinstance(value, dict) else {}
        if not ovr:
            continue
        configured = bool(
            ovr.get("api_key")
            or ovr.get("url")
            or ovr.get("host")
            or ovr.get("token")
            or ovr.get("webhook_url")
        ) or integrations.get(integ_id, {}).get("configured", False)
        integrations[integ_id] = {
            "enabled": bool(ovr.get("enabled", configured)),
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
    # OpenAI / AI providers. `ollama` is keyless and its base URL is a
    # platform setting, so the attribute below is read-only context for the
    # status/probe code — a tenant can never write it (see _reject_tenant_url).
    "openai": "openai_api_key",
    "anthropic": "anthropic_api_key",
    "gemini": "gemini_api_key",
    "ollama": "ollama_base_url",
}

# Fixed provider hosts. Tenants supply keys, never endpoints.
_GEMINI_HOST = "https://generativelanguage.googleapis.com"

# Integrations whose endpoint is fixed by the platform, never by a tenant.
_PLATFORM_URL_ONLY = frozenset({"ollama"})
# Body keys that would let a tenant redirect an outbound call.
_TENANT_URL_KEYS = ("url", "host", "base_url", "api_base", "endpoint")


def _reject_tenant_url(integration_id: str, config: Dict[str, Any]) -> None:
    """400 when a tenant tries to supply a base URL for a platform-pinned provider."""
    if integration_id not in _PLATFORM_URL_ONLY:
        return
    supplied = [k for k in _TENANT_URL_KEYS if config.get(k)]
    if supplied:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "tenant_url_not_allowed",
                "integration": integration_id,
                "keys": supplied,
                "message": (
                    f"{integration_id} is reached at the platform-configured base URL only; "
                    "remove these keys from the request."
                ),
            },
        )


async def _upsert_installed_integration(
    db: AsyncSession,
    *,
    organization_id: Optional[str],
    integration_id: str,
    config: Dict[str, Any],
    enabled: bool,
) -> str:
    """Write the org's ``InstalledIntegration`` row for ``integration_id``.

    The single place credentials reach ``installed_integrations``: the blob is
    written through ``_encrypt_secret_json`` (an ``enc:v1:`` envelope) and the
    public config excludes every secret key. Shared by
    ``POST /settings/integrations/{id}`` and ``PUT /settings/ai`` so an AI
    provider key saved from either screen lands in exactly one place — the
    row ``src.llm.factory.load_org_credential`` reads.

    Returns the installation id. Raises on failure: the AI path must not
    report success when the key was not stored.
    """
    from src.core.secrets import _encrypt_secret_json
    from src.integrations.models import InstalledIntegration

    res = await db.execute(
        select(InstalledIntegration)
        .where(
            InstalledIntegration.connector_id == integration_id,
            InstalledIntegration.organization_id == organization_id,
        )
        .limit(1)
    )
    existing = res.scalars().first()
    credential_keys = ("api_key", "token", "url", "host", "username", "password")
    encrypted_creds = _encrypt_secret_json({k: v for k, v in config.items() if k in credential_keys})
    public_config = {k: v for k, v in config.items() if k not in SECRET_KEYS}
    if existing is None:
        installation = InstalledIntegration(
            organization_id=organization_id,
            connector_id=integration_id,
            display_name=integration_id.replace("_", " ").title(),
            config_encrypted=json.dumps(public_config) if public_config else "{}",
            auth_credentials_encrypted=encrypted_creds,
            status="active" if enabled else "disabled",
            health_status="unknown",
        )
        db.add(installation)
        await db.flush()
        return installation.id
    existing.auth_credentials_encrypted = encrypted_creds
    if public_config:
        existing.config_encrypted = json.dumps(public_config)
    existing.status = "active" if enabled else "disabled"
    await db.flush()
    return existing.id


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

    _reject_tenant_url(integration_id, config)

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
        await _upsert_installed_integration(
            db,
            organization_id=org_id,
            integration_id=integration_id,
            config=config,
            enabled=enabled,
        )
    except (SecretUnreadable, SQLAlchemyError) as exc:
        # Bridge failure is non-fatal for the marketplace mirror — the
        # Settings save already succeeded. ``PUT /settings/ai`` calls the
        # same helper WITHOUT this guard, because there the row IS the
        # credential store and a failure must not report success.
        logger.warning(
            "settings_installed_integration_bridge_failed",
            integration_id=integration_id,
            organization_id=org_id,
            error=type(exc).__name__,
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
    # Valid-set must match the save whitelist — adding new integrations
    # here required matching entries in _INTEGRATION_KEY_ATTR. Previously
    # this list had only the 6 enrichers so clicking Test on Slack/
    # Teams/PagerDuty/Jira gave "Unknown integration".
    valid_integrations = {
        "virustotal", "abuseipdb", "shodan", "greynoise",
        "elasticsearch", "splunk",
        "slack", "teams", "pagerduty", "opsgenie",
        "jira", "servicenow", "openai", "anthropic",
        "gemini", "ollama",
        "misp", "cortex",
    }

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

    # Webhook / notification channels — Slack and Teams use an
    # incoming webhook URL, PagerDuty/OpsGenie use an API token.
    slack_webhook = _pick(["webhook_url", "url"], app_settings.slack_webhook_url or "")
    teams_webhook = _pick(["webhook_url", "url"], app_settings.teams_webhook_url or "")
    pagerduty_key = _pick(["api_key", "token"])
    opsgenie_key = _pick(["api_key", "token"])
    # Ticketing
    jira_url = _pick(["url", "host"])
    jira_key = _pick(["api_key", "token", "password"])
    jira_user = _pick(["username", "email"])
    servicenow_url = _pick(["url", "host"])
    servicenow_user = _pick(["username"])
    servicenow_pw = _pick(["password", "api_key"])
    # AI providers. Gemini is a keyed hosted provider on a fixed host;
    # ollama is keyless and reachable only at the PLATFORM base URL — a
    # tenant-saved url/host is never consulted for it.
    openai_key = _pick(["api_key", "token"])
    anthropic_key = _pick(["api_key", "token"])
    gemini_key = _pick(["api_key", "token"], app_settings.gemini_api_key or "")
    ollama_base_url = (app_settings.ollama_base_url or "").rstrip("/")
    # Analysis
    misp_url = _pick(["url", "host"])
    misp_key = _pick(["api_key", "token"])
    cortex_url = _pick(["url", "host"])
    cortex_key = _pick(["api_key", "token"])

    primary_map = {
        "virustotal": vt_key,
        "abuseipdb": abuse_key,
        "shodan": shodan_key,
        "greynoise": greynoise_key,
        "elasticsearch": es_url,
        "splunk": splunk_host,
        "slack": slack_webhook,
        "teams": teams_webhook,
        "pagerduty": pagerduty_key,
        "opsgenie": opsgenie_key,
        "jira": jira_url,
        "servicenow": servicenow_url,
        "openai": openai_key,
        "anthropic": anthropic_key,
        "gemini": gemini_key,
        "ollama": ollama_base_url,
        "misp": misp_url,
        "cortex": cortex_url,
    }

    if not primary_map.get(integration_name):
        raise HTTPException(
            status_code=400,
            detail=f"Integration {integration_name} is not configured"
        )

    import httpx

    # --- Webhook-style tests — POST a real probe payload to the saved
    #     webhook URL. If the webhook is valid, Slack/Teams accept it
    #     and return 200. If it's wrong, they return 403/404/400 and
    #     the test surfaces the real failure to the operator.
    async def _probe_slack() -> dict:
        # Guard against the common mistake of pasting the Slack
        # client/browser URL (https://app.slack.com/client/...) or a
        # channel deep-link. Neither accepts webhook POSTs. The real
        # incoming webhook lives at https://hooks.slack.com/services/...
        if not slack_webhook.startswith("https://hooks.slack.com/"):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Slack URL is not an incoming webhook. Real webhooks "
                    "start with 'https://hooks.slack.com/services/'. "
                    "Create one at api.slack.com/apps → Incoming Webhooks "
                    "→ Add New Webhook to Workspace."
                ),
            )
        payload = {
            "text": "PySOAR connection test — if you see this, Slack integration is working.",
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(slack_webhook, json=payload)
            if resp.status_code < 400 and (resp.text or "").strip().lower() in ("ok", ""):
                return {"message": "Test message delivered to Slack", "status": "healthy", "http_status": resp.status_code}
            # Slack's common rejection bodies are `no_team`,
            # `invalid_token`, `no_service` — surface them verbatim so
            # the operator knows exactly what's wrong.
            body = (resp.text or "").strip()
            raise HTTPException(status_code=502, detail=f"Slack returned HTTP {resp.status_code}: {body[:200] or 'no body'}")

    async def _probe_teams() -> dict:
        if not (teams_webhook.startswith("https://") and (".webhook.office.com" in teams_webhook or ".logic.azure.com" in teams_webhook)):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Teams URL is not a Microsoft Teams incoming webhook. "
                    "Expected https://<tenant>.webhook.office.com/webhookb2/... "
                    "(get one from the Teams channel → Connectors → Incoming Webhook)."
                ),
            )
        payload = {
            "@type": "MessageCard",
            "text": "PySOAR connection test — if you see this, Teams integration is working.",
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(teams_webhook, json=payload)
            if resp.status_code < 400:
                return {"message": "Test message delivered to Teams", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"Teams returned HTTP {resp.status_code}: {resp.text[:200]}")

    async def _probe_pagerduty() -> dict:
        async with httpx.AsyncClient(timeout=10.0, headers={"Authorization": f"Token token={pagerduty_key}", "Accept": "application/vnd.pagerduty+json;version=2"}) as client:
            resp = await client.get("https://api.pagerduty.com/abilities")
            if resp.status_code < 400:
                return {"message": "PagerDuty API token valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"PagerDuty returned HTTP {resp.status_code}")

    async def _probe_opsgenie() -> dict:
        async with httpx.AsyncClient(timeout=10.0, headers={"Authorization": f"GenieKey {opsgenie_key}"}) as client:
            resp = await client.get("https://api.opsgenie.com/v2/account")
            if resp.status_code < 400:
                return {"message": "OpsGenie API token valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"OpsGenie returned HTTP {resp.status_code}")

    async def _probe_jira() -> dict:
        if not jira_url:
            raise HTTPException(status_code=400, detail="Jira URL is not configured")
        auth = (jira_user, jira_key) if jira_user else None
        headers_j = {"Accept": "application/json"}
        if not auth and jira_key:
            headers_j["Authorization"] = f"Bearer {jira_key}"
        async with httpx.AsyncClient(timeout=10.0, headers=headers_j, auth=auth) as client:
            resp = await client.get(f"{jira_url.rstrip('/')}/rest/api/3/myself")
            if resp.status_code < 400:
                return {"message": "Jira credentials valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"Jira returned HTTP {resp.status_code}")

    async def _probe_servicenow() -> dict:
        if not servicenow_url or not servicenow_user:
            raise HTTPException(status_code=400, detail="ServiceNow requires url + username + password")
        async with httpx.AsyncClient(timeout=10.0, auth=(servicenow_user, servicenow_pw)) as client:
            resp = await client.get(f"{servicenow_url.rstrip('/')}/api/now/table/sys_user?sysparm_limit=1")
            if resp.status_code < 400:
                return {"message": "ServiceNow credentials valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"ServiceNow returned HTTP {resp.status_code}")

    async def _probe_openai() -> dict:
        async with httpx.AsyncClient(timeout=10.0, headers={"Authorization": f"Bearer {openai_key}"}) as client:
            resp = await client.get("https://api.openai.com/v1/models")
            if resp.status_code < 400:
                return {"message": "OpenAI API key valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"OpenAI returned HTTP {resp.status_code}")

    async def _probe_anthropic() -> dict:
        # Anthropic has no cheap auth-check; a minimal messages POST
        # with an invalid model name returns 400 auth-valid if the key
        # is good, 401 if not. Send a 1-token real request to /models.
        async with httpx.AsyncClient(timeout=10.0, headers={"x-api-key": anthropic_key, "anthropic-version": "2023-06-01"}) as client:
            resp = await client.get("https://api.anthropic.com/v1/models")
            if resp.status_code < 400:
                return {"message": "Anthropic API key valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"Anthropic returned HTTP {resp.status_code}")

    async def _probe_gemini() -> dict:
        # Fixed host; the key is only ever sent to Google's own endpoint.
        async with httpx.AsyncClient(
            timeout=10.0,
            headers={"x-goog-api-key": gemini_key, "Accept": "application/json"},
        ) as client:
            resp = await client.get(f"{_GEMINI_HOST}/v1beta/models")
            if resp.status_code < 400:
                count = len((resp.json() or {}).get("models") or [])
                return {
                    "message": f"Gemini API key valid ({count} models visible)",
                    "status": "healthy",
                    "http_status": resp.status_code,
                }
            raise HTTPException(status_code=502, detail=f"Gemini returned HTTP {resp.status_code}")

    async def _probe_ollama() -> dict:
        # Platform base URL only — tenants cannot point this anywhere.
        if not ollama_base_url:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "platform_url_not_configured",
                    "message": "ollama_base_url is not set in platform settings",
                },
            )
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{ollama_base_url}/api/tags")
            if resp.status_code < 400:
                count = len((resp.json() or {}).get("models") or [])
                return {
                    "message": f"Ollama reachable ({count} local models)",
                    "status": "healthy",
                    "http_status": resp.status_code,
                }
            raise HTTPException(status_code=502, detail=f"Ollama returned HTTP {resp.status_code}")

    async def _probe_misp() -> dict:
        async with httpx.AsyncClient(timeout=10.0, headers={"Authorization": misp_key, "Accept": "application/json"}) as client:
            resp = await client.get(f"{misp_url.rstrip('/')}/users/view/me.json")
            if resp.status_code < 400:
                return {"message": "MISP credentials valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"MISP returned HTTP {resp.status_code}")

    async def _probe_cortex() -> dict:
        async with httpx.AsyncClient(timeout=10.0, headers={"Authorization": f"Bearer {cortex_key}"}) as client:
            resp = await client.get(f"{cortex_url.rstrip('/')}/api/analyzer")
            if resp.status_code < 400:
                return {"message": "Cortex credentials valid", "status": "healthy", "http_status": resp.status_code}
            raise HTTPException(status_code=502, detail=f"Cortex returned HTTP {resp.status_code}")

    _custom_probes = {
        "slack": _probe_slack,
        "teams": _probe_teams,
        "pagerduty": _probe_pagerduty,
        "opsgenie": _probe_opsgenie,
        "jira": _probe_jira,
        "servicenow": _probe_servicenow,
        "openai": _probe_openai,
        "anthropic": _probe_anthropic,
        "gemini": _probe_gemini,
        "ollama": _probe_ollama,
        "misp": _probe_misp,
        "cortex": _probe_cortex,
    }
    if integration_name in _custom_probes:
        return await _custom_probes[integration_name]()

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
        async with httpx.AsyncClient(timeout=10.0) as client:
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


# ---------------------------------------------------------------------------
# AI provider settings (design v2 section 9)
#
# GET/PUT /settings/ai          -- admin; the org's provider/model/key status
# GET     /settings/ai/models   -- admin; live list_models() for a provider
# GET     /settings/ai/tenants  -- superuser; one row per organization
#
# Three rules hold throughout:
#   1. the API key is never returned, logged or echoed -- only its fingerprint;
#   2. every query is scoped to the caller's organization (the tenants route
#      is the one deliberate cross-org read, gated on superuser);
#   3. provider hosts are fixed. A tenant-supplied base URL is a 400.
# ---------------------------------------------------------------------------

#: Model-list calls get a hard ceiling so a hung provider cannot pin a worker.
_MODEL_LIST_TIMEOUT_SECONDS = 10.0


class _AIErrorResponse(Exception):
    """Internal: carry an exact error body out to the endpoint boundary.

    The AI contract specifies bodies like ``{"error": "unknown_model",
    "available": [...]}`` at the top level, which ``HTTPException`` would nest
    under ``detail``. Each AI endpoint catches this and returns a
    ``JSONResponse`` with the payload verbatim.
    """

    def __init__(self, status_code: int, payload: Dict[str, Any]) -> None:
        self.status_code = status_code
        self.payload = payload
        super().__init__(str(payload.get("error", "ai_error")))


def _require_org(current_user: User) -> str:
    org_id = _user_org(current_user)
    if not org_id:
        raise _AIErrorResponse(
            400,
            {
                "error": "no_organization",
                "message": "AI provider settings are per-organization; this account has none.",
            },
        )
    return str(org_id)


def _platform_api_key(provider: str) -> Optional[str]:
    """The platform key for ``provider`` from env-backed settings (never a tenant value)."""
    if provider not in KEYED_PROVIDERS:
        return None
    key = getattr(app_settings, f"{provider}_api_key", None)
    return str(key) if key else None


async def last_successful_llm_call_at(db: AsyncSession, org_id: str) -> Optional[str]:
    """``created_at`` of the org's newest non-error ``llm_call_logs`` row.

    Returns ``None`` when the table does not exist yet (migration 020 not
    applied) or the org has never made a successful call. Org-scoped.
    """
    try:
        if not await db.run_sync(_has_llm_call_logs):
            return None
        from src.llm.models import LLMCallLog

        stmt = select(func.max(LLMCallLog.created_at)).where(
            LLMCallLog.organization_id == org_id,
            LLMCallLog.stop_reason.is_not(None),
            LLMCallLog.stop_reason != "error",
        )
        newest = (await db.execute(stmt)).scalar_one_or_none()
    except SQLAlchemyError as exc:
        logger.warning(
            "llm_last_call_lookup_failed", organization_id=org_id, error=type(exc).__name__
        )
        return None
    return newest.isoformat() if isinstance(newest, datetime) else None


def _has_llm_call_logs(sync_session: Any) -> bool:
    """True when migration 020 has created ``llm_call_logs`` in this database."""
    from sqlalchemy import inspect as sa_inspect

    return bool(sa_inspect(sync_session.get_bind()).has_table("llm_call_logs"))


def _model_matches(model: str, available: List[str]) -> bool:
    """True when ``model`` names one of ``available``.

    Exact match first. Providers also publish dated ids while operators
    configure aliases (``claude-opus-4-0`` against ``claude-opus-4-20250514``),
    so a prefix relationship in either direction counts as a match. Anything
    else is an unknown model.
    """
    wanted = model.strip().lower()
    for candidate in available:
        known = str(candidate).strip().lower()
        if not known:
            continue
        if wanted == known or known.startswith(wanted) or wanted.startswith(known):
            return True
    return False


async def _list_models(
    provider: str, model: str, api_key: Optional[str], source: str
) -> List[str]:
    """``build_provider(...).list_models()`` on a fixed host, with a 10s ceiling.

    Translates provider failures into the AI contract's error bodies. The key
    is passed straight to the provider and never logged.
    """
    instance = build_provider(
        provider,  # type: ignore[arg-type]
        model=model,
        api_key=api_key,
        credential_source="org" if source == "org" else "platform",
    )
    try:
        async with asyncio.timeout(_MODEL_LIST_TIMEOUT_SECONDS):
            async with instance as entered:
                return [str(m) for m in await entered.list_models()]
    except TimeoutError as exc:
        raise _AIErrorResponse(
            504,
            {
                "error": "provider_timeout",
                "provider": provider,
                "timeout_seconds": _MODEL_LIST_TIMEOUT_SECONDS,
            },
        ) from exc
    except LLMAuthError as exc:
        logger.warning("ai_settings_invalid_credentials", provider=provider, source=source)
        raise _AIErrorResponse(400, {"error": "invalid_credentials", "provider": provider}) from exc
    except LLMNotConfigured as exc:
        raise _AIErrorResponse(
            503,
            {
                "error": "llm_not_configured",
                "provider": provider,
                "reason": getattr(exc, "reason", "not_configured"),
            },
        ) from exc
    except LLMError as exc:
        logger.warning(
            "ai_settings_provider_unavailable", provider=provider, error=type(exc).__name__
        )
        raise _AIErrorResponse(
            502,
            {
                "error": "provider_unavailable",
                "provider": provider,
                "error_class": type(exc).__name__,
            },
        ) from exc


async def _ai_credential_for_listing(
    db: AsyncSession, org_id: str, provider: str, *, use_platform_default: bool
) -> tuple[Optional[str], str]:
    """``(api_key, source)`` for a model-list call. Raises when nothing is configured."""
    if provider not in KEYED_PROVIDERS:
        # ollama: keyless, reached at the platform base URL.
        return None, "platform"
    if not use_platform_default:
        try:
            return await load_org_credential(db, org_id, provider), "org"
        except LLMNotConfigured as exc:
            reason = getattr(exc, "reason", "missing_credential")
            if reason == "secret_unreadable":
                raise _AIErrorResponse(
                    503, {"error": "secret_unreadable", "provider": provider}
                ) from exc
            platform_key = _platform_api_key(provider)
            if platform_key:
                return platform_key, "platform"
            raise _AIErrorResponse(
                503, {"error": "llm_not_configured", "provider": provider, "reason": reason}
            ) from exc
    platform_key = _platform_api_key(provider)
    if not platform_key:
        raise _AIErrorResponse(
            503,
            {"error": "llm_not_configured", "provider": provider, "reason": "missing_credential"},
        )
    return platform_key, "platform"


async def _build_ai_settings(db: AsyncSession, org_id: str) -> AISettingsResponse:
    """Assemble ``GET /settings/ai`` for one organization."""
    try:
        section = await _load_section(db, org_id, AI_SECTION)
    except SecretUnreadable as exc:
        raise _AIErrorResponse(503, {"error": "secret_unreadable", "reason": exc.reason}) from exc

    use_platform_default = bool(section.get("use_platform_default", False))
    provider = section.get("provider")
    model = section.get("model")

    configured = False
    source = "none"
    reason: Optional[str] = None
    fingerprint: Optional[str] = None
    try:
        resolved, _api_key = await resolve_llm_config(db, org_id)
        configured = True
        source = resolved.credential_source
        provider = provider or resolved.provider
        model = model or resolved.model
        fingerprint = resolved.key_fingerprint
    except LLMNotConfigured as exc:
        reason = getattr(exc, "reason", "ai_not_configured")
        if reason == "secret_unreadable":
            raise _AIErrorResponse(503, {"error": "secret_unreadable", "reason": reason}) from exc

    capabilities = section.get("capabilities")
    return AISettingsResponse(
        provider=provider if provider in SUPPORTED_PROVIDERS else None,
        model=model,
        use_platform_default=use_platform_default,
        configured=configured,
        source=source,  # type: ignore[arg-type]
        reason=reason,
        key_fingerprint=fingerprint,
        rotated_at=section.get("rotated_at"),
        last_successful_call_at=await last_successful_llm_call_at(db, org_id),
        capabilities=capabilities if isinstance(capabilities, dict) else None,
    )


@router.get("/ai", response_model=None)
async def get_ai_settings(
    db: DatabaseSession = None,
    current_user: AdminUser = None,
) -> Any:
    """The organization's AI provider configuration (admin). Never returns the key."""
    try:
        org_id = _require_org(current_user)
        return await _build_ai_settings(db, org_id)
    except _AIErrorResponse as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.payload)


@router.put("/ai", response_model=None)
async def update_ai_settings(
    payload: AISettingsUpdate,
    db: DatabaseSession = None,
    current_user: AdminUser = None,
) -> Any:
    """Set the organization's AI provider/model (admin), validating both live.

    Order of operations: the model is validated against the provider's own
    model list *before* anything is persisted, so an invalid key or a mistyped
    model never becomes stored state. Then the key (if supplied) is written
    encrypted to the org's ``InstalledIntegration`` row through the same
    helper the integrations screen uses, the ``ai`` section is upserted, and
    two audit rows are written (``ai.provider.set``, plus ``ai.key.rotated``
    when a key was supplied) carrying the fingerprint only.
    """
    try:
        org_id = _require_org(current_user)
        uid = str(getattr(current_user, "id", "") or "")
        provider = payload.provider
        model = payload.model.strip()

        url_keys = payload.supplied_url_keys()
        if url_keys:
            raise _AIErrorResponse(
                400,
                {
                    "error": "tenant_url_not_allowed",
                    "keys": url_keys,
                    "message": (
                        "Provider endpoints are platform-configured; a tenant "
                        "cannot supply a base URL."
                    ),
                },
            )

        api_key = payload.api_key.strip() if payload.api_key else None
        if api_key and provider not in KEYED_PROVIDERS:
            raise _AIErrorResponse(
                400,
                {
                    "error": "provider_takes_no_api_key",
                    "provider": provider,
                    "message": f"{provider} is reached without credentials; omit api_key.",
                },
            )

        try:
            prior = await _load_section(db, org_id, AI_SECTION)
        except SecretUnreadable as exc:
            raise _AIErrorResponse(
                503, {"error": "secret_unreadable", "reason": exc.reason}
            ) from exc

        # Which credential validates the model?
        if api_key:
            validate_key, validate_source = api_key, "org"
        else:
            validate_key, validate_source = await _ai_credential_for_listing(
                db, org_id, provider, use_platform_default=payload.use_platform_default
            )
        if provider in KEYED_PROVIDERS and not validate_key:
            raise _AIErrorResponse(
                400,
                {
                    "error": "api_key_required",
                    "provider": provider,
                    "message": (
                        f"No stored {provider} credential for this organization; supply api_key."
                    ),
                },
            )

        available = await _list_models(provider, model, validate_key, validate_source)
        if not _model_matches(model, available):
            raise _AIErrorResponse(
                422,
                {
                    "error": "unknown_model",
                    "provider": provider,
                    "model": model,
                    "available": available,
                },
            )

        now = _utc_now_iso()
        fingerprint: Optional[str] = None
        if api_key:
            fingerprint = key_fingerprint(api_key)
            await _upsert_installed_integration(
                db,
                organization_id=org_id,
                integration_id=provider,
                config={"api_key": api_key, "enabled": True},
                enabled=True,
            )
            # Mirror into the Settings integration section so the
            # integrations page shows the provider as configured. The value
            # is enveloped by _upsert_section before it touches the DB.
            await _upsert_section(
                db,
                org_id,
                f"integration:{provider}",
                {"api_key": api_key, "enabled": True},
                uid or None,
            )

        section_value: Dict[str, Any] = {
            "provider": provider,
            "model": model,
            "use_platform_default": payload.use_platform_default,
            "capabilities": {"models_seen_at": now, "model_count": len(available)},
        }
        if api_key:
            section_value["rotated_at"] = now
        # ``use_platform_default`` stays writable back to False because the
        # None-stripping merge in _upsert_section keeps False.
        await _upsert_section(db, org_id, AI_SECTION, section_value, uid or None)

        audit = AuditLogger(db, org_id)
        await audit.log_event(
            event_type="change",
            action="ai.provider.set",
            actor_type="user",
            actor_id=uid or "unknown",
            resource_type="app_settings",
            resource_id=f"{AI_SECTION}:{org_id}",
            description=f"AI provider set to {provider}/{model}",
            old_value={
                "provider": prior.get("provider"),
                "model": prior.get("model"),
                "use_platform_default": bool(prior.get("use_platform_default", False)),
            },
            new_value={
                "provider": provider,
                "model": model,
                "use_platform_default": payload.use_platform_default,
                "model_count": len(available),
            },
            risk_level="medium",
        )
        if fingerprint:
            await audit.log_event(
                event_type="change",
                action="ai.key.rotated",
                actor_type="user",
                actor_id=uid or "unknown",
                resource_type="installed_integration",
                resource_id=f"{provider}:{org_id}",
                description=f"{provider} API key stored/rotated",
                new_value={"provider": provider, "key_fingerprint": fingerprint},
                risk_level="medium",
            )
        await db.commit()

        logger.info(
            "ai_settings_updated",
            organization_id=org_id,
            provider=provider,
            model=model,
            use_platform_default=payload.use_platform_default,
            key_rotated=bool(fingerprint),
            key_fingerprint=fingerprint,
            model_count=len(available),
        )
        return await _build_ai_settings(db, org_id)
    except _AIErrorResponse as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.payload)


@router.get("/ai/models", response_model=None)
async def list_ai_models(
    provider: Optional[str] = Query(default=None, description="anthropic|gemini|openai|ollama"),
    db: DatabaseSession = None,
    current_user: AdminUser = None,
) -> Any:
    """Live model list for a provider using this org's credential (admin).

    503 ``llm_not_configured`` when neither an org credential nor a platform
    default exists for the provider.
    """
    try:
        org_id = _require_org(current_user)
        try:
            section = await _load_section(db, org_id, AI_SECTION)
        except SecretUnreadable as exc:
            raise _AIErrorResponse(
                503, {"error": "secret_unreadable", "reason": exc.reason}
            ) from exc

        name = (provider or section.get("provider") or app_settings.llm_provider or "").strip()
        if name not in SUPPORTED_PROVIDERS:
            raise _AIErrorResponse(
                422,
                {
                    "error": "unknown_provider",
                    "provider": name or None,
                    "supported": list(SUPPORTED_PROVIDERS),
                },
            )
        use_platform_default = bool(section.get("use_platform_default", False))
        api_key, source = await _ai_credential_for_listing(
            db, org_id, name, use_platform_default=use_platform_default
        )
        # The model only selects a client here; list_models ignores it.
        probe_model = str(section.get("model") or app_settings.llm_model or name)
        models = await _list_models(name, probe_model, api_key, source)
        return AIModelsResponse(
            provider=name,  # type: ignore[arg-type]
            source=source,  # type: ignore[arg-type]
            models=models,
            fetched_at=_utc_now_iso(),
        )
    except _AIErrorResponse as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.payload)


@router.get("/ai/tenants", response_model=AITenantsResponse)
async def list_ai_tenants(
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
) -> AITenantsResponse:
    """One row per organization with an ``ai`` section (superuser, cross-org).

    Deliberately reads no credentials: ``source`` is derived from
    ``use_platform_default`` plus the existence of an ``InstalledIntegration``
    row, so nothing is decrypted and no key material is touched.
    """
    from src.integrations.models import InstalledIntegration
    from src.llm.models import LLMCallLog

    rows = (
        await db.execute(
            select(AppSetting.organization_id, AppSetting.value).where(
                AppSetting.section == AI_SECTION,
                AppSetting.organization_id.is_not(None),
            )
        )
    ).all()

    installs = {
        (str(org), str(connector))
        for org, connector in (
            await db.execute(
                select(
                    InstalledIntegration.organization_id, InstalledIntegration.connector_id
                )
            )
        ).all()
    }

    last_calls: Dict[str, Any] = {}
    try:
        if await db.run_sync(_has_llm_call_logs):
            for org, newest in (
                await db.execute(
                    select(LLMCallLog.organization_id, func.max(LLMCallLog.created_at))
                    .where(
                        LLMCallLog.stop_reason.is_not(None),
                        LLMCallLog.stop_reason != "error",
                    )
                    .group_by(LLMCallLog.organization_id)
                )
            ).all():
                last_calls[str(org)] = newest
    except SQLAlchemyError as exc:
        logger.warning("ai_tenants_last_call_lookup_failed", error=type(exc).__name__)

    tenants: List[AITenantRow] = []
    for org_id, value in rows:
        cfg = value if isinstance(value, dict) else {}
        provider = cfg.get("provider")
        if bool(cfg.get("use_platform_default", False)):
            source = "platform"
        elif provider and provider not in KEYED_PROVIDERS:
            # ollama / keyless: the platform base URL is the credential.
            source = "platform"
        elif provider and (str(org_id), str(provider)) in installs:
            source = "org"
        else:
            source = "none"
        newest = last_calls.get(str(org_id))
        tenants.append(
            AITenantRow(
                organization_id=str(org_id),
                provider=provider,
                model=cfg.get("model"),
                source=source,  # type: ignore[arg-type]
                last_successful_call_at=(
                    newest.isoformat() if isinstance(newest, datetime) else None
                ),
            )
        )

    tenants.sort(key=lambda row: row.organization_id)
    return AITenantsResponse(tenants=tenants, count=len(tenants))
