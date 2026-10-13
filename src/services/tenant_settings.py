"""Per-organisation runtime settings, read where they are consumed (wave 1).

The Settings page persists each tenant's values in ``app_settings`` keyed by
``(organization_id, section)``. Before wave 1 the PATCH handlers also wrote
them into the process-wide ``src.core.config.settings`` object, so one
tenant's SMTP relay, Slack webhook or session timeout silently became every
tenant's. The handlers no longer do that; consumers call the helpers here with
the organisation the work belongs to.

Fallback rule: a tenant with no stored value gets the platform default from
the environment (``src.core.config.settings``), never another tenant's value.
Slack / Teams webhooks have no platform fallback on the tenant path: an
organisation that configured none is not notified on someone else's channel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings as platform_settings
from src.core.logging import get_logger
from src.core.secrets import SECRET_KEYS, SecretUnreadable, decrypt_secret_json, is_enveloped
from src.models.settings import AppSetting

logger = get_logger(__name__)

#: Bounds for a stored session timeout; anything outside is ignored (logged).
SESSION_TIMEOUT_MIN_MINUTES = 5
SESSION_TIMEOUT_MAX_MINUTES = 24 * 60


def _open_value(value: Any, *, section: str, organization_id: str) -> dict[str, Any]:
    """Decrypt every ``enc:v1:`` secret; an unreadable one reads as unset."""
    if not isinstance(value, dict):
        return {}
    opened: dict[str, Any] = {}
    for key, item in value.items():
        if key in SECRET_KEYS and is_enveloped(item):
            try:
                opened[key] = decrypt_secret_json(item)
            except SecretUnreadable as exc:
                logger.warning(
                    "tenant_setting_secret_unreadable",
                    section=section,
                    organization_id=organization_id,
                    key=key,
                    reason=exc.reason,
                )
                opened[key] = None
        else:
            opened[key] = item
    return opened


async def load_tenant_section(
    db: AsyncSession, organization_id: Optional[str], section: str,
) -> dict[str, Any]:
    """The organisation's stored ``section`` with secrets opened, or ``{}``.

    ``organization_id`` None returns ``{}``: there is no tenant to read for,
    and the NULL-organisation rows are never used as a cross-tenant default.
    """
    if not organization_id:
        return {}
    row = (
        await db.execute(
            select(AppSetting.value).where(
                AppSetting.section == section,
                AppSetting.organization_id == organization_id,
            ),
        )
    ).scalar_one_or_none()
    return _open_value(row, section=section, organization_id=organization_id)


@dataclass(frozen=True)
class SMTPSettings:
    """Resolved SMTP configuration for one organisation."""

    host: str
    port: int
    username: Optional[str]
    password: Optional[str]
    from_address: str
    use_tls: bool
    source: str  # "organization" or "platform"


async def smtp_settings_for(db: AsyncSession, organization_id: Optional[str]) -> SMTPSettings:
    """SMTP for ``organization_id``: the tenant's stored section, else the platform env."""
    stored = await load_tenant_section(db, organization_id, "smtp")
    if stored.get("host") or stored.get("username"):
        return SMTPSettings(
            host=str(stored.get("host") or platform_settings.smtp_host),
            port=int(stored.get("port") or platform_settings.smtp_port),
            username=stored.get("username"),
            password=stored.get("password"),
            from_address=str(stored.get("from_address") or platform_settings.smtp_from),
            use_tls=bool(stored.get("use_tls", platform_settings.smtp_tls)),
            source="organization",
        )
    return SMTPSettings(
        host=platform_settings.smtp_host,
        port=int(platform_settings.smtp_port),
        username=platform_settings.smtp_user,
        password=platform_settings.smtp_password,
        from_address=platform_settings.smtp_from,
        use_tls=bool(platform_settings.smtp_tls),
        source="platform",
    )


async def notification_webhook_for(
    db: AsyncSession, organization_id: Optional[str], channel: str,
) -> Optional[str]:
    """The organisation's Slack / Teams incoming webhook, or None.

    Reads ``integration:<channel>`` (Settings > Integrations) first, then the
    ``notifications`` section (Settings > Notifications). No platform fallback.
    """
    if channel not in ("slack", "teams"):
        raise ValueError(f"unsupported notification channel: {channel}")
    integration = await load_tenant_section(db, organization_id, f"integration:{channel}")
    url = integration.get("webhook_url") or integration.get("url")
    if url:
        return str(url)
    notifications = await load_tenant_section(db, organization_id, "notifications")
    url = notifications.get(f"{channel}_webhook_url")
    return str(url) if url else None


async def session_timeout_minutes_for(db: AsyncSession, organization_id: Optional[str]) -> int:
    """Access-token lifetime for users of ``organization_id``.

    The Security tab (``security`` section) wins over the General tab
    (``general`` section); with neither, the platform default applies.
    """
    default = int(platform_settings.access_token_expire_minutes)
    if not organization_id:
        return default
    try:
        for section in ("security", "general"):
            stored = (await load_tenant_section(db, organization_id, section)).get("session_timeout_minutes")
            if stored is None:
                continue
            try:
                minutes = int(stored)
            except (TypeError, ValueError):
                logger.warning("tenant_session_timeout_invalid", organization_id=organization_id, section=section)
                continue
            if SESSION_TIMEOUT_MIN_MINUTES <= minutes <= SESSION_TIMEOUT_MAX_MINUTES:
                return minutes
            logger.warning(
                "tenant_session_timeout_out_of_range",
                organization_id=organization_id,
                section=section,
                minutes=minutes,
            )
    except SQLAlchemyError as exc:
        logger.warning(
            "tenant_session_timeout_lookup_failed",
            organization_id=organization_id,
            error_class=exc.__class__.__name__,
        )
    return default
