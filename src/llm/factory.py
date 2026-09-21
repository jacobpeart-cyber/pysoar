"""Org-authoritative provider resolution (design section 6, *Factory*).

Resolution order for ``resolve_llm(db, org_id)``:

1. The organization's ``ai`` settings section (``app_settings`` row with
   ``organization_id == org_id`` and ``section == "ai"``). When it exists it
   is **authoritative**:

   * ``use_platform_default`` (default ``false``) ``true`` -> step 3;
   * otherwise ``provider``/``model`` come from the section and credentials
     come ONLY from that org's ``InstalledIntegration`` row whose
     ``connector_id`` equals the provider name (``anthropic`` / ``gemini`` /
     ``openai``). A missing row, an empty key or an unreadable envelope is
     ``LLMNotConfigured`` with ``source == "org"``; there is never an env
     fallback for such an org.

2. No org section: the global default section (``organization_id IS NULL``)
   may carry ``use_platform_default: true`` (set by a superuser). If it does
   not, the org is ``LLMNotConfigured`` with ``reason == "ai_not_configured"``.

3. Platform env: ``settings.llm_provider`` / ``settings.llm_model`` and the
   matching ``settings.<provider>_api_key``; ``credential_source == "platform"``.

Hosted providers always use their fixed hosts (tenants supply keys only).
``ollama`` / OpenAI-compatible base URLs are platform env only and are never
read from tenant settings. ``ollama`` needs no key, so its rows carry
``credential_source == "platform"`` even when an org section selected it.

``LLMNotConfigured`` instances raised here carry two extra attributes used by
the endpoints: ``source`` (``"org"`` / ``"platform"``) and ``reason``
(``missing_credential`` / ``secret_unreadable`` / ``provider_not_set`` /
``model_not_set`` / ``unknown_provider`` / ``ai_not_configured``).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import Settings, settings as app_settings
from src.core.logging import get_logger
from src.core.secrets import SecretUnreadable, decrypt_secret_json
from src.integrations.models import InstalledIntegration
from src.llm.base import LLMNotConfigured, LLMProvider
from src.models.settings import AppSetting

logger = get_logger(__name__)

AI_SECTION = "ai"
ProviderName = Literal["anthropic", "gemini", "openai", "ollama"]
SUPPORTED_PROVIDERS: tuple[ProviderName, ...] = ("anthropic", "gemini", "openai", "ollama")
KEYED_PROVIDERS: frozenset[str] = frozenset({"anthropic", "gemini", "openai"})

# Keys accepted inside the decrypted InstalledIntegration credential blob.
_CREDENTIAL_KEYS: tuple[str, ...] = ("api_key", "token")


def not_configured(message: str, *, source: Literal["org", "platform"], reason: str) -> LLMNotConfigured:
    """Build ``LLMNotConfigured`` with the ``source``/``reason`` attributes set."""
    err = LLMNotConfigured(message)
    err.source = source  # type: ignore[attr-defined]
    err.reason = reason  # type: ignore[attr-defined]
    return err


@dataclass(frozen=True)
class ResolvedConfig:
    """What the factory decided before instantiating a provider (no secrets)."""

    provider: ProviderName
    model: str
    credential_source: Literal["org", "platform"]
    key_fingerprint: Optional[str]  # sha256 prefix + last4, never the key


def _validate_provider(raw: Any, *, source: Literal["org", "platform"]) -> ProviderName:
    if not raw:
        raise not_configured(f"{source} ai settings do not name a provider", source=source, reason="provider_not_set")
    if raw not in SUPPORTED_PROVIDERS:
        raise not_configured(f"unsupported llm provider {raw!r}", source=source, reason="unknown_provider")
    return raw  # type: ignore[return-value]


def _validate_model(raw: Any, *, source: Literal["org", "platform"]) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise not_configured(f"{source} ai settings do not name a model", source=source, reason="model_not_set")
    return raw.strip()


def key_fingerprint(api_key: str) -> str:
    """``sha256[:12]:last4`` -- safe to show in settings UI and logs."""
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    return f"{digest[:12]}:{api_key[-4:]}" if len(api_key) >= 8 else digest[:12]


async def load_ai_section(db: AsyncSession, org_id: Optional[str]) -> Optional[dict[str, Any]]:
    """The ``ai`` section for ``org_id`` (``None`` = global default), or ``None`` when absent."""
    stmt = select(AppSetting).where(AppSetting.section == AI_SECTION)
    if org_id is None:
        stmt = stmt.where(AppSetting.organization_id.is_(None))
    else:
        stmt = stmt.where(AppSetting.organization_id == org_id)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        return None
    return row.value if isinstance(row.value, dict) else {}


async def load_org_credential(db: AsyncSession, org_id: str, provider: str) -> str:
    """The org's stored API key for ``provider``; raises ``LLMNotConfigured`` otherwise."""
    stmt = (
        select(InstalledIntegration)
        .where(
            InstalledIntegration.organization_id == org_id,
            InstalledIntegration.connector_id == provider,
        )
        .order_by(InstalledIntegration.updated_at.desc())
        .limit(1)
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise not_configured(
            f"organization has an ai section for {provider!r} but no stored credential",
            source="org",
            reason="missing_credential",
        )
    try:
        blob = decrypt_secret_json(row.auth_credentials_encrypted, required=True)
    except SecretUnreadable as exc:
        logger.error(
            "llm_org_credential_unreadable",
            organization_id=org_id,
            provider=provider,
            installation_id=row.id,
            reason=exc.reason,
        )
        raise not_configured(
            f"stored {provider!r} credential is unreadable ({exc.reason})",
            source="org",
            reason="secret_unreadable",
        ) from exc
    if not isinstance(blob, dict):
        raise not_configured(
            f"stored {provider!r} credential is not an object", source="org", reason="missing_credential"
        )
    for key in _CREDENTIAL_KEYS:
        value = blob.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise not_configured(
        f"stored {provider!r} credential has no api_key", source="org", reason="missing_credential"
    )


def _platform_key(provider: str, cfg: Settings) -> str:
    key = {
        "anthropic": cfg.anthropic_api_key,
        "gemini": cfg.gemini_api_key,
        "openai": cfg.openai_api_key,
    }.get(provider)
    if not key:
        raise not_configured(
            f"platform default provider {provider!r} has no API key configured",
            source="platform",
            reason="missing_credential",
        )
    return key


def build_provider(
    provider: ProviderName,
    *,
    model: str,
    api_key: Optional[str],
    credential_source: Literal["org", "platform"],
    cfg: Optional[Settings] = None,
) -> LLMProvider:
    """Instantiate a provider. Base URLs come from platform settings only."""
    cfg = cfg or app_settings
    if provider == "anthropic":
        from src.llm.anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=api_key or "", model=model, credential_source=credential_source)
    if provider == "gemini":
        from src.llm.gemini_provider import GeminiProvider

        return GeminiProvider(api_key=api_key or "", model=model, credential_source=credential_source)
    if provider == "openai":
        from src.llm.openai_provider import OpenAIProvider

        return OpenAIProvider(
            api_key=api_key or "",
            model=model,
            credential_source=credential_source,
            base_url=cfg.openai_base_url,
        )
    if provider == "ollama":
        from src.llm.ollama_provider import OllamaProvider

        return OllamaProvider(model=model, base_url=cfg.ollama_base_url, credential_source="platform")
    raise not_configured(f"unsupported llm provider {provider!r}", source=credential_source, reason="unknown_provider")


async def resolve_llm_config(
    db: AsyncSession, org_id: str, *, cfg: Optional[Settings] = None
) -> tuple[ResolvedConfig, Optional[str]]:
    """Decide provider/model/credential for ``org_id``. Returns ``(config, api_key)``."""
    if not org_id:
        raise ValueError("resolve_llm requires an organization id")
    cfg = cfg or app_settings

    section = await load_ai_section(db, org_id)
    use_platform = False
    if section is not None:
        use_platform = bool(section.get("use_platform_default", False))
        if not use_platform:
            provider = _validate_provider(section.get("provider"), source="org")
            model = _validate_model(section.get("model"), source="org")
            if provider in KEYED_PROVIDERS:
                api_key = await load_org_credential(db, org_id, provider)
                return (
                    ResolvedConfig(provider, model, "org", key_fingerprint(api_key)),
                    api_key,
                )
            return ResolvedConfig(provider, model, "platform", None), None
    else:
        global_section = await load_ai_section(db, None)
        use_platform = bool(global_section and global_section.get("use_platform_default", False))
        if not use_platform:
            raise not_configured(
                "organization has no ai settings and platform default is not enabled",
                source="org",
                reason="ai_not_configured",
            )

    provider = _validate_provider(cfg.llm_provider, source="platform")
    model = _validate_model(cfg.llm_model, source="platform")
    if provider in KEYED_PROVIDERS:
        api_key = _platform_key(provider, cfg)
        return ResolvedConfig(provider, model, "platform", key_fingerprint(api_key)), api_key
    return ResolvedConfig(provider, model, "platform", None), None


async def resolve_llm(db: AsyncSession, org_id: str, *, cfg: Optional[Settings] = None) -> LLMProvider:
    """Return an un-entered provider for ``org_id``; use it as ``async with provider:``."""
    resolved, api_key = await resolve_llm_config(db, org_id, cfg=cfg)
    logger.info(
        "llm_resolved",
        organization_id=org_id,
        provider=resolved.provider,
        model=resolved.model,
        credential_source=resolved.credential_source,
        key_fingerprint=resolved.key_fingerprint,
    )
    return build_provider(
        resolved.provider,
        model=resolved.model,
        api_key=api_key,
        credential_source=resolved.credential_source,
        cfg=cfg,
    )


__all__ = [
    "AI_SECTION",
    "KEYED_PROVIDERS",
    "SUPPORTED_PROVIDERS",
    "ResolvedConfig",
    "build_provider",
    "key_fingerprint",
    "load_ai_section",
    "load_org_credential",
    "not_configured",
    "resolve_llm",
    "resolve_llm_config",
]
