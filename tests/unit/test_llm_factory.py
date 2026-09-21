"""``resolve_llm``: org-authoritative resolution order against the SQLite fixture DB."""
from __future__ import annotations

import base64
import secrets as pysecrets
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import secrets as secrets_mod
from src.core.secrets import EncryptionService, encrypt_secret_json
from src.integrations.models import InstalledIntegration
from src.llm.anthropic_provider import AnthropicProvider
from src.llm.base import LLMNotConfigured
from src.llm.factory import key_fingerprint, resolve_llm, resolve_llm_config
from src.llm.gemini_provider import GeminiProvider
from src.llm.ollama_provider import OllamaProvider
from src.llm.openai_provider import OpenAIProvider
from src.models.organization import Organization
from src.models.settings import AppSetting

ORG_A = "11111111-1111-1111-1111-111111111111"
ORG_B = "22222222-2222-2222-2222-222222222222"


def _cfg(**overrides: Any) -> SimpleNamespace:
    base = dict(
        llm_provider="gemini",
        llm_model="gemini-2.5-pro",
        anthropic_api_key=None,
        openai_api_key=None,
        gemini_api_key="AIzaPlatformKey12345",
        ollama_base_url="http://ollama.internal:11434",
        openai_base_url=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> EncryptionService:
    svc = EncryptionService(master_key=base64.b64encode(pysecrets.token_bytes(32)).decode())
    monkeypatch.setattr(secrets_mod, "_resolve_service", lambda service: service or svc)
    return svc


async def _orgs(db: AsyncSession) -> None:
    db.add_all(
        [
            Organization(id=ORG_A, name="Org A", slug="org-a"),
            Organization(id=ORG_B, name="Org B", slug="org-b"),
        ]
    )
    await db.flush()


async def _ai_section(db: AsyncSession, org_id: str | None, value: dict[str, Any]) -> None:
    db.add(AppSetting(organization_id=org_id, section="ai", value=value))
    await db.flush()


async def _credential(db: AsyncSession, org_id: str, provider: str, blob: str) -> None:
    db.add(
        InstalledIntegration(
            organization_id=org_id,
            connector_id=provider,
            display_name=provider,
            config_encrypted="{}",
            auth_credentials_encrypted=blob,
            status="active",
            health_status="unknown",
        )
    )
    await db.flush()


async def test_org_section_with_credential_resolves_org_provider(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "anthropic", "model": "claude-opus-5"})
    await _credential(db_session, ORG_A, "anthropic", encrypt_secret_json({"api_key": "sk-ant-org-key-0001"}))

    resolved, key = await resolve_llm_config(db_session, ORG_A, cfg=_cfg())
    assert key == "sk-ant-org-key-0001"
    assert resolved.provider == "anthropic" and resolved.model == "claude-opus-5"
    assert resolved.credential_source == "org"
    assert resolved.key_fingerprint == key_fingerprint("sk-ant-org-key-0001")
    assert "sk-ant" not in resolved.key_fingerprint and resolved.key_fingerprint.endswith(":0001")

    provider = await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert isinstance(provider, AnthropicProvider)
    assert provider.model == "claude-opus-5" and provider.credential_source == "org"
    assert provider._api_key == "sk-ant-org-key-0001"


async def test_org_section_without_credential_never_falls_back_to_env(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "gemini", "model": "gemini-2.5-pro"})
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg(gemini_api_key="AIzaPlatformKeyShouldNotBeUsed"))
    assert info.value.source == "org" and info.value.reason == "missing_credential"  # type: ignore[attr-defined]


async def test_credential_of_another_org_is_not_visible(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "gemini", "model": "gemini-2.5-pro"})
    await _credential(db_session, ORG_B, "gemini", encrypt_secret_json({"api_key": "AIzaOrgBKey000000"}))
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert info.value.reason == "missing_credential"  # type: ignore[attr-defined]


async def test_unreadable_envelope_is_secret_unreadable(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "openai", "model": "gpt-5"})
    other = EncryptionService(master_key=base64.b64encode(pysecrets.token_bytes(32)).decode())
    await _credential(db_session, ORG_A, "openai", encrypt_secret_json({"api_key": "sk-openai-0001"}, service=other))
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert info.value.source == "org" and info.value.reason == "secret_unreadable"  # type: ignore[attr-defined]


async def test_legacy_plaintext_credential_is_rejected(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "openai", "model": "gpt-5"})
    await _credential(db_session, ORG_A, "openai", '{"api_key": "sk-openai-plain"}')
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert info.value.reason == "secret_unreadable"  # type: ignore[attr-defined]


async def test_org_section_missing_provider_or_model(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"model": "x"})
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert info.value.reason == "provider_not_set"  # type: ignore[attr-defined]
    await _ai_section(db_session, ORG_B, {"provider": "gemini"})
    with pytest.raises(LLMNotConfigured) as info2:
        await resolve_llm(db_session, ORG_B, cfg=_cfg())
    assert info2.value.reason == "model_not_set"  # type: ignore[attr-defined]


async def test_org_opting_into_platform_default_uses_env(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "anthropic", "model": "ignored", "use_platform_default": True})
    provider = await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert isinstance(provider, GeminiProvider)
    assert provider.model == "gemini-2.5-pro" and provider.credential_source == "platform"
    assert provider._api_key == "AIzaPlatformKey12345"


async def test_no_section_and_no_global_default_is_not_configured(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert info.value.source == "org" and info.value.reason == "ai_not_configured"  # type: ignore[attr-defined]


async def test_global_default_row_enables_platform_fallback(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, None, {"use_platform_default": True})
    provider = await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert isinstance(provider, GeminiProvider) and provider.credential_source == "platform"


async def test_platform_default_requires_key_and_model(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, None, {"use_platform_default": True})
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg(gemini_api_key=None))
    assert info.value.source == "platform" and info.value.reason == "missing_credential"  # type: ignore[attr-defined]
    with pytest.raises(LLMNotConfigured) as info2:
        await resolve_llm(db_session, ORG_A, cfg=_cfg(llm_model=None))
    assert info2.value.reason == "model_not_set"  # type: ignore[attr-defined]


async def test_ollama_and_openai_base_urls_are_platform_env_only(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "ollama", "model": "llama3.1", "base_url": "http://evil.internal"})
    ollama = await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert isinstance(ollama, OllamaProvider)
    assert ollama.base_url == "http://ollama.internal:11434" and ollama.credential_source == "platform"

    await _ai_section(db_session, ORG_B, {"provider": "openai", "model": "gpt-5", "base_url": "http://evil.internal"})
    await _credential(db_session, ORG_B, "openai", encrypt_secret_json({"token": "sk-openai-token-0002"}))
    openai = await resolve_llm(db_session, ORG_B, cfg=_cfg(openai_base_url="https://proxy.corp/v1"))
    assert isinstance(openai, OpenAIProvider)
    assert openai.base_url == "https://proxy.corp/v1" and openai._api_key == "sk-openai-token-0002"
    assert openai.credential_source == "org"


async def test_unknown_provider_rejected(db_session: AsyncSession, service: EncryptionService) -> None:
    await _orgs(db_session)
    await _ai_section(db_session, ORG_A, {"provider": "bedrock", "model": "x"})
    with pytest.raises(LLMNotConfigured) as info:
        await resolve_llm(db_session, ORG_A, cfg=_cfg())
    assert info.value.reason == "unknown_provider"  # type: ignore[attr-defined]


async def test_org_id_required(db_session: AsyncSession) -> None:
    with pytest.raises(ValueError):
        await resolve_llm(db_session, "", cfg=_cfg())
