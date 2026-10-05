"""Section-level secret encryption in ``app_settings`` (design v2 section 10 / F12).

Covers: the ``_upsert_section`` / ``_load_section`` round trip, that the raw
column is an ``enc:v1:`` envelope, that the integrations status endpoint never
returns a secret, that an unreadable secret is a 503 for the credential
sections and a dropped value elsewhere, the gemini/ollama additions, the
tenant-URL refusal, and a static grep proving no probe disables TLS
verification.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints import settings as settings_endpoint
from src.core.secrets import SECRET_KEYS, SecretUnreadable, encrypt_secret_json
from src.core.security import create_access_token, get_password_hash
from src.models.organization import Organization
from src.models.settings import AppSetting
from src.models.user import User

pytestmark = pytest.mark.asyncio

ORG_ID = "cc000000-0000-0000-0000-0000000000c3"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/wp7secrettoken"
SLACK_KEY = "xoxb-wp7-not-a-real-token-0000"

_SETTINGS_SOURCE = pathlib.Path(settings_endpoint.__file__)


# ---------------------------------------------------------------------------
# Static guarantee: TLS verification is never disabled in this module
# ---------------------------------------------------------------------------

def test_settings_module_never_disables_tls_verification() -> None:
    source = _SETTINGS_SOURCE.read_text(encoding="utf-8")
    offenders = re.findall(r"verify\s*=\s*False", source)
    assert offenders == [], f"TLS verification disabled in {_SETTINGS_SOURCE.name}: {offenders}"


def test_settings_module_has_no_httpx_client_without_tls() -> None:
    """Every ``httpx.AsyncClient`` in the module relies on the secure default."""
    source = _SETTINGS_SOURCE.read_text(encoding="utf-8")
    assert "verify=" not in source.replace("verify=True", "")


def test_integration_key_map_covers_every_llm_provider() -> None:
    from src.llm.factory import SUPPORTED_PROVIDERS

    for provider in SUPPORTED_PROVIDERS:
        assert provider in settings_endpoint._INTEGRATION_KEY_ATTR, provider
    assert "gemini" in settings_endpoint._INTEGRATION_KEY_ATTR
    assert "ollama" in settings_endpoint._INTEGRATION_KEY_ATTR
    assert "ollama" in settings_endpoint._PLATFORM_URL_ONLY
    assert settings_endpoint._GEMINI_HOST == "https://generativelanguage.googleapis.com"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def org(db_session: AsyncSession) -> None:
    db_session.add(Organization(id=ORG_ID, name="WP7 Enc", slug="wp7-enc"))
    await db_session.commit()


@pytest_asyncio.fixture
async def enc_admin(db_session: AsyncSession, org: None) -> User:
    user = User(
        email="wp7-enc-admin@example.com",
        hashed_password=get_password_hash("wp7-password-123"),
        full_name="Enc Admin",
        role="admin",
        is_active=True,
        is_superuser=True,
        organization_id=ORG_ID,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


def _headers(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _raw(db: AsyncSession, section: str, org_id: str | None = ORG_ID) -> dict[str, Any]:
    stmt = select(AppSetting).where(AppSetting.section == section)
    stmt = (
        stmt.where(AppSetting.organization_id == org_id)
        if org_id is not None
        else stmt.where(AppSetting.organization_id.is_(None))
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    return dict(row.value) if row is not None and isinstance(row.value, dict) else {}


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

async def test_upsert_section_envelopes_secrets_and_load_opens_them(
    db_session: AsyncSession, org: None
) -> None:
    merged = await settings_endpoint._upsert_section(
        db_session,
        ORG_ID,
        "integration:slack",
        {"api_key": SLACK_KEY, "webhook_url": SLACK_WEBHOOK, "enabled": True, "channel": "#soc"},
        None,
    )
    # The caller gets plaintext back...
    assert merged["api_key"] == SLACK_KEY
    assert merged["webhook_url"] == SLACK_WEBHOOK

    # ...but the column holds envelopes for secret keys only.
    raw = await _raw(db_session, "integration:slack")
    assert raw["api_key"].startswith("enc:v1:")
    assert raw["webhook_url"].startswith("enc:v1:")
    assert raw["channel"] == "#soc"
    assert raw["enabled"] is True
    blob = json.dumps(raw)
    assert SLACK_KEY not in blob
    assert SLACK_WEBHOOK not in blob

    opened = await settings_endpoint._load_section(db_session, ORG_ID, "integration:slack")
    assert opened["api_key"] == SLACK_KEY
    assert opened["webhook_url"] == SLACK_WEBHOOK
    assert opened["channel"] == "#soc"


async def test_upsert_section_is_idempotent(db_session: AsyncSession, org: None) -> None:
    await settings_endpoint._upsert_section(
        db_session, ORG_ID, "integration:slack", {"api_key": SLACK_KEY}, None
    )
    first = (await _raw(db_session, "integration:slack"))["api_key"]
    # Re-saving an unrelated key must not re-wrap (or double-wrap) the secret.
    await settings_endpoint._upsert_section(
        db_session, ORG_ID, "integration:slack", {"channel": "#ir"}, None
    )
    second = await _raw(db_session, "integration:slack")
    assert second["api_key"].startswith("enc:v1:")
    assert not second["api_key"][len("enc:v1:"):].startswith("enc:v1:")
    opened = await settings_endpoint._load_section(db_session, ORG_ID, "integration:slack")
    assert opened["api_key"] == SLACK_KEY
    assert opened["channel"] == "#ir"
    # Idempotent in substance even if the ciphertext nonce differs.
    assert first.startswith("enc:v1:")


async def test_secret_keys_include_the_f12_set() -> None:
    required = {
        "api_key",
        "token",
        "password",
        "secret",
        "client_secret",
        "private_key",
        "webhook_url",
    }
    assert required <= SECRET_KEYS


# ---------------------------------------------------------------------------
# HTTP: save a slack webhook, then read status
# ---------------------------------------------------------------------------

async def test_save_integration_encrypts_and_status_never_returns_secret(
    client: AsyncClient, db_session: AsyncSession, enc_admin: User
) -> None:
    saved = await client.post(
        "/api/v1/settings/integrations/slack",
        headers=_headers(enc_admin),
        json={"api_key": SLACK_KEY, "webhook_url": SLACK_WEBHOOK, "enabled": True},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["configured"] is True
    assert SLACK_KEY not in saved.text
    assert SLACK_WEBHOOK not in saved.text

    raw = await _raw(db_session, "integration:slack")
    assert raw["api_key"].startswith("enc:v1:")
    assert raw["webhook_url"].startswith("enc:v1:")

    status = await client.get("/api/v1/settings", headers=_headers(enc_admin))
    assert status.status_code == 200, status.text
    integrations = status.json()["integrations"]
    assert integrations["slack"]["configured"] is True
    assert integrations["slack"]["enabled"] is True
    # The status payload carries booleans only -- never a value, plaintext or
    # enveloped.
    assert set(integrations["slack"]) == {"enabled", "configured"}
    assert SLACK_KEY not in status.text
    assert SLACK_WEBHOOK not in status.text
    assert "enc:v1:" not in status.text


async def test_status_seeds_gemini_and_ollama(client: AsyncClient, enc_admin: User) -> None:
    status = await client.get("/api/v1/settings", headers=_headers(enc_admin))
    assert status.status_code == 200
    integrations = status.json()["integrations"]
    assert "gemini" in integrations
    assert "ollama" in integrations


async def test_ollama_save_rejects_tenant_supplied_url(
    client: AsyncClient, enc_admin: User
) -> None:
    resp = await client.post(
        "/api/v1/settings/integrations/ollama",
        headers=_headers(enc_admin),
        json={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert resp.status_code == 400, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "tenant_url_not_allowed"
    assert detail["keys"] == ["url"]


# ---------------------------------------------------------------------------
# Unreadable secrets
# ---------------------------------------------------------------------------

async def test_ai_section_unreadable_secret_is_503(
    client: AsyncClient, db_session: AsyncSession, enc_admin: User
) -> None:
    db_session.add(
        AppSetting(
            organization_id=ORG_ID,
            section="ai",
            value={
                "provider": "anthropic",
                "model": "claude-opus-5-20260101",
                "api_key": "enc:v1:" + "not-valid-ciphertext",
            },
        )
    )
    await db_session.commit()

    resp = await client.get("/api/v1/settings/ai", headers=_headers(enc_admin))
    assert resp.status_code == 503, resp.text
    assert resp.json()["error"] == "secret_unreadable"


async def test_strict_sections_raise_and_others_degrade(
    db_session: AsyncSession, org: None
) -> None:
    bad = "enc:v1:" + "not-valid-ciphertext"
    db_session.add_all(
        [
            AppSetting(
                organization_id=ORG_ID, section="integration:anthropic", value={"api_key": bad}
            ),
            AppSetting(
                organization_id=ORG_ID,
                section="notifications",
                value={"slack_webhook_url": bad, "slack_enabled": True},
            ),
        ]
    )
    await db_session.commit()

    assert settings_endpoint._section_is_strict("ai") is True
    assert settings_endpoint._section_is_strict("integration:anthropic") is True
    assert settings_endpoint._section_is_strict("notifications") is False

    with pytest.raises(SecretUnreadable):
        await settings_endpoint._load_section(db_session, ORG_ID, "integration:anthropic")

    lenient = await settings_endpoint._load_section(db_session, ORG_ID, "notifications")
    assert lenient["slack_webhook_url"] is None
    assert lenient["slack_enabled"] is True


async def test_already_enveloped_input_is_not_double_wrapped(
    db_session: AsyncSession, org: None
) -> None:
    pre = encrypt_secret_json(SLACK_KEY)
    await settings_endpoint._upsert_section(
        db_session, ORG_ID, "integration:teams", {"api_key": pre}, None
    )
    raw = await _raw(db_session, "integration:teams")
    assert raw["api_key"] == pre
    opened = await settings_endpoint._load_section(db_session, ORG_ID, "integration:teams")
    assert opened["api_key"] == SLACK_KEY
