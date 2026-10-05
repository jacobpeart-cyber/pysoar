"""``GET/PUT /settings/ai``, ``/settings/ai/models``, ``/settings/ai/tenants``, ``/health/llm``.

Work package 7 of the agentic rebuild. Nothing here talks to a real provider:
``build_provider`` is monkeypatched in the endpoint module with a fake whose
``list_models`` returns a fixed list (or raises a typed provider error), which
is exactly the seam the design intends for model validation.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Optional

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints import settings as settings_endpoint
from src.audit_evidence.models import AuditTrail
from src.core.security import create_access_token, get_password_hash
from src.integrations.models import InstalledIntegration
from src.llm.base import LLMAuthError, LLMNotConfigured
from src.llm.factory import key_fingerprint
from src.models.organization import Organization
from src.models.settings import AppSetting
from src.models.user import User

pytestmark = pytest.mark.asyncio

ORG_ID = "aa000000-0000-0000-0000-0000000000a1"
OTHER_ORG_ID = "bb000000-0000-0000-0000-0000000000b2"

#: A realistic-shaped but inert Anthropic key. Only ever used as test input.
TEST_KEY = "sk-ant-test-000000000000000000wxyz"
MODEL = "claude-opus-5-20260101"


# ---------------------------------------------------------------------------
# Fake provider
# ---------------------------------------------------------------------------

class _FakeProvider:
    """Async-context provider stub exposing only ``list_models``."""

    def __init__(self, models: Iterable[str], error: Optional[BaseException] = None) -> None:
        self._models = list(models)
        self._error = error
        self.entered = False

    async def __aenter__(self) -> "_FakeProvider":
        self.entered = True
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def list_models(self) -> list[str]:
        if self._error is not None:
            raise self._error
        return list(self._models)


def _patch_provider(
    monkeypatch: pytest.MonkeyPatch,
    models: Iterable[str] = (MODEL, "claude-haiku-5-20260101"),
    error: Optional[BaseException] = None,
) -> dict[str, Any]:
    """Replace ``build_provider`` in the endpoint module; record what it saw."""
    seen: dict[str, Any] = {}

    def _build(provider: str, *, model: str, api_key: Optional[str], credential_source: str, **_: Any) -> _FakeProvider:
        seen.update(
            provider=provider, model=model, api_key=api_key, credential_source=credential_source
        )
        return _FakeProvider(models, error)

    monkeypatch.setattr(settings_endpoint, "build_provider", _build)
    return seen


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def orgs(db_session: AsyncSession) -> None:
    db_session.add_all(
        [
            Organization(id=ORG_ID, name="WP7 Org", slug="wp7-org"),
            Organization(id=OTHER_ORG_ID, name="WP7 Other", slug="wp7-other"),
        ]
    )
    await db_session.commit()


async def _user(db_session: AsyncSession, email: str, role: str, *, superuser: bool, org: str) -> User:
    user = User(
        email=email,
        hashed_password=get_password_hash("wp7-password-123"),
        full_name=email,
        role=role,
        is_active=True,
        is_superuser=superuser,
        organization_id=org,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def ai_admin(db_session: AsyncSession, orgs: None) -> User:
    return await _user(db_session, "wp7-admin@example.com", "admin", superuser=False, org=ORG_ID)


@pytest_asyncio.fixture
async def ai_analyst(db_session: AsyncSession, orgs: None) -> User:
    return await _user(db_session, "wp7-analyst@example.com", "analyst", superuser=False, org=ORG_ID)


@pytest_asyncio.fixture
async def ai_superuser(db_session: AsyncSession, orgs: None) -> User:
    return await _user(db_session, "wp7-root@example.com", "admin", superuser=True, org=ORG_ID)


def _headers(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _raw_section(db: AsyncSession, org_id: str, section: str) -> dict[str, Any]:
    """The stored (still-enveloped) ``app_settings.value`` -- no decryption."""
    row = (
        await db.execute(
            select(AppSetting).where(
                AppSetting.organization_id == org_id, AppSetting.section == section
            )
        )
    ).scalar_one_or_none()
    return dict(row.value) if row is not None and isinstance(row.value, dict) else {}


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

async def test_get_ai_settings_rejects_analyst(client: AsyncClient, ai_analyst: User) -> None:
    resp = await client.get("/api/v1/settings/ai", headers=_headers(ai_analyst))
    assert resp.status_code == 403


async def test_put_ai_settings_rejects_analyst(
    client: AsyncClient, ai_analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_provider(monkeypatch)
    resp = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_analyst),
        json={"provider": "anthropic", "model": MODEL, "api_key": TEST_KEY},
    )
    assert resp.status_code == 403


async def test_ai_endpoints_require_authentication(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/settings/ai")).status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /settings/ai
# ---------------------------------------------------------------------------

async def test_get_ai_settings_unconfigured(client: AsyncClient, ai_admin: User) -> None:
    resp = await client.get("/api/v1/settings/ai", headers=_headers(ai_admin))
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert body["source"] == "none"
    assert body["provider"] is None
    assert body["key_fingerprint"] is None
    assert body["rotated_at"] is None
    assert body["last_successful_call_at"] is None
    assert body["reason"] == "ai_not_configured"


# ---------------------------------------------------------------------------
# PUT /settings/ai
# ---------------------------------------------------------------------------

async def test_put_stores_key_encrypted_returns_fingerprint_and_audits(
    client: AsyncClient,
    db_session: AsyncSession,
    ai_admin: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_provider(monkeypatch)

    resp = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={
            "provider": "anthropic",
            "model": MODEL,
            "use_platform_default": False,
            "api_key": TEST_KEY,
        },
    )
    assert resp.status_code == 200, resp.text

    # The raw key is validated against the provider but never echoed back.
    assert seen["api_key"] == TEST_KEY
    assert TEST_KEY not in resp.text

    body = resp.json()
    assert body["provider"] == "anthropic"
    assert body["model"] == MODEL
    assert body["configured"] is True
    assert body["source"] == "org"
    assert body["key_fingerprint"] == key_fingerprint(TEST_KEY)
    assert body["rotated_at"]
    assert body["capabilities"]["model_count"] == 2
    assert body["capabilities"]["models_seen_at"]

    # --- stored at rest: the ai section carries no key at all ...
    ai_raw = await _raw_section(db_session, ORG_ID, "ai")
    assert ai_raw["provider"] == "anthropic"
    assert "api_key" not in ai_raw
    assert TEST_KEY not in json.dumps(ai_raw)

    # ... the mirrored integration section is enveloped ...
    integ_raw = await _raw_section(db_session, ORG_ID, "integration:anthropic")
    assert isinstance(integ_raw["api_key"], str)
    assert integ_raw["api_key"].startswith("enc:v1:")
    assert TEST_KEY not in integ_raw["api_key"]

    # ... and so is the InstalledIntegration row the factory reads.
    install = (
        await db_session.execute(
            select(InstalledIntegration).where(
                InstalledIntegration.organization_id == ORG_ID,
                InstalledIntegration.connector_id == "anthropic",
            )
        )
    ).scalar_one()
    assert install.auth_credentials_encrypted.startswith("enc:v1:")
    assert TEST_KEY not in install.auth_credentials_encrypted
    assert TEST_KEY not in (install.config_encrypted or "")

    # --- audit: both events, medium risk, fingerprint only.
    trails = (
        await db_session.execute(
            select(AuditTrail).where(AuditTrail.organization_id == ORG_ID)
        )
    ).scalars().all()
    by_action = {row.action: row for row in trails}
    assert "ai.provider.set" in by_action
    assert "ai.key.rotated" in by_action
    assert by_action["ai.provider.set"].risk_level == "medium"
    assert by_action["ai.key.rotated"].risk_level == "medium"
    rotated_new = by_action["ai.key.rotated"].new_value or {}
    assert rotated_new.get("key_fingerprint") == key_fingerprint(TEST_KEY)
    assert TEST_KEY not in json.dumps(
        {a: (r.new_value, r.old_value) for a, r in by_action.items()}
    )

    # The factory now resolves this org from its own stored credential.
    from src.llm.factory import resolve_llm_config

    resolved, api_key = await resolve_llm_config(db_session, ORG_ID)
    assert (resolved.provider, resolved.model, resolved.credential_source) == (
        "anthropic",
        MODEL,
        "org",
    )
    assert api_key == TEST_KEY


async def test_put_unknown_model_returns_422_with_available(
    client: AsyncClient, ai_admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_provider(monkeypatch, models=["claude-haiku-5-20260101", "claude-sonnet-5-20260101"])
    resp = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "anthropic", "model": "gpt-9-ultra", "api_key": TEST_KEY},
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert body["error"] == "unknown_model"
    assert body["available"] == ["claude-haiku-5-20260101", "claude-sonnet-5-20260101"]


async def test_put_unknown_model_persists_nothing(
    client: AsyncClient,
    db_session: AsyncSession,
    ai_admin: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_provider(monkeypatch, models=["claude-haiku-5-20260101"])
    await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "anthropic", "model": "nope", "api_key": TEST_KEY},
    )
    assert await _raw_section(db_session, ORG_ID, "ai") == {}
    installs = (
        await db_session.execute(
            select(InstalledIntegration).where(InstalledIntegration.organization_id == ORG_ID)
        )
    ).scalars().all()
    assert installs == []


async def test_put_invalid_credentials_returns_400(
    client: AsyncClient, ai_admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_provider(monkeypatch, error=LLMAuthError("401 invalid x-api-key"))
    resp = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "anthropic", "model": MODEL, "api_key": TEST_KEY},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_credentials"
    assert TEST_KEY not in resp.text


async def test_put_rejects_unknown_provider(client: AsyncClient, ai_admin: User) -> None:
    resp = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "evilcorp", "model": MODEL, "api_key": TEST_KEY},
    )
    assert resp.status_code == 422


async def test_put_rejects_tenant_supplied_url(
    client: AsyncClient, ai_admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_provider(monkeypatch)
    resp = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={
            "provider": "openai",
            "model": MODEL,
            "api_key": TEST_KEY,
            "base_url": "http://169.254.169.254/latest/meta-data/",
        },
    )
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error"] == "tenant_url_not_allowed"
    assert body["keys"] == ["base_url"]


async def test_put_without_key_and_without_stored_credential_is_503(
    client: AsyncClient, ai_admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_provider(monkeypatch)
    monkeypatch.setattr(settings_endpoint.app_settings, "anthropic_api_key", None, raising=False)
    resp = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "anthropic", "model": MODEL},
    )
    assert resp.status_code == 503, resp.text
    assert resp.json()["error"] == "llm_not_configured"


# ---------------------------------------------------------------------------
# GET /settings/ai/models
# ---------------------------------------------------------------------------

async def test_models_503_when_nothing_configured(
    client: AsyncClient, ai_admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_provider(monkeypatch)
    monkeypatch.setattr(settings_endpoint.app_settings, "anthropic_api_key", None, raising=False)
    resp = await client.get(
        "/api/v1/settings/ai/models?provider=anthropic", headers=_headers(ai_admin)
    )
    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert body["error"] == "llm_not_configured"
    assert body["reason"] == "missing_credential"


async def test_models_lists_live_models_with_org_credential(
    client: AsyncClient, ai_admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _patch_provider(monkeypatch)
    saved = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "anthropic", "model": MODEL, "api_key": TEST_KEY},
    )
    assert saved.status_code == 200, saved.text

    resp = await client.get("/api/v1/settings/ai/models", headers=_headers(ai_admin))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["provider"] == "anthropic"
    assert body["source"] == "org"
    assert MODEL in body["models"]
    assert body["fetched_at"]
    # The org's own stored credential was used, not an ambient one.
    assert seen["api_key"] == TEST_KEY
    assert TEST_KEY not in resp.text


async def test_models_rejects_unsupported_provider(client: AsyncClient, ai_admin: User) -> None:
    resp = await client.get(
        "/api/v1/settings/ai/models?provider=sideloaded", headers=_headers(ai_admin)
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "unknown_provider"


async def test_models_rejects_analyst(client: AsyncClient, ai_analyst: User) -> None:
    resp = await client.get("/api/v1/settings/ai/models", headers=_headers(ai_analyst))
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /settings/ai/tenants  (superuser)
# ---------------------------------------------------------------------------

async def test_tenants_rejects_analyst(client: AsyncClient, ai_analyst: User) -> None:
    resp = await client.get("/api/v1/settings/ai/tenants", headers=_headers(ai_analyst))
    assert resp.status_code == 403


async def test_tenants_lists_one_row_per_org(
    client: AsyncClient,
    db_session: AsyncSession,
    ai_superuser: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_provider(monkeypatch)
    saved = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_superuser),
        json={"provider": "anthropic", "model": MODEL, "api_key": TEST_KEY},
    )
    assert saved.status_code == 200, saved.text
    # A second org on the platform default, with no credential of its own.
    db_session.add(
        AppSetting(
            organization_id=OTHER_ORG_ID,
            section="ai",
            value={"provider": "gemini", "model": "gemini-2.5-pro", "use_platform_default": True},
        )
    )
    await db_session.commit()

    resp = await client.get("/api/v1/settings/ai/tenants", headers=_headers(ai_superuser))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 2
    rows = {row["organization_id"]: row for row in body["tenants"]}
    assert rows[ORG_ID]["provider"] == "anthropic"
    assert rows[ORG_ID]["model"] == MODEL
    assert rows[ORG_ID]["source"] == "org"
    assert rows[ORG_ID]["last_successful_call_at"] is None
    assert rows[OTHER_ORG_ID]["source"] == "platform"
    assert set(rows[ORG_ID]) == {
        "organization_id",
        "provider",
        "model",
        "source",
        "last_successful_call_at",
    }
    assert TEST_KEY not in resp.text


# ---------------------------------------------------------------------------
# GET /health/llm
# ---------------------------------------------------------------------------

async def test_health_llm_shape_unconfigured(client: AsyncClient, ai_analyst: User) -> None:
    from src.api.v1.endpoints import health as health_endpoint

    health_endpoint._llm_health_cache.clear()
    resp = await client.get("/api/v1/health/llm", headers=_headers(ai_analyst))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {
        "status",
        "organization_id",
        "configured",
        "provider",
        "model",
        "source",
        "reason",
        "last_successful_call_at",
        "breaker_open",
        "checked_at",
        "cached",
    }
    assert body["status"] == "not_configured"
    assert body["organization_id"] == ORG_ID
    assert body["configured"] is False
    assert body["source"] == "none"
    assert body["cached"] is False


async def test_health_llm_reports_configured_and_caches(
    client: AsyncClient, ai_admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.api.v1.endpoints import health as health_endpoint

    health_endpoint._llm_health_cache.clear()
    _patch_provider(monkeypatch)
    saved = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "anthropic", "model": MODEL, "api_key": TEST_KEY},
    )
    assert saved.status_code == 200, saved.text

    first = await client.get("/api/v1/health/llm", headers=_headers(ai_admin))
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["status"] == "ok"
    assert body["configured"] is True
    assert body["provider"] == "anthropic"
    assert body["source"] == "org"
    assert body["breaker_open"] is False
    assert body["cached"] is False
    assert TEST_KEY not in first.text

    second = await client.get("/api/v1/health/llm", headers=_headers(ai_admin))
    assert second.status_code == 200
    assert second.json()["cached"] is True
    # Cached means no provider call and no re-resolution; the stamp is frozen.
    assert second.json()["checked_at"] == body["checked_at"]


async def test_health_llm_requires_authentication(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/health/llm")).status_code in (401, 403)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

async def test_metrics_agentic_exposes_the_three_counters(
    client: AsyncClient, ai_admin: User
) -> None:
    from src.core import metrics

    metrics.reset()
    metrics.increment(metrics.LLM_CALLS_TOTAL, provider="anthropic", stop_reason="end_turn")
    metrics.increment(metrics.LLM_CALLS_TOTAL, provider="anthropic", stop_reason="end_turn")
    metrics.increment(metrics.AGENT_POLICY_DECISIONS_TOTAL, decision="deny", reason="role")
    metrics.increment(metrics.AGENT_INJECTION_EVENTS_TOTAL, tier="lockdown")

    resp = await client.get("/api/v1/metrics/agentic", headers=_headers(ai_admin))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    counters = body["counters"]
    assert body["scope"] == "process"
    assert counters["llm_calls_total"]["total"] == 2
    assert counters["llm_calls_total"]["series"][0]["labels"] == {
        "provider": "anthropic",
        "stop_reason": "end_turn",
    }
    assert counters["agent_policy_decisions_total"]["total"] == 1
    assert counters["agent_injection_events_total"]["total"] == 1
    metrics.reset()


async def test_metrics_increment_rejects_unknown_counter() -> None:
    from src.core import metrics

    with pytest.raises(metrics.UnknownCounter):
        metrics.increment("made_up_total", provider="x")


async def test_llm_not_configured_carries_reason(db_session: AsyncSession, orgs: None) -> None:
    """Guards the reason strings the AI endpoints branch on."""
    from src.llm.factory import resolve_llm_config

    with pytest.raises(LLMNotConfigured) as excinfo:
        await resolve_llm_config(db_session, ORG_ID)
    assert getattr(excinfo.value, "reason", None) == "ai_not_configured"


async def test_last_successful_call_at_ignores_error_rows(
    client: AsyncClient,
    db_session: AsyncSession,
    ai_admin: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The timestamp comes from the newest non-error ``llm_call_logs`` row."""
    from datetime import datetime, timedelta, timezone

    from src.llm.models import LLMCallLog

    _patch_provider(monkeypatch)
    saved = await client.put(
        "/api/v1/settings/ai",
        headers=_headers(ai_admin),
        json={"provider": "anthropic", "model": MODEL, "api_key": TEST_KEY},
    )
    assert saved.status_code == 200, saved.text

    # The fixture DB is built from whatever is registered when it is created,
    # which is before ``src.main`` pulls in ``src.llm.models`` -- so
    # ``llm_call_logs`` is genuinely absent here (which is exactly what
    # ``last_successful_llm_call_at`` guards against, and why the other tests
    # see ``None``). Create it so the join itself can be exercised.
    await db_session.run_sync(
        lambda sync_session: LLMCallLog.__table__.create(
            sync_session.get_bind(), checkfirst=True
        )
    )

    good_at = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

    def _row(stop_reason: str, created_at: datetime, org: str = ORG_ID) -> LLMCallLog:
        return LLMCallLog(
            run_id=f"run-{stop_reason}-{created_at.isoformat()}",
            organization_id=org,
            purpose="chat",
            mode="interactive",
            provider="anthropic",
            model=MODEL,
            credential_source="org",
            stop_reason=stop_reason,
            created_at=created_at,
        )

    db_session.add_all(
        [
            _row("end_turn", good_at),
            # Newer, but an error: must not win.
            _row("error", good_at + timedelta(hours=5)),
            # Newer and successful, but a different org: must not leak.
            _row("end_turn", good_at + timedelta(hours=9), org=OTHER_ORG_ID),
        ]
    )
    await db_session.commit()

    resp = await client.get("/api/v1/settings/ai", headers=_headers(ai_admin))
    assert resp.status_code == 200, resp.text
    reported = resp.json()["last_successful_call_at"]
    assert reported is not None
    assert reported.startswith("2026-10-01T12:00:00")
