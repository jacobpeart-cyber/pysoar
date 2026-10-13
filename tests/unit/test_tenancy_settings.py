"""Settings are per organisation (wave 1, docs/audit/2026-10-08/PLAN.md item 5).

Before wave 1 the Settings PATCH handlers wrote each tenant's SMTP relay,
Slack / Teams webhooks, session timeout and integration keys into the one
process-wide config object, so the last tenant to save won for everyone, and
any tenant admin (``get_current_superuser`` admits tenant admins) could do it.

Covered here: admin-only writes, mandatory organisation, values stored and
read back per organisation, the process-wide config never mutated, the
consumers (SMTP, Slack/Teams, session timeout) reading the caller's
organisation, and the ``stored_not_enforced`` disclosure.
"""

from __future__ import annotations

from datetime import datetime, timezone

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings as platform_settings
from src.models.organization import Organization
from src.models.user import User
from src.services.email_service import EmailService
from src.services.tenant_settings import (
    notification_webhook_for,
    session_timeout_minutes_for,
    smtp_settings_for,
)
from tests.helpers.tenancy import bearer, make_user

SLACK_A = "https://hooks.slack.com/services/TA/BA/org-a-secret"
SLACK_B = "https://hooks.slack.com/services/TB/BB/org-b-secret"


@pytest.fixture
async def org_b_admin(db_session: AsyncSession, org_b: Organization) -> User:
    return await make_user(db_session, role="admin", organization_id=org_b.id, label="admin-b")


async def test_settings_writes_are_admin_only(
    client: AsyncClient, org_a_headers: dict, viewer_headers: dict,
) -> None:
    for headers in (org_a_headers, viewer_headers):
        for method, path, body in (
            ("GET", "/api/v1/settings", None),
            ("PATCH", "/api/v1/settings/smtp", {"host": "smtp.a.io"}),
            ("PATCH", "/api/v1/settings/notifications", {"slack_webhook_url": SLACK_A}),
            ("PATCH", "/api/v1/settings/general", {"app_name": "x"}),
            ("PATCH", "/api/v1/settings/security", {"session_timeout_minutes": 10}),
            ("PATCH", "/api/v1/settings", {"general": {"app_name": "x"}}),
            ("POST", "/api/v1/settings/integrations/virustotal", {"api_key": "k"}),
            ("POST", "/api/v1/settings/test-email", None),
            ("POST", "/api/v1/settings/test-integration/virustotal", None),
        ):
            resp = await client.request(method, path, json=body, headers=headers)
            assert resp.status_code == 403, (method, path, resp.status_code, resp.text[:200])


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict) -> None:
    resp = await client.patch("/api/v1/settings/smtp", json={"host": "smtp.x.io"}, headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"
    resp = await client.get("/api/v1/settings", headers=superuser_headers)
    assert resp.status_code == 403


async def test_ai_tenants_listing_is_platform_superuser_only(
    client: AsyncClient, org_a_admin_headers: dict, superuser_headers: dict,
) -> None:
    resp = await client.get("/api/v1/settings/ai/tenants", headers=org_a_admin_headers)
    assert resp.status_code == 403
    resp = await client.get("/api/v1/settings/ai/tenants", headers=superuser_headers)
    assert resp.status_code == 200


async def test_values_are_stored_per_org_and_never_mirrored_globally(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict,
    org_b_admin: User,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    b_headers = bearer(org_b_admin)
    before = (
        platform_settings.smtp_host,
        platform_settings.smtp_user,
        platform_settings.slack_webhook_url,
        platform_settings.access_token_expire_minutes,
        platform_settings.app_name,
        platform_settings.virustotal_api_key,
    )

    resp = await client.patch(
        "/api/v1/settings/smtp",
        json={"host": "smtp.org-a.io", "port": 2525, "username": "mailer-a", "password": "pw-a"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    resp = await client.patch(
        "/api/v1/settings/notifications", json={"slack_webhook_url": SLACK_A}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert "slack_enabled" in resp.json()["stored_not_enforced"]
    resp = await client.patch(
        "/api/v1/settings/security", json={"session_timeout_minutes": 17, "require_mfa": True},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert "require_mfa" in resp.json()["stored_not_enforced"]
    resp = await client.patch("/api/v1/settings/general", json={"app_name": "Org A SOC"}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    resp = await client.post(
        "/api/v1/settings/integrations/virustotal", json={"api_key": "vt-org-a"}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["stored_not_enforced"] == ["automatic_ioc_enrichment"]

    resp = await client.patch(
        "/api/v1/settings/notifications", json={"slack_webhook_url": SLACK_B}, headers=b_headers,
    )
    assert resp.status_code == 200, resp.text

    # The process-wide config is untouched by any tenant write.
    after = (
        platform_settings.smtp_host,
        platform_settings.smtp_user,
        platform_settings.slack_webhook_url,
        platform_settings.access_token_expire_minutes,
        platform_settings.app_name,
        platform_settings.virustotal_api_key,
    )
    assert after == before

    # Org B reads its own values, not org A's.
    status_b = (await client.get("/api/v1/settings", headers=b_headers)).json()
    assert status_b["smtp"]["host"] != "smtp.org-a.io"
    assert status_b["general"]["app_name"] != "Org A SOC"
    assert status_b["integrations"]["virustotal"]["configured"] is bool(platform_settings.virustotal_api_key)
    status_a = (await client.get("/api/v1/settings", headers=org_a_admin_headers)).json()
    assert status_a["smtp"]["host"] == "smtp.org-a.io"
    assert status_a["general"]["app_name"] == "Org A SOC"
    assert status_a["integrations"]["virustotal"]["configured"] is True
    assert "max_login_attempts" in status_a["general"]["stored_not_enforced"]

    # Consumers read the caller's organisation.
    smtp_a = await smtp_settings_for(db_session, org_a_id)
    assert (smtp_a.host, smtp_a.port, smtp_a.username, smtp_a.password) == ("smtp.org-a.io", 2525, "mailer-a", "pw-a")
    assert smtp_a.source == "organization"
    smtp_b = await smtp_settings_for(db_session, org_b_id)
    assert smtp_b.source == "platform" and smtp_b.host == platform_settings.smtp_host
    email_a = await EmailService.for_organization(db_session, org_a_id)
    assert email_a.host == "smtp.org-a.io" and email_a.is_configured

    assert await notification_webhook_for(db_session, org_a_id, "slack") == SLACK_A
    assert await notification_webhook_for(db_session, org_b_id, "slack") == SLACK_B
    assert await notification_webhook_for(db_session, org_b_id, "teams") is None
    assert await notification_webhook_for(db_session, None, "slack") is None

    assert await session_timeout_minutes_for(db_session, org_a_id) == 17
    assert await session_timeout_minutes_for(db_session, org_b_id) == platform_settings.access_token_expire_minutes


async def test_incident_notifications_use_the_incident_tenants_webhook(
    db_session: AsyncSession, org_a: Organization, org_b: Organization, org_a_admin: User,
) -> None:
    from src.api.v1.endpoints.settings import _upsert_section
    from src.services.notifications import _load_integration

    org_a_id, org_b_id, admin_id = org_a.id, org_b.id, org_a_admin.id
    await _upsert_section(db_session, org_a_id, "integration:slack", {"webhook_url": SLACK_A}, admin_id)
    cfg = await _load_integration(db_session, org_a_id, "slack")
    assert cfg is not None and cfg["webhook_url"] == SLACK_A  # opened, not the enc:v1: envelope
    assert await _load_integration(db_session, org_b_id, "slack") is None
    assert await _load_integration(db_session, None, "slack") is None


async def test_login_token_lifetime_is_the_orgs_session_timeout(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict,
) -> None:
    org_a_id = org_a.id
    user = await make_user(db_session, role="analyst", organization_id=org_a_id, label="login-a")
    email = user.email
    resp = await client.patch(
        "/api/v1/settings/security", json={"session_timeout_minutes": 12}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text

    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": "testpassword123"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["expires_in"] == 12 * 60
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    lifetime = claims["exp"] - int(datetime.now(timezone.utc).timestamp())
    assert 11 * 60 <= lifetime <= 12 * 60 + 5
