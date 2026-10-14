"""Wave 3 (W3-C): ITDR ingestion and identity-provider response.

* Identities come from an installed Okta / Entra ID integration (directory
  sync through the outbound guard) or from a validated CSV import (Active
  Directory exports); before wave 3 nothing produced them.
* Auth events in stored SIEM logs build per-identity sign-in baselines and
  raise access anomalies and brute-force / spray threats.
* Credential monitoring matches identities to the organisation's own leak rows.
* Response actions reach the identity provider, or report
  ``awaiting_integration`` honestly.
* Dashboard metrics come from rows (no invented scan time or service-account
  count).

The identity provider is mocked at the HTTP boundary (httpx MockTransport
behind the real DNS-pinning guard, with DNS answers steered through
``netguard._getaddrinfo``); the sync, guard and persistence logic are real.
"""

from __future__ import annotations

import importlib.util
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional

import httpx
import pytest
import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy import MetaData, Table, create_engine, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.models import AgentAction, SOCAgent
from src.core.config import settings
from src.darkweb.models import CredentialLeak
from src.integrations import netguard
from src.integrations.models import IntegrationConnector, InstalledIntegration
from src.itdr import directory
from src.itdr.analytics import analyze_auth_events_for_org, check_credential_exposures_for_org
from src.itdr.models import AccessAnomaly, CredentialExposure, IdentityProfile, IdentityThreat
from src.models.audit import AuditLog
from src.models.base import Base
from src.models.organization import Organization
from src.models.user import User
from src.siem.models import LogEntry
from src.ueba.models import LogIngestCursor
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/itdr"
OKTA = "https://acme.okta.com"
PUBLIC_IP = "93.184.216.34"
NOW = datetime(2026, 10, 13, 12, 30, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _dns(monkeypatch: pytest.MonkeyPatch, ip: str = PUBLIC_IP) -> None:
    async def fake(host: str, port: int) -> list[tuple[Any, ...]]:
        return [(2, 1, 6, "", (ip, port))]

    monkeypatch.setattr(netguard, "_getaddrinfo", fake)


def _idp(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> list[httpx.Request]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(directory, "_inner_transport", lambda: httpx.MockTransport(record))
    return seen


async def _okta_integration(db: AsyncSession, org_id: str, base_url: str = OKTA, *, name: str = "okta",
                            credentials: Optional[dict[str, Any]] = None) -> str:
    connector = (await db.execute(
        select(IntegrationConnector).where(IntegrationConnector.name == name)
    )).scalar_one_or_none()
    if connector is None:
        connector = IntegrationConnector(
            name=name, display_name=name, category="identity_provider", supported_actions="[]",
            supported_triggers="[]", auth_type="api_key", config_schema="{}",
        )
        db.add(connector)
        await db.flush()
    integ = InstalledIntegration(
        organization_id=org_id, connector_id=connector.id, display_name=f"{name} prod",
        config_encrypted=json.dumps({"base_url": base_url}),
        auth_credentials_encrypted="__plaintext__:" + json.dumps(credentials or {"api_key": "okta-test-token"}),
        status="active", health_status="healthy",
    )
    db.add(integ)
    await db.commit()
    return integ.id


def _okta_users() -> list[dict[str, Any]]:
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    return [
        {"id": "00u1", "status": "ACTIVE", "lastLogin": recent, "passwordChanged": old,
         "profile": {"login": "ada@corp.io", "email": "ada@corp.io", "firstName": "Ada", "lastName": "L"}},
        {"id": "00u2", "status": "ACTIVE", "lastLogin": old,
         "profile": {"login": "bert@corp.io", "email": "bert@corp.io", "displayName": "Bert"}},
        {"id": "00u3", "status": "ACTIVE", "profile": {"login": "", "email": "nobody"}},
    ]


def _okta_handler(request: httpx.Request) -> httpx.Response:
    assert request.headers["host"] == "acme.okta.com"
    assert request.headers["authorization"] == "SSWS okta-test-token"
    assert request.url.host == PUBLIC_IP
    path = request.url.path
    users = _okta_users()
    if path == "/api/v1/iam/assignees/users":
        return httpx.Response(200, json={"value": [{"id": "00u1"}]})
    if path == "/api/v1/users" and "after" not in request.url.params:
        return httpx.Response(200, json=users[:1],
                              headers={"link": f'<{OKTA}/api/v1/users?after=00u1&limit=200>; rel="next"'})
    if path == "/api/v1/users":
        return httpx.Response(200, json=users[1:])
    if path == "/api/v1/users/00u1/factors":
        return httpx.Response(200, json=[{"factorType": "token:software:totp", "status": "ACTIVE"}])
    if path.endswith("/factors"):
        return httpx.Response(200, json=[])
    if path.endswith("/lifecycle/suspend") and request.method == "POST":
        return httpx.Response(200, json={})
    return httpx.Response(404, json={"errorSummary": f"unexpected {request.method} {path}"})


def _csv(rows: list[str]) -> dict[str, Any]:
    return {"file": ("identities.csv", ("\n".join(rows) + "\n").encode(), "text/csv")}


def _log(org_id: str, *, at: datetime, received: datetime, username: str, outcome: str,
         source: str = "203.0.113.10") -> LogEntry:
    return LogEntry(
        id=str(uuid.uuid4()), timestamp=at.isoformat(), received_at=received.isoformat(),
        source_type="syslog", source_name="idp", source_ip="192.0.2.1", log_type="authentication",
        severity="informational", raw_log="auth", username=username, action="login", outcome=outcome,
        source_address=source, organization_id=org_id,
    )


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------


async def test_csv_import_accepts_ad_exports_and_reports_bad_rows(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_admin_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    rows = [
        "SamAccountName,UserPrincipalName,DisplayName,Enabled,LastLogonDate,MemberOf,MFA",
        "jdoe,jdoe@corp.io,John Doe,True,2026-10-01T08:00:00Z,Domain Users;Domain Admins,yes",
        "asmith,asmith@corp.io,Ann Smith,False,,Domain Users,no",
        "broken,not-an-email,Broken,True,,,no",
        "jdoe,jdoe2@corp.io,Dup,True,,,no",
        "badtime,bt@corp.io,Bad,True,yesterday,,no",
    ]
    dry = await client.post(f"{API}/identities/import", params={"dry_run": "true"},
                            files=_csv(rows), headers=org_a_admin_headers)
    assert dry.status_code == 200, dry.text
    assert dry.json()["valid_rows"] == 2 and dry.json()["created"] == 0
    assert (await db_session.execute(select(func.count()).select_from(IdentityProfile))).scalar() == 0

    resp = await client.post(f"{API}/identities/import", files=_csv(rows), headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rows_read"] == 5 and body["valid_rows"] == 2 and body["invalid_rows"] == 3
    assert body["created"] == 2 and body["updated"] == 0
    assert sorted(e["line"] for e in body["errors"]) == [4, 5, 6]
    assert body["columns"]["username"] == "SamAccountName"

    ids = {
        i.username: i for i in (await db_session.execute(
            select(IdentityProfile).where(IdentityProfile.organization_id == org_id)
        )).scalars().all()
    }
    jdoe = ids["jdoe"]
    assert jdoe.privilege_level == "admin" and jdoe.mfa_enabled is True
    assert jdoe.source == "csv_import" and jdoe.identity_provider == "active_directory"
    assert jdoe.account_status == "enabled" and jdoe.last_authentication.startswith("2026-10-01T08:00:00")
    assert ids["asmith"].account_status == "disabled"
    jdoe_id = jdoe.id

    again = await client.post(f"{API}/identities/import", files=_csv(rows[:2]), headers=org_a_admin_headers)
    assert again.json()["updated"] == 1 and again.json()["created"] == 0

    await assert_tenant_isolated(client, "GET", f"{API}/identities/{jdoe_id}", org_b_headers)


async def test_csv_import_rejects_bad_files_and_non_admins(
    client: AsyncClient, org_a: Organization, org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str], viewer_headers: dict[str, str],
) -> None:
    good = _csv(["username,email", "x,x@corp.io"])
    for headers in (viewer_headers, org_a_headers):
        assert (await client.post(f"{API}/identities/import", files=good, headers=headers)).status_code == 403

    missing = await client.post(f"{API}/identities/import", files=_csv(["name,dept", "a,b"]),
                                headers=org_a_admin_headers)
    assert missing.status_code == 422 and missing.json()["detail"]["error"] == "invalid_csv"

    none_valid = await client.post(f"{API}/identities/import", files=_csv(["username,email", "a,nope"]),
                                   headers=org_a_admin_headers)
    assert none_valid.status_code == 422 and none_valid.json()["detail"]["error"] == "no_valid_rows"


# ---------------------------------------------------------------------------
# Directory sync
# ---------------------------------------------------------------------------


async def test_okta_sync_creates_identities_through_the_guard(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_b: Organization,
    org_a_admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)

    resp = await client.post(f"{API}/identities/sync", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    result = resp.json()["integrations"][0]
    assert result["status"] == "ok" and result["provider"] == "okta"
    assert (result["fetched"], result["created"], result["skipped"]) == (3, 2, 1)
    assert any(r.url.params.get("after") == "00u1" for r in calls)  # followed the Link header

    rows = {
        i.username: i for i in (await db_session.execute(
            select(IdentityProfile).where(IdentityProfile.organization_id == org_id)
        )).scalars().all()
    }
    ada, bert = rows["ada@corp.io"], rows["bert@corp.io"]
    assert ada.user_id == "00u1" and ada.source == "okta" and ada.source_integration_id == integration_id
    assert ada.privilege_level == "admin" and ada.mfa_enabled is True and ada.mfa_methods == ["token:software:totp"]
    assert ada.is_dormant is False and ada.account_status == "ACTIVE" and ada.display_name == "Ada L"
    assert bert.privilege_level == "standard" and bert.mfa_enabled is False and bert.is_dormant is True

    # Nothing landed in another tenant; the run is recorded.
    assert (await db_session.execute(
        select(func.count()).select_from(IdentityProfile).where(IdentityProfile.organization_id == org_b.id)
    )).scalar() == 0
    sources = (await client.get(f"{API}/identity-sources", headers=org_a_admin_headers)).json()
    assert sources["integrations"][0]["provider"] == "okta"
    assert sources["identities_by_source"] == {"okta": 2}
    job = next(j for j in sources["jobs"] if j["job"] == f"itdr_sync:{integration_id}")
    assert job["status"] == "ok" and job["last_run_rows"] == 3

    # Re-sync updates in place.
    again = (await client.post(f"{API}/identities/sync", headers=org_a_admin_headers)).json()
    assert again["integrations"][0]["created"] == 0 and again["integrations"][0]["updated"] == 2


async def test_entra_sync_falls_back_when_graph_permissions_are_missing(
    db_session: AsyncSession, org_a: Organization, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.itdr.tasks import sync_org_directories

    org_id = org_a.id
    await _okta_integration(db_session, org_id, "https://graph.microsoft.com", name="azure_ad", credentials={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "app", "client_secret": "s3cret"})
    _dns(monkeypatch)

    def graph(request: httpx.Request) -> httpx.Response:
        host, path = request.headers["host"], request.url.path
        if host == "login.microsoftonline.com":
            assert path == "/contoso.onmicrosoft.com/oauth2/v2.0/token"
            assert b"client_credentials" in request.content
            return httpx.Response(200, json={"access_token": "graph-token"})
        assert host == "graph.microsoft.com" and request.headers["authorization"] == "Bearer graph-token"
        if path.endswith("userRegistrationDetails"):
            return httpx.Response(403, json={"error": {"message": "Authorization_RequestDenied"}})
        if path == "/v1.0/users" and "signInActivity" in request.url.params.get("$select", ""):
            return httpx.Response(403, json={"error": {"message": "needs AuditLog.Read.All"}})
        if path == "/v1.0/users":
            return httpx.Response(200, json={"value": [{
                "id": "aad-1", "userPrincipalName": "zoe@contoso.com", "mail": "zoe@contoso.com",
                "displayName": "Zoe", "accountEnabled": False, "lastPasswordChangeDateTime": "2026-01-02T03:04:05Z",
            }]})
        return httpx.Response(404)

    _idp(monkeypatch, graph)
    result = await sync_org_directories(db_session, org_id)
    entry = result["integrations"][0]
    assert entry["status"] == "ok" and entry["created"] == 1 and entry["mfa_unchecked"] == 1
    assert len(entry["warnings"]) == 2
    zoe = (await db_session.execute(
        select(IdentityProfile).where(IdentityProfile.organization_id == org_id)
    )).scalars().one()
    assert zoe.identity_provider == "azure_ad" and zoe.account_status == "disabled"
    assert zoe.mfa_enabled is False  # unknown: left at the stored default, counted as mfa_unchecked
    assert zoe.last_password_change.startswith("2026-01-02T03:04:05")


async def test_sync_refuses_internal_targets_and_needs_an_integration(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    resp = await client.post(f"{API}/identities/sync", headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "no_identity_integration"
    assert (await client.post(f"{API}/identities/sync", headers=org_a_headers)).status_code == 403

    integration_id = await _okta_integration(db_session, org_id)
    _dns(monkeypatch, ip="10.0.0.5")
    calls = _idp(monkeypatch, _okta_handler)
    body = (await client.post(f"{API}/identities/sync", headers=org_a_admin_headers)).json()
    result = body["integrations"][0]
    assert result["status"] == "failed" and "internal address" in result["error"]
    assert calls == []
    row = (await db_session.execute(
        select(LogIngestCursor).where(LogIngestCursor.consumer == f"itdr_sync:{integration_id}")
    )).scalars().one()
    assert row.last_run_status == "failed"


# ---------------------------------------------------------------------------
# Identity-provider actions and threat response
# ---------------------------------------------------------------------------


async def test_identity_action_reaches_okta_or_reports_awaiting_integration(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    okta_user = IdentityProfile(organization_id=org_id, user_id="00u2", username="bert@corp.io",
                                email="bert@corp.io", identity_provider="okta", source="okta",
                                source_integration_id=integration_id)
    ad_user = IdentityProfile(organization_id=org_id, user_id="carl", username="carl", email="carl@corp.io",
                              identity_provider="active_directory", source="csv_import")
    db_session.add_all([okta_user, ad_user])
    await db_session.commit()
    okta_id, ad_id = okta_user.id, ad_user.id
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)

    assert (await client.post(f"{API}/identities/{okta_id}/actions/disable_account",
                              headers=org_a_headers)).status_code == 403

    resp = await client.post(f"{API}/identities/{okta_id}/actions/disable_account", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "executed" and body["provider"] == "okta"
    assert [c.url.path for c in calls] == ["/api/v1/users/00u2/lifecycle/suspend"]
    await db_session.refresh(okta_user)
    assert okta_user.account_status == "SUSPENDED"

    resp = await client.post(f"{API}/identities/{ad_id}/actions/force_password_reset", headers=org_a_admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "awaiting_integration" and "Active Directory" in body["missing_dependency"]
    assert len(calls) == 1  # nothing was sent for the AD account

    audits = (await db_session.execute(
        select(AuditLog).where(AuditLog.resource_type == "identity_profile")
    )).scalars().all()
    assert {(a.resource_id, a.success) for a in audits} == {(okta_id, True), (ad_id, False)}
    assert all("okta-test-token" not in (a.new_value or "") for a in audits)

    bad = await client.post(f"{API}/identities/{okta_id}/actions/delete_everything", headers=org_a_admin_headers)
    assert bad.status_code == 400


async def test_identity_action_provider_failure_is_a_502(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident = IdentityProfile(organization_id=org_id, user_id="00u9", username="dora@corp.io", email="dora@corp.io",
                            identity_provider="okta", source_integration_id=integration_id)
    db_session.add(ident)
    await db_session.commit()
    ident_id = ident.id
    _dns(monkeypatch)
    _idp(monkeypatch, lambda r: httpx.Response(403, json={"errorSummary": "You do not have permission"}))
    resp = await client.post(f"{API}/identities/{ident_id}/actions/disable_account", headers=org_a_admin_headers)
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert detail["error"] == "identity_provider_failed"
    assert "HTTP 403" in detail["result"]["error"] and "permission" in detail["result"]["error"]


async def _responder(db: AsyncSession, org_id: str) -> None:
    db.add(SOCAgent(organization_id=org_id, name="ITDR responder", agent_type="triage_analyst", llm_model="fake-1"))
    await db.commit()


async def test_respond_never_calls_the_identity_provider_outside_the_guarded_path(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_admin_headers: dict[str, str], org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Coordinator security review: provider actions only through the policy gate.

    The respond surface proposes the guarded ``identity_provider_action``
    tool (in place of ``disable_user``) and reports the provider step as
    proposed; an analyst is refused outright. The provider is never contacted
    until an approver executes the proposal (tests/unit/test_itdr_identity_tool.py).
    """
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident = IdentityProfile(organization_id=org_id, user_id="00u2", username="bert@corp.io", email="bert@corp.io",
                            identity_provider="okta", source_integration_id=integration_id)
    db_session.add(ident)
    db_session.add(User(email="bert@corp.io", hashed_password="x", full_name="Bert", role="viewer",
                        is_active=True, organization_id=org_id))
    await db_session.flush()
    threat = IdentityThreat(organization_id=org_id, identity_id=ident.id, threat_type="brute_force",
                            severity="high", confidence_score=70.0, status="detected")
    db_session.add(threat)
    await db_session.commit()
    threat_id, ident_id = threat.id, ident.id
    await _responder(db_session, org_id)
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)

    analyst = await client.post(f"{API}/threats/{threat_id}/respond", headers=org_a_headers,
                                json={"action_type": "disable_account", "action_details": {"propose_actions": True}})
    assert analyst.status_code == 403
    assert calls == []

    resp = await client.post(f"{API}/threats/{threat_id}/respond", headers=org_a_admin_headers,
                             json={"action_type": "disable_account", "action_details": {"propose_actions": True}})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is False and body["proposed"] is True
    assert body["proposal"]["tool"] == "identity_provider_action"
    assert body["proposal"]["args"]["identity_id"] == ident_id
    assert body["proposal"]["args"]["action"] == "disable_account"
    idp = body["identity_provider"]
    assert idp["status"] == "proposed" and idp["integration_id"] == integration_id
    assert idp["tool"] == "identity_provider_action" and idp["proposal_id"] == body["proposal"]["id"]
    assert body["threat_status"] == "detected"
    assert calls == []
    assert (await db_session.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.resource_type == "identity_profile")
    )).scalar() == 0


async def test_unattended_callers_cannot_run_identity_provider_actions(
    db_session: AsyncSession, org_a: Organization, monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org_a.id
    integration_id = await _okta_integration(db_session, org_id)
    ident = IdentityProfile(organization_id=org_id, user_id="00u2", username="bert@corp.io", email="bert@corp.io",
                            identity_provider="okta", source_integration_id=integration_id)
    db_session.add(ident)
    await db_session.commit()
    _dns(monkeypatch)
    calls = _idp(monkeypatch, _okta_handler)
    with pytest.raises(PermissionError):
        await directory.run_identity_action(db_session, org_id, ident, "disable_account",
                                            actor_user_id=None, reason="task")
    assert calls == []


async def test_respond_without_identity_provider_reports_awaiting_integration(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    ident = IdentityProfile(organization_id=org_id, user_id="erin", username="erin", email="erin@corp.io",
                            identity_provider="active_directory", source="csv_import")
    db_session.add(ident)
    db_session.add(User(email="erin@corp.io", hashed_password="x", full_name="Erin", role="viewer",
                        is_active=True, organization_id=org_id))
    await db_session.flush()
    threat = IdentityThreat(organization_id=org_id, identity_id=ident.id, threat_type="brute_force",
                            severity="high", confidence_score=70.0, status="detected")
    db_session.add(threat)
    await db_session.commit()
    threat_id = threat.id
    await _responder(db_session, org_id)

    resp = await client.post(f"{API}/threats/{threat_id}/respond", headers=org_a_admin_headers,
                             json={"action_type": "disable_account", "action_details": {"propose_actions": True}})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["identity_provider"]["status"] == "awaiting_integration"
    assert "Active Directory" in body["identity_provider"]["missing_dependency"]
    assert body["proposed"] is True and body["proposal"]["tool"] == "disable_user"
    assert body["threat_status"] == "detected"


# ---------------------------------------------------------------------------
# Auth-event analysis
# ---------------------------------------------------------------------------


async def test_auth_events_build_baselines_anomalies_and_threats(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_id = org_a.id
    gina = IdentityProfile(organization_id=org_id, user_id="gina", username="gina", email="gina@corp.io")
    hank = IdentityProfile(organization_id=org_id, user_id="hank", username="hank", email="hank@corp.io",
                           is_dormant=True)
    other = IdentityProfile(organization_id=org_b.id, user_id="gina", username="gina", email="gina@corp.io")
    db_session.add_all([gina, hank, other])
    first: list[LogEntry] = [
        _log(org_id, at=NOW.replace(hour=9, minute=5) - timedelta(days=d), received=NOW - timedelta(minutes=50),
             username="gina", outcome="success")
        for d in range(1, 26)
    ]
    db_session.add_all(first)
    await db_session.commit()
    gina_id, hank_id, other_id = gina.id, hank.id, other.id

    run1 = await analyze_auth_events_for_org(db_session, org_id, now=NOW)
    assert run1["auth_rows"] == 25 and run1["identities_matched"] == 1 and run1["anomalies_created"] == 0
    await db_session.refresh(gina)
    assert gina.auth_baseline["success_total"] == 25
    assert gina.auth_baseline["hour_counts"] == {"9": 25}
    assert gina.auth_baseline["source_counts"] == {"203.0.113.10": 25}

    late = NOW - timedelta(minutes=10)
    second = [
        _log(org_id, at=NOW.replace(hour=3, minute=0), received=late, username="GINA@corp.io",
             outcome="success", source="198.51.100.99"),
        _log(org_id, at=NOW.replace(hour=4, minute=0), received=late, username="hank", outcome="success"),
    ]
    second += [_log(org_id, at=NOW.replace(hour=10, minute=i), received=late, username="gina", outcome="failure")
               for i in range(12)]
    second += [_log(org_id, at=NOW.replace(hour=11, minute=i), received=late, username=f"user{i}",
                    outcome="failure", source="192.0.2.200") for i in range(5)]
    db_session.add_all(second)
    await db_session.commit()

    run2 = await analyze_auth_events_for_org(db_session, org_id, now=NOW)
    assert run2["unmatched_names"] == 5
    anomalies = {
        (a.identity_id, a.anomaly_type): a for a in (await db_session.execute(
            select(AccessAnomaly).where(AccessAnomaly.organization_id == org_id)
        )).scalars().all()
    }
    assert set(anomalies) == {
        (gina_id, "unusual_location"), (gina_id, "unusual_time"), (hank_id, "dormant_activation"),
    }
    loc = anomalies[(gina_id, "unusual_location")]
    assert loc.observed_data["source_address"] == "198.51.100.99"
    assert loc.deviation_score == round(100 * (1 - 1 / 26), 1)

    threats = {
        t.threat_type: t for t in (await db_session.execute(
            select(IdentityThreat).where(IdentityThreat.organization_id == org_id)
        )).scalars().all()
    }
    brute = threats["brute_force"]
    assert brute.identity_id == gina_id and brute.mitre_technique_id == "T1110.001"
    assert brute.evidence["failures_in_hour"] == 12 and brute.confidence_score == 54.0
    spray = threats["password_spray"]
    assert spray.identity_id is None and spray.source_ip == "192.0.2.200"
    assert spray.evidence["distinct_names"] == 5

    await db_session.refresh(gina)
    await db_session.refresh(hank)
    assert hank.is_dormant is False
    assert gina.last_authentication == NOW.replace(hour=3, minute=0).isoformat()
    # 1 medium threat (5) + 2 unreviewed anomalies (3 each)
    assert gina.risk_score == 11.0

    # Org B's identity with the same name was never touched.
    other_row = await db_session.get(IdentityProfile, other_id)
    await db_session.refresh(other_row)
    assert other_row.auth_baseline is None

    # Nothing new: the cursor does not re-read, no duplicate rows.
    run3 = await analyze_auth_events_for_org(db_session, org_id, now=NOW)
    assert run3["status"] == "idle"
    assert (await db_session.execute(
        select(func.count()).select_from(AccessAnomaly).where(AccessAnomaly.organization_id == org_id)
    )).scalar() == 3


async def test_credential_monitoring_matches_only_own_leaks(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_id, org_b_id = org_a.id, org_b.id
    ident = IdentityProfile(organization_id=org_id, user_id="ivy", username="ivy", email="ivy@corp.io")
    db_session.add(ident)
    db_session.add_all([
        CredentialLeak(organization_id=org_id, finding_id=str(uuid.uuid4()), email="IVY@corp.io",
                       password_type="hash", breach_source="BreachOne", breach_date="2026-01-01"),
        CredentialLeak(organization_id=org_id, finding_id=str(uuid.uuid4()), username="ivy",
                       password_type="hash", breach_source="BreachTwo"),
        CredentialLeak(organization_id=org_b_id, finding_id=str(uuid.uuid4()), email="ivy@corp.io",
                       password_type="hash", breach_source="OtherTenantBreach"),
    ])
    await db_session.commit()
    ident_id = ident.id

    result = await check_credential_exposures_for_org(db_session, org_id)
    assert result["exposures_created"] == 2 and result["identities_affected"] == 1
    breaches = sorted((await db_session.execute(
        select(CredentialExposure.breach_name).where(CredentialExposure.identity_id == ident_id)
    )).scalars().all())
    assert breaches == ["BreachOne", "BreachTwo"]
    assert (await check_credential_exposures_for_org(db_session, org_id))["exposures_created"] == 0
    await db_session.refresh(ident)
    assert ident.risk_score == 10.0


async def test_check_all_route_is_operational_write(
    client: AsyncClient, org_a: Organization, org_a_headers: dict[str, str], viewer_headers: dict[str, str],
) -> None:
    assert (await client.post(f"{API}/credential-exposures/check-all", headers=viewer_headers)).status_code == 403
    resp = await client.post(f"{API}/credential-exposures/check-all", headers=org_a_headers)
    assert resp.status_code == 200 and resp.json()["exposures_created"] == 0


# ---------------------------------------------------------------------------
# Dashboard metrics from rows
# ---------------------------------------------------------------------------


async def test_dashboard_metrics_are_computed_from_rows(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    empty = (await client.get(f"{API}/dashboard/metrics", headers=org_a_headers)).json()
    assert empty["last_scan_timestamp"] is None
    assert empty["mfa_coverage_percent"] is None
    assert empty["service_accounts_over_privileged"] == 0

    org_id = org_a.id
    db_session.add_all([
        IdentityProfile(organization_id=org_id, user_id="svc1", username="svc1", email="svc1@corp.io",
                        is_service_account=True, privilege_level="admin", mfa_enabled=False, source="okta"),
        IdentityProfile(organization_id=org_id, user_id="svc2", username="svc2", email="svc2@corp.io",
                        is_service_account=True, privilege_level="standard", mfa_enabled=True, source="okta"),
        IdentityProfile(organization_id=org_id, user_id="u1", username="u1", email="u1@corp.io",
                        mfa_enabled=True, source="csv_import"),
    ])
    await db_session.commit()
    scan = await client.post(f"{API}/threats/scan", json={}, headers=org_a_headers)
    assert scan.status_code == 200, scan.text

    body = (await client.get(f"{API}/dashboard/metrics", headers=org_a_headers)).json()
    assert body["total_identities"] == 3
    assert body["service_accounts_over_privileged"] == 1
    assert body["privileged_identities"] == 1
    assert body["identities_with_mfa"] == 2 and body["mfa_coverage_percent"] == 66.7
    assert body["identities_by_source"] == {"okta": 2, "csv_import": 1}
    assert body["last_scan_timestamp"] is not None
    # The scan raised mfa_missing_privileged (critical) for svc1: active and counted.
    assert body["critical_threats_active"] == 1 and body["active_threats_total"] >= 1
    threat = (await db_session.execute(
        select(IdentityThreat).where(IdentityThreat.threat_type == "mfa_missing_privileged")
    )).scalars().one()
    threat.status = "resolved"
    await db_session.commit()
    after = (await client.get(f"{API}/dashboard/metrics", headers=org_a_headers)).json()
    assert after["critical_threats_active"] == 0


# ---------------------------------------------------------------------------
# Celery wiring
# ---------------------------------------------------------------------------


def test_itdr_ingestion_tasks_are_scheduled() -> None:
    from src.workers.celery_app import celery_app

    celery_app.loader.import_default_modules()
    names = {
        "src.itdr.tasks.sync_identity_directories",
        "src.itdr.tasks.analyze_identity_auth_events",
        "src.itdr.tasks.check_identity_credential_exposures",
    }
    assert names <= set(celery_app.tasks)
    scheduled = {e["task"] for e in celery_app.conf.beat_schedule.values()}
    assert names <= scheduled
    for name in names:
        limits = celery_app.conf.task_annotations[name]
        assert limits["time_limit"] < celery_app.conf.task_time_limit


async def test_sweep_task_runs_each_org_in_its_own_session(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    from src.core.database import async_session_factory
    from src.itdr.tasks import _analyze_identity_auth_events_async, _sync_identity_directories_async

    totals = await _analyze_identity_auth_events_async(session_factory=async_session_factory)
    assert totals["status"] == "completed" and totals["organizations"] >= 2
    sync = await _sync_identity_directories_async(session_factory=async_session_factory)
    # No organisation has an identity integration: nothing to sync, nothing invented.
    assert sync["results"] == [] and sync["failed_organizations"] == 0


# ---------------------------------------------------------------------------
# Migration 027
# ---------------------------------------------------------------------------

from tests.unit.test_migration_020 import (  # noqa: E402
    REPO_ROOT,
    _alembic_config,
    _async_url,
    _columns,
    _downgrade,
    _engine,
    _in_thread,
    _real_alembic,
    _sync_url,
    _upgrade,
    _version,
)

MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "027_ueba_itdr_ingestion.py"


def _load_migration() -> ModuleType:
    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_027_ueba_itdr_ingestion", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration()


def _pre027_metadata() -> MetaData:
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name == migration.CURSORS:
            continue
        removed = set(migration.NEW_IDENTITY_COLUMNS) if table.name == migration.IDENTITIES else set()
        columns = [c._copy() for c in table.columns if c.name not in removed]
        for column in columns:
            column.index = None
            column.unique = None
        Table(table.name, md, *columns)
    return md


@pytest.fixture
def fixture_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    db_path = tmp_path / "pysoar_027.db"
    engine = create_engine(_sync_url(db_path))
    _pre027_metadata().create_all(engine)
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "026"))
    return {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}


def test_revision_027_revises_026() -> None:
    assert migration.revision == "027" and migration.down_revision == "026"


def test_migration_027_round_trip(fixture_db: dict[str, Any]) -> None:
    with _engine(fixture_db).connect() as conn:
        assert not set(migration.NEW_IDENTITY_COLUMNS) & _columns(conn, migration.IDENTITIES)
        assert not sa.inspect(conn).has_table(migration.CURSORS)

    _upgrade(fixture_db, "027")
    assert _version(fixture_db) == "027"
    with _engine(fixture_db).connect() as conn:
        assert set(migration.NEW_IDENTITY_COLUMNS) <= _columns(conn, migration.IDENTITIES)
        assert {c.name for c in LogIngestCursor.__table__.columns} == _columns(conn, migration.CURSORS)

    _downgrade(fixture_db, "026")
    assert _version(fixture_db) == "026"
    with _engine(fixture_db).connect() as conn:
        assert not set(migration.NEW_IDENTITY_COLUMNS) & _columns(conn, migration.IDENTITIES)
        assert not sa.inspect(conn).has_table(migration.CURSORS)

    _upgrade(fixture_db, "027")  # idempotent re-apply
    assert _version(fixture_db) == "027"
