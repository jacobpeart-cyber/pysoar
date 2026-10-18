"""Okta, Microsoft Entra ID, Microsoft Defender for Endpoint and Microsoft
Teams connectors: documented requests, honest connection tests, refusals
before any request.

Vendor HTTP is faked at the network boundary (tests/unit/connector_fakes.py);
the fake bodies follow the response shapes in each vendor's API reference.
No live tenant was used.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from src.integrations.connectors.base import ConnectionTestResult
from src.integrations.engine import (
    BUILTIN_CONNECTORS,
    CONNECTOR_CLASS_MAP,
    IMPLEMENTED,
    implementation_status,
    invalid_install_fields,
    probe_connector,
)
from tests.unit.connector_fakes import PUBLIC_IP, VALID_FIELDS, fake_vendor, host_header

NAMES = ("okta", "azure_ad", "microsoft_defender", "microsoft_teams")
SECRETS = {
    "okta": ["okta-fixture-token-0001"],
    "azure_ad": ["entra-fixture-secret-0001"],
    "microsoft_defender": ["mde-fixture-secret-0001"],
    "microsoft_teams": [VALID_FIELDS["microsoft_teams"][1]["webhook_url"], "fixture-sig-0001"],
}
GRAPH_TOKEN = "graph-access-token-0001"
MDE_TOKEN = "mde-access-token-0001"
USER_GUID = "6e7b768e-07e2-4810-8459-485f84f8f204"
MACHINE_ID = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07"
ACTION_GUID = "2e9da30d-27f6-4208-81f2-9cd3d67893ba"


def _connector(name: str, **credential_overrides: Any):
    config, credentials = VALID_FIELDS[name]
    return CONNECTOR_CLASS_MAP[name](config=dict(config), credentials={**credentials, **credential_overrides})


def _no_secret(name: str, payload: Any) -> None:
    text = json.dumps(payload.to_dict() if isinstance(payload, ConnectionTestResult) else payload, default=str)
    for secret in SECRETS[name]:
        assert secret not in text, f"{name}: secret leaked in {text}"


def _json(request: httpx.Request) -> Any:
    return json.loads(request.content.decode()) if request.content else None


def _microsoft(token: str, api: Callable[[httpx.Request], httpx.Response]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if host_header(request) == "login.microsoftonline.com":
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": token})
        return api(request)

    return handler


def _refuse_everything(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"no request expected, got {request.method} {request.url}")


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_registered_as_implemented_with_honest_catalogue() -> None:
    for name in NAMES:
        assert implementation_status(name) == IMPLEMENTED
        cls = CONNECTOR_CLASS_MAP[name]
        assert cls.VERIFICATION == "implemented from the vendor's public API documentation; not verified against a live tenant"
        assert cls.name == name
    assert BUILTIN_CONNECTORS["azure_ad"]["display_name"] == "Microsoft Entra ID (Azure AD)"
    side_effects = {
        name: sorted(a for a, spec in CONNECTOR_CLASS_MAP[name].ACTIONS.items() if spec.side_effect) for name in NAMES
    }
    assert side_effects["okta"] == sorted(
        ["suspend_user", "unsuspend_user", "deactivate_user", "revoke_sessions", "expire_password", "reset_factor"]
    )
    assert "get_user" not in side_effects["azure_ad"] and "disable_user" in side_effects["azure_ad"]
    assert "isolate_machine" in side_effects["microsoft_defender"] and "get_machine" not in side_effects["microsoft_defender"]
    assert side_effects["microsoft_teams"] == ["send_alert_notification", "send_message"]
    # Each Entra / Defender action names the application permission it needs.
    for name in ("azure_ad", "microsoft_defender"):
        for action, spec in CONNECTOR_CLASS_MAP[name].ACTIONS.items():
            assert "Permission:" in spec.description, f"{name}.{action}"
    assert "privileged" in CONNECTOR_CLASS_MAP["azure_ad"].ACTIONS["reset_password"].description


# --------------------------------------------------------------------------
# Connection tests
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_okta_connection_healthy(monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda r: httpx.Response(
        200, json=[{"id": "00u1", "status": "ACTIVE", "profile": {"login": "ada@corp.io"}}],
        headers={"x-rate-limit-limit": "600", "x-rate-limit-remaining": "599", "x-rate-limit-reset": "1760000000"},
    ))
    connector = _connector("okta")
    result = await connector.test_connection()
    assert result.status == "healthy" and result.checked == "GET /api/v1/users?limit=1"
    (req,) = seen
    assert req.method == "GET" and req.url.path == "/api/v1/users" and req.url.params["limit"] == "1"
    assert host_header(req) == "acme.okta.com" and req.url.host == PUBLIC_IP
    assert req.headers["authorization"] == "SSWS okta-fixture-token-0001"
    assert connector.rate_limit.remaining == 599 and connector.rate_limit.limit == 600
    _no_secret("okta", result)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["azure_ad", "microsoft_defender"])
async def test_microsoft_connection_healthy_token_is_form_encoded(monkeypatch, name: str) -> None:
    token, host, path, body = {
        "azure_ad": (GRAPH_TOKEN, "graph.microsoft.com", "/v1.0/organization",
                     {"value": [{"id": "84841066-274d-4ec0-a5c1-276be684bdd3", "displayName": "Contoso"}]}),
        "microsoft_defender": (MDE_TOKEN, "api.securitycenter.microsoft.com", "/api/machines",
                               {"value": [{"id": MACHINE_ID, "computerDnsName": "ws1.contoso.com"}]}),
    }[name]
    seen = fake_vendor(monkeypatch, _microsoft(token, lambda r: httpx.Response(200, json=body)))
    result = await _connector(name).test_connection()

    assert result.status == "healthy", result
    token_req, api_req = seen
    assert token_req.method == "POST" and token_req.url.path == "/contoso.onmicrosoft.com/oauth2/v2.0/token"
    assert token_req.headers["content-type"].startswith("application/x-www-form-urlencoded")
    form = dict(httpx.QueryParams(token_req.content.decode()))
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == VALID_FIELDS[name][1]["client_id"]
    assert form["scope"] == {
        "azure_ad": "https://graph.microsoft.com/.default",
        "microsoft_defender": "https://api.securitycenter.microsoft.com/.default",
    }[name]
    assert "authorization" not in token_req.headers
    assert host_header(api_req) == host and api_req.url.path == path
    assert api_req.headers["authorization"] == f"Bearer {token}"
    if name == "azure_ad":
        assert api_req.url.params["$select"] == "id,displayName"
    else:
        assert api_req.url.params["$top"] == "1"
    _no_secret(name, result)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [200, 202])
async def test_teams_connection_posts_a_visible_card(monkeypatch, code: int) -> None:
    seen = fake_vendor(monkeypatch, lambda r: httpx.Response(code, text="1" if code == 200 else ""))
    result = await _connector("microsoft_teams").test_connection()
    assert result.status == "healthy" and "visible in the channel" in result.checked
    (req,) = seen
    assert req.method == "POST" and host_header(req) == "acme.webhook.office.com"
    assert "authorization" not in req.headers
    body = _json(req)
    assert body["type"] == "message"
    (attachment,) = body["attachments"]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert attachment["content"]["type"] == "AdaptiveCard"
    assert "PySOAR connection test" in json.dumps(attachment["content"])


@pytest.mark.asyncio
async def test_teams_200_with_error_text_is_unhealthy(monkeypatch) -> None:
    fake_vendor(monkeypatch, lambda r: httpx.Response(
        200, text="Webhook message delivery failed with error: Microsoft Teams endpoint returned HTTP error 413",
    ))
    result = await _connector("microsoft_teams").test_connection()
    assert result.status == "unhealthy" and "413" in result.detail


@pytest.mark.asyncio
@pytest.mark.parametrize("name", NAMES)
async def test_unhealthy_on_401_without_secret(monkeypatch, name: str) -> None:
    secret = SECRETS[name][0]

    def handler(request: httpx.Request) -> httpx.Response:
        # A hostile vendor echoing the credential back must not leak it.
        return httpx.Response(401, json={"error": {"message": f"invalid credential {secret}"}, "errorSummary": secret})

    fake_vendor(monkeypatch, handler)
    result = await _connector(name).test_connection()
    assert result.status == "unhealthy" and result.http_status == 401 and "401" in result.detail
    _no_secret(name, result)


@pytest.mark.asyncio
async def test_microsoft_token_rejection_does_not_leak_the_secret(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_client", "error_description": "AADSTS7000215 entra-fixture-secret-0001"})

    fake_vendor(monkeypatch, handler)
    result = await _connector("azure_ad").test_connection()
    assert result.status == "unhealthy" and result.http_status == 400
    _no_secret("azure_ad", result)


# --------------------------------------------------------------------------
# Field validation refuses before any request
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "config", "credentials", "field"), [
    ("okta", {}, {"domain": "acme.okta.com/evil", "api_token": "t-0001"}, "domain"),
    ("okta", {}, {"domain": "attacker.example@acme.okta.com", "api_token": "t-0001"}, "domain"),
    ("okta", {}, {"domain": "https://acme.okta.com", "api_token": "t-0001"}, "domain"),
    ("okta", {}, {"domain": "acme.okta.com?x=1", "api_token": "t-0001"}, "domain"),
    ("okta", {}, {"domain": "acme.okta.com:8443", "api_token": "t-0001"}, "domain"),
    ("okta", {}, {"domain": "10.0.0.7", "api_token": "t-0001"}, "domain"),
    ("microsoft_teams", {}, {"webhook_url": "https://hooks.example.com/webhook.office.com/x"}, "webhook_url"),
    ("microsoft_teams", {}, {"webhook_url": "http://acme.webhook.office.com/webhookb2/x"}, "webhook_url"),
    ("microsoft_teams", {}, {"webhook_url": "https://webhook.office.com.evil.example/x"}, "webhook_url"),
    ("microsoft_teams", {}, {"webhook_url": "https://user:pw@acme.webhook.office.com/x"}, "webhook_url"),
    ("microsoft_defender", {"geo": "cn"}, dict(VALID_FIELDS["microsoft_defender"][1]), "geo"),
    ("microsoft_defender", {"geo": "evil.example/"}, dict(VALID_FIELDS["microsoft_defender"][1]), "geo"),
    ("azure_ad", {}, {**VALID_FIELDS["azure_ad"][1], "tenant_id": "contoso/../evil"}, "tenant_id"),
])
async def test_invalid_fields_are_refused_before_any_request(monkeypatch, name, config, credentials, field) -> None:
    seen = fake_vendor(monkeypatch, _refuse_everything)
    assert invalid_install_fields(name, config, credentials) == [field]
    if name == "azure_ad":
        # tenant_id is checked when the token URL is built: still before a request.
        result = await CONNECTOR_CLASS_MAP[name](config=config, credentials=credentials).test_connection()
    else:
        with pytest.raises(ValueError) as excinfo:
            CONNECTOR_CLASS_MAP[name](config=config, credentials=credentials)
        assert str(credentials.get(field) or config.get(field)) not in str(excinfo.value)
        result = await probe_connector(name, config, credentials)
    assert result.status == "unhealthy"
    assert seen == []


def test_valid_variants_are_accepted() -> None:
    assert invalid_install_fields("okta", {}, {"domain": "login.acme-corp.com", "api_token": "x"}) == []
    assert invalid_install_fields("okta", {}, {"domain": "acme.oktapreview.com", "api_token": "x"}) == []
    assert invalid_install_fields("microsoft_teams", {}, {
        "webhook_url": "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=x",
    }) == []
    for geo, host in (("", "api.securitycenter.microsoft.com"), ("eu", "api-eu.securitycenter.microsoft.com"),
                      ("us", "api-us.securitycenter.microsoft.com")):
        assert invalid_install_fields("microsoft_defender", {"geo": geo}, dict(VALID_FIELDS["microsoft_defender"][1])) == []
        assert _connector_with_config("microsoft_defender", {"geo": geo}).base_url == f"https://{host}"


def _connector_with_config(name: str, config: dict[str, Any]):
    return CONNECTOR_CLASS_MAP[name](config=config, credentials=dict(VALID_FIELDS[name][1]))


# --------------------------------------------------------------------------
# Okta actions
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_okta_actions_documented_requests(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == "/api/v1/users":
            return httpx.Response(200, json=[{"id": "00u1", "status": "ACTIVE",
                                              "profile": {"login": "ada@corp.io", "email": "ada@corp.io", "firstName": "Ada"}}])
        if request.method == "GET" and request.url.raw_path == b"/api/v1/users/ada%40corp.io":
            return httpx.Response(200, json={"id": "00u1", "status": "ACTIVE", "lastLogin": "2026-10-01T10:00:00.000Z",
                                             "profile": {"login": "ada@corp.io"}})
        if request.method == "GET" and path == "/api/v1/logs":
            return httpx.Response(200, json=[{"uuid": "e-1", "eventType": "user.session.start", "severity": "INFO",
                                              "actor": {"id": "00u1"}, "outcome": {"result": "SUCCESS"},
                                              "client": {"ipAddress": "203.0.113.9"}}])
        if request.method == "GET" and path == "/api/v1/users/00u1/factors":
            return httpx.Response(200, json=[{"id": "mbl1", "factorType": "push", "provider": "OKTA", "status": "ACTIVE"}])
        if request.method == "POST" and path == "/api/v1/users/00u1/lifecycle/suspend":
            return httpx.Response(200, json={})
        if request.method == "DELETE" and path in ("/api/v1/users/00u1/sessions", "/api/v1/users/00u1/factors/mbl1"):
            return httpx.Response(204)
        return httpx.Response(404, json={"errorSummary": "Not found"})

    seen = fake_vendor(monkeypatch, handler)

    out = await _connector("okta").execute_action("search_users", {"search": 'profile.email eq "ada@corp.io"', "limit": 5})
    assert out["user_count"] == 1 and out["users"][0]["login"] == "ada@corp.io"
    assert seen[-1].url.params["search"] == 'profile.email eq "ada@corp.io"' and seen[-1].url.params["limit"] == "5"

    out = await _connector("okta").execute_action("get_user", {"user": "ada@corp.io"})
    assert out["id"] == "00u1" and out["last_login"] == "2026-10-01T10:00:00.000Z"

    out = await _connector("okta").execute_action("list_logs", {"filter": 'actor.id eq "00u1"', "since": "2026-10-01T00:00:00Z"})
    assert out["event_count"] == 1 and out["events"][0]["client_ip"] == "203.0.113.9"
    assert seen[-1].url.params["filter"] == 'actor.id eq "00u1"' and seen[-1].url.params["since"] == "2026-10-01T00:00:00Z"

    out = await _connector("okta").execute_action("list_user_factors", {"user_id": "00u1"})
    assert out["factors"][0]["id"] == "mbl1"

    out = await _connector("okta").execute_action("suspend_user", {"user_id": "00u1"})
    assert out["status"] == "SUSPENDED"
    assert seen[-1].method == "POST" and seen[-1].url.path == "/api/v1/users/00u1/lifecycle/suspend"

    out = await _connector("okta").execute_action("revoke_sessions", {"user_id": "00u1", "oauth_tokens": True})
    assert out["revoked"] is True
    assert seen[-1].method == "DELETE" and seen[-1].url.path == "/api/v1/users/00u1/sessions"
    assert seen[-1].url.params["oauthTokens"] == "true"

    out = await _connector("okta").execute_action("reset_factor", {"user_id": "00u1", "factor_id": "mbl1"})
    assert out["removed"] is True and seen[-1].method == "DELETE"

    for req in seen:
        assert req.headers["authorization"] == "SSWS okta-fixture-token-0001"
        assert host_header(req) == "acme.okta.com"


@pytest.mark.asyncio
async def test_okta_vendor_error_is_failed_and_sanitised(monkeypatch) -> None:
    fake_vendor(monkeypatch, lambda r: httpx.Response(403, json={"errorSummary": "You do not have permission okta-fixture-token-0001"}))
    out = await _connector("okta").execute_action("deactivate_user", {"user_id": "00u1"})
    assert out["status"] == "failed" and out["http_status"] == 403
    _no_secret("okta", out)


@pytest.mark.asyncio
async def test_okta_exhausted_rate_limit_is_refused_locally(monkeypatch) -> None:
    import time as _time

    reset = str(int(_time.time()) + 60)
    seen = fake_vendor(monkeypatch, lambda r: httpx.Response(
        200, json=[], headers={"x-rate-limit-remaining": "0", "x-rate-limit-reset": reset},
    ))
    connector = _connector("okta")
    await connector._make_request("GET", "/api/v1/users", params={"limit": 1})
    assert connector.rate_limit.is_exceeded()
    out = await connector.execute_action("list_user_groups", {"user_id": "00u1"})
    assert out["status"] == "failed" and "rate limit" in out["error"]
    assert len(seen) == 1


# --------------------------------------------------------------------------
# Entra ID actions
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entra_actions_documented_requests(monkeypatch) -> None:
    def api(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        assert host_header(request) == "graph.microsoft.com"
        assert request.headers["authorization"] == f"Bearer {GRAPH_TOKEN}"
        if request.method == "GET" and path == f"/v1.0/users/{USER_GUID}":
            return httpx.Response(200, json={"id": USER_GUID, "userPrincipalName": "ada@contoso.com", "accountEnabled": True})
        if request.method == "GET" and path == "/v1.0/users":
            return httpx.Response(200, json={"value": [{"id": USER_GUID, "userPrincipalName": "o'brien@contoso.com"}]})
        if request.method == "GET" and path == "/v1.0/auditLogs/signIns":
            return httpx.Response(200, json={"value": [{"id": "s-1", "createdDateTime": "2026-10-01T10:00:00Z",
                                                        "ipAddress": "203.0.113.9", "status": {"errorCode": 0},
                                                        "location": {"city": "Redmond", "countryOrRegion": "US"}}]})
        if request.method == "PATCH" and path.startswith("/v1.0/users/"):
            return httpx.Response(204)
        if request.method == "POST" and path == f"/v1.0/users/{USER_GUID}/revokeSignInSessions":
            return httpx.Response(200, json={"value": True})
        if request.method == "POST" and path == "/v1.0/identityProtection/riskyUsers/confirmCompromised":
            return httpx.Response(204)
        return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound", "message": "not found"}})

    seen = fake_vendor(monkeypatch, _microsoft(GRAPH_TOKEN, api))
    api_calls = lambda: [r for r in seen if host_header(r) == "graph.microsoft.com"]  # noqa: E731

    out = await _connector("azure_ad").execute_action("get_user", {"user": USER_GUID})
    assert out["accountEnabled"] is True
    assert api_calls()[-1].url.params["$select"] == "id,userPrincipalName,displayName,accountEnabled,mail,jobTitle,department"

    out = await _connector("azure_ad").execute_action("search_users", {"query": "o'brien", "top": 5})
    assert out["user_count"] == 1
    assert api_calls()[-1].url.params["$filter"] == "startswith(displayName,'o''brien') or startswith(userPrincipalName,'o''brien')"
    assert api_calls()[-1].url.params["$top"] == "5"

    out = await _connector("azure_ad").execute_action("list_sign_ins", {"user_id": USER_GUID, "top": 10})
    assert out["sign_ins"][0]["location"] == "Redmond, US"
    assert api_calls()[-1].url.params["$filter"] == f"userId eq '{USER_GUID}'"

    out = await _connector("azure_ad").execute_action("disable_user", {"user": USER_GUID})
    assert out["account_enabled"] is False
    req = api_calls()[-1]
    assert req.method == "PATCH" and req.url.path == f"/v1.0/users/{USER_GUID}"
    assert _json(req) == {"accountEnabled": False}

    out = await _connector("azure_ad").execute_action("revoke_sign_in_sessions", {"user": USER_GUID})
    assert out["revoked"] is True and api_calls()[-1].method == "POST"

    out = await _connector("azure_ad").execute_action("reset_password", {"user": USER_GUID})
    req = api_calls()[-1]
    assert req.method == "PATCH" and req.url.path == f"/v1.0/users/{USER_GUID}"
    sent = _json(req)["passwordProfile"]
    assert sent["forceChangePasswordNextSignIn"] is True and len(sent["password"]) >= 16
    # The generated value appears nowhere in the output (it would be persisted with the execution).
    assert sent["password"] not in json.dumps(out)
    assert out["password_status"].startswith("password replaced with an unstored random value")

    out = await _connector("azure_ad").execute_action("confirm_compromised", {"user_ids": [USER_GUID]})
    assert out["confirmed_compromised"] is True and _json(api_calls()[-1]) == {"userIds": [USER_GUID]}

    token_requests = [r for r in seen if host_header(r) == "login.microsoftonline.com"]
    assert token_requests and all(b"scope=https%3A%2F%2Fgraph.microsoft.com%2F.default" in r.content for r in token_requests)


@pytest.mark.asyncio
async def test_entra_reset_password_failure_never_echoes_the_generated_value(monkeypatch) -> None:
    sent: list[str] = []

    def api(request: httpx.Request) -> httpx.Response:
        password = _json(request)["passwordProfile"]["password"]
        sent.append(password)
        return httpx.Response(400, json={"error": {"code": "Request_BadRequest", "message": f"rejected {password}"}})

    fake_vendor(monkeypatch, _microsoft(GRAPH_TOKEN, api))
    out = await _connector("azure_ad").execute_action("reset_password", {"user": USER_GUID})
    assert out["status"] == "failed" and out["http_status"] == 400
    assert sent and sent[0] not in json.dumps(out) and "[redacted]" in out["error"]


@pytest.mark.asyncio
async def test_entra_filter_values_must_be_guids(monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, _microsoft(GRAPH_TOKEN, lambda r: httpx.Response(200, json={"value": []})))
    out = await _connector("azure_ad").execute_action("list_sign_ins", {"user_id": "x' or 1 eq 1 or userId eq 'y"})
    assert out["status"] == "failed" and out["code"] == "invalid_parameters"
    out = await _connector("azure_ad").execute_action("dismiss_risk", {"user_ids": ["not-a-guid"]})
    assert out["status"] == "failed" and out["code"] == "invalid_parameters"
    assert [r for r in seen if host_header(r) == "graph.microsoft.com"] == []


# --------------------------------------------------------------------------
# Defender for Endpoint actions
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_defender_actions_documented_requests(monkeypatch) -> None:
    machine_action = {"id": ACTION_GUID, "type": "Isolate", "status": "Pending", "machineId": MACHINE_ID,
                      "requestorComment": "IR-42", "creationDateTimeUtc": "2026-10-01T10:00:00Z"}

    def api(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        assert host_header(request) == "api-eu.securitycenter.microsoft.com"
        assert request.headers["authorization"] == f"Bearer {MDE_TOKEN}"
        if request.method == "GET" and path == "/api/machines":
            return httpx.Response(200, json={"value": [{"id": MACHINE_ID, "computerDnsName": "ws1.contoso.com",
                                                        "lastIpAddress": "10.1.2.3", "healthStatus": "Active"}]})
        if request.method == "GET" and path == f"/api/machines/{MACHINE_ID}/alerts":
            return httpx.Response(200, json={"value": [{"id": "da637", "title": "Suspicious PowerShell", "severity": "High"}]})
        if request.method == "POST" and path.startswith(f"/api/machines/{MACHINE_ID}/"):
            return httpx.Response(201, json=machine_action)
        if request.method == "GET" and path == f"/api/machineactions/{ACTION_GUID}":
            return httpx.Response(200, json={**machine_action, "status": "Succeeded"})
        if request.method == "PATCH" and path == "/api/alerts/da637":
            return httpx.Response(200, json={"id": "da637", "status": "Resolved", "classification": "TruePositive"})
        return httpx.Response(404, json={"error": {"code": "ResourceNotFound", "message": "not found"}})

    seen = fake_vendor(monkeypatch, _microsoft(MDE_TOKEN, api))
    api_calls = lambda: [r for r in seen if host_header(r) != "login.microsoftonline.com"]  # noqa: E731

    def mde():
        return _connector_with_config("microsoft_defender", {"geo": "eu"})

    out = await mde().execute_action("search_machines", {"query": "ws1.contoso.com", "top": 3})
    assert out["machines"][0]["id"] == MACHINE_ID
    assert api_calls()[-1].url.params["$filter"] == "computerDnsName eq 'ws1.contoso.com' or lastIpAddress eq 'ws1.contoso.com'"

    out = await mde().execute_action("get_machine_alerts", {"machine_id": MACHINE_ID})
    assert out["alerts"][0]["severity"] == "High"

    out = await mde().execute_action("isolate_machine", {"machine_id": MACHINE_ID, "comment": "IR-42", "isolation_type": "Selective"})
    assert out["status"] == "Pending" and out["action_id"] == ACTION_GUID
    req = api_calls()[-1]
    assert req.method == "POST" and req.url.path == f"/api/machines/{MACHINE_ID}/isolate"
    assert _json(req) == {"Comment": "IR-42", "IsolationType": "Selective"}

    await mde().execute_action("run_antivirus_scan", {"machine_id": MACHINE_ID, "comment": "IR-42"})
    req = api_calls()[-1]
    assert req.url.path == f"/api/machines/{MACHINE_ID}/runAntiVirusScan" and _json(req) == {"Comment": "IR-42", "ScanType": "Quick"}

    await mde().execute_action("restrict_app_execution", {"machine_id": MACHINE_ID, "comment": "IR-42"})
    assert api_calls()[-1].url.path == f"/api/machines/{MACHINE_ID}/restrictCodeExecution"

    out = await mde().execute_action("get_machine_action", {"action_id": ACTION_GUID})
    assert out["status"] == "Succeeded"

    out = await mde().execute_action("update_alert", {"alert_id": "da637", "status": "Resolved", "classification": "TruePositive",
                                                      "comment": "contained"})
    req = api_calls()[-1]
    assert req.method == "PATCH" and _json(req) == {"status": "Resolved", "classification": "TruePositive", "comment": "contained"}
    assert out["status"] == "Resolved"

    token_requests = [r for r in seen if host_header(r) == "login.microsoftonline.com"]
    assert all(dict(httpx.QueryParams(r.content.decode()))["scope"] == "https://api.securitycenter.microsoft.com/.default"
               for r in token_requests)


@pytest.mark.asyncio
async def test_defender_isolation_type_is_validated(monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, _refuse_everything)
    out = await _connector("microsoft_defender").execute_action(
        "isolate_machine", {"machine_id": MACHINE_ID, "comment": "x", "isolation_type": "Partial"},
    )
    assert out["status"] == "failed" and out["code"] == "invalid_parameters" and seen == []


# --------------------------------------------------------------------------
# Teams actions
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_teams_actions_post_adaptive_cards(monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda r: httpx.Response(202))
    workflows = "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=fixture-sig-0001"

    out = await _connector("microsoft_teams", webhook_url=workflows).execute_action("send_message", {
        "text": "Case 42 escalated", "title": "Escalation", "facts": [{"title": "Owner", "value": "T2"}],
    })
    assert out["posted"] is True and out["http_status"] == 202
    req = seen[-1]
    assert req.method == "POST" and host_header(req) == "prod-12.westus.logic.azure.com"
    assert req.url.path == "/workflows/abc/triggers/manual/paths/invoke" and req.url.params["sig"] == "fixture-sig-0001"
    assert "authorization" not in req.headers
    content = _json(req)["attachments"][0]["content"]
    assert content["type"] == "AdaptiveCard"
    assert {"type": "FactSet", "facts": [{"title": "Owner", "value": "T2"}]} in content["body"]

    out = await _connector("microsoft_teams").execute_action("send_alert_notification", {
        "title": "Impossible travel", "severity": "high", "summary": "ada@corp.io from two countries",
        "link": "https://soc.acme.example/alerts/7",
    })
    assert out["posted"] is True
    content = _json(seen[-1])["attachments"][0]["content"]
    assert content["actions"] == [{"type": "Action.OpenUrl", "title": "Open in PySOAR", "url": "https://soc.acme.example/alerts/7"}]
    assert "[HIGH] Impossible travel" in json.dumps(content)


@pytest.mark.asyncio
async def test_teams_failure_is_failed_without_the_url(monkeypatch) -> None:
    url = VALID_FIELDS["microsoft_teams"][1]["webhook_url"]
    fake_vendor(monkeypatch, lambda r: httpx.Response(400, json={"error": {"message": f"bad payload for {url}"}}))
    out = await _connector("microsoft_teams").execute_action("send_message", {"text": "x"})
    assert out["status"] == "failed" and out["http_status"] == 400
    _no_secret("microsoft_teams", out)


# --------------------------------------------------------------------------
# Path ids
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "action", "params"), [
    ("okta", "suspend_user", {"user_id": "../groups"}),
    ("okta", "revoke_sessions", {"user_id": "00u1/../../apps"}),
    ("okta", "reset_factor", {"user_id": "00u1", "factor_id": ".."}),
    ("okta", "get_user", {"user": "a/b@corp.io"}),
    ("azure_ad", "disable_user", {"user": "../me"}),
    ("azure_ad", "get_user", {"user": "x/y"}),
    ("microsoft_defender", "isolate_machine", {"machine_id": "../machines", "comment": "x"}),
    ("microsoft_defender", "get_machine", {"machine_id": "a/b"}),
    ("microsoft_defender", "update_alert", {"alert_id": "..", "status": "Resolved"}),
])
async def test_ids_with_slash_or_dot_segments_are_refused(monkeypatch, name, action, params) -> None:
    seen = fake_vendor(monkeypatch, _microsoft("tok-0001", lambda r: httpx.Response(200, json={})))
    out = await _connector(name).execute_action(action, params)
    assert out["status"] == "failed" and out["code"] == "invalid_parameters"
    assert [r for r in seen if host_header(r) != "login.microsoftonline.com"] == []
