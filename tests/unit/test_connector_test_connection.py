"""Each implemented connector's ``test_connection`` makes its documented
authenticated read-only call through the pinned transport, answers healthy on
the vendor's success body and unhealthy on a 401 without ever putting a
secret in ``detail``; the ``/installed/{id}/test`` route persists the result
and a vendor name that resolves to an internal address is refused.

Vendor HTTP is faked at the network boundary (tests/unit/connector_fakes.py);
AWS goes through boto3, whose client factory is replaced.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx
import pytest
from sqlalchemy import select

from src.integrations.connectors.base import REFUSED_INTERNAL, ConnectionTestResult
from src.integrations.engine import CONNECTOR_CLASS_MAP
from src.integrations.models import InstalledIntegration
from src.models.audit import AuditLog
from tests.unit.connector_fakes import (
    PUBLIC_IP,
    VALID_FIELDS,
    ensure_connector_rows,
    fake_vendor,
    host_header,
    secret_values,
)

BASE = "/api/v1/integrations"

# connector -> (vendor host, path of the read-only call, success body, status)
SUCCESS: dict[str, tuple[str, str, Any, int]] = {
    "slack": ("slack.com", "/api/auth.test", {"ok": True, "team": "acme"}, 200),
    "virustotal": ("www.virustotal.com", "/api/v3/ip_addresses/8.8.8.8", {"data": {"id": "8.8.8.8", "attributes": {}}}, 200),
    "shodan": ("api.shodan.io", "/api-info", {"plan": "dev", "query_credits": 100}, 200),
    "abuseipdb": ("api.abuseipdb.com", "/api/v2/check", {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}}, 200),
    "crowdstrike": ("api.crowdstrike.com", "/oauth2/token", {"access_token": "falcon-tok", "expires_in": 1799}, 201),
    "servicenow": ("acme.service-now.com", "/api/now/table/sys_user", {"result": [{"sys_id": "6816f79cc0a8016401c5a33be04be441"}]}, 200),
    "pagerduty": ("api.pagerduty.com", "/abilities", {"abilities": ["teams", "urgencies"]}, 200),
    "jira": ("acme.atlassian.net", "/rest/api/3/myself", {"accountId": "5b10ac8d82e05b22cc7d4ef5", "active": True}, 200),
}
SENTINEL_WORKSPACE = (
    "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg-sec"
    "/providers/Microsoft.OperationalInsights/workspaces/ws-sec"
)


def _connector(name: str):
    config, credentials = VALID_FIELDS[name]
    return CONNECTOR_CLASS_MAP[name](config=dict(config), credentials=dict(credentials))


def _assert_no_secret(name: str, result: ConnectionTestResult) -> None:
    text = json.dumps(result.to_dict())
    for secret in secret_values(name):
        assert secret not in text, f"{name}: secret leaked in {text}"


def test_every_implemented_connector_has_a_case() -> None:
    assert set(SUCCESS) | {"microsoft_sentinel", "aws_security_hub"} == set(CONNECTOR_CLASS_MAP)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(SUCCESS))
async def test_healthy_on_documented_success_body(monkeypatch, name: str) -> None:
    host, path, body, code = SUCCESS[name]
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(code, json=body))

    result = await _connector(name).test_connection()

    assert result.status == "healthy", result
    assert result.checked == CONNECTOR_CLASS_MAP[name].TEST_CALL
    assert [r.url.path for r in seen] == [path]
    request = seen[0]
    assert request.url.host == PUBLIC_IP and host_header(request) == host
    assert request.extensions["sni_hostname"] == host
    # The call is authenticated: each vendor's documented credential carrier.
    if name == "shodan":
        assert request.url.params["key"] == VALID_FIELDS[name][1]["api_key"]
    elif name == "crowdstrike":
        assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
        assert b"client_secret=cs-fixture-secret-0001" in request.content
    else:
        auth_header = {
            "virustotal": "x-apikey", "abuseipdb": "key",
        }.get(name, "authorization")
        assert request.headers.get(auth_header), f"{name}: no credential header"
    if name == "pagerduty":
        assert request.headers["authorization"] == "Token token=pd-fixture-token-0001"
        assert request.headers["accept"] == "application/vnd.pagerduty+json;version=2"
    if name == "abuseipdb":
        assert request.url.params["maxAgeInDays"] == "1"
    _assert_no_secret(name, result)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(SUCCESS) + ["microsoft_sentinel"])
async def test_unhealthy_on_401_without_secret(monkeypatch, name: str) -> None:
    secrets = secret_values(name)

    def handler(request: httpx.Request) -> httpx.Response:
        # A hostile vendor echoing the credential back must not leak it.
        return httpx.Response(401, json={"error": {"message": f"invalid credential {secrets[0]}"}})

    fake_vendor(monkeypatch, handler)
    result = await _connector(name).test_connection()

    assert result.status == "unhealthy"
    assert result.http_status == 401
    assert "401" in result.detail
    _assert_no_secret(name, result)


@pytest.mark.asyncio
async def test_slack_ok_false_is_unhealthy(monkeypatch) -> None:
    fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"ok": False, "error": "invalid_auth"}))
    result = await _connector("slack").test_connection()
    assert result.status == "unhealthy" and "invalid_auth" in result.detail


@pytest.mark.asyncio
async def test_sentinel_token_then_workspace_read(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if host_header(request) == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "arm-tok", "expires_in": 3599, "token_type": "Bearer"})
        return httpx.Response(200, json={"id": SENTINEL_WORKSPACE, "name": "ws-sec"})

    seen = fake_vendor(monkeypatch, handler)
    result = await _connector("microsoft_sentinel").test_connection()

    assert result.status == "healthy", result
    token_req, ws_req = seen
    assert token_req.url.path == "/contoso.onmicrosoft.com/oauth2/v2.0/token"
    form = dict(httpx.QueryParams(token_req.content.decode()))
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == "https://management.azure.com/.default"
    assert "authorization" not in token_req.headers
    assert host_header(ws_req) == "management.azure.com" and ws_req.url.path == SENTINEL_WORKSPACE
    assert ws_req.url.params["api-version"] == "2022-10-01"
    assert ws_req.headers["authorization"] == "Bearer arm-tok"


class _FakeSecurityHub:
    def __init__(self, error: Optional[Exception] = None) -> None:
        self.error = error
        self.calls: list[str] = []

    def describe_hub(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("describe_hub")
        if self.error:
            raise self.error
        return {"HubArn": "arn:aws:securityhub:us-east-1:111122223333:hub/default", "AutoEnableControls": True}


@pytest.mark.asyncio
async def test_aws_security_hub_describe_hub(monkeypatch) -> None:
    import boto3
    from botocore.exceptions import ClientError

    hub = _FakeSecurityHub()
    made: list[dict[str, Any]] = []

    def _client(service: str, **kwargs: Any) -> _FakeSecurityHub:
        made.append({"service": service, **kwargs})
        return hub

    monkeypatch.setattr(boto3, "client", _client)
    result = await _connector("aws_security_hub").test_connection()
    assert result.status == "healthy" and hub.calls == ["describe_hub"]
    assert made[0]["service"] == "securityhub" and made[0]["region_name"] == "us-east-1"

    denied = ClientError(
        {"Error": {"Code": "UnrecognizedClientException", "Message": "The security token included in the request is invalid"},
         "ResponseMetadata": {"HTTPStatusCode": 403}},
        "DescribeHub",
    )
    hub.error = denied
    result = await _connector("aws_security_hub").test_connection()
    assert result.status == "unhealthy" and result.http_status == 403
    _assert_no_secret("aws_security_hub", result)


@pytest.mark.asyncio
async def test_missing_required_fields_is_unhealthy_without_network(monkeypatch) -> None:
    def _no_call(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request without credentials")

    fake_vendor(monkeypatch, _no_call)
    result = await CONNECTOR_CLASS_MAP["virustotal"](config={}, credentials={}).test_connection()
    assert result.status == "unhealthy" and "api_key" in result.detail


@pytest.mark.asyncio
async def test_internal_address_is_refused(monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={}), ip="10.0.0.7")
    result = await _connector("jira").test_connection()
    assert result.status == "unhealthy"
    assert result.detail == REFUSED_INTERNAL
    assert seen == []


# --------------------------------------------------------------------------
# The route
# --------------------------------------------------------------------------


async def _install(client, headers: dict[str, str], name: str = "virustotal") -> str:
    config, credentials = VALID_FIELDS[name]
    resp = await client.post(
        f"{BASE}/install",
        json={"connector_id": name, "display_name": f"{name} test", "config": config, "credentials": credentials},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_route_persists_healthy_result(client, db_session, org_a, org_a_admin_headers, org_a_headers, monkeypatch) -> None:
    integration_id = await _install(client, org_a_admin_headers)
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"data": {"id": "8.8.8.8"}}))

    resp = await client.post(f"{BASE}/installed/{integration_id}/test", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["details"]["checked"] == "GET /api/v3/ip_addresses/8.8.8.8"
    assert len(seen) == 1 and seen[0].headers["x-apikey"] == "vt-fixture-key-0001"

    row = (await db_session.execute(select(InstalledIntegration).where(InstalledIntegration.id == integration_id))).scalar_one()
    await db_session.refresh(row)
    assert row.health_status == "healthy" and row.last_health_check and row.error_message is None
    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "integration_test", AuditLog.resource_id == integration_id)
    )).scalars().all()
    assert len(audit) == 1 and audit[0].success is True and audit[0].organization_id == org_a.id


@pytest.mark.asyncio
async def test_route_records_401_and_internal_refusal(client, db_session, org_a_admin_headers, org_a_headers, monkeypatch) -> None:
    integration_id = await _install(client, org_a_admin_headers)

    fake_vendor(monkeypatch, lambda request: httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}}))
    resp = await client.post(f"{BASE}/installed/{integration_id}/test", headers=org_a_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "unhealthy"
    assert resp.json()["details"]["http_status"] == 401
    assert "vt-fixture-key-0001" not in resp.text

    fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={}), ip="169.254.169.254")
    resp = await client.post(f"{BASE}/installed/{integration_id}/test", headers=org_a_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "unhealthy"
    assert resp.json()["message"] == REFUSED_INTERNAL

    row = (await db_session.execute(select(InstalledIntegration).where(InstalledIntegration.id == integration_id))).scalar_one()
    await db_session.refresh(row)
    assert row.health_status == "unhealthy"
    assert row.error_message == REFUSED_INTERNAL and len(row.error_message) <= 200


@pytest.mark.asyncio
async def test_health_task_uses_the_connector_test(db_session, org_a, monkeypatch) -> None:
    """The hourly health sweep runs the same connector test (no hand-rolled probe)."""
    from src.core.secrets import _encrypt_secret_json
    from src.integrations.tasks import _health_check_all_integrations_async

    org_id = org_a.id
    await ensure_connector_rows(db_session, "shodan", "okta")
    row = InstalledIntegration(
        organization_id=org_id, connector_id="shodan", display_name="shodan",
        config_encrypted="{}", auth_credentials_encrypted=_encrypt_secret_json(VALID_FIELDS["shodan"][1]),
        status="active",
    )
    planned = InstalledIntegration(
        organization_id=org_id, connector_id="okta", display_name="okta (legacy row)",
        config_encrypted="{}", auth_credentials_encrypted=_encrypt_secret_json({}), status="active",
    )
    db_session.add_all([row, planned])
    await db_session.commit()
    row_id, planned_id = row.id, planned.id

    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"plan": "dev"}))
    outcome = await _health_check_all_integrations_async(organization_id=org_id)

    assert outcome["healthy"] == 1 and outcome["unavailable"] == 1
    assert [r.url.path for r in seen] == ["/api-info"]  # nothing sent for the planned connector
    for rid, expected in ((row_id, "healthy"), (planned_id, "unavailable")):
        got = (await db_session.execute(select(InstalledIntegration).where(InstalledIntegration.id == rid))).scalar_one()
        await db_session.refresh(got)
        assert got.health_status == expected
