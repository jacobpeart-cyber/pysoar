"""The connector catalogue tells the truth.

Every catalogue entry is implemented (a connector class), log_ingest (an SDK
log poller in src/siem/cloud_poller.py) or planned; planned entries cannot be
installed (501), tested or executed; an implemented entry's actions are
exactly its class's ``ACTIONS``, each a coroutine method; the declared config
and credential fields cover every key the class reads; install and update
refuse missing required fields with 422 naming them (never the values).
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import pytest
from sqlalchemy import select

from src.integrations.connectors.base import BaseConnector, validate_params
from src.integrations.engine import (
    BUILTIN_CONNECTORS,
    CONNECTOR_CLASS_MAP,
    IMPLEMENTED,
    LOG_INGEST,
    LOG_INGEST_CONNECTORS,
    PLANNED,
    ConnectorRegistry,
    implementation_status,
)
from src.integrations.models import InstalledIntegration
from src.models.audit import AuditLog
from src.schemas.integrations import ConnectorResponse
from tests.unit.connector_fakes import VALID_FIELDS, ensure_connector_rows

BASE = "/api/v1/integrations"
CONNECTORS_DIR = Path(__file__).resolve().parents[2] / "src" / "integrations" / "connectors"


def test_every_catalogue_entry_has_an_honest_status() -> None:
    registry = ConnectorRegistry()
    assert len(registry.connectors) == len(BUILTIN_CONNECTORS) == 45
    statuses = {name: meta["implementation_status"] for name, meta in registry.connectors.items()}
    assert set(statuses.values()) == {IMPLEMENTED, LOG_INGEST, PLANNED}
    assert {n for n, s in statuses.items() if s == IMPLEMENTED} == set(CONNECTOR_CLASS_MAP)
    assert {n for n, s in statuses.items() if s == LOG_INGEST} == set(LOG_INGEST_CONNECTORS)
    for name, meta in registry.connectors.items():
        if meta["implementation_status"] == PLANNED:
            assert meta["installable"] is False, name
            assert meta["supported_actions"] == [] and meta["actions"] == [], name
            assert meta["verification"] == "not implemented in this release", name
        else:
            assert meta["installable"] is True, name
        assert "verified" not in meta["verification"].replace("not verified", ""), name
        assert "certified" not in meta["verification"], name


@pytest.mark.parametrize("name", sorted(CONNECTOR_CLASS_MAP))
def test_implemented_actions_are_the_class_actions(name: str) -> None:
    cls = CONNECTOR_CLASS_MAP[name]
    meta = ConnectorRegistry().get_connector_details(name)
    assert meta["supported_actions"] == list(cls.ACTIONS)
    assert [a["name"] for a in meta["actions"]] == list(cls.ACTIONS)
    assert cls.ACTIONS, name
    for action, spec in cls.ACTIONS.items():
        method = getattr(cls, action, None)
        assert method is not None and inspect.iscoroutinefunction(method), f"{name}.{action}"
        schema = spec.params_schema
        assert schema["type"] == "object" and schema["additionalProperties"] is False
        assert set(schema["required"]) <= set(schema["properties"]), f"{name}.{action}"
        # Every schema property is a parameter of the method and every
        # parameter without a default is required by the schema.
        params = {
            p.name: p for p in inspect.signature(method).parameters.values() if p.name != "self"
        }
        assert set(schema["properties"]) == set(params), f"{name}.{action}"
        no_default = {n for n, p in params.items() if p.default is inspect.Parameter.empty}
        assert no_default == set(schema["required"]), f"{name}.{action}"
        assert spec.output and spec.description
    assert cls.VERIFICATION == "implemented from the vendor's public API documentation; not verified against a live tenant"
    assert cls.TEST_CALL


_READ_RE = re.compile(r"self\.(credentials|config)\.get\(\s*[\"']([A-Za-z0-9_]+)[\"']")
_CRED_HELPER_RE = re.compile(r"self\._cred\(\s*[\"']([A-Za-z0-9_]+)[\"']")


@pytest.mark.parametrize("name", sorted(CONNECTOR_CLASS_MAP))
def test_declared_fields_cover_every_key_the_class_reads(name: str) -> None:
    cls = CONNECTOR_CLASS_MAP[name]
    source = inspect.getsource(inspect.getmodule(cls))
    reads = {(kind, key) for kind, key in _READ_RE.findall(source)}
    reads |= {("credentials", key) for key in _CRED_HELPER_RE.findall(source)}
    declared = {("config", f.name) for f in cls.CONFIG_FIELDS} | {("credentials", f.name) for f in cls.CREDENTIAL_FIELDS}
    assert reads, name
    assert reads <= declared, f"{name} reads undeclared keys: {sorted(reads - declared)}"
    assert {k for _, k in declared} <= {k for _, k in reads} | {"cloud"}, f"{name} declares keys it never reads"

    config, credentials = VALID_FIELDS[name]
    required = {f.name for f in cls.CONFIG_FIELDS + cls.CREDENTIAL_FIELDS if f.required}
    assert required == set(config) | set(credentials), name
    assert cls(config=dict(config), credentials=dict(credentials)).is_configured
    for field in sorted(required):
        partial_config = {k: v for k, v in config.items() if k != field}
        partial_creds = {k: v for k, v in credentials.items() if k != field}
        connector = cls(config=partial_config, credentials=partial_creds) if field not in ("domain", "instance") else None
        if connector is not None:
            assert not connector.is_configured, f"{name} configured without {field}"
        assert field in cls.missing_fields(partial_config, partial_creds)
    for f in cls.CREDENTIAL_FIELDS:
        if any(word in f.name for word in ("secret", "password", "token", "api_key")):
            assert f.secret, f"{name}.{f.name} must be secret"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(CONNECTOR_CLASS_MAP))
async def test_unknown_action_is_a_failed_result_not_an_exception(name: str) -> None:
    config, credentials = VALID_FIELDS[name]
    connector = CONNECTOR_CLASS_MAP[name](config=dict(config), credentials=dict(credentials))
    result = await connector.execute_action("drop_tables", {})
    assert result["status"] == "failed"
    assert result["error"].startswith("unknown action drop_tables; available: [")
    for action in connector.ACTIONS:
        assert action in result["error"]


def test_param_validator_reports_keys_not_values() -> None:
    schema = CONNECTOR_CLASS_MAP["crowdstrike"].ACTIONS["contain_host"].params_schema
    assert validate_params(schema, {"device_id": "abc"}) == []
    problems = validate_params(schema, {"device_id": 7, "hostname": "secret-host"})
    assert "parameter 'device_id' must be of type string" in problems
    assert "unknown parameter 'hostname'" in problems
    assert not any("secret-host" in p for p in problems)
    assert validate_params(schema, {}) == ["missing required parameter 'device_id'"]
    assert validate_params(schema, []) == ["parameters must be a JSON object"]


def test_connector_response_schema_carries_the_truth_fields() -> None:
    fields = ConnectorResponse.model_fields
    for f in ("implementation_status", "installable", "verification", "config_fields", "credential_fields", "actions",
              "install_count", "rating", "is_community", "last_updated"):
        assert f in fields
    assert "not marketplace statistics" in " ".join((ConnectorResponse.__doc__ or "").split())


def test_base_connector_is_abstract_over_test_connection() -> None:
    assert "test_connection" in BaseConnector.__abstractmethods__


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


def _detail(resp) -> dict:
    return resp.json().get("detail") or {}


@pytest.mark.asyncio
async def test_catalogue_routes_expose_status_fields_and_org_install_count(
    client, org_a, org_a_admin_headers, org_b_headers,
) -> None:
    resp = await client.get(f"{BASE}/connectors", params={"size": 100}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    items = {c["name"]: c for c in resp.json()["items"]}
    assert len(items) == 45
    vt = items["virustotal"]
    assert vt["implementation_status"] == "implemented" and vt["installable"] is True
    assert vt["actions"] and vt["actions"][0]["params_schema"]["type"] == "object"
    assert [f["name"] for f in vt["credential_fields"]] == ["api_key"] and vt["credential_fields"][0]["secret"] is True
    assert vt["install_count"] == 0 and vt["rating"] is None and vt["is_community"] is False and vt["last_updated"] is None
    splunk = items["splunk"]
    assert splunk["implementation_status"] == "planned" and splunk["installable"] is False
    assert splunk["supported_actions"] == [] and splunk["verification"] == "not implemented in this release"

    filtered = await client.get(f"{BASE}/connectors", params={"size": 100, "implementation": "implemented"}, headers=org_a_admin_headers)
    assert {c["name"] for c in filtered.json()["items"]} == set(CONNECTOR_CLASS_MAP)

    config, credentials = VALID_FIELDS["virustotal"]
    installed = await client.post(
        f"{BASE}/install",
        json={"connector_id": "virustotal", "display_name": "VT", "config": config, "credentials": credentials},
        headers=org_a_admin_headers,
    )
    assert installed.status_code == 201, installed.text
    assert "vt-fixture-key-0001" not in installed.text and installed.json()["config"] == {}

    detail = await client.get(f"{BASE}/connectors/virustotal", headers=org_a_admin_headers)
    assert detail.json()["install_count"] == 1
    other_org = await client.get(f"{BASE}/connectors/virustotal", headers=org_b_headers)
    assert other_org.json()["install_count"] == 0


@pytest.mark.asyncio
async def test_planned_connector_install_is_501(client, org_a_admin_headers) -> None:
    resp = await client.post(
        f"{BASE}/install",
        json={"connector_id": "splunk", "display_name": "Splunk", "config": {"base_url": "https://splunk.example"}, "credentials": {"token": "t"}},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 501, resp.text
    assert _detail(resp) == {
        "error": "not_implemented",
        "detail": "Splunk Enterprise has no connector implementation in this release",
    }


@pytest.mark.asyncio
async def test_install_and_update_refuse_missing_fields_naming_them(client, db_session, org_a, org_a_admin_headers) -> None:
    resp = await client.post(
        f"{BASE}/install",
        json={"connector_id": "jira", "display_name": "Jira", "credentials": {"domain": "acme", "api_token": "jira-secret-value"}},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 422, resp.text
    assert _detail(resp)["error"] == "missing_fields" and _detail(resp)["fields"] == ["email"]
    assert "jira-secret-value" not in resp.text

    bad_domain = await client.post(
        f"{BASE}/install",
        json={"connector_id": "jira", "display_name": "Jira",
              "credentials": {"domain": "evil.example/x#", "email": "a@b.example", "api_token": "jira-secret-value"}},
        headers=org_a_admin_headers,
    )
    assert bad_domain.status_code == 422 and _detail(bad_domain)["fields"] == ["domain"]
    assert "evil.example" not in bad_domain.text

    config, credentials = VALID_FIELDS["jira"]
    ok = await client.post(
        f"{BASE}/install",
        json={"connector_id": "jira", "display_name": "Jira", "config": config, "credentials": credentials},
        headers=org_a_admin_headers,
    )
    assert ok.status_code == 201, ok.text
    inst = f"{BASE}/installed/{ok.json()['id']}"

    # Rotating one secret keeps the others (merge); blanking a required one is refused.
    rotate = await client.patch(inst, json={"credentials": {"api_token": "jira-rotated-0002"}}, headers=org_a_admin_headers)
    assert rotate.status_code == 200, rotate.text
    blank = await client.patch(inst, json={"credentials": {"email": ""}}, headers=org_a_admin_headers)
    assert blank.status_code == 422 and _detail(blank)["fields"] == ["email"]

    from src.core.secrets import _decrypt_secret_json

    row = (await db_session.execute(select(InstalledIntegration).where(InstalledIntegration.id == ok.json()["id"]))).scalar_one()
    await db_session.refresh(row)
    assert not row.auth_credentials_encrypted.startswith("{")  # encrypted at rest
    stored = _decrypt_secret_json(row.auth_credentials_encrypted)
    assert stored == {**credentials, "api_token": "jira-rotated-0002"}

    audits = (await db_session.execute(
        select(AuditLog).where(AuditLog.resource_id == row.id).order_by(AuditLog.created_at)
    )).scalars().all()
    assert [a.action for a in audits] == ["integration_install", "integration_update"]
    for a in audits:
        assert "jira-rotated-0002" not in (a.new_value or "") and "jira-fixture-token-0001" not in (a.new_value or "")
    assert json.loads(audits[1].new_value)["changed"] == ["credentials.api_token"]


@pytest.mark.asyncio
async def test_existing_planned_row_is_unavailable_and_cannot_act(client, db_session, org_a, org_a_admin_headers, org_a_headers) -> None:
    await ensure_connector_rows(db_session, "okta")
    row = InstalledIntegration(
        organization_id=org_a.id, connector_id="okta", display_name="Okta (installed before this release)",
        config_encrypted="{}", auth_credentials_encrypted="", status="active",
    )
    db_session.add(row)
    await db_session.commit()
    inst = f"{BASE}/installed/{row.id}"
    assert implementation_status("okta") == PLANNED

    got = await client.get(inst, headers=org_a_headers)
    assert got.status_code == 200 and got.json()["health_status"] == "unavailable"
    listed = await client.get(f"{BASE}/installed", headers=org_a_headers)
    assert {i["health_status"] for i in listed.json()["items"]} == {"unavailable"}

    test = await client.post(f"{inst}/test", headers=org_a_headers)
    assert test.status_code == 501 and _detail(test)["error"] == "not_implemented"
    actions = await client.get(f"{inst}/actions", headers=org_a_headers)
    assert actions.status_code == 200 and actions.json()["items"] == []
    execute = await client.post(f"{inst}/actions/whatever/execute", json={"input_data": {}}, headers=org_a_headers)
    assert execute.status_code == 501 and "Okta has no connector implementation" in _detail(execute)["detail"]

    assert (await client.delete(inst, headers=org_a_admin_headers)).status_code == 204
    assert (await client.get(inst, headers=org_a_headers)).status_code == 404


@pytest.mark.asyncio
async def test_log_ingest_source_installs_with_its_poller_fields(client, org_a_admin_headers, org_a_headers) -> None:
    missing = await client.post(
        f"{BASE}/install", json={"connector_id": "aws_cloudtrail", "display_name": "CT", "credentials": {}},
        headers=org_a_admin_headers,
    )
    assert missing.status_code == 422
    assert _detail(missing)["fields"] == ["aws_access_key_id", "aws_secret_access_key"]
    ok = await client.post(
        f"{BASE}/install",
        json={"connector_id": "aws_cloudtrail", "display_name": "CT",
              "credentials": {"aws_access_key_id": "AKIAFIXTURE0002", "aws_secret_access_key": "ct-fixture-secret"}},
        headers=org_a_admin_headers,
    )
    assert ok.status_code == 201, ok.text
    test = await client.post(f"{BASE}/installed/{ok.json()['id']}/test", headers=org_a_headers)
    assert test.status_code == 501 and "SIEM cloud poller" in _detail(test)["detail"]
