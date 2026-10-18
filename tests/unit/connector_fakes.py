"""Fake vendor endpoints for the connector tests (test_connector_*.py).

Outbound HTTP is faked at the network boundary only, the way
test_outbound_pinning.py does it: ``netguard._getaddrinfo`` (the single DNS
resolution point) is steered, and ``httpx.AsyncHTTPTransport`` (the inner
transport ``PinnedTransport`` wraps) is replaced with an ``httpx.MockTransport``.
``PinnedTransport`` itself stays in front of every request, so the tests see
pinned requests (IP in the URL, vendor hostname in Host / SNI) and a name that
resolves to an internal address is still refused. Pinning is never disabled.

The credential values below are test fixtures, not real secrets.
"""

from __future__ import annotations

import socket
from typing import Any, Callable

import httpx

from src.integrations import netguard

PUBLIC_IP = "93.184.216.34"

# Exactly the declared required fields of each implemented connector, with
# values in the format each class validates.
VALID_FIELDS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "slack": ({}, {"bot_token": "xoxb-fixture-token-0001"}),
    "virustotal": ({}, {"api_key": "vt-fixture-key-0001"}),
    "shodan": ({}, {"api_key": "shodan-fixture-key-0001"}),
    "abuseipdb": ({}, {"api_key": "abuse-fixture-key-0001"}),
    "crowdstrike": ({}, {"client_id": "cs-client-0001", "client_secret": "cs-fixture-secret-0001"}),
    "servicenow": ({}, {"instance": "acme", "username": "svc-pysoar", "password": "sn-fixture-pass-0001"}),
    "pagerduty": ({"from_email": "oncall@acme.example"}, {"api_token": "pd-fixture-token-0001"}),
    "aws_security_hub": ({}, {"access_key_id": "AKIAFIXTURE0001", "secret_access_key": "aws-fixture-secret-0001"}),
    "jira": ({}, {"domain": "acme", "email": "bot@acme.example", "api_token": "jira-fixture-token-0001"}),
    "microsoft_sentinel": ({}, {
        "tenant_id": "contoso.onmicrosoft.com",
        "client_id": "00000000-0000-0000-0000-000000000001",
        "client_secret": "az-fixture-secret-0001",
        "subscription_id": "00000000-0000-0000-0000-000000000002",
        "resource_group": "rg-sec",
        "workspace_id": "ws-sec",
    }),
    "okta": ({}, {"domain": "acme.okta.com", "api_token": "okta-fixture-token-0001"}),
    "azure_ad": ({}, {
        "tenant_id": "contoso.onmicrosoft.com",
        "client_id": "00000000-0000-0000-0000-000000000003",
        "client_secret": "entra-fixture-secret-0001",
    }),
    "microsoft_defender": ({}, {
        "tenant_id": "contoso.onmicrosoft.com",
        "client_id": "00000000-0000-0000-0000-000000000004",
        "client_secret": "mde-fixture-secret-0001",
    }),
    "microsoft_teams": ({}, {
        "webhook_url": "https://acme.webhook.office.com/webhookb2/fixture-0001@fixture/IncomingWebhook/fixture/fixture-sig-0001",
    }),
    # Splunk and Elastic need a credential pair but declare none required
    # (token, or username + password; api_key, or username + password).
    "splunk": ({"base_url": "https://splunk.acme.example"}, {"token": "splunk-fixture-token-0001"}),
    "elastic": ({"base_url": "https://es.acme.example"}, {"api_key": "es-fixture-apikey-0001"}),
}


def secret_values(name: str) -> list[str]:
    config, credentials = VALID_FIELDS[name]
    return [v for k, v in {**config, **credentials}.items() if "secret" in k or "token" in k or "key" in k or "pass" in k]


def fake_vendor(
    monkeypatch: Any,
    handler: Callable[[httpx.Request], httpx.Response],
    ip: str = PUBLIC_IP,
) -> list[httpx.Request]:
    """Answer every pinned request with ``handler``; return the requests seen."""
    seen: list[httpx.Request] = []

    async def _resolve(host: str, port: int) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(netguard, "_getaddrinfo", _resolve)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda *_a, **_kw: httpx.MockTransport(_record))
    return seen


def host_header(request: httpx.Request) -> str:
    return request.headers.get("host", "")


async def ensure_connector_rows(db: Any, *names: str) -> None:
    """Catalogue rows the installed_integrations FK needs (seeded at startup in prod)."""
    import json as _json

    from sqlalchemy import select

    from src.integrations.engine import BUILTIN_CONNECTORS
    from src.integrations.models import IntegrationConnector

    for name in names:
        if (await db.execute(select(IntegrationConnector.id).where(IntegrationConnector.id == name))).scalar_one_or_none():
            continue
        meta = BUILTIN_CONNECTORS[name]
        db.add(IntegrationConnector(
            id=name, name=name, display_name=meta["display_name"],
            category=getattr(meta["category"], "value", meta["category"]),
            supported_actions="[]", supported_triggers=_json.dumps(meta["supported_triggers"]),
            auth_type=getattr(meta["auth_type"], "value", meta["auth_type"]), config_schema="{}",
        ))
    await db.flush()
