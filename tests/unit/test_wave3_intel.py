"""Wave 3 (W3-B): threat-intel lookups, enrichment and feed polling made real.

Provider HTTP is mocked at the transport boundary only: ``src.intel.outbound``
sends every request through ``netguard.resolve_and_vet`` (steered here with a
fake resolver) to an ``httpx.MockTransport``. Everything above it (key
resolution, credential decryption, caching, verdicts, persistence, routes)
is the production code.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable

import httpx
import pytest
from sqlalchemy import select

from src.core.config import settings
from src.core.secrets import encrypt_secret_json
from src.integrations import netguard
from src.intel import outbound
from src.intel import providers as intel_providers
from src.intel.feeds import FeedManager
from src.intel.models import ThreatFeed, ThreatIndicator

pytestmark = pytest.mark.asyncio

BASE = "/api/v1/threat-intel"
PUBLIC_IP = "93.184.216.34"


def _uid() -> str:
    return uuid.uuid4().hex[:10]


class _Provider:
    """MockTransport handler that records requests and answers per host."""

    def __init__(self, answers: dict[str, Callable[[httpx.Request], httpx.Response]]):
        self.answers = answers
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.headers.get("host", "")
        handler = self.answers.get(host)
        if handler is None:
            return httpx.Response(599, json={"unexpected_host": host})
        return handler(request)

    def hosts(self) -> list[str]:
        return [r.headers.get("host", "") for r in self.requests]


def _resolver(ip: str = PUBLIC_IP):
    async def resolve(_host: str, port: int) -> list[tuple[Any, ...]]:
        return [(None, None, None, "", (ip, port))]

    return resolve


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """No real DNS or network, no platform keys unless a test sets them, empty cache."""
    monkeypatch.setattr(netguard, "_getaddrinfo", _resolver())
    monkeypatch.setattr(outbound, "TRANSPORT", httpx.MockTransport(_Provider({})))
    for attr in ("virustotal_api_key", "abuseipdb_api_key"):
        monkeypatch.setattr(settings, attr, None)
    for env in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    intel_providers.cache_clear()
    yield
    intel_providers.cache_clear()


def _install(monkeypatch, provider: _Provider) -> _Provider:
    monkeypatch.setattr(outbound, "TRANSPORT", httpx.MockTransport(provider))
    return provider


def _vt_ok(malicious: int = 5) -> Callable[[httpx.Request], httpx.Response]:
    def answer(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 60, "undetected": 10},
            "reputation": -20, "country": "NL", "tags": ["c2"],
        }}})
    return answer


def _abuse_ok(score: int = 90) -> Callable[[httpx.Request], httpx.Response]:
    def answer(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {
            "abuseConfidenceScore": score, "totalReports": 12, "countryCode": "NL", "isp": "Example ISP",
        }})
    return answer


def _otx_ok(pulses: int = 4) -> Callable[[httpx.Request], httpx.Response]:
    def answer(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "pulse_info": {"count": pulses, "pulses": [{"id": f"p{i}", "name": f"pulse {i}"} for i in range(pulses)]},
            "validation": [],
        })
    return answer


def _platform_keys(monkeypatch, vt: bool = True, abuse: bool = True, otx: bool = True) -> None:
    if vt:
        monkeypatch.setattr(settings, "virustotal_api_key", "platform-vt")
    if abuse:
        monkeypatch.setattr(settings, "abuseipdb_api_key", "platform-abuse")
    if otx:
        monkeypatch.setenv("OTX_API_KEY", "platform-otx")


async def _connector(db_session, name: str):
    from src.integrations.models import IntegrationConnector

    connector = (
        await db_session.execute(select(IntegrationConnector).where(IntegrationConnector.name == name))
    ).scalars().first()
    if connector is None:
        connector = IntegrationConnector(
            name=name,
            display_name=name,
            category="threat_intel",
            vendor=name,
            description="tests",
            supported_actions="[]",
            supported_triggers="[]",
            config_schema="{}",
        )
        db_session.add(connector)
        await db_session.flush()
    return connector


# --------------------------------------------------------------------------
# Lookup and enrichment
# --------------------------------------------------------------------------


async def test_lookup_without_keys_names_every_unconfigured_provider(client, org_a_headers, monkeypatch):
    provider = _install(monkeypatch, _Provider({}))
    resp = await client.post(f"{BASE}/lookup", json={"indicator": "198.51.100.23", "type": "ip"}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["external_enrichment"] == "not_configured"
    assert set(body["not_configured"]) == {"virustotal", "abuseipdb", "otx"}
    statuses = {p["provider"]: p["status"] for p in body["providers"]}
    assert statuses == {"virustotal": "not_configured", "abuseipdb": "not_configured", "otx": "not_configured"}
    assert all("API key" in p["detail"] for p in body["providers"])
    assert body["external_sources"] == []
    assert provider.requests == []


async def test_lookup_runs_all_three_providers_through_the_pinned_guard(client, org_a_headers, monkeypatch):
    _platform_keys(monkeypatch)
    provider = _install(monkeypatch, _Provider({
        "www.virustotal.com": _vt_ok(),
        "api.abuseipdb.com": _abuse_ok(),
        "otx.alienvault.com": _otx_ok(),
    }))
    resp = await client.post(f"{BASE}/lookup", json={"indicator": "198.51.100.24", "type": "ip"}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["external_enrichment"] == "ok"
    names = {s["name"]: s for s in body["external_sources"]}
    assert set(names) == {"virustotal", "abuseipdb", "otx"}
    assert names["virustotal"]["verdict"] == "malicious"
    assert names["abuseipdb"]["confidence"] == 90
    assert names["otx"]["verdict"] == "malicious"
    assert names["virustotal"]["key_source"] == "platform"
    assert names["virustotal"]["details"]["last_analysis_stats"]["malicious"] == 5
    assert body["reputation"] == "malicious"
    assert body["not_configured"] == []

    # Every request went to the vetted IP literal with the provider's name in Host.
    assert sorted(provider.hosts()) == ["api.abuseipdb.com", "otx.alienvault.com", "www.virustotal.com"]
    for request in provider.requests:
        assert request.url.host == PUBLIC_IP
    vt = next(r for r in provider.requests if r.headers["host"] == "www.virustotal.com")
    assert vt.headers["x-apikey"] == "platform-vt"
    assert vt.url.path == "/api/v3/ip_addresses/198.51.100.24"
    assert vt.extensions.get("sni_hostname") == "www.virustotal.com"


async def test_provider_error_is_reported_not_swallowed(client, org_a_headers, monkeypatch):
    _platform_keys(monkeypatch, abuse=False, otx=False)
    _install(monkeypatch, _Provider({"www.virustotal.com": lambda _r: httpx.Response(429, json={})}))
    resp = await client.post(f"{BASE}/lookup", json={"indicator": "evil.pysoar-tests.io", "type": "domain"}, headers=org_a_headers)
    body = resp.json()
    assert body["external_enrichment"] == "enrichment_failed"
    vt = next(p for p in body["providers"] if p["provider"] == "virustotal")
    assert vt["status"] == "error" and "429" in vt["error"]
    assert any(e.startswith("virustotal:") and "rate limit" in e for e in body["external_errors"])
    assert body["external_sources"][0]["verdict"] == "error"
    assert "otx" in body["not_configured"]


async def test_internal_dns_answer_is_refused_before_any_request(client, org_a_headers, monkeypatch):
    _platform_keys(monkeypatch, abuse=False, otx=False)
    monkeypatch.setattr(netguard, "_getaddrinfo", _resolver("169.254.169.254"))
    provider = _install(monkeypatch, _Provider({"www.virustotal.com": _vt_ok()}))
    resp = await client.post(f"{BASE}/lookup", json={"indicator": "abc.pysoar-tests.io", "type": "domain"}, headers=org_a_headers)
    vt = next(p for p in resp.json()["providers"] if p["provider"] == "virustotal")
    assert vt["status"] == "error"
    assert "internal address" in vt["error"]
    assert provider.requests == []


async def test_results_cached_per_org_with_ttl(client, org_a_headers, org_b_headers, monkeypatch):
    _platform_keys(monkeypatch, abuse=False, otx=False)
    provider = _install(monkeypatch, _Provider({"www.virustotal.com": _vt_ok()}))
    payload = {"indicator": "cache.pysoar-tests.io", "type": "domain"}

    first = (await client.post(f"{BASE}/lookup", json=payload, headers=org_a_headers)).json()
    second = (await client.post(f"{BASE}/lookup", json=payload, headers=org_a_headers)).json()
    assert len(provider.requests) == 1
    assert first["external_sources"][0]["cached"] is False
    assert second["external_sources"][0]["cached"] is True

    # Another organisation never reads org A's cache entry.
    await client.post(f"{BASE}/lookup", json=payload, headers=org_b_headers)
    assert len(provider.requests) == 2

    # An expired entry is fetched again.
    monkeypatch.setattr(intel_providers, "CACHE_TTL_SECONDS", -1)
    intel_providers.cache_clear()
    await client.post(f"{BASE}/lookup", json=payload, headers=org_a_headers)
    await client.post(f"{BASE}/lookup", json=payload, headers=org_a_headers)
    assert len(provider.requests) == 4


async def test_tenant_integration_key_is_decrypted_and_used_only_for_that_tenant(
    client, db_session, org_a, org_a_headers, org_b_headers, monkeypatch,
):
    from src.integrations.models import InstalledIntegration

    org_a_id = org_a.id
    connector = await _connector(db_session, "virustotal")
    db_session.add(InstalledIntegration(
        connector_id=connector.id,
        organization_id=org_a_id,
        display_name="VT",
        config_encrypted="{}",
        auth_credentials_encrypted=encrypt_secret_json({"api_key": "tenant-a-vt"}),
    ))
    await db_session.commit()
    provider = _install(monkeypatch, _Provider({"www.virustotal.com": _vt_ok(malicious=1)}))
    payload = {"indicator": "tenant.pysoar-tests.io", "type": "domain"}

    body_a = (await client.post(f"{BASE}/lookup", json=payload, headers=org_a_headers)).json()
    vt_a = next(p for p in body_a["providers"] if p["provider"] == "virustotal")
    assert vt_a["status"] == "ok" and vt_a["key_source"] == "integration"
    assert provider.requests[0].headers["x-apikey"] == "tenant-a-vt"

    body_b = (await client.post(f"{BASE}/lookup", json=payload, headers=org_b_headers)).json()
    assert "virustotal" in body_b["not_configured"]
    assert len(provider.requests) == 1


async def test_ip_lookup_type_matches_stored_variants(client, db_session, org_a, org_a_headers):
    org_a_id = org_a.id
    db_session.add(ThreatIndicator(
        indicator_type="ipv4", value="203.0.113.77", severity="high", source="tests",
        organization_id=org_a_id, is_active=True, confidence=80, tags=["c2"],
    ))
    await db_session.commit()
    body = (await client.post(f"{BASE}/lookup", json={"indicator": "203.0.113.77", "type": "ip"}, headers=org_a_headers)).json()
    assert body["sources"] and body["sources"][0]["verdict"] == "malicious"
    assert body["type"] == "ipv4"


async def test_enrich_indicator_runs_providers_and_stores_the_outcome(client, db_session, org_a_headers, monkeypatch):
    created = await client.post(
        f"{BASE}/indicators",
        json={"indicator_type": "domain", "value": f"{_uid()}.pysoar-tests.io", "severity": "medium"},
        headers=org_a_headers,
    )
    assert created.status_code == 201, created.text
    indicator_id = created.json()["id"]
    _platform_keys(monkeypatch, abuse=False)
    _install(monkeypatch, _Provider({
        "www.virustotal.com": _vt_ok(malicious=0),
        "otx.alienvault.com": lambda _r: httpx.Response(500, text="boom"),
    }))

    resp = await client.post(f"{BASE}/indicators/{indicator_id}/enrich", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "enriched"
    statuses = {p["provider"]: p["status"] for p in body["providers"]}
    assert statuses == {"virustotal": "ok", "abuseipdb": "unsupported_type", "otx": "error"}
    assert any(e.startswith("otx:") for e in body["external_errors"])

    db_session.expire_all()
    row = (await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.id == indicator_id))).scalar_one()
    stored = row.context["external_enrichment"]
    assert stored["status"] == "ok"
    assert {p["provider"] for p in stored["providers"]} == {"virustotal", "abuseipdb", "otx"}


async def test_ioc_enrich_records_external_provider_states(client, org_a_headers, monkeypatch):
    created = await client.post(
        "/api/v1/iocs",
        json={"value": "198.51.100.99", "ioc_type": "ipv4", "threat_level": "medium"},
        headers=org_a_headers,
    )
    assert created.status_code == 201, created.text
    _platform_keys(monkeypatch, vt=False, otx=False)
    _install(monkeypatch, _Provider({"api.abuseipdb.com": _abuse_ok(score=30)}))

    resp = await client.post(f"/api/v1/iocs/{created.json()['id']}/enrich", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    external = resp.json()["enrichment_data"]["external"]
    assert external["status"] == "ok"
    assert external["results"]["abuseipdb"]["verdict"] == "suspicious"
    assert set(external["not_configured"]) == {"virustotal", "otx"}


async def test_iocs_list_type_filter_covers_variants_and_platform_rows(client, db_session, org_a, org_b, org_a_headers):
    org_a_id, org_b_id = org_a.id, org_b.id
    tag = _uid()
    db_session.add_all([
        ThreatIndicator(indicator_type="ipv4", value=f"10.1.0.1-{tag}", organization_id=org_a_id, severity="low", source="t"),
        ThreatIndicator(indicator_type="cidr", value=f"10.2.0.0/16-{tag}", organization_id=None, severity="low", source="t"),
        ThreatIndicator(indicator_type="ipv6", value=f"fd00::1-{tag}", organization_id=org_b_id, severity="low", source="t"),
    ])
    await db_session.commit()
    resp = await client.get("/api/v1/iocs", params={"ioc_type": "ip", "search": tag, "size": 50}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    values = {i["value"] for i in resp.json()["items"]}
    assert values == {f"10.1.0.1-{tag}", f"10.2.0.0/16-{tag}"}


# --------------------------------------------------------------------------
# Feed polling
# --------------------------------------------------------------------------


async def _feed(db_session, *, org_id, builtin: bool, url: str) -> str:
    feed = ThreatFeed(
        name=f"feed {_uid()}",
        feed_type="plain",
        url=url,
        provider="tests",
        is_enabled=True,
        is_builtin=builtin,
        organization_id=org_id,
        total_indicators=0,
        tags=[],
    )
    db_session.add(feed)
    await db_session.commit()
    return feed.id


def _feed_body(lines: list[str]) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _request: httpx.Response(200, content="\n".join(lines).encode())


async def test_tenant_feed_rows_are_stamped_with_the_tenant(db_session, org_a, monkeypatch):
    org_a_id = org_a.id
    _install(monkeypatch, _Provider({"feeds.pysoar-tests.io": _feed_body(["198.51.100.31", "198.51.100.32"])}))
    feed_id = await _feed(db_session, org_id=org_a_id, builtin=False, url="https://feeds.pysoar-tests.io/a.txt")

    assert await FeedManager().poll_feed(feed_id) == 2
    db_session.expire_all()
    orgs = (await db_session.execute(
        select(ThreatIndicator.organization_id).where(ThreatIndicator.feed_id == feed_id)
    )).scalars().all()
    assert orgs == [org_a_id, org_a_id]


async def test_builtin_platform_feed_rows_are_platform_intel(db_session, monkeypatch):
    _install(monkeypatch, _Provider({"feeds.pysoar-tests.io": _feed_body(["198.51.100.41"])}))
    feed_id = await _feed(db_session, org_id=None, builtin=True, url="https://feeds.pysoar-tests.io/b.txt")
    assert await FeedManager().poll_feed(feed_id) == 1
    db_session.expire_all()
    orgs = (await db_session.execute(
        select(ThreatIndicator.organization_id).where(ThreatIndicator.feed_id == feed_id)
    )).scalars().all()
    assert orgs == [None]


async def test_ownerless_custom_feed_is_refused_with_a_reason(db_session, monkeypatch):
    provider = _install(monkeypatch, _Provider({"feeds.pysoar-tests.io": _feed_body(["198.51.100.51"])}))
    feed_id = await _feed(db_session, org_id=None, builtin=False, url="https://feeds.pysoar-tests.io/c.txt")
    assert await FeedManager().poll_feed(feed_id) == 0
    assert provider.requests == []
    db_session.expire_all()
    feed = (await db_session.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))).scalar_one()
    assert "no organisation" in (feed.last_error or "")


async def test_feed_url_resolving_internal_is_refused_and_recorded(db_session, org_a, monkeypatch):
    org_a_id = org_a.id
    monkeypatch.setattr(netguard, "_getaddrinfo", _resolver("10.0.0.5"))
    provider = _install(monkeypatch, _Provider({"feeds.pysoar-tests.io": _feed_body(["198.51.100.61"])}))
    feed_id = await _feed(db_session, org_id=org_a_id, builtin=False, url="https://feeds.pysoar-tests.io/d.txt")
    assert await FeedManager().poll_feed(feed_id) == 0
    assert provider.requests == []
    db_session.expire_all()
    feed = (await db_session.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))).scalar_one()
    assert (feed.last_error or "").startswith("URL refused")


async def test_feed_list_is_own_plus_platform(client, db_session, org_a, org_b, org_a_headers):
    org_a_id, org_b_id = org_a.id, org_b.id
    own = await _feed(db_session, org_id=org_a_id, builtin=False, url="https://feeds.pysoar-tests.io/own.txt")
    platform = await _feed(db_session, org_id=None, builtin=True, url="https://feeds.pysoar-tests.io/plat.txt")
    other = await _feed(db_session, org_id=org_b_id, builtin=False, url="https://feeds.pysoar-tests.io/other.txt")
    resp = await client.get(f"{BASE}/feeds", params={"size": 200}, headers=org_a_headers)
    ids = {f["id"] for f in resp.json()["items"]}
    assert own in ids and platform in ids and other not in ids


async def test_dashboard_coverage_and_top_tags_are_computed(client, db_session, org_a, org_a_headers):
    from datetime import datetime, timezone

    org_a_id = org_a.id
    tag = f"tag-{_uid()}"
    db_session.add(ThreatFeed(
        name=f"fresh {_uid()}", feed_type="plain", url="https://feeds.pysoar-tests.io/f.txt", provider="t",
        is_enabled=True, is_builtin=False, organization_id=org_a_id, total_indicators=0, tags=[],
        last_success_at=datetime.now(timezone.utc),
    ))
    db_session.add_all([
        ThreatIndicator(indicator_type="domain", value=f"{i}-{tag}.example", organization_id=org_a_id,
                        severity="low", source="t", tags=[tag],
                        )
        for i in range(3)
    ])
    await db_session.commit()
    body = (await client.get(f"{BASE}/dashboard", headers=org_a_headers)).json()
    assert body["coverage_basis"]
    assert body["feeds_polled_24h"] >= 1
    assert 0 < body["coverage_score"] <= 100
    assert tag in body["top_tags"]
    assert body["top_tags_sample_size"] >= 3


async def test_export_csv_and_stix_are_real_formats(client, db_session, org_a, org_a_headers):
    org_a_id = org_a.id
    value = f"{_uid()}.pysoar-tests.io"
    db_session.add(ThreatIndicator(indicator_type="domain", value=value, organization_id=org_a_id,
                                   severity="high", source="t", is_active=True, tags=["x"],
    ))
    await db_session.commit()
    csv_resp = await client.get(f"{BASE}/export", params={"format": "csv"}, headers=org_a_headers)
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert value in csv_resp.text
    stix = (await client.get(f"{BASE}/export", params={"format": "stix"}, headers=org_a_headers)).json()
    assert stix["type"] == "bundle"
    patterns = [o["pattern"] for o in stix["objects"]]
    assert f"[domain-name:value = '{value}']" in patterns


async def test_poll_all_feeds_reports_a_failed_feed(db_session, org_a, monkeypatch):
    org_a_id = org_a.id
    feed_id = await _feed(db_session, org_id=org_a_id, builtin=False, url="https://feeds.pysoar-tests.io/e.txt")

    async def boom(_self, _feed_id: str) -> int:
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(FeedManager, "poll_feed", boom)
    results = await FeedManager().poll_all_feeds(only_due=False)
    assert results[feed_id] == -1
    db_session.expire_all()
    feed = (await db_session.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))).scalar_one()
    assert "parser exploded" in (feed.last_error or "")


def test_intel_outbound_is_netguard() -> None:
    """The intel / dark-web guard is the platform guard, not a copy."""
    assert outbound.IntelOutboundRefused is netguard.OutboundTargetRefused
    assert not hasattr(outbound, "refusal_reason")
    assert json.dumps(sorted(outbound.__all__))
