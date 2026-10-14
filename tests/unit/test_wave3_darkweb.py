"""Wave 3 (W3-B): dark-web monitors search their own terms.

Source HTTP is mocked at the transport boundary only (``src.intel.outbound``
-> ``httpx.MockTransport``, DNS steered through ``netguard._getaddrinfo``);
term matching, HIBP handling, persistence, credential-leak rows, routes and
the dashboard run the production code.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable

import httpx
import pytest
from sqlalchemy import select

from src.core.config import settings
from src.darkweb import engine as dw_engine
from src.darkweb.models import BrandThreat, CredentialLeak, DarkWebFinding, DarkWebMonitor
from src.darkweb.monitor_scan import MonitorTerms, parse_term_list, scan_monitor
from src.integrations import netguard
from src.intel import outbound

pytestmark = pytest.mark.asyncio

BASE = "/api/v1/darkweb"
PUBLIC_IP = "93.184.216.34"


def _uid() -> str:
    return uuid.uuid4().hex[:8]


class _Sources:
    def __init__(self, answers: dict[str, Callable[[httpx.Request], httpx.Response]]):
        self.answers = answers
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.answers.get(request.headers.get("host", ""))
        if handler is None:
            return httpx.Response(599)
        return handler(request)

    def paths(self, host: str) -> list[str]:
        return [r.url.path for r in self.requests if r.headers.get("host") == host]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    async def resolve(_host: str, port: int) -> list[tuple[Any, ...]]:
        return [(None, None, None, "", (PUBLIC_IP, port))]

    monkeypatch.setattr(netguard, "_getaddrinfo", resolve)
    monkeypatch.setattr(outbound, "TRANSPORT", httpx.MockTransport(_Sources({})))
    monkeypatch.setattr(dw_engine, "HIBP_REQUEST_SPACING_SECONDS", 0)
    for attr in ("hibp_api_key", "darkweb_marketplace_feed_url"):
        monkeypatch.setattr(settings, attr, None)
    for env in ("HIBP_API_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY", "DARKWEB_MARKETPLACE_FEED_URL"):
        monkeypatch.delenv(env, raising=False)


def _install(monkeypatch, sources: _Sources) -> _Sources:
    monkeypatch.setattr(outbound, "TRANSPORT", httpx.MockTransport(sources))
    return sources


def _hibp(breaches: list[dict] | None = None, account: dict[str, list[dict]] | None = None):
    """HIBP: /breaches (catalogue or ?domain=), /breachedaccount/<email>, others 404."""
    breaches = breaches or []
    account = account or {}

    def answer(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v3/breaches":
            domain = request.url.params.get("domain")
            rows = [b for b in breaches if not domain or b.get("Domain") == domain]
            return httpx.Response(200, json=rows)
        if path.startswith("/api/v3/breachedaccount/"):
            email = path.rsplit("/", 1)[1]
            if request.headers.get("hibp-api-key") != "hibp-test-key":
                return httpx.Response(401)
            rows = account.get(email)
            return httpx.Response(200, json=rows) if rows else httpx.Response(404)
        return httpx.Response(404)

    return answer


def _recent_breach(name: str, domain: str, title: str | None = None) -> dict:
    return {
        "Name": name, "Title": title or name, "Domain": domain, "AddedDate": "2099-01-01T00:00:00Z",
        "BreachDate": "2026-09-01", "PwnCount": 1200, "DataClasses": ["Email addresses"], "IsVerified": False,
        "Description": f"{name} breach",
    }


def _urlhaus(urls: list[str]):
    return lambda _request: httpx.Response(200, json={"query_status": "ok", "urls": [
        {"id": str(i), "url": u, "threat": "malware_download", "url_status": "online", "tags": ["exe"]}
        for i, u in enumerate(urls)
    ]})


async def _monitor(db_session, org_id: str, **terms: Any) -> DarkWebMonitor:
    monitor = DarkWebMonitor(organization_id=org_id, name=f"m {_uid()}", **terms)
    db_session.add(monitor)
    await db_session.commit()
    return monitor


async def _findings(db_session, monitor_id: str) -> list[DarkWebFinding]:
    db_session.expire_all()
    return list((await db_session.execute(
        select(DarkWebFinding).where(DarkWebFinding.monitor_id == monitor_id)
    )).scalars().all())


# --------------------------------------------------------------------------
# Term parsing
# --------------------------------------------------------------------------


def test_term_lists_accept_lists_and_legacy_json_strings():
    assert parse_term_list(["acme", " "]) == ["acme"]
    assert parse_term_list('["acme.com", "acme"]') == ["acme.com", "acme"]
    assert parse_term_list('"[\\"double.example\\"]"') == ["double.example"]
    assert parse_term_list(None) == []
    terms = MonitorTerms(search_terms=["Acme Corp", "ab"], domains=["acme.com"], emails=["soc@acme-mail.io"])
    assert terms.match_terms() == ["acme corp", "acme.com", "acme-mail.io"]


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


async def test_each_monitor_gets_only_feed_items_that_mention_its_terms(db_session, org_a, org_b, monkeypatch):
    org_a_id, org_b_id = org_a.id, org_b.id
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "abuse-key")
    sources = _install(monkeypatch, _Sources({
        "haveibeenpwned.com": _hibp(breaches=[
            _recent_breach("AcmeCorp", "acmecorp-tests.io"),
            _recent_breach("Unrelated", "unrelated.example"),
        ]),
        "urlhaus-api.abuse.ch": _urlhaus([
            "http://login-acmecorp-tests.io.phish.example/x",
            "http://globex-tests.io/payload.exe",
            "http://nobody.example/a",
        ]),
        "threatfox-api.abuse.ch": lambda _r: httpx.Response(200, json={"query_status": "ok", "data": []}),
    }))
    mon_a = await _monitor(db_session, org_a_id, search_terms=["acmecorp-tests.io"])
    mon_b = await _monitor(db_session, org_b_id, search_terms=["globex-tests"])
    mon_a_id, mon_b_id = mon_a.id, mon_b.id

    out_a = await scan_monitor(db_session, mon_a)
    out_b = await scan_monitor(db_session, mon_b)
    await db_session.commit()

    assert out_a.status == "completed" and out_b.status == "completed"
    assert out_a.sources["urlhaus"]["status"] == "ok" and out_a.sources["urlhaus"]["matched"] == 1
    assert out_a.sources["otx"]["status"] == "not_configured"
    assert out_a.sources["hibp_account"]["status"] == "skipped"

    a_rows = await _findings(db_session, mon_a_id)
    a_titles = sorted(r.title for r in a_rows)
    assert a_titles == ["Breach: AcmeCorp", "URLhaus: malware_download URL"]
    assert all(r.organization_id == org_a_id for r in a_rows)
    feed_row = next(r for r in a_rows if r.source_platform == "threat_intel_feed")
    assert feed_row.finding_type == "threat_feed_match"
    assert feed_row.affected_assets["matched_terms"] == ["acmecorp-tests.io"]
    assert "Matched monitor terms" in feed_row.description
    platforms = {r.source_platform for r in a_rows}

    b_rows = await _findings(db_session, mon_b_id)
    assert [r.title for r in b_rows] == ["URLhaus: malware_download URL"]
    assert b_rows[0].organization_id == org_b_id
    platforms |= {r.source_platform for r in b_rows}
    # Nothing is labelled as a paste site / Tor forum / Telegram channel.
    assert platforms <= {"breach_database", "threat_intel_feed"}
    # abuse.ch received the Auth-Key.
    assert all(r.headers.get("auth-key") == "abuse-key" for r in sources.requests
               if r.headers.get("host", "").endswith("abuse.ch"))

    # A second scan records nothing new (dedup per organisation).
    mon_a = (await db_session.execute(select(DarkWebMonitor).where(DarkWebMonitor.id == mon_a_id))).scalar_one()
    again = await scan_monitor(db_session, mon_a)
    assert again.created == 0 and again.skipped_duplicate == 2


async def test_hibp_account_lookup_with_key_creates_credential_leaks(db_session, org_a, monkeypatch):
    org_a_id = org_a.id
    monkeypatch.setenv("HIBP_API_KEY", "hibp-test-key")
    email = f"ciso-{_uid()}@acme-tests.io"
    sources = _install(monkeypatch, _Sources({"haveibeenpwned.com": _hibp(account={email: [
        {"Name": "BigLeak", "BreachDate": "2025-05-01", "PwnCount": 20_000_000, "DataClasses": ["Passwords"],
         "IsVerified": True, "Domain": "bigleak.example", "Description": "big"},
    ]})}))
    monitor = await _monitor(db_session, org_a_id, emails_watched=[email])
    monitor_id = monitor.id

    outcome = await scan_monitor(db_session, monitor, scan_type="quick")
    await db_session.commit()

    assert outcome.sources["hibp_account"]["status"] == "ok"
    assert outcome.sources["hibp_account"]["matched"] == 1
    assert outcome.credential_leaks_created == 1
    assert len(outcome.criticals) == 1
    account_calls = [r for r in sources.requests if "/breachedaccount/" in r.url.path]
    assert account_calls and account_calls[0].headers["hibp-api-key"] == "hibp-test-key"

    rows = await _findings(db_session, monitor_id)
    assert len(rows) == 1 and rows[0].finding_type == "credential_leak" and rows[0].severity == "critical"
    leak = (await db_session.execute(select(CredentialLeak).where(CredentialLeak.finding_id == rows[0].id))).scalar_one()
    assert leak.email == email and leak.organization_id == org_a_id and leak.breach_source == "BigLeak"


async def test_hibp_account_without_key_is_not_configured(db_session, org_a, monkeypatch):
    org_a_id = org_a.id
    sources = _install(monkeypatch, _Sources({"haveibeenpwned.com": _hibp()}))
    monitor = await _monitor(db_session, org_a_id, emails_watched=[f"x-{_uid()}@acme-tests.io"])
    outcome = await scan_monitor(db_session, monitor, scan_type="quick")
    assert outcome.sources["hibp_account"]["status"] == "not_configured"
    assert "HIBP_API_KEY" in outcome.sources["hibp_account"]["reason"]
    assert not any("/breachedaccount/" in r.url.path for r in sources.requests)
    assert outcome.status == "completed"


async def test_rejected_hibp_key_is_an_error_not_an_empty_result(db_session, org_a, monkeypatch):
    org_a_id = org_a.id
    monkeypatch.setenv("HIBP_API_KEY", "wrong-key")
    _install(monkeypatch, _Sources({"haveibeenpwned.com": _hibp()}))
    monitor = await _monitor(db_session, org_a_id, emails_watched=[f"y-{_uid()}@acme-tests.io"])
    outcome = await scan_monitor(db_session, monitor, scan_type="quick")
    assert outcome.sources["hibp_account"]["status"] == "error"
    assert "401" in outcome.sources["hibp_account"]["error"]


async def test_monitor_without_terms_searches_nothing(client, db_session, org_a, org_a_admin_headers, monkeypatch):
    org_a_id = org_a.id
    sources = _install(monkeypatch, _Sources({"haveibeenpwned.com": _hibp()}))
    monitor = await _monitor(db_session, org_a_id)
    resp = await client.post(f"{BASE}/monitors/{monitor.id}/trigger-scan", json={"scan_type": "full"}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "no_terms"
    assert body["new_findings"] == 0
    assert all(s["status"] == "skipped" for s in body["sources"].values())
    assert sources.requests == []


async def test_trigger_scan_reports_sources_and_persists(client, org_a_admin_headers, monkeypatch):
    _install(monkeypatch, _Sources({"haveibeenpwned.com": _hibp(breaches=[_recent_breach("Initech", "initech-tests.io")])}))
    created = await client.post(
        f"{BASE}/monitors",
        json={"name": f"Initech {_uid()}", "search_terms": ["initech"], "domains_watched": ["initech-tests.io"]},
        headers=org_a_admin_headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["search_terms"] == ["initech"]
    monitor_id = created.json()["id"]

    resp = await client.post(f"{BASE}/monitors/{monitor_id}/trigger-scan", json={"scan_type": "full"}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "completed"
    assert set(body["terms_searched"]) == {"initech", "initech-tests.io"}
    assert body["sources"]["hibp_domain"]["status"] == "ok"
    assert body["sources"]["hibp_breach_catalogue"]["matched"] == 1
    assert body["sources"]["urlhaus"]["status"] == "not_configured"
    assert "ABUSECH_AUTH_KEY" in body["sources"]["urlhaus"]["reason"]
    # Domain lookup and catalogue item are the same breach seen twice; both are recorded once each.
    assert body["new_findings"] == 2

    listed = await client.get(f"{BASE}/findings", params={"monitor_id": monitor_id}, headers=org_a_admin_headers)
    assert listed.json()["total"] == 2


async def test_every_source_failing_is_502_with_sources(client, db_session, org_a, org_a_admin_headers, monkeypatch):
    org_a_id = org_a.id
    _install(monkeypatch, _Sources({"haveibeenpwned.com": lambda _r: httpx.Response(503)}))
    monitor = await _monitor(db_session, org_a_id, domains_watched=["down-tests.io"])
    monitor_id = monitor.id
    resp = await client.post(f"{BASE}/monitors/{monitor_id}/trigger-scan", json={"scan_type": "quick"}, headers=org_a_admin_headers)
    assert resp.status_code == 502, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "darkweb_scan_failed"
    assert detail["sources"]["hibp_breach_catalogue"]["status"] == "error"
    assert await _findings(db_session, monitor_id) == []


async def test_credential_context_reads_legacy_json_string_watch_lists(db_session, org_a):
    from src.darkweb.tasks import _credential_context_async

    org_a_id = org_a.id
    monitor = await _monitor(db_session, org_a_id, domains_watched='["legacy-tests.io"]', emails_watched='["a@legacy-tests.io"]')
    finding = DarkWebFinding(organization_id=org_a_id, monitor_id=monitor.id, title="t", description="d")
    db_session.add(finding)
    await db_session.commit()
    ctx = await _credential_context_async(finding.id)
    assert ctx["monitored_domains"] == ["legacy-tests.io"]
    assert ctx["monitored_emails"] == ["a@legacy-tests.io"]


# --------------------------------------------------------------------------
# Honest routes
# --------------------------------------------------------------------------


async def test_takedown_is_an_honest_501(client, db_session, org_a, org_a_headers):
    org_a_id = org_a.id
    monitor = await _monitor(db_session, org_a_id, search_terms=["x"])
    finding = DarkWebFinding(organization_id=org_a_id, monitor_id=monitor.id, title="t")
    db_session.add(finding)
    await db_session.flush()
    threat = BrandThreat(organization_id=org_a_id, finding_id=finding.id, threat_type="domain_typosquat",
                         target_brand="acme", malicious_domain="acrne-tests.io")
    db_session.add(threat)
    await db_session.commit()
    threat_id = threat.id

    resp = await client.post(f"{BASE}/brand-threats/{threat_id}/initiate-takedown", headers=org_a_headers)
    assert resp.status_code == 501
    assert resp.json()["detail"]["error"] == "not_implemented"
    assert resp.json()["detail"]["reason"] == "no_takedown_provider"
    db_session.expire_all()
    row = (await db_session.execute(select(BrandThreat).where(BrandThreat.id == threat_id))).scalar_one()
    assert row.takedown_status == "identified"


async def test_bulk_remediate_records_only(client, db_session, org_a, org_a_headers):
    org_a_id = org_a.id
    monitor = await _monitor(db_session, org_a_id, search_terms=["x"])
    finding = DarkWebFinding(organization_id=org_a_id, monitor_id=monitor.id, title="t")
    db_session.add(finding)
    await db_session.flush()
    leak = CredentialLeak(organization_id=org_a_id, finding_id=finding.id, email="u@acme-tests.io", password_type="unknown")
    db_session.add(leak)
    await db_session.commit()
    resp = await client.post(
        f"{BASE}/credentials/bulk-remediate",
        json={"credential_ids": [leak.id], "action": "password_reset"},
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["execution"] == "recorded_only"
    assert body["recorded"] == 1 and body["password_reset_sent"] == 0


async def test_dashboard_reports_real_cadence_sources_and_labels(client, db_session, org_a, org_a_headers):
    org_a_id = org_a.id
    await _monitor(db_session, org_a_id, search_terms=["acme"], enabled=True)
    body = (await client.get(f"{BASE}/dashboard", headers=org_a_headers)).json()
    assert body["scan_interval_minutes"] == 30
    assert body["scan_frequency"] == "every 30 minutes"
    assert body["sources"]["hibp_account"] == {
        "label": body["sources"]["hibp_account"]["label"], "configured": False, "requires": "HIBP_API_KEY",
    }
    assert body["sources"]["hibp_domain"]["configured"] is True
    assert "not a dark-web forum" in body["source_platform_labels"]["threat_intel_feed"]
