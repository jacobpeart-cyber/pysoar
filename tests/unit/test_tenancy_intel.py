"""Wave-1 tenancy and RBAC for the threat-intel router (/api/v1/threat-intel).

Covers: org stamping, cross-tenant 404s, the NULL-organisation platform-intel
convention (readable by every tenant, read-only to them), per-organisation
feed ingestion and dedup, role gates (viewer / analyst / admin / platform
superuser) and the org-less superuser refusal.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from src.intel.feeds import FeedManager
from src.intel.models import ThreatFeed, ThreatIndicator
from tests.helpers.tenancy import assert_tenant_isolated

pytestmark = pytest.mark.asyncio

BASE = "/api/v1/threat-intel"


def _uid() -> str:
    return uuid.uuid4().hex[:10]


async def _platform_feed(db_session) -> str:
    feed = ThreatFeed(
        name=f"Platform feed {_uid()}",
        feed_type="plain",
        url="https://feeds.pysoar-tests.io/list.txt",
        provider="tests",
        is_enabled=True,
        is_builtin=True,
        organization_id=None,
        total_indicators=0,
        tags=[],
    )
    db_session.add(feed)
    await db_session.commit()
    return feed.id


async def _platform_indicator(db_session, value: str) -> str:
    ind = ThreatIndicator(
        indicator_type="domain",
        value=value,
        severity="high",
        source="platform",
        organization_id=None,
        is_active=True,
        tags=[],
    )
    db_session.add(ind)
    await db_session.commit()
    return ind.id


async def _create_indicator(client, headers, value: str) -> str:
    resp = await client.post(
        f"{BASE}/indicators",
        json={"indicator_type": "domain", "value": value, "severity": "high"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _create_feed(client, headers) -> str:
    resp = await client.post(
        f"{BASE}/feeds",
        json={
            "name": f"Org feed {_uid()}",
            "feed_type": "plain",
            "provider": "tests",
            "url": "https://feeds.pysoar-tests.io/org.txt",
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# --------------------------------------------------------------------------
# Stamping + isolation
# --------------------------------------------------------------------------


async def test_indicator_is_stamped_and_isolated(client, db_session, org_a, org_a_headers, org_b_headers):
    org_a_id = org_a.id
    value = f"a-{_uid()}.pysoar-tests.io"
    ind_id = await _create_indicator(client, org_a_headers, value)

    row = (await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.id == ind_id))).scalar_one()
    assert row.organization_id == org_a_id

    await assert_tenant_isolated(client, "GET", f"{BASE}/indicators/{ind_id}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{BASE}/indicators/{ind_id}", org_b_headers, json={"severity": "low"}
    )
    await assert_tenant_isolated(client, "DELETE", f"{BASE}/indicators/{ind_id}", org_b_headers)
    await assert_tenant_isolated(client, "POST", f"{BASE}/indicators/{ind_id}/whitelist", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{BASE}/indicators/{ind_id}/timeline", org_b_headers)
    await assert_tenant_isolated(
        client, "POST", f"{BASE}/sightings", org_b_headers, json={"indicator_id": ind_id, "source": "x"}
    )

    listing = await client.get(f"{BASE}/indicators", params={"search": value}, headers=org_b_headers)
    assert listing.status_code == 200
    assert ind_id not in [i["id"] for i in listing.json()["items"]]

    lookup = await client.post(f"{BASE}/lookup", json={"indicator": value, "type": "domain"}, headers=org_b_headers)
    assert lookup.status_code == 200
    assert lookup.json()["sources"] == []

    own = await client.get(f"{BASE}/indicators/{ind_id}", headers=org_a_headers)
    assert own.status_code == 200


async def test_feed_is_stamped_and_isolated(client, db_session, org_a, org_a_admin_headers, org_b_headers):
    org_a_id = org_a.id
    feed_id = await _create_feed(client, org_a_admin_headers)
    row = (await db_session.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))).scalar_one()
    assert row.organization_id == org_a_id

    await assert_tenant_isolated(client, "GET", f"{BASE}/feeds/{feed_id}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{BASE}/feeds/{feed_id}/stats", org_b_headers)
    listing = await client.get(f"{BASE}/feeds", headers=org_b_headers)
    assert feed_id not in [f["id"] for f in listing.json()["items"]]


@pytest.mark.parametrize(
    "path,payload,label",
    [
        ("actors", {"name": "APT-{u}"}, "actors"),
        ("campaigns", {"name": "Campaign {u}"}, "campaigns"),
        ("reports", {"title": "Report {u}", "report_type": "threat_analysis"}, "reports"),
    ],
)
async def test_actor_campaign_report_isolated(client, org_a_headers, org_b_headers, path, payload, label):
    body = {k: v.format(u=_uid()) for k, v in payload.items()}
    resp = await client.post(f"{BASE}/{path}", json=body, headers=org_a_headers)
    assert resp.status_code == 201, resp.text
    obj_id = resp.json()["id"]

    await assert_tenant_isolated(client, "GET", f"{BASE}/{path}/{obj_id}", org_b_headers)
    await assert_tenant_isolated(client, "PUT", f"{BASE}/{path}/{obj_id}", org_b_headers, json={})
    await assert_tenant_isolated(client, "DELETE", f"{BASE}/{path}/{obj_id}", org_b_headers)
    listing = await client.get(f"{BASE}/{path}", headers=org_b_headers)
    assert listing.status_code == 200
    assert obj_id not in [i["id"] for i in listing.json()["items"]]


async def test_campaign_cannot_link_other_tenants_actor(client, org_a_headers, org_b_headers):
    actor = await client.post(f"{BASE}/actors", json={"name": f"APT-{_uid()}"}, headers=org_a_headers)
    actor_id = actor.json()["id"]
    resp = await client.post(
        f"{BASE}/campaigns", json={"name": f"C {_uid()}", "actor_id": actor_id}, headers=org_b_headers
    )
    assert resp.status_code == 404


async def test_bulk_import_rejects_other_tenants_feed(client, org_a_admin_headers, org_b_headers):
    feed_id = await _create_feed(client, org_a_admin_headers)
    resp = await client.post(
        f"{BASE}/indicators/bulk",
        json={"feed_id": feed_id, "source": "x", "indicators": [{"indicator_type": "domain", "value": "x.pysoar-tests.io"}]},
        headers=org_b_headers,
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# NULL-organisation platform intel
# --------------------------------------------------------------------------


async def test_platform_indicator_visible_but_read_only(client, db_session, org_a_headers):
    value = f"plat-{_uid()}.pysoar-tests.io"
    plat_id = await _platform_indicator(db_session, value)

    listing = await client.get(f"{BASE}/indicators", params={"search": value}, headers=org_a_headers)
    assert plat_id in [i["id"] for i in listing.json()["items"]]
    assert (await client.get(f"{BASE}/indicators/{plat_id}", headers=org_a_headers)).status_code == 200

    lookup = await client.post(f"{BASE}/lookup", json={"indicator": value, "type": "domain"}, headers=org_a_headers)
    assert lookup.json()["reputation"] == "malicious"

    for method, path, body in [
        ("PUT", f"/indicators/{plat_id}", {"severity": "low"}),
        ("DELETE", f"/indicators/{plat_id}", None),
        ("POST", f"/indicators/{plat_id}/whitelist", None),
        ("POST", f"/indicators/{plat_id}/enrich", None),
    ]:
        resp = await client.request(method, f"{BASE}{path}", json=body, headers=org_a_headers)
        assert resp.status_code == 403, (method, path, resp.text)
        assert resp.json()["detail"]["error"] == "platform_intel_read_only"

    # A sighting is recorded for the tenant but never bumps the shared row.
    sighting = await client.post(
        f"{BASE}/sightings", json={"indicator_id": plat_id, "source": "edr"}, headers=org_a_headers
    )
    assert sighting.status_code == 201, sighting.text
    db_session.expire_all()
    row = (await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.id == plat_id))).scalar_one()
    assert (row.sighting_count or 0) == 0


async def test_platform_feed_visible_but_read_only(client, db_session, org_a_admin_headers):
    feed_id = await _platform_feed(db_session)
    listing = await client.get(f"{BASE}/feeds", params={"size": 200}, headers=org_a_admin_headers)
    assert feed_id in [f["id"] for f in listing.json()["items"]]
    for method, path, body in [
        ("PUT", f"/feeds/{feed_id}", {"description": "x"}),
        ("DELETE", f"/feeds/{feed_id}", None),
        ("POST", f"/feeds/{feed_id}/poll", None),
        ("POST", f"/feeds/{feed_id}/sync", None),
    ]:
        resp = await client.request(method, f"{BASE}{path}", json=body, headers=org_a_admin_headers)
        assert resp.status_code == 403, (method, path, resp.text)
        assert resp.json()["detail"]["error"] == "platform_intel_read_only"


async def test_feed_poll_stamps_org_and_dedups_per_org(db_session, org_a, monkeypatch):
    """An org feed's indicators get the org; a platform feed's get NULL; a
    value already held by the platform is not claimed or touched."""
    org_a_id = org_a.id
    shared_value = f"10.9.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"
    platform_feed_id = await _platform_feed(db_session)
    org_feed = ThreatFeed(
        name=f"Org poll feed {_uid()}",
        feed_type="plain",
        url="https://feeds.pysoar-tests.io/org-poll.txt",
        provider="tests",
        is_enabled=True,
        organization_id=org_a_id,
        total_indicators=0,
        tags=[],
    )
    db_session.add(org_feed)
    await db_session.commit()
    org_feed_id = org_feed.id

    async def fake_fetch(self, feed):
        return f"{shared_value}\n".encode()

    monkeypatch.setattr(FeedManager, "_fetch_feed_data", fake_fetch)

    assert await FeedManager().poll_feed(platform_feed_id) == 1
    assert await FeedManager().poll_feed(org_feed_id) == 1

    db_session.expire_all()
    rows = (
        await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.value == shared_value))
    ).scalars().all()
    by_feed = {r.feed_id: r for r in rows}
    assert by_feed[platform_feed_id].organization_id is None
    assert by_feed[org_feed_id].organization_id == org_a_id
    assert (by_feed[platform_feed_id].sighting_count or 0) == 0


async def test_deduplicate_indicator_is_per_org(db_session, org_a, org_b):
    org_a_id, org_b_id = org_a.id, org_b.id
    feed_id = await _platform_feed(db_session)
    value = f"dedup-{_uid()}.pysoar-tests.io"
    fm = FeedManager()
    first = await fm._deduplicate_indicator("domain", value, feed_id, organization_id=org_a_id)
    assert first is not None and first.organization_id == org_a_id
    # Same value for another org is a new row, not a claim of org A's.
    second = await fm._deduplicate_indicator("domain", value, feed_id, organization_id=org_b_id)
    assert second is not None and second.organization_id == org_b_id
    # Same org again: deduplicated.
    assert await fm._deduplicate_indicator("domain", value, feed_id, organization_id=org_a_id) is None


# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/feeds", {"name": "v", "feed_type": "plain", "provider": "p"}),
        ("PUT", "/feeds/x", {}),
        ("DELETE", "/feeds/x", None),
        ("POST", "/feeds/x/poll", None),
        ("POST", "/feeds/x/sync", None),
        ("POST", "/feeds/register-builtins", None),
        ("POST", "/feeds/poll-all", None),
        ("POST", "/indicators", {"indicator_type": "domain", "value": "v.pysoar-tests.io"}),
        ("POST", "/indicators/bulk", {"indicators": []}),
        ("PUT", "/indicators/x", {}),
        ("DELETE", "/indicators/x", None),
        ("POST", "/indicators/x/enrich", None),
        ("POST", "/indicators/x/whitelist", None),
        ("POST", "/sightings", {"indicator_id": "x"}),
        ("POST", "/actors", {"name": "v"}),
        ("PUT", "/actors/x", {}),
        ("DELETE", "/actors/x", None),
        ("POST", "/campaigns", {"name": "v"}),
        ("PUT", "/campaigns/x", {}),
        ("DELETE", "/campaigns/x", None),
        ("POST", "/reports", {"title": "v", "report_type": "threat_analysis"}),
        ("PUT", "/reports/x", {}),
        ("POST", "/reports/x/publish", None),
        ("DELETE", "/reports/x", None),
    ],
)
async def test_viewer_cannot_write(client, viewer_headers, method, path, body):
    resp = await client.request(method, f"{BASE}{path}", json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/feeds", {"name": "v", "feed_type": "plain", "provider": "p"}),
        ("PUT", "/feeds/x", {}),
        ("DELETE", "/feeds/x", None),
        ("POST", "/feeds/x/poll", None),
        ("POST", "/feeds/x/sync", None),
        ("POST", "/feeds/register-builtins", None),
        ("POST", "/feeds/poll-all", None),
    ],
)
async def test_analyst_cannot_configure_feeds(client, org_a_headers, method, path, body):
    resp = await client.request(method, f"{BASE}{path}", json=body, headers=org_a_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize("path", ["/feeds/register-builtins", "/feeds/poll-all"])
async def test_tenant_admin_cannot_run_platform_feed_actions(client, org_a_admin_headers, path):
    resp = await client.post(f"{BASE}{path}", headers=org_a_admin_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "platform_superuser_required"


async def test_platform_superuser_can_poll_all(client, superuser_headers, monkeypatch):
    called = {}

    async def fake_poll_all(self):
        called["yes"] = True
        return {}

    monkeypatch.setattr(FeedManager, "poll_all_feeds", fake_poll_all)
    resp = await client.post(f"{BASE}/feeds/poll-all", headers=superuser_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "poll_started"
    assert called.get("yes")


async def test_viewer_can_read(client, viewer_headers):
    for path in ("/stats", "/feeds", "/indicators", "/actors", "/campaigns", "/reports", "/dashboard"):
        resp = await client.get(f"{BASE}{path}", headers=viewer_headers)
        assert resp.status_code == 200, (path, resp.text)


@pytest.mark.parametrize("path", ["/stats", "/feeds", "/indicators", "/actors", "/dashboard", "/export"])
async def test_orgless_superuser_refused(client, superuser_headers, path):
    resp = await client.get(f"{BASE}{path}", headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"


# --------------------------------------------------------------------------
# Regressions
# --------------------------------------------------------------------------


async def test_register_builtins_no_longer_collides(client, superuser_headers, monkeypatch):
    """Was: any user could call it and tenant copies of built-in names hit the
    global unique constraint (500). Now: platform registration, superuser only."""

    async def fake_register(self):
        return 0

    monkeypatch.setattr(FeedManager, "register_builtin_feeds", fake_register)
    resp = await client.post(f"{BASE}/feeds/register-builtins", headers=superuser_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "feeds_registered", "count": 0}


async def test_duplicate_feed_name_is_409_not_500(client, org_a_admin_headers):
    name = f"Dup feed {_uid()}"
    body = {"name": name, "feed_type": "plain", "provider": "p"}
    assert (await client.post(f"{BASE}/feeds", json=body, headers=org_a_admin_headers)).status_code == 201
    resp = await client.post(f"{BASE}/feeds", json=body, headers=org_a_admin_headers)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "feed_name_taken"


async def test_duplicate_actor_name_is_409_not_500(client, org_a_headers, org_b_headers):
    name = f"APT-{_uid()}"
    assert (await client.post(f"{BASE}/actors", json={"name": name}, headers=org_a_headers)).status_code == 201
    resp = await client.post(f"{BASE}/actors", json={"name": name}, headers=org_b_headers)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "actor_name_taken"


async def test_lookup_reports_unreadable_integration_credentials(client, db_session, org_a, org_a_headers):
    """Was: credentials json.loads()-ed from an enc:v1 envelope, the failure
    was swallowed and the lookup claimed 'no_integrations_configured'."""
    from src.integrations.models import InstalledIntegration, IntegrationConnector

    org_a_id = org_a.id
    connector = (
        await db_session.execute(select(IntegrationConnector).where(IntegrationConnector.name == "virustotal"))
    ).scalars().first()
    if connector is None:
        connector = IntegrationConnector(
            name="virustotal",
            display_name="VirusTotal",
            category="threat_intel",
            vendor="VirusTotal",
            description="tests",
            supported_actions="[]",
            supported_triggers="[]",
            config_schema="{}",
        )
        db_session.add(connector)
        await db_session.flush()
    inst = InstalledIntegration(
        connector_id=connector.id,
        organization_id=org_a_id,
        display_name="VT",
        config_encrypted="{}",
        auth_credentials_encrypted="enc:v1:not-a-real-envelope",
    )
    db_session.add(inst)
    await db_session.commit()

    resp = await client.post(
        f"{BASE}/lookup", json={"indicator": "unseen.pysoar-tests.io", "type": "domain"}, headers=org_a_headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["external_enrichment"] == "integration_credentials_unreadable"
    assert "virustotal: credentials_unreadable" in body["external_errors"]
