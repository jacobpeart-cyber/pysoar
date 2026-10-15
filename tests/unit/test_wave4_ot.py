"""Wave 4 (W4-C): OT advisories from CISA, agent-commanded actions, alias cleanup.

docs/audit/2026-10-08/posture-risk.md (ot_security): the vulnerability
assessor used a two-entry "simulated" CVE dict, safe shutdown returned a fixed
plan with status "initiated", the segmentation audit stamped zones verified
without auditing, discovery inserted an enum-invalid asset type, and the
dash-prefixed aliases duplicated the underscore routes.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import AgentCommand, EndpointAgent
from src.agents.service import AgentService
from src.integrations import netguard
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.ot_security import advisories
from src.ot_security.actuation import reconcile_pending
from src.ot_security.models import OTAsset, OTICSAdvisory, OTIncident, OTZone
from tests.helpers.tenancy import bearer, make_user

API = "/api/v1/ot_security"
PUBLIC_IP = "104.16.10.10"

FEED = b"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>ICS Advisories</title>
<item>
  <title>Siemens SIMATIC S7-1200 CPU</title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-25-100-01</link>
  <pubDate>Thu, 10 Apr 2025 12:00:00 +0000</pubDate>
  <description>&lt;ul&gt;&lt;li&gt;CVSS v4 9.3&lt;/li&gt;&lt;li&gt;&lt;strong&gt;Vendor&lt;/strong&gt;: Siemens&lt;/li&gt;
  &lt;li&gt;&lt;strong&gt;Equipment&lt;/strong&gt;: SIMATIC S7-1200 CPU family, SIMATIC S7-1500&lt;/li&gt;
  &lt;li&gt;&lt;strong&gt;Vulnerabilities&lt;/strong&gt;: Improper Input Validation&lt;/li&gt;&lt;/ul&gt;
  CVE-2025-11111 and CVE-2025-22222</description>
</item>
<item>
  <title>Schneider Electric Modicon M241</title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-25-101-02</link>
  <description>Vendor: Schneider Electric Equipment: Modicon M241 Vulnerabilities: Missing Authentication CVE-2025-33333</description>
</item>
<item><title>Not an advisory</title><link>https://www.cisa.gov/news</link><description>x</description></item>
</channel></rss>"""


def _dns(monkeypatch: pytest.MonkeyPatch, ip: str = PUBLIC_IP) -> None:
    async def fake(host: str, port: int) -> list[tuple[Any, ...]]:
        return [(2, 1, 6, "", (ip, port))]

    monkeypatch.setattr(netguard, "_getaddrinfo", fake)


def _feed_transport(seen: list[str], body: bytes = FEED, status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(status, content=body, headers={"content-type": "application/rss+xml"})

    return httpx.MockTransport(handler)


async def _admin_b(db: AsyncSession, org_id: str, label: str = "admin-2") -> dict[str, str]:
    return bearer(await make_user(db, role="admin", organization_id=org_id, label=label))


# ---------------------------------------------------------------------------
# CISA ICS advisories
# ---------------------------------------------------------------------------


def test_parse_feed_extracts_vendor_products_and_cves() -> None:
    parsed = advisories.parse_feed(FEED)
    assert [a["advisory_id"] for a in parsed] == ["ICSA-25-100-01", "ICSA-25-101-02"]
    siemens = parsed[0]
    assert siemens["vendor"] == "Siemens"
    assert siemens["products"] == ["SIMATIC S7-1200 CPU family", "SIMATIC S7-1500"]
    assert siemens["cve_ids"] == ["CVE-2025-11111", "CVE-2025-22222"]
    assert siemens["cvss_score"] == 9.3
    assert parsed[1]["vendor"] == "Schneider Electric"


def test_parse_feed_refuses_entity_declarations() -> None:
    evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><rss><channel></channel></rss>'
    with pytest.raises(advisories.AdvisoryFeedUnavailable):
        advisories.parse_feed(evil)


def test_matching_needs_vendor_and_model() -> None:
    parsed = advisories.parse_feed(FEED)
    hit = advisories.match_asset({"vendor": "Siemens AG", "model": "S7-1200"}, parsed)
    assert [m["advisory_id"] for m in hit] == ["ICSA-25-100-01"]
    assert hit[0]["affected_versions_evaluated"] is False
    # An empty vendor used to match every catalogue entry.
    assert advisories.match_asset({"vendor": "", "model": "S7-1200"}, parsed) == []
    assert advisories.match_asset({"vendor": "Siemens", "model": None}, parsed) == []
    assert advisories.match_asset({"vendor": "Rockwell", "model": "S7-1200"}, parsed) == []
    # Word-bounded: "S7-12" is not "S7-1200".
    assert advisories.match_asset({"vendor": "Siemens", "model": "S7-12"}, parsed) == []


async def test_refresh_fetches_through_pinned_transport_and_caches(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a_id = org_a.id
    _dns(monkeypatch)
    seen: list[str] = []
    monkeypatch.setattr(advisories, "_inner_transport", lambda: _feed_transport(seen))

    status_before = (await client.get(f"{API}/advisories/status", headers=org_a_headers)).json()
    assert status_before["status"] == "not_fetched"

    analyst = await client.post(f"{API}/advisories/refresh", headers=org_a_headers)
    assert analyst.status_code == 403
    first = await client.post(f"{API}/advisories/refresh", headers=org_a_admin_headers)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "refreshed" and first.json()["new"] == 2
    # Pinned: the request went to the vetted IP literal.
    assert seen and PUBLIC_IP in seen[0]
    cached = await client.post(f"{API}/advisories/refresh", headers=org_a_admin_headers)
    assert cached.json()["status"] == "cached"
    assert len(seen) == 1

    db_session.add(OTAsset(organization_id=org_a_id, name="plc", asset_type="plc", vendor="Siemens",
                           model="S7-1200", firmware_version="4.2", purdue_level="level1_control",
                           criticality="safety_critical", protocol="s7comm"))
    db_session.add(OTAsset(organization_id=org_a_id, name="hmi", asset_type="hmi", purdue_level="level2_supervisory"))
    await db_session.commit()
    asset_id = (await db_session.execute(select(OTAsset.id).where(OTAsset.name == "plc"))).scalar_one()

    matched = (await client.get(f"{API}/advisories", headers=org_a_headers)).json()
    assert matched["total"] == 1 and matched["unmatchable_assets"] == 1
    assert matched["items"][0]["advisory_id"] == "ICSA-25-100-01"
    risk = (await client.get(f"{API}/assets/{asset_id}/risk_assessment", headers=org_a_headers)).json()
    assert risk["vulnerabilities"] == 1
    assert risk["advisory_feed"]["status"] == "current"
    report = (await client.get(f"{API}/risk_assessment", headers=org_a_headers)).json()
    assert report["advisory_feed"]["entries"] == 2
    levels = {r["name"]: r["risk_level"] for r in report["asset_risks"]}
    assert levels["hmi"] == "low"  # risk can go below "medium" now


async def test_refresh_refuses_internal_resolution_and_keeps_cache(
    client: AsyncClient, org_a_admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dns(monkeypatch, "10.0.0.5")
    seen: list[str] = []
    monkeypatch.setattr(advisories, "_inner_transport", lambda: _feed_transport(seen))
    resp = await client.post(f"{API}/advisories/refresh", params={"force": True}, headers=org_a_admin_headers)
    assert resp.status_code == 502, resp.text
    assert resp.json()["detail"]["error"] == "advisory_feed_unavailable"
    assert seen == []


async def test_without_feed_no_vulnerability_is_invented(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    asset = OTAsset(organization_id=org_a.id, name="plc", asset_type="plc", vendor="Siemens", model="S7-1200",
                    firmware_version="4.2", purdue_level="level1_control")
    db_session.add(asset)
    await db_session.commit()
    resp = await client.post(f"{API}/assets/{asset.id}/firmware_check", headers=org_a_headers)
    assert resp.status_code == 200
    assert resp.json()["vulnerabilities"] == []
    assert resp.json()["advisory_feed"]["status"] in {"not_fetched", "current"}
    if resp.json()["advisory_feed"]["status"] == "not_fetched":
        rows = (await db_session.execute(select(OTICSAdvisory.id))).all()
        assert rows == []


# ---------------------------------------------------------------------------
# safe shutdown through an ot_safe_shutdown agent
# ---------------------------------------------------------------------------


async def _shutdown_setup(db: AsyncSession, org_id: str, capabilities: list[str]) -> dict[str, str]:
    asset = OTAsset(organization_id=org_id, name="plc-1", asset_type="plc", purdue_level="level1_control",
                    ip_address="10.20.0.5", protocol="modbus_tcp")
    agent = EndpointAgent(hostname="ot-gw", status="active", capabilities=capabilities, organization_id=org_id,
                          ip_address="10.20.0.2")
    db.add_all([asset, agent])
    await db.flush()
    incident = OTIncident(organization_id=org_id, title="inc", description="d", incident_type="ransomware",
                          severity="high", affected_assets=[asset.id])
    db.add(incident)
    await db.commit()
    return {"asset": asset.id, "agent": agent.id, "incident": incident.id}


async def test_safe_shutdown_is_queued_for_approval_and_driven_by_the_result(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    ids = await _shutdown_setup(db_session, org_a_id, ["ot_safe_shutdown"])
    path = f"{API}/incidents/{ids['incident']}/safe_shutdown"

    resp = await client.post(path, headers=org_a_admin_headers)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "awaiting_approval"
    assert body["safe_shutdown_initiated"] is False
    command = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == body["command_id"]))).scalar_one()
    assert command.action == "ot_safe_shutdown" and command.approval_required
    assert command.payload["assets"][0]["asset_id"] == ids["asset"]
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "ot_safe_shutdown_requested"))).scalars()
    assert len(audit.all()) == 1

    again = await client.post(path, headers=org_a_admin_headers)
    assert again.status_code == 409 and again.json()["detail"]["error"] == "already_pending"

    other_admin = await make_user(db_session, role="admin", organization_id=org_a_id, label="approver")
    approver_id = other_admin.id
    command = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == body["command_id"]))).scalar_one()
    svc = AgentService(db_session)
    await svc.approve_command(command=command, approver_id=approver_id)
    await db_session.commit()
    queued = (await client.get(path, headers=org_a_admin_headers)).json()
    assert queued["status"] == "queued" and queued["safe_shutdown_initiated"] is False

    agent = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == ids["agent"]))).scalar_one()
    await svc.ingest_result(agent=agent, command_id=command.id, status="success", exit_code=0,
                            stdout="plc-1 placed in STOP via site procedure")
    await db_session.commit()
    done = (await client.get(path, headers=org_a_admin_headers)).json()
    assert done["status"] == "completed"
    assert done["safe_shutdown_initiated"] is True
    assert "STOP" in done["detail"]
    incident = (await client.get(f"{API}/incidents/{ids['incident']}", headers=org_a_admin_headers)).json()
    assert incident["safe_shutdown_initiated"] is True and incident["safe_shutdown_status"] == "completed"


async def test_failed_shutdown_is_failed_and_not_initiated(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    ids = await _shutdown_setup(db_session, org_a_id, ["ot_safe_shutdown"])
    resp = await client.post(f"{API}/incidents/{ids['incident']}/safe_shutdown", headers=org_a_admin_headers)
    command = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == resp.json()["command_id"]))).scalar_one()
    approver = await make_user(db_session, role="admin", organization_id=org_a_id, label="approver2")
    svc = AgentService(db_session)
    await svc.approve_command(command=command, approver_id=approver.id)
    agent = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == ids["agent"]))).scalar_one()
    await svc.ingest_result(agent=agent, command_id=command.id, status="failed", exit_code=2,
                            stderr="controller unreachable")
    await db_session.commit()
    # The beat task path applies the result.
    changed = await reconcile_pending(db_session)
    await db_session.commit()
    assert changed["incidents"] == 1
    db_session.expire_all()
    row = (await db_session.execute(select(OTIncident).where(OTIncident.id == ids["incident"]))).scalar_one()
    assert row.safe_shutdown_status == "failed"
    assert row.safe_shutdown_initiated is False
    assert "controller unreachable" in row.safe_shutdown_detail


async def test_safe_shutdown_refuses_agents_without_the_capability_or_tenant(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_b: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    ids = await _shutdown_setup(db_session, org_a.id, ["ir"])
    other = EndpointAgent(hostname="b-gw", status="active", capabilities=["ot_safe_shutdown"],
                          organization_id=org_b.id)
    db_session.add(other)
    await db_session.commit()
    other_id = other.id
    path = f"{API}/incidents/{ids['incident']}/safe_shutdown"
    resp = await client.post(path, headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "no_capable_agent"
    foreign = await client.post(path, json={"agent_id": other_id}, headers=org_a_admin_headers)
    assert foreign.status_code == 409 and foreign.json()["detail"]["error"] == "agent_not_capable"
    assert (await db_session.execute(select(AgentCommand.id))).all() == []


# ---------------------------------------------------------------------------
# segmentation probe through an ot_segmentation_probe agent
# ---------------------------------------------------------------------------


async def test_segmentation_audit_verifies_only_from_probe_results(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    control = OTZone(organization_id=org_a_id, name="control", purdue_level="level1_control",
                     network_cidr="10.30.0.0/24", allowed_communications=[])
    enterprise = OTZone(organization_id=org_a_id, name="enterprise", purdue_level="level4_enterprise",
                        network_cidr="10.40.0.0/24")
    target = OTAsset(organization_id=org_a_id, name="erp-plc-gw", asset_type="plc", purdue_level="level4_enterprise",
                     ip_address="10.40.0.9", protocol="modbus_tcp")
    agent = EndpointAgent(hostname="probe", status="active", capabilities=["ot_segmentation_probe"],
                          organization_id=org_a_id, ip_address="10.30.0.4")
    db_session.add_all([control, enterprise, target, agent])
    await db_session.commit()
    zone_id, agent_id = control.id, agent.id
    path = f"{API}/zones/{zone_id}/segmentation_audit"

    resp = await client.post(path, headers=org_a_admin_headers)
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "awaiting_approval" and resp.json()["probes_planned"] == 1
    command = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == resp.json()["command_id"]))).scalar_one()
    assert command.payload["probes"] == [{"target_ip": "10.40.0.9", "port": 502, "protocol": "modbus_tcp"}]

    approver = await make_user(db_session, role="admin", organization_id=org_a_id, label="approver3")
    svc = AgentService(db_session)
    await svc.approve_command(command=command, approver_id=approver.id)
    agent_row = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    await svc.ingest_result(agent=agent_row, command_id=command.id, status="success",
                            stdout=json.dumps({"results": [{"target_ip": "10.40.0.9", "port": 502, "reachable": True}]}))
    await db_session.commit()
    first = (await client.get(path, headers=org_a_admin_headers)).json()
    assert first["status"] == "violations_found"
    assert first["segmentation_verified"] is False
    assert first["violations"][0]["target_ip"] == "10.40.0.9"

    second = await client.post(path, headers=org_a_admin_headers)
    assert second.status_code == 202, second.text
    cmd2 = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == second.json()["command_id"]))).scalar_one()
    await svc.approve_command(command=cmd2, approver_id=approver.id)
    await svc.ingest_result(agent=agent_row, command_id=cmd2.id, status="success",
                            stdout=json.dumps({"results": [{"target_ip": "10.40.0.9", "port": 502, "reachable": False}]}))
    await db_session.commit()
    verified = (await client.get(path, headers=org_a_admin_headers)).json()
    assert verified["status"] == "verified" and verified["segmentation_verified"] is True
    zone = (await client.get(f"{API}/zones/{zone_id}", headers=org_a_admin_headers)).json()
    assert zone["segmentation_verified"] is True and zone["segmentation_audit_status"] == "verified"


async def test_segmentation_probe_agent_must_sit_inside_the_zone(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    control = OTZone(organization_id=org_a_id, name="cz", purdue_level="level1_control", network_cidr="10.31.0.0/24")
    other = OTZone(organization_id=org_a_id, name="oz", purdue_level="level3_operations", network_cidr="10.32.0.0/24")
    db_session.add_all([control, other, OTAsset(
        organization_id=org_a_id, name="hist", asset_type="historian", purdue_level="level3_operations",
        ip_address="10.32.0.7", protocol="opc_ua",
    ), EndpointAgent(hostname="elsewhere", status="active", capabilities=["ot_segmentation_probe"],
                     organization_id=org_a_id, ip_address="192.168.1.4")])
    await db_session.commit()
    resp = await client.post(f"{API}/zones/{control.id}/segmentation_audit", headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "no_capable_agent"


# ---------------------------------------------------------------------------
# aliases, discovery, asset types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/v1/ot-security/assets", "/api/v1/ot-security/alerts",
                                  "/api/v1/ot-security/zones", "/api/v1/ot-security/purdue-map"])
async def test_dash_list_duplicates_are_gone(client: AsyncClient, org_a_headers: dict[str, str], path: str) -> None:
    assert (await client.get(path, headers=org_a_headers)).status_code == 404


async def test_moved_dash_routes_answer_410_with_the_new_path(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    discover = await client.post("/api/v1/ot-security/discover", json={"cidr": "10.0.0.0/24"},
                                 headers=org_a_admin_headers)
    assert discover.status_code == 410
    assert discover.json()["detail"]["new_path"] == "/api/v1/ot_security/discover"


async def test_discovered_unknown_asset_type_lists_cleanly(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    db_session.add(OTAsset(organization_id=org_a.id, name="discovered-10.1.1.1", asset_type="unknown",
                           purdue_level="level3_operations", ip_address="10.1.1.1"))
    await db_session.commit()
    resp = await client.get(f"{API}/assets", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["items"][0]["asset_type"] == "unknown"


async def test_export_csv_is_formula_safe(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    db_session.add(OTAsset(organization_id=org_a.id, name="=cmd|'/c calc'!A1", asset_type="plc",
                           purdue_level="level1_control"))
    await db_session.commit()
    resp = await client.get(f"{API}/export", params={"format": "csv"}, headers=org_a_headers)
    assert resp.status_code == 200
    assert "'=cmd" in resp.text
