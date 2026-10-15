"""Wave 1 tenancy / RBAC conversion of the OT security router.

docs/audit/2026-10-08/posture-risk.md (ot_security section and section 3):
every route takes the mandatory ``OrganizationId`` (the ``if org_id is not
None`` helper guards are gone, and ~20 routes that read ``current_user``
without declaring it no longer raise NameError), lookups by id 404 outside
the tenant, an alert cannot reference another tenant's asset, operational
writes need analyst or admin, and policy configuration, OT bulk actions,
safe shutdown, segmentation audit and live-network discovery need admin.
Safe shutdown and segmentation audit never claim work that did not happen:
since wave 4 they command an endpoint agent (approval queue, result-driven
status, see tests/unit/test_wave4_ot.py) and are refused with a 409 that
changes nothing when no capable agent / target exists. The dash-prefixed
list mirrors in ``aliases.py`` were deleted in wave 4 and the dash discover /
export routes moved under ``/ot_security`` (the old paths answer 410).
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.models.organization import Organization
from src.ot_security.engine import OTMonitor
from src.ot_security.models import OTAlert, OTAsset, OTIncident, OTPolicyRule, OTZone
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/ot_security"

ASSET_BODY = {"name": "plc-1", "asset_type": "plc", "purdue_level": "level1_control", "ip_address": "10.10.5.7"}
ZONE_BODY = {"name": "cell-1", "purdue_level": "level1_control", "network_cidr": "10.10.0.0/16"}
INCIDENT_BODY = {"title": "t", "description": "d", "incident_type": "ransomware", "severity": "high"}
POLICY_BODY = {"name": "p", "rule_type": "network_access"}


async def _seed(db: AsyncSession, org_id: str) -> dict[str, str]:
    asset = OTAsset(
        organization_id=org_id, name="plc-seed", asset_type="plc", purdue_level="level1_control",
        ip_address="10.10.5.8",
    )
    zone = OTZone(organization_id=org_id, name="zone-seed", purdue_level="level1_control", network_cidr="10.10.0.0/16")
    incident = OTIncident(
        organization_id=org_id, title="inc", description="d", incident_type="ransomware", severity="high",
    )
    policy = OTPolicyRule(organization_id=org_id, name="pol", rule_type="network_access", enforcement_action="alert")
    db.add_all([asset, zone, incident, policy])
    await db.flush()
    alert = OTAlert(
        organization_id=org_id, asset_id=asset.id, alert_type="network_scan", severity="high",
        description="test alert", status="new",
    )
    db.add(alert)
    await db.commit()
    return {"asset": asset.id, "zone": zone.id, "incident": incident.id, "policy": policy.id, "alert": alert.id}


# ---------------------------------------------------------------------------
# isolation + stamping
# ---------------------------------------------------------------------------


async def test_asset_create_is_stamped_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(f"{API}/assets", json=ASSET_BODY, headers=org_a_headers)
    assert resp.status_code == 201, resp.text
    asset_id = resp.json()["id"]
    row = (await db_session.execute(select(OTAsset).where(OTAsset.id == asset_id))).scalar_one()
    assert row.organization_id == org_a_id

    listed = await client.get(f"{API}/assets", headers=org_b_headers)
    assert listed.status_code == 200
    assert asset_id not in {a["id"] for a in listed.json()["items"]}

    own = await client.get(f"{API}/assets/{asset_id}", headers=org_a_headers)
    assert own.status_code == 200, own.text
    for method, suffix in (
        ("GET", ""), ("PUT", ""), ("GET", "/status"), ("GET", "/risk_assessment"),
        ("POST", "/firmware_check"), ("DELETE", ""),
    ):
        body = {"name": "x"} if method == "PUT" else None
        await assert_tenant_isolated(client, method, f"{API}/assets/{asset_id}{suffix}", org_b_headers, json=body)


async def test_by_id_routes_isolated_and_work_for_owner(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)
    reads = [
        f"{API}/assets/{ids['asset']}/status",
        f"{API}/assets/{ids['asset']}/risk_assessment",
        f"{API}/alerts/{ids['alert']}",
        f"{API}/zones/{ids['zone']}",
        f"{API}/zones/{ids['zone']}/communication_matrix",
        f"{API}/incidents/{ids['incident']}",
        f"{API}/policies/{ids['policy']}",
        f"{API}/policies/{ids['policy']}/violation_history",
    ]
    for path in reads:
        own = await client.get(path, headers=org_a_headers)
        assert own.status_code == 200, (path, own.text)
        await assert_tenant_isolated(client, "GET", path, org_b_headers)

    own_check = await client.post(f"{API}/zones/{ids['zone']}/compliance_check", headers=org_a_headers)
    assert own_check.status_code == 200, own_check.text
    await assert_tenant_isolated(client, "POST", f"{API}/zones/{ids['zone']}/compliance_check", org_b_headers)
    await assert_tenant_isolated(client, "POST", f"{API}/alerts/{ids['alert']}/investigate", org_b_headers)
    await assert_tenant_isolated(client, "PUT", f"{API}/alerts/{ids['alert']}", org_b_headers, json={"status": "resolved"})
    await assert_tenant_isolated(client, "PUT", f"{API}/zones/{ids['zone']}", org_b_headers, json={"description": "x"})
    await assert_tenant_isolated(
        client, "PUT", f"{API}/incidents/{ids['incident']}", org_b_headers, json={"status": "containing"},
    )
    await assert_tenant_isolated(client, "DELETE", f"{API}/zones/{ids['zone']}", org_b_headers)

    investigated = await client.post(f"{API}/alerts/{ids['alert']}/investigate", headers=org_a_headers)
    assert investigated.status_code == 200, investigated.text
    assert investigated.json()["status"] == "investigating"

    enabled = await client.post(f"{API}/policies/{ids['policy']}/enable", headers=org_a_admin_headers)
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["enabled"] is True


async def test_admin_routes_isolated_from_other_tenant_admin_scope(
    client: AsyncClient,
    db_session: AsyncSession,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    # org A's admin cannot reach org B's rows through the admin-only routes.
    ids = await _seed(db_session, org_b.id)
    for path in (
        f"{API}/policies/{ids['policy']}/enable",
        f"{API}/policies/{ids['policy']}/disable",
        f"{API}/incidents/{ids['incident']}/safe_shutdown",
        f"{API}/zones/{ids['zone']}/segmentation_audit",
        f"{API}/assets/{ids['asset']}/discover",
    ):
        await assert_tenant_isolated(client, "POST", path, org_a_admin_headers)
    await assert_tenant_isolated(client, "DELETE", f"{API}/policies/{ids['policy']}", org_a_admin_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/policies/{ids['policy']}", org_a_admin_headers, json={"enabled": True},
    )


async def test_lists_and_aggregates_exclude_other_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)
    for resource in ("assets", "alerts", "zones", "incidents", "policies"):
        resp = await client.get(f"{API}/{resource}", headers=org_b_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["total"] == 0, resource

    dash = await client.get(f"{API}/dashboard", headers=org_b_headers)
    assert dash.status_code == 200, dash.text
    assert dash.json()["asset_inventory"]["total_assets"] == 0

    purdue = await client.get(f"{API}/purdue-map", headers=org_b_headers)
    assert purdue.status_code == 200, purdue.text
    assert purdue.json()["total_devices"] == 0

    risk = await client.get(f"{API}/risk_assessment", headers=org_b_headers)
    assert risk.status_code == 200, risk.text
    assert risk.json()["total_assets"] == 0

    report = await client.get(f"{API}/compliance/report", headers=org_b_headers)
    assert report.status_code == 200, report.text
    assert ids["asset"]


async def test_alert_cannot_reference_foreign_or_missing_asset(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    own = await _seed(db_session, org_a.id)
    foreign = await _seed(db_session, org_b.id)
    body: dict[str, Any] = {"alert_type": "network_scan", "severity": "high", "description": "d"}

    for asset_id in (foreign["asset"], "", "no-such-asset"):
        resp = await client.post(f"{API}/alerts", json={**body, "asset_id": asset_id}, headers=org_a_headers)
        assert resp.status_code == 422, resp.text
        assert resp.json()["detail"]["field"] == "asset_id"

    ok = await client.post(f"{API}/alerts", json={**body, "asset_id": own["asset"]}, headers=org_a_headers)
    assert ok.status_code == 201, ok.text


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------

WRITE_ROUTES = [
    ("POST", "/assets", ASSET_BODY),
    ("PUT", "/assets/{asset}", {"name": "x"}),
    ("DELETE", "/assets/{asset}", None),
    ("POST", "/alerts", {"asset_id": "x", "alert_type": "network_scan", "severity": "high"}),
    ("PUT", "/alerts/{alert}", {"status": "resolved"}),
    ("POST", "/alerts/{alert}/investigate", None),
    ("POST", "/zones", ZONE_BODY),
    ("PUT", "/zones/{zone}", {"description": "x"}),
    ("DELETE", "/zones/{zone}", None),
    ("POST", "/incidents", INCIDENT_BODY),
    ("PUT", "/incidents/{incident}", {"status": "contained"}),
    ("POST", "/incidents/{incident}/containment_strategy?strategy=isolate_zone", None),
]

ADMIN_ROUTES = [
    ("POST", "/policies", POLICY_BODY),
    ("PUT", "/policies/{policy}", {"enabled": True}),
    ("DELETE", "/policies/{policy}", None),
    ("POST", "/policies/{policy}/enable", None),
    ("POST", "/policies/{policy}/disable", None),
    ("POST", "/alerts/bulk_action?alert_ids={alert}&action=resolve", None),
    ("POST", "/incidents/{incident}/safe_shutdown", None),
    ("POST", "/zones/{zone}/segmentation_audit", None),
    ("POST", "/assets/{asset}/discover", None),
]


@pytest.mark.parametrize(("method", "path", "body"), WRITE_ROUTES + ADMIN_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
    method: str,
    path: str,
    body: Any,
) -> None:
    ids = await _seed(db_session, org_a.id)
    resp = await client.request(method, API + path.format(**ids), json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ROUTES)
async def test_analyst_cannot_run_admin_routes(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    method: str,
    path: str,
    body: Any,
) -> None:
    ids = await _seed(db_session, org_a.id)
    resp = await client.request(method, API + path.format(**ids), json=body, headers=org_a_headers)
    assert resp.status_code == 403, resp.text


async def test_viewer_can_read_and_run_readonly_checks(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)
    assert (await client.get(f"{API}/assets/{ids['asset']}", headers=viewer_headers)).status_code == 200
    # firmware_check and compliance_check persist nothing and touch no live system.
    fw = await client.post(f"{API}/assets/{ids['asset']}/firmware_check", headers=viewer_headers)
    assert fw.status_code == 200, fw.text
    zc = await client.post(f"{API}/zones/{ids['zone']}/compliance_check", headers=viewer_headers)
    assert zc.status_code == 200, zc.text


@pytest.mark.parametrize(
    "path",
    [
        f"{API}/assets",
        f"{API}/dashboard",
        f"{API}/purdue-map",
        f"{API}/risk_assessment",
        f"{API}/export",
        f"{API}/advisories",
        f"{API}/advisories/status",
    ],
)
async def test_orgless_superuser_gets_organization_required(
    client: AsyncClient,
    superuser_headers: dict[str, str],
    path: str,
) -> None:
    resp = await client.get(path, headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert "organization_required" in resp.text


# ---------------------------------------------------------------------------
# bulk action, honest 501s, discovery
# ---------------------------------------------------------------------------


async def test_bulk_action_rejects_unknown_action(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)
    resp = await client.post(
        f"{API}/alerts/bulk_action",
        params=[("alert_ids", ids["alert"]), ("action", "explode")],
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["field"] == "action"


async def test_safe_shutdown_without_capable_agent_is_refused_and_changes_nothing(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    # Wave 4: was an honest 501; now commanded through an ot_safe_shutdown
    # agent, and refused (409) when the incident has no target or no agent.
    ids = await _seed(db_session, org_a.id)
    resp = await client.post(f"{API}/incidents/{ids['incident']}/safe_shutdown", headers=org_a_admin_headers)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["error"] == "no_target_assets"
    db_session.expire_all()
    incident = (await db_session.execute(select(OTIncident).where(OTIncident.id == ids["incident"]))).scalar_one()
    incident.affected_assets = [ids["asset"]]
    await db_session.commit()
    resp = await client.post(f"{API}/incidents/{ids['incident']}/safe_shutdown", headers=org_a_admin_headers)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["error"] == "no_capable_agent"
    db_session.expire_all()
    incident = (await db_session.execute(select(OTIncident).where(OTIncident.id == ids["incident"]))).scalar_one()
    assert not incident.safe_shutdown_initiated
    assert incident.safe_shutdown_status is None


async def test_segmentation_audit_without_targets_is_refused_and_changes_nothing(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    # Wave 4: was an honest 501; now an agent-run probe, refused (409) when
    # there is nothing to probe (a single zone) and nothing is changed.
    ids = await _seed(db_session, org_a.id)
    resp = await client.post(f"{API}/zones/{ids['zone']}/segmentation_audit", headers=org_a_admin_headers)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["error"] == "no_probe_targets"
    db_session.expire_all()
    zone = (await db_session.execute(select(OTZone).where(OTZone.id == ids["zone"]))).scalar_one()
    assert not zone.segmentation_verified
    assert zone.last_audit is None


async def test_asset_discover_calls_engine_once_per_cidr(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed(db_session, org_a.id)
    org_a_id = org_a.id
    calls: list[tuple[str, str]] = []

    async def fake_discover(self: OTMonitor, network_range: str) -> list[dict[str, Any]]:
        calls.append((self.organization_id, network_range))
        return [{"ip_address": "10.10.5.9", "open_ports": [502]}]

    monkeypatch.setattr(OTMonitor, "discover_assets", fake_discover)
    monkeypatch.setattr(settings, "ot_discovery_allowed_cidrs", ["10.0.0.0/8"])

    resp = await client.post(
        f"{API}/assets/{ids['asset']}/discover",
        params=[("network_ranges", "10.10.5.0/24"), ("network_ranges", "10.10.6.0/24")],
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "completed"
    assert body["discovered_count"] == 2
    assert calls == [(org_a_id, "10.10.5.0/24"), (org_a_id, "10.10.6.0/24")]

    # No ranges: the asset's own address is probed.
    calls.clear()
    resp = await client.post(f"{API}/assets/{ids['asset']}/discover", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert calls == [(org_a_id, "10.10.5.8/32")]


async def test_asset_discover_validates_ranges(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed(db_session, org_a.id)
    org_b_id = org_b.id

    async def must_not_run(_self: OTMonitor, network_range: str) -> list[dict[str, Any]]:
        raise AssertionError(f"scan must not run for {network_range}")

    monkeypatch.setattr(OTMonitor, "discover_assets", must_not_run)
    monkeypatch.setattr(settings, "ot_discovery_allowed_cidrs", ["10.0.0.0/8", "192.168.0.0/16"])
    path = f"{API}/assets/{ids['asset']}/discover"

    bad = await client.post(path, params={"network_ranges": "not-a-cidr"}, headers=org_a_admin_headers)
    assert bad.status_code == 422, bad.text
    assert bad.json()["detail"]["field"] == "network_ranges"

    big = await client.post(path, params={"network_ranges": "10.10.0.0/16"}, headers=org_a_admin_headers)
    assert big.status_code == 422, big.text

    outside = await client.post(path, params={"network_ranges": "192.168.1.0/24"}, headers=org_a_admin_headers)
    assert outside.status_code == 403, outside.text
    assert outside.json()["detail"]["error"] == "cidr_outside_ot_zones"

    # The old ``org_id`` query override is gone: it cannot select another tenant.
    override = await client.post(
        path, params={"org_id": org_b_id, "network_ranges": "not-a-cidr"}, headers=org_a_admin_headers,
    )
    assert override.status_code == 422, override.text


async def test_export_is_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    await _seed(db_session, org_a.id)
    # Wave 4 moved it from the dash alias; wave 5 retired the 410 tombstone.
    gone = await client.get("/api/v1/ot-security/export", headers=org_a_headers)
    assert gone.status_code == 404, gone.text
    own = await client.get(f"{API}/export", headers=org_a_headers)
    assert own.status_code == 200, own.text
    assert own.json()["summary"]["total_assets"] == 1

    other = await client.get(f"{API}/export", headers=org_b_headers)
    assert other.status_code == 200, other.text
    assert other.json()["summary"]["total_assets"] == 0


async def _never_scan(_self: OTMonitor, network_range: str) -> list[dict[str, Any]]:
    raise AssertionError(f"scan must not run for {network_range}")


async def test_discovery_fails_closed_without_platform_allowlist(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty OT_DISCOVERY_ALLOWED_CIDRS disables discovery on both routes, zones or not."""
    ids = await _seed(db_session, org_a.id)
    monkeypatch.setattr(OTMonitor, "discover_assets", _never_scan)
    monkeypatch.setattr(settings, "ot_discovery_allowed_cidrs", [])

    asset_route = await client.post(
        f"{API}/assets/{ids['asset']}/discover", params={"network_ranges": "10.10.5.0/24"}, headers=org_a_admin_headers,
    )
    assert asset_route.status_code == 403, asset_route.text
    assert asset_route.json()["detail"]["error"] == "ot_discovery_disabled"

    alias = await client.post("/api/v1/ot_security/discover", json={"cidr": "10.10.5.0/24"}, headers=org_a_admin_headers)
    assert alias.status_code == 403, alias.text
    assert alias.json()["detail"]["error"] == "ot_discovery_disabled"


async def test_discovery_requires_zone_and_refuses_internal_ranges(
    client: AsyncClient,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ot_discovery_allowed_cidrs", ["10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16"])
    monkeypatch.setattr(OTMonitor, "discover_assets", _never_scan)

    created = await client.post(f"{API}/assets", json=ASSET_BODY, headers=org_a_headers)
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]
    path = f"{API}/assets/{asset_id}/discover"

    # No zone configured: fail closed even though the allowlist permits the range.
    no_zone = await client.post(path, params={"network_ranges": "10.10.5.0/24"}, headers=org_a_admin_headers)
    assert no_zone.status_code == 403, no_zone.text
    assert no_zone.json()["detail"]["error"] == "ot_zones_required"

    zone = await client.post(f"{API}/zones", json=ZONE_BODY, headers=org_a_headers)
    assert zone.status_code == 201, zone.text

    # Loopback and the cloud metadata address are refused even when the platform
    # allowlist (mis)configures them; the zone rule is never consulted.
    for target in ("127.0.0.1/32", "169.254.169.254/32", "224.0.0.0/24"):
        refused = await client.post(path, params={"network_ranges": target}, headers=org_a_admin_headers)
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"]["error"] == "target_network_refused", refused.text

    alias = await client.post("/api/v1/ot_security/discover", json={"cidr": "127.0.0.0/24"}, headers=org_a_admin_headers)
    assert alias.status_code == 403, alias.text
    assert alias.json()["detail"]["error"] == "target_network_refused"

    # Outside the platform allowlist but inside a zone is still refused.
    monkeypatch.setattr(settings, "ot_discovery_allowed_cidrs", ["172.16.0.0/12"])
    outside = await client.post(path, params={"network_ranges": "10.10.5.0/24"}, headers=org_a_admin_headers)
    assert outside.status_code == 403, outside.text
    assert outside.json()["detail"]["error"] == "cidr_outside_platform_allowlist"


async def test_discovery_reaches_engine_only_for_allowlisted_zone_range(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed(db_session, org_a.id)
    monkeypatch.setattr(settings, "ot_discovery_allowed_cidrs", ["10.0.0.0/8"])
    probed: list[str] = []

    async def record(_self: OTMonitor, network_range: str) -> list[dict[str, Any]]:
        probed.append(network_range)
        return []

    monkeypatch.setattr(OTMonitor, "discover_assets", record)
    ok = await client.post(
        f"{API}/assets/{ids['asset']}/discover", params={"network_ranges": "10.10.5.0/24"}, headers=org_a_admin_headers,
    )
    assert ok.status_code == 200, ok.text
    assert probed == ["10.10.5.0/24"]


async def test_zone_cidr_cannot_widen_discovery_to_internal_ranges(
    client: AsyncClient,
    org_a_headers: dict[str, str],
) -> None:
    for bad in ("127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/0"):
        resp = await client.post(f"{API}/zones", json={**ZONE_BODY, "network_cidr": bad}, headers=org_a_headers)
        assert resp.status_code == 400, f"{bad}: {resp.text}"
        assert resp.json()["detail"]["error"] == "zone_cidr_refused", resp.text

    garbage = await client.post(f"{API}/zones", json={**ZONE_BODY, "network_cidr": "not-a-cidr"}, headers=org_a_headers)
    assert garbage.status_code == 400, garbage.text
    assert garbage.json()["detail"]["error"] == "invalid_zone_cidr"

    zone = await client.post(f"{API}/zones", json=ZONE_BODY, headers=org_a_headers)
    assert zone.status_code == 201, zone.text
    zone_id = zone.json()["id"]
    # OTZoneUpdate carries no network_cidr: an update cannot move the zone at all.
    widened = await client.put(f"{API}/zones/{zone_id}", json={"network_cidr": "169.254.169.0/24"}, headers=org_a_headers)
    assert widened.status_code == 200, widened.text
    assert widened.json()["network_cidr"] == ZONE_BODY["network_cidr"]
    unchanged = await client.get(f"{API}/zones/{zone_id}", headers=org_a_headers)
    assert unchanged.json()["network_cidr"] == ZONE_BODY["network_cidr"]
