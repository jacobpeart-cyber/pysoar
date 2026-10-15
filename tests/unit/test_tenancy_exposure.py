"""Wave 1 tenancy / RBAC conversion of the exposure management router.

docs/audit/2026-10-08/posture-risk.md: every exposure route takes the
mandatory ``OrganizationId`` (the ~22 "org is None means no filter" guards
and the "first org in the database" ticket fallback are gone), lookups by id
404 outside the tenant, links and tickets cannot reference another tenant's
rows, writes need analyst or admin, discovery and scan launches are
admin-only and answer an honest 501, ``/tickets/overdue`` is reachable, and
``/report`` and ``/vulnerabilities/kev`` read real columns instead of 500ing.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.exposure.models import (
    AssetVulnerability,
    ExposureAsset,
    ExposureScan,
    ExposureVulnerability,
    RemediationTicket,
)
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/exposure"


async def _seed(db: AsyncSession, org_id: str, host: str = "web-01") -> dict[str, str]:
    asset = ExposureAsset(organization_id=org_id, hostname=host, ip_address="10.0.0.5", asset_type="server")
    vuln = ExposureVulnerability(
        organization_id=org_id, cve_id="CVE-2026-1111", title="RCE", severity="critical",
        cvss_v3_score=9.8, is_exploited_in_wild=True,
    )
    db.add_all([asset, vuln])
    await db.flush()
    link = AssetVulnerability(organization_id=org_id, asset_id=asset.id, vulnerability_id=vuln.id, status="open")
    ticket = RemediationTicket(organization_id=org_id, title="Patch RCE", remediation_type="patch")
    db.add_all([link, ticket])
    await db.commit()
    return {"asset": asset.id, "vuln": vuln.id, "link": link.id, "ticket": ticket.id}


async def test_asset_create_is_stamped_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(
        f"{API}/assets", json={"hostname": "a-web", "asset_type": "server"}, headers=org_a_headers,
    )
    assert resp.status_code == 201, resp.text
    asset_id = resp.json()["id"]
    row = (await db_session.execute(select(ExposureAsset).where(ExposureAsset.id == asset_id))).scalar_one()
    assert row.organization_id == org_a_id

    listed = await client.get(f"{API}/assets", headers=org_b_headers)
    assert listed.status_code == 200, listed.text
    assert asset_id not in {a["id"] for a in listed.json()["items"]}

    await assert_tenant_isolated(client, "GET", f"{API}/assets/{asset_id}", org_b_headers)
    await assert_tenant_isolated(client, "PUT", f"{API}/assets/{asset_id}", org_b_headers, json={"owner": "x"})
    await assert_tenant_isolated(client, "DELETE", f"{API}/assets/{asset_id}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{API}/assets/{asset_id}/vulnerabilities", org_b_headers)


async def test_vulns_links_tickets_and_surfaces_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)

    for path in ("/vulnerabilities", "/vulnerabilities/kev", "/tickets", "/asset-vulns/prioritized", "/scans"):
        resp = await client.get(f"{API}{path}", headers=org_b_headers)
        assert resp.status_code == 200, (path, resp.text)
        body = resp.json()
        items = body.get("items", body.get("kev_vulnerabilities"))
        assert items == [], (path, body)

    await assert_tenant_isolated(client, "GET", f"{API}/vulnerabilities/{ids['vuln']}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/vulnerabilities/{ids['vuln']}", org_b_headers, json={"title": "x"},
    )
    await assert_tenant_isolated(client, "DELETE", f"{API}/vulnerabilities/{ids['vuln']}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/asset-vulns/{ids['link']}", org_b_headers, json={"status": "accepted"},
    )
    await assert_tenant_isolated(client, "POST", f"{API}/asset-vulns/{ids['link']}/remediate", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{API}/tickets/{ids['ticket']}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/tickets/{ids['ticket']}", org_b_headers, json={"status": "closed"},
    )
    await assert_tenant_isolated(
        client, "POST", f"{API}/tickets/{ids['ticket']}/verify", org_b_headers, json={},
    )

    surface = await client.post(
        f"{API}/attack-surface", json={"name": "edge", "surface_type": "external"}, headers=org_a_headers,
    )
    assert surface.status_code == 201, surface.text
    surface_id = surface.json()["id"]
    b_surfaces = await client.get(f"{API}/attack-surface", headers=org_b_headers)
    assert surface_id not in {s["id"] for s in b_surfaces.json()["items"]}
    await assert_tenant_isolated(client, "GET", f"{API}/attack-surface/{surface_id}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/attack-surface/{surface_id}", org_b_headers, json={"name": "x"},
    )
    await assert_tenant_isolated(
        client, "POST", f"{API}/attack-surface/assess", org_b_headers, params={"surface_id": surface_id},
    )


async def test_links_and_tickets_cannot_reference_another_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    own = await _seed(db_session, org_a.id, host="a-host")
    foreign = await _seed(db_session, org_b.id, host="b-host")

    link = await client.post(
        f"{API}/asset-vulns",
        json={"asset_id": own["asset"], "vulnerability_id": foreign["vuln"]},
        headers=org_a_headers,
    )
    assert link.status_code == 404, link.text

    ticket = await client.post(
        f"{API}/tickets",
        json={"title": "Patch", "affected_assets": [foreign["asset"]]},
        headers=org_a_headers,
    )
    assert ticket.status_code == 422, ticket.text
    assert ticket.json()["detail"]["field"] == "affected_assets"


async def test_ticket_is_created_in_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(f"{API}/tickets", json={"title": "Patch openssl"}, headers=org_a_headers)
    assert resp.status_code == 201, resp.text
    row = (
        await db_session.execute(select(RemediationTicket).where(RemediationTicket.id == resp.json()["id"]))
    ).scalar_one()
    assert row.organization_id == org_a_id


async def test_overdue_tickets_route_is_not_shadowed(
    client: AsyncClient,
    org_a_headers: dict[str, str],
) -> None:
    resp = await client.get(f"{API}/tickets/overdue", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["items"] == []


async def test_kev_list_reads_real_columns(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    await _seed(db_session, org_a.id)
    resp = await client.get(f"{API}/vulnerabilities/kev", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    assert body["kev_vulnerabilities"][0]["cvss_score"] == 9.8


async def test_report_reads_real_columns_and_is_viewer_readable(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
) -> None:
    await _seed(db_session, org_a.id)
    resp = await client.post(f"{API}/report", params={"title": "Q4"}, headers=viewer_headers)
    assert resp.status_code == 200, resp.text
    stats = resp.json()["statistics"]
    assert stats["total_assets"] == 1
    # No closed tickets: MTTR is unknown, not "0 days".
    assert stats["mean_time_to_remediate_days"] is None
    assert stats["top_vulnerable_assets"][0]["asset_name"] == "web-01"


async def test_vulnerability_search_is_viewer_readable(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
) -> None:
    await _seed(db_session, org_a.id)
    resp = await client.post(f"{API}/vulnerabilities/search", json={"has_exploits": False}, headers=viewer_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["total"] == 1


async def test_vulnerability_delete_with_links_is_a_conflict(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)
    resp = await client.delete(f"{API}/vulnerabilities/{ids['vuln']}", headers=org_a_headers)
    assert resp.status_code == 409, resp.text


async def test_scan_import_creates_new_hosts(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    csv_data = "Host,IP,CVE,Severity,CVSS,Title\nnew-host,10.9.9.9,CVE-2026-2222,high,8.1,Bad thing\n"
    resp = await client.post(
        f"{API}/scans/import",
        json={"scanner_name": "nessus", "scan_format": "csv", "scan_data": csv_data},
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["errors"] == []
    assert body["vulnerabilities_imported"] == 1
    asset = (
        await db_session.execute(select(ExposureAsset).where(ExposureAsset.hostname == "new-host"))
    ).scalar_one()
    assert asset.organization_id == org_a_id


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/assets/discover", {"scan_type": "network", "targets": ["10.0.0.0/24"]}),
        ("/scans", {"scan_type": "vulnerability", "scan_name": "weekly"}),
    ],
)
async def test_live_scans_are_admin_only_and_honest(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
    path: str,
    body: dict[str, Any],
) -> None:
    analyst = await client.post(f"{API}{path}", json=body, headers=org_a_headers)
    assert analyst.status_code == 403, analyst.text

    admin = await client.post(f"{API}{path}", json=body, headers=org_a_admin_headers)
    assert admin.status_code == 501, admin.text
    assert admin.json()["detail"]["error"] == "not_implemented"
    scans = (await db_session.execute(select(ExposureScan))).scalars().all()
    assert scans == []


async def test_bulk_asset_import_is_real_and_stamped(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    # Wave 4 (W4-A): the import parses and writes rows (was an honest 501).
    org_a_id = org_a.id
    resp = await client.post(
        f"{API}/assets/import", json={"format": "csv", "data": "hostname\nweb-9\n"}, headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["created"] == 1
    asset = (await db_session.execute(select(ExposureAsset).where(ExposureAsset.hostname == "web-9"))).scalar_one()
    assert asset.organization_id == org_a_id


WRITE_ROUTES: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", "/assets", {"hostname": "x", "asset_type": "server"}),
    ("PUT", "/assets/missing", {"owner": "x"}),
    ("DELETE", "/assets/missing", {}),
    ("POST", "/assets/discover", {"scan_type": "network"}),
    ("POST", "/assets/import", {"format": "csv", "data": "x"}),
    ("POST", "/vulnerabilities", {"title": "x"}),
    ("PUT", "/vulnerabilities/missing", {"title": "x"}),
    ("DELETE", "/vulnerabilities/missing", {}),
    ("POST", "/asset-vulns", {"asset_id": "a", "vulnerability_id": "b"}),
    ("PUT", "/asset-vulns/missing", {"status": "accepted"}),
    ("POST", "/asset-vulns/missing/remediate", {}),
    ("POST", "/scans", {"scan_type": "vulnerability", "scan_name": "x"}),
    ("POST", "/scans/missing/cancel", {}),
    ("POST", "/scans/import", {"scanner_name": "n", "scan_format": "csv", "scan_data": "x"}),
    ("POST", "/tickets", {"title": "x"}),
    ("PUT", "/tickets/missing", {"status": "closed"}),
    ("POST", "/tickets/missing/verify", {}),
    ("POST", "/attack-surface", {"name": "x", "surface_type": "external"}),
    ("PUT", "/attack-surface/missing", {"name": "x"}),
    ("POST", "/attack-surface/assess?surface_id=missing", {}),
]


@pytest.mark.parametrize(("method", "path", "body"), WRITE_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient, viewer_headers: dict[str, str], method: str, path: str, body: dict[str, Any],
) -> None:
    resp = await client.request(method, f"{API}{path}", json=body or None, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    resp = await client.get(f"{API}/assets", headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert "organization_required" in resp.text
