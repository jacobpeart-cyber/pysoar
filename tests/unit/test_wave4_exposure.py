"""Wave 4 (W4-A): exposure management backed by stored rows.

- Scanner import constructs the real models, reports real counts and writes
  link / asset risk scores.
- SIEM discovery and bulk asset import run and report real counts (network
  discovery stays an honest 501).
- Dashboard charts read stored daily snapshots; the graph is built from
  stored relations and attack paths are an honest 501.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.exposure.models import (
    AssetVulnerability,
    AttackSurface,
    ExposureAsset,
    ExposureDailySnapshot,
    ExposureScan,
    ExposureVulnerability,
    RemediationTicket,
)
from src.exposure.scoring import asset_risk, link_risk
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.siem.models import LogEntry

API = "/api/v1/exposure"

NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2><Report name="r">
 <ReportHost name="edge-01">
  <HostProperties><tag name="host-ip">198.51.100.7</tag></HostProperties>
  <ReportItem port="443" protocol="tcp" severity="4" pluginID="1" pluginName="Critical RCE">
   <cve>CVE-2026-0001</cve><cvss3_base_score>9.8</cvss3_base_score>
  </ReportItem>
  <ReportItem port="22" protocol="tcp" severity="2" pluginID="2" pluginName="Weak SSH">
   <cvss3_base_score>5.3</cvss3_base_score>
  </ReportItem>
 </ReportHost>
 <ReportHost name="db-01">
  <HostProperties><tag name="host-ip">10.0.5.5</tag></HostProperties>
  <ReportItem port="5432" protocol="tcp" severity="3" pluginID="3" pluginName="Postgres flaw">
   <cve>CVE-2026-0002</cve>
  </ReportItem>
 </ReportHost>
</Report></NessusClientData_v2>
"""


async def _import(client: AsyncClient, headers: dict[str, str], data: str = NESSUS, fmt: str = "nessus"):
    return await client.post(
        f"{API}/scans/import", json={"scanner_name": "corp-nessus", "scan_format": fmt, "scan_data": data}, headers=headers,
    )


async def test_scan_import_counts_and_writes_risk(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    resp = await _import(client, org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["findings_read"] == 3
    assert body["links_created"] == 3 == body["vulnerabilities_imported"]
    assert body["vulnerabilities_created"] == 3
    assert body["assets_created"] == 2
    assert body["assets_updated"] == 2
    assert body["assets_rescored"] == 2
    assert body["status"] == "completed" and body["errors"] == []

    db_session.expire_all()
    edge = (await db_session.execute(select(ExposureAsset).where(ExposureAsset.hostname == "edge-01"))).scalar_one()
    assert edge.organization_id == org_id
    assert edge.ip_address == "198.51.100.7"
    assert sorted(edge.open_ports) == [22, 443]
    assert edge.vulnerability_count == 2
    expected = asset_risk(
        [
            link_risk(cvss_v3=9.8, cvss_v2=None, severity="critical", is_exploited_in_wild=False, exploit_available=False,
                      exploit_maturity="none", asset_criticality="medium", internet_facing=False),
            link_risk(cvss_v3=5.3, cvss_v2=None, severity="medium", is_exploited_in_wild=False, exploit_available=False,
                      exploit_maturity="none", asset_criticality="medium", internet_facing=False),
        ],
    )
    assert edge.risk_score == expected == 100.0
    links = (await db_session.execute(select(AssetVulnerability).where(AssetVulnerability.asset_id == edge.id))).scalars().all()
    assert sorted(round(link.risk_score, 2) for link in links) == [53.0, 98.0]
    link_id = links[0].id

    scan = await db_session.get(ExposureScan, body["import_id"])
    assert scan.status == "completed" and scan.critical_count == 1 and scan.hosts_scanned == 2

    again = (await _import(client, org_a_headers)).json()
    assert again["links_created"] == 0 and again["links_updated"] == 3 and again["assets_created"] == 0

    # A remediated link the scanner still reports is re-opened.
    remediated = await client.post(f"{API}/asset-vulns/{link_id}/remediate", headers=org_a_headers)
    assert remediated.status_code == 200
    third = (await _import(client, org_a_headers)).json()
    assert third["links_reopened"] == 1
    db_session.expire_all()
    assert (await db_session.get(AssetVulnerability, link_id)).status == "open"


async def test_unreadable_scan_is_recorded_and_refused(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    resp = await _import(client, org_a_headers, data="<NessusClientData_v2><broken", fmt="nessus")
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "scan_parse_failed"
    scan = await db_session.get(ExposureScan, detail["import_id"])
    assert scan is not None and scan.status == "failed" and scan.error_message
    assert (await db_session.execute(select(func.count(ExposureAsset.id)))).scalar() == 0

    # Rows without a host are read but skipped, with the reason.
    no_host = "Title,CVE,Severity\nOrphan,CVE-2026-0009,high\n"
    resp = await _import(client, org_a_headers, data=no_host, fmt="custom")
    assert resp.status_code == 200, resp.text
    assert resp.json()["links_created"] == 0
    assert [(s["reason"], s["count"]) for s in resp.json()["skipped"]] == [("no_asset_identifier", 1)]


async def test_skipped_findings_have_reasons(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    data = "Host,IP,CVE,Severity,Title\nweb-1,10.1.1.1,CVE-2026-0100,high,Bad\n,,CVE-2026-0101,high,No host\nweb-1,10.1.1.1,CVE-2026-0100,high,Bad\n"
    body = (await _import(client, org_a_headers, data=data, fmt="csv")).json()
    reasons = {s["reason"]: s["count"] for s in body["skipped"]}
    assert reasons == {"duplicate_in_file": 1, "no_asset_identifier": 1}
    assert body["links_created"] == 1


async def test_siem_discovery_reports_real_counts(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    now = datetime.now(timezone.utc).isoformat()
    db_session.add(ExposureAsset(organization_id=org_id, ip_address="10.7.0.1", asset_type="host"))
    for ip in ("10.7.0.1", "10.7.0.2", "10.7.0.3"):
        db_session.add(
            LogEntry(
                timestamp=now, received_at=now, source_type="syslog", source_name="fw", source_ip=ip,
                source_address=ip, log_type="network", raw_log=f"from {ip}", organization_id=org_id,
            ),
        )
    await db_session.commit()

    resp = await client.post(f"{API}/assets/discover", json={"scan_type": "siem"}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["new_assets"] == 2 and body["updated_assets"] == 1 and body["discovered_assets"] == 3
    assert body["status"] == "completed"
    scan = await db_session.get(ExposureScan, body["scan_id"])
    assert scan.scan_type == "discovery" and scan.organization_id == org_id

    network = await client.post(f"{API}/assets/discover", json={"scan_type": "network"}, headers=org_a_admin_headers)
    assert network.status_code == 501
    assert network.json()["detail"]["error"] == "not_implemented"


async def test_bulk_asset_import_csv_and_json(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    csv_data = (
        "hostname,ip_address,asset_type,criticality,is_internet_facing,tags\n"
        "web-9,10.9.0.9,server,high,true,dmz;web\n"
        ",,server,low,,\n"
        "bad-1,10.9.0.10,server,extreme,,\n"
    )
    resp = await client.post(f"{API}/assets/import", json={"format": "csv", "data": csv_data}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["created"] == 1 and body["updated"] == 0 and body["imported"] == 1
    assert {e["error"] for e in body["errors"]} == {"hostname_or_ip_required", "invalid_criticality"}
    assert body["failed"] == 2 and body["rows_read"] == 3

    json_data = '[{"ip": "10.9.0.9", "owner": "web-team"}, {"hostname": "new-json"}]'
    resp = await client.post(f"{API}/assets/import", json={"format": "json", "data": json_data}, headers=org_a_headers)
    body = resp.json()
    assert body["created"] == 1 and body["updated"] == 1
    db_session.expire_all()
    web = (await db_session.execute(select(ExposureAsset).where(ExposureAsset.ip_address == "10.9.0.9"))).scalar_one()
    assert web.owner == "web-team" and web.criticality == "high" and web.is_internet_facing
    assert web.organization_id == org_id

    bad = await client.post(f"{API}/assets/import", json={"format": "xml", "data": "<x/>"}, headers=org_a_headers)
    assert bad.status_code == 422


async def test_dashboard_from_stored_rows_and_snapshots(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    empty = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert empty["overall_risk_score"] is None
    assert empty["exposure_trend"] == [] and empty["compliance_trend"] == []
    assert empty["mean_time_to_remediate_days"] is None

    assert (await _import(client, org_a_headers)).status_code == 200
    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["total_assets"] == 2
    assert dash["open_exposures"] == 3
    assert dash["critical_vulns"] == 1 and dash["high_vulns"] == 1 and dash["medium_vulns"] == 1
    assert dash["overall_risk_score"] is not None and dash["overall_risk_score"] > 0
    assert dash["top_vulnerable_assets"][0]["hostname"] == "edge-01"
    assert dash["exposure_trend"] == []  # no snapshot stored yet: nothing invented

    cap = await client.post(f"{API}/snapshots/capture", headers=org_a_headers)
    assert cap.status_code == 200, cap.text
    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert len(dash["exposure_trend"]) == 1
    point = dash["exposure_trend"][0]
    assert point["exposures"] == 3 and point["critical"] == 1 and point["new_exposures"] == 3
    trend_b = (await client.get(f"{API}/trend", headers=org_b_headers)).json()
    assert trend_b["points"] == []

    # Capturing again the same day refreshes the row instead of adding one.
    await client.post(f"{API}/snapshots/capture", headers=org_a_headers)
    rows = (
        await db_session.execute(
            select(func.count(ExposureDailySnapshot.id)).where(ExposureDailySnapshot.organization_id == org_id),
        )
    ).scalar()
    assert rows == 1

    # Deactivated assets leave the counts.
    edge = (await db_session.execute(select(ExposureAsset).where(ExposureAsset.hostname == "edge-01"))).scalar_one()
    edge_id = edge.id
    assert (await client.delete(f"{API}/assets/{edge_id}", headers=org_a_headers)).status_code == 204
    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["total_assets"] == 1 and dash["inactive_assets"] == 1
    listed = (await client.get(f"{API}/assets", headers=org_a_headers)).json()
    assert [a["hostname"] for a in listed["items"]] == ["db-01"]
    assert listed["items"][0]["status"] == "active"
    with_inactive = (await client.get(f"{API}/assets", params={"include_inactive": True}, headers=org_a_headers)).json()
    assert {a["status"] for a in with_inactive["items"]} == {"active", "inactive"}


async def test_snapshot_task_covers_each_org(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_b: Organization,
    org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    from src.exposure.tasks import _snapshot_exposure_daily_async
    from src.workers.celery_app import celery_app

    a_id, b_id = org_a.id, org_b.id
    await _import(client, org_a_headers)
    await _import(client, org_b_headers, data=NESSUS.replace("edge-01", "edge-b"))
    result = await _snapshot_exposure_daily_async()
    assert result["snapshots_written"] == 2 and result["failures"] == []
    orgs = set(
        (await db_session.execute(select(ExposureDailySnapshot.organization_id))).scalars(),
    )
    assert orgs == {a_id, b_id}
    assert "src.exposure.tasks.snapshot_exposure_daily" in {e["task"] for e in celery_app.conf.beat_schedule.values()}


async def test_vulnerability_filters_and_fields(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    assert (await _import(client, org_a_headers)).status_code == 200
    resp = await client.get(f"{API}/vulnerabilities", params={"severity": "critical,high"}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert {v["severity"] for v in items} == {"critical", "high"}
    assert all(v["affected_assets"] == 1 and v["status"] == "open" for v in items)

    vuln = (
        await db_session.execute(select(ExposureVulnerability).where(ExposureVulnerability.cve_id == "CVE-2026-0001"))
    ).scalar_one()
    vuln.is_exploited_in_wild = True
    await db_session.commit()
    kev = await client.get(f"{API}/vulnerabilities", params={"has_exploit": "kev"}, headers=org_a_headers)
    assert [v["cve_id"] for v in kev.json()["items"]] == ["CVE-2026-0001"]
    bad = await client.get(f"{API}/vulnerabilities", params={"has_exploit": "maybe"}, headers=org_a_headers)
    assert bad.status_code == 422


async def test_kev_sync_flags_exposure_catalogue(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    assert (await _import(client, org_a_headers)).status_code == 200
    resp = await client.post(
        "/api/v1/vulnmgmt/vulnerabilities/sync-kev",
        json={"vulnerabilities": [{"cveID": "CVE-2026-0002", "dateAdded": "2026-01-01", "dueDate": "2026-01-22"}]},
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["exposure_vulnerabilities_flagged"] == 1
    kev = (await client.get(f"{API}/vulnerabilities/kev", headers=org_a_headers)).json()
    assert [v["cve_id"] for v in kev["kev_vulnerabilities"]] == ["CVE-2026-0002"]


async def test_graph_from_stored_relations_and_attack_paths_501(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    assert (await _import(client, org_a_headers)).status_code == 200
    edge = (await db_session.execute(select(ExposureAsset).where(ExposureAsset.hostname == "edge-01"))).scalar_one()
    edge.is_internet_facing = True
    await db_session.commit()

    graph = (await client.get(f"{API}/graph", headers=org_a_headers)).json()
    types = [n["type"] for n in graph["nodes"]]
    assert types.count("asset") == 2 and types.count("vulnerability") == 3 and types.count("entry_point") == 1
    assert sum(1 for e in graph["edges"] if e["type"] == "has_vulnerability") == 3
    assert [e["target"] for e in graph["edges"] if e["type"] == "exposes"] == [f"asset:{edge.id}"]
    high_only = (await client.get(f"{API}/graph", params={"min_severity": "high"}, headers=org_a_headers)).json()
    assert sum(1 for n in high_only["nodes"] if n["type"] == "vulnerability") == 2

    other = (await client.get(f"{API}/graph", headers=org_b_headers)).json()
    assert other["nodes"] == [] and other["edges"] == []

    paths = await client.get(f"{API}/attack-paths", headers=org_a_headers)
    assert paths.status_code == 501
    assert paths.json()["detail"]["error"] == "not_implemented"


async def test_attack_surface_fields_and_snapshot_rows(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    created = await client.post(f"{API}/attack-surface", json={"name": "Internal", "surface_type": "internal"}, headers=org_a_headers)
    surface_id = created.json()["id"]
    assert created.json()["assessed"] is False
    snapshot = AttackSurface(
        organization_id=org_id, name="snapshot-x", surface_type="snapshot", last_assessed_at=datetime.now(timezone.utc),
        findings=[{"change": "new_assets", "items": ["10.0.0.1", "10.0.0.2"]}], metrics={"asset_keys": ["10.0.0.1"]},
    )
    db_session.add(snapshot)
    await db_session.commit()
    snapshot_id = snapshot.id

    assessed = await client.post(f"{API}/attack-surface/assess", params={"surface_id": surface_id}, headers=org_a_headers)
    assert assessed.status_code == 200, assessed.text
    listed = (await client.get(f"{API}/attack-surface", headers=org_a_headers)).json()["items"]
    assert [s["id"] for s in listed] == [surface_id]
    row = listed[0]
    assert row["type"] == "internal" and row["total_assets"] == 2 and row["assessed"] is True
    assert row["last_assessed"] and row["exposed_assets"] == 3

    blocked = await client.post(f"{API}/attack-surface/assess", params={"surface_id": snapshot_id}, headers=org_a_headers)
    assert blocked.status_code == 409
    snaps = (await client.get(f"{API}/attack-surface", params={"include_snapshots": True}, headers=org_a_headers)).json()
    snap = next(s for s in snaps["items"] if s["id"] == snapshot_id)
    assert snap["findings"] == [{"change": "new_assets", "count": 2}]


async def test_ticket_close_sets_resolved_at_and_mttr(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    ticket = RemediationTicket(organization_id=org_id, title="Patch", remediation_type="patch", priority="high")
    db_session.add(ticket)
    await db_session.commit()
    ticket_id = ticket.id
    ticket.created_at = datetime.now(timezone.utc) - timedelta(days=2)
    await db_session.commit()

    bad = await client.put(f"{API}/tickets/{ticket_id}", json={"status": "done"}, headers=org_a_headers)
    assert bad.status_code == 422
    closed = await client.put(f"{API}/tickets/{ticket_id}", json={"status": "closed"}, headers=org_a_headers)
    assert closed.status_code == 200, closed.text
    assert closed.json()["resolved_at"] and closed.json()["completed_at"] == closed.json()["resolved_at"]
    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["mean_time_to_remediate_days"] is not None and dash["mean_time_to_remediate_days"] >= 1.9

    multi = await client.get(f"{API}/tickets", params={"status": "closed,open", "priority": "high,low"}, headers=org_a_headers)
    assert [t["id"] for t in multi.json()["items"]] == [ticket_id]


async def test_actions_are_audited_and_viewer_blocked(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    actions = set((await db_session.execute(select(AuditLog.action).where(AuditLog.organization_id == org_id))).scalars())
    assert "exposure.scan_import" in actions
    for path in ("/snapshots/capture", "/risk/recalculate"):
        assert (await client.post(f"{API}{path}", headers=viewer_headers)).status_code == 403
    recalc = await client.post(f"{API}/risk/recalculate", headers=org_a_headers)
    assert recalc.status_code == 200 and recalc.json()["assets_scored"] == 2
