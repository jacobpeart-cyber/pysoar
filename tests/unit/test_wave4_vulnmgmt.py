"""Wave 4 (W4-A): vulnerability management backed by stored rows.

- Scanner import creates real VulnerabilityInstance rows linked to inventory
  assets, deduplicated on (asset, CVE or plugin id, port/protocol), and
  reports new / updated / reopened / skipped-with-reason counts.
- Catalogue CVEs are unique per tenant, not across tenants.
- KEV sync flags tracked CVEs only (body or pinned server-side fetch).
- Patch and exception flows act on instance ids; SLA, risk and MTTR come from
  the stored rows.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.asset import Asset
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.vulnmgmt import engine as vm_engine
from src.vulnmgmt.engine import (
    KEVFeedUnavailable,
    compute_risk,
    fetch_kev_catalog,
    policy_deadline,
    sla_state,
)
from src.vulnmgmt.models import (
    PatchOperation,
    Vulnerability,
    VulnerabilityException,
    VulnerabilityInstance,
)

API = "/api/v1/vulnmgmt"

NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2>
 <Report name="weekly">
  <ReportHost name="web-01.example.test">
   <HostProperties><tag name="host-ip">10.20.0.5</tag></HostProperties>
   <ReportItem port="443" svc_name="www" protocol="tcp" severity="4" pluginID="156860" pluginName="Apache Log4j RCE">
    <cve>CVE-2021-44228</cve><cvss3_base_score>10.0</cvss3_base_score>
    <description>Log4Shell</description><solution>Upgrade log4j</solution>
   </ReportItem>
   <ReportItem port="8443" svc_name="www" protocol="tcp" severity="4" pluginID="156860" pluginName="Apache Log4j RCE">
    <cve>CVE-2021-44228</cve><cvss3_base_score>10.0</cvss3_base_score>
   </ReportItem>
   <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="70658" pluginName="SSH CBC ciphers">
   </ReportItem>
   <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information">
   </ReportItem>
  </ReportHost>
  <ReportHost name="10.20.0.9">
   <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="3" pluginID="97833" pluginName="MS17-010">
    <cve>CVE-2017-0144</cve>
   </ReportItem>
  </ReportHost>
 </Report>
</NessusClientData_v2>
"""


async def _import(client: AsyncClient, headers: dict[str, str], data: str = NESSUS, fmt: str = "nessus") -> httpx.Response:
    return await client.post(f"{API}/vulnerabilities/import-scan", json={"scan_format": fmt, "scan_data": data}, headers=headers)


async def _instances(db: AsyncSession, org_id: str) -> list[VulnerabilityInstance]:
    db.expire_all()
    return list((await db.execute(select(VulnerabilityInstance).where(VulnerabilityInstance.organization_id == org_id))).scalars())


# --------------------------------------------------------------------------- #
# Scanner import
# --------------------------------------------------------------------------- #


async def test_nessus_import_creates_linked_deduplicated_instances(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    known = Asset(organization_id=org_id, name="dc-09", hostname="dc-09", ip_address="10.20.0.9", criticality="critical")
    db_session.add(known)
    await db_session.commit()
    known_id = known.id

    resp = await _import(client, org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["findings_read"] == 5
    # log4j on 443 and 8443 are two instances; SSH ciphers keyed by plugin id; MS17-010.
    assert body["instances_created"] == 4
    assert body["new"] == 4
    assert body["instances_updated"] == 0
    assert body["vulnerabilities_created"] == 3
    assert body["assets_created"] == 1
    assert body["assets_linked"] == 1
    assert {s["reason"]: s["count"] for s in body["skipped"]} == {"informational_finding": 1}

    rows = await _instances(db_session, org_id)
    assert len(rows) == 4
    by_port = {(r.port, r.plugin_id) for r in rows}
    assert {(443, "156860"), (8443, "156860"), (22, "70658"), (445, "97833")} == by_port
    assert all(r.asset_id for r in rows)
    ms17 = next(r for r in rows if r.port == 445)
    assert ms17.asset_id == known_id
    assert ms17.business_criticality == 4
    assert all(r.risk_score is not None and r.remediation_deadline and r.first_seen for r in rows)

    catalogue = {
        v.cve_id
        for v in (await db_session.execute(select(Vulnerability).where(Vulnerability.organization_id == org_id))).scalars()
    }
    assert catalogue == {"CVE-2021-44228", "CVE-2017-0144", "NESSUS-70658"}
    created_asset = (
        await db_session.execute(select(Asset).where(Asset.organization_id == org_id, Asset.ip_address == "10.20.0.5"))
    ).scalar_one()
    assert created_asset.hostname == "web-01.example.test"

    again = await _import(client, org_a_headers)
    assert again.status_code == 200, again.text
    second = again.json()
    assert second["instances_created"] == 0
    assert second["instances_updated"] == 4
    assert second["assets_created"] == 0
    assert len(await _instances(db_session, org_id)) == 4

    audit = (
        await db_session.execute(
            select(func.count(AuditLog.id)).where(AuditLog.action == "vulnmgmt.scan_import", AuditLog.organization_id == org_id),
        )
    ).scalar()
    assert audit == 2


async def test_reimport_reopens_a_patched_instance(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    rows = await _instances(db_session, org_id)
    target = next(r for r in rows if r.port == 443).id

    patched = await client.put(f"{API}/instances/{target}", json={"status": "patched"}, headers=org_a_headers)
    assert patched.status_code == 200, patched.text
    assert patched.json()["remediated_at"]

    resp = await _import(client, org_a_headers)
    assert resp.json()["instances_reopened"] == 1
    db_session.expire_all()
    row = await db_session.get(VulnerabilityInstance, target)
    assert row.status == "open"
    assert row.remediated_at is None


@pytest.mark.parametrize(
    ("fmt", "data", "fragment"),
    [
        ("nessus", "not xml at all", "no findings could be read"),
        ("nessus", "<NessusClientData_v2><Report", "Parse error"),
        ("trivy", "{}", "Unsupported scan_format"),
        ("nessus", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x/>', "DTD"),
    ],
)
async def test_unreadable_scan_is_a_422_with_the_reason(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
    fmt: str, data: str, fragment: str,
) -> None:
    org_id = org_a.id
    resp = await _import(client, org_a_headers, data=data, fmt=fmt)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "scan_parse_failed"
    assert any(fragment.lower() in e.lower() for e in detail["errors"]), detail
    assert await _instances(db_session, org_id) == []


async def test_csv_and_openvas_imports(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    qualys = (
        "Scan Results,,,\n"
        "IP,DNS,QID,Title,Severity,CVE ID,Port,Protocol\n"
        "10.1.1.1,app-1,38173,TLS weak,3,,443,tcp\n"
        ",,11111,No host,4,CVE-2020-1111,80,tcp\n"
    )
    resp = await _import(client, org_a_headers, data=qualys, fmt="qualys")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["instances_created"] == 1
    assert {s["reason"] for s in body["skipped"]} == {"no_asset_identifier"}

    openvas = """<report><results>
      <result><name>OpenSSH flaw</name><host>10.1.1.2<hostname>ssh-1</hostname></host><port>22/tcp</port>
        <nvt oid="1.3.6.1.4.1.25623.1.0.1"><refs><ref type="cve" id="CVE-2023-38408"/></refs></nvt>
        <threat>High</threat><severity>9.8</severity></result>
    </results></report>"""
    resp = await _import(client, org_a_headers, data=openvas, fmt="openvas")
    assert resp.status_code == 200, resp.text
    assert resp.json()["instances_created"] == 1
    row = next(r for r in await _instances(db_session, org_id) if r.port == 22)
    assert row.protocol == "tcp"
    assert row.plugin_id == "1.3.6.1.4.1.25623.1.0.1"


async def test_same_cve_in_two_tenants(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    a = await _import(client, org_a_headers)
    b = await _import(client, org_b_headers)
    assert a.status_code == 200 and b.status_code == 200, (a.text, b.text)
    assert b.json()["vulnerabilities_created"] == 3
    count = (
        await db_session.execute(select(func.count(Vulnerability.id)).where(Vulnerability.cve_id == "CVE-2021-44228"))
    ).scalar()
    assert count == 2
    listed_b = await client.get(f"{API}/instances", params={"size": 100}, headers=org_b_headers)
    assert listed_b.json()["total"] == 4


# --------------------------------------------------------------------------- #
# Catalogue list / dashboard fields the page reads
# --------------------------------------------------------------------------- #


async def test_vulnerability_list_and_dashboard_fields(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    assert (await _import(client, org_a_headers)).status_code == 200
    resp = await client.get(f"{API}/vulnerabilities", params={"size": 100}, headers=org_a_headers)
    items = {i["cve_id"]: i for i in resp.json()["items"]}
    log4j = items["CVE-2021-44228"]
    assert log4j["affected_instance_count"] == 2
    assert log4j["open_instance_count"] == 2
    assert log4j["days_open"] == 0
    assert log4j["kev_listed"] is False

    dash = await client.get(f"{API}/dashboard", headers=org_a_headers)
    assert dash.status_code == 200, dash.text
    d = dash.json()
    assert d["total_vulnerabilities"] == 3
    assert d["critical_vulnerabilities"] == 1
    assert d["open_findings"] == 4
    assert d["total_instances"] == 4
    assert d["assets_affected"] == 2
    assert d["by_severity"]["critical"] == 2
    assert d["by_severity"]["high"] == 1
    assert d["by_severity"]["medium"] == 1
    assert d["mttr_days"] is None and d["mean_time_to_remediate_days"] is None
    assert d["sla_compliance"]["total"] == 4
    assert d["kev_compliance"]["total_kev_tracked"] == 0
    assert d["kev_compliance"]["compliance_percentage"] is None
    assert d["kev_listed_count"] == 0
    assert d["top_vulnerabilities"][0]["cve_id"] == "CVE-2021-44228"


# --------------------------------------------------------------------------- #
# KEV
# --------------------------------------------------------------------------- #


def _kev_doc(*entries: tuple[str, str]) -> dict[str, Any]:
    return {
        "catalogVersion": "test",
        "vulnerabilities": [{"cveID": cve, "dateAdded": "2021-12-10", "dueDate": due} for cve, due in entries],
    }


async def test_kev_sync_flags_tracked_cves_only(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    due = (datetime.now(timezone.utc) + timedelta(days=3)).date().isoformat()
    resp = await client.post(
        f"{API}/vulnerabilities/sync-kev",
        json=_kev_doc(("CVE-2021-44228", due), ("CVE-1999-0001", "2000-01-01")),
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["matched"] == 1 and body["newly_flagged"] == 1 and body["added"] == 0
    assert body["source"] == "request_body"
    total = (await db_session.execute(select(func.count(Vulnerability.id)).where(Vulnerability.organization_id == org_id))).scalar()
    assert total == 3  # nothing created from the feed

    db_session.expire_all()
    log4j = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.organization_id == org_id, Vulnerability.cve_id == "CVE-2021-44228"),
        )
    ).scalar_one()
    assert log4j.kev_listed and log4j.kev_due_date == due
    log4j_id = log4j.id
    rows = [r for r in await _instances(db_session, org_id) if r.vulnerability_id == log4j_id]
    # The KEV due date (3 days) tightens the 15-day critical SLA: approaching.
    assert all(r.remediation_deadline.startswith(due) for r in rows)
    assert {r.sla_status for r in rows} == {"approaching"}

    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["kev_listed_count"] == 1
    assert dash["open_kev_instances"] == 2
    assert dash["kev_compliance"]["total_kev_tracked"] == 2
    assert dash["kev_compliance"]["compliance_percentage"] == 100.0
    kev_list = await client.get(f"{API}/vulnerabilities", params={"kev_only": True}, headers=org_a_headers)
    assert [v["cve_id"] for v in kev_list.json()["items"]] == ["CVE-2021-44228"]


async def test_kev_sync_without_body_fetches_and_reports_feed_failure(
    client: AsyncClient, org_a_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable() -> dict[str, Any]:
        raise KEVFeedUnavailable("connect refused")

    monkeypatch.setattr("src.api.v1.endpoints.vulnmgmt.fetch_kev_catalog", unavailable)
    resp = await client.post(f"{API}/vulnerabilities/sync-kev", headers=org_a_headers)
    assert resp.status_code == 502, resp.text
    assert resp.json()["detail"]["error"] == "kev_feed_unavailable"

    async def feed() -> dict[str, Any]:
        return _kev_doc(("CVE-2017-0144", "2022-01-01"))

    monkeypatch.setattr("src.api.v1.endpoints.vulnmgmt.fetch_kev_catalog", feed)
    ok = await client.post(f"{API}/vulnerabilities/sync-kev", headers=org_a_headers)
    assert ok.status_code == 200, ok.text
    assert ok.json()["source"] == "cisa_feed"
    assert ok.json()["matched"] == 0


async def test_fetch_kev_catalog_goes_through_the_given_transport() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=_kev_doc(("CVE-2021-44228", "2021-12-24")))

    data = await fetch_kev_catalog(transport=httpx.MockTransport(handler))
    assert seen == [vm_engine.KEV_FEED_URL]
    assert data["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"

    with pytest.raises(KEVFeedUnavailable):
        await fetch_kev_catalog(transport=httpx.MockTransport(lambda _r: httpx.Response(500)))
    with pytest.raises(KEVFeedUnavailable):
        await fetch_kev_catalog(transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"x": 1})))


# --------------------------------------------------------------------------- #
# Patch and exception flows on instance ids
# --------------------------------------------------------------------------- #


async def test_patch_flow_on_instance_ids(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    target = next(r for r in await _instances(db_session, org_id) if r.port == 445).id

    plan = await client.post(
        f"{API}/patch-operations/create-plan", json={"vulnerability_instance_ids": [target, "missing"]}, headers=org_a_headers,
    )
    assert plan.status_code == 200, plan.text
    plan_body = plan.json()
    op_id = plan_body["plan_id"]
    assert plan_body["patch_operation_ids"] == [op_id]
    assert {"instance_id": "missing", "reason": "not_found"} in plan_body["skipped"]
    db_session.expire_all()
    assert (await db_session.get(VulnerabilityInstance, target)).status == "in_progress"

    dup = await client.post(
        f"{API}/patch-operations/create-plan", json={"vulnerability_instance_ids": [target]}, headers=org_a_headers,
    )
    assert dup.status_code == 409, dup.text
    assert dup.json()["detail"]["skipped"][0]["reason"] == "active_patch_operation_exists"

    not_deployed = await client.post(
        f"{API}/patch-operations/{op_id}/rollback", json={"reason": "nothing was deployed yet"}, headers=org_a_headers,
    )
    assert not_deployed.status_code == 409
    assert not_deployed.json()["detail"]["error"] == "not_reversible"

    ops = (await client.get(f"{API}/patch-operations", headers=org_a_headers)).json()["items"]
    assert ops[0]["cve_id"] == "CVE-2017-0144" and ops[0]["asset_name"]

    verify = await client.post(
        f"{API}/patch-operations/{op_id}/verify", json={"verification_results": {"passed": True}}, headers=org_a_headers,
    )
    assert verify.status_code == 200 and verify.json()["status"] == "verified"
    db_session.expire_all()
    inst = await db_session.get(VulnerabilityInstance, target)
    assert inst.status == "patched" and inst.remediated_at

    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["mttr_days"] is not None and dash["mttr_days"] >= 0
    assert dash["open_findings"] == 3

    rolled = await client.post(
        f"{API}/patch-operations/{op_id}/rollback", json={"reason": "broke the file share"}, headers=org_a_headers,
    )
    assert rolled.status_code == 200, rolled.text
    db_session.expire_all()
    assert (await db_session.get(VulnerabilityInstance, target)).status == "open"
    actions = set(
        (await db_session.execute(select(AuditLog.action).where(AuditLog.organization_id == org_id))).scalars(),
    )
    assert {"vulnmgmt.patch_plan", "vulnmgmt.patch_verify", "vulnmgmt.patch_rollback"} <= actions


async def test_exception_sets_instance_status_and_expires(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    target = next(r for r in await _instances(db_session, org_id) if r.port == 22).id

    bad = await client.post(
        f"{API}/exceptions",
        json={"vulnerability_instance_id": target, "exception_type": "because", "justification": "long enough reason"},
        headers=org_a_headers,
    )
    assert bad.status_code == 422

    resp = await client.post(
        f"{API}/exceptions",
        json={
            "vulnerability_instance_id": target,
            "exception_type": "risk_accepted",
            "justification": "Legacy appliance, isolated VLAN.",
            "expiry_date": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
        headers=org_a_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "active" and body["cve_id"] == "NESSUS-70658" and body["vulnerability_id"]
    db_session.expire_all()
    assert (await db_session.get(VulnerabilityInstance, target)).status == "accepted"
    sla_total = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()["sla_compliance"]["total"]
    assert sla_total == 3  # accepted risk leaves SLA accounting

    exc = (await db_session.execute(select(VulnerabilityException).where(VulnerabilityException.organization_id == org_id))).scalar_one()
    exc.expiry_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    await db_session.commit()
    listed = await client.get(f"{API}/exceptions", params={"status": "expired"}, headers=org_a_headers)
    assert [e["status"] for e in listed.json()["items"]] == ["expired"]

    refreshed = await client.post(f"{API}/instances/refresh-scores", headers=org_a_headers)
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["reopened_after_exception_expiry"] == 1
    db_session.expire_all()
    assert (await db_session.get(VulnerabilityInstance, target)).status == "open"


async def test_bulk_action_validates_and_stamps_remediation(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    ids = [r.id for r in await _instances(db_session, org_id)]
    bad = await client.post(
        f"{API}/instances/bulk-action", json={"instance_ids": ids, "action": "update_status", "value": "done"}, headers=org_a_headers,
    )
    assert bad.status_code == 422
    ok = await client.post(
        f"{API}/instances/bulk-action",
        json={"instance_ids": [*ids, "nope"], "action": "update_status", "value": "mitigated"},
        headers=org_a_headers,
    )
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"updated": 4, "not_found": ["nope"]}
    rows = await _instances(db_session, org_id)
    assert all(r.status == "mitigated" and r.remediated_at for r in rows)


async def test_manual_instance_is_deduplicated(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    vuln = await client.post(f"{API}/vulnerabilities", json={"cve_id": "CVE-2026-4242", "title": "x"}, headers=org_a_headers)
    vuln_id = vuln.json()["id"]
    dup_vuln = await client.post(f"{API}/vulnerabilities", json={"cve_id": "CVE-2026-4242", "title": "x"}, headers=org_a_headers)
    assert dup_vuln.status_code == 409
    body = {"vulnerability_id": vuln_id, "asset_ip": "10.0.0.7", "port": 80, "protocol": "tcp", "risk_score": 99}
    first = await client.post(f"{API}/instances", json=body, headers=org_a_headers)
    assert first.status_code == 201, first.text
    assert first.json()["risk_score"] != 99  # computed, not client-supplied
    second = await client.post(f"{API}/instances", json=body, headers=org_a_headers)
    assert second.status_code == 409
    assert second.json()["detail"]["error"] == "duplicate_instance"
    other_port = await client.post(f"{API}/instances", json={**body, "port": 8080}, headers=org_a_headers)
    assert other_port.status_code == 201


# --------------------------------------------------------------------------- #
# Scoring rules
# --------------------------------------------------------------------------- #


def test_compute_risk_uses_stored_signals() -> None:
    risk, exploitability = compute_risk(
        cvss=10.0, severity="critical", epss=None, kev_listed=False, exploit_maturity="unproven", business_criticality=None,
    )
    assert risk == 70.0 and exploitability is None
    risk, exploitability = compute_risk(
        cvss=None, severity="high", epss=0.5, kev_listed=True, exploit_maturity="weaponized", business_criticality=4,
    )
    assert risk == min(100.0, round((7.5 * 7 + 7.5 + 15 + 10) * 1.2, 2))
    assert exploitability == 50.0
    _, kev_only = compute_risk(cvss=5.0, severity="medium", epss=None, kev_listed=True, exploit_maturity=None, business_criticality=2)
    assert kev_only == 100.0


def test_sla_policy_and_state() -> None:
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    first = now - timedelta(days=10)
    assert policy_deadline("critical", first, False, None) == first + timedelta(days=15)
    assert policy_deadline("informational", first, False, None) is None
    assert policy_deadline("low", first, True, "2026-10-03") == datetime(2026, 10, 3, tzinfo=timezone.utc)
    deadline = first + timedelta(days=15)
    assert sla_state("open", deadline, first, None, now) == "within_sla"
    assert sla_state("open", deadline, first, None, deadline - timedelta(days=1)) == "approaching"
    assert sla_state("open", deadline, first, None, deadline + timedelta(seconds=1)) == "breached"
    assert sla_state("patched", deadline, first, deadline - timedelta(days=2), now + timedelta(days=30)) == "within_sla"
    assert sla_state("patched", deadline, first, deadline + timedelta(days=2), now) == "breached"


# --------------------------------------------------------------------------- #
# Roles and scheduling
# --------------------------------------------------------------------------- #


async def test_viewer_cannot_refresh_scores(client: AsyncClient, viewer_headers: dict[str, str]) -> None:
    resp = await client.post(f"{API}/instances/refresh-scores", headers=viewer_headers)
    assert resp.status_code == 403


async def test_refresh_sweep_and_beat_entries(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    from src.vulnmgmt.tasks import _refresh_scores_sweep
    from src.workers.celery_app import celery_app

    org_id = org_a.id
    assert (await _import(client, org_a_headers)).status_code == 200
    rows = await _instances(db_session, org_id)
    for r in rows:
        r.risk_score = None
    await db_session.commit()

    result = await _refresh_scores_sweep(org_id)
    assert result["instances_refreshed"] == 4 and result["failures"] == []
    assert all(r.risk_score is not None for r in await _instances(db_session, org_id))

    beat = {e["task"] for e in celery_app.conf.beat_schedule.values()}
    assert {"src.vulnmgmt.tasks.refresh_instance_scores", "src.vulnmgmt.tasks.sync_kev_catalog"} <= beat
    for name in ("src.vulnmgmt.tasks.refresh_instance_scores", "src.vulnmgmt.tasks.sync_kev_catalog"):
        assert celery_app.conf.task_annotations[name]["time_limit"] < celery_app.conf.task_time_limit

    ops = (await db_session.execute(select(func.count(PatchOperation.id)))).scalar()
    assert ops == 0
