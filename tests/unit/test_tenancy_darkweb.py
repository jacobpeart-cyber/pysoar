"""Wave-1 tenancy and RBAC for the dark-web router (/api/v1/darkweb).

Covers org stamping, cross-tenant 404s for monitors / findings / credential
leaks / brand threats, role gates (viewer read-only, admin-only monitor
configuration and scans, analyst triage), the org-less superuser refusal and
the scan / dashboard error-handling regressions.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from src.darkweb.models import BrandThreat, CredentialLeak, DarkWebFinding, DarkWebMonitor
from tests.helpers.tenancy import assert_tenant_isolated

pytestmark = pytest.mark.asyncio

BASE = "/api/v1/darkweb"


async def _monitor(client, admin_headers) -> str:
    resp = await client.post(
        f"{BASE}/monitors",
        json={"name": f"Monitor {uuid.uuid4().hex[:6]}", "emails_watched": ["soc@pysoar-tests.io"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _finding(client, analyst_headers, monitor_id: str) -> str:
    resp = await client.post(
        f"{BASE}/findings",
        json={"monitor_id": monitor_id, "title": "Leaked creds", "severity": "high"},
        headers=analyst_headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _seed_leak_and_threat(db_session, org_id: str, finding_id: str) -> tuple[str, str]:
    leak = CredentialLeak(
        organization_id=org_id,
        finding_id=finding_id,
        email="victim@pysoar-tests.io",
        password_type="plaintext",
    )
    threat = BrandThreat(
        organization_id=org_id,
        finding_id=finding_id,
        threat_type="domain_typosquat",
        target_brand="pysoar",
        malicious_domain="pys0ar-tests.io",
    )
    db_session.add_all([leak, threat])
    await db_session.commit()
    return leak.id, threat.id


async def test_monitor_and_finding_stamped_and_isolated(
    client, db_session, org_a, org_a_admin_headers, org_a_headers, org_b_headers
):
    org_a_id = org_a.id
    monitor_id = await _monitor(client, org_a_admin_headers)
    finding_id = await _finding(client, org_a_headers, monitor_id)

    monitor = (await db_session.execute(select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id))).scalar_one()
    finding = (await db_session.execute(select(DarkWebFinding).where(DarkWebFinding.id == finding_id))).scalar_one()
    assert monitor.organization_id == org_a_id
    assert finding.organization_id == org_a_id

    await assert_tenant_isolated(client, "GET", f"{BASE}/monitors/{monitor_id}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{BASE}/findings/{finding_id}", org_b_headers)
    await assert_tenant_isolated(
        client, "PATCH", f"{BASE}/findings/{finding_id}", org_b_headers, json={"status": "confirmed"}
    )
    await assert_tenant_isolated(client, "POST", f"{BASE}/findings/{finding_id}/escalate", org_b_headers)
    await assert_tenant_isolated(client, "POST", f"{BASE}/findings/{finding_id}/notify", org_b_headers)
    await assert_tenant_isolated(
        client,
        "POST",
        f"{BASE}/findings/bulk-action",
        org_b_headers,
        json={"finding_ids": [finding_id], "action": "confirm"},
    )
    # Another tenant cannot attach a finding to org A's monitor.
    await assert_tenant_isolated(
        client, "POST", f"{BASE}/findings", org_b_headers, json={"monitor_id": monitor_id, "title": "x"}
    )

    for path in ("/monitors", "/findings"):
        listing = await client.get(f"{BASE}{path}", headers=org_b_headers)
        assert listing.status_code == 200
        ids = [i["id"] for i in listing.json()["items"]]
        assert monitor_id not in ids and finding_id not in ids


async def test_monitor_config_isolated_for_other_tenant_admin(
    client, db_session, org_b, org_a_admin_headers
):
    """Org B's admin cannot update / delete / scan org A's monitor."""
    from tests.helpers.tenancy import bearer, make_user

    admin_b = await make_user(db_session, role="admin", organization_id=org_b.id, label="admin-b")
    admin_b_headers = bearer(admin_b)
    monitor_id = await _monitor(client, org_a_admin_headers)
    await assert_tenant_isolated(client, "PATCH", f"{BASE}/monitors/{monitor_id}", admin_b_headers, json={"name": "x"})
    await assert_tenant_isolated(client, "DELETE", f"{BASE}/monitors/{monitor_id}", admin_b_headers)
    await assert_tenant_isolated(
        client, "POST", f"{BASE}/monitors/{monitor_id}/trigger-scan", admin_b_headers, json={"scan_type": "quick"}
    )


async def test_credentials_and_brand_threats_isolated(
    client, db_session, org_a, org_a_admin_headers, org_a_headers, org_b_headers
):
    org_a_id = org_a.id
    monitor_id = await _monitor(client, org_a_admin_headers)
    finding_id = await _finding(client, org_a_headers, monitor_id)
    leak_id, threat_id = await _seed_leak_and_threat(db_session, org_a_id, finding_id)

    await assert_tenant_isolated(
        client, "PATCH", f"{BASE}/credentials/{leak_id}", org_b_headers, json={"is_remediated": True}
    )
    await assert_tenant_isolated(
        client,
        "POST",
        f"{BASE}/credentials/bulk-remediate",
        org_b_headers,
        json={"credential_ids": [leak_id], "action": "password_reset"},
    )
    await assert_tenant_isolated(
        client, "PATCH", f"{BASE}/brand-threats/{threat_id}", org_b_headers, json={"takedown_status": "failed"}
    )
    await assert_tenant_isolated(client, "POST", f"{BASE}/brand-threats/{threat_id}/initiate-takedown", org_b_headers)

    creds = await client.get(f"{BASE}/credentials", headers=org_b_headers)
    assert leak_id not in [c["id"] for c in creds.json()["items"]]
    threats = await client.get(f"{BASE}/brand-threats", headers=org_b_headers)
    assert threat_id not in [t["id"] for t in threats.json()["items"]]

    own = await client.patch(f"{BASE}/credentials/{leak_id}", json={"is_remediated": True}, headers=org_a_headers)
    assert own.status_code == 200, own.text


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/monitors", {"name": "v"}),
        ("PATCH", "/monitors/x", {"name": "v"}),
        ("DELETE", "/monitors/x", None),
        ("POST", "/monitors/x/trigger-scan", {"scan_type": "quick"}),
        ("POST", "/findings", {"monitor_id": "x"}),
        ("PATCH", "/findings/x", {"status": "confirmed"}),
        ("POST", "/findings/x/escalate", None),
        ("POST", "/findings/x/notify", None),
        ("POST", "/findings/bulk-action", {"finding_ids": ["x"], "action": "confirm"}),
        ("PATCH", "/credentials/x", {"is_remediated": True}),
        ("POST", "/credentials/bulk-remediate", {"credential_ids": ["x"], "action": "password_reset"}),
        ("PATCH", "/brand-threats/x", {"takedown_status": "failed"}),
        ("POST", "/brand-threats/x/initiate-takedown", None),
    ],
)
async def test_viewer_cannot_write(client, viewer_headers, method, path, body):
    resp = await client.request(method, f"{BASE}{path}", json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/monitors", {"name": "v"}),
        ("PATCH", "/monitors/x", {"name": "v"}),
        ("DELETE", "/monitors/x", None),
        ("POST", "/monitors/x/trigger-scan", {"scan_type": "quick"}),
    ],
)
async def test_analyst_cannot_configure_or_scan(client, org_a_headers, method, path, body):
    resp = await client.request(method, f"{BASE}{path}", json=body, headers=org_a_headers)
    assert resp.status_code == 403, resp.text


async def test_viewer_can_read(client, viewer_headers):
    for path in ("/monitors", "/findings", "/credentials", "/brand-threats", "/dashboard", "/report/export"):
        resp = await client.get(f"{BASE}{path}", headers=viewer_headers)
        assert resp.status_code == 200, (path, resp.text)


@pytest.mark.parametrize("path", ["/monitors", "/findings", "/credentials", "/brand-threats", "/dashboard", "/report/export"])
async def test_orgless_superuser_refused(client, superuser_headers, path):
    resp = await client.get(f"{BASE}{path}", headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"


# --------------------------------------------------------------------------
# Regressions: error handling
# --------------------------------------------------------------------------


async def test_scan_engine_failure_is_502_not_fake_completion(client, org_a_admin_headers, monkeypatch):
    """Was: an engine exception became a 'completed' scan with 0 findings."""
    from src.darkweb.engine import DarkWebScanner

    async def boom(self, *args, **kwargs):
        raise RuntimeError("upstream unreachable")

    monkeypatch.setattr(DarkWebScanner, "search_breach_databases", boom)
    monitor_id = await _monitor(client, org_a_admin_headers)
    resp = await client.post(
        f"{BASE}/monitors/{monitor_id}/trigger-scan", json={"scan_type": "quick"}, headers=org_a_admin_headers
    )
    assert resp.status_code == 502, resp.text
    assert resp.json()["detail"]["error"] == "darkweb_scan_failed"


async def test_scan_records_last_check(client, db_session, org_a_admin_headers, monkeypatch):
    """Was: wrote a non-existent attribute inside `except: pass`."""
    from src.darkweb.engine import DarkWebScanner

    async def none(self, *args, **kwargs):
        return []

    monkeypatch.setattr(DarkWebScanner, "search_breach_databases", none)
    monitor_id = await _monitor(client, org_a_admin_headers)
    resp = await client.post(
        f"{BASE}/monitors/{monitor_id}/trigger-scan", json={"scan_type": "quick"}, headers=org_a_admin_headers
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    monitor = (await db_session.execute(select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id))).scalar_one()
    assert monitor.last_check


async def test_dashboard_counts_exposed_domains(
    client, db_session, org_a, org_a_admin_headers, org_a_headers
):
    """Was: split_part() inside `except: pass` (0 on SQLite, aborted
    transaction on Postgres). Now computed portably."""
    org_a_id = org_a.id
    monitor_id = await _monitor(client, org_a_admin_headers)
    finding_id = await _finding(client, org_a_headers, monitor_id)
    await _seed_leak_and_threat(db_session, org_a_id, finding_id)

    resp = await client.get(f"{BASE}/dashboard", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    summary = resp.json()["exposure_summary"]
    assert summary["exposed_domains"] >= 1
    assert summary["exposed_emails"] >= 1
