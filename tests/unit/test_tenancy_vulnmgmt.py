"""Wave 1 tenancy / RBAC conversion of the vulnerability management router.

docs/audit/2026-10-08/posture-risk.md: every vulnmgmt route takes the
mandatory ``OrganizationId`` (the conditional org guard on the exceptions list
and the patch-schedule agent lookup are gone), lookups by id 404 outside the
tenant, an instance cannot point at another tenant's catalog vulnerability,
writes need analyst or admin, scan profiles (configuration) need admin, and
the patch "schedule" no longer dispatches a no-op agent command while
claiming a deployment.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import AgentCommand
from src.models.organization import Organization
from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/vulnmgmt"


def _cve() -> str:
    return f"CVE-2026-{uuid.uuid4().int % 10**7:07d}"


async def _seed(db: AsyncSession, org_id: str) -> dict[str, str]:
    vuln = Vulnerability(organization_id=org_id, cve_id=_cve(), title="OpenSSL overflow", severity="critical")
    db.add(vuln)
    await db.flush()
    instance = VulnerabilityInstance(organization_id=org_id, vulnerability_id=vuln.id, asset_name="web-01")
    db.add(instance)
    await db.commit()
    return {"vuln": vuln.id, "instance": instance.id}


async def test_vulnerability_create_is_stamped_and_isolated(
    client: AsyncClient,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(
        f"{API}/vulnerabilities",
        json={"cve_id": _cve(), "title": "Tenant A vuln", "organization_id": "spoofed"},
        headers=org_a_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    vuln_id = body["id"]
    assert body["organization_id"] == org_a_id

    listed = await client.get(f"{API}/vulnerabilities", headers=org_b_headers)
    assert listed.status_code == 200, listed.text
    assert vuln_id not in {row["id"] for row in listed.json()["items"]}

    await assert_tenant_isolated(client, "GET", f"{API}/vulnerabilities/{vuln_id}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/vulnerabilities/{vuln_id}", org_b_headers, json={"title": "hijack"},
    )


async def test_instances_exceptions_and_patches_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)

    listed = await client.get(f"{API}/instances", headers=org_b_headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()["items"] == []

    await assert_tenant_isolated(client, "GET", f"{API}/instances/{ids['instance']}", org_b_headers)
    await assert_tenant_isolated(
        client, "PUT", f"{API}/instances/{ids['instance']}", org_b_headers, json={"status": "patched"},
    )
    await assert_tenant_isolated(
        client, "POST", f"{API}/instances/bulk-action", org_b_headers,
        json={"instance_ids": [ids["instance"]], "action": "update_status", "value": "patched"},
    )
    await assert_tenant_isolated(
        client, "POST", f"{API}/patch-operations/create-plan", org_b_headers,
        json={"vulnerability_instance_ids": [ids["instance"]]},
    )

    exc = await client.post(
        f"{API}/exceptions",
        json={
            "vulnerability_instance_id": ids["instance"],
            "exception_type": "risk_accepted",
            "justification": "Compensating WAF rule in place.",
        },
        headers=org_a_headers,
    )
    assert exc.status_code == 201, exc.text
    exception_id = exc.json()["id"]
    b_exceptions = await client.get(f"{API}/exceptions", headers=org_b_headers)
    assert b_exceptions.status_code == 200, b_exceptions.text
    assert exception_id not in {row["id"] for row in b_exceptions.json()["items"]}
    await assert_tenant_isolated(
        client, "PUT", f"{API}/exceptions/{exception_id}", org_b_headers, json={"expiry_date": "2027-01-01"},
    )

    plan = await client.post(
        f"{API}/patch-operations/create-plan",
        json={"vulnerability_instance_ids": [ids["instance"]]},
        headers=org_a_headers,
    )
    assert plan.status_code == 200, plan.text
    patch_id = plan.json()["plan_id"]
    b_ops = await client.get(f"{API}/patch-operations", headers=org_b_headers)
    assert b_ops.json()["items"] == []
    for suffix, body in (
        ("schedule", {"deployment_date": "2026-11-01T02:00:00Z"}),
        ("verify", {"verification_results": {"passed": True}}),
        ("rollback", {"reason": "rolled back by other tenant"}),
    ):
        await assert_tenant_isolated(
            client, "POST", f"{API}/patch-operations/{patch_id}/{suffix}", org_b_headers, json=body,
        )


async def test_instance_cannot_reference_another_tenants_vulnerability(
    client: AsyncClient,
    db_session: AsyncSession,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    foreign = await _seed(db_session, org_b.id)
    resp = await client.post(
        f"{API}/instances",
        json={"vulnerability_id": foreign["vuln"], "asset_name": "a-host"},
        headers=org_a_headers,
    )
    assert resp.status_code == 404, resp.text


async def test_patch_schedule_records_date_without_fake_dispatch(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    ids = await _seed(db_session, org_a.id)
    plan = await client.post(
        f"{API}/patch-operations/create-plan",
        json={"vulnerability_instance_ids": [ids["instance"]]},
        headers=org_a_headers,
    )
    patch_id = plan.json()["plan_id"]

    resp = await client.post(
        f"{API}/patch-operations/{patch_id}/schedule",
        json={"deployment_date": "2026-11-01T02:00:00Z"},
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deployment_date"] == "2026-11-01T02:00:00Z"
    assert body["deployment_dispatched"] is False
    assert body["agent_command_id"] is None
    commands = (await db_session.execute(select(AgentCommand))).scalars().all()
    assert not [c for c in commands if (c.payload or {}).get("patch_operation_id") == patch_id]

    verify = await client.post(
        f"{API}/patch-operations/{patch_id}/verify",
        json={"verification_results": {"passed": True}},
        headers=org_a_headers,
    )
    assert verify.status_code == 200, verify.text
    assert verify.json()["recorded_only"] is True


WRITE_ROUTES: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", "/vulnerabilities", {"cve_id": "CVE-2026-0000001", "title": "x"}),
    ("PUT", "/vulnerabilities/missing", {"title": "x"}),
    ("POST", "/vulnerabilities/import-scan", {"scan_format": "nessus", "scan_data": ""}),
    ("POST", "/vulnerabilities/sync-kev", {"vulnerabilities": []}),
    ("POST", "/instances", {"vulnerability_id": "missing"}),
    ("PUT", "/instances/missing", {"status": "patched"}),
    ("POST", "/instances/bulk-action", {"instance_ids": ["x"], "action": "assign", "value": "me"}),
    ("POST", "/scan-profiles", {"name": "weekly", "scanner_type": "nessus"}),
    ("PUT", "/scan-profiles/missing", {"name": "weekly"}),
    ("POST", "/patch-operations/create-plan", {"vulnerability_instance_ids": ["x"]}),
    ("POST", "/patch-operations/missing/schedule", {"deployment_date": "2026-11-01"}),
    ("POST", "/patch-operations/missing/verify", {"verification_results": {"passed": True}}),
    ("POST", "/patch-operations/missing/rollback", {"reason": "because it broke"}),
    ("POST", "/exceptions", {"vulnerability_instance_id": "x", "justification": "long enough reason"}),
    ("PUT", "/exceptions/missing", {"expiry_date": "2027-01-01"}),
]


@pytest.mark.parametrize(("method", "path", "body"), WRITE_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient, viewer_headers: dict[str, str], method: str, path: str, body: dict[str, Any],
) -> None:
    resp = await client.request(method, f"{API}{path}", json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/scan-profiles", {"name": "weekly", "scanner_type": "nessus"}),
        ("PUT", "/scan-profiles/missing", {"name": "weekly"}),
    ],
)
async def test_scan_profiles_are_admin_only(
    client: AsyncClient,
    org_a_headers: dict[str, str],
    method: str,
    path: str,
    body: dict[str, Any],
) -> None:
    resp = await client.request(method, f"{API}{path}", json=body, headers=org_a_headers)
    assert resp.status_code == 403, resp.text


async def test_admin_creates_scan_profile_in_own_org(
    client: AsyncClient,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(
        f"{API}/scan-profiles",
        json={"name": "weekly", "scanner_type": "nessus"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["organization_id"] == org_a_id
    b_profiles = await client.get(f"{API}/scan-profiles", headers=org_b_headers)
    assert b_profiles.json()["items"] == []


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    resp = await client.get(f"{API}/vulnerabilities", headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert "organization_required" in resp.text
