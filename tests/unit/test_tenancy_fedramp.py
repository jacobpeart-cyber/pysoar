"""Tenancy and RBAC for the FedRAMP router (wave 1, docs/audit/2026-10-08/PLAN.md).

Covers: the control status query reads the tenant's real ``compliance_controls``
rows through their FedRAMP framework (it used to query a non-existent
``ComplianceControl.framework`` column, swallow the error and report every
control as "planned"), "Update Status" persists to the tenant's row and is
admin-only, readiness says what was not assessed, the POA&M report reads real
columns and its severity filter works, and an org-less superuser is refused.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import POAM, ComplianceControl, ComplianceEvidence, ComplianceFramework
from tests.helpers.tenancy import bearer, make_user

BASE = "/api/v1/fedramp"


async def _seed_fedramp(
    db: AsyncSession, org_id: str, statuses: dict[str, str], short_name: str = "fedramp_moderate",
) -> dict[str, str]:
    framework = ComplianceFramework(
        id=str(uuid.uuid4()),
        name=f"FedRAMP {uuid.uuid4().hex[:6]}",
        short_name=short_name,
        version="Rev 5",
        authority="tests",
        organization_id=org_id,
    )
    db.add(framework)
    await db.flush()
    ids: dict[str, str] = {}
    for code, control_status in statuses.items():
        control = ComplianceControl(
            id=str(uuid.uuid4()),
            framework_id=framework.id,
            control_id=code,
            control_family="Access Control",
            title=code,
            status=control_status,
            organization_id=org_id,
        )
        db.add(control)
        ids[code] = control.id
    await db.commit()
    return ids


def _by_id(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in payload["controls"]}


def _error_key(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


async def test_controls_read_the_tenants_rows(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    await _seed_fedramp(db_session, org_a.id, {"AC-2": "implemented", "AC-3": "partially_implemented"})

    own = await client.get(f"{BASE}/controls", params={"family": "AC", "limit": 500}, headers=org_a_headers)
    assert own.status_code == 200, own.text
    controls = _by_id(own.json())
    assert controls["AC-2"]["implementation_status"] == "implemented"
    assert controls["AC-3"]["implementation_status"] == "partially_implemented"
    # A baseline control with no row is not assessed, not "planned".
    assert controls["AC-1"]["implementation_status"] == "not_assessed"

    other = await client.get(f"{BASE}/controls", params={"family": "AC", "limit": 500}, headers=org_b_headers)
    assert other.status_code == 200
    assert {c["implementation_status"] for c in other.json()["controls"]} == {"not_assessed"}


async def test_readiness_is_computed_and_says_what_was_not_assessed(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    await _seed_fedramp(db_session, org_a.id, {"AC-2": "implemented", "AU-2": "planned"})

    own = await client.get(f"{BASE}/readiness", headers=org_a_headers)
    assert own.status_code == 200, own.text
    report = own.json()
    assert report["overall_readiness_score"] > 0
    assert report["assessment_status"] == "partially_assessed"
    assert report["not_assessed_controls"] == report["total_controls"] - 2
    assert report["status_breakdown"]["implemented"] == 1
    assert "AU-2" in {g["control_id"] for g in report["gap_analysis"]["gaps"]}
    # Wave 4: recommendations are derived from this tenant's gaps (they were a
    # fixed checklist); AU-2 is a P1 gap here.
    assert report["recommendations_basis"] == "computed_from_gaps"
    assert any("AU-2" in rec["action"] for rec in report["recommendations"])

    other = await client.get(f"{BASE}/readiness", headers=org_b_headers)
    assert other.status_code == 200
    assert other.json()["overall_readiness_score"] == 0
    assert other.json()["assessment_status"] == "not_assessed"


async def test_update_status_persists_to_the_tenants_row(
    client: AsyncClient, db_session: AsyncSession, org_a, org_b, org_a_admin_headers: dict[str, str],
) -> None:
    a_ids = await _seed_fedramp(db_session, org_a.id, {"AC-2": "not_implemented"})
    b_ids = await _seed_fedramp(db_session, org_b.id, {"AC-2": "not_implemented"})
    resp = await client.post(
        f"{BASE}/controls/AC-2/update",
        params={"implementation_status": "implemented", "implementation_narrative": "MFA enforced via SSO"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["persisted_to_database"] is True

    db_session.expire_all()
    a_row = await db_session.get(ComplianceControl, a_ids["AC-2"])
    b_row = await db_session.get(ComplianceControl, b_ids["AC-2"])
    assert a_row.status == "implemented"
    assert a_row.implementation_details == "MFA enforced via SSO"
    assert b_row.status == "not_implemented"


async def test_update_status_other_tenant_and_untracked(
    client: AsyncClient, db_session: AsyncSession, org_a, org_b,
) -> None:
    a_ids = await _seed_fedramp(db_session, org_a.id, {"AC-2": "not_implemented"})
    admin_b = await make_user(db_session, role="admin", organization_id=org_b.id, label="admin-b")
    resp = await client.post(
        f"{BASE}/controls/AC-2/update", params={"implementation_status": "implemented"}, headers=bearer(admin_b),
    )
    assert resp.status_code == 404, resp.text
    assert _error_key(resp) == "control_not_tracked"
    db_session.expire_all()
    assert (await db_session.get(ComplianceControl, a_ids["AC-2"])).status == "not_implemented"


async def test_update_status_input_errors(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers: dict[str, str],
) -> None:
    await _seed_fedramp(db_session, org_a.id, {"AC-2": "not_implemented"})
    bad = await client.post(
        f"{BASE}/controls/AC-2/update", params={"implementation_status": "done"}, headers=org_a_admin_headers,
    )
    assert bad.status_code == 422
    assert bad.json()["detail"]["field"] == "implementation_status"

    notes = await client.post(
        f"{BASE}/controls/AC-2/update",
        params={"implementation_status": "implemented", "assessor_notes": "looks fine"},
        headers=org_a_admin_headers,
    )
    assert notes.status_code == 501
    assert _error_key(notes) == "not_implemented"


async def test_update_status_is_admin_only(
    client: AsyncClient, viewer_headers: dict[str, str], org_a_headers: dict[str, str],
) -> None:
    for headers in (viewer_headers, org_a_headers):
        resp = await client.post(
            f"{BASE}/controls/AC-2/update", params={"implementation_status": "implemented"}, headers=headers,
        )
        assert resp.status_code == 403, resp.text


async def test_poam_report_reads_real_columns_and_filters_by_severity(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    ids = await _seed_fedramp(db_session, org_a.id, {"SC-7": "planned"})
    db_session.add_all([
        POAM(
            control_id_ref=ids["SC-7"], weakness_name="boundary", weakness_source="scan", risk_level="high",
            scheduled_completion_date=datetime.now(timezone.utc) + timedelta(days=30),
            assigned_to="netops", organization_id=org_a.id,
        ),
        POAM(
            control_id_ref=ids["SC-7"], weakness_name="minor", weakness_source="scan", risk_level="low",
            scheduled_completion_date=datetime.now(timezone.utc) - timedelta(days=3),
            organization_id=org_a.id,
        ),
    ])
    await db_session.commit()

    resp = await client.get(f"{BASE}/poam/report", params={"severity": "high"}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["control_id"] == "SC-7"
    assert items[0]["severity"] == "high"
    assert items[0]["responsible_party"] == "netops"

    full = await client.get(f"{BASE}/poam/report", headers=org_a_headers)
    assert full.json()["summary"]["total_items"] == 2
    assert full.json()["summary"]["overdue_items"] == 1

    other = await client.get(f"{BASE}/poam/report", headers=org_b_headers)
    assert other.status_code == 200
    assert other.json()["summary"]["total_items"] == 0


async def test_evidence_status_counts_the_tenants_evidence(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    ids = await _seed_fedramp(db_session, org_a.id, {"AC-2": "implemented"})
    db_session.add(ComplianceEvidence(
        control_id_ref=ids["AC-2"], evidence_type="document", title="access review",
        collected_by="tests", organization_id=org_a.id,
    ))
    await db_session.commit()

    own = await client.get(f"{BASE}/evidence/status", headers=org_a_headers)
    assert own.status_code == 200, own.text
    assert own.json()["controls_with_evidence"] == 1
    other = await client.get(f"{BASE}/evidence/status", headers=org_b_headers)
    assert other.json()["controls_with_evidence"] == 0


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    resp = await client.get(f"{BASE}/readiness", headers=superuser_headers)
    assert resp.status_code == 403
    assert _error_key(resp) == "organization_required"

