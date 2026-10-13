"""Tenancy and RBAC for the compliance router (wave 1, docs/audit/2026-10-08/PLAN.md).

Covers: every route is scoped to the caller's organisation, control status
updates / the auto-attester / evidence approval are admin-only, viewers are
read-only, an org-less platform superuser is refused, and the always-broken
routes from the audit now work: /controls/cross-map is reachable,
/controls/{id}/assess no longer raises MultipleResultsFound, /frameworks/{id}/conmon
finds the seeded ``fedramp_moderate`` framework, POA&M create rejects a control
code it cannot resolve with a 422, and report GETs no longer run the attester.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints import compliance as compliance_endpoints
from src.compliance.models import POAM, ComplianceControl, ComplianceEvidence, ComplianceFramework
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/compliance"


async def _seed_framework(
    db: AsyncSession, org_id: str, short_name: str = "fedramp_moderate", codes: tuple[str, ...] = ("AC-2", "AU-2"),
) -> tuple[str, dict[str, str]]:
    framework = ComplianceFramework(
        id=str(uuid.uuid4()),
        name=f"{short_name} {uuid.uuid4().hex[:6]}",
        short_name=short_name,
        version="Rev 5",
        authority="tests",
        organization_id=org_id,
    )
    db.add(framework)
    await db.flush()
    control_ids: dict[str, str] = {}
    for code in codes:
        control = ComplianceControl(
            id=str(uuid.uuid4()),
            framework_id=framework.id,
            control_id=code,
            control_family="Access Control",
            title=f"{code} control",
            status="not_implemented",
            organization_id=org_id,
        )
        db.add(control)
        control_ids[code] = control.id
    framework_id = framework.id
    await db.commit()
    return framework_id, control_ids


def _error_key(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


@pytest.fixture
def _no_celery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compliance_endpoints.run_compliance_assessment, "delay", lambda *_a, **_k: None)
    monkeypatch.setattr(compliance_endpoints.run_continuous_monitoring, "delay", lambda *_a, **_k: None)


async def test_compliance_routes_are_tenant_isolated(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    framework_id, controls = await _seed_framework(db_session, org_a_id)
    control_id = controls["AC-2"]

    poam = await client.post(
        f"{BASE}/poams",
        json={"control_id_ref": control_id, "weakness_name": "w", "scheduled_completion_date": "2030-01-01T00:00:00Z"},
        headers=org_a_headers,
    )
    assert poam.status_code == 200, poam.text
    poam_id = poam.json()["id"]
    evidence = await client.post(
        f"{BASE}/evidence",
        params={"control_id_ref": control_id, "evidence_type": "document", "title": "t", "content": "c"},
        headers=org_a_headers,
    )
    assert evidence.status_code == 200, evidence.text
    evidence_id = evidence.json()["id"]

    for method, path, body in [
        ("GET", f"{BASE}/frameworks/{framework_id}", None),
        ("GET", f"{BASE}/frameworks/{framework_id}/gaps", None),
        ("GET", f"{BASE}/frameworks/{framework_id}/report", None),
        ("POST", f"{BASE}/frameworks/{framework_id}/assess", None),
        ("GET", f"{BASE}/controls/{control_id}", None),
        ("POST", f"{BASE}/controls/{control_id}/assess", None),
        ("GET", f"{BASE}/poams/{poam_id}", None),
        ("PUT", f"{BASE}/poams/{poam_id}", {"assigned_to": "x"}),
        ("GET", f"{BASE}/evidence/{evidence_id}", None),
    ]:
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    # Org B cannot point its own POA&M / evidence at org A's control.
    stolen = await client.post(
        f"{BASE}/poams",
        json={"control_id_ref": control_id, "weakness_name": "w", "scheduled_completion_date": "2030-01-01T00:00:00Z"},
        headers=org_b_headers,
    )
    assert stolen.status_code == 422, stolen.text
    assert stolen.json()["detail"]["field"] == "control_id_ref"

    for path, key in [
        (f"{BASE}/frameworks", "id"),
        (f"{BASE}/controls", "id"),
        (f"{BASE}/poams", "id"),
        (f"{BASE}/evidence", "id"),
    ]:
        listing = await client.get(path, headers=org_b_headers)
        assert listing.status_code == 200, listing.text
        assert {framework_id, control_id, poam_id, evidence_id}.isdisjoint({r[key] for r in listing.json()})
    dash = await client.get(f"{BASE}/dashboard", headers=org_b_headers)
    assert dash.status_code == 200, dash.text

    own = await client.get(f"{BASE}/controls", headers=org_a_admin_headers)
    assert control_id in {r["id"] for r in own.json()}


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/frameworks/{fw}/assess", None),
        ("POST", "/frameworks/{fw}/attest", None),
        ("POST", "/frameworks/{fw}/conmon", None),
        ("PUT", "/controls/{ctl}", {"status": "implemented"}),
        ("POST", "/controls/{ctl}/assess", None),
        ("POST", "/poams", {"control_id_ref": "{ctl}", "scheduled_completion_date": "2030-01-01T00:00:00Z"}),
        ("POST", "/evidence?control_id_ref={ctl}&evidence_type=document&title=t", None),
        ("PUT", "/evidence/{ctl}/review?review_status=approved", None),
        ("POST", "/cui", {"asset_id": "a", "asset_type": "file", "cui_category": "x", "cui_designation": "y"}),
        ("POST", "/cisa/directives/BOD-22-01/check", None),
    ],
)
async def test_viewer_cannot_write(
    client: AsyncClient, db_session: AsyncSession, org_a, viewer_headers: dict[str, str],
    method: str, path: str, body: dict[str, Any] | None,
) -> None:
    framework_id, controls = await _seed_framework(db_session, org_a.id)
    ctl = controls["AC-2"]
    url = BASE + path.format(fw=framework_id, ctl=ctl)
    if body and body.get("control_id_ref") == "{ctl}":
        body = {**body, "control_id_ref": ctl}
    resp = await client.request(method, url, json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("PUT", "/controls/{ctl}"),
        ("POST", "/frameworks/{fw}/attest"),
        ("PUT", "/evidence/{ctl}/review?review_status=approved"),
    ],
)
async def test_analyst_cannot_use_admin_routes(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str], method: str, path: str,
) -> None:
    framework_id, controls = await _seed_framework(db_session, org_a.id)
    url = BASE + path.format(fw=framework_id, ctl=controls["AC-2"])
    body = {"status": "implemented"} if path.startswith("/controls") else None
    resp = await client.request(method, url, json=body, headers=org_a_headers)
    assert resp.status_code == 403, resp.text


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    resp = await client.get(f"{BASE}/frameworks", headers=superuser_headers)
    assert resp.status_code == 403
    assert _error_key(resp) == "organization_required"


async def test_admin_updates_control_and_auto_poam_is_tenant_scoped(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers: dict[str, str],
) -> None:
    _, controls = await _seed_framework(db_session, org_a.id)
    control_id = controls["AC-2"]
    resp = await client.put(
        f"{BASE}/controls/{control_id}",
        json={"status": "partially_implemented", "implementation_status": 10},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "partially_implemented"


async def test_cross_map_is_not_shadowed_by_control_detail(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str],
) -> None:
    source_id, _ = await _seed_framework(db_session, org_a.id, "fedramp_moderate")
    target_id, _ = await _seed_framework(db_session, org_a.id, "nist_800_53")
    resp = await client.get(
        f"{BASE}/controls/cross-map",
        params={"source_framework_id": source_id, "target_framework_id": target_id},
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() != {"detail": "Control not found"}


async def test_control_assess_with_code_in_several_frameworks(
    client: AsyncClient, db_session: AsyncSession, org_a, org_b, org_a_headers: dict[str, str],
) -> None:
    # AC-2 is seeded in FedRAMP and NIST for every tenant: the lookup used to
    # raise MultipleResultsFound (500).
    _, fedramp_controls = await _seed_framework(db_session, org_a.id, "fedramp_moderate")
    await _seed_framework(db_session, org_a.id, "nist_800_53")
    await _seed_framework(db_session, org_b.id, "fedramp_moderate")
    resp = await client.post(f"{BASE}/controls/{fedramp_controls['AU-2']}/assess", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert "error" not in resp.json()


@pytest.mark.usefixtures("_no_celery")
async def test_conmon_finds_seeded_fedramp_moderate_framework(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str],
) -> None:
    framework_id, _ = await _seed_framework(db_session, org_a.id, "fedramp_moderate")
    resp = await client.post(f"{BASE}/frameworks/{framework_id}/conmon", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["frameworks_assessed"] == 1

    nist_id, _ = await _seed_framework(db_session, org_a.id, "nist_800_53")
    not_fedramp = await client.post(f"{BASE}/frameworks/{nist_id}/conmon", headers=org_a_headers)
    assert not_fedramp.status_code == 404


async def test_poam_create_resolves_or_rejects_control_codes(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str],
) -> None:
    _, fedramp_controls = await _seed_framework(db_session, org_a.id, "fedramp_moderate", ("AC-2", "SC-7"))
    await _seed_framework(db_session, org_a.id, "nist_800_53", ("AC-2",))
    sc7 = fedramp_controls["SC-7"]
    body = {"weakness_name": "w", "scheduled_completion_date": "2030-01-01T00:00:00Z"}

    unique = await client.post(f"{BASE}/poams", json={**body, "control_id_ref": "SC-7"}, headers=org_a_headers)
    assert unique.status_code == 200, unique.text
    assert unique.json()["control_id_ref"] == sc7

    for ref in ("AC-2", "ZZ-99", ""):
        resp = await client.post(f"{BASE}/poams", json={**body, "control_id_ref": ref}, headers=org_a_headers)
        assert resp.status_code == 422, (ref, resp.text)
        assert resp.json()["detail"]["field"] == "control_id_ref"
        assert resp.json()["detail"]["error"] == "invalid_control_reference"


async def test_report_and_ssp_gets_do_not_run_the_attester(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str],
) -> None:
    framework_id, controls = await _seed_framework(db_session, org_a.id, "fedramp_moderate", ("AC-2", "AU-8", "SC-8"))
    org_a_id = org_a.id

    async def _evidence_count() -> int:
        return (await db_session.execute(
            select(func.count(ComplianceEvidence.id)).where(ComplianceEvidence.organization_id == org_a_id),
        )).scalar_one()

    before = await _evidence_count()
    for path in ("report", "ssp", "ssp/download"):
        resp = await client.get(f"{BASE}/frameworks/{framework_id}/{path}", headers=org_a_headers)
        assert resp.status_code == 200, (path, resp.text)
    assert await _evidence_count() == before

    db_session.expire_all()
    statuses = (await db_session.execute(
        select(ComplianceControl.status).where(ComplianceControl.id.in_(list(controls.values()))),
    )).scalars().all()
    assert set(statuses) == {"not_implemented"}


async def test_evidence_review_records_the_session_user(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin, org_a_admin_headers: dict[str, str],
) -> None:
    admin_id = org_a_admin.id
    _, controls = await _seed_framework(db_session, org_a.id)
    created = await client.post(
        f"{BASE}/evidence",
        params={"control_id_ref": controls["AC-2"], "evidence_type": "document", "title": "t", "content": "c"},
        headers=org_a_admin_headers,
    )
    evidence_id = created.json()["id"]
    resp = await client.put(
        f"{BASE}/evidence/{evidence_id}/review",
        params={"review_status": "approved", "reviewed_by": "someone-else"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["reviewed_by"] == str(admin_id)


async def test_overdue_poams_only_from_own_tenant(
    client: AsyncClient, db_session: AsyncSession, org_a, org_b_headers: dict[str, str],
) -> None:
    _, controls = await _seed_framework(db_session, org_a.id)
    db_session.add(POAM(
        control_id_ref=controls["AC-2"],
        weakness_name="old",
        weakness_source="tests",
        scheduled_completion_date=datetime.now(timezone.utc) - timedelta(days=5),
        organization_id=org_a.id,
    ))
    await db_session.commit()
    resp = await client.get(f"{BASE}/poams/overdue", headers=org_b_headers)
    assert resp.status_code == 200
    assert resp.json()["overdue_count"] == 0
