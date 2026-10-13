"""Wave 1 tenancy / RBAC conversion of the risk-quantification router.

docs/audit/2026-10-08/posture-risk.md: the ``get_*_or_404`` helpers only
filtered on the organisation when it was not None (an org-less caller read
every tenant), ``create_risk_control`` linked a control to any tenant's risk
register, and ``POST /analyze`` invented PERT inputs from the asset value and
saved them as an ordinary FAIR analysis (and returned a 500 when a scenario
had two analyses). Every route now takes the mandatory ``OrganizationId``,
lookups 404 outside the tenant, writes need analyst or admin, and ``/analyze``
only simulates analyst-authored inputs and reports the scenarios it skipped.
"""

from __future__ import annotations

from typing import Any

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import src.api.v1.endpoints.risk_quant as rq_router
from src.models.organization import Organization
from src.risk_quant.models import FAIRAnalysis, RiskControl, RiskRegister, RiskScenario
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/risk-quantification"

SCENARIO_BODY: dict[str, Any] = {
    "name": "Ransomware on billing",
    "asset_name": "billing-db",
    "asset_value_usd": 50000.0,
    "threat_type": "ransomware",
    "vulnerability_exploited": "unpatched VPN",
}
REGISTER_BODY: dict[str, Any] = {
    "name": "Billing outage",
    "risk_category": "operational",
    "inherent_risk_score": 60.0,
    "residual_risk_score": 40.0,
    "risk_treatment": "mitigate",
    "ale_annual_usd": 100000.0,
    "risk_appetite_threshold_usd": 50000.0,
}
BIA_BODY: dict[str, Any] = {
    "asset_name": "billing-db",
    "business_unit": "finance",
    "rto_hours": 4.0,
    "rpo_hours": 1.0,
    "mtpd_hours": 24.0,
    "financial_impact_per_hour_usd": 1000.0,
    "reputational_impact_score": 50.0,
    "regulatory_impact_score": 40.0,
}


def _fair_body(scenario_id: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "tef_min": 0.5, "tef_mode": 1.0, "tef_max": 2.0,
        "vuln_min": 0.1, "vuln_mode": 0.3, "vuln_max": 0.5,
        "tcap_min": 0.3, "tcap_mode": 0.5, "tcap_max": 0.8,
        "rs_min": 0.3, "rs_mode": 0.5, "rs_max": 0.8,
        "lm_min": 1000.0, "lm_mode": 5000.0, "lm_max": 20000.0,
        "primary_loss_min": 1000.0, "primary_loss_mode": 5000.0, "primary_loss_max": 20000.0,
        "secondary_loss_min": 100.0, "secondary_loss_mode": 500.0, "secondary_loss_max": 2000.0,
        "secondary_loss_event_frequency": 0.2,
        "simulation_iterations": 1000,
    }


class _QueuedTask:
    """Stand-in for the Celery task: records ``.delay`` calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def delay(self, *args: Any) -> None:
        self.calls.append(args)


@pytest.fixture
def queued(monkeypatch: pytest.MonkeyPatch) -> _QueuedTask:
    task = _QueuedTask()
    monkeypatch.setattr(rq_router, "run_fair_simulation", task)
    return task


async def _scenario(db: AsyncSession, org_id: str, name: str = "scn") -> str:
    row = RiskScenario(
        organization_id=org_id, name=name, asset_name="asset", asset_value_usd=10000.0,
        threat_type="ransomware", vulnerability_exploited="vpn", status="draft",
        analyst_id=str(uuid.uuid4()),
    )
    db.add(row)
    await db.commit()
    return row.id


async def _register(db: AsyncSession, org_id: str) -> str:
    row = RiskRegister(
        organization_id=org_id, name="reg", risk_category="operational",
        inherent_risk_score=50.0, residual_risk_score=30.0, risk_treatment="mitigate",
        ale_annual_usd=1000.0, risk_appetite_threshold_usd=5000.0,
        owner_id=str(uuid.uuid4()),
    )
    db.add(row)
    await db.commit()
    return row.id


# ---------------------------------------------------------------------------
# isolation + stamping
# ---------------------------------------------------------------------------


async def test_scenario_is_stamped_listed_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(f"{API}/scenarios", json=SCENARIO_BODY, headers=org_a_headers)
    assert resp.status_code == 201, resp.text
    scenario_id = resp.json()["id"]

    row = (await db_session.execute(select(RiskScenario).where(RiskScenario.id == scenario_id))).scalar_one()
    assert row.organization_id == org_a_id

    own = await client.get(f"{API}/scenarios", headers=org_a_headers)
    assert scenario_id in {s["id"] for s in own.json()["items"]}
    other = await client.get(f"{API}/scenarios", headers=org_b_headers)
    assert other.status_code == 200, other.text
    assert scenario_id not in {s["id"] for s in other.json()["items"]}

    await assert_tenant_isolated(client, "GET", f"{API}/scenarios/{scenario_id}", org_b_headers)
    await assert_tenant_isolated(
        client, "PATCH", f"{API}/scenarios/{scenario_id}", org_b_headers, json={"name": "pwn"},
    )
    await assert_tenant_isolated(client, "DELETE", f"{API}/scenarios/{scenario_id}", org_b_headers)


async def test_registers_controls_bias_and_analyses_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
    queued: _QueuedTask,
) -> None:
    org_a_id = org_a.id
    scenario_id = await _scenario(db_session, org_a_id)

    register = await client.post(f"{API}/risk-registers", json=REGISTER_BODY, headers=org_a_headers)
    assert register.status_code == 201, register.text
    register_id = register.json()["id"]
    control = await client.post(
        f"{API}/controls",
        json={"control_name": "EDR", "cost_annual_usd": 1000.0, "risk_register_id": register_id},
        headers=org_a_headers,
    )
    assert control.status_code == 201, control.text
    control_id = control.json()["id"]
    bia = await client.post(f"{API}/bias", json=BIA_BODY, headers=org_a_headers)
    assert bia.status_code == 201, bia.text
    bia_id = bia.json()["id"]
    analysis = await client.post(f"{API}/fair-analyses", json=_fair_body(scenario_id), headers=org_a_headers)
    assert analysis.status_code == 201, analysis.text
    analysis_id = analysis.json()["id"]
    assert queued.calls == [(analysis_id, org_a_id)]

    for path in (
        f"risk-registers/{register_id}", f"controls/{control_id}", f"bias/{bia_id}",
        f"fair-analyses/{analysis_id}",
    ):
        await assert_tenant_isolated(client, "GET", f"{API}/{path}", org_b_headers)
    for path in (f"risk-registers/{register_id}", f"controls/{control_id}", f"bias/{bia_id}"):
        await assert_tenant_isolated(client, "PATCH", f"{API}/{path}", org_b_headers, json={})
        await assert_tenant_isolated(client, "DELETE", f"{API}/{path}", org_b_headers)
    await assert_tenant_isolated(
        client, "POST", f"{API}/fair-analyses/{analysis_id}/run-simulation", org_b_headers,
    )
    await assert_tenant_isolated(
        client, "GET", f"{API}/fair-analyses/{analysis_id}/loss-exceedance-curve", org_b_headers,
    )
    await assert_tenant_isolated(client, "POST", f"{API}/controls/{control_id}/audit", org_b_headers)

    for listing, key in (
        ("risk-registers", register_id), ("controls", control_id), ("bias", bia_id),
        ("fair-analyses", analysis_id),
    ):
        resp = await client.get(f"{API}/{listing}", headers=org_b_headers)
        assert resp.status_code == 200, resp.text
        assert key not in {i["id"] for i in resp.json()["items"]}

    dashboard = await client.get(f"{API}/dashboard", headers=org_b_headers)
    assert dashboard.json()["number_of_risks"] == 0


async def test_fair_analysis_rejects_another_tenants_scenario(
    client: AsyncClient,
    db_session: AsyncSession,
    org_b: Organization,
    org_a_headers: dict[str, str],
    queued: _QueuedTask,
) -> None:
    foreign = await _scenario(db_session, org_b.id)
    resp = await client.post(f"{API}/fair-analyses", json=_fair_body(foreign), headers=org_a_headers)
    assert resp.status_code == 404, resp.text
    assert queued.calls == []


async def test_control_cannot_link_another_tenants_register(
    client: AsyncClient,
    db_session: AsyncSession,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    foreign_register = await _register(db_session, org_b.id)
    resp = await client.post(
        f"{API}/controls",
        json={"control_name": "x", "cost_annual_usd": 1.0, "risk_register_id": foreign_register},
        headers=org_a_headers,
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["field"] == "risk_register_id"
    rows = (await db_session.execute(
        select(RiskControl).where(RiskControl.risk_register_id == foreign_register),
    )).scalars().all()
    assert rows == []


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------


WRITE_ROUTES = [
    ("POST", "scenarios", SCENARIO_BODY),
    ("PATCH", "scenarios/x", {}),
    ("DELETE", "scenarios/x", None),
    ("POST", "fair-analyses", _fair_body("x")),
    ("POST", "fair-analyses/x/run-simulation", None),
    ("POST", "risk-registers", REGISTER_BODY),
    ("PATCH", "risk-registers/x", {}),
    ("DELETE", "risk-registers/x", None),
    ("POST", "controls", {"control_name": "x", "cost_annual_usd": 1.0}),
    ("PATCH", "controls/x", {}),
    ("DELETE", "controls/x", None),
    ("POST", "controls/x/audit", None),
    ("POST", "bias", BIA_BODY),
    ("PATCH", "bias/x", {}),
    ("DELETE", "bias/x", None),
    ("POST", "analyze", {"scenario_ids": []}),
]


@pytest.mark.parametrize(("method", "path", "body"), WRITE_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient,
    viewer_headers: dict[str, str],
    method: str,
    path: str,
    body: Any,
) -> None:
    resp = await client.request(method, f"{API}/{path}", json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


async def test_viewer_can_read(client: AsyncClient, viewer_headers: dict[str, str]) -> None:
    for path in ("scenarios", "fair-analyses", "risk-registers", "controls", "bias", "dashboard",
                 "heatmap", "loss-exceedance"):
        resp = await client.get(f"{API}/{path}", headers=viewer_headers)
        assert resp.status_code == 200, (path, resp.text)


async def test_orgless_superuser_is_refused(
    client: AsyncClient, superuser_headers: dict[str, str],
) -> None:
    resp = await client.get(f"{API}/scenarios", headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"


# ---------------------------------------------------------------------------
# /analyze honesty
# ---------------------------------------------------------------------------


async def test_analyze_does_not_invent_fair_inputs(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    own = await _scenario(db_session, org_a_id)
    foreign = await _scenario(db_session, org_b.id)

    resp = await client.post(f"{API}/analyze", json={"scenario_ids": [own, foreign]}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "nothing_analyzed"
    assert body["scenarios_analyzed"] == 0
    assert body["skipped"] == [
        {"scenario_id": own, "reason": "no_fair_inputs"},
        {"scenario_id": foreign, "reason": "scenario_not_found"},
    ]
    rows = (await db_session.execute(
        select(FAIRAnalysis).where(FAIRAnalysis.scenario_id.in_([own, foreign])),
    )).scalars().all()
    assert rows == [], "no default FAIRAnalysis may be fabricated"


async def test_analyze_uses_latest_authored_analysis_when_several_exist(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    queued: _QueuedTask,
) -> None:
    scenario_id = await _scenario(db_session, org_a.id)
    for _ in range(2):
        created = await client.post(f"{API}/fair-analyses", json=_fair_body(scenario_id), headers=org_a_headers)
        assert created.status_code == 201, created.text

    resp = await client.post(
        f"{API}/analyze", json={"scenario_ids": [scenario_id], "iterations": 500}, headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "completed"
    assert body["scenarios_analyzed"] == 1
    assert body["skipped"] == []
    assert body["per_scenario"][0]["scenario_id"] == scenario_id
    assert len(queued.calls) == 2


@pytest.mark.parametrize(
    ("payload", "field"),
    [({"scenario_ids": "abc"}, "scenario_ids"), ({"iterations": "many"}, "iterations"),
     ({"iterations": 0}, "iterations")],
)
async def test_analyze_rejects_malformed_input(
    client: AsyncClient, org_a_headers: dict[str, str], payload: dict[str, Any], field: str,
) -> None:
    resp = await client.post(f"{API}/analyze", json=payload, headers=org_a_headers)
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["field"] == field
