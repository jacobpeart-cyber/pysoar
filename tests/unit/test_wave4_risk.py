"""Wave 4 (W4-C): risk quantification computed from stored inputs only.

docs/audit/2026-10-08/posture-risk.md (RiskQuantification): the PERT sampler
used p + q = 1 (a U-shaped Beta), the Celery task replaced falsy inputs with
invented estimates, portfolio figures summed per-scenario percentiles over
every analysis row, and a scenario's asset value opened an incident claiming
it as loss expectancy.
"""

from __future__ import annotations

import uuid
from typing import Any

import numpy as np
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.incident import Incident
from src.models.organization import Organization
from src.risk_quant.engine import FAIREngine, FAIRInputError, simulate_analysis, validate_fair_inputs
from src.risk_quant.models import FAIRAnalysis, RiskControl, RiskRegister, RiskScenario

API = "/api/v1/risk-quantification"


def _inputs(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "tef_min": 0.5, "tef_mode": 2.0, "tef_max": 6.0,
        "vuln_min": 0.1, "vuln_mode": 0.3, "vuln_max": 0.6,
        "tcap_min": 0.3, "tcap_mode": 0.5, "tcap_max": 0.8,
        "rs_min": 0.3, "rs_mode": 0.5, "rs_max": 0.8,
        "lm_min": 1000.0, "lm_mode": 5000.0, "lm_max": 20000.0,
        "primary_loss_min": 1000.0, "primary_loss_mode": 5000.0, "primary_loss_max": 20000.0,
        "secondary_loss_min": 100.0, "secondary_loss_mode": 500.0, "secondary_loss_max": 2000.0,
        "secondary_loss_event_frequency": 0.2,
        "simulation_iterations": 2000,
    }
    body.update(overrides)
    return body


async def _scenario(db: AsyncSession, org_id: str, name: str = "scn") -> str:
    row = RiskScenario(
        organization_id=org_id, name=name, asset_name="asset", asset_value_usd=10000.0,
        threat_type="ransomware", vulnerability_exploited="vpn", status="draft",
        analyst_id=str(uuid.uuid4()),
    )
    db.add(row)
    await db.commit()
    return row.id


@pytest.fixture(autouse=True)
def _no_celery(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.api.v1.endpoints import risk_quant as rq_router

    class _Task:
        def delay(self, *args: Any) -> None:
            return None

    monkeypatch.setattr(rq_router, "run_fair_simulation", _Task())


# ---------------------------------------------------------------------------
# sampler
# ---------------------------------------------------------------------------


def test_pert_sampler_is_unimodal_with_the_pert_mean() -> None:
    engine = FAIREngine(seed=7)
    samples = engine.sample_pert_distribution(0.0, 2.0, 10.0, size=200_000)
    assert samples.min() >= 0.0 and samples.max() <= 10.0
    assert abs(samples.mean() - (0 + 4 * 2 + 10) / 6) < 0.02
    # Standard PERT: alpha = 1 + 4*2/10 = 1.8, beta = 1 + 4*8/10 = 4.2, so the
    # density peaks near the mode and vanishes at the edges. The old p+q=1
    # Beta(0.3, 0.7) piled mass at both ends instead.
    near_mode = np.mean(np.abs(samples - 2.0) < 0.5)
    near_max = np.mean(samples > 9.5)
    near_min = np.mean(samples < 0.5)
    assert near_mode > 10 * near_max
    assert near_mode > near_min
    hist, edges = np.histogram(samples, bins=20, range=(0, 10))
    assert edges[int(np.argmax(hist))] <= 2.0 < edges[int(np.argmax(hist)) + 1] + 0.5


def test_pert_rejects_unordered_triple_and_handles_degenerate() -> None:
    engine = FAIREngine(seed=1)
    with pytest.raises(ValueError):
        engine.sample_pert_distribution(5.0, 1.0, 10.0, size=10)
    assert np.all(engine.sample_pert_distribution(3.0, 3.0, 3.0, size=5) == 3.0)


def test_simulation_mean_matches_the_documented_model_and_is_reproducible() -> None:
    inputs = _inputs()
    first = FAIREngine(seed=42).run_simulation(inputs, 40_000)
    again = FAIREngine(seed=42).run_simulation(inputs, 40_000)
    assert first.ale_mean == again.ale_mean
    pert_mean = lambda lo, mo, hi: (lo + 4 * mo + hi) / 6  # noqa: E731
    expected = (
        pert_mean(0.5, 2.0, 6.0) * pert_mean(0.1, 0.3, 0.6)
        * (pert_mean(1000, 5000, 20000) + 0.2 * pert_mean(100, 500, 2000))
    )
    assert abs(first.ale_mean - expected) / expected < 0.05
    assert first.ale_p10 <= first.ale_p50 <= first.ale_p90 <= first.ale_p99
    assert first.model["reported_not_sampled"] == ["tcap", "rs", "lm"]
    assert 0.0 <= first.derived_vulnerability <= 1.0
    curve = first.loss_exceedance_curve
    assert curve["y_values"] == sorted(curve["y_values"], reverse=True)


def test_validation_names_the_missing_or_inconsistent_input() -> None:
    with pytest.raises(FAIRInputError) as missing:
        validate_fair_inputs({k: v for k, v in _inputs().items() if k != "rs_max"})
    assert missing.value.field == "rs_max"
    with pytest.raises(FAIRInputError) as unordered:
        validate_fair_inputs(_inputs(tef_min=9.0))
    assert unordered.value.field == "tef_mode"
    with pytest.raises(FAIRInputError) as prob:
        validate_fair_inputs(_inputs(vuln_max=1.5))
    assert prob.value.field == "vuln_max"


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------


async def test_create_requires_every_input_and_names_the_missing_one(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    scenario_id = await _scenario(db_session, org_a.id)
    body = _inputs(scenario_id=scenario_id)
    del body["secondary_loss_mode"]
    resp = await client.post(f"{API}/fair-analyses", json=body, headers=org_a_headers)
    assert resp.status_code == 422, resp.text
    assert any(err["loc"][-1] == "secondary_loss_mode" for err in resp.json()["details"]["errors"])

    unordered = await client.post(
        f"{API}/fair-analyses", json=_inputs(scenario_id=scenario_id, primary_loss_mode=50000.0),
        headers=org_a_headers,
    )
    assert unordered.status_code == 422, unordered.text
    assert "primary_loss_mode" in unordered.text

    no_scenario = await client.post(f"{API}/fair-analyses", json=_inputs(), headers=org_a_headers)
    assert no_scenario.status_code == 422, no_scenario.text
    rows = (await db_session.execute(select(FAIRAnalysis).where(FAIRAnalysis.scenario_id == scenario_id))).all()
    assert rows == []


async def test_run_simulation_uses_stored_inputs_and_is_reproducible(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    scenario_id = await _scenario(db_session, org_a.id)
    created = await client.post(f"{API}/fair-analyses", json=_inputs(scenario_id=scenario_id), headers=org_a_headers)
    assert created.status_code == 201, created.text
    analysis_id = created.json()["id"]

    first = await client.post(f"{API}/fair-analyses/{analysis_id}/run-simulation", headers=org_a_headers)
    second = await client.post(f"{API}/fair-analyses/{analysis_id}/run-simulation", headers=org_a_headers)
    assert first.status_code == 200, first.text
    assert first.json()["ale_mean"] == second.json()["ale_mean"]
    assert first.json()["iterations"] == 2000
    assert first.json()["model"]["vulnerability_source"] == "vuln_min/vuln_mode/vuln_max"
    row = await client.get(f"{API}/fair-analyses/{analysis_id}", headers=org_a_headers)
    assert row.json()["ale_mean"] == pytest.approx(first.json()["ale_mean"])
    assert row.json()["ale_p10"] is not None


async def test_inconsistent_stored_inputs_are_a_422_not_a_default(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    scenario_id = await _scenario(db_session, org_a.id)
    bad = FAIRAnalysis(organization_id=org_a.id, scenario_id=scenario_id, **{
        k: v for k, v in _inputs(tef_min=10.0, tef_mode=1.0, tef_max=2.0).items()
    })
    db_session.add(bad)
    await db_session.commit()
    bad_id = bad.id

    resp = await client.post(f"{API}/fair-analyses/{bad_id}/run-simulation", headers=org_a_headers)
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == {
        "error": "invalid_fair_input", "field": "tef_mode",
        "detail": "tef needs min <= mode <= max (got 10 / 1 / 2)",
    }
    analyzed = await client.post(f"{API}/analyze", json={"scenario_ids": [scenario_id]}, headers=org_a_headers)
    assert analyzed.status_code == 200, analyzed.text
    assert analyzed.json()["failed"][0]["error"] == "invalid_fair_input"
    assert analyzed.json()["failed"][0]["field"] == "tef_mode"
    db_session.expire_all()
    row = (await db_session.execute(select(FAIRAnalysis).where(FAIRAnalysis.id == bad_id))).scalar_one()
    assert row.ale_mean is None


async def test_portfolio_uses_latest_analysis_per_scenario_and_summed_draws(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    s1 = await _scenario(db_session, org_a.id, "one")
    s2 = await _scenario(db_session, org_a.id, "two")
    ids = []
    for sid in (s1, s1, s2):
        created = await client.post(f"{API}/fair-analyses", json=_inputs(scenario_id=sid), headers=org_a_headers)
        ids.append(created.json()["id"])
    analyzed = await client.post(f"{API}/analyze", json={"scenario_ids": [], "iterations": 2000},
                                 headers=org_a_headers)
    body = analyzed.json()
    assert body["scenarios_analyzed"] == 2, body
    assert body["portfolio_var_95"] > 0
    assert body["portfolio_iterations"] == 2000

    loss = await client.get(f"{API}/loss-exceedance", params={"iterations": 2000}, headers=org_a_headers)
    data = loss.json()
    assert data["analyses_count"] == 2
    rows = (await db_session.execute(
        select(FAIRAnalysis).where(FAIRAnalysis.organization_id == org_a.id, FAIRAnalysis.completed_at.is_not(None)),
    )).scalars().all()
    latest = {r.scenario_id: r for r in sorted(rows, key=lambda r: r.created_at)}
    sum_of_p90 = sum(r.ale_p90 for r in latest.values())
    # Independent scenarios: the portfolio p90 never exceeds the comonotonic sum.
    assert data["total_ale_p90"] <= sum_of_p90 + 1e-6
    assert data["total_ale_mean"] == pytest.approx(sum(r.ale_mean for r in latest.values()), rel=0.15)
    assert [p["probability"] for p in data["curve"]][:2] == [0.0, 0.05]

    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["fair_analyses_completed"] == 2
    assert dash["number_of_scenarios"] == 2
    assert dash["fair_scenarios_without_inputs"] == 0
    assert dash["fair_total_ale_mean"] == pytest.approx(sum(r.ale_mean for r in latest.values()), rel=1e-6)


async def test_dashboard_without_analyses_reports_none_not_zero(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    await _scenario(db_session, org_a.id)
    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["fair_total_ale_mean"] is None
    assert dash["fair_scenarios_without_inputs"] == 1
    assert dash["number_of_controls"] == 0
    loss = (await client.get(f"{API}/loss-exceedance", headers=org_a_headers)).json()
    assert loss["analyses_count"] == 0 and loss["curve"] == []


async def test_high_asset_value_scenario_opens_no_incident(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    before = len((await db_session.execute(select(Incident.id))).all())
    resp = await client.post(f"{API}/scenarios", json={
        "name": "crown jewels", "asset_name": "erp", "asset_value_usd": 5_000_000.0,
        "threat_type": "ransomware", "vulnerability_exploited": "vpn", "loss_type": "productivity",
    }, headers=org_a_headers)
    assert resp.status_code == 201, resp.text
    after = len((await db_session.execute(select(Incident.id))).all())
    assert after == before


async def test_control_roi_without_benefit_has_no_payback_and_is_not_a_test(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    register = RiskRegister(
        organization_id=org_a.id, name="reg", risk_category="operational", inherent_risk_score=50.0,
        residual_risk_score=30.0, risk_treatment="mitigate", ale_annual_usd=1000.0,
        risk_appetite_threshold_usd=5000.0, owner_id=str(uuid.uuid4()),
    )
    db_session.add(register)
    await db_session.flush()
    control = RiskControl(
        organization_id=org_a.id, risk_register_id=register.id, control_name="ctl", control_type="preventive",
        implementation_status="implemented", effectiveness_score=0.0, cost_annual_usd=500.0,
    )
    db_session.add(control)
    await db_session.commit()
    control_id = control.id

    resp = await client.post(f"{API}/controls/{control_id}/audit", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["payback_period_months"] is None
    db_session.expire_all()
    row = (await db_session.execute(select(RiskControl).where(RiskControl.id == control_id))).scalar_one()
    assert row.test_result is None and row.last_tested is None


def test_simulate_analysis_refuses_a_row_without_iterations() -> None:
    row = FAIRAnalysis(id="x", organization_id="o", scenario_id="s", **{
        k: v for k, v in _inputs(simulation_iterations=None).items()
    })
    with pytest.raises(FAIRInputError) as exc:
        simulate_analysis(row)
    assert exc.value.field == "simulation_iterations"
