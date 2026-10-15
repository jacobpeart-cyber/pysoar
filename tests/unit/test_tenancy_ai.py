"""Wave 1 tenancy and RBAC for ``/ai`` (ai.py) and
``GET /agentic/alerts/{id}/explain`` (agentic.py).

* every ``/ai`` route requires an organisation (``OrganizationId``); an
  org-less platform superuser gets 403 ``organization_required``;
* ``/ai/triage/batch`` triages only the caller's alerts: a foreign alert id is
  skipped, never triaged (the single-alert ``/ai/triage/alert/{id}``, the
  ``/ai/alerts/triage`` alias and ``/ai/query`` were deleted in wave 5);
* writes acting on alerts/incidents are analyst+ (viewer 403); model
  administration is admin only (analyst 403);
* ``POST /ai/models/train`` (the AgenticSOC "Train New Model" button) is an
  honest 501: nothing ever trained the model it registered;
* the agentic alert explanation is tenant-scoped (404 outside the tenant) and
  no longer returns a hard-coded "High" risk with canned actions.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.ai.models import AIAnalysis, MLModel
from src.models.alert import Alert
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

AI = "/api/v1/ai"


async def _alert(db: AsyncSession, org_id: str, title: str, severity: str = "high") -> str:
    alert = Alert(title=title, organization_id=org_id, severity=severity, source="siem", priority=4)
    db.add(alert)
    await db.commit()
    return alert.id


async def _model(db: AsyncSession, org_id: str) -> str:
    model = MLModel(
        name=f"m-{org_id[:8]}",
        model_type="anomaly_detection",
        algorithm="isolation_forest",
        version="1.0.0",
        status="ready",
        organization_id=org_id,
    )
    db.add(model)
    await db.commit()
    return model.id


async def test_batch_triage_is_tenant_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
    viewer_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    a_id = org_a.id
    alert_id = await _alert(db_session, a_id, "A brute force")
    path = f"{AI}/triage/batch"
    body = {"alert_ids": [alert_id], "limit": 5}

    # Another tenant naming A's alert triages nothing.
    resp = await client.post(path, headers=org_b_headers, json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["alerts_triaged"] == 0
    resp = await client.post(path, headers=viewer_headers, json=body)
    assert resp.status_code == 403, resp.text
    resp = await client.post(path, headers=superuser_headers, json=body)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"

    # Nothing was persisted for the refused calls.
    rows = (await db_session.execute(select(AIAnalysis).where(AIAnalysis.source_id == alert_id))).scalars().all()
    assert rows == []

    resp = await client.post(path, headers=org_a_headers, json=body)
    assert resp.status_code == 200, resp.text
    assert [t["alert_id"] for t in resp.json()["triaged_alerts"]] == [alert_id]


async def test_triaged_list_and_feedback_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    alert_id = await _alert(db_session, org_a.id, "A triage me")
    resp = await client.post(
        f"{AI}/triage/batch", headers=org_a_headers, json={"alert_ids": [alert_id], "limit": 5}
    )
    assert resp.status_code == 200, resp.text

    listed_b = await client.get(f"{AI}/alerts/triaged", headers=org_b_headers)
    assert listed_b.status_code == 200
    assert alert_id not in {row["id"] for row in listed_b.json()}
    listed_a = await client.get(f"{AI}/alerts/triaged", headers=org_a_headers)
    assert alert_id in {row["id"] for row in listed_a.json()}

    analysis_id = (
        await db_session.execute(select(AIAnalysis.id).where(AIAnalysis.source_id == alert_id))
    ).scalar_one()
    body = {"analysis_id": analysis_id, "feedback_score": 1}
    await assert_tenant_isolated(client, "POST", f"{AI}/feedback", org_b_headers, json=body)
    assert (await client.post(f"{AI}/feedback", headers=viewer_headers, json=body)).status_code == 403
    assert (await client.post(f"{AI}/feedback", headers=org_a_headers, json=body)).status_code == 200


async def test_batch_triage_viewer_forbidden(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    resp = await client.post(f"{AI}/triage/batch", headers=viewer_headers, json={"limit": 5})
    assert resp.status_code == 403, resp.text


async def test_batch_triage_without_ids_stays_in_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    own = await _alert(db_session, org_a.id, "A own")
    foreign = await _alert(db_session, org_b.id, "B foreign")
    resp = await client.post(f"{AI}/triage/batch", headers=org_a_headers, json={"limit": 10})
    assert resp.status_code == 200, resp.text
    ids = {t["alert_id"] for t in resp.json()["triaged_alerts"]}
    assert own in ids
    assert foreign not in ids


async def test_model_routes_isolated_and_admin_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    model_id = await _model(db_session, org_a.id)

    listed_b = await client.get(f"{AI}/models", headers=org_b_headers)
    assert model_id not in {m["id"] for m in listed_b.json()}
    await assert_tenant_isolated(client, "GET", f"{AI}/models/{model_id}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{AI}/models/{model_id}/drift", org_b_headers)

    # Retiring a model is admin-only.
    assert (await client.delete(f"{AI}/models/{model_id}", headers=org_a_headers)).status_code == 403
    assert (await client.delete(f"{AI}/models/{model_id}", headers=org_a_admin_headers)).status_code == 200


async def test_train_model_is_honest_501_and_admin_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_admin_headers: dict[str, str],
    org_a_headers: dict[str, str],
) -> None:
    body = {"model_type": "anomaly_detection", "algorithm": "isolation_forest", "description": "x"}
    resp = await client.post(f"{AI}/models/train", headers=org_a_headers, json=body)
    assert resp.status_code == 403, resp.text

    resp = await client.post(f"{AI}/models/train", headers=org_a_admin_headers, json=body)
    assert resp.status_code == 501, resp.text
    assert resp.json()["detail"]["error"] == "not_implemented"
    # No shell model row is registered any more.
    assert (await db_session.execute(select(MLModel))).scalars().all() == []


async def test_incident_analysis_routes_gated(
    client: AsyncClient,
    viewer_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    for path in (
        f"{AI}/analyze/incident/x",
        f"{AI}/analyze/root-cause/x",
        f"{AI}/recommend/response/x",
    ):
        resp = await client.post(path, headers=viewer_headers, json={})
        assert resp.status_code == 403, (path, resp.text)
    resp = await client.get(f"{AI}/dashboard", headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"


async def test_agentic_alert_explain_is_tenant_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    alert_id = await _alert(db_session, org_a.id, "A explain me", severity="medium")
    path = f"/api/v1/agentic/alerts/{alert_id}/explain"

    resp = await assert_tenant_isolated(client, "GET", path, org_b_headers)
    assert "A explain me" not in resp.text

    resp = await client.get(path, headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"

    resp = await client.get(path, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["alert_id"] == alert_id
    assert data["risk_assessment"] == "medium"
    assert data["recommended_actions"] == []
