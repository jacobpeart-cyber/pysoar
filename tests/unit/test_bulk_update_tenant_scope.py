"""Bulk writes only touch rows in the caller's organization.

Found in the 2026-10-08 feature audit: the OT alert ``bulk_action`` and the
API-security vulnerability ``bulk-update`` updated whatever ids they were
given, including other tenants' rows.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from src.api_security.models import APIEndpointInventory, APIVulnerability
from src.ot_security.models import OTAlert, OTAsset

ORG_A = "bulkorg-a00-4000-8000-000000000001"
ORG_B = "bulkorg-b00-4000-8000-000000000002"


async def _org_user(db_session, *, email: str, org: str, role: str = "analyst"):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    for o in (ORG_A, ORG_B):
        if await db_session.get(Organization, o) is None:
            db_session.add(Organization(id=o, name=f"BULK-{o[:9]}", slug=o[:12]))
            await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=org,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _ot_alert(db_session, org: str) -> str:
    asset = OTAsset(organization_id=org, name="plc-1", asset_type="plc", purdue_level="level_1")
    db_session.add(asset)
    await db_session.flush()
    alert = OTAlert(
        organization_id=org,
        asset_id=asset.id,
        alert_type="unauthorized_access",
        severity="high",
        description="synthetic test alert",
        status="new",
    )
    db_session.add(alert)
    await db_session.commit()
    return alert.id


async def _api_vuln(db_session, org: str) -> str:
    endpoint = APIEndpointInventory(
        service_name="svc", base_url="https://api.example.io", path="/v1/x", method="GET", organization_id=org
    )
    db_session.add(endpoint)
    await db_session.flush()
    vuln = APIVulnerability(
        endpoint_id=endpoint.id,
        vulnerability_type="bola",
        severity="high",
        description="synthetic test vulnerability",
        organization_id=org,
        status="open",
    )
    db_session.add(vuln)
    await db_session.commit()
    return vuln.id


@pytest.mark.asyncio
async def test_ot_alert_bulk_action_ignores_other_tenant_ids(client, db_session):
    _, headers_a = await _org_user(db_session, email="ot-bulk@bulkorg-a.io", org=ORG_A)
    own_id = await _ot_alert(db_session, ORG_A)
    foreign_id = await _ot_alert(db_session, ORG_B)

    resp = await client.post(
        "/api/v1/ot_security/alerts/bulk_action",
        headers=headers_a,
        params=[("alert_ids", own_id), ("alert_ids", foreign_id), ("action", "resolve")],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["alerts_updated"] == 1
    assert body["ignored_ids"] == [foreign_id]

    db_session.expire_all()
    own = (await db_session.execute(select(OTAlert).where(OTAlert.id == own_id))).scalar_one()
    foreign = (await db_session.execute(select(OTAlert).where(OTAlert.id == foreign_id))).scalar_one()
    assert own.status == "resolved"
    assert foreign.status == "new"


@pytest.mark.asyncio
async def test_api_vulnerability_bulk_update_ignores_other_tenant_ids(client, db_session):
    _, headers_a = await _org_user(db_session, email="api-bulk@bulkorg-a.io", org=ORG_A)
    own_id = await _api_vuln(db_session, ORG_A)
    foreign_id = await _api_vuln(db_session, ORG_B)

    resp = await client.post(
        "/api/v1/api-security/vulnerabilities/bulk-update",
        headers=headers_a,
        json={"vulnerability_ids": [own_id, foreign_id], "status": "remediated", "remediation": "patched"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["updated_count"] == 1
    assert body["ignored_ids"] == [foreign_id]

    db_session.expire_all()
    own = (await db_session.execute(select(APIVulnerability).where(APIVulnerability.id == own_id))).scalar_one()
    foreign = (await db_session.execute(select(APIVulnerability).where(APIVulnerability.id == foreign_id))).scalar_one()
    assert own.status == "remediated"
    assert foreign.status == "open"
    assert foreign.remediation != "patched"
