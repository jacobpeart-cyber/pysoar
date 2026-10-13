"""Backend contracts the VulnManagement and ITDR pages rely on (2026-10-08 audit).

- ``GET /vulnmgmt/dashboard`` carries the summary-card counts
  (``total_vulnerabilities``, ``critical_vulnerabilities``) scoped to the
  caller's org, and ``mttr_days`` is null until something was remediated.
- ``GET /vulnmgmt/instances?vulnerability_id=`` resolves a catalog
  vulnerability to its instance ids (patch plans and bulk actions take those).
- ``POST /vulnmgmt/exceptions`` refuses an instance outside the caller's org.
- ``POST /itdr/threats/scan`` writes ``confidence_score`` on the 0-100 scale.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from src.core.security import create_access_token, get_password_hash
from src.itdr.models import IdentityProfile, IdentityThreat
from src.models.organization import Organization
from src.models.user import User
from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance

ORG_A = "33333333-0000-4000-8000-00000000000a"
ORG_B = "44444444-0000-4000-8000-00000000000b"


def _headers(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _setup(db) -> User:
    for org_id, slug in ((ORG_A, "page-contract-a"), (ORG_B, "page-contract-b")):
        if await db.get(Organization, org_id) is None:
            db.add(Organization(id=org_id, name=slug.upper(), slug=slug))
    await db.flush()
    user = User(
        email="analyst@page-contract-a.test",
        hashed_password=get_password_hash("pw-for-tests"),
        full_name="analyst",
        role="analyst",
        is_active=True,
        organization_id=ORG_A,
    )
    db.add(user)
    await db.flush()
    return user


async def _vuln(db, org_id: str, cve: str, severity: str) -> Vulnerability:
    v = Vulnerability(organization_id=org_id, cve_id=cve, title=f"{cve} title", severity=severity)
    db.add(v)
    await db.flush()
    return v


async def _instance(db, org_id: str, vuln: Vulnerability, asset: str) -> VulnerabilityInstance:
    i = VulnerabilityInstance(organization_id=org_id, vulnerability_id=vuln.id, asset_name=asset)
    db.add(i)
    await db.flush()
    return i


@pytest.mark.asyncio
async def test_dashboard_card_counts_are_org_scoped_and_mttr_unknown(client, db_session):
    user = await _setup(db_session)
    await _vuln(db_session, ORG_A, "CVE-2026-0001", "critical")
    await _vuln(db_session, ORG_A, "CVE-2026-0002", "high")
    await _vuln(db_session, ORG_B, "CVE-2026-0003", "critical")
    await db_session.commit()

    resp = await client.get("/api/v1/vulnmgmt/dashboard", headers=_headers(user))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_vulnerabilities"] == 2
    assert body["critical_vulnerabilities"] == 1
    # Nothing patched or mitigated: MTTR is unknown, not "0 days".
    assert body["mttr_days"] is None
    assert body["sla_compliance"]["total"] == 0


@pytest.mark.asyncio
async def test_instances_filter_by_vulnerability_id(client, db_session):
    user = await _setup(db_session)
    v1 = await _vuln(db_session, ORG_A, "CVE-2026-0101", "critical")
    v2 = await _vuln(db_session, ORG_A, "CVE-2026-0102", "low")
    i1 = await _instance(db_session, ORG_A, v1, "web-01")
    i2 = await _instance(db_session, ORG_A, v1, "web-02")
    await _instance(db_session, ORG_A, v2, "db-01")
    await db_session.commit()

    resp = await client.get(
        "/api/v1/vulnmgmt/instances",
        params={"vulnerability_id": v1.id, "size": 100},
        headers=_headers(user),
    )
    assert resp.status_code == 200, resp.text
    assert {row["id"] for row in resp.json()["items"]} == {i1.id, i2.id}


@pytest.mark.asyncio
async def test_exception_requires_an_instance_in_the_callers_org(client, db_session):
    user = await _setup(db_session)
    headers = _headers(user)
    foreign_vuln = await _vuln(db_session, ORG_B, "CVE-2026-0201", "high")
    foreign_instance = await _instance(db_session, ORG_B, foreign_vuln, "b-host")
    own_vuln = await _vuln(db_session, ORG_A, "CVE-2026-0202", "high")
    own_instance = await _instance(db_session, ORG_A, own_vuln, "a-host")
    foreign_id, own_id = foreign_instance.id, own_instance.id
    await db_session.commit()

    body = {"exception_type": "risk_accepted", "justification": "Compensating WAF rule in place."}
    foreign = await client.post(
        "/api/v1/vulnmgmt/exceptions",
        json={**body, "vulnerability_instance_id": foreign_id},
        headers=headers,
    )
    assert foreign.status_code == 404, foreign.text

    own = await client.post(
        "/api/v1/vulnmgmt/exceptions",
        json={**body, "vulnerability_instance_id": own_id},
        headers=headers,
    )
    assert own.status_code == 201, own.text
    assert own.json()["vulnerability_instance_id"] == own_id


@pytest.mark.asyncio
async def test_itdr_scan_confidence_is_on_the_0_to_100_scale(client, db_session):
    user = await _setup(db_session)
    db_session.add(
        IdentityProfile(
            organization_id=ORG_A,
            user_id="root-admin",
            username="root-admin",
            email="root-admin@page-contract-a.test",
            privilege_level="admin",
            mfa_enabled=False,
        )
    )
    await db_session.commit()

    resp = await client.post("/api/v1/itdr/threats/scan", json={}, headers=_headers(user))
    assert resp.status_code == 200, resp.text
    assert resp.json()["threats_created"] >= 1

    threats = (
        await db_session.execute(select(IdentityThreat).where(IdentityThreat.organization_id == ORG_A))
    ).scalars().all()
    assert threats
    assert all(t.confidence_score == 90.0 for t in threats)
