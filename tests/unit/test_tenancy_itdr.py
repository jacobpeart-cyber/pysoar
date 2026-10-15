"""Wave 1 tenancy / RBAC conversion of the ITDR router and tasks.

docs/audit/2026-10-08/intel-detection-C.md (c) items 6-8: every ITDR route
takes the mandatory ``OrganizationId`` (the ``if org_id:`` guards that let an
org-less caller list, scan and count every tenant are gone), rows are
stamped, lookups by id 404 outside the tenant, a threat cannot be linked to
another tenant's identity, operational writes need analyst or admin, response
actions and elevation approve / revoke need admin, and the credential
exposure task only reads the organisation's own leak records.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.itdr.models import (
    AccessAnomaly,
    CredentialExposure,
    IdentityProfile,
    IdentityThreat,
    PrivilegedAccessEvent,
)
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/itdr"


def _identity_body(name: str, **extra: Any) -> dict[str, Any]:
    return {"user_id": name, "username": name, "email": f"{name}@corp.io", **extra}


async def _identity(db: AsyncSession, org_id: str, name: str, **extra: Any) -> str:
    identity = IdentityProfile(
        organization_id=org_id, user_id=name, username=name, email=f"{name}@corp.io", **extra
    )
    db.add(identity)
    await db.commit()
    return identity.id


async def _seed_children(db: AsyncSession, org_id: str, identity_id: str) -> dict[str, str]:
    threat = IdentityThreat(
        organization_id=org_id, identity_id=identity_id, threat_type="credential_stuffing",
        severity="high", confidence_score=80.0, status="detected",
    )
    exposure = CredentialExposure(
        organization_id=org_id, identity_id=identity_id, exposure_source="darkweb",
        credential_type="password",
    )
    anomaly = AccessAnomaly(
        organization_id=org_id, identity_id=identity_id, anomaly_type="unusual_time",
        deviation_score=0.8,
    )
    event = PrivilegedAccessEvent(
        organization_id=org_id, identity_id=identity_id, event_type="elevation_request",
        target_resource="prod-db", justification="incident",
    )
    db.add_all([threat, exposure, anomaly, event])
    await db.commit()
    return {"threat": threat.id, "exposure": exposure.id, "anomaly": anomaly.id, "event": event.id}


# ---------------------------------------------------------------------------
# isolation + stamping
# ---------------------------------------------------------------------------


async def test_identity_create_is_stamped_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(f"{API}/identities", json=_identity_body("alice"), headers=org_a_headers)
    assert resp.status_code == 201, resp.text[:300]
    identity_id = resp.json()["id"]
    row = (await db_session.execute(select(IdentityProfile).where(IdentityProfile.id == identity_id))).scalar_one()
    assert row.organization_id == org_a_id

    for method, path, body in (
        ("GET", f"{API}/identities/{identity_id}", None),
        ("PUT", f"{API}/identities/{identity_id}", {"display_name": "pwned"}),
        ("GET", f"{API}/identities/{identity_id}/risk-score", None),
        ("POST", f"{API}/privileged-access/request", {"identity_id": identity_id, "target_resource": "x"}),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)
    check = await client.post(
        f"{API}/credential-exposures/check", params={"identity_id": identity_id}, headers=org_b_headers
    )
    assert check.status_code == 404

    listed = await client.get(f"{API}/identities", headers=org_b_headers)
    assert listed.status_code == 200 and listed.json()["total"] == 0


async def test_threat_create_is_stamped_and_cannot_use_another_tenants_identity(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    own_identity = await _identity(db_session, org_a_id, "bob")
    foreign_identity = await _identity(db_session, org_b_id, "eve")

    foreign = await client.post(
        f"{API}/threats",
        json={"identity_id": foreign_identity, "threat_type": "x", "severity": "high"},
        headers=org_a_headers,
    )
    assert foreign.status_code == 404
    missing = await client.post(
        f"{API}/threats",
        json={"identity_id": "does-not-exist", "threat_type": "x", "severity": "high"},
        headers=org_a_headers,
    )
    assert missing.status_code == 404  # used to be a foreign-key 500

    created = await client.post(
        f"{API}/threats",
        json={"identity_id": own_identity, "threat_type": "password_spray", "severity": "high"},
        headers=org_a_headers,
    )
    assert created.status_code == 201, created.text[:300]
    threat_id = created.json()["id"]
    assert created.json()["organization_id"] == org_a_id

    for method, path, body in (
        ("GET", f"{API}/threats/{threat_id}", None),
        ("PUT", f"{API}/threats/{threat_id}", {"status": "resolved"}),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)
    listed = await client.get(f"{API}/threats", headers=org_b_headers)
    assert listed.json()["total"] == 0


async def test_child_records_are_tenant_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    identity_id = await _identity(db_session, org_a_id, "carol")
    ids = await _seed_children(db_session, org_a_id, identity_id)

    for method, path, body in (
        ("GET", f"{API}/credential-exposures/{ids['exposure']}", None),
        ("PUT", f"{API}/credential-exposures/{ids['exposure']}", {"is_remediated": True}),
        ("GET", f"{API}/anomalies/{ids['anomaly']}", None),
        ("PUT", f"{API}/anomalies/{ids['anomaly']}", {"is_reviewed": True}),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    remediate = await client.post(
        f"{API}/credential-exposures/remediate",
        json={"exposure_ids": [ids["exposure"]], "remediation_type": "password_reset"},
        headers=org_b_headers,
    )
    assert remediate.status_code == 200 and remediate.json()["updated"] == 0

    for path in ("/credential-exposures", "/anomalies", "/privileged-access"):
        listed = await client.get(API + path, headers=org_b_headers)
        assert listed.status_code == 200 and listed.json()["total"] == 0, path

    metrics = await client.get(f"{API}/dashboard/metrics", headers=org_b_headers)
    assert metrics.status_code == 200
    body = metrics.json()
    assert body["total_identities"] == 0 and body["high_threats_active"] == 0

    db_session.expire_all()
    exposure = await db_session.get(CredentialExposure, ids["exposure"])
    assert exposure.is_remediated is False


async def test_privileged_access_admin_routes_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    from tests.helpers.tenancy import bearer, make_user

    org_a_id, org_b_id = org_a.id, org_b.id
    admin_b = await make_user(db_session, role="admin", organization_id=org_b_id, label="admin-b")
    admin_b_headers = bearer(admin_b)
    identity_id = await _identity(db_session, org_a_id, "dan")
    ids = await _seed_children(db_session, org_a_id, identity_id)

    await assert_tenant_isolated(
        client, "PUT", f"{API}/privileged-access/{ids['event']}", admin_b_headers, json={"was_revoked": True},
    )

    revoked = await client.put(
        f"{API}/privileged-access/{ids['event']}", json={"was_revoked": True}, headers=org_a_admin_headers
    )
    assert revoked.status_code == 200, revoked.text[:300]


async def test_scan_only_reads_and_writes_the_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    await _identity(db_session, org_a_id, "root-a", privilege_level="admin", mfa_enabled=False)
    foreign = await _identity(db_session, org_b_id, "root-b", privilege_level="admin", mfa_enabled=False)

    resp = await client.post(f"{API}/threats/scan", headers=org_a_headers)
    assert resp.status_code == 200, resp.text[:300]
    assert resp.json()["organization_id"] == org_a_id
    assert resp.json()["identities_scanned"] == 1

    threats = (await db_session.execute(select(IdentityThreat))).scalars().all()
    assert threats and all(t.organization_id == org_a_id for t in threats)
    assert foreign not in {t.identity_id for t in threats}


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------

WRITE_ROUTES: list[tuple[str, str, Any, Any]] = [
    ("POST", "/identities", None, _identity_body("viewer-made")),
    ("PUT", "/identities/{identity}", None, {"display_name": "x"}),
    ("POST", "/threats", None, {"threat_type": "x", "severity": "high"}),
    ("PUT", "/threats/{threat}", None, {"status": "investigating"}),
    ("POST", "/threats/{threat}/respond", None, {"action_type": "contain", "action_details": {}}),
    ("POST", "/threats/scan", None, None),
    ("POST", "/credential-exposures/check", {"identity_id": "{identity}"}, None),
    ("POST", "/credential-exposures/remediate", None, {"exposure_ids": ["x"], "remediation_type": "password_reset"}),
    ("PUT", "/credential-exposures/{exposure}", None, {"is_remediated": True}),
    ("PUT", "/anomalies/{anomaly}", None, {"is_reviewed": True}),
    ("POST", "/privileged-access/request", None, {"identity_id": "{identity}", "target_resource": "x"}),
    ("PUT", "/privileged-access/{event}", None, {"was_revoked": True}),
]


def _fill(value: Any, ids: dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format(**ids)
    if isinstance(value, dict):
        return {k: _fill(v, ids) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, ids) for v in value]
    return value


@pytest.mark.parametrize("method,path,params,body", WRITE_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
    method: str,
    path: str,
    params: Any,
    body: Any,
) -> None:
    org_a_id = org_a.id
    identity_id = await _identity(db_session, org_a_id, "viewer-target")
    ids = {"identity": identity_id, **await _seed_children(db_session, org_a_id, identity_id)}
    resp = await client.request(
        method, API + _fill(path, ids), params=_fill(params, ids), json=_fill(body, ids), headers=viewer_headers
    )
    assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text[:200]}"


@pytest.mark.parametrize(
    "method,path,params,body",
    [
        ("POST", "/threats/{threat}/respond", None, {"action_type": "contain", "action_details": {}}),
        ("PUT", "/privileged-access/{event}", None, {"was_revoked": True}),
    ],
)
async def test_response_and_access_decisions_are_admin_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
    method: str,
    path: str,
    params: Any,
    body: Any,
) -> None:
    org_a_id = org_a.id
    identity_id = await _identity(db_session, org_a_id, "admin-target")
    ids = {"identity": identity_id, **await _seed_children(db_session, org_a_id, identity_id)}
    url = API + _fill(path, ids)
    analyst = await client.request(method, url, params=params, json=body, headers=org_a_headers)
    assert analyst.status_code == 403, analyst.text[:200]
    admin = await client.request(method, url, params=params, json=body, headers=org_a_admin_headers)
    assert admin.status_code == 200, admin.text[:300]


@pytest.mark.parametrize(
    "path",
    ["/identities", "/threats", "/credential-exposures", "/anomalies", "/privileged-access",
     "/dashboard/metrics"],
)
async def test_org_less_superuser_needs_an_organisation(
    client: AsyncClient, superuser_headers: dict[str, str], path: str
) -> None:
    resp = await client.get(API + path, headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"


async def test_org_less_superuser_cannot_scan_every_tenant(
    client: AsyncClient, superuser_headers: dict[str, str]
) -> None:
    # Used to scan every tenant and write threats with organization_id NULL.
    resp = await client.post(f"{API}/threats/scan", headers=superuser_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"
