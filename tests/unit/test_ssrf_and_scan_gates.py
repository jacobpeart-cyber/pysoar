"""Outbound-request and network-scan features are not an open proxy.

Found in the 2026-10-08 feature audit:
  * the generic HTTP connector fallback requested any URL the caller sent;
  * ``POST /api-security/scan/compliance/{id}`` fetched a tenant-supplied
    URL server-side for any user, without an organization check;
  * ``POST /ot-security/discover`` TCP-swept ranges from the API host for
    any user.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.integrations.engine import ActionExecutor, OutboundTargetRefused

ORG_A = "ssrforg-a00-4000-8000-000000000001"
ORG_B = "ssrforg-b00-4000-8000-000000000002"
PUBLIC_BASE = "https://93.184.216.34/api"  # public IP literal: no DNS lookup needed


async def _org_user(db_session, *, email: str, org: str, role: str = "analyst"):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, org) is None:
        db_session.add(Organization(id=org, name=f"SSRF-{org[:9]}", slug=org[:12]))
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


# --------------------------------------------------------------------------
# Generic HTTP connector fallback
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generic_target_is_pinned_to_configured_base_url():
    ex = ActionExecutor()
    config = {"base_url": PUBLIC_BASE}

    assert await ex._resolve_generic_target("/v1/items", config) == "https://93.184.216.34/api/v1/items"
    assert await ex._resolve_generic_target("https://93.184.216.34/other", config) == "https://93.184.216.34/other"
    assert await ex._resolve_generic_target("https://93.184.216.34:443/x", config) == "https://93.184.216.34:443/x"

    for bad in (
        "http://169.254.169.254/latest/meta-data/",
        "https://evil.example/x",
        "http://93.184.216.34/api",  # scheme change
        "https://93.184.216.34:8443/api",  # port change
        "//evil.example/x",
        "https://93.184.216.34@127.0.0.1/x",
    ):
        with pytest.raises(OutboundTargetRefused):
            await ex._resolve_generic_target(bad, config)


@pytest.mark.asyncio
async def test_generic_target_refuses_private_base_and_missing_config():
    ex = ActionExecutor()
    with pytest.raises(OutboundTargetRefused):
        await ex._resolve_generic_target("/x", {})
    with pytest.raises(OutboundTargetRefused):
        await ex._resolve_generic_target("/x", {"base_url": "file:///etc/passwd"})
    for private_base in ("http://127.0.0.1:6379", "http://10.0.0.5/api", "http://[::1]/", "http://169.254.169.254/"):
        with pytest.raises(OutboundTargetRefused):
            await ex._resolve_generic_target("/x", {"base_url": private_base})


@pytest.mark.asyncio
async def test_generic_http_action_refuses_before_any_request():
    ex = ActionExecutor()
    with pytest.raises(OutboundTargetRefused):
        await ex._call_generic_http_action(
            "inst-1", "do", {"url": "http://127.0.0.1:6379/", "method": "GET"}, {"base_url": PUBLIC_BASE}
        )


@pytest.mark.asyncio
async def test_execute_action_route_requires_analyst(client, db_session):
    _, viewer = await _org_user(db_session, email="viewer@ssrforg-a.io", org=ORG_A, role="viewer")
    _, analyst = await _org_user(db_session, email="analyst@ssrforg-a.io", org=ORG_A, role="analyst")
    url = "/api/v1/integrations/installed/does-not-exist/actions/none/execute"
    body = {"input_data": {"url": "http://169.254.169.254/"}}

    refused = await client.post(url, headers=viewer, json=body)
    assert refused.status_code == 403, refused.text
    # Analysts pass the role gate and reach the (tenant-scoped) lookup.
    allowed = await client.post(url, headers=analyst, json=body)
    assert allowed.status_code == 404, allowed.text


# --------------------------------------------------------------------------
# API-security compliance scan
# --------------------------------------------------------------------------


async def _api_endpoint(db_session, org: str, base_url: str) -> str:
    from src.api_security.models import APIEndpointInventory

    row = APIEndpointInventory(
        service_name="svc", base_url=base_url, path="/health", method="GET", organization_id=org
    )
    db_session.add(row)
    await db_session.commit()
    return row.id


@pytest.mark.asyncio
async def test_compliance_scan_admin_only_org_scoped_and_no_private_targets(client, db_session, monkeypatch):
    import src.api.v1.endpoints.api_security as api_sec

    queued: list[tuple] = []
    monkeypatch.setattr(api_sec, "compliance_check", lambda *args: queued.append(args))

    _, analyst = await _org_user(db_session, email="apisec-analyst@ssrforg-a.io", org=ORG_A, role="analyst")
    _, admin = await _org_user(db_session, email="apisec-admin@ssrforg-a.io", org=ORG_A, role="admin")
    own_public = await _api_endpoint(db_session, ORG_A, PUBLIC_BASE)
    own_private = await _api_endpoint(db_session, ORG_A, "http://127.0.0.1:8000")
    foreign = await _api_endpoint(db_session, ORG_B, PUBLIC_BASE)

    assert (await client.post(f"/api/v1/api-security/scan/compliance/{own_public}", headers=analyst)).status_code == 403
    assert (await client.post(f"/api/v1/api-security/scan/compliance/{foreign}", headers=admin)).status_code == 404

    private = await client.post(f"/api/v1/api-security/scan/compliance/{own_private}", headers=admin)
    assert private.status_code == 400, private.text
    assert private.json()["detail"]["error"] == "scan_target_not_allowed"
    assert queued == []

    ok = await client.post(f"/api/v1/api-security/scan/compliance/{own_public}", headers=admin)
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "compliance_check_queued"
    assert queued == [(own_public, ORG_A)]


@pytest.mark.asyncio
async def test_header_check_refuses_private_targets_without_fetching():
    from src.api_security.tasks import _check_security_headers

    passed, details = await _check_security_headers(SimpleNamespace(base_url="http://169.254.169.254", path="/latest"))
    assert passed is False
    assert details["reason"].startswith("target refused")


# --------------------------------------------------------------------------
# OT discovery sweep
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ot_discover_admin_only_and_confined_to_ot_zones(client, db_session, monkeypatch):
    from src.ot_security.models import OTZone

    monkeypatch.setenv("PYSOAR_DISABLE_NETWORK_SCAN", "1")
    _, analyst = await _org_user(db_session, email="ot-analyst@ssrforg-a.io", org=ORG_A, role="analyst")
    _, admin = await _org_user(db_session, email="ot-admin@ssrforg-a.io", org=ORG_A, role="admin")
    db_session.add(OTZone(organization_id=ORG_A, name="cell-1", purdue_level="level_1", network_cidr="10.10.0.0/16"))
    await db_session.commit()

    refused_role = await client.post("/api/v1/ot-security/discover", headers=analyst, json={"cidr": "10.10.5.0/24"})
    assert refused_role.status_code == 403

    outside = await client.post("/api/v1/ot-security/discover", headers=admin, json={"cidr": "192.168.1.0/24"})
    assert outside.status_code == 403, outside.text
    assert outside.json()["detail"]["error"] == "cidr_outside_ot_zones"

    inside = await client.post("/api/v1/ot-security/discover", headers=admin, json={"cidr": "10.10.5.0/24"})
    assert inside.status_code == 200, inside.text
    assert inside.json()["status"] == "skipped"


@pytest.mark.asyncio
async def test_ot_discover_without_zones_is_admin_only_and_size_capped(client, db_session, monkeypatch):
    monkeypatch.setenv("PYSOAR_DISABLE_NETWORK_SCAN", "1")
    _, admin = await _org_user(db_session, email="ot-admin-b@ssrforg-b.io", org=ORG_B, role="admin")

    too_big = await client.post("/api/v1/ot-security/discover", headers=admin, json={"cidr": "10.0.0.0/16"})
    assert too_big.status_code == 400
    ok = await client.post("/api/v1/ot-security/discover", headers=admin, json={"cidr": "10.0.0.0/24"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "skipped"
