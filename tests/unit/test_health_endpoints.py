"""Health endpoints.

``/health/detailed`` used to read ``database``/``redis`` keys from the public
``/health`` payload, which only ever returned ``status`` - every admin call
raised ``KeyError`` and surfaced as HTTP 500. Both endpoints now share one
dependency probe and the detailed response reports each dependency as
``ok``/``down`` (never a fabricated value).
"""

import pytest


@pytest.mark.asyncio
async def test_public_health_returns_status_only(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"status"}
    assert body["status"] in {"healthy", "degraded"}


@pytest.mark.asyncio
async def test_detailed_health_is_admin_only(client, auth_headers):
    resp = await client.get("/api/v1/health/detailed", headers=auth_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_detailed_health_reports_each_dependency(client, admin_auth_headers):
    resp = await client.get("/api/v1/health/detailed", headers=admin_auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] in {"healthy", "degraded"}
    assert body["database"] in {"ok", "down"}
    assert body["redis"] in {"ok", "down"}
    assert body["version"] and body["environment"]
    # The test database is reachable, so the probe must report it honestly.
    assert body["database"] == "ok"
    # Consistency: healthy only when every dependency is ok.
    expected = "healthy" if body["database"] == "ok" and body["redis"] == "ok" else "degraded"
    assert body["status"] == expected
