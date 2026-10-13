"""Wave 1 tenancy / RBAC conversion of the /iocs router.

docs/audit/2026-10-08/intel-detection-A.md (c) items 2, 4-8 and 10: list and
by-id lookups are scoped to the caller's organisation (plus read-only
platform feed intel), create/bulk de-duplicate inside the organisation only,
search no longer mutates rows, enrich no longer folds in other tenants'
context, and every write needs the analyst or admin role.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.intel.models import ThreatIndicator
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/iocs"


async def _create(client: AsyncClient, headers: dict[str, str], value: str, **extra: Any) -> dict:
    resp = await client.post(API, json={"value": value, "ioc_type": "domain", **extra}, headers=headers)
    assert resp.status_code == 201, resp.text[:300]
    return resp.json()


async def test_ioc_stamped_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    ioc_id = (await _create(client, org_a_headers, "a-only.example.org"))["id"]
    row = (await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.id == ioc_id))).scalar_one()
    assert row.organization_id == org_a_id

    for method, path, body in (
        ("GET", f"{API}/{ioc_id}", None),
        ("PATCH", f"{API}/{ioc_id}", {"threat_level": "low"}),
        ("POST", f"{API}/{ioc_id}/enrich", None),
        ("DELETE", f"{API}/{ioc_id}", None),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    listed_b = await client.get(API, headers=org_b_headers)
    assert listed_b.status_code == 200
    assert ioc_id not in [i["id"] for i in listed_b.json()["items"]]
    searched_b = await client.post(f"{API}/search", json={"value": "a-only.example.org"}, headers=org_b_headers)
    assert searched_b.status_code == 200 and searched_b.json() == []

    own = await client.get(f"{API}/{ioc_id}", headers=org_a_headers)
    assert own.status_code == 200 and own.json()["value"] == "a-only.example.org"


async def test_create_dedupes_inside_the_organisation_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    a = await _create(client, org_a_headers, "shared.example.org")
    b = await _create(client, org_b_headers, "shared.example.org")
    assert a["id"] != b["id"]  # B got its own row, not A's
    again = await _create(client, org_a_headers, "shared.example.org")
    assert again["id"] == a["id"] and again["sighting_count"] == 2

    bulk = await client.post(
        f"{API}/bulk",
        json={"iocs": [
            {"value": "shared.example.org", "ioc_type": "domain"},
            {"value": "bulk-new.example.org", "ioc_type": "domain"},
        ]},
        headers=org_b_headers,
    )
    assert bulk.status_code == 200, bulk.text[:300]
    assert bulk.json()["created_count"] == 1 and bulk.json()["updated_count"] == 1

    db_session.expire_all()
    a_row = (await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.id == a["id"]))).scalar_one()
    assert a_row.sighting_count == 2  # B's create and bulk never touched A's row
    bulk_row = (
        await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.value == "bulk-new.example.org"))
    ).scalar_one()
    assert bulk_row.organization_id == org_b_id
    assert a_row.organization_id == org_a_id


async def test_duplicate_legacy_rows_do_not_500(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
) -> None:
    """Regression: two existing rows for one value made create raise
    MultipleResultsFound (scalar_one_or_none) and return 500."""
    org_a_id = org_a.id
    for _ in range(2):
        db_session.add(ThreatIndicator(
            indicator_type="domain", value="dup.example.org", organization_id=org_a_id, sighting_count=1,
        ))
    await db_session.commit()
    resp = await client.post(API, json={"value": "dup.example.org", "ioc_type": "domain"}, headers=org_a_headers)
    assert resp.status_code == 201, resp.text[:300]


async def test_platform_intel_is_readable_but_read_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_b_id = org_b.id
    platform = ThreatIndicator(
        indicator_type="domain", value="feed.example.org", organization_id=None,
        confidence=80, sighting_count=5, source="feed",
    )
    other = ThreatIndicator(
        indicator_type="domain", value="feed.example.org", organization_id=org_b_id,
        confidence=10, context={"secret": "org-b note"},
    )
    db_session.add_all([platform, other])
    await db_session.commit()
    platform_id = platform.id

    got = await client.get(f"{API}/{platform_id}", headers=org_a_headers)
    assert got.status_code == 200
    listed = await client.get(API, params={"search": "feed.example"}, headers=org_a_headers)
    assert [i["id"] for i in listed.json()["items"]] == [platform_id]
    for method, path, body in (
        ("PATCH", f"{API}/{platform_id}", {"threat_level": "low"}),
        ("DELETE", f"{API}/{platform_id}", None),
        ("POST", f"{API}/{platform_id}/enrich", None),
    ):
        resp = await client.request(method, path, json=body, headers=org_a_headers)
        assert resp.status_code == 404, (method, resp.text[:200])

    # search is a read: no sighting bump on the platform row
    searched = await client.post(f"{API}/search", json={"value": "feed.example.org"}, headers=org_a_headers)
    assert [i["id"] for i in searched.json()] == [platform_id]
    db_session.expire_all()
    p_row = (await db_session.execute(select(ThreatIndicator).where(ThreatIndicator.id == platform_id))).scalar_one()
    assert p_row.sighting_count == 5

    # enrich folds in platform intel but never org B's row
    own = await _create(client, org_a_headers, "feed.example.org")
    enriched = await client.post(f"{API}/{own['id']}/enrich", headers=org_a_headers)
    assert enriched.status_code == 200, enriched.text[:300]
    data = enriched.json()["enrichment_data"]
    assert f"local_{platform_id[:8]}" in data
    assert "org-b note" not in str(data)
    assert data["source_count"] == 2


async def test_org_less_superuser_needs_an_organisation(
    client: AsyncClient, superuser_headers: dict[str, str],
) -> None:
    resp = await client.get(API, headers=superuser_headers)
    assert resp.status_code == 403
    assert "organization_required" in resp.text


WRITE_ROUTES = [
    ("POST", "", {"value": "v.example.org", "ioc_type": "domain"}),
    ("POST", "/bulk", {"iocs": [{"value": "v.example.org", "ioc_type": "domain"}]}),
    ("PATCH", "/{id}", {"threat_level": "low"}),
    ("DELETE", "/{id}", None),
    ("POST", "/{id}/enrich", None),
]


@pytest.mark.parametrize(("method", "path", "body"), WRITE_ROUTES)
async def test_viewer_cannot_write(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
    method: str,
    path: str,
    body: Any,
) -> None:
    row = ThreatIndicator(indicator_type="domain", value="viewer.example.org", organization_id=org_a.id)
    db_session.add(row)
    await db_session.commit()
    row_id = row.id
    resp = await client.request(method, API + path.replace("{id}", row_id), json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text[:300]


async def test_viewer_can_read_and_search(
    client: AsyncClient, viewer_headers: dict[str, str],
) -> None:
    assert (await client.get(API, headers=viewer_headers)).status_code == 200
    resp = await client.post(f"{API}/search", json={"value": "x.example.org"}, headers=viewer_headers)
    assert resp.status_code == 200
