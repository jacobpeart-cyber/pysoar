"""Wave 1: the flat aliases (aliases.py), and the wave 5 retirement of the
detection duplicates.

* ``_safe_list`` propagates query failures instead of returning an empty list.
* Tenant scoping is mandatory: org-less callers get 403 ``organization_required``
  on every alias that remains.
* Wave 5 deleted the detection duplicates ``/intel/iocs``, ``/intel/feeds``,
  ``/siem/dashboard`` and ``/itdr/access-anomalies`` (no page called them); the
  canonical routes keep the scoping the aliases were tested for: the caller's
  indicators plus platform-scope ones, never another tenant's.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints.aliases import _safe_list
from src.intel.models import ThreatIndicator
from src.itdr.models import AccessAnomaly, IdentityProfile
from src.models.organization import Organization

ALIAS_PATHS = [
    "/api/v1/dfir/evidence",
    "/api/v1/dfir/legal-holds",
    "/api/v1/playbooks/executions/recent",
    "/api/v1/integrations/executions",
    "/api/v1/integrations/webhooks",
]
RETIRED_PATHS = [
    "/api/v1/intel/iocs",
    "/api/v1/intel/feeds",
    "/api/v1/siem/dashboard",
    "/api/v1/itdr/access-anomalies",
]


def _indicator(value: str, org_id: str | None) -> ThreatIndicator:
    return ThreatIndicator(indicator_type="ipv4", value=value, organization_id=org_id)


@pytest.mark.parametrize("path", ALIAS_PATHS)
async def test_orgless_superuser_refused(
    client: AsyncClient, superuser_headers: dict[str, str], path: str,
) -> None:
    resp = await client.get(path, headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"


@pytest.mark.parametrize("path", RETIRED_PATHS)
async def test_retired_detection_aliases_are_gone(
    client: AsyncClient, org_a_headers: dict[str, str], path: str,
) -> None:
    resp = await client.get(path, headers=org_a_headers)
    assert resp.status_code == 404, resp.text


async def test_safe_list_raises_instead_of_empty() -> None:
    class _BrokenSession:
        async def execute(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        await _safe_list(_BrokenSession(), ThreatIndicator, org_id="org-1")


async def test_safe_list_requires_org_for_tenant_models() -> None:
    with pytest.raises(HTTPException) as exc:
        await _safe_list(object(), ThreatIndicator, org_id=None)
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "organization_required"


async def test_indicators_scoped_with_platform_rows(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    db_session.add_all(
        [
            _indicator("198.51.100.1", org_a_id),
            _indicator("198.51.100.2", org_b_id),
            _indicator("198.51.100.3", None),
        ],
    )
    await db_session.commit()

    resp = await client.get("/api/v1/threat-intel/indicators", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    values = {item["value"] for item in resp.json()["items"]}
    assert values == {"198.51.100.1", "198.51.100.3"}

    resp = await client.get("/api/v1/threat-intel/indicators", headers=org_b_headers)
    values = {item["value"] for item in resp.json()["items"]}
    assert values == {"198.51.100.2", "198.51.100.3"}


async def test_itdr_anomalies_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    profile = IdentityProfile(
        organization_id=org_a_id,
        user_id=str(uuid.uuid4()),
        username="alice",
        email="alice@pysoar-tests.io",
    )
    db_session.add(profile)
    await db_session.flush()
    db_session.add(
        AccessAnomaly(
            organization_id=org_a_id,
            identity_id=profile.id,
            anomaly_type="impossible_travel",
        ),
    )
    await db_session.commit()

    resp_a = await client.get("/api/v1/itdr/anomalies", headers=org_a_headers)
    resp_b = await client.get("/api/v1/itdr/anomalies", headers=org_b_headers)
    assert resp_a.status_code == 200, resp_a.text
    assert resp_a.json()["total"] == 1
    assert resp_b.json()["total"] == 0
