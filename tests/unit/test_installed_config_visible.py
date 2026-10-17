"""The installed-integration view returns the stored NON-secret config (so the
Configure form can pre-fill it) and never the credentials."""
from __future__ import annotations

import pytest

from tests.unit.connector_fakes import VALID_FIELDS

BASE = "/api/v1/integrations"


@pytest.mark.asyncio
async def test_installed_view_shows_config_and_never_credentials(client, org_a_admin_headers, org_a_headers) -> None:
    _config, credentials = VALID_FIELDS["crowdstrike"]
    resp = await client.post(
        f"{BASE}/install",
        json={"connector_id": "crowdstrike", "display_name": "Falcon", "config": {"cloud": "us-2"}, "credentials": credentials},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["config"] == {"cloud": "us-2"}
    installed_id = resp.json()["id"]

    one = await client.get(f"{BASE}/installed/{installed_id}", headers=org_a_headers)
    assert one.status_code == 200, one.text
    assert one.json()["config"] == {"cloud": "us-2"}
    assert credentials["client_secret"] not in one.text and "client_secret" not in one.json().get("config", {})

    listed = await client.get(f"{BASE}/installed", params={"size": 100}, headers=org_a_headers)
    assert listed.status_code == 200, listed.text
    row = next(i for i in listed.json()["items"] if i["id"] == installed_id)
    assert row["config"] == {"cloud": "us-2"} and credentials["client_secret"] not in listed.text

    patched = await client.patch(f"{BASE}/installed/{installed_id}", json={"config": {"cloud": "eu-1"}}, headers=org_a_admin_headers)
    assert patched.status_code == 200, patched.text
    assert patched.json()["config"] == {"cloud": "eu-1"}
