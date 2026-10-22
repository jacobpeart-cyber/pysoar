"""The flat webhook list (GET /integrations/webhooks) is a generic row dump;
the shared secret's bcrypt hash must never be in it."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from src.integrations.models import WebhookEndpoint
from tests.unit.connector_fakes import VALID_FIELDS

BASE = "/api/v1/integrations"


@pytest.mark.asyncio
async def test_flat_webhook_list_never_returns_the_secret_hash(client, db_session, org_a_admin_headers, org_a_headers) -> None:
    config, credentials = VALID_FIELDS["virustotal"]
    installed = await client.post(
        f"{BASE}/install",
        json={"connector_id": "virustotal", "display_name": "VT", "config": config, "credentials": credentials},
        headers=org_a_admin_headers,
    )
    assert installed.status_code == 201, installed.text
    created = await client.post(
        f"{BASE}/installed/{installed.json()['id']}/webhooks",
        json={"endpoint_path": "/hooks/vt", "http_method": "POST", "event_types": ["scan.completed"], "secret": "wh-fixture-secret-0001"},
        headers=org_a_admin_headers,
    )
    assert created.status_code in (200, 201), created.text
    stored = (await db_session.execute(select(WebhookEndpoint.secret_hash))).scalars().first()
    assert stored and stored != "wh-fixture-secret-0001"

    flat = await client.get(f"{BASE}/webhooks", params={"size": 100}, headers=org_a_headers)
    assert flat.status_code == 200, flat.text
    items = flat.json()["items"]
    assert items and all("secret_hash" not in item for item in items)
    assert stored not in flat.text and "wh-fixture-secret-0001" not in flat.text
