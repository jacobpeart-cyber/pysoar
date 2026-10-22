"""ITDR Okta auth (src/itdr/directory.py::_okta_auth): the catalogue install shape
(credentials.domain + credentials.api_token) and the earlier config.base_url shape.

The credential values are test fixtures, not real secrets.
"""

from __future__ import annotations

import json

import httpx
import pytest

from src.integrations.models import InstalledIntegration
from src.itdr import directory
from src.itdr.directory import DirectoryError, _okta_auth
from tests.unit.connector_fakes import VALID_FIELDS, ensure_connector_rows, fake_vendor, host_header

TOKEN = "okta-fixture-token-0001"


def test_catalogue_shape_derives_base_url_and_uses_api_token():
    base, headers = _okta_auth({}, {"domain": "acme.okta.com", "api_token": TOKEN})
    assert base == "https://acme.okta.com"
    assert headers["Authorization"] == f"SSWS {TOKEN}"


def test_earlier_shape_still_works_and_base_url_wins():
    base, headers = _okta_auth({"base_url": "https://legacy.okta.com/"}, {"api_key": TOKEN})
    assert base == "https://legacy.okta.com" and headers["Authorization"] == f"SSWS {TOKEN}"
    base, _ = _okta_auth({"base_url": "https://legacy.okta.com"}, {"domain": "acme.okta.com", "api_token": TOKEN})
    assert base == "https://legacy.okta.com"
    _, headers = _okta_auth({"base_url": "https://legacy.okta.com"}, {"token": TOKEN})
    assert headers["Authorization"] == f"SSWS {TOKEN}"


@pytest.mark.parametrize("config,credentials", [
    ({}, {}),
    ({}, {"domain": "acme.okta.com"}),          # no token
    ({}, {"api_token": TOKEN}),                  # no domain, no base_url
    ({"base_url": "https://acme.okta.com"}, {}),  # no token
])
def test_missing_pieces_name_both_shapes(config, credentials):
    with pytest.raises(DirectoryError) as exc:
        _okta_auth(config, credentials)
    message = str(exc.value)
    assert "credentials.domain + credentials.api_token" in message and "config.base_url" in message
    assert TOKEN not in message


@pytest.mark.parametrize("domain", [
    "https://acme.okta.com", "acme.okta.com/api", "acme.okta.com:8443", "user@acme.okta.com",
    "acme.okta.com?x=1", "acme.okta.com#f", " acme.okta.com", "acme okta.com", "10.0.0.5", "localhost",
])
def test_domain_with_scheme_path_or_port_is_refused(domain):
    with pytest.raises(DirectoryError) as exc:
        _okta_auth({}, {"domain": domain, "api_token": TOKEN})
    assert str(exc.value).startswith("Okta credentials.domain must be the org hostname")


def test_http_base_url_refused():
    with pytest.raises(DirectoryError, match="https"):
        _okta_auth({"base_url": "http://acme.okta.com"}, {"api_key": TOKEN})


@pytest.mark.asyncio
async def test_sync_with_catalogue_install_is_pinned_to_the_domain(db_session, monkeypatch):
    org_id = "okta-auth-org"
    await ensure_connector_rows(db_session, "okta")
    config, credentials = VALID_FIELDS["okta"]
    integ = InstalledIntegration(
        organization_id=org_id, connector_id="okta", display_name="Okta", status="active",
        config_encrypted=json.dumps(config), auth_credentials_encrypted="__plaintext__:" + json.dumps(credentials),
    )
    db_session.add(integ)
    await db_session.commit()
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    integ = (await db_session.execute(
        select(InstalledIntegration).options(selectinload(InstalledIntegration.connector))
        .where(InstalledIntegration.id == integ.id),
    )).scalar_one()

    def handler(request: httpx.Request) -> httpx.Response:
        assert host_header(request) == "acme.okta.com"
        assert request.headers["authorization"] == f"SSWS {TOKEN}"
        if request.url.path == "/api/v1/users":
            return httpx.Response(200, json=[{
                "id": "00u1", "status": "ACTIVE", "profile": {"login": "ada@corp.io", "email": "ada@corp.io"},
            }])
        return httpx.Response(403, json={"errorSummary": "not allowed"})

    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    fake_vendor(monkeypatch, handler)  # DNS steered to a public address
    monkeypatch.setattr(directory, "_inner_transport", lambda: httpx.MockTransport(record))
    summary = await directory.sync_integration(db_session, org_id, integ)
    assert summary["fetched"] == 1 and summary["created"] == 1
    assert seen and all(host_header(r) == "acme.okta.com" for r in seen)
