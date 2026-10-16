"""SSO tenancy and role gates: each organisation's configuration is its own,
an organisation's slug only ever uses its own identity provider, and the
configuration routes are admin-only and org-scoped."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.identity.models import SSOConfiguration
from src.models.user import User
from tests.helpers.tenancy import bearer, make_user
from tests.unit.sso_fakes import FakeIdP, configure, install, query, start, stateful_redis

ADMIN_ROUTES = [
    ("GET", "/api/v1/settings/sso"),
    ("PUT", "/api/v1/settings/sso"),
    ("DELETE", "/api/v1/settings/sso"),
    ("POST", "/api/v1/settings/sso/test"),
]


@pytest.fixture
def store(redis_mock):
    return stateful_redis(redis_mock)


@pytest.fixture
def idps(monkeypatch) -> tuple[FakeIdP, FakeIdP]:
    a = FakeIdP(issuer="https://idp-a.example.com", client_id="client-a", client_secret="secret-a")
    b = FakeIdP(issuer="https://idp-b.example.com", client_id="client-b", client_secret="secret-b")
    install(monkeypatch, a, b)
    return a, b


def _body(idp: FakeIdP, domain: str) -> dict:
    return {"issuer": idp.issuer, "client_id": idp.client_id, "client_secret": idp.client_secret,
            "allowed_email_domains": [domain], "enabled": False}


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
@pytest.mark.parametrize("who", ["viewer_headers", "org_a_headers"])
async def test_admin_routes_refuse_viewers_and_analysts(
    client: AsyncClient, viewer_headers, org_a_headers, store, idps, method: str, path: str, who: str,
) -> None:
    headers = {"viewer_headers": viewer_headers, "org_a_headers": org_a_headers}[who]
    resp = await client.request(method, path, headers=headers, json=_body(idps[0], "a-corp.io"))
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
async def test_orgless_superuser_gets_organization_required(
    client: AsyncClient, superuser_headers, store, idps, method: str, path: str,
) -> None:
    resp = await client.request(method, path, headers=superuser_headers, json=_body(idps[0], "a-corp.io"))
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_required"


async def test_admin_of_a_cannot_see_or_change_b(
    client: AsyncClient, db_session, org_a, org_b, org_a_admin_headers, store, idps,
) -> None:
    org_b_id = org_b.id
    await configure(db_session, org_b_id, idps[1], domains=("b-corp.io",))
    assert (await client.get("/api/v1/settings/sso", headers=org_a_admin_headers)).status_code == 404
    assert (await client.delete("/api/v1/settings/sso", headers=org_a_admin_headers)).status_code == 404
    assert (await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)).status_code == 404

    # A's PUT creates A's own row; B's stays as it was.
    resp = await client.put("/api/v1/settings/sso", json=_body(idps[0], "a-corp.io"), headers=org_a_admin_headers)
    assert resp.status_code == 200 and resp.json()["organization_id"] != org_b_id
    db_session.expire_all()
    b_row = (await db_session.execute(select(SSOConfiguration).where(SSOConfiguration.organization_id == org_b_id))).scalar_one()
    assert b_row.issuer == idps[1].issuer and b_row.client_id == "client-b"

    # A cannot claim B's email domain.
    resp = await client.put("/api/v1/settings/sso", json=_body(idps[0], "b-corp.io"), headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "email_domain_claimed"


async def test_b_admin_sees_only_b(client: AsyncClient, db_session, org_a, org_b, store, idps) -> None:
    await configure(db_session, org_a.id, idps[0], domains=("a-corp.io",))
    await configure(db_session, org_b.id, idps[1], domains=("b-corp.io",))
    b_admin = await make_user(db_session, role="admin", organization_id=org_b.id, label="admin-b")
    resp = await client.get("/api/v1/settings/sso", headers=bearer(b_admin))
    assert resp.status_code == 200 and resp.json()["issuer"] == idps[1].issuer


async def test_slug_uses_only_its_own_provider(client: AsyncClient, db_session, org_a, org_b, store, idps) -> None:
    slug_a, slug_b = org_a.slug, org_b.slug
    await configure(db_session, org_b.id, idps[1], domains=("b-corp.io",))
    # A has no configuration: B's is never used for A's slug.
    resp = await start(client, slug_a)
    assert resp.headers["location"] == "/login?sso_error=sso_unavailable"

    await configure(db_session, org_a.id, idps[0], domains=("a-corp.io",))
    assert (await start(client, slug_a)).headers["location"].startswith(idps[0].issuer + "/authorize?")
    assert (await start(client, slug_b)).headers["location"].startswith(idps[1].issuer + "/authorize?")
    assert query((await start(client, slug_a)).headers["location"])["client_id"] == "client-a"


async def test_b_provider_cannot_sign_in_an_org_a_user(
    client: AsyncClient, db_session, org_a, org_b, store, idps,
) -> None:
    """B's IdP asserting the email of an org A user neither binds nor signs in that user."""
    slug_b = org_b.slug
    await configure(db_session, org_b.id, idps[1], domains=("shared-corp.io",), jit_provisioning=True)
    victim = await make_user(db_session, role="admin", organization_id=org_a.id, label="victim")
    victim_id = victim.id
    victim.email = "boss@shared-corp.io"
    await db_session.commit()

    resp = await start(client, slug_b)
    code, state = idps[1].authorize(resp.headers["location"], sub="attacker", email="boss@shared-corp.io")
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert cb.headers["location"] == "/login?sso_error=account_conflict"
    db_session.expire_all()
    still = (await db_session.execute(select(User).where(User.id == victim_id))).scalar_one()
    assert still.sso_subject is None


async def test_state_from_one_org_cannot_be_redeemed_with_another_provider_code(
    client: AsyncClient, db_session, org_a, org_b, store, idps,
) -> None:
    slug_a, slug_b = org_a.slug, org_b.slug
    await configure(db_session, org_a.id, idps[0], domains=("a-corp.io",))
    await configure(db_session, org_b.id, idps[1], domains=("b-corp.io",))
    resp_a = await start(client, slug_a)
    _code_a, state_a = idps[0].authorize(resp_a.headers["location"], sub="a", email="a@a-corp.io")
    resp_b = await start(client, slug_b)
    code_b, _state_b = idps[1].authorize(resp_b.headers["location"], sub="b", email="b@b-corp.io")
    # A's state with B's code: the exchange runs at A's provider, which never issued that code.
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code_b, "state": state_a}, follow_redirects=False)
    assert cb.headers["location"] == "/login?sso_error=token_exchange_failed"


async def test_exchange_code_is_bound_to_the_users_org(
    client: AsyncClient, db_session, org_a, store, idps,
) -> None:
    """A login code always names the organisation it was minted for."""
    slug_a = org_a.slug
    org_a_id = org_a.id
    await configure(db_session, org_a_id, idps[0], domains=("a-corp.io",))
    resp = await start(client, slug_a)
    code, state = idps[0].authorize(resp.headers["location"], sub="a", email="a@a-corp.io")
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    login_code = query(cb.headers["location"])["sso"]
    import json as _json

    entry = _json.loads(store[f"sso:login:{login_code}"])
    assert entry["organization_id"] == org_a_id
    # Tamper with the stored organisation: the user is not found there, so no tokens.
    entry["organization_id"] = "00000000-0000-0000-0000-000000000000"
    store[f"sso:login:{login_code}"] = _json.dumps(entry)
    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": login_code})
    assert resp.status_code == 401


async def test_same_issuer_in_two_orgs_never_shares_cached_keys(
    client: AsyncClient, db_session, org_a, org_b, store, monkeypatch,
) -> None:
    """Org B names org A's issuer but a discovery document it controls (same host,
    same kid, another key). B's cached JWKS must never verify A's logins."""
    import httpx

    issuer = "https://idp.shared.example.com"
    idp_a = FakeIdP(issuer=issuer, client_id="client-a", client_secret="secret-a")
    idp_b = FakeIdP(issuer=issuer, client_id="client-b", client_secret="secret-b")  # same kid "key-1"
    b_base = f"{issuer}/tenant-b"

    async def fake_http(method, url, *, data=None, headers=None):
        request = httpx.Request(method, url)
        if url.startswith(b_base + "/"):
            idp_b.calls.append((method, url))
            if url.endswith("/openid-configuration"):
                doc = idp_b.discovery()
                doc.update(jwks_uri=f"{b_base}/jwks", token_endpoint=f"{b_base}/token")
                return httpx.Response(200, json=doc, request=request)
            if url.endswith("/jwks"):
                return httpx.Response(200, json=idp_b.jwks(), request=request)
            if url.endswith("/token"):
                return idp_b._token(request, data or {}, headers or {})
        return await idp_a.handle(method, url, data=data, headers=headers)

    monkeypatch.setattr("src.identity.oidc._http_request", fake_http)
    slug_a, slug_b = org_a.slug, org_b.slug
    await configure(db_session, org_a.id, idp_a, domains=("a-corp.io",))
    await configure(db_session, org_b.id, idp_b, domains=("b-corp.io",),
                    discovery_url=f"{b_base}/.well-known/openid-configuration")

    # B signs in first, caching its own discovery document and keys.
    resp = await start(client, slug_b)
    code, state = idp_b.authorize(resp.headers["location"], sub="b", email="b@b-corp.io")
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert "sso=" in cb.headers["location"], cb.headers["location"]

    # A's login still fetches and verifies against A's own keys.
    resp = await start(client, slug_a)
    code, state = idp_a.authorize(resp.headers["location"], sub="a", email="a@a-corp.io")
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert "sso=" in cb.headers["location"], cb.headers["location"]
    assert idp_a.calls_to(f"{issuer}/jwks") == 1 and idp_b.calls_to(f"{b_base}/jwks") == 1
    jwks_entries = [k for k in store if k.startswith("sso:jwks:")]
    discovery_entries = [k for k in store if k.startswith("sso:discovery:")]
    assert len(jwks_entries) == 2 and len(discovery_entries) == 2


async def test_discovery_url_must_be_on_the_issuer_host(
    client: AsyncClient, org_a_admin_headers, store, idps,
) -> None:
    body = _body(idps[0], "a-corp.io")
    body["discovery_url"] = "https://attacker.example.net/.well-known/openid-configuration"
    resp = await client.put("/api/v1/settings/sso", json=body, headers=org_a_admin_headers)
    assert resp.status_code == 422 and resp.json()["detail"]["error"] == "discovery_host_mismatch"
    body["discovery_url"] = f"{idps[0].issuer}/custom/.well-known/openid-configuration"
    resp = await client.put("/api/v1/settings/sso", json=body, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
