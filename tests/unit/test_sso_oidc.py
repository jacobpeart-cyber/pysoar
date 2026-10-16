"""OIDC single sign-on: configuration routes, discovery, the authorization-code +
PKCE flow, ID token validation and the one-time login exchange, against a fake
identity provider (tests/unit/sso_fakes.py) that signs real RS256 ID tokens."""

from __future__ import annotations

import base64
import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient
from sqlalchemy import select

from src.core.security import decode_token_full
from src.identity import oidc
from src.identity.models import Role, SSOConfiguration
from src.models.audit import AuditLog
from src.models.user import User
from tests.helpers.tenancy import make_user
from tests.unit.sso_fakes import FakeIdP, configure, install, query, start, stateful_redis

DOMAIN = "acme-sso.io"


@pytest.fixture
def store(redis_mock):
    return stateful_redis(redis_mock)


@pytest.fixture
def idp(monkeypatch) -> FakeIdP:
    provider = FakeIdP()
    install(monkeypatch, provider)
    return provider


async def _audit_rows(db, action: str, org_id=None) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.action == action)
    if org_id is not None:
        stmt = stmt.where(AuditLog.organization_id == org_id)
    return list((await db.execute(stmt)).scalars().all())


async def _login(client: AsyncClient, idp: FakeIdP, slug: str, **claims) -> dict[str, str]:
    """Run start -> authorize -> callback; return the /login redirect's query."""
    resp = await start(client, slug)
    assert resp.status_code == 302, resp.text
    code, state = idp.authorize(resp.headers["location"], **claims)
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert cb.status_code == 302, cb.text
    assert cb.headers["location"].startswith("/login?")
    return query(cb.headers["location"])


# ---------------------------------------------------------------------------
# Configuration routes
# ---------------------------------------------------------------------------


def _body(idp: FakeIdP, **overrides) -> dict:
    body = {
        "protocol": "oidc",
        "display_name": "Acme IdP",
        "issuer": idp.issuer,
        "client_id": idp.client_id,
        "client_secret": idp.client_secret,
        "allowed_email_domains": [DOMAIN.upper(), "@" + DOMAIN],
        "jit_provisioning": True,
        "default_role": "viewer",
        "enabled": False,
    }
    body.update(overrides)
    return body


async def test_configure_test_enable_and_secret_never_returned(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeIdP, store,
) -> None:
    org_id = org_a.id
    assert (await client.get("/api/v1/settings/sso", headers=org_a_admin_headers)).json()["detail"]["error"] == "sso_not_configured"

    resp = await client.put("/api/v1/settings/sso", json=_body(idp), headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["client_secret_set"] is True
    assert "client_secret" not in data and idp.client_secret not in resp.text
    assert data["allowed_email_domains"] == [DOMAIN]
    assert data["redirect_uri"].endswith("/api/v1/auth/sso/callback")
    assert data["login_url"] == f"/api/v1/auth/sso/{org_a.slug}/start"

    # Enabling before a passing test is refused.
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, enabled=True), headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "sso_test_required"

    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    test = resp.json()
    assert test["status"] == "ok" and test["key_count"] == 1 and test["key_ids"] == [idp.kid]
    assert test["token_endpoint"] == f"{idp.issuer}/token"
    assert "openid" in test["scopes_supported"]

    # client_secret omitted keeps the stored one.
    body = _body(idp, enabled=True)
    body.pop("client_secret")
    resp = await client.put("/api/v1/settings/sso", json=body, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is True and resp.json()["client_secret_set"] is True
    stored = (await db_session.execute(select(SSOConfiguration).where(SSOConfiguration.organization_id == org_id))).scalar_one()
    assert stored.client_secret == idp.client_secret

    actions = {r.action for r in (await db_session.execute(select(AuditLog).where(AuditLog.organization_id == org_id))).scalars()}
    assert {"sso_config_create", "sso_config_update", "sso_config_test"} <= actions
    for row in (await db_session.execute(select(AuditLog).where(AuditLog.organization_id == org_id))).scalars():
        assert idp.client_secret not in (row.new_value or "") + (row.old_value or "")

    resp = await client.delete("/api/v1/settings/sso", headers=org_a_admin_headers)
    assert resp.status_code == 204
    assert await _audit_rows(db_session, "sso_config_delete", org_id)
    assert (await client.get("/api/v1/settings/sso", headers=org_a_admin_headers)).status_code == 404


async def test_changing_the_issuer_clears_the_test_result(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeIdP, store,
) -> None:
    await configure(db_session, org_a.id, idp)
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, issuer="https://other-idp.example.com", enabled=True),
                            headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "sso_test_required"


async def test_saml_is_501_not_implemented(client: AsyncClient, org_a_admin_headers, store) -> None:
    resp = await client.put("/api/v1/settings/sso", json={"protocol": "saml"}, headers=org_a_admin_headers)
    assert resp.status_code == 501
    detail = resp.json()["detail"]
    assert detail["error"] == "not_implemented" and detail["reason"] == "saml_requires_xmlsec"


@pytest.mark.parametrize(
    ("overrides", "status_code", "error"),
    [
        ({"issuer": "http://idp.example.com"}, 422, "invalid_issuer"),
        ({"client_id": ""}, 422, "missing_field"),
        ({"scopes": "email profile"}, 422, "invalid_scopes"),
        ({"allowed_email_domains": ["not a domain"]}, 422, "invalid_email_domain"),
        ({"default_role": "superadmin"}, 422, "unknown_role"),
        ({"group_role_map": {"soc": "no-such-role"}}, 422, "unknown_role"),
        ({"protocol": "ldap"}, 422, "unsupported_protocol"),
        ({"allowed_email_domains": [], "enabled": True}, 422, "allowed_email_domains_required"),
    ],
)
async def test_configuration_validation(
    client: AsyncClient, org_a_admin_headers, idp: FakeIdP, store, overrides, status_code, error,
) -> None:
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, **overrides), headers=org_a_admin_headers)
    assert resp.status_code == status_code, resp.text
    assert resp.json()["detail"]["error"] == error


async def test_custom_role_by_name_is_an_allowed_mapping(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeIdP, store,
) -> None:
    db_session.add(Role(organization_id=org_a.id, name="Tier 1", default_tier="read", area_tiers={}))
    await db_session.commit()
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, group_role_map={"soc-t1": "Tier 1"}),
                            headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text


async def test_test_failure_is_502_and_recorded(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeIdP, store,
) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, idp, enabled=False, last_test_status=None)
    idp.advertised_issuer = "https://evil.example.com"
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert detail["error"] == "sso_test_failed" and detail["reason"] == "discovery_failed"
    assert "does not match" in detail["detail"]
    db_session.expire_all()
    stored = (await db_session.execute(select(SSOConfiguration).where(SSOConfiguration.organization_id == org_id))).scalar_one()
    assert stored.last_test_status == "failed" and "does not match" in stored.last_test_detail
    rows = await _audit_rows(db_session, "sso_config_test", org_id)
    assert rows and rows[-1].success is False


async def test_test_refuses_internal_targets_through_netguard(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, store,
) -> None:
    """No fake provider here: the real boundary refuses a loopback issuer."""
    await configure(db_session, org_a.id, FakeIdP(issuer="https://127.0.0.1:8443"), enabled=False)
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 502
    assert resp.json()["detail"]["reason"] == "provider_unreachable"
    assert "outbound target refused" in resp.json()["detail"]["detail"]


# ---------------------------------------------------------------------------
# Discover and start
# ---------------------------------------------------------------------------


async def test_discover_allowed_vs_unknown_domain(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    slug = org_a.slug
    await configure(db_session, org_a.id, idp)
    resp = await client.post("/api/v1/auth/sso/discover", json={"email": f"Someone@{DOMAIN.upper()}"})
    assert resp.status_code == 200
    assert resp.json() == {"available": True, "organization_slug": slug, "display_name": "Acme IdP",
                           "login_url": f"/api/v1/auth/sso/{slug}/start"}
    resp = await client.post("/api/v1/auth/sso/discover", json={"email": "someone@unknown.test"})
    assert resp.json() == {"available": False, "organization_slug": None, "display_name": None, "login_url": None}


async def test_discover_ignores_disabled_configuration(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    await configure(db_session, org_a.id, idp, enabled=False)
    resp = await client.post("/api/v1/auth/sso/discover", json={"email": f"a@{DOMAIN}"})
    assert resp.json()["available"] is False


async def test_start_stores_state_and_sends_pkce(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, idp)
    resp = await start(client, org_a.slug)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(f"{idp.issuer}/authorize?")
    params = query(location)
    assert params["response_type"] == "code" and params["scope"] == "openid email profile"
    assert params["code_challenge_method"] == "S256" and params["nonce"] and params["state"]
    assert params["redirect_uri"].endswith("/api/v1/auth/sso/callback")
    pending = json.loads(store[oidc.STATE_KEY.format(params["state"])])
    assert pending["organization_id"] == org_id and pending["nonce"] == params["nonce"]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(pending["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert challenge == params["code_challenge"]
    assert 43 <= len(pending["code_verifier"]) <= 128


async def test_start_unknown_or_disabled_org_redirects_with_error(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    resp = await start(client, "no-such-org")
    assert resp.status_code == 302 and resp.headers["location"] == "/login?sso_error=sso_unavailable"
    await configure(db_session, org_a.id, idp, enabled=False)
    resp = await start(client, org_a.slug)
    assert resp.headers["location"] == "/login?sso_error=sso_unavailable"


# ---------------------------------------------------------------------------
# Callback and exchange
# ---------------------------------------------------------------------------


async def test_happy_path_jit_create_then_exchange_once(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, idp)
    result = await _login(client, idp, org_a.slug, sub="sub-123", email=f"Jane@{DOMAIN}")
    assert "sso" in result and "sso_error" not in result

    user = (await db_session.execute(select(User).where(User.email == f"jane@{DOMAIN}"))).scalar_one()
    user_id = user.id
    assert user.organization_id == org_id and user.identity_source == "oidc" and user.sso_subject == "sub-123"
    assert user.role == "viewer" and user.full_name == "Jane Doe" and user.force_password_change is False
    assert await _audit_rows(db_session, "sso_user_provisioned", org_id)

    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert resp.status_code == 200, resp.text
    tokens = resp.json()
    payload = decode_token_full(tokens["access_token"])
    assert payload["sub"] == user_id and payload["type"] == "access" and "gen" in payload
    assert tokens["refresh_token"] and tokens["expires_in"] > 0
    me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200 and me.json()["email"] == f"jane@{DOMAIN}"
    assert await _audit_rows(db_session, "sso_login", org_id)

    again = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert again.status_code == 401 and again.json()["detail"]["error"] == "invalid_sso_code"

    # The provisioned account has no usable password.
    login = await client.post("/api/v1/auth/login", json={"email": f"jane@{DOMAIN}", "password": "anything-at-all"})
    assert login.status_code == 401


async def test_second_login_matches_by_subject(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    await configure(db_session, org_a.id, idp)
    await _login(client, idp, org_a.slug, sub="sub-1", email=f"jane@{DOMAIN}")
    # Email changed at the IdP; the subject still identifies the same account.
    result = await _login(client, idp, org_a.slug, sub="sub-1", email=f"jane.doe@{DOMAIN}")
    assert "sso" in result
    users = (await db_session.execute(select(User).where(User.sso_subject == "sub-1"))).scalars().all()
    assert len(users) == 1


async def test_existing_user_is_bound_by_email(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, idp, jit_provisioning=False)
    user = await make_user(db_session, role="analyst", organization_id=org_id, label="bob")
    user_id = user.id
    user.email = f"bob@{DOMAIN}"
    await db_session.commit()
    result = await _login(client, idp, slug, sub="bob-sub", email=f"bob@{DOMAIN}")
    assert "sso" in result
    db_session.expire_all()
    bound = (await db_session.execute(select(User).where(User.id == user_id))).scalar_one()
    assert bound.sso_subject == "bob-sub" and bound.identity_source == "local" and bound.role == "analyst"
    assert await _audit_rows(db_session, "sso_subject_bound", org_id)

    # Another subject asserting the same email is refused.
    result = await _login(client, idp, slug, sub="someone-else", email=f"bob@{DOMAIN}")
    assert result == {"sso_error": "subject_mismatch"}


async def test_group_mapping_picks_the_role(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    role = Role(organization_id=org_a.id, name="Hunters", default_tier="read", area_tiers={"hunting": "write"})
    db_session.add(role)
    await db_session.commit()
    role_id = role.id
    await configure(db_session, org_a.id, idp, groups_claim="groups",
                    group_role_map={"soc-analysts": "analyst", "hunters": "Hunters"})
    await _login(client, idp, org_a.slug, sub="a1", email=f"ann@{DOMAIN}", groups=["everyone", "soc-analysts"])
    await _login(client, idp, org_a.slug, sub="h1", email=f"hal@{DOMAIN}", groups=["hunters"])
    await _login(client, idp, org_a.slug, sub="v1", email=f"vic@{DOMAIN}", groups=["everyone"])
    by_email = {u.email: u for u in (await db_session.execute(select(User).where(User.organization_id == org_a.id))).scalars()}
    assert by_email[f"ann@{DOMAIN}"].role == "analyst" and by_email[f"ann@{DOMAIN}"].custom_role_id is None
    assert by_email[f"hal@{DOMAIN}"].custom_role_id == role_id and by_email[f"hal@{DOMAIN}"].role == "viewer"
    assert by_email[f"vic@{DOMAIN}"].role == "viewer"


def _expired(idp: FakeIdP) -> None:
    idp.claims["exp"] = int(time.time()) - 3600
    idp.claims["iat"] = int(time.time()) - 7200


def _wrong_aud(idp: FakeIdP) -> None:
    idp.claims["aud"] = "someone-elses-client"


def _unknown_kid(idp: FakeIdP) -> None:
    idp.sign_kid = "rotated-away"


def _foreign_key(idp: FakeIdP) -> None:
    idp.sign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _wrong_nonce(idp: FakeIdP) -> None:
    idp.claims["nonce"] = "not-the-nonce"


def _wrong_issuer(idp: FakeIdP) -> None:
    idp.claims["iss"] = "https://evil.example.com"


@pytest.mark.parametrize(
    ("tamper", "needle"),
    [
        (_wrong_nonce, "nonce"),
        (_wrong_aud, "audience"),
        (_expired, "expired"),
        (_unknown_kid, "rotated-away"),
        (_foreign_key, "Signature"),
        (_wrong_issuer, "issuer"),
    ],
)
async def test_bad_id_tokens_are_refused_and_audited(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store, tamper, needle,
) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, idp)
    resp = await start(client, org_a.slug)
    code, state = idp.authorize(resp.headers["location"], sub="x", email=f"x@{DOMAIN}")
    tamper(idp)
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert cb.headers["location"] == "/login?sso_error=invalid_id_token"
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert rows and rows[-1].success is False and needle in rows[-1].error_message
    assert (await db_session.execute(select(User).where(User.email == f"x@{DOMAIN}"))).scalar_one_or_none() is None
    if tamper is _unknown_kid:
        # The JWKS was refetched once for the unknown key, then refused.
        assert idp.calls_to("/jwks") == 2


async def test_unknown_kid_after_key_rotation_is_accepted_after_refetch(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    await configure(db_session, org_a.id, idp)
    await _login(client, idp, org_a.slug, sub="r1", email=f"r1@{DOMAIN}")  # caches the JWKS
    assert idp.calls_to("/jwks") == 1
    idp.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp.kid = "key-2"
    result = await _login(client, idp, org_a.slug, sub="r1", email=f"r1@{DOMAIN}")
    assert "sso" in result
    assert idp.calls_to("/jwks") == 2


async def test_hs256_token_is_refused(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    jwks = idp.jwks()
    token = jwt.encode({"iss": idp.issuer, "aud": idp.client_id, "sub": "x", "nonce": "n",
                        "iat": int(time.time()), "exp": int(time.time()) + 60},
                       idp.client_secret, algorithm="HS256", headers={"kid": idp.kid})
    with pytest.raises(oidc.OIDCError) as exc:
        oidc.validate_id_token(token, jwks, issuer=idp.issuer, client_id=idp.client_id, nonce="n")
    assert "not accepted" in exc.value.detail


@pytest.mark.parametrize(
    ("claims", "overrides", "reason"),
    [
        ({"email": "jane@elsewhere.test"}, {}, "email_domain_not_allowed"),
        ({"email_verified": False}, {}, "email_not_verified"),
        ({"email": None}, {}, "email_missing"),
        ({}, {"jit_provisioning": False}, "user_not_provisioned"),
    ],
)
async def test_identity_refusals(client: AsyncClient, db_session, org_a, idp: FakeIdP, store, claims, overrides, reason) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, idp, **overrides)
    resp = await start(client, org_a.slug)
    code, state = idp.authorize(resp.headers["location"], sub="s", email=f"jane@{DOMAIN}")
    idp.claims.update(claims)
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert cb.headers["location"] == f"/login?sso_error={reason}"
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert rows and rows[-1].description.endswith(reason)


async def test_unverified_email_allowed_when_not_required(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    await configure(db_session, org_a.id, idp, require_email_verified=False)
    result = await _login(client, idp, org_a.slug, sub="u", email=f"u@{DOMAIN}", email_verified=None)
    assert "sso" in result


async def test_deactivated_user_is_refused(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    await configure(db_session, org_a.id, idp)
    await _login(client, idp, org_a.slug, sub="d", email=f"d@{DOMAIN}")
    user = (await db_session.execute(select(User).where(User.email == f"d@{DOMAIN}"))).scalar_one()
    user.is_active = False
    await db_session.commit()
    result = await _login(client, idp, org_a.slug, sub="d", email=f"d@{DOMAIN}")
    assert result == {"sso_error": "user_inactive"}


async def test_state_replay_is_refused(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    await configure(db_session, org_a.id, idp)
    resp = await start(client, org_a.slug)
    code, state = idp.authorize(resp.headers["location"], sub="s", email=f"s@{DOMAIN}")
    first = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert "sso=" in first.headers["location"]
    replay = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert replay.headers["location"] == "/login?sso_error=invalid_state"
    forged = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": "made-up"}, follow_redirects=False)
    assert forged.headers["location"] == "/login?sso_error=invalid_state"
    assert await _audit_rows(db_session, "sso_login_failed")


async def test_idp_error_and_token_failure_never_leak_provider_text(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, idp)
    resp = await start(client, org_a.slug)
    _code, state = idp.authorize(resp.headers["location"])
    cb = await client.get("/api/v1/auth/sso/callback",
                          params={"error": "access_denied", "error_description": "<script>x</script>", "state": state},
                          follow_redirects=False)
    assert cb.headers["location"] == "/login?sso_error=idp_error"

    idp.token_status = 500
    resp = await start(client, org_a.slug)
    code, state = idp.authorize(resp.headers["location"])
    cb = await client.get("/api/v1/auth/sso/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert cb.headers["location"] == "/login?sso_error=token_exchange_failed"
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert any("HTTP 500" in (r.error_message or "") for r in rows)


async def test_untrusted_idp_mfa_answers_the_mfa_challenge(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    await configure(db_session, org_a.id, idp, trust_idp_mfa=False)
    result = await _login(client, idp, org_a.slug, sub="m", email=f"m@{DOMAIN}")
    user = (await db_session.execute(select(User).where(User.email == f"m@{DOMAIN}"))).scalar_one()
    user.mfa_enabled = True
    user.mfa_secret = "JBSWY3DPEHPK3PXP"
    await db_session.commit()
    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mfa_required"] is True and "access_token" not in body
    assert decode_token_full(body["mfa_token"])["type"] == "mfa"


async def test_trusted_idp_mfa_skips_the_challenge(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    await configure(db_session, org_a.id, idp, trust_idp_mfa=True)
    result = await _login(client, idp, org_a.slug, sub="m2", email=f"m2@{DOMAIN}")
    user = (await db_session.execute(select(User).where(User.email == f"m2@{DOMAIN}"))).scalar_one()
    user.mfa_enabled = True
    await db_session.commit()
    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert "access_token" in resp.json()


async def test_forced_password_change_never_applies_to_sso_accounts(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    await configure(db_session, org_a.id, idp)
    result = await _login(client, idp, org_a.slug, sub="f", email=f"f@{DOMAIN}")
    user = (await db_session.execute(select(User).where(User.email == f"f@{DOMAIN}"))).scalar_one()
    user.force_password_change = True
    await db_session.commit()
    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert resp.status_code == 200 and "access_token" in resp.json()


async def test_password_reset_refuses_sso_managed_accounts(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    from datetime import datetime, timedelta, timezone

    await configure(db_session, org_a.id, idp)
    await _login(client, idp, org_a.slug, sub="p", email=f"p@{DOMAIN}")
    user = (await db_session.execute(select(User).where(User.email == f"p@{DOMAIN}"))).scalar_one()
    token = "t" * 64
    user.password_reset_token = token
    user.password_reset_token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    await db_session.commit()
    for path, body in (("/api/v1/auth/password-reset/validate", {"token": token}),
                       ("/api/v1/auth/password-reset/consume", {"token": token, "new_password": "A-very-long-pass-123!"})):
        resp = await client.post(path, json=body)
        assert resp.status_code == 409, resp.text
        assert resp.json()["detail"]["error"] == "sso_managed"


async def test_exchange_rejects_unknown_code(client: AsyncClient, store) -> None:
    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": "x" * 43})
    assert resp.status_code == 401 and resp.json()["detail"]["error"] == "invalid_sso_code"


# ---------------------------------------------------------------------------
# Escalation guards (custom-role admins, superuser accounts)
# ---------------------------------------------------------------------------


async def _custom_role_admin(db, org_id: str) -> dict[str, str]:
    """A user whose custom role holds admin in Settings and write elsewhere."""
    from tests.helpers.tenancy import bearer

    role = Role(organization_id=org_id, name="Settings admin", default_tier="write", area_tiers={"settings": "admin"})
    db.add(role)
    await db.commit()
    role_id = role.id
    user = await make_user(db, role="viewer", organization_id=org_id, label="custom-admin")
    user.custom_role_id = role_id
    await db.commit()
    return bearer(user)


def _unchanged_body(idp: FakeIdP, **overrides) -> dict:
    """The trust settings ``configure`` stored, so only the named fields change."""
    body = {
        "protocol": "oidc", "display_name": "Acme IdP", "issuer": idp.issuer, "client_id": idp.client_id,
        "allowed_email_domains": [DOMAIN], "jit_provisioning": True, "default_role": "viewer",
        "require_email_verified": True, "trust_idp_mfa": True, "enabled": True,
    }
    body.update(overrides)
    return body


async def test_custom_role_admin_cannot_map_a_group_above_their_tiers(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    await configure(db_session, org_a.id, idp)
    headers = await _custom_role_admin(db_session, org_a.id)
    resp = await client.put("/api/v1/settings/sso", json=_unchanged_body(idp, group_role_map={"soc": "admin"}),
                            headers=headers)
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "tier_exceeds_caller" and "alerts" in detail["areas"] and "settings" not in detail["areas"]
    resp = await client.put("/api/v1/settings/sso", json=_unchanged_body(idp, default_role="admin"), headers=headers)
    assert resp.status_code == 403 and resp.json()["detail"]["error"] == "tier_exceeds_caller"
    # Within their tiers (analyst = write everywhere) is fine.
    resp = await client.put("/api/v1/settings/sso", json=_unchanged_body(idp, group_role_map={"soc": "analyst"}),
                            headers=headers)
    assert resp.status_code == 200, resp.text


async def test_custom_role_admin_cannot_change_trust_settings(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    await configure(db_session, org_a.id, idp)
    headers = await _custom_role_admin(db_session, org_a.id)
    for overrides, field in (
        ({"issuer": "https://attacker-idp.example.com"}, "issuer"),
        ({"client_secret": "new"}, "client_secret"),
        ({"allowed_email_domains": [DOMAIN, "other.io"]}, "allowed_email_domains"),
        ({"require_email_verified": False}, "require_email_verified"),
        ({"trust_idp_mfa": False}, "trust_idp_mfa"),
        ({"jit_provisioning": False}, "jit_provisioning"),
        ({"enabled": False}, "enabled"),
    ):
        resp = await client.put("/api/v1/settings/sso", json=_unchanged_body(idp, **overrides), headers=headers)
        assert resp.status_code == 403, (field, resp.text)
        detail = resp.json()["detail"]
        assert detail["error"] == "full_admin_required" and detail["fields"] == [field]
    resp = await client.put("/api/v1/settings/sso", json=_unchanged_body(idp, display_name="Corp login"), headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["display_name"] == "Corp login"
    resp = await client.delete("/api/v1/settings/sso", headers=headers)
    assert resp.status_code == 403 and resp.json()["detail"]["error"] == "full_admin_required"


async def test_custom_role_admin_cannot_create_a_configuration(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    headers = await _custom_role_admin(db_session, org_a.id)
    resp = await client.put("/api/v1/settings/sso", json=_body(idp), headers=headers)
    assert resp.status_code == 403 and resp.json()["detail"]["error"] == "full_admin_required"


async def test_superuser_account_is_never_bound(client: AsyncClient, db_session, org_a, idp: FakeIdP, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, idp)
    su = await make_user(db_session, role="admin", organization_id=org_id, is_superuser=True, label="su")
    su_id = su.id
    su.email = f"root@{DOMAIN}"
    await db_session.commit()
    result = await _login(client, idp, slug, sub="root-sub", email=f"root@{DOMAIN}")
    assert result == {"sso_error": "superuser_not_allowed"}
    db_session.expire_all()
    assert (await db_session.execute(select(User).where(User.id == su_id))).scalar_one().sso_subject is None
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert rows and rows[-1].description.endswith("superuser_not_allowed")


async def test_custom_role_admin_cannot_change_the_claims(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    await configure(db_session, org_a.id, idp)
    headers = await _custom_role_admin(db_session, org_a.id)
    for overrides, field in (
        ({"email_claim": "preferred_username", "require_email_verified": True}, "email_claim"),
        ({"groups_claim": "roles"}, "groups_claim"),
    ):
        resp = await client.put("/api/v1/settings/sso", json=_unchanged_body(idp, **overrides), headers=headers)
        assert resp.status_code == 403, (field, resp.text)
        assert resp.json()["detail"]["error"] == "full_admin_required" and field in resp.json()["detail"]["fields"]


async def test_non_default_email_claim_needs_verification_off(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeIdP, store,
) -> None:
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, email_claim="upn", require_email_verified=True),
                            headers=org_a_admin_headers)
    assert resp.status_code == 422 and resp.json()["detail"]["error"] == "email_claim_requires_unverified"
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, email_claim="upn", require_email_verified=False),
                            headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text


async def test_email_verified_never_vouches_for_another_claim(
    client: AsyncClient, db_session, org_a, idp: FakeIdP, store,
) -> None:
    """A row stored before the PUT rule (or written directly) still refuses at login."""
    await configure(db_session, org_a.id, idp, email_claim="upn", require_email_verified=True)
    result = await _login(client, idp, org_a.slug, sub="u", email=f"x@{DOMAIN}", upn=f"boss@{DOMAIN}")
    assert result == {"sso_error": "email_not_verified"}
