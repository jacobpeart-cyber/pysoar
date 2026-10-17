"""SAML 2.0 single sign-on (service provider): configuration and test routes, SP
metadata, the HTTP-Redirect AuthnRequest, the HTTP-POST ACS with every
refusal, the browser-bound completion step and the one-time login exchange,
against a fake IdP (tests/unit/saml_fakes.py) that signs real assertions with
signxml."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient
from lxml import etree
from sqlalchemy import select

from src.core.security import decode_token_full
from src.identity import saml as saml_sp
from src.identity.models import Role, SSOConfiguration
from src.models.audit import AuditLog
from src.models.user import User
from tests.helpers.tenancy import bearer, make_user
from tests.unit.saml_fakes import (
    NAMEID_PERSISTENT,
    FakeSAMLIdP,
    acs_url,
    configure,
    install,
    install_body,
    make_certificate,
    query,
    saml_redis,
    sp_entity_id,
)

DOMAIN = "acme-saml.io"


@pytest.fixture(autouse=True)
def store(redis_mock):
    """Every test gets a Redis mock with a real store (state, replay cache)."""
    return saml_redis(redis_mock)


@pytest.fixture
def idp(monkeypatch) -> FakeSAMLIdP:
    provider = FakeSAMLIdP()
    install(monkeypatch, provider)
    return provider


async def _audit_rows(db, action: str, org_id=None) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.action == action)
    if org_id is not None:
        stmt = stmt.where(AuditLog.organization_id == org_id)
    return list((await db.execute(stmt)).scalars().all())


async def _start(client: AsyncClient, idp: FakeSAMLIdP, slug: str) -> dict:
    resp = await client.get(f"/api/v1/auth/sso/{slug}/start", follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return idp.authn_request(resp.headers["location"])


async def _post_acs(client: AsyncClient, slug: str, saml_response: str, relay_state=None):
    data = {"SAMLResponse": saml_response}
    if relay_state is not None:
        data["RelayState"] = relay_state
    return await client.post(f"/api/v1/auth/sso/{slug}/saml/acs", data=data, follow_redirects=False)


async def _finish(client: AsyncClient, acs_resp) -> dict[str, str]:
    """Follow the ACS 303 to ``complete``; return the /login redirect's query."""
    assert acs_resp.status_code == 303, acs_resp.text
    location = acs_resp.headers["location"]
    if location.startswith("/login?"):
        return query(location)
    assert location.startswith("/api/v1/auth/sso/saml/complete?ticket="), location
    done = await client.get(location, follow_redirects=False)
    assert done.status_code == 302, done.text
    assert done.headers["location"].startswith("/login?")
    return query(done.headers["location"])


async def _login(client: AsyncClient, idp: FakeSAMLIdP, slug: str, **response_kwargs) -> dict[str, str]:
    request = await _start(client, idp, slug)
    acs = await _post_acs(client, slug, idp.response(request, **response_kwargs), request["relay_state"])
    return await _finish(client, acs)


# ---------------------------------------------------------------------------
# Configuration routes
# ---------------------------------------------------------------------------


def _body(idp: FakeSAMLIdP, **overrides) -> dict:
    saml = {"idp_sso_url": idp.sso_url, "idp_certificates": [idp.cert_b64], "want_response_signed": False,
            "clock_skew_seconds": 60}
    saml.update(overrides.pop("saml", {}))
    body = {
        "protocol": "saml",
        "display_name": "Acme SAML",
        "issuer": idp.entity_id,
        "allowed_email_domains": [DOMAIN],
        "jit_provisioning": True,
        "default_role": "viewer",
        "enabled": False,
        "saml": saml,
    }
    body.update(overrides)
    return body


async def test_configure_with_pasted_certificate_test_and_enable(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeSAMLIdP,
) -> None:
    org_id, slug = org_a.id, org_a.slug
    resp = await client.put("/api/v1/settings/sso", json=_body(idp), headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["protocol"] == "saml" and data["issuer"] == idp.entity_id
    assert data["client_id"] == sp_entity_id(slug) and data["client_secret_set"] is False
    assert data["require_email_verified"] is False and data["groups_claim"] == "groups"
    assert data["redirect_uri"] == acs_url(slug)
    saml = data["saml"]
    assert saml["sp_entity_id"] == sp_entity_id(slug) and saml["acs_url"] == acs_url(slug)
    assert saml["sp_metadata_url"] == sp_entity_id(slug) and saml["want_assertions_signed"] is True
    assert saml["idp_sso_url"] == idp.sso_url and len(saml["idp_certificates"]) == 1
    fingerprint = saml["idp_certificates"][0]["sha256_fingerprint"]
    assert fingerprint.replace(":", "").lower() == hashlib.sha256(base64.b64decode(idp.cert_b64)).hexdigest()

    resp = await client.put("/api/v1/settings/sso", json=_body(idp, enabled=True), headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "sso_test_required"

    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    test = resp.json()
    assert test["protocol"] == "saml" and test["source"] == "configuration" and test["certificate_count"] == 1
    assert any("not contacted" in w for w in test["warnings"])
    assert idp.calls == []

    # Certificates omitted keep the stored ones.
    body = _body(idp, enabled=True)
    body["saml"].pop("idp_certificates")
    resp = await client.put("/api/v1/settings/sso", json=body, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is True and len(resp.json()["saml"]["idp_certificates"]) == 1

    actions = {r.action for r in (await db_session.execute(select(AuditLog).where(AuditLog.organization_id == org_id))).scalars()}
    assert {"sso_config_create", "sso_config_update", "sso_config_test"} <= actions
    row = (await _audit_rows(db_session, "sso_config_create", org_id))[0]
    assert fingerprint in row.new_value and "BEGIN CERTIFICATE" not in row.new_value


async def test_metadata_url_test_imports_sso_url_and_certificates(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeSAMLIdP,
) -> None:
    org_id = org_a.id
    body = _body(idp, discovery_url=idp.metadata_url, saml={"idp_sso_url": None, "idp_certificates": []})
    resp = await client.put("/api/v1/settings/sso", json=body, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["saml"]["idp_certificates"] == []
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    test = resp.json()
    assert test["source"] == "metadata" and test["idp_sso_url"] == idp.sso_url and test["certificate_count"] == 1
    assert saml_sp.NAMEID_EMAIL in test["name_id_formats"]
    assert idp.calls == [("GET", idp.metadata_url)]
    db_session.expire_all()
    stored = (await db_session.execute(select(SSOConfiguration).where(SSOConfiguration.organization_id == org_id))).scalar_one()
    assert stored.saml_settings["idp_certificates"] == [idp.cert_pem]
    assert stored.saml_settings["idp_sso_url"] == idp.sso_url and stored.last_test_status == "ok"


@pytest.mark.parametrize(
    ("change", "needle"),
    [
        ("entity", "does not describe entity"),
        ("signed_requests", "WantAuthnRequestsSigned"),
        ("http_error", "HTTP 500"),
    ],
)
async def test_metadata_test_failures_are_502(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeSAMLIdP, change, needle,
) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, org_a.slug, idp, enabled=False, last_test_status=None,
                    discovery_url=idp.metadata_url,
                    issuer="https://someone-else.example.com/metadata" if change == "entity" else idp.entity_id)
    idp.want_authn_requests_signed = change == "signed_requests"
    idp.metadata_status = 500 if change == "http_error" else 200
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 502, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "sso_test_failed" and detail["reason"] == "metadata_failed" and needle in detail["detail"]
    db_session.expire_all()
    stored = (await db_session.execute(select(SSOConfiguration).where(SSOConfiguration.organization_id == org_id))).scalar_one()
    assert stored.last_test_status == "failed"
    rows = await _audit_rows(db_session, "sso_config_test", org_id)
    assert rows and rows[-1].success is False


async def test_metadata_test_refuses_internal_targets_through_netguard(
    client: AsyncClient, db_session, org_a, org_a_admin_headers,
) -> None:
    """No fake provider: the real boundary refuses a loopback metadata URL."""
    local = FakeSAMLIdP(base="https://127.0.0.1:8443")
    await configure(db_session, org_a.id, org_a.slug, local, enabled=False, discovery_url=local.metadata_url)
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 502
    assert resp.json()["detail"]["reason"] == "provider_unreachable"
    assert "outbound target refused" in resp.json()["detail"]["detail"]


async def test_test_without_certificates_or_metadata_fails(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeSAMLIdP,
) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp, enabled=False, saml={"idp_certificates": []})
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 502 and resp.json()["detail"]["reason"] == "configuration_incomplete"


async def test_test_fails_when_every_certificate_expired(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeSAMLIdP,
) -> None:
    old = make_certificate(idp.key, "old", days=10, not_before=datetime.now(timezone.utc) - timedelta(days=30))
    pem = old.public_bytes(serialization.Encoding.PEM).decode()
    await configure(db_session, org_a.id, org_a.slug, idp, enabled=False, saml={"idp_certificates": [pem]})
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 502 and resp.json()["detail"]["reason"] == "certificate_invalid"


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"saml": {"want_assertions_signed": False}}, "saml_assertion_signature_required"),
        ({"saml": {"idp_certificates": ["not a certificate"]}}, "invalid_certificate"),
        ({"saml": {"clock_skew_seconds": 301}}, "invalid_clock_skew"),
        ({"saml": {"name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}}, "invalid_name_id_format"),
        ({"saml": {"idp_sso_url": "http://idp.saml-example.com/sso"}}, "invalid_idp_sso_url"),
        ({"issuer": ""}, "missing_field"),
        ({"discovery_url": "http://idp.saml-example.com/metadata"}, "invalid_metadata_url"),
        ({"protocol": "ws-fed"}, "unsupported_protocol"),
    ],
)
async def test_configuration_validation(
    client: AsyncClient, org_a_admin_headers, idp: FakeSAMLIdP, overrides, error,
) -> None:
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, **overrides), headers=org_a_admin_headers)
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["error"] == error


async def test_changing_certificates_clears_the_test_result(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, idp: FakeSAMLIdP,
) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp)
    other = FakeSAMLIdP(common_name="rotated")
    resp = await client.put("/api/v1/settings/sso", json=_body(idp, enabled=True, saml={"idp_certificates": [other.cert_pem]}),
                            headers=org_a_admin_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "sso_test_required"


async def _custom_role_admin(db, org_id: str) -> dict[str, str]:
    role = Role(organization_id=org_id, name="Settings admin", default_tier="write", area_tiers={"settings": "admin"})
    db.add(role)
    await db.commit()
    role_id = role.id
    user = await make_user(db, role="viewer", organization_id=org_id, label="custom-admin")
    user.custom_role_id = role_id
    await db.commit()
    return bearer(user)


def _unchanged(idp: FakeSAMLIdP, slug: str, **overrides) -> dict:
    """The settings ``configure`` stored, so only the named fields change."""
    saml = {"idp_sso_url": idp.sso_url, "want_response_signed": False, "clock_skew_seconds": 60}
    saml.update(overrides.pop("saml", {}))
    body = {
        "protocol": "saml", "display_name": "Acme SAML", "issuer": idp.entity_id, "client_id": sp_entity_id(slug),
        "allowed_email_domains": [DOMAIN], "jit_provisioning": True, "default_role": "viewer",
        "groups_claim": "groups", "trust_idp_mfa": True, "enabled": True, "saml": saml,
    }
    body.update(overrides)
    return body


async def test_custom_role_admin_cannot_change_saml_trust_settings(
    client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP,
) -> None:
    slug = org_a.slug
    await configure(db_session, org_a.id, slug, idp)
    headers = await _custom_role_admin(db_session, org_a.id)
    other = FakeSAMLIdP(common_name="attacker")
    for overrides, field in (
        ({"saml": {"idp_certificates": [other.cert_pem]}}, "saml.idp_certificates"),
        ({"saml": {"idp_sso_url": "https://attacker.example.com/sso"}}, "saml.idp_sso_url"),
        ({"saml": {"name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}}, "saml.name_id_format"),
        ({"saml": {"clock_skew_seconds": 300}}, "saml.clock_skew_seconds"),
        ({"issuer": "https://attacker.example.com/metadata"}, "issuer"),
        ({"client_id": "urn:other-sp"}, "client_id"),
        ({"discovery_url": "https://attacker.example.com/metadata"}, "discovery_url"),
        ({"protocol": "oidc", "issuer": "https://idp.example.com", "client_id": "x"}, "protocol"),
    ):
        resp = await client.put("/api/v1/settings/sso", json=_unchanged(idp, slug, **overrides), headers=headers)
        assert resp.status_code == 403, (field, resp.text)
        detail = resp.json()["detail"]
        assert detail["error"] == "full_admin_required" and field in detail["fields"], (field, detail)
    # Narrowing is fine: require a signed response, lower the skew, rename the button.
    resp = await client.put("/api/v1/settings/sso", json=_unchanged(
        idp, slug, display_name="Corp SAML", saml={"want_response_signed": True, "clock_skew_seconds": 30}), headers=headers)
    assert resp.status_code == 200, resp.text
    # ... and loosening it back is a trust change again.
    resp = await client.put("/api/v1/settings/sso", json=_unchanged(idp, slug, saml={"clock_skew_seconds": 30}), headers=headers)
    assert resp.status_code == 403 and resp.json()["detail"]["fields"] == ["saml.want_response_signed"]


async def test_viewer_and_analyst_cannot_configure(
    client: AsyncClient, org_a_headers, viewer_headers, idp: FakeSAMLIdP,
) -> None:
    for headers in (org_a_headers, viewer_headers):
        resp = await client.put("/api/v1/settings/sso", json=_body(idp), headers=headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# SP metadata, discover, start
# ---------------------------------------------------------------------------


async def test_sp_metadata(client: AsyncClient, db_session, org_a, org_b, idp: FakeSAMLIdP) -> None:
    slug = org_a.slug
    await configure(db_session, org_a.id, slug, idp, enabled=False)
    resp = await client.get(f"/api/v1/auth/sso/{slug}/saml/metadata")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/samlmetadata+xml")
    root = etree.fromstring(resp.content)
    md = "urn:oasis:names:tc:SAML:2.0:metadata"
    assert root.tag == f"{{{md}}}EntityDescriptor" and root.get("entityID") == sp_entity_id(slug)
    sp = root.find(f"{{{md}}}SPSSODescriptor")
    assert sp.get("AuthnRequestsSigned") == "false" and sp.get("WantAssertionsSigned") == "true"
    acs = sp.find(f"{{{md}}}AssertionConsumerService")
    assert acs.get("Location") == acs_url(slug) and acs.get("Binding").endswith("HTTP-POST")
    assert sp.findtext(f"{{{md}}}NameIDFormat") == saml_sp.NAMEID_EMAIL
    assert sp.find(f"{{{md}}}KeyDescriptor") is None

    assert (await client.get(f"/api/v1/auth/sso/{org_b.slug}/saml/metadata")).status_code == 404
    assert (await client.get("/api/v1/auth/sso/no-such-org/saml/metadata")).json()["detail"]["error"] == "saml_not_configured"


async def test_discover_finds_saml(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp)
    resp = await client.post("/api/v1/auth/sso/discover", json={"email": f"x@{DOMAIN}"})
    assert resp.json()["available"] is True and resp.json()["login_url"] == f"/api/v1/auth/sso/{org_a.slug}/start"


async def test_start_sends_an_authn_request(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP, store) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, slug, idp)
    resp = await client.get(f"/api/v1/auth/sso/{slug}/start", follow_redirects=False)
    assert resp.status_code == 302
    request = idp.authn_request(resp.headers["location"])
    assert request["issuer"] == sp_entity_id(slug) and request["acs"] == acs_url(slug)
    assert request["destination"] == idp.sso_url and request["binding"].endswith("HTTP-POST")
    assert request["name_id_format"] == saml_sp.NAMEID_EMAIL and request["has_signature"] is False
    assert request["id"].startswith("_") and request["relay_state"]
    pending = json.loads(store[saml_sp.REQUEST_KEY.format(request["id"])])
    assert pending["organization_id"] == org_id and pending["relay_state"] == request["relay_state"]
    cookie = resp.headers["set-cookie"]
    assert cookie.startswith("pysoar_sso=") and "httponly" in cookie.lower() and "path=/api/v1/auth/sso" in cookie.lower()
    value = cookie.split(";", 1)[0].split("=", 1)[1]
    assert pending["browser"] == hashlib.sha256(value.encode()).hexdigest()


async def test_start_without_certificates_is_unavailable(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp, saml={"idp_certificates": []})
    resp = await client.get(f"/api/v1/auth/sso/{org_a.slug}/start", follow_redirects=False)
    assert resp.headers["location"] == "/login?sso_error=sso_unavailable"


# ---------------------------------------------------------------------------
# ACS, completion and exchange
# ---------------------------------------------------------------------------


async def test_happy_path_jit_create_then_exchange_once(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, org_a.slug, idp)
    result = await _login(client, idp, org_a.slug, name_id=f"Jane@{DOMAIN}")
    assert "sso" in result and "sso_error" not in result

    user = (await db_session.execute(select(User).where(User.email == f"jane@{DOMAIN}"))).scalar_one()
    user_id = user.id
    assert user.organization_id == org_id and user.sso_subject == f"Jane@{DOMAIN}" and user.full_name == "Jane Doe"
    assert user.role == "viewer" and user.identity_source == "oidc"
    assert await _audit_rows(db_session, "sso_user_provisioned", org_id)
    assert await _audit_rows(db_session, "sso_saml_assertion", org_id)

    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert resp.status_code == 200, resp.text
    payload = decode_token_full(resp.json()["access_token"])
    assert payload["sub"] == user_id and "gen" in payload
    assert await _audit_rows(db_session, "sso_login", org_id)
    again = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert again.status_code == 401 and again.json()["detail"]["error"] == "invalid_sso_code"


async def test_response_signed_too_and_persistent_name_id(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp,
                    saml={"want_response_signed": True, "name_id_format": NAMEID_PERSISTENT})
    request = await _start(client, idp, org_a.slug)
    assert request["name_id_format"] == NAMEID_PERSISTENT
    # Assertion signed but the response is not: refused.
    acs = await _post_acs(client, org_a.slug, idp.response(request, name_id="p-1", name_id_format=NAMEID_PERSISTENT,
                                                            attributes={"email": [f"pat@{DOMAIN}"]}),
                          request["relay_state"])
    assert (await _finish(client, acs)) == {"sso_error": "saml_signature_invalid"}
    result = await _login(client, idp, org_a.slug, name_id="p-1", name_id_format=NAMEID_PERSISTENT,
                          attributes={"email": [f"pat@{DOMAIN}"]}, sign_response=True)
    assert "sso" in result
    user = (await db_session.execute(select(User).where(User.email == f"pat@{DOMAIN}"))).scalar_one()
    assert user.sso_subject == "p-1"


async def test_existing_user_bound_then_matched_by_subject(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, slug, idp, jit_provisioning=False)
    user = await make_user(db_session, role="analyst", organization_id=org_id, label="bob")
    user_id = user.id
    user.email = f"bob@{DOMAIN}"
    await db_session.commit()
    kw = {"name_id": "bob-persistent", "name_id_format": NAMEID_PERSISTENT, "attributes": {"email": [f"bob@{DOMAIN}"]}}
    assert "sso" in await _login(client, idp, slug, **kw)
    db_session.expire_all()
    bound = (await db_session.execute(select(User).where(User.id == user_id))).scalar_one()
    assert bound.sso_subject == "bob-persistent" and bound.role == "analyst"
    assert await _audit_rows(db_session, "sso_subject_bound", org_id)
    # The email changed at the IdP; the NameID still identifies the account.
    kw["attributes"] = {"email": [f"robert@{DOMAIN}"]}
    assert "sso" in await _login(client, idp, slug, **kw)
    assert len((await db_session.execute(select(User).where(User.sso_subject == "bob-persistent"))).scalars().all()) == 1


async def test_group_attribute_maps_the_role(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp, group_role_map={"SOC Analysts": "analyst"})
    await _login(client, idp, org_a.slug, name_id=f"ann@{DOMAIN}", attributes={"groups": ["Everyone", "SOC Analysts"]})
    await _login(client, idp, org_a.slug, name_id=f"vic@{DOMAIN}", attributes={"groups": ["Everyone"]})
    by_email = {u.email: u for u in (await db_session.execute(select(User).where(User.organization_id == org_a.id))).scalars()}
    assert by_email[f"ann@{DOMAIN}"].role == "analyst" and by_email[f"vic@{DOMAIN}"].role == "viewer"


_FOREIGN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _past(minutes: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def _future(minutes: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


@pytest.mark.parametrize(
    ("kwargs", "reason", "needle"),
    [
        ({"signing_key": _FOREIGN_KEY, "signing_cert": make_certificate(_FOREIGN_KEY, "evil")}, "saml_signature_invalid",
         "did not verify"),
        ({"tamper": "assertion_email"}, "saml_signature_invalid", "Digest mismatch"),
        ({"sign_assertion": False}, "saml_signature_invalid", "Signature"),
        ({"audience": "https://another-sp.example.com"}, "saml_conditions_failed", "audience"),
        ({"not_on_or_after": _past(10), "confirmation_until": _past(10)}, "saml_conditions_failed", "expired"),
        ({"confirmation_until": _past(10)}, "saml_conditions_failed", "bearer confirmation expired"),
        ({"not_before": _future(10)}, "saml_conditions_failed", "not valid before"),
        ({"recipient": "https://evil.example.com/acs"}, "saml_conditions_failed", "Recipient"),
        ({"issuer": "https://evil.example.com/metadata"}, "saml_conditions_failed", "Issuer"),
        ({"status": "urn:oasis:names:tc:SAML:2.0:status:Responder"}, "saml_status_failure", "Responder"),
        ({"encrypt": True}, "saml_encrypted_unsupported", "EncryptedAssertion"),
        ({"in_response_to": "_never-issued"}, "saml_unsolicited", "_never-issued"),
        ({"in_response_to": None}, "saml_unsolicited", "IdP-initiated"),
        ({"name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}, "saml_conditions_failed", "transient"),
    ],
)
async def test_bad_responses_are_refused_and_audited(
    client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP, kwargs, reason, needle,
) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, slug, idp)
    request = await _start(client, idp, slug)
    acs = await _post_acs(client, slug, idp.response(request, name_id=f"x@{DOMAIN}", **kwargs), request["relay_state"])
    assert acs.status_code == 303 and acs.headers["location"] == f"/login?sso_error={reason}"
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert rows and rows[-1].success is False and needle in rows[-1].error_message, rows[-1].error_message
    assert (await db_session.execute(select(User).where(User.email == f"x@{DOMAIN}"))).scalar_one_or_none() is None


async def test_future_not_before_inside_the_skew_is_accepted(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp, saml={"clock_skew_seconds": 120})
    result = await _login(client, idp, org_a.slug, name_id=f"s@{DOMAIN}",
                          not_before=datetime.now(timezone.utc) + timedelta(seconds=60))
    assert "sso" in result


async def test_replayed_assertion_is_refused(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    slug = org_a.slug
    await configure(db_session, org_a.id, slug, idp)
    request = await _start(client, idp, slug)
    response = idp.response(request, name_id=f"r@{DOMAIN}")
    first = await _post_acs(client, slug, response, request["relay_state"])
    assert "sso" in await _finish(client, first)
    replay = await _post_acs(client, slug, response, request["relay_state"])
    assert replay.headers["location"] == "/login?sso_error=saml_replay"


async def test_request_id_is_single_use(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    slug = org_a.slug
    await configure(db_session, org_a.id, slug, idp)
    request = await _start(client, idp, slug)
    first = await _post_acs(client, slug, idp.response(request, name_id=f"u@{DOMAIN}"), request["relay_state"])
    assert "sso" in await _finish(client, first)
    # A second, freshly signed assertion for the same (consumed) request.
    second = await _post_acs(client, slug, idp.response(request, name_id=f"u@{DOMAIN}"), request["relay_state"])
    assert second.headers["location"] == "/login?sso_error=saml_unsolicited"


async def test_relay_state_must_match(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp)
    request = await _start(client, idp, org_a.slug)
    acs = await _post_acs(client, org_a.slug, idp.response(request, name_id=f"q@{DOMAIN}"), "not-the-relay-state")
    assert acs.headers["location"] == "/login?sso_error=invalid_state"


@pytest.mark.parametrize(
    ("kwargs", "overrides", "reason"),
    [
        ({"name_id": "abc-123", "name_id_format": NAMEID_PERSISTENT}, {}, "email_missing"),
        ({"name_id": "jane@elsewhere.test"}, {}, "email_domain_not_allowed"),
        ({"name_id": f"new@{DOMAIN}"}, {"jit_provisioning": False}, "user_not_provisioned"),
    ],
)
async def test_identity_refusals(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP, kwargs, overrides, reason) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, org_a.slug, idp, **overrides)
    result = await _login(client, idp, org_a.slug, **kwargs)
    assert result == {"sso_error": reason}
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert rows and rows[-1].description.endswith(reason)


async def test_superuser_and_inactive_accounts_are_refused(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, slug, idp)
    su = await make_user(db_session, role="admin", organization_id=org_id, is_superuser=True, label="su")
    su_id = su.id
    su.email = f"root@{DOMAIN}"
    await db_session.commit()
    assert await _login(client, idp, slug, name_id=f"root@{DOMAIN}") == {"sso_error": "superuser_not_allowed"}
    db_session.expire_all()
    assert (await db_session.execute(select(User).where(User.id == su_id))).scalar_one().sso_subject is None

    await _login(client, idp, slug, name_id=f"d@{DOMAIN}")
    user = (await db_session.execute(select(User).where(User.email == f"d@{DOMAIN}"))).scalar_one()
    user.is_active = False
    await db_session.commit()
    assert await _login(client, idp, slug, name_id=f"d@{DOMAIN}") == {"sso_error": "user_inactive"}


# ---------------------------------------------------------------------------
# Hostile XML
# ---------------------------------------------------------------------------


_XXE = b"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0">&xxe;</samlp:Response>"""

_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&lol2;</samlp:Response>"""


@pytest.mark.parametrize("document", [_XXE, _LAUGHS, _XXE.decode().encode("utf-16")])
async def test_dtd_and_entities_are_refused(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP, document) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, org_a.slug, idp)
    acs = await _post_acs(client, org_a.slug, base64.b64encode(document).decode())
    assert acs.headers["location"] == "/login?sso_error=saml_response_invalid"
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert "DTD" in rows[-1].error_message and "root:" not in rows[-1].error_message
    with pytest.raises(saml_sp.SAMLError) as exc:
        saml_sp.parse_idp_metadata(document, idp.entity_id)
    assert exc.value.reason == "metadata_failed"


async def test_injected_second_assertion_is_refused(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    """Signature wrapping: a valid signed assertion plus an unsigned one naming someone else."""
    await configure(db_session, org_a.id, org_a.slug, idp)
    request = await _start(client, idp, org_a.slug)
    root = etree.fromstring(base64.b64decode(idp.response(request, name_id=f"me@{DOMAIN}")))
    ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    forged = etree.fromstring(etree.tostring(root.find(f"{{{ns}}}Assertion")))
    forged.set("ID", "_forged")
    forged.find(f"{{{ns}}}Subject/{{{ns}}}NameID").text = f"admin@{DOMAIN}"
    forged.remove(forged.find("{http://www.w3.org/2000/09/xmldsig#}Signature"))
    root.insert(2, forged)
    acs = await _post_acs(client, org_a.slug, base64.b64encode(etree.tostring(root)).decode(), request["relay_state"])
    assert acs.headers["location"] == "/login?sso_error=saml_response_invalid"


# ---------------------------------------------------------------------------
# Browser binding and tenancy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cookie", [None, "a-different-browser"])
async def test_completion_needs_the_starting_browser(
    client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP, cookie,
) -> None:
    org_id, slug = org_a.id, org_a.slug
    await configure(db_session, org_id, slug, idp)
    request = await _start(client, idp, slug)
    acs = await _post_acs(client, slug, idp.response(request, name_id=f"v@{DOMAIN}"), request["relay_state"])
    assert acs.headers["location"].startswith("/api/v1/auth/sso/saml/complete?ticket=")
    client.cookies.clear()
    if cookie:
        client.cookies.set("pysoar_sso", cookie)
    done = await client.get(acs.headers["location"], follow_redirects=False)
    assert done.headers["location"] == "/login?sso_error=invalid_state"
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert rows and "not bound to this browser" in rows[-1].error_message
    assert (await db_session.execute(select(User).where(User.email == f"v@{DOMAIN}"))).scalar_one_or_none() is None
    # The ticket is single use.
    again = await client.get(acs.headers["location"], follow_redirects=False)
    assert again.headers["location"] == "/login?sso_error=invalid_state"


async def test_exchange_needs_the_starting_browser(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp)
    result = await _login(client, idp, org_a.slug, name_id=f"c@{DOMAIN}")
    client.cookies.clear()
    resp = await client.post("/api/v1/auth/sso/exchange", json={"code": result["sso"]})
    assert resp.status_code == 401 and resp.json()["detail"]["error"] == "invalid_sso_code"


async def test_org_b_certificate_never_validates_org_a(
    client: AsyncClient, db_session, org_a, org_b, monkeypatch,
) -> None:
    idp_a, idp_b = FakeSAMLIdP(), FakeSAMLIdP(base="https://idp-b.saml-example.com", common_name="B")
    install(monkeypatch, idp_a, idp_b)
    org_a_id = org_a.id
    await configure(db_session, org_a_id, org_a.slug, idp_a)
    await configure(db_session, org_b.id, org_b.slug, idp_b, domains=("b-saml.io",))
    request = await _start(client, idp_a, org_a.slug)
    # Org B's IdP signs an assertion for org A's request, naming org A's IdP as issuer.
    forged = idp_b.response(request, name_id=f"x@{DOMAIN}", issuer=idp_a.entity_id)
    acs = await _post_acs(client, org_a.slug, forged, request["relay_state"])
    assert acs.headers["location"] == "/login?sso_error=saml_signature_invalid"

    # A request started for org B cannot be finished at org A's ACS.
    request_b = await _start(client, idp_b, org_b.slug)
    crossed = idp_a.response(request_b, name_id=f"y@{DOMAIN}", audience=sp_entity_id(org_a.slug), acs=acs_url(org_a.slug))
    acs = await _post_acs(client, org_a.slug, crossed, request_b["relay_state"])
    assert acs.headers["location"] == "/login?sso_error=saml_unsolicited"
    assert (await db_session.execute(select(User).where(User.email.in_([f"x@{DOMAIN}", f"y@{DOMAIN}"])))).scalars().all() == []


async def test_admin_of_a_cannot_read_b_saml_config(
    client: AsyncClient, db_session, org_a_admin_headers, org_b, idp: FakeSAMLIdP,
) -> None:
    await configure(db_session, org_b.id, org_b.slug, idp)
    resp = await client.get("/api/v1/settings/sso", headers=org_a_admin_headers)
    assert resp.status_code == 404 and resp.json()["detail"]["error"] == "sso_not_configured"


async def test_disabled_config_refuses_at_acs(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    config = await configure(db_session, org_a.id, org_a.slug, idp)
    request = await _start(client, idp, org_a.slug)
    config.enabled = False
    await db_session.commit()
    acs = await _post_acs(client, org_a.slug, idp.response(request, name_id=f"z@{DOMAIN}"), request["relay_state"])
    assert acs.headers["location"] == "/login?sso_error=sso_unavailable"


async def test_saml_group_mapping_is_a_trust_setting(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    """SAML always has a groups attribute (default ``groups``), so the mapping is always a trust setting."""
    slug = org_a.slug
    await configure(db_session, org_a.id, slug, idp)
    headers = await _custom_role_admin(db_session, org_a.id)
    resp = await client.put("/api/v1/settings/sso", json=_unchanged(idp, slug, group_role_map={"SOC": "viewer"}),
                            headers=headers)
    assert resp.status_code == 403 and resp.json()["detail"]["fields"] == ["group_role_map"]
    resp = await client.put("/api/v1/settings/sso", json=_unchanged(idp, slug, display_name="Renamed"), headers=headers)
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Attribute aliasing (Name only; a duplicated Name is unusable)
# ---------------------------------------------------------------------------


async def test_duplicate_attribute_name_is_refused(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, org_a.slug, idp)
    result = await _login(client, idp, org_a.slug, name_id=f"dup@{DOMAIN}",
                          raw_attributes=[("email", None, [f"boss@{DOMAIN}"])])
    assert result == {"sso_error": "saml_response_invalid"}
    rows = await _audit_rows(db_session, "sso_login_failed", org_id)
    assert rows and "more than once" in rows[-1].error_message
    assert (await db_session.execute(select(User).where(User.organization_id == org_id,
                                                        User.email.like(f"%@{DOMAIN}")))).scalars().all() == []


async def test_friendly_name_never_satisfies_the_configured_name(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    await configure(db_session, org_a.id, org_a.slug, idp)
    result = await _login(client, idp, org_a.slug, name_id="p-9", name_id_format=NAMEID_PERSISTENT,
                          raw_attributes=[("urn:oid:0.9.2342.19200300.100.1.3", "email", [f"f@{DOMAIN}"])])
    assert result == {"sso_error": "email_missing"}


async def test_friendly_name_never_shadows_the_configured_name(client: AsyncClient, db_session, org_a, idp: FakeSAMLIdP) -> None:
    org_id = org_a.id
    await configure(db_session, org_id, org_a.slug, idp, group_role_map={"Admins": "admin"})
    result = await _login(client, idp, org_a.slug, name_id="p-10", name_id_format=NAMEID_PERSISTENT, raw_attributes=[
        ("urn:alias:mail", "email", [f"boss@{DOMAIN}"]),
        ("urn:alias:groups", "groups", ["Admins"]),
        ("email", None, [f"real@{DOMAIN}"]),
    ])
    assert "sso" in result
    users = (await db_session.execute(select(User).where(User.organization_id == org_id, User.sso_subject == "p-10"))).scalars().all()
    assert [u.email for u in users] == [f"real@{DOMAIN}"] and users[0].role == "viewer"


# ---------------------------------------------------------------------------
# Metadata download limits (streamed, capped, deadline)
# ---------------------------------------------------------------------------


class _Body:
    """An async chunk stream that counts what was pulled from it."""

    def __init__(self, chunk: bytes, count: int | None = None, delay: float = 0.0) -> None:
        self.chunk, self.count, self.delay, self.pulled = chunk, count, delay, 0

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        while self.count is None or self.pulled < self.count:
            if self.delay:
                await asyncio.sleep(self.delay)
            self.pulled += 1
            yield self.chunk


async def test_declared_oversized_metadata_is_refused_unread(monkeypatch) -> None:
    body = _Body(b"x" * 1024, count=10)
    install_body(monkeypatch, body, headers={"Content-Length": str(saml_sp.MAX_METADATA_BYTES + 1)})
    with pytest.raises(saml_sp.SAMLError) as exc:
        await saml_sp.fetch_idp_metadata("https://idp.saml-example.com/metadata", "x")
    assert exc.value.reason == "metadata_failed" and "declares" in exc.value.detail
    assert body.pulled == 0


async def test_streamed_oversized_metadata_stops_at_the_cap(
    client: AsyncClient, db_session, org_a, org_a_admin_headers, monkeypatch,
) -> None:
    chunk = 64 * 1024
    body = _Body(b"<" * chunk)  # endless, no Content-Length
    install_body(monkeypatch, body)
    idp = FakeSAMLIdP()
    await configure(db_session, org_a.id, org_a.slug, idp, enabled=False, discovery_url=idp.metadata_url)
    resp = await client.post("/api/v1/settings/sso/test", headers=org_a_admin_headers)
    assert resp.status_code == 502, resp.text
    detail = resp.json()["detail"]
    assert detail["reason"] == "metadata_failed" and "download was stopped" in detail["detail"]
    assert body.pulled == saml_sp.MAX_METADATA_BYTES // chunk + 1


async def test_slow_metadata_hits_the_deadline(monkeypatch) -> None:
    body = _Body(b"<", delay=5.0)
    install_body(monkeypatch, body)
    monkeypatch.setattr(saml_sp, "METADATA_DEADLINE_SECONDS", 0.2)
    with pytest.raises(saml_sp.SAMLError) as exc:
        await saml_sp.fetch_idp_metadata("https://idp.saml-example.com/metadata", "x")
    assert exc.value.reason == "metadata_failed" and "did not finish" in exc.value.detail
    assert body.pulled == 0
