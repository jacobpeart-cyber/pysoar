"""A fake SAML 2.0 identity provider for the SAML SSO tests (test_sso_saml.py).

Real enough to exercise the code under test end to end: an RSA key and a
self-signed certificate are generated per provider, Assertions (and, when
asked, Responses) are signed with signxml exactly as an IdP signs them
(enveloped, exclusive C14N, RSA-SHA256), the metadata document is real SAML
metadata, and the AuthnRequest the SP sends is inflated and parsed like an IdP
would. It is plugged in by replacing ``src.identity.saml._http_request`` (the
single outbound boundary), so netguard is not consulted.
"""

from __future__ import annotations

import base64
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod

from src.identity.models import SSOConfiguration
from tests.unit.sso_fakes import stateful_redis

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"


def saml_redis(redis_mock: AsyncMock) -> dict[str, str]:
    """``stateful_redis`` plus ``SET ... EX NX`` semantics (the replay cache)."""
    store = stateful_redis(redis_mock)

    async def _set(key: str, value, *_args, ex=None, nx: bool = False, **_kwargs):
        assert ex is None or ex > 0  # the replay cache always sets a positive TTL
        if nx and key in store:
            return None
        store[key] = str(value)
        return True

    redis_mock.set = AsyncMock(side_effect=_set)
    return store


def _q(ns: str, tag: str) -> str:
    return f"{{{ns}}}{tag}"


def _instant(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_certificate(key: rsa.RSAPrivateKey, common_name: str, *, days: int = 365,
                     not_before: Optional[datetime] = None) -> x509.Certificate:
    start = not_before or (datetime.now(timezone.utc) - timedelta(days=1))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )


class FakeSAMLIdP:
    """One SAML identity provider at ``base`` (entity id ``<base>/metadata``)."""

    def __init__(self, base: str = "https://idp.saml-example.com", common_name: str = "Fake SAML IdP") -> None:
        self.base = base
        self.entity_id = f"{base}/metadata"
        self.sso_url = f"{base}/sso"
        self.metadata_url = f"{base}/metadata"
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert = make_certificate(self.key, common_name)
        self.calls: list[tuple[str, str]] = []
        self.want_authn_requests_signed = False
        self.metadata_status = 200

    # -- key material -------------------------------------------------------

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @property
    def cert_b64(self) -> str:
        return base64.b64encode(self.cert.public_bytes(serialization.Encoding.DER)).decode("ascii")

    def _key_pem(self, key: Optional[rsa.RSAPrivateKey] = None) -> bytes:
        return (key or self.key).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())

    # -- metadata -----------------------------------------------------------

    def metadata(self) -> bytes:
        root = etree.Element(_q(NS_MD, "EntityDescriptor"), nsmap={"md": NS_MD, "ds": NS_DS}, entityID=self.entity_id)
        idp = etree.SubElement(root, _q(NS_MD, "IDPSSODescriptor"), {
            "protocolSupportEnumeration": NS_SAMLP,
            "WantAuthnRequestsSigned": "true" if self.want_authn_requests_signed else "false",
        })
        key = etree.SubElement(idp, _q(NS_MD, "KeyDescriptor"), use="signing")
        info = etree.SubElement(key, _q(NS_DS, "KeyInfo"))
        data = etree.SubElement(info, _q(NS_DS, "X509Data"))
        etree.SubElement(data, _q(NS_DS, "X509Certificate")).text = self.cert_b64
        for fmt in (NAMEID_EMAIL, NAMEID_PERSISTENT):
            etree.SubElement(idp, _q(NS_MD, "NameIDFormat")).text = fmt
        etree.SubElement(idp, _q(NS_MD, "SingleSignOnService"), Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                         Location=f"{self.base}/sso-post")
        etree.SubElement(idp, _q(NS_MD, "SingleSignOnService"),
                         Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location=self.sso_url)
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8")

    async def handle(self, method: str, url: str) -> httpx.Response:
        self.calls.append((method, url))
        request = httpx.Request(method, url)
        if url == self.metadata_url and method == "GET":
            if self.metadata_status != 200:
                return httpx.Response(self.metadata_status, content=b"<error/>", request=request)
            return httpx.Response(200, content=self.metadata(), request=request,
                                  headers={"Content-Type": "application/samlmetadata+xml"})
        return httpx.Response(404, content=b"not found", request=request)

    # -- the SSO step the browser would perform -------------------------------

    def authn_request(self, location: str) -> dict[str, Any]:
        """Decode the HTTP-Redirect AuthnRequest at ``location`` like an IdP."""
        assert location.startswith(self.sso_url + "?"), location
        params = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        xml = zlib.decompress(base64.b64decode(params["SAMLRequest"]), -15)
        root = etree.fromstring(xml)
        assert root.tag == _q(NS_SAMLP, "AuthnRequest")
        policy = root.find(_q(NS_SAMLP, "NameIDPolicy"))
        return {
            "id": root.get("ID"),
            "acs": root.get("AssertionConsumerServiceURL"),
            "destination": root.get("Destination"),
            "binding": root.get("ProtocolBinding"),
            "issuer": root.findtext(_q(NS_SAML, "Issuer")),
            "name_id_format": policy.get("Format") if policy is not None else None,
            "relay_state": params.get("RelayState"),
            "xml": xml,
            "has_signature": "Signature" in params or root.find(_q(NS_DS, "Signature")) is not None,
        }

    def response(
        self,
        request: Optional[dict[str, Any]],
        *,
        name_id: str = "jane@acme-saml.io",
        name_id_format: str = NAMEID_EMAIL,
        attributes: Optional[dict[str, list[str]]] = None,
        audience: Optional[str] = None,
        recipient: Optional[str] = None,
        acs: Optional[str] = None,
        in_response_to: Optional[str] = "<from request>",
        issuer: Optional[str] = None,
        not_before: Optional[datetime] = None,
        not_on_or_after: Optional[datetime] = None,
        confirmation_until: Optional[datetime] = None,
        status: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
        assertion_id: Optional[str] = None,
        sign_assertion: bool = True,
        sign_response: bool = False,
        signing_key: Optional[rsa.RSAPrivateKey] = None,
        signing_cert: Optional[x509.Certificate] = None,
        encrypt: bool = False,
        tamper: Optional[str] = None,
    ) -> str:
        """A base64 SAML Response (the HTTP-POST ``SAMLResponse`` field)."""
        now = datetime.now(timezone.utc)
        acs_url = acs or (request or {}).get("acs") or ""
        irt = (request or {}).get("id") if in_response_to == "<from request>" else in_response_to
        sp_entity = audience or (request or {}).get("issuer") or ""
        idp_entity = issuer or self.entity_id
        key = signing_key or self.key
        cert = signing_cert or self.cert
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        signer = XMLSigner(signature_algorithm=SignatureMethod.RSA_SHA256, digest_algorithm=DigestAlgorithm.SHA256,
                           c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0)

        response = etree.Element(_q(NS_SAMLP, "Response"), nsmap={"samlp": NS_SAMLP, "saml": NS_SAML}, attrib={
            "ID": "_r" + uuid.uuid4().hex, "Version": "2.0", "IssueInstant": _instant(now), "Destination": acs_url,
        })
        if irt:
            response.set("InResponseTo", irt)
        etree.SubElement(response, _q(NS_SAML, "Issuer")).text = idp_entity
        status_el = etree.SubElement(response, _q(NS_SAMLP, "Status"))
        etree.SubElement(status_el, _q(NS_SAMLP, "StatusCode"), Value=status)
        if status.endswith(":Success") is False:
            etree.SubElement(status_el, _q(NS_SAMLP, "StatusMessage")).text = "Authentication failed"
            return base64.b64encode(etree.tostring(response)).decode("ascii")

        assertion = etree.Element(_q(NS_SAML, "Assertion"), nsmap={"saml": NS_SAML}, attrib={
            "ID": assertion_id or "_a" + uuid.uuid4().hex, "Version": "2.0", "IssueInstant": _instant(now),
        })
        etree.SubElement(assertion, _q(NS_SAML, "Issuer")).text = idp_entity
        if sign_assertion:
            etree.SubElement(assertion, _q(NS_DS, "Signature"), Id="placeholder", nsmap={"ds": NS_DS})
        subject = etree.SubElement(assertion, _q(NS_SAML, "Subject"))
        etree.SubElement(subject, _q(NS_SAML, "NameID"), Format=name_id_format).text = name_id
        confirmation = etree.SubElement(subject, _q(NS_SAML, "SubjectConfirmation"),
                                        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
        data_attrs = {"Recipient": recipient or acs_url,
                      "NotOnOrAfter": _instant(confirmation_until or now + timedelta(minutes=5))}
        if irt:
            data_attrs["InResponseTo"] = irt
        etree.SubElement(confirmation, _q(NS_SAML, "SubjectConfirmationData"), data_attrs)
        conditions = etree.SubElement(assertion, _q(NS_SAML, "Conditions"), {
            "NotBefore": _instant(not_before or now - timedelta(seconds=30)),
            "NotOnOrAfter": _instant(not_on_or_after or now + timedelta(minutes=5)),
        })
        restriction = etree.SubElement(conditions, _q(NS_SAML, "AudienceRestriction"))
        etree.SubElement(restriction, _q(NS_SAML, "Audience")).text = sp_entity
        authn = etree.SubElement(assertion, _q(NS_SAML, "AuthnStatement"),
                                 AuthnInstant=_instant(now), SessionIndex="_s" + uuid.uuid4().hex)
        context = etree.SubElement(authn, _q(NS_SAML, "AuthnContext"))
        etree.SubElement(context, _q(NS_SAML, "AuthnContextClassRef")).text = (
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
        values = {"email": [name_id] if "@" in name_id else [], "name": ["Jane Doe"]}
        values.update(attributes or {})
        statement = etree.SubElement(assertion, _q(NS_SAML, "AttributeStatement"))
        for attr_name, attr_values in values.items():
            if not attr_values:
                continue
            attr = etree.SubElement(statement, _q(NS_SAML, "Attribute"), Name=attr_name,
                                    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
            for value in attr_values:
                etree.SubElement(attr, _q(NS_SAML, "AttributeValue")).text = value

        if sign_assertion:
            assertion = signer.sign(assertion, key=self._key_pem(key), cert=cert_pem)
        if tamper == "assertion_email":
            # Change a signed value after signing: the digest no longer matches.
            for node in assertion.iter(_q(NS_SAML, "NameID")):
                node.text = "boss@acme-saml.io"
        if encrypt:
            enc = etree.SubElement(response, _q(NS_SAML, "EncryptedAssertion"))
            etree.SubElement(enc, "{http://www.w3.org/2001/04/xmlenc#}EncryptedData").text = "b64-ciphertext"
        else:
            response.append(assertion)
        if sign_response:
            placeholder = etree.Element(_q(NS_DS, "Signature"), Id="placeholder", nsmap={"ds": NS_DS})
            response.insert(1, placeholder)
            response = signer.sign(response, key=self._key_pem(key), cert=cert_pem)
        return base64.b64encode(etree.tostring(response)).decode("ascii")


def install(monkeypatch: Any, *idps: FakeSAMLIdP) -> None:
    """Route ``src.identity.saml._http_request`` to the fake providers."""

    async def fake_http(method: str, url: str) -> httpx.Response:
        for idp in idps:
            if url.startswith(idp.base + "/"):
                return await idp.handle(method, url)
        return httpx.Response(404, request=httpx.Request(method, url))

    monkeypatch.setattr("src.identity.saml._http_request", fake_http)


def sp_entity_id(slug: str) -> str:
    return f"http://test/api/v1/auth/sso/{slug}/saml/metadata"


def acs_url(slug: str) -> str:
    return f"http://test/api/v1/auth/sso/{slug}/saml/acs"


async def configure(db: Any, org_id: str, slug: str, idp: FakeSAMLIdP, *,
                    domains: tuple[str, ...] = ("acme-saml.io",), saml: Optional[dict[str, Any]] = None,
                    **overrides: Any) -> SSOConfiguration:
    """Store an enabled, tested SAML configuration for ``org_id`` trusting ``idp``."""
    settings: dict[str, Any] = {
        "idp_sso_url": idp.sso_url,
        "idp_certificates": [idp.cert_pem],
        "name_id_format": NAMEID_EMAIL,
        "want_response_signed": False,
        "clock_skew_seconds": 60,
    }
    settings.update(saml or {})
    values: dict[str, Any] = {
        "organization_id": org_id,
        "protocol": "saml",
        "display_name": "Acme SAML",
        "issuer": idp.entity_id,
        "client_id": sp_entity_id(slug),
        "client_secret": None,
        "discovery_url": None,
        "email_claim": "email",
        "name_claim": "name",
        "groups_claim": "groups",
        "allowed_email_domains": list(domains),
        "group_role_map": {},
        "jit_provisioning": True,
        "default_role": "viewer",
        "require_email_verified": False,
        "trust_idp_mfa": True,
        "enabled": True,
        "last_test_status": "ok",
        "saml_settings": settings,
    }
    values.update(overrides)
    config = SSOConfiguration(**values)
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return config


def query(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
