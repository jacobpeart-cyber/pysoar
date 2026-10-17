"""SAML 2.0 single sign-on, service-provider side: SP metadata, the AuthnRequest
(HTTP-Redirect binding), IdP metadata import and Response / Assertion validation
(HTTP-POST binding).

One organisation has at most one identity provider (``SSOConfiguration``); a
SAML configuration stores the IdP entity id in ``issuer``, the IdP metadata URL
in ``discovery_url``, our SP entity id in ``client_id`` and the rest in
``saml_settings`` (``SAMLSettings``). The flow (routes in
``src.api.v1.endpoints.sso``):

1. ``start``: an unsigned AuthnRequest is deflated, base64-encoded and sent to
   the IdP single sign-on URL (HTTP-Redirect binding) with ``RelayState``; the
   request id, the organisation and the browser binding are kept in Redis under
   ``sso:saml:request:<id>`` for 10 minutes (single use).
2. ``acs``: the IdP posts the Response (HTTP-POST binding). It is parsed with
   DTDs, entities, network access and comments disabled, the Assertion's XML
   signature (and the Response's, when ``want_response_signed``) is verified
   with signxml against the stored certificate(s) only, and the values used are
   read from what the signature covers. Then: Response Status Success, Issuer =
   IdP entity id, Conditions NotBefore / NotOnOrAfter within the clock skew,
   AudienceRestriction holds our SP entity id, a bearer SubjectConfirmation
   whose Recipient is our ACS URL and whose NotOnOrAfter has not passed,
   InResponseTo names a request we issued (unsolicited responses are refused),
   and the assertion id has not been seen (Redis replay cache for its validity
   window). Encrypted assertions, NameIDs and attributes are refused.

Not supported (refused or not offered, never silently accepted): encrypted
assertions, signed AuthnRequests (an IdP whose metadata demands them is
refused), Single Logout, IdP-initiated (unsolicited) login, the HTTP-POST
binding for requests, artifact binding, SHA-1 signatures and digests, and
transient NameIDs.

Every outbound call (IdP metadata) goes through ``_http_stream``, which
resolves and vets the target with ``src.integrations.netguard``; the body is
streamed and capped (``read_capped``) within an overall deadline. Tests replace
``_http_stream`` with a fake identity provider.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import re
import secrets
import zlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from lxml import etree
from signxml import SignatureConfiguration, XMLVerifier
from signxml.algorithms import DigestAlgorithm, SignatureMethod
from signxml.exceptions import SignXMLException

from src.core.logging import get_logger
from src.integrations.netguard import OutboundTargetRefused, merge_pinned_kwargs, resolve_and_vet

logger = get_logger(__name__)

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"

PROTOCOL = NS_SAMLP
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
#: NameID formats an administrator may request. Transient identifiers change
#: per login, so they cannot be bound to an account.
NAME_ID_FORMATS: tuple[str, ...] = (NAMEID_EMAIL, NAMEID_PERSISTENT, NAMEID_UNSPECIFIED)

#: Seconds a pending AuthnRequest (request id, organisation, browser binding) lives.
REQUEST_TTL_SECONDS = 600
#: Seconds the verified-assertion ticket handed from the ACS to ``complete`` lives.
TICKET_TTL_SECONDS = 60
DEFAULT_CLOCK_SKEW_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 300
#: Largest decoded Response / metadata document accepted.
MAX_RESPONSE_BYTES = 256 * 1024
MAX_METADATA_BYTES = 1024 * 1024
#: Overall deadline for downloading IdP metadata (connect + every chunk).
METADATA_DEADLINE_SECONDS = 20.0
#: Signing certificates kept per IdP (current + rollover).
MAX_CERTIFICATES = 4
HTTP_TIMEOUT_SECONDS = 10.0

REQUEST_KEY = "sso:saml:request:{}"
TICKET_KEY = "sso:saml:ticket:{}"
REPLAY_KEY = "sso:saml:assertion:{}"

#: Accepted XML signature algorithms and digests: RSA / ECDSA with SHA-2 only.
ALLOWED_SIGNATURE_METHODS = frozenset({
    SignatureMethod.RSA_SHA256, SignatureMethod.RSA_SHA384, SignatureMethod.RSA_SHA512,
    SignatureMethod.ECDSA_SHA256, SignatureMethod.ECDSA_SHA384, SignatureMethod.ECDSA_SHA512,
})
ALLOWED_DIGESTS = frozenset({DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512})


class SAMLError(Exception):
    """A step of the SAML flow failed.

    ``reason`` is a short fixed key safe to show the user (``/login?sso_error=``
    or the test's ``reason``); ``detail`` is for the audit row and logs.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail or reason


def _q(ns: str, tag: str) -> str:
    return f"{{{ns}}}{tag}"


# ---------------------------------------------------------------------------
# Hardened parsing
# ---------------------------------------------------------------------------


def _parser() -> etree.XMLParser:
    """No DTD loading or validation, no entity expansion, no network, no huge
    trees; comments and processing instructions dropped (a comment inside a
    NameID must never split what is read from it)."""
    return etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
        huge_tree=False, remove_comments=True, remove_pis=True,
    )


def parse_xml(data: bytes, *, reason: str, limit: int, what: str) -> etree._Element:
    """Parse untrusted XML; any DTD (and so any entity declaration) is refused."""
    if len(data) > limit:
        raise SAMLError(reason, f"{what} is larger than {limit} bytes")
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise SAMLError(reason, f"{what} carries a DTD or entity declaration; they are refused")
    try:
        root = etree.fromstring(data, parser=_parser())
    except etree.XMLSyntaxError as exc:
        raise SAMLError(reason, f"{what} is not well-formed XML: {exc}") from exc
    if root is None:
        raise SAMLError(reason, f"{what} is empty")
    # Belt and braces for encodings the byte check cannot see (UTF-16).
    docinfo = root.getroottree().docinfo
    if docinfo.doctype or docinfo.internalDTD is not None or docinfo.externalDTD is not None:
        raise SAMLError(reason, f"{what} carries a DTD; it is refused")
    return root


_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def parse_instant(value: Optional[str], what: str) -> datetime:
    """An ``xs:dateTime`` (SAML instants are UTC); naive values are read as UTC."""
    if not value:
        raise SAMLError("saml_conditions_failed", f"{what} is missing")
    text = _FRACTION_RE.sub(r"\1", value.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SAMLError("saml_conditions_failed", f"{what} {value!r} is not a valid instant") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _instant_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Certificates and settings
# ---------------------------------------------------------------------------


def normalise_certificate(text: str) -> str:
    """A PEM certificate from PEM text or the bare base64 DER metadata carries."""
    raw = (text or "").strip()
    if not raw:
        raise SAMLError("certificate_invalid", "empty certificate")
    try:
        if "-----BEGIN CERTIFICATE-----" in raw:
            cert = x509.load_pem_x509_certificate(raw.encode("ascii"))
        else:
            cert = x509.load_der_x509_certificate(base64.b64decode("".join(raw.split()), validate=True))
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise SAMLError("certificate_invalid", f"not an X.509 certificate (PEM or base64 DER): {exc}") from exc
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def certificate_summary(pem: str, *, now: Optional[datetime] = None) -> dict[str, Any]:
    """What the UI and audit rows show for a stored certificate (never needed secret)."""
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    moment = now or datetime.now(timezone.utc)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256_fingerprint": ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)),
        "expired": cert.not_valid_after_utc <= moment,
    }


@dataclass(frozen=True)
class SAMLSettings:
    """``SSOConfiguration.saml_settings`` with defaults applied."""

    idp_sso_url: Optional[str] = None
    idp_certificates: tuple[str, ...] = ()
    name_id_format: str = NAMEID_EMAIL
    want_response_signed: bool = False
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS

    @classmethod
    def from_config(cls, raw: Optional[dict[str, Any]]) -> "SAMLSettings":
        raw = raw if isinstance(raw, dict) else {}
        certs = raw.get("idp_certificates")
        skew = raw.get("clock_skew_seconds")
        return cls(
            idp_sso_url=str(raw["idp_sso_url"]) if raw.get("idp_sso_url") else None,
            idp_certificates=tuple(str(c) for c in certs) if isinstance(certs, list) else (),
            name_id_format=str(raw.get("name_id_format") or NAMEID_EMAIL),
            want_response_signed=bool(raw.get("want_response_signed", False)),
            clock_skew_seconds=min(max(int(skew), 0), MAX_CLOCK_SKEW_SECONDS) if isinstance(skew, int) else DEFAULT_CLOCK_SKEW_SECONDS,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "idp_sso_url": self.idp_sso_url,
            "idp_certificates": list(self.idp_certificates),
            "name_id_format": self.name_id_format,
            "want_response_signed": self.want_response_signed,
            "clock_skew_seconds": self.clock_skew_seconds,
        }

    def audit_dict(self) -> dict[str, Any]:
        """``as_dict`` with certificates as fingerprints (audit rows stay small)."""
        values = self.as_dict()
        fingerprints = []
        for pem in self.idp_certificates:
            try:
                fingerprints.append(certificate_summary(pem)["sha256_fingerprint"])
            except ValueError:
                fingerprints.append("unreadable")
        values["idp_certificates"] = fingerprints
        return values


# ---------------------------------------------------------------------------
# SP metadata and the AuthnRequest
# ---------------------------------------------------------------------------


def sp_metadata_xml(*, entity_id: str, acs_url: str, name_id_format: str) -> bytes:
    """Our EntityDescriptor: the ACS (HTTP-POST), the NameID format, unsigned requests."""
    root = etree.Element(_q(NS_MD, "EntityDescriptor"), nsmap={"md": NS_MD}, entityID=entity_id)
    sp = etree.SubElement(root, _q(NS_MD, "SPSSODescriptor"), {
        "AuthnRequestsSigned": "false",
        "WantAssertionsSigned": "true",
        "protocolSupportEnumeration": PROTOCOL,
    })
    etree.SubElement(sp, _q(NS_MD, "NameIDFormat")).text = name_id_format
    etree.SubElement(sp, _q(NS_MD, "AssertionConsumerService"), {
        "Binding": BINDING_POST, "Location": acs_url, "index": "0", "isDefault": "true",
    })
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True)


def new_request_id() -> str:
    """An xs:ID (an NCName: must not start with a digit)."""
    return "_" + secrets.token_hex(20)


def authn_request_xml(*, request_id: str, issue_instant: datetime, destination: str, sp_entity_id: str,
                      acs_url: str, name_id_format: str) -> bytes:
    root = etree.Element(_q(NS_SAMLP, "AuthnRequest"), nsmap={"samlp": NS_SAMLP, "saml": NS_SAML}, attrib={
        "ID": request_id,
        "Version": "2.0",
        "IssueInstant": _instant_text(issue_instant),
        "Destination": destination,
        "AssertionConsumerServiceURL": acs_url,
        "ProtocolBinding": BINDING_POST,
    })
    etree.SubElement(root, _q(NS_SAML, "Issuer")).text = sp_entity_id
    etree.SubElement(root, _q(NS_SAMLP, "NameIDPolicy"), {"Format": name_id_format, "AllowCreate": "true"})
    return etree.tostring(root, encoding="UTF-8")


def redirect_url(sso_url: str, request_xml: bytes, relay_state: str) -> str:
    """HTTP-Redirect binding: raw DEFLATE, base64, then URL-encoded (unsigned)."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(request_xml) + compressor.flush()
    params = urlencode({"SAMLRequest": base64.b64encode(deflated).decode("ascii"), "RelayState": relay_state})
    return sso_url + ("&" if "?" in sso_url else "?") + params


# ---------------------------------------------------------------------------
# IdP metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdPMetadata:
    entity_id: str
    sso_url: str
    certificates: list[str]
    name_id_formats: list[str] = field(default_factory=list)


def is_https_url(value: Optional[str]) -> bool:
    parts = urlsplit(value or "")
    return parts.scheme == "https" and bool(parts.hostname)


def parse_idp_metadata(data: bytes, expected_entity_id: str) -> IdPMetadata:
    """The IdP EntityDescriptor named ``expected_entity_id`` (also inside an
    EntitiesDescriptor): its HTTP-Redirect SSO URL and signing certificates.

    Refused: no such entity, no IDPSSODescriptor for SAML 2.0, an IdP that
    demands signed AuthnRequests (not supported), no HTTP-Redirect
    SingleSignOnService, a non-https SSO URL, no signing certificate. The
    metadata's own signature is not verified: trust comes from fetching it
    over https from the URL the administrator configured.
    """
    root = parse_xml(data, reason="metadata_failed", limit=MAX_METADATA_BYTES, what="IdP metadata")
    if root.tag == _q(NS_MD, "EntityDescriptor"):
        entities = [root]
    elif root.tag == _q(NS_MD, "EntitiesDescriptor"):
        entities = list(root.iter(_q(NS_MD, "EntityDescriptor")))
    else:
        raise SAMLError("metadata_failed", f"the document is not SAML metadata (root element {root.tag})")
    matches = [e for e in entities if e.get("entityID") == expected_entity_id]
    if not matches:
        named = ", ".join(sorted({str(e.get("entityID")) for e in entities})[:5])
        raise SAMLError("metadata_failed",
                        f"the metadata does not describe entity {expected_entity_id!r} (it names: {named or 'none'})")
    entity = matches[0]
    idp = next((d for d in entity.findall(_q(NS_MD, "IDPSSODescriptor"))
                if PROTOCOL in (d.get("protocolSupportEnumeration") or "").split()), None)
    if idp is None:
        raise SAMLError("metadata_failed", "the entity has no IDPSSODescriptor for SAML 2.0")
    if (idp.get("WantAuthnRequestsSigned") or "").strip().lower() in ("true", "1"):
        raise SAMLError("metadata_failed", "the IdP demands signed AuthnRequests (WantAuthnRequestsSigned); "
                        "PySOAR sends unsigned requests, so this IdP cannot be used until request signing ships")
    sso_url = next((s.get("Location") for s in idp.findall(_q(NS_MD, "SingleSignOnService"))
                    if s.get("Binding") == BINDING_REDIRECT and s.get("Location")), None)
    if not sso_url:
        raise SAMLError("metadata_failed", "the IdP offers no HTTP-Redirect SingleSignOnService "
                        "(PySOAR sends AuthnRequests with the HTTP-Redirect binding)")
    if not is_https_url(sso_url):
        raise SAMLError("metadata_failed", f"the IdP single sign-on URL {sso_url!r} is not https")
    certs: list[str] = []
    for key in idp.findall(_q(NS_MD, "KeyDescriptor")):
        if key.get("use") not in (None, "", "signing"):
            continue
        for node in key.iter(_q(NS_DS, "X509Certificate")):
            pem = normalise_certificate(node.text or "")
            if pem not in certs:
                certs.append(pem)
    if not certs:
        raise SAMLError("metadata_failed", "the IdP metadata lists no signing certificate")
    if len(certs) > MAX_CERTIFICATES:
        raise SAMLError("metadata_failed", f"the IdP metadata lists {len(certs)} signing certificates; "
                        f"at most {MAX_CERTIFICATES} are kept")
    formats = [(n.text or "").strip() for n in idp.findall(_q(NS_MD, "NameIDFormat")) if (n.text or "").strip()]
    return IdPMetadata(entity_id=expected_entity_id, sso_url=str(sso_url), certificates=certs, name_id_formats=formats)


@asynccontextmanager
async def _http_stream(url: str) -> AsyncIterator[httpx.Response]:
    """A streamed GET to the IdP through netguard (internal addresses refused,
    pinned address, no redirects); the body is not read here.
    ``SAMLError("provider_unreachable")`` when refused or unreachable. Tests
    replace this boundary with a fake identity provider."""
    try:
        target = await resolve_and_vet(url)
    except OutboundTargetRefused as exc:
        raise SAMLError("provider_unreachable", f"outbound target refused: {exc}") from exc
    pinned = merge_pinned_kwargs(target, {"Accept": "application/samlmetadata+xml, application/xml, text/xml"})
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            async with client.stream("GET", target.pinned_url, headers=pinned["headers"],
                                     extensions=pinned["extensions"]) as response:
                yield response
    except httpx.HTTPError as exc:
        raise SAMLError("provider_unreachable", f"{type(exc).__name__}: {exc}") from exc


async def read_capped(response: httpx.Response, limit: int, what: str) -> bytes:
    """The body, refused (``metadata_failed``) when a declared Content-Length
    exceeds ``limit`` (nothing is read) or once more than ``limit`` bytes arrived."""
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError as exc:
            raise SAMLError("metadata_failed", f"{what} has an invalid Content-Length {declared!r}") from exc
        if size > limit:
            raise SAMLError("metadata_failed", f"{what} declares {size} bytes; at most {limit} are accepted")
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise SAMLError("metadata_failed", f"{what} is larger than {limit} bytes; the download was stopped")
    return bytes(body)


async def _download_metadata(url: str) -> bytes:
    async with _http_stream(url) as response:
        if response.status_code != 200:
            raise SAMLError("metadata_failed", f"GET {url} answered HTTP {response.status_code}")
        try:
            return await read_capped(response, MAX_METADATA_BYTES, "IdP metadata")
        except httpx.HTTPError as exc:
            raise SAMLError("provider_unreachable", f"{type(exc).__name__}: {exc}") from exc


async def fetch_idp_metadata(url: str, expected_entity_id: str) -> IdPMetadata:
    """Fetch (never cached, streamed, capped at ``MAX_METADATA_BYTES``, within
    ``METADATA_DEADLINE_SECONDS`` overall) and parse the IdP metadata at ``url``."""
    if not is_https_url(url):
        raise SAMLError("metadata_failed", "the IdP metadata URL must be https")
    try:
        data = await asyncio.wait_for(_download_metadata(url), timeout=METADATA_DEADLINE_SECONDS)
    except TimeoutError as exc:
        raise SAMLError("metadata_failed",
                        f"the IdP metadata download did not finish within {METADATA_DEADLINE_SECONDS:g} s") from exc
    return parse_idp_metadata(data, expected_entity_id)


# ---------------------------------------------------------------------------
# Response validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SAMLIdentity:
    """What a verified assertion says about the user."""

    name_id: str
    name_id_format: Optional[str]
    assertion_id: str
    in_response_to: Optional[str]
    #: The latest instant (skew included) the assertion is acceptable; the replay cache keeps its id until then.
    valid_until: datetime
    session_index: Optional[str]
    attributes: dict[str, list[str]]

    def claims(self, *, email_attribute: str, name_attribute: str, groups_attribute: Optional[str]) -> dict[str, Any]:
        """The claims dictionary the shared SSO user resolution reads: ``sub`` =
        NameID, the email / name attributes as strings, the groups attribute as
        a list. With no email attribute, an emailAddress NameID is the email."""
        claims: dict[str, Any] = {}
        for name, values in self.attributes.items():
            claims[name] = values[0] if len(values) == 1 else list(values)
        email = self.attributes.get(email_attribute)
        if email:
            claims[email_attribute] = email[0]
        elif self.name_id_format == NAMEID_EMAIL and "@" in self.name_id:
            claims[email_attribute] = self.name_id
        name = self.attributes.get(name_attribute)
        if name:
            claims[name_attribute] = name[0]
        if groups_attribute:
            claims[groups_attribute] = list(self.attributes.get(groups_attribute) or [])
        claims["sub"] = self.name_id
        return claims


def decode_post_response(value: str) -> bytes:
    """The ``SAMLResponse`` form field (base64, whitespace tolerated)."""
    compact = "".join((value or "").split())
    if not compact:
        raise SAMLError("saml_response_invalid", "the POST carried no SAMLResponse")
    if len(compact) > MAX_RESPONSE_BYTES * 4 // 3 + 4:
        raise SAMLError("saml_response_invalid", f"SAMLResponse is larger than {MAX_RESPONSE_BYTES} bytes")
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SAMLError("saml_response_invalid", "SAMLResponse is not base64") from exc


def _verify_signed(root: etree._Element, certificates: tuple[str, ...], *, location: str,
                   expected: etree._Element, what: str) -> etree._Element:
    """Verify the ds:Signature at ``location`` against each stored certificate;
    return the element the signature covers, which must be ``expected`` itself
    (same tag and ID). Everything downstream reads only this element."""
    if not certificates:
        raise SAMLError("saml_signature_invalid", "no IdP signing certificate is configured")
    config = SignatureConfiguration(location=location, signature_methods=ALLOWED_SIGNATURE_METHODS,
                                    digest_algorithms=ALLOWED_DIGESTS)
    failures: list[str] = []
    for pem in certificates:
        try:
            result = XMLVerifier().verify(root, x509_cert=pem, parser=_parser(), expect_config=config)
        except (SignXMLException, etree.LxmlError, ValueError) as exc:
            failures.append(f"{type(exc).__name__}: {exc}")
            continue
        signed = result.signed_xml  # type: ignore[union-attr]
        if signed is None or signed.tag != expected.tag or signed.get("ID") != expected.get("ID"):
            raise SAMLError("saml_signature_invalid", f"the signature does not cover the {what} itself")
        return signed
    raise SAMLError("saml_signature_invalid",
                    f"the {what} signature did not verify against the configured certificate(s): " + "; ".join(failures)[:1500])


def _text(element: Optional[etree._Element]) -> Optional[str]:
    if element is None or element.text is None:
        return None
    return element.text.strip() or None


def validate_response(xml: bytes, *, settings: SAMLSettings, idp_entity_id: str, sp_entity_id: str,
                      acs_url: str, now: Optional[datetime] = None) -> SAMLIdentity:
    """Verify a SAML Response for this SP and return the identity it asserts.

    Reasons: ``saml_response_invalid`` (malformed, DTD, not exactly one
    assertion), ``saml_status_failure``, ``saml_encrypted_unsupported``,
    ``saml_signature_invalid``, ``saml_conditions_failed`` (issuer, time window,
    audience, recipient, destination, missing bearer confirmation). The
    request-id match (``saml_unsolicited``) and the replay cache
    (``saml_replay``) need Redis and are checked by the route.
    """
    moment = now or datetime.now(timezone.utc)
    skew = timedelta(seconds=settings.clock_skew_seconds)
    root = parse_xml(xml, reason="saml_response_invalid", limit=MAX_RESPONSE_BYTES, what="SAML Response")
    if root.tag != _q(NS_SAMLP, "Response"):
        raise SAMLError("saml_response_invalid", f"expected a samlp:Response, got {root.tag}")

    status_code = root.find(f"{_q(NS_SAMLP, 'Status')}/{_q(NS_SAMLP, 'StatusCode')}")
    code = status_code.get("Value") if status_code is not None else None
    if code != STATUS_SUCCESS:
        nested = status_code.find(_q(NS_SAMLP, "StatusCode")) if status_code is not None else None
        message = _text(root.find(f"{_q(NS_SAMLP, 'Status')}/{_q(NS_SAMLP, 'StatusMessage')}"))
        raise SAMLError("saml_status_failure",
                        f"IdP status {code or 'missing'}"
                        + (f" / {nested.get('Value')}" if nested is not None else "")
                        + (f": {message[:300]}" if message else ""))

    for tag in ("EncryptedAssertion", "EncryptedID", "EncryptedAttribute"):
        if next(root.iter(_q(NS_SAML, tag)), None) is not None:
            raise SAMLError("saml_encrypted_unsupported",
                            f"the response carries saml:{tag}; encrypted assertions are not supported: "
                            "turn assertion encryption off for PySOAR at the IdP")

    assertions = list(root.iter(_q(NS_SAML, "Assertion")))
    if len(assertions) != 1 or assertions[0].getparent() is not root:
        raise SAMLError("saml_response_invalid",
                        f"expected exactly one assertion directly in the response, found {len(assertions)}")
    assertion = assertions[0]

    destination = root.get("Destination")
    if destination and destination != acs_url:
        raise SAMLError("saml_conditions_failed", f"response Destination {destination!r} is not this ACS ({acs_url})")
    response_issuer = _text(root.find(_q(NS_SAML, "Issuer")))
    if response_issuer and response_issuer != idp_entity_id:
        raise SAMLError("saml_conditions_failed", f"response Issuer {response_issuer!r} is not the IdP {idp_entity_id!r}")

    response_in_response_to = root.get("InResponseTo")
    if settings.want_response_signed:
        _verify_signed(root, settings.idp_certificates, location="./", expected=root, what="response")
    signed = _verify_signed(root, settings.idp_certificates, location=f"./{_q(NS_SAML, 'Assertion')}/",
                            expected=assertion, what="assertion")

    issuer = _text(signed.find(_q(NS_SAML, "Issuer")))
    if issuer != idp_entity_id:
        raise SAMLError("saml_conditions_failed", f"assertion Issuer {issuer!r} is not the IdP {idp_entity_id!r}")

    conditions = signed.find(_q(NS_SAML, "Conditions"))
    if conditions is None:
        raise SAMLError("saml_conditions_failed", "the assertion has no Conditions")
    not_on_or_after = parse_instant(conditions.get("NotOnOrAfter"), "Conditions NotOnOrAfter")
    if conditions.get("NotBefore"):
        not_before = parse_instant(conditions.get("NotBefore"), "Conditions NotBefore")
        if moment + skew < not_before:
            raise SAMLError("saml_conditions_failed",
                            f"the assertion is not valid before {not_before.isoformat()} (clock skew {skew.seconds} s)")
    if moment >= not_on_or_after + skew:
        raise SAMLError("saml_conditions_failed", f"the assertion expired at {not_on_or_after.isoformat()}")
    restrictions = conditions.findall(_q(NS_SAML, "AudienceRestriction"))
    if not restrictions:
        raise SAMLError("saml_conditions_failed", "the assertion has no AudienceRestriction")
    for restriction in restrictions:
        audiences = [_text(a) for a in restriction.findall(_q(NS_SAML, "Audience"))]
        if sp_entity_id not in audiences:
            raise SAMLError("saml_conditions_failed",
                            f"the assertion audience {audiences!r} does not include this SP ({sp_entity_id})")

    subject = signed.find(_q(NS_SAML, "Subject"))
    name_id_el = subject.find(_q(NS_SAML, "NameID")) if subject is not None else None
    name_id = _text(name_id_el)
    if not name_id:
        raise SAMLError("saml_conditions_failed", "the assertion has no Subject NameID")
    name_id_format = name_id_el.get("Format") if name_id_el is not None else None
    if name_id_format == NAMEID_TRANSIENT:
        raise SAMLError("saml_conditions_failed", "a transient NameID changes per login and cannot identify an account; "
                        "release a persistent or emailAddress NameID to PySOAR")

    confirmation_until: Optional[datetime] = None
    in_response_to: Optional[str] = None
    problems: list[str] = []
    for confirmation in subject.findall(_q(NS_SAML, "SubjectConfirmation")):
        if confirmation.get("Method") != CM_BEARER:
            problems.append(f"confirmation method {confirmation.get('Method')!r} is not bearer")
            continue
        data = confirmation.find(_q(NS_SAML, "SubjectConfirmationData"))
        if data is None:
            problems.append("bearer confirmation has no SubjectConfirmationData")
            continue
        if data.get("Recipient") != acs_url:
            problems.append(f"Recipient {data.get('Recipient')!r} is not this ACS ({acs_url})")
            continue
        try:
            until = parse_instant(data.get("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter")
        except SAMLError as exc:
            problems.append(exc.detail)
            continue
        if moment >= until + skew:
            problems.append(f"the bearer confirmation expired at {until.isoformat()}")
            continue
        confirmation_until = until
        in_response_to = data.get("InResponseTo")
        break
    if confirmation_until is None:
        raise SAMLError("saml_conditions_failed",
                        "no usable bearer SubjectConfirmation: " + ("; ".join(problems) or "none present"))
    if in_response_to and response_in_response_to and in_response_to != response_in_response_to:
        raise SAMLError("saml_conditions_failed", "the response and assertion name different requests (InResponseTo)")
    if not in_response_to and settings.want_response_signed:
        in_response_to = response_in_response_to  # covered by the verified response signature

    authn = signed.find(_q(NS_SAML, "AuthnStatement"))
    if authn is None:
        raise SAMLError("saml_conditions_failed", "the assertion has no AuthnStatement (it is not a login)")
    if authn.get("SessionNotOnOrAfter"):
        session_end = parse_instant(authn.get("SessionNotOnOrAfter"), "SessionNotOnOrAfter")
        if moment >= session_end + skew:
            raise SAMLError("saml_conditions_failed", f"the IdP session ended at {session_end.isoformat()}")

    # Attributes are keyed by Name only: a FriendlyName is a display hint any
    # attribute may carry, so it never satisfies or shadows a configured Name.
    # A Name that appears twice is ambiguous (which one is the email, which the
    # groups?), so such an assertion is unusable rather than first- or last-wins.
    attributes: dict[str, list[str]] = {}
    for statement in signed.findall(_q(NS_SAML, "AttributeStatement")):
        for attribute in statement.findall(_q(NS_SAML, "Attribute")):
            name = (attribute.get("Name") or "").strip()
            if not name:
                continue
            if name in attributes:
                raise SAMLError("saml_response_invalid",
                                f"the assertion carries attribute {name!r} more than once; it is ambiguous and refused")
            attributes[name] = [v for v in (_text(x) for x in attribute.findall(_q(NS_SAML, "AttributeValue"))) if v]

    assertion_id = signed.get("ID") or ""
    return SAMLIdentity(
        name_id=name_id,
        name_id_format=name_id_format,
        assertion_id=assertion_id,
        in_response_to=in_response_to,
        valid_until=max(not_on_or_after, confirmation_until) + skew,
        session_index=authn.get("SessionIndex"),
        attributes=attributes,
    )


def replay_key(config_id: str, assertion_id: str) -> str:
    """Replay-cache key, per configuration: one IdP's ids never collide with another's."""
    return REPLAY_KEY.format(hashlib.sha256(f"{config_id}:{assertion_id}".encode("utf-8")).hexdigest())
