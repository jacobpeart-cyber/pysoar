"""OpenID Connect single sign-on: discovery, authorization request, code exchange
and ID token validation.

One organisation has at most one identity provider (``SSOConfiguration``). The
flow (routes in ``src.api.v1.endpoints.sso``):

1. ``start``: the provider's metadata is fetched from
   ``<issuer>/.well-known/openid-configuration`` (or ``discovery_url``), a
   ``state``, ``nonce`` and PKCE S256 verifier are generated and kept in Redis
   under ``sso:state:<state>`` for 10 minutes, and the browser is sent to the
   authorization endpoint.
2. ``callback``: the state is consumed (single use, ``GETDEL``), the code is
   exchanged at the token endpoint, and the ID token is verified with PyJWT
   against the provider's JWKS (cached per configuration for an hour, refetched once
   when the token names an unknown ``kid``): signature, ``iss``, ``aud`` =
   client_id, ``exp``, ``nonce``, and an asymmetric ``alg`` that matches the key.

Every outbound call goes through ``_http_request``, which resolves and vets the
target with ``src.integrations.netguard`` (private and internal addresses are
refused) and sends the request to the pinned address. Redirects are never
followed. Tests replace ``_http_request`` with a fake identity provider.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
import jwt

from src.core.logging import get_logger
from src.integrations.netguard import OutboundTargetRefused, merge_pinned_kwargs, resolve_and_vet

logger = get_logger(__name__)

#: Seconds a pending authorization request (state, nonce, PKCE verifier) lives.
STATE_TTL_SECONDS = 600
#: Seconds the one-time login code minted by the callback lives.
LOGIN_CODE_TTL_SECONDS = 60
#: Seconds provider metadata and JWKS stay cached per issuer.
JWKS_TTL_SECONDS = 3600
#: Outbound request timeout (seconds).
HTTP_TIMEOUT_SECONDS = 10.0
#: Largest response body accepted from the provider.
MAX_RESPONSE_BYTES = 512 * 1024
#: Allowed clock skew when checking ``exp`` / ``iat`` / ``nbf``.
CLOCK_SKEW_SECONDS = 60

#: Asymmetric signature algorithms accepted for ID tokens. ``none`` and the
#: HMAC family are refused: an HS256 token "signed" with the client secret or a
#: public key would otherwise verify.
ALLOWED_ID_TOKEN_ALGS: frozenset[str] = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)

#: Browser-binding cookie set by ``start``: the state and the one-time login
#: code are only redeemable by the browser holding it (login CSRF defence).
BROWSER_COOKIE = "pysoar_sso"

STATE_KEY = "sso:state:{}"
LOGIN_KEY = "sso:login:{}"
JWKS_KEY = "sso:jwks:{}"
DISCOVERY_KEY = "sso:discovery:{}"


class OIDCError(Exception):
    """A step of the OIDC flow failed.

    ``reason`` is a short fixed key safe to show the user (it ends up in the
    ``/login?sso_error=`` redirect); ``detail`` is for the audit row and logs and
    may quote the provider.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail or reason


class UnknownKeyId(OIDCError):  # noqa: N818 (an OIDCError reason, not a generic error)
    """The ID token names a ``kid`` the cached JWKS does not hold."""


@dataclass(frozen=True)
class ProviderMetadata:
    """The parts of an OpenID provider configuration the flow uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: Optional[str]
    scopes_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    code_challenge_methods_supported: list[str]
    id_token_signing_alg_values_supported: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
            "userinfo_endpoint": self.userinfo_endpoint,
            "scopes_supported": self.scopes_supported,
            "token_endpoint_auth_methods_supported": self.token_endpoint_auth_methods_supported,
            "code_challenge_methods_supported": self.code_challenge_methods_supported,
            "id_token_signing_alg_values_supported": self.id_token_signing_alg_values_supported,
        }


# ---------------------------------------------------------------------------
# Outbound HTTP (the single boundary)
# ---------------------------------------------------------------------------


async def _http_request(
    method: str,
    url: str,
    *,
    data: Optional[dict[str, str]] = None,
    headers: Optional[dict[str, str]] = None,
) -> httpx.Response:
    """Send one request to the identity provider through netguard.

    The host is resolved once and vetted (internal addresses refused), and the
    request goes to the pinned address with the original Host / SNI. Redirects
    are not followed. Raises ``OIDCError("provider_unreachable")`` when the
    target is refused or the connection fails.
    """
    try:
        target = await resolve_and_vet(url)
    except OutboundTargetRefused as exc:
        raise OIDCError("provider_unreachable", f"outbound target refused: {exc}") from exc
    pinned = merge_pinned_kwargs(target, {"Accept": "application/json", **(headers or {})})
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            return await client.request(
                method,
                target.pinned_url,
                data=data,
                headers=pinned["headers"],
                extensions=pinned["extensions"],
            )
    except httpx.HTTPError as exc:
        raise OIDCError("provider_unreachable", f"{type(exc).__name__}: {exc}") from exc


def _json_body(response: httpx.Response, what: str) -> dict[str, Any]:
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise OIDCError(f"{what}_failed", f"{what} response is larger than {MAX_RESPONSE_BYTES} bytes")
    try:
        body = response.json()
    except ValueError as exc:
        raise OIDCError(f"{what}_failed", f"{what} response is not JSON (HTTP {response.status_code})") from exc
    if not isinstance(body, dict):
        raise OIDCError(f"{what}_failed", f"{what} response is not a JSON object")
    return body


def _cache_key(template: str, value: str) -> str:
    return template.format(hashlib.sha256(value.encode("utf-8")).hexdigest())


# Cache entries are keyed by the SSO configuration (``scope`` = its id) and the
# exact URL they came from, never by the issuer alone: two organisations may
# name the same issuer, and one of them must never be able to plant keys the
# other's ID tokens are verified against.


def metadata_cache_key(scope: str, issuer: str, discovery_url: Optional[str]) -> str:
    return _cache_key(DISCOVERY_KEY, f"{scope}:{discovery_url_for(issuer, discovery_url)}|{issuer}")


def jwks_cache_key(scope: str, jwks_uri: str) -> str:
    return _cache_key(JWKS_KEY, f"{scope}:{jwks_uri}")


# ---------------------------------------------------------------------------
# Discovery and JWKS
# ---------------------------------------------------------------------------


def discovery_url_for(issuer: str, discovery_url: Optional[str]) -> str:
    """The provider configuration URL: the override, else the well-known path."""
    if discovery_url:
        return discovery_url
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


def _issuers_match(expected: str, actual: str) -> bool:
    # OIDC Discovery requires an exact match; a trailing slash is the one
    # difference providers and admins routinely disagree on.
    return expected.rstrip("/") == str(actual).rstrip("/")


def _str_list(value: Any) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


async def fetch_metadata(issuer: str, discovery_url: Optional[str]) -> ProviderMetadata:
    """Fetch and check the provider configuration (never cached)."""
    url = discovery_url_for(issuer, discovery_url)
    response = await _http_request("GET", url)
    if response.status_code != 200:
        raise OIDCError("discovery_failed", f"GET {url} answered HTTP {response.status_code}")
    body = _json_body(response, "discovery")
    advertised = body.get("issuer")
    if not advertised or not _issuers_match(issuer, advertised):
        raise OIDCError(
            "discovery_failed",
            f"provider issuer {advertised!r} does not match the configured issuer {issuer!r}",
        )
    missing = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if not body.get(k)]
    if missing:
        raise OIDCError("discovery_failed", "provider configuration lacks " + ", ".join(missing))
    return ProviderMetadata(
        issuer=str(advertised),
        authorization_endpoint=str(body["authorization_endpoint"]),
        token_endpoint=str(body["token_endpoint"]),
        jwks_uri=str(body["jwks_uri"]),
        userinfo_endpoint=str(body["userinfo_endpoint"]) if body.get("userinfo_endpoint") else None,
        scopes_supported=_str_list(body.get("scopes_supported")),
        token_endpoint_auth_methods_supported=_str_list(body.get("token_endpoint_auth_methods_supported")),
        code_challenge_methods_supported=_str_list(body.get("code_challenge_methods_supported")),
        id_token_signing_alg_values_supported=_str_list(body.get("id_token_signing_alg_values_supported")),
    )


async def get_metadata(redis: Any, issuer: str, discovery_url: Optional[str], *, scope: str) -> ProviderMetadata:
    """Provider configuration, cached per configuration (``scope``) and discovery URL for an hour."""
    key = metadata_cache_key(scope, issuer, discovery_url)
    cached = await redis.get(key)
    if cached:
        try:
            return ProviderMetadata(**json.loads(cached))
        except (TypeError, ValueError):
            logger.warning("sso_discovery_cache_unreadable", issuer=issuer)
    metadata = await fetch_metadata(issuer, discovery_url)
    await redis.setex(key, JWKS_TTL_SECONDS, json.dumps(metadata.as_dict()))
    return metadata


async def fetch_jwks(jwks_uri: str) -> dict[str, Any]:
    """Fetch the provider's JSON Web Key Set (never cached)."""
    response = await _http_request("GET", jwks_uri)
    if response.status_code != 200:
        raise OIDCError("jwks_failed", f"GET {jwks_uri} answered HTTP {response.status_code}")
    body = _json_body(response, "jwks")
    keys = body.get("keys")
    if not isinstance(keys, list) or not keys:
        raise OIDCError("jwks_failed", "JWKS holds no keys")
    return {"keys": [k for k in keys if isinstance(k, dict)]}


async def get_jwks(redis: Any, jwks_uri: str, *, scope: str, refresh: bool = False) -> dict[str, Any]:
    """JWKS cached per configuration (``scope``) and JWKS URL for an hour;
    ``refresh`` bypasses and rewrites the cache."""
    key = jwks_cache_key(scope, jwks_uri)
    if not refresh:
        cached = await redis.get(key)
        if cached:
            try:
                return json.loads(cached)
            except ValueError:
                logger.warning("sso_jwks_cache_unreadable", jwks_uri=jwks_uri)
    jwks = await fetch_jwks(jwks_uri)
    await redis.setex(key, JWKS_TTL_SECONDS, json.dumps(jwks))
    return jwks


# ---------------------------------------------------------------------------
# Authorization request
# ---------------------------------------------------------------------------


def new_pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge) per RFC 7636."""
    verifier = secrets.token_urlsafe(64)  # 86 characters, inside 43..128
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def authorization_url(
    metadata: ProviderMetadata,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    state: str,
    nonce: str,
    code_challenge: str,
    login_hint: Optional[str] = None,
) -> str:
    """The provider authorization URL for an authorization-code + PKCE request."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if login_hint:
        params["login_hint"] = login_hint
    sep = "&" if "?" in metadata.authorization_endpoint else "?"
    return metadata.authorization_endpoint + sep + urlencode(params)


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------


async def exchange_code(
    metadata: ProviderMetadata,
    *,
    client_id: str,
    client_secret: Optional[str],
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict[str, Any]:
    """Trade the authorization code for tokens at the token endpoint.

    Client authentication: ``client_secret_basic`` unless the provider only
    advertises ``client_secret_post``; a configuration without a secret is a
    public client (PKCE alone). The provider's error body goes to the audit
    detail only.
    """
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    headers: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
    methods = metadata.token_endpoint_auth_methods_supported
    if client_secret:
        if methods and "client_secret_basic" not in methods and "client_secret_post" in methods:
            data["client_id"] = client_id
            data["client_secret"] = client_secret
        else:
            raw = f"{_form_quote(client_id)}:{_form_quote(client_secret)}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    else:
        data["client_id"] = client_id

    response = await _http_request("POST", metadata.token_endpoint, data=data, headers=headers)
    if response.status_code != 200:
        snippet = response.text[:300] if response.content else ""
        raise OIDCError("token_exchange_failed", f"token endpoint answered HTTP {response.status_code}: {snippet}")
    body = _json_body(response, "token_exchange")
    if not body.get("id_token"):
        raise OIDCError("token_exchange_failed", "token response carries no id_token (is 'openid' in the scopes?)")
    return body


def _form_quote(value: str) -> str:
    # RFC 6749 2.3.1: client_id and secret are form-urlencoded before Basic encoding.
    from urllib.parse import quote_plus

    return quote_plus(value)


# ---------------------------------------------------------------------------
# ID token validation
# ---------------------------------------------------------------------------


def _select_key(jwks: dict[str, Any], kid: Optional[str], alg: str) -> dict[str, Any]:
    keys = [k for k in jwks.get("keys", []) if k.get("use", "sig") == "sig"]
    if kid is not None:
        matches = [k for k in keys if k.get("kid") == kid]
        if not matches:
            raise UnknownKeyId("invalid_id_token", f"ID token key id {kid!r} is not in the provider JWKS")
        return matches[0]
    # No kid: only unambiguous when one signing key fits the algorithm.
    candidates = [k for k in keys if not k.get("alg") or k.get("alg") == alg]
    if len(candidates) != 1:
        raise UnknownKeyId("invalid_id_token", "ID token names no key id and the JWKS has several keys")
    return candidates[0]


def validate_id_token(
    id_token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    client_id: str,
    nonce: str,
) -> dict[str, Any]:
    """Verify an ID token and return its claims.

    Raises ``UnknownKeyId`` when the token's ``kid`` is not in ``jwks`` (the
    caller refetches the JWKS once) and ``OIDCError("invalid_id_token")`` for
    every other failure, with the specific cause in ``detail``.
    """
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise OIDCError("invalid_id_token", f"ID token header unreadable: {exc}") from exc
    alg = str(header.get("alg") or "")
    if alg not in ALLOWED_ID_TOKEN_ALGS:
        raise OIDCError("invalid_id_token", f"ID token algorithm {alg!r} is not accepted")
    jwk = _select_key(jwks, header.get("kid"), alg)
    if jwk.get("alg") and jwk["alg"] != alg:
        raise OIDCError("invalid_id_token", f"ID token algorithm {alg} does not match the key's {jwk['alg']}")
    try:
        key = jwt.PyJWK(jwk, algorithm=alg)
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise OIDCError("invalid_id_token", f"provider key {header.get('kid')!r} is unusable: {exc}") from exc

    try:
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=[alg],
            audience=client_id,
            issuer=issuer,
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": ["iss", "aud", "exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise OIDCError("invalid_id_token", "ID token has expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise OIDCError("invalid_id_token", "ID token audience is not this client") from exc
    except jwt.InvalidIssuerError as exc:
        raise OIDCError("invalid_id_token", f"ID token issuer is not {issuer!r}") from exc
    except jwt.PyJWTError as exc:
        raise OIDCError("invalid_id_token", f"ID token rejected: {type(exc).__name__}: {exc}") from exc

    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != client_id:
        raise OIDCError("invalid_id_token", "ID token has several audiences and azp is not this client")
    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce, nonce):
        raise OIDCError("invalid_id_token", "ID token nonce does not match the authorization request")
    return claims


async def verify_id_token(
    redis: Any,
    metadata: ProviderMetadata,
    id_token: str,
    *,
    issuer: str,
    client_id: str,
    nonce: str,
    scope: str,
) -> dict[str, Any]:
    """``validate_id_token`` against the configuration's cached JWKS, refetched once on an unknown kid."""
    jwks = await get_jwks(redis, metadata.jwks_uri, scope=scope)
    try:
        return validate_id_token(id_token, jwks, issuer=issuer, client_id=client_id, nonce=nonce)
    except UnknownKeyId:
        logger.info("sso_jwks_refetch_unknown_kid", issuer=metadata.issuer)
        jwks = await get_jwks(redis, metadata.jwks_uri, scope=scope, refresh=True)
        try:
            return validate_id_token(id_token, jwks, issuer=issuer, client_id=client_id, nonce=nonce)
        except UnknownKeyId as exc:
            raise OIDCError("invalid_id_token", exc.detail) from exc


# ---------------------------------------------------------------------------
# Single-use Redis entries
# ---------------------------------------------------------------------------


async def put_json(redis: Any, key: str, ttl: int, value: dict[str, Any]) -> None:
    await redis.setex(key, ttl, json.dumps(value))


async def take_json(redis: Any, key: str) -> Optional[dict[str, Any]]:
    """Read and delete ``key`` atomically (``GETDEL``); None when absent."""
    raw = await redis.getdel(key)
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def new_browser_secret() -> str:
    """The ``pysoar_sso`` cookie value: 32 random URL-safe bytes."""
    return secrets.token_urlsafe(32)


def browser_binding(cookie: str) -> str:
    """What the Redis records store for the cookie: its SHA-256, never the value."""
    return hashlib.sha256(cookie.encode("utf-8")).hexdigest()


def binding_matches(cookie: Optional[str], stored: Any) -> bool:
    """Whether the request's cookie is the one the record was bound to (constant time)."""
    if not cookie or not isinstance(stored, str) or not stored:
        return False
    return hmac.compare_digest(browser_binding(cookie), stored)


def claim(claims: dict[str, Any], name: Optional[str]) -> Any:
    """A claim by name; dotted names walk nested objects (``realm_access.roles``)."""
    if not name:
        return None
    if name in claims:
        return claims[name]
    current: Any = claims
    for part in name.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].strip().lower() if "@" in email else ""
