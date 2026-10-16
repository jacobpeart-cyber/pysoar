"""A fake OpenID provider for the SSO tests (used by test_sso_oidc.py and
test_tenancy_sso.py).

The provider is real enough to exercise the code under test end to end: an
RSA key generated per test signs ID tokens with PyJWT, the discovery document
and JWKS are served as JSON, and the token endpoint checks the authorization
code, the redirect URI, client authentication and the PKCE S256 verifier. It is
plugged in by replacing ``src.identity.oidc._http_request`` (the single
outbound boundary), so netguard is not consulted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Optional
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from src.identity.models import SSOConfiguration


def stateful_redis(redis_mock: AsyncMock) -> dict[str, str]:
    """Give the Redis mock a real key/value store (get, set, setex, getdel, delete, exists, incr)."""
    store: dict[str, str] = {}

    async def _get(key: str):
        return store.get(key)

    async def _set(key: str, value, *args, **kwargs):
        store[key] = str(value)
        return True

    async def _setex(key: str, ttl: int, value):
        store[key] = str(value)
        return True

    async def _getdel(key: str):
        return store.pop(key, None)

    async def _delete(*keys: str):
        return sum(1 for k in keys if store.pop(k, None) is not None)

    async def _exists(key: str):
        return 1 if key in store else 0

    async def _incr(key: str):
        store[key] = str(int(store.get(key, 0)) + 1)
        return int(store[key])

    redis_mock.get = AsyncMock(side_effect=_get)
    redis_mock.set = AsyncMock(side_effect=_set)
    redis_mock.setex = AsyncMock(side_effect=_setex)
    redis_mock.getdel = AsyncMock(side_effect=_getdel)
    redis_mock.delete = AsyncMock(side_effect=_delete)
    redis_mock.exists = AsyncMock(side_effect=_exists)
    redis_mock.incr = AsyncMock(side_effect=_incr)
    return store


class FakeIdP:
    """One identity provider at ``issuer``."""

    def __init__(self, issuer: str = "https://idp.example.com", client_id: str = "pysoar-client",
                 client_secret: str = "s3cret-value") -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.kid = "key-1"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.advertised_issuer = issuer
        self.calls: list[tuple[str, str]] = []
        # Authorization codes the provider has issued: code -> request params.
        self.codes: dict[str, dict[str, str]] = {}
        # Claims the next ID token carries (merged over the defaults), and
        # signing overrides used by the negative tests.
        self.claims: dict[str, Any] = {}
        self.sign_kid: Optional[str] = None
        self.sign_key: Any = None
        self.extra_jwks_keys: list[dict[str, Any]] = []
        self.token_status = 200

    # -- provider documents ------------------------------------------------

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.advertised_issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/jwks",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "scopes_supported": ["openid", "email", "profile", "groups"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def jwks(self) -> dict[str, Any]:
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        public.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [public, *self.extra_jwks_keys]}

    # -- the authorize step the browser would perform ------------------------

    def authorize(self, location: str, *, sub: str = "idp-user-1", email: str = "jane@acme-sso.io",
                  **claims: Any) -> tuple[str, str]:
        """Accept the authorization request at ``location``; return (code, state)."""
        params = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        assert params["response_type"] == "code"
        assert params["code_challenge_method"] == "S256"
        assert params["client_id"] == self.client_id
        code = uuid.uuid4().hex
        self.codes[code] = params
        self.claims = {"sub": sub, "email": email, "email_verified": True, "name": "Jane Doe", **claims}
        return code, params["state"]

    def id_token(self, params: dict[str, str]) -> str:
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "aud": self.client_id,
            "iat": now,
            "exp": now + 300,
            "nonce": params["nonce"],
            **self.claims,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        return jwt.encode(payload, self.sign_key or self.private_key, algorithm="RS256",
                          headers={"kid": self.sign_kid or self.kid})

    # -- the HTTP boundary -------------------------------------------------

    async def handle(self, method: str, url: str, *, data: Optional[dict[str, str]] = None,
                     headers: Optional[dict[str, str]] = None) -> httpx.Response:
        self.calls.append((method, url))
        request = httpx.Request(method, url)
        if url == f"{self.issuer}/.well-known/openid-configuration":
            return httpx.Response(200, json=self.discovery(), request=request)
        if url == f"{self.issuer}/jwks":
            return httpx.Response(200, json=self.jwks(), request=request)
        if url == f"{self.issuer}/token" and method == "POST":
            return self._token(request, data or {}, headers or {})
        return httpx.Response(404, json={"error": "not_found"}, request=request)

    def _token(self, request: httpx.Request, data: dict[str, str], headers: dict[str, str]) -> httpx.Response:
        if self.token_status != 200:
            return httpx.Response(self.token_status, json={"error": "server_error", "error_description": "<b>boom</b>"},
                                  request=request)
        auth = headers.get("Authorization", "")
        expected = "Basic " + base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        if auth != expected:
            return httpx.Response(401, json={"error": "invalid_client"}, request=request)
        params = self.codes.pop(data.get("code", ""), None)
        if params is None or data.get("grant_type") != "authorization_code":
            return httpx.Response(400, json={"error": "invalid_grant"}, request=request)
        if data.get("redirect_uri") != params["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "redirect_uri"},
                                  request=request)
        verifier = data.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if challenge != params["code_challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "pkce"}, request=request)
        return httpx.Response(200, json={
            "access_token": "idp-access", "token_type": "Bearer", "expires_in": 300,
            "id_token": self.id_token(params),
        }, request=request)

    def calls_to(self, suffix: str) -> int:
        return sum(1 for _m, u in self.calls if u.endswith(suffix))


def install(monkeypatch: Any, *idps: FakeIdP) -> None:
    """Route ``src.identity.oidc._http_request`` to the fake providers."""

    async def fake_http(method: str, url: str, *, data=None, headers=None) -> httpx.Response:
        for idp in idps:
            if url.startswith(idp.issuer + "/"):
                return await idp.handle(method, url, data=data, headers=headers)
        return httpx.Response(404, request=httpx.Request(method, url))

    monkeypatch.setattr("src.identity.oidc._http_request", fake_http)


async def configure(db: Any, org_id: str, idp: FakeIdP, *, domains: tuple[str, ...] = ("acme-sso.io",),
                    **overrides: Any) -> SSOConfiguration:
    """Store an enabled, tested configuration for ``org_id`` pointing at ``idp``."""
    values: dict[str, Any] = {
        "organization_id": org_id,
        "protocol": "oidc",
        "display_name": "Acme IdP",
        "issuer": idp.issuer,
        "client_id": idp.client_id,
        "client_secret": idp.client_secret,
        "scopes": "openid email profile",
        "allowed_email_domains": list(domains),
        "group_role_map": {},
        "jit_provisioning": True,
        "default_role": "viewer",
        "require_email_verified": True,
        "trust_idp_mfa": True,
        "enabled": True,
        "last_test_status": "ok",
    }
    values.update(overrides)
    config = SSOConfiguration(**values)
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return config


async def start(client: Any, slug: str) -> httpx.Response:
    return await client.get(f"/api/v1/auth/sso/{slug}/start", follow_redirects=False)


def query(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
