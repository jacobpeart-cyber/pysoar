"""Regression tests for the python-jose -> PyJWT migration.

python-jose (and its `ecdsa` dependency, GHSA Minerva timing attack, no
patched release) was removed in favor of PyJWT. These tests prove
behavioral parity on the wire:

- Tokens constructed exactly the way python-jose built them (manual
  hmac/hashlib compact JWT) still decode through src.core.security.
- Expired / tampered tokens are rejected (return None -> 401 path).
- The session-gate style decode (verify_exp disabled, signature still
  verified) keeps working.
- Agent attestation JWS (RFC 7515 compact, RS256 and ES256) signed the
  "old way" (raw cryptography primitives, identical bytes to what jose
  produced) still verify, and forgeries still 401.
"""

import base64
import hashlib
import hmac
import json
import time

import jwt as pyjwt
import pytest
from fastapi import HTTPException

from src.agents.attestation import verify_request_signature
from src.core.config import settings
from src.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    decode_token_full,
    verify_token,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _manual_hs256_token(claims: dict, secret: str) -> str:
    """Build a compact JWT byte-for-byte the way python-jose did (HS256)."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


class TestHS256TokenParity:
    def test_old_style_jose_token_still_decodes(self):
        """A token minted by python-jose (simulated with raw hmac) must
        still be accepted — existing sessions survive the migration."""
        claims = {
            "sub": "user-42",
            "exp": int(time.time()) + 300,
            "type": "access",
            "jti": "legacy-jti",
            "iat": int(time.time()),
        }
        token = _manual_hs256_token(claims, settings.jwt_secret_key)

        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-42"
        assert payload["jti"] == "legacy-jti"
        assert verify_token(token, token_type="access") == "user-42"

    def test_round_trip_access_and_refresh(self):
        access = create_access_token("user-1", extra_claims={"org_id": "org-9"})
        refresh = create_refresh_token("user-1")
        assert isinstance(access, str) and isinstance(refresh, str)

        payload = decode_token(access)
        assert payload["sub"] == "user-1"
        assert payload["type"] == "access"
        assert payload["org_id"] == "org-9"
        assert isinstance(payload["exp"], int)  # datetime exp serialized to int

        assert verify_token(refresh, token_type="refresh") == "user-1"
        assert verify_token(access, token_type="refresh") is None
        assert decode_token_full(access)["jti"]

    def test_expired_token_returns_none(self):
        """Expired -> None so callers keep returning 401, never 500."""
        claims = {"sub": "u", "exp": int(time.time()) - 100, "type": "access", "jti": "x"}
        token = _manual_hs256_token(claims, settings.jwt_secret_key)
        assert decode_token(token) is None
        assert verify_token(token) is None

    def test_tampered_signature_rejected(self):
        token = create_access_token("user-1")
        head, payload, sig = token.split(".")
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        assert decode_token(f"{head}.{payload}.{flipped}") is None

    def test_wrong_key_rejected(self):
        token = _manual_hs256_token(
            {"sub": "u", "exp": int(time.time()) + 300}, "some-other-secret"
        )
        assert decode_token(token) is None

    def test_garbage_token_returns_none(self):
        assert decode_token("not-a-jwt") is None
        assert decode_token("") is None

    def test_alg_none_rejected(self):
        """alg=none tokens must never be accepted by the pinned decode."""
        header = _b64url(b'{"alg":"none","typ":"JWT"}')
        payload = _b64url(json.dumps({"sub": "evil", "exp": int(time.time()) + 300}).encode())
        assert decode_token(f"{header}.{payload}.") is None

    def test_session_gate_style_decode_ignores_exp_but_not_signature(self):
        """session_gate/zerotrust decode with verify_exp=False must still
        read jti from an expired-but-authentic token, and reject forgeries."""
        claims = {"sub": "u", "exp": int(time.time()) - 100, "jti": "gate-jti"}
        token = _manual_hs256_token(claims, settings.jwt_secret_key)

        payload = pyjwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=["HS256"],
            options={"verify_exp": False, "verify_signature": True},
        )
        assert payload["jti"] == "gate-jti"

        forged = _manual_hs256_token(claims, "attacker-secret")
        with pytest.raises(pyjwt.PyJWTError):
            pyjwt.decode(
                forged,
                settings.jwt_secret_key,
                algorithms=["HS256"],
                options={"verify_exp": False, "verify_signature": True},
            )


# ---------------------------------------------------------------------------
# Agent attestation JWS (RS256 / ES256 over the raw request body)
# ---------------------------------------------------------------------------


class _FakeRequest:
    def __init__(self, body: bytes, headers: dict):
        self._body = body
        self.headers = headers

    async def body(self) -> bytes:
        return self._body


def _rs256_jws_old_way(payload: bytes, private_key) -> str:
    """Compact JWS exactly as python-jose emitted it: RSASSA-PKCS1-v1_5 SHA-256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = _b64url(json.dumps({"alg": "RS256"}, separators=(",", ":")).encode())
    body = _b64url(payload)
    signing_input = f"{header}.{body}".encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{_b64url(sig)}"


def _es256_jws_old_way(payload: bytes, private_key) -> str:
    """Compact JWS as jose emitted for ES256: raw R||S (2x32 bytes) signature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    header = _b64url(json.dumps({"alg": "ES256"}, separators=(",", ":")).encode())
    body = _b64url(payload)
    signing_input = f"{header}.{body}".encode("ascii")
    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header}.{body}.{_b64url(raw)}"


def _pem(public_key) -> str:
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


@pytest.mark.asyncio
class TestAttestationJWSParity:
    async def test_rs256_jws_signed_old_way_verifies(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        body = b'{"agent_id":"a-1","hostname":"host-1"}'
        jws_token = _rs256_jws_old_way(body, key)

        req = _FakeRequest(body, {"x-agent-jws": jws_token})
        payload = await verify_request_signature(req, _pem(key.public_key()))
        assert payload == body

    async def test_es256_jws_signed_old_way_verifies(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        body = b'{"agent_id":"a-2"}'
        jws_token = _es256_jws_old_way(body, key)

        req = _FakeRequest(body, {"x-agent-jws": jws_token})
        payload = await verify_request_signature(req, _pem(key.public_key()))
        assert payload == body

    async def test_payload_body_mismatch_is_401(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jws_token = _rs256_jws_old_way(b'{"agent_id":"a-1"}', key)

        req = _FakeRequest(b'{"agent_id":"tampered"}', {"x-agent-jws": jws_token})
        with pytest.raises(HTTPException) as exc:
            await verify_request_signature(req, _pem(key.public_key()))
        assert exc.value.status_code == 401

    async def test_wrong_key_is_401(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        body = b"payload"
        jws_token = _rs256_jws_old_way(body, signer)

        req = _FakeRequest(body, {"x-agent-jws": jws_token})
        with pytest.raises(HTTPException) as exc:
            await verify_request_signature(req, _pem(other.public_key()))
        assert exc.value.status_code == 401

    async def test_missing_signature_header_is_401(self):
        req = _FakeRequest(b"body", {})
        with pytest.raises(HTTPException) as exc:
            await verify_request_signature(req, "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----")
        assert exc.value.status_code == 401

    async def test_no_registered_key_skips_verification(self):
        req = _FakeRequest(b"body", {})
        assert await verify_request_signature(req, None) == b""

    async def test_hs256_jws_rejected_for_attestation(self):
        """Attestation pins RS256/ES256; an HS256 JWS (attacker using the
        PEM string as an HMAC key) must be rejected."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = _pem(key.public_key())
        body = b"payload"
        header = _b64url(b'{"alg":"HS256"}')
        b = _b64url(body)
        sig = hmac.new(pem.encode(), f"{header}.{b}".encode(), hashlib.sha256).digest()
        forged = f"{header}.{b}.{_b64url(sig)}"

        req = _FakeRequest(body, {"x-agent-jws": forged})
        with pytest.raises(HTTPException) as exc:
            await verify_request_signature(req, pem)
        assert exc.value.status_code == 401
