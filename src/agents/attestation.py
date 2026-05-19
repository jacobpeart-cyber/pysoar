"""Agent attestation helpers: verify JWS signatures from enrolled agents.

When an agent exchanges its enrollment token it may submit a public
key (PEM). If present, the API enforces that future agent-originating
requests are JWS-signed using that key. This module provides a small
utility to verify compact JWS signatures over the raw request body.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import HTTPException, Request, status

from jose import jws

logger = logging.getLogger(__name__)


async def verify_request_signature(request: Request, public_key_pem: Optional[str]) -> bytes:
    """Verify the compact JWS in header `X-Agent-JWS` signs the raw body.

    Returns the signed payload bytes on success. Raises HTTPException on
    verification failure. If `public_key_pem` is falsy, the function
    returns an empty bytes object to indicate verification is not
    required.
    """
    if not public_key_pem:
        return b""

    signature = request.headers.get("x-agent-jws") or request.headers.get("x-agent-signature")
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent requests must be JWS-signed when agent public key is registered",
        )

    body = await request.body()
    try:
        # jose.jws.verify returns the payload bytes on success, raises otherwise
        payload = jws.verify(signature, public_key_pem, algorithms=["RS256", "ES256"])  # type: ignore
    except Exception as exc:  # noqa: BLE001
        logger.debug("agent jws verify failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent JWS signature",
        )

    # Require the signed payload to exactly match the raw request body.
    if payload != body:
        logger.debug("agent jws payload mismatch: signed != body (len signed=%d len body=%d)", len(payload), len(body))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWS payload does not match request body",
        )

    return payload
