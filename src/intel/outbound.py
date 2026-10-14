"""Outbound HTTP for the threat-intel and dark-web providers.

A thin wrapper over ``src/integrations/netguard.py``, the platform's single
outbound guard. VirusTotal, AbuseIPDB, AlienVault OTX, Have I Been Pwned,
abuse.ch and the threat feed URLs are reached through the two helpers below
only. For every request the target host is resolved once by
``netguard.resolve_and_vet`` (private, loopback, link-local / cloud metadata,
carrier-grade NAT, multicast, reserved and other non-global answers are
refused with ``OutboundTargetRefused``) and the request is sent to the vetted
IP literal with the original hostname in the ``Host`` header and as the TLS
SNI / certificate name (``netguard.merge_pinned_kwargs``), so a DNS answer
that changes after the check cannot steer the connection. Requests carry
explicit timeouts and never follow redirects (a 3xx answer is returned to the
caller, which reports it as a provider error).

Tests replace ``TRANSPORT`` with an ``httpx.MockTransport`` (the transport
boundary) and ``netguard._getaddrinfo`` with a resolver that answers a public
address.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from src.integrations.netguard import (
    OutboundTargetRefused,
    merge_pinned_kwargs,
    resolve_and_vet,
)

#: Kept as the name intel / dark-web callers catch; it is netguard's exception.
IntelOutboundRefused = OutboundTargetRefused

#: Default timeouts for provider calls (seconds).
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

#: Injected by tests (``httpx.MockTransport``); ``None`` means the real network.
TRANSPORT: Optional[httpx.AsyncBaseTransport] = None

__all__ = [
    "DEFAULT_TIMEOUT",
    "IntelOutboundRefused",
    "OutboundTargetRefused",
    "guarded_get_bytes",
    "guarded_request",
]


def _client(timeout: Optional[httpx.Timeout]) -> httpx.AsyncClient:
    kwargs: dict[str, Any] = {"timeout": timeout or DEFAULT_TIMEOUT, "follow_redirects": False}
    if TRANSPORT is not None:
        kwargs["transport"] = TRANSPORT
    return httpx.AsyncClient(**kwargs)


async def guarded_request(
    method: str,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, Any]] = None,
    json: Any = None,
    data: Optional[dict[str, Any]] = None,
    timeout: Optional[httpx.Timeout] = None,
) -> httpx.Response:
    """One vetted, pinned request with timeouts and no redirect following.

    Raises ``OutboundTargetRefused`` for a refused target and
    ``httpx.HTTPError`` for transport failures; the caller decides how a
    status code is reported.
    """
    target = await resolve_and_vet(url)
    pinned = merge_pinned_kwargs(target, headers)
    async with _client(timeout) as client:
        return await client.request(
            method,
            target.pinned_url,
            headers=pinned["headers"],
            extensions=pinned["extensions"],
            params=params,
            json=json,
            data=data,
        )


async def guarded_get_bytes(
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    max_bytes: int,
    timeout: Optional[httpx.Timeout] = None,
) -> tuple[int, Optional[bytes], Optional[str]]:
    """Stream a body through the guard with a hard size ceiling.

    Returns ``(status_code, body, error)``. ``body`` is None when the status
    is not 200 or the body exceeds ``max_bytes`` (``error`` says which).
    """
    target = await resolve_and_vet(url)
    pinned = merge_pinned_kwargs(target, headers)
    async with _client(timeout) as client:
        async with client.stream(
            "GET", target.pinned_url, headers=pinned["headers"], extensions=pinned["extensions"],
        ) as resp:
            if resp.status_code != 200:
                location = resp.headers.get("location")
                detail = f"HTTP {resp.status_code}"
                if 300 <= resp.status_code < 400:
                    detail += f" redirect to {location!r} not followed"
                return resp.status_code, None, detail
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes(64 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    return resp.status_code, None, f"body exceeds the {max_bytes} byte ceiling"
                chunks.append(chunk)
            return resp.status_code, b"".join(chunks), None
