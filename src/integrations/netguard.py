"""Outbound connection guard with DNS pinning.

Every outbound integration call (generic HTTP actions, connection probes,
connector wrappers) goes through this module. A target URL is resolved
exactly once, every address in the answer is checked against the internal
ranges below, and the request is then sent to the vetted IP literal. The
original hostname travels in the ``Host`` header and as the TLS SNI /
certificate-verification name, so virtual hosting and certificate checks
still work, but a DNS answer that changes after the check (rebinding) can no
longer steer the connection to an internal address: httpx never resolves the
hostname a second time.

Mechanism (httpx 0.28 / httpcore 1.0): the request URL host is the IP literal,
``headers={"Host": <hostname[:port]>}`` overrides the Host header httpx would
derive from the URL, and ``extensions={"sni_hostname": <hostname>}`` is read by
``httpcore.AsyncHTTPConnection`` and passed to ``start_tls`` as
``server_hostname``, which drives both SNI and ``ssl`` hostname matching.
httpcore 1.0 has no separate ``server_hostname`` request extension; the
``sni_hostname`` extension is the supported spelling.

Redirects are never followed automatically by callers in this package; the
``PinnedTransport`` below re-vets every request it sends, so a client built on
it is safe even if a redirect is followed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Optional, Union
from urllib.parse import urlsplit, urlunsplit

import httpx

from src.core.url_validator import BLOCKED_HOSTNAMES

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Ranges refused in addition to the stdlib address-class flags. 169.254/16
# carries cloud metadata services; 100.64/10 is carrier-grade NAT space that
# cloud providers use for internal endpoints (e.g. Alibaba metadata).
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd00:ec2::/32"),  # AWS IPv6 metadata / DNS
)


class OutboundTargetRefused(ValueError):  # noqa: N818 (public name kept for existing callers)
    """An outbound target is outside the allowed scope or resolves to an internal address."""


def refusal_reason(ip: IPAddress) -> Optional[str]:
    """Return why ``ip`` must not be contacted, or None when it is allowed.

    This is the single implementation of the internal-address check for the
    integrations package.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        reason = refusal_reason(mapped)
        return f"{reason} (IPv4-mapped)" if reason else None
    for net in _EXTRA_BLOCKED_NETWORKS:
        if ip.version == net.version and ip in net:
            return f"{ip} is in blocked range {net}"
    checks = (
        ("loopback", ip.is_loopback),
        ("link-local", ip.is_link_local),
        ("private", ip.is_private),
        ("multicast", ip.is_multicast),
        ("reserved", ip.is_reserved),
        ("unspecified", ip.is_unspecified),
        ("not globally routable", not ip.is_global),
    )
    for label, hit in checks:
        if hit:
            return f"{ip} is a {label} address"
    return None


@dataclass(frozen=True)
class VettedTarget:
    """A URL whose host has been resolved once and checked."""

    original_url: str
    hostname: str  # ASCII (IDNA) form, no brackets
    port: int  # effective port
    scheme: str
    ip: str  # vetted address, no brackets
    pinned_url: str  # original_url with the host replaced by the IP literal
    explicit_port: Optional[int] = None

    @property
    def is_ip_literal(self) -> bool:
        return _parse_ip(self.hostname) is not None

    @property
    def host_header(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        if self.explicit_port is not None and self.explicit_port != _DEFAULT_PORTS.get(self.scheme):
            host = f"{host}:{self.explicit_port}"
        return host

    def pin(self, url: str) -> str:
        """Pin another URL on the same origin to this target's vetted IP.

        Lets a caller vet a base URL once and then build several request URLs
        from it without resolving again. Refuses a URL on a different origin.
        """
        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError as exc:
            raise OutboundTargetRefused(f"invalid port in {url!r}") from exc
        if (
            parts.scheme.lower() != self.scheme
            or _ascii_host(parts.hostname or "") != self.hostname
            or (port if port is not None else _DEFAULT_PORTS.get(parts.scheme.lower())) != self.port
        ):
            raise OutboundTargetRefused("url is not on the vetted origin")
        return _replace_host(parts, self.ip)


def _parse_ip(host: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _ascii_host(hostname: str) -> str:
    hostname = hostname.rstrip(".").lower()
    if _parse_ip(hostname) is not None or hostname.isascii():
        return hostname
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise OutboundTargetRefused(f"hostname {hostname!r} cannot be encoded") from exc


def _replace_host(parts: Any, ip: str) -> str:
    userinfo, _, _hostport = parts.netloc.rpartition("@")
    host = f"[{ip}]" if ":" in ip else ip
    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"
    if userinfo:
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


async def _getaddrinfo(host: str, port: int) -> list[tuple[Any, ...]]:
    """One DNS resolution. Isolated so tests can count and steer lookups."""
    loop = asyncio.get_running_loop()
    return await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)


async def resolve_and_vet(url: str) -> VettedTarget:
    """Resolve ``url``'s host once, refuse internal addresses, return the pinned target.

    Every address in the DNS answer must be acceptable (an answer that mixes
    public and internal addresses is refused); the first one is used.
    Raises OutboundTargetRefused.
    """
    parts = urlsplit(str(url).strip())
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise OutboundTargetRefused(f"scheme {parts.scheme or '(none)'!r} is not http(s)")
    if not parts.hostname:
        raise OutboundTargetRefused("url has no hostname")
    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise OutboundTargetRefused("url has an invalid port") from exc
    port = explicit_port if explicit_port is not None else _DEFAULT_PORTS[scheme]
    hostname = _ascii_host(parts.hostname)
    if not hostname:
        raise OutboundTargetRefused("url has no hostname")
    if hostname in BLOCKED_HOSTNAMES:
        raise OutboundTargetRefused(f"blocked hostname: {hostname}")

    literal = _parse_ip(hostname)
    if literal is not None:
        addresses: list[IPAddress] = [literal]
    else:
        try:
            answers = await _getaddrinfo(hostname, port)
        except (socket.gaierror, UnicodeError, OSError) as exc:
            raise OutboundTargetRefused(f"cannot resolve hostname {hostname}: {exc}") from exc
        addresses = []
        for info in answers:
            raw = str(info[4][0]).split("%", 1)[0]
            ip = _parse_ip(raw)
            if ip is None:
                raise OutboundTargetRefused(f"{hostname} resolved to an unparseable address {raw!r}")
            addresses.append(ip)
        if not addresses:
            raise OutboundTargetRefused(f"cannot resolve hostname {hostname}")

    for ip in addresses:
        reason = refusal_reason(ip)
        if reason:
            raise OutboundTargetRefused(f"{hostname} resolves to an internal address: {reason}")

    chosen = str(addresses[0])
    return VettedTarget(
        original_url=str(url),
        hostname=hostname,
        port=port,
        scheme=scheme,
        ip=chosen,
        pinned_url=_replace_host(parts, chosen),
        explicit_port=explicit_port,
    )


def pinned_request_kwargs(target: VettedTarget) -> dict[str, Any]:
    """httpx request kwargs that keep the original hostname for Host / SNI / TLS.

    ``extensions["sni_hostname"]`` is httpcore's per-request override of the
    TLS ``server_hostname`` (SNI and certificate hostname check). It is only
    set for https to a DNS name; an IP-literal host already verifies against
    the IP.
    """
    kwargs: dict[str, Any] = {"headers": {"Host": target.host_header}}
    if target.scheme == "https" and not target.is_ip_literal:
        kwargs["extensions"] = {"sni_hostname": target.hostname}
    else:
        kwargs["extensions"] = {}
    return kwargs


def merge_pinned_kwargs(target: VettedTarget, headers: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """``pinned_request_kwargs`` merged with caller headers (Host always wins)."""
    pinned = pinned_request_kwargs(target)
    merged = {k: v for k, v in (headers or {}).items() if str(k).lower() != "host"}
    merged.update(pinned["headers"])
    return {"headers": merged, "extensions": pinned["extensions"]}


class PinnedTransport(httpx.AsyncBaseTransport):
    """An httpx transport that vets and pins every request it sends.

    For clients whose URLs are assembled inside a connector (base URL plus an
    endpoint path), this guarantees each request, including any redirect hop,
    is resolved once, checked and sent to the vetted IP. A refused target
    raises ``httpx.ConnectError`` so existing httpx error handling reports it
    as a failed connection.
    """

    def __init__(self, inner: Optional[httpx.AsyncBaseTransport] = None, **transport_kwargs: Any) -> None:
        self._inner = inner or httpx.AsyncHTTPTransport(**transport_kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        try:
            target = await resolve_and_vet(str(request.url))
        except OutboundTargetRefused as exc:
            raise httpx.ConnectError(f"outbound target refused: {exc}", request=request) from exc
        pinned = pinned_request_kwargs(target)
        request.url = httpx.URL(target.pinned_url)
        request.headers["Host"] = pinned["headers"]["Host"]
        request.extensions = {**request.extensions, **pinned["extensions"]}
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
