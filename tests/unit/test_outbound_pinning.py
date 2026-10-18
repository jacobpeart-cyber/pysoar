"""Outbound integration calls connect to the address that was vetted.

The SSRF guard used to resolve a hostname, check the answer, and then let
httpx resolve it again for the real request, so a DNS answer that changed in
between (rebinding) reached an internal address. ``src.integrations.netguard``
now resolves once and pins the request to the vetted IP, with the original
hostname carried in the Host header and as the TLS SNI / certificate name.

DNS is steered by replacing ``netguard._getaddrinfo`` (the single resolution
point); HTTP is captured with ``httpx.MockTransport`` or a fake httpcore
network backend. No real network traffic is made.
"""

# ruff: noqa: ARG001, ARG002  (test doubles mirror httpcore/netguard call signatures)
from __future__ import annotations

import socket
from typing import Any

import httpx
import pytest

from src.integrations import netguard
from src.integrations.engine import ActionExecutor, ConnectorRegistry, IntegrationManager, OutboundTargetRefused
from src.integrations.netguard import (
    PinnedTransport,
    VettedTarget,
    pinned_request_kwargs,
    resolve_and_vet,
)

PUBLIC_IP = "93.184.216.34"
PUBLIC_IP_2 = "151.101.1.69"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def _answer(*ips: str) -> list[tuple[Any, ...]]:
    out = []
    for ip in ips:
        if ":" in ip:
            out.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 443, 0, 0)))
        else:
            out.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)))
    return out


class _Resolver:
    """Scripted DNS: each call pops the next answer; records every lookup."""

    def __init__(self, *answers: list[str]):
        self.answers = list(answers)
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, host: str, port: int):
        self.calls.append((host, port))
        ips = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return _answer(*ips)


@pytest.fixture
def capture_client(monkeypatch: pytest.MonkeyPatch):
    """Route every httpx.AsyncClient built by the code under test to a MockTransport."""
    seen: list[httpx.Request] = []
    responses: list[httpx.Response] = []
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if responses:
            return responses.pop(0)
        return httpx.Response(200, json={"ok": True})

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return seen, responses


# --------------------------------------------------------------------------
# resolve_and_vet / pinned_request_kwargs
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_public_hostname_is_pinned_to_its_vetted_ip(monkeypatch: pytest.MonkeyPatch):
    resolver = _Resolver([PUBLIC_IP])
    monkeypatch.setattr(netguard, "_getaddrinfo", resolver)

    target = await resolve_and_vet("https://api.vendor.example:8443/v1/x?q=1")

    assert isinstance(target, VettedTarget)
    assert (target.hostname, target.port, target.scheme, target.ip) == ("api.vendor.example", 8443, "https", PUBLIC_IP)
    assert target.pinned_url == f"https://{PUBLIC_IP}:8443/v1/x?q=1"
    kwargs = pinned_request_kwargs(target)
    assert kwargs["headers"] == {"Host": "api.vendor.example:8443"}
    assert kwargs["extensions"] == {"sni_hostname": "api.vendor.example"}
    assert resolver.calls == [("api.vendor.example", 8443)]


@pytest.mark.asyncio
@pytest.mark.parametrize("internal", ["169.254.169.254", "127.0.0.1", "10.1.2.3", "100.64.0.1", "::1", "::ffff:127.0.0.1", "224.0.0.1", "0.0.0.0"])
async def test_hostname_resolving_internal_is_refused(monkeypatch: pytest.MonkeyPatch, internal: str):
    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([internal]))
    with pytest.raises(OutboundTargetRefused):
        await resolve_and_vet("https://rebind.attacker.example/")


@pytest.mark.asyncio
async def test_mixed_answer_with_any_internal_address_is_refused(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([PUBLIC_IP, "169.254.169.254"]))
    with pytest.raises(OutboundTargetRefused):
        await resolve_and_vet("https://mixed.attacker.example/")


@pytest.mark.asyncio
async def test_ipv6_literal_and_ipv6_answers_are_bracketed(monkeypatch: pytest.MonkeyPatch):
    async def _no_dns(host, port):
        raise AssertionError("IP literals must not hit DNS")

    monkeypatch.setattr(netguard, "_getaddrinfo", _no_dns)
    literal = await resolve_and_vet(f"https://[{PUBLIC_V6}]:9443/a")
    assert literal.ip == PUBLIC_V6
    assert literal.pinned_url == f"https://[{PUBLIC_V6}]:9443/a"
    assert pinned_request_kwargs(literal) == {"headers": {"Host": f"[{PUBLIC_V6}]:9443"}, "extensions": {}}
    with pytest.raises(OutboundTargetRefused):
        await resolve_and_vet("http://[::1]:8080/")
    with pytest.raises(OutboundTargetRefused):
        await resolve_and_vet("http://[fe80::1]/")

    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([PUBLIC_V6]))
    named = await resolve_and_vet("https://v6only.vendor.example/p")
    assert named.pinned_url == f"https://[{PUBLIC_V6}]/p"
    assert httpx.URL(named.pinned_url).host == PUBLIC_V6


@pytest.mark.asyncio
async def test_non_http_scheme_and_blocked_names_are_refused(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([PUBLIC_IP]))
    for bad in ("file:///etc/passwd", "gopher://x.example/", "https:///nohost", "http://localhost/", "http://metadata.google.internal/"):
        with pytest.raises(OutboundTargetRefused):
            await resolve_and_vet(bad)


# --------------------------------------------------------------------------
# Base-URL pinning (ITDR directory, container scanning)
# --------------------------------------------------------------------------


async def _pinned_get(base_url: str, path: str, method: str = "GET", **kwargs: Any) -> httpx.Response:
    """The pattern every base-URL caller uses (ITDR directory, container scanning):
    pin through ``_resolve_generic_target`` and send with its Host / SNI kwargs."""
    pinned = await ActionExecutor()._resolve_generic_target(path, {"base_url": base_url})
    async with httpx.AsyncClient(follow_redirects=False) as client:
        return await client.request(
            method, str(pinned),
            headers=pinned.request_kwargs["headers"], extensions=pinned.request_kwargs["extensions"], **kwargs,
        )


@pytest.mark.asyncio
async def test_generic_target_connects_to_vetted_ip_with_hostname_in_host_and_sni(monkeypatch, capture_client):
    seen, _ = capture_client
    resolver = _Resolver([PUBLIC_IP])
    monkeypatch.setattr(netguard, "_getaddrinfo", resolver)

    resp = await _pinned_get("https://siem.customer.example/api", "/v1/items")

    assert resp.status_code == 200
    assert len(seen) == 1
    req = seen[0]
    assert req.url.host == PUBLIC_IP
    assert req.url.path == "/api/v1/items"
    assert req.headers["host"] == "siem.customer.example"
    assert req.extensions["sni_hostname"] == "siem.customer.example"


@pytest.mark.asyncio
async def test_rebinding_after_check_still_connects_only_to_first_vetted_ip(monkeypatch, capture_client):
    """First answer public, any later answer internal: the request goes to the
    first vetted IP and DNS is consulted exactly once."""
    seen, _ = capture_client
    resolver = _Resolver([PUBLIC_IP], ["127.0.0.1"], ["169.254.169.254"])
    monkeypatch.setattr(netguard, "_getaddrinfo", resolver)

    # Also make any stray stdlib lookup (e.g. inside httpx) answer internal,
    # so a second resolution anywhere would be visible.
    def _stdlib_rebound(*args, **kwargs):
        raise AssertionError("hostname was resolved a second time")

    monkeypatch.setattr(socket, "getaddrinfo", _stdlib_rebound)

    await _pinned_get("https://rebind.attacker.example", "/hook", "POST", json={"a": 1})

    assert len(resolver.calls) == 1
    assert [r.url.host for r in seen] == [PUBLIC_IP]
    assert seen[0].headers["host"] == "rebind.attacker.example"


@pytest.mark.asyncio
async def test_redirect_to_internal_address_is_not_followed(monkeypatch, capture_client):
    seen, responses = capture_client
    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([PUBLIC_IP]))
    responses.append(httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}))

    resp = await _pinned_get("https://vendor.example", "/start")

    assert resp.status_code == 302
    assert len(seen) == 1
    assert seen[0].url.host == PUBLIC_IP


@pytest.mark.asyncio
async def test_resolve_generic_target_returns_pinned_url_and_kwargs(monkeypatch):
    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([PUBLIC_IP_2]))
    pinned = await ActionExecutor()._resolve_generic_target("/x", {"base_url": "https://vendor.example/base"})
    assert pinned == f"https://{PUBLIC_IP_2}/base/x"
    assert pinned.target.hostname == "vendor.example"
    assert pinned.request_kwargs == {"headers": {"Host": "vendor.example"}, "extensions": {"sni_hostname": "vendor.example"}}


# --------------------------------------------------------------------------
# Connection probe
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_of_planned_connector_makes_no_network_call(monkeypatch):
    """Wazuh / generic webhooks have no connector class: the probe answers
    ``unavailable`` and never builds a client or resolves a name."""
    class _NeverConnect:
        def __init__(self, *args, **kwargs):
            raise AssertionError("no client may be built for a planned connector")

    async def _no_dns(host, port):
        raise AssertionError("no DNS lookup for a planned connector")

    monkeypatch.setattr(httpx, "AsyncClient", _NeverConnect)
    monkeypatch.setattr(netguard, "_getaddrinfo", _no_dns)
    manager = IntegrationManager(ConnectorRegistry())

    for name, config in (("wazuh", {"base_url": "https://wazuh.customer.example:55000"}),
                         ("webhook", {"webhook_url": "https://hooks.attacker.example/x"})):
        health, message = await manager._probe_connector(name, config, {"token": "t"})
        assert health == "unavailable" and "no connector implementation" in message


@pytest.mark.asyncio
async def test_probe_of_implemented_connector_is_pinned(monkeypatch):
    """The probe is the class's own read-only call (Slack auth.test), sent to
    the vetted IP with the vendor hostname in Host and SNI."""
    resolver = _Resolver([PUBLIC_IP])
    monkeypatch.setattr(netguard, "_getaddrinfo", resolver)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True, "team": "t"})

    # Replace only the innermost network transport: PinnedTransport stays in front.
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda *_a, **_kw: httpx.MockTransport(handler))
    manager = IntegrationManager(ConnectorRegistry())

    health, message = await manager._probe_connector("slack", {}, {"bot_token": "xoxb-test-token"})
    assert health == "healthy" and message is None
    assert [r.url.path for r in seen] == ["/api/auth.test"]
    assert seen[0].url.host == PUBLIC_IP
    assert seen[0].headers["host"] == "slack.com"
    assert seen[0].extensions["sni_hostname"] == "slack.com"
    assert resolver.calls == [("slack.com", 443)]


# --------------------------------------------------------------------------
# Connector wrappers
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connector_requests_go_through_pinned_transport(monkeypatch):
    from src.integrations.connectors.crowdstrike import CrowdStrikeConnector

    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([PUBLIC_IP]))
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "tok", "expires_in": 1800})
        return httpx.Response(200, json={"resources": [], "errors": []})

    connector = CrowdStrikeConnector(config={}, credentials={"client_id": "c", "client_secret": "s"})
    client = await connector.get_client()
    assert isinstance(client._transport, PinnedTransport)
    client._transport._inner = httpx.MockTransport(handler)

    result = await connector.contain_host("dev-1")
    await connector.close()

    assert result["success"] is True
    assert [r.url.path for r in seen] == ["/oauth2/token", "/devices/entities/devices-actions/v2"]
    for req in seen:
        assert req.url.host == PUBLIC_IP
        assert req.headers["host"] == "api.crowdstrike.com"
        assert req.extensions["sni_hostname"] == "api.crowdstrike.com"


@pytest.mark.asyncio
async def test_pinned_transport_refuses_internal_and_revets_redirect_hops(monkeypatch):
    resolver = _Resolver([PUBLIC_IP], ["10.0.0.7"])
    monkeypatch.setattr(netguard, "_getaddrinfo", resolver)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://internal.attacker.example/admin"})

    transport = PinnedTransport(inner=httpx.MockTransport(handler))
    async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
        with pytest.raises(httpx.ConnectError, match="outbound target refused"):
            await client.get("https://vendor.example/start")

    assert [r.url.host for r in seen] == [PUBLIC_IP]
    assert [c[0] for c in resolver.calls] == ["vendor.example", "internal.attacker.example"]


# --------------------------------------------------------------------------
# The real httpcore stack: TCP goes to the IP, TLS server_hostname is the name
# --------------------------------------------------------------------------


class _StopAfterTLSError(Exception):
    pass


class _FakeStream:
    def __init__(self, log: dict[str, Any]):
        self.log = log

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.log["server_hostname"] = server_hostname
        self.log["check_hostname"] = ssl_context.check_hostname
        raise _StopAfterTLSError()

    async def aclose(self):
        return None

    def get_extra_info(self, info):
        return None


class _FakeBackend:
    def __init__(self, log: dict[str, Any]):
        self.log = log

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.log["connect"] = (host, port)
        return _FakeStream(self.log)

    async def sleep(self, seconds):
        return None


@pytest.mark.asyncio
async def test_httpcore_connects_to_ip_and_verifies_tls_against_hostname(monkeypatch):
    monkeypatch.setattr(netguard, "_getaddrinfo", _Resolver([PUBLIC_IP]))
    target = await resolve_and_vet("https://secure.vendor.example/health")
    kwargs = pinned_request_kwargs(target)

    log: dict[str, Any] = {}
    inner = httpx.AsyncHTTPTransport()
    inner._pool._network_backend = _FakeBackend(log)
    async with httpx.AsyncClient(transport=inner, follow_redirects=False) as client:
        with pytest.raises(_StopAfterTLSError):
            await client.get(target.pinned_url, headers=kwargs["headers"], extensions=kwargs["extensions"])

    assert log["connect"] == (PUBLIC_IP, 443)
    assert log["server_hostname"] == "secure.vendor.example"
    assert log["check_hostname"] is True
