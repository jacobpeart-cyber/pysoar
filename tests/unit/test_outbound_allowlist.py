"""The operator allow-list for private outbound targets (OUTBOUND_PRIVATE_ALLOWLIST).

Default deny: a target that resolves to a private address is refused with a
message naming the setting. A private address inside a listed CIDR is
allowed. Loopback, link-local, the cloud metadata addresses, multicast and
unspecified stay refused whatever the list says. DNS is steered through
``netguard._getaddrinfo`` (the single resolution point); no network traffic.
"""

# ruff: noqa: ARG001, ARG005  (fakes mirror the netguard / httpx signatures)
from __future__ import annotations

import socket
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from src.core.config import Settings, settings
from src.integrations import netguard
from src.integrations.netguard import (
    PRIVATE_TARGET_HINT,
    OutboundTargetRefused,
    PinnedTransport,
    PrivateTargetRefused,
    resolve_and_vet,
)


def _dns(monkeypatch: pytest.MonkeyPatch, *ips: str) -> None:
    async def _resolve(host: str, port: int) -> list[tuple[Any, ...]]:
        out = []
        for ip in ips:
            if ":" in ip:
                out.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port, 0, 0)))
            else:
                out.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)))
        return out

    monkeypatch.setattr(netguard, "_getaddrinfo", _resolve)


def _allow(monkeypatch: pytest.MonkeyPatch, *cidrs: str) -> None:
    monkeypatch.setattr(settings, "outbound_private_allowlist", list(cidrs))


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["10.20.0.5", "172.16.4.4", "192.168.1.10", "100.64.3.3", "::ffff:10.20.0.5"])
async def test_private_target_refused_by_default_naming_the_setting(monkeypatch, ip: str) -> None:
    _allow(monkeypatch)
    _dns(monkeypatch, ip)
    with pytest.raises(PrivateTargetRefused) as info:
        await resolve_and_vet("https://splunk.corp.example:8089/services/server/info")
    message = str(info.value)
    assert PRIVATE_TARGET_HINT in message and "OUTBOUND_PRIVATE_ALLOWLIST" in message
    # Existing callers that match on the old wording keep working.
    assert "internal address" in message
    assert isinstance(info.value, OutboundTargetRefused)


@pytest.mark.asyncio
async def test_private_target_allowed_when_its_cidr_is_listed(monkeypatch) -> None:
    _allow(monkeypatch, "10.20.0.0/16")
    _dns(monkeypatch, "10.20.0.5")
    target = await resolve_and_vet("https://splunk.corp.example:8089/services/server/info")
    assert target.ip == "10.20.0.5" and target.hostname == "splunk.corp.example"
    assert target.pinned_url == "https://10.20.0.5:8089/services/server/info"

    # A neighbouring network is still refused.
    _dns(monkeypatch, "10.21.0.5")
    with pytest.raises(PrivateTargetRefused):
        await resolve_and_vet("https://splunk.corp.example/")

    # Every address of the answer must be acceptable.
    _dns(monkeypatch, "10.20.0.5", "192.168.9.9")
    with pytest.raises(PrivateTargetRefused):
        await resolve_and_vet("https://splunk.corp.example/")

    # IPv4-mapped IPv6 answers are checked as their IPv4 address.
    _dns(monkeypatch, "::ffff:10.20.0.7")
    assert (await resolve_and_vet("https://splunk.corp.example/")).ip == "::ffff:10.20.0.7"

    # IP literals follow the same rule.
    assert (await resolve_and_vet("https://10.20.9.9:9200/")).ip == "10.20.9.9"


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.8.8.8", "::1", "::ffff:127.0.0.1",
    "169.254.169.254", "169.254.10.10", "fe80::1", "fd00:ec2::254",
    "224.0.0.1", "ff02::1", "0.0.0.0", "0.1.2.3", "::", "240.0.0.1", "255.255.255.255",
])
async def test_never_allowed_addresses_refused_even_when_listed(monkeypatch, ip: str) -> None:
    _allow(monkeypatch, "0.0.0.0/0", "::/0", "127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "fd00::/8", "224.0.0.0/4")
    _dns(monkeypatch, ip)
    with pytest.raises(OutboundTargetRefused) as info:
        await resolve_and_vet("https://siem.corp.example/")
    assert not isinstance(info.value, PrivateTargetRefused)
    assert "OUTBOUND_PRIVATE_ALLOWLIST" not in str(info.value)


@pytest.mark.asyncio
async def test_blocked_hostnames_stay_refused_when_listed(monkeypatch) -> None:
    _allow(monkeypatch, "0.0.0.0/0", "::/0")
    _dns(monkeypatch, "10.0.0.1")
    for url in ("http://localhost/", "http://metadata.google.internal/"):
        with pytest.raises(OutboundTargetRefused):
            await resolve_and_vet(url)


@pytest.mark.asyncio
async def test_ipv6_ula(monkeypatch) -> None:
    _allow(monkeypatch)
    _dns(monkeypatch, "fd12:3456:789a::10")
    with pytest.raises(PrivateTargetRefused):
        await resolve_and_vet("https://es.corp.example:9200/")
    _allow(monkeypatch, "fd12:3456::/32")
    target = await resolve_and_vet("https://es.corp.example:9200/")
    assert target.pinned_url == "https://[fd12:3456:789a::10]:9200/"
    # The AWS IPv6 metadata address sits inside fc00::/7 and is never opened.
    _allow(monkeypatch, "fc00::/7")
    _dns(monkeypatch, "fd00:ec2::254")
    with pytest.raises(OutboundTargetRefused):
        await resolve_and_vet("https://es.corp.example:9200/")


@pytest.mark.asyncio
async def test_public_targets_are_unaffected(monkeypatch) -> None:
    _allow(monkeypatch)
    _dns(monkeypatch, "93.184.216.34")
    assert (await resolve_and_vet("https://api.vendor.example/")).ip == "93.184.216.34"


@pytest.mark.asyncio
async def test_list_is_read_at_call_time(monkeypatch) -> None:
    _dns(monkeypatch, "192.168.50.2")
    _allow(monkeypatch, "192.168.50.0/24")
    await resolve_and_vet("https://qradar.corp.example/")
    _allow(monkeypatch)
    with pytest.raises(PrivateTargetRefused):
        await resolve_and_vet("https://qradar.corp.example/")


@pytest.mark.asyncio
async def test_pinned_transport_private_hint_hides_the_address(monkeypatch) -> None:
    _allow(monkeypatch)
    _dns(monkeypatch, "10.20.0.5")
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda *_a, **_kw: httpx.MockTransport(lambda r: httpx.Response(200)))
    request = httpx.Request("GET", "https://splunk.corp.example/services/server/info")
    with pytest.raises(httpx.ConnectError) as hinted:
        await PinnedTransport(private_hint=True).handle_async_request(request)
    assert str(hinted.value) == f"outbound target refused: {PRIVATE_TARGET_HINT}"
    assert "10.20.0.5" not in str(hinted.value) and "splunk.corp.example" not in str(hinted.value)

    with pytest.raises(httpx.ConnectError) as plain:
        await PinnedTransport().handle_async_request(httpx.Request("GET", "https://splunk.corp.example/"))
    assert "internal address" in str(plain.value)


# --------------------------------------------------------------------------
# The setting
# --------------------------------------------------------------------------


def test_setting_defaults_to_empty() -> None:
    assert Settings.model_fields["outbound_private_allowlist"].default == []


@pytest.mark.parametrize(("raw", "expected"), [
    ('["10.0.0.0/8", "fd12::/16"]', ["10.0.0.0/8", "fd12::/16"]),
    ("10.0.0.0/8, 192.168.10.0/24", ["10.0.0.0/8", "192.168.10.0/24"]),
    ("192.168.10.7/24", ["192.168.10.0/24"]),
    ("10.1.2.3", ["10.1.2.3/32"]),
    ("", []),
    ("[]", []),
])
def test_setting_parses_json_and_comma_separated(monkeypatch, raw: str, expected: list[str]) -> None:
    monkeypatch.setenv("OUTBOUND_PRIVATE_ALLOWLIST", raw)
    assert Settings().outbound_private_allowlist == expected


@pytest.mark.parametrize("raw", ["10.0.0.0/33", "not-a-cidr", '["10.0.0.0/8", "fd12::/129"]', "10.0.0.0/8,banana", '{"a": 1}'])
def test_setting_rejects_a_malformed_cidr_at_load(monkeypatch, raw: str) -> None:
    monkeypatch.setenv("OUTBOUND_PRIVATE_ALLOWLIST", raw)
    with pytest.raises(ValidationError) as info:
        Settings()
    assert "OUTBOUND_PRIVATE_ALLOWLIST" in str(info.value)
