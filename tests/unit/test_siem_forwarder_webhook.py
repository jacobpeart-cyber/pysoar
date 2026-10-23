"""WebhookForwarder must actually deliver logs over HTTP, through the outbound guard.

Before an earlier fix, ``WebhookForwarder.flush`` built auth headers and a
payload, logged "Would forward N logs to webhook ...", cleared the
buffer, and returned True: every webhook destination silently dropped
100% of its logs while reporting success. These tests pin the real
semantics:

- 2xx response -> buffer cleared, True returned
- non-2xx / connection error -> buffer retained for retry, False
  returned, last_error populated
- retained buffer is capped (oldest evicted) so it can't grow unbounded
- every request goes through PinnedTransport: pinned to the vetted IP,
  TLS verified, redirects not followed; a private destination is refused
  (naming OUTBOUND_PRIVATE_ALLOWLIST) until the operator lists its network;
  a stored verify_tls / ca_bundle is ignored and said so
- syslog connects to the vetted address only
- the legacy CloudCollector no longer pretends to poll AWS/Azure/GCP

HTTP is faked at the network boundary (tests/unit/connector_fakes.py: DNS
steered, the inner httpx transport replaced, PinnedTransport left in front).
"""

# ruff: noqa: ARG005  (fake handlers mirror the httpx signature)
import json
import socket
from typing import Any

import httpx
import pytest

import src.siem.forwarder as forwarder_module
from src.core.config import settings
from src.integrations.netguard import PRIVATE_TARGET_HINT
from src.siem.forwarder import (
    TLS_OPT_OUT_IGNORED,
    ForwardingDestination,
    ForwardingDestType,
    ForwardingManager,
    SyslogForwarder,
    WebhookForwarder,
)
from tests.unit.connector_fakes import PUBLIC_IP, fake_vendor, host_header

PRIVATE_IP = "10.30.0.9"


def _make_destination(**overrides):
    params = {
        "id": "dest-1",
        "name": "Test Webhook",
        "dest_type": ForwardingDestType.WEBHOOK,
        "host": "collector.example.com",
        "port": 8443,
        "protocol": "https",
        "auth_config": {"api_key": "fwd-fixture-key-0001"},
        "filter_rules": {"batch_size": 10},
    }
    params.update(overrides)
    return ForwardingDestination(**params)


def _body(request: httpx.Request) -> Any:
    return json.loads(request.content.decode())


@pytest.mark.asyncio
async def test_flush_posts_batch_pinned_and_clears_buffer_on_2xx(monkeypatch):
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200))

    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}, {"message": "b"}]

    assert await forwarder.flush() is True
    assert forwarder.batch_buffer == []
    assert forwarder.last_error is None and forwarder.note is None

    (request,) = seen
    assert request.method == "POST" and request.url.path == "/"
    assert request.url.host == PUBLIC_IP and request.url.port == 8443
    assert host_header(request) == "collector.example.com:8443"
    assert request.extensions["sni_hostname"] == "collector.example.com"
    assert _body(request) == {"logs": [{"message": "a"}, {"message": "b"}]}
    assert request.headers["authorization"] == "Bearer fwd-fixture-key-0001"
    assert request.headers["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_flush_keeps_buffer_and_returns_false_on_500(monkeypatch):
    fake_vendor(monkeypatch, lambda request: httpx.Response(500, text="boom"))

    forwarder = WebhookForwarder(_make_destination())
    entries = [{"message": "a"}, {"message": "b"}]
    forwarder.batch_buffer = list(entries)

    assert await forwarder.flush() is False
    assert forwarder.batch_buffer == entries  # retained for retry
    assert "500" in forwarder.last_error


@pytest.mark.asyncio
async def test_flush_keeps_buffer_and_returns_false_on_connection_error(monkeypatch):
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    fake_vendor(monkeypatch, refuse)

    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}]

    assert await forwarder.flush() is False
    assert forwarder.batch_buffer == [{"message": "a"}]
    assert "refused" in forwarder.last_error


@pytest.mark.asyncio
async def test_failed_flush_evicts_oldest_beyond_buffer_cap(monkeypatch):
    fake_vendor(monkeypatch, lambda request: httpx.Response(503))

    dest = _make_destination(filter_rules={"batch_size": 10, "max_buffer_size": 5})
    forwarder = WebhookForwarder(dest)
    forwarder.batch_buffer = [{"seq": i} for i in range(8)]

    assert await forwarder.flush() is False
    # Oldest 3 dropped, newest 5 retained.
    assert forwarder.batch_buffer == [{"seq": i} for i in range(3, 8)]


@pytest.mark.asyncio
async def test_forward_flushes_when_batch_size_reached(monkeypatch):
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(202))

    dest = _make_destination(filter_rules={"batch_size": 2})
    forwarder = WebhookForwarder(dest)

    assert await forwarder.forward({"message": "a"}) is True
    assert seen == []  # below batch size: no HTTP yet
    assert await forwarder.forward({"message": "b"}) is True

    (request,) = seen
    assert _body(request) == {"logs": [{"message": "a"}, {"message": "b"}]}
    assert forwarder.batch_buffer == []


@pytest.mark.asyncio
async def test_retry_after_failure_resends_retained_logs(monkeypatch):
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(500))

    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}]
    assert await forwarder.flush() is False

    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200))
    assert await forwarder.flush() is True

    assert _body(seen[-1]) == {"logs": [{"message": "a"}]}
    assert forwarder.batch_buffer == []
    assert forwarder.last_error is None


@pytest.mark.asyncio
async def test_full_url_host_is_used_and_timeout_respected(monkeypatch):
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200))
    made: list[dict[str, Any]] = []
    real_client = httpx.AsyncClient

    def _client(**kwargs: Any) -> httpx.AsyncClient:
        made.append(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(forwarder_module.httpx, "AsyncClient", _client)
    dest = _make_destination(
        host="https://hooks.example.com/ingest/v1",
        filter_rules={"timeout_seconds": 3},
        auth_config={"bearer_token": "fwd-fixture-token-0002"},
    )
    forwarder = WebhookForwarder(dest)
    forwarder.batch_buffer = [{"message": "a"}]

    assert await forwarder.flush() is True
    (request,) = seen
    assert request.url.path == "/ingest/v1" and host_header(request) == "hooks.example.com"
    assert request.headers["authorization"] == "Bearer fwd-fixture-token-0002"
    (kwargs,) = made
    assert kwargs["timeout"] == 3.0 and kwargs["follow_redirects"] is False
    assert isinstance(kwargs["transport"], forwarder_module.PinnedTransport)
    assert "verify" not in kwargs


@pytest.mark.asyncio
async def test_stored_tls_opt_out_is_ignored_and_said_once(monkeypatch):
    made: list[dict[str, Any]] = []
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(500))

    def _transport(*_args: Any, **kwargs: Any) -> httpx.MockTransport:
        made.append(kwargs)
        return httpx.MockTransport(lambda request: (seen.append(request), httpx.Response(500))[1])

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", _transport)
    warnings: list[str] = []
    monkeypatch.setattr(forwarder_module.logger, "warning", lambda event, **kw: warnings.append(event))

    dest = _make_destination(filter_rules={"batch_size": 10, "verify_tls": False, "ca_bundle": "/tmp/ca.pem"})
    manager = ForwardingManager()
    manager.add_destination(dest)
    forwarder = manager.forwarders["dest-1"]
    for _ in range(3):
        forwarder.batch_buffer = [{"message": "a"}]
        assert await forwarder.flush() is False

    assert forwarder.note == TLS_OPT_OUT_IGNORED
    assert forwarder.last_error == f"HTTP 500: ; {TLS_OPT_OUT_IGNORED}"
    assert warnings.count("forwarding destination carries a TLS opt-out that is ignored") == 1
    (stats,) = manager.get_destination_stats()
    assert stats["note"] == TLS_OPT_OUT_IGNORED
    # verify=False never reached the HTTP layer.
    assert made and all(kwargs.get("verify", True) is not False for kwargs in made)
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_private_destination_refused_until_allowlisted(monkeypatch):
    monkeypatch.setattr(settings, "outbound_private_allowlist", [])
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200), ip=PRIVATE_IP)

    forwarder = WebhookForwarder(_make_destination(host="collector.corp.example"))
    forwarder.batch_buffer = [{"message": "a"}]
    assert await forwarder.flush() is False
    assert seen == []  # nothing forwarded
    assert forwarder.last_error == f"refused: {PRIVATE_TARGET_HINT}"
    assert PRIVATE_IP not in forwarder.last_error
    assert forwarder.batch_buffer == [{"message": "a"}]

    monkeypatch.setattr(settings, "outbound_private_allowlist", ["10.30.0.0/16"])
    assert await forwarder.flush() is True
    (request,) = seen
    assert request.url.host == PRIVATE_IP and host_header(request) == "collector.corp.example:8443"
    assert forwarder.last_error is None and forwarder.batch_buffer == []


@pytest.mark.asyncio
async def test_metadata_destination_refused_even_when_listed(monkeypatch):
    monkeypatch.setattr(settings, "outbound_private_allowlist", ["169.254.0.0/16", "0.0.0.0/0"])
    seen = fake_vendor(monkeypatch, lambda request: httpx.Response(200), ip="169.254.169.254")
    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}]
    assert await forwarder.flush() is False
    assert seen == [] and forwarder.last_error == "refused: target resolves to an internal address"


@pytest.mark.asyncio
async def test_redirects_are_not_followed(monkeypatch):
    seen = fake_vendor(
        monkeypatch,
        lambda request: httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"}),
    )
    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}]
    assert await forwarder.flush() is False
    assert len(seen) == 1 and forwarder.last_error.startswith("HTTP 302")
    assert forwarder.batch_buffer == [{"message": "a"}]


class _FakeSocket:
    def __init__(self, record: list[tuple[str, Any]], family: int, kind: int) -> None:
        self.record = record
        record.append(("socket", (family, kind)))

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self.record.append(("sendto", addr))
        assert data

    def connect(self, addr: tuple[str, int]) -> None:
        self.record.append(("connect", addr))

    def sendall(self, data: bytes) -> None:
        self.record.append(("sendall", len(data)))

    def close(self) -> None:
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_syslog_connects_to_the_vetted_address_only(monkeypatch, protocol):
    record: list[tuple[str, Any]] = []
    monkeypatch.setattr(forwarder_module.socket, "socket", lambda family, kind: _FakeSocket(record, family, kind))
    monkeypatch.setattr(settings, "outbound_private_allowlist", [])
    fake_vendor(monkeypatch, lambda request: httpx.Response(200), ip=PRIVATE_IP)
    dest = _make_destination(dest_type=ForwardingDestType.SYSLOG, host="syslog.corp.example", port=514, protocol=protocol)

    refused = SyslogForwarder(dest)
    assert await refused.forward({"message": "a"}) is False
    assert record == [] and refused.last_error == f"refused: {PRIVATE_TARGET_HINT}"

    monkeypatch.setattr(settings, "outbound_private_allowlist", ["10.30.0.0/24"])
    allowed = SyslogForwarder(dest)
    assert await allowed.forward({"message": "a"}) is True
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    assert record[0] == ("socket", (socket.AF_INET, kind))
    assert record[1] == ("sendto" if protocol == "udp" else "connect", (PRIVATE_IP, 514))


def test_destination_stats_surface_forwarder_last_error():
    manager = ForwardingManager()
    manager.add_destination(_make_destination())
    manager.forwarders["dest-1"].last_error = "HTTP 500: boom"

    (stats,) = manager.get_destination_stats()
    assert stats["last_error"] == "HTTP 500: boom"


@pytest.mark.asyncio
async def test_cloud_collector_refuses_to_start_instead_of_fake_polling():
    from src.siem.collector import CloudCollector

    collector = CloudCollector("aws", {"poll_interval": 60})
    await collector.start()

    assert collector.enabled is False
    assert "cloud_poller" in collector.last_error
    assert "aws_cloudtrail" in collector.last_error
    # The error must be visible through the standard health surface.
    assert "cloud_poller" in collector.get_health()["last_error"]


def test_cloud_collector_stub_poll_methods_are_gone():
    from src.siem.collector import CloudCollector

    stubs = [
        name
        for name in ("_poll_aws", "_poll_azure", "_poll_gcp", "_poll_cloud")
        if hasattr(CloudCollector, name)
    ]
    assert not stubs, (
        f"silent no-op cloud poll stubs are back: {stubs} — the real "
        "ingestion path is src.siem.cloud_poller.poll_all_cloud_integrations"
    )
