"""WebhookForwarder must actually deliver logs over HTTP.

Before this fix, ``WebhookForwarder.flush`` built auth headers and a
payload, logged "Would forward N logs to webhook ...", cleared the
buffer, and returned True — every webhook destination silently dropped
100% of its logs while reporting success. These tests pin the real
semantics:

- 2xx response -> buffer cleared, True returned
- non-2xx / connection error -> buffer retained for retry, False
  returned, last_error populated
- retained buffer is capped (oldest evicted) so it can't grow unbounded
- the legacy CloudCollector no longer pretends to poll AWS/Azure/GCP
"""

import pytest

import src.siem.forwarder as forwarder_module
from src.siem.forwarder import (
    ForwardingDestination,
    ForwardingDestType,
    ForwardingManager,
    WebhookForwarder,
)


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def _fake_client_class(recorder, response=None, exc=None):
    """Build a fake httpx.AsyncClient class recording constructor + posts."""

    class _FakeAsyncClient:
        def __init__(self, **kwargs):
            recorder["client_kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, **kwargs):
            recorder.setdefault("posts", []).append({"url": url, **kwargs})
            if exc is not None:
                raise exc
            return response

    return _FakeAsyncClient


def _make_destination(**overrides):
    params = {
        "id": "dest-1",
        "name": "Test Webhook",
        "dest_type": ForwardingDestType.WEBHOOK,
        "host": "collector.example.com",
        "port": 8443,
        "protocol": "https",
        "auth_config": {"api_key": "secret-key"},
        "filter_rules": {"batch_size": 10},
    }
    params.update(overrides)
    return ForwardingDestination(**params)


@pytest.mark.asyncio
async def test_flush_posts_batch_and_clears_buffer_on_2xx(monkeypatch):
    recorder = {}
    monkeypatch.setattr(
        forwarder_module.httpx,
        "AsyncClient",
        _fake_client_class(recorder, response=_FakeResponse(200)),
    )

    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}, {"message": "b"}]

    assert await forwarder.flush() is True
    assert forwarder.batch_buffer == []
    assert forwarder.last_error is None

    (post,) = recorder["posts"]
    assert post["url"] == "https://collector.example.com:8443/"
    assert post["json"] == {"logs": [{"message": "a"}, {"message": "b"}]}
    assert post["headers"]["Authorization"] == "Bearer secret-key"
    assert post["headers"]["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_flush_keeps_buffer_and_returns_false_on_500(monkeypatch):
    recorder = {}
    monkeypatch.setattr(
        forwarder_module.httpx,
        "AsyncClient",
        _fake_client_class(recorder, response=_FakeResponse(500, "boom")),
    )

    forwarder = WebhookForwarder(_make_destination())
    entries = [{"message": "a"}, {"message": "b"}]
    forwarder.batch_buffer = list(entries)

    assert await forwarder.flush() is False
    assert forwarder.batch_buffer == entries  # retained for retry
    assert "500" in forwarder.last_error


@pytest.mark.asyncio
async def test_flush_keeps_buffer_and_returns_false_on_connection_error(monkeypatch):
    recorder = {}
    monkeypatch.setattr(
        forwarder_module.httpx,
        "AsyncClient",
        _fake_client_class(recorder, exc=ConnectionError("refused")),
    )

    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}]

    assert await forwarder.flush() is False
    assert forwarder.batch_buffer == [{"message": "a"}]
    assert "refused" in forwarder.last_error


@pytest.mark.asyncio
async def test_failed_flush_evicts_oldest_beyond_buffer_cap(monkeypatch):
    recorder = {}
    monkeypatch.setattr(
        forwarder_module.httpx,
        "AsyncClient",
        _fake_client_class(recorder, response=_FakeResponse(503)),
    )

    dest = _make_destination(filter_rules={"batch_size": 10, "max_buffer_size": 5})
    forwarder = WebhookForwarder(dest)
    forwarder.batch_buffer = [{"seq": i} for i in range(8)]

    assert await forwarder.flush() is False
    # Oldest 3 dropped, newest 5 retained.
    assert forwarder.batch_buffer == [{"seq": i} for i in range(3, 8)]


@pytest.mark.asyncio
async def test_forward_flushes_when_batch_size_reached(monkeypatch):
    recorder = {}
    monkeypatch.setattr(
        forwarder_module.httpx,
        "AsyncClient",
        _fake_client_class(recorder, response=_FakeResponse(202)),
    )

    dest = _make_destination(filter_rules={"batch_size": 2})
    forwarder = WebhookForwarder(dest)

    assert await forwarder.forward({"message": "a"}) is True
    assert "posts" not in recorder  # below batch size — no HTTP yet
    assert await forwarder.forward({"message": "b"}) is True

    (post,) = recorder["posts"]
    assert post["json"] == {"logs": [{"message": "a"}, {"message": "b"}]}
    assert forwarder.batch_buffer == []


@pytest.mark.asyncio
async def test_retry_after_failure_resends_retained_logs(monkeypatch):
    recorder = {}
    fail_client = _fake_client_class(recorder, response=_FakeResponse(500))
    monkeypatch.setattr(forwarder_module.httpx, "AsyncClient", fail_client)

    forwarder = WebhookForwarder(_make_destination())
    forwarder.batch_buffer = [{"message": "a"}]
    assert await forwarder.flush() is False

    ok_client = _fake_client_class(recorder, response=_FakeResponse(200))
    monkeypatch.setattr(forwarder_module.httpx, "AsyncClient", ok_client)
    assert await forwarder.flush() is True

    assert recorder["posts"][-1]["json"] == {"logs": [{"message": "a"}]}
    assert forwarder.batch_buffer == []
    assert forwarder.last_error is None


@pytest.mark.asyncio
async def test_full_url_host_is_used_verbatim_and_timeout_verify_respected(monkeypatch):
    recorder = {}
    monkeypatch.setattr(
        forwarder_module.httpx,
        "AsyncClient",
        _fake_client_class(recorder, response=_FakeResponse(200)),
    )

    dest = _make_destination(
        host="https://hooks.example.com/ingest/v1",
        filter_rules={"timeout_seconds": 3, "verify_tls": False},
        auth_config={"bearer_token": "tok"},
    )
    forwarder = WebhookForwarder(dest)
    forwarder.batch_buffer = [{"message": "a"}]

    assert await forwarder.flush() is True
    (post,) = recorder["posts"]
    assert post["url"] == "https://hooks.example.com/ingest/v1"
    assert post["headers"]["Authorization"] == "Bearer tok"
    assert recorder["client_kwargs"] == {"timeout": 3.0, "verify": False}


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
