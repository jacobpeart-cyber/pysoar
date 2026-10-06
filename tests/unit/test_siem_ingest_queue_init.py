"""Regression tests for ``src.siem.ingest_queue.init``.

Production (2026-10-06) logged "redis.asyncio unavailable or connection
failed: Logger._log() got an unexpected keyword argument 'redis_url'" on
every API start: the success-path log line passed a keyword field to a
standard-library logger, which raised inside the ``try``, and the ``except``
then dropped the queue onto its in-memory fallback even though the Redis
client had been created. The same line would also have logged the Redis URL,
which can carry a password.
"""

from __future__ import annotations

import logging

import pytest
from redis.asyncio import Redis

from src.siem import ingest_queue


class _Capture(logging.Handler):
    """Collect records straight from the module logger.

    Attached directly (rather than relying on caplog at the root) because in
    the full suite other tests reconfigure standard logging, and the CI run
    showed the module's records never reaching the root logger.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def clean_queue_state(monkeypatch):
    """``init`` mutates module globals; start and end each test with none.

    ``redis.asyncio.from_url`` builds a client without opening a connection,
    so the real module can be used: no server is contacted.
    """
    monkeypatch.setattr(ingest_queue, "_redis_client", None)
    monkeypatch.setattr(ingest_queue, "_queue", None, raising=False)
    yield
    monkeypatch.setattr(ingest_queue, "_redis_client", None)


@pytest.fixture
def captured(monkeypatch):
    log = ingest_queue.logger
    handler = _Capture()
    monkeypatch.setattr(log, "disabled", False)
    monkeypatch.setattr(log, "level", logging.INFO)
    previous_disable = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    log.addHandler(handler)
    yield handler
    log.removeHandler(handler)
    logging.disable(previous_disable)


def test_init_keeps_the_redis_client_when_redis_is_available(clean_queue_state, captured):
    ingest_queue.init(redis_url="redis://:topsecretpw@redis-host:6379/1")

    assert isinstance(ingest_queue._redis_client, Redis), (
        "init fell back to the in-memory queue although redis.asyncio was importable"
    )
    assert not any("falling back to in-memory queue" in m for m in captured.messages), captured.messages


def test_init_logs_the_redis_host_but_never_the_credentials(clean_queue_state, captured):
    ingest_queue.init(redis_url="redis://:topsecretpw@redis-host:6379/1")

    assert any("redis-host" in m for m in captured.messages), captured.messages
    assert all("topsecretpw" not in m for m in captured.messages), captured.messages


def test_init_without_redis_url_uses_the_in_memory_queue(monkeypatch):
    monkeypatch.setattr(ingest_queue, "_redis_client", None)

    ingest_queue.init(redis_url=None)

    assert ingest_queue._redis_client is None
