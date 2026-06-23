"""The SIEM ingest worker must treat a Redis read timeout as an idle poll.

A blocking ``BRPOP`` can hit the connection's socket_timeout before its own
block timeout elapses; redis-py raises ``TimeoutError``. For a queue consumer
that just means "no items yet" — but the loop used to fall into its generic
``except Exception`` and log a full traceback on every idle cycle, spamming
the api log ~once per cycle. These tests pin: timeouts are swallowed as idle,
real payloads still get processed, and no error is logged.
"""

import asyncio
import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from redis.exceptions import TimeoutError as RedisTimeoutError

from src.siem import ingest_queue


class _FakeDB:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def commit(self):
        pass


@pytest.mark.asyncio
async def test_worker_loop_treats_redis_timeout_as_idle(monkeypatch):
    payload = json.dumps({"event": {"host": "h1"}, "organization_id": "org-1"})
    # idle timeout -> a real item -> cancel to exit the loop
    brpop = AsyncMock(side_effect=[
        RedisTimeoutError("Timeout reading from redis:6379"),
        ("pysoar:siem:ingest", payload),
        asyncio.CancelledError(),
    ])
    fake_client = MagicMock()
    fake_client.brpop = brpop

    monkeypatch.setattr(ingest_queue, "_redis_client", fake_client)
    monkeypatch.setattr(ingest_queue, "_db_session_factory", lambda: _FakeDB())

    processed = []

    async def fake_process(event, db=None, organization_id=None):
        processed.append((event, organization_id))

    with patch("src.siem.pipeline.process_host_event", new=fake_process), \
         patch.object(ingest_queue.logger, "exception") as log_exception:
        await ingest_queue._worker_loop()

    # The real item was consumed despite the preceding timeout...
    assert processed == [({"host": "h1"}, "org-1")]
    # ...and the timeout was NOT logged as an error.
    log_exception.assert_not_called()
    assert brpop.await_count == 3
