"""Lightweight async ingest queue for host/EDR events.

The queue decouples agent HTTP ingestion from SIEM processing, enabling
basic buffering, backpressure, and a worker task to run detection and
correlation without blocking the request path.

This is a simple prototype using asyncio.Queue; for production you
should replace it with a durable stream (Kafka/Rabbit/Redis Streams)
with partitioning, consumer groups, and persistence.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Internal state: either an in-memory asyncio.Queue or a Redis-backed list.
_queue: Optional[asyncio.Queue] = None
_worker_tasks: list[asyncio.Task] | None = None
_db_session_factory = None
_redis_client = None
_redis_key = "pysoar:siem:ingest"


def init(queue_maxsize: int = 10000, db_session_factory=None, redis_url: Optional[str] = None):
    """Initialize the ingest queue.

    If `redis_url` is provided and `redis.asyncio` is importable, the
    queue will use Redis LPUSH/BRPOP for durability. Otherwise it
    falls back to an in-memory asyncio.Queue.
    """
    global _queue, _db_session_factory, _redis_client
    if db_session_factory:
        _db_session_factory = db_session_factory
    if redis_url:
        try:
            import redis.asyncio as _redis  # type: ignore

            _redis_client = _redis.from_url(redis_url)
            logger.info("SIEM ingest queue configured with Redis", redis_url=redis_url)
            return
        except Exception as e:  # noqa: BLE001
            logger.warning(f"redis.asyncio unavailable or connection failed: {e}; falling back to in-memory queue")
    if _queue is None:
        _queue = asyncio.Queue(maxsize=queue_maxsize)


async def enqueue(event: dict[str, Any], organization_id: Optional[str] = None) -> bool:
    """Enqueue an event; returns True on success or False if queue full.

    If Redis is configured, push to the Redis list (LPUSH) for durability.
    """
    global _queue, _redis_client
    payload = {"event": event, "organization_id": organization_id}
    if _redis_client is not None:
        try:
            await _redis_client.lpush(_redis_key, json.dumps(payload))
            return True
        except Exception as e:  # noqa: BLE001
            logger.debug(f"redis enqueue failed: {e}")
            # Fall through to in-memory fallback
    if _queue is None:
        raise RuntimeError("ingest queue not initialized")
    try:
        _queue.put_nowait((event, organization_id))
        return True
    except asyncio.QueueFull:
        return False


async def _worker_loop():
    from src.siem.pipeline import process_host_event
    from src.core.database import async_session_factory

    global _queue, _db_session_factory, _redis_client
    logger.info("SIEM ingest queue worker starting")

    # If Redis client is configured, use BRPOP to consume items.
    if _redis_client is not None:
        try:
            while True:
                try:
                    # BRPOP returns (key, value) or None
                    item = await _redis_client.brpop(_redis_key, timeout=5)
                    if not item:
                        await asyncio.sleep(0.1)
                        continue
                    raw = item[1]
                    try:
                        payload = json.loads(raw)
                    except Exception:
                        logger.debug("failed to json-decode redis payload")
                        continue
                    event = payload.get("event")
                    org_id = payload.get("organization_id")
                    try:
                        async with (_db_session_factory() if _db_session_factory else async_session_factory()) as db:
                            try:
                                await process_host_event(event, db=db, organization_id=org_id)
                                await db.commit()
                            except Exception as e:
                                logger.debug(f"process_host_event error: {e}")
                    except Exception as e:
                        logger.debug(f"ingest worker db session failed: {e}")
                except asyncio.CancelledError:
                    break
                except Exception as exc:  # noqa: BLE001
                    logger.exception(f"ingest worker loop failed: {exc}")
        finally:
            logger.info("SIEM ingest queue worker stopped (redis mode)")
        return

    # In-memory queue mode
    while True:
        try:
            item = await _queue.get()
            if item is None:
                # shutdown sentinel
                break
            event, org_id = item
            try:
                async with (_db_session_factory() if _db_session_factory else async_session_factory()) as db:
                    try:
                        await process_host_event(event, db=db, organization_id=org_id)
                        await db.commit()
                    except Exception as e:
                        logger.debug(f"process_host_event error: {e}")
            except Exception as e:
                logger.debug(f"ingest worker db session failed: {e}")
            finally:
                _queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.exception(f"ingest worker loop failed: {exc}")
    logger.info("SIEM ingest queue worker stopped")


def start(loop: Optional[asyncio.AbstractEventLoop] = None, worker_count: int = 1):
    """Start one or more ingest worker tasks.

    `worker_count` controls how many concurrent consumers are created.
    In Redis mode multiple BRPOP consumers scale throughput; in-memory
    mode multiple tasks share the same asyncio.Queue.
    """
    global _worker_tasks, _queue
    if _redis_client is None and _queue is None:
        init()
    if _worker_tasks is None:
        loop = loop or asyncio.get_event_loop()
        _worker_tasks = [loop.create_task(_worker_loop()) for _ in range(max(1, worker_count))]
    return _worker_tasks


async def stop():
    global _queue, _worker_tasks, _redis_client
    if _worker_tasks:
        for t in list(_worker_tasks):
            t.cancel()
        for t in list(_worker_tasks):
            try:
                await t
            except Exception:
                pass
    _worker_tasks = None
    if _redis_client is not None:
        return
    if _queue is None:
        return
    # Signal shutdown for in-memory queue
    try:
        await _queue.put(None)
    except Exception:
        pass
    _queue = None


def is_initialized() -> bool:
    return (_redis_client is not None) or (_queue is not None)


async def get_status() -> dict:
    """Return lightweight status info useful for health checks and scaling.

    - mode: "redis" or "memory"
    - queue_length: approximate number of queued items
    - redis_connected: bool when in redis mode
    """
    global _redis_client, _queue
    if _redis_client is not None:
        try:
            llen = await _redis_client.llen(_redis_key)
            return {"mode": "redis", "queue_length": int(llen), "redis_connected": True}
        except Exception:
            return {"mode": "redis", "queue_length": -1, "redis_connected": False}
    if _queue is not None:
        return {"mode": "memory", "queue_length": _queue.qsize(), "redis_connected": False}
    return {"mode": "none", "queue_length": 0, "redis_connected": False}
