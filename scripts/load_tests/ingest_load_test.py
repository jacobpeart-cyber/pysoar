"""Simple load test harness for SIEM ingest endpoint.

Usage: run with Python in the repo root. It posts concurrent batches
of fake host events to `/api/v1/agents/_agent/host_events` authenticated
with an agent token. Configure `TARGET_URL` and `AGENT_TOKEN` via
environment variables or edit constants below.

This is intentionally minimal — suitable for local smoke/load tests.
"""
import asyncio
import os
import time
import json
import random

import httpx

TARGET = os.getenv("TARGET_URL", "http://localhost:8000/api/v1")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "pst_demo_token")
CONCURRENCY = int(os.getenv("CONCURRENCY", "20"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
ITERATIONS = int(os.getenv("ITERATIONS", "100"))

EVENT_TYPES = ["process_start", "file_create", "net_conn", "reg_write"]


def make_event(i: int) -> dict:
    return {
        "timestamp": time.time(),
        "type": random.choice(EVENT_TYPES),
        "host": f"loadtest-{i % 100}",
        "pid": random.randint(1000, 5000),
        "message": f"synthetic event {i}",
    }


async def worker(client: httpx.AsyncClient, tasks_queue: asyncio.Queue):
    while True:
        item = await tasks_queue.get()
        if item is None:
            tasks_queue.task_done()
            return
        batch = item
        try:
            r = await client.post(
                f"{TARGET}/agents/_agent/host_events",
                json={"events": batch},
                headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
                timeout=30.0,
            )
            if r.status_code >= 400:
                print("ERR", r.status_code, r.text)
        except Exception as exc:
            print("EXC", exc)
        finally:
            tasks_queue.task_done()


async def main():
    total = CONCURRENCY * ITERATIONS
    q = asyncio.Queue()
    async with httpx.AsyncClient() as client:
        # Pre-create batches
        for i in range(ITERATIONS):
            batch = [make_event(i * BATCH_SIZE + j) for j in range(BATCH_SIZE)]
            await q.put(batch)
        # Start workers
        workers = [asyncio.create_task(worker(client, q)) for _ in range(CONCURRENCY)]
        start = time.time()
        await q.join()
        # Stop workers
        for _ in workers:
            await q.put(None)
        await asyncio.gather(*workers, return_exceptions=True)
        elapsed = time.time() - start
        print(f"Completed {ITERATIONS} batches ({ITERATIONS*BATCH_SIZE} events) in {elapsed:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
