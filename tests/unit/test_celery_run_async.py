"""Celery task helpers must run async code without a pre-existing event loop.

A Celery prefork worker thread has no running event loop, and once any
prior ``asyncio.run()`` clears it, ``asyncio.get_event_loop()`` raises
``RuntimeError: There is no current event loop in thread 'MainThread'``
(Python 3.10+). The beat-scheduled ``siem.poll_cloud_integrations`` task
hit exactly this and failed every run. These tests pin the fix: each
module's ``run_async`` helper must transparently create a fresh loop.
"""

import asyncio

import pytest

from src.siem.tasks import run_async as siem_run_async
from src.workers.tasks import run_async as workers_run_async
from src.vulnmgmt.tasks import run_async as vulnmgmt_run_async


@pytest.mark.parametrize(
    "run_async",
    [siem_run_async, workers_run_async, vulnmgmt_run_async],
    ids=["siem", "workers", "vulnmgmt"],
)
def test_run_async_works_with_no_current_event_loop(run_async):
    # Reproduce the Celery worker condition: no event loop set for this thread.
    prior = None
    try:
        prior = asyncio.get_event_loop()
    except RuntimeError:
        pass
    asyncio.set_event_loop(None)
    try:
        async def _coro():
            await asyncio.sleep(0)
            return 42

        # Must NOT raise "no current event loop" — should make its own loop.
        assert run_async(_coro()) == 42
    finally:
        # Restore a usable loop for any later tests in this thread.
        asyncio.set_event_loop(prior or asyncio.new_event_loop())
