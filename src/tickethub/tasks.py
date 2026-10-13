"""TicketHub Celery tasks: the automation-rule evaluator.

``tickethub.evaluate_automation_rules`` runs every minute from beat
(``src/workers/celery_app.py``). Each run walks every organisation with an
enabled rule and evaluates that organisation's rules over the events created
since each rule's cursor; see :mod:`src.tickethub.rules` for the trigger,
condition and action grammar and for the bounds (window, batch and per-run
caps).
"""

from __future__ import annotations

import asyncio
from typing import Any

from celery import shared_task

from src.core.database import async_session_factory
from src.tickethub.rules import evaluate_rules


async def _evaluate_automation_rules_async() -> dict[str, Any]:
    async with async_session_factory() as db:
        result = await evaluate_rules(db)
    result["task"] = "evaluate_automation_rules"
    return result


@shared_task(name="tickethub.evaluate_automation_rules")
def evaluate_automation_rules() -> dict[str, Any]:
    """Beat entry point: evaluate every enabled TicketHub automation rule."""
    return asyncio.run(_evaluate_automation_rules_async())
