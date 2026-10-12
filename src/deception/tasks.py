"""
Celery tasks for Deception Technology module.

Only the honeypot dispatch reconciliation below is real. Seven placeholder
tasks (monitor_decoy_interactions, rotate_honey_tokens, check_token_canaries,
analyze_new_interactions, update_campaign_stats, deploy_scheduled_decoys,
cleanup_expired_tokens) were deleted in wave 1: each returned a hard-coded
zero count, none was scheduled and nothing called them.
"""

from celery import shared_task

from src.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Honeypot dispatch reconciliation (2026-06-11)
#
# deploy_honeypot dispatches an agent command and leaves the decoy in
# status="deploying" with the command id stored in configuration. This
# beat task closes the loop: when the agent's result arrives the decoy
# flips to active (listener confirmed) or failed (bind error etc).
# ---------------------------------------------------------------------------

import asyncio
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from src.core.config import settings

_engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
_AsyncSessionLocal = sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


# Memory bounds: the reconcile used to load every deploying honeypot as an
# ORM row in one ``.scalars().all()`` and run two point SELECTs per decoy
# under a single commit. It now walks deploying honeypots in keyset windows
# on the primary key, resolves each window's agent results / commands with
# one ``IN (...)`` lookup each, and commits + expunges per window.
RECONCILE_BATCH_SIZE = 1_000
MAX_RECONCILE_DECOYS_PER_RUN = 20_000


async def _reconcile_honeypot_dispatches() -> dict:
    from src.agents.models import AgentCommand, AgentResult
    from src.deception.models import Decoy

    activated = failed = pending = 0
    scanned = 0
    cap_hit = False
    last_id: str | None = None

    async with _AsyncSessionLocal() as db:
        while scanned < MAX_RECONCILE_DECOYS_PER_RUN:
            window = min(RECONCILE_BATCH_SIZE, MAX_RECONCILE_DECOYS_PER_RUN - scanned)
            stmt = select(Decoy).where(
                Decoy.decoy_type == "honeypot",
                Decoy.status == "deploying",
            )
            if last_id is not None:
                stmt = stmt.where(Decoy.id > last_id)
            decoys = list(
                (await db.execute(stmt.order_by(Decoy.id).limit(window))).scalars(),
            )
            if not decoys:
                break
            last_id = decoys[-1].id
            scanned += len(decoys)

            command_ids = {
                (dict((d.configuration or {}).get("listener") or {})).get("command_id")
                for d in decoys
            }
            command_ids.discard(None)
            results_by_command: dict[str, Any] = {}
            commands_by_id: dict[str, str] = {}
            if command_ids:
                for row in (
                    await db.execute(
                        select(
                            AgentResult.command_id,
                            AgentResult.status,
                            AgentResult.stderr,
                        ).where(AgentResult.command_id.in_(sorted(command_ids))),
                    )
                ).all():
                    results_by_command.setdefault(row.command_id, row)
                without_result = sorted(command_ids - set(results_by_command))
                if without_result:
                    for row in (
                        await db.execute(
                            select(AgentCommand.id, AgentCommand.status).where(
                                AgentCommand.id.in_(without_result),
                            ),
                        )
                    ).all():
                        commands_by_id[row.id] = row.status

            for decoy in decoys:
                config = dict(decoy.configuration or {})
                listener = dict(config.get("listener") or {})
                command_id = listener.get("command_id")
                if not command_id:
                    continue

                result = results_by_command.get(command_id)
                if result is not None:
                    if result.status == "success":
                        decoy.status = "active"
                        listener["state"] = "listening"
                        activated += 1
                    else:
                        decoy.status = "failed"
                        listener["state"] = "failed"
                        listener["error"] = (result.stderr or result.status or "")[:300]
                        failed += 1
                else:
                    cmd_status = commands_by_id.get(command_id)
                    if cmd_status in ("rejected", "expired", "failed"):
                        decoy.status = "failed"
                        listener["state"] = "failed"
                        listener["error"] = f"command {cmd_status}"
                        failed += 1
                    else:
                        pending += 1
                        continue

                config["listener"] = listener
                decoy.configuration = config

            await db.commit()
            db.expunge_all()

            if len(decoys) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            "reconcile_honeypot_dispatches hit per-run cap; remainder deferred",
            extra={"cap": MAX_RECONCILE_DECOYS_PER_RUN},
        )
    return {
        "activated": activated,
        "failed": failed,
        "pending": pending,
        "truncated": cap_hit,
    }


@shared_task(name="deception.reconcile_honeypot_dispatches")
def reconcile_honeypot_dispatches() -> dict:
    """Flip deploying honeypots to active/failed from agent results."""
    return asyncio.run(_reconcile_honeypot_dispatches())
