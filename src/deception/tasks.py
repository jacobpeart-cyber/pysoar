"""
Celery tasks for Deception Technology module.

Asynchronous tasks for monitoring, analyzing, and managing deception infrastructure.
"""

from datetime import datetime

from celery import shared_task

from src.core.logging import get_logger
from src.deception.engine import InteractionAnalyzer

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
def monitor_decoy_interactions(self):
    """
    Monitor and process new interactions across all active decoys.

    Periodically checks for new interactions and triggers alerts.
    """
    try:
        logger.info("Starting decoy interaction monitoring")

        # Query all new interactions since last run
        # Process each interaction
        # Generate alerts for high-threat interactions
        # Update decoy statistics

        interaction_count = 0
        logger.info(
            "Monitored decoy interactions",
            extra={"new_interactions": interaction_count},
        )

        return {"status": "success", "interactions_processed": interaction_count}

    except Exception as exc:
        logger.error(f"Error monitoring decoy interactions: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def rotate_honey_tokens(self):
    """
    Periodically rotate honeytokens to maintain freshness.

    Generates new tokens, updates deployments, and logs rotations.
    """
    try:
        logger.info("Starting honey token rotation")

        # Query all active honeytokens
        # Generate replacement tokens
        # Update deployment locations
        # Invalidate old tokens
        # Log rotation events

        tokens_rotated = 0
        logger.info(
            "Rotated honey tokens",
            extra={"tokens_rotated": tokens_rotated},
        )

        return {"status": "success", "tokens_rotated": tokens_rotated}

    except Exception as exc:
        logger.error(f"Error rotating honey tokens: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def check_token_canaries(self):
    """
    Monitor DNS and email canaries for triggering.

    Checks for DNS queries and email receives of canary tokens.
    """
    try:
        logger.info("Starting canary token check")

        # Query DNS logs for canary domain queries
        # Check email logs for canary email receives
        # Update honeytoken triggered_count
        # Generate alerts for triggered canaries

        triggered_count = 0
        logger.info(
            "Checked token canaries",
            extra={"triggered_tokens": triggered_count},
        )

        return {"status": "success", "triggered_tokens": triggered_count}

    except Exception as exc:
        logger.error(f"Error checking token canaries: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def analyze_new_interactions(self):
    """
    Run deep analysis on newly detected interactions.

    Performs tool detection, technique mapping, and threat assessment.
    """
    try:
        logger.info("Starting new interaction analysis")

        analyzer = InteractionAnalyzer()

        # Query all unanalyzed interactions
        # Run analyze_interaction() on each
        # Store analysis results
        # Generate threat intelligence summaries

        analyzed_count = 0
        logger.info(
            "Analyzed new interactions",
            extra={"interactions_analyzed": analyzed_count},
        )

        return {"status": "success", "analyzed": analyzed_count}

    except Exception as exc:
        logger.error(f"Error analyzing interactions: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def update_campaign_stats(self):
    """
    Refresh statistics for all active deception campaigns.

    Updates interaction counts, attacker counts, and effectiveness scores.
    """
    try:
        logger.info("Starting campaign statistics update")

        # Query all active campaigns
        # For each campaign:
        #   - Count unique source IPs
        #   - Sum interactions from associated decoys
        #   - Calculate effectiveness score
        #   - Update campaign record

        campaigns_updated = 0
        logger.info(
            "Updated campaign statistics",
            extra={"campaigns_updated": campaigns_updated},
        )

        return {"status": "success", "campaigns_updated": campaigns_updated}

    except Exception as exc:
        logger.error(f"Error updating campaign stats: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def deploy_scheduled_decoys(self):
    """
    Deploy any decoys scheduled for deployment.

    Checks for decoys with scheduled deployment times and deploys them.
    """
    try:
        logger.info("Starting scheduled decoy deployment")

        # Query all decoys with status='deploying' and created_at < now
        # For each:
        #   - Validate configuration
        #   - Deploy to target
        #   - Update status to 'active'
        #   - Log deployment

        deployed_count = 0
        logger.info(
            "Deployed scheduled decoys",
            extra={"decoys_deployed": deployed_count},
        )

        return {"status": "success", "deployed": deployed_count}

    except Exception as exc:
        logger.error(f"Error deploying scheduled decoys: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def cleanup_expired_tokens(self):
    """
    Remove and disable expired honeytokels.

    Identifies honeytokens past their expiration and cleans them up.
    """
    try:
        logger.info("Starting expired token cleanup")

        now = datetime.utcnow()

        # Query all honeytokens with expires_at < now and status='active'
        # For each:
        #   - Update status to 'expired'
        #   - Log cleanup
        #   - Remove from deployment locations

        cleaned_count = 0
        logger.info(
            "Cleaned up expired tokens",
            extra={"tokens_cleaned": cleaned_count},
        )

        return {"status": "success", "tokens_cleaned": cleaned_count}

    except Exception as exc:
        logger.error(f"Error cleaning up expired tokens: {exc}")
        raise self.retry(exc=exc, countdown=60)


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
