"""
Celery tasks for DFIR (Digital Forensics & Incident Response).

``dfir.reconcile_agent_collections`` is the only task. It moves evidence
collected through endpoint agents (``collect_*`` commands, see
src/dfir/collection.py) from ``pending`` / ``awaiting_approval`` to
``collected`` / ``collected_on_host`` / ``failed`` once the agent reports,
storing the returned bytes under the evidence root with hashes computed on
write.

Wave 3 deleted the five tasks that used to live here
(evidence_integrity_check, automated_artifact_extraction,
timeline_reconstruction_task, ioc_extraction_task, legal_hold_reminder):
none was dispatched or scheduled, the integrity check compared against
"unknown" and always passed, the extraction and timeline tasks worked on the
in-memory engine instead of stored rows, and the reminder sent nothing. The
real equivalents are request-driven routes over stored material:
POST /dfir/evidence/{id}/verify (re-hashes the stored file),
POST /dfir/cases/{id}/artifacts/extract-iocs and
POST /dfir/cases/{id}/timeline/reconstruct.
"""

from __future__ import annotations

from typing import Any

from celery import shared_task
from sqlalchemy import select

from src.core.logging import get_logger

logger = get_logger(__name__)

#: Evidence rows reconciled per window. Small, because an agent result for a
#: collected file carries the file base64-encoded (up to 25 MiB).
RECONCILE_BATCH_SIZE = 50
MAX_RECONCILE_PER_RUN = 2_000


async def reconcile_agent_collections(db, *, root: str | None = None) -> dict[str, Any]:
    """Apply agent results to pending collections, in keyset windows with a per-run cap."""
    from src.agents.models import AgentCommand, AgentResult, EndpointAgent
    from src.dfir.collection import PENDING_STATES, apply_command_outcome
    from src.dfir.models import ForensicEvidence
    from src.dfir.storage import evidence_root

    root = root or evidence_root()
    counts = {"collected": 0, "collected_on_host": 0, "failed": 0, "pending": 0}
    scanned = 0
    last_id: str | None = None
    truncated = False

    while True:
        if scanned >= MAX_RECONCILE_PER_RUN:
            truncated = True
            break
        window = min(RECONCILE_BATCH_SIZE, MAX_RECONCILE_PER_RUN - scanned)
        stmt = select(ForensicEvidence).where(
            ForensicEvidence.collection_status.in_(PENDING_STATES),
            ForensicEvidence.collection_command_id.is_not(None),
        )
        if last_id is not None:
            stmt = stmt.where(ForensicEvidence.id > last_id)
        rows = list((await db.execute(stmt.order_by(ForensicEvidence.id).limit(window))).scalars())
        if not rows:
            break
        last_id = rows[-1].id
        scanned += len(rows)

        command_ids = sorted({r.collection_command_id for r in rows})
        results: dict[str, Any] = {}
        for result in (
            await db.execute(
                select(AgentResult)
                .where(AgentResult.command_id.in_(command_ids))
                .order_by(AgentResult.reported_at.desc()),
            )
        ).scalars():
            results.setdefault(result.command_id, result)
        statuses = dict(
            (await db.execute(select(AgentCommand.id, AgentCommand.status).where(AgentCommand.id.in_(command_ids)))).all(),
        )
        agent_ids = sorted({r.collection_agent_id for r in rows if r.collection_agent_id})
        hostnames = dict(
            (await db.execute(select(EndpointAgent.id, EndpointAgent.hostname).where(EndpointAgent.id.in_(agent_ids)))).all(),
        ) if agent_ids else {}

        for evidence in rows:
            apply_command_outcome(
                evidence,
                root=root,
                command_status=statuses.get(evidence.collection_command_id),
                result=results.get(evidence.collection_command_id),
                agent_hostname=hostnames.get(evidence.collection_agent_id),
            )
            key = evidence.collection_status if evidence.collection_status in counts else "pending"
            counts[key] += 1

        await db.commit()
        db.expunge_all()
        if len(rows) < window:
            break

    if truncated:
        logger.warning("dfir_collection_reconcile_capped", cap=MAX_RECONCILE_PER_RUN)
    return {**counts, "truncated": truncated}


@shared_task(name="dfir.reconcile_agent_collections")
def reconcile_agent_collections_task() -> dict[str, Any]:
    """Beat entry point (every minute)."""
    from src.siem.tasks import run_async

    async def _runner() -> dict[str, Any]:
        from src.core.database import async_session_factory

        async with async_session_factory() as db:
            return await reconcile_agent_collections(db)

    return run_async(_runner())
