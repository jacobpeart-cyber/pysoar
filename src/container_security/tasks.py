"""
Container Security Celery Tasks (wave 4)

Every task works on stored rows of one organisation at a time, reads in
keyset windows, caps the rows it touches per run and commits per window.

- ``reconcile_image_scans`` (beat): applies endpoint-agent results to image
  scans queued through ``scan_container_image`` commands.
- ``cis_audit_sweep`` (beat): runs the CIS checks against the Kubernetes API
  of every cluster that has a stored credential (capped per run).
- ``scheduled_image_scan`` / ``cluster_security_audit``: on-demand,
  tenant-scoped versions for one image / cluster.
- ``stale_image_report``: images not deployed for N days (read only).

Removed in wave 4: ``runtime_monitoring`` (it read pod names with an
unpinned client and an environment token, then evaluated an empty event list:
it could never raise an alert) and ``compliance_check`` (framework scores from
self-attested booleans). Compliance now comes from stored CIS check results.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import select

from src.container_security.models import ContainerImage, ContainerImageScan, KubernetesCluster
from src.core.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "cis_audit_sweep",
    "cluster_security_audit",
    "reconcile_image_scans",
    "scheduled_image_scan",
    "stale_image_report",
]

#: Scans reconciled per window / per run.
SCAN_RECONCILE_BATCH = 100
MAX_SCAN_RECONCILE_PER_RUN = 2_000
#: Clusters audited per sweep (each audit makes ~10 paginated API reads).
MAX_CLUSTERS_PER_SWEEP = 200
CLUSTER_BATCH = 20
MAX_STALE_IMAGES = 5_000


def _factory() -> Any:
    from src.core.database import async_session_factory

    return async_session_factory


def _run(coro: Any) -> Any:
    from src.siem.tasks import run_async

    return run_async(coro)


async def reconcile_image_scans_async(factory: Any = None) -> dict[str, Any]:
    """Apply agent results to pending scans, in keyset windows with a per-run cap."""
    from src.agents.models import AgentCommand, AgentResult
    from src.container_security.scanning import PENDING_SCAN_STATES, reconcile_scan

    factory = factory or _factory()
    totals = {"scanned": 0, "changed": 0, "truncated": False}
    last_id: Optional[str] = None
    async with factory() as db:
        while True:
            if totals["scanned"] >= MAX_SCAN_RECONCILE_PER_RUN:
                totals["truncated"] = True
                break
            window = min(SCAN_RECONCILE_BATCH, MAX_SCAN_RECONCILE_PER_RUN - totals["scanned"])
            stmt = select(ContainerImageScan).where(
                ContainerImageScan.status.in_(PENDING_SCAN_STATES),
                ContainerImageScan.command_id.is_not(None),
            )
            if last_id is not None:
                stmt = stmt.where(ContainerImageScan.id > last_id)
            scans = list((await db.execute(stmt.order_by(ContainerImageScan.id).limit(window))).scalars())
            if not scans:
                break
            last_id = scans[-1].id
            totals["scanned"] += len(scans)
            command_ids = sorted({s.command_id for s in scans if s.command_id})
            results: dict[str, Any] = {}
            for result in (await db.execute(
                select(AgentResult).where(AgentResult.command_id.in_(command_ids))
                .order_by(AgentResult.reported_at.desc()),
            )).scalars():
                results.setdefault(result.command_id, result)
            statuses = dict((await db.execute(
                select(AgentCommand.id, AgentCommand.status).where(AgentCommand.id.in_(command_ids)),
            )).all())
            for scan in scans:
                if await reconcile_scan(
                    db, scan, command_status=statuses.get(scan.command_id),
                    result=results.get(scan.command_id), loaded=True,
                ):
                    totals["changed"] += 1
            await db.commit()
            db.expunge_all()
            if len(scans) < window:
                break
    if totals["truncated"]:
        logger.warning("container_scan_reconcile_capped", cap=MAX_SCAN_RECONCILE_PER_RUN)
    return totals


@shared_task(name="src.container_security.tasks.reconcile_image_scans")
def reconcile_image_scans() -> dict[str, Any]:
    """Beat entry point: apply agent scan results."""
    return _run(reconcile_image_scans_async())


async def cis_audit_sweep_async(factory: Any = None) -> dict[str, Any]:
    """CIS audit of every credentialed cluster, oldest audit first, capped per run."""
    from src.container_security.kube import run_cis_audit

    factory = factory or _factory()
    totals: dict[str, Any] = {"clusters": 0, "assessed": 0, "failed": 0, "truncated": False}
    last_id: Optional[str] = None
    async with factory() as db:
        while True:
            if totals["clusters"] >= MAX_CLUSTERS_PER_SWEEP:
                totals["truncated"] = True
                break
            window = min(CLUSTER_BATCH, MAX_CLUSTERS_PER_SWEEP - totals["clusters"])
            stmt = select(KubernetesCluster).where(KubernetesCluster.credential_encrypted.is_not(None))
            if last_id is not None:
                stmt = stmt.where(KubernetesCluster.id > last_id)
            clusters = list((await db.execute(stmt.order_by(KubernetesCluster.id).limit(window))).scalars())
            if not clusters:
                break
            last_id = clusters[-1].id
            for cluster in clusters:
                totals["clusters"] += 1
                summary = await run_cis_audit(db, cluster)
                key = "assessed" if summary["assessment_status"] == "assessed" else "failed"
                totals[key] += 1
                await db.commit()
            db.expunge_all()
            if len(clusters) < window:
                break
    logger.info("container_cis_audit_sweep", **totals)
    return totals


@shared_task(name="src.container_security.tasks.cis_audit_sweep")
def cis_audit_sweep() -> dict[str, Any]:
    """Beat entry point: daily CIS audit of credentialed clusters."""
    return _run(cis_audit_sweep_async())


async def _scan_one(image_id: str, org_id: str) -> dict[str, Any]:
    from src.container_security.scanning import request_scan

    async with _factory()() as db:
        image = (await db.execute(
            select(ContainerImage).where(
                ContainerImage.id == image_id, ContainerImage.organization_id == org_id,
            ),
        )).scalar_one_or_none()
        if image is None:
            return {"status": "not_found", "image_id": image_id}
        outcome = await request_scan(db, image, requested_by=None)
        await db.commit()
        return {"status": outcome.status, "detail": outcome.detail, "image_id": image_id}


@shared_task(name="src.container_security.tasks.scheduled_image_scan")
def scheduled_image_scan(image_id: str, org_id: str) -> dict[str, Any]:
    """Scan one image of ``org_id`` through an integration or agent (or awaiting_integration)."""
    return _run(_scan_one(image_id, org_id))


async def _audit_one(cluster_id: str, org_id: str) -> dict[str, Any]:
    from src.container_security.kube import run_cis_audit

    async with _factory()() as db:
        cluster = (await db.execute(
            select(KubernetesCluster).where(
                KubernetesCluster.id == cluster_id, KubernetesCluster.organization_id == org_id,
            ),
        )).scalar_one_or_none()
        if cluster is None:
            return {"status": "not_found", "cluster_id": cluster_id}
        summary = await run_cis_audit(db, cluster)
        await db.commit()
        return {"cluster_id": cluster_id, **summary}


@shared_task(name="src.container_security.tasks.cluster_security_audit")
def cluster_security_audit(cluster_id: str, org_id: str) -> dict[str, Any]:
    """CIS audit of one cluster of ``org_id`` against its Kubernetes API."""
    return _run(_audit_one(cluster_id, org_id))


async def _stale(org_id: str, days_threshold: int) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_threshold)
    async with _factory()() as db:
        rows = (await db.execute(
            select(
                ContainerImage.id, ContainerImage.registry, ContainerImage.repository,
                ContainerImage.tag, ContainerImage.last_deployed, ContainerImage.risk_score,
            ).where(
                ContainerImage.organization_id == org_id,
                ContainerImage.last_deployed.is_not(None),
                ContainerImage.last_deployed < cutoff,
            ).order_by(ContainerImage.last_deployed).limit(MAX_STALE_IMAGES + 1),
        )).all()
    truncated = len(rows) > MAX_STALE_IMAGES
    rows = rows[:MAX_STALE_IMAGES]
    return {
        "status": "completed",
        "org_id": org_id,
        "stale_image_count": len(rows),
        "truncated": truncated,
        "images": [
            {
                "id": r.id, "registry": r.registry, "repository": r.repository, "tag": r.tag,
                "last_deployed": r.last_deployed.isoformat() if r.last_deployed else None,
                "risk_score": r.risk_score,
            }
            for r in rows
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@shared_task(name="src.container_security.tasks.stale_image_report")
def stale_image_report(org_id: str, days_threshold: int = 90) -> dict[str, Any]:
    """Images of ``org_id`` not deployed for ``days_threshold`` days."""
    return _run(_stale(org_id, days_threshold))
