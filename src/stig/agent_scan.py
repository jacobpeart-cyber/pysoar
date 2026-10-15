"""STIG scans through endpoint agents (wave 4).

``request_stig_scan`` resolves the enrolled endpoint agent for the target
host (tenant-scoped, ``stig_scan`` or ``compliance`` capability, active) and
queues one ``stig_scan`` command: the agent evaluates the whole XCCDF
benchmark with ``oscap xccdf eval --results-arf`` and returns the ARF XML.
``reconcile_stig_scan`` applies the agent's result: the ARF is parsed by the
same ``STIGScanner.ingest_arf_result`` that handles uploaded ARF files.

When no such agent covers the host the scan row is stored as ``not_run``
with the reason; nothing is ever scored without results (the in-process
"scan" used to store 100% compliance without touching the host).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.stig.models import STIGBenchmark, STIGRule, STIGScanResult

logger = get_logger(__name__)

STIG_SCAN_ACTION = "stig_scan"
#: Scan statuses waiting on an agent.
PENDING_STATES = ("dispatched", "awaiting_approval")
#: Agent command states that end a command without a usable result.
FAILED_COMMAND_STATES = ("failed", "expired", "rejected", "cancelled")


@dataclass
class StigDispatch:
    scan: STIGScanResult
    status: str
    detail: str


def _arf_from_result(result: Any) -> bytes:
    artifacts = result.artifacts if isinstance(result.artifacts, dict) else {}
    arf = artifacts.get("arf") or artifacts.get("report") or result.stdout or ""
    return arf.encode("utf-8") if isinstance(arf, str) else bytes(arf)


async def _benchmark(db: AsyncSession, org_id: str, benchmark_id: str) -> Optional[STIGBenchmark]:
    return (await db.execute(
        select(STIGBenchmark).where(
            (STIGBenchmark.id == benchmark_id) | (STIGBenchmark.benchmark_id == benchmark_id),
            STIGBenchmark.organization_id == org_id,
        ).limit(1),
    )).scalar_one_or_none()


async def request_stig_scan(
    db: AsyncSession,
    *,
    org_id: str,
    host: str,
    benchmark_id: str,
    requested_by: Optional[str],
    target_ip: Optional[str] = None,
    profile: Optional[str] = None,
) -> StigDispatch:
    """Queue a ``stig_scan`` on the host's agent, or store the scan as ``not_run``.

    Raises:
        LookupError: the benchmark is not in ``org_id``.
    """
    from src.agents.capabilities import capability_allows
    from src.agents.service import AgentService, AgentServiceError

    benchmark = await _benchmark(db, org_id, benchmark_id)
    if benchmark is None:
        raise LookupError(f"Benchmark {benchmark_id} not found")
    rule_count = int(await db.scalar(
        select(func.count(STIGRule.id)).where(
            STIGRule.benchmark_id_ref == benchmark.id, STIGRule.organization_id == org_id),
    ) or 0)

    scan = STIGScanResult(
        benchmark_id_ref=benchmark.id,
        target_host=host,
        target_ip=target_ip,
        scan_type="agent",
        scanner="oscap via endpoint agent",
        status="not_run",
        started_at=datetime.now(timezone.utc),
        total_checks=rule_count,
        open_findings=0,
        not_a_finding=0,
        not_applicable=0,
        not_reviewed=rule_count,
        compliance_percentage=0.0,
        cat1_open=0,
        cat2_open=0,
        cat3_open=0,
        findings={},
        organization_id=org_id,
    )
    db.add(scan)
    await db.flush()

    service = AgentService(db)
    agent = await service.resolve_for_target(host, organization_id=org_id)
    if target_ip and agent is None:
        agent = await service.resolve_for_target(target_ip, organization_id=org_id)
    reason: Optional[str] = None
    if agent is None:
        reason = f"no endpoint agent is enrolled for {host} in this organisation"
    elif agent.status != "active":
        reason = f"the agent on {host} is {agent.status}"
    elif not capability_allows(agent.capabilities or [], STIG_SCAN_ACTION):
        reason = f"the agent on {host} is not enrolled with the 'stig_scan' (or 'compliance') capability"
    if reason is not None:
        scan.status_reason = reason
        await db.flush()
        return StigDispatch(scan, "not_run", reason)

    try:
        cmd = await service.issue_command(
            agent=agent,
            action=STIG_SCAN_ACTION,
            payload={
                "scan_id": scan.id,
                "benchmark_id": benchmark.benchmark_id,
                "benchmark_title": benchmark.title,
                "profile": profile,
            },
            issued_by=requested_by,
        )
    except AgentServiceError as exc:
        scan.status_reason = f"agent {agent.hostname} refused the command: {exc}"
        await db.flush()
        return StigDispatch(scan, "not_run", scan.status_reason)

    scan.agent_id = agent.id
    scan.command_id = cmd.id
    scan.status = "awaiting_approval" if cmd.status == "awaiting_approval" else "dispatched"
    scan.status_reason = None
    await db.flush()
    logger.info("stig_scan_dispatched", scan_id=scan.id, agent_id=agent.id, command_id=cmd.id)
    return StigDispatch(scan, scan.status, f"{STIG_SCAN_ACTION} queued on agent {agent.hostname} (command {cmd.id})")


def _fail(scan: STIGScanResult, reason: str) -> None:
    scan.status = "failed"
    scan.status_reason = reason[:4000]
    scan.completed_at = datetime.now(timezone.utc)


async def reconcile_stig_scan(
    db: AsyncSession,
    scan: STIGScanResult,
    *,
    command_status: Optional[str] = None,
    result: Any = None,
    loaded: bool = False,
) -> bool:
    """Apply the agent's result to a dispatched scan. True when the scan changed."""
    from src.agents.models import AgentCommand, AgentResult
    from src.stig.engine import STIGScanner

    if scan.status not in PENDING_STATES or not scan.command_id:
        return False
    if not loaded:
        result = (await db.execute(
            select(AgentResult).where(AgentResult.command_id == scan.command_id)
            .order_by(AgentResult.reported_at.desc()).limit(1),
        )).scalar_one_or_none()
        command_status = (await db.execute(
            select(AgentCommand.status).where(AgentCommand.id == scan.command_id),
        )).scalar_one_or_none()

    if result is None:
        if command_status is None or command_status in FAILED_COMMAND_STATES:
            _fail(scan, f"agent command {command_status or 'missing'} without a result")
            await db.flush()
            return True
        wanted = "awaiting_approval" if command_status == "awaiting_approval" else "dispatched"
        if scan.status != wanted:
            scan.status = wanted
            await db.flush()
            return True
        return False

    if result.status != "success":
        _fail(scan, result.stderr or f"agent reported {result.status}")
        await db.flush()
        return True
    arf = _arf_from_result(result)
    if not arf.strip():
        _fail(scan, "the agent returned no ARF output")
        await db.flush()
        return True
    outcome = await STIGScanner(db).ingest_arf_result(scan_id=scan.id, arf_xml=arf, org_id=scan.organization_id)
    if outcome.get("status") != "ingested":
        await db.refresh(scan)
        _fail(scan, f"agent output is not a usable ARF report: {outcome.get('error') or outcome.get('status')}")
        await db.flush()
    logger.info("stig_scan_reconciled", scan_id=scan.id, status=scan.status)
    return True
