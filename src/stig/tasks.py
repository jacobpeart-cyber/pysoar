"""
STIG/SCAP Celery Tasks

Asynchronous tasks for STIG scanning, remediation, benchmark updates,
reporting, and baseline comparison. Every task queries real database
rows and performs real operations.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from celery import shared_task
from sqlalchemy import func, select

from src.core.logging import get_logger

logger = get_logger(__name__)


def _run_async(coro):
    """Run an async coroutine from a sync Celery task context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# Map of STIG benchmark platform string -> agent ``os_type`` value.
# Used to filter rules to only those that apply to the host's OS.
_PLATFORM_OS_MAP = {
    "windows": {"windows"},
    "win": {"windows"},
    "rhel": {"linux"},
    "ubuntu": {"linux"},
    "centos": {"linux"},
    "linux": {"linux"},
    "macos": {"macos"},
    "darwin": {"macos"},
}


def _platform_matches(rule_platform: str, agent_os: Optional[str]) -> bool:
    """Return True if a rule tagged with ``rule_platform`` (free text from
    the STIG XML, e.g. 'Windows 10', 'RHEL 8') applies to a host whose
    enrolled agent reports ``agent_os`` ('windows'|'linux'|'macos').

    When we don't know the host's OS we keep the rule (we can't safely
    filter it out); when the rule is unlabeled we keep it too.
    """
    if not rule_platform or not agent_os:
        return True
    rp = rule_platform.lower()
    agent_os = agent_os.lower()
    for key, oses in _PLATFORM_OS_MAP.items():
        if key in rp:
            return agent_os in oses
    return True  # unknown platform string -> don't drop the rule


# ---------------------------------------------------------------------------
# Memory bounds
# ---------------------------------------------------------------------------
# run_stig_scan and auto_remediate_findings used to load every rule of a
# benchmark as a full ORM row (check/fix text blobs included) with one
# ``.scalars().all()``; the scan's poll loop re-selected every dispatched
# AgentCommand as ORM rows each tick; and the weekly fleet sweep loaded every
# active agent and every available benchmark. Each now walks its table in
# keyset windows of STIG_BATCH_SIZE on the primary key, reads only the
# columns it uses (ORM rows only where the row itself is mutated), and
# commits + releases per window. Per-run caps set ``truncated`` when hit.
STIG_BATCH_SIZE = 1_000
MAX_STIG_RULES_PER_SCAN = 5_000
MAX_STIG_REMEDIATION_RULES_PER_RUN = 10_000
MAX_STIG_FLEET_DISPATCH_PER_RUN = 10_000

# Agent result polling for run_stig_scan (module-level so tests can shrink it).
STIG_POLL_INTERVAL_SECONDS = 5.0
STIG_POLL_DEADLINE_SECONDS = 600.0

_TERMINAL_COMMAND_STATES = ("completed", "failed", "expired", "rejected")


async def _run_stig_scan_async(
    task_id: Optional[str], host: str, benchmark_id: str, org_id: str,
) -> dict[str, Any]:
    """Async core of ``run_stig_scan`` (see the task docstring)."""
    import time as _time

    from src.agents.models import AgentCommand, AgentResult, EndpointAgent
    from src.agents.service import AgentService, AgentServiceError
    from src.core.database import async_session_factory
    from src.stig.models import STIGBenchmark, STIGRule, STIGScanResult

    async with async_session_factory() as session:
        benchmark = (await session.execute(
            select(STIGBenchmark).where(STIGBenchmark.id == benchmark_id),
        )).scalar_one_or_none()

        if not benchmark:
            logger.error(f"Benchmark {benchmark_id} not found")
            return {"status": "error", "detail": "Benchmark not found"}

        agent = (await session.execute(
            select(EndpointAgent).where(
                EndpointAgent.hostname == host,
                EndpointAgent.organization_id == org_id,
            ).limit(1),
        )).scalars().first()

        agent_os = agent.os_type if agent else None
        agent_active = bool(agent and agent.status == "active")

        # Platform applicability is decided per benchmark, so either every
        # rule applies or none does: a COUNT replaces loading the rules.
        rule_count = (await session.execute(
            select(func.count(STIGRule.id)).where(STIGRule.benchmark_id_ref == benchmark_id),
        )).scalar_one()
        platform_ok = _platform_matches(benchmark.platform or "", agent_os)
        applicable_count = rule_count if platform_ok else 0

        if not agent_active:
            scan_result = STIGScanResult(
                benchmark_id_ref=benchmark_id,
                target_host=host,
                organization_id=org_id,
                scan_type="automated",
                status="no_agent",
                total_checks=applicable_count,
                not_a_finding=0,
                open_findings=0,
                not_applicable=0,
                not_reviewed=applicable_count,
                compliance_percentage=0.0,
                completed_at=datetime.now(timezone.utc),
                findings={
                    "reason": (
                        "no_agent_enrolled" if agent is None
                        else f"agent_status_{agent.status}"
                    ),
                    "host_os": agent_os,
                    "applicable_rule_count": applicable_count,
                },
            )
            session.add(scan_result)
            await session.commit()
            await session.refresh(scan_result)
            logger.warning(
                f"STIG scan for host={host} benchmark={benchmark_id}: "
                f"no active agent — enroll PySOAR agent with 'compliance' capability",
            )
            return {
                "task_id": task_id,
                "scan_id": scan_result.id,
                "host": host,
                "benchmark": benchmark_id,
                "org_id": org_id,
                "status": "no_agent",
                "applicable_rules": applicable_count,
                "compliance_percentage": None,
                "truncated": False,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Dispatch real RUN_STIG_CHECK commands to the agent for every
        # rule that has automatable check content, one window of rules
        # (four columns each) at a time.
        service = AgentService(session)
        dispatched: list[tuple[str, str]] = []  # (rule_id, command_id)
        not_automatable = 0
        dispatch_failures: list[tuple[str, str]] = []  # (rule_id, error)
        considered = 0
        rules_cap_hit = False
        last_rule_id: Optional[str] = None

        while platform_ok and considered < MAX_STIG_RULES_PER_SCAN:
            window = min(STIG_BATCH_SIZE, MAX_STIG_RULES_PER_SCAN - considered)
            stmt = select(
                STIGRule.id, STIGRule.rule_id, STIGRule.severity, STIGRule.automated_check,
            ).where(STIGRule.benchmark_id_ref == benchmark_id)
            if last_rule_id is not None:
                stmt = stmt.where(STIGRule.id > last_rule_id)
            rules = (await session.execute(stmt.order_by(STIGRule.id).limit(window))).all()
            if not rules:
                break
            last_rule_id = rules[-1].id
            considered += len(rules)

            issued: list[Any] = []
            for rule in rules:
                check = rule.automated_check or {}
                script = check.get("script") if isinstance(check, dict) else None
                if not script:
                    not_automatable += 1
                    continue
                try:
                    cmd = await service.issue_command(
                        agent=agent,
                        action="run_stig_check",
                        payload={
                            "rule_id": rule.id,
                            "check_script": script,
                            "os_type": agent_os,
                            "rule_identifier": rule.rule_id,
                            "severity": rule.severity,
                        },
                        approval_override=True,  # compliance scans are pre-authorized
                    )
                    dispatched.append((rule.id, cmd.id))
                    issued.append(cmd)
                except AgentServiceError as e:
                    dispatch_failures.append((rule.id, str(e)))

            await session.commit()
            # The agent row stays attached (issue_command advances its hash
            # chain); the window's new command rows are released.
            for cmd in issued:
                session.expunge(cmd)

            if len(rules) < window:
                break
        else:
            rules_cap_hit = platform_ok

        if rules_cap_hit:
            logger.warning(
                f"STIG scan host={host} benchmark={benchmark_id}: rule cap "
                f"{MAX_STIG_RULES_PER_SCAN} hit; remaining rules counted as not reviewed",
            )

        # Poll for results. Each command is expected to complete within the
        # command's expires_at window (15 min default). Statuses are read as
        # plain columns in id chunks, so every tick sees the agent's latest
        # write instead of the session's cached copy of the command.
        deadline = _time.monotonic() + STIG_POLL_DEADLINE_SECONDS
        cmd_ids = [c for _, c in dispatched]
        results_by_rule: dict[str, dict] = {}

        while cmd_ids and _time.monotonic() < deadline:
            await asyncio.sleep(STIG_POLL_INTERVAL_SECONDS)
            remaining: list[str] = []
            for offset in range(0, len(cmd_ids), STIG_BATCH_SIZE):
                chunk = cmd_ids[offset : offset + STIG_BATCH_SIZE]
                cmds = (await session.execute(
                    select(AgentCommand.id, AgentCommand.status, AgentCommand.payload)
                    .where(AgentCommand.id.in_(chunk)),
                )).all()
                done = [c for c in cmds if c.status in _TERMINAL_COMMAND_STATES]
                remaining.extend(c.id for c in cmds if c.status not in _TERMINAL_COMMAND_STATES)
                if not done:
                    continue
                # AgentResult is 1:1 with its command; one lookup per chunk.
                agent_results = {
                    r.command_id: r
                    for r in (await session.execute(
                        select(
                            AgentResult.command_id,
                            AgentResult.artifacts,
                            AgentResult.exit_code,
                            AgentResult.stderr,
                        ).where(AgentResult.command_id.in_([c.id for c in done])),
                    )).all()
                }
                for cmd in done:
                    rule_id = (cmd.payload or {}).get("rule_id")
                    if not rule_id:
                        continue
                    agent_result = agent_results.get(cmd.id)
                    artifact = (agent_result.artifacts or {}) if agent_result else {}
                    results_by_rule[rule_id] = {
                        "status": cmd.status,
                        "result": artifact,
                        "exit_code": agent_result.exit_code if agent_result else None,
                        "stderr": agent_result.stderr if agent_result else None,
                    }
            # End the read transaction between ticks.
            await session.commit()
            cmd_ids = remaining

        # Aggregate
        satisfied = 0
        failed = 0
        not_applicable = 0
        not_reviewed = not_automatable
        findings_detail: list[dict] = []

        for rule_id, outcome in results_by_rule.items():
            result = outcome.get("result") or {}
            check_result = (result.get("check_result") or "").lower() if isinstance(result, dict) else ""
            if outcome["status"] != "completed":
                not_reviewed += 1
                findings_detail.append({"rule_id": rule_id, "status": outcome["status"]})
            elif check_result in ("pass", "not_a_finding", "satisfied"):
                satisfied += 1
            elif check_result in ("fail", "open", "finding"):
                failed += 1
                findings_detail.append({
                    "rule_id": rule_id,
                    "status": "open",
                    "evidence": result.get("evidence"),
                })
            elif check_result in ("n/a", "not_applicable"):
                not_applicable += 1
            else:
                not_reviewed += 1

        # Rules that never got a command (dispatch failure, beyond the
        # per-scan cap, or no script).
        undispatched = applicable_count - len(dispatched)
        not_reviewed += max(0, undispatched - not_automatable)

        evaluated = satisfied + failed
        compliance_pct = (satisfied / evaluated * 100.0) if evaluated else 0.0

        scan_result = STIGScanResult(
            benchmark_id_ref=benchmark_id,
            target_host=host,
            organization_id=org_id,
            scan_type="automated",
            status="completed" if evaluated else "no_automatable_rules",
            total_checks=applicable_count,
            not_a_finding=satisfied,
            open_findings=failed,
            not_applicable=not_applicable,
            not_reviewed=not_reviewed,
            compliance_percentage=compliance_pct,
            completed_at=datetime.now(timezone.utc),
            findings={
                "agent_id": agent.id,
                "host_os": agent_os,
                "dispatched": len(dispatched),
                "dispatch_failures": dispatch_failures,
                "not_automatable": not_automatable,
                "open_findings": findings_detail,
                "truncated": rules_cap_hit,
            },
        )
        session.add(scan_result)
        await session.commit()
        await session.refresh(scan_result)

        logger.info(
            f"STIG scan complete host={host} benchmark={benchmark_id}: "
            f"{satisfied}/{evaluated} satisfied ({compliance_pct:.1f}%), "
            f"{failed} failed, {not_applicable} N/A, {not_reviewed} not reviewed",
        )
        return {
            "task_id": task_id,
            "scan_id": scan_result.id,
            "host": host,
            "benchmark": benchmark_id,
            "org_id": org_id,
            "status": scan_result.status,
            "applicable_rules": applicable_count,
            "satisfied": satisfied,
            "failed": failed,
            "not_applicable": not_applicable,
            "not_reviewed": not_reviewed,
            "compliance_percentage": compliance_pct,
            "truncated": rules_cap_hit,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@shared_task(bind=True, max_retries=3)
def run_stig_scan(self, host: str, benchmark_id: str, org_id: str):
    """Evaluate a STIG benchmark against ``host`` by dispatching real
    ``run_stig_check`` commands to the enrolled endpoint agent and
    collecting actual pass/fail results.

    Flow:
      1. Find the enrolled agent for ``host`` (org-scoped).
      2. Filter benchmark rules to those applicable to the agent's OS.
      3. For each rule with ``automated_check.script`` content, issue
         a ``RUN_STIG_CHECK`` command through ``AgentService``. The
         agent runs the platform-appropriate check (bash/powershell)
         and reports back pass/fail/not_applicable via the command
         result polling path.
      4. Aggregate real results and write an ``STIGScanResult`` row
         with an actual compliance percentage.

    Rules that are manual-review-only (no automatable content) are
    counted in ``not_reviewed``. If no agent is enrolled we record
    ``status='no_agent'`` with zero compliance — we never fabricate.
    """
    try:
        return _run_async(_run_stig_scan_async(self.request.id, host, benchmark_id, org_id))
    except Exception as exc:
        logger.error(f"STIG scan task failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


async def _auto_remediate_findings_async(
    task_id: Optional[str], scan_result_id: str, org_id: str,
) -> dict[str, Any]:
    """Async core of ``auto_remediate_findings``, one window of rules at a time."""
    from src.core.database import async_session_factory
    from src.stig.engine import STIGRemediator
    from src.stig.models import STIGRule, STIGScanResult

    async with async_session_factory() as session:
        scan = (await session.execute(
            select(STIGScanResult).where(STIGScanResult.id == scan_result_id),
        )).scalar_one_or_none()
        if not scan:
            return {"status": "error", "detail": "Scan result not found"}
        benchmark_ref = scan.benchmark_id_ref
        target_host = scan.target_host

        remediator = STIGRemediator(session)
        remediated = 0
        failed = 0
        considered = 0
        cap_hit = False
        last_rule_id: Optional[str] = None

        while considered < MAX_STIG_REMEDIATION_RULES_PER_RUN:
            window = min(STIG_BATCH_SIZE, MAX_STIG_REMEDIATION_RULES_PER_RUN - considered)
            # Rules without fix text were skipped in Python before; the
            # same filter now runs in SQL so they are never loaded.
            stmt = select(STIGRule).where(
                STIGRule.benchmark_id_ref == benchmark_ref,
                STIGRule.fix_text.isnot(None),
                STIGRule.fix_text != "",
            )
            if last_rule_id is not None:
                stmt = stmt.where(STIGRule.id > last_rule_id)
            rules = list(
                (await session.execute(stmt.order_by(STIGRule.id).limit(window))).scalars(),
            )
            if not rules:
                break
            last_rule_id = rules[-1].id
            considered += len(rules)

            for rule in rules:
                if (rule.automated_check or {}).get("not_applicable"):
                    continue
                result = await remediator._apply_fix(rule, target_host)
                if result.get("success"):
                    remediated += 1
                else:
                    failed += 1

            await session.commit()
            session.expunge_all()

            if len(rules) < window:
                break
        else:
            cap_hit = True

        if cap_hit:
            logger.warning(
                f"auto_remediate_findings scan={scan_result_id}: rule cap "
                f"{MAX_STIG_REMEDIATION_RULES_PER_RUN} hit; remainder deferred",
            )

        return {
            "task_id": task_id,
            "scan_id": scan_result_id,
            "org_id": org_id,
            "status": "completed",
            "remediated": remediated,
            "failed": failed,
            "truncated": cap_hit,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@shared_task(bind=True, max_retries=3)
def auto_remediate_findings(self, scan_result_id: str, org_id: str):
    """Auto-remediate failed findings from a scan result using the STIG
    remediator engine (records attempts + generates fix scripts)."""
    try:
        return _run_async(_auto_remediate_findings_async(self.request.id, scan_result_id, org_id))
    except Exception as exc:
        logger.error(f"Auto-remediation task failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


async def _scheduled_fleet_stig_sweep_async() -> dict[str, Any]:
    """Async core of ``scheduled_fleet_stig_sweep``.

    Active agents are paged in keyset windows (three columns each); for each
    window only the benchmarks of the orgs present in it are read, also in
    keyset windows. Dispatch order is (agent id, benchmark id).
    """
    from src.agents.models import EndpointAgent
    from src.core.database import async_session_factory
    from src.stig.models import STIGBenchmark

    dispatched: list[dict[str, str]] = []
    cap_hit = False
    last_agent_id: Optional[str] = None

    async with async_session_factory() as session:
        while True:
            stmt = select(
                EndpointAgent.id, EndpointAgent.hostname, EndpointAgent.organization_id,
            ).where(EndpointAgent.status == "active")
            if last_agent_id is not None:
                stmt = stmt.where(EndpointAgent.id > last_agent_id)
            agents = (
                await session.execute(stmt.order_by(EndpointAgent.id).limit(STIG_BATCH_SIZE))
            ).all()
            if not agents:
                break
            last_agent_id = agents[-1].id

            org_ids = sorted({a.organization_id for a in agents if a.organization_id})
            benches_by_org: dict[str, list[str]] = {}
            last_bench_id: Optional[str] = None
            while org_ids:
                bstmt = select(STIGBenchmark.id, STIGBenchmark.organization_id).where(
                    STIGBenchmark.status == "available",
                    STIGBenchmark.organization_id.in_(org_ids),
                )
                if last_bench_id is not None:
                    bstmt = bstmt.where(STIGBenchmark.id > last_bench_id)
                benches = (
                    await session.execute(
                        bstmt.order_by(STIGBenchmark.id).limit(STIG_BATCH_SIZE),
                    )
                ).all()
                for b in benches:
                    benches_by_org.setdefault(b.organization_id, []).append(b.id)
                if len(benches) < STIG_BATCH_SIZE:
                    break
                last_bench_id = benches[-1].id

            for agent in agents:
                for bench_id in benches_by_org.get(agent.organization_id, ()):
                    if len(dispatched) >= MAX_STIG_FLEET_DISPATCH_PER_RUN:
                        cap_hit = True
                        break
                    run_stig_scan.delay(
                        host=agent.hostname,
                        benchmark_id=bench_id,
                        org_id=agent.organization_id,
                    )
                    dispatched.append({"host": agent.hostname, "benchmark_id": bench_id})
                if cap_hit:
                    break

            await session.commit()
            session.expunge_all()
            if cap_hit or len(agents) < STIG_BATCH_SIZE:
                break

    if cap_hit:
        logger.warning(
            f"scheduled_fleet_stig_sweep: dispatch cap {MAX_STIG_FLEET_DISPATCH_PER_RUN} "
            f"hit; remaining (host, benchmark) pairs deferred to the next run",
        )
    return {
        "status": "dispatched",
        "count": len(dispatched),
        "items": dispatched,
        "truncated": cap_hit,
    }


@shared_task(bind=True)
def scheduled_fleet_stig_sweep(self):
    """Weekly STIG sweep across every enrolled endpoint agent and every
    imported benchmark. Dispatches ``run_stig_scan`` tasks per
    (host, benchmark) pair and returns the work list for observability.

    Federal-compliance ask: FedRAMP Moderate + DoD STIG baselines
    require continuous monitoring (NIST SP 800-137 CAESARS) with
    periodic scans. A weekly cadence is the industry norm for STIG;
    IAVM findings trigger ad-hoc scans separately.
    """
    return _run_async(_scheduled_fleet_stig_sweep_async())


@shared_task(bind=True, max_retries=2)
def update_stig_benchmarks(self, org_id: str):
    """Load built-in STIG benchmarks into the database for the given org."""
    from src.core.database import async_session_factory
    from src.stig.engine import STIGLibrary

    async def _update():
        async with async_session_factory() as session:
            library = STIGLibrary(session)
            added = await library.load_builtin_benchmarks(org_id)
            await session.commit()
            return {
                "task_id": self.request.id,
                "org_id": org_id,
                "status": "completed",
                "benchmarks_added": added,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_update())
    except Exception as exc:
        logger.error(f"Benchmark update task failed: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def generate_stig_report(self, scan_id: str, org_id: str, report_type: str = "json"):
    """Generate a STIG compliance report from a real scan result."""
    from src.core.database import async_session_factory
    from src.stig.models import STIGBenchmark, STIGScanResult

    async def _report():
        async with async_session_factory() as session:
            scan = (await session.execute(
                select(STIGScanResult).where(STIGScanResult.id == scan_id),
            )).scalar_one_or_none()
            if not scan:
                return {"status": "error", "detail": "Scan not found"}

            benchmark = (await session.execute(
                select(STIGBenchmark).where(STIGBenchmark.id == scan.benchmark_id_ref),
            )).scalar_one_or_none()

            report = {
                "report_type": report_type,
                "scan_id": scan_id,
                "host": scan.target_host,
                "benchmark_name": benchmark.title if benchmark else scan.benchmark_id_ref,
                "compliance_percentage": scan.compliance_percentage,
                "total_rules": scan.total_checks,
                "passed": scan.not_a_finding,
                "failed": scan.open_findings,
                "not_applicable": scan.not_applicable,
                "errors": scan.not_reviewed,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            return {
                "task_id": self.request.id,
                "status": "completed",
                "report": report,
            }

    try:
        return _run_async(_report())
    except Exception as exc:
        logger.error(f"Report generation task failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=2)
def compare_scan_baselines(self, scan_id_1: str, scan_id_2: str, org_id: str):
    """Compare two STIG scan results and compute the compliance delta."""
    from src.core.database import async_session_factory
    from src.stig.models import STIGScanResult

    async def _compare():
        async with async_session_factory() as session:
            scan1 = (await session.execute(
                select(STIGScanResult).where(STIGScanResult.id == scan_id_1),
            )).scalar_one_or_none()
            scan2 = (await session.execute(
                select(STIGScanResult).where(STIGScanResult.id == scan_id_2),
            )).scalar_one_or_none()

            if not scan1 or not scan2:
                return {"status": "error", "detail": "One or both scans not found"}

            delta = (scan2.compliance_percentage or 0) - (scan1.compliance_percentage or 0)
            improvements = max(0, (scan2.passed or 0) - (scan1.passed or 0))
            regressions = max(0, (scan1.passed or 0) - (scan2.passed or 0))

            return {
                "task_id": self.request.id,
                "scan_1": scan_id_1,
                "scan_2": scan_id_2,
                "org_id": org_id,
                "status": "completed",
                "compliance_delta": round(delta, 1),
                "improvements": improvements,
                "regressions": regressions,
                "scan_1_compliance": scan1.compliance_percentage,
                "scan_2_compliance": scan2.compliance_percentage,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_compare())
    except Exception as exc:
        logger.error(f"Baseline comparison task failed: {exc}")
        raise self.retry(exc=exc, countdown=60)
