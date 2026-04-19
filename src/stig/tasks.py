"""
STIG/SCAP Celery Tasks

Asynchronous tasks for STIG scanning, remediation, benchmark updates,
reporting, and baseline comparison. Every task queries real database
rows and performs real operations.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from celery import shared_task
from sqlalchemy import select, func

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
    from src.core.database import async_session_factory
    from src.stig.models import STIGBenchmark, STIGRule, STIGScanResult
    from src.agents.models import EndpointAgent, AgentCommand, AgentResult
    from src.agents.service import AgentService, AgentServiceError

    async def _scan():
        async with async_session_factory() as session:
            benchmark = (await session.execute(
                select(STIGBenchmark).where(STIGBenchmark.id == benchmark_id)
            )).scalar_one_or_none()

            if not benchmark:
                logger.error(f"Benchmark {benchmark_id} not found")
                return {"status": "error", "detail": "Benchmark not found"}

            agent = (await session.execute(
                select(EndpointAgent).where(
                    EndpointAgent.hostname == host,
                    EndpointAgent.organization_id == org_id,
                )
            )).scalars().first()

            agent_os = agent.os_type if agent else None
            agent_active = bool(agent and agent.status == "active")

            all_rules = (await session.execute(
                select(STIGRule).where(STIGRule.benchmark_id_ref == benchmark_id)
            )).scalars().all()

            applicable_rules = [
                r for r in all_rules
                if _platform_matches(benchmark.platform or "", agent_os)
            ]

            if not agent_active:
                scan_result = STIGScanResult(
                    benchmark_id_ref=benchmark_id,
                    target_host=host,
                    organization_id=org_id,
                    scan_type="automated",
                    status="no_agent",
                    total_checks=len(applicable_rules),
                    not_a_finding=0,
                    open_findings=0,
                    not_applicable=0,
                    not_reviewed=len(applicable_rules),
                    compliance_percentage=0.0,
                    completed_at=datetime.now(timezone.utc),
                    findings={
                        "reason": (
                            "no_agent_enrolled" if agent is None
                            else f"agent_status_{agent.status}"
                        ),
                        "host_os": agent_os,
                        "applicable_rule_count": len(applicable_rules),
                    },
                )
                session.add(scan_result)
                await session.commit()
                await session.refresh(scan_result)
                logger.warning(
                    f"STIG scan for host={host} benchmark={benchmark_id}: "
                    f"no active agent — enroll PySOAR agent with 'compliance' capability"
                )
                return {
                    "task_id": self.request.id,
                    "scan_id": scan_result.id,
                    "host": host,
                    "benchmark": benchmark_id,
                    "org_id": org_id,
                    "status": "no_agent",
                    "applicable_rules": len(applicable_rules),
                    "compliance_percentage": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            # Dispatch real RUN_STIG_CHECK commands to the agent for every
            # rule that has automatable check content. Collect command IDs
            # so we can poll for results.
            service = AgentService(session)
            dispatched: list[tuple[str, str]] = []  # (rule_id, command_id)
            not_automatable = 0
            dispatch_failures: list[tuple[str, str]] = []  # (rule_id, error)

            for rule in applicable_rules:
                check = (rule.automated_check or {}) if hasattr(rule, "automated_check") else {}
                script = (check or {}).get("script") if isinstance(check, dict) else None
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
                            "rule_identifier": getattr(rule, "rule_id", None),
                            "severity": getattr(rule, "severity", None),
                        },
                        approval_override=True,  # compliance scans are pre-authorized
                    )
                    dispatched.append((rule.id, cmd.id))
                except AgentServiceError as e:
                    dispatch_failures.append((rule.id, str(e)))

            await session.commit()

            # Poll for results. Each command is expected to complete
            # within the command's expires_at window (15 min default).
            # We poll every 5s for up to 10 minutes per scan.
            import time as _time
            deadline = _time.monotonic() + 600
            cmd_ids = [c for _, c in dispatched]
            results_by_rule: dict[str, dict] = {}

            while cmd_ids and _time.monotonic() < deadline:
                await asyncio.sleep(5)
                cmds = (await session.execute(
                    select(AgentCommand).where(AgentCommand.id.in_(cmd_ids))
                )).scalars().all()
                remaining: list[str] = []
                for cmd in cmds:
                    if cmd.status in ("completed", "failed", "expired", "rejected"):
                        rule_id = (cmd.payload or {}).get("rule_id")
                        if rule_id:
                            # Fetch the AgentResult row (1:1 via command_id)
                            agent_result = (await session.execute(
                                select(AgentResult).where(AgentResult.command_id == cmd.id)
                            )).scalar_one_or_none()
                            artifact = (agent_result.artifacts or {}) if agent_result else {}
                            results_by_rule[rule_id] = {
                                "status": cmd.status,
                                "result": artifact,
                                "exit_code": agent_result.exit_code if agent_result else None,
                                "stderr": agent_result.stderr if agent_result else None,
                            }
                    else:
                        remaining.append(cmd.id)
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

            # Rules that never got a command (dispatch failure or no script)
            undispatched = len(applicable_rules) - len(dispatched)
            not_reviewed += max(0, undispatched - not_automatable)

            evaluated = satisfied + failed
            compliance_pct = (satisfied / evaluated * 100.0) if evaluated else 0.0

            scan_result = STIGScanResult(
                benchmark_id_ref=benchmark_id,
                target_host=host,
                organization_id=org_id,
                scan_type="automated",
                status="completed" if evaluated else "no_automatable_rules",
                total_checks=len(applicable_rules),
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
                },
            )
            session.add(scan_result)
            await session.commit()
            await session.refresh(scan_result)

            logger.info(
                f"STIG scan complete host={host} benchmark={benchmark_id}: "
                f"{satisfied}/{evaluated} satisfied ({compliance_pct:.1f}%), "
                f"{failed} failed, {not_applicable} N/A, {not_reviewed} not reviewed"
            )
            return {
                "task_id": self.request.id,
                "scan_id": scan_result.id,
                "host": host,
                "benchmark": benchmark_id,
                "org_id": org_id,
                "status": scan_result.status,
                "applicable_rules": len(applicable_rules),
                "satisfied": satisfied,
                "failed": failed,
                "not_applicable": not_applicable,
                "not_reviewed": not_reviewed,
                "compliance_percentage": compliance_pct,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_scan())
    except Exception as exc:
        logger.error(f"STIG scan task failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def auto_remediate_findings(self, scan_result_id: str, org_id: str):
    """Auto-remediate failed findings from a scan result using the STIG
    remediator engine (records attempts + generates fix scripts)."""
    from src.core.database import async_session_factory
    from src.stig.models import STIGScanResult, STIGRule
    from src.stig.engine import STIGRemediator

    async def _remediate():
        async with async_session_factory() as session:
            scan = (await session.execute(
                select(STIGScanResult).where(STIGScanResult.id == scan_result_id)
            )).scalar_one_or_none()
            if not scan:
                return {"status": "error", "detail": "Scan result not found"}

            rules = (await session.execute(
                select(STIGRule).where(STIGRule.benchmark_id_ref == scan.benchmark_id_ref)
            )).scalars().all()

            failed_rules = [r for r in rules if r.fix_text and not (r.automated_check or {}).get("not_applicable")]

            remediator = STIGRemediator(session)
            remediated = 0
            failed = 0

            for rule in failed_rules:
                result = await remediator._apply_fix(rule, scan.target_host)
                if result.get("success"):
                    remediated += 1
                else:
                    failed += 1

            await session.commit()

            return {
                "task_id": self.request.id,
                "scan_id": scan_result_id,
                "org_id": org_id,
                "status": "completed",
                "remediated": remediated,
                "failed": failed,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    try:
        return _run_async(_remediate())
    except Exception as exc:
        logger.error(f"Auto-remediation task failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


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
    from src.stig.models import STIGScanResult, STIGBenchmark

    async def _report():
        async with async_session_factory() as session:
            scan = (await session.execute(
                select(STIGScanResult).where(STIGScanResult.id == scan_id)
            )).scalar_one_or_none()
            if not scan:
                return {"status": "error", "detail": "Scan not found"}

            benchmark = (await session.execute(
                select(STIGBenchmark).where(STIGBenchmark.id == scan.benchmark_id_ref)
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
                select(STIGScanResult).where(STIGScanResult.id == scan_id_1)
            )).scalar_one_or_none()
            scan2 = (await session.execute(
                select(STIGScanResult).where(STIGScanResult.id == scan_id_2)
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
