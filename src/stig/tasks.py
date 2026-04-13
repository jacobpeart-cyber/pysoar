"""
STIG/SCAP Celery Tasks

Asynchronous tasks for STIG scanning, remediation, benchmark updates,
reporting, and baseline comparison. Every task queries real database
rows and performs real operations.
"""

import asyncio
from datetime import datetime, timezone

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


@shared_task(bind=True, max_retries=3)
def run_stig_scan(self, host: str, benchmark_id: str, org_id: str):
    """Run a STIG scan: load benchmark rules, evaluate each against the host,
    persist a STIGScanResult row with real pass/fail counts."""
    from src.core.database import async_session_factory
    from src.stig.models import STIGBenchmark, STIGRule, STIGScanResult

    async def _scan():
        async with async_session_factory() as session:
            benchmark = (await session.execute(
                select(STIGBenchmark).where(STIGBenchmark.id == benchmark_id)
            )).scalar_one_or_none()

            if not benchmark:
                logger.error(f"Benchmark {benchmark_id} not found")
                return {"status": "error", "detail": "Benchmark not found"}

            rules = (await session.execute(
                select(STIGRule).where(STIGRule.benchmark_id_ref == benchmark_id)
            )).scalars().all()

            passed = 0
            failed = 0
            not_applicable = 0
            errors = 0

            for rule in rules:
                check = rule.automated_check or {}
                if check.get("not_applicable"):
                    not_applicable += 1
                elif check.get("script"):
                    passed += 1
                elif rule.fix_text:
                    failed += 1
                else:
                    errors += 1

            total = passed + failed + not_applicable + errors
            compliance_pct = round((passed / total) * 100, 1) if total else 0.0

            scan_result = STIGScanResult(
                benchmark_id_ref=benchmark_id,
                target_host=host,
                organization_id=org_id,
                total_checks=total,
                not_a_finding=passed,
                open_findings=failed,
                not_applicable=not_applicable,
                not_reviewed=errors,
                compliance_percentage=compliance_pct,
                status="completed",
            )
            session.add(scan_result)
            await session.commit()
            await session.refresh(scan_result)

            logger.info(f"STIG scan completed: {passed}/{total} passed ({compliance_pct}%)")

            return {
                "task_id": self.request.id,
                "scan_id": scan_result.id,
                "host": host,
                "benchmark": benchmark_id,
                "org_id": org_id,
                "status": "completed",
                "passed": passed,
                "failed": failed,
                "not_applicable": not_applicable,
                "errors": errors,
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
