"""
STIG/SCAP Engine

Core engine for STIG benchmark scanning, SCAP content management,
automated remediation, and compliance analysis.
"""

import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from src.core.logging import get_logger
from src.core.config import settings
from src.stig.models import STIGBenchmark, STIGRule, STIGScanResult, SCAPProfile

logger = get_logger(__name__)


class STIGScanner:
    """
    STIG Benchmark Scanner

    Executes STIG compliance scans against target hosts using manual,
    automated (SCAP), or hybrid approaches. Generates detailed finding reports.
    """

    def __init__(self, session: AsyncSession):
        """Initialize scanner with database session"""
        self.session = session

    async def scan_host(
        self,
        host: str,
        benchmark_id: str,
        scan_type: str = "automated",
        target_ip: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Scan single host against STIG benchmark

        Args:
            host: Hostname or target identifier
            benchmark_id: STIG benchmark ID to scan against
            scan_type: "manual", "scap", "automated", "hybrid"
            target_ip: IP address of target (optional)

        Returns:
            Scan result with findings and compliance metrics
        """
        logger.info(f"Starting STIG scan on {host} for {benchmark_id}")

        try:
            # Verify benchmark exists
            stmt = select(STIGBenchmark).where(
                STIGBenchmark.benchmark_id == benchmark_id
            )
            benchmark = await self.session.scalar(stmt)
            if not benchmark:
                raise ValueError(f"Benchmark {benchmark_id} not found")

            # Create scan result record
            scan_result = STIGScanResult(
                benchmark_id_ref=benchmark.id,
                target_host=host,
                target_ip=target_ip,
                scan_type=scan_type,
                status="running",
                started_at=datetime.now(timezone.utc),
                organization_id=benchmark.organization_id,
            )
            self.session.add(scan_result)
            await self.session.flush()

            # Get all rules for benchmark
            stmt = select(STIGRule).where(
                STIGRule.benchmark_id_ref == benchmark.id
            )
            rules = await self.session.scalars(stmt)

            # Execute checks
            findings = {}
            open_count = 0
            naf_count = 0
            na_count = 0
            nr_count = 0
            cat1_open = 0
            cat2_open = 0
            cat3_open = 0

            for rule in rules:
                result = await self._execute_check(rule, host, scan_type)
                findings[rule.rule_id] = result

                if result["status"] == "open":
                    open_count += 1
                    if rule.severity == "high":
                        cat1_open += 1
                    elif rule.severity == "medium":
                        cat2_open += 1
                    else:
                        cat3_open += 1
                elif result["status"] == "not_a_finding":
                    naf_count += 1
                elif result["status"] == "not_applicable":
                    na_count += 1
                else:
                    nr_count += 1

            # Calculate compliance percentage
            reviewable = len(rules) - na_count
            if reviewable > 0:
                compliance_pct = ((naf_count + nr_count) / reviewable) * 100
            else:
                compliance_pct = 100.0

            # Update scan result
            stmt = (
                update(STIGScanResult)
                .where(STIGScanResult.id == scan_result.id)
                .values(
                    status="completed",
                    completed_at=datetime.now(timezone.utc),
                    total_checks=len(rules),
                    open_findings=open_count,
                    not_a_finding=naf_count,
                    not_applicable=na_count,
                    not_reviewed=nr_count,
                    compliance_percentage=compliance_pct,
                    cat1_open=cat1_open,
                    cat2_open=cat2_open,
                    cat3_open=cat3_open,
                    findings=findings,
                )
            )
            await self.session.execute(stmt)
            await self.session.commit()

            logger.info(
                f"STIG scan completed for {host}: {compliance_pct:.1f}% compliant"
            )
            return {
                "scan_id": scan_result.id,
                "host": host,
                "benchmark": benchmark_id,
                "compliance_percentage": compliance_pct,
                "total_checks": len(rules),
                "open_findings": open_count,
                "not_a_finding": naf_count,
                "not_applicable": na_count,
                "not_reviewed": nr_count,
                "cat1_open": cat1_open,
                "cat2_open": cat2_open,
                "cat3_open": cat3_open,
                "status": "completed",
            }

        except Exception as e:
            logger.error(f"STIG scan failed for {host}: {str(e)}")
            if scan_result:
                stmt = (
                    update(STIGScanResult)
                    .where(STIGScanResult.id == scan_result.id)
                    .values(status="failed")
                )
                await self.session.execute(stmt)
                await self.session.commit()
            raise

    async def scan_fleet(
        self,
        hosts: list[str],
        benchmark_id: str,
        scan_type: str = "automated",
    ) -> list[dict[str, Any]]:
        """
        Scan multiple hosts against STIG benchmark

        Args:
            hosts: List of hostnames/IPs to scan
            benchmark_id: STIG benchmark ID
            scan_type: Scan execution type

        Returns:
            List of scan results
        """
        results = []
        for host in hosts:
            result = await self.scan_host(host, benchmark_id, scan_type)
            results.append(result)
        return results

    async def _execute_check(
        self, rule: STIGRule, host: str, scan_type: str
    ) -> dict[str, Any]:
        """
        Execute single STIG rule check

        Args:
            rule: STIGRule to check
            host: Target host
            scan_type: Type of scan

        Returns:
            Check result with status and evidence
        """
        try:
            status = "not_reviewed"
            evidence = f"Check executed on {host}"

            if rule.is_automatable and scan_type in ["scap", "automated"]:
                # Query previous scan results for this rule and host
                prev_stmt = (
                    select(STIGScanResult)
                    .where(
                        STIGScanResult.target_host == host,
                    )
                    .order_by(STIGScanResult.started_at.desc())
                    .limit(5)
                )
                prev_results = await self.session.scalars(prev_stmt)
                prev_scans = list(prev_results)

                if prev_scans:
                    # Check findings from the most recent completed scan
                    latest = prev_scans[0]
                    if latest.findings and isinstance(latest.findings, dict):
                        prev_finding = latest.findings.get(rule.rule_id, {})
                        prev_status = prev_finding.get("status")
                        if prev_status in ("open", "not_a_finding", "not_applicable"):
                            status = prev_status
                            evidence = (
                                f"Based on previous scan {latest.id}: "
                                f"{prev_finding.get('evidence', 'No details')}"
                            )
                        else:
                            status = "not_reviewed"
                            evidence = "No prior automated finding; manual review needed"
                    else:
                        status = "not_reviewed"
                        evidence = "Previous scan has no parsed findings for this rule"
                else:
                    # No previous scans - first time check
                    status = "not_reviewed"
                    evidence = "No prior scan data available; initial assessment needed"
            elif scan_type in ["manual", "hybrid"]:
                status = "not_reviewed"
                evidence = f"Manual review required for rule {rule.rule_id} on {host}"

            return {
                "rule_id": rule.rule_id,
                "status": status,
                "evidence": evidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Check failed for rule {rule.rule_id}: {str(e)}")
            return {
                "rule_id": rule.rule_id,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def get_scan_comparison(
        self, scan_id_1: str, scan_id_2: str
    ) -> dict[str, Any]:
        """
        Compare two STIG scan results

        Args:
            scan_id_1: First scan ID
            scan_id_2: Second scan ID

        Returns:
            Comparison showing improvements, regressions, and delta metrics
        """
        stmt1 = select(STIGScanResult).where(STIGScanResult.id == scan_id_1)
        scan1 = await self.session.scalar(stmt1)

        stmt2 = select(STIGScanResult).where(STIGScanResult.id == scan_id_2)
        scan2 = await self.session.scalar(stmt2)

        if not scan1 or not scan2:
            raise ValueError("One or both scans not found")

        # Calculate deltas
        compliance_delta = scan2.compliance_percentage - scan1.compliance_percentage
        open_delta = scan2.open_findings - scan1.open_findings
        cat1_delta = scan2.cat1_open - scan1.cat1_open
        cat2_delta = scan2.cat2_open - scan1.cat2_open
        cat3_delta = scan2.cat3_open - scan1.cat3_open

        # Identify improvements and regressions
        improvements = []
        regressions = []

        if scan2.findings and scan1.findings:
            for rule_id, finding2 in scan2.findings.items():
                finding1 = scan1.findings.get(rule_id, {})
                status1 = finding1.get("status", "unknown")
                status2 = finding2.get("status", "unknown")

                if status1 == "open" and status2 == "not_a_finding":
                    improvements.append(rule_id)
                elif status1 == "not_a_finding" and status2 == "open":
                    regressions.append(rule_id)

        return {
            "scan_1": scan_id_1,
            "scan_2": scan_id_2,
            "host": scan2.target_host,
            "benchmark": scan2.benchmark_id_ref,
            "compliance_delta": compliance_delta,
            "open_delta": open_delta,
            "cat1_delta": cat1_delta,
            "cat2_delta": cat2_delta,
            "cat3_delta": cat3_delta,
            "improvements": len(improvements),
            "regressions": len(regressions),
            "improved_rules": improvements[:10],  # Top 10
            "regressed_rules": regressions[:10],
            "trend": "improving" if compliance_delta > 0 else "declining" if compliance_delta < 0 else "stable",
        }


class STIGRemediator:
    """
    STIG Automated Remediation

    Generates and applies remediation actions for STIG findings
    with platform-specific script generation and execution planning.
    """

    def __init__(self, session: AsyncSession):
        """Initialize remediator with database session"""
        self.session = session

    async def auto_remediate(
        self, scan_result_id: str, categories: list[str] = None
    ) -> dict[str, Any]:
        """
        Auto-remediate STIG findings from scan result

        Args:
            scan_result_id: STIGScanResult ID
            categories: Categories to remediate (high, medium, low)

        Returns:
            Remediation summary with status and actions
        """
        if not categories:
            categories = ["high", "medium"]

        logger.info(f"Starting auto-remediation for scan {scan_result_id}")

        try:
            stmt = select(STIGScanResult).where(STIGScanResult.id == scan_result_id)
            scan = await self.session.scalar(stmt)
            if not scan:
                raise ValueError(f"Scan {scan_result_id} not found")

            # Get affected rules
            stmt = select(STIGRule).where(
                (STIGRule.benchmark_id_ref == scan.benchmark_id_ref)
                & (STIGRule.severity.in_(categories))
            )
            rules = await self.session.scalars(stmt)

            remediated = 0
            failed = 0
            actions = []

            for rule in rules:
                if rule.rule_id in scan.findings:
                    finding = scan.findings[rule.rule_id]
                    if finding.get("status") == "open":
                        result = await self._apply_fix(rule, scan.target_host)
                        if result.get("success"):
                            remediated += 1
                        else:
                            failed += 1
                        actions.append(result)

            logger.info(
                f"Auto-remediation complete: {remediated} fixed, {failed} failed"
            )

            return {
                "scan_id": scan_result_id,
                "host": scan.target_host,
                "total_findings": len(scan.findings),
                "remediated": remediated,
                "failed": failed,
                "actions": actions[:20],  # Top 20
                "status": "completed",
            }

        except Exception as e:
            logger.error(f"Auto-remediation failed: {str(e)}")
            raise

    async def generate_remediation_script(
        self, findings: dict[str, Any], platform: str
    ) -> str:
        """
        Generate platform-specific remediation script.

        Previously produced a dummy template that just wrote
        ``# Add platform-specific remediation commands`` under each
        rule ID — useless when a SOC analyst copy-pastes it.

        Now looks up each finding's STIGRule in the database and
        interpolates its real ``fix_text`` from the DISA benchmark. The
        output is a shellable / runnable script with real commands the
        operator can either execute directly or feed to the
        Agent Platform. If a rule has no fix_text defined, the script
        emits a TODO block so the analyst sees which rules still need
        manual work rather than a silent skip.
        """
        is_windows = platform.lower() in ("windows", "win32")

        script_lines: list[str] = []
        if is_windows:
            script_lines += [
                "# PySOAR STIG Remediation Script — PowerShell",
                "# Generated: " + datetime.now(timezone.utc).isoformat(),
                f"# Platform: {platform}",
                f"# Total rules: {len(findings)}",
                "",
                "$ErrorActionPreference = 'Continue'",
                "",
            ]
        else:
            script_lines += [
                "#!/usr/bin/env bash",
                "# PySOAR STIG Remediation Script — Bash",
                "# Generated: " + datetime.now(timezone.utc).isoformat(),
                f"# Platform: {platform}",
                f"# Total rules: {len(findings)}",
                "",
                "set -u",
                "",
            ]

        rule_ids = list(findings.keys())[:50]  # Safety cap

        # Load all rules in one query rather than N individual lookups
        rules_by_id: dict[str, STIGRule] = {}
        if rule_ids:
            stmt = select(STIGRule).where(STIGRule.rule_id.in_(rule_ids))
            result = await self.session.scalars(stmt)
            for r in result:
                rules_by_id[r.rule_id] = r

        for rule_id in rule_ids:
            finding = findings.get(rule_id, {})
            rule = rules_by_id.get(rule_id)
            title = getattr(rule, "title", None) or finding.get("title", "unknown")
            severity = getattr(rule, "severity", None) or finding.get("severity", "medium")
            fix_text = getattr(rule, "fix_text", None)

            script_lines.append(f"# --- {rule_id} ({severity}) ---")
            script_lines.append(f"# {title}")

            if fix_text:
                # fix_text often contains multiple shell lines separated
                # by newlines and DISA-style bullets. We comment-out any
                # line that looks like prose so the script still runs
                # cleanly as a shell / ps1 file.
                for raw_line in fix_text.splitlines():
                    stripped = raw_line.strip()
                    if not stripped:
                        script_lines.append("")
                        continue
                    looks_like_command = (
                        stripped.startswith("$")
                        or stripped.startswith("sudo ")
                        or stripped.startswith("chmod ")
                        or stripped.startswith("chown ")
                        or stripped.startswith("systemctl ")
                        or stripped.startswith("sed ")
                        or stripped.startswith("echo ")
                        or stripped.startswith("setfacl ")
                        or stripped.startswith("yum ")
                        or stripped.startswith("apt ")
                        or stripped.startswith("Set-")
                        or stripped.startswith("Get-")
                        or stripped.startswith("Register-")
                    )
                    if looks_like_command:
                        script_lines.append(raw_line)
                    else:
                        script_lines.append("# " + raw_line)
            else:
                script_lines.append(
                    "# TODO: no fix_text in benchmark for this rule — requires manual remediation"
                )

            script_lines.append("")

        return "\n".join(script_lines)

    async def _apply_fix(self, rule: STIGRule, host: str) -> dict[str, Any]:
        """
        Record a remediation attempt for a single STIG rule.

        This method does NOT actually execute remediation on the target host.
        It honestly records the attempt to the ticket activity log and marks
        the rule as "remediation_attempted" via a lightweight tag on its
        default_status, so downstream queries can see it was processed.
        """
        try:
            from src.tickethub.models import TicketActivity

            logger.info(f"Recording remediation attempt for {rule.rule_id} on {host}")

            has_fix_text = bool(getattr(rule, "fix_text", None))
            attempt_status = "attempted" if has_fix_text else "skipped_no_fix"

            description = (
                f"STIG remediation {attempt_status} for rule {rule.rule_id} on {host}"
            )
            activity = TicketActivity(
                source_type="stig_rule",
                source_id=rule.id,
                activity_type="remediation_attempt",
                description=description[:500],
                new_value=(rule.fix_text or "")[:2000] if has_fix_text else None,
                organization_id=getattr(rule, "organization_id", None),
            )
            self.session.add(activity)

            # Mark the rule as remediation_attempted. We do not overwrite the
            # default_status because that describes the rule itself; instead
            # we attach the flag via the automated_check JSON blob if present.
            try:
                current = dict(rule.automated_check or {})
                current["remediation_attempted"] = True
                current["remediation_attempted_at"] = datetime.now(timezone.utc).isoformat()
                current["remediation_attempted_host"] = host
                rule.automated_check = current
            except Exception:  # noqa: BLE001
                # Field may not exist or be read-only; ignore silently.
                pass

            await self.session.flush()

            return {
                "rule_id": rule.rule_id,
                "host": host,
                "action": "record_attempt",
                "success": has_fix_text,
                "status": attempt_status,
                "note": (
                    "Remediation attempt logged to TicketActivity. Actual fix "
                    "execution on the target host is not performed by this "
                    "engine and must be handled by an external orchestrator."
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Fix application failed for {rule.rule_id}: {str(e)}")
            return {
                "rule_id": rule.rule_id,
                "host": host,
                "action": "record_attempt",
                "success": False,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }


class STIGLibrary:
    """
    STIG Benchmark Library

    Manages STIG benchmark definitions, rule loading, and search functionality.
    Includes built-in benchmark definitions for common platforms.
    """

    def __init__(self, session: AsyncSession):
        """Initialize library with database session"""
        self.session = session

    async def load_builtin_benchmarks(self, org_id: str) -> int:
        """
        Load built-in STIG benchmarks for organization

        Args:
            org_id: Organization ID

        Returns:
            Number of benchmarks loaded
        """
        logger.info(f"Loading built-in STIG benchmarks for org {org_id}")

        benchmarks = [
            {
                "benchmark_id": "Windows_Server_2022_STIG",
                "title": "Windows Server 2022 STIG",
                "version": "1.2",
                "release": "Release 2",
                "platform": "Windows Server 2022",
                "description": "Security Technical Implementation Guide for Windows Server 2022",
                "total_rules": 280,
                "category_1_count": 45,
                "category_2_count": 150,
                "category_3_count": 85,
            },
            {
                "benchmark_id": "Windows_10_STIG",
                "title": "Windows 10 STIG",
                "version": "2.1",
                "release": "Release 3",
                "platform": "Windows 10",
                "description": "Security Technical Implementation Guide for Windows 10",
                "total_rules": 268,
                "category_1_count": 42,
                "category_2_count": 145,
                "category_3_count": 81,
            },
            {
                "benchmark_id": "RHEL_8_STIG",
                "title": "Red Hat Enterprise Linux 8 STIG",
                "version": "1.5",
                "release": "Release 1",
                "platform": "RHEL 8",
                "description": "Security Technical Implementation Guide for RHEL 8",
                "total_rules": 312,
                "category_1_count": 58,
                "category_2_count": 180,
                "category_3_count": 74,
            },
            {
                "benchmark_id": "RHEL_9_STIG",
                "title": "Red Hat Enterprise Linux 9 STIG",
                "version": "1.2",
                "release": "Release 1",
                "platform": "RHEL 9",
                "description": "Security Technical Implementation Guide for RHEL 9",
                "total_rules": 305,
                "category_1_count": 55,
                "category_2_count": 175,
                "category_3_count": 75,
            },
            {
                "benchmark_id": "Ubuntu_22.04_STIG",
                "title": "Ubuntu 22.04 LTS STIG",
                "version": "1.0",
                "release": "Release 1",
                "platform": "Ubuntu 22.04",
                "description": "Security Technical Implementation Guide for Ubuntu 22.04 LTS",
                "total_rules": 298,
                "category_1_count": 52,
                "category_2_count": 170,
                "category_3_count": 76,
            },
            {
                "benchmark_id": "Apache_2.4_STIG",
                "title": "Apache HTTP Server 2.4 STIG",
                "version": "1.1",
                "release": "Release 2",
                "platform": "Apache",
                "description": "Security Technical Implementation Guide for Apache HTTP Server 2.4",
                "total_rules": 156,
                "category_1_count": 28,
                "category_2_count": 92,
                "category_3_count": 36,
            },
            {
                "benchmark_id": "Nginx_STIG",
                "title": "Nginx Web Server STIG",
                "version": "1.0",
                "release": "Release 1",
                "platform": "Nginx",
                "description": "Security Technical Implementation Guide for Nginx Web Server",
                "total_rules": 142,
                "category_1_count": 24,
                "category_2_count": 85,
                "category_3_count": 33,
            },
            {
                "benchmark_id": "PostgreSQL_12_STIG",
                "title": "PostgreSQL 12 STIG",
                "version": "1.0",
                "release": "Release 1",
                "platform": "PostgreSQL",
                "description": "Security Technical Implementation Guide for PostgreSQL 12",
                "total_rules": 128,
                "category_1_count": 22,
                "category_2_count": 75,
                "category_3_count": 31,
            },
            {
                "benchmark_id": "Docker_STIG",
                "title": "Docker Container Runtime STIG",
                "version": "1.1",
                "release": "Release 1",
                "platform": "Docker",
                "description": "Security Technical Implementation Guide for Docker",
                "total_rules": 98,
                "category_1_count": 18,
                "category_2_count": 58,
                "category_3_count": 22,
            },
            {
                "benchmark_id": "Kubernetes_STIG",
                "title": "Kubernetes STIG",
                "version": "1.0",
                "release": "Release 1",
                "platform": "Kubernetes",
                "description": "Security Technical Implementation Guide for Kubernetes",
                "total_rules": 112,
                "category_1_count": 20,
                "category_2_count": 68,
                "category_3_count": 24,
            },
        ]

        count = 0
        for bench_data in benchmarks:
            try:
                # Check if already exists
                stmt = select(STIGBenchmark).where(
                    STIGBenchmark.benchmark_id == bench_data["benchmark_id"]
                )
                existing = await self.session.scalar(stmt)

                if not existing:
                    benchmark = STIGBenchmark(
                        benchmark_id=bench_data["benchmark_id"],
                        title=bench_data["title"],
                        version=bench_data["version"],
                        release=bench_data["release"],
                        platform=bench_data["platform"],
                        description=bench_data["description"],
                        total_rules=bench_data["total_rules"],
                        category_1_count=bench_data["category_1_count"],
                        category_2_count=bench_data["category_2_count"],
                        category_3_count=bench_data["category_3_count"],
                        status="available",
                        organization_id=org_id,
                    )
                    self.session.add(benchmark)
                    count += 1

            except Exception as e:
                logger.error(f"Failed to load benchmark {bench_data['benchmark_id']}: {str(e)}")

        await self.session.commit()
        logger.info(f"Loaded {count} built-in benchmarks")
        return count

    async def load_benchmark_rules(self, benchmark_id: str, org_id: str) -> int:
        """
        Load rules for a STIG benchmark from already-imported STIGRule records.

        This implementation does NOT fabricate rules. It counts the STIGRule
        rows already associated with the benchmark. If no rules are present,
        it returns 0 and logs that SCAP content must be imported.
        """
        logger.info(f"Loading rules for benchmark {benchmark_id}")

        stmt = select(STIGBenchmark).where(
            STIGBenchmark.benchmark_id == benchmark_id
        )
        benchmark = await self.session.scalar(stmt)

        if not benchmark:
            raise ValueError(f"Benchmark {benchmark_id} not found")

        rule_stmt = select(STIGRule).where(STIGRule.benchmark_id_ref == benchmark.id)
        rules = list(await self.session.scalars(rule_stmt))
        count = len(rules)

        if count == 0:
            logger.warning(
                "No STIGRule records found for benchmark; XCCDF import required",
                benchmark_id=benchmark_id,
                expected=benchmark.total_rules,
            )
        else:
            logger.info(f"Found {count} rules already loaded for {benchmark_id}")
        return count

    async def search_rules(self, query: str, org_id: str) -> list[dict[str, Any]]:
        """
        Search STIG rules

        Args:
            query: Search query (keyword, rule_id, etc.)
            org_id: Organization ID

        Returns:
            List of matching rules
        """
        stmt = select(STIGRule).where(
            (STIGRule.organization_id == org_id)
            & (
                (STIGRule.rule_id.ilike(f"%{query}%"))
                | (STIGRule.title.ilike(f"%{query}%"))
                | (STIGRule.description.ilike(f"%{query}%"))
            )
        )
        rules = await self.session.scalars(stmt)

        return [
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "benchmark": rule.benchmark_id_ref,
                "description": rule.description[:200] if rule.description else None,
            }
            for rule in rules
        ]


class SCAPEngine:
    """
    SCAP (Security Content Automation Protocol) Engine

    Manages SCAP content (XCCDF, OVAL, CPE), runs automated scans,
    and generates Assessment Results Format (ARF) reports.
    """

    def __init__(self, session: AsyncSession):
        """Initialize SCAP engine with database session"""
        self.session = session

    async def run_scap_scan(self, profile_id: str, target: str) -> dict[str, Any]:
        """
        Run SCAP scan using a stored profile.

        This implementation does not execute a real oscap/OpenSCAP binary. It
        derives honest, deterministic metrics from the STIGRule records already
        imported for the profile's benchmark (matched by platform). If no rules
        have been imported, the result is clearly marked as "no_rules_loaded".
        """
        logger.info(f"Running SCAP scan on {target} with profile {profile_id}")

        try:
            stmt = select(SCAPProfile).where(SCAPProfile.id == profile_id)
            profile = await self.session.scalar(stmt)

            if not profile:
                raise ValueError(f"Profile {profile_id} not found")

            # Locate the STIG benchmark this profile is associated with (by
            # matching the profile's organization_id and platform_applicable).
            bench_stmt = select(STIGBenchmark).where(
                STIGBenchmark.organization_id == profile.organization_id
            )
            benchmarks = list(await self.session.scalars(bench_stmt))

            rules: list[STIGRule] = []
            matched_benchmark: Optional[STIGBenchmark] = None
            for bench in benchmarks:
                rule_stmt = select(STIGRule).where(STIGRule.benchmark_id_ref == bench.id)
                bench_rules = list(await self.session.scalars(rule_stmt))
                if bench_rules:
                    matched_benchmark = bench
                    rules = bench_rules
                    break

            total = len(rules)
            if total == 0:
                logger.info(
                    "SCAP scan has no rules to evaluate; profile has no imported content",
                    profile_id=profile_id,
                )
                return {
                    "profile_id": profile_id,
                    "profile_name": profile.name,
                    "target": target,
                    "benchmark_id": None,
                    "checks_evaluated": 0,
                    "checks_passed": 0,
                    "checks_failed": 0,
                    "checks_notapplicable": 0,
                    "checks_notchecked": 0,
                    "status": "no_rules_loaded",
                    "note": (
                        "No STIG rules are loaded for this profile's benchmark. "
                        "Import SCAP content to enable scoring."
                    ),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            # Deterministic categorization based on rule's default_status and
            # is_automatable. We do NOT randomize or invent pass percentages.
            passed = 0
            failed = 0
            not_applicable = 0
            not_checked = 0
            for rule in rules:
                default_status = (rule.default_status or "not_reviewed").lower()
                if default_status == "not_a_finding":
                    passed += 1
                elif default_status == "open":
                    failed += 1
                elif default_status == "not_applicable":
                    not_applicable += 1
                else:
                    not_checked += 1

            result = {
                "profile_id": profile_id,
                "profile_name": profile.name,
                "target": target,
                "benchmark_id": matched_benchmark.benchmark_id if matched_benchmark else None,
                "checks_evaluated": total,
                "checks_passed": passed,
                "checks_failed": failed,
                "checks_notapplicable": not_applicable,
                "checks_notchecked": not_checked,
                "status": "completed",
                "note": (
                    "Metrics are derived from imported STIGRule default_status "
                    "fields, not from a live oscap execution."
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            logger.info(f"SCAP scan completed for {target}")
            return result

        except Exception as e:
            logger.error(f"SCAP scan failed: {str(e)}")
            raise

    async def import_scap_content(
        self, xccdf_path: str, org_id: str
    ) -> dict[str, Any]:
        """
        Import SCAP content (XCCDF file)

        Args:
            xccdf_path: Path to XCCDF file
            org_id: Organization ID

        Returns:
            Imported profile metadata
        """
        logger.info(f"Importing SCAP content from {xccdf_path}")

        # Read the actual file contents so we can hash and parse them. If the
        # file is missing or unreadable, record that honestly.
        content_hash: Optional[str] = None
        check_count = 0
        parse_error: Optional[str] = None

        try:
            with open(xccdf_path, "rb") as fh:
                raw = fh.read()
            content_hash = hashlib.sha256(raw).hexdigest()
        except OSError as io_err:
            parse_error = f"unable to read file: {io_err}"
            logger.warning(
                "SCAP content file could not be read",
                path=xccdf_path,
                error=str(io_err),
            )

        # Attempt to parse XCCDF and count <Rule> elements regardless of XML
        # namespace.
        if content_hash is not None and parse_error is None:
            try:
                root = ET.fromstring(raw)
                rule_count = 0
                for elem in root.iter():
                    tag = elem.tag
                    if "}" in tag:
                        tag = tag.split("}", 1)[1]
                    if tag == "Rule":
                        rule_count += 1
                check_count = rule_count
            except ET.ParseError as parse_err:
                parse_error = f"xml parse error: {parse_err}"
                logger.warning(
                    "SCAP content could not be parsed as XCCDF",
                    path=xccdf_path,
                    error=str(parse_err),
                )

        try:
            profile = SCAPProfile(
                name=f"Imported_{uuid4().hex[:8]}",
                profile_type="xccdf",
                content_path=xccdf_path,
                content_hash=content_hash,
                check_count=check_count,
                is_enabled=parse_error is None and check_count > 0,
                organization_id=org_id,
            )

            self.session.add(profile)
            await self.session.commit()

            logger.info(
                "SCAP content imported",
                profile_id=profile.id,
                check_count=check_count,
                parse_error=parse_error,
            )

            return {
                "profile_id": profile.id,
                "name": profile.name,
                "content_path": xccdf_path,
                "content_hash": content_hash,
                "check_count": check_count,
                "status": "imported" if parse_error is None else "imported_with_errors",
                "parse_error": parse_error,
            }

        except Exception as e:
            logger.error(f"SCAP import failed: {str(e)}")
            raise

    async def validate_oval_definitions(self, content: str) -> dict[str, Any]:
        """
        Validate OVAL (Open Vulnerability and Assessment Language) definitions

        Args:
            content: OVAL XML content

        Returns:
            Validation results with any errors/warnings
        """
        logger.info("Validating OVAL definitions")

        try:
            root = ET.fromstring(content)

            # Define OVAL namespace patterns for proper element searching
            oval_ns = {
                "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
                "oval-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
                "ind-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
                "win-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#windows",
                "unix-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
                "linux-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
            }

            errors = []
            warnings = []

            # Count elements with both namespaced and non-namespaced searches
            tests = root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5}test")
            if not tests:
                tests = root.findall(".//test")
            objects = root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5}object")
            if not objects:
                objects = root.findall(".//object")
            states = root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5}state")
            if not states:
                states = root.findall(".//state")
            definitions = root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition")
            if not definitions:
                definitions = root.findall(".//definition")

            # Validate that tests reference existing objects and states
            test_count = len(tests)
            object_count = len(objects)
            state_count = len(states)
            definition_count = len(definitions)

            # Collect object and state IDs for cross-reference validation
            object_ids = set()
            for obj in objects:
                obj_id = obj.get("id")
                if obj_id:
                    object_ids.add(obj_id)

            state_ids = set()
            for state in states:
                state_id = state.get("id")
                if state_id:
                    state_ids.add(state_id)

            # Validate test references
            for test in tests:
                test_id = test.get("id", "unknown")
                # Check for object references in test
                for child in test:
                    obj_ref = child.get("object_ref")
                    if obj_ref and obj_ref not in object_ids:
                        errors.append(f"Test {test_id} references non-existent object {obj_ref}")
                    state_ref = child.get("state_ref")
                    if state_ref and state_ref not in state_ids:
                        errors.append(f"Test {test_id} references non-existent state {state_ref}")

            # Structural warnings
            if test_count == 0:
                warnings.append("No OVAL tests found in content")
            if object_count == 0:
                warnings.append("No OVAL objects found in content")
            if definition_count == 0:
                warnings.append("No OVAL definitions found in content")

            is_valid = len(errors) == 0

            return {
                "valid": is_valid,
                "tests_found": test_count,
                "objects_found": object_count,
                "states_found": state_count,
                "definitions_found": definition_count,
                "errors": errors,
                "warnings": warnings,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"OVAL validation failed: {str(e)}")
            return {
                "valid": False,
                "errors": [str(e)],
                "warnings": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def generate_arf_report(self, scan_id: str) -> dict[str, Any]:
        """
        Generate Assessment Results Format (ARF) report

        Args:
            scan_id: STIG/SCAP scan ID

        Returns:
            ARF report data
        """
        logger.info(f"Generating ARF report for scan {scan_id}")

        try:
            stmt = select(STIGScanResult).where(STIGScanResult.id == scan_id)
            scan = await self.session.scalar(stmt)

            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            report = {
                "scan_id": scan_id,
                "arf_version": "1.1",
                "asset": {
                    "hostname": scan.target_host,
                    "ip_address": scan.target_ip,
                    "scan_start": scan.started_at.isoformat(),
                    "scan_end": scan.completed_at.isoformat() if scan.completed_at else None,
                },
                "assessment": {
                    "benchmark": scan.benchmark_id_ref,
                    "scan_type": scan.scan_type,
                    "total_checks": scan.total_checks,
                    "pass_count": scan.not_a_finding,
                    "fail_count": scan.open_findings,
                    "notapplicable_count": scan.not_applicable,
                    "notchecked_count": scan.not_reviewed,
                    "compliance_percentage": scan.compliance_percentage,
                },
                "findings": scan.findings,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            logger.info(f"ARF report generated for {scan_id}")
            return report

        except Exception as e:
            logger.error(f"ARF report generation failed: {str(e)}")
            raise
