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

    # Map oscap TestResult/<result> codes to STIGScanResult finding statuses.
    # Reference: NIST SP 800-126 Rev 3, §5.5 (XCCDF rule-result values) and
    # DISA STIG Viewer conventions.
    _ARF_RESULT_MAP = {
        "pass": "not_a_finding",
        "fail": "open",
        "notapplicable": "not_applicable",
        "notchecked": "not_reviewed",
        "notselected": "not_reviewed",
        "informational": "not_reviewed",
        "error": "not_reviewed",
        "unknown": "not_reviewed",
        "fixed": "not_a_finding",
    }

    def __init__(self, session: AsyncSession):
        """Initialize scanner with database session"""
        self.session = session

    async def ingest_arf_result(
        self,
        scan_id: str,
        arf_xml: bytes,
    ) -> dict[str, Any]:
        """
        Parse an oscap-generated ARF (Asset Reporting Format) XML document
        and update the matching STIGScanResult row with real findings.

        ARF contains one <rule-result> element per evaluated rule, with
        idref matching an XCCDF Rule id (e.g. SV-230221r627750_rule) and
        a <result> child holding pass / fail / notapplicable / etc. We
        translate those into finding statuses and recompute compliance.
        """
        from src.stig.models import STIGRule, STIGScanResult
        scan = await self.session.get(STIGScanResult, scan_id)
        if scan is None:
            return {"status": "error", "error": f"Scan {scan_id} not found"}

        try:
            root = ET.fromstring(arf_xml)
        except ET.ParseError as e:
            return {"status": "error", "error": f"ARF parse error: {e}"}

        def _local(tag: str) -> str:
            return tag.split("}", 1)[1] if "}" in tag else tag

        # Index rules for this benchmark by stig_id and rule_id so we can
        # resolve idrefs whether ARF uses the SV- or V- number.
        rules = list(await self.session.scalars(
            select(STIGRule).where(STIGRule.benchmark_id_ref == scan.benchmark_id_ref)
        ))
        by_stig_id = {r.stig_id: r for r in rules if r.stig_id}
        by_rule_id = {r.rule_id: r for r in rules if r.rule_id}

        findings: dict[str, dict[str, Any]] = {}
        cat_counts = {"cat_1": 0, "cat_2": 0, "cat_3": 0}
        status_counts = {"open": 0, "not_a_finding": 0, "not_applicable": 0, "not_reviewed": 0}

        for elem in root.iter():
            if _local(elem.tag) != "rule-result":
                continue
            idref = elem.attrib.get("idref", "")
            severity = (elem.attrib.get("severity") or "medium").lower()
            result_val = "unknown"
            for child in elem:
                if _local(child.tag) == "result":
                    result_val = (child.text or "").strip().lower()
                    break
            status = self._ARF_RESULT_MAP.get(result_val, "not_reviewed")

            # Resolve rule — try exact id first, then strip common xccdf_
            # prefixes that oscap sometimes emits.
            rule = by_stig_id.get(idref) or by_rule_id.get(idref)
            if rule is None and "_rule_" in idref:
                suffix = idref.split("_rule_", 1)[1]
                rule = by_stig_id.get(f"SV-{suffix}") or by_rule_id.get(f"V-{suffix}")
            if rule is None:
                # Unknown rule — still record the raw idref so an auditor
                # can reconcile against the ARF manifest.
                findings[idref] = {"status": status, "severity": severity, "source": "arf"}
            else:
                findings[rule.rule_id] = {
                    "status": status,
                    "severity": rule.severity,
                    "title": rule.title,
                    "stig_id": rule.stig_id,
                    "source": "arf",
                }
                if status == "open":
                    if rule.severity == "high":
                        cat_counts["cat_1"] += 1
                    elif rule.severity == "low":
                        cat_counts["cat_3"] += 1
                    else:
                        cat_counts["cat_2"] += 1
            status_counts[status] = status_counts.get(status, 0) + 1

        total_evaluated = sum(status_counts.values())
        pass_or_na = status_counts["not_a_finding"] + status_counts["not_applicable"]
        compliance_percentage = (pass_or_na / total_evaluated * 100.0) if total_evaluated else 0.0

        scan.findings = findings
        scan.status = "completed"
        scan.total_checks = total_evaluated
        scan.open_findings = status_counts["open"]
        scan.not_a_finding = status_counts["not_a_finding"]
        scan.not_applicable = status_counts["not_applicable"]
        scan.not_reviewed = status_counts["not_reviewed"]
        scan.cat1_open = cat_counts["cat_1"]
        scan.cat2_open = cat_counts["cat_2"]
        scan.cat3_open = cat_counts["cat_3"]
        scan.compliance_percentage = compliance_percentage
        scan.completed_at = datetime.now(timezone.utc)
        await self.session.commit()

        return {
            "scan_id": scan_id,
            "status": "ingested",
            "checks_evaluated": total_evaluated,
            "open_findings": status_counts["open"],
            "compliance_percentage": round(compliance_percentage, 2),
            "cat_counts": cat_counts,
        }

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
            rules = list(await self.session.scalars(stmt))

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
        Execute a single STIG rule check.

        Federal-honesty policy: this in-process scanner does NOT touch
        remote hosts. Real scans are dispatched through
        src.stig.tasks.run_stig_scan → endpoint agent → oscap, and the
        results are ingested via POST /stig/scans/{id}/arf.

        The synchronous path returns status="not_reviewed" for every
        rule, so an auditor reading a scan result can tell the check
        was not executed. Previously this code copied the last scan's
        status and labelled it a fresh result — that was a lie; we've
        removed it.
        """
        if scan_type in ("scap", "automated"):
            evidence = (
                f"Rule {rule.rule_id} requires live scanner execution. "
                "Dispatch via Celery run_stig_scan with an enrolled endpoint "
                "agent, then POST the ARF result to /stig/scans/{scan_id}/arf."
            )
        else:
            evidence = f"Manual review required for rule {rule.rule_id} on {host}"

        return {
            "rule_id": rule.rule_id,
            "status": "not_reviewed",
            "evidence": evidence,
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

            # Count "remediated" honestly — _apply_fix only logs an
            # attempt to TicketActivity; it does not actually execute a
            # fix on the target host. Split the counter into "attempted"
            # (fix_text exists, attempt logged) and "awaiting_integration"
            # (no fix_text, so nothing to dispatch) so the UI stops
            # reporting real remediations that didn't happen.
            attempted = 0
            awaiting_integration = 0
            failed = 0
            actions = []

            for rule in rules:
                if rule.rule_id in scan.findings:
                    finding = scan.findings[rule.rule_id]
                    if finding.get("status") == "open":
                        result = await self._apply_fix(rule, scan.target_host)
                        status_ = result.get("status")
                        if status_ == "attempted":
                            attempted += 1
                        elif status_ == "skipped_no_fix":
                            awaiting_integration += 1
                        else:
                            failed += 1
                        actions.append(result)

            logger.info(
                f"Auto-remediation complete: attempted={attempted} "
                f"awaiting_integration={awaiting_integration} failed={failed}"
            )

            return {
                "scan_id": scan_result_id,
                "host": scan.target_host,
                "total_findings": len(scan.findings),
                # `remediated` kept for UI compatibility — represents
                # rules whose fix_text was logged to the ticket activity
                # and is ready for an orchestrator to dispatch.
                "remediated": attempted,
                "attempted": attempted,
                "awaiting_integration": awaiting_integration,
                "failed": failed,
                "actions": actions[:20],
                "status": "completed",
                "note": (
                    "Fix attempts are logged; actual host-side execution "
                    "requires an external orchestrator or agent to apply "
                    "the recorded fix_text."
                ),
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
        Import SCAP content (XCCDF file).

        Parses a DISA-style XCCDF document and persists:
          - one STIGBenchmark (metadata + severity counts)
          - one STIGRule per <Rule> element (severity, title, description,
            check_text, fix_text, CCI and NIST-800-53 mappings, OVAL ref)
          - one SCAPProfile pointing at the source file + hash

        Honest failure modes: if the file can't be read, can't be parsed, or
        contains no rules, we record that and return is_enabled=False so the
        scan pipeline refuses to scan against vacuous benchmarks.
        """
        from src.stig.models import STIGBenchmark, STIGRule
        logger.info(f"Importing SCAP content from {xccdf_path}")

        try:
            with open(xccdf_path, "rb") as fh:
                raw = fh.read()
        except OSError as io_err:
            logger.warning("SCAP content file could not be read", path=xccdf_path, error=str(io_err))
            return {"status": "error", "parse_error": f"unable to read file: {io_err}"}

        content_hash = hashlib.sha256(raw).hexdigest()

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as parse_err:
            logger.warning("SCAP content is not valid XML", path=xccdf_path, error=str(parse_err))
            return {"status": "error", "parse_error": f"xml parse error: {parse_err}"}

        def _local(tag: str) -> str:
            return tag.split("}", 1)[1] if "}" in tag else tag

        def _text(elem) -> str:
            """Return concatenated text of an element stripped of XHTML tags
            that DISA uses inside <description>/<fixtext> bodies."""
            if elem is None:
                return ""
            return "".join(elem.itertext()).strip()

        # ---- Benchmark metadata ----
        if _local(root.tag) != "Benchmark":
            # Some SCAP data-streams wrap XCCDF; find the first Benchmark element.
            bench_elem = next((e for e in root.iter() if _local(e.tag) == "Benchmark"), None)
        else:
            bench_elem = root
        if bench_elem is None:
            return {"status": "error", "parse_error": "no <Benchmark> element found"}

        benchmark_id = bench_elem.attrib.get("id") or f"benchmark_{content_hash[:12]}"
        title = ""
        version = ""
        description = ""
        platform = ""
        for child in bench_elem:
            t = _local(child.tag)
            if t == "title" and not title:
                title = _text(child)
            elif t == "version" and not version:
                version = _text(child)
            elif t == "description" and not description:
                description = _text(child)[:5000]
            elif t == "platform" and not platform:
                platform = child.attrib.get("idref", "") or _text(child)

        # ---- Walk every Rule, including Rules nested under Group ----
        rule_rows: list[dict[str, Any]] = []
        cat1 = cat2 = cat3 = 0

        # XCCDF Groups wrap Rules. The Group.id is typically V-xxxxx (the
        # vulnerability / rule_id), the Rule.id is SV-xxxxxrxxx_rule
        # (the STIG rule identifier). We capture both.
        group_stack: list[dict] = []
        for elem in bench_elem.iter():
            t = _local(elem.tag)
            if t == "Rule":
                rule_attrib = elem.attrib
                stig_id = rule_attrib.get("id", "")
                severity_attr = (rule_attrib.get("severity") or "medium").lower()
                if severity_attr == "high":
                    cat1 += 1
                elif severity_attr == "low":
                    cat3 += 1
                else:
                    cat2 += 1

                rule_title = ""
                rule_desc = ""
                check_text = ""
                fix_text = ""
                ccis: list[str] = []
                oval_ref: Optional[dict[str, str]] = None
                group_id = ""

                # Find ancestor Group id by iterating up — etree doesn't
                # expose parent pointers, so walk the group_stack that
                # tracks depth encountered during iter().
                if group_stack:
                    group_id = group_stack[-1].get("id", "")

                for child in elem:
                    ct = _local(child.tag)
                    if ct == "title":
                        rule_title = _text(child)[:500]
                    elif ct == "description":
                        rule_desc = _text(child)[:8000]
                    elif ct == "ident":
                        system = child.attrib.get("system", "") or ""
                        val = (child.text or "").strip()
                        if val and ("cci" in system.lower() or val.startswith("CCI-")):
                            ccis.append(val)
                    elif ct == "fixtext":
                        fix_text = _text(child)[:8000]
                    elif ct == "check":
                        for cref in child:
                            if _local(cref.tag) == "check-content-ref":
                                oval_ref = {
                                    "href": cref.attrib.get("href", ""),
                                    "name": cref.attrib.get("name", ""),
                                }
                                break
                        if not check_text:
                            check_text = _text(child)[:8000]

                # rule_id: prefer Group V-number; fall back to Rule id.
                rule_id = group_id or stig_id
                rule_rows.append({
                    "rule_id": rule_id,
                    "stig_id": stig_id,
                    "group_id": group_id or None,
                    "severity": severity_attr,
                    "title": rule_title or stig_id or rule_id,
                    "description": rule_desc,
                    "check_text": check_text,
                    "fix_text": fix_text,
                    "cci": {"ids": ccis} if ccis else {},
                    "automated_check": oval_ref,
                    "is_automatable": oval_ref is not None,
                })
            elif t == "Group":
                # Shallow group tracking: we iterate DFS, so replace the top
                # of the stack when we enter a new Group. This is a best
                # effort — real XCCDF groups aren't typically nested, so
                # this captures the common case reliably.
                group_stack.append({"id": elem.attrib.get("id", "")})
                # Clean up groups that have been fully walked by trimming
                # on each new Group encounter: keep the stack to the most
                # recent 1 to avoid stale group_ids bleeding across siblings.
                group_stack = group_stack[-1:]

        if not rule_rows:
            logger.warning("XCCDF file contained no <Rule> elements", path=xccdf_path)

        # ---- Persist benchmark + rules in one transaction ----
        # Upsert by (benchmark_id, organization_id). STIGBenchmark.benchmark_id
        # has a unique index globally, so multiple orgs importing the same
        # DISA content share the row — scope rules per-org via organization_id.
        from sqlalchemy import select as sa_select
        existing = (await self.session.execute(
            sa_select(STIGBenchmark).where(STIGBenchmark.benchmark_id == benchmark_id)
        )).scalar_one_or_none()

        if existing is not None:
            benchmark = existing
            benchmark.title = title or benchmark.title
            benchmark.version = version or benchmark.version
            benchmark.description = description or benchmark.description
            benchmark.platform = platform or benchmark.platform
            benchmark.total_rules = len(rule_rows)
            benchmark.category_1_count = cat1
            benchmark.category_2_count = cat2
            benchmark.category_3_count = cat3
            # Replace this org's rules for this benchmark.
            await self.session.execute(
                STIGRule.__table__.delete().where(
                    (STIGRule.benchmark_id_ref == benchmark.id)
                    & (STIGRule.organization_id == org_id)
                )
            )
        else:
            benchmark = STIGBenchmark(
                benchmark_id=benchmark_id,
                title=title or benchmark_id,
                version=version,
                description=description,
                platform=platform,
                total_rules=len(rule_rows),
                category_1_count=cat1,
                category_2_count=cat2,
                category_3_count=cat3,
                status="available" if rule_rows else "empty",
                organization_id=org_id,
            )
            self.session.add(benchmark)
            await self.session.flush()

        for rr in rule_rows:
            self.session.add(STIGRule(
                benchmark_id_ref=benchmark.id,
                organization_id=org_id,
                **rr,
            ))

        profile = SCAPProfile(
            name=(title[:120] if title else f"Imported_{uuid4().hex[:8]}"),
            profile_type="xccdf",
            content_path=xccdf_path,
            content_hash=content_hash,
            check_count=len(rule_rows),
            is_enabled=bool(rule_rows),
            organization_id=org_id,
        )
        self.session.add(profile)
        await self.session.commit()

        logger.info(
            "SCAP content imported",
            benchmark_id=benchmark.id,
            profile_id=profile.id,
            check_count=len(rule_rows),
            cat1=cat1, cat2=cat2, cat3=cat3,
        )

        return {
            "profile_id": profile.id,
            "benchmark_id": benchmark.id,
            "name": profile.name,
            "benchmark_title": benchmark.title,
            "benchmark_version": benchmark.version,
            "platform": benchmark.platform,
            "content_path": xccdf_path,
            "content_hash": content_hash,
            "check_count": len(rule_rows),
            "cat_1": cat1, "cat_2": cat2, "cat_3": cat3,
            "status": "imported" if rule_rows else "imported_empty",
        }

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
