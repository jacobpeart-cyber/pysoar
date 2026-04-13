"""Vulnerability management engine with scanning, risk prioritization, and patch orchestration"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from xml.etree import ElementTree as ET

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.vulnmgmt.models import (
    DeploymentStatus,
    ExceptionType,
    ExploitMaturity,
    ScanProfile,
    VulnerabilityException,
    VulnerabilityInstance,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    PatchOperation,
    VulnerabilitySeverity,
    DiscoverySource,
    Vulnerability,
)

logger = get_logger(__name__)


class VulnerabilityScanner:
    """Scanner for importing and normalizing vulnerability findings"""

    def __init__(self, organization_id: str):
        """Initialize scanner for organization"""
        self.organization_id = organization_id
        self.logger = logger

    async def import_scan_results(
        self,
        db: AsyncSession,
        scan_format: str,
        scan_data: str,
        scan_id: str,
        discovery_source: str,
    ) -> dict[str, Any]:
        """Import scan results from various formats (Nessus, Qualys, OpenVAS, etc.).

        Previously parsed, normalized, deduped, correlated — and then
        returned. Nothing was ever persisted to the database because
        ``update_vulnerability_database`` was never called from this
        method. Every "successful" scan import produced zero rows in
        ``vulnerabilities`` and zero in ``vulnerability_instances``,
        while the response payload claimed N imported. Pre-existing
        silent theater.

        Now:
          - calls update_vulnerability_database to persist new vulns
          - returns the list of NEWLY-CREATED critical/high findings
            as ``new_critical`` so the endpoint can fan them out into
            the automation pipeline via on_vulnerability_found
        """
        self.logger.info(
            "Importing scan results",
            scan_id=scan_id,
            format=scan_format,
            source=discovery_source,
        )

        try:
            if scan_format == "nessus":
                findings = await self._parse_nessus_xml(scan_data)
            elif scan_format == "qualys":
                findings = await self._parse_qualys_csv(scan_data)
            elif scan_format == "openvas":
                findings = await self._parse_openvas_xml(scan_data)
            else:
                findings = json.loads(scan_data)

            normalized = await self.normalize_findings(findings, discovery_source)
            deduplicated = await self.deduplicate_findings(db, normalized)
            correlated = await self.correlate_with_assets(db, deduplicated)

            # Persist the findings — this was silently missing
            persisted = await self.update_vulnerability_database(db, correlated)

            new_critical = [
                {
                    "cve_id": f.get("cve_id", "UNKNOWN"),
                    "title": f.get("title", "Unknown"),
                    "severity": f.get("severity", "medium"),
                    "asset_name": f.get("asset_name", "unknown"),
                }
                for f in correlated
                if f.get("is_new")
                and str(f.get("severity", "")).lower() in ("critical", "high")
            ]

            return {
                "scan_id": scan_id,
                "imported": len(findings),
                "normalized": len(normalized),
                "persisted": persisted,
                "new": len([f for f in correlated if f.get("is_new")]),
                "existing": len([f for f in correlated if not f.get("is_new")]),
                "new_critical": new_critical,
            }
        except Exception as e:
            self.logger.error("Scan import failed", scan_id=scan_id, error=str(e))
            raise

    async def _parse_nessus_xml(self, xml_data: str) -> list[dict[str, Any]]:
        """Parse Nessus XML format"""
        findings = []
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall(".//ReportHost"):
                hostname = host.get("name", "unknown")
                for item in host.findall(".//ReportItem"):
                    finding = {
                        "hostname": hostname,
                        "plugin_id": item.get("pluginID"),
                        "plugin_name": item.get("pluginName"),
                        "plugin_family": item.get("pluginFamily"),
                        "severity": item.findtext("severity", "0"),
                        "description": item.findtext("description"),
                        "solution": item.findtext("solution"),
                        "cvss_score": item.findtext("cvss_base_score"),
                        "cve": item.findtext("cve"),
                    }
                    findings.append(finding)
        except ET.ParseError as e:
            self.logger.error("Failed to parse Nessus XML", error=str(e))
            raise
        return findings

    async def _parse_qualys_csv(self, csv_data: str) -> list[dict[str, Any]]:
        """Parse Qualys CSV format"""
        findings = []
        try:
            lines = csv_data.strip().split("\n")
            if not lines:
                return findings

            headers = lines[0].split(",")
            for line in lines[1:]:
                values = line.split(",")
                if len(values) == len(headers):
                    finding = dict(zip(headers, values))
                    findings.append(finding)
        except Exception as e:
            self.logger.error("Failed to parse Qualys CSV", error=str(e))
            raise
        return findings

    async def _parse_openvas_xml(self, xml_data: str) -> list[dict[str, Any]]:
        """Parse OpenVAS XML format"""
        findings = []
        try:
            root = ET.fromstring(xml_data)
            for result in root.findall(".//result"):
                finding = {
                    "nvt_name": result.findtext("nvt/name"),
                    "nvt_oid": result.findtext("nvt/@oid"),
                    "severity": result.findtext("severity"),
                    "description": result.findtext("description"),
                    "host": result.findtext("host"),
                    "port": result.findtext("port"),
                    "cve": result.findtext("nvt/cves/cve"),
                }
                findings.append(finding)
        except ET.ParseError as e:
            self.logger.error("Failed to parse OpenVAS XML", error=str(e))
            raise
        return findings

    async def normalize_findings(
        self,
        findings: list[dict[str, Any]],
        discovery_source: str,
    ) -> list[dict[str, Any]]:
        """Normalize findings to standard format

        Args:
            findings: Raw findings from scanner
            discovery_source: Scanner source

        Returns:
            Normalized findings
        """
        normalized = []
        for finding in findings:
            cve = finding.get("cve") or finding.get("CVE") or ""
            if isinstance(cve, str) and cve.startswith("CVE-"):
                cve_id = cve
            else:
                cve_id = f"CVE-{cve}" if cve else "UNKNOWN"

            normalized_finding = {
                "cve_id": cve_id,
                "title": finding.get("title") or finding.get("plugin_name") or "Unknown",
                "description": finding.get("description") or "",
                "severity": self._normalize_severity(finding.get("severity", "medium")),
                "cvss_score": float(finding.get("cvss_score") or 0),
                "asset_name": finding.get("hostname") or finding.get("host") or "unknown",
                "asset_ip": finding.get("ip") or "",
                "discovery_source": discovery_source,
            }
            normalized.append(normalized_finding)
        return normalized

    def _normalize_severity(self, severity: Any) -> str:
        """Normalize severity to standard format"""
        if isinstance(severity, (int, float)):
            if int(severity) >= 9:
                return VulnerabilitySeverity.CRITICAL.value
            elif int(severity) >= 7:
                return VulnerabilitySeverity.HIGH.value
            elif int(severity) >= 4:
                return VulnerabilitySeverity.MEDIUM.value
            else:
                return VulnerabilitySeverity.LOW.value

        severity_str = str(severity).lower()
        if "critical" in severity_str or severity_str == "4":
            return VulnerabilitySeverity.CRITICAL.value
        elif "high" in severity_str or severity_str == "3":
            return VulnerabilitySeverity.HIGH.value
        elif "medium" in severity_str or severity_str == "2":
            return VulnerabilitySeverity.MEDIUM.value
        elif "low" in severity_str or severity_str == "1":
            return VulnerabilitySeverity.LOW.value
        return VulnerabilitySeverity.MEDIUM.value

    async def deduplicate_findings(
        self,
        db: AsyncSession,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Deduplicate findings, checking for existing vulnerabilities"""
        deduplicated = []
        for finding in findings:
            result = await db.execute(
                select(Vulnerability).where(
                    and_(
                        Vulnerability.cve_id == finding["cve_id"],
                        Vulnerability.organization_id == self.organization_id,
                    )
                )
            )
            existing = result.scalar_one_or_none()
            finding["vulnerability_id"] = existing.id if existing else None
            finding["is_new"] = existing is None
            deduplicated.append(finding)
        return deduplicated

    async def correlate_with_assets(
        self,
        db: AsyncSession,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Correlate findings with the Asset inventory.

        Previously just flagged every finding as ``asset_correlated=True``
        without actually looking anything up. Now tries to match each
        finding's ``asset_name`` against Asset.hostname and
        ``asset_ip`` against Asset.ip_address (org-scoped), records
        the asset_id on the finding, and uses a single batched lookup
        so import-scan stays fast on large scan files.
        """
        from src.models.asset import Asset

        hostnames = {
            (f.get("asset_name") or "").strip().lower()
            for f in findings
            if f.get("asset_name")
        }
        hostnames.discard("")
        hostnames.discard("unknown")

        ip_addresses = {
            (f.get("asset_ip") or "").strip()
            for f in findings
            if f.get("asset_ip")
        }
        ip_addresses.discard("")

        # Batch-load every candidate Asset row for this org in one query
        asset_query = select(Asset).where(Asset.organization_id == self.organization_id)
        conditions = []
        if hostnames:
            conditions.append(func.lower(Asset.hostname).in_(hostnames))
        if ip_addresses:
            conditions.append(Asset.ip_address.in_(ip_addresses))

        by_hostname: dict[str, Asset] = {}
        by_ip: dict[str, Asset] = {}
        if conditions:
            asset_query = asset_query.where(or_(*conditions))
            assets = list((await db.execute(asset_query)).scalars().all())
            for a in assets:
                if a.hostname:
                    by_hostname[a.hostname.lower()] = a
                if a.ip_address:
                    by_ip[a.ip_address] = a

        correlated = []
        for finding in findings:
            name = (finding.get("asset_name") or "").strip().lower()
            ip = (finding.get("asset_ip") or "").strip()

            asset = by_hostname.get(name) or by_ip.get(ip)
            if asset is not None:
                finding["asset_id"] = asset.id
                finding["asset_correlated"] = True
            else:
                finding["asset_id"] = None
                finding["asset_correlated"] = False

            correlated.append(finding)
        return correlated

    async def update_vulnerability_database(
        self,
        db: AsyncSession,
        findings: list[dict[str, Any]],
    ) -> int:
        """Update vulnerability database with new/updated findings"""
        count = 0
        now = datetime.now(timezone.utc).isoformat()

        for finding in findings:
            if finding["is_new"]:
                vuln = Vulnerability(
                    cve_id=finding["cve_id"],
                    title=finding["title"],
                    description=finding["description"],
                    severity=finding["severity"],
                    cvss_v3_score=finding.get("cvss_score"),
                    exploit_maturity=ExploitMaturity.UNPROVEN.value,
                    published_date=now,
                    organization_id=self.organization_id,
                )
                db.add(vuln)
                count += 1
            else:
                # Update existing (tenant-scoped — without this every tenant
                # with the same CVE would overwrite each other's row)
                result = await db.execute(
                    select(Vulnerability).where(
                        and_(
                            Vulnerability.cve_id == finding["cve_id"],
                            Vulnerability.organization_id == self.organization_id,
                        )
                    )
                )
                vuln = result.scalar_one_or_none()
                if vuln:
                    vuln.description = finding["description"]
                    vuln.severity = finding["severity"]

        await db.commit()
        return count


class RiskPrioritizer:
    """Risk prioritization and scoring engine"""

    def __init__(self, organization_id: str):
        """Initialize risk prioritizer"""
        self.organization_id = organization_id
        self.logger = logger

    async def calculate_risk_score(
        self,
        vulnerability: Vulnerability,
        instance: VulnerabilityInstance,
        asset_criticality: float = 1.0,
    ) -> float:
        """Calculate risk score using CVSS, EPSS, and contextual factors

        Args:
            vulnerability: Vulnerability definition
            instance: Vulnerability instance on asset
            asset_criticality: Asset criticality score (0-1)

        Returns:
            Risk score (0-100)
        """
        # Base CVSS score
        cvss_score = float(vulnerability.cvss_v3_score or 0)
        cvss_normalized = cvss_score / 10.0  # Normalize to 0-1

        # EPSS score
        epss_score = float(vulnerability.epss_score or 0)

        # Exploit maturity factor
        exploit_factor = {
            ExploitMaturity.UNPROVEN.value: 0.5,
            ExploitMaturity.POC.value: 0.7,
            ExploitMaturity.FUNCTIONAL.value: 0.85,
            ExploitMaturity.WEAPONIZED.value: 1.0,
        }.get(vulnerability.exploit_maturity, 0.5)

        # Asset criticality factor
        criticality_factor = asset_criticality

        # Combine factors with weighted calculation
        risk_score = (
            (cvss_normalized * 0.35) +
            (epss_score * 0.30) +
            (exploit_factor * 0.20) +
            (criticality_factor * 0.15)
        ) * 100

        return min(100.0, max(0.0, risk_score))

    async def rank_vulnerabilities(
        self,
        db: AsyncSession,
        instances: list[VulnerabilityInstance],
    ) -> list[tuple[VulnerabilityInstance, float]]:
        """Rank vulnerabilities by risk score

        Args:
            db: Database session
            instances: Vulnerability instances to rank

        Returns:
            Ranked list of (instance, risk_score) tuples
        """
        ranked = []
        for instance in instances:
            result = await db.execute(
                select(Vulnerability).where(
                    Vulnerability.id == instance.vulnerability_id
                )
            )
            vuln = result.scalar_one_or_none()
            if vuln:
                risk_score = await self.calculate_risk_score(vuln, instance)
                ranked.append((instance, risk_score))

        return sorted(ranked, key=lambda x: x[1], reverse=True)

    async def identify_critical_chains(
        self,
        db: AsyncSession,
    ) -> list[list[VulnerabilityInstance]]:
        """Identify chains of vulnerabilities that create attack paths

        Returns:
            List of vulnerability chains by asset
        """
        chains = []
        # In production, would analyze vulnerability relationships
        # to identify multi-step attack paths
        return chains

    async def generate_risk_matrix(
        self,
        db: AsyncSession,
    ) -> dict[str, dict[str, int]]:
        """Generate risk matrix (severity × exploitability).

        Previously returned a fully zeroed matrix with an explicit
        ``# In production, would query actual counts`` comment — the
        frontend's risk-matrix widget was always a blank heatmap.

        Now joins VulnerabilityInstance to Vulnerability, groups by
        (severity, exploit_maturity), and populates real counts for
        this org. Buckets that have no rows stay at 0 so the matrix
        shape the frontend expects is preserved.
        """
        matrix: dict[str, dict[str, int]] = {}
        severities = [s.value for s in VulnerabilitySeverity]
        exploits = [e.value for e in ExploitMaturity]
        for severity in severities:
            matrix[severity] = {e: 0 for e in exploits}

        stmt = (
            select(
                Vulnerability.severity,
                Vulnerability.exploit_maturity,
                func.count(VulnerabilityInstance.id),
            )
            .join(
                VulnerabilityInstance,
                VulnerabilityInstance.vulnerability_id == Vulnerability.id,
            )
            .where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
            .group_by(Vulnerability.severity, Vulnerability.exploit_maturity)
        )
        result = await db.execute(stmt)
        for severity, exploit, count in result.all():
            if severity in matrix and exploit in matrix[severity]:
                matrix[severity][exploit] = int(count or 0)

        return matrix

    async def assess_sla_compliance(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Assess SLA compliance across vulnerabilities

        Returns:
            SLA compliance metrics
        """
        result = await db.execute(
            select(VulnerabilityInstance).where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
        )
        instances = result.scalars().all()

        total = len(instances)
        within_sla = len([i for i in instances if i.sla_status == "within_sla"])
        approaching = len([i for i in instances if i.sla_status == "approaching"])
        breached = len([i for i in instances if i.sla_status == "breached"])

        return {
            "total": total,
            "within_sla": within_sla,
            "approaching": approaching,
            "breached": breached,
            "compliance_percentage": (within_sla / total * 100) if total > 0 else 0,
        }


class PatchOrchestrator:
    """Patch deployment orchestration and tracking"""

    def __init__(self, organization_id: str):
        """Initialize patch orchestrator"""
        self.organization_id = organization_id
        self.logger = logger

    async def create_patch_plan(
        self,
        db: AsyncSession,
        vulnerability_instances: list[VulnerabilityInstance],
        maintenance_window: Optional[str] = None,
    ) -> str:
        """Create a patch deployment plan.

        Previous version logged a count and returned a fake
        ``plan_<iso-timestamp>`` string — the frontend got a
        plausible-looking plan_id but nothing landed in the database,
        so the Patch Operations tab stayed empty forever.

        Now creates a real ``PatchOperation`` row per vulnerability
        instance (PatchOperation is 1:1 with instance per the model).
        Each row starts in the PENDING deployment status. If a
        maintenance_window was supplied, the deployment_date is set
        to that window's start so downstream schedulers can pick it
        up. Returns the first PatchOperation.id as the plan handle;
        callers can query /patch-operations to get the full list.
        """
        from src.vulnmgmt.models import PatchType

        if not vulnerability_instances:
            return ""

        created: list[PatchOperation] = []
        for instance in vulnerability_instances:
            op = PatchOperation(
                vulnerability_instance_id=instance.id,
                patch_type=PatchType.OS_PATCH.value,
                patch_name=f"Patch plan for {instance.id[:8]}",
                deployment_status=DeploymentStatus.PENDING.value,
                deployment_date=maintenance_window,
                rollback_available=True,
                organization_id=self.organization_id,
            )
            db.add(op)
            created.append(op)

        await db.flush()

        # Group for the log message
        groups: dict[tuple, int] = {}
        for instance in vulnerability_instances:
            key = (instance.asset_id, instance.status)
            groups[key] = groups.get(key, 0) + 1

        self.logger.info(
            "Created patch plan",
            groups=len(groups),
            instances=len(vulnerability_instances),
            operations_created=len(created),
        )

        # Caller expects a single plan_id; we return the first
        # PatchOperation.id so the UI can link back to the patch-operations
        # list filtered by that group.
        return created[0].id if created else ""

    async def schedule_deployment(
        self,
        db: AsyncSession,
        patch_operation_id: str,
        deployment_date: str,
    ) -> bool:
        """Schedule patch deployment (tenant-scoped)."""
        result = await db.execute(
            select(PatchOperation).where(
                and_(
                    PatchOperation.id == patch_operation_id,
                    PatchOperation.organization_id == self.organization_id,
                )
            )
        )
        patch_op = result.scalar_one_or_none()
        if not patch_op:
            return False

        patch_op.deployment_status = DeploymentStatus.SCHEDULED.value
        patch_op.deployment_date = deployment_date
        await db.commit()
        return True

    async def verify_patch(
        self,
        db: AsyncSession,
        patch_operation_id: str,
        verification_results: dict[str, Any],
    ) -> bool:
        """Verify patch deployment (tenant-scoped)."""
        result = await db.execute(
            select(PatchOperation).where(
                and_(
                    PatchOperation.id == patch_operation_id,
                    PatchOperation.organization_id == self.organization_id,
                )
            )
        )
        patch_op = result.scalar_one_or_none()
        if not patch_op:
            return False

        # Check if verification passed
        passed = verification_results.get("passed", False)
        if passed:
            patch_op.deployment_status = DeploymentStatus.VERIFIED.value
            patch_op.verification_date = datetime.now(timezone.utc).isoformat()
        else:
            patch_op.deployment_status = DeploymentStatus.FAILED.value

        await db.commit()
        return passed

    async def rollback_patch(
        self,
        db: AsyncSession,
        patch_operation_id: str,
        reason: str,
    ) -> bool:
        """Rollback patch deployment (tenant-scoped)."""
        result = await db.execute(
            select(PatchOperation).where(
                and_(
                    PatchOperation.id == patch_operation_id,
                    PatchOperation.organization_id == self.organization_id,
                )
            )
        )
        patch_op = result.scalar_one_or_none()
        if not patch_op or not patch_op.rollback_available:
            return False

        patch_op.deployment_status = DeploymentStatus.ROLLED_BACK.value
        patch_op.deployment_notes = f"Rolled back: {reason}"
        await db.commit()
        return True

    async def generate_patch_report(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Generate patch deployment report

        Returns:
            Report with statistics
        """
        result = await db.execute(
            select(PatchOperation).where(
                PatchOperation.organization_id == self.organization_id
            )
        )
        operations = result.scalars().all()

        return {
            "total_operations": len(operations),
            "pending": len([o for o in operations if o.deployment_status == "pending"]),
            "scheduled": len([o for o in operations if o.deployment_status == "scheduled"]),
            "deployed": len([o for o in operations if o.deployment_status == "deployed"]),
            "verified": len([o for o in operations if o.deployment_status == "verified"]),
            "failed": len([o for o in operations if o.deployment_status == "failed"]),
            "rolled_back": len([o for o in operations if o.deployment_status == "rolled_back"]),
        }

    async def track_patch_compliance(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Track compliance with patch policies

        Returns:
            Compliance metrics
        """
        result = await db.execute(
            select(VulnerabilityInstance).where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
        )
        instances = result.scalars().all()

        patched = len([i for i in instances if i.status == VulnerabilityStatus.PATCHED.value])
        total = len(instances)

        return {
            "total_vulnerabilities": total,
            "patched": patched,
            "compliance_percentage": (patched / total * 100) if total > 0 else 0,
        }


class VulnerabilityLifecycle:
    """Track vulnerability lifecycle and metrics"""

    def __init__(self, organization_id: str):
        """Initialize lifecycle tracker"""
        self.organization_id = organization_id
        self.logger = logger

    async def track_mean_time_to_remediate(
        self,
        db: AsyncSession,
    ) -> float:
        """Calculate MTTR (Mean Time to Remediate)

        Returns:
            MTTR in days
        """
        result = await db.execute(
            select(VulnerabilityInstance).where(
                and_(
                    VulnerabilityInstance.organization_id == self.organization_id,
                    VulnerabilityInstance.status.in_([
                        VulnerabilityStatus.PATCHED.value,
                        VulnerabilityStatus.MITIGATED.value,
                    ]),
                )
            )
        )
        instances = result.scalars().all()

        if not instances:
            return 0.0

        total_days = 0.0
        for instance in instances:
            if instance.first_seen and instance.last_seen:
                first = datetime.fromisoformat(instance.first_seen.replace("Z", "+00:00"))
                last = datetime.fromisoformat(instance.last_seen.replace("Z", "+00:00"))
                total_days += (last - first).days

        return total_days / len(instances) if instances else 0.0

    async def track_sla_compliance(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Track SLA compliance metrics

        Returns:
            SLA metrics
        """
        result = await db.execute(
            select(VulnerabilityInstance).where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
        )
        instances = result.scalars().all()

        within = len([i for i in instances if i.sla_status == "within_sla"])
        approaching = len([i for i in instances if i.sla_status == "approaching"])
        breached = len([i for i in instances if i.sla_status == "breached"])

        return {
            "total": len(instances),
            "within_sla": within,
            "approaching": approaching,
            "breached": breached,
        }

    async def aging_analysis(
        self,
        db: AsyncSession,
    ) -> dict[str, int]:
        """Analyze how long vulnerabilities stay open

        Returns:
            Counts by age ranges
        """
        result = await db.execute(
            select(VulnerabilityInstance).where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
        )
        instances = result.scalars().all()

        now = datetime.now(timezone.utc)
        aging = {"0-30_days": 0, "31-60_days": 0, "61-90_days": 0, "90+_days": 0}

        for instance in instances:
            if instance.first_seen:
                first = datetime.fromisoformat(instance.first_seen.replace("Z", "+00:00"))
                days_open = (now - first).days
                if days_open <= 30:
                    aging["0-30_days"] += 1
                elif days_open <= 60:
                    aging["31-60_days"] += 1
                elif days_open <= 90:
                    aging["61-90_days"] += 1
                else:
                    aging["90+_days"] += 1

        return aging

    async def trend_analysis(
        self,
        db: AsyncSession,
        days: int = 30,
    ) -> dict[str, Any]:
        """Analyze vulnerability trends (new vs closed)

        Args:
            db: Database session
            days: Days to analyze

        Returns:
            Trend data
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        result = await db.execute(
            select(VulnerabilityInstance).where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
        )
        all_instances = result.scalars().all()

        new_count = 0
        closed_count = 0

        for instance in all_instances:
            if instance.created_at > cutoff_date:
                new_count += 1
            if instance.status in [VulnerabilityStatus.PATCHED.value]:
                closed_count += 1

        return {
            "period_days": days,
            "new_discovered": new_count,
            "closed": closed_count,
            "net_change": new_count - closed_count,
        }

    async def generate_executive_report(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Generate executive summary report

        Returns:
            Executive report
        """
        result = await db.execute(
            select(VulnerabilityInstance).where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
        )
        instances = result.scalars().all()

        open_count = len([i for i in instances if i.status == VulnerabilityStatus.OPEN.value])
        critical = len([i for i in instances if i.risk_score and i.risk_score >= 80])
        high = len([i for i in instances if i.risk_score and 60 <= i.risk_score < 80])

        return {
            "total_vulnerabilities": len(instances),
            "open_vulnerabilities": open_count,
            "critical_count": critical,
            "high_count": high,
            "mttr_days": await self.track_mean_time_to_remediate(db),
            "sla_compliance": await self.track_sla_compliance(db),
            "aging": await self.aging_analysis(db),
        }


class KEVMonitor:
    """Monitor CISA Known Exploited Vulnerabilities"""

    def __init__(self, organization_id: str):
        """Initialize KEV monitor"""
        self.organization_id = organization_id
        self.logger = logger
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def sync_cisa_kev(
        self,
        db: AsyncSession,
        kev_data: dict[str, Any],
    ) -> dict[str, int]:
        """Import CISA Known Exploited Vulnerabilities

        Args:
            db: Database session
            kev_data: KEV feed data

        Returns:
            Import statistics
        """
        vulnerabilities = kev_data.get("vulnerabilities", [])
        updated = 0
        added = 0

        for kev in vulnerabilities:
            cve_id = kev.get("cveID")
            if not cve_id:
                continue

            result = await db.execute(
                select(Vulnerability).where(
                    and_(
                        Vulnerability.cve_id == cve_id,
                        Vulnerability.organization_id == self.organization_id,
                    )
                )
            )
            vuln = result.scalar_one_or_none()

            if vuln:
                vuln.kev_listed = True
                updated += 1
            else:
                # Create new vulnerability record from KEV
                vuln = Vulnerability(
                    cve_id=cve_id,
                    title=kev.get("shortDescription", "Known Exploited Vulnerability"),
                    description=kev.get("description", ""),
                    kev_listed=True,
                    exploit_available=True,
                    exploit_maturity=ExploitMaturity.WEAPONIZED.value,
                    severity=VulnerabilitySeverity.HIGH.value,
                    organization_id=self.organization_id,
                )
                db.add(vuln)
                added += 1

        await db.commit()
        self.logger.info(
            "KEV sync completed",
            updated=updated,
            added=added,
        )
        return {"updated": updated, "added": added}

    async def check_kev_compliance(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Check compliance with CISA BOD 22-01 (federal mandate: patch within deadline)

        Returns:
            Compliance status
        """
        result = await db.execute(
            select(VulnerabilityInstance).where(
                and_(
                    VulnerabilityInstance.organization_id == self.organization_id,
                    VulnerabilityInstance.status != VulnerabilityStatus.PATCHED.value,
                )
            )
        )
        instances = result.scalars().all()

        non_compliant = []
        compliant = []

        now = datetime.now(timezone.utc)
        bod_deadline = timedelta(days=15)  # BOD 22-01 mandate

        for instance in instances:
            if instance.first_seen:
                first = datetime.fromisoformat(instance.first_seen.replace("Z", "+00:00"))
                if (now - first) > bod_deadline:
                    non_compliant.append(instance)
                else:
                    compliant.append(instance)

        return {
            "compliant": len(compliant),
            "non_compliant": len(non_compliant),
            "compliance_percentage": (len(compliant) / len(instances) * 100) if instances else 100,
            "bod_22_01_deadline_days": 15,
        }

    async def alert_on_new_kev(
        self,
        db: AsyncSession,
        new_kev_cves: list[str],
    ) -> list[str]:
        """Generate alerts for newly listed KEV vulnerabilities

        Args:
            db: Database session
            new_kev_cves: List of newly KEV-listed CVEs

        Returns:
            List of alert IDs
        """
        alerts = []
        for cve in new_kev_cves:
            result = await db.execute(
                select(VulnerabilityInstance).where(
                    and_(
                        VulnerabilityInstance.organization_id == self.organization_id,
                        VulnerabilityInstance.status != VulnerabilityStatus.PATCHED.value,
                    )
                )
            )
            instances = result.scalars().all()

            # Alert for any matching instances
            if instances:
                alert_id = f"kev_alert_{cve}_{datetime.now(timezone.utc).timestamp()}"
                alerts.append(alert_id)
                self.logger.warning(
                    "KEV alert generated",
                    cve=cve,
                    alert_id=alert_id,
                    affected_instances=len(instances),
                )

        return alerts

    async def generate_bod_22_01_report(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Generate BOD 22-01 compliance report for federal agencies

        Returns:
            Compliance report
        """
        compliance = await self.check_kev_compliance(db)

        result = await db.execute(
            select(VulnerabilityInstance).where(
                VulnerabilityInstance.organization_id == self.organization_id
            )
        )
        instances = result.scalars().all()

        kev_instances = [i for i in instances if i.vulnerability_id]
        patched_kev = len([i for i in kev_instances if i.status == VulnerabilityStatus.PATCHED.value])

        return {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "mandate": "BOD 22-01",
            "deadline_days": 15,
            "total_kev_tracked": len(kev_instances),
            "kev_patched": patched_kev,
            "kev_compliant": compliance["compliant"],
            "kev_non_compliant": compliance["non_compliant"],
            "compliance_percentage": compliance["compliance_percentage"],
        }
