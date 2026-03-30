"""
Exposure Management Engine

Core logic for risk scoring, asset discovery, vulnerability management,
and compliance assessment within the CTEM module.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.logging import get_logger
from src.exposure.models import (
    AssetVulnerability,
    AttackSurface,
    ExposureAsset,
    ExposureScan,
    RemediationTicket,
    Vulnerability,
)

logger = get_logger(__name__)


class RiskScorer:
    """Calculates risk scores for assets and vulnerabilities based on multiple factors"""

    def __init__(self, db_session: Session):
        """Initialize the risk scorer with a database session"""
        self.db = db_session

    def calculate_asset_risk(self, asset_id: str) -> float:
        """
        Calculate overall risk score for an asset.

        Factors considered:
        - Asset criticality
        - Internet-facing exposure
        - Vulnerability count and severity
        - Exploit availability
        - Compensating controls

        Args:
            asset_id: UUID of the asset

        Returns:
            Risk score between 0.0 and 100.0
        """
        asset = self.db.query(ExposureAsset).filter(ExposureAsset.id == asset_id).first()
        if not asset:
            logger.warning("Asset not found", asset_id=asset_id)
            return 0.0

        # Base score from criticality
        criticality_scores = {
            "critical": 25.0,
            "high": 20.0,
            "medium": 15.0,
            "low": 5.0,
        }
        base_score = criticality_scores.get(asset.criticality, 10.0)

        # Internet-facing multiplier
        internet_factor = 1.5 if asset.is_internet_facing else 1.0

        # Vulnerability severity impact
        vuln_query = self.db.query(AssetVulnerability).filter(
            AssetVulnerability.asset_id == asset_id,
            AssetVulnerability.status.in_(["open", "in_progress"]),
        )
        vulns = vuln_query.all()

        severity_impacts = 0.0
        for av in vulns:
            vuln = self.db.query(Vulnerability).filter(
                Vulnerability.id == av.vulnerability_id
            ).first()
            if vuln:
                severity_factor = self._get_severity_factor(vuln.severity)
                exploit_factor = 1.3 if vuln.exploit_available or vuln.is_exploited_in_wild else 1.0
                compensating_factor = max(0.3, 1.0 - (len(av.compensating_controls) * 0.15))
                severity_impacts += severity_factor * exploit_factor * compensating_factor

        # Normalize vulnerability impact (max contribution ~30 points)
        vuln_score = min(30.0, severity_impacts * 3.0)

        # Calculate final score
        final_score = (base_score + vuln_score) * internet_factor
        return min(100.0, final_score)

    def calculate_vulnerability_risk(self, asset_vulnerability_id: str) -> float:
        """
        Calculate contextual risk for a vulnerability on a specific asset.

        Formula: CVSS_Score * Exploit_Maturity_Factor * Asset_Criticality_Factor *
                 Internet_Facing_Factor - Compensating_Control_Reduction

        Args:
            asset_vulnerability_id: UUID of the AssetVulnerability record

        Returns:
            Contextual risk score between 0.0 and 100.0
        """
        av = self.db.query(AssetVulnerability).filter(
            AssetVulnerability.id == asset_vulnerability_id
        ).first()
        if not av:
            logger.warning("AssetVulnerability not found", av_id=asset_vulnerability_id)
            return 0.0

        vuln = self.db.query(Vulnerability).filter(
            Vulnerability.id == av.vulnerability_id
        ).first()
        asset = self.db.query(ExposureAsset).filter(
            ExposureAsset.id == av.asset_id
        ).first()

        if not vuln or not asset:
            logger.warning("Vulnerability or asset not found")
            return 0.0

        # Base CVSS score
        base_score = vuln.cvss_v3_score or vuln.cvss_v2_score or 5.0

        # Exploit maturity factor
        exploit_factors = {
            "weaponized": 1.5,
            "functional": 1.3,
            "poc": 1.1,
            "none": 1.0,
        }
        exploit_factor = exploit_factors.get(vuln.exploit_maturity, 1.0)

        # Asset criticality factor
        criticality_factors = {
            "critical": 1.5,
            "high": 1.3,
            "medium": 1.0,
            "low": 0.7,
        }
        criticality_factor = criticality_factors.get(asset.criticality, 1.0)

        # Internet-facing factor
        internet_factor = 1.3 if asset.is_internet_facing else 1.0

        # Compensating controls reduction (each control reduces by 15%, min 30%)
        control_reduction = max(0.3, 1.0 - (len(av.compensating_controls) * 0.15))

        # Final contextual risk
        risk = base_score * exploit_factor * criticality_factor * internet_factor * control_reduction
        return min(100.0, risk)

    def calculate_exposure_score(self, organization_id: str) -> dict[str, Any]:
        """
        Calculate organization-wide exposure metrics.

        Args:
            organization_id: UUID of the organization

        Returns:
            Dictionary with exposure metrics
        """
        assets = self.db.query(ExposureAsset).filter(
            ExposureAsset.organization_id == organization_id,
            ExposureAsset.is_active == True,
        ).all()

        if not assets:
            return {
                "organization_id": organization_id,
                "total_assets": 0,
                "critical_assets": 0,
                "exposed_assets": 0,
                "average_risk_score": 0.0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "exploitable_vulns": 0,
                "assets_with_kev": 0,
            }

        # Count metrics
        critical_assets = sum(1 for a in assets if a.criticality == "critical")
        exposed_assets = sum(1 for a in assets if a.is_internet_facing)

        # Vulnerability metrics
        avulns = self.db.query(AssetVulnerability).filter(
            AssetVulnerability.organization_id == organization_id,
            AssetVulnerability.status.in_(["open", "in_progress"]),
        ).all()

        critical_vulns = 0
        high_vulns = 0
        exploitable_vulns = 0
        assets_with_kev = set()

        for av in avulns:
            vuln = self.db.query(Vulnerability).filter(
                Vulnerability.id == av.vulnerability_id
            ).first()
            if vuln:
                if vuln.severity == "critical":
                    critical_vulns += 1
                elif vuln.severity == "high":
                    high_vulns += 1
                if vuln.exploit_available or vuln.is_exploited_in_wild:
                    exploitable_vulns += 1
                if vuln.is_exploited_in_wild:
                    assets_with_kev.add(av.asset_id)

        # Calculate average risk
        avg_risk = sum(a.risk_score for a in assets) / len(assets) if assets else 0.0

        return {
            "organization_id": organization_id,
            "total_assets": len(assets),
            "critical_assets": critical_assets,
            "exposed_assets": exposed_assets,
            "average_risk_score": round(avg_risk, 2),
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "exploitable_vulns": exploitable_vulns,
            "assets_with_kev": len(assets_with_kev),
        }

    def get_risk_trend(self, entity_type: str, entity_id: str, days: int = 30) -> list[dict[str, Any]]:
        """
        Get historical risk score trend for an entity.

        Args:
            entity_type: "asset" or "vulnerability"
            entity_id: UUID of the entity
            days: Number of days of history to retrieve

        Returns:
            List of daily risk score data points
        """
        # This is a placeholder implementation
        # In production, would query audit/history tables
        logger.info("Retrieving risk trend", entity_type=entity_type, entity_id=entity_id, days=days)

        trend = []
        for i in range(days):
            date = datetime.now(timezone.utc) - timedelta(days=i)
            # Placeholder data - would come from actual history
            trend.append({
                "date": date.isoformat(),
                "risk_score": 0.0,
            })
        return list(reversed(trend))

    def _get_severity_factor(self, severity: str) -> float:
        """Convert severity level to a numeric factor"""
        factors = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
            "informational": 0.5,
        }
        return factors.get(severity, 0.0)


class AssetDiscovery:
    """Discovers and manages assets across the organization"""

    def __init__(self, db_session: Session):
        """Initialize asset discovery with a database session"""
        self.db = db_session

    def discover_from_siem_logs(self, organization_id: str, time_range_hours: int = 24) -> list[dict]:
        """
        Discover assets from SIEM log analysis.

        Extracts unique IPs and hostnames from SIEM logs to identify previously unknown assets.

        Args:
            organization_id: UUID of the organization
            time_range_hours: Hours of logs to analyze

        Returns:
            List of discovered asset dictionaries
        """
        logger.info(
            "Discovering assets from SIEM logs",
            organization_id=organization_id,
            hours=time_range_hours,
        )

        # Placeholder implementation
        # In production, would integrate with actual SIEM
        discovered = []

        logger.info("Asset discovery from SIEM complete", count=len(discovered))
        return discovered

    def discover_from_network_scan(self, organization_id: str, cidr_range: str) -> list[dict]:
        """
        Discover assets from network scanning.

        Performs network discovery on specified CIDR ranges and returns identified hosts.

        Args:
            organization_id: UUID of the organization
            cidr_range: CIDR notation range (e.g., "10.0.0.0/8")

        Returns:
            List of discovered host dictionaries with IP, hostname, open ports
        """
        logger.info(
            "Discovering assets from network scan",
            organization_id=organization_id,
            cidr=cidr_range,
        )

        # Placeholder implementation
        # In production, would use tools like nmap
        discovered = []

        return discovered

    def merge_asset_data(
        self, organization_id: str, existing_asset_id: str | None, discovered_data: dict
    ) -> ExposureAsset:
        """
        Merge newly discovered asset data with existing asset records.

        Updates existing asset or creates new one with discovered information.

        Args:
            organization_id: UUID of the organization
            existing_asset_id: UUID of existing asset if updating
            discovered_data: Dictionary with asset data

        Returns:
            Updated or created ExposureAsset
        """
        if existing_asset_id:
            asset = self.db.query(ExposureAsset).filter(
                ExposureAsset.id == existing_asset_id
            ).first()
            if asset:
                # Update existing asset
                asset.last_seen = datetime.now(timezone.utc)
                if "ip_address" in discovered_data:
                    asset.ip_address = discovered_data["ip_address"]
                if "hostname" in discovered_data:
                    asset.hostname = discovered_data["hostname"]
                if "services" in discovered_data:
                    asset.services = discovered_data["services"]
                logger.info("Merged asset data", asset_id=existing_asset_id)
                return asset
        else:
            # Create new asset
            asset = ExposureAsset(
                hostname=discovered_data.get("hostname"),
                ip_address=discovered_data.get("ip_address"),
                asset_type=discovered_data.get("asset_type", "server"),
                environment=discovered_data.get("environment", "production"),
                criticality=discovered_data.get("criticality", "medium"),
                organization_id=organization_id,
                last_seen=datetime.now(timezone.utc),
            )
            logger.info("Created new asset from discovery", asset_id=asset.id)
            return asset

    def detect_shadow_it(self, organization_id: str) -> list[dict]:
        """
        Detect shadow IT assets.

        Identifies assets seen in logs or scans but not in the official inventory.

        Args:
            organization_id: UUID of the organization

        Returns:
            List of detected shadow IT assets
        """
        logger.info("Detecting shadow IT assets", organization_id=organization_id)

        # Placeholder implementation
        # Would compare log sources against official inventory
        shadow_assets = []

        return shadow_assets


class VulnerabilityManager:
    """Manages vulnerability data and operations"""

    def __init__(self, db_session: Session):
        """Initialize vulnerability manager with a database session"""
        self.db = db_session
        self.risk_scorer = RiskScorer(db_session)

    def import_scan_results(self, organization_id: str, scan_id: str, results: list[dict]) -> dict:
        """
        Import vulnerability scan results.

        Processes and stores vulnerability findings from external scanners.

        Args:
            organization_id: UUID of the organization
            scan_id: UUID of the ExposureScan
            results: List of vulnerability findings from scanner

        Returns:
            Summary of import results
        """
        logger.info("Importing scan results", scan_id=scan_id, result_count=len(results))

        created_vulns = 0
        created_asset_vulns = 0
        errors = 0

        for result in results:
            try:
                # Find or create vulnerability
                vuln = self.db.query(Vulnerability).filter(
                    Vulnerability.cve_id == result.get("cve_id"),
                    Vulnerability.organization_id == organization_id,
                ).first()

                if not vuln:
                    vuln = Vulnerability(
                        cve_id=result.get("cve_id"),
                        title=result.get("title", ""),
                        description=result.get("description"),
                        severity=result.get("severity", "medium"),
                        cvss_v3_score=result.get("cvss_v3_score"),
                        cvss_v3_vector=result.get("cvss_v3_vector"),
                        exploit_maturity=result.get("exploit_maturity", "none"),
                        organization_id=organization_id,
                    )
                    self.db.add(vuln)
                    created_vulns += 1

                # Match to assets and create AssetVulnerability records
                affected_assets = result.get("affected_assets", [])
                for asset_id in affected_assets:
                    asset_vuln = self.db.query(AssetVulnerability).filter(
                        AssetVulnerability.asset_id == asset_id,
                        AssetVulnerability.vulnerability_id == vuln.id,
                    ).first()

                    if not asset_vuln:
                        asset_vuln = AssetVulnerability(
                            asset_id=asset_id,
                            vulnerability_id=vuln.id,
                            status="open",
                            detected_at=datetime.now(timezone.utc),
                            detected_by=result.get("scanner", "unknown"),
                            scan_reference=scan_id,
                            organization_id=organization_id,
                        )
                        self.db.add(asset_vuln)
                        created_asset_vulns += 1

                        # Calculate and set risk score
                        risk = self.risk_scorer.calculate_vulnerability_risk(asset_vuln.id)
                        asset_vuln.risk_score = risk

            except Exception as e:
                logger.error("Error importing scan result", error=str(e))
                errors += 1

        self.db.commit()

        summary = {
            "vulnerabilities_created": created_vulns,
            "asset_vulnerabilities_created": created_asset_vulns,
            "errors": errors,
        }

        logger.info("Scan import complete", **summary)
        return summary

    def match_vulnerability_to_assets(self, organization_id: str, vuln_id: str) -> list[str]:
        """
        Find assets affected by a vulnerability using CPE matching.

        Args:
            organization_id: UUID of the organization
            vuln_id: UUID of the vulnerability

        Returns:
            List of affected asset IDs
        """
        vuln = self.db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln or not vuln.affected_products:
            return []

        # Match assets by CPE strings
        matching_assets = []
        assets = self.db.query(ExposureAsset).filter(
            ExposureAsset.organization_id == organization_id
        ).all()

        for asset in assets:
            for software in asset.software_inventory:
                cpe = software.get("cpe", "")
                if cpe and any(cpe in prod for prod in vuln.affected_products):
                    matching_assets.append(asset.id)
                    break

        return matching_assets

    def check_kev_status(self, cve_id: str) -> bool:
        """
        Check if CVE is in CISA Known Exploited Vulnerabilities (KEV) catalog.

        Args:
            cve_id: CVE ID to check

        Returns:
            True if in KEV catalog, False otherwise
        """
        # Placeholder implementation
        # Would call CISA KEV API
        logger.debug("Checking KEV status", cve_id=cve_id)
        return False

    def calculate_epss(self, cve_id: str) -> float:
        """
        Calculate or retrieve EPSS score for a vulnerability.

        Args:
            cve_id: CVE ID

        Returns:
            EPSS score between 0.0 and 1.0
        """
        # Placeholder implementation
        # Would call EPSS API
        logger.debug("Calculating EPSS", cve_id=cve_id)
        return 0.0

    def get_remediation_priority(self, organization_id: str) -> list[dict]:
        """
        Get prioritized list of vulnerabilities requiring remediation.

        Prioritizes by: KEV status, EPSS, CVSS, asset criticality, exploit maturity.

        Args:
            organization_id: UUID of the organization

        Returns:
            Sorted list of vulnerability priorities
        """
        logger.info("Calculating remediation priorities", organization_id=organization_id)

        avulns = self.db.query(AssetVulnerability).filter(
            AssetVulnerability.organization_id == organization_id,
            AssetVulnerability.status.in_(["open", "in_progress"]),
        ).all()

        priorities = []
        for av in avulns:
            vuln = self.db.query(Vulnerability).filter(
                Vulnerability.id == av.vulnerability_id
            ).first()
            asset = self.db.query(ExposureAsset).filter(
                ExposureAsset.id == av.asset_id
            ).first()

            if vuln and asset:
                # Calculate priority score
                kev_bonus = 1000 if vuln.is_exploited_in_wild else 0
                epss_score = vuln.epss_score or 0.0
                cvss_score = vuln.cvss_v3_score or 0.0
                criticality_mult = {"critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.8}.get(
                    asset.criticality, 1.0
                )

                priority_score = (kev_bonus + (epss_score * 100) + cvss_score) * criticality_mult

                priorities.append({
                    "asset_vulnerability_id": av.id,
                    "asset_id": av.asset_id,
                    "vulnerability_id": av.vulnerability_id,
                    "cve_id": vuln.cve_id,
                    "priority_score": priority_score,
                    "kev_status": vuln.is_exploited_in_wild,
                    "epss_score": epss_score,
                })

        return sorted(priorities, key=lambda x: x["priority_score"], reverse=True)

    def auto_create_tickets(
        self, organization_id: str, asset_vuln_ids: list[str], priority_threshold: str = "high"
    ) -> list[str]:
        """
        Automatically create remediation tickets for vulnerabilities.

        Args:
            organization_id: UUID of the organization
            asset_vuln_ids: List of AssetVulnerability IDs
            priority_threshold: Minimum priority level ("critical", "high", "medium", "low")

        Returns:
            List of created RemediationTicket IDs
        """
        logger.info(
            "Creating remediation tickets",
            count=len(asset_vuln_ids),
            threshold=priority_threshold,
        )

        created_tickets = []
        priority_levels = ["critical", "high", "medium", "low"]
        threshold_idx = priority_levels.index(priority_threshold.lower())

        for av_id in asset_vuln_ids:
            av = self.db.query(AssetVulnerability).filter(
                AssetVulnerability.id == av_id
            ).first()
            if not av:
                continue

            vuln = self.db.query(Vulnerability).filter(
                Vulnerability.id == av.vulnerability_id
            ).first()
            if not vuln:
                continue

            # Determine ticket priority
            severity_idx = priority_levels.index(vuln.severity.lower())
            if severity_idx <= threshold_idx:
                ticket = RemediationTicket(
                    title=f"Remediate {vuln.cve_id or vuln.title}",
                    description=vuln.description,
                    status="open",
                    priority=vuln.severity,
                    remediation_type="patch",
                    asset_vulnerabilities=[av_id],
                    affected_assets=[av.asset_id],
                    organization_id=organization_id,
                    due_date=datetime.now(timezone.utc) + timedelta(days=30),
                )
                self.db.add(ticket)
                created_tickets.append(ticket.id)

        self.db.commit()
        logger.info("Created remediation tickets", count=len(created_tickets))
        return created_tickets

    def get_vulnerability_trends(self, organization_id: str, days: int = 30) -> dict[str, Any]:
        """
        Get vulnerability trend data for the organization.

        Args:
            organization_id: UUID of the organization
            days: Number of days of history

        Returns:
            Dictionary with trend metrics
        """
        logger.info("Retrieving vulnerability trends", organization_id=organization_id, days=days)

        # Placeholder implementation
        # Would query historical data
        return {
            "organization_id": organization_id,
            "period_days": days,
            "daily_trends": [],
        }


class ComplianceChecker:
    """Checks and manages compliance status of assets"""

    def __init__(self, db_session: Session):
        """Initialize compliance checker with a database session"""
        self.db = db_session

    def check_cis_benchmarks(self, asset_id: str) -> dict:
        """
        Check asset compliance against CIS Benchmarks.

        Args:
            asset_id: UUID of the asset

        Returns:
            Dictionary with CIS benchmark compliance results
        """
        logger.info("Checking CIS benchmarks", asset_id=asset_id)

        # Placeholder implementation
        return {
            "asset_id": asset_id,
            "framework": "CIS",
            "checks_passed": 0,
            "checks_failed": 0,
            "compliance_percentage": 0.0,
        }

    def check_nist_controls(self, organization_id: str) -> dict:
        """
        Check organization compliance against NIST controls.

        Args:
            organization_id: UUID of the organization

        Returns:
            Dictionary with NIST control compliance results
        """
        logger.info("Checking NIST controls", organization_id=organization_id)

        # Placeholder implementation
        return {
            "organization_id": organization_id,
            "framework": "NIST",
            "controls_satisfied": 0,
            "controls_unsatisfied": 0,
        }

    def get_compliance_summary(self, organization_id: str) -> dict:
        """
        Get overall compliance summary for the organization.

        Args:
            organization_id: UUID of the organization

        Returns:
            Compliance summary across multiple frameworks
        """
        logger.info("Getting compliance summary", organization_id=organization_id)

        return {
            "organization_id": organization_id,
            "frameworks": {
                "cis": {"status": "compliant", "percentage": 0.0},
                "nist": {"status": "partial", "percentage": 0.0},
            },
        }

    def map_vulnerabilities_to_frameworks(self, vuln_ids: list[str]) -> dict:
        """
        Map vulnerabilities to compliance frameworks.

        Shows which vulnerabilities map to specific framework controls.

        Args:
            vuln_ids: List of vulnerability IDs

        Returns:
            Dictionary mapping vulnerabilities to frameworks
        """
        logger.info("Mapping vulnerabilities to frameworks", count=len(vuln_ids))

        mapping = {}
        for vuln_id in vuln_ids:
            vuln = self.db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            if vuln:
                mapping[vuln_id] = {
                    "cve_id": vuln.cve_id,
                    "frameworks": [],
                }

        return mapping
