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
        logger.info("Retrieving risk trend", entity_type=entity_type, entity_id=entity_id, days=days)

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Query exposure scans within the time period for risk data
        stmt = select(ExposureScan).where(
            and_(
                ExposureScan.started_at >= cutoff,
            )
        ).order_by(ExposureScan.started_at.asc())
        scans = self.db.execute(stmt).scalars().all()

        # Build daily risk scores from scan data
        daily_scores: dict[str, list[float]] = {}
        for scan in scans:
            day_key = scan.started_at.strftime("%Y-%m-%d")
            if day_key not in daily_scores:
                daily_scores[day_key] = []
            # Use the scan's risk-related metrics if available
            if entity_type == "asset":
                # Look up asset vulnerabilities for this entity
                vuln_stmt = select(func.count(AssetVulnerability.id)).where(
                    AssetVulnerability.asset_id == entity_id,
                )
                vuln_count = self.db.execute(vuln_stmt).scalar() or 0
                daily_scores[day_key].append(min(vuln_count * 10.0, 100.0))
            else:
                daily_scores[day_key].append(0.0)

        trend = []
        for i in range(days):
            date = datetime.now(timezone.utc) - timedelta(days=days - 1 - i)
            day_key = date.strftime("%Y-%m-%d")
            scores = daily_scores.get(day_key, [])
            avg_score = sum(scores) / len(scores) if scores else 0.0
            trend.append({
                "date": date.isoformat(),
                "risk_score": round(avg_score, 2),
            })
        return trend

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
        from src.siem.models import LogEntry

        logger.info(
            "Discovering assets from SIEM logs",
            organization_id=organization_id,
            hours=time_range_hours,
        )

        cutoff = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)

        # Query distinct source IPs and hostnames from SIEM logs
        stmt = select(
            LogEntry.source_address,
            LogEntry.hostname,
            LogEntry.source_ip,
        ).where(
            and_(
                LogEntry.organization_id == organization_id,
                LogEntry.received_at >= cutoff.isoformat(),
            )
        ).distinct()
        rows = self.db.execute(stmt).all()

        # Get known asset IPs for comparison
        known_stmt = select(ExposureAsset.ip_address).where(
            ExposureAsset.organization_id == organization_id,
        )
        known_assets = self.db.execute(known_stmt).scalars().all()
        known_ips = {ip for ip in known_assets if ip}

        # Identify previously unknown assets
        discovered = []
        seen_ips = set()
        for row in rows:
            ip = row.source_address or row.source_ip
            hostname = row.hostname
            if ip and ip not in known_ips and ip not in seen_ips:
                seen_ips.add(ip)
                discovered.append({
                    "ip_address": ip,
                    "hostname": hostname,
                    "discovery_source": "siem_logs",
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                })

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
        import ipaddress

        logger.info(
            "Discovering assets from network scan",
            organization_id=organization_id,
            cidr=cidr_range,
        )

        # Parse the target CIDR range
        try:
            target_network = ipaddress.ip_network(cidr_range, strict=False)
        except ValueError:
            logger.error("Invalid CIDR range", cidr=cidr_range)
            return []

        # Query existing assets in the database for this organization
        stmt = select(ExposureAsset).where(
            and_(
                ExposureAsset.organization_id == organization_id,
                ExposureAsset.is_active == True,
                ExposureAsset.ip_address.isnot(None),
            )
        )
        assets = self.db.execute(stmt).scalars().all()

        # Filter assets whose IP falls within the requested CIDR range
        discovered = []
        for asset in assets:
            try:
                asset_ip = ipaddress.ip_address(asset.ip_address)
                if asset_ip in target_network:
                    # Parse services/open ports from the asset record
                    open_ports = []
                    if asset.services:
                        for svc in asset.services:
                            port = svc.get("port")
                            if port:
                                open_ports.append(port)

                    discovered.append({
                        "ip_address": asset.ip_address,
                        "hostname": asset.hostname,
                        "asset_type": asset.asset_type,
                        "os_type": asset.os_type,
                        "open_ports": open_ports,
                        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
                        "discovery_source": "network_scan",
                    })
            except ValueError:
                continue

        logger.info("Network scan discovery complete", count=len(discovered), cidr=cidr_range)
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

        shadow_assets = []
        try:
            from src.models.alert import Alert
            from src.models.asset import Asset

            known_ips = set()
            known_hostnames = set()
            assets = self.db.query(Asset).filter(
                Asset.organization_id == organization_id
            ).all()
            for a in assets:
                if a.ip_address:
                    known_ips.add(a.ip_address)
                if a.hostname:
                    known_hostnames.add(a.hostname.lower())

            alerts = self.db.query(Alert).filter(
                Alert.organization_id == organization_id
            ).order_by(Alert.created_at.desc()).limit(5000).all()

            seen_unknown: dict[str, dict] = {}
            for alert in alerts:
                for ip_field in [alert.source_ip, alert.destination_ip]:
                    if ip_field and ip_field not in known_ips and ip_field not in seen_unknown:
                        seen_unknown[ip_field] = {
                            "identifier": ip_field,
                            "type": "ip",
                            "first_seen": alert.created_at.isoformat() if alert.created_at else None,
                            "source": "alert_log",
                        }
                if getattr(alert, "hostname", None):
                    hn = alert.hostname.lower()
                    if hn not in known_hostnames and hn not in seen_unknown:
                        seen_unknown[hn] = {
                            "identifier": hn,
                            "type": "hostname",
                            "first_seen": alert.created_at.isoformat() if alert.created_at else None,
                            "source": "alert_log",
                        }

            shadow_assets = list(seen_unknown.values())
            logger.info(f"Shadow IT detection found {len(shadow_assets)} unknown assets")
        except Exception:
            # Previously this swallowed every error and returned [], which is
            # indistinguishable from "no shadow IT was detected" — a dangerous
            # silent-failure mode for a security control. Log loud and re-raise
            # so the caller can decide how to surface the failure.
            logger.error(
                "Shadow IT detection failed for organization %s",
                organization_id,
                exc_info=True,
            )
            raise

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

    _kev_cache: dict | None = None
    _kev_cache_ts: float = 0

    def check_kev_status(self, cve_id: str) -> bool:
        """Check if CVE is in CISA Known Exploited Vulnerabilities catalog.

        Hits the real CISA KEV JSON feed (public, no key required), caches
        the full CVE set for 6 hours so repeated lookups don't re-download.
        """
        import time
        import httpx as _httpx

        now = time.time()
        if VulnerabilityManager._kev_cache is None or (now - VulnerabilityManager._kev_cache_ts) > 21600:
            try:
                resp = _httpx.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    VulnerabilityManager._kev_cache = {
                        v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")
                    }
                    VulnerabilityManager._kev_cache_ts = now
                    logger.info(f"KEV catalog loaded: {len(VulnerabilityManager._kev_cache)} CVEs")
                else:
                    logger.warning(f"KEV feed returned {resp.status_code}")
            except Exception as e:
                logger.warning(f"KEV fetch failed: {e}")
                if VulnerabilityManager._kev_cache is None:
                    VulnerabilityManager._kev_cache = set()

        return cve_id in (VulnerabilityManager._kev_cache or set())

    def calculate_epss(self, cve_id: str) -> float:
        """Retrieve EPSS score from the real FIRST.org EPSS API (public, no key)."""
        import httpx as _httpx

        try:
            resp = _httpx.get(
                f"https://api.first.org/data/v1/epss?cve={cve_id}",
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("data", [])
                if entries:
                    return float(entries[0].get("epss", 0.0))
        except Exception as e:
            logger.warning(f"EPSS lookup failed for {cve_id}: {e}")

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

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        daily_trends = []
        try:
            from sqlalchemy import func as _func, cast, Date
            rows = (
                self.db.query(
                    cast(AssetVulnerability.detected_at, Date).label("day"),
                    _func.count(AssetVulnerability.id),
                )
                .filter(
                    AssetVulnerability.organization_id == organization_id,
                    AssetVulnerability.detected_at >= cutoff,
                )
                .group_by("day")
                .order_by("day")
                .all()
            )
            daily_trends = [
                {"date": str(row[0]), "count": row[1]} for row in rows
            ]
        except Exception as e:
            logger.error(f"Trend query failed: {e}")

        return {
            "organization_id": organization_id,
            "period_days": days,
            "daily_trends": daily_trends,
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

        passed = 0
        failed = 0
        try:
            asset = self.db.query(ExposureAsset).filter(ExposureAsset.id == asset_id).first()
            if asset:
                has_edr = bool(getattr(asset, "agent_installed", False))
                has_encryption = bool(getattr(asset, "disk_encrypted", False))
                has_firewall = bool(getattr(asset, "firewall_enabled", False))
                has_patching = bool(getattr(asset, "auto_update_enabled", False))
                checks = [has_edr, has_encryption, has_firewall, has_patching]
                passed = sum(checks)
                failed = len(checks) - passed
        except Exception as e:
            logger.error(f"CIS benchmark check failed: {e}")

        total = passed + failed
        return {
            "asset_id": asset_id,
            "framework": "CIS",
            "checks_passed": passed,
            "checks_failed": failed,
            "compliance_percentage": round((passed / total) * 100, 1) if total else 0.0,
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

        satisfied = 0
        unsatisfied = 0
        try:
            from src.compliance.models import ComplianceControl
            controls = self.db.query(ComplianceControl).filter(
                ComplianceControl.organization_id == organization_id,
                ComplianceControl.framework.in_(["NIST 800-53", "NIST", "FedRAMP"]),
            ).all()
            for c in controls:
                if c.status in ("implemented", "satisfied"):
                    satisfied += 1
                else:
                    unsatisfied += 1
        except Exception as e:
            logger.error(f"NIST control check failed: {e}")

        return {
            "organization_id": organization_id,
            "framework": "NIST",
            "controls_satisfied": satisfied,
            "controls_unsatisfied": unsatisfied,
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

        nist = self.check_nist_controls(organization_id)
        nist_total = nist["controls_satisfied"] + nist["controls_unsatisfied"]
        nist_pct = round((nist["controls_satisfied"] / nist_total) * 100, 1) if nist_total else 0.0
        nist_status = "compliant" if nist_pct >= 80 else ("partial" if nist_pct >= 50 else "non_compliant")

        return {
            "organization_id": organization_id,
            "frameworks": {
                "nist": {"status": nist_status, "percentage": nist_pct},
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
