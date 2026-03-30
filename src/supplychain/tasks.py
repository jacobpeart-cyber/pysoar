"""Celery Tasks for Supply Chain Security Module

Background tasks for dependency scanning, vulnerability cross-reference,
vendor assessment, SBOM regeneration, and typosquatting detection.
"""

from datetime import datetime, timedelta

from celery import shared_task

from src.core.config import settings
from src.core.logging import get_logger
from src.supplychain.engine import (
    DependencyScanner,
    SupplyChainRiskAnalyzer,
    VendorRiskManager,
)

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
def scheduled_dependency_scan(self, organization_id: str, scan_type: str = "full"):
    """
    Scheduled task to scan dependencies across organization applications.

    Executed periodically (daily/weekly) to detect new dependencies,
    outdated packages, and known vulnerabilities.

    Args:
        organization_id: Organization to scan
        scan_type: Type of scan ('full', 'incremental', 'critical')

    Returns:
        Dictionary with scan results
    """
    try:
        logger.info(
            f"Starting dependency scan for organization {organization_id} (type={scan_type})"
        )

        scanner = DependencyScanner()

        # Simulate scanning multiple applications
        scan_results = {
            "organization_id": organization_id,
            "scan_type": scan_type,
            "scan_started": datetime.utcnow().isoformat(),
            "applications_scanned": 0,
            "total_dependencies_found": 0,
            "new_vulnerabilities": 0,
            "outdated_packages": 0,
        }

        # Mock scanning results
        if scan_type in ["full", "incremental"]:
            scan_results["applications_scanned"] = 5
            scan_results["total_dependencies_found"] = 342
            scan_results["new_vulnerabilities"] = 3
            scan_results["outdated_packages"] = 12

        logger.info(
            f"Dependency scan completed: {scan_results['total_dependencies_found']} "
            f"dependencies, {scan_results['new_vulnerabilities']} new vulnerabilities"
        )

        return scan_results

    except Exception as exc:
        logger.error(f"Dependency scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def vulnerability_cross_reference(
    self, component_id: str, component_name: str, component_version: str
):
    """
    Cross-reference component against multiple vulnerability databases.

    Checks NVD, OSV, and other sources for known vulnerabilities
    related to the component.

    Args:
        component_id: Component database ID
        component_name: Component name
        component_version: Component version

    Returns:
        Dictionary with vulnerability findings
    """
    try:
        logger.info(
            f"Cross-referencing vulnerabilities for {component_name}@{component_version}"
        )

        result = {
            "component_id": component_id,
            "component_name": component_name,
            "component_version": component_version,
            "cross_reference_date": datetime.utcnow().isoformat(),
            "databases_checked": ["NVD", "OSV", "GitHub"],
            "vulnerabilities_found": [],
            "total_cves": 0,
            "max_severity": "none",
        }

        # Mock vulnerability lookup
        # In production, would query actual vulnerability APIs
        mock_cves = [
            {
                "cve_id": "CVE-2024-1234",
                "severity": "high",
                "description": "Remote code execution vulnerability",
                "published_date": "2024-01-15",
            },
            {
                "cve_id": "CVE-2024-5678",
                "severity": "medium",
                "description": "Denial of service vulnerability",
                "published_date": "2024-02-20",
            },
        ]

        result["vulnerabilities_found"] = mock_cves
        result["total_cves"] = len(mock_cves)
        if mock_cves:
            result["max_severity"] = max(cve["severity"] for cve in mock_cves)

        logger.info(
            f"Found {result['total_cves']} CVEs for {component_name}@{component_version}"
        )

        return result

    except Exception as exc:
        logger.error(f"Vulnerability cross-reference failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=2)
def vendor_certification_expiry_check(self, organization_id: str):
    """
    Check for expiring vendor certifications and compliance deadlines.

    Runs periodically to identify vendors with certifications expiring
    within 90 days and alert for renewal.

    Args:
        organization_id: Organization to check

    Returns:
        Dictionary with expiring certification alerts
    """
    try:
        logger.info(f"Checking vendor certification expiry for {organization_id}")

        manager = VendorRiskManager()

        result = {
            "organization_id": organization_id,
            "check_date": datetime.utcnow().isoformat(),
            "expiring_soon": [],
            "expired": [],
            "vendor_count": 0,
        }

        # Mock vendor certification check
        expiring_certs = [
            {
                "vendor_name": "Third-Party Vendor A",
                "certification": "SOC2",
                "expiry_date": (datetime.utcnow() + timedelta(days=45)).isoformat(),
                "days_until_expiry": 45,
            },
            {
                "vendor_name": "Third-Party Vendor B",
                "certification": "ISO27001",
                "expiry_date": (datetime.utcnow() + timedelta(days=120)).isoformat(),
                "days_until_expiry": 120,
            },
        ]

        result["expiring_soon"] = [c for c in expiring_certs if c["days_until_expiry"] < 90]
        result["expired"] = [c for c in expiring_certs if c["days_until_expiry"] < 0]
        result["vendor_count"] = 2

        if result["expiring_soon"]:
            logger.warning(f"Found {len(result['expiring_soon'])} vendors with expiring certifications")

        return result

    except Exception as exc:
        logger.error(f"Certification expiry check failed: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def sbom_regeneration(self, sbom_id: str, regeneration_type: str = "standard"):
    """
    Regenerate SBOM for an application with latest component data.

    Updates SBOM with current dependency tree, vulnerability status,
    and compliance information.

    Args:
        sbom_id: SBOM to regenerate
        regeneration_type: Type of regeneration ('standard', 'deep_scan')

    Returns:
        Dictionary with regeneration results
    """
    try:
        logger.info(f"Regenerating SBOM {sbom_id} (type={regeneration_type})")

        result = {
            "sbom_id": sbom_id,
            "regeneration_type": regeneration_type,
            "regeneration_started": datetime.utcnow().isoformat(),
            "status": "completed",
            "components_updated": 0,
            "vulnerabilities_updated": 0,
            "compliance_status": "compliant",
        }

        # Mock SBOM regeneration
        if regeneration_type == "standard":
            result["components_updated"] = 45
            result["vulnerabilities_updated"] = 2
        elif regeneration_type == "deep_scan":
            result["components_updated"] = 128
            result["vulnerabilities_updated"] = 8

        logger.info(
            f"SBOM regeneration complete: {result['components_updated']} "
            f"components, {result['vulnerabilities_updated']} vulnerabilities updated"
        )

        return result

    except Exception as exc:
        logger.error(f"SBOM regeneration failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def typosquatting_scan(
    self,
    organization_id: str,
    package_type: str = "pypi",
    threshold: float = 0.85,
):
    """
    Scan organization dependencies for typosquatting attacks.

    Detects package names similar to popular packages using
    Levenshtein distance comparison.

    Args:
        organization_id: Organization to scan
        package_type: Package manager type
        threshold: Similarity threshold (0-1)

    Returns:
        Dictionary with suspected typosquatting packages
    """
    try:
        logger.info(
            f"Starting typosquatting scan for {organization_id} "
            f"(type={package_type}, threshold={threshold})"
        )

        analyzer = SupplyChainRiskAnalyzer()

        result = {
            "organization_id": organization_id,
            "package_type": package_type,
            "scan_date": datetime.utcnow().isoformat(),
            "suspected_typosquats": [],
            "packages_scanned": 0,
            "suspicious_count": 0,
        }

        # Mock popular packages list
        popular_packages = {
            "pypi": [
                "requests",
                "django",
                "flask",
                "numpy",
                "pandas",
                "sqlalchemy",
                "celery",
            ],
            "npm": [
                "react",
                "vue",
                "angular",
                "express",
                "lodash",
                "moment",
                "axios",
            ],
        }

        # Mock organization dependencies
        org_dependencies = ["requsts", "dajngo", "flsk", "request-lib", "django-ext"]

        # Detect typosquatting
        if package_type in popular_packages:
            suspected = analyzer.detect_typosquatting(
                org_dependencies,
                popular_packages[package_type],
                threshold,
            )
            result["suspected_typosquats"] = suspected
            result["packages_scanned"] = len(org_dependencies)
            result["suspicious_count"] = len(suspected)

            if suspected:
                logger.warning(f"Found {len(suspected)} suspected typosquatting packages")

        return result

    except Exception as exc:
        logger.error(f"Typosquatting scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60)
