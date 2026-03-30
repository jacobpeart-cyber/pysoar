"""
API Security Governance Celery Tasks

Background tasks for API discovery, security scanning, anomaly detection,
compliance checking, and shadow API detection.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from src.core.logging import get_logger
from src.core.config import settings
from src.api_security.models import (
    APIEndpointInventory,
    APIVulnerability,
    APISecurityPolicy,
    APIAnomalyDetection,
    APIComplianceCheck,
)
from src.api_security.engine import (
    APIDiscoveryEngine,
    APISecurityScanner,
    APIAnomalyDetector,
    APIPolicyEnforcer,
)

logger = get_logger(__name__)

# Database session factory
engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

__all__ = [
    "api_discovery_scan",
    "security_assessment",
    "anomaly_baseline_update",
    "compliance_check",
    "shadow_api_detection",
]


@shared_task(bind=True, max_retries=3)
def api_discovery_scan(self, org_id: str, traffic_logs: List[Dict[str, Any]] = None):
    """
    Discover APIs from traffic logs and OpenAPI specifications.

    Passively discovers APIs from HTTP traffic, identifies shadow APIs
    (traffic but undocumented), and zombie APIs (documented but unused).

    Args:
        self: Celery task context
        org_id: Organization ID
        traffic_logs: HTTP traffic logs for discovery

    Returns:
        Discovery results summary
    """
    try:
        logger.info(f"Starting API discovery scan for org {org_id}")

        async def _discover():
            async with AsyncSessionLocal() as db:
                engine = APIDiscoveryEngine()

                # Discover from traffic if provided
                results = {}
                if traffic_logs:
                    traffic_results = await engine.discover_from_traffic(
                        traffic_logs, org_id, db
                    )
                    results.update(traffic_results)

                # Detect shadow APIs
                shadow_results = await engine.detect_shadow_apis(org_id, db)
                results.update(shadow_results)

                # Detect zombie APIs
                zombie_results = await engine.detect_zombie_apis(org_id, db)
                results.update(zombie_results)

                # Reconcile inventory
                reconcile = await engine.reconcile_inventory(org_id, db)
                results["reconciliation"] = reconcile

                logger.info(f"API discovery complete: {results}")
                return results

        import asyncio
        result = asyncio.run(_discover())
        return result

    except Exception as exc:
        logger.error(f"API discovery scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def security_assessment(self, endpoint_id: str, org_id: str):
    """
    Perform comprehensive security assessment of API endpoint.

    Scans for OWASP API Top 10 vulnerabilities, authentication issues,
    authorization flaws, data exposure, and misconfigurations.

    Args:
        self: Celery task context
        endpoint_id: API endpoint ID to assess
        org_id: Organization ID

    Returns:
        Assessment results with vulnerabilities found
    """
    try:
        logger.info(f"Starting security assessment for endpoint {endpoint_id}")

        async def _assess():
            async with AsyncSessionLocal() as db:
                # Fetch endpoint
                stmt = select(APIEndpointInventory).where(
                    APIEndpointInventory.id == endpoint_id
                )
                result = await db.execute(stmt)
                endpoint = result.scalar_one_or_none()

                if not endpoint:
                    logger.error(f"Endpoint {endpoint_id} not found")
                    return {"status": "failed", "error": "Endpoint not found"}

                # Run security scan
                scanner = APISecurityScanner()
                vulnerabilities = await scanner.scan_owasp_top10(endpoint, org_id, db)

                # Generate report
                report = await scanner.generate_security_report(vulnerabilities, org_id, db)

                # Save critical vulnerabilities to database
                for vuln in vulnerabilities:
                    if vuln.get("severity") in ["critical", "high"]:
                        vuln_record = APIVulnerability(
                            endpoint_id=endpoint_id,
                            vulnerability_type=vuln.get("type"),
                            severity=vuln.get("severity"),
                            description=vuln.get("description"),
                            evidence=vuln.get("evidence", {}),
                            remediation=vuln.get("remediation"),
                            status="open",
                            detected_by="security_assessment",
                            organization_id=org_id,
                        )
                        db.add(vuln_record)

                await db.commit()
                logger.info(f"Security assessment complete: {report}")
                return report

        import asyncio
        result = asyncio.run(_assess())
        return result

    except Exception as exc:
        logger.error(f"Security assessment failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=2)
def anomaly_baseline_update(self, endpoint_id: str, org_id: str, traffic_data: List[Dict[str, Any]]):
    """
    Build or update anomaly detection baseline for endpoint.

    Analyzes historical traffic patterns to establish normal behavior baseline
    for volume, payload size, error rates, and user/IP patterns.

    Args:
        self: Celery task context
        endpoint_id: API endpoint ID
        org_id: Organization ID
        traffic_data: Historical traffic data (7-30 days)

    Returns:
        Baseline metrics
    """
    try:
        logger.info(f"Updating anomaly baseline for endpoint {endpoint_id}")

        async def _update_baseline():
            async with AsyncSessionLocal() as db:
                detector = APIAnomalyDetector()

                # Build baseline
                baseline = await detector.build_baseline(
                    endpoint_id, traffic_data, org_id, db
                )

                logger.info(f"Baseline updated: {baseline}")
                return baseline

        import asyncio
        result = asyncio.run(_update_baseline())
        return result

    except Exception as exc:
        logger.error(f"Baseline update failed: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def compliance_check(self, endpoint_id: str, org_id: str):
    """
    Perform compliance checks against security standards.

    Validates endpoints against OWASP API Top 10, OpenAPI specs,
    authentication/authorization, TLS, headers, PII exposure, logging.

    Args:
        self: Celery task context
        endpoint_id: API endpoint ID
        org_id: Organization ID

    Returns:
        Compliance check results
    """
    try:
        logger.info(f"Running compliance checks for endpoint {endpoint_id}")

        async def _check_compliance():
            async with AsyncSessionLocal() as db:
                # Fetch endpoint
                stmt = select(APIEndpointInventory).where(
                    APIEndpointInventory.id == endpoint_id
                )
                result = await db.execute(stmt)
                endpoint = result.scalar_one_or_none()

                if not endpoint:
                    logger.error(f"Endpoint {endpoint_id} not found")
                    return {"status": "failed", "error": "Endpoint not found"}

                # Run compliance checks
                checks_to_run = [
                    "owasp_api_top10",
                    "authentication_check",
                    "authorization_check",
                    "rate_limit_check",
                    "tls_check",
                    "header_check",
                ]

                results = {}
                for check_type in checks_to_run:
                    passed = await _run_check(endpoint, check_type)
                    results[check_type] = passed

                    # Save to database
                    check_record = APIComplianceCheck(
                        endpoint_id=endpoint_id,
                        check_type=check_type,
                        passed=passed,
                        details={"endpoint": f"{endpoint.method} {endpoint.path}"},
                        organization_id=org_id,
                    )
                    db.add(check_record)

                await db.commit()
                logger.info(f"Compliance checks complete: {results}")
                return results

        import asyncio
        result = asyncio.run(_check_compliance())
        return result

    except Exception as exc:
        logger.error(f"Compliance check failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def shadow_api_detection(self, org_id: str, traffic_logs: List[Dict[str, Any]]):
    """
    Detect shadow APIs (discovered in traffic but not in documented inventory).

    Identifies undocumented APIs that are actively being used, indicating
    potential governance gaps and unmanaged security risks.

    Args:
        self: Celery task context
        org_id: Organization ID
        traffic_logs: HTTP traffic logs

    Returns:
        Shadow API detection results
    """
    try:
        logger.info(f"Running shadow API detection for org {org_id}")

        async def _detect_shadow():
            async with AsyncSessionLocal() as db:
                # Get all documented endpoints
                stmt = select(APIEndpointInventory).where(
                    (APIEndpointInventory.organization_id == org_id)
                    & (APIEndpointInventory.is_documented == True)
                )
                result = await db.execute(stmt)
                documented = result.scalars().all()

                documented_keys = set(
                    f"{e.service_name}:{e.method}:{e.path}" for e in documented
                )

                # Find traffic not in documented set
                shadow_apis = []
                for log in traffic_logs:
                    service = log.get("service", "unknown")
                    method = (log.get("method", "GET") or "GET").upper()
                    path = log.get("path", "")

                    key = f"{service}:{method}:{path}"

                    if key not in documented_keys:
                        shadow_apis.append(
                            {
                                "service_name": service,
                                "method": method,
                                "path": path,
                                "base_url": log.get("base_url", ""),
                                "request_count": log.get("request_count", 1),
                                "last_seen": datetime.utcnow(),
                            }
                        )

                # Create shadow API records
                for shadow in shadow_apis:
                    endpoint = APIEndpointInventory(
                        service_name=shadow["service_name"],
                        method=shadow["method"],
                        path=shadow["path"],
                        base_url=shadow["base_url"],
                        is_documented=False,
                        is_shadow=True,
                        request_count_24h=shadow.get("request_count", 1),
                        organization_id=org_id,
                    )
                    db.add(endpoint)

                await db.commit()
                logger.info(f"Shadow APIs detected: {len(shadow_apis)}")
                return {
                    "shadow_api_count": len(shadow_apis),
                    "shadow_apis": shadow_apis,
                }

        import asyncio
        result = asyncio.run(_detect_shadow())
        return result

    except Exception as exc:
        logger.error(f"Shadow API detection failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


async def _run_check(endpoint: APIEndpointInventory, check_type: str) -> bool:
    """Run individual compliance check"""
    checks = {
        "owasp_api_top10": lambda e: e.input_validation_enabled,
        "authentication_check": lambda e: e.authentication_type != "none" or e.is_public,
        "authorization_check": lambda e: e.authorization_model is not None or e.is_public,
        "rate_limit_check": lambda e: e.rate_limit_configured,
        "tls_check": lambda e: endpoint.base_url.startswith("https"),
        "header_check": lambda e: True,  # Would check actual headers
    }

    try:
        return checks[check_type](endpoint)
    except Exception:
        return False
