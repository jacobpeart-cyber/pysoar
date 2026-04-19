"""
Container Security Celery Tasks

Background tasks for image scanning, cluster auditing, runtime monitoring,
compliance checking, and vulnerability reporting.
"""

import os
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import asyncio
import httpx
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from src.core.logging import get_logger
from src.core.config import settings


def _cluster_auth(cluster) -> Optional[tuple[str, str]]:
    """Resolve (api_url, bearer_token) for a KubernetesCluster row.

    Precedence:
      1. env var ``PYSOAR_KUBE_TOKEN_{NAME}`` (name uppercased, non-alnum → _)
      2. env var ``PYSOAR_KUBE_TOKEN`` (single-cluster deployments)
      3. in-cluster service account token at /var/run/secrets/kubernetes.io/serviceaccount/token
    Returns None if no credentials found.
    """
    if not cluster or not cluster.endpoint:
        return None
    sanitized = re.sub(r"[^A-Z0-9]", "_", cluster.name.upper())
    token = (
        os.getenv(f"PYSOAR_KUBE_TOKEN_{sanitized}")
        or os.getenv("PYSOAR_KUBE_TOKEN")
    )
    if not token:
        sa_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if os.path.exists(sa_path):
            try:
                with open(sa_path) as f:
                    token = f.read().strip()
            except OSError:
                token = None
    if not token:
        return None
    return cluster.endpoint.rstrip("/"), token


async def _list_cluster_pods(cluster) -> List[tuple[str, str]]:
    """Query the cluster's Kubernetes API for running pods.

    Returns list of (namespace, pod_name). Returns [] on failure; caller
    must treat empty as 'no pods found / cluster unreachable' and not
    fabricate targets.
    """
    auth = _cluster_auth(cluster)
    if not auth:
        logger.warning(
            "KubernetesCluster %s has no bearer token configured "
            "(set PYSOAR_KUBE_TOKEN_%s or PYSOAR_KUBE_TOKEN); skipping pod list",
            cluster.name,
            re.sub(r"[^A-Z0-9]", "_", cluster.name.upper()),
        )
        return []
    api_url, token = auth
    url = f"{api_url}/api/v1/pods?limit=500"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            r = await client.get(url, headers=headers)
        if r.status_code != 200:
            logger.error(
                "K8s API %s returned HTTP %d: %s",
                cluster.name, r.status_code, r.text[:200],
            )
            return []
        data = r.json()
        pods: List[tuple[str, str]] = []
        for item in data.get("items", []):
            meta = item.get("metadata") or {}
            ns = meta.get("namespace")
            name = meta.get("name")
            if ns and name:
                pods.append((ns, name))
        logger.info("Fetched %d pods from cluster %s", len(pods), cluster.name)
        return pods
    except (httpx.HTTPError, ValueError, KeyError) as e:
        logger.error("K8s pod list failed for cluster %s: %s", cluster.name, e)
        return []
from src.container_security.models import (
    ContainerImage,
    ImageVulnerability,
    KubernetesCluster,
    K8sSecurityFinding,
    RuntimeAlert,
)
from src.container_security.engine import (
    ImageScanner,
    K8sSecurityAuditor,
    RuntimeProtector,
    K8sRemediator,
    ComplianceChecker,
)

logger = get_logger(__name__)

# Database session factory
engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

__all__ = [
    "scheduled_image_scan",
    "cluster_security_audit",
    "runtime_monitoring",
    "compliance_check",
    "stale_image_report",
]


@shared_task(bind=True, max_retries=3)
def scheduled_image_scan(self, image_id: str, org_id: str):
    """
    Scheduled container image vulnerability scan.

    Scans image registry, checks for vulnerabilities, verifies signature,
    and updates image risk score.

    Args:
        self: Celery task context
        image_id: Container image ID
        org_id: Organization ID
    """
    try:
        logger.info(f"Starting scheduled scan for image {image_id}")

        async def _scan():
            async with AsyncSessionLocal() as db:
                # Fetch image
                stmt = select(ContainerImage).where(ContainerImage.id == image_id)
                result = await db.execute(stmt)
                image = result.scalar_one_or_none()

                if not image:
                    logger.error(f"Image {image_id} not found")
                    return {"status": "failed", "error": "Image not found"}

                # Run scan
                scanner = ImageScanner()
                scan_result = await scanner.scan_image(
                    image.registry,
                    image.repository,
                    image.tag,
                    image.digest_sha256,
                )

                # Update image with scan results
                image.vulnerability_count_critical = scan_result[
                    "vulnerability_count_critical"
                ]
                image.vulnerability_count_high = scan_result["vulnerability_count_high"]
                image.vulnerability_count_medium = scan_result[
                    "vulnerability_count_medium"
                ]
                image.vulnerability_count_low = scan_result["vulnerability_count_low"]

                # Calculate risk score
                image.risk_score = scanner.calculate_image_risk_score(
                    scan_result["vulnerability_count_critical"],
                    scan_result["vulnerability_count_high"],
                    scan_result["vulnerability_count_medium"],
                    image.is_signed,
                )

                # Check compliance status
                if (
                    scan_result["vulnerability_count_critical"] > 0
                    or scan_result["vulnerability_count_high"] > 1
                ):
                    image.compliance_status = "non_compliant"
                else:
                    image.compliance_status = "compliant"

                image.scanned_at = scan_result["scanned_at"]

                # Store vulnerabilities
                for vuln in scan_result["vulnerabilities"]:
                    existing = await db.execute(
                        select(ImageVulnerability).where(
                            ImageVulnerability.image_id == image_id,
                            ImageVulnerability.cve_id == vuln["cve_id"],
                        )
                    )
                    if not existing.scalar_one_or_none():
                        db.add(
                            ImageVulnerability(
                                image_id=image_id,
                                cve_id=vuln["cve_id"],
                                package_name=vuln["package"],
                                package_version=vuln["version"],
                                fixed_version=vuln.get("fixed_version"),
                                severity=vuln["severity"],
                                cvss_score=vuln.get("cvss"),
                                exploit_available=vuln.get("exploit_available", False),
                                description=vuln["description"],
                                remediation=f"Update {vuln['package']} to {vuln.get('fixed_version')}",
                                organization_id=org_id,
                            )
                        )

                await db.commit()

                logger.info(
                    f"Image {image_id} scan complete: "
                    f"{scan_result['vulnerability_count_critical']} critical vulnerabilities"
                )

                return {
                    "status": "completed",
                    "image_id": image_id,
                    "vulnerabilities": scan_result["total_vulnerabilities"],
                    "risk_score": image.risk_score,
                }

        return asyncio.run(_scan())

    except Exception as exc:
        logger.error(f"Image scan failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def cluster_security_audit(self, cluster_id: str, org_id: str):
    """
    Scheduled Kubernetes cluster security audit.

    Audits cluster configuration, checks CIS benchmarks, RBAC, network policies,
    pod security, and secrets management.

    Args:
        self: Celery task context
        cluster_id: Kubernetes cluster ID
        org_id: Organization ID
    """
    try:
        logger.info(f"Starting security audit for cluster {cluster_id}")

        async def _audit():
            async with AsyncSessionLocal() as db:
                # Fetch cluster
                stmt = select(KubernetesCluster).where(
                    KubernetesCluster.id == cluster_id
                )
                result = await db.execute(stmt)
                cluster = result.scalar_one_or_none()

                if not cluster:
                    logger.error(f"Cluster {cluster_id} not found")
                    return {"status": "failed", "error": "Cluster not found"}

                auditor = K8sSecurityAuditor()

                # Run audits
                config_audit = await auditor.audit_cluster_config(cluster)
                rbac_audit = await auditor.audit_rbac(cluster)
                policy_audit = await auditor.audit_network_policies(cluster)
                pod_audit = await auditor.audit_pod_security(cluster)
                secrets_audit = await auditor.audit_secrets_management(cluster)
                controller_audit = await auditor.audit_admission_controllers(cluster)
                cis_audit = await auditor.check_cis_k8s_benchmark(cluster)

                # Store findings
                finding_types = []

                for finding in config_audit.get("findings", []):
                    f = K8sSecurityFinding(
                        cluster_id=cluster_id,
                        finding_type=finding["type"],
                        namespace="cluster",
                        resource_type="Cluster",
                        resource_name=cluster.name,
                        severity=finding["severity"],
                        description=finding.get("message", ""),
                        status="open",
                        organization_id=org_id,
                    )
                    db.add(f)
                    finding_types.append(finding["type"])

                for finding in rbac_audit.get("findings", []):
                    f = K8sSecurityFinding(
                        cluster_id=cluster_id,
                        finding_type=finding.get("type", "rbac_misconfiguration"),
                        namespace=finding.get("namespace", "kube-system"),
                        resource_type="Role",
                        resource_name=finding.get("role", "unknown"),
                        severity=finding.get("severity", "high"),
                        description=f"RBAC: {finding}",
                        status="open",
                        organization_id=org_id,
                    )
                    db.add(f)

                for finding in policy_audit.get("findings", []):
                    f = K8sSecurityFinding(
                        cluster_id=cluster_id,
                        finding_type=finding.get("type", "network_policy_missing"),
                        namespace=finding.get("namespace", "default"),
                        resource_type="NetworkPolicy",
                        resource_name="default",
                        severity=finding.get("severity", "high"),
                        description=f"Network Policy: {finding}",
                        status="open",
                        organization_id=org_id,
                    )
                    db.add(f)

                # Update cluster scores
                total_findings = (
                    config_audit.get("findings_count", 0)
                    + rbac_audit.get("rbac_findings", 0)
                    + policy_audit.get("policy_findings", 0)
                    + pod_audit.get("pod_security_findings", 0)
                )

                cluster.risk_score = min(100, total_findings * 5)
                cluster.compliance_score = max(
                    0, 100 - cluster.risk_score
                )
                cluster.last_audit = datetime.utcnow()

                await db.commit()

                logger.info(
                    f"Cluster {cluster_id} audit complete: "
                    f"{total_findings} findings, risk_score={cluster.risk_score}"
                )

                return {
                    "status": "completed",
                    "cluster_id": cluster_id,
                    "findings": total_findings,
                    "risk_score": cluster.risk_score,
                    "cis_compliance": cis_audit.get("compliance_percentage", 0),
                }

        return asyncio.run(_audit())

    except Exception as exc:
        logger.error(f"Cluster audit failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def runtime_monitoring(self, cluster_id: str, org_id: str):
    """
    Continuous container runtime anomaly monitoring.

    Monitors runtime behavior, detects container escapes, crypto mining,
    reverse shells, and lateral movement.

    Args:
        self: Celery task context
        cluster_id: Kubernetes cluster ID
        org_id: Organization ID
    """
    try:
        logger.info(f"Starting runtime monitoring for cluster {cluster_id}")

        async def _monitor():
            async with AsyncSessionLocal() as db:
                cluster_stmt = select(KubernetesCluster).where(
                    KubernetesCluster.id == cluster_id
                )
                result = await db.execute(cluster_stmt)
                cluster = result.scalar_one_or_none()

                if not cluster:
                    return {"status": "failed", "error": "Cluster not found"}

                protector = RuntimeProtector()
                alerts_created = 0

                # Query real RuntimeAlert rows and cluster pod information from DB
                existing_alerts_query = select(RuntimeAlert).where(
                    RuntimeAlert.cluster_id == cluster_id,
                    RuntimeAlert.status == "new",
                )
                existing_result = await db.execute(existing_alerts_query)
                existing_alerts = list(existing_result.scalars().all())

                # Derive namespaces and pods from existing alert data
                ns_pod_pairs = set()
                for existing_alert in existing_alerts:
                    ns = existing_alert.namespace or "default"
                    pod = existing_alert.pod_name or "unknown"
                    ns_pod_pairs.add((ns, pod))

                # If no prior alerts exist, pull the live pod list from the
                # cluster's Kubernetes API so we can monitor real workloads.
                if not ns_pod_pairs:
                    live = await _list_cluster_pods(cluster)
                    ns_pod_pairs = set(live)
                    if not ns_pod_pairs:
                        # Cluster unreachable or no pods running — return
                        # cleanly. We never fabricate monitoring targets.
                        logger.info(
                            "No pods retrievable from cluster %s; skipping this cycle",
                            cluster_id,
                        )
                        return {
                            "status": "skipped",
                            "cluster_id": cluster_id,
                            "reason": "no_pods_available",
                        }

                for namespace, pod in ns_pod_pairs:
                        # Check for anomalies
                        runtime_check = await protector.monitor_container_runtime(
                            cluster_id, namespace, pod
                        )

                        for alert in runtime_check.get("alerts", []):
                            runtime_alert = RuntimeAlert(
                                cluster_id=cluster_id,
                                alert_type=alert.get("type", "unexpected_process"),
                                namespace=namespace,
                                pod_name=pod,
                                container_name=None,
                                process_name=alert.get("process"),
                                severity=alert.get("severity", "medium"),
                                description=f"Runtime anomaly: {alert.get('type')}",
                                status="new",
                                organization_id=org_id,
                            )
                            db.add(runtime_alert)
                            alerts_created += 1

                        # Check for specific threats
                        escape_check = await protector.detect_container_escape(
                            namespace, pod, "container-0"
                        )
                        if escape_check.get("escape_detected"):
                            runtime_alert = RuntimeAlert(
                                cluster_id=cluster_id,
                                alert_type="container_escape",
                                namespace=namespace,
                                pod_name=pod,
                                container_name="container-0",
                                severity="critical",
                                description="Potential container escape detected",
                                status="new",
                                organization_id=org_id,
                            )
                            db.add(runtime_alert)
                            alerts_created += 1

                        # Check crypto mining
                        mining_check = await protector.detect_crypto_mining(
                            namespace, pod
                        )
                        if mining_check.get("crypto_mining_detected"):
                            runtime_alert = RuntimeAlert(
                                cluster_id=cluster_id,
                                alert_type="crypto_mining",
                                namespace=namespace,
                                pod_name=pod,
                                severity="high",
                                description="Crypto mining process detected",
                                status="new",
                                organization_id=org_id,
                            )
                            db.add(runtime_alert)
                            alerts_created += 1

                await db.commit()

                logger.info(
                    f"Runtime monitoring for {cluster_id} complete: {alerts_created} alerts"
                )

                return {
                    "status": "completed",
                    "cluster_id": cluster_id,
                    "alerts_created": alerts_created,
                }

        return asyncio.run(_monitor())

    except Exception as exc:
        logger.error(f"Runtime monitoring failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def compliance_check(self, cluster_id: str, org_id: str):
    """
    Compliance framework checking.

    Checks NSA/CISA hardening, DoD STIG, and SOC 2 compliance.

    Args:
        self: Celery task context
        cluster_id: Kubernetes cluster ID
        org_id: Organization ID
    """
    try:
        logger.info(f"Starting compliance check for cluster {cluster_id}")

        async def _check():
            async with AsyncSessionLocal() as db:
                stmt = select(KubernetesCluster).where(
                    KubernetesCluster.id == cluster_id
                )
                result = await db.execute(stmt)
                cluster = result.scalar_one_or_none()

                if not cluster:
                    return {"status": "failed", "error": "Cluster not found"}

                checker = ComplianceChecker()

                nsa_cisa = await checker.check_nsa_cisa_hardening(cluster)
                dod_stig = await checker.check_dod_stig(cluster)
                soc2 = await checker.check_soc2_controls(cluster)

                overall_compliance = int(
                    (
                        nsa_cisa["compliance_score"]
                        + dod_stig["compliance_score"]
                        + soc2["compliance_score"]
                    )
                    / 3
                )

                cluster.compliance_score = overall_compliance

                await db.commit()

                logger.info(
                    f"Compliance check for {cluster_id} complete: {overall_compliance}% compliant"
                )

                return {
                    "status": "completed",
                    "cluster_id": cluster_id,
                    "compliance_score": overall_compliance,
                    "frameworks": {
                        "nsa_cisa": nsa_cisa["compliance_score"],
                        "dod_stig": dod_stig["compliance_score"],
                        "soc2": soc2["compliance_score"],
                    },
                }

        return asyncio.run(_check())

    except Exception as exc:
        logger.error(f"Compliance check failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def stale_image_report(self, org_id: str, days_threshold: int = 90):
    """
    Generate stale image report.

    Identifies container images not deployed in specified days.

    Args:
        self: Celery task context
        org_id: Organization ID
        days_threshold: Days threshold for stale image
    """
    try:
        logger.info(f"Generating stale image report for org {org_id}")

        async def _report():
            async with AsyncSessionLocal() as db:
                # Find stale images
                cutoff_date = datetime.utcnow() - timedelta(days=days_threshold)

                stmt = select(ContainerImage).where(
                    ContainerImage.organization_id == org_id,
                    ContainerImage.last_deployed < cutoff_date,
                )

                result = await db.execute(stmt)
                stale_images = result.scalars().all()

                stale_list = [
                    {
                        "id": img.id,
                        "registry": img.registry,
                        "repository": img.repository,
                        "tag": img.tag,
                        "last_deployed": img.last_deployed,
                        "risk_score": img.risk_score,
                        "vulnerability_count": (
                            img.vulnerability_count_critical
                            + img.vulnerability_count_high
                        ),
                    }
                    for img in stale_images
                ]

                logger.info(f"Found {len(stale_list)} stale images")

                return {
                    "status": "completed",
                    "org_id": org_id,
                    "stale_image_count": len(stale_list),
                    "images": stale_list,
                    "generated_at": datetime.utcnow(),
                }

        return asyncio.run(_report())

    except Exception as exc:
        logger.error(f"Stale image report failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60)
