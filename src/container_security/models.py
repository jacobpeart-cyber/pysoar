"""
Container Security Models

SQLAlchemy models for container image scanning, Kubernetes cluster auditing,
security findings, and runtime anomaly detection.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel, utc_now

__all__ = [
    "ContainerImage",
    "ImageVulnerability",
    "KubernetesCluster",
    "K8sSecurityFinding",
    "RuntimeAlert",
]


class ContainerImage(BaseModel):
    """
    Container image metadata and vulnerability scanning results.

    Tracks image provenance, signature verification, vulnerability counts,
    compliance status, and deployment history.
    """

    __tablename__ = "container_images"

    registry: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    repository: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tag: Mapped[str] = mapped_column(String(255), nullable=False)
    digest_sha256: Mapped[str] = mapped_column(String(255), nullable=False)
    image_size_mb: Mapped[float] = mapped_column(Float, nullable=True)

    # Operating system info
    os: Mapped[str] = mapped_column(String(100), nullable=True)
    architecture: Mapped[str] = mapped_column(String(50), nullable=True)

    # Timestamps
    created_at_source: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # Vulnerability counts
    vulnerability_count_critical: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_count_high: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_count_medium: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_count_low: Mapped[int] = mapped_column(Integer, default=0)

    # Signature and provenance
    is_signed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    signature_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Base image tracking
    base_image: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sbom_generated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Compliance status: compliant, non_compliant, not_scanned, exception
    compliance_status: Mapped[str] = mapped_column(
        String(50), default="not_scanned", index=True
    )

    # Risk scoring (0-100)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)

    # Image labels/metadata
    labels: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    # Last deployment timestamp
    last_deployed: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_image_registry_repo_tag", "registry", "repository", "tag"),
        Index("ix_image_org_risk", "organization_id", "risk_score"),
    )


class ImageVulnerability(BaseModel):
    """
    Known vulnerabilities in container images.

    Tracks CVE details, severity, CVSS scores, exploit availability,
    and remediation information.
    """

    __tablename__ = "image_vulnerabilities"

    image_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("container_images.id"), nullable=False, index=True
    )

    cve_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    package_version: Mapped[str] = mapped_column(String(100), nullable=False)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Severity: critical, high, medium, low, negligible
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # CVSS v3.1 score
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Exploit availability
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)

    # CVE description
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Container layer where vulnerability was introduced
    layer_introduced: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Remediation steps
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_vuln_image_cve", "image_id", "cve_id"),
        Index("ix_vuln_org_cve", "organization_id", "cve_id"),
    )


class KubernetesCluster(BaseModel):
    """
    Kubernetes cluster configuration and compliance state.

    Tracks cluster metadata, security controls, compliance scores,
    and audit history.
    """

    __tablename__ = "kubernetes_clusters"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    version: Mapped[str] = mapped_column(String(50), nullable=False)

    # Provider: eks, aks, gke, openshift, rancher, k3s, self_managed
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)

    # Cluster metrics
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    namespace_count: Mapped[int] = mapped_column(Integer, default=0)
    pod_count: Mapped[int] = mapped_column(Integer, default=0)

    # Security features
    rbac_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    network_policy_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Pod Security Standards: privileged, baseline, restricted
    pod_security_standards: Mapped[str] = mapped_column(
        String(50), default="baseline", index=True
    )

    audit_logging_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encryption_at_rest: Mapped[bool] = mapped_column(Boolean, default=False)
    secrets_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)

    # Admission controllers
    admission_controllers: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    # Audit timestamps
    last_audit: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # Scores (0-100)
    compliance_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_cluster_org_risk", "organization_id", "risk_score"),
        Index("ix_cluster_org_provider", "organization_id", "provider"),
    )


class K8sSecurityFinding(BaseModel):
    """
    Kubernetes cluster security findings from configuration audits.

    Tracks policy violations, misconfigurations, and CIS benchmark failures.
    Supports remediation workflow and compliance tracking.
    """

    __tablename__ = "k8s_security_findings"

    cluster_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("kubernetes_clusters.id"), nullable=False, index=True
    )

    # Finding types
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # Examples: privileged_container, host_network, host_pid, writable_root_fs,
    # no_resource_limits, no_security_context, default_service_account,
    # exposed_dashboard, tiller_exposed, rbac_misconfiguration, network_policy_missing,
    # secret_in_env, image_pull_always, no_liveness_probe, no_readiness_probe,
    # host_path_mount, capability_added, run_as_root

    # Cluster-level findings (RBAC config, encryption-at-rest, etc.) are
    # not namespaced — namespace is nullable so these store honestly as
    # NULL instead of with a magic sentinel.
    namespace: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Severity levels
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # CIS Kubernetes Benchmark reference
    cis_benchmark_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Status: open, remediated, accepted, false_positive
    status: Mapped[str] = mapped_column(
        String(50), default="open", nullable=False, index=True
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_finding_cluster_status", "cluster_id", "status"),
        Index("ix_finding_org_type", "organization_id", "finding_type"),
    )


class RuntimeAlert(BaseModel):
    """
    Runtime anomaly alerts from container and pod monitoring.

    Detects suspicious behavior including privilege escalation, container escapes,
    crypto mining, lateral movement, and other runtime anomalies.
    """

    __tablename__ = "runtime_alerts"

    cluster_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("kubernetes_clusters.id"), nullable=False, index=True
    )

    # Alert type: unexpected_process, file_system_modification, network_connection_anomaly,
    # privilege_escalation, container_escape, crypto_mining, reverse_shell,
    # sensitive_file_access, namespace_breakout, syscall_anomaly, dns_exfiltration,
    # lateral_movement
    alert_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    namespace: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    pod_name: Mapped[str] = mapped_column(String(255), nullable=False)
    container_name: Mapped[str] = mapped_column(String(255), nullable=True)

    # Process info
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    process_args: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Severity
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Network info (if applicable)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # MITRE ATT&CK technique
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Status: new, investigating, confirmed, contained, resolved
    status: Mapped[str] = mapped_column(
        String(50), default="new", nullable=False, index=True
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_alert_cluster_status", "cluster_id", "status"),
        Index("ix_alert_org_type", "organization_id", "alert_type"),
        Index("ix_alert_pod", "namespace", "pod_name"),
    )
