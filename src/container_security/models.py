"""
Container Security Models

SQLAlchemy models for container image scanning, Kubernetes cluster auditing,
security findings, and runtime anomaly detection.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel, utc_now

__all__ = [
    "ContainerImage",
    "ContainerImageScan",
    "ImageVulnerability",
    "K8sCheckResult",
    "K8sSecurityFinding",
    "KubernetesCluster",
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
        DateTime(timezone=True), nullable=True,
    )
    # Set only when a scanner actually reported on the image (wave 4: it
    # used to default to the insert time, so a never-scanned image showed a
    # scan date).
    scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    # Scan lifecycle: not_scanned, pending, awaiting_approval,
    # awaiting_integration, completed, failed. ``scan_error`` carries the
    # reason for awaiting_integration / failed.
    scan_status: Mapped[Optional[str]] = mapped_column(
        String(50), default="not_scanned", nullable=True,
    )
    scan_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

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
        String(50), default="not_scanned", index=True,
    )

    # Risk scoring (0-100)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)

    # Image labels/metadata
    labels: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    # Last deployment timestamp
    last_deployed: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
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
        String(36), ForeignKey("container_images.id"), nullable=False, index=True,
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
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
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

    # Unique per organisation (it used to be unique across all tenants, so a
    # second tenant could not register a cluster with a name already taken).
    name: Mapped[str] = mapped_column(String(255), nullable=False)
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
        String(50), default="baseline", index=True,
    )

    audit_logging_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encryption_at_rest: Mapped[bool] = mapped_column(Boolean, default=False)
    secrets_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)

    # Admission controllers
    admission_controllers: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    # Audit timestamps
    last_audit: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True,
    )

    # Scores (0-100)
    compliance_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)

    # Kubernetes API credential (kubeconfig or bearer token), stored as an
    # ``enc:v1:`` envelope from src.core.secrets; never returned by the API.
    credential_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    credential_type: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    credential_set_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    # CIS assessment against the Kubernetes API: not_assessed (no credential
    # or never run), assessed, failed (the API could not be read).
    assessment_status: Mapped[Optional[str]] = mapped_column(
        String(30), default="not_assessed", nullable=True,
    )
    assessment_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
    )

    __table_args__ = (
        Index("ix_cluster_org_risk", "organization_id", "risk_score"),
        Index("ix_cluster_org_provider", "organization_id", "provider"),
        UniqueConstraint("organization_id", "name", name="uq_kubernetes_clusters_org_name"),
    )

    @property
    def has_credential(self) -> bool:
        return bool(self.credential_encrypted)

    @property
    def compliance_status(self) -> str:
        """compliant / partial / non_compliant from an API assessment, else not_assessed."""
        if self.assessment_status != "assessed":
            return "not_assessed"
        score = self.compliance_score or 0
        if score >= 80:
            return "compliant"
        return "non_compliant" if score < 60 else "partial"


class K8sSecurityFinding(BaseModel):
    """
    Kubernetes cluster security findings from configuration audits.

    Tracks policy violations, misconfigurations, and CIS benchmark failures.
    Supports remediation workflow and compliance tracking.
    """

    __tablename__ = "k8s_security_findings"

    cluster_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("kubernetes_clusters.id"), nullable=False, index=True,
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
        String(50), default="open", nullable=False, index=True,
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False,
    )

    # Wave 4: findings are deduplicated per (cluster, image, check).
    # ``check_id`` is the CIS check, ``image_ref`` the container image the
    # finding is about (NULL for cluster-wide checks) and ``dedupe_key`` the
    # sha256 of the three, unique per organisation.
    check_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    image_ref: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    dedupe_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
    )

    __table_args__ = (
        Index("ix_finding_cluster_status", "cluster_id", "status"),
        Index("ix_finding_org_type", "organization_id", "finding_type"),
        UniqueConstraint("organization_id", "dedupe_key", name="uq_k8s_findings_org_dedupe"),
    )


class RuntimeAlert(BaseModel):
    """
    Runtime anomaly alerts from container and pod monitoring.

    Detects suspicious behavior including privilege escalation, container escapes,
    crypto mining, lateral movement, and other runtime anomalies.
    """

    __tablename__ = "runtime_alerts"

    cluster_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("kubernetes_clusters.id"), nullable=False, index=True,
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
        String(50), default="new", nullable=False, index=True,
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
    )

    __table_args__ = (
        Index("ix_alert_cluster_status", "cluster_id", "status"),
        Index("ix_alert_org_type", "organization_id", "alert_type"),
        Index("ix_alert_pod", "namespace", "pod_name"),
    )


class ContainerImageScan(BaseModel):
    """One image scan request and its outcome (wave 4).

    ``method`` is ``integration`` (an installed Trivy / Grype / Anchore
    scanner integration answered over HTTP) or ``agent`` (an endpoint agent
    enrolled with the ``container_scan`` capability ran ``trivy`` / ``grype``
    and returned its JSON report). ``status``: pending, awaiting_approval,
    completed, failed.
    """

    __tablename__ = "container_image_scans"

    image_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("container_images.id"), nullable=False, index=True,
    )
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    scanner: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    integration_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    command_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    requested_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vulnerabilities_new: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vulnerabilities_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vulnerabilities_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
    )

    __table_args__ = (
        Index("ix_image_scan_org_status", "organization_id", "status"),
    )


class K8sCheckResult(BaseModel):
    """Latest result of one CIS Kubernetes check for one cluster (wave 4).

    ``status`` is pass, fail, not_assessed or error. A check is only ever
    ``pass`` after it was evaluated against data read from the cluster's
    Kubernetes API; without a credential every check is ``not_assessed``.
    """

    __tablename__ = "k8s_check_results"

    cluster_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("kubernetes_clusters.id"), nullable=False, index=True,
    )
    check_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    evaluated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True,
    )

    __table_args__ = (
        UniqueConstraint("cluster_id", "check_id", name="uq_k8s_check_results_cluster_check"),
    )
