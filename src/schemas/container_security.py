"""
Container Security Schemas

Pydantic models for container security API request/response validation.
"""

import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
from urllib.parse import urlsplit

from src.schemas.base import DBModel
from pydantic import BaseModel, Field, field_validator

__all__ = [
    "ContainerImageResponse",
    "ContainerImageCreateRequest",
    "ContainerImageUpdateRequest",
    "ImageVulnerabilityResponse",
    "ImageVulnerabilityCreateRequest",
    "KubernetesClusterResponse",
    "KubernetesClusterCreateRequest",
    "KubernetesClusterUpdateRequest",
    "K8sSecurityFindingResponse",
    "K8sSecurityFindingCreateRequest",
    "K8sSecurityFindingUpdateRequest",
    "RuntimeAlertResponse",
    "RuntimeAlertCreateRequest",
    "RuntimeAlertUpdateRequest",
    "ImageScanRequest",
    "ImageScanResponse",
    "ClusterAuditRequest",
    "ClusterAuditResponse",
    "SecurityFindingRemediationRequest",
    "SecurityFindingRemediationResponse",
    "RuntimeAlertInvestigationRequest",
    "PodQuarantineRequest",
    "DashboardOverviewResponse",
    "ComplianceMatrixResponse",
    "ClusterComplianceResponse",
    "PaginationParams",
    "ClusterCredentialRequest",
    "ImageScanRecordResponse",
    "K8sCheckResultResponse",
    "ScannerAvailabilityResponse",
]


# Enums
class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_SCANNED = "not_scanned"
    EXCEPTION = "exception"


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class FindingStatus(str, Enum):
    OPEN = "open"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class RuntimeAlertStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class PodSecurityStandards(str, Enum):
    PRIVILEGED = "privileged"
    BASELINE = "baseline"
    RESTRICTED = "restricted"


class FindingType(str, Enum):
    PRIVILEGED_CONTAINER = "privileged_container"
    HOST_NETWORK = "host_network"
    HOST_PID = "host_pid"
    WRITABLE_ROOT_FS = "writable_root_fs"
    NO_RESOURCE_LIMITS = "no_resource_limits"
    NO_SECURITY_CONTEXT = "no_security_context"
    DEFAULT_SERVICE_ACCOUNT = "default_service_account"
    EXPOSED_DASHBOARD = "exposed_dashboard"
    TILLER_EXPOSED = "tiller_exposed"
    RBAC_MISCONFIGURATION = "rbac_misconfiguration"
    NETWORK_POLICY_MISSING = "network_policy_missing"
    SECRET_IN_ENV = "secret_in_env"
    IMAGE_PULL_ALWAYS = "image_pull_always"
    NO_LIVENESS_PROBE = "no_liveness_probe"
    NO_READINESS_PROBE = "no_readiness_probe"
    HOST_PATH_MOUNT = "host_path_mount"
    CAPABILITY_ADDED = "capability_added"
    RUN_AS_ROOT = "run_as_root"


class AlertType(str, Enum):
    UNEXPECTED_PROCESS = "unexpected_process"
    FILE_SYSTEM_MODIFICATION = "file_system_modification"
    NETWORK_CONNECTION_ANOMALY = "network_connection_anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONTAINER_ESCAPE = "container_escape"
    CRYPTO_MINING = "crypto_mining"
    REVERSE_SHELL = "reverse_shell"
    SENSITIVE_FILE_ACCESS = "sensitive_file_access"
    NAMESPACE_BREAKOUT = "namespace_breakout"
    SYSCALL_ANOMALY = "syscall_anomaly"
    DNS_EXFILTRATION = "dns_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Container Image Schemas
class ImageVulnerabilityResponse(DBModel):
    """Image vulnerability details"""

    id: str = ""
    image_id: str = ""
    cve_id: str = ""
    package_name: str = ""
    package_version: str = ""
    fixed_version: Optional[str] = None
    # critical / high / medium / low / negligible / unknown (as the scanner reported)
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    description: Optional[str] = None
    layer_introduced: Optional[str] = None
    remediation: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ImageVulnerabilityCreateRequest(BaseModel):
    """Create vulnerability"""

    cve_id: str = ""
    package_name: str = ""
    package_version: str = ""
    severity: VulnerabilitySeverity
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    description: Optional[str] = None
    remediation: Optional[str] = None


class ContainerImageResponse(DBModel):
    """Container image with metadata"""

    id: str = ""
    registry: str = ""
    repository: str = ""
    tag: str = ""
    digest_sha256: str = ""
    image_size_mb: Optional[float] = None
    os: Optional[str] = None
    architecture: Optional[str] = None
    created_at_source: Optional[datetime] = None
    scanned_at: Optional[datetime] = None
    vulnerability_count_critical: int = 0
    vulnerability_count_high: int = 0
    vulnerability_count_medium: int = 0
    vulnerability_count_low: int = 0
    is_signed: bool = False
    signature_verified: bool = False
    base_image: Optional[str] = None
    sbom_generated: bool = False
    # compliant / non_compliant only after a real scanner reported;
    # not_scanned otherwise (also scan_failed on legacy rows).
    compliance_status: str = "not_scanned"
    risk_score: int = 0
    labels: Dict[str, Any] = Field(default_factory=dict)
    last_deployed: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Wave 4: not_scanned / pending / awaiting_approval / awaiting_integration /
    # completed / failed, with the reason for the last two.
    scan_status: Optional[str] = "not_scanned"
    scan_error: Optional[str] = None
    last_scan_id: Optional[str] = None

    class Config:
        from_attributes = True


_DIGEST_RE = re.compile(r"^(sha256:)?[0-9a-fA-F]{64}$")


class ContainerImageCreateRequest(BaseModel):
    """Register a container image (registry/repository:tag, optional digest)."""

    registry: str = Field(..., min_length=1, max_length=255)
    repository: str = Field(..., min_length=1, max_length=255)
    tag: str = Field(..., min_length=1, max_length=255)
    # Optional: a sha256 image digest ("sha256:<64 hex>" or the 64 hex chars).
    digest_sha256: Optional[str] = None
    image_size_mb: Optional[float] = None
    os: Optional[str] = None
    architecture: Optional[str] = None
    base_image: Optional[str] = None
    labels: Optional[Dict[str, Any]] = {}

    @field_validator("digest_sha256")
    @classmethod
    def _digest(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        value = value.strip()
        if not _DIGEST_RE.match(value):
            raise ValueError("digest_sha256 must be 'sha256:' followed by 64 hex characters")
        return value.lower() if value.startswith("sha256:") else "sha256:" + value.lower()


class ContainerImageUpdateRequest(BaseModel):
    """Update container image"""

    labels: Optional[Dict[str, Any]] = None
    base_image: Optional[str] = None
    sbom_generated: Optional[bool] = None


# Kubernetes Cluster Schemas
class KubernetesClusterResponse(DBModel):
    """Kubernetes cluster details"""

    id: str = ""
    name: str = ""
    version: str = ""
    provider: str = ""
    endpoint: str = ""
    node_count: int = 0
    namespace_count: int = 0
    pod_count: int = 0
    rbac_enabled: bool = False
    network_policy_enabled: bool = False
    pod_security_standards: PodSecurityStandards
    audit_logging_enabled: bool = False
    encryption_at_rest: bool = False
    secrets_encrypted: bool = False
    admission_controllers: Dict[str, Any]
    last_audit: Optional[datetime] = None
    compliance_score: int = 0
    risk_score: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Wave 4. The security booleans above are self-attested (PATCH); the CIS
    # assessment below is read from the Kubernetes API.
    has_credential: bool = False
    credential_type: Optional[str] = None
    credential_set_at: Optional[datetime] = None
    assessment_status: Optional[str] = "not_assessed"
    assessment_error: Optional[str] = None
    # compliant / partial / non_compliant from an API assessment, else not_assessed
    compliance_status: str = "not_assessed"

    class Config:
        from_attributes = True


class KubernetesClusterCreateRequest(BaseModel):
    """Register a Kubernetes cluster"""

    name: str = Field(..., min_length=1, max_length=255)
    version: str = Field(..., min_length=1, max_length=50)
    provider: str = Field("", max_length=50)
    endpoint: str = Field(..., min_length=1, max_length=255)
    pod_security_standards: PodSecurityStandards = PodSecurityStandards.BASELINE
    admission_controllers: Optional[Dict[str, Any]] = {}

    @field_validator("endpoint")
    @classmethod
    def _https(cls, value: str) -> str:
        parts = urlsplit(value.strip())
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("endpoint must be the https:// URL of the Kubernetes API server")
        return value.strip()


class ClusterCredentialRequest(BaseModel):
    """Kubernetes API credential: a kubeconfig, or a bearer token (+ optional CA)."""

    kubeconfig: Optional[str] = Field(None, max_length=200_000)
    context: Optional[str] = Field(None, max_length=255)
    token: Optional[str] = Field(None, max_length=20_000)
    # base64-encoded PEM CA bundle for the API server (token credentials)
    ca_data: Optional[str] = Field(None, max_length=200_000)


class KubernetesClusterUpdateRequest(BaseModel):
    """Update Kubernetes cluster"""

    version: Optional[str] = None
    node_count: Optional[int] = None
    namespace_count: Optional[int] = None
    pod_count: Optional[int] = None
    rbac_enabled: Optional[bool] = None
    network_policy_enabled: Optional[bool] = None
    audit_logging_enabled: Optional[bool] = None
    encryption_at_rest: Optional[bool] = None
    secrets_encrypted: Optional[bool] = None


# Security Finding Schemas
class K8sSecurityFindingResponse(DBModel):
    """Kubernetes security finding"""

    id: str = ""
    cluster_id: str = ""
    # cis_<check> for CIS findings (e.g. cis_5_2_2); legacy rows keep older names
    finding_type: str = ""
    namespace: Optional[str] = None
    resource_type: str = ""
    resource_name: str = ""
    severity: Severity
    description: str = ""
    remediation: Optional[str] = None
    cis_benchmark_id: Optional[str] = None
    status: FindingStatus
    detected_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Wave 4: deduplicated per (cluster, image, check)
    check_id: Optional[str] = None
    image_ref: Optional[str] = None
    last_seen_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class K8sSecurityFindingCreateRequest(BaseModel):
    """Create security finding"""

    cluster_id: str = ""
    finding_type: FindingType
    namespace: str = Field(..., min_length=1)
    resource_type: str = ""
    resource_name: str = ""
    severity: Severity
    description: str = ""
    remediation: Optional[str] = None
    cis_benchmark_id: Optional[str] = None


class K8sSecurityFindingUpdateRequest(BaseModel):
    """Update security finding"""

    status: Optional[FindingStatus] = None
    remediation: Optional[str] = None


# Runtime Alert Schemas
class RuntimeAlertResponse(DBModel):
    """Runtime security alert"""

    id: str = ""
    cluster_id: str = ""
    alert_type: AlertType
    namespace: str = ""
    pod_name: str = ""
    container_name: Optional[str] = None
    process_name: Optional[str] = None
    process_args: Optional[str] = None
    severity: Severity
    description: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    mitre_technique: Optional[str] = None
    status: RuntimeAlertStatus
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RuntimeAlertCreateRequest(BaseModel):
    """Create runtime alert"""

    cluster_id: str = ""
    alert_type: AlertType
    namespace: str = ""
    pod_name: str = ""
    container_name: Optional[str] = None
    severity: Severity
    description: str = ""


class RuntimeAlertUpdateRequest(BaseModel):
    """Update runtime alert"""

    status: Optional[RuntimeAlertStatus] = None
    mitre_technique: Optional[str] = None


# Operation Request/Response Schemas
class ImageScanRequest(BaseModel):
    """Request image scan"""

    image_id: str = ""


class ImageScanResponse(BaseModel):
    """Image scan response.

    ``status``: completed (an integration scanner answered), pending /
    awaiting_approval (queued on an agent), failed, or awaiting_integration
    (no scanner; nothing was scanned).
    """

    status: str = ""
    image_id: str = ""
    vulnerabilities: int = 0
    risk_score: int = 0
    compliance_status: str = "not_scanned"
    detail: str = ""
    scan_id: Optional[str] = None
    method: Optional[str] = None
    scan_status: Optional[str] = None


class ClusterAuditRequest(BaseModel):
    """Request cluster audit"""

    cluster_id: str = ""
    audit_type: Optional[str] = "full"


class ClusterAuditResponse(BaseModel):
    """CIS audit through the Kubernetes API.

    ``status`` is ``assessed`` (checks evaluated on API data), ``failed``
    (the API could not be read) or ``not_assessed`` (no credential). Only an
    assessed run has a ``cis_compliance`` percentage.
    """

    status: str = ""
    cluster_id: str = ""
    findings: int = 0
    risk_score: int = 0
    compliance_score: int = 0
    cis_compliance: Optional[float] = None
    compliance_status: str = "not_assessed"
    reason: Optional[str] = None
    checks: Dict[str, int] = Field(default_factory=dict)
    findings_new: int = 0
    findings_updated: int = 0
    findings_resolved: int = 0
    benchmark: str = ""


class SecurityFindingRemediationRequest(BaseModel):
    """Request remediation"""

    finding_id: str = ""
    remediation_type: Optional[str] = "auto_generated"


class SecurityFindingRemediationResponse(BaseModel):
    """Remediation response"""

    status: str = ""
    finding_id: str = ""
    manifest: str = ""
    description: str = ""


class RuntimeAlertInvestigationRequest(BaseModel):
    """Investigate runtime alert"""

    alert_id: str = ""
    notes: Optional[str] = None


class PodQuarantineRequest(BaseModel):
    """Quarantine pod"""

    cluster_id: str = ""
    namespace: str = ""
    pod_name: str = ""
    reason: str = ""


# Dashboard Schemas
class VulnerabilityCountResponse(BaseModel):
    """Vulnerability count summary"""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0


class ClusterComplianceResponse(BaseModel):
    """Cluster compliance status"""

    cluster_name: str = ""
    risk_score: int = 0
    compliance_score: int = 0
    findings_count: int = 0
    # compliant / partial / non_compliant / not_assessed
    status: str = ""
    assessment_status: Optional[str] = None


class DashboardOverviewResponse(BaseModel):
    """Dashboard overview"""

    total_images: int = 0
    total_clusters: int = 0
    total_vulnerabilities: VulnerabilityCountResponse
    critical_findings: int = 0
    runtime_alerts_new: int = 0
    high_risk_images: int = Field(default=0)
    non_compliant_clusters: int = Field(default=0)
    # Flattened aliases for the frontend ContainerSecurity summary cards
    open_findings: int = 0
    active_alerts: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    top_vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    cluster_compliance: List[ClusterComplianceResponse] = Field(default_factory=list)
    runtime_alert_trends: List[Dict[str, Any]] = Field(default_factory=list)


class ComplianceMatrixResponse(BaseModel):
    """Compliance per cluster from stored CIS check results.

    Only the CIS Kubernetes checks are evaluated against the API; there is no
    mapping to NSA/CISA, DoD STIG or SOC 2, so those scores are null.
    """

    cluster_name: str = ""
    nsa_cisa_score: Optional[int] = None
    dod_stig_score: Optional[int] = None
    soc2_score: Optional[int] = None
    overall_compliance: Optional[int] = None
    timestamp: Optional[datetime] = None
    cluster_id: Optional[str] = None
    cis_score: Optional[float] = None
    status: str = "not_assessed"
    reason: Optional[str] = None
    checks: Dict[str, int] = Field(default_factory=dict)


class K8sCheckResultResponse(DBModel):
    """Stored result of one CIS check (pass / fail / not_assessed)."""

    id: str = ""
    cluster_id: str = ""
    check_id: str = ""
    title: str = ""
    status: str = ""
    reason: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    evaluated_at: Optional[datetime] = None


class ImageScanRecordResponse(DBModel):
    """One image scan request and its outcome."""

    id: str = ""
    image_id: str = ""
    method: str = ""
    scanner: Optional[str] = None
    status: str = ""
    integration_id: Optional[str] = None
    agent_id: Optional[str] = None
    command_id: Optional[str] = None
    requested_by: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    vulnerabilities_new: int = 0
    vulnerabilities_updated: int = 0
    vulnerabilities_total: int = 0
    created_at: Optional[datetime] = None


class ScannerAvailabilityResponse(BaseModel):
    """Which real scan paths exist for the caller's organisation."""

    status: str = "awaiting_integration"  # available | awaiting_integration
    integrations: List[Dict[str, Any]] = Field(default_factory=list)
    agents: List[Dict[str, Any]] = Field(default_factory=list)
    reason: Optional[str] = None


class PaginationParams(BaseModel):
    """Pagination parameters"""

    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)
