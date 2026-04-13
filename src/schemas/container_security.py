"""
Container Security Schemas

Pydantic models for container security API request/response validation.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

from src.schemas.base import DBModel
from pydantic import BaseModel, Field

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
    severity: VulnerabilitySeverity
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
    compliance_status: ComplianceStatus
    risk_score: int = 0
    labels: Dict[str, Any]
    last_deployed: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ContainerImageCreateRequest(BaseModel):
    """Create container image"""

    registry: str = Field(..., min_length=1)
    repository: str = Field(..., min_length=1)
    tag: str = Field(..., min_length=1)
    digest_sha256: str = Field(..., min_length=64)
    image_size_mb: Optional[float] = None
    os: Optional[str] = None
    architecture: Optional[str] = None
    base_image: Optional[str] = None
    labels: Optional[Dict[str, Any]] = {}


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

    class Config:
        from_attributes = True


class KubernetesClusterCreateRequest(BaseModel):
    """Create Kubernetes cluster"""

    name: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    provider: str = ""
    endpoint: str = Field(..., min_length=1)
    pod_security_standards: PodSecurityStandards = PodSecurityStandards.BASELINE
    admission_controllers: Optional[Dict[str, Any]] = {}


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
    finding_type: FindingType
    namespace: str = ""
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
    """Image scan response"""

    status: str = ""
    image_id: str = ""
    vulnerabilities: int = 0
    risk_score: int = 0
    compliance_status: ComplianceStatus


class ClusterAuditRequest(BaseModel):
    """Request cluster audit"""

    cluster_id: str = ""
    audit_type: Optional[str] = "full"


class ClusterAuditResponse(BaseModel):
    """Cluster audit response"""

    status: str = ""
    cluster_id: str = ""
    findings: int = 0
    risk_score: int = 0
    compliance_score: int = 0
    cis_compliance: float = 0.0


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
    status: str = ""


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
    """Compliance matrix across frameworks"""

    cluster_name: str = ""
    nsa_cisa_score: int = 0
    dod_stig_score: int = 0
    soc2_score: int = 0
    overall_compliance: int = 0
    timestamp: Optional[datetime] = None


class PaginationParams(BaseModel):
    """Pagination parameters"""

    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)
