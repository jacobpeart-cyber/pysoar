"""
API Security Governance Models

SQLAlchemy models for API endpoint inventory, vulnerability tracking,
security policies, anomaly detection, and compliance checks.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
from sqlalchemy import (, Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
    String,
    Integer,
    Float,
    Text,
    DateTime,
    Boolean,
    JSON,
    Index,
    ForeignKey,
    UniqueConstraint,
    Enum as SQLEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel, utc_now

__all__ = [
    "APIEndpointInventory",
    "APIVulnerability",
    "APISecurityPolicy",
    "APIAnomalyDetection",
    "APIComplianceCheck",
]


class AuthenticationTypeEnum(str, Enum):
    """API authentication types"""
    NONE = "none"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    BASIC = "basic"
    MTLS = "mtls"
    CUSTOM = "custom"


class VulnerabilityTypeEnum(str, Enum):
    """OWASP API Top 10 vulnerability types"""
    BOLA = "bola"  # Broken Object Level Authorization
    BROKEN_AUTH = "broken_auth"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    LACK_OF_RESOURCES_RATE_LIMITING = "lack_of_resources_rate_limiting"
    BROKEN_FUNCTION_LEVEL_AUTH = "broken_function_level_auth"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    INJECTION = "injection"
    IMPROPER_ASSETS_MANAGEMENT = "improper_assets_management"
    INSUFFICIENT_LOGGING = "insufficient_logging"


class PolicyTypeEnum(str, Enum):
    """API security policy types"""
    AUTHENTICATION = "authentication"
    RATE_LIMITING = "rate_limiting"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_FILTERING = "output_filtering"
    CORS = "cors"
    TLS_VERSION = "tls_version"
    HEADER_SECURITY = "header_security"
    SCHEMA_VALIDATION = "schema_validation"
    SIZE_LIMIT = "size_limit"
    IP_ALLOWLIST = "ip_allowlist"


class AnomalyTypeEnum(str, Enum):
    """API anomaly detection types"""
    UNUSUAL_VOLUME = "unusual_volume"
    UNUSUAL_PAYLOAD_SIZE = "unusual_payload_size"
    UNUSUAL_ERROR_RATE = "unusual_error_rate"
    UNUSUAL_SOURCE = "unusual_source"
    UNUSUAL_TIME = "unusual_time"
    SCHEMA_VIOLATION = "schema_violation"
    ENUMERATION_ATTEMPT = "enumeration_attempt"
    CREDENTIAL_STUFFING = "credential_stuffing"
    DATA_SCRAPING = "data_scraping"
    PARAMETER_TAMPERING = "parameter_tampering"


class ComplianceCheckTypeEnum(str, Enum):
    """Compliance check types"""
    OWASP_API_TOP10 = "owasp_api_top10"
    OPENAPI_VALIDATION = "openapi_validation"
    AUTHENTICATION_CHECK = "authentication_check"
    AUTHORIZATION_CHECK = "authorization_check"
    RATE_LIMIT_CHECK = "rate_limit_check"
    TLS_CHECK = "tls_check"
    HEADER_CHECK = "header_check"
    PII_EXPOSURE_CHECK = "pii_exposure_check"
    LOGGING_CHECK = "logging_check"
    VERSIONING_CHECK = "versioning_check"


class APIEndpointInventory(BaseModel):
    """
    API endpoint discovery and inventory tracking.

    Maintains comprehensive catalog of all discovered APIs (documented and shadow),
    authentication methods, data classification, usage metrics, and deprecation status.
    """

    __tablename__ = "api_endpoint_inventory"

    service_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    method: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # GET, POST, PUT, DELETE, PATCH
    api_version: Mapped[str] = mapped_column(String(50), nullable=True)

    authentication_type: Mapped[str] = mapped_column(
        SQLEnum(AuthenticationTypeEnum), default=AuthenticationTypeEnum.NONE, nullable=False
    )
    authorization_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_classification: Mapped[str] = mapped_column(
        String(50), default="internal", nullable=False
    )  # public, internal, confidential, restricted

    is_public: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_documented: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_shadow: Mapped[bool] = mapped_column(
        Boolean, default=False, index=True
    )  # Discovered but not documented
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    rate_limit_configured: Mapped[bool] = mapped_column(Boolean, default=False)
    input_validation_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    response_encryption: Mapped[bool] = mapped_column(Boolean, default=False)

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    request_count_24h: Mapped[int] = mapped_column(Integer, default=0)
    error_rate: Mapped[float] = mapped_column(Float, default=0.0)

    owner_team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    openapi_spec_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_endpoint_service_method_path", "service_name", "method", "path"),
        Index("ix_endpoint_org_shadow_documented", "organization_id", "is_shadow", "is_documented"),
        Index("ix_endpoint_org_auth_type", "organization_id", "authentication_type"),
    )


class APIVulnerability(BaseModel):
    """
    API vulnerability findings and tracking.

    Records OWASP API Top 10 vulnerabilities, severity levels, evidence,
    remediation guidance, and remediation status.
    """

    __tablename__ = "api_vulnerabilities"

    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("api_endpoint_inventory.id"), nullable=False, index=True
    )
    vulnerability_type: Mapped[str] = mapped_column(
        SQLEnum(VulnerabilityTypeEnum), nullable=False, index=True
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # critical, high, medium, low

    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(
        String(50), default="open", nullable=False, index=True
    )  # open, remediated, accepted, false_positive

    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    detected_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_vuln_endpoint_type_status", "endpoint_id", "vulnerability_type", "status"),
        Index("ix_vuln_org_severity_status", "organization_id", "severity", "status"),
    )


class APISecurityPolicy(BaseModel):
    """
    API security policy definitions and enforcement.

    Defines organizational security policies for APIs, enforcement levels,
    and applicable scope (services, paths, methods).
    """

    __tablename__ = "api_security_policies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    policy_type: Mapped[str] = mapped_column(
        SQLEnum(PolicyTypeEnum), nullable=False, index=True
    )
    rules: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    enforcement_level: Mapped[str] = mapped_column(
        String(50), default="enforce", nullable=False
    )  # enforce, monitor, disabled
    applies_to: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default={}
    )  # {services: [], paths: [], methods: []}

    violations_count: Mapped[int] = mapped_column(Integer, default=0, index=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_policy_org_type_enforcement", "organization_id", "policy_type", "enforcement_level"),
    )


class APIAnomalyDetection(BaseModel):
    """
    API anomaly detection and baseline tracking.

    Detects unusual API behavior including volume spikes, payload size anomalies,
    error rate changes, enumeration attempts, credential stuffing, and data scraping.
    """

    __tablename__ = "api_anomaly_detection"

    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("api_endpoint_inventory.id"), nullable=False, index=True
    )
    anomaly_type: Mapped[str] = mapped_column(
        SQLEnum(AnomalyTypeEnum), nullable=False, index=True
    )

    baseline_value: Mapped[float] = mapped_column(Float, nullable=False)
    observed_value: Mapped[float] = mapped_column(Float, nullable=False)
    deviation_percentage: Mapped[float] = mapped_column(Float, nullable=False)

    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # critical, high, medium, low, info

    source_ips: Mapped[List[str]] = mapped_column(JSON, default=[])
    sample_requests: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=[])

    status: Mapped[str] = mapped_column(
        String(50), default="open", nullable=False, index=True
    )  # open, investigating, resolved, false_positive

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_anomaly_endpoint_type_severity", "endpoint_id", "anomaly_type", "severity"),
        Index("ix_anomaly_org_status", "organization_id", "status"),
    )


class APIComplianceCheck(BaseModel):
    """
    API compliance assessment and validation.

    Tracks compliance checks against OWASP API Top 10, OpenAPI specifications,
    authentication/authorization, TLS, headers, PII exposure, and logging requirements.
    """

    __tablename__ = "api_compliance_checks"

    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("api_endpoint_inventory.id"), nullable=False, index=True
    )
    check_type: Mapped[str] = mapped_column(
        SQLEnum(ComplianceCheckTypeEnum), nullable=False, index=True
    )

    passed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    last_checked: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    remediation_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_compliance_endpoint_type_passed", "endpoint_id", "check_type", "passed"),
        Index("ix_compliance_org_type_passed", "organization_id", "check_type", "passed"),
    )
