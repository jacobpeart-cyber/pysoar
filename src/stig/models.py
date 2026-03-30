"""
STIG/SCAP Models

SQLAlchemy models for STIG benchmark management, rule tracking, scan results,
and SCAP profile management. Supports comprehensive compliance automation.
"""

from datetime import datetime
from typing import Any, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel, utc_now

__all__ = [
    "STIGBenchmark",
    "STIGRule",
    "STIGScanResult",
    "SCAPProfile",
]


class STIGBenchmark(BaseModel):
    """
    STIG Benchmark Definition

    Stores metadata for STIG benchmarks including versions, rule counts by category,
    and publication information. Each benchmark can be scanned across multiple hosts.
    """

    __tablename__ = "stig_benchmarks"

    benchmark_id: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=True)
    version: Mapped[str] = mapped_column(String(50), nullable=True)
    release: Mapped[str] = mapped_column(String(50), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    platform: Mapped[str] = mapped_column(String(100), nullable=True)
    total_rules: Mapped[int] = mapped_column(Integer, default=0)
    category_1_count: Mapped[int] = mapped_column(
        Integer, default=0
    )  # CAT I - High
    category_2_count: Mapped[int] = mapped_column(
        Integer, default=0
    )  # CAT II - Medium
    category_3_count: Mapped[int] = mapped_column(
        Integer, default=0
    )  # CAT III - Low
    status: Mapped[str] = mapped_column(String(50), default="available", index=True)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    tags: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_stig_benchmarks_status_created", "status", "created_at"),
        Index("ix_stig_benchmarks_org_benchmark", "organization_id", "benchmark_id"),
    )


class STIGRule(BaseModel):
    """
    STIG Rule Definition

    Represents individual STIG rules with severity, check/fix text, automation support,
    and NIST/CCI mappings. Rules are uniquely identified by V-number (rule_id).
    """

    __tablename__ = "stig_rules"

    benchmark_id_ref: Mapped[str] = mapped_column(
        String(36), ForeignKey("stig_benchmarks.id"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # V-number
    stig_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # SV-number
    group_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # high, medium, low
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    check_text: Mapped[str] = mapped_column(Text, nullable=True)
    fix_text: Mapped[str] = mapped_column(Text, nullable=True)
    cci: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # Control Correlation Identifiers
    nist_controls: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # NIST 800-53 controls
    automated_check: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )  # SCAP/OVAL check definition
    is_automatable: Mapped[bool] = mapped_column(Boolean, default=True)
    default_status: Mapped[str] = mapped_column(
        String(50), default="not_reviewed", index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_stig_rules_benchmark_rule", "benchmark_id_ref", "rule_id"),
        Index("ix_stig_rules_severity_org", "severity", "organization_id"),
    )


class STIGScanResult(BaseModel):
    """
    STIG Scan Result

    Tracks scan execution details, findings per rule, and compliance metrics.
    Aggregates check results (open/not_a_finding/not_applicable/not_reviewed)
    by severity category for dashboard and reporting.
    """

    __tablename__ = "stig_scan_results"

    benchmark_id_ref: Mapped[str] = mapped_column(
        String(36), ForeignKey("stig_benchmarks.id"), nullable=False, index=True
    )
    target_host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    scan_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # manual, scap, automated, hybrid
    scanner: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # running, completed, failed
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    open_findings: Mapped[int] = mapped_column(Integer, default=0)
    not_a_finding: Mapped[int] = mapped_column(Integer, default=0)
    not_applicable: Mapped[int] = mapped_column(Integer, default=0)
    not_reviewed: Mapped[int] = mapped_column(Integer, default=0)
    compliance_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    cat1_open: Mapped[int] = mapped_column(Integer, default=0)
    cat2_open: Mapped[int] = mapped_column(Integer, default=0)
    cat3_open: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # per-rule results
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_stig_scan_results_target_time", "target_host", "completed_at"),
        Index("ix_stig_scan_results_status_benchmark", "status", "benchmark_id_ref"),
        Index("ix_stig_scan_results_org_created", "organization_id", "created_at"),
    )


class SCAPProfile(BaseModel):
    """
    SCAP Profile Configuration

    Manages SCAP content (XCCDF, OVAL, CPE) for automated scanning.
    Stores content paths, checksums for integrity, and platform applicability.
    """

    __tablename__ = "scap_profiles"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    profile_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # xccdf, oval, cpe, custom
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # SHA-512
    platform_applicable: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    check_count: Mapped[int] = mapped_column(Integer, default=0)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_scap_profiles_org_type", "organization_id", "profile_type"),
        Index("ix_scap_profiles_enabled", "is_enabled", "created_at"),
    )
