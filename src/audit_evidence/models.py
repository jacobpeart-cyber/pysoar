"""
Audit & Evidence Collection Models

SQLAlchemy models for audit trails, evidence packages, evidence items,
and automated collection rules for compliance audit support.
"""

from datetime import datetime
from typing import Any, Optional
from sqlalchemy import (, Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
    String,
    Integer,
    Text,
    DateTime,
    Boolean,
    JSON,
    Index,
    ForeignKey,
)
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel, utc_now

__all__ = [
    "AuditTrail",
    "EvidencePackage",
    "AutomatedEvidenceRule",
]


class AuditTrail(BaseModel):
    """
    Audit Trail Entry

    Comprehensive audit logging for all system events including access,
    changes, administrative actions, policy updates, and security events.
    Supports detailed event tracking with before/after values and risk assessment.
    """

    __tablename__ = "audit_trails"

    event_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # access, change, admin, policy, compliance, security, data
    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # user.login, policy.update, control.assess
    actor_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # user, system, api, service
    actor_id: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    actor_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    old_value: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    new_value: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    result: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # success, failure, denied
    risk_level: Mapped[str] = mapped_column(
        String(20), default="info", index=True
    )  # critical, high, medium, low, info
    session_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_audit_trails_event_created", "event_type", "created_at"),
        Index("ix_audit_trails_actor_created", "actor_id", "created_at"),
        Index("ix_audit_trails_resource_created", "resource_type", "resource_id"),
    )


class EvidencePackage(BaseModel):
    """
    Evidence Package

    Organizes evidence items for compliance audits and assessments.
    Maps evidence to compliance controls, tracks package status, and manages
    submission to auditors. Supports integrity verification via package hash.
    """

    __tablename__ = "evidence_packages"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    package_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # fedramp_conmon, cmmc_assessment, soc2_audit, hipaa_audit, pci_audit, custom
    framework_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("compliance_frameworks.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(50), default="collecting", index=True
    )  # collecting, review, approved, submitted, archived
    evidence_items: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # evidence IDs
    control_mappings: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # control_id -> evidence_ids
    assessor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    submitted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    package_hash: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # SHA-512 integrity hash
    extra_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_evidence_packages_status_created", "status", "created_at"),
        Index("ix_evidence_packages_framework", "framework_id", "organization_id"),
        Index("ix_evidence_packages_due_date", "due_date", "status"),
    )


class AutomatedEvidenceRule(BaseModel):
    """
    Automated Evidence Collection Rule

    Defines automated collection methods for evidence (API queries, log analysis,
    config checks, scan results, metrics). Rules schedule evidence collection
    and map evidence to compliance controls.
    """

    __tablename__ = "automated_evidence_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    control_ids: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # which controls this supports
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    collection_method: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # api_query, log_query, config_check, scan_result, metric_snapshot
    collection_config: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # query, endpoint, etc.
    schedule: Mapped[str] = mapped_column(
        String(50), default="daily", index=True
    )  # daily, weekly, monthly, on_demand
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_collected_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_automated_evidence_rules_enabled", "is_enabled", "schedule"),
        Index(
            "ix_automated_evidence_rules_last_collected",
            "last_collected_at",
            "schedule",
        ),
    )
