"""ATT&CK knowledge-base tables.

ATT&CK is global reference data, so these tables are NOT tenant-scoped.
Objects are keyed by their STIX id (stable, unique) and carry the
human-facing ATT&CK external id (Txxxx / Gxxxx / Mxxxx / Sxxxx).

Relationships are stored as junction tables keyed by external id —
resolved by the loader after all objects are in, so load order and
forward references don't matter.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import BaseModel


class AttackTactic(BaseModel):
    """An ATT&CK tactic (the 'why' — e.g. TA0006 Credential Access)."""

    __tablename__ = "attack_kb_tactics"

    stix_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # TA0006
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    shortname: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)  # credential-access
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(String(30), nullable=False, index=True)  # enterprise / ics
    attack_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)


class AttackTechnique(BaseModel):
    """An ATT&CK technique or sub-technique (the 'how' — T1110 / T1110.001)."""

    __tablename__ = "attack_kb_techniques"

    stix_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # T1110.001
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    parent_external_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)  # T1110
    # Tactic shortnames this technique belongs to (kill_chain_phases).
    tactics: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    platforms: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    detection: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    data_sources: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # raw STIX x_mitre_data_sources
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # successor external_id
    attack_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    __table_args__ = (
        Index("ix_attack_tech_domain_sub", "domain", "is_subtechnique"),
    )


class AttackMitigation(BaseModel):
    """An ATT&CK mitigation / course-of-action (Mxxxx)."""

    __tablename__ = "attack_kb_mitigations"

    stix_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AttackGroup(BaseModel):
    """An ATT&CK intrusion-set / threat group (Gxxxx)."""

    __tablename__ = "attack_kb_groups"

    stix_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AttackSoftware(BaseModel):
    """An ATT&CK software entry — malware or tool (Sxxxx)."""

    __tablename__ = "attack_kb_software"

    stix_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    software_type: Mapped[str] = mapped_column(String(20), default="malware", nullable=False)  # malware / tool
    aliases: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    platforms: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AttackDataComponent(BaseModel):
    """A data component (e.g. 'Process Creation') and its parent data
    source (e.g. 'Process'). Detecting a technique requires the data
    component's telemetry — so this is the bridge to 'do we even have
    that source?'."""

    __tablename__ = "attack_kb_data_components"

    stix_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    data_source_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# --- Relationship junctions (keyed by external id, resolved post-load) ---

class AttackTechniqueMitigation(BaseModel):
    """mitigation M -> defends technique T."""

    __tablename__ = "attack_kb_technique_mitigation"

    technique_external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    mitigation_external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    __table_args__ = (
        Index("ix_attack_tm_pair", "technique_external_id", "mitigation_external_id", unique=True),
    )


class AttackGroupTechnique(BaseModel):
    """group G -> uses technique T."""

    __tablename__ = "attack_kb_group_technique"

    group_external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    __table_args__ = (
        Index("ix_attack_gt_pair", "group_external_id", "technique_external_id", unique=True),
    )


class AttackSoftwareTechnique(BaseModel):
    """software S -> uses technique T."""

    __tablename__ = "attack_kb_software_technique"

    software_external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    __table_args__ = (
        Index("ix_attack_st_pair", "software_external_id", "technique_external_id", unique=True),
    )


class AttackTechniqueDataComponent(BaseModel):
    """How technique T is detectable: data component + concrete log source.

    In ATT&CK v16+ the linkage is technique <- detects <- detection-
    strategy -> analytics -> log sources. ``log_source_name`` holds the
    concrete telemetry channel (e.g. 'linux:syslog', 'WinEventLog:
    Security', 'auditd:SYSCALL') — the actionable 'do we collect this?'
    signal — and ``data_component_name`` the ATT&CK data component."""

    __tablename__ = "attack_kb_technique_datacomponent"

    technique_external_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    data_component_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    log_source_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    data_source_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_attack_tdc_pair", "technique_external_id", "data_component_name", "log_source_name", unique=True),
    )


class AttackSyncState(BaseModel):
    """Single-row record of the loaded ATT&CK dataset version + counts."""

    __tablename__ = "attack_kb_sync_state"

    attack_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    domains: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    object_counts: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    source_release: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="empty", nullable=False)  # empty/syncing/loaded/failed
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    techniques_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
