"""
OT/ICS Security Models

SQLAlchemy models for OT asset inventory, threat detection, zone management,
incident tracking, and compliance policy enforcement.

Supports Purdue model hierarchical segmentation and NERC-CIP / IEC 62443 compliance.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import BaseModel, utc_now

__all__ = [
    "OTAsset",
    "OTAlert",
    "OTZone",
    "OTIncident",
    "OTPolicyRule",
]


class OTAsset(BaseModel):
    """
    Operational Technology Asset inventory and management.

    Tracks industrial control systems (PLCs, HMIs, SCADA, DCS), engineering workstations,
    network infrastructure, and IoT sensors. Records protocol profiles, firmware versions,
    Purdue model tier placement, criticality, and known vulnerabilities.
    """

    __tablename__ = "ot_assets"

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # plc, hmi, scada_server, rtu, dcs, historian, engineering_workstation, safety_system, network_switch, firewall, iot_sensor, actuator, robot, cnc_machine

    vendor: Mapped[Optional[str]] = mapped_column(String(255))
    model: Mapped[Optional[str]] = mapped_column(String(255))
    firmware_version: Mapped[Optional[str]] = mapped_column(String(100))

    protocol: Mapped[Optional[str]] = mapped_column(
        String(50)
    )  # modbus_tcp, modbus_rtu, dnp3, opc_ua, opc_da, ethernetip, profinet, bacnet, mqtt, s7comm, iec61850, hart, foundation_fieldbus

    ip_address: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    serial_number: Mapped[Optional[str]] = mapped_column(String(255), unique=True)

    purdue_level: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # level0_process, level1_control, level2_supervisory, level3_operations, level3_5_dmz, level4_enterprise, level5_internet

    zone: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    cell_area: Mapped[Optional[str]] = mapped_column(String(255))

    criticality: Mapped[str] = mapped_column(
        String(50), default="supporting", index=True
    )  # safety_critical, mission_critical, important, supporting

    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    firmware_current: Mapped[bool] = mapped_column(Boolean, default=False)
    known_vulnerabilities_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)

    __table_args__ = (
        Index("ix_ot_assets_org_type", "organization_id", "asset_type"),
        Index("ix_ot_assets_org_level", "organization_id", "purdue_level"),
        UniqueConstraint("organization_id", "serial_number", name="uq_org_serial"),
    )


class OTAlert(BaseModel):
    """
    OT Security Alerts and anomaly detection.

    Captures protocol violations, unauthorized commands, firmware changes,
    network scanning, communication anomalies, and safety system events.
    Links to affected assets, MITRE ICS ATT&CK techniques, and response actions.
    """

    __tablename__ = "ot_alerts"

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("ot_assets.id"), nullable=False, index=True
    )

    alert_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # unauthorized_access, firmware_change, configuration_change, protocol_anomaly, network_scan, unauthorized_command, safety_violation, communication_loss, new_device_detected, plc_mode_change, setpoint_change, logic_change, excessive_traffic, known_exploit_attempt

    severity: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # critical, high, medium, low, info

    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45))
    protocol_used: Mapped[Optional[str]] = mapped_column(String(50))
    command_function_code: Mapped[Optional[str]] = mapped_column(String(100))

    description: Mapped[str] = mapped_column(Text, nullable=False)
    raw_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    mitre_ics_technique: Mapped[Optional[str]] = mapped_column(String(100), index=True)

    status: Mapped[str] = mapped_column(
        String(50), default="new", index=True
    )  # new, investigating, confirmed, contained, resolved, false_positive

    response_action: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        Index("ix_ot_alerts_org_asset", "organization_id", "asset_id"),
        Index("ix_ot_alerts_org_severity", "organization_id", "severity"),
        Index("ix_ot_alerts_org_status", "organization_id", "status"),
    )


class OTZone(BaseModel):
    """
    OT Network Security Zones based on Purdue model.

    Defines network segmentation boundaries, authorized communications,
    allowed protocols, firewall rules, and compliance status.
    Enables zone-to-zone communication policies and segmentation audits.
    """

    __tablename__ = "ot_zones"

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    purdue_level: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # level0_process, level1_control, level2_supervisory, level3_operations, level3_5_dmz, level4_enterprise, level5_internet

    network_cidr: Mapped[str] = mapped_column(String(50), nullable=False)

    allowed_protocols: Mapped[List[str]] = mapped_column(JSON, default=[])
    allowed_communications: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSON, default=[]
    )  # [{source_zone, dest_zone, protocol, ports}]

    assets_count: Mapped[int] = mapped_column(Integer, default=0)
    compliance_status: Mapped[str] = mapped_column(
        String(50), default="unknown"
    )  # unknown, compliant, non_compliant

    last_audit: Mapped[Optional[datetime]] = mapped_column(DateTime)

    firewall_rules: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})
    segmentation_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        Index("ix_ot_zones_org_level", "organization_id", "purdue_level"),
        UniqueConstraint("organization_id", "name", name="uq_org_zone_name"),
    )


class OTIncident(BaseModel):
    """
    OT Security Incident tracking and response coordination.

    Records cyber-physical incidents involving OT assets, affected zones,
    operational impact (downtime, safety risks), physical impact assessment,
    containment strategies, and safe shutdown procedures.
    """

    __tablename__ = "ot_incidents"

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    affected_assets: Mapped[List[str]] = mapped_column(JSON, default=[])
    affected_zones: Mapped[List[str]] = mapped_column(JSON, default=[])

    incident_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # ransomware, unauthorized_access, insider_threat, supply_chain, protocol_exploitation, safety_system_compromise, data_exfiltration, denial_of_service, physical_damage_risk

    severity: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # critical, high, medium, low

    physical_impact_risk: Mapped[str] = mapped_column(
        String(50), default="none"
    )  # none, low, moderate, high, critical_safety

    operational_impact: Mapped[str] = mapped_column(
        String(50), default="no_impact"
    )  # no_impact, degraded_performance, partial_outage, full_outage, safety_shutdown

    status: Mapped[str] = mapped_column(
        String(50), default="detected", index=True
    )  # detected, assessing, containing, eradicating, recovering, post_incident

    containment_strategy: Mapped[Optional[str]] = mapped_column(
        String(50)
    )  # network_isolation, process_shutdown_safe, emergency_stop, monitoring_only, partial_isolation

    safe_shutdown_initiated: Mapped[bool] = mapped_column(Boolean, default=False)

    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    __table_args__ = (
        Index("ix_ot_incidents_org_severity", "organization_id", "severity"),
        Index("ix_ot_incidents_org_status", "organization_id", "status"),
    )


class OTPolicyRule(BaseModel):
    """
    OT Security Policy Rules and enforcement.

    Defines network access policies, protocol restrictions, command whitelists,
    firmware update policies, maintenance windows, and patch management.
    Tracks violations and enforcement actions (alert, block, quarantine, safe shutdown).
    """

    __tablename__ = "ot_policy_rules"

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    rule_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # network_access, protocol_restriction, command_whitelist, firmware_policy, change_management, maintenance_window, remote_access, usb_policy, patch_policy

    purdue_levels_applied: Mapped[List[str]] = mapped_column(JSON, default=[])
    conditions: Mapped[Dict[str, Any]] = mapped_column(JSON, default={})

    enforcement_action: Mapped[str] = mapped_column(
        String(50), default="alert"
    )  # alert, block, quarantine, safe_shutdown, log_only

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    violations_count: Mapped[int] = mapped_column(Integer, default=0)
    last_violation: Mapped[Optional[datetime]] = mapped_column(DateTime)

    __table_args__ = (
        Index("ix_ot_policies_org_type", "organization_id", "rule_type"),
        UniqueConstraint("organization_id", "name", name="uq_org_policy_name"),
    )
