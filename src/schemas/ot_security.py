"""
OT/ICS Security Schemas

Pydantic models for request/response validation across all OT security endpoints.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

from src.schemas.base import DBModel
from pydantic import BaseModel, Field

__all__ = [
    "OTAssetResponse",
    "OTAssetCreate",
    "OTAssetUpdate",
    "OTAlertResponse",
    "OTAlertCreate",
    "OTAlertUpdate",
    "OTZoneResponse",
    "OTZoneCreate",
    "OTZoneUpdate",
    "OTIncidentResponse",
    "OTIncidentCreate",
    "OTIncidentUpdate",
    "OTPolicyRuleResponse",
    "OTPolicyRuleCreate",
    "OTPolicyRuleUpdate",
    "OTDashboardResponse",
    "OTComplianceReportResponse",
    "OTRiskAssessmentResponse",
    "OTAssetListResponse",
    "OTAlertListResponse",
    "OTZoneListResponse",
    "OTIncidentListResponse",
    "OTPolicyListResponse",
]


# Enums
class AssetType(str, Enum):
    PLC = "plc"
    HMI = "hmi"
    SCADA_SERVER = "scada_server"
    RTU = "rtu"
    DCS = "dcs"
    HISTORIAN = "historian"
    ENGINEERING_WORKSTATION = "engineering_workstation"
    SAFETY_SYSTEM = "safety_system"
    NETWORK_SWITCH = "network_switch"
    FIREWALL = "firewall"
    IOT_SENSOR = "iot_sensor"
    ACTUATOR = "actuator"
    ROBOT = "robot"
    CNC_MACHINE = "cnc_machine"


class Protocol(str, Enum):
    MODBUS_TCP = "modbus_tcp"
    MODBUS_RTU = "modbus_rtu"
    DNP3 = "dnp3"
    OPC_UA = "opc_ua"
    OPC_DA = "opc_da"
    ETHERNETIP = "ethernetip"
    PROFINET = "profinet"
    BACNET = "bacnet"
    MQTT = "mqtt"
    S7COMM = "s7comm"
    IEC61850 = "iec61850"
    HART = "hart"
    FOUNDATION_FIELDBUS = "foundation_fieldbus"


class PurdueLevel(str, Enum):
    LEVEL0_PROCESS = "level0_process"
    LEVEL1_CONTROL = "level1_control"
    LEVEL2_SUPERVISORY = "level2_supervisory"
    LEVEL3_OPERATIONS = "level3_operations"
    LEVEL3_5_DMZ = "level3_5_dmz"
    LEVEL4_ENTERPRISE = "level4_enterprise"
    LEVEL5_INTERNET = "level5_internet"


class Criticality(str, Enum):
    SAFETY_CRITICAL = "safety_critical"
    MISSION_CRITICAL = "mission_critical"
    IMPORTANT = "important"
    SUPPORTING = "supporting"


class AlertType(str, Enum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    FIRMWARE_CHANGE = "firmware_change"
    CONFIGURATION_CHANGE = "configuration_change"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    NETWORK_SCAN = "network_scan"
    UNAUTHORIZED_COMMAND = "unauthorized_command"
    SAFETY_VIOLATION = "safety_violation"
    COMMUNICATION_LOSS = "communication_loss"
    NEW_DEVICE_DETECTED = "new_device_detected"
    PLC_MODE_CHANGE = "plc_mode_change"
    SETPOINT_CHANGE = "setpoint_change"
    LOGIC_CHANGE = "logic_change"
    EXCESSIVE_TRAFFIC = "excessive_traffic"
    KNOWN_EXPLOIT_ATTEMPT = "known_exploit_attempt"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentType(str, Enum):
    RANSOMWARE = "ransomware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    PROTOCOL_EXPLOITATION = "protocol_exploitation"
    SAFETY_SYSTEM_COMPROMISE = "safety_system_compromise"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    PHYSICAL_DAMAGE_RISK = "physical_damage_risk"


class PhysicalImpactRisk(str, Enum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL_SAFETY = "critical_safety"


class OperationalImpact(str, Enum):
    NO_IMPACT = "no_impact"
    DEGRADED_PERFORMANCE = "degraded_performance"
    PARTIAL_OUTAGE = "partial_outage"
    FULL_OUTAGE = "full_outage"
    SAFETY_SHUTDOWN = "safety_shutdown"


class ContainmentStrategy(str, Enum):
    NETWORK_ISOLATION = "network_isolation"
    PROCESS_SHUTDOWN_SAFE = "process_shutdown_safe"
    EMERGENCY_STOP = "emergency_stop"
    MONITORING_ONLY = "monitoring_only"
    PARTIAL_ISOLATION = "partial_isolation"


class RuleType(str, Enum):
    NETWORK_ACCESS = "network_access"
    PROTOCOL_RESTRICTION = "protocol_restriction"
    COMMAND_WHITELIST = "command_whitelist"
    FIRMWARE_POLICY = "firmware_policy"
    CHANGE_MANAGEMENT = "change_management"
    MAINTENANCE_WINDOW = "maintenance_window"
    REMOTE_ACCESS = "remote_access"
    USB_POLICY = "usb_policy"
    PATCH_POLICY = "patch_policy"


class EnforcementAction(str, Enum):
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    SAFE_SHUTDOWN = "safe_shutdown"
    LOG_ONLY = "log_only"


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    ASSESSING = "assessing"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    POST_INCIDENT = "post_incident"


# OT Asset Schemas
class OTAssetResponse(DBModel):
    """OT Asset Response"""

    id: str = ""
    organization_id: str = ""
    name: str = ""
    asset_type: AssetType
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    protocol: Optional[Protocol] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    purdue_level: PurdueLevel
    zone: Optional[str] = None
    cell_area: Optional[str] = None
    criticality: Criticality
    last_seen: Optional[datetime] = None
    is_online: bool = False
    firmware_current: bool = False
    known_vulnerabilities_count: int = 0
    risk_score: float = 0.0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class OTAssetCreate(BaseModel):
    """Create OT Asset"""

    name: str = ""
    asset_type: AssetType
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    protocol: Optional[Protocol] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    purdue_level: PurdueLevel
    zone: Optional[str] = None
    cell_area: Optional[str] = None
    criticality: Criticality = Criticality.SUPPORTING


class OTAssetUpdate(BaseModel):
    """Update OT Asset"""

    name: Optional[str] = None
    firmware_version: Optional[str] = None
    ip_address: Optional[str] = None
    zone: Optional[str] = None
    criticality: Optional[Criticality] = None
    firmware_current: Optional[bool] = None


class OTAssetListResponse(BaseModel):
    """Paginated OT Asset List"""

    items: List[OTAssetResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# OT Alert Schemas
class OTAlertResponse(DBModel):
    """OT Alert Response"""

    id: str = ""
    organization_id: str = ""
    asset_id: str = ""
    alert_type: AlertType
    severity: AlertSeverity
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol_used: Optional[str] = None
    command_function_code: Optional[str] = None
    description: str = ""
    raw_data: Dict[str, Any] = {}
    mitre_ics_technique: Optional[str] = None
    status: AlertStatus
    response_action: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class OTAlertCreate(BaseModel):
    """Create OT Alert"""

    asset_id: str = ""
    alert_type: AlertType
    severity: AlertSeverity
    description: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol_used: Optional[str] = None
    command_function_code: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    mitre_ics_technique: Optional[str] = None


class OTAlertUpdate(BaseModel):
    """Update OT Alert"""

    status: Optional[AlertStatus] = None
    response_action: Optional[str] = None


class OTAlertListResponse(BaseModel):
    """Paginated OT Alert List"""

    items: List[OTAlertResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# OT Zone Schemas
class OTZoneResponse(DBModel):
    """OT Zone Response"""

    id: str = ""
    organization_id: str = ""
    name: str = ""
    description: Optional[str] = None
    purdue_level: PurdueLevel
    network_cidr: str = ""
    allowed_protocols: List[str] = []
    allowed_communications: List[Dict[str, Any]] = []
    assets_count: int = 0
    compliance_status: str = ""
    last_audit: Optional[datetime] = None
    firewall_rules: Dict[str, Any] = {}
    segmentation_verified: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class OTZoneCreate(BaseModel):
    """Create OT Zone"""

    name: str = ""
    description: Optional[str] = None
    purdue_level: PurdueLevel
    network_cidr: str = ""
    allowed_protocols: Optional[List[str]] = None
    allowed_communications: Optional[List[Dict[str, Any]]] = None


class OTZoneUpdate(BaseModel):
    """Update OT Zone"""

    description: Optional[str] = None
    allowed_protocols: Optional[List[str]] = None
    allowed_communications: Optional[List[Dict[str, Any]]] = None
    firewall_rules: Optional[Dict[str, Any]] = None


class OTZoneListResponse(BaseModel):
    """Paginated OT Zone List"""

    items: List[OTZoneResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# OT Incident Schemas
class OTIncidentResponse(DBModel):
    """OT Incident Response"""

    id: str = ""
    organization_id: str = ""
    title: str = ""
    description: str = ""
    affected_assets: List[str] = []
    affected_zones: List[str] = []
    incident_type: IncidentType
    severity: AlertSeverity
    physical_impact_risk: PhysicalImpactRisk
    operational_impact: OperationalImpact
    status: IncidentStatus
    containment_strategy: Optional[ContainmentStrategy] = None
    safe_shutdown_initiated: bool = False
    detected_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class OTIncidentCreate(BaseModel):
    """Create OT Incident"""

    title: str = ""
    description: str = ""
    incident_type: IncidentType
    severity: AlertSeverity
    affected_assets: Optional[List[str]] = None
    affected_zones: Optional[List[str]] = None


class OTIncidentUpdate(BaseModel):
    """Update OT Incident"""

    status: Optional[IncidentStatus] = None
    containment_strategy: Optional[ContainmentStrategy] = None
    safe_shutdown_initiated: Optional[bool] = None
    physical_impact_risk: Optional[PhysicalImpactRisk] = None
    operational_impact: Optional[OperationalImpact] = None


class OTIncidentListResponse(BaseModel):
    """Paginated OT Incident List"""

    items: List[OTIncidentResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# OT Policy Schemas
class OTPolicyRuleResponse(DBModel):
    """OT Policy Rule Response"""

    id: str = ""
    organization_id: str = ""
    name: str = ""
    description: Optional[str] = None
    rule_type: RuleType
    purdue_levels_applied: List[str] = []
    conditions: Dict[str, Any] = {}
    enforcement_action: EnforcementAction
    enabled: bool = False
    violations_count: int = 0
    last_violation: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class OTPolicyRuleCreate(BaseModel):
    """Create OT Policy Rule"""

    name: str = ""
    description: Optional[str] = None
    rule_type: RuleType
    purdue_levels_applied: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None
    enforcement_action: EnforcementAction = EnforcementAction.ALERT


class OTPolicyRuleUpdate(BaseModel):
    """Update OT Policy Rule"""

    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    enforcement_action: Optional[EnforcementAction] = None
    enabled: Optional[bool] = None


class OTPolicyListResponse(BaseModel):
    """Paginated OT Policy List"""

    items: List[OTPolicyRuleResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# Dashboard Schemas
class AssetInventoryStats(BaseModel):
    """Asset Inventory Statistics"""

    total_assets: int = 0
    by_type: Dict[str, int] = {}
    by_purdue_level: Dict[str, int] = {}
    by_criticality: Dict[str, int] = {}
    online_count: int = 0
    offline_count: int = 0


class AlertStats(BaseModel):
    """Alert Statistics"""

    total_alerts: int = 0
    by_severity: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    new_alerts_24h: int = 0
    resolved_24h: int = 0


class ComplianceScores(BaseModel):
    """Compliance Scores"""

    nerc_cip: float = 0.0
    iec_62443: float = 0.0
    nist_sp_800_82: float = 0.0
    overall: float = 0.0


class OTDashboardResponse(BaseModel):
    """OT Security Dashboard Response"""

    timestamp: Optional[datetime] = None
    asset_inventory: AssetInventoryStats
    alert_summary: AlertStats
    critical_risks: List[str] = []
    zones_by_level: Dict[str, int] = {}
    compliance_scores: ComplianceScores
    top_vulnerabilities: List[Dict[str, Any]] = []
    purdue_model_visualization: Dict[str, Any] = {}


# Compliance Schemas
class ComplianceReportResponse(BaseModel):
    """ICS Compliance Report Response"""

    timestamp: Optional[datetime] = None
    nerc_cip: Dict[str, Any] = {}
    iec_62443: Dict[str, Any] = {}
    nist_sp_800_82: Dict[str, Any] = {}
    overall_compliant: bool = False
    remediation_actions: List[str] = []


# Risk Assessment Schemas
class AssetRisk(BaseModel):
    """Asset Risk Assessment"""

    asset_id: str = ""
    name: str = ""
    risk_score: float = 0.0
    risk_level: str  # critical, high, medium, low
    vulnerabilities: List[str] = []
    exposure_factors: List[str] = []


class OTRiskAssessmentResponse(BaseModel):
    """OT Risk Assessment Report Response"""

    timestamp: Optional[datetime] = None
    total_assets: int = 0
    critical_risk_assets: int = 0
    high_risk_assets: int = 0
    medium_risk_assets: int = 0
    asset_risks: List[AssetRisk] = []
    network_risks: List[Dict[str, Any]] = []
    compliance_risks: List[Dict[str, Any]] = []
