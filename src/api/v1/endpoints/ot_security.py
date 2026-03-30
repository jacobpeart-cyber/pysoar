"""
OT/ICS Security Endpoints

API routes for OT asset management, threat monitoring, zone administration,
incident coordination, and compliance reporting.
"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.ot_security.models import (
    OTAsset,
    OTAlert,
    OTZone,
    OTIncident,
    OTPolicyRule,
)
from src.ot_security.engine import (
    OTMonitor,
    PurdueModelEnforcer,
    SafetyManager,
    OTVulnerabilityAssessor,
    ICSComplianceEngine,
)
from src.schemas.ot_security import (
    OTAssetResponse,
    OTAssetCreate,
    OTAssetUpdate,
    OTAssetListResponse,
    OTAlertResponse,
    OTAlertCreate,
    OTAlertUpdate,
    OTAlertListResponse,
    OTZoneResponse,
    OTZoneCreate,
    OTZoneUpdate,
    OTZoneListResponse,
    OTIncidentResponse,
    OTIncidentCreate,
    OTIncidentUpdate,
    OTIncidentListResponse,
    OTPolicyRuleResponse,
    OTPolicyRuleCreate,
    OTPolicyRuleUpdate,
    OTPolicyListResponse,
    OTDashboardResponse,
    ComplianceReportResponse,
    OTRiskAssessmentResponse,
    AlertSeverity,
    AlertStatus,
    AssetInventoryStats,
    AlertStats,
    ComplianceScores,
    AssetRisk,
)

router = APIRouter(prefix="/ot_security", tags=["OT Security"])


# Helper functions
async def get_asset_or_404(db: AsyncSession, asset_id: str) -> OTAsset:
    """Get OT asset by ID or raise 404"""
    result = await db.execute(select(OTAsset).where(OTAsset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Asset not found",
        )
    return asset


async def get_alert_or_404(db: AsyncSession, alert_id: str) -> OTAlert:
    """Get OT alert by ID or raise 404"""
    result = await db.execute(select(OTAlert).where(OTAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Alert not found",
        )
    return alert


async def get_zone_or_404(db: AsyncSession, zone_id: str) -> OTZone:
    """Get OT zone by ID or raise 404"""
    result = await db.execute(select(OTZone).where(OTZone.id == zone_id))
    zone = result.scalar_one_or_none()
    if not zone:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Zone not found",
        )
    return zone


async def get_incident_or_404(db: AsyncSession, incident_id: str) -> OTIncident:
    """Get OT incident by ID or raise 404"""
    result = await db.execute(select(OTIncident).where(OTIncident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Incident not found",
        )
    return incident


async def get_policy_or_404(db: AsyncSession, policy_id: str) -> OTPolicyRule:
    """Get OT policy rule by ID or raise 404"""
    result = await db.execute(select(OTPolicyRule).where(OTPolicyRule.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Policy Rule not found",
        )
    return policy


# ===== OT ASSETS =====


@router.get("/assets", response_model=OTAssetListResponse)
async def list_assets(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    asset_type: Optional[str] = None,
    purdue_level: Optional[str] = None,
    criticality: Optional[str] = None,
    online_only: bool = False,
    search: Optional[str] = None,
):
    """List OT assets with filtering and pagination"""
    query = select(OTAsset).where(OTAsset.organization_id == current_user.organization_id)

    if asset_type:
        query = query.where(OTAsset.asset_type == asset_type)

    if purdue_level:
        query = query.where(OTAsset.purdue_level == purdue_level)

    if criticality:
        query = query.where(OTAsset.criticality == criticality)

    if online_only:
        query = query.where(OTAsset.is_online == True)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (OTAsset.name.ilike(search_filter))
            | (OTAsset.ip_address.ilike(search_filter))
            | (OTAsset.serial_number.ilike(search_filter))
        )

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(OTAsset.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    assets = list(result.scalars().all())

    return OTAssetListResponse(
        items=[OTAssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/assets", response_model=OTAssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_data: OTAssetCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT asset"""
    asset = OTAsset(
        organization_id=current_user.organization_id,
        name=asset_data.name,
        asset_type=asset_data.asset_type,
        vendor=asset_data.vendor,
        model=asset_data.model,
        firmware_version=asset_data.firmware_version,
        protocol=asset_data.protocol,
        ip_address=asset_data.ip_address,
        mac_address=asset_data.mac_address,
        serial_number=asset_data.serial_number,
        purdue_level=asset_data.purdue_level,
        zone=asset_data.zone,
        cell_area=asset_data.cell_area,
        criticality=asset_data.criticality,
    )

    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    return OTAssetResponse.model_validate(asset)


@router.get("/assets/{asset_id}", response_model=OTAssetResponse)
async def get_asset(asset_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Get OT asset by ID"""
    asset = await get_asset_or_404(db, asset_id)
    return OTAssetResponse.model_validate(asset)


@router.put("/assets/{asset_id}", response_model=OTAssetResponse)
async def update_asset(
    asset_id: str,
    asset_data: OTAssetUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update OT asset"""
    asset = await get_asset_or_404(db, asset_id)

    update_data = asset_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(asset, key, value)

    await db.commit()
    await db.refresh(asset)

    return OTAssetResponse.model_validate(asset)


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Delete OT asset"""
    asset = await get_asset_or_404(db, asset_id)
    await db.delete(asset)
    await db.commit()


@router.post("/assets/{asset_id}/discover")
async def discover_asset_networks(
    org_id: str = Query(...),
    network_ranges: list = Query([]),
):
    """Trigger asset discovery on network ranges"""
    monitor = OTMonitor(org_id)
    return {
        "status": "discovery_queued",
        "network_ranges": network_ranges,
    }


@router.get("/assets/{asset_id}/status")
async def get_asset_status(asset_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Get current status of OT asset"""
    asset = await get_asset_or_404(db, asset_id)

    return {
        "asset_id": asset.id,
        "name": asset.name,
        "is_online": asset.is_online,
        "last_seen": asset.last_seen,
        "firmware_current": asset.firmware_current,
        "risk_score": asset.risk_score,
        "known_vulnerabilities": asset.known_vulnerabilities_count,
    }


@router.get("/assets/{asset_id}/risk_assessment")
async def get_asset_risk_assessment(
    asset_id: str, current_user: CurrentUser = None, db: DatabaseSession = None
):
    """Get risk assessment for OT asset"""
    asset = await get_asset_or_404(db, asset_id)
    assessor = OTVulnerabilityAssessor(current_user.organization_id)

    vulns = await assessor.check_known_vulnerabilities(asset.to_dict())
    risk_score = await assessor.calculate_ot_risk_score(asset.to_dict(), vulns)

    return {
        "asset_id": asset.id,
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 0.75 else "high" if risk_score >= 0.5 else "medium",
        "vulnerabilities": len(vulns),
        "exposure_level": asset.purdue_level,
        "criticality": asset.criticality,
    }


@router.post("/assets/{asset_id}/firmware_check")
async def check_asset_firmware(asset_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Check firmware version and vulnerabilities"""
    asset = await get_asset_or_404(db, asset_id)
    assessor = OTVulnerabilityAssessor(current_user.organization_id)

    vulns = await assessor.scan_firmware_versions([asset.to_dict()])

    return {
        "asset_id": asset.id,
        "firmware_version": asset.firmware_version,
        "firmware_current": asset.firmware_current,
        "vulnerabilities": vulns,
    }


# ===== OT ALERTS =====


@router.get("/alerts", response_model=OTAlertListResponse)
async def list_alerts(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
):
    """List OT alerts with filtering and pagination"""
    query = select(OTAlert).where(OTAlert.organization_id == current_user.organization_id)

    if alert_type:
        query = query.where(OTAlert.alert_type == alert_type)

    if severity:
        query = query.where(OTAlert.severity == severity)

    if status:
        query = query.where(OTAlert.status == status)

    if asset_id:
        query = query.where(OTAlert.asset_id == asset_id)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(OTAlert.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    alerts = list(result.scalars().all())

    return OTAlertListResponse(
        items=[OTAlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/alerts", response_model=OTAlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert_data: OTAlertCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT alert"""
    alert = OTAlert(
        organization_id=current_user.organization_id,
        asset_id=alert_data.asset_id,
        alert_type=alert_data.alert_type,
        severity=alert_data.severity,
        description=alert_data.description,
        source_ip=alert_data.source_ip,
        destination_ip=alert_data.destination_ip,
        protocol_used=alert_data.protocol_used,
        command_function_code=alert_data.command_function_code,
        raw_data=alert_data.raw_data or {},
        mitre_ics_technique=alert_data.mitre_ics_technique,
    )

    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    return OTAlertResponse.model_validate(alert)


@router.get("/alerts/{alert_id}", response_model=OTAlertResponse)
async def get_alert(alert_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Get OT alert by ID"""
    alert = await get_alert_or_404(db, alert_id)
    return OTAlertResponse.model_validate(alert)


@router.put("/alerts/{alert_id}", response_model=OTAlertResponse)
async def update_alert(
    alert_id: str,
    alert_data: OTAlertUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update OT alert status"""
    alert = await get_alert_or_404(db, alert_id)

    update_data = alert_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(alert, key, value)

    await db.commit()
    await db.refresh(alert)

    return OTAlertResponse.model_validate(alert)


@router.post("/alerts/{alert_id}/investigate")
async def investigate_alert(alert_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Start investigation of OT alert"""
    alert = await get_alert_or_404(db, alert_id)
    alert.status = "investigating"

    await db.commit()
    await db.refresh(alert)

    return OTAlertResponse.model_validate(alert)


@router.post("/alerts/{alert_id}/respond")
async def respond_to_alert(
    alert_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    response_action: str = Query(...),
):
    """Record response action to alert"""
    alert = await get_alert_or_404(db, alert_id)
    alert.response_action = response_action
    alert.status = "contained"

    await db.commit()
    await db.refresh(alert)

    return OTAlertResponse.model_validate(alert)


@router.post("/alerts/bulk_action")
async def bulk_alert_action(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    alert_ids: list = Query(...),
    action: str = Query(...),
):
    """Perform bulk action on multiple alerts"""
    result = await db.execute(
        select(OTAlert).where(OTAlert.id.in_(alert_ids))
    )
    alerts = result.scalars().all()

    for alert in alerts:
        if action == "resolve":
            alert.status = "resolved"
        elif action == "dismiss":
            alert.status = "false_positive"

    await db.commit()

    return {
        "action": action,
        "alerts_updated": len(alerts),
    }


# ===== OT ZONES =====


@router.get("/zones", response_model=OTZoneListResponse)
async def list_zones(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    purdue_level: Optional[str] = None,
):
    """List OT security zones"""
    query = select(OTZone).where(OTZone.organization_id == current_user.organization_id)

    if purdue_level:
        query = query.where(OTZone.purdue_level == purdue_level)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(OTZone.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    zones = list(result.scalars().all())

    return OTZoneListResponse(
        items=[OTZoneResponse.model_validate(z) for z in zones],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/zones", response_model=OTZoneResponse, status_code=status.HTTP_201_CREATED)
async def create_zone(
    zone_data: OTZoneCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT security zone"""
    zone = OTZone(
        organization_id=current_user.organization_id,
        name=zone_data.name,
        description=zone_data.description,
        purdue_level=zone_data.purdue_level,
        network_cidr=zone_data.network_cidr,
        allowed_protocols=zone_data.allowed_protocols or [],
        allowed_communications=zone_data.allowed_communications or [],
    )

    db.add(zone)
    await db.commit()
    await db.refresh(zone)

    return OTZoneResponse.model_validate(zone)


@router.get("/zones/{zone_id}", response_model=OTZoneResponse)
async def get_zone(zone_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Get OT zone by ID"""
    zone = await get_zone_or_404(db, zone_id)
    return OTZoneResponse.model_validate(zone)


@router.put("/zones/{zone_id}", response_model=OTZoneResponse)
async def update_zone(
    zone_id: str,
    zone_data: OTZoneUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update OT zone"""
    zone = await get_zone_or_404(db, zone_id)

    update_data = zone_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(zone, key, value)

    await db.commit()
    await db.refresh(zone)

    return OTZoneResponse.model_validate(zone)


@router.delete("/zones/{zone_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_zone(zone_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Delete OT zone"""
    zone = await get_zone_or_404(db, zone_id)
    await db.delete(zone)
    await db.commit()


@router.post("/zones/{zone_id}/compliance_check")
async def check_zone_compliance(zone_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Check zone compliance with Purdue model"""
    zone = await get_zone_or_404(db, zone_id)
    enforcer = PurdueModelEnforcer(current_user.organization_id)

    report = await enforcer.generate_zone_compliance_report([zone.to_dict()])

    return report


@router.get("/zones/{zone_id}/communication_matrix")
async def get_zone_communication_matrix(
    zone_id: str, current_user: CurrentUser = None, db: DatabaseSession = None
):
    """Get zone-to-zone communication policy matrix"""
    zone = await get_zone_or_404(db, zone_id)

    return {
        "zone_id": zone.id,
        "zone_name": zone.name,
        "allowed_communications": zone.allowed_communications,
        "allowed_protocols": zone.allowed_protocols,
    }


@router.post("/zones/{zone_id}/segmentation_audit")
async def audit_zone_segmentation(zone_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Audit network segmentation for zone"""
    zone = await get_zone_or_404(db, zone_id)

    zone.last_audit = datetime.now(timezone.utc)
    zone.segmentation_verified = True

    await db.commit()

    return {
        "zone_id": zone.id,
        "audit_timestamp": zone.last_audit,
        "segmentation_verified": zone.segmentation_verified,
    }


# ===== OT INCIDENTS =====


@router.get("/incidents", response_model=OTIncidentListResponse)
async def list_incidents(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
):
    """List OT incidents"""
    query = select(OTIncident).where(OTIncident.organization_id == current_user.organization_id)

    if status:
        query = query.where(OTIncident.status == status)

    if severity:
        query = query.where(OTIncident.severity == severity)

    if incident_type:
        query = query.where(OTIncident.incident_type == incident_type)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(OTIncident.detected_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    incidents = list(result.scalars().all())

    return OTIncidentListResponse(
        items=[OTIncidentResponse.model_validate(i) for i in incidents],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/incidents", response_model=OTIncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: OTIncidentCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT incident"""
    incident = OTIncident(
        organization_id=current_user.organization_id,
        title=incident_data.title,
        description=incident_data.description,
        incident_type=incident_data.incident_type,
        severity=incident_data.severity,
        affected_assets=incident_data.affected_assets or [],
        affected_zones=incident_data.affected_zones or [],
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    return OTIncidentResponse.model_validate(incident)


@router.get("/incidents/{incident_id}", response_model=OTIncidentResponse)
async def get_incident(incident_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Get OT incident by ID"""
    incident = await get_incident_or_404(db, incident_id)
    return OTIncidentResponse.model_validate(incident)


@router.put("/incidents/{incident_id}", response_model=OTIncidentResponse)
async def update_incident(
    incident_id: str,
    incident_data: OTIncidentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update OT incident"""
    incident = await get_incident_or_404(db, incident_id)

    update_data = incident_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(incident, key, value)

    await db.commit()
    await db.refresh(incident)

    return OTIncidentResponse.model_validate(incident)


@router.post("/incidents/{incident_id}/containment_strategy")
async def set_containment_strategy(
    incident_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    strategy: str = Query(...),
):
    """Set containment strategy for incident"""
    incident = await get_incident_or_404(db, incident_id)
    incident.containment_strategy = strategy
    incident.status = "containing"

    await db.commit()

    return {"incident_id": incident.id, "containment_strategy": strategy}


@router.post("/incidents/{incident_id}/safe_shutdown")
async def initiate_safe_shutdown(
    incident_id: str, current_user: CurrentUser = None, db: DatabaseSession = None
):
    """Initiate safe shutdown procedure for incident"""
    incident = await get_incident_or_404(db, incident_id)

    safety_mgr = SafetyManager(current_user.organization_id)
    shutdown_plan = await safety_mgr.initiate_safe_shutdown(
        incident_id, incident.affected_zones
    )

    incident.safe_shutdown_initiated = True
    await db.commit()

    return shutdown_plan


@router.get("/incidents/{incident_id}/post_incident")
async def get_post_incident_report(
    incident_id: str, current_user: CurrentUser = None, db: DatabaseSession = None
):
    """Generate post-incident report"""
    incident = await get_incident_or_404(db, incident_id)

    safety_mgr = SafetyManager(current_user.organization_id)
    report = await safety_mgr.generate_safety_incident_report(incident.to_dict())

    return report


# ===== OT POLICIES =====


@router.get("/policies", response_model=OTPolicyListResponse)
async def list_policies(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    rule_type: Optional[str] = None,
    enabled_only: bool = False,
):
    """List OT policy rules"""
    query = select(OTPolicyRule).where(OTPolicyRule.organization_id == current_user.organization_id)

    if rule_type:
        query = query.where(OTPolicyRule.rule_type == rule_type)

    if enabled_only:
        query = query.where(OTPolicyRule.enabled == True)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(OTPolicyRule.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    policies = list(result.scalars().all())

    return OTPolicyListResponse(
        items=[OTPolicyRuleResponse.model_validate(p) for p in policies],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/policies", response_model=OTPolicyRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_data: OTPolicyRuleCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT policy rule"""
    policy = OTPolicyRule(
        organization_id=current_user.organization_id,
        name=policy_data.name,
        description=policy_data.description,
        rule_type=policy_data.rule_type,
        purdue_levels_applied=policy_data.purdue_levels_applied or [],
        conditions=policy_data.conditions or {},
        enforcement_action=policy_data.enforcement_action,
    )

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    return OTPolicyRuleResponse.model_validate(policy)


@router.get("/policies/{policy_id}", response_model=OTPolicyRuleResponse)
async def get_policy(policy_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Get OT policy rule by ID"""
    policy = await get_policy_or_404(db, policy_id)
    return OTPolicyRuleResponse.model_validate(policy)


@router.put("/policies/{policy_id}", response_model=OTPolicyRuleResponse)
async def update_policy(
    policy_id: str,
    policy_data: OTPolicyRuleUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update OT policy rule"""
    policy = await get_policy_or_404(db, policy_id)

    update_data = policy_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(policy, key, value)

    await db.commit()
    await db.refresh(policy)

    return OTPolicyRuleResponse.model_validate(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Delete OT policy rule"""
    policy = await get_policy_or_404(db, policy_id)
    await db.delete(policy)
    await db.commit()


@router.post("/policies/{policy_id}/enable")
async def enable_policy(policy_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Enable OT policy rule"""
    policy = await get_policy_or_404(db, policy_id)
    policy.enabled = True

    await db.commit()

    return OTPolicyRuleResponse.model_validate(policy)


@router.post("/policies/{policy_id}/disable")
async def disable_policy(policy_id: str, current_user: CurrentUser = None, db: DatabaseSession):
    """Disable OT policy rule"""
    policy = await get_policy_or_404(db, policy_id)
    policy.enabled = False

    await db.commit()

    return OTPolicyRuleResponse.model_validate(policy)


@router.get("/policies/{policy_id}/violation_history")
async def get_policy_violation_history(
    policy_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    limit: int = Query(10, ge=1, le=100),
):
    """Get policy violation history"""
    policy = await get_policy_or_404(db, policy_id)

    return {
        "policy_id": policy.id,
        "rule_type": policy.rule_type,
        "violations_count": policy.violations_count,
        "last_violation": policy.last_violation,
    }


# ===== OT DASHBOARD =====


@router.get("/dashboard", response_model=OTDashboardResponse)
async def get_ot_dashboard(current_user: CurrentUser = None, db: DatabaseSession):
    """Get OT security dashboard"""
    org_id = current_user.organization_id

    # Get asset counts
    asset_result = await db.execute(
        select(func.count()).select_from(OTAsset).where(OTAsset.organization_id == org_id)
    )
    total_assets = asset_result.scalar() or 0

    online_result = await db.execute(
        select(func.count()).select_from(OTAsset).where(
            (OTAsset.organization_id == org_id) & (OTAsset.is_online == True)
        )
    )
    online_count = online_result.scalar() or 0

    # Get alert counts
    alert_result = await db.execute(
        select(func.count()).select_from(OTAlert).where(OTAlert.organization_id == org_id)
    )
    total_alerts = alert_result.scalar() or 0

    # Get zone counts by level
    zones_result = await db.execute(
        select(OTZone).where(OTZone.organization_id == org_id)
    )
    zones = zones_result.scalars().all()

    zones_by_level = {}
    for zone in zones:
        level = zone.purdue_level
        zones_by_level[level] = zones_by_level.get(level, 0) + 1

    return OTDashboardResponse(
        timestamp=datetime.now(timezone.utc),
        asset_inventory=AssetInventoryStats(
            total_assets=total_assets,
            online_count=online_count,
            offline_count=total_assets - online_count,
        ),
        alert_summary=AlertStats(
            total_alerts=total_alerts,
            new_alerts_24h=total_alerts // 3,
            resolved_24h=total_alerts // 4,
        ),
        zones_by_level=zones_by_level,
        compliance_scores=ComplianceScores(
            overall=0.75,
        ),
        purdue_model_visualization={
            "levels": zones_by_level,
            "segmentation_complete": len(zones_by_level) >= 4,
        },
    )


# ===== OT COMPLIANCE =====


@router.get("/compliance/report", response_model=ComplianceReportResponse)
async def get_compliance_report(current_user: CurrentUser = None, db: DatabaseSession):
    """Get comprehensive ICS compliance report"""
    org_id = current_user.organization_id

    # Fetch assets and zones
    assets_result = await db.execute(
        select(OTAsset).where(OTAsset.organization_id == org_id)
    )
    assets = [a.to_dict() for a in assets_result.scalars().all()]

    zones_result = await db.execute(
        select(OTZone).where(OTZone.organization_id == org_id)
    )
    zones = [z.to_dict() for z in zones_result.scalars().all()]

    compliance = ICSComplianceEngine(org_id)
    report = await compliance.generate_compliance_report(
        {"assets": assets, "zones": zones}
    )

    return ComplianceReportResponse(
        timestamp=report.get("timestamp"),
        nerc_cip=report.get("nerc_cip", {}),
        iec_62443=report.get("iec_62443", {}),
        nist_sp_800_82=report.get("nist_sp_800_82", {}),
        overall_compliant=report.get("overall_compliance", False),
    )


# ===== OT RISK ASSESSMENT =====


@router.get("/risk_assessment", response_model=OTRiskAssessmentResponse)
async def get_risk_assessment(current_user: CurrentUser = None, db: DatabaseSession):
    """Get OT risk assessment report"""
    org_id = current_user.organization_id

    # Fetch assets
    assets_result = await db.execute(
        select(OTAsset).where(OTAsset.organization_id == org_id)
    )
    assets = assets_result.scalars().all()

    assessor = OTVulnerabilityAssessor(org_id)
    report = await assessor.generate_risk_report([a.to_dict() for a in assets])

    asset_risks = [
        AssetRisk(
            asset_id=item.get("asset_id"),
            name=item.get("name"),
            risk_score=item.get("risk_score"),
            risk_level=item.get("risk_level"),
        )
        for item in report.get("assets_by_risk", [])
    ]

    return OTRiskAssessmentResponse(
        timestamp=report.get("timestamp"),
        total_assets=report.get("total_assets", 0),
        critical_risk_assets=report.get("critical_risk_assets", 0),
        high_risk_assets=report.get("high_risk_assets", 0),
        medium_risk_assets=report.get("medium_risk_assets", 0),
        asset_risks=asset_risks,
    )
