"""
OT/ICS Security Endpoints

API routes for OT asset management, threat monitoring, zone administration,
incident coordination, and compliance reporting.
"""

import math
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network
from typing import Annotated, Optional

from fastapi import Depends, APIRouter, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.models.user import User, UserRole
from src.core.config import settings
from src.core.logging import get_logger
from src.services.automation import AutomationService
from src.ot_security.models import (
    OTAsset,
    OTAlert,
    OTZone,
    OTIncident,
    OTPolicyRule,
)
from src.ot_security.netguard import check_discovery_target, internal_network_reason, parse_cidrs
from src.ot_security.engine import (
    MAX_DISCOVERY_PREFIX,
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
    AssetInventoryStats,
    AlertStats,
    ComplianceScores,
    AssetRisk,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/ot_security", tags=["OT Security"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


# Helper functions (tenant-scoped)
async def get_asset_or_404(db: AsyncSession, asset_id: str, org_id: str) -> OTAsset:
    """Get OT asset by ID or raise 404 (tenant-scoped)"""
    stmt = select(OTAsset).where(OTAsset.id == asset_id, OTAsset.organization_id == org_id)
    result = await db.execute(stmt)
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Asset not found",
        )
    return asset


async def get_alert_or_404(db: AsyncSession, alert_id: str, org_id: str) -> OTAlert:
    """Get OT alert by ID or raise 404 (tenant-scoped)"""
    stmt = select(OTAlert).where(OTAlert.id == alert_id, OTAlert.organization_id == org_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Alert not found",
        )
    return alert


async def get_zone_or_404(db: AsyncSession, zone_id: str, org_id: str) -> OTZone:
    """Get OT zone by ID or raise 404 (tenant-scoped)"""
    stmt = select(OTZone).where(OTZone.id == zone_id, OTZone.organization_id == org_id)
    result = await db.execute(stmt)
    zone = result.scalar_one_or_none()
    if not zone:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Zone not found",
        )
    return zone


async def get_incident_or_404(db: AsyncSession, incident_id: str, org_id: str) -> OTIncident:
    """Get OT incident by ID or raise 404 (tenant-scoped)"""
    stmt = select(OTIncident).where(OTIncident.id == incident_id, OTIncident.organization_id == org_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OT Incident not found",
        )
    return incident


async def get_policy_or_404(db: AsyncSession, policy_id: str, org_id: str) -> OTPolicyRule:
    """Get OT policy rule by ID or raise 404 (tenant-scoped)"""
    stmt = select(OTPolicyRule).where(OTPolicyRule.id == policy_id, OTPolicyRule.organization_id == org_id)
    result = await db.execute(stmt)
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
    org_id: OrganizationId,
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
    query = select(OTAsset).where(OTAsset.organization_id == org_id)

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
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT asset"""
    asset = OTAsset(
        organization_id=org_id,
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
async def get_asset(asset_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get OT asset by ID"""
    asset = await get_asset_or_404(db, asset_id, org_id)
    return OTAssetResponse.model_validate(asset)


@router.put("/assets/{asset_id}", response_model=OTAssetResponse)
async def update_asset(
    asset_id: str,
    asset_data: OTAssetUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update OT asset"""
    asset = await get_asset_or_404(db, asset_id, org_id)

    update_data = asset_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(asset, key, value)

    await db.commit()
    await db.refresh(asset)

    return OTAssetResponse.model_validate(asset)


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: str, org_id: OrganizationId, _user: AnalystUser = None, db: DatabaseSession = None
):
    """Delete OT asset"""
    asset = await get_asset_or_404(db, asset_id, org_id)
    await db.delete(asset)
    await db.commit()



def _validate_zone_cidr(raw: Optional[str]) -> Optional[str]:
    """Normalise a zone CIDR; 400 when unparseable or a platform-internal range."""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return ""
    try:
        net = ip_network(text, strict=False)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_zone_cidr", "field": "network_cidr", "detail": f"{raw}: {exc}"},
        ) from exc
    reason = internal_network_reason(net)
    if reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "zone_cidr_refused",
                "field": "network_cidr",
                "detail": f"{net} is a {reason} range and cannot be an OT zone",
            },
        )
    return str(net)


async def enforce_discovery_targets(db: AsyncSession, org_id: str, nets) -> None:
    """Refuse (403) any discovery target outside the platform allowlist, outside
    the tenant's OT zones, or inside a loopback/link-local/metadata range.
    Fails closed when the platform allowlist is empty or the tenant has no zone."""
    allowlist = parse_cidrs(settings.ot_discovery_allowed_cidrs)
    zone_cidrs = (
        await db.execute(select(OTZone.network_cidr).where(OTZone.organization_id == org_id))
    ).scalars().all()
    zones = parse_cidrs(zone_cidrs)
    for net in nets:
        refusal = check_discovery_target(net, allowlist, zones)
        if refusal is not None:
            logger.warning("ot_discover_refused", organization_id=org_id, cidr=str(net), error=refusal.error)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": refusal.error, "detail": refusal.detail},
            )


@router.post("/assets/{asset_id}/discover")
async def discover_asset_networks(
    asset_id: str,
    org_id: OrganizationId,
    current_user: AdminRoleUser = None,
    db: DatabaseSession = None,
    network_ranges: list[str] = Query([]),
):
    """Actively probe OT ports on the given network ranges (live-network scan).

    Admin only: the TCP sweep runs from the API host's network. Each range
    is passed to ``OTMonitor.discover_assets(network_range)`` (one CIDR per
    call). With no ``network_ranges`` the asset's own address is probed. When
    the organization has OT zones configured, every range must lie inside one
    of their ``network_cidr`` networks AND inside the platform allowlist
    ``OT_DISCOVERY_ALLOWED_CIDRS`` (same rule as ``/ot-security/discover``);
    loopback, link-local and metadata ranges are always refused.
    """
    asset = await get_asset_or_404(db, asset_id, org_id)

    ranges = list(network_ranges) or ([f"{asset.ip_address}/32"] if asset.ip_address else [])
    if not ranges:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "network_ranges_required",
                "field": "network_ranges",
                "detail": "the asset has no ip_address; pass at least one network_ranges CIDR",
            },
        )
    nets = []
    for raw in ranges:
        try:
            net = ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "invalid_cidr", "field": "network_ranges", "detail": f"{raw}: {exc}"},
            ) from exc
        if net.prefixlen < MAX_DISCOVERY_PREFIX:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "cidr_too_large",
                    "field": "network_ranges",
                    "detail": f"{raw} exceeds the /{MAX_DISCOVERY_PREFIX} safety cap",
                },
            )
        nets.append(net)

    await enforce_discovery_targets(db, org_id, nets)

    logger.info(
        "ot_asset_discover_requested",
        user_id=str(getattr(current_user, "id", "")),
        organization_id=org_id,
        asset_id=asset_id,
        ranges=[str(n) for n in nets],
    )

    monitor = OTMonitor(org_id)
    discovered: list[dict] = []
    status_label = "completed"
    error_message: Optional[str] = None
    for net in nets:
        try:
            result = await monitor.discover_assets(str(net))
        except Exception as exc:  # noqa: BLE001
            logger.error("ot_asset_discover_failed", organization_id=org_id, cidr=str(net), error=str(exc))
            status_label = "failed"
            error_message = str(exc)[:500]
            break
        if result and isinstance(result[0], dict) and result[0].get("status") in {"skipped", "rejected"}:
            status_label = str(result[0]["status"])
            error_message = result[0].get("reason")
            break
        discovered.extend(result)

    return {
        "asset_id": asset_id,
        "status": status_label,
        "network_ranges": [str(n) for n in nets],
        "discovered_count": len(discovered),
        "discovered": discovered[:50],
        "error": error_message,
    }


@router.get("/assets/{asset_id}/status")
async def get_asset_status(asset_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get current status of OT asset"""
    asset = await get_asset_or_404(db, asset_id, org_id)

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
async def get_asset_risk_assessment(asset_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get risk assessment for OT asset"""
    asset = await get_asset_or_404(db, asset_id, org_id)
    assessor = OTVulnerabilityAssessor(org_id)

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
async def check_asset_firmware(asset_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Check firmware version and vulnerabilities"""
    asset = await get_asset_or_404(db, asset_id, org_id)
    assessor = OTVulnerabilityAssessor(org_id)

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
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
):
    """List OT alerts with filtering and pagination"""
    query = select(OTAlert).where(OTAlert.organization_id == org_id)

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
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT alert"""
    # asset_id is a NOT NULL FK: it must name an asset of the caller's org
    # (an empty or foreign id used to become an IntegrityError 500).
    owned_asset = None
    if alert_data.asset_id:
        owned_asset = (
            await db.execute(
                select(OTAsset.id).where(OTAsset.id == alert_data.asset_id, OTAsset.organization_id == org_id)
            )
        ).scalar_one_or_none()
    if owned_asset is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_asset_id",
                "field": "asset_id",
                "detail": "asset_id must name an OT asset in your organization",
            },
        )
    alert = OTAlert(
        organization_id=org_id,
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

    # Trigger automation rules
    try:
        automation = AutomationService(db)
        await automation.on_ot_security_alert(
            asset_name=alert_data.asset_id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            organization_id=org_id,
        )
    except Exception as e:
        logger.error(f"Automation failed for OT alert {alert.id}: {e}")

    return OTAlertResponse.model_validate(alert)


@router.get("/alerts/{alert_id}", response_model=OTAlertResponse)
async def get_alert(alert_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get OT alert by ID"""
    alert = await get_alert_or_404(db, alert_id, org_id)
    return OTAlertResponse.model_validate(alert)


@router.put("/alerts/{alert_id}", response_model=OTAlertResponse)
async def update_alert(
    alert_id: str,
    alert_data: OTAlertUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update OT alert status"""
    alert = await get_alert_or_404(db, alert_id, org_id)

    update_data = alert_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(alert, key, value)

    await db.commit()
    await db.refresh(alert)

    return OTAlertResponse.model_validate(alert)


@router.post("/alerts/{alert_id}/investigate")
async def investigate_alert(
    alert_id: str, org_id: OrganizationId, _user: AnalystUser = None, db: DatabaseSession = None
):
    """Start investigation of OT alert"""
    alert = await get_alert_or_404(db, alert_id, org_id)
    alert.status = "investigating"

    await db.commit()
    await db.refresh(alert)

    return OTAlertResponse.model_validate(alert)


@router.post("/alerts/{alert_id}/respond")
async def respond_to_alert(
    alert_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    response_action: str = Query(...),
):
    """Record response action to alert"""
    alert = await get_alert_or_404(db, alert_id, org_id)
    alert.response_action = response_action
    alert.status = "contained"

    await db.commit()
    await db.refresh(alert)

    return OTAlertResponse.model_validate(alert)


@router.post("/alerts/bulk_action")
async def bulk_alert_action(
    org_id: OrganizationId,
    current_user: AdminRoleUser = None,
    db: DatabaseSession = None,
    alert_ids: list = Query(...),
    action: str = Query(...),
):
    """Perform bulk action on alerts in the caller's organization.

    Ids that do not exist in the caller's organization are not touched and
    are returned in ``ignored_ids``. Admin only (OT bulk action).
    """
    if action not in {"resolve", "dismiss"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_action", "field": "action", "detail": "action must be 'resolve' or 'dismiss'"},
        )
    result = await db.execute(
        select(OTAlert).where(OTAlert.id.in_(alert_ids), OTAlert.organization_id == org_id)
    )
    alerts = result.scalars().all()

    for alert in alerts:
        if action == "resolve":
            alert.status = "resolved"
        elif action == "dismiss":
            alert.status = "false_positive"

    await db.commit()

    updated_ids = {str(a.id) for a in alerts}
    ignored_ids = [str(i) for i in dict.fromkeys(alert_ids) if str(i) not in updated_ids]
    if ignored_ids:
        logger.warning(
            "ot_alert_bulk_action_ignored_ids",
            user_id=str(getattr(current_user, "id", "")),
            organization_id=org_id,
            ignored_count=len(ignored_ids),
        )

    return {
        "action": action,
        "alerts_updated": len(alerts),
        "ignored_ids": ignored_ids,
    }


# ===== OT ZONES =====


@router.get("/zones", response_model=OTZoneListResponse)
async def list_zones(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    purdue_level: Optional[str] = None,
):
    """List OT security zones"""
    query = select(OTZone).where(OTZone.organization_id == org_id)

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
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT security zone"""
    zone = OTZone(
        organization_id=org_id,
        name=zone_data.name,
        description=zone_data.description,
        purdue_level=zone_data.purdue_level,
        network_cidr=_validate_zone_cidr(zone_data.network_cidr),
        allowed_protocols=zone_data.allowed_protocols or [],
        allowed_communications=zone_data.allowed_communications or [],
    )

    db.add(zone)
    await db.commit()
    await db.refresh(zone)

    return OTZoneResponse.model_validate(zone)


@router.get("/zones/{zone_id}", response_model=OTZoneResponse)
async def get_zone(zone_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get OT zone by ID"""
    zone = await get_zone_or_404(db, zone_id, org_id)
    return OTZoneResponse.model_validate(zone)


@router.put("/zones/{zone_id}", response_model=OTZoneResponse)
async def update_zone(
    zone_id: str,
    zone_data: OTZoneUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update OT zone"""
    zone = await get_zone_or_404(db, zone_id, org_id)

    update_data = zone_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if key == "network_cidr":
            value = _validate_zone_cidr(value)
        setattr(zone, key, value)

    await db.commit()
    await db.refresh(zone)

    return OTZoneResponse.model_validate(zone)


@router.delete("/zones/{zone_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_zone(
    zone_id: str, org_id: OrganizationId, _user: AnalystUser = None, db: DatabaseSession = None
):
    """Delete OT zone"""
    zone = await get_zone_or_404(db, zone_id, org_id)
    await db.delete(zone)
    await db.commit()


@router.post("/zones/{zone_id}/compliance_check")
async def check_zone_compliance(zone_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Check zone compliance with Purdue model"""
    zone = await get_zone_or_404(db, zone_id, org_id)
    enforcer = PurdueModelEnforcer(org_id)

    report = await enforcer.generate_zone_compliance_report([zone.to_dict()])

    return report


@router.get("/zones/{zone_id}/communication_matrix")
async def get_zone_communication_matrix(zone_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get zone-to-zone communication policy matrix"""
    zone = await get_zone_or_404(db, zone_id, org_id)

    return {
        "zone_id": zone.id,
        "zone_name": zone.name,
        "allowed_communications": zone.allowed_communications,
        "allowed_protocols": zone.allowed_protocols,
    }


@router.post("/zones/{zone_id}/segmentation_audit")
async def audit_zone_segmentation(
    zone_id: str, org_id: OrganizationId, _user: AdminRoleUser = None, db: DatabaseSession = None
):
    """Audit network segmentation for zone: not implemented.

    This used to stamp ``segmentation_verified=True`` without auditing
    anything, which drove the UI's "Verified" badge. No firewall/flow data
    source exists yet, so it now returns an honest 501 and changes nothing.
    """
    await get_zone_or_404(db, zone_id, org_id)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": (
                "Segmentation auditing is not implemented: no firewall or flow data source is "
                "connected, so the zone's segmentation cannot be verified. Nothing was changed."
            ),
        },
    )


# ===== OT INCIDENTS =====


@router.get("/incidents", response_model=OTIncidentListResponse)
async def list_incidents(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
):
    """List OT incidents"""
    query = select(OTIncident).where(OTIncident.organization_id == org_id)

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
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT incident"""
    incident = OTIncident(
        organization_id=org_id,
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
async def get_incident(incident_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get OT incident by ID"""
    incident = await get_incident_or_404(db, incident_id, org_id)
    return OTIncidentResponse.model_validate(incident)


@router.put("/incidents/{incident_id}", response_model=OTIncidentResponse)
async def update_incident(
    incident_id: str,
    incident_data: OTIncidentUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Update OT incident"""
    incident = await get_incident_or_404(db, incident_id, org_id)

    update_data = incident_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(incident, key, value)

    await db.commit()
    await db.refresh(incident)

    return OTIncidentResponse.model_validate(incident)


@router.post("/incidents/{incident_id}/containment_strategy")
async def set_containment_strategy(
    incident_id: str,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    strategy: str = Query(...),
):
    """Set containment strategy for incident"""
    incident = await get_incident_or_404(db, incident_id, org_id)
    incident.containment_strategy = strategy
    incident.status = "containing"

    await db.commit()

    return {"incident_id": incident.id, "containment_strategy": strategy}


@router.post("/incidents/{incident_id}/safe_shutdown")
async def initiate_safe_shutdown(
    incident_id: str, org_id: OrganizationId, current_user: AdminRoleUser = None, db: DatabaseSession = None
):
    """Initiate safe shutdown for an incident: not implemented.

    This used to return a fixed step template with status "initiated" and set
    ``safe_shutdown_initiated=True`` although no PLC/SIS command was sent. No
    OT control integration exists, so it now returns an honest 501 and leaves
    the incident unchanged.
    """
    await get_incident_or_404(db, incident_id, org_id)
    logger.warning(
        "ot_safe_shutdown_not_implemented",
        user_id=str(getattr(current_user, "id", "")),
        organization_id=org_id,
        incident_id=incident_id,
    )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": (
                "Safe shutdown is not implemented: no PLC/SIS control integration is connected, so "
                "no shutdown command was sent and the incident was not marked as shut down. "
                "Follow the site's manual safe-shutdown procedure."
            ),
        },
    )


@router.get("/incidents/{incident_id}/post_incident")
async def get_post_incident_report(incident_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Generate post-incident report"""
    incident = await get_incident_or_404(db, incident_id, org_id)

    safety_mgr = SafetyManager(org_id)
    report = await safety_mgr.generate_safety_incident_report(incident.to_dict())

    return report


# ===== OT POLICIES =====


@router.get("/policies", response_model=OTPolicyListResponse)
async def list_policies(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    rule_type: Optional[str] = None,
    enabled_only: bool = False,
):
    """List OT policy rules"""
    query = select(OTPolicyRule).where(OTPolicyRule.organization_id == org_id)

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
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Create a new OT policy rule"""
    policy = OTPolicyRule(
        organization_id=org_id,
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
async def get_policy(policy_id: str, org_id: OrganizationId, db: DatabaseSession = None):
    """Get OT policy rule by ID"""
    policy = await get_policy_or_404(db, policy_id, org_id)
    return OTPolicyRuleResponse.model_validate(policy)


@router.put("/policies/{policy_id}", response_model=OTPolicyRuleResponse)
async def update_policy(
    policy_id: str,
    policy_data: OTPolicyRuleUpdate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Update OT policy rule"""
    policy = await get_policy_or_404(db, policy_id, org_id)

    update_data = policy_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(policy, key, value)

    await db.commit()
    await db.refresh(policy)

    return OTPolicyRuleResponse.model_validate(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str, org_id: OrganizationId, _user: AdminRoleUser = None, db: DatabaseSession = None
):
    """Delete OT policy rule"""
    policy = await get_policy_or_404(db, policy_id, org_id)
    await db.delete(policy)
    await db.commit()


@router.post("/policies/{policy_id}/enable")
async def enable_policy(
    policy_id: str, org_id: OrganizationId, _user: AdminRoleUser = None, db: DatabaseSession = None
):
    """Enable OT policy rule"""
    policy = await get_policy_or_404(db, policy_id, org_id)
    policy.enabled = True

    await db.commit()

    return OTPolicyRuleResponse.model_validate(policy)


@router.post("/policies/{policy_id}/disable")
async def disable_policy(
    policy_id: str, org_id: OrganizationId, _user: AdminRoleUser = None, db: DatabaseSession = None
):
    """Disable OT policy rule"""
    policy = await get_policy_or_404(db, policy_id, org_id)
    policy.enabled = False

    await db.commit()

    return OTPolicyRuleResponse.model_validate(policy)


@router.get("/policies/{policy_id}/violation_history")
async def get_policy_violation_history(
    policy_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    limit: int = Query(10, ge=1, le=100),
):
    """Get policy violation history"""
    policy = await get_policy_or_404(db, policy_id, org_id)

    return {
        "policy_id": policy.id,
        "rule_type": policy.rule_type,
        "violations_count": policy.violations_count,
        "last_violation": policy.last_violation,
    }


# ===== OT DASHBOARD =====


@router.get("/dashboard", response_model=OTDashboardResponse)
async def get_ot_dashboard(org_id: OrganizationId, db: DatabaseSession = None):
    """Get OT security dashboard"""
    now = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)

    # Get asset counts
    asset_result = await db.execute(
        select(func.count()).select_from(OTAsset).where(OTAsset.organization_id == org_id)
    )
    total_assets = asset_result.scalar() or 0

    online_result = await db.execute(
        select(func.count()).select_from(OTAsset).where(
            and_(OTAsset.organization_id == org_id, OTAsset.is_online == True)
        )
    )
    online_count = online_result.scalar() or 0

    # Get alert counts (real 24h windows, not //3 / //4)
    alert_result = await db.execute(
        select(func.count()).select_from(OTAlert).where(OTAlert.organization_id == org_id)
    )
    total_alerts = alert_result.scalar() or 0

    new_24h_result = await db.execute(
        select(func.count()).select_from(OTAlert).where(
            and_(
                OTAlert.organization_id == org_id,
                OTAlert.created_at >= window_24h,
            )
        )
    )
    new_alerts_24h = new_24h_result.scalar() or 0

    resolved_24h_result = await db.execute(
        select(func.count()).select_from(OTAlert).where(
            and_(
                OTAlert.organization_id == org_id,
                OTAlert.status.in_(["resolved", "contained", "false_positive"]),
                OTAlert.updated_at >= window_24h,
            )
        )
    )
    resolved_24h = resolved_24h_result.scalar() or 0

    # Get zone counts by level
    zones_result = await db.execute(
        select(OTZone).where(OTZone.organization_id == org_id)
    )
    zones = list(zones_result.scalars().all())

    zones_by_level: dict = {}
    for zone in zones:
        level = zone.purdue_level
        zones_by_level[level] = zones_by_level.get(level, 0) + 1

    # Real compliance score: share of zones with compliance_status == "compliant"
    compliant_zones = sum(1 for z in zones if z.compliance_status == "compliant")
    zone_compliance = (compliant_zones / len(zones)) if zones else 0.0

    # Firmware currency rate across assets
    firmware_current_result = await db.execute(
        select(func.count()).select_from(OTAsset).where(
            and_(OTAsset.organization_id == org_id, OTAsset.firmware_current == True)
        )
    )
    firmware_current_count = firmware_current_result.scalar() or 0
    firmware_score = (firmware_current_count / total_assets) if total_assets else 0.0

    overall_compliance = round((zone_compliance + firmware_score) / 2, 3) if (zones or total_assets) else 0.0

    return OTDashboardResponse(
        timestamp=now,
        asset_inventory=AssetInventoryStats(
            total_assets=total_assets,
            online_count=online_count,
            offline_count=total_assets - online_count,
        ),
        alert_summary=AlertStats(
            total_alerts=total_alerts,
            new_alerts_24h=new_alerts_24h,
            resolved_24h=resolved_24h,
        ),
        zones_by_level=zones_by_level,
        compliance_scores=ComplianceScores(
            overall=overall_compliance,
        ),
        purdue_model_visualization={
            "levels": zones_by_level,
            "segmentation_complete": len(zones_by_level) >= 4,
            "zone_compliance": round(zone_compliance, 3),
            "firmware_score": round(firmware_score, 3),
        },
    )


# Map Purdue string enum to numeric level
_PURDUE_LEVEL_NUMERIC = {
    "level0_process": 0,
    "level1_control": 1,
    "level2_supervisory": 2,
    "level3_operations": 3,
    "level3_5_dmz": 3,  # collapsed with ops for visualization
    "level4_enterprise": 4,
    "level5_internet": 5,
}


@router.get("/purdue-map")
async def get_purdue_map(org_id: OrganizationId, db: DatabaseSession = None):
    """Return asset devices grouped by numeric Purdue level for the visualization tab."""

    result = await db.execute(
        select(OTAsset).where(OTAsset.organization_id == org_id)
    )
    assets = list(result.scalars().all())

    buckets: dict = {lvl: [] for lvl in range(6)}
    for a in assets:
        lvl = _PURDUE_LEVEL_NUMERIC.get(a.purdue_level, 3)
        buckets[lvl].append(
            {
                "id": a.id,
                "name": a.name,
                "asset_type": a.asset_type,
                "type": a.asset_type,
                "ip_address": a.ip_address,
                "ipAddress": a.ip_address,
                "ip": a.ip_address,
                "vendor": a.vendor,
                "protocol": a.protocol,
                "zone": a.zone,
                "criticality": a.criticality,
                "is_online": a.is_online,
                "status": "online" if a.is_online else "offline",
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
        )

    levels = [
        {"level": lvl, "devices": buckets[lvl], "device_count": len(buckets[lvl])}
        for lvl in sorted(buckets.keys())
    ]
    total_devices = sum(len(v) for v in buckets.values())
    segmented = sum(1 for lvl, devs in buckets.items() if devs) >= 4

    return {
        "levels": levels,
        "total_devices": total_devices,
        "segmentation_complete": segmented,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ===== OT COMPLIANCE =====


@router.get("/compliance/report", response_model=ComplianceReportResponse)
async def get_compliance_report(org_id: OrganizationId, db: DatabaseSession = None):
    """Get comprehensive ICS compliance report"""

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
async def get_risk_assessment(org_id: OrganizationId, db: DatabaseSession = None):
    """Get OT risk assessment report"""

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
