"""Stored system facts for SSPs and FedRAMP plans (wave 4).

Every fact here is read from the organisation's own rows or from the running
deployment's configuration. Anything the platform does not record (hosting
provider, authorisation boundary, named officials, ...) is returned as an
explicit ``[TO BE COMPLETED: ...]`` placeholder and listed in
``missing_facts``; nothing is filled in from a template describing some
other architecture.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger

logger = get_logger(__name__)

MAX_LISTED = 50


def placeholder(what: str) -> str:
    return f"[TO BE COMPLETED: {what}]"


def _scheme(url: Optional[str]) -> Optional[str]:
    if not url or "://" not in url:
        return None
    return url.split("://", 1)[0].split("+", 1)[0]


async def collect_system_facts(db: AsyncSession, org_id: str) -> dict[str, Any]:
    """Return the facts a security plan can state about this organisation's system."""
    from src.agents.models import EndpointAgent
    from src.compliance.models import ComplianceFramework
    from src.core.config import settings
    from src.integrations.models import InstalledIntegration
    from src.models.asset import Asset
    from src.models.organization import Organization
    from src.models.playbook import Playbook
    from src.models.user import User
    from src.remediation.models import RemediationPolicy
    from src.zerotrust.models import MicroSegment, ZeroTrustPolicy

    missing: list[str] = []

    def need(value: Any, what: str) -> Any:
        if value in (None, "", [], {}):
            missing.append(what)
            return placeholder(what)
        return value

    org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
    address_parts = [p for p in (
        getattr(org, "address", None), getattr(org, "city", None), getattr(org, "country", None)) if p]
    organization = {
        "id": org_id,
        "name": need(getattr(org, "name", None), "organisation name"),
        "description": need(getattr(org, "description", None), "organisation description"),
        "address": need(", ".join(address_parts) if address_parts else None, "organisation address"),
        "contact_email": need(getattr(org, "email", None), "organisation contact e-mail"),
        "website": getattr(org, "website", None),
    }

    users_by_role = {
        str(role): int(n) for role, n in (await db.execute(
            select(User.role, func.count(User.id))
            .where(User.organization_id == org_id, User.is_active.is_(True))
            .group_by(User.role),
        )).all()
    }
    mfa_users = int(await db.scalar(select(func.count(User.id)).where(
        User.organization_id == org_id, User.is_active.is_(True), User.mfa_enabled.is_(True))) or 0)

    agents_rows = (await db.execute(
        select(EndpointAgent.os_type, EndpointAgent.status, func.count(EndpointAgent.id))
        .where(EndpointAgent.organization_id == org_id)
        .group_by(EndpointAgent.os_type, EndpointAgent.status),
    )).all()
    agents = [{"os_type": os_type or "unknown", "status": status, "count": int(n)} for os_type, status, n in agents_rows]

    asset_rows = (await db.execute(
        select(Asset.asset_type, func.count(Asset.id)).where(Asset.organization_id == org_id).group_by(Asset.asset_type),
    )).all()
    assets_by_type = {str(t or "unknown"): int(n) for t, n in asset_rows}

    integrations = [
        {"name": r.display_name, "connector_id": r.connector_id, "status": r.status, "health": r.health_status}
        for r in (await db.execute(
            select(InstalledIntegration.display_name, InstalledIntegration.connector_id,
                   InstalledIntegration.status, InstalledIntegration.health_status)
            .where(InstalledIntegration.organization_id == org_id)
            .order_by(InstalledIntegration.display_name).limit(MAX_LISTED),
        )).all()
    ]

    zt_policies = [
        {"name": r.name, "enabled": bool(r.is_enabled)}
        for r in (await db.execute(
            select(ZeroTrustPolicy.name, ZeroTrustPolicy.is_enabled)
            .where(ZeroTrustPolicy.organization_id == org_id)
            .order_by(ZeroTrustPolicy.name).limit(MAX_LISTED),
        )).all()
    ]
    segments = int(await db.scalar(select(func.count(MicroSegment.id)).where(MicroSegment.organization_id == org_id)) or 0)
    playbooks = int(await db.scalar(select(func.count(Playbook.id)).where(
        Playbook.organization_id == org_id, Playbook.is_enabled.is_(True))) or 0)
    remediation_policies = int(await db.scalar(select(func.count(RemediationPolicy.id)).where(
        RemediationPolicy.organization_id == org_id, RemediationPolicy.is_enabled.is_(True))) or 0)
    frameworks = [
        r for r in (await db.execute(
            select(ComplianceFramework.short_name).where(
                ComplianceFramework.organization_id == org_id, ComplianceFramework.is_enabled.is_(True)),
        )).scalars().all()
    ]

    deployment = {
        "application": settings.app_name,
        "environment": settings.app_env,
        "database_engine": _scheme(settings.database_url),
        "cache_and_queue": _scheme(settings.redis_url),
        "task_queue": "celery" if settings.celery_broker_url else None,
        "field_encryption_configured": bool(getattr(settings, "encryption_master_key", None)),
    }
    hosting = {
        "provider": need(None, "hosting provider and region(s)"),
        "network_architecture": need(None, "network architecture and segmentation"),
        "authorization_boundary": need(None, "authorisation boundary description and diagram"),
    }
    roles = {
        "system_owner": need(None, "system owner (name and title)"),
        "authorizing_official": need(None, "authorising official"),
        "isso": need(None, "information system security officer"),
    }
    if not integrations:
        missing.append("external interconnections (no integrations are installed)")
    if not agents:
        missing.append("managed endpoints (no endpoint agents are enrolled)")

    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "organization": organization,
        "deployment": deployment,
        "hosting": hosting,
        "roles": roles,
        "users": {"active_by_role": users_by_role, "active_with_mfa": mfa_users},
        "endpoint_agents": agents,
        "assets_by_type": assets_by_type,
        "installed_integrations": integrations,
        "policies": {
            "zero_trust_policies": zt_policies,
            "micro_segments": segments,
            "enabled_playbooks": playbooks,
            "enabled_remediation_policies": remediation_policies,
        },
        "enabled_frameworks": frameworks,
        "missing_facts": missing,
        "basis": "read from this organisation's stored rows and the deployment configuration",
    }
