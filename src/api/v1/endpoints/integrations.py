"""Integration marketplace and connector management endpoints.

The connector catalogue is derived from the connector classes
(src/integrations/connectors/): a connector with a class is ``implemented``
and declares its actions, config / credential fields and read-only test
call; the other catalogue entries are ``planned`` (install, test and execute
answer 501 ``not_implemented``) or ``log_ingest`` (installable SIEM log
sources with no actions).
"""

import json
import math
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Path, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
# Credential envelope helpers live in src.core.secrets (design v2 section 10);
# re-exported here because settings.py, main.py and siem/cloud_poller.py
# import them from this module.
from src.core.secrets import _decrypt_secret_json, _encrypt_secret_json  # noqa: F401
from src.core.security import get_password_hash
from src.core.utils import safe_json_loads
from src.integrations.connectors.base import sanitize_message, validate_params
from src.integrations.engine import (
    IMPLEMENTED,
    LOG_INGEST,
    PLANNED,
    ActionExecutor,
    ConnectorRegistry,
    IntegrationManager,
    connector_class,
    implementation_status,
    installed_connector_name,
    invalid_install_fields,
    missing_install_fields,
    probe_connector,
    record_health,
    sync_connector_actions,
)
from src.models.audit import AuditLog
from src.models.user import UserRole
from src.integrations.models import (
    HealthStatus,
    IntegrationAction,
    IntegrationConnector,
    IntegrationExecution,
    InstalledIntegration,
    WebhookEndpoint,
)
from src.schemas.integrations import (
    ActionExecutionRequest,
    ConnectorListResponse,
    ConnectorResponse,
    DashboardExecutionStatsResponse,
    DashboardIntegrationHealthResponse,
    DashboardSummaryResponse,
    ErrorRateMetric,
    ExecutionHistoryListResponse,
    ExecutionStatistics,
    IntegrationActionListResponse,
    IntegrationActionResponse,
    IntegrationExecutionResponse,
    IntegrationInstallRequest,
    IntegrationStatusResponse,
    IntegrationTestResponse,
    InstalledIntegrationListResponse,
    InstalledIntegrationResponse,
    InstalledIntegrationUpdate,
    TopConnectorUsage,
    WebhookListResponse,
    WebhookRegisterRequest,
    WebhookResponse,
    WebhookTestRequest,
    WebhookTestResponse,
)

router = APIRouter(prefix="/integrations", tags=["Integrations"])

# Role gates (wave 1). The connector catalogue is a global, read-only
# registry; installed integrations, executions and webhooks are tenant-owned.
# Install / uninstall / configure / credential updates / enable / disable and
# webhook registration are configuration (admin); running actions and
# connection tests are operational (analyst+); viewers are read-only.
_ADMIN = Depends(require_role([UserRole.ADMIN]))
_ANALYST = Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))

# Shared instances (in production, use dependency injection)
registry = ConnectorRegistry()
manager = IntegrationManager(registry)
executor = ActionExecutor()


def _not_implemented(display_name: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": f"{display_name} has no connector implementation in this release",
        },
    )


def _display_name(connector_name: str) -> str:
    meta = registry.get_connector_details(connector_name) or {}
    return meta.get("display_name") or connector_name


def _audit(
    db: AsyncSession,
    *,
    user: Any,
    org_id: str,
    action: str,
    resource_id: Optional[str],
    description: str,
    details: Optional[dict[str, Any]] = None,
    success: bool = True,
    error: Optional[str] = None,
) -> None:
    """Stage an AuditLog row (committed with the handler's transaction).

    ``details`` never carries credential values: callers pass field names.
    """
    db.add(AuditLog(
        user_id=getattr(user, "id", None),
        organization_id=org_id,
        action=action,
        resource_type="integration",
        resource_id=resource_id,
        description=description[:4000],
        new_value=json.dumps(details or {}, default=str)[:20000],
        success=success,
        error_message=error,
    ))


def _field_problem(error: str, fields: list[str], message: str) -> HTTPException:
    """422 naming the fields, never their values."""
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"error": error, "fields": sorted(set(fields)), "detail": message},
    )


def _validate_install_payload(connector_name: str, config: dict[str, Any], credentials: dict[str, Any]) -> None:
    missing = missing_install_fields(connector_name, config, credentials)
    if missing:
        raise _field_problem("missing_fields", missing, "required config / credential fields are missing")
    invalid = invalid_install_fields(connector_name, config, credentials)
    if invalid:
        raise _field_problem("invalid_fields", invalid, "config / credential fields have an invalid format")


async def _ensure_connector_row(db: AsyncSession, connector_name: str, meta: dict[str, Any]) -> None:
    """The installed_integrations FK needs the catalogue row; create it from the registry if absent."""
    existing = (
        await db.execute(select(IntegrationConnector.id).where(IntegrationConnector.id == connector_name))
    ).scalar_one_or_none()
    if existing is not None:
        return
    category = meta.get("category")
    auth_type = meta.get("auth_type")
    db.add(IntegrationConnector(
        id=connector_name,
        name=connector_name,
        display_name=meta.get("display_name") or connector_name,
        description=meta.get("description") or None,
        vendor=meta.get("vendor") or None,
        category=getattr(category, "value", category) or "threat_intel",
        version=meta.get("version", "1.0.0"),
        supported_actions=json.dumps(meta.get("supported_actions") or []),
        supported_triggers=json.dumps(meta.get("supported_triggers") or []),
        auth_type=getattr(auth_type, "value", auth_type) or "api_key",
        config_schema=meta.get("config_schema") or "{}",
        is_builtin=True,
        is_community=False,
    ))
    await db.flush()


async def _org_install_counts(db: AsyncSession, org_id: Optional[str]) -> dict[str, int]:
    """Installs per connector name for the caller's organisation (no organisation: none)."""
    rows = (
        await db.execute(
            select(IntegrationConnector.name, func.count(InstalledIntegration.id))
            .join(IntegrationConnector, IntegrationConnector.id == InstalledIntegration.connector_id)
            .where(InstalledIntegration.organization_id == org_id)
            .group_by(IntegrationConnector.name)
        )
    ).all()
    return {str(name).lower(): int(count) for name, count in rows}


def _connector_response(meta: dict[str, Any], install_count: int) -> ConnectorResponse:
    category = meta.get("category", "")
    auth_type = meta.get("auth_type", "")
    return ConnectorResponse(
        id=meta.get("name", ""),
        name=meta.get("name", ""),
        display_name=meta.get("display_name", ""),
        description=meta.get("description"),
        vendor=meta.get("vendor"),
        category=getattr(category, "value", category),
        version=meta.get("version", "1.0.0"),
        auth_type=getattr(auth_type, "value", auth_type),
        supported_actions=meta.get("supported_actions", []),
        supported_triggers=meta.get("supported_triggers", []),
        icon_url=None,
        documentation_url=None,
        config_schema=safe_json_loads(meta.get("config_schema"), {}) if isinstance(meta.get("config_schema"), str) else (meta.get("config_schema") or {}),
        is_builtin=meta.get("is_builtin", False),
        # Not marketplace statistics (see ConnectorResponse).
        is_community=False,
        rating=None,
        install_count=install_count,
        last_updated=None,
        integration_role=meta.get("integration_role"),
        implementation_status=meta.get("implementation_status", PLANNED),
        installable=bool(meta.get("installable")),
        verification=meta.get("verification", ""),
        test_call=meta.get("test_call"),
        config_fields=meta.get("config_fields") or [],
        credential_fields=meta.get("credential_fields") or [],
        actions=meta.get("actions") or [],
        created_at=None,
        updated_at=None,
    )


def _installed_response(i: InstalledIntegration) -> InstalledIntegrationResponse:
    """Installed-integration view; a planned connector's row reads ``unavailable``."""
    connector_name = installed_connector_name(i)
    health = i.health_status
    if implementation_status(connector_name) == PLANNED:
        health = HealthStatus.UNAVAILABLE.value
    return InstalledIntegrationResponse(
        id=i.id,
        connector_id=i.connector_id,
        display_name=i.display_name,
        config={},
        status=i.status,
        health_status=health,
        last_health_check=i.last_health_check,
        last_successful_action=i.last_successful_action,
        error_message=i.error_message,
        rate_limit_remaining=i.rate_limit_remaining,
        rate_limit_reset=i.rate_limit_reset,
        created_at=i.created_at,
        updated_at=i.updated_at,
    )


# Helper functions
async def get_installed_integration_or_404(
    db: AsyncSession,
    integration_id: str,
    org_id: str,
) -> InstalledIntegration:
    """Get the caller's installed integration by ID; another tenant's is a 404."""
    stmt = (
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(
            InstalledIntegration.id == integration_id,
            InstalledIntegration.organization_id == org_id,
        )
    )
    result = await db.execute(stmt)
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found",
        )
    return integration


async def get_action_or_404(
    db: AsyncSession,
    action_id: str,
    connector_id: Optional[str] = None,
) -> IntegrationAction:
    """Get action by ID or raise 404.

    IntegrationAction is a global, connector-scoped definition with no
    own ``organization_id`` column. Tenant isolation is enforced by the
    caller resolving the action through an org-scoped InstalledIntegration
    and passing that integration's ``connector_id`` here, so an action
    belonging to a different connector can't be executed against this
    install.
    """
    stmt = select(IntegrationAction).where(IntegrationAction.id == action_id)
    if connector_id is not None:
        stmt = stmt.where(IntegrationAction.connector_id == connector_id)
    result = await db.execute(stmt)
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action not found",
        )
    return action


# Marketplace endpoints
@router.get("/connectors", response_model=ConnectorListResponse)
async def list_connectors(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    category: Optional[str] = None,
    search: Optional[str] = None,
    implementation: Optional[str] = Query(None, pattern="^(implemented|planned|log_ingest)$"),
):
    """List the connector catalogue (implemented, log-ingest and planned entries)."""
    connectors = registry.list_connectors(
        category=category,
        search=search,
        limit=size * 10,
    )
    if implementation:
        connectors = [c for c in connectors if c.get("implementation_status") == implementation]

    # Apply pagination
    total = len(connectors)
    start = (page - 1) * size
    end = start + size
    page_connectors = connectors[start:end]

    counts = await _org_install_counts(db, current_user.organization_id)
    items = [_connector_response(meta, counts.get(meta.get("name", ""), 0)) for meta in page_connectors]

    pages = math.ceil(total / size) if total > 0 else 1

    return ConnectorListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/connectors/{connector_name}")
async def get_connector_details(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    connector_name: str = Path(...),
):
    """Get detailed information about a specific connector"""
    connector_meta = registry.get_connector_details(connector_name)
    if not connector_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found",
        )
    counts = await _org_install_counts(db, current_user.organization_id)
    return _connector_response(connector_meta, counts.get(connector_name, 0))


# Installed integrations endpoints
@router.post(
    "/install",
    response_model=InstalledIntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[_ADMIN],
)
async def install_connector(
    request: IntegrationInstallRequest,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Install a connector.

    501 ``not_implemented`` for a planned connector; 422 ``missing_fields`` /
    ``invalid_fields`` naming the config or credential fields (never their
    values). Credentials are stored AES-256-GCM encrypted and never returned.
    The connector's declared actions are mirrored into ``integration_actions``.
    """
    connector_name = (request.connector_id or "").lower()
    connector_meta = registry.get_connector_details(connector_name)
    if not connector_meta:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Connector not found: {request.connector_id}",
        )
    if not connector_meta.get("installable"):
        raise _not_implemented(connector_meta.get("display_name") or connector_name)

    config = dict(request.config or {})
    credentials = dict(request.credentials or {})
    _validate_install_payload(connector_name, config, credentials)

    # Check if already installed
    result = await db.execute(
        select(InstalledIntegration).where(
            and_(
                InstalledIntegration.organization_id == org_id,
                InstalledIntegration.connector_id == connector_name,
            ),
        ),
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connector already installed",
        )

    await _ensure_connector_row(db, connector_name, connector_meta)
    installation = InstalledIntegration(
        organization_id=org_id,
        connector_id=connector_name,
        display_name=request.display_name,
        config_encrypted=json.dumps(config),  # non-secret
        auth_credentials_encrypted=_encrypt_secret_json(credentials),
    )
    db.add(installation)
    await db.flush()
    await sync_connector_actions(db, connector_name, connector_name)
    _audit(
        db, user=current_user, org_id=org_id, action="integration_install", resource_id=installation.id,
        description=f"installed {connector_name}",
        details={"connector": connector_name, "config_fields": sorted(config), "credential_fields": sorted(credentials)},
    )
    await db.commit()

    integration = await get_installed_integration_or_404(db, installation.id, org_id)
    return _installed_response(integration)


@router.get("/installed", response_model=InstalledIntegrationListResponse)
async def list_installed_integrations(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    connector_category: Optional[str] = Query(None, alias="category"),
):
    """List installed integrations"""
    query = select(InstalledIntegration).options(
        selectinload(InstalledIntegration.connector),
    )

    # Filter by organization
    query = query.where(InstalledIntegration.organization_id == org_id)

    # Apply status filter
    if status:
        query = query.where(InstalledIntegration.status == status)

    # Apply category filter
    if connector_category:
        query = query.where(InstalledIntegration.connector.has(
            category=connector_category,
        ))

    # Get total count
    count_query = select(func.count()).select_from(
        select(InstalledIntegration.id).where(query.whereclause),
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(InstalledIntegration.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    integrations = list(result.scalars().all())

    items = [_installed_response(i) for i in integrations]

    pages = math.ceil(total / size) if total > 0 else 1

    return InstalledIntegrationListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/installed/{integration_id}", response_model=InstalledIntegrationResponse)
async def get_installed_integration(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Get details of installed integration"""
    integration = await get_installed_integration_or_404(db, integration_id, org_id)
    return _installed_response(integration)


@router.patch("/installed/{integration_id}", response_model=InstalledIntegrationResponse, dependencies=[_ADMIN])
async def update_installed_integration(
    request: InstalledIntegrationUpdate,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    integration_id: str = Path(...),
):
    """Update installed integration configuration.

    ``config`` and ``credentials`` are merged over the stored values (so a
    secret can be rotated without resending the others, which are never
    returned) and the result must still carry every required field: 422
    ``missing_fields`` / ``invalid_fields`` otherwise, naming fields only.
    """
    integration = await get_installed_integration_or_404(db, integration_id, org_id)
    connector_name = installed_connector_name(integration)

    changed: list[str] = []
    if request.display_name:
        integration.display_name = request.display_name
        changed.append("display_name")
    if request.config is not None or request.credentials is not None:
        stored_config = safe_json_loads(integration.config_encrypted, {}) or {}
        stored_credentials = _decrypt_secret_json(integration.auth_credentials_encrypted) or {}
        config = {**(stored_config if isinstance(stored_config, dict) else {}), **(request.config or {})}
        credentials = {**stored_credentials, **(request.credentials or {})}
        if implementation_status(connector_name) != PLANNED:
            _validate_install_payload(connector_name, config, credentials)
        integration.config_encrypted = json.dumps(config)
        integration.auth_credentials_encrypted = _encrypt_secret_json(credentials)
        changed += [f"config.{k}" for k in sorted(request.config or {})]
        changed += [f"credentials.{k}" for k in sorted(request.credentials or {})]
        if request.credentials:
            # New credentials invalidate the last verdict until the next test.
            integration.health_status = HealthStatus.UNKNOWN.value

    _audit(
        db, user=current_user, org_id=org_id, action="integration_update", resource_id=integration.id,
        description=f"updated {connector_name}", details={"connector": connector_name, "changed": changed},
    )
    await db.commit()
    integration = await get_installed_integration_or_404(db, integration_id, org_id)
    return _installed_response(integration)


@router.post("/installed/{integration_id}/test", response_model=IntegrationTestResponse, dependencies=[_ANALYST])
async def test_integration(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    integration_id: str = Path(...),
):
    """Test the connection with the connector's own authenticated read-only call.

    The call (``details.checked``) goes through the pinned transport with TLS
    verification on; a target that resolves to an internal address is refused
    and recorded ``unhealthy``. ``health_status``, ``last_health_check`` and a
    sanitised ``error_message`` are persisted. 501 for a planned connector
    and for a log-ingest source (its poller records health).
    """
    integration = await get_installed_integration_or_404(db, integration_id, org_id)
    connector_name = installed_connector_name(integration)
    impl = implementation_status(connector_name)
    if impl == PLANNED:
        raise _not_implemented(_display_name(connector_name))
    if impl == LOG_INGEST:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={
                "error": "not_implemented",
                "detail": f"{_display_name(connector_name)} has no connection test; the SIEM cloud poller records health_status on every poll",
            },
        )

    config = safe_json_loads(integration.config_encrypted, {}) or {}
    credentials = _decrypt_secret_json(integration.auth_credentials_encrypted) or {}
    result = await probe_connector(connector_name, config if isinstance(config, dict) else {}, credentials)
    record_health(integration, result)
    _audit(
        db, user=current_user, org_id=org_id, action="integration_test", resource_id=integration.id,
        description=f"connection test of {connector_name}: {result.status}",
        details={"connector": connector_name, "checked": result.checked, "http_status": result.http_status},
        success=result.healthy, error=None if result.healthy else integration.error_message,
    )
    await db.commit()

    return IntegrationTestResponse(
        status=result.status,
        message=result.detail,
        details={
            "connector": connector_name,
            "checked": result.checked,
            "http_status": result.http_status,
            "implementation_status": IMPLEMENTED,
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/installed/{integration_id}/enable", response_model=IntegrationStatusResponse, dependencies=[_ADMIN])
async def enable_integration(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Enable integration"""
    integration = await get_installed_integration_or_404(db, integration_id, org_id)

    integration.status = "active"
    await db.commit()
    await db.refresh(integration)

    return IntegrationStatusResponse(
        id=integration.id,
        status=integration.status,
        health_status=integration.health_status,
        last_health_check=integration.last_health_check,
        connected=integration.status == "active",
        error_message=integration.error_message,
        timestamp="",
    )


@router.post("/installed/{integration_id}/disable", response_model=IntegrationStatusResponse, dependencies=[_ADMIN])
async def disable_integration(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Disable integration"""
    integration = await get_installed_integration_or_404(db, integration_id, org_id)

    integration.status = "inactive"
    await db.commit()
    await db.refresh(integration)

    return IntegrationStatusResponse(
        id=integration.id,
        status=integration.status,
        health_status=integration.health_status,
        last_health_check=integration.last_health_check,
        connected=False,
        error_message=integration.error_message,
        timestamp="",
    )


@router.delete("/installed/{integration_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[_ADMIN])
async def uninstall_integration(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    integration_id: str = Path(...),
):
    """Uninstall integration (works for planned connectors too)."""
    integration = await get_installed_integration_or_404(db, integration_id, org_id)
    connector_name = installed_connector_name(integration)
    _audit(
        db, user=current_user, org_id=org_id, action="integration_uninstall", resource_id=integration.id,
        description=f"uninstalled {connector_name}", details={"connector": connector_name},
    )
    await db.delete(integration)
    await db.commit()


# Action endpoints
@router.get("/installed/{integration_id}/actions", response_model=IntegrationActionListResponse)
async def list_integration_actions(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List the actions the integration's connector class declares (none for a planned connector)."""
    integration = await get_installed_integration_or_404(db, integration_id, org_id)
    cls = connector_class(installed_connector_name(integration))
    declared = list(cls.ACTIONS) if cls is not None else []

    if declared:
        present = (
            await db.execute(
                select(func.count(IntegrationAction.id)).where(
                    IntegrationAction.connector_id == integration.connector_id,
                    IntegrationAction.action_name.in_(declared),
                )
            )
        ).scalar() or 0
        if present < len(declared):
            # Installs that predate the action mirror get their rows now.
            await sync_connector_actions(db, integration.connector_id, installed_connector_name(integration))
            await db.commit()

    query = select(IntegrationAction).where(
        IntegrationAction.connector_id == integration.connector_id,
        IntegrationAction.action_name.in_(declared),
    )

    # Get total count
    count_query = select(func.count()).select_from(
        select(IntegrationAction.id).where(query.whereclause),
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(IntegrationAction.action_name)
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    actions = list(result.scalars().all())

    items = [
        IntegrationActionResponse(
            id=a.id,
            connector_id=a.connector_id,
            action_name=a.action_name,
            display_name=a.display_name,
            description=a.description,
            action_type=a.action_type,
            input_schema=safe_json_loads(a.input_schema, {}) if a.input_schema else {},
            output_schema=safe_json_loads(a.output_schema, {}) if a.output_schema else {},
            requires_approval=a.requires_approval,
            timeout_seconds=a.timeout_seconds,
            is_idempotent=a.is_idempotent,
            created_at=a.created_at,
            updated_at=a.updated_at,
        )
        for a in actions
    ]

    pages = math.ceil(total / size) if total > 0 else 1

    return IntegrationActionListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.post(
    "/installed/{integration_id}/actions/{action_id}/execute",
    response_model=IntegrationExecutionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[_ANALYST],
)
async def execute_action(
    request: ActionExecutionRequest,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    integration_id: str = Path(...),
    action_id: str = Path(...),
):
    """Execute an integration action (analyst role or above).

    501 for a planned or log-ingest connector; 404 for an action the
    connector does not declare; 422 ``invalid_parameters`` when
    ``input_data`` does not match the action's ``params_schema``. A vendor
    error is a ``failed`` execution carrying the HTTP status and a sanitised
    message. One execution row is written per call.
    """
    integration = await get_installed_integration_or_404(db, integration_id, org_id)
    connector_name = installed_connector_name(integration)
    cls = connector_class(connector_name)
    if cls is None:
        raise _not_implemented(_display_name(connector_name))

    # Get action — scoped to the installed integration's connector so an
    # action belonging to a different connector can't be executed here.
    action = await get_action_or_404(db, action_id, integration.connector_id)
    spec = cls.ACTIONS.get(action.action_name)
    if spec is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    problems = validate_params(spec.params_schema, request.input_data)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_parameters", "problems": problems},
        )

    execution_result = await executor.execute_action(
        installation_id=integration.id,
        action_name=action.action_name,
        input_data=request.input_data,
        triggered_by="manual",
        playbook_run_id=request.playbook_run_id,
    )
    succeeded = execution_result.get("status") == "success"
    _audit(
        db, user=current_user, org_id=org_id, action="integration_action_execute", resource_id=integration.id,
        description=f"{connector_name}.{action.action_name}: {execution_result.get('status')}",
        details={
            "connector": connector_name,
            "action": action.action_name,
            "side_effect": spec.side_effect,
            "execution_id": execution_result.get("execution_id"),
            "http_status": execution_result.get("http_status"),
        },
        success=succeeded,
        error=execution_result.get("error_message"),
    )
    await db.commit()

    execution = None
    if execution_result.get("execution_id"):
        execution = (
            await db.execute(
                select(IntegrationExecution).where(
                    IntegrationExecution.id == execution_result["execution_id"],
                    IntegrationExecution.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()
    if execution is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "execution_not_recorded", "detail": sanitize_message(execution_result.get("error_message"))},
        )

    return IntegrationExecutionResponse(
        id=execution.id,
        installation_id=integration_id,
        action_id=execution.action_id,
        triggered_by=execution.triggered_by,
        status=execution.status,
        input_data=safe_json_loads(execution.input_data, {}),
        output_data=safe_json_loads(execution.output_data, None) if execution.output_data else None,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        duration_ms=execution.duration_ms,
        error_message=execution.error_message,
        error_code=execution_result.get("error_code"),
        http_status=execution_result.get("http_status"),
        retry_count=execution.retry_count,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
    )


@router.get(
    "/installed/{integration_id}/executions",
    response_model=ExecutionHistoryListResponse,
)
async def get_execution_history(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """Get execution history for integration"""
    await get_installed_integration_or_404(db, integration_id, org_id)

    query = select(IntegrationExecution).where(
        IntegrationExecution.installed_id == integration_id,
        IntegrationExecution.organization_id == org_id,
    )

    # Filter by status
    if status:
        query = query.where(IntegrationExecution.status == status)

    # Get total count
    count_query = select(func.count()).select_from(
        select(IntegrationExecution.id).where(query.whereclause),
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(IntegrationExecution.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    executions = list(result.scalars().all())

    items = [
        IntegrationExecutionResponse(
            id=e.id,
            installation_id=e.installed_id,
            action_id=e.action_id,
            triggered_by=e.triggered_by,
            status=e.status,
            input_data=safe_json_loads(e.input_data, {}),
            output_data=safe_json_loads(e.output_data, None) if e.output_data else None,
            started_at=e.started_at,
            completed_at=e.completed_at,
            duration_ms=e.duration_ms,
            error_message=e.error_message,
            retry_count=e.retry_count,
            created_at=e.created_at,
            updated_at=e.updated_at,
        )
        for e in executions
    ]

    pages = math.ceil(total / size) if total > 0 else 1

    return ExecutionHistoryListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


# Webhook endpoints
@router.post(
    "/installed/{integration_id}/webhooks",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[_ADMIN],
)
async def register_webhook(
    request: WebhookRegisterRequest,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Register webhook for integration"""
    await get_installed_integration_or_404(db, integration_id, org_id)

    # Create webhook
    webhook = WebhookEndpoint(
        organization_id=org_id,
        installed_id=integration_id,
        endpoint_path=request.endpoint_path,
        http_method=request.http_method,
        secret_hash=get_password_hash(request.secret) if getattr(request, "secret", None) else "",
        event_types=json.dumps(request.event_types),
        transform_template=request.transform_template,
    )

    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)

    return WebhookResponse(
        id=webhook.id,
        installation_id=webhook.installed_id,
        endpoint_path=webhook.endpoint_path,
        http_method=webhook.http_method,
        event_types=safe_json_loads(webhook.event_types, []),
        is_active=webhook.is_active,
        last_received=webhook.last_received,
        received_count=webhook.received_count,
        created_at=webhook.created_at,
        updated_at=webhook.updated_at,
    )


@router.get(
    "/installed/{integration_id}/webhooks",
    response_model=WebhookListResponse,
)
async def list_webhooks(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List webhooks for integration"""
    await get_installed_integration_or_404(db, integration_id, org_id)

    query = select(WebhookEndpoint).where(
        WebhookEndpoint.installed_id == integration_id,
        WebhookEndpoint.organization_id == org_id,
    )

    # Get total count
    count_query = select(func.count()).select_from(
        select(WebhookEndpoint.id).where(query.whereclause),
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(WebhookEndpoint.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    webhooks = list(result.scalars().all())

    items = [
        WebhookResponse(
            id=w.id,
            installation_id=w.installed_id,
            endpoint_path=w.endpoint_path,
            http_method=w.http_method,
            event_types=safe_json_loads(w.event_types, []),
            is_active=w.is_active,
            last_received=w.last_received,
            received_count=w.received_count,
            created_at=w.created_at,
            updated_at=w.updated_at,
        )
        for w in webhooks
    ]

    pages = math.ceil(total / size) if total > 0 else 1

    return WebhookListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.post(
    "/installed/{integration_id}/webhooks/{webhook_id}/test",
    dependencies=[_ANALYST],
)
async def test_webhook(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    webhook_id: str = Path(...),
):
    """Webhook test: not implemented.

    PySOAR has no public inbound receiver route for registered webhook
    endpoints, so there is no pipeline a test event could pass through. This
    route used to bump ``received_count``/``last_received`` with a synthetic
    payload, inflating the inbound counters with events that never arrived.
    It now returns 501 after the tenant-scoped lookup.
    """
    await get_installed_integration_or_404(db, integration_id, org_id)
    result = await db.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == webhook_id,
            WebhookEndpoint.installed_id == integration_id,
            WebhookEndpoint.organization_id == org_id,
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "detail": "PySOAR has no inbound webhook receiver yet, so a test event "
            "cannot be delivered through a registered webhook endpoint",
        },
    )


@router.delete(
    "/installed/{integration_id}/webhooks/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[_ADMIN],
)
async def delete_webhook(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    webhook_id: str = Path(...),
):
    """Delete webhook"""
    await get_installed_integration_or_404(db, integration_id, org_id)

    # Get webhook — scoped to this installed integration so a webhook
    # belonging to another tenant's install can't be deleted by id.
    result = await db.execute(
        select(WebhookEndpoint).where(
            and_(
                WebhookEndpoint.id == webhook_id,
                WebhookEndpoint.installed_id == integration_id,
                WebhookEndpoint.organization_id == org_id,
            )
        ),
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )

    await db.delete(webhook)
    await db.commit()


# Dashboard endpoints
# ---------------------------------------------------------------------------
# Dashboard helpers — shared between the three dashboard endpoints
# ---------------------------------------------------------------------------


async def _compute_integration_health(
    db: AsyncSession, org_id: str
) -> tuple[list[InstalledIntegration], dict[str, int]]:
    query = select(InstalledIntegration).where(
        InstalledIntegration.organization_id == org_id
    )
    result = await db.execute(query)
    integrations = list(result.scalars().all())

    health_counts = {"healthy": 0, "degraded": 0, "unhealthy": 0, "unknown": 0}
    for integration in integrations:
        h = integration.health_status or "unknown"
        if h in health_counts:
            health_counts[h] += 1
        else:
            health_counts["unknown"] += 1
    return integrations, health_counts


async def _compute_execution_stats(
    db: AsyncSession,
    org_id: str,
    period: str,
) -> dict[str, Any]:
    """Real IntegrationExecution aggregates over the requested window."""
    from datetime import timedelta
    from src.integrations.models import IntegrationExecution, IntegrationAction

    now = datetime.now(timezone.utc)
    if period == "hour":
        cutoff = now - timedelta(hours=1)
    elif period == "week":
        cutoff = now - timedelta(days=7)
    elif period == "month":
        cutoff = now - timedelta(days=30)
    else:  # day
        cutoff = now - timedelta(days=1)

    base = select(IntegrationExecution).where(
        and_(
            IntegrationExecution.organization_id == org_id,
            IntegrationExecution.created_at >= cutoff,
        )
    )
    result = await db.execute(base)
    executions = list(result.scalars().all())

    total = len(executions)
    successful = sum(1 for e in executions if e.status == "success")
    failed = sum(1 for e in executions if e.status in ("failed", "error"))

    # by_connector — resolve the connector's name via the FK. There's
    # no `connector_name` column on InstalledIntegration; the prior
    # reference raised AttributeError and crashed /dashboard/stats.
    by_connector: dict[str, int] = {}
    installed_ids = list({e.installed_id for e in executions if e.installed_id})
    connector_map: dict[str, str] = {}
    if installed_ids:
        inst_rows = await db.execute(
            select(InstalledIntegration)
            .options(selectinload(InstalledIntegration.connector))
            .where(
                InstalledIntegration.id.in_(installed_ids),
                InstalledIntegration.organization_id == org_id,
            )
        )
        for inst in inst_rows.scalars().all():
            cname = getattr(inst.connector, "name", None) if inst.connector else None
            connector_map[inst.id] = cname or inst.connector_id or "unknown"
    for e in executions:
        name = connector_map.get(e.installed_id, "unknown")
        by_connector[name] = by_connector.get(name, 0) + 1

    # by_action_type via action_id → IntegrationAction.action_type
    by_action_type: dict[str, int] = {}
    action_ids = list({e.action_id for e in executions if e.action_id})
    action_map: dict[str, str] = {}
    if action_ids:
        act_rows = await db.execute(
            select(IntegrationAction).where(IntegrationAction.id.in_(action_ids))
        )
        for a in act_rows.scalars().all():
            action_map[a.id] = getattr(a, "action_type", None) or a.action_name or "unknown"
    for e in executions:
        atype = action_map.get(e.action_id, "unknown")
        by_action_type[atype] = by_action_type.get(atype, 0) + 1

    # Average duration
    durations = [e.duration_ms for e in executions if e.duration_ms is not None]
    avg_duration = (sum(durations) / len(durations)) if durations else None

    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "by_connector": by_connector,
        "by_action_type": by_action_type,
        "avg_duration_ms": avg_duration,
        "executions": executions,
        "connector_map": connector_map,
    }


@router.get("/dashboard/health", response_model=DashboardIntegrationHealthResponse)
async def get_health_dashboard(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get integration health overview dashboard.

    Previously returned real counts but hardcoded ``integrations=[]``
    so the per-integration table on the frontend had no rows. Now
    serializes the actual installed integrations into the list.
    """
    integrations, health_counts = await _compute_integration_health(db, org_id)

    # Re-fetch with connector eager-loaded so we can resolve the
    # human-readable connector name without per-row lazy loads. The
    # prior serializer referenced `i.name` and `i.connector_name` —
    # neither exists on InstalledIntegration, so this endpoint
    # raised AttributeError and 500d the health dashboard.
    hydrated_integrations = []
    if integrations:
        hydrated_res = await db.execute(
            select(InstalledIntegration)
            .options(selectinload(InstalledIntegration.connector))
            .where(InstalledIntegration.id.in_([i.id for i in integrations]))
        )
        hydrated_integrations = list(hydrated_res.scalars().all())
    else:
        hydrated_integrations = integrations

    integration_dicts = [
        {
            "id": i.id,
            "name": i.display_name,
            "connector_name": (
                getattr(i.connector, "name", None) if i.connector else None
            ) or i.connector_id,
            "status": i.status,
            "health_status": i.health_status or "unknown",
            "last_health_check": i.last_health_check,
            "error_message": i.error_message,
        }
        for i in hydrated_integrations
    ]

    return DashboardIntegrationHealthResponse(
        total_installed=len(integrations),
        healthy=health_counts["healthy"],
        degraded=health_counts["degraded"],
        unhealthy=health_counts["unhealthy"],
        unknown=health_counts["unknown"],
        integrations=integration_dicts,
        last_updated=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/dashboard/stats", response_model=DashboardExecutionStatsResponse)
async def get_execution_stats(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    period: str = Query("day", pattern="^(hour|day|week|month)$"),
):
    """Get execution statistics dashboard.

    Previously returned hardcoded zeros / empty dicts for every
    tenant regardless of how many IntegrationExecution rows existed.
    Now runs real aggregates over the requested window.
    """
    stats = await _compute_execution_stats(db, org_id, period)

    return DashboardExecutionStatsResponse(
        period=period,
        total_executions=stats["total"],
        successful=stats["successful"],
        failed=stats["failed"],
        by_connector=stats["by_connector"],
        by_action_type=stats["by_action_type"],
        last_updated=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get complete dashboard summary with real top_connectors + high_error_rate.

    Previously hardcoded ``top_connectors=[]``, ``high_error_rate=[]``,
    ``total_executions=0``, ``success_rate=0.0``, and delegated to the
    broken execution stats path. Now computes all of them from the
    last 24 hours of IntegrationExecution rows:
      - top_connectors: top 5 by execution count
      - high_error_rate: any connector with > 50% failure rate and
        ≥ 3 executions (so a single failing call doesn't trigger)
      - success_rate and avg_execution_time_ms come from the same
        window.
    """
    integrations, health_counts = await _compute_integration_health(db, org_id)
    stats = await _compute_execution_stats(db, org_id, period="day")

    total = stats["total"]
    successful = stats["successful"]
    success_rate = (successful / total * 100.0) if total > 0 else 0.0

    # Top 5 connectors by execution count
    top_connectors = [
        {"connector_name": name, "executions": count}
        for name, count in sorted(
            stats["by_connector"].items(), key=lambda kv: -kv[1]
        )[:5]
    ]

    # Per-connector failure rates for high_error_rate detection
    per_connector_counts: dict[str, dict[str, int]] = {}
    for e in stats["executions"]:
        name = stats["connector_map"].get(e.installed_id, "unknown")
        bucket = per_connector_counts.setdefault(name, {"total": 0, "failed": 0})
        bucket["total"] += 1
        if e.status in ("failed", "error"):
            bucket["failed"] += 1

    high_error_rate = []
    for name, bucket in per_connector_counts.items():
        if bucket["total"] >= 3:
            fr = bucket["failed"] / bucket["total"]
            if fr > 0.5:
                high_error_rate.append(
                    {
                        "connector_name": name,
                        "total": bucket["total"],
                        "failed": bucket["failed"],
                        "failure_rate": round(fr * 100, 1),
                    }
                )

    now_iso = datetime.now(timezone.utc).isoformat()

    # Re-fetch with connector eager-loaded to resolve names without
    # crashing on missing attributes.
    hydrated_summary_integrations = []
    if integrations:
        hydrated_res = await db.execute(
            select(InstalledIntegration)
            .options(selectinload(InstalledIntegration.connector))
            .where(InstalledIntegration.id.in_([i.id for i in integrations]))
        )
        hydrated_summary_integrations = list(hydrated_res.scalars().all())

    integration_dicts = [
        {
            "id": i.id,
            "name": i.display_name,
            "connector_name": (
                getattr(i.connector, "name", None) if i.connector else None
            ) or i.connector_id,
            "status": i.status,
            "health_status": i.health_status or "unknown",
            "last_health_check": i.last_health_check,
            "error_message": i.error_message,
        }
        for i in hydrated_summary_integrations
    ]

    return DashboardSummaryResponse(
        total_installed=len(integrations),
        total_executions=total,
        success_rate=round(success_rate, 1),
        avg_execution_time_ms=stats["avg_duration_ms"],
        health_overview=DashboardIntegrationHealthResponse(
            total_installed=len(integrations),
            healthy=health_counts["healthy"],
            degraded=health_counts["degraded"],
            unhealthy=health_counts["unhealthy"],
            unknown=health_counts["unknown"],
            integrations=integration_dicts,
            last_updated=now_iso,
        ),
        top_connectors=top_connectors,
        high_error_rate=high_error_rate,
        period_stats=DashboardExecutionStatsResponse(
            period="day",
            total_executions=total,
            successful=successful,
            failed=stats["failed"],
            by_connector=stats["by_connector"],
            by_action_type=stats["by_action_type"],
            last_updated=now_iso,
        ),
        last_updated=now_iso,
    )
