"""Integration marketplace and connector management endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Path, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession
from src.core.security import get_password_hash
from src.core.utils import safe_json_loads
from src.integrations.engine import ConnectorRegistry, IntegrationManager, ActionExecutor
from src.integrations.models import (
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

# Shared instances (in production, use dependency injection)
registry = ConnectorRegistry()
manager = IntegrationManager(registry)
executor = ActionExecutor()


# Helper functions
async def get_installed_integration_or_404(
    integration_id: str,
    db: AsyncSession,
) -> InstalledIntegration:
    """Get installed integration by ID or raise 404"""
    result = await db.execute(
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(InstalledIntegration.id == integration_id),
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found",
        )
    return integration


async def get_action_or_404(
    action_id: str,
    db: AsyncSession,
) -> IntegrationAction:
    """Get action by ID or raise 404"""
    result = await db.execute(
        select(IntegrationAction).where(IntegrationAction.id == action_id),
    )
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
):
    """List available connectors in marketplace"""
    # Get connectors from registry
    connectors = registry.list_connectors(
        category=category,
        search=search,
        limit=size * 10,
    )

    # Apply pagination
    total = len(connectors)
    start = (page - 1) * size
    end = start + size
    page_connectors = connectors[start:end]

    # Convert to response schema
    items = []
    for connector_meta in page_connectors:
        items.append(
            ConnectorResponse(
                id=connector_meta.get("name", ""),
                name=connector_meta.get("name", ""),
                display_name=connector_meta.get("display_name", ""),
                description=connector_meta.get("description"),
                vendor=connector_meta.get("vendor"),
                category=connector_meta.get("category", ""),
                version=connector_meta.get("version", "1.0.0"),
                auth_type=connector_meta.get("auth_type", ""),
                supported_actions=connector_meta.get("supported_actions", []),
                supported_triggers=connector_meta.get("supported_triggers", []),
                icon_url=None,
                documentation_url=None,
                config_schema=connector_meta.get("config_schema", {}) if isinstance(connector_meta.get("config_schema"), dict) else safe_json_loads(connector_meta.get("config_schema", "{}"), {}) if isinstance(connector_meta.get("config_schema"), str) else {},
                is_builtin=connector_meta.get("is_builtin", False),
                is_community=connector_meta.get("is_community", False),
                rating=connector_meta.get("rating"),
                install_count=connector_meta.get("install_count", 0),
                last_updated=connector_meta.get("last_updated"),
                created_at=None,
                updated_at=None,
            ),
        )

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
    connector_name: str = Path(...),
):
    """Get detailed information about a specific connector"""
    connector_meta = registry.get_connector_details(connector_name)
    if not connector_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found",
        )

    return ConnectorResponse(
        id=connector_meta.get("name", ""),
        name=connector_meta.get("name", ""),
        display_name=connector_meta.get("display_name", ""),
        description=connector_meta.get("description"),
        vendor=connector_meta.get("vendor"),
        category=connector_meta.get("category", ""),
        version=connector_meta.get("version", "1.0.0"),
        auth_type=connector_meta.get("auth_type", ""),
        supported_actions=connector_meta.get("supported_actions", []),
        supported_triggers=connector_meta.get("supported_triggers", []),
        icon_url=None,
        documentation_url=None,
        config_schema=safe_json_loads(connector_meta.get("config_schema"), {}),
        is_builtin=connector_meta.get("is_builtin", False),
        is_community=connector_meta.get("is_community", False),
        rating=connector_meta.get("rating"),
        install_count=connector_meta.get("install_count", 0),
        last_updated=connector_meta.get("last_updated"),
        created_at=None,
        updated_at=None,
    )


# Installed integrations endpoints
@router.post("/install", response_model=InstalledIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def install_connector(
    request: IntegrationInstallRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Install a connector"""
    # Validate connector exists
    connector_meta = registry.get_connector_details(request.connector_id)
    if not connector_meta:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Connector not found: {request.connector_id}",
        )

    # Check if already installed
    result = await db.execute(
        select(InstalledIntegration).where(
            and_(
                InstalledIntegration.organization_id == getattr(current_user, "organization_id", None),
                InstalledIntegration.connector_id == request.connector_id,
            ),
        ),
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connector already installed",
        )

    # Create installation record
    installation = InstalledIntegration(
        organization_id=getattr(current_user, "organization_id", None),
        connector_id=request.connector_id,
        display_name=request.display_name,
        config_encrypted=json.dumps(request.config),
        auth_credentials_encrypted=json.dumps(request.credentials),
    )

    db.add(installation)
    await db.commit()
    await db.refresh(installation)

    return InstalledIntegrationResponse(
        id=installation.id,
        connector_id=installation.connector_id,
        display_name=installation.display_name,
        config={},
        status=installation.status,
        health_status=installation.health_status,
        last_health_check=installation.last_health_check,
        last_successful_action=installation.last_successful_action,
        error_message=installation.error_message,
        rate_limit_remaining=installation.rate_limit_remaining,
        rate_limit_reset=installation.rate_limit_reset,
        created_at=installation.created_at,
        updated_at=installation.updated_at,
    )


@router.get("/installed", response_model=InstalledIntegrationListResponse)
async def list_installed_integrations(
    current_user: CurrentUser = None,
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
    query = query.where(InstalledIntegration.organization_id == getattr(current_user, "organization_id", None))

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

    items = [
        InstalledIntegrationResponse(
            id=i.id,
            connector_id=i.connector_id,
            display_name=i.display_name,
            config={},
            status=i.status,
            health_status=i.health_status,
            last_health_check=i.last_health_check,
            last_successful_action=i.last_successful_action,
            error_message=i.error_message,
            rate_limit_remaining=i.rate_limit_remaining,
            rate_limit_reset=i.rate_limit_reset,
            created_at=i.created_at,
            updated_at=i.updated_at,
        )
        for i in integrations
    ]

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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Get details of installed integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    return InstalledIntegrationResponse(
        id=integration.id,
        connector_id=integration.connector_id,
        display_name=integration.display_name,
        config={},
        status=integration.status,
        health_status=integration.health_status,
        last_health_check=integration.last_health_check,
        last_successful_action=integration.last_successful_action,
        error_message=integration.error_message,
        rate_limit_remaining=integration.rate_limit_remaining,
        rate_limit_reset=integration.rate_limit_reset,
        created_at=integration.created_at,
        updated_at=integration.updated_at,
    )


@router.patch("/installed/{integration_id}", response_model=InstalledIntegrationResponse)
async def update_installed_integration(
    request: InstalledIntegrationUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Update installed integration configuration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Update fields
    if request.display_name:
        integration.display_name = request.display_name
    if request.config:
        integration.config_encrypted = json.dumps(request.config)
    if request.credentials:
        integration.auth_credentials_encrypted = json.dumps(request.credentials)

    await db.commit()
    await db.refresh(integration)

    return InstalledIntegrationResponse(
        id=integration.id,
        connector_id=integration.connector_id,
        display_name=integration.display_name,
        config={},
        status=integration.status,
        health_status=integration.health_status,
        last_health_check=integration.last_health_check,
        last_successful_action=integration.last_successful_action,
        error_message=integration.error_message,
        rate_limit_remaining=integration.rate_limit_remaining,
        rate_limit_reset=integration.rate_limit_reset,
        created_at=integration.created_at,
        updated_at=integration.updated_at,
    )


@router.post("/installed/{integration_id}/test", response_model=IntegrationTestResponse)
async def test_integration(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Test connection to installed integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Real connection test: resolve the connector's test URL and probe it.
    # If the connector has no built-in test URL we check the stored
    # health_status and last_health_check freshness.
    import httpx

    connector = integration.connector_name
    config = safe_json_loads(integration.config_encrypted, {}) if integration.config_encrypted else {}

    test_url = config.get("base_url") or config.get("host") or config.get("url")
    health_path = config.get("health_path", "/health")

    test_status = "unknown"
    error_msg = None

    if test_url:
        full_url = f"{test_url.rstrip('/')}{health_path}"
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(full_url)
                if resp.status_code < 400:
                    test_status = "healthy"
                else:
                    test_status = "unhealthy"
                    error_msg = f"HTTP {resp.status_code}"
        except httpx.TimeoutException:
            test_status = "unhealthy"
            error_msg = "Connection timed out"
        except Exception as exc:
            test_status = "unhealthy"
            error_msg = str(exc)[:200]
    else:
        test_status = integration.health_status or "unknown"

    # Persist the result
    integration.health_status = test_status
    integration.last_health_check = datetime.now(timezone.utc)
    if error_msg:
        integration.error_message = error_msg
    await db.commit()

    return IntegrationTestResponse(
        status=test_status,
        message=error_msg,
        details={"connector": connector, "tested_url": test_url},
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/installed/{integration_id}/enable", response_model=IntegrationStatusResponse)
async def enable_integration(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Enable integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

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


@router.post("/installed/{integration_id}/disable", response_model=IntegrationStatusResponse)
async def disable_integration(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Disable integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

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


@router.delete("/installed/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def uninstall_integration(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Uninstall integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    await db.delete(integration)
    await db.commit()


# Action endpoints
@router.get("/installed/{integration_id}/actions", response_model=IntegrationActionListResponse)
async def list_integration_actions(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List available actions for integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Get actions for this connector
    query = select(IntegrationAction).where(
        IntegrationAction.connector_id == integration.connector_id,
    )

    # Get total count
    count_query = select(func.count()).select_from(
        select(IntegrationAction.id).where(query.whereclause),
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(IntegrationAction.created_at.desc())
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
)
async def execute_action(
    request: ActionExecutionRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    action_id: str = Path(...),
):
    """Execute an integration action"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Get action
    action = await get_action_or_404(db, action_id)

    # Execute action
    execution_result = await executor.execute_action(
        integration_id=integration_id,
        action_name=action.action_name,
        input_data=request.input_data,
        playbook_run_id=request.playbook_run_id,
    )

    # Create execution record
    execution = IntegrationExecution(
        organization_id=getattr(current_user, "organization_id", None),
        installed_id=integration_id,
        action_id=action_id,
        triggered_by="manual",
        input_data=json.dumps(request.input_data),
        output_data=json.dumps(execution_result.get("output_data", {})),
        status=execution_result.get("status", "failed"),
        duration_ms=execution_result.get("duration_ms"),
        error_message=execution_result.get("error_message"),
        playbook_run_id=request.playbook_run_id,
    )

    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    return IntegrationExecutionResponse(
        id=execution.id,
        installation_id=integration_id,
        action_id=action_id,
        triggered_by=execution.triggered_by,
        status=execution.status,
        input_data=safe_json_loads(execution.input_data, {}),
        output_data=safe_json_loads(execution.output_data, None) if execution.output_data else None,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        duration_ms=execution.duration_ms,
        error_message=execution.error_message,
        retry_count=execution.retry_count,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
    )


@router.get(
    "/installed/{integration_id}/executions",
    response_model=ExecutionHistoryListResponse,
)
async def get_execution_history(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """Get execution history for integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    query = select(IntegrationExecution).where(
        IntegrationExecution.installed_id == integration_id,
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
)
async def register_webhook(
    request: WebhookRegisterRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
):
    """Register webhook for integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Create webhook
    webhook = WebhookEndpoint(
        organization_id=getattr(current_user, "organization_id", None),
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List webhooks for integration"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    query = select(WebhookEndpoint).where(
        WebhookEndpoint.installed_id == integration_id,
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
)
async def test_webhook(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    webhook_id: str = Path(...),
):
    """Fire a synthetic test event through the webhook processing pipeline.

    Looks up the webhook, verifies tenant ownership, constructs a
    ``pysoar.webhook.test`` payload, and records the test in the webhook's
    ``last_received`` / ``received_count`` counters. Returns the synthetic
    payload so the UI can display what was fired.
    """
    integration = await get_installed_integration_or_404(db, integration_id)
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    result = await db.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == webhook_id,
            WebhookEndpoint.installed_id == integration_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )

    test_payload = {
        "event": "pysoar.webhook.test",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "webhook_id": webhook_id,
        "integration_id": integration_id,
        "source": "ui_test_button",
        "actor_id": getattr(current_user, "id", None),
    }

    # Record the synthetic test in the webhook's counters so operators see it
    # reflected in the UI immediately.
    webhook.last_received = datetime.utcnow()
    webhook.received_count = (webhook.received_count or 0) + 1
    await db.commit()
    await db.refresh(webhook)

    return {
        "status": "test_fired",
        "webhook_id": webhook_id,
        "endpoint_path": webhook.endpoint_path,
        "payload": test_payload,
        "received_count": webhook.received_count,
    }


@router.delete(
    "/installed/{integration_id}/webhooks/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_webhook(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    integration_id: str = Path(...),
    webhook_id: str = Path(...),
):
    """Delete webhook"""
    integration = await get_installed_integration_or_404(db, integration_id)

    # Check authorization
    if integration.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Get webhook
    result = await db.execute(
        select(WebhookEndpoint).where(WebhookEndpoint.id == webhook_id),
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
    db: AsyncSession, org_id: Optional[str]
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
    org_id: Optional[str],
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

    # by_connector via installed_integration → connector_name
    by_connector: dict[str, int] = {}
    installed_ids = list({e.installed_id for e in executions if e.installed_id})
    connector_map: dict[str, str] = {}
    if installed_ids:
        inst_rows = await db.execute(
            select(InstalledIntegration).where(InstalledIntegration.id.in_(installed_ids))
        )
        for inst in inst_rows.scalars().all():
            connector_map[inst.id] = inst.connector_name or "unknown"
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
            action_map[a.id] = getattr(a, "action_type", None) or a.name or "unknown"
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get integration health overview dashboard.

    Previously returned real counts but hardcoded ``integrations=[]``
    so the per-integration table on the frontend had no rows. Now
    serializes the actual installed integrations into the list.
    """
    org_id = getattr(current_user, "organization_id", None)
    integrations, health_counts = await _compute_integration_health(db, org_id)

    integration_dicts = [
        {
            "id": i.id,
            "name": i.name,
            "connector_name": i.connector_name,
            "status": i.status,
            "health_status": i.health_status or "unknown",
            "last_health_check": i.last_health_check,
            "error_message": i.error_message,
        }
        for i in integrations
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
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    period: str = Query("day", pattern="^(hour|day|week|month)$"),
):
    """Get execution statistics dashboard.

    Previously returned hardcoded zeros / empty dicts for every
    tenant regardless of how many IntegrationExecution rows existed.
    Now runs real aggregates over the requested window.
    """
    org_id = getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
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
    org_id = getattr(current_user, "organization_id", None)
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

    integration_dicts = [
        {
            "id": i.id,
            "name": i.name,
            "connector_name": i.connector_name,
            "status": i.status,
            "health_status": i.health_status or "unknown",
            "last_health_check": i.last_health_check,
            "error_message": i.error_message,
        }
        for i in integrations
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
