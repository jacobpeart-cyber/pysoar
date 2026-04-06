"""Integration marketplace and connector management endpoints"""

import json
import math
from typing import Optional

from fastapi import APIRouter, Path, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession
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
                config_schema=json.loads(connector_meta.get("config_schema", "{}")),
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
        config_schema=json.loads(connector_meta.get("config_schema", "{}")),
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

    # Test connection
    test_result = await manager.test_connection(integration_id)

    return IntegrationTestResponse(
        status=test_result.get("status", "unknown"),
        message=test_result.get("error_message"),
        details={},
        timestamp=test_result.get("timestamp", ""),
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
            input_schema=json.loads(a.input_schema) if a.input_schema else {},
            output_schema=json.loads(a.output_schema) if a.output_schema else {},
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
        input_data=json.loads(execution.input_data),
        output_data=json.loads(execution.output_data) if execution.output_data else None,
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
            input_data=json.loads(e.input_data) if e.input_data else {},
            output_data=json.loads(e.output_data) if e.output_data else None,
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
        secret_hash="",  # Would hash the secret in production
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
        event_types=json.loads(webhook.event_types),
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
            event_types=json.loads(w.event_types),
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
@router.get("/dashboard/health", response_model=DashboardIntegrationHealthResponse)
async def get_health_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get integration health overview dashboard"""
    query = select(InstalledIntegration).where(
        InstalledIntegration.organization_id == getattr(current_user, "organization_id", None),
    )

    result = await db.execute(query)
    integrations = list(result.scalars().all())

    health_counts = {
        "healthy": 0,
        "degraded": 0,
        "unhealthy": 0,
        "unknown": 0,
    }

    for integration in integrations:
        status = integration.health_status or "unknown"
        if status in health_counts:
            health_counts[status] += 1

    return DashboardIntegrationHealthResponse(
        total_installed=len(integrations),
        healthy=health_counts["healthy"],
        degraded=health_counts["degraded"],
        unhealthy=health_counts["unhealthy"],
        unknown=health_counts["unknown"],
        integrations=[],
        last_updated="",
    )


@router.get("/dashboard/stats", response_model=DashboardExecutionStatsResponse)
async def get_execution_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    period: str = Query("day", pattern="^(hour|day|week|month)$"),
):
    """Get execution statistics dashboard"""
    return DashboardExecutionStatsResponse(
        period=period,
        total_executions=0,
        successful=0,
        failed=0,
        by_connector={},
        by_action_type={},
        last_updated="",
    )


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get complete dashboard summary"""
    query = select(InstalledIntegration).where(
        InstalledIntegration.organization_id == getattr(current_user, "organization_id", None),
    )

    result = await db.execute(query)
    integrations = list(result.scalars().all())

    health_counts = {
        "healthy": 0,
        "degraded": 0,
        "unhealthy": 0,
        "unknown": 0,
    }

    for integration in integrations:
        status = integration.health_status or "unknown"
        if status in health_counts:
            health_counts[status] += 1

    return DashboardSummaryResponse(
        total_installed=len(integrations),
        total_executions=0,
        success_rate=0.0,
        avg_execution_time_ms=None,
        health_overview=DashboardIntegrationHealthResponse(
            total_installed=len(integrations),
            healthy=health_counts["healthy"],
            degraded=health_counts["degraded"],
            unhealthy=health_counts["unhealthy"],
            unknown=health_counts["unknown"],
            integrations=[],
            last_updated="",
        ),
        top_connectors=[],
        high_error_rate=[],
        period_stats=DashboardExecutionStatsResponse(
            period="day",
            total_executions=0,
            successful=0,
            failed=0,
            by_connector={},
            by_action_type={},
            last_updated="",
        ),
        last_updated="",
    )
