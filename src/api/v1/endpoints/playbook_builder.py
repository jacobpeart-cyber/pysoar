"""Visual Playbook Builder API endpoints

``POST /playbook-builder/{id}/run`` (and the older ``/execute``) creates a real
pending ``VisualPlaybookExecution`` and dispatches it to the worker; poll
``GET /playbook-builder/executions`` or ``/executions/{execution_id}``. A
playbook with a node the engine cannot execute is refused with 501
``not_implemented`` before any run starts. Privileged nodes (containment,
agent_command, api_call, and integration actions not on the read-only
allowlist) are admin-only at dispatch and re-checked by the runner against
the role recorded on the execution (``forbidden_privileged_node``).
"""

import json
import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import AdminUser, CurrentUser, DatabaseSession, OrganizationId, require_role
from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.models.user import UserRole
from src.playbook_builder.engine import (
    PlaybookDesigner,
    PlaybookExecutionEngine,
    TemplateLibrary,
)
from src.playbook_builder.models import (
    PlaybookEdge,
    VisualPlaybookExecution,
    PlaybookNode,
    PlaybookNodeExecution,
    VisualPlaybook,
)
from src.schemas.playbook_builder import (
    CreateFromTemplateRequest,
    PlaybookCloneRequest,
    PlaybookCreate,
    PlaybookDashboardResponse,
    PlaybookEdgeCreate,
    PlaybookEdgeResponse,
    PlaybookEdgeUpdate,
    PlaybookExecutionListResponse,
    PlaybookExecutionResponse,
    PlaybookExecutionStatusResponse,
    PlaybookExecutionSummary,
    PlaybookExecutionSummaryListResponse,
    PlaybookExecutionTrigger,
    PlaybookExportResponse,
    PlaybookImportRequest,
    PlaybookListResponse,
    PlaybookNodeCreate,
    PlaybookNodeExecutionResponse,
    PlaybookNodeResponse,
    PlaybookNodeUpdate,
    PlaybookResponse,
    PlaybookTemplateListResponse,
    PlaybookTemplateResponse,
    PlaybookUpdate,
    PlaybookValidateRequest,
    PlaybookValidateResponse,
)
from src.playbook_builder.tasks import async_playbook_execution

router = APIRouter(prefix="/playbook-builder", tags=["Playbook Builder"])

#: Authoring and running visual playbooks: analysts and admins (viewers are
#: read-only). Deleting a playbook is admin-only.
_ANALYST_WRITE = [Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
_ADMIN_WRITE = [Depends(require_role([UserRole.ADMIN]))]
logger = get_logger(__name__)



def _effective_role(user) -> str:
    """Role recorded on the execution: platform superusers count as admin."""
    return "admin" if user.is_superuser else str(user.role)


async def _start_execution(
    playbook: VisualPlaybook,
    request: PlaybookExecutionTrigger,
    current_user,
    db: AsyncSession,
) -> VisualPlaybookExecution:
    """Create a pending execution for ``playbook`` and dispatch it, or refuse honestly."""
    if not any(n.node_type == "trigger" for n in playbook.nodes):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "no_trigger_node", "message": "The playbook needs a trigger node to run"},
        )
    problems = PlaybookExecutionEngine().unsupported_nodes(playbook)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={"error": "not_implemented", "message": "Some nodes cannot execute", "nodes": problems},
        )
    # Privileged by capability (PlaybookExecutionEngine.node_is_privileged),
    # fail closed; the runner re-checks against the role recorded below.
    privileged = PlaybookExecutionEngine().privileged_nodes(playbook)
    role = _effective_role(current_user)
    if privileged and role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "containment_requires_admin", "nodes": privileged},
        )

    execution = VisualPlaybookExecution(
        playbook_id=playbook.id,
        organization_id=playbook.organization_id,
        status="pending",
        triggered_by=current_user.id,
        triggered_by_role=role,
        trigger_event=json.dumps(request.trigger_event) if request.trigger_event else None,
        variables=json.dumps(request.variables) if request.variables else None,
    )
    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    try:
        async_playbook_execution.delay(playbook_id=playbook.id, execution_id=execution.id)
    except Exception as exc:  # broker down: the run did not start, say so on the row and to the caller
        logger.error("visual_playbook_dispatch_failed", execution_id=execution.id, error=str(exc))
        execution.status = "failed"
        execution.error_message = f"dispatch to the worker failed: {exc}"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "dispatch_failed", "execution_id": execution.id},
        ) from exc
    logger.info("visual_playbook_execution_queued", execution_id=execution.id, playbook_id=playbook.id)
    return execution


# Playbook CRUD endpoints
@router.get("", response_model=PlaybookListResponse)
async def list_playbooks(
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    is_template: Optional[bool] = None,
):
    """List playbooks with filtering and pagination"""
    query = select(VisualPlaybook).options(
        selectinload(VisualPlaybook.nodes),
        selectinload(VisualPlaybook.edges),
    ).where(
        VisualPlaybook.organization_id == org_id,
    )

    if search:
        query = query.where(VisualPlaybook.name.ilike(f"%{search}%"))

    if status:
        query = query.where(VisualPlaybook.status == status)

    if category:
        query = query.where(VisualPlaybook.category == category)

    if is_template is not None:
        query = query.where(VisualPlaybook.is_template == is_template)

    # Get total count
    count_result = await db.execute(
        select(func.count(VisualPlaybook.id)).where(
            VisualPlaybook.organization_id == org_id,
        ),
    )
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * size
    query = query.offset(offset).limit(size)

    result = await db.execute(query)
    playbooks = result.scalars().all()

    items = [_playbook_to_response(pb) for pb in playbooks]
    pages = math.ceil(total / size) if size > 0 else 0

    return PlaybookListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED, dependencies=_ANALYST_WRITE)
async def create_playbook(
    request: PlaybookCreate,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new playbook"""
    designer = PlaybookDesigner()
    playbook = designer.create_playbook(
        organization_id=org_id,
        name=request.name,
        description=request.description,
        category=request.category,
        trigger_type=request.trigger_type,
    )

    if request.trigger_config:
        playbook.trigger_config = json.dumps(request.trigger_config)

    db.add(playbook)
    await db.commit()

    # Re-fetch with eager loading to avoid lazy load crash
    result = await db.execute(
        select(VisualPlaybook).options(
            selectinload(VisualPlaybook.nodes),
            selectinload(VisualPlaybook.edges),
        ).where(VisualPlaybook.id == playbook.id),
    )
    playbook = result.scalar_one()

    logger.info(f"Created playbook: {playbook.id} ({playbook.name})")
    return _playbook_to_response(playbook)


# ---------------------------------------------------------------------------
# Literal-path routes declared BEFORE /{playbook_id}.
#
# FastAPI matches routes in declaration order. The dynamic catch-all
# ``/{playbook_id}`` (GET) ate /templates and /dashboard before they
# could fire — the frontend's template browser and Playbook Builder
# dashboard have been returning ``"Playbook not found"`` ever since
# the module shipped. These routes must stay physically above the
# dynamic path handler below.
# ---------------------------------------------------------------------------


@router.get("/templates", response_model=PlaybookTemplateListResponse)
async def list_templates_early(
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List available playbook templates.

    Previously positioned after the ``/{playbook_id}`` catch-all so
    every call matched the dynamic route first and returned
    "Playbook not found". Also had a dict(list).items() bug that
    would have crashed it once the routing was fixed. Both are
    corrected here.
    """
    templates = TemplateLibrary.get_templates()

    # templates is dict[template_id, template_dict]. Slice by keys
    # rather than values so we can keep the id alongside the payload.
    all_ids = list(templates.keys())
    offset = (page - 1) * size
    paginated_ids = all_ids[offset : offset + size]

    total = len(all_ids)
    pages = math.ceil(total / size) if size > 0 else 0

    items = [
        PlaybookTemplateResponse(
            id=tid,
            name=templates[tid].get("name"),
            description=templates[tid].get("description"),
            category=templates[tid].get("category"),
            nodes=templates[tid].get("nodes", []),
            edges=templates[tid].get("edges", []),
            node_count=len(templates[tid].get("nodes", [])),
            edge_count=len(templates[tid].get("edges", [])),
            created_at=None,
            updated_at=None,
        )
        for tid in paginated_ids
    ]

    return PlaybookTemplateListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/dashboard", response_model=PlaybookDashboardResponse)
async def get_dashboard_early(
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Playbook builder dashboard with real execution aggregates.

    Previously unreachable due to the same ``/{playbook_id}`` route
    collision. Also hardcoded ``successful_executions=0``,
    ``failed_executions=0``, ``avg_execution_time_ms=0.0``,
    ``success_rate=0.0`` regardless of the real execution history.
    Now computes all four from VisualPlaybookExecution rows.
    """

    # Count playbooks (org-scoped)
    total_result = await db.execute(
        select(func.count(VisualPlaybook.id)).where(
            VisualPlaybook.organization_id == org_id,
        ),
    )
    total_playbooks = total_result.scalar() or 0

    active_result = await db.execute(
        select(func.count(VisualPlaybook.id)).where(
            VisualPlaybook.organization_id == org_id,
            VisualPlaybook.status == "active",
        ),
    )
    active_playbooks = active_result.scalar() or 0

    draft_result = await db.execute(
        select(func.count(VisualPlaybook.id)).where(
            VisualPlaybook.organization_id == org_id,
            VisualPlaybook.status == "draft",
        ),
    )
    draft_playbooks = draft_result.scalar() or 0

    total_templates = len(TemplateLibrary.get_templates())

    # Real execution aggregates
    exec_result = await db.execute(
        select(VisualPlaybookExecution).where(
            VisualPlaybookExecution.organization_id == org_id,
        ),
    )
    executions = list(exec_result.scalars().all())
    total_executions = len(executions)
    successful = sum(1 for e in executions if e.status == "completed")
    failed = sum(1 for e in executions if e.status in ("failed", "error"))

    # Pull duration from started_at/completed_at timestamps
    durations_ms: list[float] = [float(e.duration_ms) for e in executions if e.duration_ms is not None]
    avg_execution_time_ms = (
        round(sum(durations_ms) / len(durations_ms), 1) if durations_ms else 0.0
    )
    success_rate = (
        round((successful / total_executions) * 100.0, 1)
        if total_executions > 0
        else 0.0
    )

    return PlaybookDashboardResponse(
        total_playbooks=total_playbooks,
        active_playbooks=active_playbooks,
        draft_playbooks=draft_playbooks,
        total_templates=total_templates,
        execution_stats={
            "total_executions": total_executions,
            "successful_executions": successful,
            "failed_executions": failed,
            "avg_execution_time_ms": avg_execution_time_ms,
            "success_rate": success_rate,
        },
    )


@router.get("/executions", response_model=PlaybookExecutionSummaryListResponse)
async def list_org_executions(
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """Recent visual-playbook executions across the caller's organisation.

    Registered before ``/{playbook_id}`` so the literal path is not captured
    by the playbook lookup (which used to 404 this call silently).
    """

    conditions = [VisualPlaybookExecution.organization_id == org_id]
    if status_filter:
        conditions.append(VisualPlaybookExecution.status == status_filter)

    total = (
        await db.execute(
            select(func.count(VisualPlaybookExecution.id)).where(*conditions),
        )
    ).scalar() or 0

    rows = (
        await db.execute(
            select(VisualPlaybookExecution, VisualPlaybook.name)
            .join(VisualPlaybook, VisualPlaybook.id == VisualPlaybookExecution.playbook_id)
            .where(*conditions, VisualPlaybook.organization_id == org_id)
            .order_by(VisualPlaybookExecution.created_at.desc())
            .offset((page - 1) * size)
            .limit(size),
        )
    ).all()

    playbook_ids = {ex.playbook_id for ex, _ in rows}
    execution_ids = [ex.id for ex, _ in rows]

    node_counts: dict[str, int] = {}
    if playbook_ids:
        node_counts = dict(
            (
                await db.execute(
                    select(PlaybookNode.playbook_id, func.count(PlaybookNode.id))
                    .where(PlaybookNode.playbook_id.in_(playbook_ids))
                    .group_by(PlaybookNode.playbook_id),
                )
            ).all(),
        )

    completed_counts: dict[str, int] = {}
    if execution_ids:
        completed_counts = dict(
            (
                await db.execute(
                    select(PlaybookNodeExecution.execution_id, func.count(PlaybookNodeExecution.id))
                    .where(
                        PlaybookNodeExecution.execution_id.in_(execution_ids),
                        PlaybookNodeExecution.status == "completed",
                    )
                    .group_by(PlaybookNodeExecution.execution_id),
                )
            ).all(),
        )

    items = [
        PlaybookExecutionSummary(
            **_execution_to_response(ex).model_dump(),
            playbook_name=name,
            total_nodes=node_counts.get(ex.playbook_id, 0),
            nodes_executed=completed_counts.get(ex.id, 0),
        )
        for ex, name in rows
    ]

    return PlaybookExecutionSummaryListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if size > 0 else 0,
    )


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific playbook"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)
    return _playbook_to_response(playbook)


@router.put("/{playbook_id}", response_model=PlaybookResponse, dependencies=_ANALYST_WRITE)
async def update_playbook(
    playbook_id: str,
    request: PlaybookUpdate,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a playbook"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    if request.name is not None:
        playbook.name = request.name
    if request.description is not None:
        playbook.description = request.description
    if request.category is not None:
        playbook.category = request.category
    if request.trigger_type is not None:
        playbook.trigger_type = request.trigger_type
    if request.trigger_config is not None:
        playbook.trigger_config = json.dumps(request.trigger_config)
    if request.status is not None:
        playbook.status = request.status
    if request.canvas_data is not None:
        playbook.canvas_data = json.dumps(request.canvas_data)

    playbook.version += 1
    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)

    logger.info(f"Updated playbook: {playbook.id}")
    return _playbook_to_response(playbook)


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=_ADMIN_WRITE)
async def delete_playbook(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a playbook"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)
    await db.delete(playbook)
    await db.commit()
    logger.info(f"Deleted playbook: {playbook_id}")


# Validation endpoint
@router.post("/{playbook_id}/validate", response_model=PlaybookValidateResponse)
async def validate_playbook(
    playbook_id: str,
    request: PlaybookValidateRequest,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Validate playbook structure"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    designer = PlaybookDesigner()
    is_valid, errors = designer.validate_playbook(playbook)
    for problem in PlaybookExecutionEngine().unsupported_nodes(playbook):
        errors.append(f"Node {problem['node_id']} cannot execute: {problem['reason']}")
        is_valid = False

    return PlaybookValidateResponse(is_valid=is_valid, errors=errors)


# Clone endpoint
@router.post("/{playbook_id}/clone", response_model=PlaybookResponse, dependencies=_ANALYST_WRITE)
async def clone_playbook(
    playbook_id: str,
    request: PlaybookCloneRequest,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Clone a playbook"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    designer = PlaybookDesigner()
    cloned = designer.clone_playbook(
        playbook,
        request.new_name,
        org_id,
    )

    db.add(cloned)
    await db.commit()

    # Re-fetch with eager loading to avoid lazy-load greenlet crash
    result = await db.execute(
        select(VisualPlaybook).options(
            selectinload(VisualPlaybook.nodes),
            selectinload(VisualPlaybook.edges),
        ).where(VisualPlaybook.id == cloned.id),
    )
    cloned = result.scalar_one()

    logger.info(f"Cloned playbook {playbook_id} to {cloned.id}")
    return _playbook_to_response(cloned)


# Import/Export endpoints
@router.post("/{playbook_id}/export", response_model=PlaybookExportResponse)
async def export_playbook(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Export playbook as JSON"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    designer = PlaybookDesigner()
    export_data = designer.export_playbook_json(playbook)

    return PlaybookExportResponse(**export_data)


@router.post("/import", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED, dependencies=_ANALYST_WRITE)
async def import_playbook(
    request: PlaybookImportRequest,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Import a playbook from JSON"""
    designer = PlaybookDesigner()
    playbook = designer.import_playbook_json(
        org_id,
        request.playbook_data,
    )

    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)

    logger.info(f"Imported playbook: {playbook.id}")
    return _playbook_to_response(playbook)


# Node management endpoints
@router.post("/{playbook_id}/nodes", response_model=PlaybookNodeResponse, dependencies=_ANALYST_WRITE)
async def add_node(
    playbook_id: str,
    request: PlaybookNodeCreate,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Add a node to a playbook"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    designer = PlaybookDesigner()
    node = designer.add_node(
        playbook,
        request.node_type,
        request.display_name,
        request.position_x,
        request.position_y,
        request.config,
        request.description,
        request.timeout_seconds,
        request.retry_count,
        request.on_error,
    )

    db.add(node)
    await db.commit()
    await db.refresh(node)

    logger.info(f"Added node to playbook: {node.node_id}")
    return _node_to_response(node)


@router.put("/{playbook_id}/nodes/{node_id}", response_model=PlaybookNodeResponse, dependencies=_ANALYST_WRITE)
async def update_node(
    playbook_id: str,
    node_id: str,
    request: PlaybookNodeUpdate,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a node"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)
    node = await _get_node_or_404(playbook, node_id)

    if request.display_name is not None:
        node.display_name = request.display_name
    if request.description is not None:
        node.description = request.description
    if request.position_x is not None:
        node.position_x = request.position_x
    if request.position_y is not None:
        node.position_y = request.position_y
    if request.config is not None:
        node.config = json.dumps(request.config)
    if request.timeout_seconds is not None:
        node.timeout_seconds = request.timeout_seconds
    if request.retry_count is not None:
        node.retry_count = request.retry_count
    if request.on_error is not None:
        node.on_error = request.on_error

    db.add(node)
    await db.commit()
    await db.refresh(node)

    logger.info(f"Updated node: {node_id}")
    return _node_to_response(node)


@router.delete("/{playbook_id}/nodes/{node_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=_ANALYST_WRITE)
async def remove_node(
    playbook_id: str,
    node_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Remove a node from a playbook"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    designer = PlaybookDesigner()
    if not designer.remove_node(playbook, node_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    db.add(playbook)
    await db.commit()
    logger.info(f"Removed node: {node_id}")


# Edge management endpoints
@router.post("/{playbook_id}/edges", response_model=PlaybookEdgeResponse, dependencies=_ANALYST_WRITE)
async def connect_nodes(
    playbook_id: str,
    request: PlaybookEdgeCreate,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Connect two nodes"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    designer = PlaybookDesigner()
    edge = designer.connect_nodes(
        playbook,
        request.source_node_id,
        request.target_node_id,
        request.edge_type,
        request.condition_expression,
        request.label,
        request.priority,
    )

    db.add(edge)
    await db.commit()
    await db.refresh(edge)

    logger.info(f"Connected nodes: {request.source_node_id} -> {request.target_node_id}")
    return _edge_to_response(edge)


@router.put("/{playbook_id}/edges/{edge_id}", response_model=PlaybookEdgeResponse, dependencies=_ANALYST_WRITE)
async def update_edge(
    playbook_id: str,
    edge_id: str,
    request: PlaybookEdgeUpdate,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an edge"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)
    edge = await _get_edge_or_404(playbook, edge_id)

    if request.edge_type is not None:
        edge.edge_type = request.edge_type
    if request.condition_expression is not None:
        edge.condition_expression = request.condition_expression
    if request.label is not None:
        edge.label = request.label
    if request.priority is not None:
        edge.priority = request.priority

    db.add(edge)
    await db.commit()
    await db.refresh(edge)

    logger.info(f"Updated edge: {edge_id}")
    return _edge_to_response(edge)


@router.delete("/{playbook_id}/edges/{edge_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=_ANALYST_WRITE)
async def disconnect_nodes(
    playbook_id: str,
    edge_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Remove an edge"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)
    edge = await _get_edge_or_404(playbook, edge_id)

    await db.delete(edge)
    await db.commit()
    logger.info(f"Removed edge: {edge_id}")


# Execution endpoints
@router.post("/{playbook_id}/execute", response_model=PlaybookExecutionResponse, dependencies=_ANALYST_WRITE)
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecutionTrigger,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Trigger playbook execution (same as ``/run``)."""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)
    execution = await _start_execution(playbook, request, current_user, db)
    return _execution_to_response(execution)


@router.post(
    "/{playbook_id}/run",
    response_model=PlaybookExecutionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST_WRITE,
)
async def run_playbook(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    request: Optional[PlaybookExecutionTrigger] = None,
):
    """Start a real execution; poll ``/executions/{id}`` for node-by-node status.

    501 ``not_implemented`` when a node cannot execute (listed in ``nodes``),
    422 without a trigger node, 403 for containment nodes unless admin.
    """
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)
    execution = await _start_execution(playbook, request or PlaybookExecutionTrigger(), current_user, db)
    return _execution_to_response(execution)


@router.get("/{playbook_id}/executions", response_model=PlaybookExecutionListResponse)
async def list_executions(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List playbook executions"""
    playbook = await _get_playbook_or_404(db, playbook_id, org_id)

    query = (
        select(VisualPlaybookExecution)
        .where(VisualPlaybookExecution.playbook_id == playbook.id, VisualPlaybookExecution.organization_id == org_id)
        .order_by(VisualPlaybookExecution.created_at.desc())
    )

    # Get total count
    count_result = await db.execute(
        select(func.count(VisualPlaybookExecution.id)).where(
            VisualPlaybookExecution.playbook_id == playbook.id,
        ),
    )
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * size
    query = query.offset(offset).limit(size)

    result = await db.execute(query)
    executions = result.scalars().all()

    items = [_execution_to_response(ex) for ex in executions]
    pages = math.ceil(total / size) if size > 0 else 0

    return PlaybookExecutionListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/executions/{execution_id}", response_model=PlaybookExecutionStatusResponse)
async def get_execution_status(
    execution_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get execution status"""
    result = await db.execute(
        select(VisualPlaybookExecution).where(VisualPlaybookExecution.id == execution_id),
    )
    execution = result.scalar_one_or_none()

    if not execution or execution.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")

    # Get node executions
    result = await db.execute(
        select(PlaybookNodeExecution).where(
            PlaybookNodeExecution.execution_id == execution_id,
            PlaybookNodeExecution.organization_id == org_id,
        ).order_by(PlaybookNodeExecution.started_at),
    )
    node_executions = result.scalars().all()
    node_summary: dict[str, int] = {}
    for ne in node_executions:
        node_summary[ne.status] = node_summary.get(ne.status, 0) + 1

    # Get total node count from the playbook to calculate real progress
    playbook_result = await db.execute(
        select(func.count(PlaybookNode.id)).where(
            PlaybookNode.playbook_id == execution.playbook_id,
        ),
    )
    total_nodes = playbook_result.scalar() or 0
    completed_nodes = len([ne for ne in node_executions if ne.status == "completed"])
    progress = (completed_nodes / max(1, total_nodes)) * 100
    if execution.status in ("completed", "partial", "failed"):
        progress = 100.0
    else:
        progress = min(progress, 99.0)

    return PlaybookExecutionStatusResponse(
        execution_id=execution.id,
        playbook_id=execution.playbook_id,
        status=execution.status,
        current_node_id=execution.current_node_id,
        progress_percent=progress,
        node_executions=[_node_execution_to_response(ne) for ne in node_executions],
        error_message=execution.error_message,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        duration_ms=execution.duration_ms,
        execution_path=safe_json_loads(execution.execution_path, []) or [],
        node_summary=node_summary,
    )


# /templates moved above the /{playbook_id} catch-all (earlier in
# this file) to fix a P0 route-ordering collision. This shim is a
# placeholder so the import structure stays intact.


@router.post("/templates/{template_id}/create", response_model=PlaybookResponse, dependencies=_ANALYST_WRITE)
async def create_from_template(
    template_id: str,
    request: CreateFromTemplateRequest,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create playbook from template"""
    templates = TemplateLibrary.get_templates()

    if template_id not in templates:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Template not found",
        )

    template_data = templates[template_id]

    designer = PlaybookDesigner()
    playbook = designer.import_playbook_json(
        org_id,
        {**template_data, "name": request.playbook_name},
    )

    db.add(playbook)
    await db.commit()

    # Re-fetch with eager loading to avoid lazy-load greenlet crash
    result = await db.execute(
        select(VisualPlaybook).options(
            selectinload(VisualPlaybook.nodes),
            selectinload(VisualPlaybook.edges),
        ).where(VisualPlaybook.id == playbook.id),
    )
    playbook = result.scalar_one()

    logger.info(f"Created playbook from template {template_id}")
    return _playbook_to_response(playbook)


# Dashboard endpoint
# /dashboard moved above the /{playbook_id} catch-all (earlier in
# this file) to fix a P0 route-ordering collision.


# Helper functions
async def _get_playbook_or_404(
    db: AsyncSession,
    playbook_id: str,
    organization_id: str,
) -> VisualPlaybook:
    """Get playbook or raise 404"""
    result = await db.execute(
        select(VisualPlaybook).options(
            selectinload(VisualPlaybook.nodes),
            selectinload(VisualPlaybook.edges),
        ).where(
            VisualPlaybook.id == playbook_id,
            VisualPlaybook.organization_id == organization_id,
        ),
    )
    playbook = result.scalar_one_or_none()

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found",
        )

    return playbook


async def _get_node_or_404(playbook: VisualPlaybook, node_id: str) -> PlaybookNode:
    """Get node from playbook or raise 404"""
    node = next((n for n in playbook.nodes if n.node_id == node_id), None)

    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    return node


async def _get_edge_or_404(playbook: VisualPlaybook, edge_id: str) -> PlaybookEdge:
    """Get edge from playbook or raise 404"""
    edge = next((e for e in playbook.edges if e.id == edge_id), None)

    if not edge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Edge not found")

    return edge


def _playbook_to_response(playbook: VisualPlaybook) -> PlaybookResponse:
    """Convert playbook to response"""
    return PlaybookResponse(
        id=playbook.id,
        organization_id=playbook.organization_id,
        name=playbook.name,
        description=playbook.description,
        version=playbook.version,
        category=playbook.category,
        trigger_type=playbook.trigger_type,
        trigger_config=safe_json_loads(playbook.trigger_config, None),
        status=playbook.status,
        execution_count=playbook.execution_count,
        avg_execution_time_ms=playbook.avg_execution_time_ms,
        success_rate=playbook.success_rate,
        last_executed=playbook.last_executed,
        is_template=playbook.is_template,
        template_category=playbook.template_category,
        created_by=playbook.created_by,
        nodes=[_node_to_response(n) for n in playbook.nodes],
        edges=[_edge_to_response(e) for e in playbook.edges],
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
    )


def _node_to_response(node: PlaybookNode) -> PlaybookNodeResponse:
    """Convert node to response"""
    return PlaybookNodeResponse(
        id=node.id,
        node_id=node.node_id,
        node_type=node.node_type,
        display_name=node.display_name,
        description=node.description,
        position_x=node.position_x,
        position_y=node.position_y,
        config=safe_json_loads(node.config, None),
        timeout_seconds=node.timeout_seconds,
        retry_count=node.retry_count,
        on_error=node.on_error,
        input_schema=safe_json_loads(node.input_schema, None),
        output_schema=safe_json_loads(node.output_schema, None),
        created_at=node.created_at,
        updated_at=node.updated_at,
    )


def _edge_to_response(edge: PlaybookEdge) -> PlaybookEdgeResponse:
    """Convert edge to response"""
    return PlaybookEdgeResponse(
        id=edge.id,
        playbook_id=edge.playbook_id,
        source_node_id=edge.source_node_id,
        target_node_id=edge.target_node_id,
        edge_type=edge.edge_type,
        condition_expression=edge.condition_expression,
        label=edge.label,
        priority=edge.priority,
        created_at=edge.created_at,
        updated_at=edge.updated_at,
    )


def _execution_to_response(execution: VisualPlaybookExecution) -> PlaybookExecutionResponse:
    """Convert execution to response"""
    return PlaybookExecutionResponse(
        id=execution.id,
        playbook_id=execution.playbook_id,
        organization_id=execution.organization_id,
        trigger_event=safe_json_loads(execution.trigger_event, None),
        status=execution.status,
        current_node_id=execution.current_node_id,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        duration_ms=execution.duration_ms,
        execution_path=safe_json_loads(execution.execution_path, []),
        variables=safe_json_loads(execution.variables, None),
        error_message=execution.error_message,
        triggered_by=execution.triggered_by,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
    )


def _node_execution_to_response(
    node_execution: PlaybookNodeExecution,
) -> PlaybookNodeExecutionResponse:
    """Convert node execution to response"""
    return PlaybookNodeExecutionResponse(
        id=node_execution.id,
        execution_id=node_execution.execution_id,
        node_id=node_execution.node_id,
        status=node_execution.status,
        started_at=node_execution.started_at,
        completed_at=node_execution.completed_at,
        duration_ms=node_execution.duration_ms,
        input_data=safe_json_loads(node_execution.input_data, None),
        output_data=safe_json_loads(node_execution.output_data, None),
        error_message=node_execution.error_message,
        retry_attempt=node_execution.retry_attempt,
        approved_by=node_execution.approved_by,
        created_at=node_execution.created_at,
        updated_at=node_execution.updated_at,
    )
