"""Playbook management endpoints

Steps run through ``src.services.playbook_engine`` (see its docstring for what
each step type really does). Create/update reject unknown step types and the
removed ``run_script``; running a playbook that contains a privileged step
(containment, outbound HTTP, or a non-read-only integration action; see
``playbook_engine.is_privileged_step``) is admin-only.
"""

import json
import math
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import AdminUser, CurrentUser, DatabaseSession, OrganizationId, require_role
from src.core.database import async_session_factory
from src.models.alert import Alert
from src.models.incident import Incident
from src.models.user import UserRole
from src.core.utils import safe_json_loads
from src.models.playbook import (
    ExecutionStatus,
    Playbook,
    PlaybookExecution,
    PlaybookStatus,
)
from src.schemas.playbook import (
    PlaybookCreate,
    PlaybookExecuteRequest,
    PlaybookExecutionListResponse,
    PlaybookExecutionResponse,
    PlaybookListResponse,
    PlaybookResponse,
    PlaybookUpdate,
)
from src.services.playbook_engine import (
    REMOVED_ACTIONS,
    SUPPORTED_ACTIONS,
    PlaybookEngine,
    is_privileged_step,
    summarize_steps,
)
from src.services.websocket_manager import create_notification_callback

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])

#: Operational writes (running a playbook): analysts and admins. Authoring,
#: editing and deleting playbooks stay admin-only (AdminUser).
_ANALYST_WRITE = [Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]


#: The UI's "schedule" trigger is stored as the enum value "scheduled".
_TRIGGER_ALIASES = {"schedule": "scheduled"}


def _validate_steps(steps: list) -> None:
    """422 for removed or unknown step types (nothing unknown is ever stored)."""
    problems = []
    for idx, step in enumerate(steps):
        action = step.action
        if action in REMOVED_ACTIONS:
            problems.append({"step": idx + 1, "action": action, "error": REMOVED_ACTIONS[action]})
        elif action not in SUPPORTED_ACTIONS:
            problems.append({"step": idx + 1, "action": action, "error": "unknown step type"})
    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_steps", "steps": problems, "supported_actions": sorted(SUPPORTED_ACTIONS)},
        )


def execution_to_response(execution: PlaybookExecution) -> PlaybookExecutionResponse:
    """PlaybookExecution row -> response, with per-step results and a status summary."""
    step_results = safe_json_loads(execution.step_results, None)
    return PlaybookExecutionResponse(
        id=execution.id,
        playbook_id=execution.playbook_id,
        incident_id=execution.incident_id,
        status=execution.status,
        current_step=execution.current_step,
        total_steps=execution.total_steps,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        input_data=safe_json_loads(execution.input_data, None),
        output_data=safe_json_loads(execution.output_data, None),
        step_results=step_results,
        step_summary=summarize_steps(step_results) if isinstance(step_results, list) else None,
        error_message=execution.error_message,
        error_step=execution.error_step,
        triggered_by=execution.triggered_by,
        trigger_source=execution.trigger_source,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
    )


async def run_playbook_execution(execution_id: str):
    """Background task to run playbook execution"""
    async with async_session_factory() as db:
        try:
            engine = PlaybookEngine(db)
            # Publish only to the execution's tenant channel (playbooks:<org>).
            execution_org = (
                await db.execute(
                    select(PlaybookExecution.organization_id).where(
                        PlaybookExecution.id == execution_id,
                    ),
                )
            ).scalar_one_or_none()
            notify_callback = create_notification_callback("playbooks", execution_org)
            await engine.execute(execution_id, notify_callback)
            await db.commit()
        except Exception as e:
            await db.rollback()
            raise e


async def get_playbook_or_404(db: AsyncSession, playbook_id: str, org_id: str) -> Playbook:
    """Get the caller's playbook by ID or raise 404 (always tenant-scoped)"""
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id, Playbook.organization_id == org_id),
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )
    return playbook


def playbook_to_response(playbook: Playbook) -> PlaybookResponse:
    """Convert playbook model to response schema"""
    steps = safe_json_loads(playbook.steps, [])
    trigger_conditions = safe_json_loads(playbook.trigger_conditions, None)
    variables = safe_json_loads(playbook.variables, None)
    tags = safe_json_loads(playbook.tags, None)

    return PlaybookResponse(
        id=playbook.id,
        name=playbook.name,
        description=playbook.description,
        status=playbook.status,
        trigger_type=playbook.trigger_type,
        trigger_conditions=trigger_conditions,
        steps=steps,
        variables=variables,
        category=playbook.category,
        tags=tags,
        version=playbook.version,
        is_enabled=playbook.is_enabled,
        timeout_seconds=playbook.timeout_seconds,
        max_retries=playbook.max_retries,
        created_by=playbook.created_by,
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
    )


@router.get("", response_model=PlaybookListResponse)
async def list_playbooks(
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    playbook_status: Optional[str] = Query(None, alias="status"),
    category: Optional[str] = None,
    trigger_type: Optional[str] = None,
):
    """List the caller's playbooks with filtering and pagination"""
    query = select(Playbook).where(Playbook.organization_id == org_id)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (Playbook.name.ilike(search_filter))
            | (Playbook.description.ilike(search_filter))
        )

    if playbook_status:
        query = query.where(Playbook.status == playbook_status)

    if category:
        query = query.where(Playbook.category == category)

    if trigger_type:
        query = query.where(Playbook.trigger_type == trigger_type)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(Playbook.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    playbooks = list(result.scalars().all())

    return PlaybookListResponse(
        items=[playbook_to_response(p) for p in playbooks],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    playbook_data: PlaybookCreate,
    org_id: OrganizationId,
    current_user: AdminUser = None,
    db: DatabaseSession = None,
):
    """Create a new playbook in the caller's organisation (admin only)"""
    _validate_steps(playbook_data.steps)
    playbook = Playbook(
        organization_id=org_id,
        name=playbook_data.name,
        description=playbook_data.description,
        trigger_type=_TRIGGER_ALIASES.get(playbook_data.trigger_type, playbook_data.trigger_type),
        trigger_conditions=json.dumps(playbook_data.trigger_conditions) if playbook_data.trigger_conditions else None,
        steps=json.dumps([s.model_dump() for s in playbook_data.steps]),
        variables=json.dumps(playbook_data.variables) if playbook_data.variables else None,
        category=playbook_data.category,
        tags=json.dumps(playbook_data.tags) if playbook_data.tags else None,
        timeout_seconds=playbook_data.timeout_seconds,
        max_retries=playbook_data.max_retries,
        status=PlaybookStatus.DRAFT.value,
        created_by=current_user.id,
    )

    db.add(playbook)
    await db.flush()
    await db.refresh(playbook)

    return playbook_to_response(playbook)


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a playbook by ID"""
    playbook = await get_playbook_or_404(db, playbook_id, org_id)
    return playbook_to_response(playbook)


@router.patch("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: str,
    playbook_data: PlaybookUpdate,
    org_id: OrganizationId,
    current_user: AdminUser = None,
    db: DatabaseSession = None,
):
    """Update a playbook (admin only)"""
    playbook = await get_playbook_or_404(db, playbook_id, org_id)

    if playbook_data.steps is not None:
        _validate_steps(playbook_data.steps)
    update_data = playbook_data.model_dump(exclude_unset=True, exclude_none=True)
    if "trigger_type" in update_data:
        update_data["trigger_type"] = _TRIGGER_ALIASES.get(update_data["trigger_type"], update_data["trigger_type"])

    # Handle JSON fields
    if "steps" in update_data:
        update_data["steps"] = json.dumps([s.model_dump() for s in update_data["steps"]])
    if "trigger_conditions" in update_data:
        update_data["trigger_conditions"] = json.dumps(update_data["trigger_conditions"])
    if "variables" in update_data:
        update_data["variables"] = json.dumps(update_data["variables"])
    if "tags" in update_data:
        update_data["tags"] = json.dumps(update_data["tags"])

    # Increment version on content changes
    if any(k in update_data for k in ["steps", "trigger_conditions", "variables"]):
        playbook.version += 1

    for key, value in update_data.items():
        setattr(playbook, key, value)

    await db.flush()
    await db.refresh(playbook)

    return playbook_to_response(playbook)


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: AdminUser = None,
    db: DatabaseSession = None,
):
    """Delete a playbook (admin only)"""
    playbook = await get_playbook_or_404(db, playbook_id, org_id)
    await db.delete(playbook)
    await db.flush()


@router.post(
    "/{playbook_id}/execute", response_model=PlaybookExecutionResponse, dependencies=_ANALYST_WRITE
)
async def execute_playbook(
    playbook_id: str,
    execute_data: PlaybookExecuteRequest,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    background_tasks: BackgroundTasks = None,
):
    """Execute a playbook against the caller's own alert/incident"""
    playbook = await get_playbook_or_404(db, playbook_id, org_id)

    # The engine mutates the target alert/incident, so both must belong to
    # the caller's organisation (404 otherwise, never another tenant's row).
    if execute_data.alert_id:
        found = await db.execute(
            select(Alert.id).where(Alert.id == execute_data.alert_id, Alert.organization_id == org_id)
        )
        if found.scalar_one_or_none() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if execute_data.incident_id:
        found = await db.execute(
            select(Incident.id).where(
                Incident.id == execute_data.incident_id, Incident.organization_id == org_id
            )
        )
        if found.scalar_one_or_none() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if not playbook.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Playbook is disabled",
        )

    if playbook.status != PlaybookStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Playbook is not active",
        )

    steps = safe_json_loads(playbook.steps, [])

    # Privileged by capability (containment, outbound HTTP, non-read-only
    # integration actions), not by a name allowlist.
    containment_steps = sorted({
        s.get("action") for s in steps
        if isinstance(s, dict) and is_privileged_step(str(s.get("action") or ""), s.get("parameters") or {})
    })
    if containment_steps and not (current_user.is_superuser or current_user.role == UserRole.ADMIN.value):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "containment_requires_admin", "containment_steps": containment_steps},
        )

    # Fold alert_id / incident_id from the request into input_data so
    # step executors (update_alert, add_comment, isolate_host, etc.) can
    # resolve the target entity without needing a separate lookup. The
    # PlaybookExecuteRequest schema accepts both optional fields but
    # previously we only persisted incident_id on the execution row,
    # leaving alert-driven playbooks unable to mutate their source alert.
    input_data = dict(execute_data.input_data or {})
    if execute_data.alert_id:
        input_data["alert_id"] = execute_data.alert_id
        # Fall back to alert_id as the generic target if none set
        input_data.setdefault("target_id", execute_data.alert_id)
    if execute_data.incident_id:
        input_data["incident_id"] = execute_data.incident_id
        input_data["target_id"] = input_data.get("target_id") or execute_data.incident_id

    execution = PlaybookExecution(
        organization_id=org_id,
        playbook_id=playbook.id,
        incident_id=execute_data.incident_id,
        status=ExecutionStatus.PENDING.value,
        total_steps=len(steps),
        input_data=json.dumps(input_data) if input_data else None,
        triggered_by=current_user.id,
        triggered_by_user_id=current_user.id,
        trigger_source="manual",
    )

    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    # Schedule background execution — commit() above ensures the row is
    # visible to the new session that run_playbook_execution creates.
    background_tasks.add_task(run_playbook_execution, execution.id)

    return execution_to_response(execution)


@router.get("/{playbook_id}/executions", response_model=PlaybookExecutionListResponse)
async def list_playbook_executions(
    playbook_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    execution_status: Optional[str] = Query(None, alias="status"),
):
    """List the caller's executions of one of the caller's playbooks.

    Executions carry the organisation (stamped at creation; migration 014
    backfilled historic rows from the triggering user).
    """
    await get_playbook_or_404(db, playbook_id, org_id)

    query = select(PlaybookExecution).where(
        PlaybookExecution.playbook_id == playbook_id,
        PlaybookExecution.organization_id == org_id,
    )

    if execution_status:
        query = query.where(PlaybookExecution.status == execution_status)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(PlaybookExecution.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    executions = list(result.scalars().all())

    items = [execution_to_response(execution) for execution in executions]

    return PlaybookExecutionListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/{playbook_id}/executions/{execution_id}", response_model=PlaybookExecutionResponse)
async def get_playbook_execution(
    playbook_id: str,
    execution_id: str,
    org_id: OrganizationId,
    _current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """One execution of one of the caller's playbooks, for polling a run.

    Carries per-step ``status`` / ``started_at`` / ``finished_at`` / ``result`` /
    ``error`` in ``step_results`` and a per-status ``step_summary``.
    """
    await get_playbook_or_404(db, playbook_id, org_id)
    execution = (
        await db.execute(
            select(PlaybookExecution).where(
                PlaybookExecution.id == execution_id,
                PlaybookExecution.playbook_id == playbook_id,
                PlaybookExecution.organization_id == org_id,
            ),
        )
    ).scalar_one_or_none()
    if execution is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    return execution_to_response(execution)
