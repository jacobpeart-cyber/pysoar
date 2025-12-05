"""Playbook management endpoints"""

import json
import math
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import AdminUser, CurrentUser, DatabaseSession
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

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


async def get_playbook_or_404(db: AsyncSession, playbook_id: str) -> Playbook:
    """Get playbook by ID or raise 404"""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )
    return playbook


def playbook_to_response(playbook: Playbook) -> PlaybookResponse:
    """Convert playbook model to response schema"""
    steps = json.loads(playbook.steps) if playbook.steps else []
    trigger_conditions = json.loads(playbook.trigger_conditions) if playbook.trigger_conditions else None
    variables = json.loads(playbook.variables) if playbook.variables else None
    tags = json.loads(playbook.tags) if playbook.tags else None

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
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    playbook_status: Optional[str] = Query(None, alias="status"),
    category: Optional[str] = None,
    trigger_type: Optional[str] = None,
):
    """List playbooks with filtering and pagination"""
    query = select(Playbook)

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
    current_user: AdminUser,
    db: DatabaseSession,
):
    """Create a new playbook (admin only)"""
    playbook = Playbook(
        name=playbook_data.name,
        description=playbook_data.description,
        trigger_type=playbook_data.trigger_type,
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
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Get a playbook by ID"""
    playbook = await get_playbook_or_404(db, playbook_id)
    return playbook_to_response(playbook)


@router.patch("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: str,
    playbook_data: PlaybookUpdate,
    current_user: AdminUser,
    db: DatabaseSession,
):
    """Update a playbook (admin only)"""
    playbook = await get_playbook_or_404(db, playbook_id)

    update_data = playbook_data.model_dump(exclude_unset=True, exclude_none=True)

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
    current_user: AdminUser,
    db: DatabaseSession,
):
    """Delete a playbook (admin only)"""
    playbook = await get_playbook_or_404(db, playbook_id)
    await db.delete(playbook)
    await db.flush()


@router.post("/{playbook_id}/execute", response_model=PlaybookExecutionResponse)
async def execute_playbook(
    playbook_id: str,
    execute_data: PlaybookExecuteRequest,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Execute a playbook"""
    playbook = await get_playbook_or_404(db, playbook_id)

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

    steps = json.loads(playbook.steps) if playbook.steps else []

    execution = PlaybookExecution(
        playbook_id=playbook.id,
        incident_id=execute_data.incident_id,
        status=ExecutionStatus.PENDING.value,
        total_steps=len(steps),
        input_data=json.dumps(execute_data.input_data) if execute_data.input_data else None,
        triggered_by=current_user.id,
        trigger_source="manual",
    )

    db.add(execution)
    await db.flush()
    await db.refresh(execution)

    # In production, this would trigger a Celery task
    # For now, we just create the execution record

    return PlaybookExecutionResponse(
        id=execution.id,
        playbook_id=execution.playbook_id,
        incident_id=execution.incident_id,
        status=execution.status,
        current_step=execution.current_step,
        total_steps=execution.total_steps,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        input_data=json.loads(execution.input_data) if execution.input_data else None,
        output_data=None,
        step_results=None,
        error_message=execution.error_message,
        error_step=execution.error_step,
        triggered_by=execution.triggered_by,
        trigger_source=execution.trigger_source,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
    )


@router.get("/{playbook_id}/executions", response_model=PlaybookExecutionListResponse)
async def list_playbook_executions(
    playbook_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    execution_status: Optional[str] = Query(None, alias="status"),
):
    """List executions for a playbook"""
    await get_playbook_or_404(db, playbook_id)

    query = select(PlaybookExecution).where(PlaybookExecution.playbook_id == playbook_id)

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

    items = []
    for execution in executions:
        items.append(PlaybookExecutionResponse(
            id=execution.id,
            playbook_id=execution.playbook_id,
            incident_id=execution.incident_id,
            status=execution.status,
            current_step=execution.current_step,
            total_steps=execution.total_steps,
            started_at=execution.started_at,
            completed_at=execution.completed_at,
            input_data=json.loads(execution.input_data) if execution.input_data else None,
            output_data=json.loads(execution.output_data) if execution.output_data else None,
            step_results=json.loads(execution.step_results) if execution.step_results else None,
            error_message=execution.error_message,
            error_step=execution.error_step,
            triggered_by=execution.triggered_by,
            trigger_source=execution.trigger_source,
            created_at=execution.created_at,
            updated_at=execution.updated_at,
        ))

    return PlaybookExecutionListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )
