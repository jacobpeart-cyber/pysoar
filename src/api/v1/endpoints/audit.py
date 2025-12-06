"""Audit log endpoints"""

import math
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import get_current_superuser, get_db
from src.models.audit import AuditLog
from src.models.user import User
from src.schemas.audit import AuditLogResponse, AuditLogListResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[str] = None,
    success: Optional[bool] = None,
) -> AuditLogListResponse:
    """List audit logs with filtering (admin only)"""

    # Build query
    query = select(AuditLog).options(selectinload(AuditLog.user))
    count_query = select(func.count(AuditLog.id))

    # Apply filters
    if action:
        query = query.where(AuditLog.action == action)
        count_query = count_query.where(AuditLog.action == action)

    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
        count_query = count_query.where(AuditLog.resource_type == resource_type)

    if user_id:
        query = query.where(AuditLog.user_id == user_id)
        count_query = count_query.where(AuditLog.user_id == user_id)

    if success is not None:
        query = query.where(AuditLog.success == success)
        count_query = count_query.where(AuditLog.success == success)

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply pagination and ordering
    offset = (page - 1) * size
    query = query.order_by(desc(AuditLog.created_at)).offset(offset).limit(size)

    # Execute query
    result = await db.execute(query)
    logs = result.scalars().all()

    # Transform to response
    items = [
        AuditLogResponse(
            id=log.id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            description=log.description,
            user_id=log.user_id,
            user_email=log.user.email if log.user else None,
            user_name=log.user.full_name if log.user else None,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            old_value=log.old_value,
            new_value=log.new_value,
            success=log.success,
            error_message=log.error_message,
            created_at=log.created_at,
        )
        for log in logs
    ]

    return AuditLogListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/actions")
async def list_audit_actions(
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """List all possible audit actions"""
    from src.models.audit import AuditAction

    return {
        "actions": [action.value for action in AuditAction]
    }


@router.get("/resource-types")
async def list_resource_types(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """List all resource types that have audit logs"""
    query = select(AuditLog.resource_type).distinct()
    result = await db.execute(query)
    types = result.scalars().all()

    return {
        "resource_types": list(types)
    }


@router.get("/stats")
async def get_audit_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser),
) -> dict:
    """Get audit log statistics"""

    # Total logs
    total_query = select(func.count(AuditLog.id))
    total_result = await db.execute(total_query)
    total = total_result.scalar() or 0

    # Success vs failure
    success_query = select(func.count(AuditLog.id)).where(AuditLog.success == True)
    success_result = await db.execute(success_query)
    successful = success_result.scalar() or 0

    failed_query = select(func.count(AuditLog.id)).where(AuditLog.success == False)
    failed_result = await db.execute(failed_query)
    failed = failed_result.scalar() or 0

    # By action type
    action_query = (
        select(AuditLog.action, func.count(AuditLog.id))
        .group_by(AuditLog.action)
        .order_by(desc(func.count(AuditLog.id)))
        .limit(10)
    )
    action_result = await db.execute(action_query)
    by_action = {row[0]: row[1] for row in action_result.all()}

    # By resource type
    resource_query = (
        select(AuditLog.resource_type, func.count(AuditLog.id))
        .group_by(AuditLog.resource_type)
        .order_by(desc(func.count(AuditLog.id)))
    )
    resource_result = await db.execute(resource_query)
    by_resource = {row[0]: row[1] for row in resource_result.all()}

    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "by_action": by_action,
        "by_resource_type": by_resource,
    }
