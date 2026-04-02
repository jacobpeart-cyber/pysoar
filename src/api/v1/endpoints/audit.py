"""Audit log endpoints"""

import math
from typing import Any, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import DatabaseSession, get_current_superuser, get_db
from src.models.audit import AuditLog
from src.models.user import User
from src.schemas.audit import AuditLogResponse, AuditLogListResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    db: DatabaseSession = None,
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
    db: DatabaseSession = None,
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
    db: DatabaseSession = None,
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


@router.get("/export")
async def export_audit_logs(
    db: DatabaseSession = None,
    current_user: User = Depends(get_current_superuser),
    format: str = Query("csv", pattern="^(csv|json|xml)$"),
    days: int = Query(30, ge=1, le=365),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
) -> Any:
    """
    Export audit logs as CSV, JSON, or XML file download.

    For government compliance (FedRAMP, NIST 800-53 AU controls).
    """
    from datetime import datetime, timedelta, timezone
    from fastapi.responses import StreamingResponse
    import io
    import csv
    import json

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    query = select(AuditLog).where(AuditLog.created_at >= cutoff)
    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    query = query.order_by(desc(AuditLog.created_at))

    result = await db.execute(query)
    logs = result.scalars().all()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Timestamp", "User", "Action", "Resource Type", "Resource ID",
            "Description", "IP Address", "Success", "Request ID"
        ])
        for log in logs:
            writer.writerow([
                log.created_at.isoformat() if log.created_at else "",
                getattr(log, "user_email", None) or getattr(log, "user_id", ""),
                log.action,
                log.resource_type,
                log.resource_id or "",
                log.description or "",
                log.ip_address or "",
                "Yes" if log.success else "No",
                log.request_id or "",
            ])
        content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=pysoar_audit_{timestamp}.csv"},
        )

    elif format == "json":
        data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "period_days": days,
            "total_records": len(logs),
            "records": [
                {
                    "timestamp": log.created_at.isoformat() if log.created_at else None,
                    "user": getattr(log, "user_email", None) or getattr(log, "user_id", ""),
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "description": log.description,
                    "ip_address": log.ip_address,
                    "success": log.success,
                    "old_value": log.old_value,
                    "new_value": log.new_value,
                    "request_id": log.request_id,
                }
                for log in logs
            ],
        }
        content = json.dumps(data, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=pysoar_audit_{timestamp}.json"},
        )

    elif format == "xml":
        lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<AuditExport>']
        lines.append(f'  <ExportTimestamp>{datetime.now(timezone.utc).isoformat()}</ExportTimestamp>')
        lines.append(f'  <PeriodDays>{days}</PeriodDays>')
        lines.append(f'  <TotalRecords>{len(logs)}</TotalRecords>')
        lines.append('  <Records>')
        for log in logs:
            lines.append('    <Record>')
            lines.append(f'      <Timestamp>{log.created_at.isoformat() if log.created_at else ""}</Timestamp>')
            lines.append(f'      <User>{getattr(log, "user_email", "") or getattr(log, "user_id", "")}</User>')
            lines.append(f'      <Action>{log.action or ""}</Action>')
            lines.append(f'      <ResourceType>{log.resource_type or ""}</ResourceType>')
            lines.append(f'      <ResourceID>{log.resource_id or ""}</ResourceID>')
            lines.append(f'      <Description>{log.description or ""}</Description>')
            lines.append(f'      <IPAddress>{log.ip_address or ""}</IPAddress>')
            lines.append(f'      <Success>{"true" if log.success else "false"}</Success>')
            lines.append(f'      <RequestID>{log.request_id or ""}</RequestID>')
            lines.append('    </Record>')
        lines.append('  </Records>')
        lines.append('</AuditExport>')
        content = "\n".join(lines)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/xml",
            headers={"Content-Disposition": f"attachment; filename=pysoar_audit_{timestamp}.xml"},
        )
