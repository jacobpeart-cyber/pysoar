"""Unified Ticket Hub API endpoints."""

import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Body, HTTPException, Query, status
from sqlalchemy import select, func, desc

from src.api.deps import CurrentUser, DatabaseSession
from src.tickethub.models import TicketComment, TicketActivity, AutomationRule, TicketLink
from src.tickethub.engine import TicketAggregator

router = APIRouter(prefix="/tickethub", tags=["ticket-hub"])


# ============================================================================
# UNIFIED TICKET LIST & KANBAN
# ============================================================================


@router.get("/tickets")
async def list_unified_tickets(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    source_type: Optional[str] = None,
    kanban_column: Optional[str] = None,
    search: Optional[str] = None,
    assigned_to: Optional[str] = None,
    priority: Optional[str] = None,
):
    """Get paginated list of all tickets across all modules."""
    org_id = getattr(current_user, "organization_id", None)
    aggregator = TicketAggregator(db)

    source_types = [source_type] if source_type else None

    return await aggregator.get_unified_tickets(
        organization_id=org_id,
        source_types=source_types,
        kanban_column=kanban_column,
        search=search,
        assigned_to=assigned_to,
        priority=priority,
        page=page,
        size=size,
    )


@router.get("/tickets/{source_type}/{source_id}")
async def get_ticket_detail(
    source_type: str,
    source_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get detailed view of a specific ticket with comments and activity."""
    org_id = getattr(current_user, "organization_id", None)
    aggregator = TicketAggregator(db)

    # Get the ticket from aggregation
    result = await aggregator.get_unified_tickets(
        organization_id=org_id,
        source_types=[source_type],
        size=500,
    )
    ticket = next((t for t in result["items"] if t["source_id"] == source_id), None)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # Get comments (tenant-scoped)
    comments_result = await db.execute(
        select(TicketComment)
        .where(
            TicketComment.source_type == source_type,
            TicketComment.source_id == source_id,
            TicketComment.organization_id == org_id,
        )
        .order_by(TicketComment.created_at.asc())
    )
    comments = [
        {
            "id": c.id,
            "content": c.content,
            "author_id": c.author_id,
            "parent_comment_id": c.parent_comment_id,
            "is_edited": c.is_edited,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in comments_result.scalars().all()
    ]

    # Get activity (tenant-scoped)
    activity_result = await db.execute(
        select(TicketActivity)
        .where(
            TicketActivity.source_type == source_type,
            TicketActivity.source_id == source_id,
            TicketActivity.organization_id == org_id,
        )
        .order_by(TicketActivity.created_at.desc())
        .limit(50)
    )
    activity = [
        {
            "id": a.id,
            "activity_type": a.activity_type,
            "description": a.description,
            "actor_id": a.actor_id,
            "old_value": a.old_value,
            "new_value": a.new_value,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in activity_result.scalars().all()
    ]

    # Get links (tenant-scoped)
    links_result = await db.execute(
        select(TicketLink).where(
            TicketLink.organization_id == org_id,
            (TicketLink.source_type_a == source_type) & (TicketLink.source_id_a == source_id)
            | (TicketLink.source_type_b == source_type) & (TicketLink.source_id_b == source_id),
        )
    )
    links = [
        {
            "id": l.id,
            "link_type": l.link_type,
            "other_source_type": l.source_type_b if l.source_id_a == source_id else l.source_type_a,
            "other_source_id": l.source_id_b if l.source_id_a == source_id else l.source_id_a,
        }
        for l in links_result.scalars().all()
    ]

    return {
        "ticket": ticket,
        "comments": comments,
        "activity": activity,
        "links": links,
    }


@router.patch("/tickets/{source_type}/{source_id}/status")
async def update_ticket_status(
    source_type: str,
    source_id: str,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update ticket status (maps back to source-specific status)."""
    new_status = data.get("status")
    if not new_status:
        raise HTTPException(status_code=400, detail="status is required")

    # Get source model and update (tenant-scoped)
    model = _get_source_model(source_type)
    if not model:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}")

    org_id = getattr(current_user, "organization_id", None)
    stmt = select(model).where(model.id == source_id)
    if hasattr(model, "organization_id"):
        stmt = stmt.where(model.organization_id == org_id)
    result = await db.execute(stmt)
    record = result.scalars().first()
    if not record:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # Translate generic kanban column labels (new/in_progress/review/
    # closed) back to the source model's native status vocabulary.
    # Previously this wrote the raw UI label into e.g. Incident.status,
    # corrupting records that use open/investigating/contained/etc.
    # When new_status is already a native status, KANBAN_MAP falls
    # through and we accept it as-is.
    from src.tickethub.engine import KANBAN_MAP
    mapping = KANBAN_MAP.get(source_type, {})
    translated_status = new_status
    if new_status in mapping:
        candidates = mapping[new_status]
        if candidates:
            translated_status = candidates[0]

    old_status = record.status
    record.status = translated_status
    await db.flush()

    # Log activity
    activity = TicketActivity(
        id=str(uuid.uuid4()),
        source_type=source_type,
        source_id=source_id,
        activity_type="status_change",
        actor_id=str(current_user.id),
        description=f"Status changed from {old_status} to {translated_status}",
        old_value=old_status,
        new_value=translated_status,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(activity)
    await db.flush()

    return {
        "status": "updated",
        "old_status": old_status,
        "new_status": translated_status,
        "ui_column": new_status if new_status in mapping else None,
    }


# ============================================================================
# KANBAN BOARD
# ============================================================================


@router.get("/kanban")
async def get_kanban_board(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get kanban board with tickets grouped into 4 columns."""
    org_id = getattr(current_user, "organization_id", None)
    aggregator = TicketAggregator(db)
    return await aggregator.get_kanban_board(organization_id=org_id)


@router.post("/kanban/move")
async def move_kanban_card(
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Move a ticket between kanban columns (drag-and-drop)."""
    source_type = data.get("source_type")
    source_id = data.get("source_id")
    target_column = data.get("target_column")

    if not all([source_type, source_id, target_column]):
        raise HTTPException(status_code=400, detail="source_type, source_id, target_column required")

    # Map kanban column to first valid status for this source type
    from src.tickethub.engine import KANBAN_MAP
    mapping = KANBAN_MAP.get(source_type, {})
    target_statuses = mapping.get(target_column, [])
    if not target_statuses:
        raise HTTPException(status_code=400, detail=f"No status mapping for {source_type}/{target_column}")

    new_status = target_statuses[0]  # Use first valid status

    # Update source record (tenant-scoped)
    model = _get_source_model(source_type)
    if not model:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}")

    org_id = getattr(current_user, "organization_id", None)
    stmt = select(model).where(model.id == source_id)
    if hasattr(model, "organization_id"):
        stmt = stmt.where(model.organization_id == org_id)
    result = await db.execute(stmt)
    record = result.scalars().first()
    if not record:
        raise HTTPException(status_code=404, detail="Ticket not found")

    old_status = record.status
    record.status = new_status
    await db.flush()

    # Log activity
    activity = TicketActivity(
        id=str(uuid.uuid4()),
        source_type=source_type,
        source_id=source_id,
        activity_type="status_change",
        actor_id=str(current_user.id),
        description=f"Moved to {target_column}: {old_status} → {new_status}",
        old_value=old_status,
        new_value=new_status,
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(activity)
    await db.flush()

    return {"status": "moved", "old_status": old_status, "new_status": new_status, "column": target_column}


# ============================================================================
# COMMENTS
# ============================================================================


@router.get("/tickets/{source_type}/{source_id}/comments")
async def list_comments(
    source_type: str,
    source_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """List comments on a ticket."""
    org_id = getattr(current_user, "organization_id", None)
    result = await db.execute(
        select(TicketComment)
        .where(
            TicketComment.source_type == source_type,
            TicketComment.source_id == source_id,
            TicketComment.organization_id == org_id,
        )
        .order_by(TicketComment.created_at.asc())
    )
    return list(result.scalars().all())


@router.post("/tickets/{source_type}/{source_id}/comments", status_code=status.HTTP_201_CREATED)
async def add_comment(
    source_type: str,
    source_id: str,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Add a comment to a ticket."""
    comment = TicketComment(
        id=str(uuid.uuid4()),
        source_type=source_type,
        source_id=source_id,
        content=data.get("content", ""),
        author_id=str(current_user.id),
        parent_comment_id=data.get("parent_comment_id"),
        mentioned_users=json.dumps(data.get("mentioned_users", [])),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(comment)

    # Log activity
    activity = TicketActivity(
        id=str(uuid.uuid4()),
        source_type=source_type,
        source_id=source_id,
        activity_type="comment_added",
        actor_id=str(current_user.id),
        description=f"Comment added",
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(activity)
    await db.flush()
    await db.refresh(comment)

    return comment


@router.delete("/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_comment(
    comment_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a comment (tenant-scoped)."""
    org_id = getattr(current_user, "organization_id", None)
    result = await db.execute(
        select(TicketComment).where(
            TicketComment.id == comment_id,
            TicketComment.organization_id == org_id,
        )
    )
    comment = result.scalars().first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    await db.delete(comment)
    await db.flush()


# ============================================================================
# ACTIVITY LOG
# ============================================================================


@router.get("/tickets/{source_type}/{source_id}/activity")
async def get_activity_log(
    source_type: str,
    source_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get activity timeline for a ticket (tenant-scoped)."""
    org_id = getattr(current_user, "organization_id", None)
    result = await db.execute(
        select(TicketActivity)
        .where(
            TicketActivity.source_type == source_type,
            TicketActivity.source_id == source_id,
            TicketActivity.organization_id == org_id,
        )
        .order_by(TicketActivity.created_at.desc())
        .limit(100)
    )
    return list(result.scalars().all())


# ============================================================================
# AUTOMATION RULES
# ============================================================================


@router.get("/automation/rules")
async def list_automation_rules(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """List automation rules."""
    org_id = getattr(current_user, "organization_id", None)
    query = select(AutomationRule)
    if org_id:
        query = query.where(AutomationRule.organization_id == org_id)
    query = query.order_by(AutomationRule.priority.desc())
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/automation/rules", status_code=status.HTTP_201_CREATED)
async def create_automation_rule(
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create an automation rule."""
    rule = AutomationRule(
        id=str(uuid.uuid4()),
        name=data.get("name", "New Rule"),
        description=data.get("description"),
        is_enabled=data.get("is_enabled", True),
        trigger_type=data.get("trigger_type", "manual"),
        trigger_conditions=json.dumps(data.get("trigger_conditions", {})),
        actions=json.dumps(data.get("actions", [])),
        priority=data.get("priority", 0),
        cooldown_minutes=data.get("cooldown_minutes", 0),
        created_by=str(current_user.id),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.put("/automation/rules/{rule_id}")
async def update_automation_rule(
    rule_id: str,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an automation rule (tenant-scoped)."""
    org_id = getattr(current_user, "organization_id", None)
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.id == rule_id,
            AutomationRule.organization_id == org_id,
        )
    )
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    for field in ["name", "description", "is_enabled", "trigger_type", "priority", "cooldown_minutes"]:
        if field in data:
            setattr(rule, field, data[field])
    if "trigger_conditions" in data:
        rule.trigger_conditions = json.dumps(data["trigger_conditions"])
    if "actions" in data:
        rule.actions = json.dumps(data["actions"])

    await db.flush()
    await db.refresh(rule)
    return rule


@router.delete("/automation/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_automation_rule(
    rule_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete an automation rule (tenant-scoped)."""
    org_id = getattr(current_user, "organization_id", None)
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.id == rule_id,
            AutomationRule.organization_id == org_id,
        )
    )
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.flush()


# ============================================================================
# TICKET LINKING
# ============================================================================


@router.post("/tickets/{source_type}/{source_id}/links", status_code=status.HTTP_201_CREATED)
async def create_ticket_link(
    source_type: str,
    source_id: str,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Link two tickets together."""
    link = TicketLink(
        id=str(uuid.uuid4()),
        source_type_a=source_type,
        source_id_a=source_id,
        source_type_b=data.get("target_source_type"),
        source_id_b=data.get("target_source_id"),
        link_type=data.get("link_type", "related"),
        created_by=str(current_user.id),
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(link)
    await db.flush()
    await db.refresh(link)
    return link


@router.get("/tickets/{source_type}/{source_id}/links")
async def get_ticket_links(
    source_type: str,
    source_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get linked tickets (tenant-scoped)."""
    org_id = getattr(current_user, "organization_id", None)
    result = await db.execute(
        select(TicketLink).where(
            TicketLink.organization_id == org_id,
            (TicketLink.source_type_a == source_type) & (TicketLink.source_id_a == source_id)
            | (TicketLink.source_type_b == source_type) & (TicketLink.source_id_b == source_id),
        )
    )
    return list(result.scalars().all())


# ============================================================================
# DASHBOARD
# ============================================================================


@router.get("/dashboard")
async def get_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get aggregated ticket hub statistics."""
    org_id = getattr(current_user, "organization_id", None)
    aggregator = TicketAggregator(db)
    return await aggregator.get_dashboard_stats(organization_id=org_id)


# ============================================================================
# HELPER
# ============================================================================


def _get_source_model(source_type: str):
    """Get the SQLAlchemy model for a source type."""
    try:
        if source_type == "incident":
            from src.models.incident import Incident
            return Incident
        elif source_type == "case_task":
            from src.models.case import Task
            return Task
        elif source_type == "remediation_ticket":
            from src.exposure.models import RemediationTicket
            return RemediationTicket
        elif source_type == "action_item":
            from src.collaboration.models import ActionItem
            return ActionItem
        elif source_type == "poam":
            from src.compliance.models import POAM
            return POAM
    except ImportError:
        pass
    return None
