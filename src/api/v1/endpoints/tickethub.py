"""Unified Ticket Hub API endpoints."""

import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import delete, desc, func, select

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.models.user import UserRole
from src.tickethub.models import (
    AutomationRule,
    AutomationRuleFiring,
    TicketActivity,
    TicketComment,
    TicketLink,
)
from src.tickethub.engine import TicketAggregator
from src.tickethub.rules import (
    RuleInvalidError,
    RuleSpec,
    RuleUnsupportedError,
    get_scoped_ticket,
    parse_rule,
    ticket_model_for,
)

router = APIRouter(prefix="/tickethub", tags=["ticket-hub"])

#: Ticket work (status, kanban, comments, links): analysts and admins.
_ANALYST_WRITE = [Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
#: Automation rules are configuration: admins only.
_ADMIN_WRITE = [Depends(require_role([UserRole.ADMIN]))]


# ============================================================================
# UNIFIED TICKET LIST & KANBAN
# ============================================================================


@router.get("/tickets")
async def list_unified_tickets(
    org_id: OrganizationId,
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
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get detailed view of a specific ticket with comments and activity."""
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


@router.patch("/tickets/{source_type}/{source_id}/status", dependencies=_ANALYST_WRITE)
async def update_ticket_status(
    source_type: str,
    source_id: str,
    org_id: OrganizationId,
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

    record = await _get_scoped_record(db, model, source_id, org_id)
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
        organization_id=org_id,
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
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get kanban board with tickets grouped into 4 columns."""
    aggregator = TicketAggregator(db)
    return await aggregator.get_kanban_board(organization_id=org_id)


@router.post("/kanban/move", dependencies=_ANALYST_WRITE)
async def move_kanban_card(
    org_id: OrganizationId,
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

    record = await _get_scoped_record(db, model, source_id, org_id)
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
        organization_id=org_id,
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
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """List comments on a ticket."""
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


@router.post(
    "/tickets/{source_type}/{source_id}/comments",
    status_code=status.HTTP_201_CREATED,
    dependencies=_ANALYST_WRITE,
)
async def add_comment(
    source_type: str,
    source_id: str,
    org_id: OrganizationId,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Add a comment to one of the caller's tickets."""
    await _require_ticket(db, source_type, source_id, org_id)
    comment = TicketComment(
        id=str(uuid.uuid4()),
        source_type=source_type,
        source_id=source_id,
        content=data.get("content", ""),
        author_id=str(current_user.id),
        parent_comment_id=data.get("parent_comment_id"),
        mentioned_users=json.dumps(data.get("mentioned_users", [])),
        organization_id=org_id,
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
        organization_id=org_id,
    )
    db.add(activity)
    await db.flush()
    await db.refresh(comment)

    return comment


@router.delete("/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=_ANALYST_WRITE)
async def delete_comment(
    comment_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a comment (tenant-scoped)."""
    result = await db.execute(
        select(TicketComment).where(
            TicketComment.id == comment_id,
            TicketComment.organization_id == org_id,
        )
    )
    comment = result.scalars().first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comment.author_id != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "not_comment_author", "detail": "only the author or an admin can delete a comment"},
        )
    await db.delete(comment)
    await db.flush()


# ============================================================================
# ACTIVITY LOG
# ============================================================================


@router.get("/tickets/{source_type}/{source_id}/activity")
async def get_activity_log(
    source_type: str,
    source_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get activity timeline for a ticket (tenant-scoped)."""
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
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """List automation rules."""
    query = select(AutomationRule).where(AutomationRule.organization_id == org_id)
    query = query.order_by(AutomationRule.priority.desc())
    result = await db.execute(query)
    return list(result.scalars().all())


def _validated_rule(trigger_type, trigger_conditions, actions) -> RuleSpec:
    """Validate a rule the evaluator must be able to run, or refuse it.

    501 ``not_implemented`` when the trigger / condition / action cannot be
    evaluated by the platform (the rule would never do anything), 400
    ``invalid_rule`` when the input is malformed.
    """
    try:
        return parse_rule(trigger_type, trigger_conditions, actions)
    except RuleUnsupportedError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={"error": "not_implemented", "reason": exc.reason},
        ) from exc
    except RuleInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_rule", "reason": exc.reason},
        ) from exc


def _int_field(data: dict, key: str) -> int:
    try:
        return int(data.get(key) or 0)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400, detail={"error": "invalid_rule", "reason": f"{key} must be an integer"}
        ) from exc


async def _get_rule_or_404(db, rule_id: str, org_id: str) -> AutomationRule:
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.id == rule_id,
            AutomationRule.organization_id == org_id,
        )
    )
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.post("/automation/rules", status_code=status.HTTP_201_CREATED, dependencies=_ADMIN_WRITE)
async def create_automation_rule(
    org_id: OrganizationId,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create an automation rule the beat evaluator will run.

    Rules the platform cannot evaluate are refused with 501 and the reason
    (see ``src/tickethub/rules.py`` for the supported grammar).
    """
    name = data.get("name").strip() if isinstance(data.get("name"), str) else ""
    if not name:
        raise HTTPException(status_code=400, detail={"error": "invalid_rule", "reason": "name is required"})
    spec = _validated_rule(data.get("trigger_type"), data.get("trigger_conditions"), data.get("actions"))
    rule = AutomationRule(
        id=str(uuid.uuid4()),
        name=name[:255],
        description=data.get("description"),
        is_enabled=bool(data.get("is_enabled", True)),
        trigger_type=str(data["trigger_type"]).strip().lower(),
        trigger_conditions=spec.conditions,
        actions=spec.actions,
        priority=_int_field(data, "priority"),
        cooldown_minutes=max(0, _int_field(data, "cooldown_minutes")),
        created_by=str(current_user.id),
        organization_id=org_id,
        evaluation_status="active",
        # Fires on events from now on, never on history.
        last_evaluated_at=datetime.now(timezone.utc),
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.put("/automation/rules/{rule_id}", dependencies=_ADMIN_WRITE)
async def update_automation_rule(
    rule_id: str,
    org_id: OrganizationId,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update an automation rule (tenant-scoped, re-validated)."""
    rule = await _get_rule_or_404(db, rule_id, org_id)

    rule_shape_changed = any(k in data for k in ("trigger_type", "trigger_conditions", "actions"))
    if rule_shape_changed:
        spec = _validated_rule(
            data.get("trigger_type", rule.trigger_type),
            data.get("trigger_conditions", rule.trigger_conditions),
            data.get("actions", rule.actions),
        )
        if "trigger_type" in data:
            rule.trigger_type = str(data["trigger_type"]).strip().lower()
        rule.trigger_conditions = spec.conditions
        rule.actions = spec.actions
        rule.evaluation_status = "active"
        rule.unsupported_reason = None

    if "name" in data:
        if not isinstance(data["name"], str) or not data["name"].strip():
            raise HTTPException(status_code=400, detail={"error": "invalid_rule", "reason": "name is required"})
        rule.name = data["name"].strip()[:255]
    if "description" in data:
        rule.description = data["description"]
    if "priority" in data:
        rule.priority = _int_field(data, "priority")
    if "cooldown_minutes" in data:
        rule.cooldown_minutes = max(0, _int_field(data, "cooldown_minutes"))
    if "is_enabled" in data:
        enable = bool(data["is_enabled"])
        if enable and not rule.is_enabled:
            if not rule_shape_changed:
                # Re-enabling a stored rule: refuse one the evaluator cannot run.
                _validated_rule(rule.trigger_type, rule.trigger_conditions, rule.actions)
                rule.evaluation_status = "active"
                rule.unsupported_reason = None
            # A paused rule resumes on new events, not on the backlog.
            rule.last_evaluated_at = datetime.now(timezone.utc)
        rule.is_enabled = enable

    await db.flush()
    await db.refresh(rule)
    return rule


@router.get("/automation/rules/{rule_id}/firings")
async def list_automation_rule_firings(
    rule_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    result: Optional[str] = Query(None, description="Filter by outcome (success, failed, ...)"),
):
    """What this rule actually did: one row per (event, action), newest first."""
    rule = await _get_rule_or_404(db, rule_id, org_id)
    base = select(AutomationRuleFiring).where(
        AutomationRuleFiring.rule_id == rule.id,
        AutomationRuleFiring.organization_id == org_id,
    )
    if result:
        base = base.where(AutomationRuleFiring.result == result)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0
    rows = (
        await db.execute(
            base.order_by(desc(AutomationRuleFiring.fired_at), AutomationRuleFiring.id)
            .offset((page - 1) * size)
            .limit(size)
        )
    ).scalars().all()
    return {
        "rule_id": rule.id,
        "execution_count": rule.execution_count,
        "last_triggered_at": rule.last_triggered_at,
        "evaluation_status": rule.evaluation_status,
        "unsupported_reason": rule.unsupported_reason,
        "items": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "organization_id": f.organization_id,
                "target_type": f.target_type,
                "target_id": f.target_id,
                "event_id": f.event_id,
                "action": f.action,
                "result": f.result,
                "error": f.error,
                "detail": f.detail,
                "fired_at": f.fired_at,
            }
            for f in rows
        ],
        "total": total,
        "page": page,
        "size": size,
    }


@router.delete("/automation/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=_ADMIN_WRITE)
async def delete_automation_rule(
    rule_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete an automation rule (tenant-scoped)."""
    result = await db.execute(
        select(AutomationRule).where(
            AutomationRule.id == rule_id,
            AutomationRule.organization_id == org_id,
        )
    )
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    # Firing history goes with the rule (the AuditLog rows stay).
    await db.execute(
        delete(AutomationRuleFiring).where(
            AutomationRuleFiring.rule_id == rule.id,
            AutomationRuleFiring.organization_id == org_id,
        )
    )
    await db.delete(rule)
    await db.flush()


# ============================================================================
# TICKET LINKING
# ============================================================================


@router.post(
    "/tickets/{source_type}/{source_id}/links",
    status_code=status.HTTP_201_CREATED,
    dependencies=_ANALYST_WRITE,
)
async def create_ticket_link(
    source_type: str,
    source_id: str,
    org_id: OrganizationId,
    data: dict = Body(...),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Link two of the caller's tickets together (both must exist in the tenant)."""
    target_type = data.get("target_source_type")
    target_id = data.get("target_source_id")
    if not target_type or not target_id:
        raise HTTPException(status_code=400, detail="target_source_type and target_source_id are required")
    await _require_ticket(db, source_type, source_id, org_id)
    await _require_ticket(db, target_type, target_id, org_id)
    link = TicketLink(
        id=str(uuid.uuid4()),
        source_type_a=source_type,
        source_id_a=source_id,
        source_type_b=data.get("target_source_type"),
        source_id_b=data.get("target_source_id"),
        link_type=data.get("link_type", "related"),
        created_by=str(current_user.id),
        organization_id=org_id,
    )
    db.add(link)
    await db.flush()
    await db.refresh(link)
    return link


@router.get("/tickets/{source_type}/{source_id}/links")
async def get_ticket_links(
    source_type: str,
    source_id: str,
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get linked tickets (tenant-scoped)."""
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
    org_id: OrganizationId,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get aggregated ticket hub statistics."""
    aggregator = TicketAggregator(db)
    return await aggregator.get_dashboard_stats(organization_id=org_id)


# ============================================================================
# HELPER
# ============================================================================


async def _get_scoped_record(db, model, source_id: str, org_id: str):
    """Load a source record only if it belongs to ``org_id`` (see ``get_scoped_ticket``)."""
    return await get_scoped_ticket(db, model, source_id, org_id)


async def _require_ticket(db, source_type: str, source_id: str, org_id: str) -> None:
    """404 unless ``source_type``/``source_id`` names a ticket in the caller's tenant."""
    model = _get_source_model(source_type)
    if not model:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}")
    if await _get_scoped_record(db, model, source_id, org_id) is None:
        raise HTTPException(status_code=404, detail="Ticket not found")


def _get_source_model(source_type: str):
    """Get the SQLAlchemy model for a source type."""
    return ticket_model_for(source_type)
