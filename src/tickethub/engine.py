"""
Ticket Hub Aggregation Engine.

Queries all 8 source ticket systems, normalizes to a common shape,
and provides kanban board grouping with status mapping.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Kanban column mapping for each source type
KANBAN_MAP = {
    "incident": {
        "new": ["open"],
        "in_progress": ["investigating", "containment", "eradication"],
        "review": ["recovery"],
        "closed": ["closed"],
    },
    "case_task": {
        "new": ["pending"],
        "in_progress": ["in_progress"],
        "review": ["review"],
        "closed": ["completed", "done"],
    },
    "remediation_ticket": {
        "new": ["open"],
        "in_progress": ["assigned", "in_progress"],
        "review": ["verification"],
        "closed": ["closed", "reopened"],
    },
    "remediation_execution": {
        "new": ["pending", "awaiting_approval"],
        "in_progress": ["approved", "running"],
        "review": ["completed"],
        "closed": ["failed", "rolled_back", "cancelled", "timed_out"],
    },
    "action_item": {
        "new": ["pending"],
        "in_progress": ["in_progress"],
        "review": ["blocked"],
        "closed": ["completed", "cancelled"],
    },
    "poam": {
        "new": ["open"],
        "in_progress": ["in_progress"],
        "review": ["delayed"],
        "closed": ["completed", "cancelled", "accepted"],
    },
    "compliance_control": {
        "new": ["not_implemented", "planned"],
        "in_progress": ["partially_implemented"],
        "review": ["implemented"],
        "closed": ["not_applicable"],
    },
    "compliance_evidence": {
        "new": ["pending"],
        "in_progress": ["pending"],
        "review": ["reviewed"],
        "closed": ["approved", "rejected"],
    },
}


def _get_kanban_column(source_type: str, status: str) -> str:
    """Map a source-specific status to a kanban column."""
    mapping = KANBAN_MAP.get(source_type, {})
    status_lower = (status or "").lower()
    for column, statuses in mapping.items():
        if status_lower in statuses:
            return column
    return "new"


def _safe_str(val) -> Optional[str]:
    return str(val) if val is not None else None


def _safe_date(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


class TicketAggregator:
    """Aggregates tickets from all PySOAR modules into a unified view."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_unified_tickets(
        self,
        organization_id: Optional[str] = None,
        source_types: Optional[List[str]] = None,
        kanban_column: Optional[str] = None,
        search: Optional[str] = None,
        assigned_to: Optional[str] = None,
        priority: Optional[str] = None,
        page: int = 1,
        size: int = 50,
    ) -> Dict[str, Any]:
        """Query all source tables and return normalized tickets."""

        # Run all queries in parallel
        tasks = []
        requested_types = source_types or [
            "incident", "case_task", "remediation_ticket",
            "action_item", "poam",
        ]

        if "incident" in requested_types:
            tasks.append(self._fetch_incidents(organization_id))
        if "case_task" in requested_types:
            tasks.append(self._fetch_case_tasks(organization_id))
        if "remediation_ticket" in requested_types:
            tasks.append(self._fetch_remediation_tickets(organization_id))
        if "action_item" in requested_types:
            tasks.append(self._fetch_action_items(organization_id))
        if "poam" in requested_types:
            tasks.append(self._fetch_poams(organization_id))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten and filter
        all_tickets = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Ticket fetch failed: {result}")
                continue
            all_tickets.extend(result)

        # Apply filters
        if kanban_column:
            all_tickets = [t for t in all_tickets if t["kanban_column"] == kanban_column]
        if search:
            search_lower = search.lower()
            all_tickets = [t for t in all_tickets if search_lower in (t.get("title", "") or "").lower() or search_lower in (t.get("description", "") or "").lower()]
        if assigned_to:
            all_tickets = [t for t in all_tickets if t.get("assigned_to") == assigned_to]
        if priority:
            all_tickets = [t for t in all_tickets if t.get("priority") == priority]

        # Sort by created_at desc
        all_tickets.sort(key=lambda t: t.get("created_at", ""), reverse=True)

        # Paginate
        total = len(all_tickets)
        start = (page - 1) * size
        items = all_tickets[start:start + size]

        return {
            "items": items,
            "total": total,
            "page": page,
            "size": size,
            "pages": (total + size - 1) // size,
        }

    async def get_kanban_board(self, organization_id: Optional[str] = None) -> Dict[str, List]:
        """Get tickets grouped into kanban columns."""
        result = await self.get_unified_tickets(organization_id=organization_id, size=500)
        tickets = result["items"]

        board = {"new": [], "in_progress": [], "review": [], "closed": []}
        for ticket in tickets:
            col = ticket.get("kanban_column", "new")
            if col in board:
                board[col].append(ticket)

        return board

    async def get_dashboard_stats(self, organization_id: Optional[str] = None) -> Dict:
        """Get aggregated ticket statistics."""
        result = await self.get_unified_tickets(organization_id=organization_id, size=1000)
        tickets = result["items"]

        by_source = {}
        by_column = {"new": 0, "in_progress": 0, "review": 0, "closed": 0}
        by_priority = {}
        overdue = 0

        now = datetime.now(timezone.utc)
        for t in tickets:
            src = t.get("source_type", "unknown")
            by_source[src] = by_source.get(src, 0) + 1

            col = t.get("kanban_column", "new")
            if col in by_column:
                by_column[col] += 1

            pri = t.get("priority", "medium")
            by_priority[pri] = by_priority.get(pri, 0) + 1

            due = t.get("due_date")
            if due and col not in ("closed",):
                try:
                    due_dt = datetime.fromisoformat(due.replace("Z", "+00:00")) if isinstance(due, str) else due
                    if due_dt < now:
                        overdue += 1
                except (ValueError, TypeError):
                    pass

        return {
            "total_tickets": len(tickets),
            "by_source_type": by_source,
            "by_kanban_column": by_column,
            "by_priority": by_priority,
            "overdue_count": overdue,
            "open_count": by_column["new"] + by_column["in_progress"] + by_column["review"],
            "closed_count": by_column["closed"],
        }

    # --- Source fetchers ---

    async def _fetch_incidents(self, org_id: Optional[str]) -> List[Dict]:
        from src.models.incident import Incident
        query = select(Incident)
        if org_id:
            query = query.where(Incident.organization_id == org_id) if hasattr(Incident, "organization_id") else query
        query = query.order_by(Incident.created_at.desc()).limit(200)
        result = await self.db.execute(query)
        return [self._normalize_incident(r) for r in result.scalars().all()]

    async def _fetch_case_tasks(self, org_id: Optional[str]) -> List[Dict]:
        from src.models.case import Task
        query = select(Task).order_by(Task.created_at.desc()).limit(200)
        result = await self.db.execute(query)
        return [self._normalize_case_task(r) for r in result.scalars().all()]

    async def _fetch_remediation_tickets(self, org_id: Optional[str]) -> List[Dict]:
        from src.exposure.models import RemediationTicket
        query = select(RemediationTicket)
        if org_id:
            query = query.where(RemediationTicket.organization_id == org_id)
        query = query.order_by(RemediationTicket.created_at.desc()).limit(200)
        result = await self.db.execute(query)
        return [self._normalize_remediation_ticket(r) for r in result.scalars().all()]

    async def _fetch_action_items(self, org_id: Optional[str]) -> List[Dict]:
        from src.collaboration.models import ActionItem
        query = select(ActionItem).order_by(ActionItem.created_at.desc()).limit(200)
        result = await self.db.execute(query)
        return [self._normalize_action_item(r) for r in result.scalars().all()]

    async def _fetch_poams(self, org_id: Optional[str]) -> List[Dict]:
        from src.compliance.models import POAM
        query = select(POAM)
        if org_id:
            query = query.where(POAM.organization_id == org_id)
        query = query.order_by(POAM.created_at.desc()).limit(200)
        result = await self.db.execute(query)
        return [self._normalize_poam(r) for r in result.scalars().all()]

    # --- Normalizers ---

    def _normalize_incident(self, row) -> Dict:
        return {
            "id": row.id,
            "source_type": "incident",
            "source_id": row.id,
            "title": row.title,
            "description": getattr(row, "description", None),
            "status": row.status,
            "kanban_column": _get_kanban_column("incident", row.status),
            "priority": str(getattr(row, "priority", 3)),
            "severity": row.severity,
            "assigned_to": _safe_str(getattr(row, "assigned_to", None)),
            "created_at": _safe_date(row.created_at),
            "updated_at": _safe_date(row.updated_at),
            "due_date": None,
            "source_url": f"/incidents/{row.id}",
            "tags": [],
        }

    def _normalize_case_task(self, row) -> Dict:
        return {
            "id": row.id,
            "source_type": "case_task",
            "source_id": row.id,
            "title": row.title,
            "description": getattr(row, "description", None),
            "status": getattr(row, "status", "pending"),
            "kanban_column": _get_kanban_column("case_task", getattr(row, "status", "pending")),
            "priority": str(getattr(row, "priority", 3)),
            "severity": None,
            "assigned_to": _safe_str(getattr(row, "assigned_to", None)),
            "created_at": _safe_date(row.created_at),
            "updated_at": _safe_date(row.updated_at),
            "due_date": _safe_str(getattr(row, "due_date", None)),
            "source_url": f"/incidents",
            "tags": [],
        }

    def _normalize_remediation_ticket(self, row) -> Dict:
        return {
            "id": row.id,
            "source_type": "remediation_ticket",
            "source_id": row.id,
            "title": row.title,
            "description": getattr(row, "description", None),
            "status": row.status,
            "kanban_column": _get_kanban_column("remediation_ticket", row.status),
            "priority": getattr(row, "priority", "medium"),
            "severity": None,
            "assigned_to": _safe_str(getattr(row, "assigned_to", None)),
            "created_at": _safe_date(row.created_at),
            "updated_at": _safe_date(row.updated_at),
            "due_date": _safe_date(getattr(row, "due_date", None)),
            "source_url": f"/exposure",
            "tags": [],
        }

    def _normalize_action_item(self, row) -> Dict:
        return {
            "id": row.id,
            "source_type": "action_item",
            "source_id": row.id,
            "title": row.title,
            "description": getattr(row, "description", None),
            "status": row.status,
            "kanban_column": _get_kanban_column("action_item", row.status),
            "priority": getattr(row, "priority", "medium"),
            "severity": None,
            "assigned_to": _safe_str(getattr(row, "assigned_to", None)),
            "created_at": _safe_date(row.created_at),
            "updated_at": _safe_date(row.updated_at),
            "due_date": _safe_date(getattr(row, "due_date", None)),
            "source_url": f"/warroom",
            "tags": [],
        }

    def _normalize_poam(self, row) -> Dict:
        return {
            "id": row.id,
            "source_type": "poam",
            "source_id": row.id,
            "title": getattr(row, "weakness_name", "POAM"),
            "description": getattr(row, "weakness_description", None),
            "status": row.status,
            "kanban_column": _get_kanban_column("poam", row.status),
            "priority": getattr(row, "risk_level", "moderate"),
            "severity": getattr(row, "risk_level", None),
            "assigned_to": _safe_str(getattr(row, "assigned_to", None)),
            "created_at": _safe_date(row.created_at),
            "updated_at": _safe_date(row.updated_at),
            "due_date": _safe_date(getattr(row, "scheduled_completion_date", None)),
            "source_url": f"/compliance",
            "tags": [],
        }
