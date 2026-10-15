"""
Route aliases / flat-list endpoints.

These exist to keep the frontend working when it calls a URL that the
canonical endpoint files don't expose directly (e.g. `/privacy/dsr` where
the canonical is `/privacy/dsr/requests`, or `/dfir/evidence` where the
canonical is `/dfir/cases/{id}/evidence`).

Every route here is wired to a real DB query scoped to the current user's
organization. If the underlying table is empty the response is an honest
empty list — no hardcoded data.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from sqlalchemy import and_, desc, func, or_, select

from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    _organization_required,
)
from src.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["aliases"])


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _org_id(current_user: Any) -> Optional[str]:
    return getattr(current_user, "organization_id", None)


async def _safe_list(
    db,
    model,
    *,
    org_id: Optional[str],
    page: int = 1,
    size: int = 20,
    order_by=None,
    filters: Optional[List] = None,
    include_platform_rows: bool = False,
) -> Dict[str, Any]:
    """Generic paginated list query, scoped to ``org_id``.

    Tenant scoping is mandatory for tenant-owned models: a caller with no
    organisation gets 403 ``organization_required`` (wave 1). With
    ``include_platform_rows`` the platform-scope rows (``organization_id IS
    NULL``, e.g. indicators from global feeds) are listed too, read-only.

    Query failures propagate (the global handler returns a 500 with an error
    key) instead of being disguised as an empty list.
    """
    where_clauses = []
    if hasattr(model, "organization_id"):
        if not org_id:
            raise _organization_required()
        if include_platform_rows:
            where_clauses.append(
                or_(model.organization_id == org_id, model.organization_id.is_(None)),
            )
        else:
            where_clauses.append(model.organization_id == org_id)
    if filters:
        where_clauses.extend(filters)

    stmt = select(model)
    if where_clauses:
        stmt = stmt.where(and_(*where_clauses))

    count_stmt = select(func.count()).select_from(model)
    if where_clauses:
        count_stmt = count_stmt.where(and_(*where_clauses))
    total = (await db.execute(count_stmt)).scalar() or 0

    if order_by is None and hasattr(model, "created_at"):
        order_by = desc(model.created_at)
    if order_by is not None:
        stmt = stmt.order_by(order_by)

    stmt = stmt.offset((page - 1) * size).limit(size)
    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    items = [_row_to_dict(r) for r in rows]
    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size if size else 1,
    }


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Best-effort SQLAlchemy row -> plain dict."""
    try:
        mapper = getattr(row, "__mapper__", None)
        if mapper is not None:
            d: Dict[str, Any] = {}
            for col in mapper.columns:
                val = getattr(row, col.key, None)
                if isinstance(val, datetime):
                    d[col.key] = val.isoformat()
                else:
                    d[col.key] = val
            return d
    except Exception as exc:
        logger.debug("SQLAlchemy row mapping failed; falling back to public attrs", error=str(exc))
    # Fallback: pull public attrs
    return {k: v for k, v in vars(row).items() if not k.startswith("_") and not callable(v)}


# --------------------------------------------------------------------------
# FedRAMP
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# STIG
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Privacy flat aliases
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Risk Quantification
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Threat Intelligence flat aliases
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Threat Modeling
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# DFIR
# --------------------------------------------------------------------------


@router.get("/dfir/evidence")
async def dfir_evidence_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of forensic evidence across all cases in the org."""
    from src.dfir.models import ForensicEvidence

    return await _safe_list(
        db,
        ForensicEvidence,
        org_id=_org_id(current_user),
        page=page,
        size=size,
    )


@router.get("/dfir/legal-holds")
async def dfir_legal_holds_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of legal holds for the org."""
    from src.dfir.models import LegalHold

    return await _safe_list(
        db,
        LegalHold,
        org_id=_org_id(current_user),
        page=page,
        size=size,
    )


# --------------------------------------------------------------------------
# Simulation
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Playbooks
# --------------------------------------------------------------------------


@router.get("/playbooks/executions/recent")
async def playbooks_executions_recent(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    limit: int = Query(20, ge=1, le=200),
):
    """The caller's most recent playbook executions across all their playbooks.

    Always tenant-scoped (executions are stamped with the organisation when
    created); query failures propagate instead of returning an empty list.
    """
    from src.models.playbook import PlaybookExecution

    stmt = (
        select(PlaybookExecution)
        .where(PlaybookExecution.organization_id == org_id)
        .order_by(desc(PlaybookExecution.created_at))
        .limit(limit)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return {"items": [_row_to_dict(r) for r in rows], "total": len(rows)}


# --------------------------------------------------------------------------
# Agentic SOC aliases
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Agent platform
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# SIEM
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# ITDR
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Container Security
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# OT/ICS Security: the dash-prefixed list mirrors (/ot-security/assets, /alerts,
# /zones, /purdue-map) were deleted in wave 4. The frontend calls the canonical
# underscore routes (/ot_security/...) exclusively, and the purdue-map mirror
# always failed (int() of a Purdue level name) behind an empty-map fallback.
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Supply Chain
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Integrations
# --------------------------------------------------------------------------


@router.get("/integrations/executions")
async def integrations_executions_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of integration executions across all installs."""
    from src.integrations.models import IntegrationExecution

    return await _safe_list(
        db,
        IntegrationExecution,
        org_id=_org_id(current_user),
        page=page,
        size=size,
    )


@router.get("/integrations/webhooks")
async def integrations_webhooks_flat(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """Flat list of webhooks across all integrations."""
    from src.integrations.models import WebhookEndpoint

    return await _safe_list(
        db,
        WebhookEndpoint,
        org_id=_org_id(current_user),
        page=page,
        size=size,
    )


# --------------------------------------------------------------------------
# OT Security bulk discover + server-side export: moved in wave 4 to
# POST /ot_security/discover and GET /ot_security/export (src/api/v1/endpoints/
# ot_security.py). The old dash paths answer 410 Gone with the new path and do
# nothing else.
# --------------------------------------------------------------------------

