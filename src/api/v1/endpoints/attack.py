"""MITRE ATT&CK knowledge base API (read-only reference data + sync)."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from src.api.deps import CurrentUser, DatabaseSession
from src.attack.models import AttackSyncState, AttackTechnique
from src.attack.service import AttackService
from src.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/attack", tags=["mitre-attack"])


@router.get("/status")
async def attack_status(db: DatabaseSession = None, current_user: CurrentUser = None):
    """Loaded ATT&CK dataset version + object counts."""
    state = (await db.execute(select(AttackSyncState))).scalars().first()
    tech_count = (await db.execute(select(func.count()).select_from(AttackTechnique))).scalar() or 0
    if state is None:
        return {"status": "empty", "techniques": 0, "note": "ATT&CK KB not synced — POST /attack/sync"}
    return {
        "status": state.status,
        "attack_version": state.attack_version,
        "domains": state.domains,
        "techniques": tech_count,
        "object_counts": state.object_counts,
        "source_release": state.source_release,
        "last_error": state.last_error,
    }


@router.get("/techniques/{external_id}")
async def get_technique(external_id: str, db: DatabaseSession = None, current_user: CurrentUser = None):
    """Full context for one technique (tactics, mitigations, groups, software, data sources)."""
    tech = await AttackService(db).get_technique(external_id.upper())
    if tech is None:
        raise HTTPException(status_code=404, detail=f"Technique {external_id} not found")
    return tech


@router.get("/techniques")
async def list_techniques(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    tactic: Optional[str] = Query(None, description="tactic shortname, e.g. credential-access"),
    platform: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    include_subtechniques: bool = Query(True),
    include_deprecated: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    q = select(AttackTechnique)
    if domain:
        q = q.where(AttackTechnique.domain == domain)
    if not include_subtechniques:
        q = q.where(AttackTechnique.is_subtechnique == False)  # noqa: E712
    if not include_deprecated:
        q = q.where(AttackTechnique.is_deprecated == False)  # noqa: E712
    q = q.order_by(AttackTechnique.external_id).limit(limit).offset(offset)
    rows = (await db.execute(q)).scalars().all()
    # tactic/platform live in JSON columns — filter in Python.
    out = []
    for t in rows:
        if tactic and tactic not in (t.tactics or []):
            continue
        if platform and platform not in (t.platforms or []):
            continue
        out.append({
            "external_id": t.external_id, "name": t.name, "domain": t.domain,
            "tactics": t.tactics or [], "platforms": t.platforms or [],
            "is_subtechnique": t.is_subtechnique, "is_deprecated": t.is_deprecated,
        })
    return {"techniques": out, "count": len(out)}


@router.get("/search")
async def search_attack(
    q: str = Query(..., min_length=1),
    limit: int = Query(25, ge=1, le=100),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    return await AttackService(db).search(q, limit=limit)


@router.get("/coverage")
async def attack_coverage(
    technique_ids: str = Query(..., description="comma-separated technique ids"),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Detection-rule coverage per technique (blind-spot map)."""
    ids = [t.strip().upper() for t in technique_ids.split(",") if t.strip()]
    return {"coverage": await AttackService(db).coverage(ids)}


@router.post("/sync")
async def sync_attack(db: DatabaseSession = None, current_user: CurrentUser = None):
    """Download + load the pinned ATT&CK dataset (Enterprise + ICS). Superuser only."""
    if not getattr(current_user, "is_superuser", False):
        raise HTTPException(status_code=403, detail="ATT&CK sync requires superuser")
    from src.attack.sync import sync_attack_kb
    result = await sync_attack_kb(db)
    if result.get("status") == "failed":
        raise HTTPException(status_code=502, detail=f"ATT&CK sync failed: {result.get('error')}")
    return result
