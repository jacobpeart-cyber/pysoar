"""Exposure risk scoring written onto the stored rows.

Every number here is derived from stored columns; nothing is estimated from
counts of unrelated rows.

Link (asset-vulnerability) risk, 0-100::

    base      = CVSS v3, else CVSS v2, else the severity default below (0-10)
    exploit   = 1.30 if the CVE is exploited in the wild (KEV)
                else 1.25 / 1.15 / 1.05 for weaponized / functional / poc
                else 1.10 if any exploit is available, else 1.00
    asset     = 1.20 / 1.10 / 1.00 / 0.80 for critical / high / medium / low
    internet  = 1.15 when the asset is internet-facing
    controls  = max(0.5, 1 - 0.1 x compensating controls recorded on the link)
    risk      = min(100, base x 10 x exploit x asset x internet x controls)

Asset risk = highest open-link risk + 2 per further open link, capped at 100;
0 when the asset has no open or in-progress link. ``vulnerability_count`` is
the number of open or in-progress links.

Organisation risk (dashboard / daily snapshot) = mean asset risk over active
assets; None when there are no active assets.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.exposure.models import AssetVulnerability, ExposureAsset, ExposureVulnerability

logger = get_logger(__name__)

#: Severity default used only when a catalogue row has no CVSS score.
SEVERITY_BASE: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 0.5,
    "unknown": 5.0,
}
EXPLOIT_MATURITY_FACTOR: dict[str, float] = {"weaponized": 1.25, "functional": 1.15, "poc": 1.05}
CRITICALITY_FACTOR: dict[str, float] = {"critical": 1.2, "high": 1.1, "medium": 1.0, "low": 0.8}
OPEN_LINK_STATUSES: tuple[str, ...] = ("open", "in_progress")

#: Assets rescored per window, and the per-call ceiling for an org sweep.
RESCORE_BATCH = 200
MAX_RESCORE_ASSETS_PER_RUN = 50_000


def link_risk(
    *,
    cvss_v3: Optional[float],
    cvss_v2: Optional[float],
    severity: Optional[str],
    is_exploited_in_wild: bool,
    exploit_available: bool,
    exploit_maturity: Optional[str],
    asset_criticality: Optional[str],
    internet_facing: bool,
    compensating_controls: int = 0,
) -> float:
    """Risk of one vulnerability on one asset (formula in the module docstring)."""
    if cvss_v3 is not None:
        base = float(cvss_v3)
    elif cvss_v2 is not None:
        base = float(cvss_v2)
    else:
        base = SEVERITY_BASE.get((severity or "unknown").lower(), SEVERITY_BASE["unknown"])
    if is_exploited_in_wild:
        exploit = 1.30
    elif (exploit_maturity or "").lower() in EXPLOIT_MATURITY_FACTOR:
        exploit = EXPLOIT_MATURITY_FACTOR[(exploit_maturity or "").lower()]
    elif exploit_available:
        exploit = 1.10
    else:
        exploit = 1.0
    asset = CRITICALITY_FACTOR.get((asset_criticality or "medium").lower(), 1.0)
    internet = 1.15 if internet_facing else 1.0
    controls = max(0.5, 1.0 - 0.1 * max(0, compensating_controls))
    return round(min(100.0, base * 10.0 * exploit * asset * internet * controls), 2)


def asset_risk(open_link_scores: Iterable[float]) -> float:
    """Highest open-link risk + 2 per further open link, capped at 100."""
    scores = sorted((float(s) for s in open_link_scores), reverse=True)
    if not scores:
        return 0.0
    return round(min(100.0, scores[0] + 2.0 * (len(scores) - 1)), 2)


async def rescore_assets(db: AsyncSession, organization_id: str, asset_ids: Iterable[str]) -> dict[str, int]:
    """Recompute link and asset risk for ``asset_ids`` (in windows) and write them."""
    ids = sorted({a for a in asset_ids if a})
    links_scored = 0
    assets_scored = 0
    for offset in range(0, len(ids), RESCORE_BATCH):
        chunk = ids[offset : offset + RESCORE_BATCH]
        assets = {
            row.id: row
            for row in (
                await db.execute(
                    select(ExposureAsset.id, ExposureAsset.criticality, ExposureAsset.is_internet_facing).where(
                        ExposureAsset.organization_id == organization_id, ExposureAsset.id.in_(chunk),
                    ),
                )
            ).all()
        }
        if not assets:
            continue
        rows = (
            await db.execute(
                select(
                    AssetVulnerability.id,
                    AssetVulnerability.asset_id,
                    AssetVulnerability.compensating_controls,
                    ExposureVulnerability.cvss_v3_score,
                    ExposureVulnerability.cvss_v2_score,
                    ExposureVulnerability.severity,
                    ExposureVulnerability.is_exploited_in_wild,
                    ExposureVulnerability.exploit_available,
                    ExposureVulnerability.exploit_maturity,
                    ExposureVulnerability.epss_score,
                )
                .join(ExposureVulnerability, AssetVulnerability.vulnerability_id == ExposureVulnerability.id)
                .where(
                    AssetVulnerability.organization_id == organization_id,
                    AssetVulnerability.asset_id.in_(list(assets)),
                    AssetVulnerability.status.in_(OPEN_LINK_STATUSES),
                ),
            )
        ).all()
        by_asset: dict[str, list[float]] = {aid: [] for aid in assets}
        link_updates: list[dict[str, Any]] = []
        for r in rows:
            asset = assets[r.asset_id]
            score = link_risk(
                cvss_v3=r.cvss_v3_score,
                cvss_v2=r.cvss_v2_score,
                severity=r.severity,
                is_exploited_in_wild=bool(r.is_exploited_in_wild),
                exploit_available=bool(r.exploit_available),
                exploit_maturity=r.exploit_maturity,
                asset_criticality=asset.criticality,
                internet_facing=bool(asset.is_internet_facing),
                compensating_controls=len(r.compensating_controls or []),
            )
            by_asset[r.asset_id].append(score)
            impact = r.cvss_v3_score if r.cvss_v3_score is not None else r.cvss_v2_score
            values: dict[str, Any] = {"id": r.id, "risk_score": score}
            if impact is not None:
                values["impact_score"] = round(float(impact) * 10.0, 2)
            if r.epss_score is not None:
                values["exploitability_score"] = round(float(r.epss_score) * 100.0, 2)
            elif r.is_exploited_in_wild:
                values["exploitability_score"] = 100.0
            link_updates.append(values)
        # Group by key set: the ORM bulk UPDATE needs uniform parameter sets.
        groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for values in link_updates:
            groups.setdefault(tuple(sorted(values)), []).append(values)
        for group in groups.values():
            await db.execute(update(AssetVulnerability), group)
        links_scored += len(link_updates)
        await db.execute(
            update(ExposureAsset),
            [
                {"id": aid, "risk_score": asset_risk(scores), "vulnerability_count": len(scores)}
                for aid, scores in by_asset.items()
            ],
        )
        assets_scored += len(by_asset)
    await db.flush()
    return {"assets_scored": assets_scored, "links_scored": links_scored}


async def rescore_organization(
    db: AsyncSession, organization_id: str, max_assets: int = MAX_RESCORE_ASSETS_PER_RUN,
) -> dict[str, Any]:
    """Rescore every asset of the org in keyset windows (capped per call)."""
    last_id: Optional[str] = None
    totals = {"assets_scored": 0, "links_scored": 0}
    truncated = False
    while True:
        if totals["assets_scored"] >= max_assets:
            truncated = True
            break
        stmt = select(ExposureAsset.id).where(ExposureAsset.organization_id == organization_id)
        if last_id is not None:
            stmt = stmt.where(ExposureAsset.id > last_id)
        window = min(RESCORE_BATCH, max_assets - totals["assets_scored"])
        ids = list((await db.execute(stmt.order_by(ExposureAsset.id).limit(window))).scalars())
        if not ids:
            break
        last_id = ids[-1]
        result = await rescore_assets(db, organization_id, ids)
        totals["assets_scored"] += result["assets_scored"]
        totals["links_scored"] += result["links_scored"]
        await db.commit()
        if len(ids) < window:
            break
    if truncated:
        logger.warning("exposure rescore hit its per-run asset cap", organization_id=organization_id, cap=max_assets)
    return {**totals, "truncated": truncated}


async def organization_risk(db: AsyncSession, organization_id: str) -> Optional[float]:
    """Mean stored asset risk over active assets; None without active assets."""
    avg = (
        await db.execute(
            select(func.avg(ExposureAsset.risk_score)).where(
                and_(ExposureAsset.organization_id == organization_id, ExposureAsset.is_active == True),  # noqa: E712
            ),
        )
    ).scalar()
    return round(float(avg), 1) if avg is not None else None


def utc_day(moment: Optional[datetime] = None) -> str:
    return (moment or datetime.now(timezone.utc)).date().isoformat()
