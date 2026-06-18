"""Download + load the real MITRE ATT&CK STIX bundles.

Pinned to a specific release for reproducibility (bump deliberately).
Not run on boot — triggered by `POST /attack/sync` or the
`python -m src.attack.sync` CLI. Prod has the egress; download failure
leaves any previously-loaded data intact.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.attack.loader import load_stix_bundle
from src.attack.models import AttackSyncState

logger = logging.getLogger(__name__)

# Pinned ATT&CK dataset version. Bump when intentionally updating.
ATTACK_VERSION = "19.1"
_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
DEFAULT_DOMAINS = ("enterprise", "ics")


def _domain_url(domain: str, version: str) -> str:
    return f"{_BASE}/{domain}-attack/{domain}-attack-{version}.json"


async def sync_attack_kb(
    db: AsyncSession,
    domains: tuple[str, ...] = DEFAULT_DOMAINS,
    version: str = ATTACK_VERSION,
) -> dict:
    """Download each domain's STIX bundle and load it into the KB."""
    results: dict[str, dict] = {}
    state = (await db.execute(select(AttackSyncState))).scalars().first()
    if state is None:
        state = AttackSyncState()
        db.add(state)
    state.status = "syncing"
    await db.commit()

    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            for domain in domains:
                url = _domain_url(domain, version)
                logger.info("Downloading ATT&CK %s %s", domain, version)
                resp = await client.get(url)
                resp.raise_for_status()
                bundle = resp.json()
                counts = await load_stix_bundle(
                    db, bundle, domain=domain, attack_version=version,
                    source_release=f"attack-stix-data {version}",
                )
                await db.commit()
                results[domain] = counts
        return {"status": "loaded", "version": version, "domains": results}
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        state = (await db.execute(select(AttackSyncState))).scalars().first()
        if state is not None:
            state.status = "failed" if not state.techniques_count else "loaded"
            state.last_error = str(exc)[:500]
            await db.commit()
        logger.error("ATT&CK sync failed: %s", exc)
        return {"status": "failed", "error": str(exc)[:300]}


async def _cli() -> None:
    from src.core.database import async_session_factory
    async with async_session_factory() as db:
        result = await sync_attack_kb(db)
        print(result)


if __name__ == "__main__":
    import asyncio
    asyncio.run(_cli())
