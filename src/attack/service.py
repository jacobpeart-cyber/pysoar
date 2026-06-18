"""ATT&CK query service — reads the KB graph for the API, agent tools,
and the hunt scope phase."""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.attack.models import (
    AttackDataComponent,
    AttackGroup,
    AttackGroupTechnique,
    AttackMitigation,
    AttackSoftware,
    AttackSoftwareTechnique,
    AttackTechnique,
    AttackTechniqueDataComponent,
    AttackTechniqueMitigation,
)

# ATT&CK technique ids: Txxxx optionally .xxx — captured case-sensitively
# (real ids are upper-T) but we also recognize lowercase to normalize.
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class AttackService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_technique(self, external_id: str) -> Optional[dict[str, Any]]:
        tech = (await self.db.execute(
            select(AttackTechnique).where(AttackTechnique.external_id == external_id)
        )).scalar_one_or_none()
        if tech is None:
            return None

        mit_ids = (await self.db.execute(
            select(AttackTechniqueMitigation.mitigation_external_id)
            .where(AttackTechniqueMitigation.technique_external_id == external_id)
        )).scalars().all()
        mitigations = []
        if mit_ids:
            rows = (await self.db.execute(
                select(AttackMitigation).where(AttackMitigation.external_id.in_(mit_ids))
            )).scalars().all()
            mitigations = [{"external_id": m.external_id, "name": m.name} for m in rows]

        grp_ids = (await self.db.execute(
            select(AttackGroupTechnique.group_external_id)
            .where(AttackGroupTechnique.technique_external_id == external_id)
        )).scalars().all()
        groups = []
        if grp_ids:
            rows = (await self.db.execute(
                select(AttackGroup).where(AttackGroup.external_id.in_(grp_ids))
            )).scalars().all()
            groups = [{"external_id": g.external_id, "name": g.name} for g in rows]

        sw_ids = (await self.db.execute(
            select(AttackSoftwareTechnique.software_external_id)
            .where(AttackSoftwareTechnique.technique_external_id == external_id)
        )).scalars().all()
        software = []
        if sw_ids:
            rows = (await self.db.execute(
                select(AttackSoftware).where(AttackSoftware.external_id.in_(sw_ids))
            )).scalars().all()
            software = [{"external_id": s.external_id, "name": s.name} for s in rows]

        dc_rows = (await self.db.execute(
            select(AttackTechniqueDataComponent)
            .where(AttackTechniqueDataComponent.technique_external_id == external_id)
        )).scalars().all()
        data_components = [
            {"data_component": d.data_component_name, "log_source": d.log_source_name,
             "data_source": d.data_source_name}
            for d in dc_rows
        ]
        # Distinct concrete telemetry channels that detect this technique —
        # the actionable "do we collect this?" list.
        log_sources = sorted({d.log_source_name for d in dc_rows if d.log_source_name})

        subs = (await self.db.execute(
            select(AttackTechnique).where(AttackTechnique.parent_external_id == external_id)
        )).scalars().all()
        subtechniques = [{"external_id": s.external_id, "name": s.name} for s in subs]

        return {
            "external_id": tech.external_id,
            "name": tech.name,
            "description": tech.description,
            "domain": tech.domain,
            "is_subtechnique": tech.is_subtechnique,
            "parent_external_id": tech.parent_external_id,
            "tactics": tech.tactics or [],
            "platforms": tech.platforms or [],
            "detection": tech.detection,
            "data_sources": tech.data_sources or [],
            "is_deprecated": tech.is_deprecated,
            "mitigations": mitigations,
            "groups": groups,
            "software": software,
            "data_components": data_components,
            "log_sources": log_sources,
            "subtechniques": subtechniques,
        }

    async def search(self, query: str, limit: int = 25) -> dict[str, list]:
        like = f"%{query}%"
        techs = (await self.db.execute(
            select(AttackTechnique).where(
                or_(AttackTechnique.name.ilike(like), AttackTechnique.external_id.ilike(like))
            ).limit(limit)
        )).scalars().all()
        # Groups: match name OR any alias (aliases is JSON; filter in Python).
        all_groups = (await self.db.execute(select(AttackGroup))).scalars().all()
        q_low = query.lower()
        groups = [
            g for g in all_groups
            if q_low in g.name.lower()
            or any(q_low in str(a).lower() for a in (g.aliases or []))
            or q_low in g.external_id.lower()
        ][:limit]
        sw = (await self.db.execute(
            select(AttackSoftware).where(
                or_(AttackSoftware.name.ilike(like), AttackSoftware.external_id.ilike(like))
            ).limit(limit)
        )).scalars().all()
        return {
            "techniques": [{"external_id": t.external_id, "name": t.name,
                            "is_deprecated": t.is_deprecated} for t in techs],
            "groups": [{"external_id": g.external_id, "name": g.name} for g in groups],
            "software": [{"external_id": s.external_id, "name": s.name,
                          "type": s.software_type} for s in sw],
        }

    async def extract_technique_ids(self, text: str) -> dict[str, list]:
        """Pull technique ids from free text, validated against the KB.

        Returns {valid, deprecated, unknown} — so a hypothesis citing a
        bogus or retired id is surfaced rather than silently hunted.
        """
        candidates = {m.group(0).upper() for m in _TECH_RE.finditer(text or "")}
        valid, deprecated, unknown = [], [], []
        for cand in sorted(candidates):
            tech = (await self.db.execute(
                select(AttackTechnique).where(AttackTechnique.external_id == cand)
            )).scalar_one_or_none()
            if tech is None:
                unknown.append(cand)
            elif tech.is_deprecated:
                deprecated.append(cand)
            else:
                valid.append(cand)
        return {"valid": valid, "deprecated": deprecated, "unknown": unknown}

    async def coverage(self, technique_ids: list[str]) -> list[dict[str, Any]]:
        """For each technique id, how many active detection rules list it."""
        from src.siem.models import DetectionRule

        active = (await self.db.execute(
            select(DetectionRule).where(DetectionRule.enabled == True)  # noqa: E712
        )).scalars().all()
        # Parse each rule's mitre_techniques JSON once.
        rule_techs: list[set] = []
        for r in active:
            try:
                techs = json.loads(r.mitre_techniques or "[]")
                if isinstance(techs, list):
                    rule_techs.append({str(t) for t in techs})
            except (ValueError, TypeError):
                continue

        out = []
        for tid in technique_ids:
            count = sum(1 for s in rule_techs if tid in s)
            out.append({"technique": tid, "covered": count > 0, "rule_count": count})
        return out
