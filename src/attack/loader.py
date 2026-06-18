"""STIX 2.1 → ATT&CK KB loader.

Parses a MITRE ATT&CK STIX bundle into the normalized attack_kb_*
tables. Two passes: pass 1 upserts objects and builds a stix_id →
external_id map; pass 2 resolves `relationship` objects into junction
rows using that map (so forward references and load order don't matter).

Idempotent: upserts by stix_id, and clears+reloads this domain's
relationship junctions on each run.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.attack.models import (
    AttackDataComponent,
    AttackGroup,
    AttackGroupTechnique,
    AttackMitigation,
    AttackSoftware,
    AttackSoftwareTechnique,
    AttackSyncState,
    AttackTactic,
    AttackTechnique,
    AttackTechniqueDataComponent,
    AttackTechniqueMitigation,
)

logger = logging.getLogger(__name__)


def _ext_id(obj: dict) -> Optional[str]:
    """Pull the ATT&CK external id (Txxxx / Gxxxx / ...) from a STIX object."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _is_deprecated(obj: dict) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


async def _upsert(db: AsyncSession, model, stix_id: str, values: dict):
    """Insert or update a KB row by stix_id."""
    row = (await db.execute(select(model).where(model.stix_id == stix_id))).scalar_one_or_none()
    if row is None:
        db.add(model(stix_id=stix_id, **values))
    else:
        for k, v in values.items():
            setattr(row, k, v)


async def load_stix_bundle(
    db: AsyncSession,
    bundle: dict,
    domain: str,
    attack_version: Optional[str] = None,
    source_release: Optional[str] = None,
) -> dict[str, int]:
    """Load one STIX bundle (one domain) into the KB. Returns object counts."""
    objects = bundle.get("objects", [])
    counts = {"tactics": 0, "techniques": 0, "mitigations": 0, "groups": 0,
              "software": 0, "data_components": 0, "relationships": 0}

    # stix_id -> external_id (and data-component stix_id -> name) for pass 2.
    stix_to_ext: dict[str, str] = {}
    dc_stix_to_name: dict[str, str] = {}
    ds_stix_to_name: dict[str, str] = {}
    # v16+ detection chain: detection-strategy -> analytics -> log sources.
    analytic_log_sources: dict[str, list] = {}   # analytic stix_id -> [{component_ref, name}]
    ds_analytic_refs: dict[str, list] = {}        # detection-strategy stix_id -> [analytic stix_id]

    # --- Pass 1: objects ---
    for obj in objects:
        otype = obj.get("type")
        if otype == "x-mitre-data-source":
            ds_stix_to_name[obj["id"]] = obj.get("name", "")
            continue
        if otype == "x-mitre-analytic":
            analytic_log_sources[obj["id"]] = [
                {"component_ref": ls.get("x_mitre_data_component_ref"), "name": ls.get("name")}
                for ls in obj.get("x_mitre_log_source_references", []) or []
            ]
            continue
        if otype == "x-mitre-detection-strategy":
            ds_analytic_refs[obj["id"]] = obj.get("x_mitre_analytic_refs", []) or []
            continue
        if otype == "relationship":
            continue

        ext = _ext_id(obj)
        if otype == "x-mitre-tactic":
            if not ext:
                continue
            stix_to_ext[obj["id"]] = ext
            await _upsert(db, AttackTactic, obj["id"], {
                "external_id": ext, "name": obj.get("name", ""),
                "shortname": obj.get("x_mitre_shortname"),
                "description": obj.get("description"), "domain": domain,
                "attack_version": attack_version,
            })
            counts["tactics"] += 1
        elif otype == "attack-pattern":
            if not ext:
                continue
            stix_to_ext[obj["id"]] = ext
            phases = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])
                      if p.get("kill_chain_name") == "mitre-attack"]
            await _upsert(db, AttackTechnique, obj["id"], {
                "external_id": ext, "name": obj.get("name", ""),
                "description": obj.get("description"), "domain": domain,
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "tactics": phases,
                "platforms": obj.get("x_mitre_platforms", []) or [],
                "detection": obj.get("x_mitre_detection"),
                "data_sources": obj.get("x_mitre_data_sources", []) or [],
                "is_deprecated": _is_deprecated(obj),
                "attack_version": attack_version,
                # parent_external_id is set in pass 2 from subtechnique-of.
            })
            counts["techniques"] += 1
        elif otype == "course-of-action":
            if not ext:
                continue
            stix_to_ext[obj["id"]] = ext
            await _upsert(db, AttackMitigation, obj["id"], {
                "external_id": ext, "name": obj.get("name", ""),
                "description": obj.get("description"), "domain": domain,
                "is_deprecated": _is_deprecated(obj),
            })
            counts["mitigations"] += 1
        elif otype == "intrusion-set":
            if not ext:
                continue
            stix_to_ext[obj["id"]] = ext
            await _upsert(db, AttackGroup, obj["id"], {
                "external_id": ext, "name": obj.get("name", ""),
                "description": obj.get("description"),
                "aliases": obj.get("aliases", []) or [],
                "is_deprecated": _is_deprecated(obj),
            })
            counts["groups"] += 1
        elif otype in ("malware", "tool"):
            if not ext:
                continue
            stix_to_ext[obj["id"]] = ext
            await _upsert(db, AttackSoftware, obj["id"], {
                "external_id": ext, "name": obj.get("name", ""),
                "description": obj.get("description"),
                "software_type": "tool" if otype == "tool" else "malware",
                "aliases": obj.get("x_mitre_aliases", []) or [],
                "platforms": obj.get("x_mitre_platforms", []) or [],
                "is_deprecated": _is_deprecated(obj),
            })
            counts["software"] += 1
        elif otype == "x-mitre-data-component":
            dc_stix_to_name[obj["id"]] = obj.get("name", "")
            await _upsert(db, AttackDataComponent, obj["id"], {
                "name": obj.get("name", ""),
                "data_source_name": None,  # resolved below if ref present
                "description": obj.get("description"),
            })
            counts["data_components"] += 1

    await db.flush()

    # Resolve data-component → data-source names now that both are known.
    for obj in objects:
        if obj.get("type") == "x-mitre-data-component":
            ds_ref = obj.get("x_mitre_data_source_ref")
            ds_name = ds_stix_to_name.get(ds_ref)
            if ds_name:
                row = (await db.execute(
                    select(AttackDataComponent).where(AttackDataComponent.stix_id == obj["id"])
                )).scalar_one_or_none()
                if row:
                    row.data_source_name = ds_name

    # --- Pass 2: relationships (clear this domain's junctions first) ---
    # Junctions are keyed by external id; clearing by the techniques in
    # this domain keeps reloads idempotent without cross-domain wipeout.
    domain_tech_ids = set((await db.execute(
        select(AttackTechnique.external_id).where(AttackTechnique.domain == domain)
    )).scalars().all())

    for junction, col in (
        (AttackTechniqueMitigation, AttackTechniqueMitigation.technique_external_id),
        (AttackGroupTechnique, AttackGroupTechnique.technique_external_id),
        (AttackSoftwareTechnique, AttackSoftwareTechnique.technique_external_id),
        (AttackTechniqueDataComponent, AttackTechniqueDataComponent.technique_external_id),
    ):
        if domain_tech_ids:
            await db.execute(delete(junction).where(col.in_(domain_tech_ids)))
    await db.flush()

    seen_tm, seen_gt, seen_st, seen_tdc = set(), set(), set(), set()
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rtype = obj.get("relationship_type")
        src, tgt = obj.get("source_ref"), obj.get("target_ref")

        if rtype == "subtechnique-of":
            sub_ext, parent_ext = stix_to_ext.get(src), stix_to_ext.get(tgt)
            if sub_ext and parent_ext:
                row = (await db.execute(
                    select(AttackTechnique).where(AttackTechnique.external_id == sub_ext)
                )).scalar_one_or_none()
                if row:
                    row.parent_external_id = parent_ext
                counts["relationships"] += 1
        elif rtype == "mitigates":
            m_ext, t_ext = stix_to_ext.get(src), stix_to_ext.get(tgt)
            if m_ext and t_ext and (t_ext, m_ext) not in seen_tm:
                seen_tm.add((t_ext, m_ext))
                db.add(AttackTechniqueMitigation(technique_external_id=t_ext, mitigation_external_id=m_ext))
                counts["relationships"] += 1
        elif rtype == "uses":
            s_ext, t_ext = stix_to_ext.get(src), stix_to_ext.get(tgt)
            # target must be a technique
            if not (t_ext and t_ext.startswith("T")):
                continue
            if src.startswith("intrusion-set--") and s_ext and (s_ext, t_ext) not in seen_gt:
                seen_gt.add((s_ext, t_ext))
                db.add(AttackGroupTechnique(group_external_id=s_ext, technique_external_id=t_ext))
                counts["relationships"] += 1
            elif src.split("--")[0] in ("malware", "tool") and s_ext and (s_ext, t_ext) not in seen_st:
                seen_st.add((s_ext, t_ext))
                db.add(AttackSoftwareTechnique(software_external_id=s_ext, technique_external_id=t_ext))
                counts["relationships"] += 1
        elif rtype == "revoked-by":
            old_ext, new_ext = stix_to_ext.get(src), stix_to_ext.get(tgt)
            if old_ext and new_ext:
                row = (await db.execute(
                    select(AttackTechnique).where(AttackTechnique.external_id == old_ext)
                )).scalar_one_or_none()
                if row:
                    row.is_deprecated = True
                    row.revoked_by = new_ext
        elif rtype == "detects":
            t_ext = stix_to_ext.get(tgt)
            if not (t_ext and t_ext.startswith("T")):
                continue
            # v16+: source is a detection-strategy -> analytics -> log
            # sources. Resolve the whole chain to (data_component,
            # log_source) pairs. v15-: source is a data component directly.
            pairs = []  # (data_component_name, log_source_name)
            if src in ds_analytic_refs:
                for an_id in ds_analytic_refs[src]:
                    for ls in analytic_log_sources.get(an_id, []):
                        dc_name = dc_stix_to_name.get(ls.get("component_ref")) or ""
                        pairs.append((dc_name, ls.get("name")))
            elif src in dc_stix_to_name:
                pairs.append((dc_stix_to_name[src], None))

            for dc_name, log_source in pairs:
                if not dc_name and not log_source:
                    continue
                key = (t_ext, dc_name, log_source)
                if key in seen_tdc:
                    continue
                seen_tdc.add(key)
                db.add(AttackTechniqueDataComponent(
                    technique_external_id=t_ext,
                    data_component_name=dc_name or "(unspecified)",
                    log_source_name=log_source,
                ))
                counts["relationships"] += 1

    await db.flush()

    # --- Sync state ---
    state = (await db.execute(select(AttackSyncState))).scalars().first()
    total_tech = (await db.execute(
        select(AttackTechnique.external_id)
    )).scalars().all()
    if state is None:
        state = AttackSyncState()
        db.add(state)
    state.attack_version = attack_version
    domains = set(state.domains or [])
    domains.add(domain)
    state.domains = sorted(domains)
    oc = dict(state.object_counts or {})
    oc[domain] = counts
    state.object_counts = oc
    state.source_release = source_release
    state.status = "loaded"
    state.last_error = None
    state.techniques_count = len(set(total_tech))

    logger.info("Loaded ATT&CK %s domain=%s counts=%s", attack_version, domain, counts)
    return counts
