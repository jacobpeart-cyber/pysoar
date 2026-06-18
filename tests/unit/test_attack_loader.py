"""ATT&CK STIX loader — parses MITRE STIX bundles into the KB tables.

Uses a small hand-built STIX bundle (the real shapes, a few objects) so
the parser logic is tested without the 50 MB download.
"""

import pytest
from sqlalchemy import select, func

from src.attack.models import (
    AttackTactic,
    AttackTechnique,
    AttackMitigation,
    AttackGroup,
    AttackSoftware,
    AttackTechniqueMitigation,
    AttackGroupTechnique,
    AttackTechniqueDataComponent,
    AttackSyncState,
)


def _bundle():
    """A miniature but structurally-real enterprise STIX bundle."""
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-tactic", "id": "x-mitre-tactic--aaa",
                "name": "Credential Access", "x_mitre_shortname": "credential-access",
                "description": "Steal credentials.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0006"}],
            },
            {
                "type": "attack-pattern", "id": "attack-pattern--t1110",
                "name": "Brute Force",
                "description": "Adversaries may brute force.",
                "x_mitre_platforms": ["Windows", "Linux"],
                "x_mitre_data_sources": ["Authentication logs"],
                "x_mitre_detection": "Monitor failed logons.",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
            },
            {
                "type": "attack-pattern", "id": "attack-pattern--t1110-001",
                "name": "Password Guessing",
                "description": "Guess passwords.",
                "x_mitre_is_subtechnique": True,
                "x_mitre_platforms": ["Windows"],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.001"}],
            },
            {
                # deprecated/revoked technique — must be flagged, not silently kept
                "type": "attack-pattern", "id": "attack-pattern--t1086",
                "name": "PowerShell (deprecated)",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1086"}],
            },
            {
                "type": "course-of-action", "id": "course-of-action--m1032",
                "name": "Multi-factor Authentication",
                "description": "Use MFA.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "M1032"}],
            },
            {
                "type": "intrusion-set", "id": "intrusion-set--g0016",
                "name": "APT29", "aliases": ["APT29", "Cozy Bear"],
                "description": "Russia-attributed.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}],
            },
            {
                "type": "malware", "id": "malware--s0002",
                "name": "Mimikatz", "x_mitre_aliases": ["Mimikatz"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0002"}],
            },
            {
                "type": "x-mitre-data-component", "id": "x-mitre-data-component--dc1",
                "name": "Logon Session Creation",
                "x_mitre_data_source_ref": "x-mitre-data-source--ds1",
            },
            {
                "type": "x-mitre-data-source", "id": "x-mitre-data-source--ds1",
                "name": "Logon Session",
            },
            # v16+ detection chain: detection-strategy -> analytic -> log source
            {
                "type": "x-mitre-analytic", "id": "x-mitre-analytic--an1",
                "name": "Failed logon analytic",
                "x_mitre_log_source_references": [
                    {"x_mitre_data_component_ref": "x-mitre-data-component--dc1",
                     "name": "linux:syslog", "channel": "auth"},
                ],
            },
            {
                "type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--str1",
                "name": "Brute force detection",
                "x_mitre_analytic_refs": ["x-mitre-analytic--an1"],
            },
            # relationships
            {"type": "relationship", "id": "rel--1", "relationship_type": "subtechnique-of",
             "source_ref": "attack-pattern--t1110-001", "target_ref": "attack-pattern--t1110"},
            {"type": "relationship", "id": "rel--2", "relationship_type": "mitigates",
             "source_ref": "course-of-action--m1032", "target_ref": "attack-pattern--t1110"},
            {"type": "relationship", "id": "rel--3", "relationship_type": "uses",
             "source_ref": "intrusion-set--g0016", "target_ref": "attack-pattern--t1110"},
            {"type": "relationship", "id": "rel--4", "relationship_type": "uses",
             "source_ref": "malware--s0002", "target_ref": "attack-pattern--t1110-001"},
            {"type": "relationship", "id": "rel--5", "relationship_type": "detects",
             "source_ref": "x-mitre-detection-strategy--str1", "target_ref": "attack-pattern--t1110"},
        ],
    }


async def _load(db, **kw):
    from src.attack.loader import load_stix_bundle
    return await load_stix_bundle(db, _bundle(), domain="enterprise", attack_version="17.1", **kw)


@pytest.mark.asyncio
async def test_loads_core_objects(db_session):
    result = await _load(db_session)
    await db_session.commit()

    assert (await db_session.scalar(select(func.count()).select_from(AttackTactic))) == 1
    # 3 techniques incl. the deprecated one
    assert (await db_session.scalar(select(func.count()).select_from(AttackTechnique))) == 3
    assert (await db_session.scalar(select(func.count()).select_from(AttackMitigation))) == 1
    assert (await db_session.scalar(select(func.count()).select_from(AttackGroup))) == 1
    assert (await db_session.scalar(select(func.count()).select_from(AttackSoftware))) == 1
    assert result["techniques"] >= 3


@pytest.mark.asyncio
async def test_subtechnique_parenting_and_fields(db_session):
    await _load(db_session)
    await db_session.commit()

    sub = (await db_session.execute(
        select(AttackTechnique).where(AttackTechnique.external_id == "T1110.001")
    )).scalar_one()
    assert sub.is_subtechnique is True
    assert sub.parent_external_id == "T1110"

    parent = (await db_session.execute(
        select(AttackTechnique).where(AttackTechnique.external_id == "T1110")
    )).scalar_one()
    assert parent.is_subtechnique is False
    assert "credential-access" in parent.tactics
    assert "Windows" in parent.platforms
    assert "failed logons" in (parent.detection or "").lower()


@pytest.mark.asyncio
async def test_deprecated_technique_flagged(db_session):
    await _load(db_session)
    await db_session.commit()
    dep = (await db_session.execute(
        select(AttackTechnique).where(AttackTechnique.external_id == "T1086")
    )).scalar_one()
    assert dep.is_deprecated is True


@pytest.mark.asyncio
async def test_relationships_resolved(db_session):
    await _load(db_session)
    await db_session.commit()

    tm = (await db_session.execute(select(AttackTechniqueMitigation))).scalars().all()
    assert any(r.technique_external_id == "T1110" and r.mitigation_external_id == "M1032" for r in tm)

    gt = (await db_session.execute(select(AttackGroupTechnique))).scalars().all()
    assert any(r.group_external_id == "G0016" and r.technique_external_id == "T1110" for r in gt)

    tdc = (await db_session.execute(select(AttackTechniqueDataComponent))).scalars().all()
    assert any(
        r.technique_external_id == "T1110"
        and r.data_component_name == "Logon Session Creation"
        and r.log_source_name == "linux:syslog"
        for r in tdc
    )


@pytest.mark.asyncio
async def test_idempotent_reload(db_session):
    await _load(db_session)
    await db_session.commit()
    await _load(db_session)
    await db_session.commit()
    # No duplicates on re-run.
    assert (await db_session.scalar(select(func.count()).select_from(AttackTechnique))) == 3
    assert (await db_session.scalar(select(func.count()).select_from(AttackTechniqueMitigation))) == 1


@pytest.mark.asyncio
async def test_sync_state_recorded(db_session):
    await _load(db_session)
    await db_session.commit()
    state = (await db_session.execute(select(AttackSyncState))).scalars().first()
    assert state is not None
    assert state.status == "loaded"
    assert state.attack_version == "17.1"
    assert "enterprise" in state.domains
    assert state.techniques_count == 3
