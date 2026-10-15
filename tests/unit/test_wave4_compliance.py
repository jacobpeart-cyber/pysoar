"""Wave 4 (W4-D): compliance made honest.

The attester asserts only what it checks and records ``not_assessed`` with
the reason otherwise; each assessed control carries its evidence basis; a
manual status is never overwritten; evidence rows are not re-inserted on
every run; the SSP is built from stored system facts with explicit
placeholders; the framework score is refreshed from the controls; the
dashboard trend and score history read stored assessments; POA&M delete is
role-gated and audited; the control filters accept what the page sends; the
BOD 22-01 check is computed; migration 033 round-trips.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy import MetaData, Table, create_engine, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit_evidence.models import AuditTrail
from src.compliance import attester as attester_mod
from src.compliance.attester import ATTESTER_SOURCE, ControlAutoAttester
from src.compliance.models import (
    POAM,
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)
from src.compliance.tasks import compliance_attestation_sweep_async
from src.core.config import settings
from src.core.database import async_session_factory
from src.models.audit import AuditLog
from src.models.base import Base
from src.models.user import User
from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance
from tests.helpers.tenancy import bearer, make_user

BASE = "/api/v1/compliance"
CODES = ("AC-2", "AC-3", "AC-7", "AU-8", "IA-2", "SI-4", "PL-2", "AC-1")


async def _framework(db: AsyncSession, org_id: str, codes: tuple[str, ...] = CODES,
                     short_name: str = "fedramp_moderate") -> tuple[str, dict[str, str]]:
    fw = ComplianceFramework(
        id=str(uuid.uuid4()), name=f"{short_name} {uuid.uuid4().hex[:6]}", short_name=short_name,
        version="Rev 5", authority="tests", organization_id=org_id,
    )
    db.add(fw)
    await db.flush()
    ids: dict[str, str] = {}
    for code in codes:
        c = ComplianceControl(
            id=str(uuid.uuid4()), framework_id=fw.id, control_id=code, control_family="Access Control",
            title=f"{code} control", status="not_implemented", priority="p1", organization_id=org_id,
        )
        db.add(c)
        ids[code] = c.id
    fw_id = fw.id
    await db.commit()
    return fw_id, ids


async def _controls(db: AsyncSession, ids: dict[str, str]) -> dict[str, ComplianceControl]:
    db.expire_all()
    rows = (await db.execute(select(ComplianceControl).where(ComplianceControl.id.in_(list(ids.values()))))).scalars()
    return {r.control_id: r for r in rows}


# ---------------------------------------------------------------------------
# attester
# ---------------------------------------------------------------------------


async def test_attester_asserts_only_what_it_checks(db_session: AsyncSession, org_a, org_a_user) -> None:
    org_id = org_a.id
    fw_id, ids = await _framework(db_session, org_id)

    summary = await ControlAutoAttester(db_session, org_id).attest_all(framework_id=fw_id)
    assert summary["attested"] == len(CODES) - 1  # AC-1 has no rule
    rows = await _controls(db_session, ids)

    # No rule -> untouched.
    assert rows["AC-1"].status == "not_implemented" and rows["AC-1"].assessment_basis is None
    # Procedural controls are not assessed, with the reason.
    for code in ("AC-3", "AU-8", "PL-2"):
        assert rows[code].status == "not_assessed", code
        assert rows[code].last_assessment_result == "not_assessed"
        assert rows[code].assessment_basis["result"] == "not_assessed"
        assert rows[code].assessment_basis["reason"]
    # AC-7 reads the lockout configuration: 5 attempts / 15 min fails the
    # FedRAMP parameters (3 attempts / 30 min).
    assert rows["AC-7"].status == "not_implemented"
    assert rows["AC-7"].assessment_basis["result"] == "fail"
    assert {f["kind"] for f in rows["AC-7"].assessment_basis["basis"]} == {"config"}
    # IA-2: the analyst has no MFA.
    assert rows["IA-2"].assessment_basis["result"] == "fail"
    # SI-4: no logs, no rules.
    assert rows["SI-4"].status == "not_implemented"
    # Nothing is implemented without a check and approved evidence.
    assert not any(r.status == "implemented" for r in rows.values())


async def test_pass_needs_approved_evidence_to_be_implemented(
    db_session: AsyncSession, org_a, org_a_user,
) -> None:
    org_id = org_a.id
    user_id = org_a_user.id
    fw_id, ids = await _framework(db_session, org_id, codes=("IA-2",))
    user = await db_session.get(User, user_id)
    user.mfa_enabled = True
    await db_session.commit()

    await ControlAutoAttester(db_session, org_id).attest_all(framework_id=fw_id)
    row = (await _controls(db_session, ids))["IA-2"]
    assert row.assessment_basis["result"] == "pass"
    assert row.status == "partially_implemented"  # technical check only
    assert row.last_assessment_result == "satisfied"
    assert {"kind": "count", "source": "active users with MFA enabled", "value": 1} in row.assessment_basis["basis"]

    db_session.add(ComplianceEvidence(
        control_id_ref=ids["IA-2"], organization_id=org_id, evidence_type="policy", title="MFA policy",
        collected_by="someone", is_automated=False, is_valid=True, review_status="approved",
    ))
    await db_session.commit()
    await ControlAutoAttester(db_session, org_id).attest_all(framework_id=fw_id)
    row = (await _controls(db_session, ids))["IA-2"]
    assert row.status == "implemented" and row.implementation_status == 100.0
    assert row.assessment_basis["approved_evidence"] is True


async def test_manual_status_is_never_overwritten_and_evidence_is_upserted(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers,
) -> None:
    org_id = org_a.id
    fw_id, ids = await _framework(db_session, org_id, codes=("AC-7", "AU-8"))
    resp = await client.put(
        f"{BASE}/controls/{ids['AC-7']}", json={"status": "implemented"}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status_source"] == "manual"

    for _ in range(2):
        resp = await client.post(f"{BASE}/frameworks/{fw_id}/attest", headers=org_a_admin_headers)
        assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["manual_status_kept"] == 1
    assert {c["control_id"]: c["result"] for c in body["controls"]} == {"AC-7": "fail", "AU-8": "not_assessed"}

    rows = await _controls(db_session, ids)
    assert rows["AC-7"].status == "implemented"  # the person's status stands
    assert rows["AC-7"].assessment_basis["result"] == "fail"  # the check is still recorded
    count = (await db_session.execute(
        select(func.count(ComplianceEvidence.id)).where(
            ComplianceEvidence.organization_id == org_id, ComplianceEvidence.source_system == ATTESTER_SOURCE),
    )).scalar()
    assert count == 2  # one per control, not one per run
    valid = (await db_session.execute(
        select(func.count(ComplianceEvidence.id)).where(
            ComplianceEvidence.organization_id == org_id, ComplianceEvidence.source_system == ATTESTER_SOURCE,
            ComplianceEvidence.is_valid.is_(True)),
    )).scalar()
    assert valid == 0  # neither check passed
    audit = (await db_session.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "compliance_attest", AuditLog.organization_id == org_id),
    )).scalar()
    assert audit == 2


async def test_attest_is_admin_only(
    client: AsyncClient, db_session: AsyncSession, org_a, org_b, org_a_headers, viewer_headers,
) -> None:
    org_b_id = org_b.id
    fw_id, _ = await _framework(db_session, org_a.id, codes=("AU-8",))
    for headers in (org_a_headers, viewer_headers):
        assert (await client.post(f"{BASE}/frameworks/{fw_id}/attest", headers=headers)).status_code == 403
    admin_b = await make_user(db_session, role="admin", organization_id=org_b_id, label="admin-b")
    assert (await client.post(f"{BASE}/frameworks/{fw_id}/attest", headers=bearer(admin_b))).status_code == 404


async def test_a_broken_rule_is_recorded_not_hidden(
    db_session: AsyncSession, org_a, monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(db: AsyncSession, org_id: str) -> Any:
        raise RuntimeError("db down")

    monkeypatch.setitem(attester_mod._RULES, "AU-8", boom)
    fw_id, ids = await _framework(db_session, org_a.id, codes=("AU-8",))
    await ControlAutoAttester(db_session, org_a.id).attest_all(framework_id=fw_id)
    row = (await _controls(db_session, ids))["AU-8"]
    assert row.status == "not_assessed"
    assert "RuntimeError" in row.assessment_basis["reason"]


# ---------------------------------------------------------------------------
# SSP, score, dashboard
# ---------------------------------------------------------------------------


async def test_ssp_is_built_from_stored_facts_with_placeholders(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers,
) -> None:
    fw_id, ids = await _framework(db_session, org_a.id, codes=("AC-2",))
    resp = await client.get(f"{BASE}/frameworks/{fw_id}/ssp", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    ssp = resp.json()
    facts = ssp["system_facts"]
    assert facts["organization"]["name"] == org_a.name
    assert facts["hosting"]["provider"].startswith("[TO BE COMPLETED")
    assert "hosting provider and region(s)" in facts["missing_facts"]
    # A GET runs no attester.
    assert (await _controls(db_session, ids))["AC-2"].assessment_basis is None

    md = await client.get(f"{BASE}/frameworks/{fw_id}/ssp/download", headers=org_a_headers)
    assert md.status_code == 200
    text = md.text
    assert "[TO BE COMPLETED" in text
    for invented in ("GovCloud", "Cloudflare", "KMS", "Multi-AZ"):
        assert invented not in text


async def test_assessment_refreshes_score_and_feeds_the_trend(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.api.v1.endpoints import compliance as compliance_endpoints

    monkeypatch.setattr(compliance_endpoints.run_compliance_assessment, "delay", lambda *_a, **_k: None)
    fw_id, ids = await _framework(db_session, org_a.id, codes=("AC-2", "AU-2"))
    row = await db_session.get(ComplianceControl, ids["AC-2"])
    row.status, row.last_assessment_result = "implemented", "satisfied"
    await db_session.commit()

    resp = await client.post(f"{BASE}/frameworks/{fw_id}/assess", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["compliance_score"] == 50.0
    db_session.expire_all()
    fw = await db_session.get(ComplianceFramework, fw_id)
    assert fw.compliance_score == 50.0 and fw.implemented_controls == 1 and fw.total_controls == 2

    hist = await client.get(f"{BASE}/score-history", headers=org_a_headers)
    assert hist.status_code == 200, hist.text  # used to 500 on control_count
    assert [h["score"] for h in hist.json()["history"]] == [50.0]

    dash = (await client.get(f"{BASE}/dashboard", headers=org_a_headers)).json()
    assert [t["score"] for t in dash["trends"]] == [50.0]
    assert dash["control_status_breakdown"]["implemented"] == 1
    assert dash["control_status_breakdown"]["not_implemented"] == 1


async def test_attestation_sweep_runs_per_org(db_session: AsyncSession, org_a) -> None:
    fw_id, ids = await _framework(db_session, org_a.id, codes=("AU-8", "AC-1"))
    totals = await compliance_attestation_sweep_async(async_session_factory)
    assert totals["frameworks"] >= 1 and totals["controls_attested"] >= 1
    rows = await _controls(db_session, ids)
    assert rows["AU-8"].status == "not_assessed"
    fw = await db_session.get(ComplianceFramework, fw_id)
    assert fw.total_controls == 2


# ---------------------------------------------------------------------------
# POA&M delete, filters, CISA
# ---------------------------------------------------------------------------


async def test_poam_delete_is_gated_scoped_and_audited(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, viewer_headers, org_b_headers,
) -> None:
    _, ids = await _framework(db_session, org_a.id, codes=("AC-2",))
    poam = POAM(
        control_id_ref=ids["AC-2"], weakness_name="w", weakness_source="tests", risk_level="high",
        scheduled_completion_date=datetime.now(timezone.utc) + timedelta(days=5), organization_id=org_a.id,
    )
    db_session.add(poam)
    await db_session.commit()
    poam_id = poam.id
    control = await db_session.get(ComplianceControl, ids["AC-2"])
    control.poam_id = poam_id
    await db_session.commit()

    assert (await client.delete(f"{BASE}/poams/{poam_id}", headers=viewer_headers)).status_code == 403
    assert (await client.delete(f"{BASE}/poams/{poam_id}", headers=org_b_headers)).status_code == 404
    resp = await client.delete(f"{BASE}/poams/{poam_id}", headers=org_a_headers)
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    assert await db_session.get(POAM, poam_id) is None
    assert (await db_session.get(ComplianceControl, ids["AC-2"])).poam_id is None
    trail = (await db_session.execute(
        select(func.count(AuditTrail.id)).where(AuditTrail.action == "poam.delete", AuditTrail.resource_id == poam_id),
    )).scalar()
    assert trail == 1


async def test_control_filters_accept_what_the_page_sends(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers,
) -> None:
    _, ids = await _framework(db_session, org_a.id, codes=("AC-2", "AU-2"), short_name="nist_800_53")
    row = await db_session.get(ComplianceControl, ids["AU-2"])
    row.status = "partially_implemented"
    await db_session.commit()
    got = await client.get(f"{BASE}/controls", params={"framework_id": "nist_800_53", "limit": 100},
                           headers=org_a_headers)
    assert {c["control_id"] for c in got.json()} == {"AC-2", "AU-2"}
    fam = await client.get(f"{BASE}/controls", params={"family": "AU"}, headers=org_a_headers)
    assert [c["control_id"] for c in fam.json()] == ["AU-2"]
    part = await client.get(f"{BASE}/controls", params={"status": "partially"}, headers=org_a_headers)
    assert [c["control_id"] for c in part.json()] == ["AU-2"]


async def test_kev_check_is_computed(db_session: AsyncSession, org_a) -> None:
    from src.compliance.engine import CISAComplianceManager

    mgr = CISAComplianceManager(db_session, org_a.id)
    assert (await mgr.check_kev_compliance())["compliance_status"] == "not_assessed"

    vuln = Vulnerability(
        cve_id="CVE-2021-44228", title="log4shell", severity="critical", kev_listed=True,
        kev_due_date=(datetime.now(timezone.utc) - timedelta(days=3)).date().isoformat(),
        organization_id=org_a.id,
    )
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(VulnerabilityInstance(
        vulnerability_id=vuln.id, asset_name="web-1", status="open", organization_id=org_a.id,
    ))
    await db_session.commit()
    result = await mgr.check_kev_compliance()
    assert result["compliance_status"] == "non_compliant"
    assert result["overdue_cves"] == ["CVE-2021-44228"]


# ---------------------------------------------------------------------------
# migration 033
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "033_compliance_stig_honest_state.py"


def _load_migration() -> ModuleType:
    from tests.unit.test_migration_020 import _real_alembic

    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_033_compliance", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_033_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.unit.test_migration_020 import (
        _alembic_config,
        _async_url,
        _columns,
        _downgrade,
        _engine,
        _in_thread,
        _real_alembic,
        _sync_url,
        _upgrade,
        _version,
    )

    migration = _load_migration()
    assert migration.revision == "033" and migration.down_revision == "032"
    removed = {t: {name for name, _ in cols} for t, cols in migration.ADDITIONS.items()}
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        cols = [c._copy() for c in table.columns if c.name not in removed.get(table.name, set())]
        for c in cols:
            c.index = None
            c.unique = None
        Table(table.name, md, *cols)
    db_path = tmp_path / "pysoar_033.db"
    engine = create_engine(_sync_url(db_path))
    md.create_all(engine)
    now = datetime.now(timezone.utc).isoformat()
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO compliance_controls (id, framework_id, control_id, control_family, title, priority, status, "
            "implementation_status, last_assessment_result, implementation_details, assessment_method, "
            "assessment_frequency, evidence_ids, related_controls, mitre_techniques, risk_if_not_implemented, tags, "
            "organization_id, created_at, updated_at) "
            "VALUES ('c1', 'f1', 'AC-6', 'AC', 't', 'p1', 'implemented', 100, 'satisfied', "
            "'narrative\n\nEvidence:\n  - x', 'automated', 'annual', '[]', '{}', '[]', 'high', '[]', 'o1', :now, :now)",
        ), {"now": now})
        conn.execute(sa.text(
            "INSERT INTO compliance_evidence (id, control_id_ref, evidence_type, title, collected_at, collected_by, "
            "is_automated, is_valid, review_status, source_system, tags, organization_id, created_at, updated_at) "
            "VALUES ('e1', 'c1', 'attestation', 'Auto-attestation: AC-6', :now, 'system', 1, 1, 'pending', "
            "'PySOAR Control Auto-Attester', '[]', 'o1', :now, :now)",
        ), {"now": now})
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "032"))
    fixture_db = {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}

    _upgrade(fixture_db, "033")
    assert _version(fixture_db) == "033"
    with _engine(fixture_db).connect() as conn:
        for table, names in removed.items():
            assert names <= _columns(conn, table), table
        status, details = conn.execute(sa.text(
            "SELECT status, implementation_details FROM compliance_controls WHERE id = 'c1'")).one()
        assert status == "not_assessed" and details is None
        assert conn.execute(sa.text("SELECT is_valid FROM compliance_evidence WHERE id = 'e1'")).scalar() in (0, False)

    _downgrade(fixture_db, "032")
    with _engine(fixture_db).connect() as conn:
        for table, names in removed.items():
            assert not names & _columns(conn, table), table
    _upgrade(fixture_db, "033")
    assert _version(fixture_db) == "033"
