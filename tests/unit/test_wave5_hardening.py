"""Wave 5 (W5-C): residual hardening sweep.

* Zero Trust: the continuous session evaluation is a real, scheduled sync
  task (the async ``@shared_task`` functions could never run); the other six
  were deleted.
* OT: ``/ot_security/compliance/report`` is computed from stored zones and
  assets (pass / fail / not_assessed with the basis) instead of fixed
  passes; serial numbers are unique per organisation (409 in-tenant).
* Migration 035: ``ot_assets.serial_number``, ``siem_data_sources.name`` and
  ``detection_rules.name`` unique per organisation (round trip on SQLite).
* Separation of duties on evidence approval through the audit-evidence
  route; the attestation sweep seeds the FedRAMP catalogue.
* The exposure tasks that wrote without scanning are gone.
"""

from __future__ import annotations

import importlib.util
import inspect
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest
import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy import MetaData, Table, create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import ComplianceControl, ComplianceEvidence, ComplianceFramework
from src.compliance.tasks import compliance_attestation_sweep_async
from src.core.config import settings
from src.core.database import async_session_factory
from src.models.base import Base
from src.ot_security.models import OTAsset, OTICSAdvisory, OTZone
from src.siem.models import DetectionRule, SIEMDataSource
from src.workers.celery_app import celery_app
from src.zerotrust import tasks as zt_tasks
from src.zerotrust.models import AccessDecision
from tests.helpers.tenancy import bearer, make_user

REPO_ROOT = Path(__file__).resolve().parents[2]
OT = "/api/v1/ot_security"


# ---------------------------------------------------------------------------
# Zero Trust tasks
# ---------------------------------------------------------------------------


def test_zerotrust_tasks_are_sync_registered_and_scheduled() -> None:
    task_fns = [
        obj for obj in vars(zt_tasks).values()
        if hasattr(obj, "run") and getattr(obj, "__module__", "") == zt_tasks.__name__
    ]
    assert [t.name for t in task_fns] == ["src.zerotrust.tasks.continuous_session_evaluation"]
    for t in task_fns:
        assert not inspect.iscoroutinefunction(t.run)
    assert "src.zerotrust.tasks.continuous_session_evaluation" in celery_app.tasks
    schedule = {e["task"] for e in celery_app.conf.beat_schedule.values()}
    assert "src.zerotrust.tasks.continuous_session_evaluation" in schedule
    for gone in ("assess_device_fleet", "update_micro_segments", "detect_policy_violations",
                 "calculate_zero_trust_maturity", "rotate_session_tokens", "generate_zero_trust_report"):
        assert not hasattr(zt_tasks, gone)


def _decision(org_id: str, session_id: str, created_at: datetime) -> AccessDecision:
    return AccessDecision(
        subject_type="user", subject_id="alice", resource_type="application", resource_id="payroll",
        decision="allow", risk_score=10.0, risk_factors="[]", context="{}", decision_reason="test",
        session_id=session_id, organization_id=org_id, created_at=created_at,
    )


async def test_session_sweep_evaluates_recent_sessions_of_each_org_only(
    db_session: AsyncSession, org_a, org_b, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(timezone.utc)
    db_session.add_all([
        _decision(org_a.id, "sess-recent", now - timedelta(minutes=10)),
        _decision(org_a.id, "sess-recent", now - timedelta(minutes=5)),
        _decision(org_a.id, "sess-old", now - timedelta(hours=9)),
        _decision(org_b.id, "sess-b", now - timedelta(minutes=1)),
    ])
    await db_session.commit()
    seen: list[tuple[str, str]] = []

    async def fake_eval(self, session_id: str):
        seen.append((self.organization_id, session_id))
        return None

    monkeypatch.setattr(zt_tasks.PolicyDecisionPoint, "continuous_evaluation", fake_eval)
    result = await zt_tasks.evaluate_active_sessions(db_session, org_a.id)
    assert result == {"evaluated_sessions": 1, "escalated": 0}
    assert seen == [(org_a.id, "sess-recent")]

    seen.clear()
    totals = await zt_tasks._continuous_session_sweep_async(async_session_factory)
    assert totals["organizations"] >= 2 and totals["failed_organizations"] == 0
    assert {(org_a.id, "sess-recent"), (org_b.id, "sess-b")} <= set(seen)
    assert (org_a.id, "sess-old") not in seen


# ---------------------------------------------------------------------------
# OT compliance report and serial numbers
# ---------------------------------------------------------------------------


def _requirements(report: dict) -> dict[str, dict]:
    return {
        f"{fw}:{req['id']}": req
        for fw in ("nerc_cip", "iec_62443", "nist_sp_800_82")
        for req in report[fw]["requirements"]
    }


async def test_ot_compliance_report_with_no_data_is_not_assessed(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    resp = await client.get(f"{OT}/compliance/report", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["overall_compliant"] is False
    assert {r["status"] for r in _requirements(body).values()} == {"not_assessed"}
    for fw in ("nerc_cip", "iec_62443", "nist_sp_800_82"):
        assert body[fw]["compliant"] is None and body[fw]["requirements_met"] == 0


async def test_ot_compliance_report_is_computed_from_stored_state(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    db_session.add_all([
        OTZone(organization_id=org_id, name="control", purdue_level="level1_control", network_cidr="10.1.0.0/24",
               allowed_protocols=["modbus_tcp"], segmentation_verified=True, segmentation_audit_status="verified"),
        OTZone(organization_id=org_id, name="dmz", purdue_level="level3_5_dmz", network_cidr="10.3.0.0/24",
               allowed_protocols=[], allowed_communications=[], segmentation_audit_status="violations_found"),
        OTAsset(organization_id=org_id, name="plc-1", asset_type="plc", purdue_level="level1_control",
                zone="control", vendor="Acme", model="PLC-9000", firmware_current=True,
                known_vulnerabilities_count=2),
        OTAsset(organization_id=org_id, name="hmi-1", asset_type="hmi", purdue_level="level2_supervisory",
                firmware_current=False),
    ])
    db_session.add(OTICSAdvisory(advisory_id=f"ICSA-{uuid.uuid4().hex[:6]}", title="t", vendor="Acme"))
    await db_session.commit()

    body = (await client.get(f"{OT}/compliance/report", headers=org_a_headers)).json()
    reqs = _requirements(body)
    assert reqs["nerc_cip:CIP-002"]["status"] == "fail"  # hmi-1 has no zone
    assert reqs["nerc_cip:CIP-005"]["status"] == "fail"  # dmz probe found violations
    assert reqs["nerc_cip:CIP-005"]["evidence"]["zones_with_violations"] == ["dmz"]
    assert reqs["nerc_cip:CIP-007 R2"]["status"] == "fail"  # hmi-1 firmware not current
    assert reqs["nerc_cip:CIP-009"]["status"] == "not_assessed"
    assert reqs["nerc_cip:CIP-010 R3"]["status"] == "fail"
    assert reqs["nerc_cip:CIP-010 R3"]["evidence"]["assets_with_advisories"] == ["plc-1"]
    assert reqs["iec_62443:SR 5.2"]["status"] == "fail"
    assert reqs["iec_62443:SR 5.2"]["evidence"]["zones_without_policy"] == ["dmz"]
    assert reqs["iec_62443:SL-A"]["status"] == "not_assessed"
    assert body["overall_compliant"] is False
    assert any(a.startswith("NERC-CIP CIP-005") for a in body["remediation_actions"])


async def test_ot_serial_numbers_are_unique_per_organisation(
    client: AsyncClient, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    body = {"name": "plc", "asset_type": "plc", "purdue_level": "level1_control", "serial_number": "SN-42"}
    first = await client.post(f"{OT}/assets", json=body, headers=org_a_headers)
    assert first.status_code == 201, first.text
    dup = await client.post(f"{OT}/assets", json=body, headers=org_a_headers)
    assert dup.status_code == 409, dup.text
    assert dup.json()["detail"]["error"] == "serial_number_conflict"
    other = await client.post(f"{OT}/assets", json=body, headers=org_b_headers)
    assert other.status_code == 201, other.text


async def test_siem_names_are_unique_per_organisation(db_session: AsyncSession, org_a, org_b) -> None:
    for org_id in (org_a.id, org_b.id, None):
        db_session.add(DetectionRule(name="brute-force", title="t", organization_id=org_id))
        db_session.add(SIEMDataSource(name="fw-syslog", source_type="syslog", organization_id=org_id))
    await db_session.commit()
    for row in (
        DetectionRule(name="brute-force", title="t", organization_id=org_a.id),
        DetectionRule(name="brute-force", title="t", organization_id=None),
        SIEMDataSource(name="fw-syslog", source_type="syslog", organization_id=org_b.id),
    ):
        db_session.add(row)
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()


# ---------------------------------------------------------------------------
# Migration 035
# ---------------------------------------------------------------------------

MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "035_per_org_unique_names.py"
TARGETS = {"ot_assets": "serial_number", "siem_data_sources": "name", "detection_rules": "name"}


def _load_migration() -> ModuleType:
    from tests.unit.test_migration_020 import _real_alembic

    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_035_per_org", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _globally_unique(conn: sa.Connection, table: str, column: str) -> bool:
    insp = sa.inspect(conn)
    # The platform-row partial index (``uq_<table>_platform_name``) is not
    # a global uniqueness.
    return any(u["column_names"] == [column] for u in insp.get_unique_constraints(table)) or any(
        i["column_names"] == [column] and i.get("unique") and not i["name"].endswith("_platform_name")
        for i in insp.get_indexes(table)
    )


def _names(conn: sa.Connection, table: str) -> set[str]:
    insp = sa.inspect(conn)
    return {i["name"] for i in insp.get_indexes(table)} | {
        u["name"] for u in insp.get_unique_constraints(table) if u.get("name")
    }


def test_migration_035_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.unit.test_migration_020 import (
        _alembic_config,
        _async_url,
        _downgrade,
        _engine,
        _in_thread,
        _real_alembic,
        _sync_url,
        _upgrade,
        _version,
    )

    migration = _load_migration()
    assert migration.revision == "035" and migration.down_revision == "034"
    # Pre-035 shape: the three columns globally unique (inline, unnamed on
    # SQLite), no per-organisation indexes; every column nullable so the
    # test rows stay short.
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        cols = [c._copy() for c in table.columns]
        for c in cols:
            c.index = None
            c.unique = TARGETS.get(table.name) == c.name or None
            if not c.primary_key:
                c.nullable = True
        Table(table.name, md, *cols)
    db_path = tmp_path / "pysoar_035.db"
    engine = create_engine(_sync_url(db_path))
    md.create_all(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO detection_rules (id, name, title, organization_id) VALUES ('r1', 'x', 't', 'o1')"))
        conn.execute(sa.text("INSERT INTO ot_assets (id, name, serial_number, organization_id) VALUES ('a1', 'p', 'SN', 'o1')"))
        for table, column in TARGETS.items():
            assert _globally_unique(conn, table, column), table
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "034"))
    db = {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}

    _upgrade(db, "035")
    assert _version(db) == "035"
    with _engine(db).begin() as conn:
        for table, column in TARGETS.items():
            assert not _globally_unique(conn, table, column), table
        assert "uq_org_serial" in _names(conn, "ot_assets")
        for table, (org_unique, platform_unique, plain) in migration.NAMED_TABLES.items():
            assert {org_unique, platform_unique, plain} <= _names(conn, table), table
        # Same name / serial in another organisation is now accepted ...
        conn.execute(sa.text("INSERT INTO detection_rules (id, name, title, organization_id) VALUES ('r2', 'x', 't', 'o2')"))
        conn.execute(sa.text("INSERT INTO ot_assets (id, name, serial_number, organization_id) VALUES ('a2', 'p', 'SN', 'o2')"))
    # ... but not twice in one organisation.
    for sql in (
        "INSERT INTO detection_rules (id, name, title, organization_id) VALUES ('r3', 'x', 't', 'o1')",
        "INSERT INTO ot_assets (id, name, serial_number, organization_id) VALUES ('a3', 'p', 'SN', 'o1')",
    ):
        with pytest.raises(sa.exc.IntegrityError), _engine(db).begin() as conn:
            conn.execute(sa.text(sql))

    # Downgrade with names shared across organisations keeps the data and
    # reports instead of failing; without them the global uniqueness returns.
    _downgrade(db, "034")
    with _engine(db).begin() as conn:
        assert not _globally_unique(conn, "detection_rules", "name")
        conn.execute(sa.text("DELETE FROM detection_rules WHERE id = 'r2'"))
        conn.execute(sa.text("DELETE FROM ot_assets WHERE id = 'a2'"))
    _upgrade(db, "035")
    _downgrade(db, "034")
    with _engine(db).connect() as conn:
        for table, column in TARGETS.items():
            assert _globally_unique(conn, table, column), table
    _upgrade(db, "035")
    _upgrade(db, "035")  # idempotent at head
    assert _version(db) == "035"


# ---------------------------------------------------------------------------
# Separation of duties (audit-evidence approval) and FedRAMP sweep seeding
# ---------------------------------------------------------------------------


async def test_audit_evidence_uploader_cannot_approve(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin, org_a_admin_headers: dict[str, str],
) -> None:
    org_id, admin_id, admin_email = org_a.id, org_a_admin.id, org_a_admin.email
    second = await make_user(db_session, role="admin", organization_id=org_id, label="admin-a-approver")
    second_headers = bearer(second)
    fw = ComplianceFramework(name=f"fw {uuid.uuid4().hex[:6]}", short_name=f"fw_{uuid.uuid4().hex[:6]}",
                             version="1", authority="tests", organization_id=org_id)
    db_session.add(fw)
    await db_session.flush()
    ctl = ComplianceControl(framework_id=fw.id, control_id="AC-5", control_family="AC", title="SoD",
                            organization_id=org_id)
    db_session.add(ctl)
    await db_session.flush()
    rows = [
        ComplianceEvidence(control_id_ref=ctl.id, evidence_type="document", title=title, collected_by=by,
                           organization_id=org_id)
        for title, by in (("by id", admin_id), ("legacy by email", admin_email.upper()))
    ]
    db_session.add_all(rows)
    await db_session.commit()
    ids = [r.id for r in rows]

    for evidence_id in ids:
        own = await client.post(f"/api/v1/audit-evidence/evidence/{evidence_id}/approve", headers=org_a_admin_headers)
        assert own.status_code == 409, own.text
        assert own.json()["detail"]["error"] == "separation_of_duties"
    ok = await client.post(f"/api/v1/audit-evidence/evidence/{ids[0]}/approve", headers=second_headers)
    assert ok.status_code == 200, ok.text


async def test_attestation_sweep_seeds_the_fedramp_catalogue(db_session: AsyncSession, org_a) -> None:
    org_id = org_a.id
    totals = await compliance_attestation_sweep_async(async_session_factory)
    assert totals["fedramp_catalogs_seeded"] >= 1
    count = (await db_session.execute(select(func.count(ComplianceFramework.id)).where(
        ComplianceFramework.organization_id == org_id,
        ComplianceFramework.short_name == "fedramp_moderate"))).scalar()
    assert count == 1
    again = await compliance_attestation_sweep_async(async_session_factory)
    assert again["fedramp_catalogs_seeded"] == 0


# ---------------------------------------------------------------------------
# Exposure tasks that wrote without scanning
# ---------------------------------------------------------------------------


def test_legacy_exposure_tasks_are_gone() -> None:
    from src.exposure import tasks as exposure_tasks

    for name in ("run_vuln_scan", "import_scanner_results", "calculate_risk_scores", "run_vulnerability_scan"):
        assert not hasattr(exposure_tasks, name), name
        assert f"src.exposure.tasks.{name}" not in celery_app.tasks
        assert f"src.exposure.tasks.{name}" not in celery_app.conf.task_annotations
    assert "src.exposure.tasks.check_sla_breaches" in celery_app.tasks
