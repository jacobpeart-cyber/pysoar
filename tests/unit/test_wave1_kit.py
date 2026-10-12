"""Wave 1 foundation kit (docs/audit/2026-10-08/PLAN.md, "Wave 1").

Covers: the tenancy dependency (``OrganizationId`` / ``resolve_organization_scope``),
migration 023 (organization_id on audit_logs and hunt_notebooks, with the
notebook backfill), AuditLog stamping, HuntNotebook scoping, the Celery
include list, the simulation task app and the removal of the hard-coded-zero
intel and deception tasks.
"""

from __future__ import annotations

import importlib
import importlib.util
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import MetaData, Table, create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_organization_id, resolve_organization_scope
from src.core.config import settings
from src.hunting.models import HuntHypothesis, HuntNotebook, HuntSession
from src.models.audit import AuditLog
from src.models.base import Base
from src.models.organization import Organization
from src.models.user import User
from tests.helpers.tenancy import assert_tenant_isolated
from tests.unit.test_migration_020 import (
    REPO_ROOT,
    _alembic_config,
    _async_url,
    _columns,
    _downgrade,
    _engine,
    _in_thread,
    _indexes,
    _orm_table,
    _real_alembic,
    _sync_url,
    _upgrade,
    _version,
)

# ---------------------------------------------------------------------------
# Tenancy dependency
# ---------------------------------------------------------------------------


def _user(org: str | None, *, superuser: bool = False, role: str = "analyst") -> User:
    return User(
        id=str(uuid.uuid4()),
        email="u@pysoar-tests.io",
        hashed_password="x",
        role=role,
        is_active=True,
        is_superuser=superuser,
        organization_id=org,
    )


def _error_key(exc: pytest.ExceptionInfo[HTTPException]) -> str:
    assert exc.value.status_code == 403
    return exc.value.detail["error"]


async def test_organization_id_returns_callers_org() -> None:
    assert await get_current_organization_id(_user("org-1")) == "org-1"


@pytest.mark.parametrize("superuser", [False, True])
async def test_organization_id_refuses_orgless_users_including_superusers(superuser: bool) -> None:
    with pytest.raises(HTTPException) as exc:
        await get_current_organization_id(_user(None, superuser=superuser))
    assert _error_key(exc) == "organization_required"


def test_scope_superuser_explicit_org_selects_tenant() -> None:
    assert resolve_organization_scope(_user(None, superuser=True), "org-x") == "org-x"
    assert resolve_organization_scope(_user("org-1", superuser=True), "org-x") == "org-x"


def test_scope_superuser_without_explicit_org_needs_own_org() -> None:
    assert resolve_organization_scope(_user("org-1", superuser=True), None) == "org-1"
    with pytest.raises(HTTPException) as exc:
        resolve_organization_scope(_user(None, superuser=True), None)
    assert _error_key(exc) == "organization_required"


def test_scope_tenant_user_explicit_org_must_match() -> None:
    admin = _user("org-1", role="admin")
    assert resolve_organization_scope(admin, "org-1") == "org-1"
    assert resolve_organization_scope(admin, None) == "org-1"
    with pytest.raises(HTTPException) as exc:
        resolve_organization_scope(admin, "org-2")
    assert _error_key(exc) == "organization_mismatch"
    with pytest.raises(HTTPException) as exc:
        resolve_organization_scope(_user(None), "org-2")
    assert _error_key(exc) == "organization_mismatch"


# ---------------------------------------------------------------------------
# Migration 023
# ---------------------------------------------------------------------------

MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "023_tenant_columns.py"


def _load_migration() -> ModuleType:
    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_023_tenant_columns", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration()


def _pre023_metadata() -> MetaData:
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        removed = {migration.COLUMN} if table.name in migration.TABLES else set()
        columns = [c._copy() for c in table.columns if c.name not in removed]
        for column in columns:
            column.index = None
            column.unique = None
        Table(table.name, md, *columns)
    return md


@pytest.fixture
def fixture_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    db_path = tmp_path / "pysoar_023.db"
    engine = create_engine(_sync_url(db_path))
    _pre023_metadata().create_all(engine)
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "022"))
    return {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}


def _seed_notebook(conn: sa.Connection) -> dict[str, str]:
    org, hyp, sess, nb = (str(uuid.uuid4()) for _ in range(4))
    conn.execute(_orm_table("organizations").insert(), [{"id": org, "name": "Org A", "slug": "org-a"}])
    conn.execute(
        _orm_table("hunt_hypotheses").insert(),
        [{"id": hyp, "organization_id": org, "title": "h", "hunt_type": "ioc_sweep"}],
    )
    conn.execute(
        _orm_table("hunt_sessions").insert(),
        [{"id": sess, "organization_id": org, "hypothesis_id": hyp}],
    )
    conn.execute(
        sa.text("INSERT INTO hunt_notebooks (id, session_id, title, version, is_published, created_at, updated_at) "
                "VALUES (:id, :sess, 'nb', 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"),
        {"id": nb, "sess": sess},
    )
    return {"org": org, "notebook": nb}


def test_revision_023_revises_022() -> None:
    assert migration.revision == "023" and migration.down_revision == "022"


def test_upgrade_adds_backfills_and_downgrade_drops(fixture_db: dict[str, Any]) -> None:
    with _engine(fixture_db).begin() as conn:
        for table in migration.TABLES:
            assert migration.COLUMN not in _columns(conn, table)
        seeded = _seed_notebook(conn)

    _upgrade(fixture_db, "023")
    assert _version(fixture_db) == "023"
    with _engine(fixture_db).connect() as conn:
        for table in migration.TABLES:
            assert migration.COLUMN in _columns(conn, table)
            assert f"ix_{table}_organization_id" in _indexes(conn, table)
        backfilled = conn.execute(
            sa.text("SELECT organization_id FROM hunt_notebooks WHERE id = :id"), {"id": seeded["notebook"]}
        ).scalar_one()
        assert backfilled == seeded["org"]

    _downgrade(fixture_db, "022")
    assert _version(fixture_db) == "022"
    with _engine(fixture_db).connect() as conn:
        for table in migration.TABLES:
            assert migration.COLUMN not in _columns(conn, table)

    _upgrade(fixture_db, "023")  # idempotent re-apply
    assert _version(fixture_db) == "023"


# ---------------------------------------------------------------------------
# AuditLog stamping
# ---------------------------------------------------------------------------


async def test_audit_rows_from_a_route_carry_the_callers_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_user: User,
    org_a_headers: dict[str, str],
) -> None:
    resp = await client.post(
        "/api/v1/alerts",
        json={"title": "wave1 audit stamp", "severity": "low", "source": "manual"},
        headers=org_a_headers,
    )
    assert resp.status_code in (200, 201), resp.text[:300]
    rows = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "alert_create"))
    ).scalars().all()
    assert rows and all(r.organization_id == org_a.id and r.user_id == org_a_user.id for r in rows)


async def test_audit_stamp_rules(
    db_session: AsyncSession, org_a: Organization, org_b: Organization, org_a_user: User
) -> None:
    stamped = AuditLog(user_id=org_a_user.id, action="x", resource_type="t")
    explicit = AuditLog(user_id=org_a_user.id, organization_id=org_b.id, action="x", resource_type="t")
    anonymous = AuditLog(user_id=None, action="login_failed", resource_type="auth")
    db_session.add_all([stamped, explicit, anonymous])
    await db_session.flush()
    assert stamped.organization_id == org_a.id
    assert explicit.organization_id == org_b.id
    assert anonymous.organization_id is None


# ---------------------------------------------------------------------------
# HuntNotebook scoping
# ---------------------------------------------------------------------------


async def _hunt_session(db: AsyncSession, org_id: str) -> HuntSession:
    hyp = HuntHypothesis(organization_id=org_id, title="wave1", hunt_type="ioc_sweep")
    db.add(hyp)
    await db.flush()
    sess = HuntSession(organization_id=org_id, hypothesis_id=hyp.id)
    db.add(sess)
    await db.commit()
    return sess


async def test_notebooks_are_stamped_and_tenant_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    sess_a_id = (await _hunt_session(db_session, org_a_id)).id
    sess_b_id = (await _hunt_session(db_session, org_b_id)).id

    resp = await client.post(
        "/api/v1/hunting/notebooks", json={"session_id": sess_a_id, "title": "A notes"}, headers=org_a_headers
    )
    assert resp.status_code == 201, resp.text[:300]
    nb_id = resp.json()["id"]
    row = (await db_session.execute(select(HuntNotebook).where(HuntNotebook.id == nb_id))).scalar_one()
    assert row.organization_id == org_a_id

    # Org B can neither attach a notebook to org A's session nor see/touch A's notebook.
    cross = await client.post(
        "/api/v1/hunting/notebooks", json={"session_id": sess_a_id, "title": "x"}, headers=org_b_headers
    )
    assert cross.status_code == 404
    listed = await client.get("/api/v1/hunting/notebooks", headers=org_b_headers)
    assert listed.status_code == 200 and listed.json()["total"] == 0
    for method, path, body in (
        ("GET", f"/api/v1/hunting/notebooks/{nb_id}", None),
        ("PUT", f"/api/v1/hunting/notebooks/{nb_id}", {"title": "pwned"}),
        ("POST", f"/api/v1/hunting/notebooks/{nb_id}/publish", None),
        ("GET", f"/api/v1/hunting/notebooks/{nb_id}/export", None),
    ):
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    own = await client.post(
        "/api/v1/hunting/notebooks", json={"session_id": sess_b_id, "title": "B notes"}, headers=org_b_headers
    )
    assert own.status_code == 201
    listed_a = await client.get("/api/v1/hunting/notebooks", headers=org_a_headers)
    assert [n["id"] for n in listed_a.json()["items"]] == [nb_id]

    # An org-less platform superuser gets no implicit cross-tenant view.
    su = await client.get("/api/v1/hunting/notebooks", headers=superuser_headers)
    assert su.status_code == 403
    assert "organization_required" in su.text


# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------

SRC = REPO_ROOT / "src"


def _task_modules_on_disk() -> set[str]:
    found = {f"src.{p.parent.name}.tasks" for p in SRC.glob("*/tasks.py")}
    return found | {"src.tasks.automation_tasks"}


def test_every_task_module_is_included_and_registers() -> None:
    from celery import Task

    from src.workers.celery_app import celery_app

    included = set(celery_app.conf.include)
    assert _task_modules_on_disk() <= included, _task_modules_on_disk() - included
    celery_app.loader.import_default_modules()
    for name in ("vulnmgmt", "container_security", "risk_quant", "zerotrust", "ot_security", "simulation"):
        module = importlib.import_module(f"src.{name}.tasks")
        tasks = [v for v in vars(module).values() if isinstance(v, Task)]
        assert tasks, name
        for task in tasks:
            assert task.name in celery_app.tasks, task.name
    for entry in celery_app.conf.beat_schedule.values():
        assert entry["task"] in celery_app.tasks, entry["task"]


def test_simulation_tasks_use_the_shared_app_and_real_session_factory() -> None:
    from celery import Celery

    import src.simulation.tasks as sim
    from src.workers.celery_app import celery_app

    source = Path(sim.__file__).read_text(encoding="utf-8")
    assert "src.database" not in source
    assert not any(isinstance(v, Celery) for v in vars(sim).values())
    assert sim.execute_simulation.name in celery_app.tasks


REMOVED = {
    "src.intel.tasks": (
        "enrich_new_indicators",
        "check_indicator_expiration",
        "update_ioc_cache",
        "generate_intel_summary",
        "correlate_indicators_with_logs",
        "sync_mitre_mappings",
    ),
    "src.deception.tasks": (
        "monitor_decoy_interactions",
        "rotate_honey_tokens",
        "check_token_canaries",
        "analyze_new_interactions",
        "update_campaign_stats",
        "deploy_scheduled_decoys",
        "cleanup_expired_tokens",
    ),
}


def test_hard_coded_zero_tasks_are_gone_and_nothing_references_them() -> None:
    from src.workers.celery_app import celery_app

    celery_app.loader.import_default_modules()
    names = {n for fns in REMOVED.values() for n in fns}
    for module_name, fns in REMOVED.items():
        module = importlib.import_module(module_name)
        for fn in fns:
            assert not hasattr(module, fn), f"{module_name}.{fn}"
            assert f"{module_name}.{fn}" not in celery_app.tasks
    # No route or task still calls one, so no route needed a 501 conversion.
    # (The module docstrings name them; only call sites matter.)
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits = [n for n in names if f"{n}(" in text or f"{n}.delay" in text or f"{n}.apply_async" in text]
        assert not hits, f"{path} still references {hits}"
    # The real tasks in those modules survive.
    assert "intel.poll_threat_feeds" in celery_app.tasks
    assert "deception.reconcile_honeypot_dispatches" in celery_app.tasks
