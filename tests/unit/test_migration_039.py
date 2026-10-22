"""Migration 039: ``integration_executions.playbook_run_id`` becomes
VARCHAR(100) (callers pass ``playbook_execution:<uuid>``, 55 characters) and
``error_code`` / ``http_status`` are added idempotently; downgrade drops the
two columns and keeps the width."""
from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import MetaData, Table, create_engine

import src.integrations.models as integration_models  # noqa: F401  (registers the tables)
from src.core.config import settings
from src.integrations.models import IntegrationExecution
from src.models.base import Base

TABLE = "integration_executions"
NEW = ("error_code", "http_status")


def test_model_declares_the_columns_and_width() -> None:
    cols = IntegrationExecution.__table__.c
    assert all(name in cols for name in NEW)
    assert cols.playbook_run_id.type.length == 100


def test_containment_run_ref_keeps_the_full_playbook_reference() -> None:
    from src.services.containment import engine_run_ref

    ref = "playbook_execution:0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"
    assert engine_run_ref(ref) == ref
    assert len(engine_run_ref("x" * 150)) <= 100


def _pre_039_metadata() -> MetaData:
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        cols = []
        for c in table.columns:
            if table.name == TABLE and c.name in NEW:
                continue
            copy = c._copy()
            copy.index = None
            copy.unique = None
            if table.name == TABLE and c.name == "playbook_run_id":
                copy.type = sa.String(36)
            if not copy.primary_key:
                copy.nullable = True
            cols.append(copy)
        Table(table.name, md, *cols)
    return md


def test_migration_039_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    db_path = tmp_path / "pysoar_039.db"
    engine = create_engine(_sync_url(db_path))
    _pre_039_metadata().create_all(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO organizations (id, name, slug) VALUES ('o1', 'Org', 'org')"))
        conn.execute(sa.text(
            "INSERT INTO integration_executions (id, organization_id, installed_id, action_id, triggered_by, "
            "playbook_run_id, input_data, status, retry_count) "
            "VALUES ('e1', 'o1', 'i1', 'a1', 'manual', 'run-1', '{}', 'failed', 0)"
        ))
        before = {c["name"]: c for c in sa.inspect(conn).get_columns(TABLE)}
        assert not any(name in before for name in NEW)
        assert before["playbook_run_id"]["type"].length == 36
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "038"))
    db = {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}

    _upgrade(db, "039")
    assert _version(db) == "039"
    with _engine(db).begin() as conn:
        after = {c["name"]: c for c in sa.inspect(conn).get_columns(TABLE)}
        assert all(name in after for name in NEW)
        assert after["playbook_run_id"]["type"].length == 100
        assert conn.execute(sa.text(f"SELECT error_code, http_status FROM {TABLE} WHERE id = 'e1'")).one() == (None, None)
        conn.execute(sa.text(
            f"UPDATE {TABLE} SET error_code = 'http_error', http_status = 404, "
            "playbook_run_id = 'playbook_execution:0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b' WHERE id = 'e1'"
        ))
    _upgrade(db, "039")  # idempotent at head

    _downgrade(db, "038")
    with _engine(db).connect() as conn:
        cols = {c["name"]: c for c in sa.inspect(conn).get_columns(TABLE)}
        assert not any(name in cols for name in NEW)
        assert cols["playbook_run_id"]["type"].length == 100  # width is kept
        assert conn.execute(sa.text(f"SELECT count(*) FROM {TABLE}")).scalar() == 1
    _upgrade(db, "039")
    assert _version(db) == "039"
