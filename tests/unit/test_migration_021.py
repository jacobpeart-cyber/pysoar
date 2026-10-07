"""Migration 021 (first-approver columns for require_second_approver) round trip.

The pre-021 schema is the ORM metadata minus the three columns 021 adds,
stamped at 020, then driven through the real ``alembic upgrade 021`` /
``alembic downgrade 020`` commands (helpers shared with the 020 test).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import MetaData, Table, create_engine

from src.core.config import settings
from src.models.base import Base
from tests.unit.test_migration_020 import (
    REPO_ROOT,
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

MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "021_second_approver.py"


def _load_migration() -> ModuleType:
    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_021_second_approver", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration()


def _pre021_metadata() -> MetaData:
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        removed = set(migration.NEW_COLUMNS) if table.name == migration.TABLE else set()
        columns = [c._copy() for c in table.columns if c.name not in removed]
        for column in columns:
            column.index = None
            column.unique = None
        Table(table.name, md, *columns)
    return md


@pytest.fixture
def fixture_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    db_path = tmp_path / "pysoar_021.db"
    engine = create_engine(_sync_url(db_path))
    _pre021_metadata().create_all(engine)
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "020"))
    return {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}


def test_revision_021_revises_020() -> None:
    assert migration.revision == "021" and migration.down_revision == "020"


def test_upgrade_adds_and_downgrade_drops_first_approver_columns(fixture_db: dict[str, Any]) -> None:
    with _engine(fixture_db).connect() as conn:
        assert not set(migration.NEW_COLUMNS) & _columns(conn, migration.TABLE)

    _upgrade(fixture_db, "021")
    assert _version(fixture_db) == "021"
    with _engine(fixture_db).connect() as conn:
        assert set(migration.NEW_COLUMNS) <= _columns(conn, migration.TABLE)
        nullable = {c["name"]: c["nullable"] for c in sa.inspect(conn).get_columns(migration.TABLE)}
        assert all(nullable[name] for name in migration.NEW_COLUMNS)

    _downgrade(fixture_db, "020")
    assert _version(fixture_db) == "020"
    with _engine(fixture_db).connect() as conn:
        assert not set(migration.NEW_COLUMNS) & _columns(conn, migration.TABLE)

    # Idempotent re-apply.
    _upgrade(fixture_db, "021")
    assert _version(fixture_db) == "021"
