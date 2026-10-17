"""``alembic upgrade head`` on an empty database, and on an existing one.

Revisions 001-006 created placeholder tables that never matched the models, so
replaying the chain on an empty database failed at 007 (``iocs.ioc_type``).
``alembic/env.py`` now builds an empty database from the models and stamps it
at head (Alembic's documented recipe for new databases); any database that
already has tables is migrated exactly as before.

The empty-database case runs the real ``alembic`` CLI in a fresh interpreter,
so the schema is built only from the models ``alembic/env.py`` itself imports;
it is then compared with ``Base.metadata`` after ``import src.main`` (every
model the app registers). The existing-database cases drive the real
``alembic.command`` API with the helpers from ``test_migration_020``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import warnings
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine

import src.main  # noqa: F401  - registers every model the app uses on Base.metadata
from src.core.config import settings
from src.models.base import Base
from tests.unit.test_migration_020 import _alembic_config, _async_url, _in_thread, _real_alembic, _sync_url

REPO_ROOT = Path(__file__).resolve().parents[2]

# Run the installed alembic CLI from the repository root. The repository's own
# ``alembic/`` package would shadow the installed one through the ``''`` entry
# Python puts first on ``sys.path`` for ``-c``; it is removed before the import,
# and alembic.ini's ``prepend_sys_path = .`` puts the root back for env.py.
_CLI = "import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; from alembic.config import main; main()"


def _cli(db_path: Path, *argv: str) -> str:
    env = {**os.environ, "DATABASE_URL": _async_url(db_path), "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, "-c", _CLI, *argv],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"alembic {' '.join(argv)} failed:\n{output[-4000:]}"
    return output


def _head() -> str:
    _, _, script = _real_alembic()
    cfg = _alembic_config(Path("unused.db"))
    heads = script.ScriptDirectory.from_config(cfg).get_heads()
    assert len(heads) == 1
    return heads[0]


def _version(db_path: Path) -> str | None:
    engine = create_engine(_sync_url(db_path))
    try:
        with engine.connect() as conn:
            if not sa.inspect(conn).has_table("alembic_version"):
                return None
            return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
    finally:
        engine.dispose()


def _snapshot(db_path: Path) -> dict[str, dict[str, object]]:
    """Table -> {column: (type, nullable)} plus index and FK shapes."""
    engine = create_engine(_sync_url(db_path))
    try:
        with engine.connect() as conn:
            inspector = sa.inspect(conn)
            out: dict[str, dict[str, object]] = {}
            for table in inspector.get_table_names():
                if table == "alembic_version":
                    continue
                shape: dict[str, object] = {
                    c["name"]: (str(c["type"]), c["nullable"]) for c in inspector.get_columns(table)
                }
                shape["__indexes__"] = sorted(
                    (ix["name"], tuple(ix["column_names"]), bool(ix["unique"])) for ix in inspector.get_indexes(table)
                )
                shape["__fks__"] = sorted(
                    (tuple(fk["constrained_columns"]), fk["referred_table"]) for fk in inspector.get_foreign_keys(table)
                )
                out[table] = shape
            return out
    finally:
        engine.dispose()


def _assert_matches_models(db_path: Path) -> None:
    """Every table and column in ``Base.metadata`` exists; type spellings are reported."""
    snapshot = _snapshot(db_path)
    dialect = sa.dialects.sqlite.dialect()
    missing_tables = sorted(set(Base.metadata.tables) - set(snapshot))
    assert not missing_tables, f"tables missing after upgrade head: {missing_tables}"
    missing_columns: list[str] = []
    type_notes: list[str] = []
    for name, table in Base.metadata.tables.items():
        reflected = snapshot[name]
        for column in table.columns:
            if column.name not in reflected:
                missing_columns.append(f"{name}.{column.name}")
                continue
            want = column.type.compile(dialect=dialect)
            got = reflected[column.name][0]
            if want.split("(")[0].upper() != str(got).split("(")[0].upper():
                type_notes.append(f"{name}.{column.name}: model {want}, database {got}")
    assert not missing_columns, f"columns missing after upgrade head: {missing_columns}"
    if type_notes:  # SQLite-only spellings (e.g. JSONB / UUID affinities); not a failure
        warnings.warn("type spelling differences on SQLite: " + "; ".join(type_notes), stacklevel=2)


def test_env_registers_every_model_the_app_registers(tmp_path: Path) -> None:
    """``alembic upgrade head`` on an empty file DB builds every app table and column."""
    db_path = tmp_path / "empty.db"
    output = _cli(db_path, "upgrade", "head")
    assert "empty database" in output
    assert "Running upgrade" not in output  # the legacy chain is not replayed
    assert _version(db_path) == _head()
    _assert_matches_models(db_path)
    extra = sorted(set(_snapshot(db_path)) - set(Base.metadata.tables))
    assert not extra, f"tables the models do not declare: {extra}"


def test_upgrade_is_a_noop_then_tail_round_trips(tmp_path: Path) -> None:
    db_path = tmp_path / "empty.db"
    _cli(db_path, "upgrade", "head")
    built = _snapshot(db_path)

    again = _cli(db_path, "upgrade", "head")
    assert "empty database" not in again
    assert "Running upgrade" not in again
    assert _snapshot(db_path) == built

    # The latest revisions run downgrade / upgrade against the bootstrapped
    # (create_all-shaped) schema, as they do on production. 037's downgrade
    # used to name a foreign key only its own upgrade creates.
    down = _cli(db_path, "downgrade", "036")
    assert "Running downgrade 038 -> 037" in down and "Running downgrade 037 -> 036" in down
    assert _version(db_path) == "036"
    assert "sso_configurations" not in _snapshot(db_path)
    _cli(db_path, "upgrade", "head")
    assert _version(db_path) == _head()
    _assert_matches_models(db_path)


def test_stamp_on_empty_database_does_not_build_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "stamp.db"
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(_alembic_config(db_path), "head"))
    assert _version(db_path) == _head()
    assert _snapshot(db_path) == {}


def test_existing_database_at_head_is_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Production's shape: tables from create_all, stamped at head. Upgrade is a no-op."""
    db_path = tmp_path / "prod_like.db"
    engine = create_engine(_sync_url(db_path))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(
            Base.metadata.tables["organizations"].insert(),
            {"id": "00000000-0000-0000-0000-000000000001", "name": "Existing Org", "slug": "existing-org"},
        )
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "038"))
    before = _snapshot(db_path)

    _in_thread(lambda: command.upgrade(cfg, "head"))

    assert _version(db_path) == "038"
    assert _snapshot(db_path) == before
    engine = create_engine(_sync_url(db_path))
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT name FROM organizations")).scalars().all() == ["Existing Org"]
    engine.dispose()


def test_tables_without_version_are_not_bootstrapped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A database with tables but no revision is not treated as empty."""
    db_path = tmp_path / "unknown.db"
    engine = create_engine(_sync_url(db_path))
    Base.metadata.tables["organizations"].create(engine)
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    _, command, _ = _real_alembic()
    with pytest.raises(Exception, match="already exists"):  # the legacy chain hits the existing table
        _in_thread(lambda: command.upgrade(_alembic_config(db_path), "head"))
    assert _version(db_path) is None
