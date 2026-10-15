"""Migration 036 (wave 5): ``nl_queries`` is dropped with the retired
natural-language query feature; downgrade recreates it; both idempotent."""
from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine

from src.core.config import settings
from src.models.base import Base

TABLE = "nl_queries"


def test_model_is_gone() -> None:
    assert TABLE not in Base.metadata.tables
    import src.ai.models as models

    assert not hasattr(models, "NLQuery")


def test_migration_036_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    db_path = tmp_path / "pysoar_036.db"
    engine = create_engine(_sync_url(db_path))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        # The pre-036 table as init_db's create_all made it from the removed model.
        conn.execute(sa.text(
            f"CREATE TABLE {TABLE} (id VARCHAR(36) PRIMARY KEY, natural_language TEXT NOT NULL, "
            "interpreted_intent VARCHAR(100) NOT NULL, generated_query TEXT NOT NULL, "
            "query_parameters JSON NOT NULL, results_summary TEXT, result_count INTEGER NOT NULL, "
            "execution_time_ms INTEGER NOT NULL, user_id VARCHAR(36), was_helpful BOOLEAN, "
            "organization_id VARCHAR(36), created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
        ))
        assert sa.inspect(conn).has_table(TABLE)
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "035"))
    db = {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}

    _upgrade(db, "036")
    assert _version(db) == "036"
    with _engine(db).connect() as conn:
        assert not sa.inspect(conn).has_table(TABLE)
    _upgrade(db, "036")  # idempotent at head

    _downgrade(db, "035")
    with _engine(db).connect() as conn:
        insp = sa.inspect(conn)
        assert insp.has_table(TABLE)
        cols = {c["name"] for c in insp.get_columns(TABLE)}
        assert {"id", "natural_language", "interpreted_intent", "organization_id", "created_at"} <= cols
    _downgrade(db, "035")  # idempotent: the table is only created when missing

    _upgrade(db, "036")
    with _engine(db).connect() as conn:
        assert not sa.inspect(conn).has_table(TABLE)
