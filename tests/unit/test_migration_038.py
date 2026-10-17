"""Migration 038 (SAML settings): ``sso_configurations.saml_settings`` is added
idempotently and removed on downgrade."""
from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import MetaData, Table, create_engine

import src.identity.models as identity_models  # noqa: F401  (registers the tables)
from src.core.config import settings
from src.identity.models import SSOConfiguration
from src.models.base import Base

TABLE = "sso_configurations"
COLUMN = "saml_settings"


def test_model_declares_the_column() -> None:
    assert COLUMN in SSOConfiguration.__table__.c


def _pre_038_metadata() -> MetaData:
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        cols = []
        for c in table.columns:
            if table.name == TABLE and c.name == COLUMN:
                continue
            copy = c._copy()
            copy.index = None
            copy.unique = None
            if not copy.primary_key:
                copy.nullable = True
            cols.append(copy)
        Table(table.name, md, *cols)
    return md


def test_migration_038_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    db_path = tmp_path / "pysoar_038.db"
    engine = create_engine(_sync_url(db_path))
    _pre_038_metadata().create_all(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO organizations (id, name, slug) VALUES ('o1', 'Org', 'org')"))
        conn.execute(sa.text(
            "INSERT INTO sso_configurations (id, organization_id, protocol, issuer, client_id) "
            "VALUES ('s1', 'o1', 'oidc', 'https://idp.example.com', 'client')"
        ))
        assert COLUMN not in {c["name"] for c in sa.inspect(conn).get_columns(TABLE)}
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "037"))
    db = {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}

    _upgrade(db, "038")
    assert _version(db) == "038"
    with _engine(db).begin() as conn:
        assert COLUMN in {c["name"] for c in sa.inspect(conn).get_columns(TABLE)}
        assert conn.execute(sa.text(f"SELECT {COLUMN} FROM {TABLE} WHERE id = 's1'")).scalar() is None
        conn.execute(sa.text(f"UPDATE {TABLE} SET {COLUMN} = '{{\"idp_sso_url\": \"https://idp.example.com/sso\"}}' WHERE id = 's1'"))
    _upgrade(db, "038")  # idempotent at head

    _downgrade(db, "037")
    with _engine(db).connect() as conn:
        assert COLUMN not in {c["name"] for c in sa.inspect(conn).get_columns(TABLE)}
        assert conn.execute(sa.text(f"SELECT count(*) FROM {TABLE}")).scalar() == 1
    _upgrade(db, "038")
    assert _version(db) == "038"
