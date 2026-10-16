"""Migration 037 (identity package): the SSO / SCIM / roles tables and the four
user identity columns are added idempotently and removed on downgrade."""
from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import MetaData, Table, create_engine

import src.identity.models as identity_models  # noqa: F401  (registers the tables)
from src.core.config import settings
from src.identity.models import BUILTIN_ROLE_TIERS, TIER_ORDER, Role, Tier
from src.models.base import Base
from src.models.user import User

NEW_TABLES = ("roles", "sso_configurations", "scim_tokens")
NEW_USER_COLUMNS = ("custom_role_id", "external_id", "identity_source", "sso_subject")


def test_models_declare_the_identity_schema() -> None:
    for table in NEW_TABLES:
        assert table in Base.metadata.tables, table
    for column in NEW_USER_COLUMNS:
        assert column in User.__table__.c, column
    assert User.__table__.c.identity_source.default.arg == "local"
    assert {t.value for t in Tier} == set(TIER_ORDER)
    assert set(BUILTIN_ROLE_TIERS) == {"viewer", "analyst", "admin"}
    role = Role(organization_id="o", name="SOC manager", default_tier="write", area_tiers={"playbooks": "admin", "x": "bogus"})
    assert role.tier_for("playbooks") == "admin" and role.tier_for("alerts") == "write" and role.tier_for("x") == "none"


def _pre_037_metadata() -> MetaData:
    """The schema as it was before 037: no identity tables, no identity user columns."""
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in NEW_TABLES:
            continue
        cols = []
        for c in table.columns:
            if table.name == "users" and c.name in NEW_USER_COLUMNS:
                continue
            copy = c._copy()
            copy.index = None
            copy.unique = None
            if not copy.primary_key:
                copy.nullable = True
            cols.append(copy)
        Table(table.name, md, *cols)
    return md


def test_migration_037_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    db_path = tmp_path / "pysoar_037.db"
    engine = create_engine(_sync_url(db_path))
    _pre_037_metadata().create_all(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO organizations (id, name, slug) VALUES ('o1', 'Org', 'org')"))
        conn.execute(sa.text(
            "INSERT INTO users (id, email, hashed_password, role, organization_id) "
            "VALUES ('u1', 'a@org.example', 'x', 'analyst', 'o1')"
        ))
        insp = sa.inspect(conn)
        assert not any(insp.has_table(t) for t in NEW_TABLES)
        assert not ({c["name"] for c in insp.get_columns("users")} & set(NEW_USER_COLUMNS))
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "036"))
    db = {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}

    _upgrade(db, "037")
    assert _version(db) == "037"
    with _engine(db).begin() as conn:
        insp = sa.inspect(conn)
        assert all(insp.has_table(t) for t in NEW_TABLES)
        user_cols = {c["name"] for c in insp.get_columns("users")}
        assert set(NEW_USER_COLUMNS) <= user_cols
        # existing rows got the default identity source
        assert conn.execute(sa.text("SELECT identity_source FROM users WHERE id = 'u1'")).scalar() == "local"
        names = {ix["name"] for ix in insp.get_indexes("users")} | {
            uc["name"] for uc in insp.get_unique_constraints("users") if uc.get("name")
        }
        assert {"uq_users_org_sso_subject", "ix_users_org_external_id"} <= names
        # a role can be created and assigned; the same subject twice in one organisation is refused
        conn.execute(sa.text(
            "INSERT INTO roles (id, organization_id, name, default_tier, area_tiers) VALUES ('r1', 'o1', 'SOC manager', 'write', '{}')"
        ))
        conn.execute(sa.text("UPDATE users SET custom_role_id = 'r1', sso_subject = 'sub-1' WHERE id = 'u1'"))
        conn.execute(sa.text(
            "INSERT INTO users (id, email, hashed_password, role, organization_id, sso_subject) "
            "VALUES ('u2', 'b@org.example', 'x', 'viewer', 'o1', 'sub-2')"
        ))
    with pytest.raises(sa.exc.IntegrityError), _engine(db).begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO users (id, email, hashed_password, role, organization_id, sso_subject) "
            "VALUES ('u3', 'c@org.example', 'x', 'viewer', 'o1', 'sub-1')"
        ))
    _upgrade(db, "037")  # idempotent at head

    _downgrade(db, "036")
    with _engine(db).connect() as conn:
        insp = sa.inspect(conn)
        assert not any(insp.has_table(t) for t in NEW_TABLES)
        assert not ({c["name"] for c in insp.get_columns("users")} & set(NEW_USER_COLUMNS))
        assert conn.execute(sa.text("SELECT count(*) FROM users")).scalar() == 2
    _upgrade(db, "037")
    assert _version(db) == "037"
