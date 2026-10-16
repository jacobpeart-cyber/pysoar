"""Celery processes run every task coroutine on a fresh event loop, so their
engine must not pool asyncpg connections across loops: PYSOAR_DB_POOL=null
selects NullPool for the Postgres engine, and nothing else changes."""
from __future__ import annotations

import pytest
from sqlalchemy.pool import NullPool

from src.core import database
from src.core.config import settings

PG_URL = "postgresql+asyncpg://pysoar:secret@db.invalid:5432/pysoar"


def test_null_pool_mode_for_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "database_url", PG_URL)
    monkeypatch.setenv("PYSOAR_DB_POOL", "null")
    engine = database._create_engine()
    try:
        assert isinstance(engine.sync_engine.pool, NullPool)
    finally:
        engine.sync_engine.dispose()


def test_default_postgres_engine_still_pools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "database_url", PG_URL)
    monkeypatch.delenv("PYSOAR_DB_POOL", raising=False)
    engine = database._create_engine()
    try:
        assert not isinstance(engine.sync_engine.pool, NullPool)
        assert engine.sync_engine.pool.size() == 20
    finally:
        engine.sync_engine.dispose()


def test_compose_sets_null_pool_on_celery_services_only() -> None:
    import yaml
    from pathlib import Path

    compose = yaml.safe_load((Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    for name in ("worker", "scheduler"):
        assert str((services[name].get("environment") or {}).get("PYSOAR_DB_POOL")).lower() == "null", name
    assert "PYSOAR_DB_POOL" not in (services["api"].get("environment") or {})
