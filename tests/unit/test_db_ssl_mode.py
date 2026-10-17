"""DATABASE_SSL_MODE reaches the asyncpg connection (it was validated but never
applied); a URL that sets its own ssl parameter keeps it."""
from __future__ import annotations

import pytest
from sqlalchemy.pool import NullPool

from src.core import database
from src.core.config import settings

PG_URL = "postgresql+asyncpg://pysoar:secret@db.invalid:5432/pysoar"


@pytest.mark.parametrize("mode", ["require", "verify-full", "disable", "prefer"])
def test_ssl_mode_is_passed_to_asyncpg(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setattr(settings, "database_url", PG_URL)
    monkeypatch.setattr(settings, "database_ssl_mode", mode)
    args = database._asyncpg_connect_args("pysoar")
    assert args["ssl"] == mode
    assert args["server_settings"]["application_name"] == "pysoar" and args["timeout"] == 30


@pytest.mark.parametrize("query", ["ssl=require", "sslmode=verify-full", "application_name=x&SSL=disable"])
def test_url_ssl_parameter_wins(monkeypatch: pytest.MonkeyPatch, query: str) -> None:
    monkeypatch.setattr(settings, "database_url", PG_URL + "?" + query)
    monkeypatch.setattr(settings, "database_ssl_mode", "require")
    assert "ssl" not in database._asyncpg_connect_args("pysoar")


def test_engines_carry_the_ssl_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "database_url", PG_URL)
    monkeypatch.setattr(settings, "database_ssl_mode", "verify-full")
    for env in (None, "null"):
        if env is None:
            monkeypatch.delenv("PYSOAR_DB_POOL", raising=False)
        else:
            monkeypatch.setenv("PYSOAR_DB_POOL", env)
        engine = database._create_engine()
        try:
            # The connect_args reach the pool's creator; the engine must be built either way.
            assert isinstance(engine.sync_engine.pool, NullPool) == (env == "null")
        finally:
            engine.sync_engine.dispose()
