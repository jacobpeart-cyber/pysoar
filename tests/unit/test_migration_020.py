"""Migration 020 (agentic guardrails) on a fresh SQLite fixture DB.

The pre-020 schema is built from the ORM metadata minus everything 020 adds
(the migration module publishes ``NEW_TABLES`` / ``NEW_COLUMNS`` /
``NEW_INDEXES`` for exactly this purpose), stamped at revision 019, and then
driven through the real ``alembic upgrade head`` / ``alembic downgrade 019``
commands. The repository's own ``alembic/`` package shadows the installed
``alembic`` distribution on ``sys.path``, so the real package is loaded
explicitly by :func:`_real_alembic`.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import secrets
import sys
import sysconfig
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest
import sqlalchemy as sa
from sqlalchemy import Index, MetaData, Table, UniqueConstraint, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

# Every model module must be registered on Base.metadata before the pre-020
# schema is derived from it.
import src.agentic.models
import src.agents.models
import src.audit_evidence.models
import src.intel.models
import src.models
import src.siem.models
import src.tickethub.models  # noqa: F401
from src.audit_evidence.models import AUDIT_CHAIN_FIELDS, AUDIT_GENESIS_HASH, audit_row_hash
from src.core.config import settings
from src.core.secrets import (
    SECRET_ENVELOPE_PREFIX,
    EncryptionService,
    decrypt_secret_json,
    encrypt_secret_json,
    is_enveloped,
    open_secret_keys,
)
from src.models.base import Base

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "020_agentic_guardrails.py"


# ---------------------------------------------------------------------------
# Loading the real alembic package and the migration module
# ---------------------------------------------------------------------------


def _real_alembic() -> tuple[ModuleType, ModuleType, ModuleType]:
    """Return ``(alembic.config, alembic.command, alembic.script)`` from site-packages."""
    site = sysconfig.get_paths()["purelib"]
    current = sys.modules.get("alembic")
    if current is not None and getattr(current, "__file__", "") and str(Path(current.__file__).parent) == str(
        Path(site) / "alembic",
    ):
        import alembic.command
        import alembic.config
        import alembic.script

        return alembic.config, alembic.command, alembic.script

    for name in [k for k in sys.modules if k == "alembic" or k.startswith("alembic.")]:
        del sys.modules[name]
    sys.path.insert(0, site)
    try:
        import alembic.command
        import alembic.config
        import alembic.script
    finally:
        sys.path.remove(site)
    return alembic.config, alembic.command, alembic.script


def _load_migration() -> ModuleType:
    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_020_agentic_guardrails", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration()


def _alembic_config(db_path: Path) -> Any:
    alembic_config, _, _ = _real_alembic()
    cfg = alembic_config.Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _async_url(db_path))
    return cfg


def _async_url(db_path: Path) -> str:
    return "sqlite+aiosqlite:///" + db_path.as_posix()


def _sync_url(db_path: Path) -> str:
    return "sqlite:///" + db_path.as_posix()


def _in_thread(fn: Callable[[], Any]) -> Any:
    """Run ``fn`` on a fresh thread so ``alembic/env.py``'s ``asyncio.run`` never
    touches the pytest-asyncio loop of this thread. Exceptions propagate."""
    box: dict[str, Any] = {}

    def _target() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:
            box["error"] = exc

    thread = threading.Thread(target=_target, name="alembic-runner")
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box.get("result")


def _run_async(coro_factory: Callable[[], Any]) -> Any:
    return _in_thread(lambda: asyncio.run(coro_factory()))


# ---------------------------------------------------------------------------
# Pre-020 schema
# ---------------------------------------------------------------------------


def build_pre020_metadata() -> MetaData:
    """``Base.metadata`` without the tables, columns and indexes 020 adds."""
    md = MetaData()
    dropped_indexes = {name for names in migration.NEW_INDEXES.values() for name in names}
    for table in Base.metadata.sorted_tables:
        if table.name in migration.NEW_TABLES:
            continue
        removed = set(migration.NEW_COLUMNS.get(table.name, ()))
        columns = [c._copy() for c in table.columns if c.name not in removed]
        for column in columns:
            # Indexes/unique constraints are re-added explicitly below from
            # ``table.indexes`` / ``table.constraints``; drop the column-level
            # flags so they are not created twice.
            column.index = None
            column.unique = None
        for tbl, col in migration.RELAXED_NOT_NULL:
            if tbl == table.name:
                for column in columns:
                    if column.name == col:
                        column.nullable = False
        extras: list[Any] = []
        for constraint in table.constraints:
            if isinstance(constraint, UniqueConstraint) and all(c.name not in removed for c in constraint.columns):
                extras.append(UniqueConstraint(*[c.name for c in constraint.columns], name=constraint.name))
        for index in table.indexes:
            if index.name in dropped_indexes:
                continue
            names = [getattr(c, "name", None) for c in index.expressions]
            if any(n is None for n in names) or any(n in removed for n in names):
                continue
            extras.append(Index(index.name, *names, unique=index.unique))
        Table(table.name, md, *columns, *extras)
    return md


@pytest.fixture
def master_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture
def fixture_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, master_key: str) -> dict[str, Any]:
    """A file-backed SQLite DB in the pre-020 shape, stamped at revision 019."""
    db_path = tmp_path / "pysoar_020.db"
    engine = create_engine(_sync_url(db_path))
    build_pre020_metadata().create_all(engine)
    engine.dispose()

    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    monkeypatch.setattr(settings, "encryption_master_key", master_key)

    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "019"))
    return {"path": db_path, "cfg": cfg, "url": _sync_url(db_path), "key": master_key}


def _upgrade(db: dict[str, Any], target: str = "020") -> None:
    # Pinned to 020: later revisions (021+) have their own round-trip tests.
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.upgrade(db["cfg"], target))


def _downgrade(db: dict[str, Any], target: str = "019") -> None:
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.downgrade(db["cfg"], target))


def _engine(db: dict[str, Any]) -> Engine:
    return create_engine(db["url"])


def _version(db: dict[str, Any]) -> str | None:
    with _engine(db).connect() as conn:
        return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


def _columns(conn: sa.Connection, table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(conn).get_columns(table)}


def _indexes(conn: sa.Connection, table: str) -> set[str]:
    return {i["name"] for i in sa.inspect(conn).get_indexes(table)}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _orm_table(name: str) -> Table:
    """The ORM table, used for Core inserts so Python-side column defaults apply.

    Columns 020 adds have no defaults, so they are simply absent from the
    generated INSERT and the pre-020 fixture schema accepts it.
    """
    return Base.metadata.tables[name]


def _seed_org_and_users(conn: sa.Connection) -> dict[str, str]:
    org_a, org_b = str(uuid.uuid4()), str(uuid.uuid4())
    u_in_a, u_no_org = str(uuid.uuid4()), str(uuid.uuid4())
    conn.execute(
        _orm_table("organizations").insert(),
        [
            {"id": org_a, "name": "Org A", "slug": "org-a"},
            {"id": org_b, "name": "Org B", "slug": "org-b"},
        ],
    )
    conn.execute(
        _orm_table("users").insert(),
        [
            {"id": u_in_a, "email": "a@example.com", "hashed_password": "x", "organization_id": org_a},
            {"id": u_no_org, "email": "noorg@example.com", "hashed_password": "x", "organization_id": None},
        ],
    )
    return {"org_a": org_a, "org_b": org_b, "u_in_a": u_in_a, "u_no_org": u_no_org}


def _insert_setting(conn: sa.Connection, section: str, value: Any, org: str | None = None) -> str:
    row_id = str(uuid.uuid4())
    now = _now()
    conn.execute(
        sa.text(
            "INSERT INTO app_settings (id, organization_id, section, value, created_at, updated_at) "
            "VALUES (:id, :org, :section, :value, :now, :now)",
        ),
        {"id": row_id, "org": org, "section": section, "value": json.dumps(value), "now": now},
    )
    return row_id


def _read_setting(conn: sa.Connection, row_id: str, with_backup: bool = True) -> tuple[Any, Any]:
    cols = "value, value_pre020" if with_backup else "value, NULL"
    row = conn.execute(sa.text(f"SELECT {cols} FROM app_settings WHERE id = :id"), {"id": row_id}).one()
    value = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    backup = json.loads(row[1]) if isinstance(row[1], str) else row[1]
    return value, backup


# ---------------------------------------------------------------------------
# Revision metadata
# ---------------------------------------------------------------------------


def test_revision_020_is_on_the_head_lineage_and_revises_019(tmp_path: Path) -> None:
    _, _, script = _real_alembic()
    cfg = _alembic_config(tmp_path / "unused.db")
    directory = script.ScriptDirectory.from_config(cfg)
    head = directory.get_current_head()
    # 020 stays on the linear history to head (later revisions build on it).
    assert "020" in {r.revision for r in directory.walk_revisions("base", head)}
    rev = directory.get_revision("020")
    assert rev is not None and rev.down_revision == "019"
    assert migration.revision == "020" and migration.down_revision == "019"


# ---------------------------------------------------------------------------
# Upgrade / downgrade round trip
# ---------------------------------------------------------------------------


def test_upgrade_head_then_downgrade_restores_pre020_schema(fixture_db: dict[str, Any]) -> None:
    assert _version(fixture_db) == "019"
    _upgrade(fixture_db)
    assert _version(fixture_db) == "020"

    with _engine(fixture_db).connect() as conn:
        inspector = sa.inspect(conn)
        for table in migration.NEW_TABLES:
            assert inspector.has_table(table), table
        for table, cols in migration.NEW_COLUMNS.items():
            present = _columns(conn, table)
            for col in cols:
                assert col in present, f"{table}.{col} missing after upgrade"
        for table, names in migration.NEW_INDEXES.items():
            present = _indexes(conn, table)
            for name in names:
                assert name in present, f"{table} index {name} missing after upgrade"
        unique = {i["name"]: i["unique"] for i in inspector.get_indexes("audit_trails")}
        assert unique["uq_audit_trails_org_prev_hash"]
        conf = next(c for c in inspector.get_columns("investigations") if c["name"] == "confidence_score")
        assert conf["nullable"] is True
        assert conn.execute(
            sa.text("SELECT COUNT(*) FROM app_settings WHERE section = :s"),
            {"s": migration.CRYPTO_CANARY_SECTION},
        ).scalar() == 1

    _downgrade(fixture_db)
    assert _version(fixture_db) == "019"

    with _engine(fixture_db).connect() as conn:
        inspector = sa.inspect(conn)
        for table in migration.NEW_TABLES:
            assert not inspector.has_table(table), table
        for table, cols in migration.NEW_COLUMNS.items():
            present = _columns(conn, table)
            for col in cols:
                assert col not in present, f"{table}.{col} still present after downgrade"
        for table, names in migration.NEW_INDEXES.items():
            present = _indexes(conn, table)
            for name in names:
                assert name not in present, f"{table} index {name} still present after downgrade"
        conf = next(c for c in inspector.get_columns("investigations") if c["name"] == "confidence_score")
        assert conf["nullable"] is False

    # And it can be applied again on the restored schema.
    _upgrade(fixture_db)
    assert _version(fixture_db) == "020"


# ---------------------------------------------------------------------------
# Secrets: master key guard, canary, envelope, idempotency, round-trip
# ---------------------------------------------------------------------------


def test_missing_master_key_hard_fails_before_any_change(
    fixture_db: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _engine(fixture_db).begin() as conn:
        row_id = _insert_setting(conn, "integration:virustotal", {"api_key": "vt-plain", "enabled": True})

    monkeypatch.setattr(settings, "encryption_master_key", None)
    with pytest.raises(RuntimeError, match="ENCRYPTION_MASTER_KEY"):
        _upgrade(fixture_db)

    assert _version(fixture_db) == "019"
    with _engine(fixture_db).connect() as conn:
        assert "value_pre020" not in _columns(conn, "app_settings")
        assert not sa.inspect(conn).has_table("llm_call_logs")
        value, _ = _read_setting(conn, row_id, with_backup=False)
        assert value == {"api_key": "vt-plain", "enabled": True}
        assert conn.execute(
            sa.text("SELECT COUNT(*) FROM app_settings WHERE section = :s"),
            {"s": migration.CRYPTO_CANARY_SECTION},
        ).scalar() == 0


def test_canary_under_a_different_key_refuses_to_encrypt(fixture_db: dict[str, Any]) -> None:
    other = EncryptionService(master_key=base64.b64encode(secrets.token_bytes(32)).decode())
    plaintext = secrets.token_hex(8)
    with _engine(fixture_db).begin() as conn:
        _insert_setting(
            conn,
            migration.CRYPTO_CANARY_SECTION,
            {
                "envelope": encrypt_secret_json({"canary": plaintext}, service=other),
                **migration.canary_payload(plaintext),
            },
        )
        row_id = _insert_setting(conn, "integration:shodan", {"api_key": "shodan-plain"})

    with pytest.raises(RuntimeError, match="_crypto_canary"):
        _upgrade(fixture_db)

    assert _version(fixture_db) == "019"
    with _engine(fixture_db).connect() as conn:
        value, _ = _read_setting(conn, row_id, with_backup=False)
        assert value == {"api_key": "shodan-plain"}


def test_secrets_are_enveloped_backed_up_and_round_trip(fixture_db: dict[str, Any]) -> None:
    service = EncryptionService(master_key=fixture_db["key"])
    pre_enveloped = encrypt_secret_json("already-secret", service=service)
    original = {
        "integration:virustotal": {"api_key": "vt-plain", "enabled": True, "url": "https://vt"},
        "smtp": {"host": "mail.example.com", "username": "bot", "password": "hunter2", "port": 587},
        "notifications": {"slack_webhook_url": "https://hooks.slack.com/x", "email_enabled": False},
        "general": {"app_name": "PySOAR", "timezone": "UTC"},
        "integration:jira": {"token": pre_enveloped, "nested": {"client_secret": "cs", "list": [{"password": "p"}]}},
        "ai": {"provider": "anthropic", "api_key": "", "model": "claude"},
    }
    ids: dict[str, str] = {}
    with _engine(fixture_db).begin() as conn:
        for section, value in original.items():
            ids[section] = _insert_setting(conn, section, value)

    _upgrade(fixture_db)

    with _engine(fixture_db).connect() as conn:
        for section, before in original.items():
            value, backup = _read_setting(conn, ids[section])
            assert backup == before, f"{section}: value_pre020 must be the verbatim pre-020 value"
            # Opening every envelope (including the one that pre-dated 020)
            # yields the plaintext the operator originally saved.
            assert open_secret_keys(value, service=service) == open_secret_keys(before, service=service), section

        vt, _ = _read_setting(conn, ids["integration:virustotal"])
        assert is_enveloped(vt["api_key"]) and vt["api_key"].startswith(SECRET_ENVELOPE_PREFIX)
        assert decrypt_secret_json(vt["api_key"], service=service) == "vt-plain"
        assert vt["enabled"] is True and vt["url"] == "https://vt"

        smtp, _ = _read_setting(conn, ids["smtp"])
        assert is_enveloped(smtp["password"]) and smtp["host"] == "mail.example.com" and smtp["port"] == 587

        notif, _ = _read_setting(conn, ids["notifications"])
        assert is_enveloped(notif["slack_webhook_url"]) and notif["email_enabled"] is False

        general, _ = _read_setting(conn, ids["general"])
        assert general == original["general"]

        jira, _ = _read_setting(conn, ids["integration:jira"])
        assert jira["token"] == pre_enveloped, "already-enveloped values are left byte-for-byte"
        assert is_enveloped(jira["nested"]["client_secret"])
        assert is_enveloped(jira["nested"]["list"][0]["password"])

        ai, _ = _read_setting(conn, ids["ai"])
        assert ai["api_key"] == "", "empty secrets are not enveloped"
        assert ai["provider"] == "anthropic"

        # Every envelope is distinct ciphertext (fresh nonce), never a shared blob.
        envelopes = {vt["api_key"], smtp["password"], notif["slack_webhook_url"], jira["nested"]["client_secret"]}
        assert len(envelopes) == 4


def test_secrets_step_is_idempotent_on_rerun(fixture_db: dict[str, Any]) -> None:
    with _engine(fixture_db).begin() as conn:
        row_id = _insert_setting(conn, "integration:virustotal", {"api_key": "vt-plain"})
    _upgrade(fixture_db)

    service = EncryptionService(master_key=fixture_db["key"])
    with _engine(fixture_db).connect() as conn:
        first_value, first_backup = _read_setting(conn, row_id)

    with _engine(fixture_db).begin() as conn:
        assert migration.verify_or_write_canary(conn, service, sa.JSON()) == "verified"
        stats = migration.envelope_app_settings_secrets(conn, service, sa.JSON())
    assert stats == {"rows": 1, "backed_up": 0, "enveloped": 0, "secrets": 0}

    with _engine(fixture_db).connect() as conn:
        second_value, second_backup = _read_setting(conn, row_id)
    assert second_value == first_value
    assert second_backup == first_backup == {"api_key": "vt-plain"}


def test_canary_is_written_once_and_verifies_under_same_key(fixture_db: dict[str, Any]) -> None:
    service = EncryptionService(master_key=fixture_db["key"])
    with _engine(fixture_db).begin() as conn:
        assert migration.verify_or_write_canary(conn, service, sa.JSON()) == "written"
        assert migration.verify_or_write_canary(conn, service, sa.JSON()) == "verified"
        count = conn.execute(
            sa.text("SELECT COUNT(*) FROM app_settings WHERE section = :s"),
            {"s": migration.CRYPTO_CANARY_SECTION},
        ).scalar()
    assert count == 1

    other = EncryptionService(master_key=base64.b64encode(secrets.token_bytes(32)).decode())
    with _engine(fixture_db).begin() as conn:
        with pytest.raises(RuntimeError, match="does not decrypt"):
            migration.verify_or_write_canary(conn, other, sa.JSON())


def test_downgrade_restores_plaintext_values_from_backup(fixture_db: dict[str, Any]) -> None:
    before = {"api_key": "vt-plain", "enabled": True}
    with _engine(fixture_db).begin() as conn:
        row_id = _insert_setting(conn, "integration:virustotal", before)
    _upgrade(fixture_db)
    with _engine(fixture_db).connect() as conn:
        value, _ = _read_setting(conn, row_id)
        assert is_enveloped(value["api_key"])

    _downgrade(fixture_db)
    with _engine(fixture_db).connect() as conn:
        value, _ = _read_setting(conn, row_id, with_backup=False)
    assert value == before


# ---------------------------------------------------------------------------
# Playbook organization backfill
# ---------------------------------------------------------------------------


def test_playbook_organization_backfilled_from_created_by(fixture_db: dict[str, Any]) -> None:
    with _engine(fixture_db).begin() as conn:
        ids = _seed_org_and_users(conn)
        playbooks = {
            "by_org_user": ids["u_in_a"],
            "by_orgless_user": ids["u_no_org"],
            "no_author": None,
            "unknown_author": str(uuid.uuid4()),
        }
        pb_ids = {}
        for name, author in playbooks.items():
            pb_ids[name] = str(uuid.uuid4())
            conn.execute(
                _orm_table("playbooks").insert(),
                {"id": pb_ids[name], "name": name, "steps": "[]", "created_by": author},
            )

    _upgrade(fixture_db)

    with _engine(fixture_db).connect() as conn:
        rows = dict(conn.execute(sa.text("SELECT id, organization_id FROM playbooks")).all())
    assert rows[pb_ids["by_org_user"]] == ids["org_a"]
    assert rows[pb_ids["by_orgless_user"]] is None
    assert rows[pb_ids["no_author"]] is None
    assert rows[pb_ids["unknown_author"]] is None


# ---------------------------------------------------------------------------
# Audit hash chain backfill
# ---------------------------------------------------------------------------


def _seed_audit_rows(conn: sa.Connection, org_id: str, count: int, start: datetime) -> list[str]:
    ids = []
    for i in range(count):
        row_id = str(uuid.uuid4())
        ids.append(row_id)
        conn.execute(
            _orm_table("audit_trails").insert(),
            {
                "id": row_id,
                "organization_id": org_id,
                "event_type": "access",
                "action": f"legacy.step{i}",
                "actor_type": "user",
                "actor_id": f"user-{i}",
                "resource_type": "incident",
                "resource_id": f"inc-{i}",
                "description": f"legacy row {i}",
                "old_value": None,
                "new_value": {"i": i, "note": "pre-020"},
                "result": "success",
                "risk_level": "low",
                "created_at": start + timedelta(seconds=i),
                "updated_at": start + timedelta(seconds=i),
            },
        )
    return ids


def test_audit_chain_backfilled_per_org_and_verifiable(fixture_db: dict[str, Any]) -> None:
    start = _now() - timedelta(days=1)
    with _engine(fixture_db).begin() as conn:
        ids = _seed_org_and_users(conn)
        a_ids = _seed_audit_rows(conn, ids["org_a"], 5, start)
        b_ids = _seed_audit_rows(conn, ids["org_b"], 3, start)

    _upgrade(fixture_db)

    table = sa.table(
        "audit_trails",
        *[
            sa.column(name, sa.DateTime(timezone=True) if name == "created_at" else sa.JSON() if name.endswith("_value") else sa.String())
            for name in AUDIT_CHAIN_FIELDS
        ],
        sa.column("prev_hash", sa.String()),
        sa.column("row_hash", sa.String()),
    )
    with _engine(fixture_db).connect() as conn:
        for org_id, expected_ids in ((ids["org_a"], a_ids), (ids["org_b"], b_ids)):
            rows = conn.execute(
                sa.select(table).where(table.c.organization_id == org_id).order_by(table.c.created_at, table.c.id),
            ).mappings().all()
            assert [r["id"] for r in rows] == expected_ids, "chained in (created_at, id) order"
            prev = AUDIT_GENESIS_HASH
            for row in rows:
                assert row["prev_hash"] == prev
                expected = audit_row_hash({k: row[k] for k in AUDIT_CHAIN_FIELDS}, prev)
                assert row["row_hash"] == expected
                prev = row["row_hash"]
        assert conn.execute(sa.text("SELECT COUNT(*) FROM audit_trails WHERE row_hash IS NULL")).scalar() == 0

    # The runtime verifier accepts the backfilled chain and is org-scoped.
    from src.audit_evidence.engine import AuditLogger

    async def _verify() -> tuple[dict[str, Any], dict[str, Any]]:
        engine = create_async_engine(_async_url(fixture_db["path"]))
        try:
            async with AsyncSession(engine) as session:
                a = await AuditLogger(session, ids["org_a"]).verify_chain()
                b = await AuditLogger(session, ids["org_b"]).verify_chain()
                return a, b
        finally:
            await engine.dispose()

    result_a, result_b = _run_async(_verify)
    assert result_a == {"ok": True, "first_bad_row": None, "checked": 5, "total": 5, "reason": None}
    assert result_b == {"ok": True, "first_bad_row": None, "checked": 3, "total": 3, "reason": None}


def test_audit_backfill_skips_orgs_already_chained(fixture_db: dict[str, Any]) -> None:
    start = _now() - timedelta(hours=1)
    with _engine(fixture_db).begin() as conn:
        ids = _seed_org_and_users(conn)
        _seed_audit_rows(conn, ids["org_a"], 2, start)
    _upgrade(fixture_db)

    with _engine(fixture_db).connect() as conn:
        before = conn.execute(sa.text("SELECT id, row_hash FROM audit_trails ORDER BY created_at")).all()
    with _engine(fixture_db).begin() as conn:
        stats = migration.backfill_audit_chain(conn)
    assert stats == {"organizations": 0, "rows": 0}
    with _engine(fixture_db).connect() as conn:
        after = conn.execute(sa.text("SELECT id, row_hash FROM audit_trails ORDER BY created_at")).all()
    assert before == after


def test_new_tables_have_expected_shape(fixture_db: dict[str, Any]) -> None:
    _upgrade(fixture_db)
    with _engine(fixture_db).connect() as conn:
        inspector = sa.inspect(conn)
        call_log = _columns(conn, "llm_call_logs")
        for col in (
            "run_id", "organization_id", "actor_user_id", "soc_agent_id", "purpose", "mode", "role",
            "propose_actions", "session_id", "investigation_id", "provider", "model", "credential_source",
            "prompt_version", "system_prompt_sha256", "tools_offered", "messages_sha256",
            "input_uncached_tokens", "cache_read_tokens", "cache_write_tokens", "output_tokens",
            "thinking_tokens", "total_billable_tokens", "usage_estimated", "latency_ms", "stop_reason",
            "injection_tier", "request_id", "data_sent_bytes", "redactions_applied",
        ):
            assert col in call_log, col
        daily = _columns(conn, "llm_usage_daily")
        for col in ("organization_id", "day", "provider", "model", "purpose", "mode", "credential_source",
                    "actor_key", "calls", "errors", "total_billable_tokens", "cost_usd"):
            assert col in daily, col
        uniques = {u["name"] for u in inspector.get_unique_constraints("llm_usage_daily")}
        assert "uq_llm_usage_daily_bucket" in uniques

        # agent_run_transcripts matches the ORM model column-for-column.
        from src.agentic.transcript import AgentRunTranscript

        # ``summary`` is added by revision 022 (its own round-trip test).
        orm_cols = {c.name for c in AgentRunTranscript.__table__.columns} - {"summary"}
        assert _columns(conn, "agent_run_transcripts") == orm_cols
        transcript_indexes = {i["name"]: i for i in inspector.get_indexes("agent_run_transcripts")}
        assert transcript_indexes["ix_agent_run_transcripts_run_id"]["unique"]
