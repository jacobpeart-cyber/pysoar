"""Wave 4 (W4-E): data lake pipelines, lineage, quality and storage honest.

Built-in pipelines are the scheduled platform tasks and are never reported
``active`` with a success rate; user pipelines are registrations (nothing
executes them) and cannot be switched to ``active``; registered sources
store their connection settings encrypted and never return them; lineage
and quality of built-in sources come from the platform tables and the
beat schedule; the storage probe says when it cannot measure; the fake
data-lake tasks report ``not_implemented``; migration 034 round-trips.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest
import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy import MetaData, Table, create_engine
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.data_lake.engine import StorageManager
from src.data_lake.models import DataSource
from src.data_lake.tasks import pipeline_execution, retention_enforcement, tier_management
from src.models.base import Base
from src.siem.models import LogEntry

BASE = "/api/v1/data-lake"


@pytest.mark.asyncio
async def test_registered_source_config_is_encrypted_and_never_returned(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    body = {"name": "Customer events", "source_type": "custom", "ingestion_type": "pull", "format": "json",
            "connection_config": {"connection_string": "postgres://u:secret@db/x"}}
    assert (await client.post(f"{BASE}/sources", json=body, headers=viewer_headers)).status_code == 403
    resp = await client.post(f"{BASE}/sources", json=body, headers=org_a_admin_headers)
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert "secret" not in resp.text
    assert out["connection_config_encrypted"] == {"configured": True, "keys": ["connection_string"]}
    assert out["status"] == "registered" and out["ingestion_note"] and out["builtin"] is False

    row = await db_session.get(DataSource, out["id"])
    assert row.connection_config_encrypted["envelope"].startswith("enc:v1:")


@pytest.mark.asyncio
async def test_builtin_pipelines_are_scheduled_and_user_pipelines_registered(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    listed = (await client.get(f"{BASE}/pipelines", headers=org_a_admin_headers)).json()
    builtins = [p for p in listed["items"] if p["builtin"]]
    assert builtins and all(p["status"] == "scheduled" and p["last_run"] is None for p in builtins)
    assert any(p["task"] == "src.dlp.tasks.dlp_content_scan_sweep" for p in builtins)

    created = await client.post(f"{BASE}/pipelines", json={"name": "enrich", "pipeline_type": "enrichment"},
                                headers=org_a_admin_headers)
    assert created.status_code == 201, created.text
    assert created.json()["status"] == "registered"
    refused = await client.patch(f"{BASE}/pipelines/{created.json()['id']}", json={"status": "active"},
                                 headers=org_a_admin_headers)
    assert refused.status_code == 409 and refused.json()["detail"]["error"] == "no_executor"

    status = (await client.get(f"{BASE}/dashboard/pipeline-status", headers=org_a_admin_headers)).json()
    assert status["active_pipelines"] == 0 and status["registered_pipelines"] == 1
    assert status["scheduled_builtin_pipelines"] == len(builtins)
    assert status["avg_success_rate"] is None
    metrics = (await client.get(f"{BASE}/dashboard/metrics", headers=org_a_admin_headers)).json()
    assert metrics["ingestion_metrics"]["success_rate"] is None
    assert metrics["pipeline_health"]["avg_success_rate"] is None


@pytest.mark.asyncio
async def test_builtin_source_lineage_and_quality_from_the_table(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    now = datetime.now(timezone.utc).isoformat()
    for _ in range(3):
        db_session.add(LogEntry(id=str(uuid.uuid4()), timestamp=now, received_at=now, source_type="syslog",
                                source_name="fw", source_ip="192.0.2.1", log_type="network",
                                severity="low", raw_log="deny", organization_id=org_a_id))
    await db_session.commit()

    sources = (await client.get(f"{BASE}/sources", params={"size": 100}, headers=org_a_headers)).json()
    siem = next(s for s in sources["items"] if s["name"] == "SIEM Logs")
    assert siem["builtin"] is True and siem["builtin_table"] == "log_entries"

    lineage = (await client.get(f"{BASE}/catalog/lineage/{siem['id']}", headers=org_a_headers)).json()
    assert lineage["builtin_table"] == "log_entries"
    tasks = {c["task"] for c in lineage["downstream_consumers"]}
    assert {"src.dlp.tasks.dlp_content_scan_sweep", "src.ueba.tasks.bridge_siem_logs"} <= tasks

    quality = (await client.get(f"{BASE}/catalog/quality/{siem['id']}", headers=org_a_headers)).json()
    assert quality["total_records"] == 3 and quality["records_24h"] == 3
    assert quality["status"] == "healthy" and quality["empty_days_last_7"] == 6
    assert quality["basis"].startswith("table log_entries")

    assert (await client.get(f"{BASE}/catalog/quality/{siem['id']}", headers=org_b_headers)).status_code == 404
    assert (await client.get(f"{BASE}/catalog/lineage/{siem['id']}", headers=org_b_headers)).status_code == 404


@pytest.mark.asyncio
async def test_storage_probe_reports_when_it_cannot_measure(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    body = (await client.get(f"{BASE}/dashboard/storage-breakdown", headers=org_a_headers)).json()
    # The test database is SQLite: no pg_total_relation_size, so no bytes.
    assert body["probe"]["available"] is False and "PostgreSQL" in body["probe"]["reason"]
    assert body["total_bytes"] is None


def test_fake_data_lake_tasks_are_not_implemented() -> None:
    assert pipeline_execution.run("p", "o", "s")["status"] == "not_implemented"
    assert tier_management.run("s", "o")["status"] == "not_implemented"
    assert retention_enforcement.run("s", "o")["status"] == "not_implemented"
    assert StorageManager().compact_partitions("s")["status"] == "not_implemented"


# ---------------------------------------------------------------------------
# migration 034
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "034_privacy_dlp_datalake_real_state.py"


def _load_migration() -> ModuleType:
    from tests.unit.test_migration_020 import _real_alembic

    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_034_privacy", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_034_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.unit.test_migration_020 import (
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

    migration = _load_migration()
    assert migration.revision == "034" and migration.down_revision == "033"
    removed = {t: {name for name, _ in cols} for t, cols in migration.ADDITIONS.items()}
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name == migration.CURSOR_TABLE:
            continue
        cols = [c._copy() for c in table.columns if c.name not in removed.get(table.name, set())]
        for c in cols:
            c.index = None
            c.unique = None
        Table(table.name, md, *cols)
    db_path = tmp_path / "pysoar_034.db"
    engine = create_engine(_sync_url(db_path))
    md.create_all(engine)
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "033"))
    fixture_db = {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}

    _upgrade(fixture_db, "034")
    assert _version(fixture_db) == "034"
    with _engine(fixture_db).connect() as conn:
        for table, names in removed.items():
            assert names <= _columns(conn, table), table
        assert sa.inspect(conn).has_table(migration.CURSOR_TABLE)
        uniques = {u["name"] for u in sa.inspect(conn).get_unique_constraints("dlp_violations")}
        assert migration.VIOLATION_UNIQUE in uniques

    _downgrade(fixture_db, "033")
    with _engine(fixture_db).connect() as conn:
        for table, names in removed.items():
            assert not names & _columns(conn, table), table
        assert not sa.inspect(conn).has_table(migration.CURSOR_TABLE)
