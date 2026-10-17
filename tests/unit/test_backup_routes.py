"""The in-app /api/v1/backup routes (src/api/v1/endpoints/backup.py).

* ``create`` runs a real ``pg_dump`` found on PATH and writes a gzip dump
  ``pysoar_api_YYYYMMDD-HHMMSS.sql.gz`` into BACKUP_DIR; without ``pg_dump``
  it answers 503 and writes nothing (no metadata stand-in file).
* ``restore`` always answers 409 and never starts a process.
* ``delete`` and ``status`` only ever see BACKUP_DIR.

The pg_dump used here is a small script the test writes into a temporary
directory on PATH; it records the arguments and environment it was started
with and prints a few lines of SQL. Nothing in the route is mocked.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import stat
import sys

import pytest
from sqlalchemy import select

from src.api.v1.endpoints import backup as backup_endpoints
from src.models.audit import AuditLog

DUMP_SQL = "-- fake pg_dump output for tests\nCREATE TABLE marker (id integer);\n"

FAKE_PG_DUMP = """\
import json, os, sys
with open(os.environ["FAKE_PG_DUMP_RECORD"], "w") as fh:
    json.dump({"argv": sys.argv[1:], "PGPASSWORD": os.environ.get("PGPASSWORD"),
               "PGSSLMODE": os.environ.get("PGSSLMODE")}, fh)
if os.environ.get("FAKE_PG_DUMP_FAIL"):
    sys.stdout.write("partial output\\n")
    sys.stderr.write("pg_dump: error: connection refused\\n")
    sys.exit(1)
sys.stdout.buffer.write(%r.encode())
""" % DUMP_SQL


def _install_fake_pg_dump(tmp_path, monkeypatch) -> str:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "fake_pg_dump.py"
    script.write_text(FAKE_PG_DUMP)
    if os.name == "nt":
        (bindir / "pg_dump.bat").write_text(f'@"{sys.executable}" "{script}" %*\r\n')
    else:
        launcher = bindir / "pg_dump"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    record = tmp_path / "pg_dump_call.json"
    monkeypatch.setenv("FAKE_PG_DUMP_RECORD", str(record))
    return str(record)


@pytest.fixture
def backup_dir(tmp_path, monkeypatch):
    target = tmp_path / "backups"
    monkeypatch.setattr(backup_endpoints, "BACKUP_DIR", str(target))
    return target


@pytest.fixture
def postgres_url(monkeypatch):
    monkeypatch.setattr(
        backup_endpoints.settings, "database_url",
        "postgresql+asyncpg://dumper:s3cr%40t@dbhost:5433/pysoardb",
    )
    monkeypatch.setattr(backup_endpoints.settings, "database_ssl_mode", "disable")


@pytest.fixture
def no_notification(monkeypatch):
    sent: list[dict] = []
    from src.workers import tasks
    monkeypatch.setattr(tasks.send_notification_task, "delay", lambda **kw: sent.append(kw))
    return sent


def _no_process(*_args, **_kwargs):
    raise AssertionError("no process may be started for this request")


async def _audit_rows(db_session, action: str) -> list[AuditLog]:
    rows = await db_session.execute(select(AuditLog).where(AuditLog.action == action))
    return list(rows.scalars())


@pytest.mark.asyncio
async def test_tenant_admin_is_refused_every_write(client, org_a_admin_headers, backup_dir, monkeypatch):
    monkeypatch.setattr(backup_endpoints.subprocess, "Popen", _no_process)
    monkeypatch.setattr(backup_endpoints.subprocess, "run", _no_process)
    backup_dir.mkdir()
    existing = backup_dir / "pysoar_20261001.sql.gz"
    existing.write_bytes(gzip.compress(b"x"))

    for method, url in (
        ("post", "/api/v1/backup/create"),
        ("post", "/api/v1/backup/restore"),
        ("delete", f"/api/v1/backup/backups/{existing.name}"),
    ):
        resp = await getattr(client, method)(url, headers=org_a_admin_headers)
        assert resp.status_code == 403, (url, resp.text)
        assert resp.json()["detail"]["error"] == "platform_superuser_required"
    assert [p.name for p in backup_dir.iterdir()] == [existing.name]


@pytest.mark.asyncio
@pytest.mark.usefixtures("postgres_url")
async def test_create_writes_a_real_gzip_dump(
    client, db_session, superuser_headers, backup_dir, no_notification, tmp_path, monkeypatch,
):
    record = _install_fake_pg_dump(tmp_path, monkeypatch)

    resp = await client.post("/api/v1/backup/create", headers=superuser_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success"
    assert re.fullmatch(r"pysoar_api_\d{8}-\d{6}\.sql\.gz", body["filename"]), body
    assert "/" not in body["filename"] and str(backup_dir) not in json.dumps(body)

    dump = backup_dir / body["filename"]
    assert body["size_bytes"] == dump.stat().st_size > 0
    assert gzip.decompress(dump.read_bytes()).decode() == DUMP_SQL
    assert [p.name for p in backup_dir.iterdir()] == [dump.name]  # no .part left behind
    if os.name != "nt":
        assert stat.S_IMODE(dump.stat().st_mode) == 0o600

    call = json.loads(open(record).read())
    assert call["argv"] == ["--no-password", "-h", "dbhost", "-p", "5433", "-U", "dumper", "-d", "pysoardb"]
    assert call["PGPASSWORD"] == "s3cr@t"  # decoded from the URL, never on the command line
    assert call["PGSSLMODE"] == "disable"
    assert len(no_notification) == 1

    rows = await _audit_rows(db_session, "backup_create")
    assert [(r.resource_id, r.success) for r in rows] == [(body["filename"], True)]

    resp = await client.get("/api/v1/backup/status", headers=superuser_headers)
    assert resp.status_code == 200, resp.text
    status = resp.json()
    assert [b["filename"] for b in status["backups"]] == [dump.name]
    assert status["pg_dump_available"] is True
    assert "auto_backup_enabled" not in status and "retention_days" not in status


@pytest.mark.asyncio
@pytest.mark.usefixtures("postgres_url")
async def test_create_without_pg_dump_is_503_and_writes_nothing(
    client, db_session, superuser_headers, backup_dir, tmp_path, monkeypatch,
):
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(backup_endpoints.subprocess, "Popen", _no_process)

    resp = await client.post("/api/v1/backup/create", headers=superuser_headers)
    assert resp.status_code == 503, resp.text
    detail = resp.json()["detail"]
    assert "pg_dump is not installed" in detail and "deploy/backup-db.sh" in detail
    assert not backup_dir.exists()

    rows = await _audit_rows(db_session, "backup_create")
    assert [r.success for r in rows] == [False]


@pytest.mark.asyncio
async def test_create_against_a_non_postgres_database_is_503(client, superuser_headers, backup_dir, tmp_path, monkeypatch):
    _install_fake_pg_dump(tmp_path, monkeypatch)
    monkeypatch.setattr(backup_endpoints.settings, "database_url", "sqlite+aiosqlite:///./x.db")
    monkeypatch.setattr(backup_endpoints.subprocess, "Popen", _no_process)

    resp = await client.post("/api/v1/backup/create", headers=superuser_headers)
    assert resp.status_code == 503, resp.text
    assert "PostgreSQL" in resp.json()["detail"]
    assert not backup_dir.exists()


@pytest.mark.asyncio
@pytest.mark.usefixtures("postgres_url")
async def test_failed_pg_dump_leaves_no_file(client, superuser_headers, backup_dir, tmp_path, monkeypatch):
    _install_fake_pg_dump(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_PG_DUMP_FAIL", "1")

    resp = await client.post("/api/v1/backup/create", headers=superuser_headers)
    assert resp.status_code == 500, resp.text
    assert "connection refused" in resp.json()["detail"]
    assert list(backup_dir.iterdir()) == []


@pytest.mark.asyncio
async def test_restore_is_refused_without_running_anything(client, db_session, superuser_headers, backup_dir, monkeypatch):
    monkeypatch.setattr(backup_endpoints.subprocess, "run", _no_process)
    monkeypatch.setattr(backup_endpoints.subprocess, "Popen", _no_process)
    backup_dir.mkdir()
    dump = backup_dir / "pysoar_20261002.sql.gz"
    dump.write_bytes(gzip.compress(b"SELECT 1;\n"))

    resp = await client.post(
        "/api/v1/backup/restore", headers=superuser_headers, json={"filename": dump.name, "confirm": True},
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "restore_not_supported_in_app"
    assert "deploy/restore-db.sh" in detail["message"] and "backup-restore.md" in detail["message"]
    assert dump.exists()
    rows = await _audit_rows(db_session, "backup_restore")
    assert [r.success for r in rows] == [False]


@pytest.mark.asyncio
async def test_delete_stays_inside_backup_dir(client, superuser_headers, backup_dir, tmp_path):
    backup_dir.mkdir()
    outside = tmp_path / "secret.sql.gz"
    outside.write_bytes(b"outside")
    (backup_dir / "sub").mkdir()

    for name in ("..%5Csecret.sql.gz", "..%2Fsecret.sql.gz"):
        resp = await client.delete(f"/api/v1/backup/backups/{name}", headers=superuser_headers)
        assert resp.status_code in (400, 404), (name, resp.text)
    resp = await client.delete("/api/v1/backup/backups/..%5Csecret.sql.gz", headers=superuser_headers)
    assert resp.status_code == 400, resp.text
    # A directory inside BACKUP_DIR is not a backup file.
    resp = await client.delete("/api/v1/backup/backups/sub", headers=superuser_headers)
    assert resp.status_code == 404, resp.text
    assert outside.exists()

    dump = backup_dir / "pysoar_api_20261017-120000.sql.gz"
    dump.write_bytes(gzip.compress(b"x"))
    resp = await client.delete(f"/api/v1/backup/backups/{dump.name}", headers=superuser_headers)
    assert resp.status_code == 200, resp.text
    assert not dump.exists()
