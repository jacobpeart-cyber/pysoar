"""Whole-database backups are a platform-superuser operation.

Found in the 2026-10-08 feature audit: create, restore and delete under
``/backup`` were gated on the tenant ``admin`` role, but they dump or replace
the entire multi-tenant database, so any tenant's admin could read or
overwrite every tenant's data. They now require ``is_superuser``; the
read-only status listing is admin-readable.
"""

from __future__ import annotations

import pytest

from src.api.v1.endpoints import backup as backup_endpoints

ORG = "bkp-org-0000-4000-8000-000000000001"


async def _org_user(db_session, *, email: str, role: str = "admin", is_superuser: bool = False) -> tuple[object, dict]:
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, ORG) is None:
        db_session.add(Organization(id=ORG, name="BKP-ORG", slug="bkp-org"))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        is_superuser=is_superuser,
        organization_id=ORG,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


def _refuse_subprocess(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("pg_dump/pg_restore must not run for a refused request")


@pytest.mark.asyncio
async def test_tenant_admin_cannot_create_restore_or_delete(client, db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(backup_endpoints, "BACKUP_DIR", str(tmp_path))
    monkeypatch.setattr(backup_endpoints.subprocess, "run", _refuse_subprocess)
    existing = tmp_path / "pysoar_20261001_000000.sql.gz"
    existing.write_bytes(b"synthetic dump bytes")

    _, headers = await _org_user(db_session, email="bkp-admin@bkp-org.io", role="admin")
    calls = [
        ("post", "/api/v1/backup/create", None),
        ("post", "/api/v1/backup/restore", {"filename": existing.name, "confirm": True}),
        ("delete", f"/api/v1/backup/backups/{existing.name}", None),
        ("get", "/api/v1/backup/notifications/test", None),
    ]
    for method, url, body in calls:
        kwargs = {"headers": headers}
        if body is not None:
            kwargs["json"] = body
        resp = await getattr(client, method)(url, **kwargs)
        assert resp.status_code == 403, (url, resp.text)
        assert resp.json()["detail"]["error"] == "platform_superuser_required"

    assert existing.exists()
    assert [p.name for p in tmp_path.iterdir()] == [existing.name]


@pytest.mark.asyncio
async def test_status_is_admin_readable_but_not_viewer_readable(client, db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(backup_endpoints, "BACKUP_DIR", str(tmp_path))
    (tmp_path / "pysoar_20261001_000000.sql.gz").write_bytes(b"synthetic")

    _, viewer = await _org_user(db_session, email="bkp-viewer@bkp-org.io", role="viewer")
    resp = await client.get("/api/v1/backup/status", headers=viewer)
    assert resp.status_code == 403, resp.text

    _, admin = await _org_user(db_session, email="bkp-admin2@bkp-org.io", role="admin")
    resp = await client.get("/api/v1/backup/status", headers=admin)
    assert resp.status_code == 200, resp.text
    assert resp.json()["backup_count"] == 1


@pytest.mark.asyncio
async def test_platform_superuser_keeps_backup_operations(client, db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(backup_endpoints, "BACKUP_DIR", str(tmp_path))

    def _no_pg_dump(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("pg_dump")

    monkeypatch.setattr(backup_endpoints.subprocess, "run", _no_pg_dump)
    _, headers = await _org_user(db_session, email="bkp-root@bkp-org.io", role="admin", is_superuser=True)

    resp = await client.post("/api/v1/backup/create", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "partial"

    dump = tmp_path / "pysoar_20261002_000000.sql.gz"
    dump.write_bytes(b"synthetic dump bytes")
    resp = await client.post("/api/v1/backup/restore", headers=headers, json={"filename": dump.name})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "confirmation_required"

    resp = await client.delete(f"/api/v1/backup/backups/{dump.name}", headers=headers)
    assert resp.status_code == 200, resp.text
    assert not dump.exists()

    # Path traversal is still refused for superusers.
    resp = await client.post("/api/v1/backup/restore", headers=headers, json={"filename": "../secret", "confirm": True})
    assert resp.status_code == 400
