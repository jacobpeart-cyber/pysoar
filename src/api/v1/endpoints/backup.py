"""Backup and Restore API endpoints for PySOAR.

Backups are whole-database dumps covering every tenant, so creating,
restoring and deleting them is limited to platform superusers
(``PlatformSuperUser``: ``is_superuser``; the tenant ``admin`` role is not
enough). Before 2026-10-08 any tenant admin could dump or replace every
tenant's data.

The supported backup and restore path for a compose install is
``deploy/backup-db.sh`` and ``deploy/restore-db.sh``
(docs/operations/backup-restore.md). These routes:

* ``POST /backup/create`` runs ``pg_dump`` (postgresql-client-15 in the
  backend image) against ``DATABASE_URL`` and writes a gzip plain-SQL dump
  ``pysoar_api_YYYYMMDD-HHMMSS.sql.gz`` (UTC) into ``BACKUP_DIR``, which
  docker-compose.yml mounts from the host's ``./backups``. Without
  ``pg_dump`` it answers 503 and writes nothing.
* ``POST /backup/restore`` always refuses with 409: replacing the live
  database from inside the api would mean ending the api's and the
  workers' own connections and swapping the database under them.
  ``deploy/restore-db.sh`` does that from the host with the services stopped.
* ``GET /backup/status`` and ``DELETE /backup/backups/{filename}`` only ever
  see files directly inside ``BACKUP_DIR``.
"""

import gzip
import os
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.engine import make_url

from src.api.deps import AdminUser, DatabaseSession, PlatformSuperUser
from src.core.config import settings
from src.core.logging import get_logger
from src.models.audit import AuditLog

logger = get_logger(__name__)

router = APIRouter(prefix="/backup", tags=["backup-restore"])

BACKUP_DIR = os.environ.get("BACKUP_DIR", "/app/backups")

# pg_dump of the whole database; a stuck dump is killed after this long.
PG_DUMP_TIMEOUT_SECONDS = 600

RESTORE_REFUSAL = (
    "Restoring from inside the running api is not supported: it would have to end "
    "its own and the workers' database connections and swap the database under "
    "them. Restore from the host with deploy/restore-db.sh, which checks the dump "
    "in a scratch database, stops the services and keeps the previous database "
    "(docs/operations/backup-restore.md)."
)


class BackupUnavailableError(Exception):
    """pg_dump cannot run here; nothing was written."""


def _safe_backup_path(filename: str) -> str:
    """Resolve a backup filename to an absolute path strictly inside
    BACKUP_DIR, rejecting path traversal (e.g. '../../etc/passwd').

    Backups are flat files in BACKUP_DIR, so any directory separator or
    relative component is invalid — this prevents a caller from reading or
    deleting arbitrary files on the host.
    """
    if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid backup filename")
    backup_root = os.path.normpath(BACKUP_DIR)
    candidate = os.path.normpath(os.path.join(backup_root, filename))
    if os.path.dirname(candidate) != backup_root:
        raise HTTPException(status_code=400, detail="Invalid backup filename")
    return candidate


async def _audit(
    db, user, action: str, resource_id: Optional[str], description: str, success: bool,
    error: Optional[str] = None,
) -> None:
    """One AuditLog row per backup operation. Best-effort: a failure to
    record is logged, never turned into a different HTTP answer."""
    try:
        db.add(AuditLog(
            user_id=str(user.id),
            organization_id=getattr(user, "organization_id", None),
            action=action,
            resource_type="database_backup",
            resource_id=resource_id,
            description=description,
            success=success,
            error_message=error,
        ))
        await db.commit()
    except Exception:
        logger.error("could not record audit row for %s", action, exc_info=True)


def _pg_dump_command(pg_dump: str) -> tuple[list[str], dict[str, str]]:
    """argv and environment for pg_dump against DATABASE_URL. The password
    travels in PGPASSWORD, never on the command line."""
    url = make_url(settings.database_url)
    if not url.drivername.startswith("postgresql"):
        raise BackupUnavailableError(
            f"DATABASE_URL uses {url.drivername}; database dumps need PostgreSQL"
        )
    env = os.environ.copy()
    env["PGPASSWORD"] = url.password or ""
    # DATABASE_SSL_MODE is applied to the api's own connection
    # (src/core/database.py); pg_dump gets the same mode.
    env["PGSSLMODE"] = settings.database_ssl_mode
    argv = [
        pg_dump,
        "--no-password",
        "-h", url.host or "localhost",
        "-p", str(url.port or 5432),
        "-U", url.username or "",
        "-d", url.database or "",
    ]
    return argv, env


def _write_dump(argv: list[str], env: dict[str, str], final_path: str) -> int:
    """Stream pg_dump's plain SQL through gzip into final_path. The file is
    created owner-only (mode 600) under a temporary name and renamed into
    place only when pg_dump exited 0. Returns the size in bytes."""
    part = final_path + ".part"
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with tempfile.TemporaryFile() as err, os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=6) as gz:
                proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=err)
                timer = threading.Timer(PG_DUMP_TIMEOUT_SECONDS, proc.kill)
                timer.start()
                try:
                    if proc.stdout is None:  # pragma: no cover - stdout=PIPE always sets it
                        raise RuntimeError("pg_dump produced no output stream")
                    shutil.copyfileobj(proc.stdout, gz, 1024 * 1024)
                    returncode = proc.wait()
                finally:
                    timer.cancel()
            if returncode != 0:
                err.seek(0)
                stderr = err.read().decode("utf-8", "replace").strip()
                raise RuntimeError(f"pg_dump exited {returncode}: {stderr[-500:]}")
        os.replace(part, final_path)
    except BaseException:
        try:
            os.remove(part)
        except FileNotFoundError:
            pass
        raise
    return os.path.getsize(final_path)


@router.get("/status")
async def get_backup_status(current_user: AdminUser):
    """Get backup system status and list available backups.

    Read-only, so tenant admins may view it (previously any user could);
    it exposes file names and sizes only, never contents. Every operation
    that writes or deletes a backup requires a platform superuser.
    """
    backups = []

    if os.path.isdir(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if not (f.endswith(".sql.gz") or f.endswith(".sql")):
                continue
            filepath = os.path.join(BACKUP_DIR, f)
            if not os.path.isfile(filepath):
                continue
            stat = os.stat(filepath)
            backups.append({
                "filename": f,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })

    return {
        "backup_dir": BACKUP_DIR,
        "backup_count": len(backups),
        "backups": backups[:20],
        "pg_dump_available": shutil.which("pg_dump") is not None,
    }


@router.post("/create")
async def create_backup(current_user: PlatformSuperUser, db: DatabaseSession):
    """Dump the whole database with pg_dump into BACKUP_DIR (gzip plain SQL). Platform superuser only."""
    pg_dump = shutil.which("pg_dump")
    try:
        if pg_dump is None:
            raise BackupUnavailableError("pg_dump is not installed in this container")
        argv, env = _pg_dump_command(pg_dump)
    except BackupUnavailableError as exc:
        detail = (
            f"Backup unavailable: {exc}. Nothing was written. Use deploy/backup-db.sh "
            "(docs/operations/backup-restore.md)."
        )
        await _audit(db, current_user, "backup_create", None, "database backup refused", False, str(exc))
        raise HTTPException(status_code=503, detail=detail) from None

    created = datetime.now(timezone.utc)
    filename = f"pysoar_api_{created.strftime('%Y%m%d-%H%M%S')}.sql.gz"
    filepath = os.path.join(BACKUP_DIR, filename)
    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        if os.path.exists(filepath):
            raise HTTPException(status_code=409, detail=f"{filename} already exists; retry in a second")
        size = await run_in_threadpool(_write_dump, argv, env, filepath)
    except HTTPException:
        raise
    except PermissionError as exc:
        logger.error("backup directory not writable: %s", exc)
        await _audit(db, current_user, "backup_create", filename, "database backup failed", False, str(exc))
        raise HTTPException(
            status_code=500,
            detail=(
                f"Backup failed: {BACKUP_DIR} is not writable by the api's user. On a compose "
                "install the host's ./backups must belong to that uid (deploy/start-production.sh "
                "prints it)."
            ),
        ) from exc
    except Exception as exc:
        logger.error("database backup failed: %s", exc)
        await _audit(db, current_user, "backup_create", filename, "database backup failed", False, str(exc)[:500])
        raise HTTPException(status_code=500, detail=f"Backup failed: {exc}") from exc

    logger.info("database backup written", filename=filename, size_bytes=size)
    # Notification is best-effort: the dump already succeeded, so a failure to
    # queue the mail is logged, not returned.
    try:
        from src.workers.tasks import send_notification_task
        send_notification_task.delay(
            channel="email",
            recipients=[settings.first_admin_email],
            subject="PySOAR Backup Completed",
            message=f"Database backup completed.\nFile: {filename}\nSize: {round(size / (1024 * 1024), 2)} MB",
        )
    except Exception:
        logger.error("backup notification dispatch failed for %s", filename, exc_info=True)
    await _audit(
        db, current_user, "backup_create", filename,
        f"database backup {filename} written ({size} bytes)", True,
    )
    return {
        "status": "success",
        "filename": filename,
        "size_bytes": size,
        "size_mb": round(size / (1024 * 1024), 2),
        "created_at": created.isoformat(),
    }


@router.post("/restore", status_code=409)
async def restore_backup(current_user: PlatformSuperUser, db: DatabaseSession):
    """Refused (409): restore with deploy/restore-db.sh from the host. Platform superuser only."""
    await _audit(db, current_user, "backup_restore", None, "in-app database restore refused", False, "not supported in-app")
    raise HTTPException(
        status_code=409,
        detail={"error": "restore_not_supported_in_app", "message": RESTORE_REFUSAL},
    )


@router.delete("/backups/{filename}")
async def delete_backup(
    filename: str,
    current_user: PlatformSuperUser,
    db: DatabaseSession,
):
    """Delete a backup file. Platform superuser only."""
    filepath = _safe_backup_path(filename)
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="Backup not found")

    os.remove(filepath)
    await _audit(db, current_user, "backup_delete", filename, f"database backup {filename} deleted", True)
    return {"status": "deleted", "filename": filename}


@router.get("/notifications/test")
async def test_email_notification(current_user: PlatformSuperUser):
    """Send a test email notification to verify SMTP configuration.

    Platform superuser only: it mails the platform's first-admin address
    and reports the platform SMTP host."""
    from src.services.email_service import EmailService
    email_service = EmailService()

    if not email_service.is_configured:
        return {
            "status": "not_configured",
            "message": "SMTP not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD in .env",
        }

    try:
        sent = await email_service.send_email(
            to=[settings.first_admin_email],
            subject="PySOAR Test Notification",
            body="This is a test email from PySOAR. If you received this, email notifications are working.",
            html_body="<h2>PySOAR Test Notification</h2><p>Email notifications are <strong>working correctly</strong>.</p>",
        )
        return {
            "status": "sent" if sent else "failed",
            "recipient": settings.first_admin_email,
            "smtp_host": settings.smtp_host,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "smtp_host": settings.smtp_host,
        }
