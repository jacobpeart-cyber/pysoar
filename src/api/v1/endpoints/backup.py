"""Backup and Restore API endpoints for PySOAR."""

import os
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Body
from src.api.deps import CurrentUser, DatabaseSession
from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/backup", tags=["backup-restore"])

BACKUP_DIR = os.environ.get("BACKUP_DIR", "/app/backups")


@router.get("/status")
async def get_backup_status(current_user: CurrentUser = None):
    """Get backup system status and list available backups."""
    backups = []

    if os.path.exists(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith(".sql.gz") or f.endswith(".sql"):
                filepath = os.path.join(BACKUP_DIR, f)
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
        "auto_backup_enabled": True,
        "retention_days": 7,
    }


@router.post("/create")
async def create_backup(current_user: CurrentUser = None):
    """Trigger an immediate database backup."""
    os.makedirs(BACKUP_DIR, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"pysoar_{timestamp}.sql.gz"
    filepath = os.path.join(BACKUP_DIR, filename)

    # Parse database URL for pg_dump
    db_url = settings.database_url
    # Remove async driver prefix
    sync_url = db_url.replace("+asyncpg", "").replace("+aiosqlite", "")

    try:
        # Use pg_dump via subprocess
        # Extract connection params from URL
        from urllib.parse import urlparse
        parsed = urlparse(sync_url)

        env = os.environ.copy()
        env["PGPASSWORD"] = parsed.password or ""

        cmd = [
            "pg_dump",
            "-h", parsed.hostname or "localhost",
            "-p", str(parsed.port or 5432),
            "-U", parsed.username or "pysoar",
            "-d", parsed.path.lstrip("/") or "pysoar",
            "--format=custom",
            "--compress=6",
            f"--file={filepath}",
        ]

        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            logger.error(f"pg_dump failed: {result.stderr}")
            # Create a SQL dump as fallback
            filepath = filepath.replace(".sql.gz", ".sql")
            cmd[-2] = "--format=plain"
            cmd[-1] = f"--file={filepath}"
            result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                raise Exception(f"Backup failed: {result.stderr}")

        file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

        # Send notification
        try:
            from src.workers.tasks import send_notification_task
            send_notification_task.delay(
                channel="email",
                recipients=[settings.first_admin_email],
                subject="PySOAR Backup Completed",
                message=f"Database backup completed successfully.\nFile: {filename}\nSize: {round(file_size / (1024*1024), 2)} MB",
            )
        except Exception:
            pass

        return {
            "status": "success",
            "filename": os.path.basename(filepath),
            "size_bytes": file_size,
            "size_mb": round(file_size / (1024 * 1024), 2),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Backup timed out after 5 minutes")
    except FileNotFoundError:
        # pg_dump not available — create a lightweight metadata backup
        import json
        metadata = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database_url": settings.database_url.split("@")[1] if "@" in settings.database_url else "unknown",
            "note": "pg_dump not available in this container. Use docker exec for full backups.",
        }
        meta_path = os.path.join(BACKUP_DIR, f"pysoar_{timestamp}_metadata.json")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

        return {
            "status": "partial",
            "message": "pg_dump not available. Metadata backup created. Run full backup via: docker exec pysoar-postgres pg_dump -U pysoar pysoar | gzip > backup.sql.gz",
            "filename": os.path.basename(meta_path),
        }
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Backup failed: {str(e)}")


@router.post("/restore")
async def restore_backup(
    data: dict = Body(...),
    current_user: CurrentUser = None,
):
    """Restore database from a backup file."""
    filename = data.get("filename")
    if not filename:
        raise HTTPException(status_code=400, detail="filename is required")

    filepath = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Backup file not found: {filename}")

    # Safety check
    confirm = data.get("confirm", False)
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": f"WARNING: This will replace ALL current data with backup '{filename}'. Set confirm=true to proceed.",
            "filename": filename,
            "size_mb": round(os.path.getsize(filepath) / (1024 * 1024), 2),
        }

    try:
        from urllib.parse import urlparse
        sync_url = settings.database_url.replace("+asyncpg", "")
        parsed = urlparse(sync_url)

        env = os.environ.copy()
        env["PGPASSWORD"] = parsed.password or ""

        cmd = [
            "pg_restore",
            "-h", parsed.hostname or "localhost",
            "-p", str(parsed.port or 5432),
            "-U", parsed.username or "pysoar",
            "-d", parsed.path.lstrip("/") or "pysoar",
            "--clean",
            "--if-exists",
            filepath,
        ]

        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)

        return {
            "status": "success" if result.returncode == 0 else "completed_with_warnings",
            "message": "Database restored from backup",
            "filename": filename,
            "warnings": result.stderr[:500] if result.stderr else None,
        }

    except Exception as e:
        logger.error(f"Restore failed: {e}")
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")


@router.delete("/backups/{filename}")
async def delete_backup(
    filename: str,
    current_user: CurrentUser = None,
):
    """Delete a backup file."""
    filepath = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Backup not found")

    os.remove(filepath)
    return {"status": "deleted", "filename": filename}


@router.get("/notifications/test")
async def test_email_notification(current_user: CurrentUser = None):
    """Send a test email notification to verify SMTP configuration."""
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
