"""Regression tests for the P0 audit fixes.

Covers, in order:
  - backup.py path-traversal guard
  - container image scanner no longer fabricates CVEs from the image name
  - playbook notification action reports failure instead of fake success
  - cleanup task reports an error status instead of success-on-failure
  - syslog UDP protocol retains in-flight task references
"""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException


# --------------------------------------------------------------------------
# backup.py — path traversal
# --------------------------------------------------------------------------
def test_safe_backup_path_rejects_traversal():
    from src.api.v1.endpoints.backup import _safe_backup_path

    for bad in ["../../etc/passwd", "..", ".", "a/b.sql", "a\\b.sql", "/etc/shadow", ""]:
        with pytest.raises(HTTPException) as exc:
            _safe_backup_path(bad)
        assert exc.value.status_code == 400


def test_safe_backup_path_accepts_plain_filename():
    from src.api.v1.endpoints.backup import _safe_backup_path, BACKUP_DIR
    import os

    p = _safe_backup_path("pysoar_20260101.sql.gz")
    assert os.path.dirname(p) == os.path.normpath(BACKUP_DIR)


def test_backup_mutations_require_admin():
    # The destructive endpoints must depend on AdminUser, not CurrentUser.
    import inspect
    from src.api.v1.endpoints import backup
    from src.api.deps import AdminUser

    for fn in (backup.create_backup, backup.restore_backup, backup.delete_backup):
        ann = inspect.signature(fn).parameters["current_user"].annotation
        assert ann is AdminUser, f"{fn.__name__} must require AdminUser, got {ann}"


# --------------------------------------------------------------------------
# container scanner — no fabricated CVEs
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_image_scanner_does_not_fabricate_from_name():
    from src.container_security.engine import ImageScanner

    # 'nginx' previously yielded two canned OpenSSL CVEs purely from the name.
    res = await ImageScanner().scan_image(
        registry="docker.io", repository="library/nginx", tag="latest",
        digest="sha256:abc", db=None,
    )
    assert res["vulnerabilities"] == []
    assert res["total_vulnerabilities"] == 0
    assert res["status"] == "no_scanner_backend"


def test_known_vulns_catalog_removed():
    import src.container_security.engine as eng
    assert not hasattr(eng, "_KNOWN_VULNS")
    assert not hasattr(eng.ImageScanner, "_match_vulns")


# --------------------------------------------------------------------------
# playbook notification — honest failure
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_notification_action_reports_enqueue_failure():
    from src.playbooks.actions import SendNotificationAction

    fake_task = MagicMock()
    fake_task.delay.side_effect = RuntimeError("broker down")
    with patch.dict("sys.modules", {"src.workers.tasks": MagicMock(send_notification_task=fake_task)}):
        out = await SendNotificationAction().execute(
            {"channel": "email", "recipients": ["a@b.com"], "subject": "s", "message": "m"}, {}
        )
    assert out["success"] is False
    assert "error" in out


@pytest.mark.asyncio
async def test_notification_action_success_path():
    from src.playbooks.actions import SendNotificationAction

    fake_task = MagicMock()  # delay() succeeds
    with patch.dict("sys.modules", {"src.workers.tasks": MagicMock(send_notification_task=fake_task)}):
        out = await SendNotificationAction().execute(
            {"channel": "email", "recipients": ["a@b.com"], "subject": "s", "message": "m"}, {}
        )
    assert out["success"] is True


# --------------------------------------------------------------------------
# cleanup task — error status instead of fake success
# --------------------------------------------------------------------------
def test_cleanup_reports_error_on_failure():
    import src.core.database as db_mod
    from src.workers.tasks import cleanup_old_executions

    def _boom(*a, **k):
        raise RuntimeError("db unavailable")

    with patch.object(db_mod, "async_session_factory", _boom):
        result = cleanup_old_executions()
    assert result["status"] == "error"
    assert result["cleaned_up"] == 0
    assert "error" in result


# --------------------------------------------------------------------------
# syslog UDP — task reference retained
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_syslog_udp_retains_task_reference():
    from src.siem.collector import SyslogUDPProtocol

    started = asyncio.Event()
    release = asyncio.Event()

    class _Collector:
        async def _process_syslog_message(self, message):
            started.set()
            await release.wait()

    proto = SyslogUDPProtocol(_Collector())
    proto.datagram_received(b"<13>test message", ("127.0.0.1", 514))

    # While the coroutine is in-flight, its task must be retained (not GC-able).
    await started.wait()
    assert len(proto._tasks) == 1

    # Once it completes, the done-callback discards it.
    release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert len(proto._tasks) == 0
