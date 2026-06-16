"""Detection rules for real forwarded syslog (Linux auth.log).

The builtin rules only matched PySOAR's own audit events
(source_type="audit", action="login_failed"). Forwarded host syslog
arrives as source_type="syslog" with no normalized action, so a real
"Failed password for root from ..." line matched NOTHING — live logs
produced zero alerts. These rules match on raw_log content so forwarded
auth logs actually drive detection.
"""

import json

import pytest

from src.models.alert import Alert
from src.siem.models import DetectionRule


REAL_AUTH_LINES = {
    "ssh-failed-password": "sshd[2451]: Failed password for root from 203.0.113.9 port 51234 ssh2",
    "ssh-invalid-user": "sshd[2452]: Invalid user admin from 198.51.100.7 port 40222",
    "ssh-possible-breakin": "sshd[2453]: Address 198.51.100.7 maps to x.example, but this does not map back POSSIBLE BREAK-IN ATTEMPT!",
    "sudo-auth-failure": "sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0",
}


def test_builtin_rules_include_syslog_auth_coverage():
    from src.siem.rule_seeder import BUILTIN_RULES

    names = {r["name"] for r in BUILTIN_RULES}
    for required in REAL_AUTH_LINES:
        assert required in names, f"missing syslog rule {required}"

    # Each syslog rule must match on raw_log (not the audit-only fields).
    for rule in BUILTIN_RULES:
        if rule["name"] in REAL_AUTH_LINES:
            assert "raw_log" in rule["detection_logic"], (
                f"{rule['name']} must match raw_log to fire on forwarded syslog"
            )


async def _seed_builtins(db_session):
    from src.siem.rule_seeder import seed_builtin_detection_rules
    from src.siem.engine_manager import reload_rules
    await seed_builtin_detection_rules(db_session)
    await db_session.commit()
    await reload_rules(db_session)


@pytest.mark.asyncio
@pytest.mark.parametrize("rule_name,line", list(REAL_AUTH_LINES.items()))
async def test_real_auth_line_fires_an_alert(db_session, rule_name, line):
    from src.siem.pipeline import process_log

    await _seed_builtins(db_session)

    _log, alerts, _ = await process_log(
        raw_log=line,
        source_type="syslog",
        source_name="syslog/test-host",
        source_ip="203.0.113.9",
        db=db_session,
        organization_id="org-owner",
    )

    assert alerts, f"{rule_name}: real auth line '{line[:40]}...' produced no alert"
    rows = (
        await db_session.execute(
            __import__("sqlalchemy").select(Alert).where(Alert.source == "siem")
        )
    ).scalars().all()
    assert any(a.organization_id == "org-owner" for a in rows)


@pytest.mark.asyncio
async def test_benign_syslog_does_not_alert(db_session):
    # A normal cron line must NOT trip the auth rules (false-positive guard).
    from src.siem.pipeline import process_log

    await _seed_builtins(db_session)
    _log, alerts, _ = await process_log(
        raw_log="CRON[12345]: (root) CMD (/usr/bin/some-housekeeping)",
        source_type="syslog",
        source_name="syslog/test-host",
        source_ip="10.0.0.1",
        db=db_session,
        organization_id="org-owner",
    )
    assert not alerts, "benign cron line should not fire an auth rule"
