"""SIEM pipeline tenant propagation — live-log detection gap.

When host/cloud syslog began flowing into prod, every log_entry and the
alerts it produced landed with organization_id=NULL. Since auto-triage
(the autonomous investigator's intake) is per-org, NULL-org alerts were
never investigated — the live detection chain was broken at the tenant
boundary. The Alert created in process_log step 5 simply never set the
org, and the syslog batch handler never resolved a default org to pass.
"""

import json

import pytest

from src.models.alert import Alert
from src.siem.models import DetectionRule


async def _seed_matching_rule(db_session):
    rule = DetectionRule(
        name="test-failed-password",
        title="SSH Failed Password",
        description="Fires on failed SSH password attempts",
        status="active",
        enabled=True,
        severity="high",
        detection_logic=json.dumps({"raw_log": {"contains": "Failed password"}}),
        condition="selection",
        mitre_techniques=json.dumps(["T1110.001"]),
    )
    db_session.add(rule)
    await db_session.commit()
    from src.siem.engine_manager import reload_rules
    await reload_rules(db_session)
    return rule


@pytest.mark.asyncio
async def test_alert_inherits_org_from_process_log(db_session):
    from src.siem.pipeline import process_log

    await _seed_matching_rule(db_session)
    org = "org-owner-123"

    log_entry, alerts, _ = await process_log(
        raw_log="sshd[1010]: Failed password for root from 203.0.113.7 port 22 ssh2",
        source_type="syslog",
        source_name="syslog/test",
        source_ip="203.0.113.7",
        db=db_session,
        organization_id=org,
    )

    assert log_entry.organization_id == org
    assert alerts, "rule did not fire — detection_logic format may be wrong"

    rows = (
        await db_session.execute(
            __import__("sqlalchemy").select(Alert).where(Alert.source == "siem")
        )
    ).scalars().all()
    assert rows, "no SIEM alert persisted"
    assert all(a.organization_id == org for a in rows), "alert lost tenant scope"


@pytest.mark.asyncio
async def test_syslog_handler_stamps_default_org(db_session, monkeypatch):
    # The batch handler must resolve SOME org so the autonomous
    # investigator can pick up the resulting alerts.
    from src.api.v1.endpoints import siem as siem_ep
    import src.siem.pipeline as pipeline_mod

    captured = {}

    async def fake_process_log(**kwargs):
        captured["organization_id"] = kwargs.get("organization_id")
        from types import SimpleNamespace
        return SimpleNamespace(id="x"), [], []

    # The handler does `from src.siem.pipeline import process_log`
    # locally, so patch at the source module.
    monkeypatch.setattr(pipeline_mod, "process_log", fake_process_log, raising=False)
    monkeypatch.setenv("SIEM_DEFAULT_ORG_ID", "owner-org-xyz")

    await siem_ep._syslog_batch_handler(
        [{"raw_message": "test log line", "source_ip": "10.0.0.1", "hostname": "h1"}]
    )

    assert captured["organization_id"] == "owner-org-xyz"
