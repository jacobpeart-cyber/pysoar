"""Auto-created incidents must inherit containment artifacts from their alert.

The Agentic SOC's ``remediate_incident`` (and ``_queue_incident_containment``,
and the remediation policy engine) act on an incident's structured
``affected_systems`` / ``indicators`` fields. The automation pipeline was
creating incidents with all of those NULL — even when the source alert had
``hostname='staging-api'`` and ``destination_ip='185.220.101.7'`` — so every
remediation silently no-oped ("no containable artifacts"). These tests pin
the fix: the incident inherits the host to isolate and the *public* IOCs to
block, while RFC1918 source IPs (the internal host's own address) are excluded.
"""

import json

import pytest

from src.models.alert import Alert
from src.models.incident import Incident
from src.services.automation import AutomationService


def _alert(**kw) -> Alert:
    base = dict(title="t", severity="critical", source="manual")
    base.update(kw)
    return Alert(**base)


def test_artifacts_c2_beacon_extracts_host_and_public_ip(db_session):
    svc = AutomationService(db_session)
    a = _alert(
        title="C2 beacon: staging-api to 185.220.101.7",
        category="c2",
        source_ip="10.2.40.12",          # internal beaconing host — private, NOT an IOC
        destination_ip="185.220.101.7",  # C2 server — public, block it
        hostname="staging-api",          # internal host — isolate it
        username="cron",
    )
    art = svc._incident_artifacts_from_alert(a)
    assert art["affected_systems"] == ["staging-api"]
    assert art["affected_users"] == ["cron"]
    assert "185.220.101.7" in art["indicators"]
    assert "10.2.40.12" not in art["indicators"]  # private source IP excluded


def test_artifacts_failed_login_extracts_foreign_ip(db_session):
    svc = AutomationService(db_session)
    a = _alert(
        title="Multiple failed logins for alice@corp from foreign IP",
        category="authentication",
        source_ip="203.0.113.42",  # foreign attacker — public, block it
        hostname="sso-01",
        username="alice@corp",
    )
    art = svc._incident_artifacts_from_alert(a)
    assert art["affected_systems"] == ["sso-01"]
    assert art["affected_users"] == ["alice@corp"]
    assert art["indicators"] == ["203.0.113.42"]


def test_artifacts_darkweb_has_nothing_to_contain(db_session):
    svc = AutomationService(db_session)
    a = _alert(title="Dark Web: data_breach_listing", category="data_leak")
    art = svc._incident_artifacts_from_alert(a)
    assert art["affected_systems"] == []
    assert art["indicators"] == []


def test_artifacts_harvest_ip_from_title_text(db_session):
    """When only free text carries the signal, public IPs are still harvested."""
    svc = AutomationService(db_session)
    a = _alert(title="Beacon observed to 185.220.101.7 over 443", category="c2")
    art = svc._incident_artifacts_from_alert(a)
    assert "185.220.101.7" in art["indicators"]


@pytest.mark.asyncio
async def test_auto_created_incident_is_actionable(db_session):
    """End-to-end: an auto-created incident carries the host + IOC, so a
    downstream remediate_incident has something real to isolate/block."""
    from src.services.agent_tools import AgentToolRegistry

    svc = AutomationService(db_session)
    a = _alert(
        title="C2 beacon: staging-api to 185.220.101.7",
        category="c2",
        source_ip="10.2.40.12",
        destination_ip="185.220.101.7",
        hostname="staging-api",
        username="cron",
        organization_id="org-1",
    )
    db_session.add(a)
    await db_session.commit()
    await db_session.refresh(a)

    inc = await svc._auto_create_incident(a, "org-1", None)
    await db_session.commit()
    assert inc is not None
    assert json.loads(inc.affected_systems) == ["staging-api"]
    assert "185.220.101.7" in json.loads(inc.indicators)
    assert inc.organization_id == "org-1"

    # And the agent's remediation now actually contains it.
    out = await AgentToolRegistry(db_session).execute(
        "remediate_incident", {"incident_id": inc.id}
    )
    assert out["success"] is True
    r = out["result"]
    assert "staging-api" in r["hosts_isolated"]
    assert "185.220.101.7" in r["indicators_blocked"]
