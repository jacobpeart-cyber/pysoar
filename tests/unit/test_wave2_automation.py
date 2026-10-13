"""Wave 2 package C: automation rules, TicketHub rules, alert bulk actions.

* TicketHub automation rules are validated on write (501 for what the
  platform cannot evaluate), evaluated by the beat task over new alerts /
  incidents / ticket status changes per organisation, and every firing is
  recorded and exposed through ``GET /tickethub/automation/rules/{id}/firings``.
* The alert pipeline in ``src/services/automation.py`` matches only the
  tenant's IOCs (plus platform feed intel), counts repeats per tenant and
  queues real playbook executions instead of reporting "N playbooks".
* ``POST /alerts/bulk`` returns per-id results and is audited.

Outbound boundaries are mocked (the Slack HTTP post, the Celery broker);
the rule engine, notification fan-out and containment service run for real.
"""

from __future__ import annotations

import importlib.util
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy import MetaData, Table, create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.intel.models import ThreatIndicator
from src.models.alert import Alert
from src.models.audit import AuditLog
from src.models.base import Base
from src.models.incident import Incident
from src.models.organization import Organization
from src.models.playbook import Playbook, PlaybookExecution
from src.models.settings import AppSetting
from src.models.user import User
from src.services.automation import AutomationService
from src.tickethub import rules as rules_mod
from src.tickethub.models import AutomationRule, AutomationRuleFiring, TicketActivity
from src.tickethub.rules import RuleInvalidError, RuleUnsupportedError, evaluate_rules, parse_rule
from src.workers.celery_app import celery_app
from tests.helpers.tenancy import assert_tenant_isolated

pytestmark = pytest.mark.asyncio

RULES_URL = "/api/v1/tickethub/automation/rules"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _rule(
    db: AsyncSession,
    org_id: str,
    *,
    trigger_type: str = "alert_created",
    conditions: Any = None,
    actions: Any = None,
    cooldown: int = 0,
    cursor: datetime | None = None,
    enabled: bool = True,
) -> str:
    rule = AutomationRule(
        name=f"rule-{uuid.uuid4().hex[:6]}",
        trigger_type=trigger_type,
        trigger_conditions=conditions if conditions is not None else {},
        actions=actions if actions is not None else [{"type": "set_status", "value": "acknowledged"}],
        cooldown_minutes=cooldown,
        is_enabled=enabled,
        organization_id=org_id,
        last_evaluated_at=cursor or (_now() - timedelta(minutes=10)),
    )
    db.add(rule)
    await db.commit()
    return rule.id


async def _alert(db: AsyncSession, org_id: str, **fields: Any) -> str:
    alert = Alert(
        organization_id=org_id,
        title=fields.pop("title", "Suspicious login"),
        severity=fields.pop("severity", "critical"),
        source=fields.pop("source", "siem"),
        status=fields.pop("status", "new"),
        created_at=fields.pop("created_at", _now() - timedelta(minutes=1)),
        **fields,
    )
    db.add(alert)
    await db.commit()
    return alert.id


async def _fresh(db: AsyncSession, model: Any, row_id: str) -> Any:
    return (
        await db.execute(select(model).where(model.id == row_id).execution_options(populate_existing=True))
    ).scalar_one()


async def _firings(db: AsyncSession, rule_id: str) -> list[AutomationRuleFiring]:
    return list(
        (
            await db.execute(
                select(AutomationRuleFiring)
                .where(AutomationRuleFiring.rule_id == rule_id)
                .order_by(AutomationRuleFiring.action),
            )
        ).scalars().all(),
    )


# --------------------------------------------------------------------------- #
# Rule grammar
# --------------------------------------------------------------------------- #
def test_parse_rule_accepts_frontend_shapes() -> None:
    # The TicketHub form posts trigger "siem_alert" and an actions object.
    spec = parse_rule("siem_alert", '{"severity": ["critical", "high"]}', {"set_status": "acknowledged", "notify": {}})
    assert spec.trigger == "alert_created"
    assert spec.conditions == {"severity": ["critical", "high"]}
    assert spec.actions == [{"type": "set_status", "value": "acknowledged"}, {"type": "notify"}]


@pytest.mark.parametrize(
    ("trigger", "conditions", "actions", "fragment"),
    [
        ("manual", {}, [{"type": "notify"}], "manual rules"),
        ("webhook_received", {}, [{"type": "notify"}], "not evaluated"),
        ("alert_created", {"mitre_tactic": "TA0001"}, [{"type": "notify"}], "cannot be evaluated"),
        ("alert_created", {}, [{"type": "run_playbook"}], "not implemented"),
        ("incident_created", {}, [{"type": "block_ip"}], "cannot run on incident_created"),
        ("alert_created", {}, [], "no actions"),
    ],
)
def test_parse_rule_unsupported(trigger: str, conditions: Any, actions: Any, fragment: str) -> None:
    with pytest.raises(RuleUnsupportedError) as exc:
        parse_rule(trigger, conditions, actions)
    assert fragment in exc.value.reason


def test_parse_rule_invalid() -> None:
    with pytest.raises(RuleInvalidError):
        parse_rule("alert_created", {}, [{"type": "set_status", "value": "frobnicated"}])
    with pytest.raises(RuleInvalidError):
        parse_rule("alert_created", "{not json", [{"type": "notify"}])


# --------------------------------------------------------------------------- #
# Rule routes
# --------------------------------------------------------------------------- #
async def test_create_rule_validates_and_returns_501_for_unsupported(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    ok = await client.post(
        RULES_URL,
        json={
            "name": "Ack criticals",
            "trigger_type": "siem_alert",
            "trigger_conditions": {"severity": "critical"},
            "actions": {"set_status": "acknowledged"},
        },
        headers=org_a_admin_headers,
    )
    assert ok.status_code == 201, ok.text
    body = ok.json()
    assert body["evaluation_status"] == "active"
    assert body["actions"] == [{"type": "set_status", "value": "acknowledged"}]
    assert body["trigger_conditions"] == {"severity": "critical"}
    assert body["last_evaluated_at"]

    manual = await client.post(
        RULES_URL,
        json={"name": "m", "trigger_type": "manual", "actions": [{"type": "notify"}]},
        headers=org_a_admin_headers,
    )
    assert manual.status_code == 501
    assert manual.json()["detail"]["error"] == "not_implemented"
    assert "manual" in manual.json()["detail"]["reason"]

    bad = await client.post(
        RULES_URL,
        json={"name": "b", "trigger_type": "alert_created", "actions": [{"type": "set_status", "value": "x"}]},
        headers=org_a_admin_headers,
    )
    assert bad.status_code == 400
    assert bad.json()["detail"]["error"] == "invalid_rule"

    # PUT re-validates.
    put = await client.put(
        f"{RULES_URL}/{body['id']}", json={"actions": [{"type": "run_script"}]}, headers=org_a_admin_headers,
    )
    assert put.status_code == 501


async def test_rule_routes_are_admin_only_and_tenant_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    payload = {"name": "r", "trigger_type": "alert_created", "actions": [{"type": "notify"}]}
    for headers in (org_a_headers, viewer_headers):
        assert (await client.post(RULES_URL, json=payload, headers=headers)).status_code == 403
    created = await client.post(RULES_URL, json=payload, headers=org_a_admin_headers)
    rule_id = created.json()["id"]

    await assert_tenant_isolated(client, "GET", f"{RULES_URL}/{rule_id}/firings", org_b_headers)
    await assert_tenant_isolated(client, "PUT", f"{RULES_URL}/{rule_id}", org_b_headers, json={"name": "x"})
    await assert_tenant_isolated(client, "DELETE", f"{RULES_URL}/{rule_id}", org_b_headers)
    listed = await client.get(RULES_URL, headers=org_b_headers)
    assert rule_id not in {r["id"] for r in listed.json()}
    # Viewers read the firing history of their own tenant.
    assert (await client.get(f"{RULES_URL}/{rule_id}/firings", headers=viewer_headers)).status_code == 200


# --------------------------------------------------------------------------- #
# Evaluator
# --------------------------------------------------------------------------- #
async def test_evaluator_fires_matching_alerts_only_in_the_rule_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    rule_id = await _rule(
        db_session,
        org_a_id,
        conditions={"severity": ["critical", "high"], "title_contains": "login"},
        actions=[
            {"type": "set_status", "value": "acknowledged"},
            {"type": "add_tag", "tag": "auto-triaged"},
            {"type": "notify"},
        ],
    )
    hit = await _alert(db_session, org_a_id)
    low = await _alert(db_session, org_a_id, severity="low")
    other_title = await _alert(db_session, org_a_id, title="Port scan")
    other_tenant = await _alert(db_session, org_b_id)
    old = await _alert(db_session, org_a_id, created_at=_now() - timedelta(hours=2))

    summary = await evaluate_rules(db_session)
    assert summary["fired"] == 1 and summary["errors"] == 0

    alert = await _fresh(db_session, Alert, hit)
    assert alert.status == "acknowledged"
    assert json.loads(alert.tags) == ["auto-triaged"]
    for untouched in (low, other_title, other_tenant, old):
        assert (await _fresh(db_session, Alert, untouched)).status == "new"

    firings = await _firings(db_session, rule_id)
    assert {(f.action, f.result) for f in firings} == {
        ("add_tag", "success"),
        ("set_status", "success"),
        # No channel configured: honest, not success.
        ("notify", "awaiting_integration"),
    }
    assert all(f.target_id == hit and f.organization_id == org_a_id for f in firings)

    rule = await _fresh(db_session, AutomationRule, rule_id)
    assert rule.execution_count == 1 and rule.last_triggered_at is not None

    audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.action.like("automation_rule_%")))
    ).scalars().all()
    assert len(audit) == 3 and all(a.organization_id == org_a_id for a in audit)
    activity = (
        await db_session.execute(select(TicketActivity).where(TicketActivity.source_id == hit))
    ).scalars().all()
    assert {a.activity_type for a in activity} >= {"automation_status_change", "automation_tag"}

    # A second run never fires the same event again.
    await evaluate_rules(db_session)
    assert len(await _firings(db_session, rule_id)) == 3
    assert (await _fresh(db_session, AutomationRule, rule_id)).execution_count == 1

    resp = await client.get(f"{RULES_URL}/{rule_id}/firings", headers=org_a_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3 and body["execution_count"] == 1
    assert {i["action"] for i in body["items"]} == {"set_status", "add_tag", "notify"}
    assert (await client.get(f"{RULES_URL}/{rule_id}/firings", headers=org_b_headers)).status_code == 404


async def test_notify_uses_the_tenant_channel(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    db_session.add(AppSetting(
        organization_id=org_a_id, section="notifications",
        value={"slack_webhook_url": "https://hooks.slack.test/T000/B000/a"},
    ))
    db_session.add(AppSetting(
        organization_id=org_b_id, section="notifications",
        value={"slack_webhook_url": "https://hooks.slack.test/T000/B000/b"},
    ))
    await db_session.commit()
    rule_id = await _rule(db_session, org_a_id, actions=[{"type": "notify", "message": "look"}])
    await _alert(db_session, org_a_id)

    post = AsyncMock(return_value=(True, "200"))
    with patch("src.services.notifications._post_json", post):
        await evaluate_rules(db_session)

    assert post.await_count == 1
    assert post.await_args.args[0].endswith("/a")  # org A's webhook, never org B's
    [firing] = await _firings(db_session, rule_id)
    assert firing.result == "success" and firing.detail["sent"] == ["slack: 200"]


async def test_notify_failure_is_recorded_as_failed(db_session: AsyncSession, org_a: Organization) -> None:
    org_a_id = org_a.id
    db_session.add(AppSetting(
        organization_id=org_a_id, section="notifications",
        value={"slack_webhook_url": "https://hooks.slack.test/T000/B000/a"},
    ))
    await db_session.commit()
    rule_id = await _rule(db_session, org_a_id, actions=[{"type": "notify"}])
    await _alert(db_session, org_a_id)
    with patch("src.services.notifications._post_json", AsyncMock(return_value=(False, "500: boom"))):
        await evaluate_rules(db_session)
    [firing] = await _firings(db_session, rule_id)
    assert firing.result == "failed" and "500: boom" in firing.error


async def test_containment_goes_through_the_shared_service(
    db_session: AsyncSession, org_a: Organization,
) -> None:
    """No endpoint agent covers the host: detection_only, never success."""
    org_a_id = org_a.id
    rule_id = await _rule(db_session, org_a_id, actions=[{"type": "block_ip"}, {"type": "isolate_host"}])
    await _alert(db_session, org_a_id, source_ip="203.0.113.7")  # no hostname

    await evaluate_rules(db_session)

    by_action = {f.action: f for f in await _firings(db_session, rule_id)}
    assert by_action["block_ip"].result == "detection_only"
    assert by_action["block_ip"].detail["target"] == "203.0.113.7"
    assert by_action["isolate_host"].result == "failed"
    assert "hostname" in by_action["isolate_host"].error
    containment_audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "containment_block_ip"))
    ).scalars().all()
    assert len(containment_audit) == 1 and containment_audit[0].organization_id == org_a_id
    assert f"automation_rule:{rule_id}" in containment_audit[0].new_value


async def test_ticket_status_change_rule_and_cross_tenant_assignee(
    db_session: AsyncSession,
    org_a: Organization,
    org_a_user: User,
    org_b_user: User,
) -> None:
    org_a_id, analyst_id, outsider_id = org_a.id, org_a_user.id, org_b_user.id
    incident = Incident(organization_id=org_a_id, title="Ransomware", severity="high", status="closed")
    db_session.add(incident)
    await db_session.commit()
    incident_id = incident.id
    ok_rule = await _rule(
        db_session, org_a_id, trigger_type="ticket_status_change",
        conditions={"source_type": "incident", "to_status": "closed"},
        actions=[{"type": "assign", "user_id": analyst_id}],
    )
    bad_rule = await _rule(
        db_session, org_a_id, trigger_type="ticket_status_change",
        conditions={"to_status": "closed"},
        actions=[{"type": "assign", "user_id": outsider_id}],
    )
    db_session.add(TicketActivity(
        source_type="incident", source_id=incident_id, activity_type="status_change",
        description="Status changed", old_value="recovery", new_value="closed",
        organization_id=org_a_id, created_at=_now() - timedelta(seconds=30),
    ))
    await db_session.commit()

    await evaluate_rules(db_session)

    assert (await _fresh(db_session, Incident, incident_id)).assigned_to == analyst_id
    [ok] = await _firings(db_session, ok_rule)
    assert ok.result == "success" and ok.target_type == "incident"
    [bad] = await _firings(db_session, bad_rule)
    assert bad.result == "failed" and "not an active user of this organisation" in bad.error


async def test_unsupported_stored_rule_is_marked_never_ignored(
    db_session: AsyncSession, org_a: Organization,
) -> None:
    org_a_id = org_a.id
    legacy = await _rule(db_session, org_a_id, trigger_type="manual",
                         actions=json.dumps([{"type": "notify"}]))
    await _alert(db_session, org_a_id)

    summary = await evaluate_rules(db_session)

    rule = await _fresh(db_session, AutomationRule, legacy)
    assert rule.evaluation_status == "unsupported"
    assert "manual" in rule.unsupported_reason
    assert summary["unsupported"] == 1
    assert await _firings(db_session, legacy) == []


async def test_cooldown_and_disabled_rules(db_session: AsyncSession, org_a: Organization) -> None:
    org_a_id = org_a.id
    cooled = await _rule(db_session, org_a_id, cooldown=60)
    disabled = await _rule(db_session, org_a_id, enabled=False)
    first = await _alert(db_session, org_a_id, created_at=_now() - timedelta(minutes=2))
    second = await _alert(db_session, org_a_id, created_at=_now() - timedelta(minutes=1))

    await evaluate_rules(db_session)

    firings = await _firings(db_session, cooled)
    assert [f.target_id for f in firings] == [first]
    assert (await _fresh(db_session, Alert, second)).status == "new"
    assert await _firings(db_session, disabled) == []


async def test_window_cap_defers_the_rest_to_the_next_run(
    db_session: AsyncSession, org_a: Organization, monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a_id = org_a.id
    monkeypatch.setattr(rules_mod, "MAX_EVENTS_PER_RULE_PER_RUN", 2)
    monkeypatch.setattr(rules_mod, "EVENT_BATCH", 2)
    rule_id = await _rule(db_session, org_a_id)
    base = _now() - timedelta(minutes=5)
    ids = [await _alert(db_session, org_a_id, created_at=base + timedelta(seconds=i)) for i in range(5)]

    first = await evaluate_rules(db_session)
    assert first["truncated"] is True
    assert len(await _firings(db_session, rule_id)) == 2

    for _ in range(3):
        await evaluate_rules(db_session)
    assert sorted(f.target_id for f in await _firings(db_session, rule_id)) == sorted(ids)


async def test_rule_created_through_route_ignores_history(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    before = await _alert(db_session, org_a_id, created_at=_now() - timedelta(minutes=30))
    resp = await client.post(
        RULES_URL,
        json={"name": "r", "trigger_type": "alert_created", "actions": [{"type": "set_status", "value": "closed"}]},
        headers=org_a_admin_headers,
    )
    rule_id = resp.json()["id"]
    await evaluate_rules(db_session)
    assert await _firings(db_session, rule_id) == []
    assert (await _fresh(db_session, Alert, before)).status == "new"


def test_evaluator_task_is_registered_on_beat() -> None:
    import src.tickethub.tasks  # noqa: F401

    assert "src.tickethub.tasks" in celery_app.conf.include
    entry = celery_app.conf.beat_schedule["tickethub-evaluate-automation-rules"]
    assert entry == {"task": "tickethub.evaluate_automation_rules", "schedule": 60.0}
    assert "tickethub.evaluate_automation_rules" in celery_app.tasks
    limits = celery_app.conf.task_annotations["tickethub.evaluate_automation_rules"]
    assert limits["soft_time_limit"] < limits["time_limit"] < celery_app.conf.task_time_limit


# --------------------------------------------------------------------------- #
# Alert pipeline (src/services/automation.py)
# --------------------------------------------------------------------------- #
async def test_ioc_matching_is_tenant_scoped(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    for org, value in ((org_b_id, "198.51.100.9"), (None, "192.0.2.44"), (org_a_id, "203.0.113.20")):
        db_session.add(ThreatIndicator(
            organization_id=org, value=value, indicator_type="ipv4", severity="high",
            source="test", is_active=True, is_whitelisted=False,
        ))
    await db_session.commit()

    svc = AutomationService(db_session)
    other = Alert(organization_id=org_a_id, title="t", severity="low", source="s", source_ip="198.51.100.9")
    assert await svc._check_ioc_matches(other, org_a_id) == []
    assert other.severity == "low"

    platform = Alert(organization_id=org_a_id, title="t", severity="low", source="s", source_ip="192.0.2.44")
    own = Alert(organization_id=org_a_id, title="t", severity="low", source="s", source_ip="203.0.113.20")
    assert len(await svc._check_ioc_matches(platform, org_a_id)) == 1
    assert len(await svc._check_ioc_matches(own, org_a_id)) == 1
    counts = dict((
        await db_session.execute(select(ThreatIndicator.value, ThreatIndicator.sighting_count))
    ).all())
    assert counts["203.0.113.20"] == 1  # own row counted
    assert not counts["192.0.2.44"]  # shared feed row untouched
    assert not counts["198.51.100.9"]


async def test_repeat_threshold_counts_only_the_tenant(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    for _ in range(3):
        await _alert(db_session, org_b_id, severity="low", source="edr")
    svc = AutomationService(db_session)
    alert = Alert(organization_id=org_a_id, title="t", severity="low", source="edr")
    assert await svc._auto_create_incident(alert, org_a_id, None) is None


async def test_alert_playbooks_are_queued_for_real_and_tenant_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    for org in (org_a_id, org_b_id):
        db_session.add(Playbook(
            organization_id=org, name=f"pb-{org[:4]}", status="active", trigger_type="alert",
            trigger_conditions=json.dumps({"severity": "medium"}), steps=json.dumps([{"type": "notify"}]),
            is_enabled=True,
        ))
    await db_session.commit()

    with patch("src.playbooks.tasks.run_playbook_execution") as task:
        resp = await client.post(
            "/api/v1/alerts",
            json={"title": "x", "severity": "medium", "source": "manual"},
            headers=org_a_headers,
        )
    assert resp.status_code == 201
    executions = (await db_session.execute(select(PlaybookExecution))).scalars().all()
    assert len(executions) == 1
    [execution] = executions
    assert execution.organization_id == org_a_id and execution.status == "pending"
    task.delay.assert_called_once_with(execution.id)


# --------------------------------------------------------------------------- #
# Alerts: bulk + aggregates
# --------------------------------------------------------------------------- #
async def test_bulk_returns_per_id_results_and_is_audited(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_user: User,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id, analyst_id = org_a.id, org_b.id, org_a_user.id
    mine = await _alert(db_session, org_a_id)
    theirs = await _alert(db_session, org_b_id)
    missing = str(uuid.uuid4())

    resp = await client.post(
        "/api/v1/alerts/bulk",
        json={"alert_ids": [mine, theirs, missing, mine], "action": "acknowledge"},
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["results"] == [
        {"id": mine, "status": "updated"},
        {"id": theirs, "status": "not_found"},
        {"id": missing, "status": "not_found"},
    ]
    assert body["success_count"] == 1 and body["failure_count"] == 2
    assert (await _fresh(db_session, Alert, mine)).status == "acknowledged"
    assert (await _fresh(db_session, Alert, theirs)).status == "new"

    [audit] = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "alert_bulk_acknowledge"))
    ).scalars().all()
    assert audit.organization_id == org_a_id and audit.user_id == analyst_id
    assert json.loads(audit.new_value)["results"] == body["results"]


async def test_bulk_role_gates_and_assignee_scope(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b_user: User,
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id, outsider = org_a.id, org_b_user.id
    alert_id = await _alert(db_session, org_a_id)
    ack = {"alert_ids": [alert_id], "action": "acknowledge"}
    assert (await client.post("/api/v1/alerts/bulk", json=ack, headers=viewer_headers)).status_code == 403
    delete = {"alert_ids": [alert_id], "action": "delete"}
    assert (await client.post("/api/v1/alerts/bulk", json=delete, headers=org_a_headers)).status_code == 403
    assign = {"alert_ids": [alert_id], "action": "assign", "value": outsider}
    resp = await client.post("/api/v1/alerts/bulk", json=assign, headers=org_a_headers)
    assert resp.status_code == 400 and resp.json()["detail"]["error"] == "invalid_assignee"

    deleted = await client.post("/api/v1/alerts/bulk", json=delete, headers=org_a_admin_headers)
    assert deleted.json()["results"] == [{"id": alert_id, "status": "deleted"}]


async def test_alert_list_and_stats_are_tenant_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    await _alert(db_session, org_a_id, severity="high", source="edr")
    for _ in range(3):
        await _alert(db_session, org_b_id, severity="critical", source="waf")

    listed = (await client.get("/api/v1/alerts", headers=org_a_headers)).json()
    assert listed["total"] == 1
    stats = (await client.get("/api/v1/alerts/stats", headers=org_a_headers)).json()
    assert stats["total"] == 1
    assert stats["by_severity"] == {"high": 1}
    assert stats["by_source"] == {"edr": 1}


async def test_dashboard_ioc_tile_is_tenant_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    """Dashboard 'IOCs Tracked' reads GET /iocs?size=1 -> total."""
    org_a_id, org_b_id = org_a.id, org_b.id
    for org, value in ((org_a_id, "203.0.113.1"), (org_b_id, "203.0.113.2"), (org_b_id, "203.0.113.3")):
        db_session.add(ThreatIndicator(
            organization_id=org, value=value, indicator_type="ipv4", severity="high",
            source="test", is_active=True, is_whitelisted=False,
        ))
    await db_session.commit()
    resp = await client.get("/api/v1/iocs", params={"size": 1}, headers=org_a_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


# --------------------------------------------------------------------------- #
# Migration 024
# --------------------------------------------------------------------------- #
from tests.unit.test_migration_020 import (  # noqa: E402
    REPO_ROOT,
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

MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / "024_automation_rule_firings.py"


def _load_migration() -> ModuleType:
    _real_alembic()
    spec = importlib.util.spec_from_file_location("migration_024_automation_rule_firings", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration()


def _pre024_metadata() -> MetaData:
    md = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name == migration.FIRINGS:
            continue
        removed = set(migration.NEW_RULE_COLUMNS) if table.name == migration.RULES else set()
        columns = [c._copy() for c in table.columns if c.name not in removed]
        for column in columns:
            column.index = None
            column.unique = None
        Table(table.name, md, *columns)
    return md


@pytest.fixture
def fixture_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    db_path = tmp_path / "pysoar_024.db"
    engine = create_engine(_sync_url(db_path))
    _pre024_metadata().create_all(engine)
    engine.dispose()
    monkeypatch.setattr(settings, "database_url", _async_url(db_path))
    cfg = _alembic_config(db_path)
    _, command, _ = _real_alembic()
    _in_thread(lambda: command.stamp(cfg, "023"))
    return {"path": db_path, "cfg": cfg, "url": _sync_url(db_path)}


def test_revision_024_revises_023() -> None:
    assert migration.revision == "024" and migration.down_revision == "023"


def test_migration_024_round_trip(fixture_db: dict[str, Any]) -> None:
    with _engine(fixture_db).connect() as conn:
        assert not set(migration.NEW_RULE_COLUMNS) & _columns(conn, migration.RULES)
        assert not sa.inspect(conn).has_table(migration.FIRINGS)

    _upgrade(fixture_db, "024")
    assert _version(fixture_db) == "024"
    with _engine(fixture_db).connect() as conn:
        assert set(migration.NEW_RULE_COLUMNS) <= _columns(conn, migration.RULES)
        assert {c.name for c in AutomationRuleFiring.__table__.columns} == _columns(conn, migration.FIRINGS)

    _downgrade(fixture_db, "023")
    assert _version(fixture_db) == "023"
    with _engine(fixture_db).connect() as conn:
        assert not set(migration.NEW_RULE_COLUMNS) & _columns(conn, migration.RULES)
        assert not sa.inspect(conn).has_table(migration.FIRINGS)

    _upgrade(fixture_db, "024")  # idempotent re-apply
    assert _version(fixture_db) == "024"
