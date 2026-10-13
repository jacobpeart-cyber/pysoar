"""TicketHub automation rules: validation, matching and execution.

An ``AutomationRule`` row says "when <trigger> happens and <conditions> hold,
do <actions>". This module is the only place that interprets those columns:

* :func:`parse_rule` validates a rule. It raises :class:`RuleUnsupportedError`
  (the route answers 501, the evaluator marks the row ``unsupported``) for a
  trigger or action the platform cannot carry out, and :class:`RuleInvalidError`
  (400) for malformed input. Nothing is ever silently ignored: an unknown
  condition key is an error, not a match-everything.
* :func:`evaluate_rules` is the beat evaluator's core
  (``src/tickethub/tasks.py``). Per organisation, per enabled rule, it reads
  the events created since the rule's cursor in fixed windows, matches the
  stored conditions and executes the stored actions through existing paths,
  writing one :class:`AutomationRuleFiring` row (and one AuditLog row) per
  action with the honest outcome.

Triggers (``trigger_type``)
---------------------------
``alert_created`` (alias ``siem_alert``, ``alert``)
    New alerts. Conditions: severity, status, source, category, alert_type,
    hostname, source_ip, destination_ip, username, domain, title_contains.
``incident_created``
    New incidents. Conditions: severity, status, incident_type, priority,
    title_contains.
``ticket_status_change``
    TicketHub status changes (``TicketActivity`` rows with
    ``activity_type="status_change"``, written by the status and kanban
    routes). Conditions: source_type, from_status, to_status.
``manual``
    Unsupported: there is no event that would fire it.

A condition value is a scalar (case-insensitive equality) or a non-empty list
(membership). Empty conditions match every event of the trigger.

Actions (``actions``)
---------------------
A list of ``{"type": ..., ...}`` objects, a single such object, or the
shorthand ``{"set_status": "acknowledged", "notify": {}}``.

``set_status`` {value}
    Alert / incident status (validated against the model's enum) or the
    ticket's native status (validated against the TicketHub kanban map).
``assign`` {user_id}
    Assign to a user of the same organisation.
``add_tag`` {tag}
    Alerts and incidents only.
``notify`` {message?}
    The organisation's notification channels
    (``src.services.notifications.send_incident_notifications``, per-tenant
    Slack / Teams / PagerDuty / OpsGenie). No channel configured is recorded
    as ``awaiting_integration``, not success.
``block_ip`` / ``isolate_host``
    Alerts only; the alert's source_ip / hostname goes to
    ``src.services.containment`` (endpoint-agent commands, high-blast ones
    through the agent approval queue as ``queued_for_approval``;
    ``detection_only`` when no agent or integration covers the target).

Rule actions write ``automation_*`` activity types, never ``status_change``,
so a rule can never re-trigger itself (loop guard).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import and_, distinct, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.models.alert import Alert, AlertStatus
from src.models.audit import AuditLog
from src.models.incident import Incident, IncidentStatus
from src.models.user import User
from src.tickethub.models import AutomationRule, AutomationRuleFiring, TicketActivity

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Bounds (prod OOM post-mortem conventions: windowed reads, per-run caps)
# --------------------------------------------------------------------------- #
#: Events read per round trip (plain column tuples, not ORM objects).
EVENT_BATCH = 200
#: Events one rule may examine per run; the rest is deferred (cursor holds).
MAX_EVENTS_PER_RULE_PER_RUN = 1_000
#: Rules evaluated per run across all organisations.
MAX_RULES_PER_RUN = 500
#: Rules read per round trip.
RULE_PAGE = 100
#: A cursor older than this is clamped: a rule re-enabled after a long pause
#: does not replay days of backlog.
MAX_LOOKBACK = timedelta(hours=24)
#: The window re-reads this much before the cursor, so an event committed a
#: little after its created_at is not missed. Per-event dedupe (firings
#: ``event_id``) keeps the overlap from firing twice.
SETTLE_OVERLAP = timedelta(minutes=2)
#: Actions per rule.
MAX_ACTIONS_PER_RULE = 10

RESULT_SUCCESS = "success"
RESULT_FAILED = "failed"
RESULT_AWAITING_INTEGRATION = "awaiting_integration"
RESULT_DETECTION_ONLY = "detection_only"
RESULT_QUEUED_FOR_APPROVAL = "queued_for_approval"

TRIGGER_ALIASES: dict[str, str] = {
    "alert_created": "alert_created",
    "siem_alert": "alert_created",
    "alert": "alert_created",
    "incident_created": "incident_created",
    "ticket_status_change": "ticket_status_change",
}

UNSUPPORTED_TRIGGERS: dict[str, str] = {
    "manual": (
        "manual rules have no triggering event, so the evaluator would never fire "
        "them; run a playbook manually instead"
    ),
}

_CONDITION_FIELDS: dict[str, frozenset[str]] = {
    "alert_created": frozenset({
        "severity", "status", "source", "category", "alert_type", "hostname",
        "source_ip", "destination_ip", "username", "domain", "title_contains",
    }),
    "incident_created": frozenset({"severity", "status", "incident_type", "priority", "title_contains"}),
    "ticket_status_change": frozenset({"source_type", "from_status", "to_status"}),
}

_ACTIONS_BY_TRIGGER: dict[str, frozenset[str]] = {
    "alert_created": frozenset({"set_status", "assign", "add_tag", "notify", "block_ip", "isolate_host"}),
    "incident_created": frozenset({"set_status", "assign", "add_tag", "notify"}),
    "ticket_status_change": frozenset({"set_status", "assign", "notify"}),
}

_KNOWN_ACTIONS = frozenset().union(*_ACTIONS_BY_TRIGGER.values())

_ALERT_STATUSES = frozenset(s.value for s in AlertStatus)
_INCIDENT_STATUSES = frozenset(s.value for s in IncidentStatus)


class RuleUnsupportedError(Exception):
    """The rule cannot be evaluated by the platform (route: 501)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RuleInvalidError(ValueError):
    """The rule is malformed (route: 400)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class RuleSpec:
    """A validated rule."""

    trigger: str
    conditions: dict[str, Any]
    actions: list[dict[str, Any]]


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def _load_json(value: Any, what: str) -> Any:
    """Stored rules may hold JSON text (legacy double-encoding) or native JSON."""
    if isinstance(value, str):
        if not value.strip():
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise RuleInvalidError(f"{what} is not valid JSON") from exc
    return value


def _normalize_actions(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        if "type" in raw:
            raw = [raw]
        else:
            # Shorthand: {"set_status": "closed", "notify": {}}
            items: list[dict[str, Any]] = []
            for key, value in raw.items():
                if isinstance(value, dict):
                    items.append({"type": key, **value})
                else:
                    items.append({"type": key, "value": value})
            raw = items
    if not isinstance(raw, list):
        raise RuleInvalidError("actions must be a list of action objects or an object")
    actions: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("type"), str) or not item["type"]:
            raise RuleInvalidError("every action needs a string 'type'")
        actions.append(dict(item))
    return actions


def _param(action: dict[str, Any], *names: str) -> Optional[str]:
    for name in names:
        value = action.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def parse_rule(trigger_type: Any, trigger_conditions: Any, actions: Any) -> RuleSpec:
    """Validate a rule; raise :class:`RuleUnsupportedError` or :class:`RuleInvalidError`."""
    raw_trigger = (trigger_type or "").strip().lower() if isinstance(trigger_type, str) else ""
    if not raw_trigger:
        raise RuleInvalidError("trigger_type is required")
    if raw_trigger in UNSUPPORTED_TRIGGERS:
        raise RuleUnsupportedError(UNSUPPORTED_TRIGGERS[raw_trigger])
    trigger = TRIGGER_ALIASES.get(raw_trigger)
    if trigger is None:
        raise RuleUnsupportedError(
            f"trigger_type '{raw_trigger}' is not evaluated by the platform; supported: "
            f"{sorted(TRIGGER_ALIASES)}",
        )

    conditions = _load_json(trigger_conditions, "trigger_conditions") or {}
    if not isinstance(conditions, dict):
        raise RuleInvalidError("trigger_conditions must be an object")
    allowed = _CONDITION_FIELDS[trigger]
    unknown = sorted(set(conditions) - allowed)
    if unknown:
        raise RuleUnsupportedError(
            f"condition(s) {unknown} cannot be evaluated for {trigger}; supported: {sorted(allowed)}",
        )
    for key, value in conditions.items():
        if isinstance(value, list):
            if not value or not all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in value):
                raise RuleInvalidError(f"condition '{key}' must be a non-empty list of strings or numbers")
        elif not isinstance(value, (str, int)) or isinstance(value, bool):
            raise RuleInvalidError(f"condition '{key}' must be a string, a number or a list of them")
        if key == "title_contains" and not isinstance(value, str):
            raise RuleInvalidError("condition 'title_contains' must be a string")

    action_list = _normalize_actions(_load_json(actions, "actions"))
    if not action_list:
        raise RuleUnsupportedError("the rule has no actions, so firing it would do nothing")
    if len(action_list) > MAX_ACTIONS_PER_RULE:
        raise RuleInvalidError(f"a rule may carry at most {MAX_ACTIONS_PER_RULE} actions")

    permitted = _ACTIONS_BY_TRIGGER[trigger]
    normalized: list[dict[str, Any]] = []
    for action in action_list:
        kind = action["type"].strip().lower()
        if kind not in _KNOWN_ACTIONS:
            raise RuleUnsupportedError(
                f"action '{kind}' is not implemented; supported actions: {sorted(_KNOWN_ACTIONS)}",
            )
        if kind not in permitted:
            raise RuleUnsupportedError(
                f"action '{kind}' cannot run on {trigger} targets; supported there: {sorted(permitted)}",
            )
        out: dict[str, Any] = {"type": kind}
        if kind == "set_status":
            value = _param(action, "value", "status")
            if not value:
                raise RuleInvalidError("set_status needs a 'value'")
            if trigger == "alert_created" and value not in _ALERT_STATUSES:
                raise RuleInvalidError(f"set_status '{value}' is not an alert status: {sorted(_ALERT_STATUSES)}")
            if trigger == "incident_created" and value not in _INCIDENT_STATUSES:
                raise RuleInvalidError(
                    f"set_status '{value}' is not an incident status: {sorted(_INCIDENT_STATUSES)}",
                )
            out["value"] = value
        elif kind == "assign":
            user_id = _param(action, "user_id", "value", "assignee")
            if not user_id:
                raise RuleInvalidError("assign needs a 'user_id'")
            out["user_id"] = user_id
        elif kind == "add_tag":
            tag = _param(action, "tag", "value")
            if not tag:
                raise RuleInvalidError("add_tag needs a 'tag'")
            out["tag"] = tag[:100]
        elif kind == "notify":
            message = _param(action, "message", "value")
            if message:
                out["message"] = message[:2000]
        normalized.append(out)

    return RuleSpec(trigger=trigger, conditions=dict(conditions), actions=normalized)


# --------------------------------------------------------------------------- #
# Ticket source models (shared with the TicketHub router)
# --------------------------------------------------------------------------- #
def ticket_model_for(source_type: str) -> Any:
    """The SQLAlchemy model behind a TicketHub source type, or None."""
    try:
        if source_type == "incident":
            return Incident
        if source_type == "case_task":
            from src.models.case import Task
            return Task
        if source_type == "remediation_ticket":
            from src.exposure.models import RemediationTicket
            return RemediationTicket
        if source_type == "action_item":
            from src.collaboration.models import ActionItem
            return ActionItem
        if source_type == "poam":
            from src.compliance.models import POAM
            return POAM
    except ImportError:
        return None
    return None


async def get_scoped_ticket(db: AsyncSession, model: Any, source_id: str, org_id: str) -> Any:
    """Load a source record only if it belongs to ``org_id``.

    Case tasks carry no organization_id; they are scoped through the owning
    incident. Every other source model has its own organization_id.
    """
    from src.models.case import Task

    stmt = select(model).where(model.id == source_id)
    if model is Task:
        stmt = stmt.where(Task.incident_id.in_(select(Incident.id).where(Incident.organization_id == org_id)))
    else:
        stmt = stmt.where(model.organization_id == org_id)
    return (await db.execute(stmt)).scalars().first()


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #
@dataclass
class RuleEvent:
    """One triggering event, as plain values (no ORM object is held)."""

    event_id: str
    created_at: datetime
    target_type: str
    target_id: str
    values: dict[str, Any] = field(default_factory=dict)
    title: str = ""


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


_ALERT_COLUMNS = (
    Alert.id, Alert.created_at, Alert.title, Alert.severity, Alert.status, Alert.source,
    Alert.category, Alert.alert_type, Alert.hostname, Alert.source_ip, Alert.destination_ip,
    Alert.username, Alert.domain,
)
_INCIDENT_COLUMNS = (
    Incident.id, Incident.created_at, Incident.title, Incident.severity, Incident.status,
    Incident.incident_type, Incident.priority,
)
_ACTIVITY_COLUMNS = (
    TicketActivity.id, TicketActivity.created_at, TicketActivity.source_type,
    TicketActivity.source_id, TicketActivity.old_value, TicketActivity.new_value,
)


def _event_query(trigger: str, org_id: str, start: datetime, end: datetime, after: Optional[tuple[datetime, str]]):
    if trigger == "alert_created":
        model, cols = Alert, _ALERT_COLUMNS
        stmt = select(*cols).where(Alert.organization_id == org_id)
    elif trigger == "incident_created":
        model, cols = Incident, _INCIDENT_COLUMNS
        stmt = select(*cols).where(Incident.organization_id == org_id)
    else:
        model, cols = TicketActivity, _ACTIVITY_COLUMNS
        stmt = select(*cols).where(
            TicketActivity.organization_id == org_id,
            TicketActivity.activity_type == "status_change",
        )
    stmt = stmt.where(model.created_at >= start, model.created_at <= end)
    if after is not None:
        last_at, last_id = after
        stmt = stmt.where(or_(model.created_at > last_at, and_(model.created_at == last_at, model.id > last_id)))
    return stmt.order_by(model.created_at.asc(), model.id.asc()).limit(EVENT_BATCH)


def _to_event(trigger: str, row: Any) -> RuleEvent:
    if trigger == "alert_created":
        values = {
            "severity": row.severity, "status": row.status, "source": row.source,
            "category": row.category, "alert_type": row.alert_type, "hostname": row.hostname,
            "source_ip": row.source_ip, "destination_ip": row.destination_ip,
            "username": row.username, "domain": row.domain,
        }
        return RuleEvent(row.id, _aware(row.created_at), "alert", row.id, values, row.title or "")
    if trigger == "incident_created":
        values = {
            "severity": row.severity, "status": row.status,
            "incident_type": row.incident_type, "priority": row.priority,
        }
        return RuleEvent(row.id, _aware(row.created_at), "incident", row.id, values, row.title or "")
    values = {"source_type": row.source_type, "from_status": row.old_value, "to_status": row.new_value}
    return RuleEvent(row.id, _aware(row.created_at), row.source_type, row.source_id, values, "")


def _norm(value: Any) -> str:
    return str(value).strip().lower()


def matches(spec: RuleSpec, event: RuleEvent) -> bool:
    """True when every stored condition holds for ``event``."""
    for key, expected in spec.conditions.items():
        if key == "title_contains":
            if _norm(expected) not in (event.title or "").lower():
                return False
            continue
        actual = event.values.get(key)
        if actual is None:
            return False
        if isinstance(expected, list):
            if _norm(actual) not in {_norm(v) for v in expected}:
                return False
        elif _norm(actual) != _norm(expected):
            return False
    return True


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
@dataclass
class ActionOutcome:
    result: str
    error: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleContext:
    rule_id: str
    rule_name: str
    organization_id: str

    @property
    def actor(self) -> str:
        return f"system:automation_rule:{self.rule_id}"


async def _load_target(db: AsyncSession, ctx: RuleContext, event: RuleEvent) -> Any:
    if event.target_type == "alert":
        stmt = select(Alert).where(Alert.id == event.target_id, Alert.organization_id == ctx.organization_id)
        return (await db.execute(stmt)).scalars().first()
    model = ticket_model_for(event.target_type)
    if model is None:
        return None
    return await get_scoped_ticket(db, model, event.target_id, ctx.organization_id)


def _record_activity(db: AsyncSession, ctx: RuleContext, event: RuleEvent, kind: str, description: str,
                     old: Optional[str] = None, new: Optional[str] = None) -> None:
    db.add(TicketActivity(
        source_type=event.target_type,
        source_id=event.target_id,
        activity_type=f"automation_{kind}",
        actor_id=None,
        description=description[:500],
        old_value=old,
        new_value=new,
        extra_metadata={"rule_id": ctx.rule_id, "actor": ctx.actor},
        organization_id=ctx.organization_id,
    ))


async def _act_set_status(db: AsyncSession, ctx: RuleContext, event: RuleEvent, action: dict[str, Any]) -> ActionOutcome:
    target = await _load_target(db, ctx, event)
    if target is None:
        return ActionOutcome(RESULT_FAILED, "target no longer exists in this organisation")
    value = action["value"]
    if event.target_type not in ("alert", "incident"):
        from src.tickethub.engine import KANBAN_MAP

        native = {s for statuses in KANBAN_MAP.get(event.target_type, {}).values() for s in statuses}
        if value not in native:
            return ActionOutcome(
                RESULT_FAILED, f"'{value}' is not a {event.target_type} status: {sorted(native)}",
            )
    old = getattr(target, "status", None)
    if old == value:
        return ActionOutcome(RESULT_SUCCESS, detail={"status": value, "changed": False})
    target.status = value
    if event.target_type == "alert" and value in (AlertStatus.RESOLVED.value, AlertStatus.CLOSED.value):
        if not getattr(target, "resolved_at", None):
            target.resolved_at = datetime.now(timezone.utc).isoformat()
    _record_activity(db, ctx, event, "status_change", f"Rule '{ctx.rule_name}' set status {old} -> {value}", old, value)
    return ActionOutcome(RESULT_SUCCESS, detail={"old_status": old, "status": value, "changed": True})


async def _act_assign(db: AsyncSession, ctx: RuleContext, event: RuleEvent, action: dict[str, Any]) -> ActionOutcome:
    user_id = action["user_id"]
    user = (await db.execute(
        select(User.id).where(User.id == user_id, User.organization_id == ctx.organization_id, User.is_active == True),  # noqa: E712
    )).scalar_one_or_none()
    if user is None:
        return ActionOutcome(RESULT_FAILED, f"user {user_id} is not an active user of this organisation")
    target = await _load_target(db, ctx, event)
    if target is None:
        return ActionOutcome(RESULT_FAILED, "target no longer exists in this organisation")
    if not hasattr(target, "assigned_to"):
        return ActionOutcome(RESULT_FAILED, f"{event.target_type} tickets have no assignee field")
    old = target.assigned_to
    target.assigned_to = user_id
    _record_activity(db, ctx, event, "assign", f"Rule '{ctx.rule_name}' assigned to {user_id}", old, user_id)
    return ActionOutcome(RESULT_SUCCESS, detail={"assigned_to": user_id, "previous": old})


async def _act_add_tag(db: AsyncSession, ctx: RuleContext, event: RuleEvent, action: dict[str, Any]) -> ActionOutcome:
    target = await _load_target(db, ctx, event)
    if target is None:
        return ActionOutcome(RESULT_FAILED, "target no longer exists in this organisation")
    try:
        tags = json.loads(target.tags) if target.tags else []
    except (json.JSONDecodeError, TypeError):
        return ActionOutcome(RESULT_FAILED, "existing tags are not a JSON list; not overwriting them")
    if not isinstance(tags, list):
        return ActionOutcome(RESULT_FAILED, "existing tags are not a JSON list; not overwriting them")
    tag = action["tag"]
    if tag in tags:
        return ActionOutcome(RESULT_SUCCESS, detail={"tag": tag, "changed": False})
    tags.append(tag)
    target.tags = json.dumps(tags)
    _record_activity(db, ctx, event, "tag", f"Rule '{ctx.rule_name}' added tag {tag}", None, tag)
    return ActionOutcome(RESULT_SUCCESS, detail={"tag": tag, "changed": True})


async def _act_notify(db: AsyncSession, ctx: RuleContext, event: RuleEvent, action: dict[str, Any]) -> ActionOutcome:
    from src.services.notifications import send_incident_notifications

    title = event.title or f"{event.target_type} {event.target_id}"
    payload: dict[str, Any] = {
        "title": f"[Rule: {ctx.rule_name}] {title}"[:300],
        "severity": event.values.get("severity") or "medium",
        "summary": action.get("message") or f"Automation rule '{ctx.rule_name}' fired on {event.target_type} {event.target_id}.",
        "trigger": ctx.actor,
    }
    if event.target_type == "incident":
        payload["incident_id"] = event.target_id
    sent = await send_incident_notifications(db, organization_id=ctx.organization_id, event=payload)
    detail = {"sent": sent.get("sent", []), "failed": sent.get("failed", []), "skipped": sent.get("skipped", [])}
    if detail["sent"]:
        return ActionOutcome(RESULT_SUCCESS, detail=detail)
    if detail["failed"]:
        return ActionOutcome(RESULT_FAILED, "; ".join(detail["failed"])[:1000], detail)
    return ActionOutcome(
        RESULT_AWAITING_INTEGRATION,
        "no notification channel (Slack, Teams, PagerDuty, OpsGenie) is configured for this organisation",
        detail,
    )


def _containment_outcome(result: Any) -> ActionOutcome:
    """Map a ``ContainmentResult`` to a firing outcome without upgrading it."""
    data = result.to_dict()
    if result.failed:
        return ActionOutcome(RESULT_FAILED, result.error or result.detail, data)
    if result.status == "executed":
        return ActionOutcome(RESULT_SUCCESS, None, data)
    if result.status == "queued_for_approval":
        return ActionOutcome(RESULT_QUEUED_FOR_APPROVAL, None, data)
    if result.status == RESULT_AWAITING_INTEGRATION:
        return ActionOutcome(RESULT_AWAITING_INTEGRATION, result.missing_dependency or result.detail, data)
    return ActionOutcome(RESULT_DETECTION_ONLY, result.detail, data)


async def _act_containment(db: AsyncSession, ctx: RuleContext, event: RuleEvent, action: dict[str, Any]) -> ActionOutcome:
    kind = action["type"]
    field_name = "source_ip" if kind == "block_ip" else "hostname"
    target_value = event.values.get(field_name)
    if not target_value:
        return ActionOutcome(RESULT_FAILED, f"the alert has no {field_name} to act on")
    # Imported lazily: the shared containment path (endpoint-agent command
    # queue, CrowdStrike integration) pulls in the agents / integrations
    # packages, which the evaluator does not otherwise need.
    from src.services import containment

    common: dict[str, Any] = {
        "actor": ctx.actor,
        "reason": f"automation rule '{ctx.rule_name}' on alert {event.target_id}",
        "execution_ref": f"automation_rule:{ctx.rule_id}:{event.event_id}",
    }
    if kind == "block_ip":
        result = await containment.block_ip(db, ctx.organization_id, ip=target_value, **common)
    else:
        result = await containment.isolate_host(db, ctx.organization_id, hostname=target_value, **common)
    outcome = _containment_outcome(result)
    outcome.detail = {"target": target_value, **outcome.detail}
    return outcome


_ACTION_HANDLERS: dict[str, Callable[[AsyncSession, RuleContext, RuleEvent, dict[str, Any]], Any]] = {
    "set_status": _act_set_status,
    "assign": _act_assign,
    "add_tag": _act_add_tag,
    "notify": _act_notify,
    "block_ip": _act_containment,
    "isolate_host": _act_containment,
}


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


async def fire_rule(db: AsyncSession, ctx: RuleContext, spec: RuleSpec, event: RuleEvent, now: datetime) -> list[AutomationRuleFiring]:
    """Execute every action of ``spec`` on ``event``; one firing row per action.

    A failing action is recorded as ``failed`` with its error and does not
    stop the remaining actions. Each action runs in a SAVEPOINT so a failed
    one leaves no partial writes behind.
    """
    firings: list[AutomationRuleFiring] = []
    for action in spec.actions:
        kind = action["type"]
        try:
            async with db.begin_nested():
                outcome = await _ACTION_HANDLERS[kind](db, ctx, event, action)
        except Exception as exc:  # recorded on the firing row, never swallowed
            logger.warning("automation_rule_action_failed", rule_id=ctx.rule_id, action=kind,
                           target_id=event.target_id, error=str(exc))
            outcome = ActionOutcome(RESULT_FAILED, f"{type(exc).__name__}: {exc}"[:2000])
        firing = AutomationRuleFiring(
            rule_id=ctx.rule_id,
            organization_id=ctx.organization_id,
            target_type=event.target_type,
            target_id=event.target_id,
            event_id=event.event_id,
            action=kind,
            result=outcome.result,
            error=outcome.error,
            detail=_json_safe(outcome.detail) if outcome.detail else None,
            fired_at=now,
        )
        db.add(firing)
        db.add(AuditLog(
            user_id=None,
            organization_id=ctx.organization_id,
            action=f"automation_rule_{kind}",
            resource_type=event.target_type,
            resource_id=event.target_id,
            description=f"{ctx.actor} ({ctx.rule_name}): {kind} -> {outcome.result}"[:1000],
            new_value=json.dumps({"rule_id": ctx.rule_id, "event_id": event.event_id, "action": action,
                                  "result": outcome.result}, default=str),
            success=outcome.result in (RESULT_SUCCESS,),
            error_message=outcome.error,
        ))
        firings.append(firing)
    return firings


# --------------------------------------------------------------------------- #
# Evaluator
# --------------------------------------------------------------------------- #
async def _mark_unsupported(db: AsyncSession, rule_id: str, reason: str) -> None:
    await db.execute(
        update(AutomationRule)
        .where(AutomationRule.id == rule_id)
        .values(evaluation_status="unsupported", unsupported_reason=reason[:2000]),
    )


async def _already_fired(db: AsyncSession, rule_id: str, event_ids: list[str]) -> set[str]:
    if not event_ids:
        return set()
    rows = await db.execute(
        select(distinct(AutomationRuleFiring.event_id)).where(
            AutomationRuleFiring.rule_id == rule_id,
            AutomationRuleFiring.event_id.in_(event_ids),
        ),
    )
    return {r[0] for r in rows.all()}


async def evaluate_rule(db: AsyncSession, rule_id: str, org_id: str, now: datetime) -> dict[str, Any]:
    """Evaluate one rule over its event window and commit the outcome."""
    stmt = (
        select(AutomationRule)
        .where(AutomationRule.id == rule_id, AutomationRule.organization_id == org_id)
        .with_for_update(skip_locked=True)
    )
    rule = (await db.execute(stmt)).scalars().first()
    stats = {"rule_id": rule_id, "events": 0, "matched": 0, "fired": 0, "cooldown_skipped": 0, "truncated": False}
    if rule is None or not rule.is_enabled:
        await db.rollback()
        stats["skipped"] = "locked_or_disabled"
        return stats

    try:
        spec = parse_rule(rule.trigger_type, rule.trigger_conditions, rule.actions)
    except (RuleUnsupportedError, RuleInvalidError) as exc:
        await _mark_unsupported(db, rule_id, exc.reason)
        await db.commit()
        stats["unsupported"] = exc.reason
        return stats

    ctx = RuleContext(rule_id=rule.id, rule_name=rule.name, organization_id=org_id)
    cursor = _aware(rule.last_evaluated_at or rule.created_at or now)
    start = max(cursor - SETTLE_OVERLAP, now - MAX_LOOKBACK)
    cooldown = timedelta(minutes=rule.cooldown_minutes or 0)
    last_fired = _aware(rule.last_triggered_at) if rule.last_triggered_at else None
    if rule.evaluation_status != "active":
        rule.evaluation_status = "active"
        rule.unsupported_reason = None

    new_cursor = now
    after: Optional[tuple[datetime, str]] = None
    fired_events = 0
    while True:
        rows = (await db.execute(_event_query(spec.trigger, org_id, start, now, after))).all()
        if not rows:
            break
        events = [_to_event(spec.trigger, r) for r in rows]
        done = await _already_fired(db, rule_id, [e.event_id for e in events])
        for event in events:
            if stats["events"] >= MAX_EVENTS_PER_RULE_PER_RUN:
                stats["truncated"] = True
                break
            stats["events"] += 1
            after = (event.created_at, event.event_id)
            if event.event_id in done or not matches(spec, event):
                continue
            stats["matched"] += 1
            if cooldown and last_fired is not None and now - last_fired < cooldown:
                stats["cooldown_skipped"] += 1
                continue
            await fire_rule(db, ctx, spec, event, now)
            fired_events += 1
            last_fired = now
        if stats["truncated"]:
            # Deferred, not dropped: the next run starts at the last event
            # examined. The settle overlap is pre-subtracted here so a backlog
            # larger than the overlap can never pin the cursor in place.
            new_cursor = (after[0] if after else start) + SETTLE_OVERLAP
            logger.warning("automation_rule_window_capped", rule_id=rule_id, cap=MAX_EVENTS_PER_RULE_PER_RUN)
            break
        if len(rows) < EVENT_BATCH:
            break

    rule.last_evaluated_at = new_cursor
    if fired_events:
        rule.execution_count = (rule.execution_count or 0) + fired_events
        rule.last_triggered_at = now
    stats["fired"] = fired_events
    await db.commit()
    return stats


async def evaluate_rules(db: AsyncSession, now: Optional[datetime] = None) -> dict[str, Any]:
    """One evaluator run: every enabled rule of every organisation, bounded."""
    now = now or datetime.now(timezone.utc)
    summary: dict[str, Any] = {
        "organizations": 0, "rules": 0, "fired": 0, "unsupported": 0, "errors": 0, "truncated": False,
    }
    org_ids = [
        r[0] for r in (await db.execute(
            select(distinct(AutomationRule.organization_id)).where(
                AutomationRule.is_enabled == True,  # noqa: E712
                AutomationRule.organization_id.is_not(None),
            ),
        )).all()
    ]
    for org_id in sorted(org_ids):
        summary["organizations"] += 1
        last_id = ""
        while True:
            page = [
                r[0] for r in (await db.execute(
                    select(AutomationRule.id)
                    .where(
                        AutomationRule.organization_id == org_id,
                        AutomationRule.is_enabled == True,  # noqa: E712
                        AutomationRule.id > last_id,
                    )
                    .order_by(AutomationRule.id.asc())
                    .limit(RULE_PAGE),
                )).all()
            ]
            await db.rollback()  # end the read transaction before per-rule locks
            for rule_id in page:
                if summary["rules"] >= MAX_RULES_PER_RUN:
                    summary["truncated"] = True
                    break
                summary["rules"] += 1
                try:
                    stats = await evaluate_rule(db, rule_id, org_id, now)
                except Exception as exc:  # one broken rule must not stop the sweep
                    await db.rollback()
                    summary["errors"] += 1
                    logger.error("automation_rule_evaluation_failed", rule_id=rule_id, organization_id=org_id,
                                 error=str(exc), exc_info=True)
                    continue
                summary["fired"] += stats.get("fired", 0)
                if "unsupported" in stats:
                    summary["unsupported"] += 1
                if stats.get("truncated"):
                    summary["truncated"] = True
            if summary["truncated"] and summary["rules"] >= MAX_RULES_PER_RUN:
                break
            if len(page) < RULE_PAGE:
                break
            last_id = page[-1]
        if summary["rules"] >= MAX_RULES_PER_RUN:
            if len(org_ids) > summary["organizations"]:
                summary["truncated"] = True
            logger.warning("automation_rule_run_capped", cap=MAX_RULES_PER_RUN)
            break
    return summary
