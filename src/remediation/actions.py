"""Remediation action registry and the one runner every remediation path uses.

``ACTION_REGISTRY`` is the source of truth for the action keys a remediation
policy, a manual remediation, a remediation playbook step or a quick action
may reference (exposed read-only as ``GET /remediation/actions``). Policies
that reference a key outside it are rejected at create/update time.

``run_action`` executes one step and returns a JSON-safe step record:

* containment keys (``firewall_block``, ``host_isolate``, ``account_disable``,
  ``file_quarantine``) go through ``src.services.containment`` (endpoint agent
  command queue or an executable integration), which writes the AuditLog row;
* agent-command keys (``process_kill``, ``collect_forensics``) and
  ``notification`` go through the existing engine executors and get an
  AuditLog row written here.

Step record keys: ``action_type`` (canonical key), ``target``, ``path``,
``status`` (``executed`` / ``queued_for_approval`` / ``detection_only`` /
``awaiting_integration`` / ``failed``), ``success`` (True only when a real
command or integration call was issued), ``result`` (= status), ``reversible``,
``revert`` (the stored revert handle, or None), ``detail``, ``error``,
``missing_dependency``, ``details`` (the raw containment / executor result),
``started_at``, ``finished_at``, ``timestamp``, ``audit_log_id``.

``revert_step`` reverses a step only when it recorded ``reversible`` and a
``revert`` handle; it never guesses from values such as an IP or a hostname.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.agents.capabilities import requires_approval as _agent_requires_approval
from src.core.logging import get_logger
from src.models.audit import AuditLog
from src.models.base import utc_now
from src.models.user import User
from src.services import containment

logger = get_logger(__name__)

# Containment statuses (read defensively: the service owns these names).
EXECUTED: str = getattr(containment, "EXECUTED", "executed")
QUEUED_FOR_APPROVAL: str = getattr(containment, "QUEUED_FOR_APPROVAL", "queued_for_approval")
DETECTION_ONLY: str = getattr(containment, "DETECTION_ONLY", "detection_only")
AWAITING_INTEGRATION: str = getattr(containment, "AWAITING_INTEGRATION", "awaiting_integration")
MANUAL_REQUIRED: str = getattr(containment, "MANUAL_REQUIRED", "manual_required")
FAILED = "failed"

#: Statuses where a real command or integration call was issued.
ACTUATED_STATUSES = frozenset({EXECUTED, QUEUED_FOR_APPROVAL})
#: Statuses where nothing actuated but nothing errored either.
NOT_ACTUATED_STATUSES = frozenset({DETECTION_ONLY, AWAITING_INTEGRATION, MANUAL_REQUIRED})

PATH_CONTAINMENT = "containment"
PATH_AGENT_COMMAND = "agent_command"
PATH_NOTIFICATION = "notification"


@dataclass(frozen=True)
class ActionParameter:
    """One parameter an action accepts (values come from the step, else the trigger data)."""

    name: str
    type: str
    required: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type, "required": self.required, "description": self.description}


@dataclass(frozen=True)
class ActionSpec:
    """A remediation action the engine can execute."""

    key: str
    label: str
    description: str
    target_type: str
    path: str
    reversible: bool
    requires_approval: bool
    risk_level: str = "high"
    parameters: tuple[ActionParameter, ...] = ()
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "target_type": self.target_type,
            "path": self.path,
            "parameters": [p.to_dict() for p in self.parameters],
            "requires_approval": self.requires_approval,
            "reversible": self.reversible,
            "risk_level": self.risk_level,
            "aliases": list(self.aliases),
            # Compatibility with the RemediationAction row shape.
            "action_type": self.key,
            "name": self.label,
            "is_reversible": self.reversible,
        }


_REGISTRY_LIST: tuple[ActionSpec, ...] = (
    ActionSpec(
        key="firewall_block",
        label="Block IP",
        description=(
            "Host-firewall block_ip on every enrolled endpoint agent with the 'ir' capability. "
            "Without one the step is detection_only (or awaiting_integration when a firewall "
            "integration without an executable block action is installed). Target: an IP address."
        ),
        target_type="ip",
        path=PATH_CONTAINMENT,
        reversible=True,
        requires_approval=_agent_requires_approval("block_ip"),
        aliases=("block_ip", "auto_block"),
    ),
    ActionSpec(
        key="host_isolate",
        label="Isolate host",
        description=(
            "Network isolation through the host's enrolled endpoint agent, else an installed "
            "CrowdStrike Falcon integration (contain_host). Target: a hostname or asset name."
        ),
        target_type="host",
        path=PATH_CONTAINMENT,
        reversible=True,
        requires_approval=_agent_requires_approval("isolate_host"),
        aliases=("isolate_host", "auto_isolate"),
    ),
    ActionSpec(
        key="account_disable",
        label="Disable account",
        description=(
            "Disable a local account through the endpoint agent on 'hostname'. Directory accounts "
            "(AD / Entra / Okta) need an identity-provider connector PySOAR does not implement: "
            "the step reports awaiting_integration or detection_only. PySOAR login accounts are "
            "never touched. Target: a username. Not reversible (no enable command exists)."
        ),
        target_type="user",
        path=PATH_CONTAINMENT,
        reversible=False,
        requires_approval=_agent_requires_approval("disable_account"),
        parameters=(
            ActionParameter("hostname", "string", False, "Host whose local account is disabled via its agent"),
        ),
        aliases=("disable_user", "disable_account", "auto_disable"),
    ),
    ActionSpec(
        key="file_quarantine",
        label="Quarantine file",
        description=(
            "quarantine_file command on the host's enrolled endpoint agent. Target: the hostname."
        ),
        target_type="host",
        path=PATH_CONTAINMENT,
        reversible=True,
        requires_approval=_agent_requires_approval("quarantine_file"),
        parameters=(ActionParameter("file_path", "string", True, "Absolute path of the file to quarantine"),),
        aliases=("quarantine_file", "auto_quarantine"),
    ),
    ActionSpec(
        key="process_kill",
        label="Kill process",
        description="kill_process command on the host's enrolled endpoint agent. Target: the hostname.",
        target_type="host",
        path=PATH_AGENT_COMMAND,
        reversible=False,
        requires_approval=_agent_requires_approval("kill_process"),
        parameters=(
            ActionParameter("pid", "integer", False, "Process id"),
            ActionParameter("process_name", "string", False, "Process image name"),
        ),
        aliases=("kill_process",),
    ),
    ActionSpec(
        key="collect_forensics",
        label="Collect forensics",
        description=(
            "Process list, network connections and memory dump commands on the host's enrolled "
            "endpoint agent (each tracked separately). Target: the hostname."
        ),
        target_type="host",
        path=PATH_AGENT_COMMAND,
        reversible=False,
        requires_approval=_agent_requires_approval("collect_memory_dump"),
        risk_level="medium",
    ),
    ActionSpec(
        key="notification",
        label="Send notification email",
        description=(
            "Email through the organisation's SMTP settings (else the platform relay). Without a "
            "configured mail service the step is awaiting_integration."
        ),
        target_type="any",
        path=PATH_NOTIFICATION,
        reversible=False,
        requires_approval=False,
        risk_level="low",
        parameters=(
            ActionParameter("recipients", "array", True, "Email addresses"),
            ActionParameter("subject", "string", False, "Subject line"),
            ActionParameter("body", "string", False, "Message body"),
        ),
        aliases=("notify",),
    ),
)

ACTION_REGISTRY: dict[str, ActionSpec] = {spec.key: spec for spec in _REGISTRY_LIST}
_ALIASES: dict[str, str] = {alias: spec.key for spec in _REGISTRY_LIST for alias in spec.aliases}


def resolve_action(key: Optional[str]) -> Optional[ActionSpec]:
    """The spec for a canonical key or one of its aliases, else None."""
    if not key:
        return None
    key = str(key).strip()
    canonical = key if key in ACTION_REGISTRY else _ALIASES.get(key)
    return ACTION_REGISTRY.get(canonical) if canonical else None


def list_actions() -> list[dict[str, Any]]:
    """Registry entries for ``GET /remediation/actions``."""
    return [spec.to_dict() for spec in _REGISTRY_LIST]


class UnknownActionError(ValueError):
    """A policy / step references action keys outside the registry."""

    def __init__(self, unknown: list[str]):
        self.unknown = unknown
        super().__init__(f"unknown remediation action(s): {', '.join(unknown)}")


def step_key(step: Any) -> Optional[str]:
    """The action key a stored step / policy action names."""
    if not isinstance(step, dict):
        return None
    for name in ("type", "action_type", "action", "action_id"):
        value = step.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def normalize_actions(actions: list[Any]) -> list[dict[str, Any]]:
    """Validate policy actions against the registry and store canonical keys.

    Raises ``UnknownActionError`` listing every unknown or malformed entry.
    """
    unknown: list[str] = []
    normalized: list[dict[str, Any]] = []
    for idx, action in enumerate(actions or []):
        key = step_key(action)
        spec = resolve_action(key)
        if spec is None:
            unknown.append(key or f"#{idx} (no action type)")
            continue
        params = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
        entry = {k: v for k, v in action.items() if k not in ("action_type", "action", "action_id")}
        entry["type"] = spec.key
        entry["parameters"] = params
        normalized.append(entry)
    if unknown:
        raise UnknownActionError(unknown)
    return normalized


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return utc_now().isoformat()


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


async def actor_user_id(db: AsyncSession, org_id: str, actor: Optional[str]) -> Optional[str]:
    """``actor`` when it is a user of ``org_id`` (safe for FK columns), else None."""
    if not actor or actor.startswith("system:"):
        return None
    found = await db.execute(select(User.id).where(User.id == actor, User.organization_id == org_id))
    return found.scalar_one_or_none()


async def _audit(
    db: AsyncSession,
    org_id: str,
    *,
    actor: str,
    action: str,
    resource_id: Optional[str],
    description: str,
    payload: dict[str, Any],
    success: bool,
    error: Optional[str],
) -> str:
    row = AuditLog(
        user_id=await actor_user_id(db, org_id, actor),
        organization_id=org_id,
        action=action,
        resource_type="remediation",
        resource_id=resource_id,
        description=description[:4000],
        new_value=json.dumps(payload, default=str),
        success=success,
        error_message=error,
    )
    db.add(row)
    await db.flush()
    return row.id


def _param(name: str, parameters: dict[str, Any], trigger_data: dict[str, Any]) -> Any:
    value = parameters.get(name)
    if value in (None, ""):
        value = trigger_data.get(name)
    return value


def _step(
    spec_key: str,
    requested: Optional[str],
    target: str,
    *,
    path: str,
    status: str,
    detail: str,
    started_at: str,
    reversible: bool = False,
    revert: Optional[dict[str, Any]] = None,
    error: Optional[str] = None,
    missing_dependency: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    audit_log_id: Optional[str] = None,
) -> dict[str, Any]:
    finished = _now_iso()
    step = {
        "action_type": spec_key,
        "target": target,
        "path": path,
        "status": status,
        "result": status,
        "success": status in ACTUATED_STATUSES,
        "reversible": bool(reversible and revert),
        "revert": revert if reversible else None,
        "detail": detail,
        "error": error,
        "missing_dependency": missing_dependency,
        "details": _json_safe(details or {}),
        "audit_log_id": audit_log_id,
        "started_at": started_at,
        "finished_at": finished,
        "timestamp": finished,
    }
    if requested and requested != spec_key:
        step["requested_type"] = requested
    return step


async def _crowdstrike_installation_id(db: AsyncSession, org_id: str) -> Optional[str]:
    from src.integrations.models import InstalledIntegration, IntegrationStatus

    rows = (await db.execute(
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(
            InstalledIntegration.organization_id == org_id,
            InstalledIntegration.status == IntegrationStatus.ACTIVE.value,
        ),
    )).scalars().all()
    for row in rows:
        name = (row.connector.name if row.connector is not None else row.connector_id or "").lower()
        if name == "crowdstrike":
            return row.id
    return None


async def _revert_handle(
    db: AsyncSession, org_id: str, spec: ActionSpec, result: Any, *, target: str, file_path: Optional[str],
) -> Optional[dict[str, Any]]:
    """The handle ``revert_step`` needs, or None when the result cannot be reversed."""
    if not (getattr(result, "reversible", False) and getattr(result, "actuated", False)) or getattr(result, "failed", False):
        return None
    commands = list(getattr(result, "commands", None) or [])
    if not commands and getattr(result, "command_id", None) and getattr(result, "agent_id", None):
        commands = [{"agent_id": result.agent_id, "command_id": result.command_id}]
    commands = [{"agent_id": c.get("agent_id"), "command_id": c.get("command_id")} for c in commands if c.get("agent_id")]
    if spec.key == "firewall_block" and commands:
        return {"kind": "agent_commands", "reverse_action": "unblock_ip", "payload": {"ip": target}, "commands": commands}
    if spec.key == "file_quarantine" and commands and file_path:
        return {
            "kind": "agent_commands", "reverse_action": "unquarantine_file", "payload": {"path": file_path},
            "commands": commands,
        }
    if spec.key == "host_isolate":
        if commands:
            return {
                "kind": "agent_commands", "reverse_action": "release_host",
                "payload": {"hostname": result.target}, "commands": commands,
            }
        if (getattr(result, "integration", None) or "").lower() == "crowdstrike":
            installation_id = await _crowdstrike_installation_id(db, org_id)
            if installation_id:
                return {
                    "kind": "crowdstrike_lift_containment", "installation_id": installation_id,
                    "hostname": result.target,
                }
    return None


async def _run_containment(
    db: AsyncSession,
    org_id: str,
    spec: ActionSpec,
    requested: Optional[str],
    target: str,
    parameters: dict[str, Any],
    trigger_data: dict[str, Any],
    *,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    approval_override: bool,
    unattended: bool,
    started_at: str,
) -> dict[str, Any]:
    common: dict[str, Any] = {
        "actor": actor, "reason": reason, "execution_ref": execution_ref, "approval_override": approval_override,
    }
    if unattended:
        # Scheduled / policy-triggered runs: the service never actuates
        # without a human (agent commands wait for approval, integration
        # containment returns manual_required).
        common["unattended"] = True
    file_path: Optional[str] = None
    if spec.key == "firewall_block":
        # Target validation (IP format, loopback ...) is the service's.
        result = await containment.block_ip(db, org_id, ip=target, **common)
    elif spec.key == "host_isolate":
        result = await containment.isolate_host(db, org_id, hostname=target, **common)
    elif spec.key == "account_disable":
        hostname = _param("hostname", parameters, trigger_data)
        result = await containment.disable_user(
            db, org_id, username=target, hostname=str(hostname) if hostname else None, **common,
        )
    else:  # file_quarantine
        file_path = _param("file_path", parameters, trigger_data)
        file_path = str(file_path) if file_path else None
        if not file_path:
            return _step(
                spec.key, requested, target, path=spec.path, status=FAILED, started_at=started_at,
                detail="file_quarantine needs a file_path parameter; nothing was quarantined",
                error="missing_parameter:file_path",
            )
        result = await containment.quarantine_file(db, org_id, hostname=target, file_path=file_path, **common)

    status = FAILED if getattr(result, "failed", False) else result.status
    revert = await _revert_handle(db, org_id, spec, result, target=target, file_path=file_path)
    details = result.to_dict() if hasattr(result, "to_dict") else dict(vars(result))
    return _step(
        spec.key, requested, target, path=spec.path, status=status, started_at=started_at,
        detail=result.detail, reversible=revert is not None, revert=revert,
        error=getattr(result, "error", None), missing_dependency=getattr(result, "missing_dependency", None),
        details=details, audit_log_id=getattr(result, "audit_log_id", None),
    )


def _normalize_executor_result(spec: ActionSpec, raw: dict[str, Any]) -> tuple[str, str, Optional[str], Optional[str]]:
    """(status, detail, error, missing_dependency) for an engine executor result."""
    if spec.key == "notification":
        if raw.get("email_sent"):
            return EXECUTED, f"email sent to {', '.join(raw.get('recipients') or [])}", None, None
        err = raw.get("email_error")
        if not raw.get("recipients"):
            return FAILED, "notification needs recipients; nothing was sent", "missing_parameter:recipients", None
        if err and "not configured" in err.lower():
            return AWAITING_INTEGRATION, "no mail service is configured; nothing was sent", err, "SMTP settings"
        return FAILED, f"email was not sent: {err or 'mail service refused'}", err or "send_failed", None
    if spec.key == "collect_forensics":
        subs = raw.get("sub_results") or []
        queued = [s for s in subs if s.get("success")]
        if not raw.get("agent_id"):
            return DETECTION_ONLY, "no enrolled endpoint agent for the host; nothing was collected", None, \
                "an enrolled endpoint agent with the 'ir' capability"
        if not queued:
            errors = "; ".join(str(s.get("error")) for s in subs if s.get("error"))
            return FAILED, f"every forensics command was rejected: {errors}", errors or "rejected", None
        return EXECUTED, f"{len(queued)} of {len(subs)} forensics commands queued", None, None
    # process_kill
    if raw.get("success"):
        status = QUEUED_FOR_APPROVAL if raw.get("command_status") == "awaiting_approval" else EXECUTED
        return status, f"kill_process command {raw.get('command_id')} {raw.get('command_status')}", None, None
    err = str(raw.get("error") or "failed")
    if "no agent enrolled" in err:
        return DETECTION_ONLY, "no enrolled endpoint agent for the host; nothing was killed", None, \
            "an enrolled endpoint agent with the 'ir' capability"
    return FAILED, f"kill_process was not dispatched: {err}", err, None


async def _run_executor(
    db: AsyncSession,
    org_id: str,
    spec: ActionSpec,
    requested: Optional[str],
    target: str,
    parameters: dict[str, Any],
    trigger_data: dict[str, Any],
    *,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    started_at: str,
) -> dict[str, Any]:
    from src.remediation.engine import (
        ForensicsCollectionExecutor,
        NotificationExecutor,
        ProcessActionExecutor,
    )

    executor_cls = {
        "process_kill": ProcessActionExecutor,
        "collect_forensics": ForensicsCollectionExecutor,
        "notification": NotificationExecutor,
    }[spec.key]
    params = dict(parameters)
    for p in spec.parameters:
        value = _param(p.name, parameters, trigger_data)
        if value not in (None, ""):
            params[p.name] = value
    context = {
        "execution_id": execution_ref or "unknown",
        "organization_id": org_id,
        "initiated_by": await actor_user_id(db, org_id, actor),
        "trigger_data": trigger_data,
    }
    raw = await executor_cls(db).execute(target=target, parameters=params, context=context)
    status, detail, error, missing = _normalize_executor_result(spec, raw)
    audit_id = await _audit(
        db, org_id, actor=actor, action=f"remediation_{spec.key}", resource_id=raw.get("command_id"),
        description=f"{spec.key} {target}: {status} ({actor}). {detail}",
        payload={"step": spec.key, "target": target, "status": status, "reason": reason,
                 "execution_ref": execution_ref, "result": raw},
        success=status in ACTUATED_STATUSES, error=error,
    )
    return _step(
        spec.key, requested, target, path=spec.path, status=status, started_at=started_at, detail=detail,
        error=error, missing_dependency=missing, details=raw, audit_log_id=audit_id,
    )


async def run_action(
    db: AsyncSession,
    org_id: str,
    key: Optional[str],
    target: str,
    parameters: Optional[dict[str, Any]] = None,
    *,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    approval_override: bool = False,
    trigger_data: Optional[dict[str, Any]] = None,
    unattended: bool = False,
) -> dict[str, Any]:
    """Execute one remediation step and return its record (never raises for a step failure).

    ``unattended`` must be True for runs no human clicked (policy-triggered,
    scheduled, approval-timeout auto-approval).
    """
    started_at = _now_iso()
    spec = resolve_action(key)
    parameters = parameters if isinstance(parameters, dict) else {}
    trigger_data = trigger_data if isinstance(trigger_data, dict) else {}
    target = str(target or "").strip()
    if spec is None:
        return _step(
            str(key or "unknown"), None, target, path="none", status=FAILED, started_at=started_at,
            detail=f"unknown remediation action {key!r}; nothing was executed", error="unknown_action",
        )
    if not target or target in ("unknown", "unspecified"):
        return _step(
            spec.key, key, target, path=spec.path, status=FAILED, started_at=started_at,
            detail=f"{spec.key} needs a {spec.target_type} target; nothing was executed", error="missing_target",
        )
    try:
        if spec.path == PATH_CONTAINMENT:
            return await _run_containment(
                db, org_id, spec, key, target, parameters, trigger_data, actor=actor, reason=reason,
                execution_ref=execution_ref, approval_override=approval_override, unattended=unattended,
                started_at=started_at,
            )
        return await _run_executor(
            db, org_id, spec, key, target, parameters, trigger_data, actor=actor, reason=reason,
            execution_ref=execution_ref, started_at=started_at,
        )
    except ValueError as exc:
        return _step(
            spec.key, key, target, path=spec.path, status=FAILED, started_at=started_at,
            detail=f"{spec.key} was not executed: {exc}", error=str(exc),
        )


def summarize_steps(steps: list[dict[str, Any]]) -> tuple[str, str, Optional[str]]:
    """(execution status, overall_result, error_message) for a finished run.

    A failed step fails the run. A run whose steps could not act (detection_only
    / awaiting_integration) is never reported as a success.
    """
    if not steps:
        return FAILED, "failure", "no actions were executed"
    ok = [s for s in steps if s.get("success")]
    failed = [
        s for s in steps
        if not s.get("success") and s.get("status") not in NOT_ACTUATED_STATUSES
    ]
    idle = [s for s in steps if not s.get("success") and s.get("status") in NOT_ACTUATED_STATUSES]
    if failed:
        message = "; ".join(
            f"{s.get('action_type', '?')}: {s.get('error') or s.get('detail') or 'failed'}" for s in failed
        )[:2000]
        return FAILED, ("partial_success" if ok else "failure"), message
    if idle and not ok:
        idle_statuses = {s.get("status") for s in idle}
        for idle_status in (MANUAL_REQUIRED, AWAITING_INTEGRATION, DETECTION_ONLY):
            if idle_status in idle_statuses:
                return idle_status, "pending", None
    if idle:
        return "completed", "partial_success", None
    if any(s.get("status") == QUEUED_FOR_APPROVAL for s in ok):
        return "awaiting_approval", "pending", None
    return "completed", "success", None


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def is_containment_step(step: Any) -> bool:
    return isinstance(step, dict) and step.get("path") == PATH_CONTAINMENT


def step_is_reversible(step: Any) -> bool:
    """True when the step actuated and recorded a revert handle."""
    return (
        isinstance(step, dict)
        and bool(step.get("success"))
        and bool(step.get("reversible"))
        and isinstance(step.get("revert"), dict)
    )


async def _revert_agent_commands(
    db: AsyncSession, org_id: str, revert: dict[str, Any], *, issued_by: Optional[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    from src.agents.models import EndpointAgent
    from src.agents.service import AgentService, AgentServiceError

    svc = AgentService(db)
    issued: list[dict[str, Any]] = []
    problems: list[str] = []
    reverse_action = str(revert.get("reverse_action") or "")
    payload = revert.get("payload") if isinstance(revert.get("payload"), dict) else {}
    for entry in revert.get("commands") or []:
        agent_id = entry.get("agent_id") if isinstance(entry, dict) else None
        agent = (await db.execute(
            select(EndpointAgent).where(EndpointAgent.id == str(agent_id), EndpointAgent.organization_id == org_id),
        )).scalar_one_or_none() if agent_id else None
        if agent is None:
            problems.append(f"endpoint agent {agent_id} not found; cannot queue {reverse_action}")
            continue
        try:
            # The admin's rollback request is the authorisation, as in the
            # engine's legacy unblock path.
            cmd = await svc.issue_command(
                agent=agent, action=reverse_action, payload=payload, issued_by=issued_by, approval_override=True,
            )
        except AgentServiceError as exc:
            problems.append(f"agent {agent.id}: {exc}")
            continue
        issued.append({
            "agent_id": agent.id, "hostname": agent.hostname, "command_id": cmd.id,
            "command_status": cmd.status, "reverses_command_id": entry.get("command_id"), "action": reverse_action,
        })
    return issued, problems


async def _revert_crowdstrike(
    revert: dict[str, Any], execution_ref: Optional[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    from src.integrations.engine import ActionExecutor

    executor = ActionExecutor()
    hostname = str(revert.get("hostname") or "")
    installation_id = str(revert.get("installation_id") or "")
    # One implementation of the Falcon lookup: it validates and escapes the
    # hostname and verifies the device. invalid_hostname / host_not_found /
    # ambiguous_host leave the action failed and not reverted.
    _, device_id, err = await containment.crowdstrike_device_for_host(
        executor, installation_id, hostname, execution_ref,
    )
    if err or not device_id:
        return [], [err or f"no CrowdStrike device for {hostname}"]
    hosts = [device_id]
    lift = await executor.execute_action(
        installation_id=installation_id, action_name="lift_containment", input_data={"device_id": str(hosts[0])},
        triggered_by="playbook", playbook_run_id=execution_ref,
    )
    output = lift.get("output_data") or {}
    if lift.get("status") != "success" or (isinstance(output, dict) and (output.get("error") or output.get("success") is False)):
        return [], [lift.get("error_message") or str(output.get("error") or "lift_containment failed")]
    return [{"integration": "crowdstrike", "device_id": str(hosts[0]), "integration_execution_id": lift.get("execution_id")}], []


async def revert_step(
    db: AsyncSession, org_id: str, step: dict[str, Any], *, actor: str, execution_ref: Optional[str],
) -> dict[str, Any]:
    """Reverse one recorded step through its revert handle (agent queue or integration)."""
    action_type = step.get("action_type")
    if not step_is_reversible(step):
        reason = (
            "forward action did not actuate; nothing to reverse" if not step.get("success")
            else "not reversible: the step recorded no revert handle"
        )
        return {"action": action_type, "rolled_back": False, "reversible": False, "reason": reason}
    revert = step["revert"]
    kind = revert.get("kind")
    if kind == "agent_commands":
        issued, problems = await _revert_agent_commands(
            db, org_id, revert, issued_by=await actor_user_id(db, org_id, actor),
        )
    elif kind == "crowdstrike_lift_containment":
        issued, problems = await _revert_crowdstrike(revert, execution_ref)
    else:
        issued, problems = [], [f"unknown revert handle kind {kind!r}"]

    ioc_id = (step.get("details") or {}).get("ioc_id") or step.get("ioc_id")
    if issued and ioc_id:
        from src.intel.models import ThreatIndicator

        ioc = (await db.execute(
            select(ThreatIndicator).where(ThreatIndicator.id == ioc_id, ThreatIndicator.organization_id == org_id),
        )).scalar_one_or_none()
        if ioc is not None and ioc.is_active:
            ioc.is_active = False

    rolled_back = bool(issued) and not problems
    audit_id = await _audit(
        db, org_id, actor=actor, action=f"containment_rollback_{action_type}", resource_id=execution_ref,
        description=(
            f"rollback {action_type} {step.get('target')}: "
            f"{'reversed' if rolled_back else 'not fully reversed'} ({actor})"
        ),
        payload={"revert": revert, "issued": issued, "problems": problems, "execution_ref": execution_ref},
        success=rolled_back, error="; ".join(problems) or None,
    )
    outcome: dict[str, Any] = {
        "action": action_type, "rolled_back": rolled_back, "reversible": True,
        "reverse_commands": issued, "audit_log_id": audit_id,
    }
    if problems:
        outcome["reason"] = "; ".join(problems)[:2000]
    return outcome
