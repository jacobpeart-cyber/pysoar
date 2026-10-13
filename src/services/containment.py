"""Containment actuation shared by playbooks, the visual builder and the agentic registry.

One code path turns a containment request into a real actuation, or says
honestly that none was possible:

* ``block_ip``: a host-firewall ``block_ip`` command on every enrolled,
  IR-capable endpoint agent of the organisation (``AgentService.issue_command``).
* ``isolate_host``: an ``isolate_host`` command on the host's enrolled agent,
  else ``contain_host`` through an installed CrowdStrike Falcon integration
  (``ActionExecutor`` in ``src/integrations/engine.py``).
* ``disable_user``: a ``disable_account`` command on the named host's agent
  (local account). No identity-provider connector can disable a directory
  account today, so without a host the request is not actuated.
* ``quarantine_file``: a ``quarantine_file`` command on the host's agent.

Result status (``ContainmentResult.status``):

``executed``
    A real command was queued for delivery to an agent, or an integration
    call returned success. Never set otherwise.
``queued_for_approval``
    A real agent command was created but the action is high-blast and waits
    in the agent approval queue (``/agents/commands/{id}/approve``).
``detection_only``
    Nothing actuated: no enrolled agent / capable integration covers the
    target, or the attempt failed (``error`` set and ``failed`` True). The
    request is recorded in the audit log only.
``awaiting_integration``
    The organisation installed an integration of the right category (e.g. a
    firewall or identity provider) but PySOAR has no executable connector
    action for it yet. ``missing_dependency`` names what is missing.
``manual_required``
    Only with ``unattended=True`` (automation rules, scheduled or auto-triggered
    runs: no human in the loop). The only actuation path executes immediately
    (an integration such as CrowdStrike ``contain_host``), so it is NOT called;
    ``detail`` names the integration and the action an operator must trigger.

Unattended callers (``unattended=True``) never actuate without a human: the
agent path always yields an ``awaiting_approval`` command (approval override
is ignored and an action that would not need approval is refused), and the
integration path returns ``manual_required`` without calling the engine.

Every call writes exactly one ``AuditLog`` row (actor, target, result).
All lookups are scoped to ``org_id``; another tenant's agent or integration is
never selected.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.agents.capabilities import capability_allows
from src.agents.models import EndpointAgent
from src.core.logging import get_logger
from src.integrations.models import InstalledIntegration, IntegrationStatus
from src.models.asset import Asset
from src.models.audit import AuditLog
from src.models.user import User

logger = get_logger(__name__)

EXECUTED = "executed"
QUEUED_FOR_APPROVAL = "queued_for_approval"
DETECTION_ONLY = "detection_only"
AWAITING_INTEGRATION = "awaiting_integration"
MANUAL_REQUIRED = "manual_required"

STATUSES: frozenset[str] = frozenset({
    EXECUTED, QUEUED_FOR_APPROVAL, DETECTION_ONLY, AWAITING_INTEGRATION, MANUAL_REQUIRED,
})

#: Endpoint agents in these states may receive a command (same rule as the
#: remediation engine and the agentic registry).
DISPATCHABLE_AGENT_STATES: tuple[str, ...] = ("active", "offline")

#: Agent actions that have a real reverse command.
_REVERSIBLE_AGENT_ACTIONS = {"block_ip": "unblock_ip", "isolate_host": "release_host", "quarantine_file": "unquarantine_file"}

#: Integration categories that could actuate each action once a connector
#: implementation exists (used to report ``awaiting_integration``).
_CATEGORY_FOR_ACTION = {
    "block_ip": ("firewall", "waf"),
    "isolate_host": ("edr",),
    "quarantine_file": ("edr",),
    "disable_user": ("identity_provider",),
}

_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*",
)


class InvalidTargetError(ValueError):
    """A containment target failed validation; ``code`` is the machine-readable reason."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _validate_hostname(value: Any) -> str:
    """Stripped, lower-cased RFC 1123 hostname (or asset id), else ``InvalidTargetError('invalid_hostname')``.

    Hostnames reach this service from alert fields and automation rules, so
    anything that is not a plain hostname (quotes, commas, spaces, wildcards)
    is refused before any lookup. An IP literal is accepted unless it is
    loopback, unspecified or multicast.
    """
    host = str(value or "").strip().lower()
    if not _HOSTNAME_RE.fullmatch(host):
        raise InvalidTargetError("invalid_hostname", f"{str(value)[:80]!r} is not a valid hostname")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise InvalidTargetError("invalid_hostname", f"{host} is a loopback, unspecified or multicast address")
    return host


def _validate_ip(value: Any) -> str:
    """Canonical IP for block_ip, else ``InvalidTargetError('invalid_ip')``.

    Private (RFC 1918) addresses are allowed: blocking an internal peer is a
    legitimate lateral-movement response. Loopback, unspecified and multicast
    addresses are refused (blocking them breaks the host or means nothing).
    """
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        raise InvalidTargetError("invalid_ip", f"{str(value)[:80]!r} is not an IP address") from None
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise InvalidTargetError("invalid_ip", f"{addr} is a loopback, unspecified or multicast address")
    return str(addr)


def fql_quote(value: str) -> str:
    """Escape backslashes and single quotes for a CrowdStrike FQL string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


#: Connectors with a real, executable implementation for an action.
_EXECUTABLE_CONNECTORS = {"isolate_host": ("crowdstrike",)}


class UnattendedRefusedError(Exception):
    """An unattended caller asked for an agent action that would not wait for approval."""


@dataclass
class ContainmentResult:
    """Outcome of one containment request (see the module docstring for ``status``)."""

    action: str
    target: str
    status: str
    detail: str
    reversible: bool = False
    command_id: Optional[str] = None
    command_status: Optional[str] = None
    agent_id: Optional[str] = None
    agent_hostname: Optional[str] = None
    integration: Optional[str] = None
    integration_execution_id: Optional[str] = None
    commands: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    asset_id: Optional[str] = None
    missing_dependency: Optional[str] = None
    error: Optional[str] = None
    failed: bool = False
    audit_log_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"invalid containment status: {self.status}")

    @property
    def actuated(self) -> bool:
        """True when a real command or integration call was issued."""
        return self.status in (EXECUTED, QUEUED_FOR_APPROVAL)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Resolution helpers (shared with src/services/agent_tools.py)
# ---------------------------------------------------------------------------


async def dispatchable_agents(db: AsyncSession, org_id: str) -> list[EndpointAgent]:
    """Enrolled endpoint agents of ``org_id`` that may receive a command."""
    q = select(EndpointAgent).where(
        EndpointAgent.organization_id == org_id,
        EndpointAgent.status.in_(DISPATCHABLE_AGENT_STATES),
    )
    return list((await db.execute(q)).scalars().all())


async def find_asset(db: AsyncSession, org_id: str, ref: str) -> Optional[Asset]:
    """The org's asset whose id, name or hostname equals ``ref``."""
    q = select(Asset).where(
        Asset.organization_id == org_id,
        or_(Asset.id == ref, Asset.name == ref, func.lower(Asset.hostname) == ref.lower()),
    )
    return (await db.execute(q)).scalars().first()


async def agent_for_host(
    db: AsyncSession, org_id: str, asset: Optional[Asset], hostname: str,
) -> Optional[EndpointAgent]:
    """The org's enrolled endpoint agent for ``asset`` (or the raw hostname), if any."""
    names = {
        n.lower()
        for n in (hostname, getattr(asset, "hostname", None), getattr(asset, "name", None), getattr(asset, "fqdn", None))
        if n
    }
    if not names:
        return None
    q = (
        select(EndpointAgent)
        .where(
            EndpointAgent.organization_id == org_id,
            EndpointAgent.status.in_(DISPATCHABLE_AGENT_STATES),
            func.lower(EndpointAgent.hostname).in_(sorted(names)),
        )
        .order_by(EndpointAgent.last_heartbeat_at.desc().nullslast())
    )
    return (await db.execute(q)).scalars().first()


async def _active_integrations(db: AsyncSession, org_id: str) -> list[InstalledIntegration]:
    q = (
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(
            InstalledIntegration.organization_id == org_id,
            InstalledIntegration.status == IntegrationStatus.ACTIVE.value,
        )
    )
    return list((await db.execute(q)).scalars().all())


def _connector_name(integration: InstalledIntegration) -> str:
    connector = integration.connector
    return (connector.name if connector is not None else "").lower()


def _connector_category(integration: InstalledIntegration) -> str:
    connector = integration.connector
    return str(getattr(connector, "category", "") or "").lower()


async def _integration_paths(
    db: AsyncSession, org_id: str, action: str,
) -> tuple[Optional[InstalledIntegration], list[str]]:
    """(an executable integration for ``action``, names of installed but non-executable ones)."""
    executable = _EXECUTABLE_CONNECTORS.get(action, ())
    categories = _CATEGORY_FOR_ACTION.get(action, ())
    chosen: Optional[InstalledIntegration] = None
    unsupported: list[str] = []
    for integ in await _active_integrations(db, org_id):
        name = _connector_name(integ)
        if name in executable and chosen is None:
            chosen = integ
        elif _connector_category(integ) in categories:
            unsupported.append(name or integ.display_name)
    return chosen, unsupported


async def _audit_user_id(db: AsyncSession, org_id: str, actor: str) -> Optional[str]:
    """``actor`` when it is a user of ``org_id`` (FK-safe), else ``None``."""
    if not actor or actor.startswith("system:"):
        return None
    found = await db.execute(select(User.id).where(User.id == actor, User.organization_id == org_id))
    return found.scalar_one_or_none()


async def _audit(
    db: AsyncSession, org_id: str, *, actor: str, reason: str, execution_ref: Optional[str], result: ContainmentResult,
) -> ContainmentResult:
    user_id = await _audit_user_id(db, org_id, actor)
    payload = result.to_dict()
    payload.update({"actor": actor, "reason": reason, "execution_ref": execution_ref})
    row = AuditLog(
        user_id=user_id,
        organization_id=org_id,
        action=f"containment_{result.action}",
        resource_type="containment",
        resource_id=(result.command_id or result.asset_id or None),
        description=f"{result.action} {result.target}: {result.status} ({actor}). {result.detail}"[:4000],
        new_value=json.dumps(payload, default=str),
        success=result.actuated and not result.failed,
        error_message=result.error,
    )
    db.add(row)
    await db.flush()
    result.audit_log_id = row.id
    logger.info(
        "containment_action",
        action=result.action, target=result.target, status=result.status,
        organization_id=org_id, actor=actor, execution_ref=execution_ref,
    )
    return result


async def _issue(
    db: AsyncSession,
    agent: EndpointAgent,
    action: str,
    payload: dict[str, Any],
    *,
    issued_by: Optional[str],
    approval_override: bool,
    unattended: bool = False,
) -> Any:
    from src.agents.capabilities import requires_approval
    from src.agents.service import AgentService

    if unattended:
        if not requires_approval(action):
            raise UnattendedRefusedError(f"{action} would run without approval; unattended callers may only queue for approval")
        approval_override = False
    cmd = await AgentService(db).issue_command(
        agent=agent, action=action, payload=payload, issued_by=issued_by, approval_override=approval_override,
    )
    if unattended and cmd.status != "awaiting_approval":
        raise RuntimeError(f"unattended {action} command {cmd.id} was not queued for approval (status {cmd.status})")
    return cmd


def _status_for_command(command_status: str) -> str:
    return QUEUED_FOR_APPROVAL if command_status == "awaiting_approval" else EXECUTED


async def _resolve_issued_by(db: AsyncSession, org_id: str, actor: str, issued_by: Optional[str]) -> Optional[str]:
    if issued_by is not None:
        return issued_by
    return await _audit_user_id(db, org_id, actor)


async def _single_host_agent_action(
    db: AsyncSession,
    org_id: str,
    *,
    action: str,
    agent_action: str,
    hostname: str,
    asset: Optional[Asset],
    payload: dict[str, Any],
    actor: str,
    issued_by: Optional[str],
    approval_override: bool,
    unattended: bool = False,
) -> tuple[Optional[ContainmentResult], Optional[Asset], Optional[EndpointAgent], Optional[str]]:
    """Try the host's agent. Returns (result if actuated, asset, agent, rejection error)."""
    from src.agents.service import AgentServiceError

    label = (asset.hostname or asset.name) if asset else hostname
    agent = await agent_for_host(db, org_id, asset, hostname)
    if agent is None:
        return None, asset, None, None
    if not capability_allows(list(agent.capabilities or []), agent_action):
        return None, asset, agent, (
            f"Action '{agent_action}' is not permitted for agent capabilities {agent.capabilities}. "
            "Re-enroll with the required capability."
        )
    try:
        cmd = await _issue(
            db, agent, agent_action, payload,
            issued_by=await _resolve_issued_by(db, org_id, actor, issued_by),
            approval_override=approval_override, unattended=unattended,
        )
    except UnattendedRefusedError as exc:
        return ContainmentResult(
            action=action, target=label, status=MANUAL_REQUIRED,
            detail=f"Unattended request: an operator must run {agent_action} on {agent.hostname} ({exc})",
            agent_id=agent.id, agent_hostname=agent.hostname, asset_id=asset.id if asset else None,
        ), asset, agent, None
    except AgentServiceError as exc:
        return None, asset, agent, str(exc)
    status = _status_for_command(cmd.status)
    verb = "awaits approval" if status == QUEUED_FOR_APPROVAL else "queued"
    return ContainmentResult(
        action=action, target=label, status=status,
        detail=f"{agent_action} command {cmd.id} {verb} on endpoint agent {agent.hostname}",
        reversible=agent_action in _REVERSIBLE_AGENT_ACTIONS,
        command_id=cmd.id, command_status=cmd.status, agent_id=agent.id, agent_hostname=agent.hostname,
        asset_id=asset.id if asset else None,
    ), asset, agent, None


def _no_path_result(
    action: str, target: str, *, asset: Optional[Asset], agent: Optional[EndpointAgent],
    rejection: Optional[str], unsupported: list[str], needs: str,
) -> ContainmentResult:
    if unsupported:
        names = ", ".join(sorted(set(unsupported)))
        return ContainmentResult(
            action=action, target=target, status=AWAITING_INTEGRATION,
            detail=f"Installed integration(s) {names} have no executable {action} action in PySOAR; nothing was changed.",
            asset_id=asset.id if asset else None, agent_id=agent.id if agent else None,
            agent_hostname=agent.hostname if agent else None,
            missing_dependency=f"{action} connector implementation for {names}", error=rejection,
        )
    if agent is not None:
        detail = f"Endpoint agent {agent.hostname} cannot run {action}: {rejection}. Request recorded only."
    else:
        detail = f"No enrolled endpoint agent or capable integration for {target}: request recorded only."
    return ContainmentResult(
        action=action, target=target, status=DETECTION_ONLY, detail=detail,
        asset_id=asset.id if asset else None, agent_id=agent.id if agent else None,
        agent_hostname=agent.hostname if agent else None, missing_dependency=needs, error=rejection,
    )


# ---------------------------------------------------------------------------
# Integration actuation
# ---------------------------------------------------------------------------


def _integration_error(output: Any) -> Optional[str]:
    if not isinstance(output, dict):
        return "integration returned no structured output"
    if output.get("error"):
        return str(output["error"])
    if output.get("success") is False:
        return f"integration reported failure: {output.get('errors') or 'no detail'}"
    return None


async def crowdstrike_device_for_host(
    executor: Any, installation_id: str, hostname: str, execution_ref: Optional[str],
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """The single Falcon device whose hostname equals ``hostname`` exactly.

    Returns (last integration execution id, device id, error). ``error`` is
    ``invalid_hostname``, ``host_not_found`` or ``ambiguous_host`` (prefix) when
    the target is not exactly one verified device. Shared with remediation's
    revert path so lookup and verification are one implementation.
    """
    try:
        host = _validate_hostname(hostname)
    except InvalidTargetError as exc:
        return None, None, str(exc)
    lookup = await executor.execute_action(
        installation_id=installation_id, action_name="search_hosts",
        input_data={"filter_query": f"hostname:'{fql_quote(host)}'", "limit": 2},
        triggered_by="playbook", playbook_run_id=execution_ref,
    )
    exec_id = lookup.get("execution_id")
    if lookup.get("status") != "success":
        return exec_id, None, lookup.get("error_message") or "search_hosts failed"
    output = lookup.get("output_data") or {}
    err = _integration_error(output)
    if err:
        return exec_id, None, err
    hosts = output.get("hosts") or []
    if not hosts:
        return exec_id, None, f"host_not_found: CrowdStrike has no device named {host}"
    if len(hosts) > 1:
        return exec_id, None, f"ambiguous_host: CrowdStrike matched {len(hosts)} devices for {host}"
    device_id = str(hosts[0])
    detail = await executor.execute_action(
        installation_id=installation_id, action_name="get_device", input_data={"device_id": device_id},
        triggered_by="playbook", playbook_run_id=execution_ref,
    )
    exec_id = detail.get("execution_id") or exec_id
    if detail.get("status") != "success":
        return exec_id, None, detail.get("error_message") or "get_device failed"
    device = detail.get("output_data") or {}
    err = _integration_error(device)
    if err:
        return exec_id, None, err
    if str(device.get("hostname") or "").strip().lower() != host:
        return exec_id, None, (
            f"host_not_found: device {device_id} is named {device.get('hostname')!r}, not {host}"
        )
    return exec_id, device_id, None


async def _crowdstrike_contain(
    integ: InstalledIntegration, hostname: str, execution_ref: Optional[str],
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Resolve the verified Falcon device for ``hostname`` and contain it.

    Returns (integration execution id, device id, error).
    """
    from src.integrations.engine import ActionExecutor

    executor = ActionExecutor()
    exec_id, device_id, err = await crowdstrike_device_for_host(executor, integ.id, hostname, execution_ref)
    if err or device_id is None:
        return exec_id, None, err or "host_not_found"
    contain = await executor.execute_action(
        installation_id=integ.id, action_name="contain_host", input_data={"device_id": device_id},
        triggered_by="playbook", playbook_run_id=execution_ref,
    )
    if contain.get("status") != "success":
        return contain.get("execution_id"), device_id, contain.get("error_message") or "contain_host failed"
    err = _integration_error(contain.get("output_data"))
    return contain.get("execution_id"), device_id, err


def _invalid_target_result(action: str, target: Any, exc: InvalidTargetError) -> ContainmentResult:
    return ContainmentResult(
        action=action, target=str(target or "")[:255], status=DETECTION_ONLY,
        detail=f"Refused before any lookup: {exc}", error=exc.code, failed=True,
    )


# ---------------------------------------------------------------------------
# Public actions
# ---------------------------------------------------------------------------


async def block_ip(
    db: AsyncSession,
    org_id: str,
    *,
    ip: str,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    issued_by: Optional[str] = None,
    approval_override: bool = False,
    unattended: bool = False,
) -> ContainmentResult:
    """Host-firewall block on every enrolled IR-capable agent of the org."""
    from src.agents.service import AgentServiceError

    if not ip:
        raise ValueError("block_ip requires an ip")
    try:
        ip = _validate_ip(ip)
    except InvalidTargetError as exc:
        result = _invalid_target_result("block_ip", ip, exc)
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
    commands: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    issuer = await _resolve_issued_by(db, org_id, actor, issued_by)
    for agent in await dispatchable_agents(db, org_id):
        if not capability_allows(list(agent.capabilities or []), "block_ip"):
            continue  # not IR-enrolled: ineligible, not a failure
        try:
            cmd = await _issue(
                db, agent, "block_ip", {"ip": ip, "reason": reason},
                issued_by=issuer, approval_override=approval_override, unattended=unattended,
            )
            commands.append({"agent_id": agent.id, "hostname": agent.hostname, "command_id": cmd.id, "command_status": cmd.status})
        except (AgentServiceError, UnattendedRefusedError) as exc:
            rejected.append({"agent_id": agent.id, "hostname": agent.hostname, "error": str(exc)})

    if commands:
        all_pending = all(c["command_status"] == "awaiting_approval" for c in commands)
        status = QUEUED_FOR_APPROVAL if all_pending else EXECUTED
        result = ContainmentResult(
            action="block_ip", target=ip, status=status,
            detail=f"block_ip queued to {len(commands)} endpoint agent(s); per-host firewall rules tagged pysoar-block-{ip}",
            reversible=True, command_id=commands[0]["command_id"], command_status=commands[0]["command_status"],
            commands=commands, rejected=rejected,
        )
    else:
        _, unsupported = await _integration_paths(db, org_id, "block_ip")
        result = _no_path_result(
            "block_ip", ip, asset=None, agent=None, rejection=None, unsupported=unsupported,
            needs="an enrolled endpoint agent with the 'ir' capability, or a firewall integration with a block action",
        )
        result.rejected = rejected
    return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)


async def isolate_host(
    db: AsyncSession,
    org_id: str,
    *,
    hostname: str,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    issued_by: Optional[str] = None,
    approval_override: bool = False,
    unattended: bool = False,
) -> ContainmentResult:
    """Network isolation via the host's agent, else an installed CrowdStrike integration."""
    if not hostname:
        raise ValueError("isolate_host requires a hostname")
    try:
        _validate_hostname(hostname)
    except InvalidTargetError as exc:
        result = _invalid_target_result("isolate_host", hostname, exc)
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
    hostname = str(hostname).strip()
    asset = await find_asset(db, org_id, hostname)
    label = (asset.hostname or asset.name) if asset else hostname
    done, asset, agent, rejection = await _single_host_agent_action(
        db, org_id, action="isolate_host", agent_action="isolate_host", hostname=hostname, asset=asset,
        payload={"hostname": label, "reason": reason}, actor=actor, issued_by=issued_by,
        approval_override=approval_override, unattended=unattended,
    )
    if done is not None:
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=done)

    integ, unsupported = await _integration_paths(db, org_id, "isolate_host")
    if integ is not None and unattended:
        name = _connector_name(integ)
        result = ContainmentResult(
            action="isolate_host", target=label, status=MANUAL_REQUIRED,
            detail=(
                f"Unattended request not executed: an operator must trigger {name} contain_host for {label} "
                f"(integration '{integ.display_name}') from the alert."
            ),
            integration=name, asset_id=asset.id if asset else None, agent_id=agent.id if agent else None,
            agent_hostname=agent.hostname if agent else None, error=rejection,
        )
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
    if integ is not None:
        exec_id, device_id, err = await _crowdstrike_contain(integ, label, execution_ref)
        if err is None:
            result = ContainmentResult(
                action="isolate_host", target=label, status=EXECUTED,
                detail=f"CrowdStrike Falcon contained device {device_id} ({label})",
                reversible=True, integration=_connector_name(integ), integration_execution_id=exec_id,
                asset_id=asset.id if asset else None, agent_id=agent.id if agent else None,
            )
        else:
            result = ContainmentResult(
                action="isolate_host", target=label, status=DETECTION_ONLY,
                detail=f"CrowdStrike Falcon containment of {label} failed: {err}",
                integration=_connector_name(integ), integration_execution_id=exec_id,
                asset_id=asset.id if asset else None, error=err, failed=True,
            )
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)

    result = _no_path_result(
        "isolate_host", label, asset=asset, agent=agent, rejection=rejection, unsupported=unsupported,
        needs=f"an enrolled endpoint agent with the 'ir' capability on {label}, or a CrowdStrike Falcon integration",
    )
    return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)


async def disable_user(
    db: AsyncSession,
    org_id: str,
    *,
    username: str,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    hostname: Optional[str] = None,
    issued_by: Optional[str] = None,
    approval_override: bool = False,
    unattended: bool = False,
) -> ContainmentResult:
    """Disable a local account through the named host's agent.

    Directory accounts (AD / Entra / Okta) need an identity-provider connector
    that PySOAR does not implement yet: ``awaiting_integration`` when one is
    installed, ``detection_only`` otherwise. PySOAR's own login accounts are
    never touched here.
    """
    if not username:
        raise ValueError("disable_user requires a username")
    if hostname:
        try:
            _validate_hostname(hostname)
        except InvalidTargetError as exc:
            result = _invalid_target_result("disable_user", username, exc)
            return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
        hostname = str(hostname).strip()
    asset = agent = None
    rejection: Optional[str] = None
    if hostname:
        done, asset, agent, rejection = await _single_host_agent_action(
            db, org_id, action="disable_user", agent_action="disable_account", hostname=hostname,
            asset=await find_asset(db, org_id, hostname), payload={"username": username, "reason": reason}, actor=actor, issued_by=issued_by,
            approval_override=approval_override, unattended=unattended,
        )
        if done is not None:
            done.target = username
            done.reversible = False  # the agent has no enable_account command
            return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=done)
    _, unsupported = await _integration_paths(db, org_id, "disable_user")
    needs = (
        f"an enrolled endpoint agent with the 'ir' capability on {hostname}"
        if hostname
        else "a host (for a local account via its endpoint agent) or an identity-provider connector with a disable_user action"
    )
    result = _no_path_result(
        "disable_user", username, asset=asset, agent=agent, rejection=rejection, unsupported=unsupported, needs=needs,
    )
    return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)


async def quarantine_file(
    db: AsyncSession,
    org_id: str,
    *,
    hostname: str,
    file_path: str,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    issued_by: Optional[str] = None,
    approval_override: bool = False,
    unattended: bool = False,
) -> ContainmentResult:
    """Quarantine ``file_path`` on ``hostname`` through the host's agent."""
    if not hostname or not file_path:
        raise ValueError("quarantine_file requires hostname and file_path")
    try:
        _validate_hostname(hostname)
    except InvalidTargetError as exc:
        result = _invalid_target_result("quarantine_file", hostname, exc)
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
    hostname = str(hostname).strip()
    done, asset, agent, rejection = await _single_host_agent_action(
        db, org_id, action="quarantine_file", agent_action="quarantine_file", hostname=hostname,
        asset=await find_asset(db, org_id, hostname), payload={"path": file_path, "reason": reason}, actor=actor, issued_by=issued_by,
        approval_override=approval_override, unattended=unattended,
    )
    if done is not None:
        done.target = f"{done.target}:{file_path}"
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=done)
    label = (asset.hostname or asset.name) if asset else hostname
    _, unsupported = await _integration_paths(db, org_id, "quarantine_file")
    result = _no_path_result(
        "quarantine_file", f"{label}:{file_path}", asset=asset, agent=agent, rejection=rejection,
        unsupported=unsupported, needs=f"an enrolled endpoint agent with the 'ir' capability on {label}",
    )
    return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
