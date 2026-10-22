"""Containment actuation shared by playbooks, the visual builder and the agentic registry.

One code path turns a containment request into a real actuation, or says
honestly that none was possible:

* ``block_ip``: a host-firewall ``block_ip`` command on every enrolled,
  IR-capable endpoint agent of the organisation (``AgentService.issue_command``).
* ``isolate_host``: an ``isolate_host`` command on the host's enrolled agent,
  else an installed EDR integration with an adapter (``ADAPTERS``):
  CrowdStrike Falcon ``contain_host`` or Microsoft Defender for Endpoint
  ``isolate_machine`` (Full), called through ``ActionExecutor`` in
  ``src/integrations/engine.py``.
* ``disable_user``: a ``disable_account`` command on the named host's agent
  (local account), else an installed identity-provider integration with an
  adapter: Okta ``suspend_user`` + ``revoke_sessions`` or Microsoft Entra ID
  ``disable_user`` + ``revoke_sign_in_sessions``. Identity-provider actions
  run only for an administrator (see below).
* ``quarantine_file``: a ``quarantine_file`` command on the host's agent.

Integration adapters
--------------------
``ADAPTERS`` maps each action to the connectors that can carry it out, in a
fixed order (isolate_host: crowdstrike, then microsoft_defender; disable_user:
okta, then azure_ad). Every adapter resolves the target to exactly one vendor
object first (exact hostname / login, verified by a second read) and refuses
``host_not_found`` / ``user_not_found`` / ``ambiguous_host`` before any change.
When an organisation has several capable integrations they are tried in that
order (installations of one connector oldest first); a target the first does
not know (``*_not_found``) moves on to the next, any other refusal or vendor
error stops there. Every vendor call goes through
``ActionExecutor.execute_action`` (``triggered_by="playbook"``, the execution
reference as ``playbook_run_id``), so each one leaves an
``integration_executions`` row; all their ids are in
``integration_execution_ids``.

Result status (``ContainmentResult.status``):

``executed``
    A real command was queued for delivery to an agent, or an integration
    call returned success. Never set otherwise. With ``failed`` True the
    target WAS changed but a follow-up call failed (e.g. an Okta user was
    suspended and session revocation failed); ``detail`` says which part ran.
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
    Also returned for an identity-provider action whose actor is not an
    administrator.

Unattended callers (``unattended=True``) never actuate without a human: the
agent path always yields an ``awaiting_approval`` command (approval override
is ignored and an action that would not need approval is refused), and the
integration path returns ``manual_required`` without calling the engine.

Identity-provider adapters (Okta, Entra ID) additionally require the actor to
be, right now, an active administrator of the organisation over ``itdr``
(built-in admin, platform superuser, or a custom role granting it): an
interactive admin, or the admin who approved a remediation run (the run's
actor is its approver). Anyone else gets ``manual_required`` and no vendor
call is made.

Every call writes exactly one ``AuditLog`` row (actor, target, result).
All lookups are scoped to ``org_id``; another tenant's agent or integration is
never selected.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable, Optional

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


#: Longest login accepted (RFC 3696 erratum: 64 + 1 + 255).
MAX_LOGIN_LENGTH = 320
_LOGIN_LOCAL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+=^_`{|}~.\-]{1,64}")
_LOGIN_DOMAIN_RE = re.compile(r"(?=.{1,255}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")


def _validate_login(value: Any) -> str:
    """Stripped directory login / user principal name (``user@domain``), else ``InvalidTargetError('invalid_login')``.

    Okta logins and Entra ID UPNs are ``local@domain``: exactly one ``@``, a
    local part of RFC 5322 atext characters and dots, a hostname-shaped
    domain, no whitespace, at most ``MAX_LOGIN_LENGTH`` characters. Anything
    else (a bare ``jdoe``, a path, quotes, wildcards) is refused before any
    lookup.
    """
    login = str(value or "").strip()
    local, sep, domain = login.partition("@")
    if (
        not sep
        or len(login) > MAX_LOGIN_LENGTH
        or any(ch.isspace() for ch in login)
        or not _LOGIN_LOCAL_RE.fullmatch(local)
        or local.startswith(".") or local.endswith(".") or ".." in local
        or not _LOGIN_DOMAIN_RE.fullmatch(domain)
    ):
        raise InvalidTargetError("invalid_login", f"{str(value)[:80]!r} is not a directory login (user@domain)")
    return login


def fql_quote(value: str) -> str:
    """Escape backslashes and single quotes for a CrowdStrike FQL string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


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
    #: Installed integration that acted, every engine execution row of this
    #: request (lookups included), the vendor object acted on (Falcon device
    #: id, Defender machine id, Okta / Entra user id) and, for Defender, the
    #: machineAction id ``get_machine_action`` reads.
    integration_id: Optional[str] = None
    integration_execution_ids: list[str] = field(default_factory=list)
    vendor_id: Optional[str] = None
    vendor_action_id: Optional[str] = None
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
        .order_by(InstalledIntegration.created_at, InstalledIntegration.id)
    )
    return list((await db.execute(q)).scalars().all())


def _connector_name(integration: InstalledIntegration) -> str:
    connector = integration.connector
    return (connector.name if connector is not None else "").lower()


def _connector_category(integration: InstalledIntegration) -> str:
    connector = integration.connector
    return str(getattr(connector, "category", "") or "").lower()


async def _integration_candidates(
    db: AsyncSession, org_id: str, action: str,
) -> tuple[list[tuple["IntegrationAdapter", InstalledIntegration]], list[str]]:
    """(executable integrations for ``action`` in adapter order, names of installed but non-executable ones).

    Order: the adapter order of ``ADAPTERS[action]``, then installation age
    (oldest first), then id. Only the organisation's active rows are read.
    """
    adapters = ADAPTERS.get(action, ())
    rank = {adapter.connector: i for i, adapter in enumerate(adapters)}
    categories = _CATEGORY_FOR_ACTION.get(action, ())
    found: list[tuple[int, int, IntegrationAdapter, InstalledIntegration]] = []
    unsupported: list[str] = []
    for position, integ in enumerate(await _active_integrations(db, org_id)):
        name = _connector_name(integ)
        if name in rank:
            found.append((rank[name], position, adapters[rank[name]], integ))
        elif _connector_category(integ) in categories:
            unsupported.append(name or integ.display_name)
    found.sort(key=lambda item: (item[0], item[1]))
    return [(adapter, integ) for _, _, adapter, integ in found], unsupported


async def _integration_paths(
    db: AsyncSession, org_id: str, action: str,
) -> tuple[Optional[InstalledIntegration], list[str]]:
    """(the first executable integration for ``action``, names of installed but non-executable ones)."""
    candidates, unsupported = await _integration_candidates(db, org_id, action)
    return (candidates[0][1] if candidates else None), unsupported


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


#: Width of ``integration_executions.playbook_run_id``.
_RUN_REF_MAX = 36


def engine_run_ref(execution_ref: Optional[str]) -> Optional[str]:
    """``execution_ref`` as it fits ``integration_executions.playbook_run_id`` (VARCHAR(36)).

    ``playbook_execution:<uuid>`` (55 characters) does not fit, and on
    PostgreSQL the engine's history write would fail and leave no execution
    row. A longer reference is stored as its last ``:`` segment (the run's id);
    the audit row keeps the full reference.
    """
    if execution_ref is None or len(execution_ref) <= _RUN_REF_MAX:
        return execution_ref
    tail = execution_ref.rsplit(":", 1)[-1]
    return tail if 0 < len(tail) <= _RUN_REF_MAX else execution_ref[-_RUN_REF_MAX:]


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
        triggered_by="playbook", playbook_run_id=engine_run_ref(execution_ref),
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
        triggered_by="playbook", playbook_run_id=engine_run_ref(execution_ref),
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


@dataclass
class AdapterContext:
    """One adapter run: the engine executor, the installation and the request's references."""

    executor: Any
    installation_id: str
    execution_ref: Optional[str]
    reason: str = ""
    target: str = ""


@dataclass
class AdapterOutcome:
    """Result of an adapter's resolve / apply / revert.

    ``changed`` (apply / revert) is True when the vendor object's state was
    changed even if ``error`` is set (a follow-up call failed). ``state`` is
    what resolve read (Okta status, Entra ``accountEnabled``) for apply.
    """

    execution_ids: list[str] = field(default_factory=list)
    vendor_id: Optional[str] = None
    error: Optional[str] = None
    detail: str = ""
    changed: bool = False
    reversible: bool = False
    vendor_action_id: Optional[str] = None
    state: Any = None


async def _engine_call(
    ctx: AdapterContext, action_name: str, input_data: dict[str, Any], ids: list[str],
) -> tuple[Optional[dict[str, Any]], Optional[str], Optional[int]]:
    """One connector action through ``ActionExecutor.execute_action``: (output, error, http status)."""
    out = await ctx.executor.execute_action(
        installation_id=ctx.installation_id, action_name=action_name, input_data=input_data,
        triggered_by="playbook", playbook_run_id=engine_run_ref(ctx.execution_ref),
    )
    if out.get("execution_id"):
        ids.append(str(out["execution_id"]))
    if out.get("status") != "success":
        return None, f"{action_name}: {out.get('error_message') or 'failed'}", out.get("http_status")
    output = out.get("output_data") or {}
    err = _integration_error(output)
    if err:
        return None, f"{action_name}: {err}", None
    return output, None, None


def _vendor_comment(ctx: AdapterContext, verb: str) -> str:
    """Comment recorded in the vendor's action log: names PySOAR and the execution reference."""
    text = f"PySOAR {verb}, execution {ctx.execution_ref or 'interactive'}"
    if ctx.reason:
        text = f"{text}: {ctx.reason}"
    return text[:500]


# -- CrowdStrike Falcon ------------------------------------------------------


async def _crowdstrike_resolve(ctx: AdapterContext, target: str) -> AdapterOutcome:
    exec_id, device_id, err = await crowdstrike_device_for_host(ctx.executor, ctx.installation_id, target, ctx.execution_ref)
    ids = [exec_id] if exec_id else []
    if err or device_id is None:
        return AdapterOutcome(ids, error=err or "host_not_found")
    return AdapterOutcome(ids, vendor_id=device_id)


async def _crowdstrike_apply(ctx: AdapterContext, found: AdapterOutcome) -> AdapterOutcome:
    ids: list[str] = []
    contain = await ctx.executor.execute_action(
        installation_id=ctx.installation_id, action_name="contain_host", input_data={"device_id": found.vendor_id},
        triggered_by="playbook", playbook_run_id=engine_run_ref(ctx.execution_ref),
    )
    if contain.get("execution_id"):
        ids.append(contain["execution_id"])
    if contain.get("status") != "success":
        return AdapterOutcome(ids, error=contain.get("error_message") or "contain_host failed")
    err = _integration_error(contain.get("output_data"))
    if err:
        return AdapterOutcome(ids, error=err)
    return AdapterOutcome(
        ids, detail=f"CrowdStrike Falcon contained device {found.vendor_id} ({ctx.target})", changed=True, reversible=True,
    )


async def _crowdstrike_revert(ctx: AdapterContext, vendor_id: str) -> AdapterOutcome:
    ids: list[str] = []
    _, err, _ = await _engine_call(ctx, "lift_containment", {"device_id": vendor_id}, ids)
    if err:
        return AdapterOutcome(ids, error=err)
    return AdapterOutcome(ids, detail=f"CrowdStrike Falcon lifted containment of device {vendor_id}", changed=True)


# -- Microsoft Defender for Endpoint ----------------------------------------


async def _defender_resolve(ctx: AdapterContext, target: str) -> AdapterOutcome:
    """The single Defender machine whose ``computerDnsName`` equals ``target`` exactly."""
    ids: list[str] = []
    try:
        host = _validate_hostname(target)
    except InvalidTargetError as exc:
        return AdapterOutcome(ids, error=str(exc))
    found, err, _ = await _engine_call(ctx, "search_machines", {"query": host, "top": 10}, ids)
    if err or found is None:
        return AdapterOutcome(ids, error=err)
    # search_machines filters computerDnsName OR lastIpAddress: keep exact
    # computerDnsName matches only.
    matches = {
        str(m["id"]) for m in found.get("machines") or []
        if isinstance(m, dict) and m.get("id") and str(m.get("computer_dns_name") or "").strip().lower() == host
    }
    if not matches:
        return AdapterOutcome(ids, error=f"host_not_found: Microsoft Defender has no machine whose computerDnsName is {host}")
    if len(matches) > 1:
        return AdapterOutcome(ids, error=f"ambiguous_host: Microsoft Defender matched {len(matches)} machines for {host}")
    machine_id = matches.pop()
    machine, err, _ = await _engine_call(ctx, "get_machine", {"machine_id": machine_id}, ids)
    if err or machine is None:
        return AdapterOutcome(ids, error=err)
    name = str(machine.get("computer_dns_name") or "").strip().lower()
    if name != host or str(machine.get("id") or "") != machine_id:
        return AdapterOutcome(ids, error=(
            f"host_not_found: machine {machine_id} is named {machine.get('computer_dns_name')!r}, not {host}"
        ))
    return AdapterOutcome(ids, vendor_id=machine_id)


async def _defender_apply(ctx: AdapterContext, found: AdapterOutcome) -> AdapterOutcome:
    ids: list[str] = []
    out, err, _ = await _engine_call(ctx, "isolate_machine", {
        "machine_id": found.vendor_id, "comment": _vendor_comment(ctx, "isolate_host"), "isolation_type": "Full",
    }, ids)
    if err or out is None:
        return AdapterOutcome(ids, error=err)
    action_id = out.get("action_id")
    progress = (
        f"machine action {action_id} ({out.get('status') or 'status not reported'}); "
        "get_machine_action reads its progress" if action_id else "Defender returned no machine action id"
    )
    return AdapterOutcome(
        ids, detail=f"Microsoft Defender full isolation requested for machine {found.vendor_id} ({ctx.target}): {progress}",
        changed=True, reversible=True, vendor_action_id=str(action_id) if action_id else None,
    )


async def _defender_revert(ctx: AdapterContext, vendor_id: str) -> AdapterOutcome:
    ids: list[str] = []
    out, err, _ = await _engine_call(ctx, "unisolate_machine", {
        "machine_id": vendor_id, "comment": _vendor_comment(ctx, "rollback of isolate_host"),
    }, ids)
    if err or out is None:
        return AdapterOutcome(ids, error=err)
    return AdapterOutcome(
        ids, detail=f"Microsoft Defender release from isolation requested for machine {vendor_id}: machine action "
                    f"{out.get('action_id')} ({out.get('status') or 'status not reported'})",
        changed=True, vendor_action_id=str(out["action_id"]) if out.get("action_id") else None,
    )


# -- Identity providers --------------------------------------------------------


def _user_lookup_error(provider: str, login: str, err: Optional[str], http_status: Optional[int]) -> str:
    if http_status == 404:
        return f"user_not_found: {provider} has no user {login}"
    return err or "user lookup failed"


async def _okta_resolve(ctx: AdapterContext, target: str) -> AdapterOutcome:
    """The Okta user whose login equals ``target`` (case-insensitive)."""
    ids: list[str] = []
    try:
        login = _validate_login(target)
    except InvalidTargetError as exc:
        return AdapterOutcome(ids, error=str(exc))
    user, err, http_status = await _engine_call(ctx, "get_user", {"user": login}, ids)
    if err or user is None:
        return AdapterOutcome(ids, error=_user_lookup_error("Okta", login, err, http_status))
    if str(user.get("login") or "").strip().lower() != login.lower() or not user.get("id"):
        return AdapterOutcome(ids, error=f"user_not_found: Okta user {user.get('id')} has login {user.get('login')!r}, not {login}")
    return AdapterOutcome(ids, vendor_id=str(user["id"]), state=str(user.get("status") or "").upper())


async def _okta_apply(ctx: AdapterContext, found: AdapterOutcome) -> AdapterOutcome:
    ids: list[str] = []
    already = found.state == "SUSPENDED"
    if not already:
        _, err, _ = await _engine_call(ctx, "suspend_user", {"user_id": found.vendor_id}, ids)
        if err:
            return AdapterOutcome(ids, error=err)
    _, err, _ = await _engine_call(ctx, "revoke_sessions", {"user_id": found.vendor_id}, ids)
    first = (
        f"Okta user {found.vendor_id} ({ctx.target}) was already SUSPENDED (left as is)" if already
        else f"Okta suspended user {found.vendor_id} ({ctx.target})"
    )
    if err:
        return AdapterOutcome(
            ids, error=err, changed=not already, reversible=not already,
            detail=f"{first}; session revocation FAILED ({err}): existing sessions may still be valid",
        )
    return AdapterOutcome(ids, detail=f"{first}; every Okta session revoked", changed=True, reversible=not already)


async def _okta_revert(ctx: AdapterContext, vendor_id: str) -> AdapterOutcome:
    ids: list[str] = []
    _, err, _ = await _engine_call(ctx, "unsuspend_user", {"user_id": vendor_id}, ids)
    if err:
        return AdapterOutcome(ids, error=err)
    return AdapterOutcome(
        ids, changed=True,
        detail=f"Okta unsuspended user {vendor_id}; the sessions revoked at disable time cannot be restored (the user signs in again)",
    )


async def _entra_resolve(ctx: AdapterContext, target: str) -> AdapterOutcome:
    """The Entra ID user whose userPrincipalName equals ``target`` (case-insensitive)."""
    ids: list[str] = []
    try:
        login = _validate_login(target)
    except InvalidTargetError as exc:
        return AdapterOutcome(ids, error=str(exc))
    user, err, http_status = await _engine_call(ctx, "get_user", {"user": login}, ids)
    if err or user is None:
        return AdapterOutcome(ids, error=_user_lookup_error("Microsoft Entra ID", login, err, http_status))
    upn = str(user.get("userPrincipalName") or "").strip()
    if upn.lower() != login.lower() or not user.get("id"):
        return AdapterOutcome(ids, error=f"user_not_found: Entra ID user {user.get('id')} is {upn!r}, not {login}")
    return AdapterOutcome(ids, vendor_id=str(user["id"]), state=user.get("accountEnabled"))


async def _entra_apply(ctx: AdapterContext, found: AdapterOutcome) -> AdapterOutcome:
    ids: list[str] = []
    already = found.state is False
    if not already:
        _, err, _ = await _engine_call(ctx, "disable_user", {"user": found.vendor_id}, ids)
        if err:
            return AdapterOutcome(ids, error=err)
    _, err, _ = await _engine_call(ctx, "revoke_sign_in_sessions", {"user": found.vendor_id}, ids)
    first = (
        f"Entra ID user {found.vendor_id} ({ctx.target}) was already disabled (left as is)" if already
        else f"Entra ID disabled sign-in for user {found.vendor_id} ({ctx.target})"
    )
    if err:
        return AdapterOutcome(
            ids, error=err, changed=not already, reversible=not already,
            detail=f"{first}; sign-in session revocation FAILED ({err}): refresh tokens may still be valid",
        )
    return AdapterOutcome(
        ids, detail=f"{first}; refresh tokens and session cookies revoked", changed=True, reversible=not already,
    )


async def _entra_revert(ctx: AdapterContext, vendor_id: str) -> AdapterOutcome:
    ids: list[str] = []
    _, err, _ = await _engine_call(ctx, "enable_user", {"user": vendor_id}, ids)
    if err:
        return AdapterOutcome(ids, error=err)
    return AdapterOutcome(
        ids, changed=True,
        detail=f"Entra ID enabled sign-in for user {vendor_id}; the sessions revoked at disable time cannot be restored",
    )


@dataclass(frozen=True)
class IntegrationAdapter:
    """How one connector carries out one containment action.

    ``resolve(ctx, target)`` finds exactly one vendor object (no change),
    ``apply(ctx, resolved)`` changes it, ``revert(ctx, vendor_id)`` undoes
    it (remediation rollback). ``operation`` names the vendor actions an
    operator must trigger when the request is not executed.
    """

    action: str
    connector: str
    label: str
    operation: str
    resolve: Callable[[AdapterContext, str], Awaitable[AdapterOutcome]]
    apply: Callable[[AdapterContext, AdapterOutcome], Awaitable[AdapterOutcome]]
    revert: Callable[[AdapterContext, str], Awaitable[AdapterOutcome]]
    identity: bool = False


#: (action) -> adapters in the order they are tried.
ADAPTERS: dict[str, tuple[IntegrationAdapter, ...]] = {
    "isolate_host": (
        IntegrationAdapter(
            "isolate_host", "crowdstrike", "CrowdStrike Falcon", "contain_host",
            _crowdstrike_resolve, _crowdstrike_apply, _crowdstrike_revert,
        ),
        IntegrationAdapter(
            "isolate_host", "microsoft_defender", "Microsoft Defender for Endpoint", "isolate_machine",
            _defender_resolve, _defender_apply, _defender_revert,
        ),
    ),
    "disable_user": (
        IntegrationAdapter(
            "disable_user", "okta", "Okta", "suspend_user + revoke_sessions",
            _okta_resolve, _okta_apply, _okta_revert, identity=True,
        ),
        IntegrationAdapter(
            "disable_user", "azure_ad", "Microsoft Entra ID", "disable_user + revoke_sign_in_sessions",
            _entra_resolve, _entra_apply, _entra_revert, identity=True,
        ),
    ),
}

#: Connectors with a real, executable implementation for an action (derived from ``ADAPTERS``).
_EXECUTABLE_CONNECTORS: dict[str, tuple[str, ...]] = {
    action: tuple(adapter.connector for adapter in adapters) for action, adapters in ADAPTERS.items()
}


def adapter_for(action: str, connector: str) -> Optional[IntegrationAdapter]:
    """The adapter for ``connector`` and ``action``, if one exists (remediation's revert uses it)."""
    for adapter in ADAPTERS.get(action, ()):
        if adapter.connector == connector:
            return adapter
    return None


def _is_not_found(error: Optional[str]) -> bool:
    return bool(error) and str(error).startswith(("host_not_found", "user_not_found"))


async def _actuate_via_integrations(
    action: str,
    target: str,
    candidates: list[tuple[IntegrationAdapter, InstalledIntegration]],
    *,
    execution_ref: Optional[str],
    reason: str,
    asset: Optional[Asset] = None,
) -> ContainmentResult:
    """Run the first adapter that knows ``target`` (see the module docstring for the order)."""
    from src.integrations.engine import ActionExecutor

    executor = ActionExecutor()
    misses: list[str] = []
    all_ids: list[str] = []
    asset_id = asset.id if asset else None
    for index, (adapter, integ) in enumerate(candidates):
        ctx = AdapterContext(executor, integ.id, execution_ref, reason=reason, target=target)
        found = await adapter.resolve(ctx, target)
        all_ids.extend(found.execution_ids)
        common: dict[str, Any] = {
            "action": action, "target": target, "integration": adapter.connector, "integration_id": integ.id,
            "integration_execution_ids": all_ids, "asset_id": asset_id,
        }
        if found.error or not found.vendor_id:
            err = found.error or "target not resolved"
            if _is_not_found(err) and index + 1 < len(candidates):
                misses.append(err)
                continue
            err = "; ".join([*misses, err])
            return ContainmentResult(
                status=DETECTION_ONLY, detail=f"{adapter.label} {action} of {target} refused or failed before any change: {err}",
                integration_execution_id=all_ids[-1] if all_ids else None, error=err, failed=True, **common,
            )
        done = await adapter.apply(ctx, found)
        all_ids.extend(done.execution_ids)
        common.update(vendor_id=found.vendor_id, vendor_action_id=done.vendor_action_id)
        last_id = all_ids[-1] if all_ids else None
        if done.error and not done.changed:
            return ContainmentResult(
                status=DETECTION_ONLY, detail=f"{adapter.label} {action} of {target} failed: {done.error}",
                integration_execution_id=last_id, error=done.error, failed=True, **common,
            )
        return ContainmentResult(
            status=EXECUTED, detail=done.detail, reversible=done.reversible, integration_execution_id=last_id,
            error=done.error, failed=bool(done.error), **common,
        )
    raise ValueError(f"no integration candidates for {action}")  # callers check candidates first


def _manual_required_result(
    action: str, target: str, adapter: IntegrationAdapter, integ: InstalledIntegration, why: str, **extra: Any,
) -> ContainmentResult:
    return ContainmentResult(
        action=action, target=target, status=MANUAL_REQUIRED,
        detail=(
            f"{why}: an operator must trigger {adapter.connector} {adapter.operation} for {target} "
            f"(integration '{integ.display_name}') from the alert."
        ),
        integration=adapter.connector, integration_id=integ.id, **extra,
    )


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
    """Network isolation via the host's agent, else an installed EDR integration (``ADAPTERS['isolate_host']``)."""
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

    candidates, unsupported = await _integration_candidates(db, org_id, "isolate_host")
    if candidates and unattended:
        adapter, integ = candidates[0]
        result = _manual_required_result(
            "isolate_host", label, adapter, integ, "Unattended request not executed",
            asset_id=asset.id if asset else None, agent_id=agent.id if agent else None,
            agent_hostname=agent.hostname if agent else None, error=rejection,
        )
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
    if candidates:
        result = await _actuate_via_integrations(
            "isolate_host", label, candidates, execution_ref=execution_ref, reason=reason, asset=asset,
        )
        if result.status == EXECUTED and agent is not None:
            result.agent_id = agent.id
        return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)

    result = _no_path_result(
        "isolate_host", label, asset=asset, agent=agent, rejection=rejection, unsupported=unsupported,
        needs=(
            f"an enrolled endpoint agent with the 'ir' capability on {label}, or a CrowdStrike Falcon or "
            "Microsoft Defender for Endpoint integration"
        ),
    )
    return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)


async def _identity_disable(
    db: AsyncSession,
    org_id: str,
    login: str,
    candidates: list[tuple[IntegrationAdapter, InstalledIntegration]],
    *,
    actor: str,
    reason: str,
    execution_ref: Optional[str],
    unattended: bool,
    agent: Optional[EndpointAgent],
    rejection: Optional[str],
) -> ContainmentResult:
    """The identity-provider leg of ``disable_user`` (gated: attended, administrator actor)."""
    from src.identity import roles as identity_roles

    adapter, integ = candidates[0]
    extra: dict[str, Any] = {
        "agent_id": agent.id if agent else None, "agent_hostname": agent.hostname if agent else None, "error": rejection,
    }
    if unattended:
        return _manual_required_result("disable_user", login, adapter, integ, "Unattended request not executed", **extra)
    if not await identity_roles.user_has_tier(db, None if actor.startswith("system:") else actor, org_id, "itdr", "admin"):
        return _manual_required_result(
            "disable_user", login, adapter, integ,
            f"Identity-provider actions run only for an administrator; {actor} is not one", **extra,
        )
    return await _actuate_via_integrations(
        "disable_user", login, candidates, execution_ref=execution_ref, reason=reason,
    )


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
    """Disable a local account through the named host's agent, else a directory account.

    Without a host (or when the host has no capable agent) a directory login
    (``user@domain``) is disabled through the first installed identity-provider
    adapter that knows it (``ADAPTERS['disable_user']``: Okta, then Entra ID),
    and only when the request is attended and ``actor`` is an ``itdr``
    administrator; otherwise ``manual_required`` with no vendor call. A
    username that is not a login is refused (``invalid_login``) before any
    lookup when no host was named. Active Directory has no connector, so an
    installed but unimplemented identity integration is
    ``awaiting_integration``. PySOAR's own login accounts are never touched.
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
    candidates, unsupported = await _integration_candidates(db, org_id, "disable_user")
    if candidates:
        try:
            login = _validate_login(username)
        except InvalidTargetError as exc:
            login = None
            if not hostname:
                result = _invalid_target_result("disable_user", username, exc)
                return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
        if login is not None:
            result = await _identity_disable(
                db, org_id, login, candidates, actor=actor, reason=reason, execution_ref=execution_ref,
                unattended=unattended, agent=agent, rejection=rejection,
            )
            return await _audit(db, org_id, actor=actor, reason=reason, execution_ref=execution_ref, result=result)
    needs = (
        f"an enrolled endpoint agent with the 'ir' capability on {hostname}"
        if hostname
        else "a host (for a local account via its endpoint agent) or an Okta / Microsoft Entra ID integration"
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
