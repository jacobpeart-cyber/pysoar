"""OT actions commanded through endpoint agents: safe shutdown and segmentation probes.

PySOAR never talks to a PLC, SIS or firewall itself. Both actions are queued
as commands for an endpoint agent the operator enrolled with the matching
capability (``src.agents.capabilities``):

* ``ot_safe_shutdown`` (action ``ot_safe_shutdown``): an agent on an OT
  gateway / engineering workstation runs the site's own shutdown procedure for
  the incident's assets. High blast radius, so the command waits in the agent
  approval queue (a second administrator approves it).
* ``ot_segmentation_probe`` (action ``ot_segmentation_probe``): an agent
  inside a zone attempts TCP connections to assets of the other zones on their
  protocol port and reports which were reachable. Active probing of OT
  networks, so it also goes through the approval queue.

Status is result-driven: the incident / zone records the command id and its
status follows the command (awaiting_approval, queued, in_progress) until the
agent posts a result. Only an agent-reported success sets
``safe_shutdown_initiated``; only a completed probe with every planned probe
answered and no reachable-but-forbidden target sets ``segmentation_verified``.
Without a capable agent the request is refused (409 ``no_capable_agent``) and
nothing is changed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.ot_security.models import OTAsset, OTIncident, OTZone

logger = get_logger(__name__)

SAFE_SHUTDOWN_CAPABILITY = "ot_safe_shutdown"
SAFE_SHUTDOWN_ACTION = "ot_safe_shutdown"
SEGMENTATION_PROBE_CAPABILITY = "ot_segmentation_probe"
SEGMENTATION_PROBE_ACTION = "ot_segmentation_probe"

#: TCP port probed for each stored asset protocol (assets with another or no
#: protocol are not probed: there is no port to test).
PROTOCOL_PORTS: dict[str, int] = {
    "modbus_tcp": 502,
    "s7comm": 102,
    "dnp3": 20000,
    "ethernetip": 44818,
    "opc_ua": 4840,
    "bacnet": 47808,
    "iec61850": 102,
    "mqtt": 1883,
    "profinet": 34964,
}
MAX_PROBES = 200
MAX_PROBES_PER_ZONE = 50

#: Agent command status -> incident / zone status while no result exists.
_PENDING = {"awaiting_approval": "awaiting_approval", "queued": "queued",
            "dispatched": "in_progress", "running": "in_progress"}
PENDING_STATES = ("awaiting_approval", "queued", "in_progress")


class ActuationRefused(Exception):
    """The action cannot be commanded; ``error`` is the API error key."""

    def __init__(self, error: str, detail: str, status_code: int = 409, **extra: Any):
        super().__init__(detail)
        self.error = error
        self.detail = detail
        self.status_code = status_code
        self.extra = extra

    def as_detail(self) -> dict[str, Any]:
        return {"error": self.error, "detail": self.detail, **self.extra}


async def capable_agents(db: AsyncSession, org_id: str, capability: str) -> list[Any]:
    """Active agents of this tenant enrolled with ``capability``."""
    from src.agents.models import EndpointAgent

    rows = (await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.organization_id == org_id,
            EndpointAgent.status == "active",
        ).order_by(EndpointAgent.hostname).limit(500),
    )).scalars().all()
    return [a for a in rows if capability in (a.capabilities or [])]


def _in_cidr(ip: Optional[str], cidr: Optional[str]) -> bool:
    try:
        return bool(ip) and bool(cidr) and ip_address(ip) in ip_network(cidr, strict=False)
    except ValueError:
        return False


async def select_agent(
    db: AsyncSession, org_id: str, capability: str, agent_id: Optional[str] = None,
    *, inside_cidr: Optional[str] = None,
) -> Any:
    """Pick the agent to command, or raise ActuationRefused."""
    agents = await capable_agents(db, org_id, capability)
    if inside_cidr is not None:
        agents = [a for a in agents if _in_cidr(a.ip_address, inside_cidr)]
    where = f" inside {inside_cidr}" if inside_cidr is not None else ""
    if agent_id:
        for agent in agents:
            if agent.id == agent_id:
                return agent
        raise ActuationRefused(
            "agent_not_capable",
            f"Agent {agent_id} is not an active agent of this organisation enrolled with the "
            f"'{capability}' capability{where}.",
            capability=capability,
        )
    if not agents:
        raise ActuationRefused(
            "no_capable_agent",
            f"No active endpoint agent enrolled with the '{capability}' capability{where}. Enrol one on "
            "an OT gateway or engineering workstation; nothing was sent and nothing was changed.",
            capability=capability,
        )
    if len(agents) > 1:
        raise ActuationRefused(
            "agent_selection_required",
            f"Several agents carry the '{capability}' capability{where}; pass agent_id.",
            capability=capability,
            agent_ids=[a.id for a in agents],
        )
    return agents[0]


async def _audit(db: AsyncSession, *, user: Any, org_id: str, action: str, resource_type: str,
                 resource_id: str, description: str, payload: dict[str, Any], success: bool = True,
                 error: Optional[str] = None) -> None:
    from src.models.audit import AuditLog

    db.add(AuditLog(
        user_id=str(user.id) if user is not None else None,
        organization_id=org_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description[:4000],
        new_value=json.dumps(payload, default=str),
        success=success,
        error_message=error,
    ))
    await db.flush()


async def _issue(db: AsyncSession, agent: Any, action: str, payload: dict[str, Any], user: Any) -> Any:
    from src.agents.service import AgentService, AgentServiceError

    try:
        return await AgentService(db).issue_command(
            agent=agent, action=action, payload=payload, issued_by=str(user.id) if user is not None else None,
        )
    except AgentServiceError as exc:
        raise ActuationRefused("agent_command_refused", str(exc)) from exc


async def _command_state(db: AsyncSession, command_id: Optional[str]) -> tuple[Optional[str], Any]:
    from src.agents.models import AgentCommand, AgentResult

    if not command_id:
        return None, None
    command_status = (await db.execute(
        select(AgentCommand.status).where(AgentCommand.id == command_id),
    )).scalar_one_or_none()
    result = (await db.execute(
        select(AgentResult).where(AgentResult.command_id == command_id)
        .order_by(AgentResult.reported_at.desc()).limit(1),
    )).scalar_one_or_none()
    return command_status, result


def _result_text(result: Any) -> str:
    text = (result.stdout or "").strip() or (result.stderr or "").strip()
    return text[:4000]


# ---------------------------------------------------------------------------
# safe shutdown
# ---------------------------------------------------------------------------


async def request_safe_shutdown(
    db: AsyncSession, incident: OTIncident, *, user: Any, agent_id: Optional[str] = None,
) -> dict[str, Any]:
    """Queue an ``ot_safe_shutdown`` command for the incident's assets."""
    if incident.safe_shutdown_status in PENDING_STATES:
        raise ActuationRefused(
            "already_pending",
            f"A safe shutdown command is already {incident.safe_shutdown_status} for this incident.",
            command_id=incident.safe_shutdown_command_id,
        )
    asset_ids = [str(a) for a in (incident.affected_assets or []) if a]
    assets = list((await db.execute(
        select(OTAsset).where(
            and_(OTAsset.organization_id == incident.organization_id, OTAsset.id.in_(asset_ids)),
        ),
    )).scalars().all()) if asset_ids else []
    if not assets:
        raise ActuationRefused(
            "no_target_assets",
            "The incident lists no affected OT asset of this organisation; a safe shutdown needs the "
            "assets to act on (set affected_assets).",
        )
    agent = await select_agent(db, incident.organization_id, SAFE_SHUTDOWN_CAPABILITY, agent_id)
    payload = {
        "ot_incident_id": incident.id,
        "affected_zones": list(incident.affected_zones or []),
        "assets": [
            {
                "asset_id": a.id, "name": a.name, "ip_address": a.ip_address, "protocol": a.protocol,
                "vendor": a.vendor, "model": a.model, "purdue_level": a.purdue_level,
                "criticality": a.criticality,
            }
            for a in assets
        ],
    }
    command = await _issue(db, agent, SAFE_SHUTDOWN_ACTION, payload, user)
    now = datetime.now(timezone.utc)
    incident.safe_shutdown_command_id = command.id
    incident.safe_shutdown_status = _PENDING.get(command.status, "queued")
    incident.safe_shutdown_requested_at = now
    incident.safe_shutdown_detail = None
    incident.safe_shutdown_initiated = False
    await _audit(
        db, user=user, org_id=incident.organization_id, action="ot_safe_shutdown_requested",
        resource_type="ot_incident", resource_id=incident.id,
        description=f"Safe shutdown of {len(assets)} asset(s) queued for agent {agent.hostname}",
        payload={"command_id": command.id, "agent_id": agent.id, "command_status": command.status,
                 "asset_ids": [a.id for a in assets]},
    )
    logger.warning("ot_safe_shutdown_requested", incident_id=incident.id, command_id=command.id,
                   agent_id=agent.id, organization_id=incident.organization_id)
    return safe_shutdown_view(incident, agent_id=agent.id)


async def reconcile_safe_shutdown(db: AsyncSession, incident: OTIncident) -> bool:
    """Apply the agent's command status / result to the incident. True when changed."""
    if incident.safe_shutdown_status not in PENDING_STATES or not incident.safe_shutdown_command_id:
        return False
    command_status, result = await _command_state(db, incident.safe_shutdown_command_id)
    before = (incident.safe_shutdown_status, incident.safe_shutdown_initiated)
    if result is None:
        if command_status in _PENDING:
            incident.safe_shutdown_status = _PENDING[command_status]
        else:
            incident.safe_shutdown_status = "failed"
            incident.safe_shutdown_detail = f"agent command {command_status or 'missing'}"
    elif result.status == "success" and command_status == "completed":
        incident.safe_shutdown_status = "completed"
        incident.safe_shutdown_initiated = True
        incident.safe_shutdown_detail = _result_text(result) or None
    else:
        incident.safe_shutdown_status = "failed"
        incident.safe_shutdown_detail = _result_text(result) or f"agent reported {result.status}"
    changed = before != (incident.safe_shutdown_status, incident.safe_shutdown_initiated)
    if changed:
        await db.flush()
    return changed


def safe_shutdown_view(incident: OTIncident, **extra: Any) -> dict[str, Any]:
    return {
        "incident_id": incident.id,
        "status": incident.safe_shutdown_status or "not_requested",
        "command_id": incident.safe_shutdown_command_id,
        "requested_at": incident.safe_shutdown_requested_at,
        "safe_shutdown_initiated": bool(incident.safe_shutdown_initiated),
        "detail": incident.safe_shutdown_detail,
        "capability": SAFE_SHUTDOWN_CAPABILITY,
        **extra,
    }


# ---------------------------------------------------------------------------
# segmentation probe
# ---------------------------------------------------------------------------


def _allowed_destinations(zone: OTZone) -> set[str]:
    allowed: set[str] = set()
    for rule in zone.allowed_communications or []:
        if not isinstance(rule, dict):
            continue
        source = rule.get("source_zone")
        if source not in (None, "", zone.id, zone.name):
            continue
        dest = rule.get("dest_zone")
        if dest:
            allowed.add(str(dest))
    return allowed


async def build_probe_plan(db: AsyncSession, zone: OTZone) -> list[dict[str, Any]]:
    """Probes from ``zone`` to the stored assets of the tenant's other zones.

    A target's zone is the other zone whose CIDR contains the asset's IP; the
    expected outcome is ``allowed`` when this zone's ``allowed_communications``
    names that zone as a destination, otherwise ``blocked``.
    """
    others = [
        z for z in (await db.execute(
            select(OTZone).where(OTZone.organization_id == zone.organization_id, OTZone.id != zone.id),
        )).scalars().all()
        if z.network_cidr
    ]
    if not others:
        return []
    assets = list((await db.execute(
        select(OTAsset).where(
            OTAsset.organization_id == zone.organization_id,
            OTAsset.ip_address.is_not(None),
        ).order_by(OTAsset.name).limit(5000),
    )).scalars().all())
    allowed = _allowed_destinations(zone)
    plan: list[dict[str, Any]] = []
    for other in others:
        expected = "allowed" if (other.id in allowed or other.name in allowed) else "blocked"
        count = 0
        for asset in assets:
            port = PROTOCOL_PORTS.get((asset.protocol or "").lower())
            if port is None or _in_cidr(asset.ip_address, zone.network_cidr):
                continue
            if not _in_cidr(asset.ip_address, other.network_cidr):
                continue
            plan.append({
                "target_ip": asset.ip_address, "port": port, "protocol": asset.protocol,
                "asset_id": asset.id, "target_zone_id": other.id, "target_zone": other.name,
                "expected": expected,
            })
            count += 1
            if count >= MAX_PROBES_PER_ZONE or len(plan) >= MAX_PROBES:
                break
        if len(plan) >= MAX_PROBES:
            break
    return plan


async def request_segmentation_audit(
    db: AsyncSession, zone: OTZone, *, user: Any, agent_id: Optional[str] = None,
) -> dict[str, Any]:
    """Queue an ``ot_segmentation_probe`` command run from inside ``zone``."""
    if zone.segmentation_audit_status in PENDING_STATES:
        raise ActuationRefused(
            "already_pending",
            f"A segmentation audit is already {zone.segmentation_audit_status} for this zone.",
            command_id=zone.segmentation_audit_command_id,
        )
    plan = await build_probe_plan(db, zone)
    if not plan:
        raise ActuationRefused(
            "no_probe_targets",
            "Nothing to probe: no asset with an IP address and a known protocol port lies in another "
            "zone's CIDR. Add the other zones and their assets first.",
        )
    agent = await select_agent(
        db, zone.organization_id, SEGMENTATION_PROBE_CAPABILITY, agent_id, inside_cidr=zone.network_cidr,
    )
    payload = {
        "zone_id": zone.id,
        "zone_cidr": zone.network_cidr,
        "timeout_seconds": 2,
        "probes": [{k: p[k] for k in ("target_ip", "port", "protocol")} for p in plan],
    }
    command = await _issue(db, agent, SEGMENTATION_PROBE_ACTION, payload, user)
    zone.segmentation_audit_command_id = command.id
    zone.segmentation_audit_status = _PENDING.get(command.status, "queued")
    zone.segmentation_findings = {"plan": plan, "agent_id": agent.id}
    await _audit(
        db, user=user, org_id=zone.organization_id, action="ot_segmentation_audit_requested",
        resource_type="ot_zone", resource_id=zone.id,
        description=f"Segmentation probe of {len(plan)} target(s) queued for agent {agent.hostname}",
        payload={"command_id": command.id, "agent_id": agent.id, "command_status": command.status,
                 "probes": len(plan)},
    )
    return segmentation_view(zone)


def _probe_results(result: Any) -> list[dict[str, Any]]:
    artifacts = result.artifacts if isinstance(result.artifacts, dict) else {}
    doc: Any = artifacts.get("results")
    if doc is None:
        try:
            doc = json.loads(result.stdout or "")
        except (TypeError, ValueError):
            raise ValueError("agent output is not JSON") from None
    if isinstance(doc, dict):
        doc = doc.get("results")
    if not isinstance(doc, list):
        raise ValueError("agent output has no results list")
    out = []
    for row in doc:
        if isinstance(row, dict) and isinstance(row.get("reachable"), bool) and row.get("target_ip"):
            try:
                out.append({"target_ip": str(row["target_ip"]), "port": int(row.get("port") or 0),
                            "reachable": row["reachable"]})
            except (TypeError, ValueError):
                continue
    return out


async def reconcile_segmentation_audit(db: AsyncSession, zone: OTZone) -> bool:
    """Apply the agent's probe result to the zone. True when changed."""
    if zone.segmentation_audit_status not in PENDING_STATES or not zone.segmentation_audit_command_id:
        return False
    command_status, result = await _command_state(db, zone.segmentation_audit_command_id)
    findings = dict(zone.segmentation_findings or {})
    before = (zone.segmentation_audit_status, zone.segmentation_verified)
    now = datetime.now(timezone.utc)
    if result is None:
        if command_status in _PENDING:
            zone.segmentation_audit_status = _PENDING[command_status]
        else:
            zone.segmentation_audit_status = "failed"
            findings["error"] = f"agent command {command_status or 'missing'}"
    elif result.status != "success" or command_status != "completed":
        zone.segmentation_audit_status = "failed"
        findings["error"] = _result_text(result) or f"agent reported {result.status}"
    else:
        try:
            observed = _probe_results(result)
        except ValueError as exc:
            zone.segmentation_audit_status = "failed"
            findings["error"] = str(exc)
        else:
            by_target = {(r["target_ip"], r["port"]): r["reachable"] for r in observed}
            violations, unexpected_blocked, missing = [], [], []
            for probe in findings.get("plan") or []:
                key = (probe["target_ip"], int(probe["port"]))
                if key not in by_target:
                    missing.append(probe)
                elif by_target[key] and probe["expected"] == "blocked":
                    violations.append(probe)
                elif not by_target[key] and probe["expected"] == "allowed":
                    unexpected_blocked.append(probe)
            findings.update({"results": observed, "violations": violations,
                             "unexpected_blocked": unexpected_blocked, "missing": missing})
            if violations:
                zone.segmentation_audit_status = "violations_found"
            elif missing:
                zone.segmentation_audit_status = "incomplete"
            else:
                zone.segmentation_audit_status = "verified"
            zone.segmentation_verified = zone.segmentation_audit_status == "verified"
            zone.segmentation_audited_at = now
            zone.last_audit = now.replace(tzinfo=None)
    zone.segmentation_findings = findings
    changed = before != (zone.segmentation_audit_status, zone.segmentation_verified)
    await db.flush()
    return changed


def segmentation_view(zone: OTZone) -> dict[str, Any]:
    findings = zone.segmentation_findings or {}
    return {
        "zone_id": zone.id,
        "status": zone.segmentation_audit_status or "not_audited",
        "command_id": zone.segmentation_audit_command_id,
        "segmentation_verified": bool(zone.segmentation_verified),
        "audited_at": zone.segmentation_audited_at,
        "probes_planned": len(findings.get("plan") or []),
        "violations": findings.get("violations") or [],
        "unexpected_blocked": findings.get("unexpected_blocked") or [],
        "missing": findings.get("missing") or [],
        "error": findings.get("error"),
        "capability": SEGMENTATION_PROBE_CAPABILITY,
    }


async def reconcile_pending(db: AsyncSession, limit: int = 200) -> dict[str, int]:
    """Reconcile pending shutdowns and probes (bounded), for the beat task."""
    changed = {"incidents": 0, "zones": 0}
    incidents = (await db.execute(
        select(OTIncident).where(OTIncident.safe_shutdown_status.in_(PENDING_STATES)).limit(limit),
    )).scalars().all()
    for incident in incidents:
        if await reconcile_safe_shutdown(db, incident):
            changed["incidents"] += 1
    zones = (await db.execute(
        select(OTZone).where(OTZone.segmentation_audit_status.in_(PENDING_STATES)).limit(limit),
    )).scalars().all()
    for zone in zones:
        if await reconcile_segmentation_audit(db, zone):
            changed["zones"] += 1
    return changed
