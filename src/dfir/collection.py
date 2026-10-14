"""Evidence collection through endpoint agents (``collect_*`` commands).

``request_collection`` issues the agent command through
``AgentService.issue_command`` (capability allowlist, approval queue and hash
chain all apply) and registers a ForensicEvidence row whose
``collection_status`` follows that command. ``apply_command_outcome`` closes
the loop when the agent reports: the bytes the agent returned are written
under the evidence root and hashed on write, and the custody log records the
agent as the collector. With no enrolled agent for the host, nothing is
created and the caller gets ``awaiting_agent`` with the reason.

Command status -> collection status:

* ``awaiting_approval`` -> ``awaiting_approval`` (memory dumps need a second admin)
* ``queued`` / ``dispatched`` / ``running`` -> ``pending``
* result ``success`` -> ``collected`` (bytes stored) or ``collected_on_host``
  (memory dumps: the agent writes the dump on the host and reports its path
  and hash; the bytes are not transferred)
* result not ``success``, or the command ``rejected`` / ``expired`` / ``failed``
  -> ``failed`` with ``collection_error``
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.capabilities import AgentAction, capability_allows
from src.core.logging import get_logger
from src.dfir.models import ForensicEvidence
from src.dfir.storage import relative_location, store_evidence_bytes
from src.models.audit import AuditLog

logger = get_logger(__name__)

#: collection_type -> (agent action, evidence_type, stored file name)
COLLECTION_TYPES: dict[str, tuple[str, str, str]] = {
    "process_list": (AgentAction.COLLECT_PROCESS_LIST.value, "process_list", "process_list.txt"),
    "network_connections": (AgentAction.COLLECT_NETWORK_CONNECTIONS.value, "network_connections", "network_connections.txt"),
    "file": (AgentAction.COLLECT_FILE.value, "file", "collected_file.bin"),
    "memory_dump": (AgentAction.COLLECT_MEMORY_DUMP.value, "memory_dump", "memory_dump.bin"),
}

#: Largest file a ``collect_file`` request may ask the agent to return (the
#: bytes travel base64-encoded in the agent's result post).
MAX_COLLECT_FILE_BYTES = 25 * 1024 * 1024
#: The agent truncates command stdout at this many characters.
AGENT_STDOUT_LIMIT = 16384

PENDING_STATES = ("pending", "awaiting_approval")
_FAILED_COMMAND_STATES = ("rejected", "expired", "failed", "denied")


class CollectionRequestError(ValueError):
    """The collection request itself is invalid (maps to 400)."""


@dataclass
class CollectionOutcome:
    status: str  # awaiting_agent | awaiting_approval | pending
    detail: str
    evidence: Optional[ForensicEvidence] = None
    command_id: Optional[str] = None
    agent_id: Optional[str] = None
    agent_hostname: Optional[str] = None


def build_payload(collection_type: str, path: Optional[str], max_bytes: Optional[int], pid: Optional[int]) -> dict[str, Any]:
    if collection_type not in COLLECTION_TYPES:
        raise CollectionRequestError(
            f"collection_type must be one of {', '.join(sorted(COLLECTION_TYPES))}",
        )
    if collection_type == "file":
        if not path or not path.strip():
            raise CollectionRequestError("path is required for a file collection")
        if len(path) > 1024:
            raise CollectionRequestError("path is longer than 1024 characters")
        limit = int(max_bytes or 1024 * 1024)
        if limit < 1 or limit > MAX_COLLECT_FILE_BYTES:
            raise CollectionRequestError(f"max_bytes must be between 1 and {MAX_COLLECT_FILE_BYTES}")
        return {"path": path.strip(), "max_bytes": limit}
    if collection_type == "memory_dump":
        if pid is None or int(pid) <= 0:
            raise CollectionRequestError("pid is required for a memory dump")
        return {"pid": int(pid)}
    return {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_custody(evidence: ForensicEvidence, entry: dict[str, Any]) -> None:
    chain = dict(evidence.chain_of_custody_log or {})
    entries = list(chain.get("entries", []))
    entries.append(entry)
    chain["entries"] = entries
    evidence.chain_of_custody_log = chain


async def _audit(
    db: AsyncSession, org_id: str, *, user_id: Optional[str], action: str, resource_id: Optional[str],
    description: str, payload: dict[str, Any], success: bool, error: Optional[str] = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            organization_id=org_id,
            action=action,
            resource_type="forensic_evidence",
            resource_id=resource_id,
            description=description[:4000],
            new_value=json.dumps(payload, default=str),
            success=success,
            error_message=error,
        ),
    )
    await db.flush()


async def request_collection(
    db: AsyncSession,
    *,
    org_id: str,
    case_id: str,
    hostname: str,
    collection_type: str,
    payload: dict[str, Any],
    actor_user_id: str,
    actor_name: str,
    notes: Optional[str] = None,
) -> CollectionOutcome:
    """Queue a ``collect_*`` command on the host's agent, or report ``awaiting_agent``."""
    from src.agents.service import AgentService, AgentServiceError
    from src.services.containment import agent_for_host, find_asset

    action, evidence_type, _ = COLLECTION_TYPES[collection_type]
    asset = await find_asset(db, org_id, hostname)
    agent = await agent_for_host(db, org_id, asset, hostname)
    audit_payload = {"hostname": hostname, "collection_type": collection_type, "agent_action": action, "payload": payload}

    if agent is None:
        detail = (
            f"No enrolled endpoint agent for {hostname} in this organisation: nothing was collected. "
            "Enroll an agent with the 'ir' capability on the host, then request the collection again."
        )
        await _audit(
            db, org_id, user_id=actor_user_id, action=f"dfir_collect_{collection_type}", resource_id=None,
            description=f"{action} on {hostname}: awaiting_agent", payload={**audit_payload, "status": "awaiting_agent"},
            success=False,
        )
        return CollectionOutcome(status="awaiting_agent", detail=detail)

    if not capability_allows(list(agent.capabilities or []), action):
        detail = (
            f"Endpoint agent {agent.hostname} is enrolled with {agent.capabilities} and cannot run {action}; "
            "re-enroll it with the 'ir' capability. Nothing was collected."
        )
        await _audit(
            db, org_id, user_id=actor_user_id, action=f"dfir_collect_{collection_type}", resource_id=None,
            description=f"{action} on {hostname}: awaiting_agent (capability)",
            payload={**audit_payload, "status": "awaiting_agent", "agent_id": agent.id}, success=False,
        )
        return CollectionOutcome(status="awaiting_agent", detail=detail, agent_id=agent.id, agent_hostname=agent.hostname)

    try:
        cmd = await AgentService(db).issue_command(agent=agent, action=action, payload=payload, issued_by=actor_user_id)
    except AgentServiceError as exc:
        await _audit(
            db, org_id, user_id=actor_user_id, action=f"dfir_collect_{collection_type}", resource_id=None,
            description=f"{action} on {agent.hostname}: refused", payload={**audit_payload, "agent_id": agent.id},
            success=False, error=str(exc),
        )
        raise

    status = "awaiting_approval" if cmd.status == "awaiting_approval" else "pending"
    evidence = ForensicEvidence(
        case_id=case_id,
        evidence_type=evidence_type,
        source_device=agent.hostname,
        source_ip=getattr(agent, "ip_address", None),
        acquisition_method="live_acquisition",
        storage_location="",
        handling_notes=notes,
        organization_id=org_id,
        collection_status=status,
        collection_command_id=cmd.id,
        collection_agent_id=agent.id,
        chain_of_custody_log={
            "entries": [
                {
                    "timestamp": _now_iso(),
                    "actor": actor_name,
                    "action": "collection_requested",
                    "details": f"{action} queued on endpoint agent {agent.hostname} (command {cmd.id}, {cmd.status})",
                },
            ],
        },
    )
    db.add(evidence)
    await db.flush()
    await _audit(
        db, org_id, user_id=actor_user_id, action=f"dfir_collect_{collection_type}", resource_id=evidence.id,
        description=f"{action} on {agent.hostname}: command {cmd.id} {cmd.status}",
        payload={**audit_payload, "agent_id": agent.id, "command_id": cmd.id, "command_status": cmd.status},
        success=True,
    )
    verb = "awaits a second approver" if status == "awaiting_approval" else "is queued"
    return CollectionOutcome(
        status=status,
        detail=f"{action} command {cmd.id} {verb} on endpoint agent {agent.hostname}",
        evidence=evidence, command_id=cmd.id, agent_id=agent.id, agent_hostname=agent.hostname,
    )


def _collected_bytes(collection_type: str, stdout: Optional[str], artifacts: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """The evidence bytes in an agent result, plus notes for the custody entry."""
    notes: dict[str, Any] = {}
    if collection_type == "file":
        encoded = artifacts.get("content_base64")
        if not isinstance(encoded, str):
            raise ValueError("agent result has no content_base64 for the collected file")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"agent returned undecodable file content: {exc}") from exc
        if artifacts.get("path"):
            notes["host_path"] = str(artifacts["path"])[:1024]
        return data, notes
    text = stdout or ""
    if len(text) >= AGENT_STDOUT_LIMIT:
        notes["agent_truncated_output_at_chars"] = AGENT_STDOUT_LIMIT
    return text.encode("utf-8"), notes


def apply_command_outcome(
    evidence: ForensicEvidence,
    *,
    root: str,
    command_status: Optional[str],
    result: Any = None,
    agent_hostname: Optional[str] = None,
) -> bool:
    """Move ``evidence`` along from its agent command. Returns True when it changed.

    ``result`` is the AgentResult row (or an object with ``status``,
    ``stdout``, ``stderr`` and ``artifacts``) when the agent has reported.
    """
    if evidence.collection_status not in PENDING_STATES:
        return False
    collector = f"agent:{agent_hostname or evidence.source_device}"
    collection_type = next(
        (k for k, (_, etype, _) in COLLECTION_TYPES.items() if etype == evidence.evidence_type), "file",
    )

    if result is None:
        if command_status in _FAILED_COMMAND_STATES:
            evidence.collection_status = "failed"
            evidence.collection_error = f"agent command {command_status}"
            _append_custody(evidence, {
                "timestamp": _now_iso(), "actor": collector, "action": "collection_failed",
                "details": evidence.collection_error,
            })
            return True
        wanted = "awaiting_approval" if command_status == "awaiting_approval" else "pending"
        if evidence.collection_status != wanted:
            evidence.collection_status = wanted
            return True
        return False

    if result.status != "success":
        evidence.collection_status = "failed"
        evidence.collection_error = ((result.stderr or "") or f"agent reported {result.status}")[:2000]
        _append_custody(evidence, {
            "timestamp": _now_iso(), "actor": collector, "action": "collection_failed",
            "details": evidence.collection_error,
        })
        return True

    artifacts = dict(result.artifacts or {})
    if collection_type == "memory_dump":
        evidence.collection_status = "collected_on_host"
        if isinstance(artifacts.get("size_bytes"), int):
            evidence.file_size_bytes = artifacts["size_bytes"]
        _append_custody(evidence, {
            "timestamp": _now_iso(), "actor": collector, "action": "collected_on_host",
            "details": (
                f"memory dump written on the host at {artifacts.get('dump_path')}; the bytes were not "
                "transferred to PySOAR, so no server-side hash exists"
            ),
            "agent_reported_sha256": artifacts.get("sha256"),
        })
        return True

    try:
        data, notes = _collected_bytes(collection_type, result.stdout, artifacts)
        if not data:
            raise ValueError("agent returned no content")
        stored = store_evidence_bytes(
            root, evidence.organization_id, evidence.case_id, COLLECTION_TYPES[collection_type][2], data,
        )
    except (ValueError, OSError) as exc:
        evidence.collection_status = "failed"
        evidence.collection_error = str(exc)[:2000]
        _append_custody(evidence, {
            "timestamp": _now_iso(), "actor": collector, "action": "collection_failed",
            "details": evidence.collection_error,
        })
        return True

    agent_sha = artifacts.get("sha256")
    if collection_type == "file" and isinstance(agent_sha, str) and agent_sha.lower() != stored.sha256:
        notes["agent_reported_sha256"] = agent_sha
        notes["agent_hash_matches"] = False
    elif collection_type == "file" and isinstance(agent_sha, str):
        notes["agent_hash_matches"] = True

    evidence.storage_location = relative_location(root, stored.path)
    evidence.original_hash_sha256 = stored.sha256
    evidence.original_hash_md5 = stored.md5
    evidence.file_size_bytes = stored.size
    evidence.collection_status = "collected"
    evidence.collection_error = None
    _append_custody(evidence, {
        "timestamp": _now_iso(), "actor": collector, "action": "collected",
        "hash": stored.sha256, "hash_md5": stored.md5, "hash_sha512": stored.sha512, "size_bytes": stored.size,
        **notes,
    })
    return True


async def reconcile_evidence(db: AsyncSession, evidence: ForensicEvidence, *, root: str) -> bool:
    """Single-row reconcile used by the read routes (the beat task batches)."""
    from sqlalchemy import select

    from src.agents.models import AgentCommand, AgentResult, EndpointAgent

    if evidence.collection_status not in PENDING_STATES or not evidence.collection_command_id:
        return False
    result = (
        await db.execute(
            select(AgentResult).where(AgentResult.command_id == evidence.collection_command_id)
            .order_by(AgentResult.reported_at.desc()).limit(1),
        )
    ).scalar_one_or_none()
    command_status = (
        await db.execute(select(AgentCommand.status).where(AgentCommand.id == evidence.collection_command_id))
    ).scalar_one_or_none()
    hostname = None
    if evidence.collection_agent_id:
        hostname = (
            await db.execute(select(EndpointAgent.hostname).where(EndpointAgent.id == evidence.collection_agent_id))
        ).scalar_one_or_none()
    changed = apply_command_outcome(
        evidence, root=root, command_status=command_status, result=result, agent_hostname=hostname,
    )
    if changed:
        await db.flush()
        logger.info(
            "dfir_collection_reconciled",
            evidence_id=evidence.id, status=evidence.collection_status, command_id=evidence.collection_command_id,
        )
    return changed
