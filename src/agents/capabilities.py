"""Agent capability & command allowlist.

Each enrolled agent is stamped with one or more capabilities at
enrollment time. A capability gates which ``action`` values PySOAR is
allowed to dispatch to that agent. This is enforced on BOTH sides:

- **Server side** (``AgentService.issue_command``): refuses to enqueue a
  command whose action isn't in the enrolled agent's capability set.
- **Agent side** (``agent/pysoar_agent.py``): independently refuses any
  inbound command whose ``action`` or ``command_hash`` isn't in the
  local signed allowlist the operator burned in at install time.

This two-sided enforcement means that even if a PySOAR admin account is
compromised, the attacker cannot turn BAS-enrolled agents into a shell
on customer endpoints. They'd have to re-enroll the agent with new
capabilities, which requires physical access and an operator token.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Optional


class AgentCapability(str, Enum):
    """Capability classes an agent may be enrolled with.

    An agent may have multiple capabilities — e.g. a lab host used for
    both Breach & Attack Simulation and Purple Team exercises. IR
    capability is intentionally separable so IR agents can ship to
    production endpoints without carrying the BAS atomic test library.
    """

    BAS = "bas"              # Runs MITRE ATT&CK atomic tests
    LIVE_RESPONSE = "ir"     # Incident response actions: kill/isolate/collect
    PURPLE_TEAM = "purple"   # Orchestrated red+blue live correlation


class AgentAction(str, Enum):
    """Concrete actions a command may request.

    Every action is bounded, parameterized, and reviewable. There is
    intentionally no generic "exec_shell" — a SOC platform must not be
    a C2. If a future action is needed, it's added here, an allowlisted
    implementation is shipped in the agent, and the command hash is
    re-pinned.
    """

    # --- BAS ---
    RUN_ATOMIC_TEST = "run_atomic_test"        # payload = {mitre_id, target_host}

    # --- Live Response (IR) ---
    KILL_PROCESS = "kill_process"              # payload = {pid or process_name}
    ISOLATE_HOST = "isolate_host"              # network quarantine
    RELEASE_HOST = "release_host"              # reverse isolate
    DISABLE_ACCOUNT = "disable_account"        # payload = {username}
    COLLECT_FILE = "collect_file"              # payload = {path}
    COLLECT_PROCESS_LIST = "collect_process_list"
    COLLECT_NETWORK_CONNECTIONS = "collect_network_connections"
    COLLECT_MEMORY_DUMP = "collect_memory_dump"
    QUARANTINE_FILE = "quarantine_file"        # payload = {path}
    UNQUARANTINE_FILE = "unquarantine_file"

    # --- Purple Team ---
    PURPLE_FIRE_TECHNIQUE = "purple_fire_technique"  # BAS test + live SIEM watch


# Which actions each capability unlocks
CAPABILITY_ACTIONS: dict[AgentCapability, set[AgentAction]] = {
    AgentCapability.BAS: {
        AgentAction.RUN_ATOMIC_TEST,
    },
    AgentCapability.LIVE_RESPONSE: {
        AgentAction.KILL_PROCESS,
        AgentAction.ISOLATE_HOST,
        AgentAction.RELEASE_HOST,
        AgentAction.DISABLE_ACCOUNT,
        AgentAction.COLLECT_FILE,
        AgentAction.COLLECT_PROCESS_LIST,
        AgentAction.COLLECT_NETWORK_CONNECTIONS,
        AgentAction.COLLECT_MEMORY_DUMP,
        AgentAction.QUARANTINE_FILE,
        AgentAction.UNQUARANTINE_FILE,
    },
    AgentCapability.PURPLE_TEAM: {
        AgentAction.RUN_ATOMIC_TEST,
        AgentAction.PURPLE_FIRE_TECHNIQUE,
        AgentAction.COLLECT_PROCESS_LIST,
    },
}


# Actions that require multi-party approval before execution.
# These are the ones an auditor will ask about first: anything that can
# take an endpoint offline, reset credentials, or touch memory.
HIGH_BLAST_ACTIONS: set[AgentAction] = {
    AgentAction.ISOLATE_HOST,
    AgentAction.RELEASE_HOST,
    AgentAction.DISABLE_ACCOUNT,
    AgentAction.COLLECT_MEMORY_DUMP,
    AgentAction.KILL_PROCESS,
    AgentAction.QUARANTINE_FILE,
    AgentAction.UNQUARANTINE_FILE,
}


def capability_allows(capabilities: list[str], action: str) -> bool:
    """Return True if ``action`` is permitted for any of the given capabilities.

    Accepts strings (the DB stores JSON lists of strings) so callers
    don't have to round-trip through the enums.
    """
    try:
        action_enum = AgentAction(action)
    except ValueError:
        return False

    for cap in capabilities:
        try:
            cap_enum = AgentCapability(cap)
        except ValueError:
            continue
        if action_enum in CAPABILITY_ACTIONS.get(cap_enum, set()):
            return True
    return False


def requires_approval(action: str) -> bool:
    """True if this action requires the high-blast approval workflow."""
    try:
        return AgentAction(action) in HIGH_BLAST_ACTIONS
    except ValueError:
        return True  # unknown actions default to requiring approval


def command_hash(action: str, payload: Optional[dict]) -> str:
    """Produce a deterministic SHA-256 over ``(action, payload)``.

    Used for:
    - the agent-side signed allowlist (agent precomputes hashes of every
      action it's willing to run and refuses anything else);
    - the tamper-evident audit chain (each AgentCommand row links to the
      hash of the previous command for that agent).
    """
    import json as _json

    canonical = _json.dumps(
        {"action": action, "payload": payload or {}},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
