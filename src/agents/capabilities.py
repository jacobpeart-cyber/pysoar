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
    COMPLIANCE = "compliance"  # DISA STIG / CIS benchmark checks
    DECEPTION = "deception"  # Hosts honeypot listeners, reports interactions
    CONTAINER_SCAN = "container_scan"  # Runs trivy / grype against a container image (wave 4)
    OT_SAFE_SHUTDOWN = "ot_safe_shutdown"  # OT gateway: runs the site's safe-shutdown procedure (wave 4)
    OT_SEGMENTATION_PROBE = "ot_segmentation_probe"  # In-zone TCP reachability probes (wave 4)
    STIG_SCAN = "stig_scan"  # Runs a whole-benchmark oscap evaluation (wave 4)


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
    BLOCK_IP = "block_ip"                      # payload = {ip} — host firewall drop
    UNBLOCK_IP = "unblock_ip"                  # payload = {ip} — reverse block_ip
    DISABLE_ACCOUNT = "disable_account"        # payload = {username}
    COLLECT_FILE = "collect_file"              # payload = {path}
    COLLECT_PROCESS_LIST = "collect_process_list"
    COLLECT_NETWORK_CONNECTIONS = "collect_network_connections"
    COLLECT_MEMORY_DUMP = "collect_memory_dump"
    QUARANTINE_FILE = "quarantine_file"        # payload = {path}
    UNQUARANTINE_FILE = "unquarantine_file"

    # --- Purple Team ---
    PURPLE_FIRE_TECHNIQUE = "purple_fire_technique"  # BAS test + live SIEM watch

    # --- Compliance ---
    RUN_STIG_CHECK = "run_stig_check"   # payload = {rule_id, check_content, os_type}
    RUN_CIS_CHECK = "run_cis_check"     # payload = {rule_id, check_content, os_type}

    # --- Deception ---
    DEPLOY_HONEYPOT = "deploy_honeypot"  # payload = {decoy_id, port, banner, service}
    STOP_HONEYPOT = "stop_honeypot"      # payload = {decoy_id}
    # Non-listener decoys (honeyfile, honeycred, breadcrumb, ...): the agent
    # plants / removes the artefact. Status comes from the command result.
    DEPLOY_DECOY = "deploy_decoy"        # payload = {decoy_id, decoy_type, category, configuration}
    REMOVE_DECOY = "remove_decoy"        # payload = {decoy_id, decoy_type}

    # --- Container scanning (wave 4) ---
    # payload = {image_ref, scanner: trivy|grype, scan_id}; the agent runs the
    # scanner with JSON output and returns the report on stdout (or as
    # artifacts.report). Read-only on the host, so no approval is required.
    SCAN_CONTAINER_IMAGE = "scan_container_image"

    # --- OT security (wave 4, src/ot_security/actuation.py) ---
    # payload = {ot_incident_id, affected_zones, assets: [{asset_id, name,
    # ip_address, protocol, vendor, model, purdue_level, criticality}]}; the
    # agent runs the site's own shutdown procedure and reports success/failure.
    OT_SAFE_SHUTDOWN = "ot_safe_shutdown"
    # payload = {zone_id, zone_cidr, timeout_seconds, probes: [{target_ip, port,
    # protocol}]}; the agent attempts each TCP connection and returns
    # {"results": [{target_ip, port, reachable}]} on stdout (or artifacts.results).
    OT_SEGMENTATION_PROBE = "ot_segmentation_probe"

    # --- STIG scanning (wave 4, src/stig/agent_scan.py) ---
    # payload = {scan_id, benchmark_id (XCCDF id), profile, benchmark_title};
    # the agent runs ``oscap xccdf eval --results-arf`` against the benchmark
    # and returns the ARF XML on stdout (or as artifacts.arf). Read-only on
    # the host, so no approval is required.
    STIG_SCAN = "stig_scan"


# Which actions each capability unlocks
CAPABILITY_ACTIONS: dict[AgentCapability, set[AgentAction]] = {
    AgentCapability.BAS: {
        AgentAction.RUN_ATOMIC_TEST,
    },
    AgentCapability.LIVE_RESPONSE: {
        AgentAction.KILL_PROCESS,
        AgentAction.ISOLATE_HOST,
        AgentAction.RELEASE_HOST,
        AgentAction.BLOCK_IP,
        AgentAction.UNBLOCK_IP,
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
    AgentCapability.COMPLIANCE: {
        AgentAction.RUN_STIG_CHECK,
        AgentAction.RUN_CIS_CHECK,
    },
    AgentCapability.DECEPTION: {
        AgentAction.DEPLOY_HONEYPOT,
        AgentAction.STOP_HONEYPOT,
        AgentAction.DEPLOY_DECOY,
        AgentAction.REMOVE_DECOY,
    },
}
CAPABILITY_ACTIONS[AgentCapability.CONTAINER_SCAN] = {AgentAction.SCAN_CONTAINER_IMAGE}
CAPABILITY_ACTIONS[AgentCapability.OT_SAFE_SHUTDOWN] = {AgentAction.OT_SAFE_SHUTDOWN}
CAPABILITY_ACTIONS[AgentCapability.OT_SEGMENTATION_PROBE] = {AgentAction.OT_SEGMENTATION_PROBE}


# Actions that require multi-party approval before execution.
# These are the ones an auditor will ask about first: anything that can
# take an endpoint offline, reset credentials, or touch memory.
HIGH_BLAST_ACTIONS: set[AgentAction] = {
    AgentAction.ISOLATE_HOST,
    AgentAction.RELEASE_HOST,
    AgentAction.BLOCK_IP,
    AgentAction.UNBLOCK_IP,
    AgentAction.DISABLE_ACCOUNT,
    AgentAction.COLLECT_MEMORY_DUMP,
    AgentAction.KILL_PROCESS,
    AgentAction.QUARANTINE_FILE,
    AgentAction.UNQUARANTINE_FILE,
}
# Wave 4 (OT): shutting down plant equipment and actively probing OT networks
# both wait for a second administrator in the approval queue.
HIGH_BLAST_ACTIONS |= {AgentAction.OT_SAFE_SHUTDOWN, AgentAction.OT_SEGMENTATION_PROBE}
# Wave 4 (STIG): only agents enrolled with the explicit "stig_scan" capability
# may run a whole-benchmark evaluation. Folding it into "compliance" would
# silently widen every existing compliance enrolment; operators re-enrol
# an agent with "stig_scan" to grant it.
CAPABILITY_ACTIONS[AgentCapability.STIG_SCAN] = {AgentAction.STIG_SCAN}


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
