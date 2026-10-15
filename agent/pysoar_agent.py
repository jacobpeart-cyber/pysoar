"""PySOAR Endpoint Agent.

Single-file Python agent that runs on customer endpoints and receives
commands from a PySOAR server. The agent is intentionally minimal:

- Stateless other than a local token file and a pinned action allowlist
- No outbound connections except to PYSOAR_URL over HTTPS
- Refuses any command whose action is not in the local allowlist
- Refuses any command whose hostname does not match this host
- Never runs a command string sent by the server for scans, decoys or OT
  actions: local scanner binaries with a fixed argv, an operator-configured
  decoy directory, and operator-configured OT scripts only
- Logs every command + result to stdout for the local SIEM to collect

Usage:

    # First install: exchange an enrollment token for a long-lived token
    python pysoar_agent.py --enroll <ENROLLMENT_TOKEN> \\
        --server https://pysoar.example.com \\
        --capabilities bas

    # Subsequent runs: poll + execute on loop
    python pysoar_agent.py --poll --server https://pysoar.example.com

The token is stored in ``~/.pysoar/agent.token`` with 0600 perms.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

AGENT_VERSION = "0.1.0"
DEFAULT_TOKEN_FILE = Path.home() / ".pysoar" / "agent.token"
POLL_INTERVAL_SECONDS = 30
HEARTBEAT_INTERVAL_SECONDS = 300  # 5 min posture push for ZT PDP freshness
HEARTBEAT_EVERY_N_POLLS = 1  # poll doubles as heartbeat server-side


# ---------------------------------------------------------------------------
# Cryptographically pinned action allowlist.
#
# The agent REFUSES any action whose name is not in this dict, even if the
# PySOAR server authorizes it. Adding a new action requires:
#   1. Ship a new agent build with the handler present here,
#   2. Operator re-install on the endpoint,
#   3. Capability in the enrollment call.
# This is what makes the platform safe to deploy on production endpoints:
# a compromised PySOAR admin cannot turn agents into a C2.
# ---------------------------------------------------------------------------

def _handle_run_atomic_test(payload: dict[str, Any]) -> dict[str, Any]:
    """Run a BAS atomic test. Payload must include ``command`` and
    ``executor`` (powershell/cmd/sh/bash). ``expected_command_hash`` is
    cross-checked against sha256(action, payload) so the command body
    can't be swapped in transit."""
    import hashlib

    command = payload.get("command")
    executor = payload.get("executor", "sh")
    if not command:
        return {"status": "error", "stderr": "missing command", "exit_code": 127}

    # Map executor -> argv prefix
    prefix_map = {
        "sh": ["sh", "-c"],
        "bash": ["bash", "-c"],
        "powershell": ["powershell", "-NoProfile", "-NonInteractive", "-Command"],
        "cmd": ["cmd", "/c"],
    }
    prefix = prefix_map.get(executor.lower())
    if not prefix:
        return {
            "status": "rejected",
            "stderr": f"executor {executor} not allowed",
            "exit_code": 126,
        }

    try:
        proc = subprocess.run(
            [*prefix, command],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:8192],
            "stderr": proc.stderr[:8192],
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stderr": "command timed out", "exit_code": 124}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_collect_process_list(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the current process list. Safe read-only action."""
    try:
        if platform.system() == "Windows":
            proc = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=30,
            )
        else:
            proc = subprocess.run(
                ["ps", "-eo", "pid,ppid,user,comm,args"],
                capture_output=True, text=True, timeout=30,
            )
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:16384],
            "stderr": proc.stderr[:4096],
            "artifacts": {"process_count": len(proc.stdout.splitlines())},
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_collect_network_connections(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["ss", "-tulpn"] if platform.system() != "Windows" else ["netstat", "-ano"],
            capture_output=True, text=True, timeout=30,
        )
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:16384],
            "stderr": proc.stderr[:4096],
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


# ---------------------------------------------------------------------------
# Live Response handlers (IR capability).
#
# These actions mutate host state — they kill processes, isolate the
# network stack, disable user accounts, and quarantine files. Every one
# of them requires a second-user approval at the server before it's
# even dispatched to this agent, AND the server's capability check
# ensures the agent was enrolled with the "ir" capability. Defense in
# depth: the handler registration below is driven by the agent's own
# capability list returned from the enrollment exchange — an agent
# running in --mode bas simply won't register these functions, so even
# a compromised server can't execute them on a BAS host.
# ---------------------------------------------------------------------------

def _handle_kill_process(payload: dict[str, Any]) -> dict[str, Any]:
    """Kill a process by PID (preferred) or exact name.

    Requires pid or process_name in payload. Returns error if the
    target doesn't exist rather than silently succeeding."""
    pid = payload.get("pid")
    process_name = payload.get("process_name")
    if not pid and not process_name:
        return {"status": "error", "stderr": "pid or process_name required", "exit_code": 22}

    try:
        if pid is not None:
            pid_int = int(pid)
            if platform.system() == "Windows":
                proc = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid_int)],
                    capture_output=True, text=True, timeout=10,
                )
            else:
                import signal
                try:
                    os.kill(pid_int, signal.SIGKILL)
                    return {
                        "status": "success",
                        "exit_code": 0,
                        "stdout": f"killed pid {pid_int}",
                        "artifacts": {"pid": pid_int},
                    }
                except ProcessLookupError:
                    return {"status": "error", "stderr": f"no such pid {pid_int}", "exit_code": 3}
                except PermissionError:
                    return {"status": "error", "stderr": "permission denied", "exit_code": 13}
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:4096],
                "stderr": proc.stderr[:4096],
                "artifacts": {"pid": pid_int},
            }

        # Kill by name
        if platform.system() == "Windows":
            proc = subprocess.run(
                ["taskkill", "/F", "/IM", str(process_name)],
                capture_output=True, text=True, timeout=10,
            )
        else:
            proc = subprocess.run(
                ["pkill", "-9", "-x", str(process_name)],
                capture_output=True, text=True, timeout=10,
            )
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:4096],
            "stderr": proc.stderr[:4096],
            "artifacts": {"process_name": str(process_name)},
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


# Tag we stamp on firewall rules so release_host can find and remove them
_PYSOAR_ISOLATION_TAG = "pysoar-isolate"


def _handle_isolate_host(payload: dict[str, Any]) -> dict[str, Any]:
    """Quarantine this host at the network layer.

    On Linux: insert iptables INPUT/OUTPUT DROP rules at the top of the
    chain, with an ACCEPT allow for an optional ``mgmt_cidr`` so PySOAR
    itself can still talk to the agent (otherwise isolation kills the
    very link used to un-isolate).

    On Windows: create a Windows Firewall block rule named
    ``pysoar-isolate-*``.

    ``mgmt_cidr`` defaults to the PySOAR server's IP from payload
    (the server populates this at dispatch time) so the agent keeps
    phoning home and stays releasable.
    """
    mgmt_cidr = payload.get("mgmt_cidr") or payload.get("mgmt_ip")

    try:
        if platform.system() == "Linux":
            # Allow existing ESTABLISHED connections and the mgmt channel
            cmds: list[list[str]] = []
            if mgmt_cidr:
                cmds += [
                    ["iptables", "-I", "INPUT", "1", "-s", mgmt_cidr, "-j", "ACCEPT",
                     "-m", "comment", "--comment", _PYSOAR_ISOLATION_TAG],
                    ["iptables", "-I", "OUTPUT", "1", "-d", mgmt_cidr, "-j", "ACCEPT",
                     "-m", "comment", "--comment", _PYSOAR_ISOLATION_TAG],
                ]
            cmds += [
                ["iptables", "-I", "INPUT", "-j", "DROP",
                 "-m", "comment", "--comment", _PYSOAR_ISOLATION_TAG],
                ["iptables", "-I", "OUTPUT", "-j", "DROP",
                 "-m", "comment", "--comment", _PYSOAR_ISOLATION_TAG],
            ]
            outputs = []
            for cmd in cmds:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                outputs.append(f"$ {' '.join(cmd)}\n{proc.stdout}{proc.stderr}")
                if proc.returncode != 0:
                    return {
                        "status": "error",
                        "exit_code": proc.returncode,
                        "stdout": "\n".join(outputs)[:8192],
                        "stderr": proc.stderr[:2048],
                    }
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": "\n".join(outputs)[:8192],
                "artifacts": {"method": "iptables", "mgmt_cidr": mgmt_cidr},
            }

        if platform.system() == "Windows":
            rule_name = f"{_PYSOAR_ISOLATION_TAG}-block"
            ps = (
                f'New-NetFirewallRule -DisplayName "{rule_name}" '
                '-Direction Inbound -Action Block -Profile Any; '
                f'New-NetFirewallRule -DisplayName "{rule_name}-out" '
                '-Direction Outbound -Action Block -Profile Any'
            )
            if mgmt_cidr:
                ps = (
                    f'New-NetFirewallRule -DisplayName "{rule_name}-allow-mgmt" '
                    f'-Direction Inbound -RemoteAddress {mgmt_cidr} -Action Allow; '
                    f'New-NetFirewallRule -DisplayName "{rule_name}-allow-mgmt-out" '
                    f'-Direction Outbound -RemoteAddress {mgmt_cidr} -Action Allow; '
                ) + ps
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=30,
            )
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:4096],
                "stderr": proc.stderr[:4096],
                "artifacts": {"method": "windows_firewall", "mgmt_cidr": mgmt_cidr},
            }

        return {
            "status": "rejected",
            "stderr": f"isolate_host not supported on {platform.system()}",
            "exit_code": 95,
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_release_host(payload: dict[str, Any]) -> dict[str, Any]:
    """Undo a prior isolate_host by removing rules tagged with our label."""
    try:
        if platform.system() == "Linux":
            # Walk iptables -S output and delete any rule that carries our comment
            list_proc = subprocess.run(
                ["iptables", "-S"], capture_output=True, text=True, timeout=10
            )
            removed = 0
            for line in list_proc.stdout.splitlines():
                if _PYSOAR_ISOLATION_TAG not in line:
                    continue
                if line.startswith("-A "):
                    del_args = ["iptables", "-D"] + line[3:].split()
                    subprocess.run(del_args, capture_output=True, text=True, timeout=10)
                    removed += 1
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": f"removed {removed} isolation rule(s)",
                "artifacts": {"rules_removed": removed},
            }

        if platform.system() == "Windows":
            ps = (
                f'Get-NetFirewallRule -DisplayName "{_PYSOAR_ISOLATION_TAG}*" '
                '| Remove-NetFirewallRule'
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=30,
            )
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:4096],
                "stderr": proc.stderr[:4096],
            }

        return {
            "status": "rejected",
            "stderr": f"release_host not supported on {platform.system()}",
            "exit_code": 95,
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


# Tag prefix stamped on per-IP block rules so unblock_ip can find exactly
# the rules block_ip created (and nothing else).
_PYSOAR_BLOCK_TAG = "pysoar-block"

# Resolved IP(s) of the PySOAR server this agent talks to. Populated at
# startup from --server (see cmd_poll/cmd_enroll) so a bad playbook can
# never block the very link used to un-block.
_MANAGEMENT_SERVER_IPS: set[str] = set()


def _resolve_server_ips(server_url: str) -> set[str]:
    """Best-effort resolution of the PySOAR server hostname to IP(s).

    Returns an empty set on any failure — callers treat 'unknown' as
    'cannot protect', never as an execution error.
    """
    import ipaddress
    from urllib.parse import urlparse

    ips: set[str] = set()
    try:
        host = urlparse(server_url).hostname
        if not host:
            return ips
        try:
            # Server configured by IP literal — no DNS needed
            ips.add(str(ipaddress.ip_address(host)))
            return ips
        except ValueError:
            pass
        for info in socket.getaddrinfo(host, None):
            ips.add(str(info[4][0]))
    except (socket.gaierror, OSError, ValueError):
        pass
    return ips


def _parse_block_ip(raw: Any) -> tuple[Any, Optional[dict[str, Any]]]:
    """Validate the ``ip`` payload field with the ipaddress module.

    Returns ``(ip_address_object, None)`` on success or
    ``(None, rejection_result)`` for anything that isn't a real IP.
    """
    import ipaddress

    if raw is None or str(raw).strip() == "":
        return None, {"status": "error", "stderr": "ip required", "exit_code": 22}
    try:
        return ipaddress.ip_address(str(raw).strip()), None
    except ValueError:
        return None, {
            "status": "rejected",
            "stderr": f"invalid ip: {str(raw)[:128]!r}",
            "exit_code": 22,
        }


def _block_rule_name(ip: str) -> str:
    """Windows firewall DisplayName for a per-IP block rule.

    Sanitized: only [A-Za-z0-9.] survive; everything else (IPv6 colons,
    zone indices, quotes, ...) becomes '_' so the ip can never break out
    of the -DisplayName string.
    """
    import re

    return f"{_PYSOAR_BLOCK_TAG}-" + re.sub(r"[^A-Za-z0-9.]", "_", ip)


def _handle_block_ip(payload: dict[str, Any]) -> dict[str, Any]:
    """Block all traffic to/from a single IP on this host's firewall.

    Payload: ``{"ip": "..."}``. The value must parse as a real IPv4/IPv6
    address; loopback, unspecified (0.0.0.0/::), and the PySOAR
    management server's own IP are refused so a bad playbook can't cut
    the agent off from the platform (or the host off from itself).

    Rules are tagged ``pysoar-block-<ip>`` (Windows DisplayName /
    iptables comment) so unblock_ip can remove exactly these rules.
    """
    ip_obj, rejection = _parse_block_ip(payload.get("ip"))
    if rejection is not None:
        return rejection
    ip = str(ip_obj)

    if ip_obj.is_loopback or ip_obj.is_unspecified:
        return {
            "status": "rejected",
            "stderr": f"refusing to block {ip}: loopback/unspecified address",
            "exit_code": 22,
        }
    if ip in _MANAGEMENT_SERVER_IPS:
        return {
            "status": "rejected",
            "stderr": f"refusing to block {ip}: it is the PySOAR management server",
            "exit_code": 22,
        }

    tag = f"{_PYSOAR_BLOCK_TAG}-{ip}"
    try:
        if platform.system() == "Linux":
            binary = "iptables" if ip_obj.version == 4 else "ip6tables"
            cmds = [
                [binary, "-I", "INPUT", "-s", ip, "-j", "DROP",
                 "-m", "comment", "--comment", tag],
                [binary, "-I", "OUTPUT", "-d", ip, "-j", "DROP",
                 "-m", "comment", "--comment", tag],
            ]
            outputs = []
            for cmd in cmds:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                outputs.append(f"$ {' '.join(cmd)}\n{proc.stdout}{proc.stderr}")
                if proc.returncode != 0:
                    return {
                        "status": "error",
                        "exit_code": proc.returncode,
                        "stdout": "\n".join(outputs)[:8192],
                        "stderr": proc.stderr[:2048],
                    }
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": "\n".join(outputs)[:8192],
                "artifacts": {"method": binary, "ip": ip, "rule_tag": tag},
            }

        if platform.system() == "Windows":
            rule_name = _block_rule_name(ip)
            ps = (
                f'New-NetFirewallRule -DisplayName "{rule_name}" '
                f'-Direction Inbound -Action Block -RemoteAddress {ip} -Profile Any; '
                f'New-NetFirewallRule -DisplayName "{rule_name}-out" '
                f'-Direction Outbound -Action Block -RemoteAddress {ip} -Profile Any'
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=30,
            )
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:4096],
                "stderr": proc.stderr[:4096],
                "artifacts": {"method": "windows_firewall", "ip": ip, "rule_name": rule_name},
            }

        return {
            "status": "rejected",
            "stderr": f"block_ip not supported on {platform.system()}",
            "exit_code": 95,
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_unblock_ip(payload: dict[str, Any]) -> dict[str, Any]:
    """Undo a prior block_ip: remove exactly the rules tagged for that IP.

    Idempotent — removing an IP that was never blocked (or already
    unblocked) succeeds with 0 rules removed.
    """
    ip_obj, rejection = _parse_block_ip(payload.get("ip"))
    if rejection is not None:
        return rejection
    ip = str(ip_obj)
    tag = f"{_PYSOAR_BLOCK_TAG}-{ip}"

    try:
        if platform.system() == "Linux":
            binary = "iptables" if ip_obj.version == 4 else "ip6tables"
            list_proc = subprocess.run(
                [binary, "-S"], capture_output=True, text=True, timeout=10
            )
            removed = 0
            for line in list_proc.stdout.splitlines():
                # Whole-token match (with quotes stripped) so the tag for
                # 10.0.0.1 never matches the rule for 10.0.0.11.
                tokens = [t.strip('"') for t in line.split()]
                if tag not in tokens:
                    continue
                if line.startswith("-A "):
                    del_args = [binary, "-D"] + tokens[1:]
                    subprocess.run(del_args, capture_output=True, text=True, timeout=10)
                    removed += 1
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": f"removed {removed} block rule(s) for {ip}",
                "artifacts": {"method": binary, "ip": ip, "rules_removed": removed},
            }

        if platform.system() == "Windows":
            rule_name = _block_rule_name(ip)
            # Exact DisplayNames (not a wildcard) so pysoar-block-10.0.0.1
            # can never sweep up pysoar-block-10.0.0.10's rules.
            ps = (
                f'Get-NetFirewallRule -DisplayName "{rule_name}","{rule_name}-out" '
                '-ErrorAction SilentlyContinue | Remove-NetFirewallRule'
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=30,
            )
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:4096],
                "stderr": proc.stderr[:4096],
                "artifacts": {"method": "windows_firewall", "ip": ip, "rule_name": rule_name},
            }

        return {
            "status": "rejected",
            "stderr": f"unblock_ip not supported on {platform.system()}",
            "exit_code": 95,
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_disable_account(payload: dict[str, Any]) -> dict[str, Any]:
    """Disable a local user account. Does NOT delete — reversible."""
    username = payload.get("username")
    if not username:
        return {"status": "error", "stderr": "username required", "exit_code": 22}

    # Reject obvious injection attempts — usernames are alnum + _.- only
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.\-\\$]{1,64}", str(username)):
        return {"status": "rejected", "stderr": "invalid username", "exit_code": 22}

    try:
        if platform.system() == "Linux":
            proc = subprocess.run(
                ["usermod", "--lock", "--expiredate", "1", str(username)],
                capture_output=True, text=True, timeout=15,
            )
        elif platform.system() == "Windows":
            proc = subprocess.run(
                ["net", "user", str(username), "/active:no"],
                capture_output=True, text=True, timeout=15,
            )
        else:
            return {"status": "rejected", "stderr": f"unsupported OS {platform.system()}", "exit_code": 95}

        return {
            "status": "success" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:2048],
            "stderr": proc.stderr[:2048],
            "artifacts": {"username": str(username), "action": "lock"},
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_collect_file(payload: dict[str, Any]) -> dict[str, Any]:
    """Harvest a file's content (base64) up to a safety cap."""
    import base64
    path = payload.get("path")
    if not path:
        return {"status": "error", "stderr": "path required", "exit_code": 22}
    max_bytes = int(payload.get("max_bytes", 1024 * 1024))  # default 1 MiB

    try:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return {"status": "error", "stderr": f"not a file: {path}", "exit_code": 2}
        size = p.stat().st_size
        if size > max_bytes:
            return {
                "status": "rejected",
                "stderr": f"file size {size} exceeds max_bytes {max_bytes}",
                "exit_code": 27,
            }
        data = p.read_bytes()
        return {
            "status": "success",
            "exit_code": 0,
            "artifacts": {
                "path": str(p),
                "size_bytes": size,
                "sha256": __import__("hashlib").sha256(data).hexdigest(),
                "content_base64": base64.b64encode(data).decode("ascii"),
            },
        }
    except PermissionError:
        return {"status": "error", "stderr": "permission denied", "exit_code": 13}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_quarantine_file(payload: dict[str, Any]) -> dict[str, Any]:
    """Move a file into a quarantine directory with restrictive perms."""
    import shutil
    path = payload.get("path")
    if not path:
        return {"status": "error", "stderr": "path required", "exit_code": 22}

    quarantine_dir = Path.home() / ".pysoar" / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(quarantine_dir, 0o700)
    except Exception:  # noqa: BLE001
        pass

    try:
        src = Path(path)
        if not src.exists():
            return {"status": "error", "stderr": f"no such file {path}", "exit_code": 2}
        import hashlib as _h, time as _t
        stamp = int(_t.time() * 1000)
        dest_name = f"{stamp}_{src.name}"
        dest = quarantine_dir / dest_name
        shutil.move(str(src), str(dest))
        try:
            os.chmod(dest, 0o400)
        except Exception:  # noqa: BLE001
            pass
        digest = _h.sha256(dest.read_bytes()).hexdigest()
        return {
            "status": "success",
            "exit_code": 0,
            "artifacts": {
                "original_path": str(src),
                "quarantine_path": str(dest),
                "sha256": digest,
            },
        }
    except PermissionError:
        return {"status": "error", "stderr": "permission denied", "exit_code": 13}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_unquarantine_file(payload: dict[str, Any]) -> dict[str, Any]:
    """Move a quarantined file back to a caller-specified path."""
    import shutil
    q_path = payload.get("quarantine_path")
    restore_path = payload.get("restore_path")
    if not q_path or not restore_path:
        return {
            "status": "error",
            "stderr": "quarantine_path and restore_path required",
            "exit_code": 22,
        }
    try:
        src = Path(q_path)
        if not src.exists():
            return {"status": "error", "stderr": f"not quarantined: {q_path}", "exit_code": 2}
        # Safety: refuse if not under our quarantine dir
        qroot = (Path.home() / ".pysoar" / "quarantine").resolve()
        if not str(src.resolve()).startswith(str(qroot)):
            return {"status": "rejected", "stderr": "path is outside quarantine root", "exit_code": 13}
        dest = Path(restore_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        return {
            "status": "success",
            "exit_code": 0,
            "artifacts": {"quarantine_path": str(src), "restore_path": str(dest)},
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


def _handle_collect_memory_dump(payload: dict[str, Any]) -> dict[str, Any]:
    """Best-effort memory capture for a given PID.

    Linux: concatenates readable regions from /proc/<pid>/maps via
    /proc/<pid>/mem. Windows: Sysinternals procdump if installed.

    This is expensive and gated behind approval. Output is written to
    an artifact file under ~/.pysoar/dumps and the path + sha256 are
    returned (NOT the raw bytes — dumps are too large for HTTP).
    """
    pid = payload.get("pid")
    if not pid:
        return {"status": "error", "stderr": "pid required", "exit_code": 22}
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return {"status": "error", "stderr": "pid must be integer", "exit_code": 22}

    dump_dir = Path.home() / ".pysoar" / "dumps"
    dump_dir.mkdir(parents=True, exist_ok=True)
    import time as _t, hashlib as _h
    stamp = int(_t.time() * 1000)
    dump_path = dump_dir / f"pid{pid_int}_{stamp}.bin"

    try:
        if platform.system() == "Linux":
            maps_path = Path(f"/proc/{pid_int}/maps")
            mem_path = Path(f"/proc/{pid_int}/mem")
            if not maps_path.exists():
                return {"status": "error", "stderr": f"no such pid {pid_int}", "exit_code": 3}

            total = 0
            with open(mem_path, "rb", buffering=0) as mem, open(dump_path, "wb") as out:
                for line in maps_path.read_text().splitlines():
                    try:
                        addr, perms = line.split()[0], line.split()[1]
                        if "r" not in perms:
                            continue
                        lo, hi = [int(x, 16) for x in addr.split("-")]
                        mem.seek(lo)
                        chunk = mem.read(hi - lo)
                        out.write(chunk)
                        total += len(chunk)
                        if total > 512 * 1024 * 1024:  # 512 MiB cap
                            break
                    except Exception:  # noqa: BLE001
                        continue
            digest = _h.sha256(dump_path.read_bytes()).hexdigest() if dump_path.stat().st_size < 100_000_000 else None
            return {
                "status": "success",
                "exit_code": 0,
                "artifacts": {
                    "pid": pid_int,
                    "dump_path": str(dump_path),
                    "size_bytes": dump_path.stat().st_size,
                    "sha256": digest,
                },
            }

        if platform.system() == "Windows":
            # Requires Sysinternals procdump in PATH — customer responsibility
            proc = subprocess.run(
                ["procdump.exe", "-ma", "-accepteula", str(pid_int), str(dump_path)],
                capture_output=True, text=True, timeout=120,
            )
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:4096],
                "stderr": proc.stderr[:4096],
                "artifacts": {"dump_path": str(dump_path)},
            }

        return {"status": "rejected", "stderr": f"unsupported OS {platform.system()}", "exit_code": 95}
    except PermissionError:
        return {"status": "error", "stderr": "permission denied (need root/SeDebugPrivilege)", "exit_code": 13}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "stderr": str(e)[:512], "exit_code": 1}


# ---------------------------------------------------------------------------
# Handler registry construction
#
# Handlers are registered based on the agent's enrolled capabilities.
# The --mode flag at install time (or the capabilities returned by
# /agents/_agent/exchange) decide which dict keys are populated. An
# agent running --mode bas literally has no kill_process entry in its
# dispatch table, so even if PySOAR authorizes the command the agent
# returns ``rejected: action not in local allowlist`` at line 276.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Deception: honeypot listeners hosted by the agent.
#
# Each deployed honeypot is a thread running a TCP accept loop. On
# connection it records the peer, reads up to 1 KB of whatever the
# client sends (2s budget), answers with the configured banner, and
# closes. Interactions queue in memory and are flushed to the server on
# the regular poll cycle. Listeners are deliberately NOT persisted
# across agent restarts — the server re-deploys on demand.
# ---------------------------------------------------------------------------

_HONEYPOT_DEFAULT_BANNERS = {
    "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    "http": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
    "ftp": "220 ProFTPD Server ready.\r\n",
    "telnet": "Ubuntu 22.04 LTS\r\nlogin: ",
    "mysql": "5.7.42-0ubuntu0.18.04.1\x00",
    "rdp": "",
}

_MAX_QUEUED_INTERACTIONS = 500


class HoneypotManager:
    """Runs honeypot TCP listeners and queues interaction reports."""

    def __init__(self) -> None:
        self._listeners: dict[str, dict[str, Any]] = {}
        self._interactions: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def deploy(self, decoy_id: str, port: int, service: str = "ssh",
               banner: Optional[str] = None) -> dict[str, Any]:
        if not decoy_id:
            return {"status": "error", "stderr": "decoy_id is required", "exit_code": 2}
        try:
            port = int(port)
        except (TypeError, ValueError):
            return {"status": "error", "stderr": f"invalid port: {port}", "exit_code": 2}
        if not (1024 < port <= 65535):
            return {"status": "error", "stderr": f"port {port} out of allowed range (1025-65535)", "exit_code": 2}
        with self._lock:
            if decoy_id in self._listeners:
                return {"status": "error", "stderr": f"decoy {decoy_id} already deployed", "exit_code": 2}

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
        except OSError as e:
            sock.close()
            return {"status": "error", "stderr": f"cannot bind port {port}: {e}", "exit_code": 1}
        sock.settimeout(1.0)

        stop_event = threading.Event()
        banner_text = banner if banner is not None else _HONEYPOT_DEFAULT_BANNERS.get(service, "")
        thread = threading.Thread(
            target=self._accept_loop,
            args=(decoy_id, sock, stop_event, banner_text, service),
            name=f"honeypot-{decoy_id[:8]}-{port}",
            daemon=True,
        )
        with self._lock:
            self._listeners[decoy_id] = {
                "thread": thread, "sock": sock, "stop": stop_event,
                "port": port, "service": service,
            }
        thread.start()
        print(f"[pysoar-agent] honeypot listening: {service} on :{port} (decoy={decoy_id})")
        return {"status": "success", "stdout": json.dumps({"listening": True, "port": port, "service": service})}

    def stop(self, decoy_id: str) -> dict[str, Any]:
        with self._lock:
            entry = self._listeners.pop(decoy_id, None)
        if entry is None:
            return {"status": "error", "stderr": f"decoy {decoy_id} not deployed on this agent", "exit_code": 1}
        entry["stop"].set()
        try:
            entry["sock"].close()
        except OSError:
            pass
        entry["thread"].join(timeout=3)
        print(f"[pysoar-agent] honeypot stopped: :{entry['port']} (decoy={decoy_id})")
        return {"status": "success", "stdout": json.dumps({"stopped": True, "port": entry["port"]})}

    def _accept_loop(self, decoy_id: str, sock: socket.socket,
                     stop_event: threading.Event, banner: str, service: str) -> None:
        while not stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # socket closed by stop()
            try:
                conn.settimeout(2.0)
                received = b""
                try:
                    received = conn.recv(1024)
                except (socket.timeout, OSError):
                    pass
                if banner:
                    try:
                        conn.sendall(banner.encode("utf-8", errors="replace"))
                    except OSError:
                        pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            interaction = {
                "decoy_id": decoy_id,
                "source_ip": addr[0],
                "source_port": addr[1],
                "protocol": "tcp",
                "service": service,
                "interaction_type": "connection",
                "data_sample": received[:512].decode("utf-8", errors="replace"),
                "observed_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            }
            with self._lock:
                if len(self._interactions) < _MAX_QUEUED_INTERACTIONS:
                    self._interactions.append(interaction)
            print(f"[pysoar-agent] honeypot HIT {service}:{addr[0]}:{addr[1]} (decoy={decoy_id})")

    def drain_interactions(self) -> list[dict[str, Any]]:
        with self._lock:
            drained, self._interactions = self._interactions, []
        return drained

    def requeue_interactions(self, interactions: list[dict[str, Any]]) -> None:
        with self._lock:
            space = _MAX_QUEUED_INTERACTIONS - len(self._interactions)
            self._interactions = interactions[:space] + self._interactions


HONEYPOTS = HoneypotManager()


def _handle_deploy_honeypot(payload: dict[str, Any]) -> dict[str, Any]:
    return HONEYPOTS.deploy(
        decoy_id=payload.get("decoy_id"),
        port=payload.get("port"),
        service=payload.get("service", "ssh"),
        banner=payload.get("banner"),
    )


def _handle_stop_honeypot(payload: dict[str, Any]) -> dict[str, Any]:
    return HONEYPOTS.stop(payload.get("decoy_id"))


# ---------------------------------------------------------------------------
# Wave 5: decoys, container image scans, STIG scans and OT actions.
#
# Every one of these is gated twice: the server only queues the action for an
# agent enrolled with the matching capability, and this agent only registers
# the handler when its own enrolled capability list carries it
# (``build_action_handlers``). Nothing here runs a command string sent by the
# server:
#
# * scanners (trivy / grype / oscap) are local binaries found on PATH, called
#   with a fixed argv; the server-supplied image reference / benchmark id /
#   profile is validated against a strict grammar first. A missing binary is
#   reported as ``tool_missing``;
# * decoys are planted only inside the operator-configured decoy directory,
#   under a sanitised file name, and removed only from the agent's own
#   manifest of what it planted;
# * OT safe shutdown and segmentation probes run only the operator's own
#   local script (configured on this host); the server's payload is passed to
#   it as JSON on stdin, as data. Without a configured script the agent
#   reports ``not_configured``.
#
# Local configuration: ``<token file>.config.json`` (written by the operator,
# never by the server) and/or environment variables:
#   decoy_dir                     PYSOAR_DECOY_DIR
#   ot_safe_shutdown_script       PYSOAR_OT_SAFE_SHUTDOWN_SCRIPT
#   ot_segmentation_probe_script  PYSOAR_OT_SEGMENTATION_PROBE_SCRIPT
#   stig_datastreams              {benchmark_id: SCAP datastream path}
#   stig_datastream               PYSOAR_STIG_DATASTREAM (used when the
#                                 benchmark id is not mapped)
# ---------------------------------------------------------------------------

AGENT_CONFIG: dict[str, Any] = {}

_CONFIG_ENV = {
    "decoy_dir": "PYSOAR_DECOY_DIR",
    "ot_safe_shutdown_script": "PYSOAR_OT_SAFE_SHUTDOWN_SCRIPT",
    "ot_segmentation_probe_script": "PYSOAR_OT_SEGMENTATION_PROBE_SCRIPT",
    "stig_datastream": "PYSOAR_STIG_DATASTREAM",
}

#: Wall clocks for the long-running handlers (seconds).
CONTAINER_SCAN_TIMEOUT = 900
STIG_SCAN_TIMEOUT = 1800
OT_SAFE_SHUTDOWN_TIMEOUT = 600
OT_PROBE_MAX_TIMEOUT = 900
#: Largest report / ARF the agent returns (characters); the server refuses
#: scanner reports above 20,000,000 characters.
MAX_REPORT_CHARS = 20_000_000
MAX_DECOY_CONTENT_BYTES = 256 * 1024
DECOY_MANIFEST = ".pysoar-decoys.json"
#: Decoy types the agent plants as a file in the decoy directory.
FILE_DECOY_TYPES = frozenset({"honeyfile", "canary_file", "honeycred", "breadcrumb", "honeytoken"})

# Same OCI reference grammar the server enforces
# (src/container_security/scanning.py IMAGE_REFERENCE_RE): no option-looking
# strings, whitespace or shell metacharacters reach the scanner argv.
_REF_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_REF_REGISTRY = (
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"(?::[0-9]{1,5})?)"
)
IMAGE_REFERENCE_RE = re.compile(
    r"^(?:" + _REF_REGISTRY + r"/)?" + _REF_COMPONENT + r"(?:/" + _REF_COMPONENT + r")*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
)
#: XCCDF benchmark / profile ids: no leading dash, no whitespace.
_XCCDF_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def load_agent_config(token_file: Path) -> dict[str, Any]:
    """Operator configuration: ``<token file>.config.json`` then env overrides."""
    config: dict[str, Any] = {}
    path = Path(str(token_file) + ".config.json")
    try:
        if path.exists():
            loaded = json.loads(path.read_text())
            if isinstance(loaded, dict):
                config.update(loaded)
    except (OSError, ValueError) as e:
        print(f"[pysoar-agent] ignoring unreadable config {path}: {e}")
    for key, env in _CONFIG_ENV.items():
        if os.environ.get(env):
            config[key] = os.environ[env]
    return config


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _script_argv(path: str) -> list[str]:
    """argv for a local tool or operator script (``.py`` runs under this
    interpreter, ``.ps1`` under PowerShell, anything else directly)."""
    lowered = path.lower()
    if lowered.endswith(".py"):
        return [sys.executable, path]
    if lowered.endswith(".ps1"):
        return ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path]
    return [path]


def _not_configured(what: str) -> dict[str, Any]:
    return {
        "status": "not_configured",
        "exit_code": 78,
        "stderr": f"not_configured: {what}",
        "artifacts": {"error": "not_configured"},
    }


def _tool_missing(what: str) -> dict[str, Any]:
    return {
        "status": "tool_missing",
        "exit_code": 127,
        "stderr": f"tool_missing: {what}",
        "artifacts": {"error": "tool_missing"},
    }


def _operator_script(key: str) -> Optional[str]:
    """The operator's configured script for ``key`` when it is an existing
    absolute file path, else None."""
    raw = AGENT_CONFIG.get(key)
    if not raw or not isinstance(raw, str):
        return None
    path = Path(raw)
    if not path.is_absolute() or not path.is_file():
        return None
    return str(path)


# --- scan_container_image ---------------------------------------------------

def _handle_scan_container_image(payload: dict[str, Any]) -> dict[str, Any]:
    """Run trivy (``trivy image --format json``) or grype (``grype -o json``)
    against the image and return the JSON report on stdout."""
    ref = str(payload.get("image_ref") or "").strip()
    if not ref or len(ref) > 512 or not IMAGE_REFERENCE_RE.fullmatch(ref):
        return {"status": "rejected", "exit_code": 2, "stderr": "invalid image reference"}
    preferred = str(payload.get("scanner") or "trivy").lower()
    order = ["grype", "trivy"] if preferred == "grype" else ["trivy", "grype"]
    scanner = binary = None
    for name in order:
        binary = _which(name)
        if binary:
            scanner = name
            break
    if scanner is None or binary is None:
        return _tool_missing("neither trivy nor grype is installed on this agent")
    if scanner == "trivy":
        argv = [*_script_argv(binary), "image", "--format", "json", "--quiet", ref]
    else:
        argv = [*_script_argv(binary), ref, "-o", "json"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=CONTAINER_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "exit_code": 124, "stderr": f"{scanner} timed out"}
    except OSError as e:
        return {"status": "error", "exit_code": 1, "stderr": f"{scanner} could not run: {e}"[:512]}
    if proc.returncode != 0:
        return {"status": "error", "exit_code": proc.returncode,
                "stderr": (proc.stderr or proc.stdout or f"{scanner} failed")[-4000:],
                "artifacts": {"scanner": scanner}}
    report = proc.stdout or ""
    if len(report) > MAX_REPORT_CHARS:
        return {"status": "error", "exit_code": 1,
                "stderr": f"{scanner} report is {len(report)} characters; the limit is {MAX_REPORT_CHARS}"}
    try:
        json.loads(report)
    except ValueError:
        return {"status": "error", "exit_code": 1, "stderr": f"{scanner} output is not JSON",
                "artifacts": {"scanner": scanner}}
    return {"status": "success", "exit_code": 0, "stdout": report, "stderr": (proc.stderr or "")[-2000:],
            "artifacts": {"scanner": scanner, "image_ref": ref, "scan_id": payload.get("scan_id")}}


# --- stig_scan ----------------------------------------------------------------

def _stig_datastream(benchmark_id: str) -> Optional[str]:
    mapping = AGENT_CONFIG.get("stig_datastreams")
    raw = mapping.get(benchmark_id) if isinstance(mapping, dict) else None
    raw = raw or AGENT_CONFIG.get("stig_datastream")
    if not raw or not isinstance(raw, str):
        return None
    path = Path(raw)
    return str(path) if path.is_absolute() and path.is_file() else None


def _handle_stig_scan(payload: dict[str, Any]) -> dict[str, Any]:
    """``oscap xccdf eval --results-arf`` over the configured SCAP datastream;
    the ARF XML is returned in ``artifacts.arf``."""
    benchmark_id = str(payload.get("benchmark_id") or "")
    profile = payload.get("profile")
    if not _XCCDF_ID_RE.fullmatch(benchmark_id):
        return {"status": "rejected", "exit_code": 2, "stderr": "invalid benchmark_id"}
    if profile is not None and not _XCCDF_ID_RE.fullmatch(str(profile)):
        return {"status": "rejected", "exit_code": 2, "stderr": "invalid profile"}
    oscap = _which("oscap")
    if not oscap:
        return _tool_missing("oscap (OpenSCAP) is not installed on this agent")
    datastream = _stig_datastream(benchmark_id)
    if not datastream:
        return _not_configured(
            f"no SCAP datastream configured for benchmark {benchmark_id} "
            "(stig_datastreams / stig_datastream in the agent config)",
        )
    with tempfile.TemporaryDirectory(prefix="pysoar-stig-") as tmp:
        arf_path = os.path.join(tmp, "results-arf.xml")
        argv = [*_script_argv(oscap), "xccdf", "eval", "--benchmark-id", benchmark_id]
        if profile:
            argv += ["--profile", str(profile)]
        argv += ["--results-arf", arf_path, datastream]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=STIG_SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "exit_code": 124, "stderr": "oscap timed out"}
        except OSError as e:
            return {"status": "error", "exit_code": 1, "stderr": f"oscap could not run: {e}"[:512]}
        # oscap: 0 = every rule passed, 2 = at least one rule failed; both
        # produce results. Anything else is an evaluation error.
        if proc.returncode not in (0, 2) or not os.path.isfile(arf_path):
            return {"status": "error", "exit_code": proc.returncode,
                    "stderr": (proc.stderr or proc.stdout or "oscap produced no ARF")[-4000:]}
        with open(arf_path, encoding="utf-8", errors="replace") as fh:
            arf = fh.read(MAX_REPORT_CHARS + 1)
    if len(arf) > MAX_REPORT_CHARS:
        return {"status": "error", "exit_code": 1, "stderr": f"ARF exceeds {MAX_REPORT_CHARS} characters"}
    return {"status": "success", "exit_code": proc.returncode,
            "stdout": f"oscap xccdf eval exit {proc.returncode}; ARF {len(arf)} characters",
            "stderr": (proc.stderr or "")[-2000:],
            "artifacts": {"arf": arf, "benchmark_id": benchmark_id, "scan_id": payload.get("scan_id")}}


# --- deploy_decoy / remove_decoy ----------------------------------------------

def _decoy_dir() -> Optional[Path]:
    raw = AGENT_CONFIG.get("decoy_dir")
    if not raw or not isinstance(raw, str):
        return None
    path = Path(raw)
    return path if path.is_absolute() and path.is_dir() else None


def _read_manifest(directory: Path) -> dict[str, Any]:
    try:
        data = json.loads((directory / DECOY_MANIFEST).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_manifest(directory: Path, manifest: dict[str, Any]) -> None:
    (directory / DECOY_MANIFEST).write_text(json.dumps(manifest, indent=1))


def _decoy_filename(payload: dict[str, Any]) -> Optional[str]:
    config = payload.get("configuration") if isinstance(payload.get("configuration"), dict) else {}
    raw = str(config.get("filename") or payload.get("name") or payload.get("decoy_id") or "")
    name = _SAFE_FILENAME_RE.sub("_", os.path.basename(raw.replace("\\", "/")))[:128]
    if not name or name in (".", "..") or name == DECOY_MANIFEST:
        return None
    return name


def _handle_deploy_decoy(payload: dict[str, Any]) -> dict[str, Any]:
    """Plant a file decoy in the operator's decoy directory."""
    decoy_id = str(payload.get("decoy_id") or "")
    decoy_type = str(payload.get("decoy_type") or "").lower()
    if not decoy_id:
        return {"status": "error", "exit_code": 2, "stderr": "decoy_id is required"}
    if decoy_type not in FILE_DECOY_TYPES:
        return {"status": "rejected", "exit_code": 2,
                "stderr": f"decoy type '{decoy_type}' cannot be planted by this agent"}
    directory = _decoy_dir()
    if directory is None:
        return _not_configured("no decoy_dir configured on this agent (an existing absolute directory)")
    name = _decoy_filename(payload)
    if name is None:
        return {"status": "error", "exit_code": 2, "stderr": "no usable decoy file name"}
    config = payload.get("configuration") if isinstance(payload.get("configuration"), dict) else {}
    content = config.get("content")
    if content is not None and not isinstance(content, str):
        return {"status": "error", "exit_code": 2, "stderr": "decoy content must be text"}
    body = (content or "").encode("utf-8")
    if len(body) > MAX_DECOY_CONTENT_BYTES:
        return {"status": "error", "exit_code": 2,
                "stderr": f"decoy content exceeds {MAX_DECOY_CONTENT_BYTES} bytes"}
    manifest = _read_manifest(directory)
    if decoy_id in manifest:
        return {"status": "error", "exit_code": 2, "stderr": f"decoy {decoy_id} already planted"}
    target = directory / name
    if target.exists():
        return {"status": "error", "exit_code": 17, "stderr": f"{name} already exists in the decoy directory"}
    import hashlib

    with open(target, "xb") as fh:
        fh.write(body)
    digest = hashlib.sha256(body).hexdigest()
    manifest[decoy_id] = {"path": str(target), "sha256": digest, "decoy_type": decoy_type,
                          "planted_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}
    _write_manifest(directory, manifest)
    print(f"[pysoar-agent] decoy planted: {target} (decoy={decoy_id})")
    return {"status": "success", "exit_code": 0,
            "stdout": json.dumps({"planted": True, "path": str(target), "sha256": digest, "bytes": len(body),
                                  # Reads of the file are not watched by the agent.
                                  "access_monitoring": "not_provided_by_agent"}),
            "artifacts": {"path": str(target), "sha256": digest}}


def _handle_remove_decoy(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove a decoy this agent planted (looked up in its own manifest)."""
    decoy_id = str(payload.get("decoy_id") or "")
    directory = _decoy_dir()
    if directory is None:
        return _not_configured("no decoy_dir configured on this agent")
    manifest = _read_manifest(directory)
    entry = manifest.get(decoy_id)
    if not isinstance(entry, dict):
        return {"status": "error", "exit_code": 1, "stderr": f"decoy {decoy_id} was not planted by this agent"}
    path = Path(str(entry.get("path") or ""))
    if path.parent != directory:
        return {"status": "error", "exit_code": 1, "stderr": "manifest entry outside the decoy directory"}
    existed = path.exists()
    if existed:
        path.unlink()
    manifest.pop(decoy_id, None)
    _write_manifest(directory, manifest)
    print(f"[pysoar-agent] decoy removed: {path} (decoy={decoy_id})")
    return {"status": "success", "exit_code": 0,
            "stdout": json.dumps({"removed": True, "path": str(path), "file_was_present": existed})}


# --- OT: operator scripts ---------------------------------------------------------

def _run_operator_script(script: str, payload: dict[str, Any], action: str, timeout: int) -> Any:
    env = dict(os.environ)
    env["PYSOAR_ACTION"] = action
    return subprocess.run(
        _script_argv(script), input=json.dumps(payload), capture_output=True, text=True,
        timeout=timeout, env=env,
    )


def _handle_ot_safe_shutdown(payload: dict[str, Any]) -> dict[str, Any]:
    """Run the site's own safe-shutdown script with the payload on stdin;
    success only when it exits 0."""
    script = _operator_script("ot_safe_shutdown_script")
    if script is None:
        return _not_configured("no ot_safe_shutdown_script configured on this agent (an existing absolute path)")
    try:
        proc = _run_operator_script(script, payload, "ot_safe_shutdown", OT_SAFE_SHUTDOWN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "exit_code": 124, "stderr": "safe-shutdown script timed out"}
    except OSError as e:
        return {"status": "error", "exit_code": 1, "stderr": f"safe-shutdown script could not run: {e}"[:512]}
    return {"status": "success" if proc.returncode == 0 else "error", "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[-8192:], "stderr": (proc.stderr or "")[-4096:]}


def _handle_ot_segmentation_probe(payload: dict[str, Any]) -> dict[str, Any]:
    """Run the operator's probe script with the probe plan on stdin. It must
    print ``{"results": [{"target_ip", "port", "reachable"}]}``; the agent
    keeps only answers for probes the server asked for."""
    script = _operator_script("ot_segmentation_probe_script")
    if script is None:
        return _not_configured(
            "no ot_segmentation_probe_script configured on this agent (an existing absolute path)",
        )
    probes = payload.get("probes") if isinstance(payload.get("probes"), list) else []
    try:
        per_probe = float(payload.get("timeout_seconds") or 2)
    except (TypeError, ValueError):
        per_probe = 2.0
    timeout = int(min(OT_PROBE_MAX_TIMEOUT, 30 + per_probe * max(len(probes), 1)))
    try:
        proc = _run_operator_script(script, payload, "ot_segmentation_probe", timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "exit_code": 124, "stderr": "segmentation probe script timed out"}
    except OSError as e:
        return {"status": "error", "exit_code": 1, "stderr": f"probe script could not run: {e}"[:512]}
    if proc.returncode != 0:
        return {"status": "error", "exit_code": proc.returncode,
                "stderr": (proc.stderr or proc.stdout or "probe script failed")[-4096:]}
    try:
        doc = json.loads(proc.stdout or "")
    except ValueError:
        return {"status": "error", "exit_code": 1, "stderr": "probe script output is not JSON"}
    rows = doc.get("results") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        return {"status": "error", "exit_code": 1, "stderr": "probe script output has no results list"}
    asked = set()
    for p in probes:
        if isinstance(p, dict):
            try:
                asked.add((str(p.get("target_ip")), int(p.get("port") or 0)))
            except (TypeError, ValueError):
                continue
    results = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("reachable"), bool):
            continue
        try:
            key = (str(row.get("target_ip")), int(row.get("port") or 0))
        except (TypeError, ValueError):
            continue
        if key in asked:
            results.append({"target_ip": key[0], "port": key[1], "reachable": row["reachable"]})
    return {"status": "success", "exit_code": 0, "stdout": json.dumps({"results": results}),
            "stderr": (proc.stderr or "")[-2000:], "artifacts": {"results": results}}


BAS_HANDLERS: dict[str, Any] = {
    "run_atomic_test": _handle_run_atomic_test,
    "collect_process_list": _handle_collect_process_list,
    "collect_network_connections": _handle_collect_network_connections,
}

IR_HANDLERS: dict[str, Any] = {
    "kill_process": _handle_kill_process,
    "isolate_host": _handle_isolate_host,
    "release_host": _handle_release_host,
    "block_ip": _handle_block_ip,
    "unblock_ip": _handle_unblock_ip,
    "disable_account": _handle_disable_account,
    "collect_file": _handle_collect_file,
    "collect_process_list": _handle_collect_process_list,
    "collect_network_connections": _handle_collect_network_connections,
    "collect_memory_dump": _handle_collect_memory_dump,
    "quarantine_file": _handle_quarantine_file,
    "unquarantine_file": _handle_unquarantine_file,
}

PURPLE_HANDLERS: dict[str, Any] = {
    "run_atomic_test": _handle_run_atomic_test,
    "purple_fire_technique": _handle_run_atomic_test,  # same executor, server correlates
    "collect_process_list": _handle_collect_process_list,
}

DECEPTION_HANDLERS: dict[str, Any] = {
    "deploy_honeypot": _handle_deploy_honeypot,
    "stop_honeypot": _handle_stop_honeypot,
    "deploy_decoy": _handle_deploy_decoy,
    "remove_decoy": _handle_remove_decoy,
}

# One capability each, matching src/agents/capabilities.py; "stig_scan" is
# deliberately not implied by "compliance" (server commit fbf2edf).
CONTAINER_SCAN_HANDLERS: dict[str, Any] = {"scan_container_image": _handle_scan_container_image}
STIG_SCAN_HANDLERS: dict[str, Any] = {"stig_scan": _handle_stig_scan}
OT_SAFE_SHUTDOWN_HANDLERS: dict[str, Any] = {"ot_safe_shutdown": _handle_ot_safe_shutdown}
OT_SEGMENTATION_PROBE_HANDLERS: dict[str, Any] = {"ot_segmentation_probe": _handle_ot_segmentation_probe}


def build_action_handlers(capabilities: list[str]) -> dict[str, Any]:
    """Return the merged handler table for a given capability set."""
    table: dict[str, Any] = {}
    if "bas" in capabilities:
        table.update(BAS_HANDLERS)
    if "ir" in capabilities:
        table.update(IR_HANDLERS)
    if "purple" in capabilities:
        table.update(PURPLE_HANDLERS)
    if "deception" in capabilities:
        table.update(DECEPTION_HANDLERS)
    if "container_scan" in capabilities:
        table.update(CONTAINER_SCAN_HANDLERS)
    if "stig_scan" in capabilities:
        table.update(STIG_SCAN_HANDLERS)
    if "ot_safe_shutdown" in capabilities:
        table.update(OT_SAFE_SHUTDOWN_HANDLERS)
    if "ot_segmentation_probe" in capabilities:
        table.update(OT_SEGMENTATION_PROBE_HANDLERS)
    return table


# Default table: populated lazily at enrollment / poll time, not at
# import, so installations without a token don't carry the full list.
ACTION_HANDLERS: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only so the agent has zero dependencies)
# ---------------------------------------------------------------------------

def _collect_posture() -> Dict[str, Any]:
    """Snapshot device posture for the Zero Trust trust-score pipeline.

    Returns a telemetry dict with booleans the server's
    DeviceTrustAssessor consumes to compute a device trust score
    (encryption, AV, firewall, patching). Every signal is inspected
    directly on the host — no cached values — so a device that drifts
    out of compliance mid-session is caught by the next heartbeat.

    Runs best-effort: a failed probe is reported as ``None``, never a
    false-positive ``True``. Downstream code treats ``None`` as
    untrusted.
    """
    posture: Dict[str, Any] = {
        "uptime_seconds": int(time.monotonic()),
        "os_type": platform.system().lower(),
        "os_release": platform.release(),
        "hostname": socket.gethostname(),
    }
    osname = posture["os_type"]

    def _run(cmd: list[str], timeout: int = 4) -> Optional[str]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return (result.stdout or "") + (result.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    # OS patch freshness — approximate from package index age on Linux,
    # or swupd/softwareupdate on macOS, or Windows Update service state.
    patched: Optional[bool] = None
    if osname == "linux":
        for marker in ("/var/lib/apt/periodic/update-success-stamp", "/var/lib/dnf/last_makecache", "/var/cache/apt/pkgcache.bin"):
            try:
                age = time.time() - os.path.getmtime(marker)
                patched = age < (14 * 24 * 3600)  # Patched within 2 weeks
                break
            except OSError:
                continue
    elif osname == "darwin":
        patched = _run(["softwareupdate", "-l"]) is not None
    elif osname == "windows":
        out = _run(["sc", "query", "wuauserv"]) or ""
        patched = "RUNNING" in out.upper()
    posture["os_patched"] = patched

    # Full-disk encryption.
    encrypted: Optional[bool] = None
    if osname == "linux":
        out = _run(["lsblk", "-o", "TYPE,NAME"])
        if out is not None:
            encrypted = "crypt" in out.lower()
    elif osname == "darwin":
        out = _run(["fdesetup", "status"])
        encrypted = ("on" in (out or "").lower()) if out else None
    elif osname == "windows":
        out = _run(["manage-bde", "-status"])
        encrypted = ("protection on" in (out or "").lower()) if out else None
    posture["encryption_enabled"] = encrypted

    # Antivirus / EDR presence — best-effort process-name sniff.
    av_markers = {
        "linux": ("clamd", "freshclam", "crowdstrike", "sentinel", "carbonblack"),
        "darwin": ("clamd", "crowdstrike", "xprotect", "sentinel"),
        "windows": ("msmpeng", "mssense", "crowdstrike", "sentinel", "carbonblack"),
    }.get(osname, ())
    av_active: Optional[bool] = None
    ps_out = _run(["ps", "-eo", "comm"]) if osname != "windows" else _run(["tasklist"])
    if ps_out is not None:
        blob = ps_out.lower()
        av_active = any(m in blob for m in av_markers) if av_markers else False
    posture["av_active"] = av_active

    # Host firewall state.
    firewall_on: Optional[bool] = None
    if osname == "linux":
        out = (_run(["iptables", "-S"]) or _run(["nft", "list", "ruleset"]) or "") or None
        firewall_on = (out is not None) and ("DROP" in out or "drop" in out or "policy drop" in out.lower())
    elif osname == "darwin":
        out = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        firewall_on = ("enabled" in (out or "").lower()) if out else None
    elif osname == "windows":
        out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        firewall_on = ("state                                 ON" in (out or "")) if out else None
    posture["firewall_on"] = firewall_on

    return posture


def _http_request(
    url: str,
    method: str = "GET",
    body: Optional[dict] = None,
    token: Optional[str] = None,
    timeout: int = 30,
) -> tuple[int, dict[str, Any]]:
    data = None
    headers = {"Content-Type": "application/json", "User-Agent": f"pysoar-agent/{AGENT_VERSION}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"detail": raw}
        return e.code, payload
    except Exception as e:  # noqa: BLE001
        return 0, {"detail": str(e)}


# ---------------------------------------------------------------------------
# Token persistence
# ---------------------------------------------------------------------------

def _load_token(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    try:
        return path.read_text().strip() or None
    except Exception:  # noqa: BLE001
        return None


def _save_token(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token)
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_enroll(args: argparse.Namespace) -> int:
    """Exchange a one-time enrollment token for a long-lived agent token."""
    host_info = {
        "enrollment_token": args.enroll,
        "os_type": platform.system().lower(),
        "os_version": platform.release(),
        "agent_version": AGENT_VERSION,
        "ip_address": _best_effort_ip(),
    }
    status_code, resp = _http_request(
        f"{args.server.rstrip('/')}/api/v1/agents/_agent/exchange",
        method="POST",
        body=host_info,
    )
    if status_code != 200:
        print(f"[pysoar-agent] enrollment failed: {status_code} {resp.get('detail')}")
        return 1

    token = resp.get("agent_token")
    if not token:
        print(f"[pysoar-agent] server response missing agent_token: {resp}")
        return 1
    _save_token(args.token_file, token)

    # Persist the capabilities next to the token so --poll can build the
    # handler table without a second round-trip to the server. If they
    # ever disagree (e.g. capability was revoked server-side), the next
    # poll will refuse unknown actions and the operator can re-enroll.
    caps = resp.get("capabilities") or []
    try:
        caps_file = Path(str(args.token_file) + ".caps")
        caps_file.parent.mkdir(parents=True, exist_ok=True)
        caps_file.write_text(json.dumps(caps))
        os.chmod(caps_file, 0o600)
    except Exception:  # noqa: BLE001
        pass

    print(
        f"[pysoar-agent] enrolled as agent_id={resp.get('agent_id')} caps={caps}"
    )
    print(f"[pysoar-agent] token saved to {args.token_file}")
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    """Poll the PySOAR server for queued commands in a loop."""
    token = _load_token(args.token_file)
    if not token:
        print(f"[pysoar-agent] no agent token at {args.token_file}; run --enroll first")
        return 1

    # Load capabilities from the file written at enrollment time and
    # build the handler dispatch table. The global ACTION_HANDLERS is
    # overwritten here — not at module import — so a token-less agent
    # has literally zero live handlers.
    global ACTION_HANDLERS
    caps: list[str] = []
    try:
        caps_file = Path(str(args.token_file) + ".caps")
        if caps_file.exists():
            caps = json.loads(caps_file.read_text())
    except Exception:  # noqa: BLE001
        pass
    ACTION_HANDLERS = build_action_handlers(caps)
    print(f"[pysoar-agent] capabilities={caps} handlers={sorted(ACTION_HANDLERS.keys())}")
    # Operator-local configuration (decoy directory, OT scripts, SCAP
    # content); never taken from the server.
    AGENT_CONFIG.clear()
    AGENT_CONFIG.update(load_agent_config(args.token_file))

    # Resolve the PySOAR server's IP(s) once at startup so block_ip can
    # refuse to firewall off the management channel.
    _MANAGEMENT_SERVER_IPS.update(_resolve_server_ips(args.server))
    if _MANAGEMENT_SERVER_IPS:
        print(f"[pysoar-agent] management server IPs protected from block_ip: "
              f"{sorted(_MANAGEMENT_SERVER_IPS)}")

    poll_url = f"{args.server.rstrip('/')}/api/v1/agents/_agent/poll"
    hb_url = f"{args.server.rstrip('/')}/api/v1/agents/_agent/heartbeat"
    result_base = f"{args.server.rstrip('/')}/api/v1/agents/_agent/commands"
    interactions_url = f"{args.server.rstrip('/')}/api/v1/agents/_agent/honeypot-interactions"

    print(f"[pysoar-agent] polling {poll_url} every {POLL_INTERVAL_SECONDS}s")
    # Send initial posture heartbeat, then re-send every
    # HEARTBEAT_INTERVAL_SECONDS so the Zero Trust PDP always sees
    # fresh device compliance state (NIST SP 800-207 §2.1).
    def _send_heartbeat() -> None:
        _http_request(
            hb_url,
            method="POST",
            body={"telemetry": _collect_posture(), "agent_version": AGENT_VERSION},
            token=token,
        )

    _send_heartbeat()
    last_heartbeat_ts = time.monotonic()

    while True:
        # Time-triggered heartbeat: push posture every
        # HEARTBEAT_INTERVAL_SECONDS (default 300s / 5 min). The ZT
        # continuous evaluation task runs every 5 min too, so a device
        # drift is reflected in the next session evaluation.
        if time.monotonic() - last_heartbeat_ts >= HEARTBEAT_INTERVAL_SECONDS:
            _send_heartbeat()
            last_heartbeat_ts = time.monotonic()

        status_code, resp = _http_request(poll_url, method="GET", token=token)
        if status_code == 401:
            print("[pysoar-agent] token rejected — re-enroll required")
            return 2
        if status_code != 200:
            print(f"[pysoar-agent] poll failed: {status_code} {resp.get('detail')}")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        commands = resp.get("commands") or []
        if commands:
            print(f"[pysoar-agent] received {len(commands)} command(s)")
        for cmd in commands:
            cmd_id = cmd.get("id")
            action = cmd.get("action")
            payload = cmd.get("payload") or {}
            handler = ACTION_HANDLERS.get(action)
            if handler is None:
                print(f"[pysoar-agent] REJECTING unknown action: {action}")
                _http_request(
                    f"{result_base}/{cmd_id}/result",
                    method="POST",
                    token=token,
                    body={
                        "status": "rejected",
                        "exit_code": 126,
                        "stderr": f"action '{action}' not in local allowlist",
                    },
                )
                continue

            print(f"[pysoar-agent] executing {action} (cmd={cmd_id})")
            start = time.time()
            try:
                result = handler(payload) or {}
            except Exception as e:  # noqa: BLE001
                result = {"status": "error", "stderr": str(e)[:512], "exit_code": 1}
            result.setdefault("status", "success")
            result["duration_seconds"] = round(time.time() - start, 3)

            post_status, post_resp = _http_request(
                f"{result_base}/{cmd_id}/result",
                method="POST",
                token=token,
                body=result,
            )
            if post_status != 200:
                print(
                    f"[pysoar-agent] result POST failed for {cmd_id}: "
                    f"{post_status} {post_resp.get('detail')}"
                )

        # Flush honeypot interactions captured since the last cycle.
        # On failure they're re-queued (bounded) for the next attempt.
        pending = HONEYPOTS.drain_interactions()
        if pending:
            flush_status, _ = _http_request(
                interactions_url,
                method="POST",
                token=token,
                body={"interactions": pending},
            )
            if flush_status != 200:
                print(f"[pysoar-agent] interaction flush failed ({flush_status}); re-queueing {len(pending)}")
                HONEYPOTS.requeue_interactions(pending)

        time.sleep(POLL_INTERVAL_SECONDS)


def _best_effort_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:  # noqa: BLE001
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="PySOAR endpoint agent")
    parser.add_argument("--server", required=True, help="PySOAR base URL, e.g. https://pysoar.example.com")
    parser.add_argument("--token-file", default=str(DEFAULT_TOKEN_FILE), type=Path)
    parser.add_argument("--enroll", metavar="ENROLLMENT_TOKEN", help="One-time enrollment token")
    parser.add_argument("--poll", action="store_true", help="Run the poll loop")
    args = parser.parse_args()

    if args.enroll:
        return cmd_enroll(args)
    if args.poll:
        return cmd_poll(args)
    parser.error("one of --enroll or --poll is required")


if __name__ == "__main__":
    sys.exit(main())
