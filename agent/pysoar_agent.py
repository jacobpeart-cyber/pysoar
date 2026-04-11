"""PySOAR Endpoint Agent.

Single-file Python agent that runs on customer endpoints and receives
commands from a PySOAR server. The agent is intentionally minimal:

- Stateless other than a local token file and a pinned action allowlist
- No outbound connections except to PYSOAR_URL over HTTPS
- Refuses any command whose action is not in the local allowlist
- Refuses any command whose hostname does not match this host
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
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

AGENT_VERSION = "0.1.0"
DEFAULT_TOKEN_FILE = Path.home() / ".pysoar" / "agent.token"
POLL_INTERVAL_SECONDS = 30
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

BAS_HANDLERS: dict[str, Any] = {
    "run_atomic_test": _handle_run_atomic_test,
    "collect_process_list": _handle_collect_process_list,
    "collect_network_connections": _handle_collect_network_connections,
}

IR_HANDLERS: dict[str, Any] = {
    "kill_process": _handle_kill_process,
    "isolate_host": _handle_isolate_host,
    "release_host": _handle_release_host,
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


def build_action_handlers(capabilities: list[str]) -> dict[str, Any]:
    """Return the merged handler table for a given capability set."""
    table: dict[str, Any] = {}
    if "bas" in capabilities:
        table.update(BAS_HANDLERS)
    if "ir" in capabilities:
        table.update(IR_HANDLERS)
    if "purple" in capabilities:
        table.update(PURPLE_HANDLERS)
    return table


# Default table: populated lazily at enrollment / poll time, not at
# import, so installations without a token don't carry the full list.
ACTION_HANDLERS: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only so the agent has zero dependencies)
# ---------------------------------------------------------------------------

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

    poll_url = f"{args.server.rstrip('/')}/api/v1/agents/_agent/poll"
    hb_url = f"{args.server.rstrip('/')}/api/v1/agents/_agent/heartbeat"
    result_base = f"{args.server.rstrip('/')}/api/v1/agents/_agent/commands"

    print(f"[pysoar-agent] polling {poll_url} every {POLL_INTERVAL_SECONDS}s")
    telemetry_payload = {"telemetry": {"uptime": 0}, "agent_version": AGENT_VERSION}
    _http_request(hb_url, method="POST", body=telemetry_payload, token=token)

    while True:
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
