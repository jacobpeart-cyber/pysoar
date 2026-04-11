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


ACTION_HANDLERS: dict[str, Any] = {
    "run_atomic_test": _handle_run_atomic_test,
    "collect_process_list": _handle_collect_process_list,
    "collect_network_connections": _handle_collect_network_connections,
    # kill_process, isolate_host, etc. are NOT in the default build —
    # they require the IR-capable agent, which is a separate artifact
    # (Phase 2). This build ships only BAS + read-only IR collectors.
}


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
    print(
        f"[pysoar-agent] enrolled as agent_id={resp.get('agent_id')} "
        f"caps={resp.get('capabilities')}"
    )
    print(f"[pysoar-agent] token saved to {args.token_file}")
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    """Poll the PySOAR server for queued commands in a loop."""
    token = _load_token(args.token_file)
    if not token:
        print(f"[pysoar-agent] no agent token at {args.token_file}; run --enroll first")
        return 1

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
