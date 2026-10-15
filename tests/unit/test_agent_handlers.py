"""Wave 5 (W5-C): agent-side handlers for the actions the server already sends.

``deploy_decoy`` / ``remove_decoy`` (deception), ``scan_container_image``
(container_scan), ``stig_scan`` (stig_scan), ``ot_safe_shutdown`` and
``ot_segmentation_probe`` (their own capabilities) are registered only for
the matching enrolled capability. Scanners are local binaries with a fixed
argv (``tool_missing`` when absent); decoys are planted only in the
operator's decoy directory; OT actions run only the operator's configured
script (``not_configured`` otherwise). Each result is checked against the
server code that consumes it (container report parser, STIG ARF ingest,
segmentation probe parser, decoy reconcile).

Scanner and script "binaries" here are small Python files written by the
tests; no real trivy, grype, oscap or OT tooling is involved.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import textwrap
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.capabilities import CAPABILITY_ACTIONS
from src.agents.models import AgentCommand, EndpointAgent
from src.agents.service import AgentService
from src.container_security.scanning import _report_from_result, parse_report
from src.ot_security.actuation import _probe_results
from src.stig.models import STIGBenchmark, STIGRule

REPO_ROOT = Path(__file__).resolve().parents[2]
NEW_ACTIONS = {
    "deception": {"deploy_decoy", "remove_decoy"},
    "container_scan": {"scan_container_image"},
    "stig_scan": {"stig_scan"},
    "ot_safe_shutdown": {"ot_safe_shutdown"},
    "ot_segmentation_probe": {"ot_segmentation_probe"},
}


@pytest.fixture
def agent() -> Any:
    spec = importlib.util.spec_from_file_location(
        f"pysoar_agent_handlers_{uuid.uuid4().hex[:6]}", REPO_ROOT / "agent" / "pysoar_agent.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    mod.AGENT_CONFIG.clear()
    return mod


def _script(path: Path, body: str) -> str:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(path)


def _fake_tools(agent: Any, monkeypatch: pytest.MonkeyPatch, tools: dict[str, str]) -> None:
    monkeypatch.setattr(agent, "_which", lambda name: tools.get(name))


TRIVY = """
import json, sys
open(sys.argv[0] + ".argv", "w").write(json.dumps(sys.argv[1:]))
print(json.dumps({"SchemaVersion": 2, "Results": [{"Target": sys.argv[-1], "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1",
     "FixedVersion": "3.0.2", "Severity": "HIGH"}]}]}))
"""
GRYPE = """
import json, sys
open(sys.argv[0] + ".argv", "w").write(json.dumps(sys.argv[1:]))
print(json.dumps({"matches": [{"vulnerability": {"id": "CVE-2024-0002", "severity": "Critical",
    "fix": {"versions": ["1.2"]}}, "artifact": {"name": "zlib", "version": "1.1"}}]}))
"""


# ---------------------------------------------------------------------------
# Capability flags
# ---------------------------------------------------------------------------

def test_handlers_are_registered_only_for_their_capability(agent: Any) -> None:
    for capability, actions in NEW_ACTIONS.items():
        table = agent.build_action_handlers([capability])
        assert actions <= set(table), capability
        # The server grants the same actions for the same capability.
        server = {a.value for cap, acts in CAPABILITY_ACTIONS.items() if cap.value == capability for a in acts}
        assert actions <= server, capability
        others = set().union(*(a for c, a in NEW_ACTIONS.items() if c != capability))
        assert not (others & set(table)), capability
    # "compliance" does not imply stig_scan; bas/ir carry none of the new actions.
    assert "stig_scan" not in agent.build_action_handlers(["compliance"])
    assert not (set().union(*NEW_ACTIONS.values()) & set(agent.build_action_handlers(["bas", "ir", "purple"])))
    assert "run_atomic_test" in agent.build_action_handlers(["bas"])


# ---------------------------------------------------------------------------
# scan_container_image
# ---------------------------------------------------------------------------

def test_container_scan_runs_trivy_and_the_server_parses_the_report(
    agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    trivy = _script(tmp_path / "trivy.py", TRIVY)
    _fake_tools(agent, monkeypatch, {"trivy": trivy})
    ref = "registry.example.com:5000/team/app:1.4"
    result = agent._handle_scan_container_image({"image_ref": ref, "scanner": "trivy", "scan_id": "s1"})
    assert result["status"] == "success", result
    assert json.loads(Path(trivy + ".argv").read_text()) == ["image", "--format", "json", "--quiet", ref]
    used, vulns = parse_report(_report_from_result(SimpleNamespace(**result)))
    assert used == "trivy"
    assert [(v["cve_id"], v["package"], v["severity"]) for v in vulns] == [("CVE-2024-0001", "openssl", "high")]


def test_container_scan_falls_back_to_grype_and_reports_tool_missing(
    agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    grype = _script(tmp_path / "grype.py", GRYPE)
    _fake_tools(agent, monkeypatch, {"grype": grype})
    result = agent._handle_scan_container_image({"image_ref": "alpine:3.19", "scanner": "trivy"})
    assert result["status"] == "success", result
    assert json.loads(Path(grype + ".argv").read_text()) == ["alpine:3.19", "-o", "json"]
    used, vulns = parse_report(_report_from_result(SimpleNamespace(**result)))
    assert used == "grype" and vulns[0]["cve_id"] == "CVE-2024-0002"

    _fake_tools(agent, monkeypatch, {})
    missing = agent._handle_scan_container_image({"image_ref": "alpine:3.19"})
    assert missing["status"] == "tool_missing" and missing["stderr"].startswith("tool_missing")


@pytest.mark.parametrize("ref", ["--output=/etc/passwd", "alpine; rm -rf /", "a b", "", "-alpine", "alpine:3.19 --x"])
def test_container_scan_refuses_malformed_references(
    agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ref: str,
) -> None:
    trivy = _script(tmp_path / "trivy.py", TRIVY)
    _fake_tools(agent, monkeypatch, {"trivy": trivy})
    assert agent._handle_scan_container_image({"image_ref": ref})["status"] == "rejected"
    assert not Path(trivy + ".argv").exists()


# ---------------------------------------------------------------------------
# stig_scan (end to end: server dispatch -> agent handler -> server ingest)
# ---------------------------------------------------------------------------

OSCAP = """
import json, sys
args = sys.argv[1:]
open(sys.argv[0] + ".argv", "w").write(json.dumps(args))
arf = args[args.index("--results-arf") + 1]
rules = json.loads(open(sys.argv[0] + ".rules").read())
rows = "".join(
    '<rule-result idref="%s" severity="high"><result>%s</result></rule-result>' % (rid, res)
    for rid, res in rules.items()
)
open(arf, "w").write(
    '<arf:asset-report-collection xmlns:arf="urn:oasis:names:tc:dfi:arf:1.0">'
    '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">' + rows + '</TestResult>'
    '</arf:asset-report-collection>'
)
sys.exit(2)
"""


async def test_stig_scan_arf_is_ingested_by_the_server(
    agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers,
) -> None:
    org_id = org_a.id
    bench = STIGBenchmark(benchmark_id=f"RHEL_9_{uuid.uuid4().hex[:8]}", title="RHEL 9", platform="RHEL 9",
                          organization_id=org_id)
    db_session.add(bench)
    await db_session.flush()
    rules = []
    for i in range(3):
        rid = f"SV-{uuid.uuid4().hex[:6]}r{i}_rule"
        db_session.add(STIGRule(benchmark_id_ref=bench.id, rule_id=rid, stig_id=rid, severity="medium",
                                title=f"rule {i}", organization_id=org_id))
        rules.append(rid)
    host = EndpointAgent(hostname="rhel-w5", status="active", capabilities=["stig_scan"], os_type="linux",
                         organization_id=org_id)
    db_session.add(host)
    bench_pk, xccdf_id = bench.id, bench.benchmark_id
    await db_session.commit()
    host_id = host.id

    body = (await client.post("/api/v1/stig/scans/launch", json={"host": "rhel-w5", "benchmark_id": bench_pk},
                              headers=org_a_admin_headers)).json()
    assert body["status"] == "dispatched", body
    cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == body["command_id"]))).scalar_one()
    payload, command_id = dict(cmd.payload), cmd.id

    oscap = _script(tmp_path / "oscap.py", OSCAP)
    Path(oscap + ".rules").write_text(json.dumps({rules[0]: "fail", rules[1]: "pass", rules[2]: "pass"}))
    _fake_tools(agent, monkeypatch, {"oscap": oscap})
    assert agent._handle_stig_scan(payload)["status"] == "not_configured"
    datastream = tmp_path / "ssg-rhel9-ds.xml"
    datastream.write_text("<ds/>")
    agent.AGENT_CONFIG["stig_datastreams"] = {xccdf_id: str(datastream)}
    result = agent._handle_stig_scan(payload)
    assert result["status"] == "success", result
    argv = json.loads(Path(oscap + ".argv").read_text())
    assert argv[:4] == ["xccdf", "eval", "--benchmark-id", xccdf_id] and argv[-1] == str(datastream)

    db_host = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == host_id))).scalar_one()
    db_cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == command_id))).scalar_one()
    db_cmd.status = "dispatched"
    await AgentService(db_session).ingest_result(
        agent=db_host, command_id=command_id, status=result["status"], exit_code=result["exit_code"],
        stdout=result.get("stdout"), stderr=result.get("stderr"), artifacts=result.get("artifacts") or {},
    )
    await db_session.commit()
    done = (await client.get(f"/api/v1/stig/scans/{body['scan_id']}", headers=org_a_headers)).json()
    assert done["status"] == "completed", done
    assert (done["open_findings"], done["not_a_finding"]) == (1, 2)


def test_stig_scan_tool_missing_and_refuses_option_like_ids(agent: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_tools(agent, monkeypatch, {})
    assert agent._handle_stig_scan({"benchmark_id": "RHEL_9"})["status"] == "tool_missing"
    assert agent._handle_stig_scan({"benchmark_id": "--remediate"})["status"] == "rejected"
    assert agent._handle_stig_scan({"benchmark_id": "RHEL_9", "profile": "-x y"})["status"] == "rejected"


# ---------------------------------------------------------------------------
# deploy_decoy / remove_decoy
# ---------------------------------------------------------------------------

def test_decoys_are_planted_and_removed_only_in_the_decoy_directory(agent: Any, tmp_path: Path) -> None:
    payload = {
        "decoy_id": "d-1", "decoy_type": "honeyfile", "category": "file", "name": "x",
        "configuration": {"filename": "../../etc/cron.d/passwords.xlsx", "content": "lure"},
    }
    assert agent._handle_deploy_decoy(payload)["status"] == "not_configured"
    decoy_dir = tmp_path / "decoys"
    decoy_dir.mkdir()
    agent.AGENT_CONFIG["decoy_dir"] = str(decoy_dir)

    result = agent._handle_deploy_decoy(payload)
    assert result["status"] == "success", result
    planted = decoy_dir / "passwords.xlsx"  # basename only, inside the directory
    assert planted.read_text() == "lure"
    assert json.loads(result["stdout"])["access_monitoring"] == "not_provided_by_agent"
    assert agent._handle_deploy_decoy(payload)["status"] == "error"  # already planted
    assert agent._handle_deploy_decoy({**payload, "decoy_type": "honeydns"})["status"] == "rejected"

    assert agent._handle_remove_decoy({"decoy_id": "unknown"})["status"] == "error"
    removed = agent._handle_remove_decoy({"decoy_id": "d-1", "decoy_type": "honeyfile"})
    assert removed["status"] == "success" and not planted.exists()


# ---------------------------------------------------------------------------
# OT actions: operator scripts only
# ---------------------------------------------------------------------------

PROBE = """
import json, sys
plan = json.load(sys.stdin)
results = [{"target_ip": p["target_ip"], "port": p["port"], "reachable": p["port"] == 502}
           for p in plan["probes"]]
results.append({"target_ip": "203.0.113.9", "port": 22, "reachable": True})  # never asked for
print(json.dumps({"results": results}))
"""
SHUTDOWN = """
import json, os, sys
plan = json.load(sys.stdin)
print("stopped %d assets via %s" % (len(plan["assets"]), os.environ["PYSOAR_ACTION"]))
sys.exit(0 if plan["assets"] else 3)
"""


def test_ot_actions_run_only_the_configured_script(agent: Any, tmp_path: Path) -> None:
    probe_payload = {"zone_id": "z", "zone_cidr": "10.0.1.0/24", "timeout_seconds": 2, "probes": [
        {"target_ip": "10.0.2.5", "port": 502, "protocol": "modbus_tcp"},
        {"target_ip": "10.0.2.6", "port": 102, "protocol": "s7comm"},
    ]}
    shutdown_payload = {"ot_incident_id": "i", "affected_zones": [], "assets": [{"asset_id": "a", "name": "plc"}]}
    # A server-supplied command string is never a script source.
    assert agent._handle_ot_segmentation_probe({**probe_payload, "command": "rm -rf /"})["status"] == "not_configured"
    assert agent._handle_ot_safe_shutdown(shutdown_payload)["status"] == "not_configured"
    agent.AGENT_CONFIG["ot_segmentation_probe_script"] = "relative/probe.py"
    assert agent._handle_ot_segmentation_probe(probe_payload)["status"] == "not_configured"

    agent.AGENT_CONFIG["ot_segmentation_probe_script"] = _script(tmp_path / "probe.py", PROBE)
    agent.AGENT_CONFIG["ot_safe_shutdown_script"] = _script(tmp_path / "shutdown.py", SHUTDOWN)
    probe = agent._handle_ot_segmentation_probe(probe_payload)
    assert probe["status"] == "success", probe
    parsed = _probe_results(SimpleNamespace(**probe))
    assert parsed == [
        {"target_ip": "10.0.2.5", "port": 502, "reachable": True},
        {"target_ip": "10.0.2.6", "port": 102, "reachable": False},
    ]
    shutdown = agent._handle_ot_safe_shutdown(shutdown_payload)
    assert shutdown["status"] == "success" and "stopped 1 assets via ot_safe_shutdown" in shutdown["stdout"]
    failed = agent._handle_ot_safe_shutdown({**shutdown_payload, "assets": []})
    assert failed["status"] == "error" and failed["exit_code"] == 3


# ---------------------------------------------------------------------------
# Poll loop with a fake transport
# ---------------------------------------------------------------------------

class _StopLoopError(Exception):
    pass


def test_poll_loop_dispatches_new_actions_and_posts_results(
    agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "agent.token"
    token_file.write_text("tok")
    Path(str(token_file) + ".caps").write_text(json.dumps(["deception", "container_scan"]))
    decoy_dir = tmp_path / "decoys"
    decoy_dir.mkdir()
    Path(str(token_file) + ".config.json").write_text(json.dumps({"decoy_dir": str(decoy_dir)}))
    _fake_tools(agent, monkeypatch, {"trivy": _script(tmp_path / "trivy.py", TRIVY)})

    commands = [
        {"id": "c1", "action": "deploy_decoy", "payload": {
            "decoy_id": "d-9", "decoy_type": "canary_file", "configuration": {"filename": "salaries.csv"}}},
        {"id": "c2", "action": "scan_container_image", "payload": {"image_ref": "nginx:1.25", "scanner": "trivy"}},
        {"id": "c3", "action": "ot_safe_shutdown", "payload": {"assets": []}},
    ]
    posted: dict[str, dict[str, Any]] = {}

    def fake_http(url: str, *_args: Any, body: Any = None, **_kwargs: Any):
        if url.endswith("/_agent/poll"):
            return 200, {"commands": commands}
        if "/_agent/commands/" in url:
            posted[url.split("/_agent/commands/")[1].split("/")[0]] = body
        return 200, {}

    def stop(_seconds: float) -> None:
        raise _StopLoopError

    monkeypatch.setattr(agent, "_http_request", fake_http)
    monkeypatch.setattr(agent, "_collect_posture", lambda: {})
    monkeypatch.setattr(agent, "_resolve_server_ips", lambda _server: set())
    monkeypatch.setattr(agent.time, "sleep", stop)
    with pytest.raises(_StopLoopError):
        agent.cmd_poll(SimpleNamespace(token_file=token_file, server="https://pysoar.test"))

    assert posted["c1"]["status"] == "success" and (decoy_dir / "salaries.csv").exists()
    assert posted["c2"]["status"] == "success"
    assert parse_report(_report_from_result(SimpleNamespace(**posted["c2"])))[0] == "trivy"
    # Not enrolled with ot_safe_shutdown: refused by the local allowlist.
    assert posted["c3"]["status"] == "rejected" and "not in local allowlist" in posted["c3"]["stderr"]
