"""config.outboundPrivateAllowlist renders into the chart's ConfigMap as OUTBOUND_PRIVATE_ALLOWLIST.

Renders deploy/helm/pysoar with ``helm template`` (the binary must be on PATH,
or named by the HELM_BIN environment variable; the test is skipped without
it, the helm.yml workflow renders the chart on every chart change). Render
validation only: nothing is applied to a cluster.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
from typing import Any, Optional

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "pysoar"
EXAMPLE = CHART / "values-example-production.yaml"


def _helm() -> Optional[str]:
    return os.environ.get("HELM_BIN") or shutil.which("helm")


pytestmark = pytest.mark.skipif(_helm() is None, reason="helm is not on PATH (set HELM_BIN to run this render test)")


def _render(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_helm(), "template", "pysoar", str(CHART), "-n", "pysoar", "-f", str(EXAMPLE), *args],
        capture_output=True, text=True, check=False, timeout=120,
    )


def _docs(out: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all(out) if isinstance(d, dict)]


def _configmap(docs: list[dict[str, Any]]) -> dict[str, str]:
    (cm,) = [d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "pysoar-config"]
    return cm["data"]


def _migration_env(docs: list[dict[str, Any]]) -> dict[str, str]:
    (job,) = [d for d in docs if d.get("kind") == "Job"]
    (container,) = job["spec"]["template"]["spec"]["containers"]
    return {e["name"]: e.get("value") for e in container.get("env", [])}


def test_default_is_an_empty_json_list() -> None:
    proc = _render()
    assert proc.returncode == 0, proc.stderr
    docs = _docs(proc.stdout)
    assert json.loads(_configmap(docs)["OUTBOUND_PRIVATE_ALLOWLIST"]) == []
    assert json.loads(_migration_env(docs)["OUTBOUND_PRIVATE_ALLOWLIST"]) == []


def test_listed_cidrs_render_as_a_json_list() -> None:
    cidrs = ["10.20.0.0/24", "fd12:3456::/48"]
    proc = _render("--set-json", f"config.outboundPrivateAllowlist={json.dumps(cidrs)}")
    assert proc.returncode == 0, proc.stderr
    docs = _docs(proc.stdout)
    assert json.loads(_configmap(docs)["OUTBOUND_PRIVATE_ALLOWLIST"]) == cidrs
    assert json.loads(_migration_env(docs)["OUTBOUND_PRIVATE_ALLOWLIST"]) == cidrs


def test_the_rendered_value_is_what_the_settings_parser_reads(monkeypatch) -> None:
    from src.core.config import Settings

    proc = _render("--set-json", 'config.outboundPrivateAllowlist=["10.20.0.7/24"]')
    assert proc.returncode == 0, proc.stderr
    monkeypatch.setenv("OUTBOUND_PRIVATE_ALLOWLIST", _configmap(_docs(proc.stdout))["OUTBOUND_PRIVATE_ALLOWLIST"])
    assert Settings().outbound_private_allowlist == ["10.20.0.0/24"]


@pytest.mark.parametrize(("args", "message"), [
    (("--set", "config.extra.OUTBOUND_PRIVATE_ALLOWLIST=10.0.0.0/8"), "not config.extra.OUTBOUND_PRIVATE_ALLOWLIST"),
    (("--set", "config.outboundPrivateAllowlist=10.0.0.0/8"), "must be a list of CIDRs"),
])
def test_the_chart_refuses_the_other_spellings(args: tuple[str, ...], message: str) -> None:
    proc = _render(*args)
    assert proc.returncode != 0 and message in proc.stderr
