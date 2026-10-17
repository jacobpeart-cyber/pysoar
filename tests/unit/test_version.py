"""Build identity: the VERSION file, the commit fallback and /health reporting them."""

from pathlib import Path

import pytest

from src.core import version as version_mod

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_version_file_is_semver_and_is_the_module_version():
    raw = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert version_mod.SEMVER_RE.match(raw), raw
    assert version_mod.__version__ == raw


def test_package_version_is_the_version_file():
    import src

    assert src.__version__ == version_mod.__version__


@pytest.mark.parametrize("value", ["0.9.0", "1.2.3-rc.1", "10.0.0+build.7"])
def test_read_version_accepts_semver(tmp_path, value):
    f = tmp_path / "VERSION"
    f.write_text(value + "\n", encoding="utf-8")
    assert version_mod.read_version(f) == value


@pytest.mark.parametrize("value", ["", "v0.9.0", "0.9", "01.2.3", "1.2.3.4", "latest"])
def test_read_version_refuses_non_semver(tmp_path, value):
    f = tmp_path / "VERSION"
    f.write_text(value, encoding="utf-8")
    with pytest.raises(RuntimeError):
        version_mod.read_version(f)


def test_read_version_refuses_missing_file(tmp_path):
    with pytest.raises(RuntimeError):
        version_mod.read_version(tmp_path / "VERSION")


def test_commit_is_unknown_without_build_arg(monkeypatch):
    monkeypatch.delenv("PYSOAR_COMMIT", raising=False)
    assert version_mod.get_commit() == "unknown"


@pytest.mark.parametrize("value", ["", "unknown", "not-a-sha", "<script>", "abc12"])
def test_commit_is_unknown_when_malformed(monkeypatch, value):
    monkeypatch.setenv("PYSOAR_COMMIT", value)
    assert version_mod.get_commit() == "unknown"


def test_commit_is_reported_when_set(monkeypatch):
    sha = "dc336f6a1b2c3d4e5f60718293a4b5c6d7e8f901"
    monkeypatch.setenv("PYSOAR_COMMIT", sha)
    assert version_mod.get_commit() == sha


@pytest.mark.asyncio
async def test_health_reports_version_and_unknown_commit(client, monkeypatch):
    monkeypatch.delenv("PYSOAR_COMMIT", raising=False)
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == version_mod.__version__
    assert body["commit"] == "unknown"


@pytest.mark.asyncio
async def test_health_reports_build_commit(client, monkeypatch):
    monkeypatch.setenv("PYSOAR_COMMIT", "dc336f6")
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200, resp.text
    assert resp.json()["commit"] == "dc336f6"
