"""The root Dockerfile does ``COPY . .``: the build context must leave the
host's secrets and local state behind, or a ``docker compose build`` on the
production host bakes its live ``.env`` and private keys into the image."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _patterns(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


@pytest.mark.parametrize("pattern", [".env", ".env.*", "!.env.example", "*.key", "*.pem", "*.pem.*", "nginx/ssl/", "docker-compose.override.yml"])
def test_backend_build_context_excludes_secrets(pattern: str) -> None:
    assert pattern in _patterns(ROOT / ".dockerignore")


@pytest.mark.parametrize("pattern", [".env", ".env.*"])
def test_frontend_build_context_excludes_env_files(pattern: str) -> None:
    assert pattern in _patterns(ROOT / "frontend" / ".dockerignore")


def test_dockerfile_still_copies_the_tree() -> None:
    # The guard above only matters while the image is built from the whole tree.
    assert "COPY --chown=pysoar:pysoar . ." in (ROOT / "Dockerfile").read_text(encoding="utf-8")
