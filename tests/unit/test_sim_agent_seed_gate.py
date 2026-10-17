"""The simulation-agent seeder runs at boot outside production only, unless the
operator opts in explicitly; in production the shared host must not get an
auto-enrolled agent with bas / live_response / stig_scan for every tenant."""
from __future__ import annotations

import pytest

from src.core.config import settings


@pytest.mark.parametrize(
    ("app_env", "explicit", "expected"),
    [
        ("development", None, True),
        ("staging", None, True),
        ("production", None, False),
        ("production", True, True),
        ("production", False, False),
        ("development", False, False),
    ],
)
def test_seed_sim_agent_gate(monkeypatch: pytest.MonkeyPatch, app_env: str, explicit, expected: bool) -> None:
    monkeypatch.setattr(settings, "app_env", app_env)
    monkeypatch.setattr(settings, "sim_agent_seed_enabled", explicit)
    assert settings.seed_sim_agent is expected
