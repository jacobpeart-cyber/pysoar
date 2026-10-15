"""Route inventory: every served /api/v1 route is called by the UI or documented.

The frontend call list is the one ``scripts/contract_diff.py`` parses from
``frontend/src``; the allowlist is ``docs/api/api-only-routes.md`` (KEEP-API,
called dynamically, EXPOSE, pending retirement). A new backend route therefore
needs either a page that calls it or a row in that file, and a deleted route
must take its row with it.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("contract_diff", ROOT / "scripts" / "contract_diff.py")
assert _SPEC is not None and _SPEC.loader is not None
contract_diff = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(contract_diff)

pytestmark = pytest.mark.skipif(
    not contract_diff.FRONTEND_SRC.is_dir(), reason="frontend/src is not checked out",
)


@pytest.fixture(scope="module")
def inventory() -> dict:
    from src.main import app

    backend = contract_diff.backend_routes(app)
    frontend, _unparsed = contract_diff.frontend_calls()
    api_only = contract_diff.api_only_routes()
    return {
        "backend": backend,
        "frontend": frontend,
        "api_only": api_only,
        "report": contract_diff.diff(backend, frontend, api_only),
    }


def _fmt(keys) -> str:
    return "\n".join(f"  {m} {p}" for m, p in sorted(keys))


def test_allowlist_parses(inventory: dict) -> None:
    sections = inventory["api_only"]
    assert set(sections) == {"keep", "dynamic", "expose", "pending"}
    # The file is the real allowlist, not an empty stub.
    assert len(sections["keep"]) > 100
    assert ("GET", "/api/v1/agents/_agent/poll") in sections["keep"]


def test_frontend_calls_are_parsed(inventory: dict) -> None:
    assert len(inventory["frontend"]) > 100
    assert ("GET", "/api/v1/alerts") in inventory["frontend"]


def test_every_served_route_is_called_or_documented(inventory: dict) -> None:
    unclassified = inventory["report"]["unclassified"]
    assert not unclassified, (
        "Served /api/v1 routes that no page calls and docs/api/api-only-routes.md does not list "
        "(call them from the UI, add a KEEP-API / EXPOSE row, or delete the route):\n" + _fmt(unclassified)
    )


def test_every_documented_route_is_served(inventory: dict) -> None:
    stale = inventory["report"]["stale_documented"]
    assert not stale, (
        "docs/api/api-only-routes.md lists routes the app does not serve (remove the rows):\n" + _fmt(stale)
    )


def test_keep_api_rows_are_not_called_by_the_frontend(inventory: dict) -> None:
    called = inventory["report"]["documented_but_called"]
    assert not called, (
        "KEEP-API / dynamic rows the frontend now calls literally (delete the rows):\n" + _fmt(called)
    )


def test_each_route_is_listed_once(inventory: dict) -> None:
    sections = inventory["api_only"]
    seen: dict[tuple[str, str], str] = {}
    dupes = []
    for name, rows in sections.items():
        for key in rows:
            if key in seen:
                dupes.append((key, seen[key], name))
            seen[key] = name
    assert not dupes, f"routes listed in two sections: {dupes}"


def test_no_frontend_call_without_a_backend_route(inventory: dict) -> None:
    missing = inventory["report"]["missing"]
    assert not missing, "frontend calls with no backend route:\n" + "\n".join(
        f"  {m} {p} <- {', '.join(files)}" for (m, p), files in missing
    )


def test_retired_routes_are_gone(inventory: dict) -> None:
    """A sample of the routes wave 5 deleted (FAKE, duplicate or superseded)."""
    backend = inventory["backend"]
    for key in (
        ("GET", "/api/v1/privacy/dsr"),
        ("GET", "/api/v1/intel/iocs"),
        ("POST", "/api/v1/ai/query"),
        ("POST", "/api/v1/agentic/agents/{x}/start"),
        ("GET", "/api/v1/deception/coverage"),
        ("GET", "/api/v1/phishing_sim/dashboard"),
        ("POST", "/api/v1/auth/mfa/verify"),
        ("POST", "/api/v1/playbook-builder/{x}/execute"),
        ("POST", "/api/v1/collaboration/artifacts/{x}/download"),
        ("GET", "/api/v1/itdr/dashboard/risk-overview"),
    ):
        assert key not in backend, key
