"""Stub-honesty cleanup (2026-07-01 audit).

- BrandProtection takedown methods no longer fabricate provider progress
  (status "in_progress", progress=50, invented resolution dates); they
  report ``no_takedown_provider`` because no takedown provider exists.
- CredentialAnalyzer.auto_remediate either applies a REAL local account
  action (force_password_change / deactivate, like remediation's
  AccountActionExecutor) or honestly says nothing was executed — it no
  longer claims "notification_sent": True without sending anything.
- DependencyScanner.scan_container_image no longer returns one hardcoded
  fake dependency for every image; with no scanner on PATH it reports
  ``no_scanner_backend`` (container_security ImageScanner precedent).
- The dead src/integrations/{slack,pagerduty,siem}.py duplicates (which
  imported a nonexistent src.integrations.base and could never load) are
  deleted; the working versions live in src/integrations/connectors/.
- NaturalLanguageQueryEngine.process_query measures real elapsed time
  instead of hardcoding execution_time_ms=150, and the async Celery task
  persists results onto the NLQuery row instead of dropping them.
"""

import asyncio
import importlib.util

import pytest


# ---------------------------------------------------------------------------
# Dark web: takedown honesty
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initiate_takedown_reports_no_provider():
    from src.darkweb.engine import BrandProtection

    result = await BrandProtection().initiate_takedown_process(
        "threat-1", "phishing_site"
    )

    assert result["status"] == "no_takedown_provider"
    assert result["provider"] is None
    assert "manual" in result["detail"].lower()
    # The fabricated fields must stay gone.
    assert "estimated_resolution" not in result
    assert "progress" not in result


@pytest.mark.asyncio
async def test_track_takedown_status_reports_no_provider():
    from src.darkweb.engine import BrandProtection

    result = await BrandProtection().track_takedown_status("takedown-1")

    assert result["status"] == "no_takedown_provider"
    assert "progress" not in result
    assert "estimated_completion" not in result


# ---------------------------------------------------------------------------
# Dark web: credential auto-remediation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_remediate_without_db_does_not_claim_success():
    from src.darkweb.engine import CredentialAnalyzer

    result = await CredentialAnalyzer().auto_remediate("user-1", "password_reset")

    assert result["status"] == "not_executed"
    assert result.get("notification_sent") is not True
    assert "no remediation was performed" in result["detail"].lower()


@pytest.mark.asyncio
async def test_auto_remediate_rejects_unknown_action():
    from src.darkweb.engine import CredentialAnalyzer

    result = await CredentialAnalyzer().auto_remediate("user-1", "launch_missiles")

    assert result["status"] == "unsupported_action"


@pytest.mark.asyncio
async def test_auto_remediate_applies_real_account_action(db_session, test_user):
    from src.darkweb.engine import CredentialAnalyzer

    result = await CredentialAnalyzer().auto_remediate(
        test_user.email, "account_disabled", db=db_session
    )

    assert result["status"] == "applied"
    assert result["matched_user_id"] == test_user.id
    assert result["notification_sent"] is False  # honest: nothing is sent

    await db_session.refresh(test_user)
    assert test_user.is_active is False
    assert test_user.force_password_change is True


@pytest.mark.asyncio
async def test_auto_remediate_unknown_user_is_honest(db_session):
    from src.darkweb.engine import CredentialAnalyzer

    result = await CredentialAnalyzer().auto_remediate(
        "nobody@nowhere.example", "password_reset", db=db_session
    )

    assert result["status"] == "user_not_found"


# ---------------------------------------------------------------------------
# Supply chain: container image scan
# ---------------------------------------------------------------------------


def test_scan_container_image_no_backend_is_honest(monkeypatch):
    from src.supplychain import engine as sc_engine

    monkeypatch.setattr(sc_engine.shutil, "which", lambda _name: None)

    scanner = sc_engine.DependencyScanner()
    result = scanner.scan_container_image("registry.example/app@sha256:abc")

    assert result["status"] == "no_scanner_backend"
    assert result["scanner_backend"] is None
    assert result["dependencies"] == []
    assert "not a clean scan" in result["message"].lower()


def test_scan_container_image_never_returns_fake_dependency(monkeypatch):
    """Guard: the canned 'base-os-package' fabrication must stay gone."""
    from src.supplychain import engine as sc_engine

    monkeypatch.setattr(sc_engine.shutil, "which", lambda _name: None)

    result = sc_engine.DependencyScanner().scan_container_image("anything:latest")
    names = [d.get("name") for d in result["dependencies"]]
    assert "base-os-package" not in names


def test_scan_container_image_parses_syft_output(monkeypatch):
    from src.supplychain import engine as sc_engine

    monkeypatch.setattr(
        sc_engine.shutil, "which", lambda name: "/usr/bin/syft" if name == "syft" else None
    )

    class FakeProc:
        returncode = 0
        stderr = ""
        stdout = (
            '{"artifacts": [{"name": "openssl", "version": "3.0.2", '
            '"type": "deb", "purl": "pkg:deb/ubuntu/openssl@3.0.2"}]}'
        )

    monkeypatch.setattr(
        sc_engine.subprocess, "run", lambda *a, **kw: FakeProc()
    )

    result = sc_engine.DependencyScanner().scan_container_image("ubuntu:22.04")

    assert result["status"] == "completed"
    assert result["scanner_backend"] == "syft"
    assert result["dependencies"] == [
        {
            "name": "openssl",
            "version": "3.0.2",
            "package_type": "deb",
            "purl": "pkg:deb/ubuntu/openssl@3.0.2",
        }
    ]


# ---------------------------------------------------------------------------
# Dead integration duplicates are deleted
# ---------------------------------------------------------------------------


def test_dead_integration_duplicates_are_deleted():
    for mod in (
        "src.integrations.slack",
        "src.integrations.pagerduty",
        "src.integrations.siem",
    ):
        assert importlib.util.find_spec(mod) is None, (
            f"{mod} is back — it was a dead duplicate importing the "
            "nonexistent src.integrations.base (ImportError on load); the "
            "working connector lives in src.integrations.connectors"
        )

    # The real connectors and the package itself must still import.
    import src.integrations  # noqa: F401
    from src.integrations.connectors import (  # noqa: F401
        PagerDutyConnector,
        SlackConnector,
    )


# ---------------------------------------------------------------------------
# AI: NL query timing and async persistence
# ---------------------------------------------------------------------------


def test_nl_query_execution_time_is_measured(monkeypatch):
    from src.ai import engine as ai_engine

    nlq = ai_engine.NaturalLanguageQueryEngine()
    monkeypatch.setattr(nlq, "_execute_query", lambda intent, params: [])
    monkeypatch.setattr(nlq, "_summarize_results", lambda q, r: "no results")

    ticks = iter([100.0, 100.5])  # 0.5 is exactly representable in binary
    monkeypatch.setattr(ai_engine.time, "perf_counter", lambda: next(ticks))

    result = nlq.process_query("show me the logs")

    # Measured from perf_counter, not the old hardcoded 150.
    assert result["execution_time_ms"] == 500


def test_process_nl_query_async_persists_results(monkeypatch):
    from src.ai import tasks as ai_tasks
    from src.ai.models import NLQuery
    from src.core.database import async_session_factory

    canned = {
        "intent": "alert_lookup",
        "query_generated": "alerts last 7d",
        "results_count": 3,
        "results": [],
        "summary": "3 open alerts",
        "execution_time_ms": 12,
    }
    monkeypatch.setattr(
        "src.ai.engine.NaturalLanguageQueryEngine.process_query",
        lambda self, nl, ctx=None: canned,
    )

    async def _create_row() -> str:
        async with async_session_factory() as session:
            row = NLQuery(
                natural_language="show alerts",
                interpreted_intent="pending",
                generated_query="",
                user_id="user-1",
                organization_id="org-1",
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    query_id = asyncio.run(_create_row())

    outcome = ai_tasks.process_nl_query_async.apply(
        args=[query_id, "show alerts", "user-1"]
    ).get()

    assert outcome["status"] == "success"
    assert outcome["persisted"] is True

    async def _fetch_row():
        from sqlalchemy import select

        async with async_session_factory() as session:
            return (
                await session.execute(select(NLQuery).where(NLQuery.id == query_id))
            ).scalar_one()

    row = asyncio.run(_fetch_row())
    assert row.interpreted_intent == "alert_lookup"
    assert row.results_summary == "3 open alerts"
    assert row.result_count == 3
    assert row.execution_time_ms == 12


def test_process_nl_query_async_is_honest_when_row_missing(monkeypatch):
    from src.ai import tasks as ai_tasks

    monkeypatch.setattr(
        "src.ai.engine.NaturalLanguageQueryEngine.process_query",
        lambda self, nl, ctx=None: {
            "intent": "log_search",
            "query_generated": "",
            "results_count": 0,
            "results": [],
            "summary": "",
            "execution_time_ms": 1,
        },
    )

    outcome = ai_tasks.process_nl_query_async.apply(
        args=["no-such-query-id", "anything", "user-1"]
    ).get()

    assert outcome["status"] == "success"
    assert outcome["persisted"] is False
