"""The integration housekeeping Celery tasks must do real work.

Before this fix, all five tasks in ``src.integrations.tasks`` were
stubs that returned zero counts / empty lists with "In production, ..."
comments. These tests exercise the real logic (via the module-level
``_*_async`` helpers the Celery entrypoints wrap):

- health_check_all_integrations probes every installed integration
- execution_cleanup deletes old integration_executions rows
- webhook_cleanup deletes stale DEACTIVATED webhook endpoints only
- rate_limit_reset clears lapsed rate-limit windows only
- connector_update_check reports genuine registry-vs-DB version drift
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from src.integrations.models import (
    InstalledIntegration,
    IntegrationAction,
    IntegrationConnector,
    IntegrationExecution,
    WebhookEndpoint,
)
from src.integrations.tasks import (
    _connector_update_check_async,
    _execution_cleanup_async,
    _health_check_all_integrations_async,
    _rate_limit_reset_async,
    _webhook_cleanup_async,
)

ORG = "org-1"


def _connector(name="splunk", version="1.0.0"):
    return IntegrationConnector(
        id=name,
        name=name,
        display_name=name.title(),
        category="siem",
        version=version,
        supported_actions="[]",
        supported_triggers="[]",
        auth_type="api_key",
        config_schema="{}",
        is_builtin=True,
    )


def _integration(connector_id="splunk", status="active", **overrides):
    params = {
        "organization_id": ORG,
        "connector_id": connector_id,
        "display_name": f"{connector_id} instance",
        "config_encrypted": "{}",
        "auth_credentials_encrypted": "{}",
        "status": status,
        "health_status": "unknown",
    }
    params.update(overrides)
    return InstalledIntegration(**params)


@pytest.mark.asyncio
async def test_health_check_all_integrations_probes_every_row(db_session, monkeypatch):
    connector = _connector()
    first = _integration()
    second = _integration(status="error")
    inactive = _integration(status="inactive")
    db_session.add_all([connector, first, second, inactive])
    await db_session.commit()

    from src.integrations.engine import IntegrationManager

    checked_ids = []
    statuses = {first.id: "healthy", second.id: "unhealthy"}

    async def fake_test_connection(self, installation_id):
        checked_ids.append(installation_id)
        return {"installation_id": installation_id, "status": statuses[installation_id]}

    monkeypatch.setattr(IntegrationManager, "test_connection", fake_test_connection)

    results = await _health_check_all_integrations_async()

    assert sorted(checked_ids) == sorted([first.id, second.id])  # inactive skipped
    assert results["total_checked"] == 2
    assert results["healthy"] == 1
    assert results["unhealthy"] == 1
    assert results["degraded"] == 0
    assert results["timestamp"]


@pytest.mark.asyncio
async def test_health_check_filters_by_organization(db_session, monkeypatch):
    connector = _connector()
    mine = _integration()
    other = _integration(organization_id="org-2")
    db_session.add_all([connector, mine, other])
    await db_session.commit()

    from src.integrations.engine import IntegrationManager

    checked_ids = []

    async def fake_test_connection(self, installation_id):
        checked_ids.append(installation_id)
        return {"installation_id": installation_id, "status": "unknown"}

    monkeypatch.setattr(IntegrationManager, "test_connection", fake_test_connection)

    results = await _health_check_all_integrations_async(organization_id=ORG)

    assert checked_ids == [mine.id]
    assert results["total_checked"] == 1
    assert results["unknown"] == 1


@pytest.mark.asyncio
async def test_execution_cleanup_deletes_only_old_rows(db_session):
    connector = _connector()
    integration = _integration()
    action = IntegrationAction(
        connector_id=connector.id,
        action_name="query",
        display_name="Query",
        input_schema="{}",
        output_schema="{}",
        retry_policy="{}",
    )
    db_session.add_all([connector, integration, action])
    await db_session.flush()

    now = datetime.now(timezone.utc)
    old = IntegrationExecution(
        organization_id=ORG,
        installed_id=integration.id,
        action_id=action.id,
        input_data="{}",
        status="success",
        created_at=now - timedelta(days=45),
    )
    recent = IntegrationExecution(
        organization_id=ORG,
        installed_id=integration.id,
        action_id=action.id,
        input_data="{}",
        status="success",
        created_at=now - timedelta(days=5),
    )
    db_session.add_all([old, recent])
    await db_session.commit()

    result = await _execution_cleanup_async(days_old=30)

    assert result["status"] == "success"
    assert result["deleted_count"] == 1

    # Query column values directly — the task deleted through its own
    # session, so db_session's identity map would mask the deletion.
    remaining_ids = set(
        (await db_session.execute(select(IntegrationExecution.id))).scalars().all()
    )
    assert remaining_ids == {recent.id}


@pytest.mark.asyncio
async def test_webhook_cleanup_only_deletes_stale_inactive_endpoints(db_session):
    connector = _connector()
    integration = _integration()
    db_session.add_all([connector, integration])
    await db_session.flush()

    now = datetime.now(timezone.utc)

    def _endpoint(path, is_active, age_days):
        return WebhookEndpoint(
            organization_id=ORG,
            installed_id=integration.id,
            endpoint_path=path,
            secret_hash="x" * 64,
            event_types="[]",
            is_active=is_active,
            created_at=now - timedelta(days=age_days),
            updated_at=now - timedelta(days=age_days),
        )

    stale_inactive = _endpoint("/hooks/stale-inactive", False, 120)
    old_but_active = _endpoint("/hooks/old-active", True, 120)
    fresh_inactive = _endpoint("/hooks/fresh-inactive", False, 5)
    db_session.add_all([stale_inactive, old_but_active, fresh_inactive])
    await db_session.commit()

    result = await _webhook_cleanup_async(days_old=90)

    assert result["status"] == "success"
    assert result["deleted_count"] == 1

    remaining_paths = set(
        (await db_session.execute(select(WebhookEndpoint.endpoint_path))).scalars().all()
    )
    # Live config and recent rows must survive; only the stale inactive
    # endpoint gets deleted.
    assert remaining_paths == {"/hooks/old-active", "/hooks/fresh-inactive"}


@pytest.mark.asyncio
async def test_rate_limit_reset_clears_only_lapsed_windows(db_session):
    connector = _connector()
    now = datetime.now(timezone.utc)
    lapsed = _integration(
        status="rate_limited",
        rate_limit_remaining=0,
        rate_limit_reset=(now - timedelta(minutes=10)).isoformat(),
    )
    still_limited = _integration(
        status="rate_limited",
        rate_limit_remaining=0,
        rate_limit_reset=(now + timedelta(hours=1)).isoformat(),
    )
    untracked = _integration()
    db_session.add_all([connector, lapsed, still_limited, untracked])
    await db_session.commit()

    result = await _rate_limit_reset_async()

    assert result["status"] == "success"
    assert result["reset_count"] == 1

    rows = {
        row_id: (row_status, remaining, reset)
        for row_id, row_status, remaining, reset in (
            await db_session.execute(
                select(
                    InstalledIntegration.id,
                    InstalledIntegration.status,
                    InstalledIntegration.rate_limit_remaining,
                    InstalledIntegration.rate_limit_reset,
                )
            )
        ).all()
    }
    assert rows[lapsed.id] == ("active", None, None)
    assert rows[still_limited.id][0] == "rate_limited"
    assert rows[still_limited.id][1] == 0
    assert rows[untracked.id][0] == "active"


@pytest.mark.asyncio
async def test_connector_update_check_reports_registry_version_drift(db_session):
    stale = _connector(name="splunk", version="0.9.0")  # registry ships 1.0.0
    current = _connector(name="qradar", version="1.0.0")
    unknown = _connector(name="totally-custom", version="0.1.0")  # not in registry
    db_session.add_all([stale, current, unknown])
    await db_session.commit()

    result = await _connector_update_check_async()

    assert result["status"] == "success"
    assert result["source"] == "builtin_registry"
    updates = {u["connector"]: u for u in result["available_updates"]}
    assert set(updates) == {"splunk"}
    assert updates["splunk"]["installed_version"] == "0.9.0"
    assert updates["splunk"]["available_version"] == "1.0.0"
