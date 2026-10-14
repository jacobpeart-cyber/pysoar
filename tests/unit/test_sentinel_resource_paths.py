"""Sentinel incident / playbook ids are appended to the API base URL, so they
must be plain ARM resource paths: a crafted id must never move the request
(and its bearer token) to another host or path."""

import pytest

from src.integrations.connectors.microsoft_sentinel import azure_resource_path

GOOD = "/subscriptions/0000-1111/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/ws1/providers/Microsoft.SecurityInsights/incidents/abc-123"


def test_valid_arm_path_is_returned_unchanged() -> None:
    assert azure_resource_path(GOOD) == GOOD
    assert azure_resource_path(f"  {GOOD}  ") == GOOD


@pytest.mark.parametrize(
    "bad",
    [
        "@evil.example/x",
        "/subscriptions/abc@evil.example/x",
        "/subscriptions/abc/../../etc",
        "/subscriptions/abc//double",
        "/subscriptions/abc/incidents/1?api-version=evil",
        "/subscriptions/abc/incidents/1#frag",
        "https://evil.example/subscriptions/abc",
        "subscriptions/abc/incidents/1",
        "/subscriptions/abc/inci dents/1",
        "",
        None,
    ],
)
def test_crafted_ids_are_refused(bad) -> None:
    with pytest.raises(ValueError):
        azure_resource_path(bad)


@pytest.mark.asyncio
async def test_update_incident_refuses_crafted_id_before_any_request(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.integrations.connectors import microsoft_sentinel as mod

    connector = mod.MicrosoftSentinelConnector.__new__(mod.MicrosoftSentinelConnector)
    connector.credentials = {"subscription_id": "s", "tenant_id": "t", "client_id": "c", "client_secret": "x"}
    monkeypatch.setattr(type(connector), "is_configured", property(lambda self: True), raising=False)

    async def _token(self):
        return "tok"

    async def _never(*args, **kwargs):
        raise AssertionError("no request may be made for a crafted id")

    monkeypatch.setattr(type(connector), "_get_oauth_token", _token, raising=False)
    monkeypatch.setattr(type(connector), "_get_headers", lambda self: {}, raising=False)
    monkeypatch.setattr(type(connector), "_make_request", _never, raising=False)
    result = await connector.update_incident("@evil.example/x", {"title": "t"})
    assert "invalid incident_id" in result["error"]
    result = await connector.run_playbook("/subscriptions/abc/../../x")
    assert "invalid playbook_id" in result["error"]
