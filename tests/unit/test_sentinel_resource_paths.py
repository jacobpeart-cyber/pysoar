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


def _connector():
    from src.integrations.connectors import microsoft_sentinel as mod

    connector = mod.MicrosoftSentinelConnector.__new__(mod.MicrosoftSentinelConnector)
    connector.credentials = {
        "subscription_id": "0000-1111", "tenant_id": "t", "client_id": "c", "client_secret": "x",
        "resource_group": "rg-sec", "workspace_id": "ws1",
    }
    return connector


def test_incident_ids_resolve_inside_the_configured_workspace_only() -> None:
    c = _connector()
    assert c._scoped_incident_path("abc-123") == GOOD
    assert c._scoped_incident_path(GOOD) == GOOD
    assert c._scoped_incident_path(GOOD.replace("/resourceGroups/", "/resourcegroups/")) == GOOD
    for bad in (
        GOOD.replace("ws1", "ws-other"),                      # another workspace
        GOOD.replace("0000-1111", "2222-3333"),               # another subscription
        GOOD + "/comments/1",                                 # deeper resource
        "/subscriptions/0000-1111/resourceGroups/rg-sec/providers/Microsoft.Compute/virtualMachines/vm1",
        "/subscriptions/0000-1111/./x",
        "",
    ):
        with pytest.raises(ValueError):
            c._scoped_incident_path(bad)


def test_playbook_ids_resolve_to_logic_apps_in_the_configured_subscription_only() -> None:
    c = _connector()
    own = "/subscriptions/0000-1111/resourceGroups/rg-sec/providers/Microsoft.Logic/workflows/Block-IP"
    other_rg = "/subscriptions/0000-1111/resourceGroups/rg-automation/providers/Microsoft.Logic/workflows/Block-IP"
    assert c._scoped_workflow_path("Block-IP") == own
    assert c._scoped_workflow_path(own) == own
    assert c._scoped_workflow_path(other_rg) == other_rg
    for bad in (
        other_rg.replace("0000-1111", "2222-3333"),
        "/subscriptions/0000-1111/resourceGroups/rg-sec/providers/Microsoft.Compute/virtualMachines/vm1",
        own + "/runs/1",
        "/subscriptions/0000-1111/resourceGroups/rg-sec/providers/Microsoft.Logic/workflows/../x",
    ):
        with pytest.raises(ValueError):
            c._scoped_workflow_path(bad)


def test_dot_segments_are_refused_by_the_path_check() -> None:
    for bad in ("/subscriptions/abc/./incidents/1", "/subscriptions/abc/incidents/..", "/subscriptions/abc/../x"):
        with pytest.raises(ValueError):
            azure_resource_path(bad)
