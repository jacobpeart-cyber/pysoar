import pytest

from src.integrations.engine import ActionExecutor


@pytest.mark.asyncio
async def test_execute_action_with_mocked_connector(monkeypatch):
    """ActionExecutor.execute_action should return success when connector call succeeds."""

    async def fake_call(self, installation_id, action_name, input_data):
        return {"provider": "mock", "result": "ok"}

    async def fake_persist(self, *args, **kwargs):
        return None

    monkeypatch.setattr(ActionExecutor, "_call_connector_action", fake_call)
    monkeypatch.setattr(ActionExecutor, "_persist_execution", fake_persist)

    executor = ActionExecutor()
    result = await executor.execute_action(
        installation_id="inst-mock",
        action_name="send_message",
        input_data={"text": "hello"},
    )

    assert result["status"] == "success"
    assert result["output_data"]["provider"] == "mock"
