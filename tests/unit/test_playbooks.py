"""Tests for playbook functionality"""

import pytest
from httpx import AsyncClient

from src.playbooks.actions import get_action, list_available_actions


class TestPlaybookActions:
    """Tests for playbook action functions"""

    def test_list_available_actions(self):
        """Test listing available actions"""
        actions = list_available_actions()

        assert len(actions) > 0
        assert any(a["name"] == "enrich_ip" for a in actions)
        assert any(a["name"] == "send_notification" for a in actions)

    def test_get_action_exists(self):
        """Test getting an existing action"""
        action = get_action("enrich_ip")

        assert action is not None
        assert action.name == "enrich_ip"

    def test_get_action_not_exists(self):
        """Test getting a non-existent action"""
        action = get_action("nonexistent_action")

        assert action is None

    @pytest.mark.asyncio
    async def test_conditional_action_equals(self):
        """Test conditional action with equals operator"""
        action = get_action("conditional")
        result = await action.execute(
            parameters={
                "field": "severity",
                "operator": "equals",
                "value": "high",
            },
            context={"severity": "high"},
        )

        assert result["success"] is True
        assert result["condition_met"] is True

    @pytest.mark.asyncio
    async def test_conditional_action_not_equals(self):
        """Test conditional action when values don't match"""
        action = get_action("conditional")
        result = await action.execute(
            parameters={
                "field": "severity",
                "operator": "equals",
                "value": "high",
            },
            context={"severity": "low"},
        )

        assert result["success"] is True
        assert result["condition_met"] is False

    @pytest.mark.asyncio
    async def test_execute_integration_action_playbook_action(self, monkeypatch):
        """Test the playbook integration action wrapper."""

        class DummyExecutor:
            async def execute_action(
                self,
                installation_id,
                action_name,
                input_data,
                triggered_by=None,
                playbook_run_id=None,
            ):
                return {
                    "status": "success",
                    "output_data": {
                        "provider": "slack",
                        "channel": "#security",
                    },
                }

        monkeypatch.setattr("src.playbooks.actions.ActionExecutor", DummyExecutor)

        action = get_action("execute_integration_action")
        assert action is not None

        result = await action.execute(
            parameters={
                "installation_id": "inst-001",
                "action_name": "send_message",
                "input_data": {"channel": "#security", "text": "Alert"},
            },
            context={"playbook_execution_id": "pb-123"},
        )

        assert result["success"] is True
        assert result["execution"]["status"] == "success"
        assert result["execution"]["output_data"]["provider"] == "slack"

    @pytest.mark.asyncio
    async def test_virus_total_enrich_and_notify_playbook_action(self, monkeypatch):
        """Test the VirusTotal enrichment and Slack notification playbook action."""

        class DummyExecutor:
            async def execute_action(
                self,
                installation_id,
                action_name,
                input_data,
                triggered_by=None,
                playbook_run_id=None,
            ):
                if action_name.startswith("scan_"):
                    return {
                        "status": "success",
                        "output_data": {
                            "provider": "virustotal",
                            "malicious": 5,
                            "suspicious": 2,
                            "reputation": -10,
                            "tags": ["botnet", "malicious"],
                        },
                    }
                if action_name == "send_message":
                    return {
                        "status": "success",
                        "output_data": {
                            "provider": "slack",
                            "channel": "#security",
                        },
                    }
                return {"status": "failed", "error": "unknown action"}

        async def dummy_upsert(self, **kwargs):
            return "ioc-123"

        monkeypatch.setattr("src.playbooks.actions.ActionExecutor", DummyExecutor)
        monkeypatch.setattr(
            "src.playbooks.actions.VirusTotalEnrichAndNotifyAction._upsert_threat_indicator",
            dummy_upsert,
        )

        action = get_action("virus_total_enrich_and_notify")
        assert action is not None

        result = await action.execute(
            parameters={
                "ioc_type": "ip",
                "value": "8.8.8.8",
                "virustotal_installation_id": "vt-001",
                "slack_installation_id": "slack-001",
                "slack_channel": "#security",
            },
            context={"playbook_execution_id": "pb-123"},
        )

        assert result["success"] is True
        assert result["virus_total"]["provider"] == "virustotal"
        assert result["slack"]["status"] == "success"
        assert result["indicator_id"] == "ioc-123"

    @pytest.mark.asyncio
    async def test_virus_total_enrich_and_notify_hash_action(self, monkeypatch):
        """Test VirusTotal enrichment action mapping for hash indicators."""

        recorded = {"actions": []}

        class DummyExecutor:
            async def execute_action(
                self,
                installation_id,
                action_name,
                input_data,
                triggered_by=None,
                playbook_run_id=None,
            ):
                recorded["actions"].append(action_name)
                return {
                    "status": "success",
                    "output_data": {
                        "provider": "virustotal",
                        "malicious": 1,
                        "suspicious": 0,
                        "reputation": -3,
                        "tags": ["malicious"],
                    },
                }

        async def dummy_upsert(self, **kwargs):
            return "ioc-456"

        monkeypatch.setattr("src.playbooks.actions.ActionExecutor", DummyExecutor)
        monkeypatch.setattr(
            "src.playbooks.actions.VirusTotalEnrichAndNotifyAction._upsert_threat_indicator",
            dummy_upsert,
        )

        action = get_action("virus_total_enrich_and_notify")
        result = await action.execute(
            parameters={
                "ioc_type": "hash",
                "value": "abcd1234",
                "virustotal_installation_id": "vt-001",
                "slack_installation_id": "slack-001",
                "slack_channel": "#security",
            },
            context={"playbook_execution_id": "pb-456"},
        )

        assert result["success"] is True
        assert recorded["actions"][0] == "scan_file"
        assert result["indicator_id"] == "ioc-456"


@pytest.mark.asyncio
class TestPlaybookEndpoints:
    """Tests for playbook API endpoints"""

    async def test_create_playbook(self, client: AsyncClient, admin_auth_headers):
        """Test creating a playbook (admin only)"""
        response = await client.post(
            "/api/v1/playbooks",
            headers=admin_auth_headers,
            json={
                "name": "Test Playbook",
                "description": "A test playbook",
                "trigger_type": "manual",
                "steps": [
                    {
                        "id": "step1",
                        "name": "Enrich IP",
                        "action": "enrich_ip",
                        "parameters": {},
                    }
                ],
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Playbook"
        assert data["status"] == "draft"
        assert len(data["steps"]) == 1

    async def test_create_playbook_not_admin(self, client: AsyncClient, auth_headers):
        """Test creating a playbook as non-admin (should fail)"""
        response = await client.post(
            "/api/v1/playbooks",
            headers=auth_headers,
            json={
                "name": "Test Playbook",
                "steps": [{"id": "step1", "name": "Step 1", "action": "wait"}],
            },
        )

        assert response.status_code == 403

    async def test_list_playbooks(self, client: AsyncClient, auth_headers, admin_auth_headers):
        """Test listing playbooks"""
        # Create a playbook first
        await client.post(
            "/api/v1/playbooks",
            headers=admin_auth_headers,
            json={
                "name": "Test Playbook",
                "steps": [{"id": "step1", "name": "Step 1", "action": "wait", "parameters": {}}],
            },
        )

        response = await client.get(
            "/api/v1/playbooks",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    async def test_get_playbook(self, client: AsyncClient, auth_headers, admin_auth_headers):
        """Test getting a specific playbook"""
        # Create a playbook first
        create_response = await client.post(
            "/api/v1/playbooks",
            headers=admin_auth_headers,
            json={
                "name": "Test Playbook",
                "steps": [{"id": "step1", "name": "Step 1", "action": "wait", "parameters": {}}],
            },
        )
        playbook_id = create_response.json()["id"]

        response = await client.get(
            f"/api/v1/playbooks/{playbook_id}",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == playbook_id

    async def test_update_playbook(self, client: AsyncClient, admin_auth_headers):
        """Test updating a playbook"""
        # Create a playbook first
        create_response = await client.post(
            "/api/v1/playbooks",
            headers=admin_auth_headers,
            json={
                "name": "Test Playbook",
                "steps": [{"id": "step1", "name": "Step 1", "action": "wait", "parameters": {}}],
            },
        )
        playbook_id = create_response.json()["id"]

        # Update the playbook
        response = await client.patch(
            f"/api/v1/playbooks/{playbook_id}",
            headers=admin_auth_headers,
            json={
                "name": "Updated Playbook",
                "status": "active",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Playbook"
        assert data["status"] == "active"

    async def test_delete_playbook(self, client: AsyncClient, admin_auth_headers):
        """Test deleting a playbook"""
        # Create a playbook first
        create_response = await client.post(
            "/api/v1/playbooks",
            headers=admin_auth_headers,
            json={
                "name": "Test Playbook to Delete",
                "steps": [{"id": "step1", "name": "Step 1", "action": "wait", "parameters": {}}],
            },
        )
        playbook_id = create_response.json()["id"]

        # Delete the playbook
        response = await client.delete(
            f"/api/v1/playbooks/{playbook_id}",
            headers=admin_auth_headers,
        )

        assert response.status_code == 204
