"""Tests for alert functionality"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestAlertEndpoints:
    """Tests for alert API endpoints"""

    async def test_create_alert(self, client: AsyncClient, auth_headers):
        """Test creating an alert"""
        response = await client.post(
            "/api/v1/alerts",
            headers=auth_headers,
            json={
                "title": "Test Alert",
                "description": "This is a test alert",
                "severity": "high",
                "source": "manual",
                "source_ip": "192.168.1.1",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "Test Alert"
        assert data["severity"] == "high"
        assert data["status"] == "new"
        assert "id" in data

    async def test_list_alerts(self, client: AsyncClient, auth_headers):
        """Test listing alerts"""
        # Create an alert first
        await client.post(
            "/api/v1/alerts",
            headers=auth_headers,
            json={
                "title": "Test Alert",
                "severity": "medium",
            },
        )

        response = await client.get(
            "/api/v1/alerts",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert len(data["items"]) >= 1

    async def test_get_alert(self, client: AsyncClient, auth_headers):
        """Test getting a specific alert"""
        # Create an alert first
        create_response = await client.post(
            "/api/v1/alerts",
            headers=auth_headers,
            json={
                "title": "Test Alert",
                "severity": "low",
            },
        )
        alert_id = create_response.json()["id"]

        response = await client.get(
            f"/api/v1/alerts/{alert_id}",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == alert_id
        assert data["title"] == "Test Alert"

    async def test_update_alert(self, client: AsyncClient, auth_headers):
        """Test updating an alert"""
        # Create an alert first
        create_response = await client.post(
            "/api/v1/alerts",
            headers=auth_headers,
            json={
                "title": "Test Alert",
                "severity": "medium",
            },
        )
        alert_id = create_response.json()["id"]

        # Update the alert
        response = await client.patch(
            f"/api/v1/alerts/{alert_id}",
            headers=auth_headers,
            json={
                "status": "acknowledged",
                "severity": "high",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "acknowledged"
        assert data["severity"] == "high"

    async def test_delete_alert(self, client: AsyncClient, auth_headers):
        """Test deleting an alert"""
        # Create an alert first
        create_response = await client.post(
            "/api/v1/alerts",
            headers=auth_headers,
            json={
                "title": "Test Alert to Delete",
                "severity": "low",
            },
        )
        alert_id = create_response.json()["id"]

        # Delete the alert
        response = await client.delete(
            f"/api/v1/alerts/{alert_id}",
            headers=auth_headers,
        )

        assert response.status_code == 204

        # Verify it's deleted
        get_response = await client.get(
            f"/api/v1/alerts/{alert_id}",
            headers=auth_headers,
        )
        assert get_response.status_code == 404

    async def test_get_alert_stats(self, client: AsyncClient, auth_headers):
        """Test getting alert statistics"""
        response = await client.get(
            "/api/v1/alerts/stats",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "by_severity" in data
        assert "by_status" in data

    async def test_alert_not_found(self, client: AsyncClient, auth_headers):
        """Test getting non-existent alert"""
        response = await client.get(
            "/api/v1/alerts/nonexistent-id",
            headers=auth_headers,
        )

        assert response.status_code == 404

    async def test_create_alert_no_auth(self, client: AsyncClient):
        """Test creating alert without authentication"""
        response = await client.post(
            "/api/v1/alerts",
            json={
                "title": "Test Alert",
                "severity": "medium",
            },
        )

        assert response.status_code == 401
