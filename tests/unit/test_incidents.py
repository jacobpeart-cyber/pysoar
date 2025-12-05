"""Tests for incident functionality"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestIncidentEndpoints:
    """Tests for incident API endpoints"""

    async def test_create_incident(self, client: AsyncClient, auth_headers):
        """Test creating an incident"""
        response = await client.post(
            "/api/v1/incidents",
            headers=auth_headers,
            json={
                "title": "Test Incident",
                "description": "This is a test incident",
                "severity": "high",
                "incident_type": "malware",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "Test Incident"
        assert data["severity"] == "high"
        assert data["status"] == "open"
        assert "id" in data

    async def test_list_incidents(self, client: AsyncClient, auth_headers):
        """Test listing incidents"""
        # Create an incident first
        await client.post(
            "/api/v1/incidents",
            headers=auth_headers,
            json={
                "title": "Test Incident",
                "severity": "medium",
            },
        )

        response = await client.get(
            "/api/v1/incidents",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    async def test_get_incident(self, client: AsyncClient, auth_headers):
        """Test getting a specific incident"""
        # Create an incident first
        create_response = await client.post(
            "/api/v1/incidents",
            headers=auth_headers,
            json={
                "title": "Test Incident",
                "severity": "low",
            },
        )
        incident_id = create_response.json()["id"]

        response = await client.get(
            f"/api/v1/incidents/{incident_id}",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == incident_id

    async def test_update_incident(self, client: AsyncClient, auth_headers):
        """Test updating an incident"""
        # Create an incident first
        create_response = await client.post(
            "/api/v1/incidents",
            headers=auth_headers,
            json={
                "title": "Test Incident",
                "severity": "medium",
            },
        )
        incident_id = create_response.json()["id"]

        # Update the incident
        response = await client.patch(
            f"/api/v1/incidents/{incident_id}",
            headers=auth_headers,
            json={
                "status": "investigating",
                "severity": "high",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "investigating"
        assert data["severity"] == "high"

    async def test_delete_incident(self, client: AsyncClient, auth_headers):
        """Test deleting an incident"""
        # Create an incident first
        create_response = await client.post(
            "/api/v1/incidents",
            headers=auth_headers,
            json={
                "title": "Test Incident to Delete",
                "severity": "low",
            },
        )
        incident_id = create_response.json()["id"]

        # Delete the incident
        response = await client.delete(
            f"/api/v1/incidents/{incident_id}",
            headers=auth_headers,
        )

        assert response.status_code == 204

    async def test_link_alert_to_incident(self, client: AsyncClient, auth_headers):
        """Test linking an alert to an incident"""
        # Create an alert
        alert_response = await client.post(
            "/api/v1/alerts",
            headers=auth_headers,
            json={
                "title": "Test Alert",
                "severity": "high",
            },
        )
        alert_id = alert_response.json()["id"]

        # Create an incident
        incident_response = await client.post(
            "/api/v1/incidents",
            headers=auth_headers,
            json={
                "title": "Test Incident",
                "severity": "high",
            },
        )
        incident_id = incident_response.json()["id"]

        # Link alert to incident
        response = await client.post(
            f"/api/v1/incidents/{incident_id}/alerts/{alert_id}",
            headers=auth_headers,
        )

        assert response.status_code == 200

    async def test_get_incident_stats(self, client: AsyncClient, auth_headers):
        """Test getting incident statistics"""
        response = await client.get(
            "/api/v1/incidents/stats",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "by_severity" in data
        assert "by_status" in data
