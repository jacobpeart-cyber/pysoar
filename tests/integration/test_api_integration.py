"""Integration tests for API workflows"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.alert import Alert
from src.models.incident import Incident
from src.models.ioc import IOC


@pytest.mark.asyncio
class TestAlertToIncidentWorkflow:
    """Test the complete alert-to-incident workflow"""

    async def test_create_alert_and_escalate_to_incident(
        self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession
    ):
        """Test creating an alert and escalating it to an incident"""
        # Create an alert
        alert_response = await client.post(
            "/api/v1/alerts",
            headers=admin_auth_headers,
            json={
                "title": "Suspicious Network Activity",
                "description": "Multiple connection attempts to known malicious IP",
                "severity": "high",
                "source": "siem",
            },
        )
        assert alert_response.status_code == 201
        alert_data = alert_response.json()
        alert_id = alert_data["id"]

        # Create an incident
        incident_response = await client.post(
            "/api/v1/incidents",
            headers=admin_auth_headers,
            json={
                "title": "Potential Data Exfiltration",
                "description": "Investigation into suspicious network activity",
                "severity": "high",
                "incident_type": "data_breach",
            },
        )
        assert incident_response.status_code == 201
        incident_data = incident_response.json()
        incident_id = incident_data["id"]

        # Link alert to incident
        link_response = await client.patch(
            f"/api/v1/alerts/{alert_id}",
            headers=admin_auth_headers,
            json={"incident_id": incident_id},
        )
        assert link_response.status_code == 200
        assert link_response.json()["incident_id"] == incident_id

    async def test_bulk_alert_creation_and_correlation(
        self, client: AsyncClient, admin_auth_headers
    ):
        """Test creating multiple related alerts"""
        alerts = [
            {
                "title": f"Alert {i}",
                "severity": "medium",
                "source": "edr",
                "source_ip": "192.168.1.100",
            }
            for i in range(5)
        ]

        created_alerts = []
        for alert in alerts:
            response = await client.post(
                "/api/v1/alerts",
                headers=admin_auth_headers,
                json=alert,
            )
            assert response.status_code == 201
            created_alerts.append(response.json())

        # Verify all alerts were created
        assert len(created_alerts) == 5

        # List alerts filtered by source IP
        response = await client.get(
            "/api/v1/alerts?source_ip=192.168.1.100",
            headers=admin_auth_headers,
        )
        assert response.status_code == 200


@pytest.mark.asyncio
class TestIOCEnrichment:
    """Test IOC enrichment workflow"""

    async def test_create_and_search_iocs(
        self, client: AsyncClient, auth_headers, db_session: AsyncSession
    ):
        """Test creating IOCs and searching for them"""
        # Create multiple IOCs
        iocs = [
            {"value": "192.168.1.1", "ioc_type": "ip_address", "threat_level": "high"},
            {"value": "malware.exe", "ioc_type": "file_name", "threat_level": "critical"},
            {"value": "evil.com", "ioc_type": "domain", "threat_level": "high"},
        ]

        for ioc in iocs:
            response = await client.post(
                "/api/v1/iocs",
                headers=auth_headers,
                json=ioc,
            )
            assert response.status_code == 201

        # Search for IOCs
        response = await client.get(
            "/api/v1/iocs?threat_level=high",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        high_threat_iocs = [i for i in data["items"] if i["threat_level"] == "high"]
        assert len(high_threat_iocs) >= 2


@pytest.mark.asyncio
class TestAssetManagement:
    """Test asset management workflow"""

    async def test_asset_inventory_workflow(
        self, client: AsyncClient, auth_headers, db_session: AsyncSession
    ):
        """Test complete asset inventory workflow"""
        # Create assets
        assets = [
            {
                "name": "Web Server",
                "hostname": "web-01",
                "asset_type": "server",
                "ip_address": "10.0.0.1",
                "criticality": "critical",
            },
            {
                "name": "Database Server",
                "hostname": "db-01",
                "asset_type": "server",
                "ip_address": "10.0.0.2",
                "criticality": "critical",
            },
            {
                "name": "Employee Workstation",
                "hostname": "ws-001",
                "asset_type": "workstation",
                "ip_address": "10.0.1.1",
                "criticality": "medium",
            },
        ]

        for asset in assets:
            response = await client.post(
                "/api/v1/assets",
                headers=auth_headers,
                json=asset,
            )
            assert response.status_code == 201

        # List critical assets
        response = await client.get(
            "/api/v1/assets?criticality=critical",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        critical_assets = [a for a in data["items"] if a["criticality"] == "critical"]
        assert len(critical_assets) >= 2


@pytest.mark.asyncio
class TestIncidentLifecycle:
    """Test incident lifecycle management"""

    async def test_incident_status_progression(
        self, client: AsyncClient, admin_auth_headers
    ):
        """Test progressing an incident through its lifecycle"""
        # Create incident
        response = await client.post(
            "/api/v1/incidents",
            headers=admin_auth_headers,
            json={
                "title": "Security Incident",
                "severity": "high",
                "incident_type": "malware",
            },
        )
        assert response.status_code == 201
        incident = response.json()
        incident_id = incident["id"]
        assert incident["status"] == "open"

        # Progress through statuses
        statuses = ["investigating", "containment", "eradication", "recovery", "closed"]

        for status in statuses:
            response = await client.patch(
                f"/api/v1/incidents/{incident_id}",
                headers=admin_auth_headers,
                json={"status": status},
            )
            assert response.status_code == 200
            assert response.json()["status"] == status
