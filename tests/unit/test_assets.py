"""Tests for Asset functionality"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.asset import Asset


@pytest.mark.asyncio
class TestAssetEndpoints:
    """Tests for Asset API endpoints"""

    async def test_create_asset(self, client: AsyncClient, auth_headers):
        """Test creating an asset"""
        response = await client.post(
            "/api/v1/assets",
            headers=auth_headers,
            json={
                "name": "Web Server 1",
                "hostname": "web-srv-01",
                "asset_type": "server",
                "ip_address": "192.168.1.10",
                "criticality": "high",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Web Server 1"
        assert data["hostname"] == "web-srv-01"
        assert data["asset_type"] == "server"

    async def test_list_assets(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test listing assets"""
        asset1 = Asset(
            name="Server 1",
            asset_type="server",
            criticality="high",
        )
        asset2 = Asset(
            name="Workstation 1",
            asset_type="workstation",
            criticality="medium",
        )
        db_session.add(asset1)
        db_session.add(asset2)
        await db_session.commit()

        response = await client.get(
            "/api/v1/assets",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert len(data["items"]) >= 2

    async def test_get_asset(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test getting a specific asset"""
        asset = Asset(
            name="Test Server",
            hostname="test-srv",
            asset_type="server",
            ip_address="10.0.0.5",
            criticality="critical",
        )
        db_session.add(asset)
        await db_session.commit()
        await db_session.refresh(asset)

        response = await client.get(
            f"/api/v1/assets/{asset.id}",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Server"
        assert data["hostname"] == "test-srv"

    async def test_update_asset(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test updating an asset"""
        asset = Asset(
            name="Old Name",
            asset_type="server",
            criticality="low",
        )
        db_session.add(asset)
        await db_session.commit()
        await db_session.refresh(asset)

        response = await client.patch(
            f"/api/v1/assets/{asset.id}",
            headers=auth_headers,
            json={
                "name": "New Name",
                "criticality": "high",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "New Name"
        assert data["criticality"] == "high"

    async def test_delete_asset(self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession):
        """Test deleting an asset"""
        asset = Asset(
            name="Delete Me",
            asset_type="workstation",
            criticality="low",
        )
        db_session.add(asset)
        await db_session.commit()
        await db_session.refresh(asset)

        response = await client.delete(
            f"/api/v1/assets/{asset.id}",
            headers=admin_auth_headers,
        )

        assert response.status_code == 204

    async def test_filter_by_type(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test filtering assets by type"""
        server = Asset(name="Server", asset_type="server", criticality="high")
        workstation = Asset(name="Workstation", asset_type="workstation", criticality="medium")
        db_session.add(server)
        db_session.add(workstation)
        await db_session.commit()

        response = await client.get(
            "/api/v1/assets?asset_type=server",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["asset_type"] == "server"

    async def test_filter_by_criticality(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test filtering assets by criticality"""
        critical = Asset(name="Critical Asset", asset_type="server", criticality="critical")
        low = Asset(name="Low Asset", asset_type="workstation", criticality="low")
        db_session.add(critical)
        db_session.add(low)
        await db_session.commit()

        response = await client.get(
            "/api/v1/assets?criticality=critical",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["criticality"] == "critical"
