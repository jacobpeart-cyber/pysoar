"""Tests for IOC functionality"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.ioc import IOC


@pytest.mark.asyncio
class TestIOCEndpoints:
    """Tests for IOC API endpoints"""

    async def test_create_ioc(self, client: AsyncClient, auth_headers):
        """Test creating an IOC"""
        response = await client.post(
            "/api/v1/iocs",
            headers=auth_headers,
            json={
                "value": "192.168.1.100",
                "ioc_type": "ip_address",
                "threat_level": "high",
                "description": "Malicious IP address",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["value"] == "192.168.1.100"
        assert data["ioc_type"] == "ip_address"
        assert data["threat_level"] == "high"

    async def test_create_ioc_no_auth(self, client: AsyncClient):
        """Test creating IOC without authentication"""
        response = await client.post(
            "/api/v1/iocs",
            json={
                "value": "192.168.1.100",
                "ioc_type": "ip_address",
            },
        )

        assert response.status_code == 401

    async def test_list_iocs(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test listing IOCs"""
        # Create test IOCs
        ioc1 = IOC(
            value="10.0.0.1",
            ioc_type="ip_address",
            threat_level="medium",
        )
        ioc2 = IOC(
            value="malware.exe",
            ioc_type="file_hash",
            threat_level="high",
        )
        db_session.add(ioc1)
        db_session.add(ioc2)
        await db_session.commit()

        response = await client.get(
            "/api/v1/iocs",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert len(data["items"]) >= 2

    async def test_get_ioc(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test getting a specific IOC"""
        ioc = IOC(
            value="evil.com",
            ioc_type="domain",
            threat_level="critical",
        )
        db_session.add(ioc)
        await db_session.commit()
        await db_session.refresh(ioc)

        response = await client.get(
            f"/api/v1/iocs/{ioc.id}",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["value"] == "evil.com"
        assert data["ioc_type"] == "domain"

    async def test_update_ioc(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test updating an IOC"""
        ioc = IOC(
            value="suspicious.com",
            ioc_type="domain",
            threat_level="low",
        )
        db_session.add(ioc)
        await db_session.commit()
        await db_session.refresh(ioc)

        response = await client.patch(
            f"/api/v1/iocs/{ioc.id}",
            headers=auth_headers,
            json={"threat_level": "high"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["threat_level"] == "high"

    async def test_delete_ioc(self, client: AsyncClient, admin_auth_headers, db_session: AsyncSession):
        """Test deleting an IOC"""
        ioc = IOC(
            value="delete-me.com",
            ioc_type="domain",
            threat_level="low",
        )
        db_session.add(ioc)
        await db_session.commit()
        await db_session.refresh(ioc)

        response = await client.delete(
            f"/api/v1/iocs/{ioc.id}",
            headers=admin_auth_headers,
        )

        assert response.status_code == 204

    async def test_search_iocs(self, client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test searching IOCs"""
        ioc = IOC(
            value="searchme.evil.com",
            ioc_type="domain",
            threat_level="high",
        )
        db_session.add(ioc)
        await db_session.commit()

        response = await client.get(
            "/api/v1/iocs?search=searchme",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) >= 1


class TestIOCValidation:
    """Tests for IOC validation"""

    @pytest.mark.asyncio
    async def test_invalid_ioc_type(self, client: AsyncClient, auth_headers):
        """Test creating IOC with invalid type"""
        response = await client.post(
            "/api/v1/iocs",
            headers=auth_headers,
            json={
                "value": "test",
                "ioc_type": "invalid_type",
            },
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_empty_value(self, client: AsyncClient, auth_headers):
        """Test creating IOC with empty value"""
        response = await client.post(
            "/api/v1/iocs",
            headers=auth_headers,
            json={
                "value": "",
                "ioc_type": "ip_address",
            },
        )

        assert response.status_code == 422
